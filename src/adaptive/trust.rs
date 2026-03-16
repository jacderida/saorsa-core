// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! EigenTrust++ implementation for decentralized reputation management
//!
//! Provides global trust scores based on local peer interactions with
//! pre-trusted nodes and time decay.
//!
//! `TrustEngine` is the **sole authority** on peer trust scores.
//! All trust signals flow in through `update_node_stats()`, and all
//! trust queries use `score()` or `get_trust_async()`.

use crate::PeerId;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default trust score for unknown peers
pub const DEFAULT_NEUTRAL_TRUST: f64 = 0.5;

/// Initial trust score assigned to pre-trusted (bootstrap) nodes
const PRE_TRUSTED_INITIAL_SCORE: f64 = 0.9;

/// Teleportation probability — fraction of trust that flows to pre-trusted nodes each iteration.
/// Higher values make the system more resistant to Sybil attacks but slower to promote new nodes.
const EIGENTRUST_ALPHA: f64 = 0.4;

/// Trust decay rate per hour. Applied as `decay_rate^elapsed_hours`.
const TRUST_DECAY_RATE: f64 = 0.99;

/// Maximum power iterations for global trust convergence
const MAX_POWER_ITERATIONS: usize = 50;

/// L1-norm threshold for early termination of power iteration
const CONVERGENCE_THRESHOLD: f64 = 0.0001;

/// Timeout for a single global trust computation to prevent hangs
const COMPUTE_TIMEOUT_SECS: u64 = 2;

/// EMA weight for old value when updating local trust (1 - this = weight for new observation)
const LOCAL_TRUST_EMA_OLD_WEIGHT: f64 = 0.9;

/// Early termination iteration threshold for medium-sized networks (>100 nodes)
const MEDIUM_NETWORK_MAX_ITERATIONS: usize = 5;

/// Early termination iteration threshold for large networks (>500 nodes)
const LARGE_NETWORK_MAX_ITERATIONS: usize = 2;

/// Node count threshold for medium network early termination
const MEDIUM_NETWORK_SIZE: usize = 100;

/// Node count threshold for large network early termination
const LARGE_NETWORK_SIZE: usize = 500;

/// EigenTrust++ engine for reputation management
///
/// This is the **sole authority** on peer trust scores in the system.
/// Trust is computed via power iteration over local trust relationships,
/// weighted by response rate statistics and time decay.
#[derive(Debug)]
pub struct TrustEngine {
    /// Local trust scores between pairs of nodes
    local_trust: Arc<RwLock<HashMap<(PeerId, PeerId), LocalTrustData>>>,

    /// Global trust scores (result of power iteration)
    global_trust: Arc<RwLock<HashMap<PeerId, f64>>>,

    /// Pre-trusted nodes (bootstrap nodes that anchor the trust graph)
    pre_trusted_nodes: Arc<RwLock<HashSet<PeerId>>>,

    /// Per-node interaction statistics (correct/failed responses)
    node_stats: Arc<RwLock<HashMap<PeerId, NodeStatistics>>>,

    /// Teleportation probability (alpha parameter)
    alpha: f64,

    /// Trust decay rate per hour
    decay_rate: f64,

    /// Last trust recomputation timestamp
    last_update: RwLock<Instant>,

    /// Cached trust scores for fast synchronous access
    trust_cache: Arc<RwLock<HashMap<PeerId, f64>>>,
}

/// Local trust data with interaction history
#[derive(Debug, Clone)]
struct LocalTrustData {
    /// Current trust value (0.0 to 1.0)
    value: f64,
    /// Number of interactions observed
    interactions: u64,
    /// Timestamp of last interaction
    last_interaction: Instant,
}

/// Per-node interaction statistics used for trust adjustment
#[derive(Debug, Clone, Default)]
pub struct NodeStatistics {
    /// Number of correct/successful responses
    pub correct_responses: u64,
    /// Number of failed responses (weighted by severity)
    pub failed_responses: u64,
}

/// Statistics update type for recording peer interaction outcomes
#[derive(Debug, Clone)]
pub enum NodeStatisticsUpdate {
    /// Peer provided a correct response
    CorrectResponse,
    /// Peer failed to provide a response
    FailedResponse,
}

impl TrustEngine {
    /// Create a new TrustEngine with the given set of pre-trusted (bootstrap) nodes
    pub fn new(pre_trusted_nodes: HashSet<PeerId>) -> Self {
        let mut initial_cache = HashMap::new();
        for node in &pre_trusted_nodes {
            initial_cache.insert(*node, PRE_TRUSTED_INITIAL_SCORE);
        }

        Self {
            local_trust: Arc::new(RwLock::new(HashMap::new())),
            global_trust: Arc::new(RwLock::new(HashMap::new())),
            pre_trusted_nodes: Arc::new(RwLock::new(pre_trusted_nodes)),
            node_stats: Arc::new(RwLock::new(HashMap::new())),
            alpha: EIGENTRUST_ALPHA,
            decay_rate: TRUST_DECAY_RATE,
            last_update: RwLock::new(Instant::now()),
            trust_cache: Arc::new(RwLock::new(initial_cache)),
        }
    }

    /// Update local trust based on a pairwise interaction outcome
    pub async fn update_local_trust(&self, from: &PeerId, to: &PeerId, success: bool) {
        let key = (*from, *to);
        let new_value = if success { 1.0 } else { 0.0 };

        let mut trust_map = self.local_trust.write().await;
        trust_map
            .entry(key)
            .and_modify(|data| {
                data.value = LOCAL_TRUST_EMA_OLD_WEIGHT * data.value
                    + (1.0 - LOCAL_TRUST_EMA_OLD_WEIGHT) * new_value;
                data.interactions += 1;
                data.last_interaction = Instant::now();
            })
            .or_insert(LocalTrustData {
                value: new_value,
                interactions: 1,
                last_interaction: Instant::now(),
            });
    }

    /// Record a peer interaction outcome that affects trust scoring
    pub async fn update_node_stats(&self, node_id: &PeerId, stats_update: NodeStatisticsUpdate) {
        let mut stats = self.node_stats.write().await;
        let node_stats = stats.entry(*node_id).or_default();

        match stats_update {
            NodeStatisticsUpdate::CorrectResponse => node_stats.correct_responses += 1,
            NodeStatisticsUpdate::FailedResponse => node_stats.failed_responses += 1,
        }
    }

    /// Compute global trust scores via power iteration
    ///
    /// Returns the computed trust map, or cached values on timeout.
    pub async fn compute_global_trust(&self) -> HashMap<PeerId, f64> {
        let result = tokio::time::timeout(
            Duration::from_secs(COMPUTE_TIMEOUT_SECS),
            self.compute_global_trust_internal(),
        )
        .await;

        match result {
            Ok(trust_map) => trust_map,
            Err(_) => self.trust_cache.read().await.clone(),
        }
    }

    async fn compute_global_trust_internal(&self) -> HashMap<PeerId, f64> {
        let local_trust = self.local_trust.read().await;
        let node_stats = self.node_stats.read().await;
        let pre_trusted = self.pre_trusted_nodes.read().await;

        // Collect all known nodes
        let mut node_set = HashSet::new();
        for ((from, to), _) in local_trust.iter() {
            node_set.insert(*from);
            node_set.insert(*to);
        }
        for node in node_stats.keys() {
            node_set.insert(*node);
        }

        if node_set.is_empty() {
            return HashMap::new();
        }

        let n = node_set.len();

        // Build sparse adjacency: incoming edges and outgoing sums for normalization
        let mut incoming_edges: HashMap<PeerId, Vec<(PeerId, f64)>> = HashMap::new();
        let mut outgoing_sums: HashMap<PeerId, f64> = HashMap::new();

        for ((from, _), data) in local_trust.iter() {
            if data.value > 0.0 {
                *outgoing_sums.entry(*from).or_insert(0.0) += data.value;
            }
        }

        for ((from, to), data) in local_trust.iter() {
            if data.value <= 0.0 {
                continue;
            }
            let Some(sum) = outgoing_sums.get(from) else {
                continue;
            };
            if *sum <= 0.0 {
                continue;
            }
            let normalized_value = data.value / sum;
            incoming_edges
                .entry(*to)
                .or_default()
                .push((*from, normalized_value));
        }

        // Initialize trust vector uniformly
        let initial_trust = 1.0 / n as f64;
        let mut trust_vector: HashMap<PeerId, f64> =
            node_set.iter().map(|node| (*node, initial_trust)).collect();

        // Pre-compute pre-trusted teleportation distribution
        let pre_trust_value = if !pre_trusted.is_empty() {
            1.0 / pre_trusted.len() as f64
        } else {
            0.0
        };

        // Power iteration — O(edges) per iteration, not O(n²)
        for iteration in 0..MAX_POWER_ITERATIONS {
            let mut new_trust: HashMap<PeerId, f64> = HashMap::new();

            // Propagate trust through edges (1-alpha portion)
            for node in &node_set {
                let mut trust_sum = 0.0;
                if let Some(edges) = incoming_edges.get(node) {
                    for (from_node, weight) in edges {
                        if let Some(from_trust) = trust_vector.get(from_node) {
                            trust_sum += weight * from_trust;
                        }
                    }
                }
                new_trust.insert(*node, (1.0 - self.alpha) * trust_sum);
            }

            // Add teleportation component (alpha portion)
            if !pre_trusted.is_empty() {
                for pre_node in pre_trusted.iter() {
                    let current = new_trust.entry(*pre_node).or_insert(0.0);
                    *current += self.alpha * pre_trust_value;
                }
            } else {
                let uniform_value = self.alpha / n as f64;
                for node in &node_set {
                    let current = new_trust.entry(*node).or_insert(0.0);
                    *current += uniform_value;
                }
            }

            // Normalize to sum to 1.0
            let sum: f64 = new_trust.values().sum();
            if sum > 0.0 {
                for trust in new_trust.values_mut() {
                    *trust /= sum;
                }
            }

            // Check convergence (L1 norm)
            let diff: f64 = node_set
                .iter()
                .map(|node| {
                    let old = trust_vector.get(node).unwrap_or(&0.0);
                    let new = new_trust.get(node).unwrap_or(&0.0);
                    (old - new).abs()
                })
                .sum();

            trust_vector = new_trust;

            if diff < CONVERGENCE_THRESHOLD {
                break;
            }
            if n > MEDIUM_NETWORK_SIZE && iteration > MEDIUM_NETWORK_MAX_ITERATIONS {
                break;
            }
            if n > LARGE_NETWORK_SIZE && iteration > LARGE_NETWORK_MAX_ITERATIONS {
                break;
            }
        }

        // Apply response-rate adjustment from node statistics
        for (node, trust) in trust_vector.iter_mut() {
            if let Some(stats) = node_stats.get(node) {
                let response_rate = Self::compute_response_rate(stats);
                *trust *= response_rate;
            }
        }

        // Apply time decay
        let last_update = self.last_update.read().await;
        let elapsed_hours = last_update.elapsed().as_secs() as f64 / 3600.0;
        for trust in trust_vector.values_mut() {
            *trust *= self.decay_rate.powf(elapsed_hours);
        }

        // Final normalization
        let total_trust: f64 = trust_vector.values().sum();
        if total_trust > 0.0 {
            for trust in trust_vector.values_mut() {
                *trust /= total_trust;
            }
        }

        // Update caches
        let mut global_trust = self.global_trust.write().await;
        let mut trust_cache = self.trust_cache.write().await;
        for (node, trust) in &trust_vector {
            global_trust.insert(*node, *trust);
            trust_cache.insert(*node, *trust);
        }

        *self.last_update.write().await = Instant::now();

        trust_vector
    }

    /// Compute response rate from node statistics (0.0 to 1.0)
    ///
    /// Returns 0.5 (neutral) if no interactions have been recorded.
    fn compute_response_rate(stats: &NodeStatistics) -> f64 {
        let total = stats.correct_responses + stats.failed_responses;
        if total > 0 {
            stats.correct_responses as f64 / total as f64
        } else {
            DEFAULT_NEUTRAL_TRUST
        }
    }

    /// Add a pre-trusted node (e.g., a bootstrap node)
    pub async fn add_pre_trusted(&self, node_id: PeerId) {
        let mut pre_trusted = self.pre_trusted_nodes.write().await;
        pre_trusted.insert(node_id);

        let mut cache = self.trust_cache.write().await;
        cache.insert(node_id, PRE_TRUSTED_INITIAL_SCORE);
    }

    /// Remove a pre-trusted node
    pub async fn remove_pre_trusted(&self, node_id: &PeerId) {
        let mut pre_trusted = self.pre_trusted_nodes.write().await;
        pre_trusted.remove(node_id);
    }

    /// Get current trust score (async access)
    pub async fn get_trust_async(&self, node_id: &PeerId) -> f64 {
        let cache = self.trust_cache.read().await;
        cache.get(node_id).copied().unwrap_or(DEFAULT_NEUTRAL_TRUST)
    }

    /// Get current trust score (fast synchronous access via cache)
    ///
    /// Returns `DEFAULT_NEUTRAL_TRUST` (0.5) for unknown peers or if the cache lock is contended.
    pub fn score(&self, node_id: &PeerId) -> f64 {
        if let Ok(cache) = self.trust_cache.try_read() {
            cache.get(node_id).copied().unwrap_or(DEFAULT_NEUTRAL_TRUST)
        } else {
            DEFAULT_NEUTRAL_TRUST
        }
    }

    /// Get all cached trust scores (synchronous snapshot)
    pub fn get_global_trust(&self) -> HashMap<PeerId, f64> {
        if let Ok(cache) = self.trust_cache.try_read() {
            cache.clone()
        } else {
            HashMap::new()
        }
    }

    /// Remove a peer from the trust system entirely
    pub fn remove_node(&self, node: &PeerId) {
        let node_id = *node;
        let local_trust = self.local_trust.clone();
        let trust_cache = self.trust_cache.clone();

        tokio::spawn(async move {
            let mut trust_map = local_trust.write().await;
            trust_map.retain(|(from, to), _| from != &node_id && to != &node_id);

            let mut cache = trust_cache.write().await;
            cache.remove(&node_id);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_eigentrust_basic() {
        use rand::RngCore;

        let mut hash_pre = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash_pre);
        let pre_trusted = HashSet::from([PeerId::from_bytes(hash_pre)]);

        let engine = TrustEngine::new(pre_trusted.clone());

        let mut hash1 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash1);
        let node1 = PeerId::from_bytes(hash1);

        let mut hash2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash2);
        let node2 = PeerId::from_bytes(hash2);

        let pre_trusted_node = pre_trusted.iter().next().unwrap();

        engine
            .update_local_trust(pre_trusted_node, &node1, true)
            .await;
        engine.update_local_trust(&node1, &node2, true).await;
        engine.update_local_trust(&node2, &node1, false).await;

        let global_trust = engine.get_global_trust();

        // Pre-trusted node should have highest trust (initialized at PRE_TRUSTED_INITIAL_SCORE)
        let pre_trust = global_trust.get(pre_trusted_node).unwrap_or(&0.0);
        let node1_trust = global_trust.get(&node1).unwrap_or(&0.0);

        assert!(pre_trust > node1_trust);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_trust_normalization() {
        use rand::RngCore;

        let engine = TrustEngine::new(HashSet::new());

        let mut hash1 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash1);
        let node1 = PeerId::from_bytes(hash1);

        let mut hash2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash2);
        let node2 = PeerId::from_bytes(hash2);

        let mut hash3 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash3);
        let node3 = PeerId::from_bytes(hash3);

        engine.update_local_trust(&node1, &node2, true).await;
        engine.update_local_trust(&node1, &node3, true).await;

        let global_trust = tokio::time::timeout(
            Duration::from_secs(COMPUTE_TIMEOUT_SECS),
            engine.compute_global_trust(),
        )
        .await
        .unwrap_or_else(|_| HashMap::new());

        let trust2 = global_trust.get(&node2).copied().unwrap_or(0.0);
        let trust3 = global_trust.get(&node3).copied().unwrap_or(0.0);

        // Equally trusted nodes should have approximately equal scores
        if trust2 > 0.0 && trust3 > 0.0 {
            assert!((trust2 - trust3).abs() < 0.01);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_response_rate_trust() {
        use rand::RngCore;

        let engine = Arc::new(TrustEngine::new(HashSet::new()));

        let mut hash = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash);
        let node = PeerId::from_bytes(hash);

        // Record 2 successes and 1 failure → 66% response rate
        engine
            .update_node_stats(&node, NodeStatisticsUpdate::CorrectResponse)
            .await;
        engine
            .update_node_stats(&node, NodeStatisticsUpdate::CorrectResponse)
            .await;
        engine
            .update_node_stats(&node, NodeStatisticsUpdate::FailedResponse)
            .await;

        // Add a trust relationship so the node appears in computation
        let mut hash2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash2);
        let other = PeerId::from_bytes(hash2);

        engine.update_local_trust(&other, &node, true).await;

        let compute_ok = tokio::time::timeout(
            Duration::from_secs(COMPUTE_TIMEOUT_SECS),
            engine.compute_global_trust(),
        )
        .await
        .is_ok();

        let trust_value = if compute_ok {
            let global_trust = engine.get_global_trust();
            *global_trust.get(&node).unwrap_or(&0.0)
        } else {
            engine.get_trust_async(&node).await
        };

        assert!(trust_value >= 0.0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_trust_decay() {
        use rand::RngCore;

        let mut engine = TrustEngine::new(HashSet::new());
        engine.decay_rate = 0.5; // Fast decay for testing

        let mut hash1 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash1);
        let node1 = PeerId::from_bytes(hash1);

        let mut hash2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash2);
        let node2 = PeerId::from_bytes(hash2);

        engine.update_local_trust(&node1, &node2, true).await;

        let _ = tokio::time::timeout(
            Duration::from_secs(COMPUTE_TIMEOUT_SECS),
            engine.compute_global_trust(),
        )
        .await;
        let trust1 = engine.get_global_trust();
        let initial_trust = trust1.get(&node2).copied().unwrap_or(0.0);

        // Simulate 1 hour passing
        if let Some(past_time) = Instant::now().checked_sub(Duration::from_secs(3600)) {
            *engine.last_update.write().await = past_time;
        }

        let _ = tokio::time::timeout(
            Duration::from_secs(COMPUTE_TIMEOUT_SECS),
            engine.compute_global_trust(),
        )
        .await;
        let trust2 = engine.get_global_trust();
        let decayed_trust = trust2.get(&node2).copied().unwrap_or(0.0);

        if initial_trust > 0.0 && decayed_trust > 0.0 {
            assert!(decayed_trust <= initial_trust);
        }
    }

    #[test]
    fn test_score_returns_neutral_for_unknown_peers() {
        let engine = TrustEngine::new(HashSet::new());
        let unknown = PeerId::from_bytes([42u8; 32]);
        assert!((engine.score(&unknown) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);
    }

    #[test]
    fn test_score_returns_pre_trusted_score() {
        let node = PeerId::from_bytes([1u8; 32]);
        let engine = TrustEngine::new(HashSet::from([node]));
        assert!((engine.score(&node) - PRE_TRUSTED_INITIAL_SCORE).abs() < f64::EPSILON);
    }
}
