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

//! Local trust scoring based on direct peer interactions.
//!
//! Scores use an exponential moving average (EMA) that blends each new
//! observation and decays toward neutral when idle. No background task
//! needed — decay is applied lazily on each read or write.
//!
//! Future: full EigenTrust with peer-to-peer trust gossip.

use crate::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Default trust score for unknown peers
pub const DEFAULT_NEUTRAL_TRUST: f64 = 0.5;

/// Minimum trust score a peer can reach
const MIN_TRUST_SCORE: f64 = 0.0;

/// Maximum trust score a peer can reach
const MAX_TRUST_SCORE: f64 = 1.0;

/// EMA weight for each new observation (higher = faster response to events)
const EMA_WEIGHT: f64 = 0.1;

/// Decay constant (per-second).
///
/// Tuned so that the worst possible score (0.0) takes 3 days of idle time
/// to decay back above the block threshold (0.15).
///
/// Derivation: 0.15 = 0.5 - 0.5 * e^(-λ * 259200)  →  λ = -ln(0.7) / 259200
const DECAY_LAMBDA: f64 = 1.3761e-6;

/// Per-node trust state
#[derive(Debug, Clone)]
struct PeerTrust {
    /// Current trust score (between MIN and MAX)
    score: f64,
    /// When the score was last updated (for decay calculation)
    last_updated: Instant,
}

impl PeerTrust {
    fn new() -> Self {
        Self {
            score: DEFAULT_NEUTRAL_TRUST,
            last_updated: Instant::now(),
        }
    }

    /// Apply time-based decay toward neutral, then clamp to bounds.
    ///
    /// Uses exponential decay: `score = neutral + (score - neutral) * e^(-λt)`
    /// This smoothly pulls the score back toward 0.5 over time.
    fn apply_decay(&mut self) {
        let elapsed_secs = self.last_updated.elapsed().as_secs_f64();
        if elapsed_secs > 0.0 {
            let decay_factor = (-DECAY_LAMBDA * elapsed_secs).exp();
            self.score =
                DEFAULT_NEUTRAL_TRUST + (self.score - DEFAULT_NEUTRAL_TRUST) * decay_factor;
            self.score = self.score.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE);
            self.last_updated = Instant::now();
        }
    }

    /// Apply a new observation via EMA, after first applying decay.
    fn record(&mut self, observation: f64) {
        self.apply_decay();
        self.score = (1.0 - EMA_WEIGHT) * self.score + EMA_WEIGHT * observation;
        self.score = self.score.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE);
        self.last_updated = Instant::now();
    }

    /// Get the current score with decay applied (does not mutate).
    fn decayed_score(&self) -> f64 {
        let elapsed_secs = self.last_updated.elapsed().as_secs_f64();
        if elapsed_secs > 0.0 {
            let decay_factor = (-DECAY_LAMBDA * elapsed_secs).exp();
            let score = DEFAULT_NEUTRAL_TRUST + (self.score - DEFAULT_NEUTRAL_TRUST) * decay_factor;
            score.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE)
        } else {
            self.score
        }
    }
}

/// Observation value for a successful interaction
const SUCCESS_OBSERVATION: f64 = 1.0;

/// Observation value for a failed interaction
const FAILURE_OBSERVATION: f64 = 0.0;

/// Statistics update type for recording peer interaction outcomes
#[derive(Debug, Clone)]
pub enum NodeStatisticsUpdate {
    /// Peer provided a correct response
    CorrectResponse,
    /// Peer failed to provide a response
    FailedResponse,
}

/// Local trust engine based on direct peer observations.
///
/// Scores are an exponential moving average of success/failure observations
/// that decays toward neutral (0.5) when idle. Bounded by `MIN_TRUST_SCORE`
/// and `MAX_TRUST_SCORE`.
///
/// This is the **sole authority** on peer trust scores in the system.
#[derive(Debug)]
pub struct TrustEngine {
    /// Per-node trust state
    peers: Arc<RwLock<HashMap<PeerId, PeerTrust>>>,
}

impl TrustEngine {
    /// Create a new TrustEngine
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a peer interaction outcome
    pub async fn update_node_stats(&self, node_id: &PeerId, update: NodeStatisticsUpdate) {
        let mut peers = self.peers.write().await;
        let entry = peers.entry(*node_id).or_insert_with(PeerTrust::new);

        let observation = match update {
            NodeStatisticsUpdate::CorrectResponse => SUCCESS_OBSERVATION,
            NodeStatisticsUpdate::FailedResponse => FAILURE_OBSERVATION,
        };

        entry.record(observation);
    }

    /// Get current trust score for a peer (synchronous).
    ///
    /// Applies time decay lazily — no background task needed.
    /// Returns `DEFAULT_NEUTRAL_TRUST` (0.5) for unknown peers.
    pub fn score(&self, node_id: &PeerId) -> f64 {
        if let Ok(peers) = self.peers.try_read() {
            peers
                .get(node_id)
                .map(|p| p.decayed_score())
                .unwrap_or(DEFAULT_NEUTRAL_TRUST)
        } else {
            DEFAULT_NEUTRAL_TRUST
        }
    }

    /// Remove a peer from the trust system entirely
    pub async fn remove_node(&self, node_id: &PeerId) {
        let mut peers = self.peers.write().await;
        peers.remove(node_id);
    }

    /// Simulate time passing for a peer (test only).
    ///
    /// Shifts the peer's `last_updated` timestamp backward by the given duration,
    /// so the next `score()` call applies the corresponding decay.
    #[cfg(test)]
    pub async fn simulate_elapsed(&self, node_id: &PeerId, elapsed: std::time::Duration) {
        let mut peers = self.peers.write().await;
        if let Some(trust) = peers.get_mut(node_id) {
            if let Some(past) = Instant::now().checked_sub(elapsed) {
                trust.last_updated = past;
            }
        }
    }
}

impl Default for TrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unknown_peer_returns_neutral() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_successes_increase_score() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        for _ in 0..50 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }

        let score = engine.score(&peer);
        assert!(
            score > DEFAULT_NEUTRAL_TRUST,
            "Score {score} should be above neutral"
        );
        assert!(score <= MAX_TRUST_SCORE, "Score {score} should be <= max");
    }

    #[tokio::test]
    async fn test_failures_decrease_score() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        for _ in 0..50 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }

        let score = engine.score(&peer);
        assert!(
            score < DEFAULT_NEUTRAL_TRUST,
            "Score {score} should be below neutral"
        );
        assert!(score >= MIN_TRUST_SCORE, "Score {score} should be >= min");
    }

    #[tokio::test]
    async fn test_scores_clamped_to_bounds() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Many successes — should not exceed MAX
        for _ in 0..1000 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        let score = engine.score(&peer);
        assert!(score >= MIN_TRUST_SCORE, "Score {score} below min");
        assert!(score <= MAX_TRUST_SCORE, "Score {score} above max");

        // Many failures — should not go below MIN
        for _ in 0..2000 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }
        let score = engine.score(&peer);
        assert!(score >= MIN_TRUST_SCORE, "Score {score} below min");
        assert!(score <= MAX_TRUST_SCORE, "Score {score} above max");
    }

    #[tokio::test]
    async fn test_remove_node_resets_to_neutral() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        engine
            .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
            .await;
        assert!(engine.score(&peer) < DEFAULT_NEUTRAL_TRUST);

        engine.remove_node(&peer).await;
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_ema_blends_observations() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // First failure moves score below neutral
        engine
            .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
            .await;
        let after_fail = engine.score(&peer);
        assert!(after_fail < DEFAULT_NEUTRAL_TRUST);

        // A success moves it back up (but not all the way to neutral)
        engine
            .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
            .await;
        let after_success = engine.score(&peer);
        assert!(after_success > after_fail, "Success should increase score");
    }

    /// 3 days of idle time from worst score (0.0) should cross the block threshold (0.15)
    #[test]
    fn test_worst_score_unblocks_after_3_days() {
        let three_days_secs: u64 = 3 * 24 * 3600;
        let mut trust = PeerTrust {
            score: MIN_TRUST_SCORE,
            last_updated: Instant::now() - std::time::Duration::from_secs(three_days_secs),
        };

        trust.apply_decay();

        assert!(
            trust.score >= 0.15,
            "After 3 days, score {} should be >= block threshold 0.15",
            trust.score
        );
    }

    /// Just under 3 days should NOT be enough to unblock
    #[test]
    fn test_worst_score_still_blocked_before_3_days() {
        let just_under_3_days: u64 = 3 * 24 * 3600 - 3600; // 3 days minus 1 hour
        let mut trust = PeerTrust {
            score: MIN_TRUST_SCORE,
            last_updated: Instant::now() - std::time::Duration::from_secs(just_under_3_days),
        };

        trust.apply_decay();

        assert!(
            trust.score < 0.15,
            "Before 3 days, score {} should still be < block threshold 0.15",
            trust.score
        );
    }

    #[test]
    fn test_decay_from_high_score_moves_down() {
        let one_week_secs: u64 = 7 * 24 * 3600;
        let mut trust = PeerTrust {
            score: 0.95,
            last_updated: Instant::now() - std::time::Duration::from_secs(one_week_secs),
        };

        trust.apply_decay();

        assert!(trust.score < 0.95, "Score should have decayed from 0.95");
        assert!(
            trust.score > DEFAULT_NEUTRAL_TRUST,
            "Score should still be above neutral after 1 week"
        );
    }

    #[test]
    fn test_decay_from_low_score_moves_up() {
        let one_week_secs: u64 = 7 * 24 * 3600;
        let mut trust = PeerTrust {
            score: 0.1,
            last_updated: Instant::now() - std::time::Duration::from_secs(one_week_secs),
        };

        trust.apply_decay();

        assert!(
            trust.score > 0.1,
            "Low score should decay upward toward neutral"
        );
    }
}
