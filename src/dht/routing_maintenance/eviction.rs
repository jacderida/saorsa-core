//! Reputation-based node eviction
//!
//! Manages eviction decisions based on:
//! - Consecutive communication failures
//! - Low trust scores (queried live from TrustEngine)
//! - Failed validation checks
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashMap;
use std::sync::Arc;

use crate::PeerId;
use crate::adaptive::trust::TrustEngine;

use super::config::MaintenanceConfig;
use super::liveness::NodeLivenessState;

/// Reasons why a node might be evicted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionReason {
    /// Too many consecutive communication failures
    ConsecutiveFailures(u32),
    /// Trust score fell below minimum threshold
    LowTrust(String), // String representation of f64 for Eq
    /// Close group consensus: node is no longer valid
    CloseGroupRejection,
}

/// Manages eviction decisions for nodes.
///
/// Queries [`TrustEngine`] live for trust scores — never caches them locally.
pub struct EvictionManager {
    /// Configuration for eviction thresholds
    config: MaintenanceConfig,
    /// Liveness state for each tracked node
    liveness_states: HashMap<PeerId, NodeLivenessState>,
    /// Trust engine for live trust score queries
    trust_engine: Option<Arc<TrustEngine>>,
    /// Nodes explicitly marked for eviction with reason
    marked_for_eviction: HashMap<PeerId, EvictionReason>,
}

impl EvictionManager {
    /// Create a new eviction manager without a trust engine
    #[must_use]
    pub fn new(config: MaintenanceConfig) -> Self {
        Self {
            config,
            liveness_states: HashMap::new(),
            trust_engine: None,
            marked_for_eviction: HashMap::new(),
        }
    }

    /// Set the trust engine for live score queries.
    ///
    /// Called after construction when the trust engine becomes available.
    pub fn set_trust_engine(&mut self, trust_engine: Arc<TrustEngine>) {
        self.trust_engine = Some(trust_engine);
    }

    /// Mark a node for eviction with a specific reason
    pub fn record_eviction(&mut self, node_id: &PeerId, reason: EvictionReason) {
        self.marked_for_eviction.insert(*node_id, reason);
    }

    /// Get trust score for a node (live query from TrustEngine)
    #[must_use]
    pub fn get_trust_score(&self, node_id: &PeerId) -> Option<f64> {
        self.trust_engine
            .as_ref()
            .map(|engine| engine.score(node_id))
    }

    /// Get the eviction reason if any
    #[must_use]
    pub fn get_eviction_reason(&self, node_id: &PeerId) -> Option<EvictionReason> {
        // Check explicitly marked nodes first (highest priority)
        if let Some(reason) = self.marked_for_eviction.get(node_id) {
            return Some(reason.clone());
        }

        // Check consecutive failures (most common)
        if let Some(state) = self
            .liveness_states
            .get(node_id)
            .filter(|s| s.should_evict(&self.config))
        {
            return Some(EvictionReason::ConsecutiveFailures(
                state.consecutive_failures,
            ));
        }

        // Check trust score from live engine query
        if let Some(engine) = &self.trust_engine {
            let score = engine.score(node_id);
            if score < self.config.min_trust_threshold {
                return Some(EvictionReason::LowTrust(format!("{score:.4}")));
            }
        }

        None
    }

    /// Get list of all nodes that should be evicted
    #[must_use]
    pub fn get_eviction_candidates(&self) -> Vec<(PeerId, EvictionReason)> {
        let mut candidates = Vec::new();

        // Check explicitly marked nodes first (highest priority)
        for (node_id, reason) in &self.marked_for_eviction {
            candidates.push((*node_id, reason.clone()));
        }

        // Check all nodes in liveness states
        for node_id in self.liveness_states.keys() {
            if self.marked_for_eviction.contains_key(node_id) {
                continue;
            }
            if let Some(reason) = self.get_eviction_reason(node_id) {
                candidates.push((*node_id, reason));
            }
        }

        candidates
    }

    /// Remove a node from tracking (after eviction)
    pub fn remove_node(&mut self, node_id: &PeerId) {
        self.liveness_states.remove(node_id);
        self.marked_for_eviction.remove(node_id);
    }
}

/// Test-only methods
#[cfg(test)]
impl EvictionManager {
    pub fn record_failure(&mut self, node_id: &PeerId) {
        let state = self.liveness_states.entry(*node_id).or_default();
        state.record_failure();
    }

    pub fn record_success(&mut self, node_id: &PeerId) {
        let state = self.liveness_states.entry(*node_id).or_default();
        state.record_success();
    }

    pub fn get_consecutive_failures(&self, node_id: &PeerId) -> u32 {
        self.liveness_states
            .get(node_id)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0)
    }

    pub fn should_evict(&self, node_id: &PeerId) -> bool {
        self.liveness_states
            .get(node_id)
            .map(|s| s.should_evict(&self.config))
            .unwrap_or(false)
    }

    pub fn should_evict_for_trust(&self, node_id: &PeerId) -> bool {
        self.trust_engine
            .as_ref()
            .map(|engine| engine.score(node_id) < self.config.min_trust_threshold)
            .unwrap_or(false)
    }

    pub fn get_liveness_state(&self, node_id: &PeerId) -> Option<&NodeLivenessState> {
        self.liveness_states.get(node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::trust::NodeStatisticsUpdate;
    use std::collections::HashSet;

    fn make_node_id() -> PeerId {
        PeerId::random()
    }

    /// Create a TrustEngine and set a specific node's trust score by recording events
    fn engine_with_score(node_id: &PeerId, successes: u64, failures: u64) -> Arc<TrustEngine> {
        let engine = Arc::new(TrustEngine::new(HashSet::new()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            for _ in 0..successes {
                engine
                    .update_node_stats(node_id, NodeStatisticsUpdate::CorrectResponse)
                    .await;
            }
            for _ in 0..failures {
                engine
                    .update_node_stats(node_id, NodeStatisticsUpdate::FailedResponse)
                    .await;
            }
            // Force a recomputation so scores are populated
            // For unit tests, we also need a local trust edge for the node to appear
            let other = PeerId::random();
            engine.update_local_trust(&other, node_id, true).await;
            let _ = engine.compute_global_trust().await;
        });

        engine
    }

    #[test]
    fn test_evict_after_consecutive_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.record_failure(&node_id);
        assert!(!manager.should_evict(&node_id));

        manager.record_failure(&node_id);
        assert!(manager.should_evict(&node_id));
    }

    #[test]
    fn test_evict_for_low_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let node_id = make_node_id();
        // 0 successes, 10 failures → very low response rate
        let engine = engine_with_score(&node_id, 0, 10);

        let manager = {
            let mut m = EvictionManager::new(config);
            m.set_trust_engine(engine);
            m
        };
        assert!(manager.should_evict_for_trust(&node_id));
    }

    #[test]
    fn test_no_evict_for_good_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let node_id = make_node_id();
        // 10 successes, 0 failures → high response rate
        let engine = engine_with_score(&node_id, 10, 0);

        let manager = {
            let mut m = EvictionManager::new(config);
            m.set_trust_engine(engine);
            m
        };
        assert!(!manager.should_evict_for_trust(&node_id));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.record_failure(&node_id);
        manager.record_success(&node_id);

        assert_eq!(manager.get_consecutive_failures(&node_id), 0);
    }

    #[test]
    fn test_eviction_reason_consecutive_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        for _ in 0..3 {
            manager.record_failure(&node_id);
        }

        let reason = manager.get_eviction_reason(&node_id);
        assert!(matches!(
            reason,
            Some(EvictionReason::ConsecutiveFailures(3))
        ));
    }

    #[test]
    fn test_eviction_reason_low_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            max_consecutive_failures: 10,
            ..Default::default()
        };
        let node_id = make_node_id();
        let engine = engine_with_score(&node_id, 0, 10);

        let manager = {
            let mut m = EvictionManager::new(config);
            m.set_trust_engine(engine);
            m
        };
        let reason = manager.get_eviction_reason(&node_id);
        assert!(matches!(reason, Some(EvictionReason::LowTrust(_))));
    }

    #[test]
    fn test_get_eviction_candidates() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let failing_node = make_node_id();
        for _ in 0..3 {
            manager.record_failure(&failing_node);
        }

        let good_node = make_node_id();
        manager.record_success(&good_node);

        let candidates = manager.get_eviction_candidates();
        assert_eq!(candidates.len(), 1); // Only the failing node
    }

    #[test]
    fn test_remove_node() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);

        manager.remove_node(&node_id);

        assert_eq!(manager.get_consecutive_failures(&node_id), 0);
        assert!(manager.get_liveness_state(&node_id).is_none());
    }

    #[test]
    fn test_no_trust_engine_means_no_trust_eviction() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let manager = EvictionManager::new(config);

        let node_id = make_node_id();
        // Without a trust engine, trust-based eviction should never trigger
        assert!(!manager.should_evict_for_trust(&node_id));
        assert!(manager.get_trust_score(&node_id).is_none());
    }
}
