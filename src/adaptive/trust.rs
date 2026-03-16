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
//! `TrustEngine` is the **sole authority** on peer trust scores.
//! Scores are computed as the response rate (successes / total interactions)
//! from direct observations — no transitive trust propagation yet.
//!
//! Future: full EigenTrust with peer-to-peer trust gossip.

use crate::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default trust score for unknown peers (no interactions recorded)
pub const DEFAULT_NEUTRAL_TRUST: f64 = 0.5;

/// Per-node interaction statistics
#[derive(Debug, Clone, Default)]
struct NodeStatistics {
    /// Number of successful responses
    correct_responses: u64,
    /// Number of failed responses
    failed_responses: u64,
}

impl NodeStatistics {
    /// Response rate as a fraction (0.0 to 1.0).
    /// Returns `DEFAULT_NEUTRAL_TRUST` if no interactions have been recorded.
    fn response_rate(&self) -> f64 {
        let total = self.correct_responses + self.failed_responses;
        if total > 0 {
            self.correct_responses as f64 / total as f64
        } else {
            DEFAULT_NEUTRAL_TRUST
        }
    }
}

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
/// Scores are the response rate (successes / total) for each peer.
/// Unknown peers default to `DEFAULT_NEUTRAL_TRUST` (0.5).
///
/// This is the **sole authority** on peer trust scores in the system.
/// Future versions will add EigenTrust power iteration with peer gossip
/// for transitive trust propagation.
#[derive(Debug)]
pub struct TrustEngine {
    /// Per-node interaction statistics
    node_stats: Arc<RwLock<HashMap<PeerId, NodeStatistics>>>,
}

impl TrustEngine {
    /// Create a new TrustEngine
    pub fn new() -> Self {
        Self {
            node_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a peer interaction outcome
    pub async fn update_node_stats(&self, node_id: &PeerId, update: NodeStatisticsUpdate) {
        let mut stats = self.node_stats.write().await;
        let entry = stats.entry(*node_id).or_default();

        match update {
            NodeStatisticsUpdate::CorrectResponse => entry.correct_responses += 1,
            NodeStatisticsUpdate::FailedResponse => entry.failed_responses += 1,
        }
    }

    /// Get current trust score for a peer (synchronous).
    ///
    /// Returns the response rate (successes / total interactions),
    /// or `DEFAULT_NEUTRAL_TRUST` (0.5) for unknown peers.
    pub fn score(&self, node_id: &PeerId) -> f64 {
        if let Ok(stats) = self.node_stats.try_read() {
            stats
                .get(node_id)
                .map(|s| s.response_rate())
                .unwrap_or(DEFAULT_NEUTRAL_TRUST)
        } else {
            DEFAULT_NEUTRAL_TRUST
        }
    }

    /// Remove a peer from the trust system entirely
    pub async fn remove_node(&self, node_id: &PeerId) {
        let mut stats = self.node_stats.write().await;
        stats.remove(node_id);
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

        for _ in 0..10 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }

        assert!((engine.score(&peer) - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_failures_decrease_score() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        for _ in 0..10 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }

        assert!(engine.score(&peer).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_mixed_interactions() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // 7 successes, 3 failures → 70% response rate
        for _ in 0..7 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        for _ in 0..3 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }

        assert!((engine.score(&peer) - 0.7).abs() < f64::EPSILON);
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
    async fn test_scores_bounded() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        for _ in 0..1000 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }

        let score = engine.score(&peer);
        assert!(score >= 0.0);
        assert!(score <= 1.0);
    }
}
