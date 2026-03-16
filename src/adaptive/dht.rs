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

//! AdaptiveDHT — the trust boundary for all DHT operations.
//!
//! `AdaptiveDHT` is the **sole component** that creates and owns the [`TrustEngine`].
//! All DHT operations flow through it, and all trust signals originate from it.
//!
//! Internal DHT operations (iterative lookups) record trust via the `TrustEngine`
//! reference passed to `DhtNetworkManager`. Application-level trust signals
//! (data verification outcomes) are reported through [`AdaptiveDHT::report_app_event`].

use crate::PeerId;
use crate::adaptive::trust::{NodeStatisticsUpdate, TrustEngine};
use crate::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};

use crate::error::P2pResult as Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Default trust score threshold below which a peer is evicted and blocked
const DEFAULT_BLOCK_THRESHOLD: f64 = 0.15;

/// Configuration for the AdaptiveDHT layer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdaptiveDhtConfig {
    /// Trust score below which a peer is evicted from the routing table
    /// and blocked from sending DHT messages or being re-added to the RT.
    /// Eviction is immediate when a peer's score crosses this threshold.
    /// Default: 0.15
    pub block_threshold: f64,
}

impl Default for AdaptiveDhtConfig {
    fn default() -> Self {
        Self {
            block_threshold: DEFAULT_BLOCK_THRESHOLD,
        }
    }
}

/// Trust-relevant events observable by the saorsa-core network layer.
///
/// Each variant maps to an internal [`NodeStatisticsUpdate`] with appropriate severity.
/// Only events that saorsa-core can directly observe are included here.
/// Application-level events (data verification, storage checks) belong in
/// the consuming application and should be added when that layer exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustEvent {
    // === Positive signals ===
    /// Peer provided a correct response to a request
    SuccessfulResponse,
    /// Peer connection was established and authenticated
    SuccessfulConnection,

    // === Negative signals ===
    /// Could not establish a connection to the peer
    ConnectionFailed,
    /// Connection attempt timed out
    ConnectionTimeout,
}

impl TrustEvent {
    /// Convert a TrustEvent to the internal NodeStatisticsUpdate
    fn to_stats_update(self) -> NodeStatisticsUpdate {
        match self {
            TrustEvent::SuccessfulResponse | TrustEvent::SuccessfulConnection => {
                NodeStatisticsUpdate::CorrectResponse
            }
            TrustEvent::ConnectionFailed | TrustEvent::ConnectionTimeout => {
                NodeStatisticsUpdate::FailedResponse
            }
        }
    }
}

/// AdaptiveDHT — the trust boundary for all DHT operations.
///
/// Owns the `TrustEngine` and `DhtNetworkManager`. All DHT operations
/// should go through this component. Application-level trust signals
/// are reported via [`report_app_event`](Self::report_app_event).
pub struct AdaptiveDHT {
    /// The underlying DHT network manager (handles raw DHT operations)
    dht_manager: Arc<DhtNetworkManager>,

    /// The trust engine — sole authority on peer trust scores
    trust_engine: Arc<TrustEngine>,

    /// Configuration for trust-weighted behavior
    config: AdaptiveDhtConfig,
}

impl AdaptiveDHT {
    /// Create a new AdaptiveDHT instance.
    ///
    /// This creates the `TrustEngine` and the `DhtNetworkManager` with the
    /// trust engine injected. Call [`start`](Self::start) to begin DHT
    /// operations and the periodic blocked-peer sweep.
    pub async fn new(
        transport: Arc<crate::transport_handle::TransportHandle>,
        mut dht_config: DhtNetworkConfig,
        adaptive_config: AdaptiveDhtConfig,
    ) -> Result<Self> {
        dht_config.block_threshold = adaptive_config.block_threshold;

        let trust_engine = Arc::new(TrustEngine::new());

        let dht_manager = Arc::new(
            DhtNetworkManager::new(transport, Some(trust_engine.clone()), dht_config).await?,
        );

        Ok(Self {
            dht_manager,
            trust_engine,
            config: adaptive_config,
        })
    }

    // =========================================================================
    // Trust API — the only place where external callers record trust events
    // =========================================================================

    /// Report an application-level trust event for a peer.
    ///
    /// Use this for outcomes that the DHT layer cannot observe directly,
    /// such as data verification results from saorsa-node.
    pub async fn report_app_event(&self, peer_id: &PeerId, event: TrustEvent) {
        self.trust_engine
            .update_node_stats(peer_id, event.to_stats_update())
            .await;
    }

    /// Get the current trust score for a peer (synchronous).
    ///
    /// Returns `DEFAULT_NEUTRAL_TRUST` (0.5) for unknown peers.
    pub fn peer_trust(&self, peer_id: &PeerId) -> f64 {
        self.trust_engine.score(peer_id)
    }

    /// Get a reference to the underlying trust engine for advanced use cases.
    pub fn trust_engine(&self) -> &Arc<TrustEngine> {
        &self.trust_engine
    }

    /// Get the adaptive DHT configuration.
    pub fn config(&self) -> &AdaptiveDhtConfig {
        &self.config
    }

    // =========================================================================
    // DHT operations — delegates to DhtNetworkManager
    // =========================================================================

    /// Get the underlying DHT network manager.
    ///
    /// All DHT operations are accessible through this reference.
    /// The DHT manager records trust internally for per-peer outcomes
    /// during iterative lookups.
    pub fn dht_manager(&self) -> &Arc<DhtNetworkManager> {
        &self.dht_manager
    }

    /// Start the DHT manager.
    ///
    /// Trust scores are computed live — no background tasks needed.
    /// Peers are evicted from the routing table immediately when their
    /// trust drops below the block threshold.
    pub async fn start(&self) -> Result<()> {
        Arc::clone(&self.dht_manager).start().await
    }

    /// Stop the DHT manager gracefully.
    pub async fn stop(&self) -> Result<()> {
        self.dht_manager.stop().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::trust::DEFAULT_NEUTRAL_TRUST;

    #[test]
    fn test_trust_event_mapping() {
        // Positive events map to CorrectResponse
        assert!(matches!(
            TrustEvent::SuccessfulResponse.to_stats_update(),
            NodeStatisticsUpdate::CorrectResponse
        ));
        assert!(matches!(
            TrustEvent::SuccessfulConnection.to_stats_update(),
            NodeStatisticsUpdate::CorrectResponse
        ));

        // Failure events map to FailedResponse
        assert!(matches!(
            TrustEvent::ConnectionFailed.to_stats_update(),
            NodeStatisticsUpdate::FailedResponse
        ));
        assert!(matches!(
            TrustEvent::ConnectionTimeout.to_stats_update(),
            NodeStatisticsUpdate::FailedResponse
        ));
    }

    #[test]
    fn test_adaptive_dht_config_defaults() {
        let config = AdaptiveDhtConfig::default();
        assert!((config.block_threshold - DEFAULT_BLOCK_THRESHOLD).abs() < f64::EPSILON);
    }

    // =========================================================================
    // Integration tests: full trust signal flow
    // =========================================================================

    /// Test: trust events flow through to TrustEngine and change scores immediately
    #[tokio::test]
    async fn test_trust_events_affect_scores() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        // Unknown peer starts at neutral trust
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);

        // Record 10 successes — score should be 1.0 immediately (no recompute needed)
        for _ in 0..10 {
            engine
                .update_node_stats(&peer, TrustEvent::SuccessfulResponse.to_stats_update())
                .await;
        }

        assert!((engine.score(&peer) - 1.0).abs() < f64::EPSILON);
    }

    /// Test: failures reduce trust below block threshold
    #[tokio::test]
    async fn test_failures_reduce_trust_below_block_threshold() {
        let engine = Arc::new(TrustEngine::new());
        let bad_peer = PeerId::random();

        // Record only failures — score should be 0.0 immediately
        for _ in 0..20 {
            engine
                .update_node_stats(&bad_peer, TrustEvent::ConnectionFailed.to_stats_update())
                .await;
        }

        let trust = engine.score(&bad_peer);
        assert!(
            trust < DEFAULT_BLOCK_THRESHOLD,
            "Bad peer trust {trust} should be below block threshold {DEFAULT_BLOCK_THRESHOLD}"
        );
    }

    /// Test: TrustEngine scores are bounded 0.0-1.0
    #[tokio::test]
    async fn test_trust_scores_bounded() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        for _ in 0..100 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }

        let score = engine.score(&peer);
        assert!(score >= 0.0, "Score must be >= 0.0, got {score}");
        assert!(score <= 1.0, "Score must be <= 1.0, got {score}");
    }

    /// Test: all TrustEvent variants produce valid stats updates
    #[test]
    fn test_all_trust_events_produce_valid_updates() {
        let events = [
            TrustEvent::SuccessfulResponse,
            TrustEvent::SuccessfulConnection,
            TrustEvent::ConnectionFailed,
            TrustEvent::ConnectionTimeout,
        ];

        for event in events {
            // Should not panic
            let _update = event.to_stats_update();
        }
    }
}
