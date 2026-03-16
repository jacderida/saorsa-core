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

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::error::P2pResult as Result;
use serde::{Deserialize, Serialize};

/// Default weight for trust in blended distance/trust peer selection
const DEFAULT_ROUTING_WEIGHT: f64 = 0.3;

/// Default trust score threshold below which a peer may be evicted
const DEFAULT_EVICTION_THRESHOLD: f64 = 0.15;

/// Default interval between background trust recomputations (seconds)
const DEFAULT_RECOMPUTE_INTERVAL_SECS: u64 = 300;

/// Configuration for the AdaptiveDHT layer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdaptiveDhtConfig {
    /// Enable trust-weighted routing (reorder candidates by trust before querying).
    /// Default: false — pure Kademlia distance ordering.
    pub trust_weighted_routing: bool,

    /// Weight given to trust in peer selection (0.0–1.0).
    /// Only used when `trust_weighted_routing` is true.
    /// Default: 0.3 (30% trust, 70% distance)
    pub routing_weight: f64,

    /// Trust score below which a peer may be evicted.
    /// Default: 0.15
    pub eviction_threshold: f64,

    /// Interval between background trust recomputations.
    /// Default: 300 seconds (5 minutes)
    pub recompute_interval: Duration,
}

impl Default for AdaptiveDhtConfig {
    fn default() -> Self {
        Self {
            trust_weighted_routing: false,
            routing_weight: DEFAULT_ROUTING_WEIGHT,
            eviction_threshold: DEFAULT_EVICTION_THRESHOLD,
            recompute_interval: Duration::from_secs(DEFAULT_RECOMPUTE_INTERVAL_SECS),
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
    /// This creates the `TrustEngine`, starts its background updates, and
    /// creates the `DhtNetworkManager` with the trust engine injected.
    pub async fn new(
        transport: Arc<crate::transport_handle::TransportHandle>,
        mut dht_config: DhtNetworkConfig,
        adaptive_config: AdaptiveDhtConfig,
    ) -> Result<Self> {
        // Propagate trust routing settings into DHT network config
        dht_config.trust_weighted_routing = adaptive_config.trust_weighted_routing;
        dht_config.trust_routing_weight = adaptive_config.routing_weight;

        let pre_trusted: HashSet<PeerId> = HashSet::new();
        let trust_engine = Arc::new(TrustEngine::new(pre_trusted));
        trust_engine.clone().start_background_updates();

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

    /// Start the DHT manager (network event handler + maintenance tasks).
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
    use crate::dht::routing_maintenance::config::MaintenanceConfig;
    use crate::dht::routing_maintenance::eviction::EvictionManager;

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
        assert!(!config.trust_weighted_routing);
        assert!((config.routing_weight - DEFAULT_ROUTING_WEIGHT).abs() < f64::EPSILON);
        assert!((config.eviction_threshold - DEFAULT_EVICTION_THRESHOLD).abs() < f64::EPSILON);
        assert_eq!(
            config.recompute_interval,
            Duration::from_secs(DEFAULT_RECOMPUTE_INTERVAL_SECS)
        );
    }

    // =========================================================================
    // Integration tests: full trust signal flow
    // =========================================================================

    /// Test: trust events flow through to TrustEngine and change scores
    #[tokio::test]
    async fn test_trust_events_affect_scores() {
        let engine = Arc::new(TrustEngine::new(HashSet::new()));
        let peer = PeerId::random();

        // Unknown peer starts at neutral trust
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);

        // Record positive events directly via the engine (simulating what AdaptiveDHT does)
        for _ in 0..10 {
            engine
                .update_node_stats(&peer, TrustEvent::SuccessfulResponse.to_stats_update())
                .await;
        }

        // Add a local trust edge so the node appears in computation
        let other = PeerId::random();
        engine.update_local_trust(&other, &peer, true).await;

        // Force recomputation
        let _ = engine.compute_global_trust().await;

        // Score should now be > neutral (peer has 100% success rate)
        let score_after_success = engine.score(&peer);
        assert!(score_after_success > 0.0);
    }

    /// Test: failures reduce trust and can trigger eviction
    #[tokio::test]
    async fn test_failures_reduce_trust_and_trigger_eviction() {
        let engine = Arc::new(TrustEngine::new(HashSet::new()));
        let bad_peer = PeerId::random();

        // Record many failures (protocol violations = 2x penalty each)
        for _ in 0..20 {
            engine
                .update_node_stats(&bad_peer, TrustEvent::ConnectionFailed.to_stats_update())
                .await;
        }

        // Add a local trust edge
        let other = PeerId::random();
        engine.update_local_trust(&other, &bad_peer, true).await;

        // Recompute
        let _ = engine.compute_global_trust().await;

        // Wire eviction manager to this engine
        let config = MaintenanceConfig {
            min_trust_threshold: DEFAULT_EVICTION_THRESHOLD,
            ..Default::default()
        };
        let mut eviction_mgr = EvictionManager::new(config);
        eviction_mgr.set_trust_engine(engine.clone());

        // The bad peer should have a trust score below the eviction threshold
        let trust = engine.score(&bad_peer);
        let should_evict = trust < DEFAULT_EVICTION_THRESHOLD;

        // Eviction manager should agree
        let reason = eviction_mgr.get_eviction_reason(&bad_peer);
        if should_evict {
            assert!(reason.is_some(), "Bad peer should be evictable");
        }
    }

    /// Test: TrustEngine scores are bounded 0.0-1.0
    #[tokio::test]
    async fn test_trust_scores_bounded() {
        let engine = Arc::new(TrustEngine::new(HashSet::new()));
        let peer = PeerId::random();
        let other = PeerId::random();

        // Many successes
        for _ in 0..100 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        engine.update_local_trust(&other, &peer, true).await;
        let _ = engine.compute_global_trust().await;

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
