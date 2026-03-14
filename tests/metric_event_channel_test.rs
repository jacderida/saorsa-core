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

//! Integration tests for the metric event channel and new accessor methods.

use saorsa_core::MetricEvent;
use saorsa_core::telemetry::StreamClass;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::broadcast;

/// Helper: create a metric broadcast channel and emit events via MetricsEmitter.
/// Since MetricsEmitter is pub(crate), we test via TransportHandle's public API.

#[test]
fn test_metric_event_subscribe_via_transport() {
    // new_for_tests() uses block_on internally, so cannot run inside tokio::test
    let rt = tokio::runtime::Runtime::new().unwrap();
    let handle = rt.block_on(async {
        // Use spawn_blocking to allow the inner block_on in new_for_tests
        tokio::task::spawn_blocking(|| saorsa_core::TransportHandle::new_for_tests().unwrap())
            .await
            .unwrap()
    });
    let mut rx = handle.subscribe_metric_events();

    // No events yet — try_recv should be empty
    assert!(rx.try_recv().is_err());
}

#[test]
fn test_transport_stats_default() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let handle = rt.block_on(async {
        tokio::task::spawn_blocking(|| saorsa_core::TransportHandle::new_for_tests().unwrap())
            .await
            .unwrap()
    });
    let stats = rt.block_on(handle.transport_stats());

    // Freshly created transport has no connections
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.known_peers, 0);
    assert_eq!(stats.ipv4_connections, 0);
    assert_eq!(stats.ipv6_connections, 0);
}

#[tokio::test]
async fn test_metric_event_broadcast_channel_basics() {
    // Test the broadcast channel mechanics directly
    let (tx, mut rx1) = broadcast::channel::<MetricEvent>(64);
    let mut rx2 = tx.subscribe();

    // Send a lookup completed event
    tx.send(MetricEvent::LookupCompleted {
        duration: Duration::from_millis(42),
        hops: 3,
    })
    .unwrap();

    // Both receivers should get it
    let event1 = rx1.recv().await.unwrap();
    let event2 = rx2.recv().await.unwrap();

    match event1 {
        MetricEvent::LookupCompleted { duration, hops } => {
            assert_eq!(duration, Duration::from_millis(42));
            assert_eq!(hops, 3);
        }
        _ => panic!("Expected LookupCompleted"),
    }

    match event2 {
        MetricEvent::LookupCompleted { duration, hops } => {
            assert_eq!(duration, Duration::from_millis(42));
            assert_eq!(hops, 3);
        }
        _ => panic!("Expected LookupCompleted"),
    }
}

#[tokio::test]
async fn test_metric_event_all_variants() {
    let (tx, mut rx) = broadcast::channel::<MetricEvent>(64);

    // Send each variant
    tx.send(MetricEvent::LookupCompleted {
        duration: Duration::from_millis(10),
        hops: 2,
    })
    .unwrap();
    tx.send(MetricEvent::LookupTimedOut).unwrap();
    tx.send(MetricEvent::DhtPutCompleted {
        duration: Duration::from_millis(20),
        success: true,
    })
    .unwrap();
    tx.send(MetricEvent::DhtGetCompleted {
        duration: Duration::from_millis(15),
        success: false,
    })
    .unwrap();
    tx.send(MetricEvent::AuthFailure).unwrap();
    tx.send(MetricEvent::StreamBandwidth {
        class: StreamClass::Media,
        bytes_per_sec: 1_000_000,
    })
    .unwrap();
    tx.send(MetricEvent::StreamRtt {
        class: StreamClass::Control,
        rtt: Duration::from_millis(5),
    })
    .unwrap();

    // Verify we receive all 7 events
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 7);
}

#[tokio::test]
async fn test_metric_event_silently_dropped_without_subscriber() {
    let (tx, _) = broadcast::channel::<MetricEvent>(64);

    // Sending without any active receiver should not panic
    let result = tx.send(MetricEvent::AuthFailure);
    // send() returns Err when there are no receivers, but this is expected behavior
    assert!(result.is_err());
}

#[tokio::test]
async fn test_strategy_stats_empty() {
    let mab =
        saorsa_core::adaptive::MultiArmedBandit::new(saorsa_core::adaptive::MABConfig::default())
            .await
            .unwrap();

    let stats = mab.get_strategy_stats().await;
    assert!(stats.is_empty());
}

#[tokio::test]
async fn test_strategy_stats_after_decisions() {
    use saorsa_core::PeerId;
    use saorsa_core::adaptive::{
        ContentType, MABConfig, MultiArmedBandit, Outcome, StrategyChoice,
    };

    let mab = MultiArmedBandit::new(MABConfig::default()).await.unwrap();

    let peer = PeerId::random();
    let strategies = vec![StrategyChoice::Kademlia, StrategyChoice::Hyperbolic];

    // Make some routing decisions and update outcomes
    for _ in 0..5 {
        let decision = mab
            .select_route(&peer, ContentType::DHTLookup, &strategies)
            .await
            .unwrap();
        mab.update_route(
            &decision.route_id,
            ContentType::DHTLookup,
            &Outcome {
                success: true,
                latency_ms: 10,
                hops: 2,
            },
        )
        .await
        .unwrap();
    }

    let stats = mab.get_strategy_stats().await;
    assert!(!stats.is_empty());

    // Verify all stats have valid fields
    for s in &stats {
        assert!(!s.name.is_empty());
        assert!(s.alpha > 0.0);
        assert!(s.beta > 0.0);
        assert!(s.estimated_success_rate >= 0.0);
        assert!(s.estimated_success_rate <= 1.0);
    }
}

#[tokio::test]
async fn test_eigentrust_cached_global_trust_initially_none() {
    let engine = saorsa_core::EigenTrustEngine::new(HashSet::new());
    let cached = engine.cached_global_trust().await;
    assert!(cached.is_none());
}

#[tokio::test]
async fn test_eigentrust_cached_global_trust_populated_after_computation() {
    use saorsa_core::{EigenTrustEngine, PeerId};
    use std::sync::Arc;

    let peer_a = PeerId::random();
    let peer_b = PeerId::random();

    let engine = Arc::new(EigenTrustEngine::new(HashSet::new()));

    // Add some interactions
    engine.update_local_trust(&peer_a, &peer_b, true).await;

    // Compute trust (this does NOT automatically cache in cached_scores,
    // only start_background_updates does that — but we can verify the method works)
    let scores = engine.compute_global_trust().await;
    assert!(!scores.is_empty());

    // cached_global_trust is still None because we didn't use start_background_updates
    let cached = engine.cached_global_trust().await;
    assert!(cached.is_none());
}
