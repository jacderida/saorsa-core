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

//! Metric events emitted by saorsa-core's internal systems.
//!
//! These carry raw measurements — aggregation and formatting is the
//! responsibility of the subscriber (typically saorsa-node).
//!
//! Emitted on a dedicated broadcast channel, separate from [`P2PEvent`].
//! High-volume and loss-tolerant: if no subscriber exists, events are
//! silently dropped.

use crate::telemetry::StreamClass;
use std::time::Duration;

/// Classifies the NAT situation for a connection.
///
/// This is a simplified classification for metrics purposes, distinct from
/// [`peer_record::NatType`] which provides detailed NAT type detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionNatType {
    /// Direct connection — no NAT traversal needed
    Direct,
    /// NAT traversal (hole-punch) was performed
    NatTraversal,
    /// Connection was relayed through a third party
    Relay,
    /// NAT situation could not be determined
    Unknown,
}

/// Reason a connection attempt failed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConnectionFailureReason {
    /// Connection attempt timed out
    Timeout,
    /// Connection was refused by the remote peer
    Refused,
    /// NAT traversal (hole-punch) failed
    NatTraversalFailed,
    /// Post-quantum handshake failed
    HandshakeFailed,
    /// Connection was rate-limited
    RateLimited,
    /// Connection was blocked by GeoIP policy
    GeoBlocked,
    /// Other failure reason
    Other(String),
}

/// Metric events emitted by saorsa-core's internal systems.
///
/// These carry raw measurements — aggregation and formatting is the
/// responsibility of the subscriber (typically saorsa-node).
///
/// Emitted on a dedicated broadcast channel, separate from [`P2PEvent`].
/// High-volume and loss-tolerant: if no subscriber exists, events are
/// silently dropped.
#[derive(Debug, Clone)]
pub enum MetricEvent {
    /// A DHT lookup completed successfully
    LookupCompleted {
        /// How long the lookup took
        duration: Duration,
        /// Number of hops to resolve
        hops: u8,
    },

    /// A DHT lookup timed out without a result
    LookupTimedOut,

    /// A DHT PUT operation completed
    DhtPutCompleted {
        /// How long the PUT took
        duration: Duration,
        /// Whether the PUT succeeded
        success: bool,
    },

    /// A DHT GET operation completed
    DhtGetCompleted {
        /// How long the GET took
        duration: Duration,
        /// Whether the GET succeeded
        success: bool,
    },

    /// An authentication or signature verification failure
    AuthFailure,

    /// A stream bandwidth measurement sample
    StreamBandwidth {
        /// The stream class being measured
        class: StreamClass,
        /// Measured bandwidth in bytes per second
        bytes_per_sec: u64,
    },

    /// A stream round-trip-time measurement sample
    StreamRtt {
        /// The stream class being measured
        class: StreamClass,
        /// Measured round-trip time
        rtt: Duration,
    },

    // --- Transport ---
    /// A transport-level connection was established (includes PQ handshake).
    ConnectionEstablished {
        /// Time taken to establish the connection
        duration: Duration,
        /// NAT classification for this connection
        nat_type: ConnectionNatType,
    },

    /// A transport-level connection attempt failed.
    ConnectionFailed {
        /// Why the connection failed
        reason: ConnectionFailureReason,
    },

    /// The post-quantum handshake (ML-DSA identity exchange) completed.
    HandshakeCompleted {
        /// Time taken for the handshake
        duration: Duration,
    },

    // --- Replication ---
    /// Replication repair cycle triggered after node departure.
    ReplicationStarted {
        /// Number of keys requiring repair
        keys_to_repair: u64,
    },

    /// Replication repair cycle completed.
    ReplicationCompleted {
        /// Total time for the repair cycle
        duration: Duration,
        /// Number of keys successfully repaired
        keys_repaired: u64,
        /// Total bytes transferred during repair
        bytes_transferred: u64,
    },

    /// A grace period expired without the node returning.
    GracePeriodExpired {
        /// Number of keys affected by this node's departure
        keys_affected: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_transport_variants_clone_and_debug() {
        let events: Vec<MetricEvent> = vec![
            MetricEvent::ConnectionEstablished {
                duration: Duration::from_millis(42),
                nat_type: ConnectionNatType::Direct,
            },
            MetricEvent::ConnectionFailed {
                reason: ConnectionFailureReason::Timeout,
            },
            MetricEvent::ConnectionFailed {
                reason: ConnectionFailureReason::Other("test".into()),
            },
            MetricEvent::HandshakeCompleted {
                duration: Duration::from_millis(10),
            },
            MetricEvent::ReplicationStarted { keys_to_repair: 5 },
            MetricEvent::ReplicationCompleted {
                duration: Duration::from_secs(3),
                keys_repaired: 4,
                bytes_transferred: 1024,
            },
            MetricEvent::GracePeriodExpired { keys_affected: 10 },
        ];

        for event in &events {
            let cloned = event.clone();
            let debug_str = format!("{:?}", cloned);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn connection_nat_type_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ConnectionNatType::Direct);
        set.insert(ConnectionNatType::NatTraversal);
        set.insert(ConnectionNatType::Relay);
        set.insert(ConnectionNatType::Unknown);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn connection_failure_reason_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ConnectionFailureReason::Timeout);
        set.insert(ConnectionFailureReason::Refused);
        set.insert(ConnectionFailureReason::NatTraversalFailed);
        set.insert(ConnectionFailureReason::HandshakeFailed);
        set.insert(ConnectionFailureReason::RateLimited);
        set.insert(ConnectionFailureReason::GeoBlocked);
        set.insert(ConnectionFailureReason::Other("a".into()));
        set.insert(ConnectionFailureReason::Other("b".into()));
        assert_eq!(set.len(), 8);
    }

    #[test]
    fn transport_events_via_broadcast_channel() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<MetricEvent>(16);

        let _ = tx.send(MetricEvent::ConnectionEstablished {
            duration: Duration::from_millis(100),
            nat_type: ConnectionNatType::NatTraversal,
        });
        let _ = tx.send(MetricEvent::ConnectionFailed {
            reason: ConnectionFailureReason::GeoBlocked,
        });
        let _ = tx.send(MetricEvent::HandshakeCompleted {
            duration: Duration::from_millis(50),
        });
        let _ = tx.send(MetricEvent::ReplicationStarted { keys_to_repair: 3 });
        let _ = tx.send(MetricEvent::ReplicationCompleted {
            duration: Duration::from_secs(1),
            keys_repaired: 2,
            bytes_transferred: 512,
        });
        let _ = tx.send(MetricEvent::GracePeriodExpired { keys_affected: 7 });

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 6);
    }
}
