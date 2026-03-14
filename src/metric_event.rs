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
}
