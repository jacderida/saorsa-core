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

//! Bridges internal telemetry recording with the metric event channel.
//!
//! Each method records to [`TelemetryCollector`] (internal health checks) AND
//! broadcasts a [`MetricEvent`]. If no subscriber is listening, the broadcast
//! is silently dropped (zero overhead).

use crate::metric_event::MetricEvent;
use crate::telemetry::{StreamClass, TelemetryCollector};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

/// Bridges internal telemetry recording with the metric event channel.
///
/// Each method records to [`TelemetryCollector`] (for internal health checks)
/// AND broadcasts a [`MetricEvent`] (for external monitoring). If no subscriber
/// is listening, the broadcast is silently dropped.
#[allow(dead_code)]
pub(crate) struct MetricsEmitter {
    telemetry: Arc<TelemetryCollector>,
    metric_tx: broadcast::Sender<MetricEvent>,
}

#[allow(dead_code)]
impl MetricsEmitter {
    /// Create a new metrics emitter.
    pub fn new(
        telemetry: Arc<TelemetryCollector>,
        metric_tx: broadcast::Sender<MetricEvent>,
    ) -> Self {
        Self {
            telemetry,
            metric_tx,
        }
    }

    /// Record a completed DHT lookup.
    pub async fn record_lookup(&self, duration: Duration, hops: u8) {
        self.telemetry.record_lookup(duration, hops).await;
        // Silently drop if no subscribers
        let _ = self
            .metric_tx
            .send(MetricEvent::LookupCompleted { duration, hops });
    }

    /// Record a lookup timeout.
    pub fn record_timeout(&self) {
        self.telemetry.record_timeout();
        let _ = self.metric_tx.send(MetricEvent::LookupTimedOut);
    }

    /// Record a DHT PUT operation.
    pub fn record_dht_put(&self, duration: Duration, success: bool) {
        self.telemetry.record_dht_put();
        let _ = self
            .metric_tx
            .send(MetricEvent::DhtPutCompleted { duration, success });
    }

    /// Record a DHT GET operation.
    pub fn record_dht_get(&self, duration: Duration, success: bool) {
        self.telemetry.record_dht_get();
        let _ = self
            .metric_tx
            .send(MetricEvent::DhtGetCompleted { duration, success });
    }

    /// Record an authentication failure.
    pub fn record_auth_failure(&self) {
        self.telemetry.record_auth_failure();
        let _ = self.metric_tx.send(MetricEvent::AuthFailure);
    }

    /// Record a stream bandwidth measurement.
    pub async fn record_stream_bandwidth(&self, class: StreamClass, bytes_per_sec: u64) {
        self.telemetry
            .record_stream_bandwidth(class, bytes_per_sec)
            .await;
        let _ = self.metric_tx.send(MetricEvent::StreamBandwidth {
            class,
            bytes_per_sec,
        });
    }

    /// Record a stream round-trip-time measurement.
    pub async fn record_stream_rtt(&self, class: StreamClass, rtt: Duration) {
        self.telemetry.record_stream_rtt(class, rtt).await;
        let _ = self.metric_tx.send(MetricEvent::StreamRtt { class, rtt });
    }
}
