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

//! Unified metrics registry that aggregates Prometheus output from all internal collectors.
//!
//! Collectors that live in publicly exported modules (DHT, telemetry) are held as concrete
//! `Arc<T>` references. Collectors from modules not yet re-exported at the crate root
//! (e.g. persistence) can be registered via the [`PrometheusCollector`] trait, which any
//! type that produces Prometheus text can implement.

use crate::dht::metrics::DhtMetricsAggregator;
use crate::telemetry::TelemetryCollector;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

/// Trait for any component that can export metrics as Prometheus text.
///
/// This allows collectors from modules not directly accessible to the health module
/// (e.g. persistence) to be registered at runtime by downstream crates.
#[async_trait]
pub trait PrometheusCollector: Send + Sync {
    /// Export metrics as Prometheus text format
    async fn export_prometheus(&self) -> String;
}

/// Registry that holds references to all internal metric collectors and produces
/// a combined Prometheus text export.
#[derive(Clone)]
pub struct MetricsRegistry {
    dht_aggregator: Option<Arc<DhtMetricsAggregator>>,
    telemetry: Option<Arc<TelemetryCollector>>,
    additional: Vec<Arc<dyn PrometheusCollector>>,
}

impl MetricsRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            dht_aggregator: None,
            telemetry: None,
            additional: Vec::new(),
        }
    }

    /// Register the DHT metrics aggregator (covers DHT, security, trust, and placement metrics)
    pub fn register_dht(&mut self, agg: Arc<DhtMetricsAggregator>) {
        self.dht_aggregator = Some(agg);
    }

    /// Register the telemetry collector
    pub fn register_telemetry(&mut self, tel: Arc<TelemetryCollector>) {
        self.telemetry = Some(tel);
    }

    /// Register any additional collector that implements [`PrometheusCollector`].
    ///
    /// This is the extension point for collectors from modules not directly accessible
    /// to saorsa-core's health module (e.g. persistence metrics, application-level metrics).
    pub fn register_collector(&mut self, collector: Arc<dyn PrometheusCollector>) {
        self.additional.push(collector);
    }

    /// Export all registered collectors as a single Prometheus text block
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();

        if let Some(ref agg) = self.dht_aggregator {
            match agg.export_prometheus().await {
                Ok(text) => {
                    output.push_str(&text);
                    output.push('\n');
                }
                Err(e) => {
                    warn!("Failed to export DHT prometheus metrics: {}", e);
                }
            }
        }

        if let Some(ref tel) = self.telemetry {
            output.push_str(&tel.export_prometheus().await);
            output.push('\n');
        }

        for collector in &self.additional {
            output.push_str(&collector.export_prometheus().await);
            output.push('\n');
        }

        output
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCollector {
        output: String,
    }

    #[async_trait]
    impl PrometheusCollector for MockCollector {
        async fn export_prometheus(&self) -> String {
            self.output.clone()
        }
    }

    #[tokio::test]
    async fn test_empty_registry_produces_empty_output() {
        let registry = MetricsRegistry::new();
        let output = registry.export_prometheus().await;
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn test_registry_with_telemetry() {
        let mut registry = MetricsRegistry::new();
        let collector = Arc::new(TelemetryCollector::new());

        collector.record_dht_put();
        collector.record_dht_get();

        registry.register_telemetry(collector);
        let output = registry.export_prometheus().await;

        assert!(output.contains("p2p_dht_puts_total 1"));
        assert!(output.contains("p2p_dht_gets_total 1"));
    }

    #[tokio::test]
    async fn test_registry_with_additional_collector() {
        let mut registry = MetricsRegistry::new();

        let mock = Arc::new(MockCollector {
            output: "# HELP mock_metric A mock metric\n# TYPE mock_metric gauge\nmock_metric 42\n"
                .to_string(),
        });

        registry.register_collector(mock);
        let output = registry.export_prometheus().await;

        assert!(output.contains("mock_metric 42"));
    }

    #[tokio::test]
    async fn test_registry_with_dht_aggregator() {
        let mut registry = MetricsRegistry::new();
        let agg = Arc::new(DhtMetricsAggregator::new());

        registry.register_dht(agg);
        let output = registry.export_prometheus().await;

        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
    }

    #[tokio::test]
    async fn test_registry_concatenates_all_sources() {
        let mut registry = MetricsRegistry::new();

        registry.register_dht(Arc::new(DhtMetricsAggregator::new()));
        registry.register_telemetry(Arc::new(TelemetryCollector::new()));
        registry.register_collector(Arc::new(MockCollector {
            output: "# HELP p2p_storage_read_total Total read operations\n# TYPE p2p_storage_read_total counter\np2p_storage_read_total 5\n".to_string(),
        }));

        let output = registry.export_prometheus().await;

        // Should contain metrics from all three sources
        assert!(output.contains("p2p_lookup_latency_p95_ms"));
        assert!(output.contains("p2p_storage_read_total 5"));
    }
}
