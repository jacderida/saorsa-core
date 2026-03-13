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

//! Storage metrics collection and reporting

use std::fmt::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Metrics collector for storage operations
pub struct MetricsCollector {
    /// Read operation metrics
    read_metrics: Arc<RwLock<OperationMetrics>>,

    /// Write operation metrics
    write_metrics: Arc<RwLock<OperationMetrics>>,

    /// Delete operation metrics
    delete_metrics: Arc<RwLock<OperationMetrics>>,
}

#[derive(Debug, Default)]
struct OperationMetrics {
    count: u64,
    total_duration: Duration,
    min_duration: Option<Duration>,
    max_duration: Option<Duration>,
    errors: u64,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            read_metrics: Arc::new(RwLock::new(OperationMetrics::default())),
            write_metrics: Arc::new(RwLock::new(OperationMetrics::default())),
            delete_metrics: Arc::new(RwLock::new(OperationMetrics::default())),
        }
    }

    /// Record a read operation
    pub async fn record_read(&self, duration: Duration, success: bool) {
        let mut metrics = self.read_metrics.write().await;
        Self::record_operation(&mut metrics, duration, success);
    }

    /// Record a write operation
    pub async fn record_write(&self, duration: Duration, success: bool) {
        let mut metrics = self.write_metrics.write().await;
        Self::record_operation(&mut metrics, duration, success);
    }

    /// Record a delete operation
    pub async fn record_delete(&self, duration: Duration, success: bool) {
        let mut metrics = self.delete_metrics.write().await;
        Self::record_operation(&mut metrics, duration, success);
    }

    /// Record an operation in metrics
    fn record_operation(metrics: &mut OperationMetrics, duration: Duration, success: bool) {
        metrics.count += 1;
        metrics.total_duration += duration;

        if success {
            // Update min/max
            if let Some(min) = metrics.min_duration {
                if duration < min {
                    metrics.min_duration = Some(duration);
                }
            } else {
                metrics.min_duration = Some(duration);
            }

            if let Some(max) = metrics.max_duration {
                if duration > max {
                    metrics.max_duration = Some(duration);
                }
            } else {
                metrics.max_duration = Some(duration);
            }
        } else {
            metrics.errors += 1;
        }
    }

    /// Get average read latency
    pub async fn avg_read_latency(&self) -> Duration {
        let metrics = self.read_metrics.read().await;
        if metrics.count > 0 {
            metrics.total_duration / metrics.count as u32
        } else {
            Duration::ZERO
        }
    }

    /// Get average write latency
    pub async fn avg_write_latency(&self) -> Duration {
        let metrics = self.write_metrics.read().await;
        if metrics.count > 0 {
            metrics.total_duration / metrics.count as u32
        } else {
            Duration::ZERO
        }
    }

    /// Export metrics in Prometheus text format
    pub async fn export_prometheus(&self) -> String {
        let mut out = String::with_capacity(1024);

        for (op_name, metrics_lock) in [
            ("read", &self.read_metrics),
            ("write", &self.write_metrics),
            ("delete", &self.delete_metrics),
        ] {
            let metrics = metrics_lock.read().await;
            let prefix = format!("p2p_storage_{}", op_name);

            let _ = writeln!(out, "# HELP {prefix}_total Total {op_name} operations");
            let _ = writeln!(out, "# TYPE {prefix}_total counter");
            let _ = writeln!(out, "{prefix}_total {}", metrics.count);

            let _ = writeln!(out, "# HELP {prefix}_errors_total Total {op_name} errors");
            let _ = writeln!(out, "# TYPE {prefix}_errors_total counter");
            let _ = writeln!(out, "{prefix}_errors_total {}", metrics.errors);

            let avg = if metrics.count > 0 {
                metrics.total_duration.as_millis() as f64 / metrics.count as f64
            } else {
                0.0
            };
            let _ = writeln!(out, "# HELP {prefix}_avg_duration_ms Average {op_name} duration in ms");
            let _ = writeln!(out, "# TYPE {prefix}_avg_duration_ms gauge");
            let _ = writeln!(out, "{prefix}_avg_duration_ms {avg:.2}");

            if let Some(min) = metrics.min_duration {
                let _ = writeln!(out, "# HELP {prefix}_min_duration_ms Minimum {op_name} duration in ms");
                let _ = writeln!(out, "# TYPE {prefix}_min_duration_ms gauge");
                let _ = writeln!(out, "{prefix}_min_duration_ms {:.2}", min.as_secs_f64() * 1000.0);
            }

            if let Some(max) = metrics.max_duration {
                let _ = writeln!(out, "# HELP {prefix}_max_duration_ms Maximum {op_name} duration in ms");
                let _ = writeln!(out, "# TYPE {prefix}_max_duration_ms gauge");
                let _ = writeln!(out, "{prefix}_max_duration_ms {:.2}", max.as_secs_f64() * 1000.0);
            }
        }

        out
    }

    /// Reset all metrics
    pub async fn reset(&self) {
        *self.read_metrics.write().await = OperationMetrics::default();
        *self.write_metrics.write().await = OperationMetrics::default();
        *self.delete_metrics.write().await = OperationMetrics::default();
    }
}

/// Timer for measuring operation duration
pub struct Timer {
    start: Instant,
}

impl Timer {
    /// Start a new timer
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_export_prometheus_with_operations() {
        let collector = MetricsCollector::new();

        collector.record_read(Duration::from_millis(10), true).await;
        collector.record_read(Duration::from_millis(20), true).await;
        collector
            .record_write(Duration::from_millis(30), true)
            .await;
        collector
            .record_delete(Duration::from_millis(5), false)
            .await;

        let output = collector.export_prometheus().await;

        assert!(output.contains("p2p_storage_read_total 2"));
        assert!(output.contains("p2p_storage_read_errors_total 0"));
        assert!(output.contains("p2p_storage_read_avg_duration_ms 15.00"));
        assert!(output.contains("p2p_storage_read_min_duration_ms 10.00"));
        assert!(output.contains("p2p_storage_read_max_duration_ms 20.00"));

        assert!(output.contains("p2p_storage_write_total 1"));
        assert!(output.contains("p2p_storage_write_avg_duration_ms 30.00"));

        assert!(output.contains("p2p_storage_delete_total 1"));
        assert!(output.contains("p2p_storage_delete_errors_total 1"));
    }

    #[tokio::test]
    async fn test_export_prometheus_empty() {
        let collector = MetricsCollector::new();
        let output = collector.export_prometheus().await;

        assert!(output.contains("p2p_storage_read_total 0"));
        assert!(output.contains("p2p_storage_read_errors_total 0"));
        assert!(output.contains("p2p_storage_read_avg_duration_ms 0.00"));
        assert!(output.contains("p2p_storage_write_total 0"));
        assert!(output.contains("p2p_storage_delete_total 0"));

        // No min/max when no operations recorded
        assert!(!output.contains("min_duration_ms"));
        assert!(!output.contains("max_duration_ms"));
    }

    #[tokio::test]
    async fn test_export_prometheus_format_valid() {
        let collector = MetricsCollector::new();
        collector.record_read(Duration::from_millis(5), true).await;

        let output = collector.export_prometheus().await;

        for line in output.lines() {
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                assert!(line.starts_with("# HELP") || line.starts_with("# TYPE"));
                continue;
            }
            // Metric lines should have name and value
            assert!(line.contains(' '), "Missing space in metric line: {}", line);
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            assert_eq!(parts.len(), 2);
            assert!(
                parts[1].trim().parse::<f64>().is_ok(),
                "Invalid metric value: {}",
                parts[1]
            );
        }
    }
}
