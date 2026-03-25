//! Telemetry configuration types.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Telemetry configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled.
    pub enabled: bool,
    /// Service name for traces.
    pub service_name: String,
    /// Service version.
    pub service_version: String,
    /// Service instance ID.
    pub service_instance_id: Option<String>,
    /// Environment (e.g., "production", "staging").
    pub environment: Option<String>,
    /// Trace configuration.
    pub traces: TraceConfig,
    /// Metrics configuration.
    pub metrics: MetricsConfig,
    /// OTLP exporter configuration.
    pub otlp: Option<OtlpConfig>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "sbc".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            service_instance_id: None,
            environment: None,
            traces: TraceConfig::default(),
            metrics: MetricsConfig::default(),
            otlp: None,
        }
    }
}

impl TelemetryConfig {
    /// Creates a new configuration builder.
    #[must_use]
    pub fn builder() -> TelemetryConfigBuilder {
        TelemetryConfigBuilder::default()
    }
}

/// Builder for telemetry configuration.
#[derive(Debug, Default)]
pub struct TelemetryConfigBuilder {
    config: TelemetryConfig,
}

impl TelemetryConfigBuilder {
    /// Sets whether telemetry is enabled.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Sets the service name.
    #[must_use]
    pub fn service_name(mut self, name: impl Into<String>) -> Self {
        self.config.service_name = name.into();
        self
    }

    /// Sets the service version.
    #[must_use]
    pub fn service_version(mut self, version: impl Into<String>) -> Self {
        self.config.service_version = version.into();
        self
    }

    /// Sets the service instance ID.
    #[must_use]
    pub fn service_instance_id(mut self, id: impl Into<String>) -> Self {
        self.config.service_instance_id = Some(id.into());
        self
    }

    /// Sets the environment.
    #[must_use]
    pub fn environment(mut self, env: impl Into<String>) -> Self {
        self.config.environment = Some(env.into());
        self
    }

    /// Sets trace configuration.
    #[must_use]
    pub fn traces(mut self, traces: TraceConfig) -> Self {
        self.config.traces = traces;
        self
    }

    /// Sets metrics configuration.
    #[must_use]
    pub fn metrics(mut self, metrics: MetricsConfig) -> Self {
        self.config.metrics = metrics;
        self
    }

    /// Sets OTLP exporter configuration.
    #[must_use]
    pub fn otlp(mut self, otlp: OtlpConfig) -> Self {
        self.config.otlp = Some(otlp);
        self
    }

    /// Sets the OTLP endpoint (convenience method).
    #[must_use]
    pub fn otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let otlp = self.config.otlp.get_or_insert_with(OtlpConfig::default);
        otlp.endpoint = endpoint.into();
        self
    }

    /// Builds the configuration.
    #[must_use]
    pub fn build(self) -> TelemetryConfig {
        self.config
    }
}

/// Trace configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceConfig {
    /// Whether tracing is enabled.
    pub enabled: bool,
    /// Sampling ratio (0.0 to 1.0).
    pub sampling_ratio: f64,
    /// Maximum number of attributes per span.
    pub max_attributes_per_span: u32,
    /// Maximum number of events per span.
    pub max_events_per_span: u32,
    /// Maximum number of links per span.
    pub max_links_per_span: u32,
    /// Batch export configuration.
    pub batch: BatchConfig,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sampling_ratio: 1.0,
            max_attributes_per_span: 128,
            max_events_per_span: 128,
            max_links_per_span: 128,
            batch: BatchConfig::default(),
        }
    }
}

/// Metrics configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Whether metrics are enabled.
    pub enabled: bool,
    /// Export interval in milliseconds.
    pub export_interval_ms: u64,
    /// Prometheus configuration.
    pub prometheus: Option<PrometheusConfig>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_interval_ms: 60000,
            prometheus: None,
        }
    }
}

impl MetricsConfig {
    /// Returns the export interval as a Duration.
    #[must_use]
    pub const fn export_interval(&self) -> Duration {
        Duration::from_millis(self.export_interval_ms)
    }
}

/// Prometheus configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    /// Whether Prometheus export is enabled.
    pub enabled: bool,
    /// HTTP endpoint path for metrics.
    pub endpoint_path: String,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint_path: "/metrics".to_string(),
        }
    }
}

/// Batch export configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BatchConfig {
    /// Maximum number of spans in a batch.
    pub max_export_batch_size: u32,
    /// Maximum queue size.
    pub max_queue_size: u32,
    /// Export timeout in milliseconds.
    pub export_timeout_ms: u64,
    /// Scheduled delay in milliseconds.
    pub scheduled_delay_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_export_batch_size: 512,
            max_queue_size: 2048,
            export_timeout_ms: 30000,
            scheduled_delay_ms: 5000,
        }
    }
}

impl BatchConfig {
    /// Returns the export timeout as a Duration.
    #[must_use]
    pub const fn export_timeout(&self) -> Duration {
        Duration::from_millis(self.export_timeout_ms)
    }

    /// Returns the scheduled delay as a Duration.
    #[must_use]
    pub const fn scheduled_delay(&self) -> Duration {
        Duration::from_millis(self.scheduled_delay_ms)
    }
}

/// OTLP exporter configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OtlpConfig {
    /// OTLP endpoint URL.
    pub endpoint: String,
    /// Protocol to use.
    pub protocol: OtlpProtocol,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Headers to include in requests.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// TLS configuration.
    pub tls: Option<OtlpTlsConfig>,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            protocol: OtlpProtocol::Grpc,
            timeout_ms: 10000,
            headers: std::collections::HashMap::new(),
            tls: None,
        }
    }
}

impl OtlpConfig {
    /// Returns the timeout as a Duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// OTLP protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OtlpProtocol {
    /// gRPC protocol.
    #[default]
    Grpc,
    /// HTTP/protobuf protocol.
    HttpProtobuf,
    /// HTTP/JSON protocol.
    HttpJson,
}

impl std::fmt::Display for OtlpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grpc => write!(f, "grpc"),
            Self::HttpProtobuf => write!(f, "http/protobuf"),
            Self::HttpJson => write!(f, "http/json"),
        }
    }
}

/// OTLP TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpTlsConfig {
    /// Path to CA certificate.
    pub ca_cert_path: Option<String>,
    /// Path to client certificate.
    pub client_cert_path: Option<String>,
    /// Path to client key.
    pub client_key_path: Option<String>,
    /// Whether to verify server certificate.
    pub verify_certificate: bool,
}

impl Default for OtlpTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            verify_certificate: true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();
        assert!(config.enabled);
        assert_eq!(config.service_name, "sbc");
        assert!(config.traces.enabled);
        assert!(config.metrics.enabled);
    }

    #[test]
    fn test_config_builder() {
        let config = TelemetryConfig::builder()
            .service_name("test-service")
            .service_instance_id("instance-1")
            .environment("test")
            .otlp_endpoint("http://otel-collector:4317")
            .build();

        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.service_instance_id, Some("instance-1".to_string()));
        assert_eq!(config.environment, Some("test".to_string()));
        assert!(config.otlp.is_some());
        assert_eq!(
            config.otlp.as_ref().unwrap().endpoint,
            "http://otel-collector:4317"
        );
    }

    #[test]
    fn test_batch_config_durations() {
        let config = BatchConfig::default();
        assert_eq!(config.export_timeout(), Duration::from_secs(30));
        assert_eq!(config.scheduled_delay(), Duration::from_secs(5));
    }

    #[test]
    fn test_metrics_export_interval() {
        let config = MetricsConfig::default();
        assert_eq!(config.export_interval(), Duration::from_secs(60));
    }

    #[test]
    fn test_otlp_protocol_display() {
        assert_eq!(format!("{}", OtlpProtocol::Grpc), "grpc");
        assert_eq!(format!("{}", OtlpProtocol::HttpProtobuf), "http/protobuf");
        assert_eq!(format!("{}", OtlpProtocol::HttpJson), "http/json");
    }
}
