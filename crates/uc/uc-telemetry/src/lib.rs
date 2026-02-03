//! # OpenTelemetry Integration for USG SBC
//!
//! This crate provides OpenTelemetry integration for distributed tracing and metrics
//! collection in the USG Session Border Controller.
//!
//! ## Features
//!
//! - **tracing**: Integration with the `tracing` crate for span propagation
//! - **metrics**: Prometheus metrics export
//! - **otlp**: OTLP exporter for traces and metrics
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Audit Events (trace logging)
//! - **AU-3**: Content of Audit Records
//! - **AU-6**: Audit Review, Analysis, and Reporting
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Telemetry Provider                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │   Traces          │     Metrics     │     Logs              │
//! │   (OpenTelemetry) │   (Prometheus)  │   (tracing)           │
//! ├─────────────────────────────────────────────────────────────┤
//! │                      Exporters                               │
//! │   OTLP/gRPC      │  Prometheus HTTP │  stdout/file          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use uc_telemetry::{TelemetryConfig, TelemetryProvider};
//!
//! let config = TelemetryConfig::builder()
//!     .service_name("sbc-daemon")
//!     .otlp_endpoint("http://localhost:4317")
//!     .build();
//!
//! let provider = TelemetryProvider::new(config).await?;
//! provider.init_global()?;
//! ```

#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod provider;
pub mod span;

// tracing_layer and metrics modules can be added when needed
// #[cfg(feature = "tracing")]
// pub mod tracing_layer;

// #[cfg(feature = "metrics")]
// pub mod metrics;

pub use config::{TelemetryConfig, TelemetryConfigBuilder};
pub use error::{TelemetryError, TelemetryResult};
pub use provider::TelemetryProvider;
pub use span::{SpanContext, SpanKind};

// #[cfg(feature = "metrics")]
// pub use metrics::{Counter, Gauge, Histogram, MetricAttributes};

/// Re-export OpenTelemetry for convenience.
pub use opentelemetry;
pub use opentelemetry_sdk;

#[cfg(feature = "tracing")]
pub use tracing_opentelemetry;

/// Standard span attributes for SIP/VoIP operations.
pub mod attributes {
    use opentelemetry::KeyValue;

    /// Creates a span attribute for Call-ID.
    pub fn call_id(id: impl Into<String>) -> KeyValue {
        KeyValue::new("sip.call_id", id.into())
    }

    /// Creates a span attribute for SIP method.
    pub fn sip_method(method: impl Into<String>) -> KeyValue {
        KeyValue::new("sip.method", method.into())
    }

    /// Creates a span attribute for SIP status code.
    pub fn sip_status_code(code: u16) -> KeyValue {
        KeyValue::new("sip.status_code", i64::from(code))
    }

    /// Creates a span attribute for transaction ID.
    pub fn transaction_id(id: impl Into<String>) -> KeyValue {
        KeyValue::new("sip.transaction_id", id.into())
    }

    /// Creates a span attribute for dialog ID.
    pub fn dialog_id(id: impl Into<String>) -> KeyValue {
        KeyValue::new("sip.dialog_id", id.into())
    }

    /// Creates a span attribute for source IP.
    pub fn source_ip(ip: impl Into<String>) -> KeyValue {
        KeyValue::new("net.peer.ip", ip.into())
    }

    /// Creates a span attribute for source port.
    pub fn source_port(port: u16) -> KeyValue {
        KeyValue::new("net.peer.port", i64::from(port))
    }

    /// Creates a span attribute for destination IP.
    pub fn destination_ip(ip: impl Into<String>) -> KeyValue {
        KeyValue::new("net.host.ip", ip.into())
    }

    /// Creates a span attribute for destination port.
    pub fn destination_port(port: u16) -> KeyValue {
        KeyValue::new("net.host.port", i64::from(port))
    }

    /// Creates a span attribute for transport protocol.
    pub fn transport(protocol: impl Into<String>) -> KeyValue {
        KeyValue::new("net.transport", protocol.into())
    }

    /// Creates a span attribute for codec.
    pub fn codec(name: impl Into<String>) -> KeyValue {
        KeyValue::new("media.codec", name.into())
    }

    /// Creates a span attribute for RTP SSRC.
    pub fn rtp_ssrc(ssrc: u32) -> KeyValue {
        KeyValue::new("rtp.ssrc", i64::from(ssrc))
    }

    /// Creates a span attribute for error type.
    pub fn error_type(error: impl Into<String>) -> KeyValue {
        KeyValue::new("error.type", error.into())
    }

    /// Creates a span attribute for error message.
    pub fn error_message(message: impl Into<String>) -> KeyValue {
        KeyValue::new("error.message", message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_id_attribute() {
        let attr = attributes::call_id("abc123@example.com");
        assert_eq!(attr.key.as_str(), "sip.call_id");
    }

    #[test]
    fn test_sip_method_attribute() {
        let attr = attributes::sip_method("INVITE");
        assert_eq!(attr.key.as_str(), "sip.method");
    }

    #[test]
    fn test_sip_status_code_attribute() {
        let attr = attributes::sip_status_code(200);
        assert_eq!(attr.key.as_str(), "sip.status_code");
    }
}
