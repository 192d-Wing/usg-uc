//! Error types for the telemetry module.

use opentelemetry::trace::TraceError;
use thiserror::Error;

/// Result type alias for telemetry operations.
pub type TelemetryResult<T> = Result<T, TelemetryError>;

/// Errors that can occur during telemetry operations.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// Configuration error.
    #[error("configuration error: {reason}")]
    ConfigError {
        /// Reason for the configuration error.
        reason: String,
    },

    /// Initialization failed.
    #[error("initialization failed: {reason}")]
    InitializationFailed {
        /// Reason for the failure.
        reason: String,
    },

    /// Exporter error.
    #[error("exporter error: {reason}")]
    ExporterError {
        /// Reason for the error.
        reason: String,
    },

    /// Trace error.
    #[error("trace error: {reason}")]
    TraceError {
        /// Reason for the error.
        reason: String,
    },

    /// Metrics error.
    #[error("metrics error: {reason}")]
    MetricsError {
        /// Reason for the error.
        reason: String,
    },

    /// Already initialized.
    #[error("telemetry already initialized")]
    AlreadyInitialized,

    /// Not initialized.
    #[error("telemetry not initialized")]
    NotInitialized,

    /// Shutdown error.
    #[error("shutdown error: {reason}")]
    ShutdownError {
        /// Reason for the error.
        reason: String,
    },
}

impl From<TraceError> for TelemetryError {
    fn from(err: TraceError) -> Self {
        Self::TraceError {
            reason: err.to_string(),
        }
    }
}

impl From<opentelemetry_sdk::metrics::MetricError> for TelemetryError {
    fn from(err: opentelemetry_sdk::metrics::MetricError) -> Self {
        Self::MetricsError {
            reason: err.to_string(),
        }
    }
}
