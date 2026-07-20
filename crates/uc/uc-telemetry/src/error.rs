//! Error types for the telemetry module.

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

// Note: TraceError was removed from opentelemetry_sdk::trace in 0.32 (as MetricError
// was in 0.31). Trace/metric errors are constructed via TelemetryError::TraceError /
// ::MetricsError { reason: ... } directly rather than through a From impl.
