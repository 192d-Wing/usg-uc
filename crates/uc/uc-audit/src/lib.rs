//! # SBC Audit
//!
//! NIST 800-53 Rev5 compliant audit logging for the USG Session Border Controller.
//!
//! ## NIST 800-53 Rev5 Controls Implemented
//!
//! - **AU-2**: Event Logging - defines auditable events
//! - **AU-3**: Content of Audit Records - specifies required fields
//! - **AU-8**: Time Stamps - uses reliable time sources
//! - **AU-9**: Protection of Audit Information - integrity via hash chain
//! - **AU-10**: Non-repudiation - cryptographic binding of records
//!
//! ## Features
//!
//! - Structured audit events for all SBC operations
//! - Hash chain for tamper detection
//! - Configurable output sinks (structured logging)
//! - Thread-safe global logger
//!
//! ## Example
//!
//! ```ignore
//! use uc_audit::{log_event, AuditEvent, CallAttempt};
//!
//! // Log a call attempt
//! log_event(AuditEvent::CallAttempt(CallAttempt {
//!     call_id: call_id.clone(),
//!     from_uri: "sip:alice@example.com".to_string(),
//!     to_uri: "sip:bob@example.com".to_string(),
//!     source_ip: "2001:db8::1".parse().unwrap(),
//!     attestation: Some(AttestationLevel::Full),
//! }));
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod event;
pub mod record;
pub mod sink;

pub use event::{AuditEvent, AuditEventType};
pub use record::AuditRecord;

use std::sync::{Arc, Mutex, OnceLock};

/// Global audit logger instance.
static AUDIT_LOGGER: OnceLock<Arc<AuditLogger>> = OnceLock::new();

/// Audit logger with hash chain integrity.
///
/// This struct is thread-safe and can be shared across threads.
pub struct AuditLogger {
    sink: Mutex<Box<dyn sink::AuditSink>>,
    sequence: std::sync::atomic::AtomicU64,
    last_hash: Mutex<[u8; 48]>,
}

impl AuditLogger {
    /// Creates a new audit logger with the given sink.
    fn new(sink: Box<dyn sink::AuditSink>) -> Self {
        Self {
            sink: Mutex::new(sink),
            sequence: std::sync::atomic::AtomicU64::new(0),
            last_hash: Mutex::new([0u8; 48]),
        }
    }

    /// Logs an audit event.
    ///
    /// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
    pub fn log(&self, event: AuditEvent) {
        let sequence = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = chrono::Utc::now();

        // Compute hash chain
        let last_hash = {
            let guard = self.last_hash.lock();
            guard.map_or([0u8; 48], |hash| *hash)
        };

        let record = AuditRecord::new(sequence, event, timestamp, last_hash);

        // Update hash chain
        if let Ok(mut guard) = self.last_hash.lock() {
            *guard = record.hash_chain;
        }

        // Output to sink
        if let Ok(sink) = self.sink.lock() {
            sink.write(&record);
        }
    }
}

/// Initializes the global audit logger.
///
/// This should be called once at application startup.
///
/// ## NIST 800-53 Rev5: AU-2 (Event Logging)
///
/// ## Errors
///
/// Returns an error if the logger is already initialized.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn init() -> Result<(), AuditError> {
    init_with_sink(Box::new(sink::TracingSink))
}

/// Initializes the global audit logger with a custom sink.
///
/// ## Errors
///
/// Returns an error if the logger is already initialized.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn init_with_sink(sink: Box<dyn sink::AuditSink>) -> Result<(), AuditError> {
    AUDIT_LOGGER
        .set(Arc::new(AuditLogger::new(sink)))
        .map_err(|_| AuditError::AlreadyInitialized)
}

/// Logs an audit event to the global logger.
///
/// If the logger is not initialized, this is a no-op.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records)
pub fn log_event(event: AuditEvent) {
    if let Some(logger) = AUDIT_LOGGER.get() {
        logger.log(event);
    }
}

/// Audit subsystem errors.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Logger was already initialized.
    #[error("audit logger already initialized")]
    AlreadyInitialized,
}
