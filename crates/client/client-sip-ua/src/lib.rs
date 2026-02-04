//! SIP User Agent for the USG SIP Soft Client.
//!
//! This crate provides the SIP signaling layer including:
//! - Registration management
//! - Call control (INVITE/BYE/CANCEL)
//! - Dialog management
//! - ICE/DTLS-SRTP media negotiation
//!
//! Authentication is via mutual TLS with smart card (CAC/PIV) certificates.
//! Password-based digest authentication is NOT supported.

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

pub mod call_agent;
pub mod dtls_handler;
pub mod ice_handler;
pub mod media_session;
pub mod registration;

pub use call_agent::{CallAgent, CallEvent};
pub use dtls_handler::{DtlsEvent, DtlsHandler};
pub use ice_handler::{IceEvent, IceHandler};
pub use media_session::{MediaSession, MediaSessionEvent, MediaSessionState};
pub use registration::{RegistrationAgent, RegistrationEvent};

// Re-export ReferStatus for transfer progress handling (RFC 3515)
pub use proto_dialog::refer::ReferStatus;

use thiserror::Error;

/// SIP UA error types.
#[derive(Debug, Error)]
pub enum SipUaError {
    /// Registration failed.
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),

    /// Call failed.
    #[error("Call failed: {0}")]
    CallFailed(String),

    /// Transaction error.
    #[error("Transaction error: {0}")]
    TransactionError(String),

    /// Dialog error.
    #[error("Dialog error: {0}")]
    DialogError(String),

    /// Transport error.
    #[error("Transport error: {0}")]
    TransportError(String),

    /// ICE error.
    #[error("ICE error: {0}")]
    IceError(String),

    /// DTLS error.
    #[error("DTLS error: {0}")]
    DtlsError(String),

    /// Certificate error.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Smart card not present.
    #[error("Smart card not present")]
    SmartCardNotPresent,

    /// Invalid state for operation.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for SIP UA operations.
pub type SipUaResult<T> = Result<T, SipUaError>;
