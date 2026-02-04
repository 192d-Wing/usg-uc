//! Application core for the USG SIP Soft Client.
//!
//! This crate provides the central application logic including:
//! - Call management
//! - Contact management
//! - Settings persistence
//! - Event coordination between GUI and SIP/Audio layers

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

pub mod app;
pub mod audio_session;
pub mod call_manager;
pub mod cert_store;
pub mod contact_manager;
pub mod settings;
pub mod sip_transport;

pub use app::{AppEvent, AppState, ClientApp, PinOperationType};
pub use audio_session::{
    AudioSession, AudioSessionConfig, AudioSessionConfigBuilder, AudioSessionEvent,
};
pub use call_manager::{CallManager, CallManagerEvent, IncomingCallInfo};
pub use cert_store::{CertStoreError, CertStoreResult, CertificateStore, SignatureAlgorithm};
pub use contact_manager::{ContactManager, ContactStore, create_contact};
pub use settings::{GeneralSettings, NetworkSettings, Settings, SettingsManager, UiSettings};
pub use sip_transport::{
    CertVerificationMode, SipTransport, TransportConfig, TransportEvent,
    build_response_from_request, generate_tag,
};

use thiserror::Error;

/// Application error types.
#[derive(Debug, Error)]
pub enum AppError {
    /// SIP error.
    #[error("SIP error: {0}")]
    Sip(String),

    /// Audio error.
    #[error("Audio error: {0}")]
    Audio(String),

    /// Settings error.
    #[error("Settings error: {0}")]
    Settings(String),

    /// Contact error.
    #[error("Contact error: {0}")]
    Contact(String),

    /// Smart card error.
    #[error("Smart card error: {0}")]
    SmartCard(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result type for application operations.
pub type AppResult<T> = Result<T, AppError>;
