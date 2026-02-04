//! Shared types for the USG SIP Soft Client.
//!
//! This crate provides common type definitions used across the soft client,
//! including call states, account configuration, audio settings, and contacts.

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

pub mod account;
pub mod audio;
pub mod call;
pub mod contact;
pub mod error;
pub mod sensitive;

pub use account::{
    CertificateConfig, CertificateInfo, CertificateSelectionMode, RegistrationState,
    ServerCertVerificationMode, SipAccount, TransportPreference, TurnConfig,
};
pub use audio::{AudioConfig, AudioDevice, CodecPreference};
pub use call::{
    CallDirection, CallEndReason, CallFailureReason, CallFocus, CallHistoryEntry, CallInfo,
    CallState,
};
pub use contact::{Contact, PhoneNumber, PhoneNumberType};
pub use error::{ClientError, ClientResult};
pub use sensitive::{SensitiveString, SessionToken, SmartCardPin, SrtpKeyMaterial};
