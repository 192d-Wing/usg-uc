//! # SBC Types
//!
//! Shared types, error enumerations, and constants for the USG Session Border Controller.
//!
//! This crate provides the foundational types used across all SBC components.
//! It has no dependencies on other workspace crates, serving as the base layer.
//!
//! ## CNSA 2.0 Compliance
//!
//! Types in this crate enforce CNSA 2.0 algorithm restrictions at the type level:
//! - Only P-384 and P-521 curves are representable
//! - Only SHA-384 and SHA-512 hash algorithms are representable
//! - Only AES-256 cipher configurations are representable
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! This crate supports the following control families:
//! - **SC-13**: Cryptographic Protection (via algorithm enums)
//! - **AU-2**: Event Logging (via audit event types)

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// Clippy style preferences for protocol implementation code
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]

pub mod address;
pub mod attestation;
pub mod codec;
pub mod error;
pub mod identifier;
pub mod media;
pub mod nist;
pub mod protocol;

pub use address::SbcSocketAddr;
pub use attestation::AttestationLevel;
pub use codec::CodecId;
pub use error::{SbcError, SbcResult};
pub use identifier::{CallId, DialogId, TransactionId};
pub use media::MediaMode;
