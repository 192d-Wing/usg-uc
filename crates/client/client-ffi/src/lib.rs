//! `UniFFI` bindings layer for the SIP Soft Client.
//!
//! This crate is the single public API consumed by the three native shells
//! (`SwiftUI` for iOS/macOS, Kotlin/Compose for Android, `WinUI` 3/C# for
//! Windows). It wraps `client-core` behind FFI-friendly mirror types and a
//! push-based event listener; all behavior lives below this crate, shells are
//! intentionally thin.
//!
//! Generate bindings with the bundled CLI (see `src/bin/uniffi_bindgen.rs`).

// Errors are described on the `ClientError` variants themselves; per-method
// `# Errors` sections add nothing for generated foreign-language docs.
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
// UniFFI-exported functions must take owned values; the FFI layer cannot
// borrow across the language boundary.
#![allow(clippy::needless_pass_by_value)]

uniffi::setup_scaffolding!();

mod client;
mod types;

pub use client::{
    ClientConfig, EventListener, SipClient, init_logging, list_input_devices, list_output_devices,
};
pub use types::{
    AppEvent, AudioDevice, AudioDeviceCategory, AudioDeviceKind, AudioSettings, CallDirection,
    CallEndReason, CallHistoryEntry, CallInfo, CallState, ClassificationBanner, ClientError,
    CodecKind, Contact, PhoneNumber, PhoneNumberKind, PinOperation, RegistrationState,
    SipAccountConfig, TransportKind,
};
