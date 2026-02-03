//! Audio pipeline for the USG SIP Soft Client.
//!
//! This crate provides audio capture, playback, codec integration,
//! jitter buffering, and RTP/SRTP handling for voice calls.

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

// Modules will be added as implementation progresses
// pub mod device;
// pub mod jitter_buffer;
// pub mod pipeline;
// pub mod rtp_handler;

use thiserror::Error;

/// Audio error types.
#[derive(Debug, Error)]
pub enum AudioError {
    /// No input device available.
    #[error("No input device available")]
    NoInputDevice,

    /// No output device available.
    #[error("No output device available")]
    NoOutputDevice,

    /// Device not found.
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    /// Stream error.
    #[error("Stream error: {0}")]
    StreamError(String),

    /// Codec error.
    #[error("Codec error: {0}")]
    CodecError(String),

    /// RTP error.
    #[error("RTP error: {0}")]
    RtpError(String),

    /// SRTP error.
    #[error("SRTP error: {0}")]
    SrtpError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for audio operations.
pub type AudioResult<T> = Result<T, AudioError>;
