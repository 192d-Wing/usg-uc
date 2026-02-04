//! Audio pipeline for the USG SIP Soft Client.
//!
//! This crate provides audio capture, playback, codec integration,
//! jitter buffering, and RTP/SRTP handling for voice calls.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
//! │  Microphone │───▶│   Capture   │───▶│   Encoder   │
//! │   (CPAL)    │    │   Stream    │    │  (Codec)    │
//! └─────────────┘    └─────────────┘    └──────┬──────┘
//!                                              │
//!                                              ▼
//!                                       ┌─────────────┐
//!                                       │     RTP     │
//!                                       │ Transmitter │
//!                                       └──────┬──────┘
//!                                              │
//!                                         UDP Socket
//!                                              │
//!                                              ▼
//!                                       ┌─────────────┐
//!                                       │     RTP     │
//!                                       │  Receiver   │
//!                                       └──────┬──────┘
//!                                              │
//!                                              ▼
//! ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
//! │   Speaker   │◀───│  Playback   │◀───│   Decoder   │
//! │   (CPAL)    │    │   Stream    │    │  (Codec)    │
//! └─────────────┘    └─────────────┘    └──────┬──────┘
//!                                              │
//!                                       ┌──────┴──────┐
//!                                       │   Jitter    │
//!                                       │   Buffer    │
//!                                       └─────────────┘
//! ```
//!
//! ## Modules
//!
//! - [`device`]: Audio device enumeration and selection
//! - [`stream`]: CPAL-based audio capture and playback
//! - [`codec`]: Audio codec integration (G.711, G.722, Opus)
//! - [`jitter_buffer`]: Adaptive jitter buffer for RTP reordering
//! - [`rtp_handler`]: RTP/SRTP packet handling
//! - [`pipeline`]: Main audio pipeline coordinator

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

pub mod codec;
pub mod device;
pub mod jitter_buffer;
pub mod pipeline;
pub mod rtp_handler;
pub mod stream;

pub use codec::{negotiate_codec, CodecPipeline};
pub use device::{DeviceManager, DEFAULT_SAMPLE_RATE, SAMPLE_RATE_16KHZ, SAMPLE_RATE_48KHZ, SAMPLE_RATE_8KHZ};
pub use jitter_buffer::{BufferedPacket, JitterBuffer, JitterBufferResult, JitterBufferStats};
pub use pipeline::{AudioPipeline, PipelineConfig, PipelineState, PipelineStats};
pub use rtp_handler::{generate_ssrc, RtpReceiver, RtpStats, RtpTransmitter};
pub use stream::{CaptureStream, PlaybackStream, Sample};

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
