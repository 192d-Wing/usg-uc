//! Codec error types.

use thiserror::Error;

/// Result type for codec operations.
pub type CodecResult<T> = Result<T, CodecError>;

/// Codec errors.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Encoding failed.
    #[error("encoding failed: {reason}")]
    EncodingFailed {
        /// Error description.
        reason: String,
    },

    /// Decoding failed.
    #[error("decoding failed: {reason}")]
    DecodingFailed {
        /// Error description.
        reason: String,
    },

    /// Invalid frame size.
    #[error("invalid frame size: expected {expected}, got {actual}")]
    InvalidFrameSize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },

    /// Buffer too small.
    #[error("buffer too small: needed {needed} bytes, available {available}")]
    BufferTooSmall {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        available: usize,
    },

    /// Unsupported sample rate.
    #[error("unsupported sample rate: {rate} Hz")]
    UnsupportedSampleRate {
        /// Sample rate.
        rate: u32,
    },

    /// Unsupported channel count.
    #[error("unsupported channel count: {channels}")]
    UnsupportedChannels {
        /// Channel count.
        channels: u8,
    },

    /// Codec not available.
    #[error("codec not available: {name}")]
    CodecNotAvailable {
        /// Codec name.
        name: String,
    },

    /// Invalid configuration.
    #[error("invalid configuration: {reason}")]
    InvalidConfig {
        /// Error description.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CodecError::InvalidFrameSize {
            expected: 160,
            actual: 80,
        };
        assert!(err.to_string().contains("160"));
        assert!(err.to_string().contains("80"));
    }
}
