//! Wire codecs for the DTLS 1.2 association.
//!
//! Everything a peer sends is parsed here through the bounds-checked
//! [`reader::Reader`]; no parser indexes or slices peer input directly, and a
//! malformed message is an `Err`, never a panic.
//!
//! ## NIST 800-53 Rev5: SI-10 (Information Input Validation)

pub mod alert;
pub mod extensions;
pub mod handshake_msg;
pub mod reader;

/// Why a peer-supplied structure could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The input ended before the structure did.
    Truncated,
    /// Bytes were left over after the structure ended.
    TrailingBytes,
    /// A field holds a value the encoding does not allow.
    Malformed,
    /// A value is too large to encode in its length prefix.
    Oversized,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated",
            Self::TrailingBytes => "trailing bytes",
            Self::Malformed => "malformed",
            Self::Oversized => "oversized",
        })
    }
}

impl std::error::Error for WireError {}

/// Result of a wire codec operation.
pub type WireResult<T> = Result<T, WireError>;
