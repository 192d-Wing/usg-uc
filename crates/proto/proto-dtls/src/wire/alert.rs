//! TLS alert codec (RFC 5246 §7.2).

#![deny(clippy::indexing_slicing)]

use super::WireResult;
use super::reader::Reader;

/// Alert level `warning`.
pub const LEVEL_WARNING: u8 = 1;
/// Alert level `fatal`.
pub const LEVEL_FATAL: u8 = 2;

/// `close_notify`.
pub const CLOSE_NOTIFY: u8 = 0;
/// `unexpected_message`.
pub const UNEXPECTED_MESSAGE: u8 = 10;
/// `handshake_failure`.
pub const HANDSHAKE_FAILURE: u8 = 40;
/// `bad_certificate`.
pub const BAD_CERTIFICATE: u8 = 42;
/// `illegal_parameter`.
pub const ILLEGAL_PARAMETER: u8 = 47;
/// `decode_error`.
pub const DECODE_ERROR: u8 = 50;
/// `decrypt_error`.
pub const DECRYPT_ERROR: u8 = 51;
/// `protocol_version`.
pub const PROTOCOL_VERSION: u8 = 70;
/// `internal_error`.
pub const INTERNAL_ERROR: u8 = 80;
/// `no_renegotiation`.
pub const NO_RENEGOTIATION: u8 = 100;
/// `unsupported_extension` (RFC 5246 §7.4.1.4).
pub const UNSUPPORTED_EXTENSION: u8 = 110;

/// A TLS alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    /// Alert level (1 warning, 2 fatal).
    pub level: u8,
    /// Alert description.
    pub description: u8,
}

impl Alert {
    /// A fatal alert.
    #[must_use]
    pub const fn fatal(description: u8) -> Self {
        Self {
            level: LEVEL_FATAL,
            description,
        }
    }

    /// A warning alert.
    #[must_use]
    pub const fn warning(description: u8) -> Self {
        Self {
            level: LEVEL_WARNING,
            description,
        }
    }

    /// Parses an alert; the fragment must be exactly two bytes.
    ///
    /// # Errors
    /// Returns an error if the fragment is not exactly two bytes.
    pub fn parse(fragment: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(fragment);
        let level = r.u8()?;
        let description = r.u8()?;
        r.finish()?;
        Ok(Self { level, description })
    }

    /// Encodes the alert.
    #[must_use]
    pub const fn encode(self) -> [u8; 2] {
        [self.level, self.description]
    }

    /// True for anything that ends the association: a fatal level, or any
    /// level other than `warning` (RFC 5246 §7.2: unknown levels are fatal).
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        self.level != LEVEL_WARNING
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_bounds() {
        let alert = Alert::fatal(BAD_CERTIFICATE);
        assert_eq!(Alert::parse(&alert.encode()).unwrap(), alert);
        assert!(alert.is_fatal());
        assert!(!Alert::warning(CLOSE_NOTIFY).is_fatal());
        assert!(Alert::parse(&[]).is_err());
        assert!(Alert::parse(&[2]).is_err());
        assert!(Alert::parse(&[2, 40, 0]).is_err());
    }
}
