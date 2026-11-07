//! CDR error types.

use std::fmt;

/// CDR result type.
pub type CdrResult<T> = Result<T, CdrError>;

/// CDR errors.
#[derive(Debug)]
pub enum CdrError {
    /// Invalid emitter or sink configuration.
    Config {
        /// Message.
        message: String,
    },
    /// Record could not be serialized.
    FormatError {
        /// Message.
        message: String,
    },
    /// IO error.
    IoError {
        /// Message.
        message: String,
    },
    /// The writer thread could not be started.
    WriterThread {
        /// Message.
        message: String,
    },
    /// A CDR file failed integrity verification.
    ///
    /// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
    Verify {
        /// 1-based line number of the first failure (0 = whole file).
        line: u64,
        /// Reason.
        reason: String,
    },
}

impl CdrError {
    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    pub(crate) fn verify(line: u64, reason: impl Into<String>) -> Self {
        Self::Verify {
            line,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for CdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config { message } => write!(f, "CDR config error: {message}"),
            Self::FormatError { message } => write!(f, "Format error: {message}"),
            Self::IoError { message } => write!(f, "IO error: {message}"),
            Self::WriterThread { message } => write!(f, "CDR writer thread: {message}"),
            Self::Verify { line, reason } => {
                write!(f, "CDR verification failed at line {line}: {reason}")
            }
        }
    }
}

impl std::error::Error for CdrError {}

impl From<std::io::Error> for CdrError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError {
            message: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for CdrError {
    fn from(e: serde_json::Error) -> Self {
        Self::FormatError {
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_error_display() {
        let error = CdrError::verify(7, "hash mismatch");
        let s = error.to_string();
        assert!(s.contains("line 7"));
        assert!(s.contains("hash mismatch"));
    }

    #[test]
    fn test_io_error_from() {
        let e: CdrError = std::io::Error::other("disk full").into();
        assert!(e.to_string().contains("disk full"));
    }
}
