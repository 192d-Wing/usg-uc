//! CDR error types.

use std::fmt;

/// CDR result type.
pub type CdrResult<T> = Result<T, CdrError>;

/// CDR errors.
#[derive(Debug)]
pub enum CdrError {
    /// Write error.
    WriteError {
        /// Message.
        message: String,
    },
    /// Format error.
    FormatError {
        /// Message.
        message: String,
    },
    /// Invalid field.
    InvalidField {
        /// Field name.
        field: String,
        /// Reason.
        reason: String,
    },
    /// Buffer full.
    BufferFull {
        /// Current size.
        size: usize,
    },
    /// IO error.
    IoError {
        /// Message.
        message: String,
    },
}

impl fmt::Display for CdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriteError { message } => write!(f, "Write error: {message}"),
            Self::FormatError { message } => write!(f, "Format error: {message}"),
            Self::InvalidField { field, reason } => {
                write!(f, "Invalid field '{field}': {reason}")
            }
            Self::BufferFull { size } => write!(f, "Buffer full: {size} records"),
            Self::IoError { message } => write!(f, "IO error: {message}"),
        }
    }
}

impl std::error::Error for CdrError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_error_display() {
        let error = CdrError::WriteError {
            message: "disk full".to_string(),
        };
        assert!(error.to_string().contains("disk full"));
    }

    #[test]
    fn test_buffer_full_display() {
        let error = CdrError::BufferFull { size: 1000 };
        assert!(error.to_string().contains("1000"));
    }
}
