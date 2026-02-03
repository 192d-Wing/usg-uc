//! RFC 5424 syslog message formatting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Syslog severity levels (RFC 5424).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    /// System is unusable.
    Emergency = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// Critical conditions.
    Critical = 2,
    /// Error conditions.
    Error = 3,
    /// Warning conditions.
    Warning = 4,
    /// Normal but significant condition.
    Notice = 5,
    /// Informational messages.
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Emergency => write!(f, "EMERGENCY"),
            Self::Alert => write!(f, "ALERT"),
            Self::Critical => write!(f, "CRITICAL"),
            Self::Error => write!(f, "ERROR"),
            Self::Warning => write!(f, "WARNING"),
            Self::Notice => write!(f, "NOTICE"),
            Self::Info => write!(f, "INFO"),
            Self::Debug => write!(f, "DEBUG"),
        }
    }
}

/// Syslog facility codes (RFC 5424).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Facility {
    /// Kernel messages.
    Kern = 0,
    /// User-level messages.
    User = 1,
    /// Mail system.
    Mail = 2,
    /// System daemons.
    Daemon = 3,
    /// Security/authorization messages.
    Auth = 4,
    /// Internal syslog messages.
    Syslog = 5,
    /// Line printer subsystem.
    Lpr = 6,
    /// Network news subsystem.
    News = 7,
    /// UUCP subsystem.
    Uucp = 8,
    /// Clock daemon.
    Cron = 9,
    /// Security/authorization messages (private).
    AuthPriv = 10,
    /// FTP daemon.
    Ftp = 11,
    /// Local use 0.
    Local0 = 16,
    /// Local use 1.
    Local1 = 17,
    /// Local use 2.
    Local2 = 18,
    /// Local use 3.
    Local3 = 19,
    /// Local use 4.
    Local4 = 20,
    /// Local use 5.
    Local5 = 21,
    /// Local use 6.
    Local6 = 22,
    /// Local use 7.
    Local7 = 23,
}

/// Syslog message per RFC 5424.
#[derive(Debug, Clone)]
pub struct SyslogMessage {
    /// Facility.
    pub facility: Facility,
    /// Severity.
    pub severity: Severity,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Hostname.
    pub hostname: String,
    /// Application name.
    pub app_name: String,
    /// Process ID.
    pub proc_id: Option<String>,
    /// Message ID.
    pub msg_id: Option<String>,
    /// Structured data.
    pub structured_data: Vec<StructuredData>,
    /// Message.
    pub message: String,
}

impl SyslogMessage {
    /// Creates a new syslog message.
    #[must_use]
    pub fn new(severity: Severity, message: impl Into<String>) -> Self {
        Self {
            facility: Facility::Local0,
            severity,
            timestamp: Utc::now(),
            hostname: gethostname(),
            app_name: "sbc".to_string(),
            proc_id: Some(std::process::id().to_string()),
            msg_id: None,
            structured_data: Vec::new(),
            message: message.into(),
        }
    }

    /// Sets the facility.
    #[must_use]
    pub const fn with_facility(mut self, facility: Facility) -> Self {
        self.facility = facility;
        self
    }

    /// Sets the app name.
    #[must_use]
    pub fn with_app_name(mut self, app_name: impl Into<String>) -> Self {
        self.app_name = app_name.into();
        self
    }

    /// Sets the message ID.
    #[must_use]
    pub fn with_msg_id(mut self, msg_id: impl Into<String>) -> Self {
        self.msg_id = Some(msg_id.into());
        self
    }

    /// Adds structured data.
    #[must_use]
    pub fn with_structured_data(mut self, sd: StructuredData) -> Self {
        self.structured_data.push(sd);
        self
    }

    /// Formats as RFC 5424 message.
    #[must_use]
    pub fn to_rfc5424(&self) -> String {
        let priority = (self.facility as u8) * 8 + (self.severity as u8);
        let timestamp = self.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ");
        let proc_id = self.proc_id.as_deref().unwrap_or("-");
        let msg_id = self.msg_id.as_deref().unwrap_or("-");

        let sd_str = if self.structured_data.is_empty() {
            "-".to_string()
        } else {
            self.structured_data
                .iter()
                .fold(String::new(), |mut acc, sd| {
                    use std::fmt::Write;
                    let _ = write!(acc, "{sd}");
                    acc
                })
        };

        format!(
            "<{}>1 {} {} {} {} {} {} {}",
            priority,
            timestamp,
            self.hostname,
            self.app_name,
            proc_id,
            msg_id,
            sd_str,
            self.message
        )
    }

    /// Formats as BSD syslog message.
    #[must_use]
    pub fn to_bsd(&self) -> String {
        let priority = (self.facility as u8) * 8 + (self.severity as u8);
        let timestamp = self.timestamp.format("%b %d %H:%M:%S");

        format!(
            "<{}>{} {} {}: {}",
            priority, timestamp, self.hostname, self.app_name, self.message
        )
    }
}

/// Structured data element per RFC 5424.
#[derive(Debug, Clone)]
pub struct StructuredData {
    /// SD-ID.
    pub id: String,
    /// Parameters.
    pub params: Vec<(String, String)>,
}

impl StructuredData {
    /// Creates new structured data.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            params: Vec::new(),
        }
    }

    /// Adds a parameter.
    #[must_use]
    pub fn with_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((name.into(), value.into()));
        self
    }
}

impl std::fmt::Display for StructuredData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}", self.id)?;
        for (name, value) in &self.params {
            // Escape special characters in value
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace(']', "\\]");
            write!(f, " {}=\"{}\"", name, escaped)?;
        }
        write!(f, "]")
    }
}

/// Gets the hostname.
fn gethostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Emergency < Severity::Debug);
        assert!(Severity::Error < Severity::Warning);
    }

    #[test]
    fn test_message_creation() {
        let msg = SyslogMessage::new(Severity::Info, "Test message")
            .with_facility(Facility::Local0)
            .with_app_name("test");

        assert_eq!(msg.severity, Severity::Info);
        assert_eq!(msg.message, "Test message");
        assert_eq!(msg.app_name, "test");
    }

    #[test]
    fn test_rfc5424_format() {
        let msg = SyslogMessage::new(Severity::Info, "Test");
        let formatted = msg.to_rfc5424();

        // Should start with priority
        assert!(formatted.starts_with('<'));
        assert!(formatted.contains("Test"));
    }

    #[test]
    fn test_structured_data() {
        let sd = StructuredData::new("test@123")
            .with_param("key", "value")
            .with_param("key2", "value with \"quotes\"");

        let formatted = sd.to_string();
        assert!(formatted.starts_with("[test@123"));
        assert!(formatted.contains("key=\"value\""));
        assert!(formatted.contains("\\\"quotes\\\""));
    }

    #[test]
    fn test_bsd_format() {
        let msg = SyslogMessage::new(Severity::Info, "Test");
        let formatted = msg.to_bsd();

        assert!(formatted.starts_with('<'));
        assert!(formatted.contains("Test"));
    }
}
