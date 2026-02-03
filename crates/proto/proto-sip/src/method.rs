//! SIP request methods per RFC 3261.
//!
//! This module provides all standard SIP methods defined in RFC 3261 and common
//! extensions, plus support for custom extension methods per RFC 3261 Section 7.1.

use std::fmt;
use std::str::FromStr;

/// SIP request methods per RFC 3261 and extensions.
///
/// RFC 3261 allows extension methods that are not part of the core spec.
/// Unknown methods are parsed as `Extension(String)` rather than rejected,
/// providing full RFC 3261 compliance for method extensibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// INVITE - Establish a session (RFC 3261).
    Invite,
    /// ACK - Confirm final response to INVITE (RFC 3261).
    Ack,
    /// BYE - Terminate a session (RFC 3261).
    Bye,
    /// CANCEL - Cancel a pending request (RFC 3261).
    Cancel,
    /// REGISTER - Register contact information (RFC 3261).
    Register,
    /// OPTIONS - Query capabilities (RFC 3261).
    Options,
    /// PRACK - Provisional response acknowledgment (RFC 3262).
    Prack,
    /// SUBSCRIBE - Subscribe to event notifications (RFC 6665).
    Subscribe,
    /// NOTIFY - Send event notification (RFC 6665).
    Notify,
    /// PUBLISH - Publish event state (RFC 3903).
    Publish,
    /// INFO - Mid-session signaling (RFC 6086).
    Info,
    /// REFER - Transfer request (RFC 3515).
    Refer,
    /// MESSAGE - Instant messaging (RFC 3428).
    Message,
    /// UPDATE - Modify session parameters (RFC 3311).
    Update,
    /// Extension method (RFC 3261 Section 7.1 allows custom methods).
    Extension(String),
}

impl Method {
    /// Returns the method string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Register => "REGISTER",
            Self::Options => "OPTIONS",
            Self::Prack => "PRACK",
            Self::Subscribe => "SUBSCRIBE",
            Self::Notify => "NOTIFY",
            Self::Publish => "PUBLISH",
            Self::Info => "INFO",
            Self::Refer => "REFER",
            Self::Message => "MESSAGE",
            Self::Update => "UPDATE",
            Self::Extension(name) => name.as_str(),
        }
    }

    /// Returns true if this method creates a dialog.
    #[must_use]
    pub fn creates_dialog(&self) -> bool {
        matches!(self, Self::Invite | Self::Subscribe)
    }

    /// Returns true if this method is target refresh.
    #[must_use]
    pub fn is_target_refresh(&self) -> bool {
        matches!(
            self,
            Self::Invite | Self::Update | Self::Subscribe | Self::Notify | Self::Refer
        )
    }

    /// Returns true if this method may have a body.
    #[must_use]
    pub fn may_have_body(&self) -> bool {
        matches!(
            self,
            Self::Invite
                | Self::Ack
                | Self::Prack
                | Self::Update
                | Self::Message
                | Self::Info
                | Self::Publish
                | Self::Notify
                | Self::Extension(_)
        )
    }

    /// Returns true if this is a standard RFC 3261 core method.
    #[must_use]
    pub fn is_rfc3261_core(&self) -> bool {
        matches!(
            self,
            Self::Invite | Self::Ack | Self::Bye | Self::Cancel | Self::Register | Self::Options
        )
    }

    /// Returns true if this is an extension method.
    #[must_use]
    pub fn is_extension(&self) -> bool {
        matches!(self, Self::Extension(_))
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Method {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // RFC 3261 Section 7.1: Methods are case-sensitive, but we're lenient
        // in parsing (accept lowercase) while being strict in generation (uppercase).
        Ok(match s.to_uppercase().as_str() {
            "INVITE" => Self::Invite,
            "ACK" => Self::Ack,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "REGISTER" => Self::Register,
            "OPTIONS" => Self::Options,
            "PRACK" => Self::Prack,
            "SUBSCRIBE" => Self::Subscribe,
            "NOTIFY" => Self::Notify,
            "PUBLISH" => Self::Publish,
            "INFO" => Self::Info,
            "REFER" => Self::Refer,
            "MESSAGE" => Self::Message,
            "UPDATE" => Self::Update,
            // RFC 3261 allows extension methods - store as uppercase
            _ => Self::Extension(s.to_uppercase()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_as_str() {
        assert_eq!(Method::Invite.as_str(), "INVITE");
        assert_eq!(Method::Register.as_str(), "REGISTER");
        assert_eq!(Method::Bye.as_str(), "BYE");
    }

    #[test]
    fn test_method_from_str() {
        assert_eq!("INVITE".parse::<Method>().unwrap(), Method::Invite);
        assert_eq!("invite".parse::<Method>().unwrap(), Method::Invite);
        assert_eq!("BYE".parse::<Method>().unwrap(), Method::Bye);
    }

    #[test]
    fn test_method_extension() {
        // RFC 3261 allows extension methods
        let method: Method = "CUSTOM".parse().unwrap();
        assert!(matches!(method, Method::Extension(ref s) if s == "CUSTOM"));
        assert!(method.is_extension());
        assert_eq!(method.as_str(), "CUSTOM");
    }

    #[test]
    fn test_method_extension_display() {
        let method = Method::Extension("FOOBAR".to_string());
        assert_eq!(format!("{method}"), "FOOBAR");
    }

    #[test]
    fn test_method_creates_dialog() {
        assert!(Method::Invite.creates_dialog());
        assert!(Method::Subscribe.creates_dialog());
        assert!(!Method::Bye.creates_dialog());
        assert!(!Method::Register.creates_dialog());
    }

    #[test]
    fn test_method_display() {
        assert_eq!(format!("{}", Method::Invite), "INVITE");
    }

    #[test]
    fn test_method_is_rfc3261_core() {
        assert!(Method::Invite.is_rfc3261_core());
        assert!(Method::Ack.is_rfc3261_core());
        assert!(Method::Bye.is_rfc3261_core());
        assert!(Method::Cancel.is_rfc3261_core());
        assert!(Method::Register.is_rfc3261_core());
        assert!(Method::Options.is_rfc3261_core());
        assert!(!Method::Subscribe.is_rfc3261_core()); // RFC 6665
        assert!(!Method::Extension("CUSTOM".to_string()).is_rfc3261_core());
    }
}
