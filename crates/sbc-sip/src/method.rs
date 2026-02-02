//! SIP request methods per RFC 3261.

use crate::error::{SipError, SipResult};
use std::fmt;
use std::str::FromStr;

/// SIP request methods per RFC 3261 and extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

impl Method {
    /// Returns the method string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
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
        matches!(self, Self::Invite | Self::Update | Self::Subscribe | Self::Notify | Self::Refer)
    }

    /// Returns true if this method requires body.
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
        )
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Method {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        match s.to_uppercase().as_str() {
            "INVITE" => Ok(Self::Invite),
            "ACK" => Ok(Self::Ack),
            "BYE" => Ok(Self::Bye),
            "CANCEL" => Ok(Self::Cancel),
            "REGISTER" => Ok(Self::Register),
            "OPTIONS" => Ok(Self::Options),
            "PRACK" => Ok(Self::Prack),
            "SUBSCRIBE" => Ok(Self::Subscribe),
            "NOTIFY" => Ok(Self::Notify),
            "PUBLISH" => Ok(Self::Publish),
            "INFO" => Ok(Self::Info),
            "REFER" => Ok(Self::Refer),
            "MESSAGE" => Ok(Self::Message),
            "UPDATE" => Ok(Self::Update),
            _ => Err(SipError::InvalidMethod {
                method: s.to_string(),
            }),
        }
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
    fn test_method_from_str_invalid() {
        let result = "INVALID".parse::<Method>();
        assert!(matches!(result, Err(SipError::InvalidMethod { .. })));
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
}
