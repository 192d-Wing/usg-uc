//! SIP response status codes per RFC 3261.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All functions have bounded execution
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::error::{SipError, SipResult};
use std::fmt;

/// SIP response status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    // 1xx Provisional
    /// 100 Trying.
    pub const TRYING: Self = Self(100);
    /// 180 Ringing.
    pub const RINGING: Self = Self(180);
    /// 181 Call Is Being Forwarded.
    pub const CALL_IS_BEING_FORWARDED: Self = Self(181);
    /// 182 Queued.
    pub const QUEUED: Self = Self(182);
    /// 183 Session Progress.
    pub const SESSION_PROGRESS: Self = Self(183);

    // 2xx Success
    /// 200 OK.
    pub const OK: Self = Self(200);
    /// 202 Accepted.
    pub const ACCEPTED: Self = Self(202);

    // 3xx Redirection
    /// 300 Multiple Choices.
    pub const MULTIPLE_CHOICES: Self = Self(300);
    /// 301 Moved Permanently.
    pub const MOVED_PERMANENTLY: Self = Self(301);
    /// 302 Moved Temporarily.
    pub const MOVED_TEMPORARILY: Self = Self(302);

    // 4xx Client Error
    /// 400 Bad Request.
    pub const BAD_REQUEST: Self = Self(400);
    /// 401 Unauthorized.
    pub const UNAUTHORIZED: Self = Self(401);
    /// 403 Forbidden.
    pub const FORBIDDEN: Self = Self(403);
    /// 404 Not Found.
    pub const NOT_FOUND: Self = Self(404);
    /// 405 Method Not Allowed.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// 406 Not Acceptable.
    pub const NOT_ACCEPTABLE: Self = Self(406);
    /// 407 Proxy Authentication Required.
    pub const PROXY_AUTHENTICATION_REQUIRED: Self = Self(407);
    /// 408 Request Timeout.
    pub const REQUEST_TIMEOUT: Self = Self(408);
    /// 410 Gone.
    pub const GONE: Self = Self(410);
    /// 413 Request Entity Too Large.
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self(413);
    /// 414 Request-URI Too Long.
    pub const REQUEST_URI_TOO_LONG: Self = Self(414);
    /// 415 Unsupported Media Type.
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    /// 420 Bad Extension.
    pub const BAD_EXTENSION: Self = Self(420);
    /// 421 Extension Required.
    pub const EXTENSION_REQUIRED: Self = Self(421);
    /// 423 Interval Too Brief.
    pub const INTERVAL_TOO_BRIEF: Self = Self(423);
    /// 480 Temporarily Unavailable.
    pub const TEMPORARILY_UNAVAILABLE: Self = Self(480);
    /// 481 Call/Transaction Does Not Exist.
    pub const CALL_DOES_NOT_EXIST: Self = Self(481);
    /// 482 Loop Detected.
    pub const LOOP_DETECTED: Self = Self(482);
    /// 483 Too Many Hops.
    pub const TOO_MANY_HOPS: Self = Self(483);
    /// 484 Address Incomplete.
    pub const ADDRESS_INCOMPLETE: Self = Self(484);
    /// 485 Ambiguous.
    pub const AMBIGUOUS: Self = Self(485);
    /// 486 Busy Here.
    pub const BUSY_HERE: Self = Self(486);
    /// 487 Request Terminated.
    pub const REQUEST_TERMINATED: Self = Self(487);
    /// 488 Not Acceptable Here.
    pub const NOT_ACCEPTABLE_HERE: Self = Self(488);
    /// 489 Bad Event.
    pub const BAD_EVENT: Self = Self(489);
    /// 491 Request Pending.
    pub const REQUEST_PENDING: Self = Self(491);
    /// 493 Undecipherable.
    pub const UNDECIPHERABLE: Self = Self(493);

    // 5xx Server Error
    /// 500 Server Internal Error.
    pub const SERVER_INTERNAL_ERROR: Self = Self(500);
    /// 501 Not Implemented.
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// 502 Bad Gateway.
    pub const BAD_GATEWAY: Self = Self(502);
    /// 503 Service Unavailable.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// 504 Server Time-out.
    pub const SERVER_TIMEOUT: Self = Self(504);
    /// 505 Version Not Supported.
    pub const VERSION_NOT_SUPPORTED: Self = Self(505);
    /// 513 Message Too Large.
    pub const MESSAGE_TOO_LARGE: Self = Self(513);

    // 6xx Global Failure
    /// 600 Busy Everywhere.
    pub const BUSY_EVERYWHERE: Self = Self(600);
    /// 603 Decline.
    pub const DECLINE: Self = Self(603);
    /// 604 Does Not Exist Anywhere.
    pub const DOES_NOT_EXIST_ANYWHERE: Self = Self(604);
    /// 606 Not Acceptable.
    pub const NOT_ACCEPTABLE_GLOBAL: Self = Self(606);

    /// Creates a new status code.
    ///
    /// ## Errors
    ///
    /// Returns an error if the code is not in valid range (100-699).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(code: u16) -> SipResult<Self> {
        if !(100..=699).contains(&code) {
            return Err(SipError::InvalidStatusCode { code });
        }

        // Power of 10 Rule 5: Assert post-condition after validation
        debug_assert!(
            (100..=699).contains(&code),
            "validated status code should be in range"
        );

        Ok(Self(code))
    }

    /// Returns the numeric code.
    #[must_use]
    pub fn code(&self) -> u16 {
        self.0
    }

    /// Returns true if this is a provisional response (1xx).
    #[must_use]
    pub fn is_provisional(&self) -> bool {
        (100..200).contains(&self.0)
    }

    /// Returns true if this is a success response (2xx).
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// Returns true if this is a redirect response (3xx).
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.0)
    }

    /// Returns true if this is a client error (4xx).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// Returns true if this is a server error (5xx).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }

    /// Returns true if this is a global failure (6xx).
    #[must_use]
    pub fn is_global_failure(&self) -> bool {
        (600..700).contains(&self.0)
    }

    /// Returns true if this is a final response (>= 200).
    #[must_use]
    pub fn is_final(&self) -> bool {
        self.0 >= 200
    }

    /// Returns the reason phrase for common status codes.
    #[must_use]
    pub fn reason_phrase(&self) -> &'static str {
        match self.0 {
            100 => "Trying",
            180 => "Ringing",
            181 => "Call Is Being Forwarded",
            182 => "Queued",
            183 => "Session Progress",
            200 => "OK",
            202 => "Accepted",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Moved Temporarily",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            410 => "Gone",
            413 => "Request Entity Too Large",
            414 => "Request-URI Too Long",
            415 => "Unsupported Media Type",
            420 => "Bad Extension",
            421 => "Extension Required",
            423 => "Interval Too Brief",
            480 => "Temporarily Unavailable",
            481 => "Call/Transaction Does Not Exist",
            482 => "Loop Detected",
            483 => "Too Many Hops",
            484 => "Address Incomplete",
            485 => "Ambiguous",
            486 => "Busy Here",
            487 => "Request Terminated",
            488 => "Not Acceptable Here",
            489 => "Bad Event",
            491 => "Request Pending",
            493 => "Undecipherable",
            500 => "Server Internal Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Server Time-out",
            505 => "Version Not Supported",
            513 => "Message Too Large",
            600 => "Busy Everywhere",
            603 => "Decline",
            604 => "Does Not Exist Anywhere",
            606 => "Not Acceptable (Global)",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason_phrase())
    }
}

impl From<StatusCode> for u16 {
    fn from(status: StatusCode) -> Self {
        status.0
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = SipError;

    fn try_from(code: u16) -> SipResult<Self> {
        Self::new(code)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_categories() {
        assert!(StatusCode::TRYING.is_provisional());
        assert!(!StatusCode::TRYING.is_final());

        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::OK.is_final());

        assert!(StatusCode::MOVED_TEMPORARILY.is_redirect());
        assert!(StatusCode::BAD_REQUEST.is_client_error());
        assert!(StatusCode::SERVER_INTERNAL_ERROR.is_server_error());
        assert!(StatusCode::BUSY_EVERYWHERE.is_global_failure());
    }

    #[test]
    fn test_status_code_display() {
        assert_eq!(format!("{}", StatusCode::OK), "200 OK");
        assert_eq!(format!("{}", StatusCode::RINGING), "180 Ringing");
    }

    #[test]
    fn test_status_code_from_u16() {
        assert_eq!(StatusCode::try_from(200).unwrap(), StatusCode::OK);
        assert!(StatusCode::try_from(99).is_err());
        assert!(StatusCode::try_from(700).is_err());
    }

    #[test]
    fn test_status_code_constants() {
        assert_eq!(StatusCode::OK.code(), 200);
        assert_eq!(StatusCode::RINGING.code(), 180);
        assert_eq!(StatusCode::NOT_FOUND.code(), 404);
    }
}
