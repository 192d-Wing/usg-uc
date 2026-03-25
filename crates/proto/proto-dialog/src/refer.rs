//! RFC 3515 REFER method support for call transfer.
//!
//! The REFER method enables one party to request another to access a
//! URI specified in the Refer-To header. This is commonly used for:
//!
//! - Attended transfer (consultation with transferee first)
//! - Blind transfer (immediate transfer without consultation)
//! - Click-to-dial applications
//!
//! ## RFC 3515 Compliance
//!
//! - REFER creates an implicit subscription to refer status
//! - Refer-To header specifies the transfer target
//! - Referred-By header identifies the referrer
//! - NOTIFY messages report transfer progress
//!
//! ## Subscription States
//!
//! The implicit subscription follows this lifecycle:
//! 1. Pending: REFER received but not processed
//! 2. Active: Transfer in progress, NOTIFY being sent
//! 3. Terminated: Transfer completed or failed

use crate::error::{DialogError, DialogResult};
use std::time::{Duration, Instant};

/// REFER subscription state per RFC 3515.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferSubscriptionState {
    /// REFER received but not yet processed.
    Pending,
    /// Transfer in progress, NOTIFY being sent.
    Active,
    /// Transfer completed or failed.
    Terminated,
}

impl std::fmt::Display for ReferSubscriptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

impl std::str::FromStr for ReferSubscriptionState {
    type Err = DialogError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "terminated" => Ok(Self::Terminated),
            _ => Err(DialogError::InvalidParameter {
                name: "subscription-state".to_string(),
                reason: format!("unknown state: {s}"),
            }),
        }
    }
}

/// REFER transfer status per RFC 3515.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferStatus {
    /// Transfer is in progress.
    Trying,
    /// Transfer target is ringing.
    Ringing,
    /// Transfer completed successfully.
    Success,
    /// Transfer failed.
    Failed,
}

impl ReferStatus {
    /// Returns the SIP status code for this refer status.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Trying => 100,
            Self::Ringing => 180,
            Self::Success => 200,
            Self::Failed => 503,
        }
    }

    /// Creates a refer status from a SIP status code.
    pub fn from_status_code(code: u16) -> Self {
        match code {
            100 => Self::Trying,
            180..=183 => Self::Ringing,
            200..=299 => Self::Success,
            _ => Self::Failed,
        }
    }

    /// Returns true if this is a final status.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Success | Self::Failed)
    }
}

impl std::fmt::Display for ReferStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trying => write!(f, "Trying"),
            Self::Ringing => write!(f, "Ringing"),
            Self::Success => write!(f, "Success"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// REFER request context.
///
/// Tracks the state of an outgoing REFER request.
#[derive(Debug, Clone)]
pub struct ReferRequest {
    /// Refer-To URI.
    refer_to: String,
    /// Referred-By header value (optional).
    referred_by: Option<String>,
    /// When the REFER was sent.
    sent_at: Instant,
    /// Current subscription state.
    subscription_state: ReferSubscriptionState,
    /// Latest status update.
    current_status: Option<ReferStatus>,
    /// Subscription expiration.
    expires: Duration,
    /// Whether norefersub option was requested.
    no_refer_sub: bool,
}

impl ReferRequest {
    /// Creates a new REFER request.
    pub fn new(refer_to: impl Into<String>) -> Self {
        Self {
            refer_to: refer_to.into(),
            referred_by: None,
            sent_at: Instant::now(),
            subscription_state: ReferSubscriptionState::Pending,
            current_status: None,
            expires: Duration::from_secs(180), // Default 3 minutes
            no_refer_sub: false,
        }
    }

    /// Sets the Referred-By header.
    #[must_use]
    pub fn with_referred_by(mut self, referred_by: impl Into<String>) -> Self {
        self.referred_by = Some(referred_by.into());
        self
    }

    /// Sets the subscription expiration.
    #[must_use]
    pub fn with_expires(mut self, expires: Duration) -> Self {
        self.expires = expires;
        self
    }

    /// Sets the norefersub option (no implicit subscription).
    #[must_use]
    pub fn with_no_refer_sub(mut self, no_refer_sub: bool) -> Self {
        self.no_refer_sub = no_refer_sub;
        self
    }

    /// Returns the Refer-To URI.
    pub fn refer_to(&self) -> &str {
        &self.refer_to
    }

    /// Returns the Referred-By header value.
    pub fn referred_by(&self) -> Option<&str> {
        self.referred_by.as_deref()
    }

    /// Returns when the REFER was sent.
    pub fn sent_at(&self) -> Instant {
        self.sent_at
    }

    /// Returns the current subscription state.
    pub fn subscription_state(&self) -> ReferSubscriptionState {
        self.subscription_state
    }

    /// Returns the current status.
    pub fn current_status(&self) -> Option<ReferStatus> {
        self.current_status
    }

    /// Returns the subscription expiration duration.
    pub fn expires(&self) -> Duration {
        self.expires
    }

    /// Returns whether norefersub was requested.
    pub fn no_refer_sub(&self) -> bool {
        self.no_refer_sub
    }

    /// Updates the subscription state.
    pub fn set_subscription_state(&mut self, state: ReferSubscriptionState) {
        self.subscription_state = state;
    }

    /// Updates the status from a NOTIFY.
    pub fn update_status(&mut self, status: ReferStatus) {
        self.current_status = Some(status);
        if status.is_final() {
            self.subscription_state = ReferSubscriptionState::Terminated;
        } else if self.subscription_state == ReferSubscriptionState::Pending {
            self.subscription_state = ReferSubscriptionState::Active;
        }
    }

    /// Checks if the subscription has expired.
    pub fn is_expired(&self) -> bool {
        self.sent_at.elapsed() > self.expires
    }

    /// Checks if the transfer is complete (final status received).
    pub fn is_complete(&self) -> bool {
        self.current_status.is_some_and(|s| s.is_final())
    }

    /// Returns the Refer-To header value for the SIP message.
    pub fn refer_to_header(&self) -> String {
        self.refer_to.clone()
    }

    /// Returns the Referred-By header value for the SIP message.
    pub fn referred_by_header(&self) -> Option<String> {
        self.referred_by.clone()
    }
}

/// Incoming REFER handler.
///
/// Tracks the state of an incoming REFER that needs to be processed.
#[derive(Debug, Clone)]
pub struct ReferHandler {
    /// Refer-To URI from the incoming REFER.
    refer_to: String,
    /// Referred-By URI.
    referred_by: Option<String>,
    /// When the REFER was received.
    received_at: Instant,
    /// Current subscription state.
    subscription_state: ReferSubscriptionState,
    /// Latest status to send.
    current_status: ReferStatus,
    /// Subscription expiration.
    expires: Duration,
    /// CSeq for NOTIFY requests.
    notify_cseq: u32,
}

impl ReferHandler {
    /// Creates a new REFER handler.
    pub fn new(refer_to: impl Into<String>) -> Self {
        Self {
            refer_to: refer_to.into(),
            referred_by: None,
            received_at: Instant::now(),
            subscription_state: ReferSubscriptionState::Pending,
            current_status: ReferStatus::Trying,
            expires: Duration::from_secs(180),
            notify_cseq: 1,
        }
    }

    /// Sets the Referred-By value.
    #[must_use]
    pub fn with_referred_by(mut self, referred_by: impl Into<String>) -> Self {
        self.referred_by = Some(referred_by.into());
        self
    }

    /// Sets the subscription expiration.
    #[must_use]
    pub fn with_expires(mut self, expires: Duration) -> Self {
        self.expires = expires;
        self
    }

    /// Returns the Refer-To URI.
    pub fn refer_to(&self) -> &str {
        &self.refer_to
    }

    /// Returns the Referred-By URI.
    pub fn referred_by(&self) -> Option<&str> {
        self.referred_by.as_deref()
    }

    /// Returns the current status.
    pub fn current_status(&self) -> ReferStatus {
        self.current_status
    }

    /// Returns the subscription state.
    pub fn subscription_state(&self) -> ReferSubscriptionState {
        self.subscription_state
    }

    /// Returns the next NOTIFY CSeq and increments.
    pub fn next_notify_cseq(&mut self) -> u32 {
        let cseq = self.notify_cseq;
        self.notify_cseq += 1;
        cseq
    }

    /// Accepts the REFER (sends 202 Accepted).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn accept(&mut self) -> DialogResult<()> {
        if self.subscription_state != ReferSubscriptionState::Pending {
            return Err(DialogError::InvalidStateTransition {
                from: self.subscription_state.to_string(),
                to: "Active".to_string(),
            });
        }
        self.subscription_state = ReferSubscriptionState::Active;
        Ok(())
    }

    /// Rejects the REFER.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn reject(&mut self) -> DialogResult<()> {
        self.subscription_state = ReferSubscriptionState::Terminated;
        self.current_status = ReferStatus::Failed;
        Ok(())
    }

    /// Updates the transfer status.
    pub fn update_status(&mut self, status: ReferStatus) {
        self.current_status = status;
        if status.is_final() {
            self.subscription_state = ReferSubscriptionState::Terminated;
        }
    }

    /// Checks if the subscription has expired.
    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed() > self.expires
    }

    /// Checks if the transfer is complete.
    pub fn is_complete(&self) -> bool {
        self.current_status.is_final()
    }

    /// Generates the Subscription-State header value.
    pub fn subscription_state_header(&self) -> String {
        match self.subscription_state {
            ReferSubscriptionState::Pending => "pending".to_string(),
            ReferSubscriptionState::Active => {
                let remaining = self.expires.saturating_sub(self.received_at.elapsed());
                format!("active;expires={}", remaining.as_secs())
            }
            ReferSubscriptionState::Terminated => {
                if self.current_status == ReferStatus::Success {
                    "terminated;reason=noresource".to_string()
                } else {
                    "terminated;reason=rejected".to_string()
                }
            }
        }
    }

    /// Generates the NOTIFY body (sipfrag).
    pub fn notify_body(&self) -> String {
        format!(
            "SIP/2.0 {} {}",
            self.current_status.status_code(),
            self.current_status
        )
    }
}

/// Parses a Refer-To header value.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn parse_refer_to(value: &str) -> DialogResult<String> {
    let value = value.trim();
    // Handle <uri> format
    if value.starts_with('<') && value.ends_with('>') {
        Ok(value[1..value.len() - 1].to_string())
    } else if value.contains('<') && value.contains('>') {
        // "Name" <uri> format
        let start = value
            .find('<')
            .ok_or_else(|| DialogError::InvalidParameter {
                name: "Refer-To".to_string(),
                reason: "missing URI".to_string(),
            })?;
        let end = value
            .find('>')
            .ok_or_else(|| DialogError::InvalidParameter {
                name: "Refer-To".to_string(),
                reason: "missing URI".to_string(),
            })?;
        Ok(value[start + 1..end].to_string())
    } else {
        Ok(value.to_string())
    }
}

/// Generates a Refer-To header value.
pub fn format_refer_to(uri: &str, replaces: Option<&str>) -> String {
    replaces.map_or_else(
        || format!("<{uri}>"),
        |replaces| format!("<{uri}>?Replaces={replaces}"),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_refer_status_from_code() {
        assert_eq!(ReferStatus::from_status_code(100), ReferStatus::Trying);
        assert_eq!(ReferStatus::from_status_code(180), ReferStatus::Ringing);
        assert_eq!(ReferStatus::from_status_code(200), ReferStatus::Success);
        assert_eq!(ReferStatus::from_status_code(486), ReferStatus::Failed);
    }

    #[test]
    fn test_refer_status_is_final() {
        assert!(!ReferStatus::Trying.is_final());
        assert!(!ReferStatus::Ringing.is_final());
        assert!(ReferStatus::Success.is_final());
        assert!(ReferStatus::Failed.is_final());
    }

    #[test]
    fn test_refer_request() {
        let request =
            ReferRequest::new("sip:bob@example.com").with_referred_by("sip:alice@example.com");

        assert_eq!(request.refer_to(), "sip:bob@example.com");
        assert_eq!(request.referred_by(), Some("sip:alice@example.com"));
        assert_eq!(
            request.subscription_state(),
            ReferSubscriptionState::Pending
        );
    }

    #[test]
    fn test_refer_request_update_status() {
        let mut request = ReferRequest::new("sip:bob@example.com");

        request.update_status(ReferStatus::Trying);
        assert_eq!(request.subscription_state(), ReferSubscriptionState::Active);
        assert!(!request.is_complete());

        request.update_status(ReferStatus::Success);
        assert_eq!(
            request.subscription_state(),
            ReferSubscriptionState::Terminated
        );
        assert!(request.is_complete());
    }

    #[test]
    fn test_refer_handler() {
        let mut handler = ReferHandler::new("sip:bob@example.com");

        assert_eq!(
            handler.subscription_state(),
            ReferSubscriptionState::Pending
        );

        handler.accept().unwrap();
        assert_eq!(handler.subscription_state(), ReferSubscriptionState::Active);

        handler.update_status(ReferStatus::Ringing);
        assert_eq!(handler.current_status(), ReferStatus::Ringing);
        assert!(!handler.is_complete());

        handler.update_status(ReferStatus::Success);
        assert!(handler.is_complete());
    }

    #[test]
    fn test_refer_handler_notify_body() {
        let mut handler = ReferHandler::new("sip:bob@example.com");
        handler.accept().unwrap();

        handler.update_status(ReferStatus::Ringing);
        assert_eq!(handler.notify_body(), "SIP/2.0 180 Ringing");

        handler.update_status(ReferStatus::Success);
        assert_eq!(handler.notify_body(), "SIP/2.0 200 Success");
    }

    #[test]
    fn test_parse_refer_to() {
        assert_eq!(
            parse_refer_to("<sip:bob@example.com>").unwrap(),
            "sip:bob@example.com"
        );
        assert_eq!(
            parse_refer_to("\"Bob\" <sip:bob@example.com>").unwrap(),
            "sip:bob@example.com"
        );
        assert_eq!(
            parse_refer_to("sip:bob@example.com").unwrap(),
            "sip:bob@example.com"
        );
    }

    #[test]
    fn test_format_refer_to() {
        assert_eq!(
            format_refer_to("sip:bob@example.com", None),
            "<sip:bob@example.com>"
        );
        assert_eq!(
            format_refer_to("sip:bob@example.com", Some("call-id%3Bfrom-tag%3Dto-tag")),
            "<sip:bob@example.com>?Replaces=call-id%3Bfrom-tag%3Dto-tag"
        );
    }

    #[test]
    fn test_subscription_state_parse() {
        assert_eq!(
            "pending".parse::<ReferSubscriptionState>().unwrap(),
            ReferSubscriptionState::Pending
        );
        assert_eq!(
            "active".parse::<ReferSubscriptionState>().unwrap(),
            ReferSubscriptionState::Active
        );
        assert_eq!(
            "terminated".parse::<ReferSubscriptionState>().unwrap(),
            ReferSubscriptionState::Terminated
        );
    }

    #[test]
    fn test_refer_handler_cseq() {
        let mut handler = ReferHandler::new("sip:bob@example.com");
        assert_eq!(handler.next_notify_cseq(), 1);
        assert_eq!(handler.next_notify_cseq(), 2);
        assert_eq!(handler.next_notify_cseq(), 3);
    }

    // Additional tests for improved coverage

    #[test]
    fn test_subscription_state_display() {
        assert_eq!(format!("{}", ReferSubscriptionState::Pending), "pending");
        assert_eq!(format!("{}", ReferSubscriptionState::Active), "active");
        assert_eq!(
            format!("{}", ReferSubscriptionState::Terminated),
            "terminated"
        );
    }

    #[test]
    fn test_subscription_state_parse_case_insensitive() {
        assert_eq!(
            "PENDING".parse::<ReferSubscriptionState>().unwrap(),
            ReferSubscriptionState::Pending
        );
        assert_eq!(
            "Active".parse::<ReferSubscriptionState>().unwrap(),
            ReferSubscriptionState::Active
        );
        assert_eq!(
            "TERMINATED".parse::<ReferSubscriptionState>().unwrap(),
            ReferSubscriptionState::Terminated
        );
    }

    #[test]
    fn test_subscription_state_parse_invalid() {
        let result = "invalid".parse::<ReferSubscriptionState>();
        assert!(
            matches!(result, Err(DialogError::InvalidParameter { name, reason })
            if name == "subscription-state" && reason.contains("unknown state"))
        );
    }

    #[test]
    fn test_refer_status_status_code() {
        assert_eq!(ReferStatus::Trying.status_code(), 100);
        assert_eq!(ReferStatus::Ringing.status_code(), 180);
        assert_eq!(ReferStatus::Success.status_code(), 200);
        assert_eq!(ReferStatus::Failed.status_code(), 503);
    }

    #[test]
    fn test_refer_status_display() {
        assert_eq!(format!("{}", ReferStatus::Trying), "Trying");
        assert_eq!(format!("{}", ReferStatus::Ringing), "Ringing");
        assert_eq!(format!("{}", ReferStatus::Success), "Success");
        assert_eq!(format!("{}", ReferStatus::Failed), "Failed");
    }

    #[test]
    fn test_refer_status_from_code_ranges() {
        // Test 180-183 range for ringing
        assert_eq!(ReferStatus::from_status_code(181), ReferStatus::Ringing);
        assert_eq!(ReferStatus::from_status_code(183), ReferStatus::Ringing);

        // Test 200-299 range for success
        assert_eq!(ReferStatus::from_status_code(202), ReferStatus::Success);
        assert_eq!(ReferStatus::from_status_code(299), ReferStatus::Success);

        // Test other codes as failed
        assert_eq!(ReferStatus::from_status_code(400), ReferStatus::Failed);
        assert_eq!(ReferStatus::from_status_code(500), ReferStatus::Failed);
        assert_eq!(ReferStatus::from_status_code(603), ReferStatus::Failed);
    }

    #[test]
    fn test_refer_request_with_expires() {
        let request =
            ReferRequest::new("sip:bob@example.com").with_expires(Duration::from_secs(300));
        assert_eq!(request.expires(), Duration::from_secs(300));
    }

    #[test]
    fn test_refer_request_with_no_refer_sub() {
        let request = ReferRequest::new("sip:bob@example.com").with_no_refer_sub(true);
        assert!(request.no_refer_sub());

        let request2 = ReferRequest::new("sip:bob@example.com").with_no_refer_sub(false);
        assert!(!request2.no_refer_sub());
    }

    #[test]
    fn test_refer_request_default_values() {
        let request = ReferRequest::new("sip:bob@example.com");
        assert_eq!(request.refer_to(), "sip:bob@example.com");
        assert!(request.referred_by().is_none());
        assert_eq!(
            request.subscription_state(),
            ReferSubscriptionState::Pending
        );
        assert!(request.current_status().is_none());
        assert_eq!(request.expires(), Duration::from_secs(180));
        assert!(!request.no_refer_sub());
    }

    #[test]
    fn test_refer_request_sent_at() {
        let before = Instant::now();
        let request = ReferRequest::new("sip:bob@example.com");
        let after = Instant::now();

        assert!(request.sent_at() >= before);
        assert!(request.sent_at() <= after);
    }

    #[test]
    fn test_refer_request_set_subscription_state() {
        let mut request = ReferRequest::new("sip:bob@example.com");
        assert_eq!(
            request.subscription_state(),
            ReferSubscriptionState::Pending
        );

        request.set_subscription_state(ReferSubscriptionState::Active);
        assert_eq!(request.subscription_state(), ReferSubscriptionState::Active);

        request.set_subscription_state(ReferSubscriptionState::Terminated);
        assert_eq!(
            request.subscription_state(),
            ReferSubscriptionState::Terminated
        );
    }

    #[test]
    fn test_refer_request_headers() {
        let request =
            ReferRequest::new("sip:bob@example.com").with_referred_by("sip:alice@example.com");

        assert_eq!(request.refer_to_header(), "sip:bob@example.com");
        assert_eq!(
            request.referred_by_header(),
            Some("sip:alice@example.com".to_string())
        );
    }

    #[test]
    fn test_refer_request_headers_no_referred_by() {
        let request = ReferRequest::new("sip:bob@example.com");
        assert_eq!(request.refer_to_header(), "sip:bob@example.com");
        assert!(request.referred_by_header().is_none());
    }

    #[test]
    fn test_refer_request_update_status_from_active() {
        let mut request = ReferRequest::new("sip:bob@example.com");
        request.set_subscription_state(ReferSubscriptionState::Active);

        // Update status when already active should stay active (for non-final)
        request.update_status(ReferStatus::Ringing);
        assert_eq!(request.subscription_state(), ReferSubscriptionState::Active);
        assert_eq!(request.current_status(), Some(ReferStatus::Ringing));
    }

    #[test]
    fn test_refer_request_update_status_to_failed() {
        let mut request = ReferRequest::new("sip:bob@example.com");

        request.update_status(ReferStatus::Failed);
        assert_eq!(
            request.subscription_state(),
            ReferSubscriptionState::Terminated
        );
        assert!(request.is_complete());
    }

    #[test]
    fn test_refer_request_is_complete_without_status() {
        let request = ReferRequest::new("sip:bob@example.com");
        assert!(!request.is_complete());
    }

    #[test]
    fn test_refer_request_clone() {
        let request = ReferRequest::new("sip:bob@example.com")
            .with_referred_by("sip:alice@example.com")
            .with_expires(Duration::from_secs(60));

        let cloned = request.clone();
        assert_eq!(cloned.refer_to(), request.refer_to());
        assert_eq!(cloned.referred_by(), request.referred_by());
        assert_eq!(cloned.expires(), request.expires());
    }

    #[test]
    fn test_refer_handler_with_referred_by() {
        let handler =
            ReferHandler::new("sip:bob@example.com").with_referred_by("sip:alice@example.com");
        assert_eq!(handler.referred_by(), Some("sip:alice@example.com"));
    }

    #[test]
    fn test_refer_handler_with_expires() {
        let handler =
            ReferHandler::new("sip:bob@example.com").with_expires(Duration::from_secs(60));
        // Can't directly check expires, but we can verify it was set
        // by checking subscription_state_header when active
        let mut handler = handler;
        handler.accept().unwrap();
        let header = handler.subscription_state_header();
        assert!(header.starts_with("active;expires="));
    }

    #[test]
    fn test_refer_handler_reject() {
        let mut handler = ReferHandler::new("sip:bob@example.com");
        handler.reject().unwrap();

        assert_eq!(
            handler.subscription_state(),
            ReferSubscriptionState::Terminated
        );
        assert_eq!(handler.current_status(), ReferStatus::Failed);
        assert!(handler.is_complete());
    }

    #[test]
    fn test_refer_handler_accept_invalid_state() {
        let mut handler = ReferHandler::new("sip:bob@example.com");
        handler.accept().unwrap();

        // Trying to accept again should fail
        let result = handler.accept();
        assert!(matches!(
            result,
            Err(DialogError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn test_refer_handler_subscription_state_header_pending() {
        let handler = ReferHandler::new("sip:bob@example.com");
        assert_eq!(handler.subscription_state_header(), "pending");
    }

    #[test]
    fn test_refer_handler_subscription_state_header_terminated_success() {
        let mut handler = ReferHandler::new("sip:bob@example.com");
        handler.accept().unwrap();
        handler.update_status(ReferStatus::Success);

        assert_eq!(
            handler.subscription_state_header(),
            "terminated;reason=noresource"
        );
    }

    #[test]
    fn test_refer_handler_subscription_state_header_terminated_failed() {
        let mut handler = ReferHandler::new("sip:bob@example.com");
        handler.reject().unwrap();

        assert_eq!(
            handler.subscription_state_header(),
            "terminated;reason=rejected"
        );
    }

    #[test]
    fn test_refer_handler_notify_body_trying() {
        let handler = ReferHandler::new("sip:bob@example.com");
        assert_eq!(handler.notify_body(), "SIP/2.0 100 Trying");
    }

    #[test]
    fn test_refer_handler_notify_body_failed() {
        let mut handler = ReferHandler::new("sip:bob@example.com");
        handler.update_status(ReferStatus::Failed);
        assert_eq!(handler.notify_body(), "SIP/2.0 503 Failed");
    }

    #[test]
    fn test_refer_handler_clone() {
        let handler =
            ReferHandler::new("sip:bob@example.com").with_referred_by("sip:alice@example.com");

        let cloned = handler.clone();
        assert_eq!(cloned.refer_to(), handler.refer_to());
        assert_eq!(cloned.referred_by(), handler.referred_by());
    }

    #[test]
    fn test_refer_handler_debug() {
        let handler = ReferHandler::new("sip:bob@example.com");
        let debug_str = format!("{handler:?}");
        assert!(debug_str.contains("ReferHandler"));
        assert!(debug_str.contains("sip:bob@example.com"));
    }

    #[test]
    fn test_refer_request_debug() {
        let request = ReferRequest::new("sip:bob@example.com");
        let debug_str = format!("{request:?}");
        assert!(debug_str.contains("ReferRequest"));
        assert!(debug_str.contains("sip:bob@example.com"));
    }

    #[test]
    fn test_parse_refer_to_with_whitespace() {
        assert_eq!(
            parse_refer_to("  <sip:bob@example.com>  ").unwrap(),
            "sip:bob@example.com"
        );
    }

    #[test]
    fn test_subscription_state_copy() {
        let state = ReferSubscriptionState::Active;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_refer_status_copy() {
        let status = ReferStatus::Ringing;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn test_subscription_state_eq() {
        assert_eq!(
            ReferSubscriptionState::Pending,
            ReferSubscriptionState::Pending
        );
        assert_ne!(
            ReferSubscriptionState::Pending,
            ReferSubscriptionState::Active
        );
    }

    #[test]
    fn test_refer_status_eq() {
        assert_eq!(ReferStatus::Trying, ReferStatus::Trying);
        assert_ne!(ReferStatus::Trying, ReferStatus::Ringing);
    }
}
