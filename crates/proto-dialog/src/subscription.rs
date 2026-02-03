//! RFC 6665 - SIP-Specific Event Notification Framework.
//!
//! This module implements the SIP event notification framework for
//! SUBSCRIBE/NOTIFY dialogs per RFC 6665.
//!
//! ## RFC 6665 Overview
//!
//! - SUBSCRIBE creates a subscription to an event package
//! - NOTIFY delivers event state to subscribers
//! - Subscriptions have an expiration and can be refreshed
//! - Subscription states: pending, active, terminated
//!
//! ## Common Event Packages
//!
//! - `presence` (RFC 3856) - User presence
//! - `dialog` (RFC 4235) - Dialog state
//! - `message-summary` (RFC 3842) - Message waiting indication
//! - `refer` (RFC 3515) - REFER implicit subscription
//! - `reg` (RFC 3680) - Registration state

use std::time::{Duration, Instant};

/// Default subscription expiration (3600 seconds per RFC 6665).
pub const DEFAULT_SUBSCRIPTION_EXPIRES: u32 = 3600;

/// Minimum subscription expiration (60 seconds).
pub const MIN_SUBSCRIPTION_EXPIRES: u32 = 60;

/// Subscription state per RFC 6665 Section 4.1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Subscription is being established (awaiting authorization).
    Pending,
    /// Subscription is active and authorized.
    Active,
    /// Subscription has been terminated.
    Terminated,
}

impl std::fmt::Display for SubscriptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

/// Termination reason per RFC 6665 Section 4.1.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    /// Subscription was deactivated (no longer authorized).
    Deactivated,
    /// Subscription expired due to timeout.
    Timeout,
    /// Subscription was explicitly terminated by subscriber.
    Unsubscribed,
    /// Resource no longer exists.
    NoResource,
    /// Subscription rejected due to policy.
    Rejected,
    /// Internal error occurred.
    InternalError,
    /// Subscription was terminated for an unspecified reason.
    Other(String),
}

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deactivated => write!(f, "deactivated"),
            Self::Timeout => write!(f, "timeout"),
            Self::Unsubscribed => write!(f, "unsubscribed"),
            Self::NoResource => write!(f, "noresource"),
            Self::Rejected => write!(f, "rejected"),
            Self::InternalError => write!(f, "probation"),
            Self::Other(reason) => write!(f, "{}", reason),
        }
    }
}

impl TerminationReason {
    /// Parses a termination reason from a string.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "deactivated" => Self::Deactivated,
            "timeout" => Self::Timeout,
            "unsubscribed" => Self::Unsubscribed,
            "noresource" => Self::NoResource,
            "rejected" => Self::Rejected,
            "probation" => Self::InternalError,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Event package identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventPackage {
    /// Event type (e.g., "presence", "dialog", "message-summary").
    pub event_type: String,
    /// Event ID parameter (for multiple subscriptions to same event).
    pub id: Option<String>,
}

impl EventPackage {
    /// Creates a new event package.
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            id: None,
        }
    }

    /// Creates an event package with an ID.
    pub fn with_id(event_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            id: Some(id.into()),
        }
    }

    /// Presence event package (RFC 3856).
    pub fn presence() -> Self {
        Self::new("presence")
    }

    /// Dialog event package (RFC 4235).
    pub fn dialog() -> Self {
        Self::new("dialog")
    }

    /// Message summary event package (RFC 3842).
    pub fn message_summary() -> Self {
        Self::new("message-summary")
    }

    /// Refer event package (RFC 3515).
    pub fn refer() -> Self {
        Self::new("refer")
    }

    /// Registration event package (RFC 3680).
    pub fn reg() -> Self {
        Self::new("reg")
    }

    /// Formats as Event header value.
    pub fn to_header_value(&self) -> String {
        match &self.id {
            Some(id) => format!("{};id={}", self.event_type, id),
            None => self.event_type.clone(),
        }
    }

    /// Parses from Event header value.
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split(';').collect();
        if parts.is_empty() {
            return None;
        }

        let event_type = parts[0].trim().to_string();
        let mut id = None;

        for part in &parts[1..] {
            let param = part.trim();
            if let Some(id_value) = param.strip_prefix("id=") {
                id = Some(id_value.trim().to_string());
            }
        }

        Some(Self { event_type, id })
    }
}

impl std::fmt::Display for EventPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Subscription-State header value per RFC 6665.
#[derive(Debug, Clone)]
pub struct SubscriptionStateHeader {
    /// Current state.
    pub state: SubscriptionState,
    /// Termination reason (only for terminated state).
    pub reason: Option<TerminationReason>,
    /// Time until subscription expires (for active/pending).
    pub expires: Option<u32>,
    /// Retry-after hint (for terminated due to error).
    pub retry_after: Option<u32>,
}

impl SubscriptionStateHeader {
    /// Creates an active subscription state.
    pub fn active(expires: u32) -> Self {
        Self {
            state: SubscriptionState::Active,
            reason: None,
            expires: Some(expires),
            retry_after: None,
        }
    }

    /// Creates a pending subscription state.
    pub fn pending(expires: u32) -> Self {
        Self {
            state: SubscriptionState::Pending,
            reason: None,
            expires: Some(expires),
            retry_after: None,
        }
    }

    /// Creates a terminated subscription state.
    pub fn terminated(reason: TerminationReason) -> Self {
        Self {
            state: SubscriptionState::Terminated,
            reason: Some(reason),
            expires: None,
            retry_after: None,
        }
    }

    /// Creates a terminated state with retry-after hint.
    pub fn terminated_with_retry(reason: TerminationReason, retry_after: u32) -> Self {
        Self {
            state: SubscriptionState::Terminated,
            reason: Some(reason),
            expires: None,
            retry_after: Some(retry_after),
        }
    }

    /// Formats as Subscription-State header value.
    pub fn to_header_value(&self) -> String {
        let mut value = self.state.to_string();

        if let Some(ref reason) = self.reason {
            value.push_str(&format!(";reason={}", reason));
        }

        if let Some(expires) = self.expires {
            value.push_str(&format!(";expires={}", expires));
        }

        if let Some(retry_after) = self.retry_after {
            value.push_str(&format!(";retry-after={}", retry_after));
        }

        value
    }

    /// Parses from Subscription-State header value.
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split(';').collect();
        if parts.is_empty() {
            return None;
        }

        let state = match parts[0].trim().to_lowercase().as_str() {
            "pending" => SubscriptionState::Pending,
            "active" => SubscriptionState::Active,
            "terminated" => SubscriptionState::Terminated,
            _ => return None,
        };

        let mut reason = None;
        let mut expires = None;
        let mut retry_after = None;

        for part in &parts[1..] {
            let param = part.trim();
            if let Some(r) = param.strip_prefix("reason=") {
                reason = Some(TerminationReason::parse(r));
            } else if let Some(e) = param.strip_prefix("expires=") {
                expires = e.parse().ok();
            } else if let Some(ra) = param.strip_prefix("retry-after=") {
                retry_after = ra.parse().ok();
            }
        }

        Some(Self {
            state,
            reason,
            expires,
            retry_after,
        })
    }
}

impl std::fmt::Display for SubscriptionStateHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// A SIP event subscription (subscriber side).
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Subscription ID (dialog ID).
    id: String,
    /// Event package.
    event: EventPackage,
    /// Current state.
    state: SubscriptionState,
    /// Expiration time in seconds.
    expires: u32,
    /// When the subscription was created.
    created_at: Instant,
    /// When the subscription was last refreshed.
    refreshed_at: Instant,
    /// Resource URI (what we're subscribed to).
    resource_uri: String,
    /// Subscriber URI (who we are).
    subscriber_uri: String,
    /// Termination reason if terminated.
    termination_reason: Option<TerminationReason>,
}

impl Subscription {
    /// Creates a new subscription.
    pub fn new(
        id: impl Into<String>,
        event: EventPackage,
        resource_uri: impl Into<String>,
        subscriber_uri: impl Into<String>,
        expires: u32,
    ) -> Self {
        let now = Instant::now();
        Self {
            id: id.into(),
            event,
            state: SubscriptionState::Pending,
            expires,
            created_at: now,
            refreshed_at: now,
            resource_uri: resource_uri.into(),
            subscriber_uri: subscriber_uri.into(),
            termination_reason: None,
        }
    }

    /// Returns the subscription ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the event package.
    pub fn event(&self) -> &EventPackage {
        &self.event
    }

    /// Returns the current state.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    /// Returns the expiration time in seconds.
    pub fn expires(&self) -> u32 {
        self.expires
    }

    /// Returns the resource URI.
    pub fn resource_uri(&self) -> &str {
        &self.resource_uri
    }

    /// Returns the subscriber URI.
    pub fn subscriber_uri(&self) -> &str {
        &self.subscriber_uri
    }

    /// Returns the termination reason if terminated.
    pub fn termination_reason(&self) -> Option<&TerminationReason> {
        self.termination_reason.as_ref()
    }

    /// Returns when the subscription was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Activates the subscription (authorization granted).
    pub fn activate(&mut self) {
        if self.state == SubscriptionState::Pending {
            self.state = SubscriptionState::Active;
        }
    }

    /// Refreshes the subscription with a new expiration.
    pub fn refresh(&mut self, expires: u32) {
        self.expires = expires;
        self.refreshed_at = Instant::now();
    }

    /// Terminates the subscription.
    pub fn terminate(&mut self, reason: TerminationReason) {
        self.state = SubscriptionState::Terminated;
        self.termination_reason = Some(reason);
    }

    /// Returns time remaining until expiration.
    pub fn time_remaining(&self) -> Duration {
        let expires = Duration::from_secs(self.expires as u64);
        let elapsed = self.refreshed_at.elapsed();

        if elapsed >= expires {
            Duration::ZERO
        } else {
            expires - elapsed
        }
    }

    /// Returns remaining seconds until expiration.
    pub fn remaining_seconds(&self) -> u32 {
        self.time_remaining().as_secs() as u32
    }

    /// Checks if the subscription has expired.
    pub fn is_expired(&self) -> bool {
        self.state == SubscriptionState::Terminated || self.time_remaining() == Duration::ZERO
    }

    /// Checks if the subscription is active.
    pub fn is_active(&self) -> bool {
        self.state == SubscriptionState::Active && !self.is_expired()
    }

    /// Processes a NOTIFY with Subscription-State header.
    pub fn process_notify(&mut self, state_header: &SubscriptionStateHeader) {
        self.state = state_header.state;

        if let Some(expires) = state_header.expires {
            self.refresh(expires);
        }

        if let Some(ref reason) = state_header.reason {
            self.termination_reason = Some(reason.clone());
        }
    }
}

/// A subscription notifier (server side).
#[derive(Debug, Clone)]
pub struct Notifier {
    /// Subscription ID.
    id: String,
    /// Event package.
    event: EventPackage,
    /// Current state.
    state: SubscriptionState,
    /// Expiration time in seconds.
    expires: u32,
    /// When the subscription was created.
    created_at: Instant,
    /// When the subscription was last refreshed.
    refreshed_at: Instant,
    /// Subscriber URI (who is subscribed).
    subscriber_uri: String,
    /// Resource URI (what they're subscribed to).
    resource_uri: String,
    /// Number of NOTIFYs sent.
    notify_count: u32,
    /// Whether a final NOTIFY has been sent.
    final_notify_sent: bool,
}

impl Notifier {
    /// Creates a new notifier for a subscription.
    pub fn new(
        id: impl Into<String>,
        event: EventPackage,
        subscriber_uri: impl Into<String>,
        resource_uri: impl Into<String>,
        expires: u32,
    ) -> Self {
        let now = Instant::now();
        Self {
            id: id.into(),
            event,
            state: SubscriptionState::Pending,
            expires,
            created_at: now,
            refreshed_at: now,
            subscriber_uri: subscriber_uri.into(),
            resource_uri: resource_uri.into(),
            notify_count: 0,
            final_notify_sent: false,
        }
    }

    /// Returns the subscription ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the event package.
    pub fn event(&self) -> &EventPackage {
        &self.event
    }

    /// Returns the current state.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    /// Returns the subscriber URI.
    pub fn subscriber_uri(&self) -> &str {
        &self.subscriber_uri
    }

    /// Returns the resource URI.
    pub fn resource_uri(&self) -> &str {
        &self.resource_uri
    }

    /// Returns the NOTIFY count.
    pub fn notify_count(&self) -> u32 {
        self.notify_count
    }

    /// Returns when the subscription was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Activates the subscription (authorize it).
    pub fn activate(&mut self) {
        self.state = SubscriptionState::Active;
    }

    /// Rejects the subscription.
    pub fn reject(&mut self) {
        self.state = SubscriptionState::Terminated;
    }

    /// Refreshes the subscription.
    pub fn refresh(&mut self, expires: u32) {
        self.expires = expires;
        self.refreshed_at = Instant::now();
    }

    /// Returns remaining seconds until expiration.
    pub fn remaining_seconds(&self) -> u32 {
        let expires = Duration::from_secs(self.expires as u64);
        let elapsed = self.refreshed_at.elapsed();

        if elapsed >= expires {
            0
        } else {
            (expires - elapsed).as_secs() as u32
        }
    }

    /// Checks if expired.
    pub fn is_expired(&self) -> bool {
        self.remaining_seconds() == 0
    }

    /// Generates the Subscription-State header for a NOTIFY.
    pub fn generate_state_header(&self) -> SubscriptionStateHeader {
        match self.state {
            SubscriptionState::Pending => SubscriptionStateHeader::pending(self.remaining_seconds()),
            SubscriptionState::Active => SubscriptionStateHeader::active(self.remaining_seconds()),
            SubscriptionState::Terminated => {
                SubscriptionStateHeader::terminated(TerminationReason::Timeout)
            }
        }
    }

    /// Records that a NOTIFY was sent.
    pub fn record_notify(&mut self) {
        self.notify_count += 1;
    }

    /// Terminates the subscription and marks for final NOTIFY.
    pub fn terminate(&mut self, reason: TerminationReason) -> SubscriptionStateHeader {
        self.state = SubscriptionState::Terminated;
        self.final_notify_sent = true;
        SubscriptionStateHeader::terminated(reason)
    }

    /// Checks if final NOTIFY has been sent.
    pub fn is_final_notify_sent(&self) -> bool {
        self.final_notify_sent
    }
}

/// Parses the Allow-Events header.
pub fn parse_allow_events(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Formats the Allow-Events header.
pub fn format_allow_events(events: &[String]) -> String {
    events.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_state_display() {
        assert_eq!(SubscriptionState::Pending.to_string(), "pending");
        assert_eq!(SubscriptionState::Active.to_string(), "active");
        assert_eq!(SubscriptionState::Terminated.to_string(), "terminated");
    }

    #[test]
    fn test_termination_reason_display() {
        assert_eq!(TerminationReason::Timeout.to_string(), "timeout");
        assert_eq!(TerminationReason::Unsubscribed.to_string(), "unsubscribed");
        assert_eq!(TerminationReason::NoResource.to_string(), "noresource");
    }

    #[test]
    fn test_termination_reason_parse() {
        assert_eq!(
            TerminationReason::parse("timeout"),
            TerminationReason::Timeout
        );
        assert_eq!(
            TerminationReason::parse("TIMEOUT"),
            TerminationReason::Timeout
        );
    }

    #[test]
    fn test_event_package_creation() {
        let presence = EventPackage::presence();
        assert_eq!(presence.event_type, "presence");
        assert!(presence.id.is_none());

        let dialog = EventPackage::with_id("dialog", "abc123");
        assert_eq!(dialog.event_type, "dialog");
        assert_eq!(dialog.id, Some("abc123".to_string()));
    }

    #[test]
    fn test_event_package_to_header() {
        let presence = EventPackage::presence();
        assert_eq!(presence.to_header_value(), "presence");

        let dialog = EventPackage::with_id("dialog", "abc123");
        assert_eq!(dialog.to_header_value(), "dialog;id=abc123");
    }

    #[test]
    fn test_event_package_parse() {
        let presence = EventPackage::parse("presence").unwrap();
        assert_eq!(presence.event_type, "presence");
        assert!(presence.id.is_none());

        let dialog = EventPackage::parse("dialog;id=abc123").unwrap();
        assert_eq!(dialog.event_type, "dialog");
        assert_eq!(dialog.id, Some("abc123".to_string()));
    }

    #[test]
    fn test_subscription_state_header_active() {
        let header = SubscriptionStateHeader::active(3600);
        assert_eq!(header.state, SubscriptionState::Active);
        assert_eq!(header.expires, Some(3600));
        assert_eq!(header.to_header_value(), "active;expires=3600");
    }

    #[test]
    fn test_subscription_state_header_terminated() {
        let header = SubscriptionStateHeader::terminated(TerminationReason::Timeout);
        assert_eq!(header.state, SubscriptionState::Terminated);
        assert_eq!(header.to_header_value(), "terminated;reason=timeout");
    }

    #[test]
    fn test_subscription_state_header_parse() {
        let header = SubscriptionStateHeader::parse("active;expires=3600").unwrap();
        assert_eq!(header.state, SubscriptionState::Active);
        assert_eq!(header.expires, Some(3600));

        let header = SubscriptionStateHeader::parse("terminated;reason=timeout").unwrap();
        assert_eq!(header.state, SubscriptionState::Terminated);
        assert!(matches!(
            header.reason,
            Some(TerminationReason::Timeout)
        ));
    }

    #[test]
    fn test_subscription_creation() {
        let sub = Subscription::new(
            "sub-123",
            EventPackage::presence(),
            "sip:alice@example.com",
            "sip:bob@example.com",
            3600,
        );

        assert_eq!(sub.id(), "sub-123");
        assert_eq!(sub.event().event_type, "presence");
        assert_eq!(sub.state(), SubscriptionState::Pending);
        assert_eq!(sub.expires(), 3600);
    }

    #[test]
    fn test_subscription_lifecycle() {
        let mut sub = Subscription::new(
            "sub-123",
            EventPackage::presence(),
            "sip:alice@example.com",
            "sip:bob@example.com",
            3600,
        );

        // Start pending
        assert_eq!(sub.state(), SubscriptionState::Pending);

        // Activate
        sub.activate();
        assert_eq!(sub.state(), SubscriptionState::Active);

        // Refresh
        sub.refresh(7200);
        assert_eq!(sub.expires(), 7200);

        // Terminate
        sub.terminate(TerminationReason::Unsubscribed);
        assert_eq!(sub.state(), SubscriptionState::Terminated);
        assert!(matches!(
            sub.termination_reason(),
            Some(TerminationReason::Unsubscribed)
        ));
    }

    #[test]
    fn test_subscription_process_notify() {
        let mut sub = Subscription::new(
            "sub-123",
            EventPackage::presence(),
            "sip:alice@example.com",
            "sip:bob@example.com",
            3600,
        );

        let state_header = SubscriptionStateHeader::active(1800);
        sub.process_notify(&state_header);

        assert_eq!(sub.state(), SubscriptionState::Active);
        assert_eq!(sub.expires(), 1800);
    }

    #[test]
    fn test_notifier_creation() {
        let notifier = Notifier::new(
            "sub-123",
            EventPackage::presence(),
            "sip:bob@example.com",
            "sip:alice@example.com",
            3600,
        );

        assert_eq!(notifier.id(), "sub-123");
        assert_eq!(notifier.state(), SubscriptionState::Pending);
    }

    #[test]
    fn test_notifier_lifecycle() {
        let mut notifier = Notifier::new(
            "sub-123",
            EventPackage::presence(),
            "sip:bob@example.com",
            "sip:alice@example.com",
            3600,
        );

        // Activate
        notifier.activate();
        assert_eq!(notifier.state(), SubscriptionState::Active);

        // Generate state header
        let header = notifier.generate_state_header();
        assert_eq!(header.state, SubscriptionState::Active);

        // Record NOTIFY
        notifier.record_notify();
        assert_eq!(notifier.notify_count(), 1);

        // Terminate
        let header = notifier.terminate(TerminationReason::Timeout);
        assert_eq!(header.state, SubscriptionState::Terminated);
        assert!(notifier.is_final_notify_sent());
    }

    #[test]
    fn test_parse_allow_events() {
        let events = parse_allow_events("presence, dialog, message-summary");
        assert_eq!(events.len(), 3);
        assert!(events.contains(&"presence".to_string()));
        assert!(events.contains(&"dialog".to_string()));
    }

    #[test]
    fn test_format_allow_events() {
        let events = vec![
            "presence".to_string(),
            "dialog".to_string(),
        ];
        assert_eq!(format_allow_events(&events), "presence, dialog");
    }
}
