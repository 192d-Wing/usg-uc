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
//!
//! ## Event Package Validation (RFC 6665 §7.2)
//!
//! Per RFC 6665 §7.2, event packages MUST be registered with IANA.
//! This module provides validation against known IANA registrations.

use std::collections::HashSet;
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

// ============================================================================
// RFC 6665 §7.2 - Event Package Validation
// ============================================================================

/// IANA-registered SIP event packages per RFC 6665 §7.2.
///
/// This list contains event packages registered with IANA as of 2024.
/// See: https://www.iana.org/assignments/sip-events/sip-events.xhtml
pub const IANA_REGISTERED_EVENT_PACKAGES: &[&str] = &[
    // RFC 3265/6665 - SIP-Specific Event Notification
    "presence",
    // RFC 3515 - REFER Method
    "refer",
    // RFC 3680 - Registration Event Package
    "reg",
    // RFC 3842 - Message Waiting Indication
    "message-summary",
    // RFC 3856 - Presence Event Package
    "presence",
    // RFC 3857 - Watcher Information
    "presence.winfo",
    // RFC 4235 - Dialog Event Package
    "dialog",
    // RFC 4538 - Media Authorization
    "ua-profile",
    // RFC 4575 - Conference Event Package
    "conference",
    // RFC 4730 - KPML (Key Press Markup Language)
    "kpml",
    // RFC 5070 - Consent Event Package
    "consent-pending-additions",
    // RFC 5362 - Resource Lists Event Package
    "presence.rl",
    // RFC 5359 - Line Event Package
    "line-seize",
    // RFC 5373 - Call Completion
    "call-completion",
    // RFC 5628 - Media Description Changes
    "Mediadesc",
    // RFC 6446 - Session Recording
    "session-recording",
    // RFC 6665 - SIP Events
    "poc-settings",
    // RFC 6910 - Auto-Configuration
    "as-feature-event",
    // RFC 7614 - Location Conveyance
    "held",
    // RFC 7840 - Registration for Multiple Phone Numbers
    "reg",
    // RFC 8068 - Pending Additions
    "pending-additions",
    // Additional commonly used packages
    "vq-rtcpxr", // VoIP metrics (RFC 6035)
    "xcap-diff", // XCAP Diff Event (RFC 5875)
    "spirits-INDPs",
    "spirits-user-prof",
    "dialog.winfo",
    "reg.winfo",
    "message-summary.winfo",
    "pres", // Alias for presence
];

/// Result of event package validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventPackageValidation {
    /// Event package is IANA-registered and valid.
    Valid,
    /// Event package is not IANA-registered but allowed (warn).
    UnregisteredAllowed {
        /// Warning message.
        warning: String,
    },
    /// Event package is not IANA-registered and not allowed.
    Invalid {
        /// Error reason.
        reason: String,
    },
}

/// Event package registry for validation per RFC 6665 §7.2.
///
/// Per RFC 6665, event packages MUST be registered with IANA.
/// This registry provides validation against known registrations
/// and can be configured to allow or reject unknown packages.
///
/// ## Example
///
/// ```
/// use proto_dialog::subscription::{EventPackageRegistry, EventPackageValidation};
///
/// let registry = EventPackageRegistry::new();
///
/// // Validate known package
/// assert!(matches!(
///     registry.validate("presence"),
///     EventPackageValidation::Valid
/// ));
///
/// // Unknown package
/// let result = registry.validate("unknown-event");
/// assert!(matches!(result, EventPackageValidation::UnregisteredAllowed { .. }));
///
/// // Strict mode rejects unknown packages
/// let strict = EventPackageRegistry::strict();
/// let result = strict.validate("unknown-event");
/// assert!(matches!(result, EventPackageValidation::Invalid { .. }));
/// ```
#[derive(Debug, Clone)]
pub struct EventPackageRegistry {
    /// Set of known IANA-registered packages.
    registered: HashSet<String>,
    /// Whether to allow unregistered packages (with warning).
    allow_unregistered: bool,
    /// Additional custom packages allowed.
    custom_packages: HashSet<String>,
}

impl Default for EventPackageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EventPackageRegistry {
    /// Creates a new registry with IANA-registered packages.
    ///
    /// By default, allows unregistered packages with a warning.
    #[must_use]
    pub fn new() -> Self {
        let registered: HashSet<String> = IANA_REGISTERED_EVENT_PACKAGES
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        Self {
            registered,
            allow_unregistered: true,
            custom_packages: HashSet::new(),
        }
    }

    /// Creates a strict registry that rejects unregistered packages.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            allow_unregistered: false,
            ..Self::new()
        }
    }

    /// Creates a permissive registry that allows any event package.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allow_unregistered: true,
            ..Self::new()
        }
    }

    /// Adds a custom event package to the allowed list.
    pub fn add_custom_package(&mut self, package: impl Into<String>) {
        self.custom_packages.insert(package.into().to_lowercase());
    }

    /// Removes a custom event package from the allowed list.
    pub fn remove_custom_package(&mut self, package: &str) -> bool {
        self.custom_packages.remove(&package.to_lowercase())
    }

    /// Sets whether unregistered packages are allowed.
    pub fn set_allow_unregistered(&mut self, allow: bool) {
        self.allow_unregistered = allow;
    }

    /// Checks if a package is IANA-registered.
    #[must_use]
    pub fn is_iana_registered(&self, event_type: &str) -> bool {
        self.registered.contains(&event_type.to_lowercase())
    }

    /// Checks if a package is custom-allowed.
    #[must_use]
    pub fn is_custom_allowed(&self, event_type: &str) -> bool {
        self.custom_packages.contains(&event_type.to_lowercase())
    }

    /// Checks if a package is allowed (registered or custom).
    #[must_use]
    pub fn is_allowed(&self, event_type: &str) -> bool {
        let lower = event_type.to_lowercase();
        self.registered.contains(&lower)
            || self.custom_packages.contains(&lower)
            || self.allow_unregistered
    }

    /// Validates an event package per RFC 6665 §7.2.
    ///
    /// Returns the validation result indicating whether the package
    /// is valid, allowed with warning, or rejected.
    #[must_use]
    pub fn validate(&self, event_type: &str) -> EventPackageValidation {
        let lower = event_type.to_lowercase();

        // Check IANA registration
        if self.registered.contains(&lower) {
            return EventPackageValidation::Valid;
        }

        // Check custom packages
        if self.custom_packages.contains(&lower) {
            return EventPackageValidation::Valid;
        }

        // Unregistered package
        if self.allow_unregistered {
            EventPackageValidation::UnregisteredAllowed {
                warning: format!(
                    "Event package '{}' is not IANA-registered per RFC 6665 §7.2",
                    event_type
                ),
            }
        } else {
            EventPackageValidation::Invalid {
                reason: format!(
                    "Event package '{}' is not IANA-registered per RFC 6665 §7.2. \
                     Registered packages must be used for interoperability.",
                    event_type
                ),
            }
        }
    }

    /// Validates an EventPackage struct.
    #[must_use]
    pub fn validate_package(&self, package: &EventPackage) -> EventPackageValidation {
        self.validate(&package.event_type)
    }

    /// Returns all IANA-registered packages.
    #[must_use]
    pub fn registered_packages(&self) -> Vec<&str> {
        IANA_REGISTERED_EVENT_PACKAGES.to_vec()
    }

    /// Returns all custom packages.
    #[must_use]
    pub fn custom_packages(&self) -> Vec<String> {
        self.custom_packages.iter().cloned().collect()
    }
}

/// Validates an event package against IANA registrations.
///
/// This is a convenience function using the default (permissive) registry.
///
/// # Arguments
///
/// * `event_type` - The event type to validate
///
/// # Returns
///
/// The validation result.
#[must_use]
pub fn validate_event_package(event_type: &str) -> EventPackageValidation {
    EventPackageRegistry::new().validate(event_type)
}

/// Validates an event package strictly (rejects unregistered).
///
/// # Arguments
///
/// * `event_type` - The event type to validate
///
/// # Returns
///
/// `true` if the package is IANA-registered.
#[must_use]
pub fn is_event_package_registered(event_type: &str) -> bool {
    EventPackageRegistry::new().is_iana_registered(event_type)
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

    // ========================================================================
    // RFC 6665 §7.2 - Event Package Validation Tests
    // ========================================================================

    #[test]
    fn test_event_package_registry_creation() {
        let registry = EventPackageRegistry::new();

        // Common packages should be registered
        assert!(registry.is_iana_registered("presence"));
        assert!(registry.is_iana_registered("dialog"));
        assert!(registry.is_iana_registered("message-summary"));
        assert!(registry.is_iana_registered("refer"));
        assert!(registry.is_iana_registered("reg"));
    }

    #[test]
    fn test_event_package_registry_case_insensitive() {
        let registry = EventPackageRegistry::new();

        // Should be case-insensitive
        assert!(registry.is_iana_registered("PRESENCE"));
        assert!(registry.is_iana_registered("Presence"));
        assert!(registry.is_iana_registered("Dialog"));
    }

    #[test]
    fn test_event_package_validation_valid() {
        let registry = EventPackageRegistry::new();

        let result = registry.validate("presence");
        assert!(matches!(result, EventPackageValidation::Valid));

        let result = registry.validate("dialog");
        assert!(matches!(result, EventPackageValidation::Valid));

        let result = registry.validate("conference");
        assert!(matches!(result, EventPackageValidation::Valid));
    }

    #[test]
    fn test_event_package_validation_unregistered_allowed() {
        let registry = EventPackageRegistry::new(); // Default: permissive

        let result = registry.validate("my-custom-event");
        match result {
            EventPackageValidation::UnregisteredAllowed { warning } => {
                assert!(warning.contains("not IANA-registered"));
            }
            _ => panic!("Expected UnregisteredAllowed, got {:?}", result),
        }
    }

    #[test]
    fn test_event_package_validation_strict_rejects() {
        let registry = EventPackageRegistry::strict();

        let result = registry.validate("my-custom-event");
        match result {
            EventPackageValidation::Invalid { reason } => {
                assert!(reason.contains("not IANA-registered"));
            }
            _ => panic!("Expected Invalid, got {:?}", result),
        }
    }

    #[test]
    fn test_event_package_registry_custom() {
        let mut registry = EventPackageRegistry::strict();

        // Add custom package
        registry.add_custom_package("my-enterprise-event");

        // Should now be allowed
        assert!(registry.is_custom_allowed("my-enterprise-event"));
        assert!(registry.is_allowed("my-enterprise-event"));

        let result = registry.validate("my-enterprise-event");
        assert!(matches!(result, EventPackageValidation::Valid));

        // Other unknown packages still rejected
        let result = registry.validate("another-unknown");
        assert!(matches!(result, EventPackageValidation::Invalid { .. }));
    }

    #[test]
    fn test_event_package_registry_remove_custom() {
        let mut registry = EventPackageRegistry::strict();

        registry.add_custom_package("temp-event");
        assert!(registry.is_custom_allowed("temp-event"));

        let removed = registry.remove_custom_package("temp-event");
        assert!(removed);
        assert!(!registry.is_custom_allowed("temp-event"));
    }

    #[test]
    fn test_event_package_validate_package_struct() {
        let registry = EventPackageRegistry::new();

        let presence = EventPackage::presence();
        assert!(matches!(
            registry.validate_package(&presence),
            EventPackageValidation::Valid
        ));

        let unknown = EventPackage::new("unknown-event");
        assert!(matches!(
            registry.validate_package(&unknown),
            EventPackageValidation::UnregisteredAllowed { .. }
        ));
    }

    #[test]
    fn test_validate_event_package_convenience() {
        // Valid package
        assert!(matches!(
            validate_event_package("presence"),
            EventPackageValidation::Valid
        ));

        // Unknown package (allowed with warning in default mode)
        assert!(matches!(
            validate_event_package("unknown"),
            EventPackageValidation::UnregisteredAllowed { .. }
        ));
    }

    #[test]
    fn test_is_event_package_registered() {
        assert!(is_event_package_registered("presence"));
        assert!(is_event_package_registered("dialog"));
        assert!(!is_event_package_registered("unknown-event"));
    }

    #[test]
    fn test_event_package_registry_all_iana_packages() {
        let registry = EventPackageRegistry::new();
        let packages = registry.registered_packages();

        // Should have a reasonable number of packages
        assert!(packages.len() >= 10);

        // Key packages should be present
        assert!(packages.contains(&"presence"));
        assert!(packages.contains(&"dialog"));
        assert!(packages.contains(&"refer"));
    }

    #[test]
    fn test_event_package_registry_permissive() {
        let registry = EventPackageRegistry::permissive();

        // Should allow any package
        assert!(registry.is_allowed("any-random-event"));
    }

    #[test]
    fn test_event_package_winfo_variants() {
        let registry = EventPackageRegistry::new();

        // Watcher info packages
        assert!(registry.is_iana_registered("presence.winfo"));
        assert!(registry.is_iana_registered("dialog.winfo"));
        assert!(registry.is_iana_registered("reg.winfo"));
    }
}
