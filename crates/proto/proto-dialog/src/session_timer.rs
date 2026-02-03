//! Session timer support per RFC 4028.
//!
//! ## RFC 4028 Compliance
//!
//! - Session-Expires header negotiation
//! - Min-SE header handling
//! - 422 (Session Interval Too Small) response handling
//! - Automatic refresh scheduling
//! - Refresher role negotiation
//!
//! ## Session Refresh Flow
//!
//! 1. Session established with Session-Expires header
//! 2. Refresher sends re-INVITE or UPDATE at session_expires/2
//! 3. If refresh not received, session terminates at session_expires
//!
//! ## 422 Response Handling
//!
//! When a UAS receives a request with Session-Expires less than its
//! minimum (Min-SE), it responds with 422 and includes Min-SE header.
//! The UAC must then retry with the higher value.

use crate::error::{DialogError, DialogResult};
use crate::{DEFAULT_SESSION_EXPIRES, MIN_SESSION_EXPIRES};
use std::time::{Duration, Instant};

/// Session timer refresher role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefresherRole {
    /// UAC (caller) is responsible for refreshing.
    Uac,
    /// UAS (callee) is responsible for refreshing.
    Uas,
}

impl std::fmt::Display for RefresherRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uac => write!(f, "uac"),
            Self::Uas => write!(f, "uas"),
        }
    }
}

impl RefresherRole {
    /// Parses from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "uac" => Some(Self::Uac),
            "uas" => Some(Self::Uas),
            _ => None,
        }
    }
}

/// Session timer for RFC 4028 compliance.
#[derive(Debug, Clone)]
pub struct SessionTimer {
    /// Session expires value in seconds.
    session_expires: u32,
    /// Minimum session expires (Min-SE).
    min_se: u32,
    /// Refresher role.
    refresher: RefresherRole,
    /// When the timer was last refreshed.
    last_refresh: Instant,
    /// Whether session timers are active.
    active: bool,
}

impl SessionTimer {
    /// Creates a new session timer.
    pub fn new(session_expires: u32, refresher: RefresherRole) -> Self {
        Self {
            session_expires: session_expires.max(MIN_SESSION_EXPIRES),
            min_se: MIN_SESSION_EXPIRES,
            refresher,
            last_refresh: Instant::now(),
            active: true,
        }
    }

    /// Creates a session timer with default values.
    pub fn default_timer(refresher: RefresherRole) -> Self {
        Self::new(DEFAULT_SESSION_EXPIRES, refresher)
    }

    /// Returns the session expires value.
    pub fn session_expires(&self) -> u32 {
        self.session_expires
    }

    /// Returns the minimum session expires.
    pub fn min_se(&self) -> u32 {
        self.min_se
    }

    /// Sets the minimum session expires.
    pub fn set_min_se(&mut self, min_se: u32) {
        self.min_se = min_se.max(MIN_SESSION_EXPIRES);
    }

    /// Returns the refresher role.
    pub fn refresher(&self) -> RefresherRole {
        self.refresher
    }

    /// Returns whether the timer is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivates the timer.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Refreshes the timer.
    pub fn refresh(&mut self) {
        self.last_refresh = Instant::now();
    }

    /// Updates the session expires value.
    pub fn update_expires(&mut self, expires: u32) {
        self.session_expires = expires.max(self.min_se);
        self.refresh();
    }

    /// Returns time since last refresh.
    pub fn time_since_refresh(&self) -> Duration {
        self.last_refresh.elapsed()
    }

    /// Returns time until expiration.
    pub fn time_until_expiry(&self) -> Duration {
        let expires = Duration::from_secs(self.session_expires as u64);
        let elapsed = self.last_refresh.elapsed();

        if elapsed >= expires {
            Duration::ZERO
        } else {
            expires.checked_sub(elapsed).unwrap()
        }
    }

    /// Checks if the session has expired.
    pub fn is_expired(&self) -> bool {
        if !self.active {
            return false;
        }
        self.time_until_expiry() == Duration::ZERO
    }

    /// Returns when a refresh should be sent.
    ///
    /// Per RFC 4028, refresh should be sent at session_expires / 2.
    pub fn refresh_interval(&self) -> Duration {
        Duration::from_secs((self.session_expires / 2) as u64)
    }

    /// Checks if it's time to send a refresh.
    pub fn should_refresh(&self) -> bool {
        if !self.active {
            return false;
        }
        self.last_refresh.elapsed() >= self.refresh_interval()
    }

    /// Formats as Session-Expires header value.
    pub fn to_header(&self) -> String {
        format!("{};refresher={}", self.session_expires, self.refresher)
    }
}

impl Default for SessionTimer {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_EXPIRES, RefresherRole::Uac)
    }
}

/// Session timer negotiation result.
#[derive(Debug, Clone)]
pub struct SessionTimerNegotiation {
    /// The negotiated session expires value.
    pub session_expires: u32,
    /// The refresher role.
    pub refresher: RefresherRole,
    /// Whether a 422 response was needed.
    pub needs_422: bool,
    /// The Min-SE value if 422 is needed.
    pub required_min_se: Option<u32>,
}

impl SessionTimerNegotiation {
    /// Creates a successful negotiation result.
    pub fn success(session_expires: u32, refresher: RefresherRole) -> Self {
        Self {
            session_expires,
            refresher,
            needs_422: false,
            required_min_se: None,
        }
    }

    /// Creates a 422 response result.
    pub fn too_small(required_min_se: u32) -> Self {
        Self {
            session_expires: 0,
            refresher: RefresherRole::Uac,
            needs_422: true,
            required_min_se: Some(required_min_se),
        }
    }
}

/// Negotiates session timer parameters for incoming INVITE.
///
/// Per RFC 4028 Section 5, the UAS checks if the Session-Expires value
/// is acceptable. If too small, it returns 422 with Min-SE header.
///
/// # Arguments
///
/// * `requested_expires` - Session-Expires value from incoming request
/// * `requested_refresher` - Refresher preference from incoming request
/// * `local_min_se` - Our minimum acceptable session interval
/// * `we_are_uas` - True if we are the UAS (callee)
///
/// # Returns
///
/// Negotiation result indicating success or need for 422 response.
pub fn negotiate_session_timer(
    requested_expires: u32,
    requested_refresher: Option<RefresherRole>,
    local_min_se: u32,
    we_are_uas: bool,
) -> SessionTimerNegotiation {
    // Check if requested interval is too small
    if requested_expires < local_min_se {
        return SessionTimerNegotiation::too_small(local_min_se);
    }

    // Determine refresher per RFC 4028 Section 7.1
    let refresher = match requested_refresher {
        Some(role) => role,
        None => {
            // If not specified, UAS should refresh by default per RFC 4028
            if we_are_uas {
                RefresherRole::Uas
            } else {
                RefresherRole::Uac
            }
        }
    };

    SessionTimerNegotiation::success(requested_expires, refresher)
}

/// Parses a Session-Expires header value.
///
/// Format: `<delta-seconds>[;refresher=<uac|uas>]`
///
/// # Examples
///
/// - "1800" -> (1800, None)
/// - "1800;refresher=uac" -> (1800, Some(RefresherRole::Uac))
///
/// # Errors
/// Returns an error if the operation fails.
pub fn parse_session_expires(value: &str) -> DialogResult<(u32, Option<RefresherRole>)> {
    let parts: Vec<&str> = value.split(';').collect();

    let expires: u32 = parts
        .first()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| DialogError::InvalidParameter {
            name: "Session-Expires".to_string(),
            reason: "invalid delta-seconds".to_string(),
        })?;

    let mut refresher = None;
    for part in parts.iter().skip(1) {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("refresher=") {
            refresher = RefresherRole::from_str(value);
        }
    }

    Ok((expires, refresher))
}

/// Parses a Min-SE header value.
///
/// Format: `<delta-seconds>`
///
/// # Errors
/// Returns an error if the operation fails.
pub fn parse_min_se(value: &str) -> DialogResult<u32> {
    value
        .trim()
        .parse()
        .map_err(|_| DialogError::InvalidParameter {
            name: "Min-SE".to_string(),
            reason: "invalid delta-seconds".to_string(),
        })
}

/// Creates a Session-Expires header value.
pub fn format_session_expires(expires: u32, refresher: Option<RefresherRole>) -> String {
    match refresher {
        Some(role) => format!("{expires};refresher={role}"),
        None => format!("{expires}"),
    }
}

/// Creates a Min-SE header value.
pub fn format_min_se(min_se: u32) -> String {
    min_se.to_string()
}

/// Handles a 422 response by updating the session timer.
///
/// Per RFC 4028 Section 8.1.1, when receiving 422, the UAC should
/// retry with the Min-SE value from the response.
pub fn handle_422_response(
    current_timer: &mut SessionTimer,
    min_se_from_response: u32,
) -> DialogResult<()> {
    if min_se_from_response < MIN_SESSION_EXPIRES {
        return Err(DialogError::InvalidSessionTimer {
            reason: format!(
                "Min-SE {min_se_from_response} below RFC minimum {MIN_SESSION_EXPIRES}"
            ),
        });
    }

    current_timer.set_min_se(min_se_from_response);
    current_timer.update_expires(min_se_from_response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_timer_creation() {
        let timer = SessionTimer::new(300, RefresherRole::Uac);
        assert_eq!(timer.session_expires(), 300);
        assert_eq!(timer.refresher(), RefresherRole::Uac);
        assert!(timer.is_active());
    }

    #[test]
    fn test_session_timer_min_se() {
        // Should enforce minimum
        let timer = SessionTimer::new(60, RefresherRole::Uac);
        assert_eq!(timer.session_expires(), MIN_SESSION_EXPIRES);
    }

    #[test]
    fn test_session_timer_refresh() {
        let timer = SessionTimer::new(300, RefresherRole::Uac);

        // Should not need refresh immediately
        assert!(!timer.should_refresh());

        // Manually check time calculations
        assert!(timer.time_until_expiry().as_secs() > 0);
        assert_eq!(timer.refresh_interval(), Duration::from_secs(150));
    }

    #[test]
    fn test_session_timer_deactivate() {
        let mut timer = SessionTimer::new(1, RefresherRole::Uac);
        timer.deactivate();

        assert!(!timer.is_active());
        assert!(!timer.is_expired());
        assert!(!timer.should_refresh());
    }

    #[test]
    fn test_refresher_role() {
        assert_eq!(RefresherRole::from_str("uac"), Some(RefresherRole::Uac));
        assert_eq!(RefresherRole::from_str("UAS"), Some(RefresherRole::Uas));
        assert_eq!(RefresherRole::from_str("invalid"), None);
    }

    #[test]
    fn test_session_timer_header() {
        let timer = SessionTimer::new(1800, RefresherRole::Uac);
        assert_eq!(timer.to_header(), "1800;refresher=uac");
    }

    #[test]
    fn test_update_expires() {
        let mut timer = SessionTimer::new(300, RefresherRole::Uac);
        timer.update_expires(600);
        assert_eq!(timer.session_expires(), 600);
    }

    #[test]
    fn test_negotiate_session_timer_success() {
        let result = negotiate_session_timer(1800, Some(RefresherRole::Uac), 90, true);
        assert!(!result.needs_422);
        assert_eq!(result.session_expires, 1800);
        assert_eq!(result.refresher, RefresherRole::Uac);
    }

    #[test]
    fn test_negotiate_session_timer_too_small() {
        let result = negotiate_session_timer(60, None, 180, true);
        assert!(result.needs_422);
        assert_eq!(result.required_min_se, Some(180));
    }

    #[test]
    fn test_negotiate_session_timer_default_refresher() {
        // UAS should default to refresher when not specified
        let result = negotiate_session_timer(1800, None, 90, true);
        assert_eq!(result.refresher, RefresherRole::Uas);

        // UAC should be refresher when not specified and we're UAC
        let result = negotiate_session_timer(1800, None, 90, false);
        assert_eq!(result.refresher, RefresherRole::Uac);
    }

    #[test]
    fn test_parse_session_expires() {
        let (expires, refresher) = parse_session_expires("1800").unwrap();
        assert_eq!(expires, 1800);
        assert!(refresher.is_none());

        let (expires, refresher) = parse_session_expires("1800;refresher=uac").unwrap();
        assert_eq!(expires, 1800);
        assert_eq!(refresher, Some(RefresherRole::Uac));

        let (expires, refresher) = parse_session_expires("3600;refresher=uas").unwrap();
        assert_eq!(expires, 3600);
        assert_eq!(refresher, Some(RefresherRole::Uas));
    }

    #[test]
    fn test_parse_min_se() {
        assert_eq!(parse_min_se("90").unwrap(), 90);
        assert_eq!(parse_min_se("  180  ").unwrap(), 180);
        assert!(parse_min_se("invalid").is_err());
    }

    #[test]
    fn test_format_session_expires() {
        assert_eq!(format_session_expires(1800, None), "1800");
        assert_eq!(
            format_session_expires(1800, Some(RefresherRole::Uac)),
            "1800;refresher=uac"
        );
    }

    #[test]
    fn test_handle_422_response() {
        let mut timer = SessionTimer::new(60, RefresherRole::Uac);
        handle_422_response(&mut timer, 180).unwrap();

        assert_eq!(timer.min_se(), 180);
        assert_eq!(timer.session_expires(), 180);
    }

    #[test]
    fn test_handle_422_response_invalid() {
        let mut timer = SessionTimer::new(300, RefresherRole::Uac);
        // Min-SE below RFC minimum should fail
        let result = handle_422_response(&mut timer, 30);
        assert!(result.is_err());
    }
}
