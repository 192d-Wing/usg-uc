//! Session timer support per RFC 4028.

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
            expires - elapsed
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
}
