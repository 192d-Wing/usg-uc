//! Policy actions.

/// Header manipulation action.
#[derive(Debug, Clone)]
pub enum HeaderAction {
    /// Add a header.
    Add {
        /// Header name.
        name: String,
        /// Header value.
        value: String,
    },
    /// Remove a header.
    Remove {
        /// Header name.
        name: String,
    },
    /// Modify a header.
    Modify {
        /// Header name.
        name: String,
        /// New value.
        value: String,
    },
    /// Replace header value using pattern.
    Replace {
        /// Header name.
        name: String,
        /// Pattern to match.
        pattern: String,
        /// Replacement.
        replacement: String,
    },
}

impl HeaderAction {
    /// Creates an add header action.
    pub fn add(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Add {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Creates a remove header action.
    pub fn remove(name: impl Into<String>) -> Self {
        Self::Remove { name: name.into() }
    }

    /// Creates a modify header action.
    pub fn modify(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Modify {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Policy action.
#[derive(Debug, Clone, Default)]
pub enum PolicyAction {
    /// Allow the request to proceed.
    #[default]
    Allow,
    /// Deny the request with a status code.
    Deny {
        /// SIP status code.
        status_code: u16,
        /// Reason phrase.
        reason: String,
    },
    /// Redirect the request.
    Redirect {
        /// Target URI.
        target: String,
    },
    /// Route to a specific destination.
    Route {
        /// Route name/ID.
        route_id: String,
    },
    /// Manipulate headers.
    ManipulateHeaders(Vec<HeaderAction>),
    /// Set a variable for later use.
    SetVariable {
        /// Variable name.
        name: String,
        /// Variable value.
        value: String,
    },
    /// Log the request.
    Log {
        /// Log message.
        message: String,
        /// Log level.
        level: LogLevel,
    },
    /// Rate limit.
    RateLimit {
        /// Requests per second.
        rps: u32,
    },
    /// Multiple actions.
    Multiple(Vec<PolicyAction>),
    /// Continue to next rule.
    Continue,
}

/// Log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Debug level.
    Debug,
    /// Info level.
    Info,
    /// Warning level.
    Warn,
    /// Error level.
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug => write!(f, "debug"),
            Self::Info => write!(f, "info"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
        }
    }
}

impl PolicyAction {
    /// Creates an allow action.
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Creates a deny action.
    pub fn deny(status_code: u16, reason: impl Into<String>) -> Self {
        Self::Deny {
            status_code,
            reason: reason.into(),
        }
    }

    /// Creates a route action.
    pub fn route(route_id: impl Into<String>) -> Self {
        Self::Route {
            route_id: route_id.into(),
        }
    }

    /// Creates a redirect action.
    pub fn redirect(target: impl Into<String>) -> Self {
        Self::Redirect {
            target: target.into(),
        }
    }

    /// Creates a log action.
    pub fn log(message: impl Into<String>, level: LogLevel) -> Self {
        Self::Log {
            message: message.into(),
            level,
        }
    }

    /// Returns whether this is a terminal action (stops processing).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Allow | Self::Deny { .. } | Self::Redirect { .. }
        )
    }

    /// Returns whether this action denies the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_action() {
        let add = HeaderAction::add("X-Custom", "value");
        assert!(matches!(add, HeaderAction::Add { .. }));

        let remove = HeaderAction::remove("Via");
        assert!(matches!(remove, HeaderAction::Remove { .. }));
    }

    #[test]
    fn test_policy_action_allow() {
        let action = PolicyAction::allow();
        assert!(action.is_terminal());
        assert!(!action.is_deny());
    }

    #[test]
    fn test_policy_action_deny() {
        let action = PolicyAction::deny(403, "Forbidden");
        assert!(action.is_terminal());
        assert!(action.is_deny());
    }

    #[test]
    fn test_policy_action_route() {
        let action = PolicyAction::route("trunk-1");
        assert!(!action.is_terminal());
    }

    #[test]
    fn test_policy_action_continue() {
        let action = PolicyAction::Continue;
        assert!(!action.is_terminal());
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }
}
