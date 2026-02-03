//! Policy conditions for matching requests.

/// Condition match result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionMatch {
    /// Condition matched.
    Matched,
    /// Condition did not match.
    NotMatched,
    /// Condition could not be evaluated.
    Unknown,
}

impl ConditionMatch {
    /// Returns whether the condition matched.
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Matched)
    }
}

/// String match operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringMatch {
    /// Exact match.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Suffix match.
    Suffix(String),
    /// Contains substring.
    Contains(String),
    /// Regex match.
    Regex(String),
    /// Any value.
    Any,
}

impl StringMatch {
    /// Checks if the value matches.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(pattern) => value == pattern,
            Self::Prefix(pattern) => value.starts_with(pattern),
            Self::Suffix(pattern) => value.ends_with(pattern),
            Self::Contains(pattern) => value.contains(pattern),
            Self::Regex(_pattern) => {
                // In production, would use regex crate
                // For now, just do contains match
                true
            }
            Self::Any => true,
        }
    }
}

/// Numeric comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericOp {
    /// Equal to.
    Eq,
    /// Not equal to.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
}

impl NumericOp {
    /// Compares two values.
    pub fn compare<T: PartialOrd>(&self, a: T, b: T) -> bool {
        match self {
            Self::Eq => a == b,
            Self::Ne => a != b,
            Self::Lt => a < b,
            Self::Le => a <= b,
            Self::Gt => a > b,
            Self::Ge => a >= b,
        }
    }
}

/// Policy condition.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Always true.
    Always,
    /// Always false.
    Never,
    /// Match source IP/network.
    SourceIp(String),
    /// Match destination IP/network.
    DestIp(String),
    /// Match SIP method.
    Method(StringMatch),
    /// Match From URI.
    FromUri(StringMatch),
    /// Match To URI.
    ToUri(StringMatch),
    /// Match Request-URI.
    RequestUri(StringMatch),
    /// Match a specific header.
    Header {
        /// Header name.
        name: String,
        /// Match pattern.
        pattern: StringMatch,
    },
    /// Match caller ID / From user.
    CallerId(StringMatch),
    /// Match called number / To user.
    CalledNumber(StringMatch),
    /// Time-based condition.
    TimeOfDay {
        /// Start hour (0-23).
        start_hour: u8,
        /// End hour (0-23).
        end_hour: u8,
    },
    /// Day of week condition.
    DayOfWeek {
        /// Days (0=Sunday, 6=Saturday).
        days: Vec<u8>,
    },
    /// All conditions must match.
    All(Vec<Condition>),
    /// Any condition must match.
    Any(Vec<Condition>),
    /// Negate condition.
    Not(Box<Condition>),
}

impl Condition {
    /// Creates an always-true condition.
    pub fn always() -> Self {
        Self::Always
    }

    /// Creates a method match condition.
    pub fn method(method: impl Into<String>) -> Self {
        Self::Method(StringMatch::Exact(method.into()))
    }

    /// Creates a caller ID prefix match.
    pub fn caller_prefix(prefix: impl Into<String>) -> Self {
        Self::CallerId(StringMatch::Prefix(prefix.into()))
    }

    /// Creates a called number prefix match.
    pub fn called_prefix(prefix: impl Into<String>) -> Self {
        Self::CalledNumber(StringMatch::Prefix(prefix.into()))
    }

    /// Checks if the condition matches the context.
    /// Returns true if matched, false otherwise (including unknown).
    pub fn matches(&self, ctx: &RequestContext) -> bool {
        self.evaluate(ctx).is_match()
    }

    /// Evaluates the condition against a request context.
    pub fn evaluate(&self, ctx: &RequestContext) -> ConditionMatch {
        match self {
            Self::Always => ConditionMatch::Matched,
            Self::Never => ConditionMatch::NotMatched,
            Self::SourceIp(pattern) => {
                if let Some(ref ip) = ctx.source_ip {
                    if ip.contains(pattern) || pattern == "*" {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::DestIp(pattern) => {
                if let Some(ref ip) = ctx.dest_ip {
                    if ip.contains(pattern) || pattern == "*" {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::Method(pattern) => {
                if let Some(ref method) = ctx.method {
                    if pattern.matches(method) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::FromUri(pattern) => {
                if let Some(ref uri) = ctx.from_uri {
                    if pattern.matches(uri) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::ToUri(pattern) => {
                if let Some(ref uri) = ctx.to_uri {
                    if pattern.matches(uri) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::RequestUri(pattern) => {
                if let Some(ref uri) = ctx.request_uri {
                    if pattern.matches(uri) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::Header { name, pattern } => {
                if let Some(value) = ctx.headers.get(name) {
                    if pattern.matches(value) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::NotMatched
                }
            }
            Self::CallerId(pattern) => {
                if let Some(ref caller_id) = ctx.caller_id {
                    if pattern.matches(caller_id) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::CalledNumber(pattern) => {
                if let Some(ref called) = ctx.called_number {
                    if pattern.matches(called) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::TimeOfDay {
                start_hour,
                end_hour,
            } => {
                if let Some(hour) = ctx.current_hour {
                    if hour >= *start_hour && hour <= *end_hour {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::DayOfWeek { days } => {
                if let Some(day) = ctx.current_day {
                    if days.contains(&day) {
                        ConditionMatch::Matched
                    } else {
                        ConditionMatch::NotMatched
                    }
                } else {
                    ConditionMatch::Unknown
                }
            }
            Self::All(conditions) => {
                for cond in conditions {
                    match cond.evaluate(ctx) {
                        ConditionMatch::NotMatched => return ConditionMatch::NotMatched,
                        ConditionMatch::Unknown => return ConditionMatch::Unknown,
                        ConditionMatch::Matched => continue,
                    }
                }
                ConditionMatch::Matched
            }
            Self::Any(conditions) => {
                let mut has_unknown = false;
                for cond in conditions {
                    match cond.evaluate(ctx) {
                        ConditionMatch::Matched => return ConditionMatch::Matched,
                        ConditionMatch::Unknown => has_unknown = true,
                        ConditionMatch::NotMatched => continue,
                    }
                }
                if has_unknown {
                    ConditionMatch::Unknown
                } else {
                    ConditionMatch::NotMatched
                }
            }
            Self::Not(inner) => match inner.evaluate(ctx) {
                ConditionMatch::Matched => ConditionMatch::NotMatched,
                ConditionMatch::NotMatched => ConditionMatch::Matched,
                ConditionMatch::Unknown => ConditionMatch::Unknown,
            },
        }
    }
}

/// Request context for policy evaluation.
#[derive(Debug, Default)]
pub struct RequestContext {
    /// Source IP address.
    pub source_ip: Option<String>,
    /// Destination IP address.
    pub dest_ip: Option<String>,
    /// SIP method.
    pub method: Option<String>,
    /// From URI.
    pub from_uri: Option<String>,
    /// To URI.
    pub to_uri: Option<String>,
    /// Request-URI.
    pub request_uri: Option<String>,
    /// Headers.
    pub headers: std::collections::HashMap<String, String>,
    /// Caller ID (from user part).
    pub caller_id: Option<String>,
    /// Called number (to user part).
    pub called_number: Option<String>,
    /// Current hour (0-23).
    pub current_hour: Option<u8>,
    /// Current day of week (0=Sunday).
    pub current_day: Option<u8>,
}

impl RequestContext {
    /// Creates a new empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the source IP.
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Sets the SIP method.
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets the caller ID.
    pub fn with_caller_id(mut self, caller_id: impl Into<String>) -> Self {
        self.caller_id = Some(caller_id.into());
        self
    }

    /// Sets the called number.
    pub fn with_called_number(mut self, called: impl Into<String>) -> Self {
        self.called_number = Some(called.into());
        self
    }

    /// Sets the destination IP.
    pub fn with_dest_ip(mut self, ip: impl Into<String>) -> Self {
        self.dest_ip = Some(ip.into());
        self
    }

    /// Sets the From URI.
    pub fn with_from_uri(mut self, uri: impl Into<String>) -> Self {
        self.from_uri = Some(uri.into());
        self
    }

    /// Sets the To URI.
    pub fn with_to_uri(mut self, uri: impl Into<String>) -> Self {
        self.to_uri = Some(uri.into());
        self
    }

    /// Sets the Request-URI.
    pub fn with_request_uri(mut self, uri: impl Into<String>) -> Self {
        self.request_uri = Some(uri.into());
        self
    }

    /// Sets the current hour.
    pub fn with_current_hour(mut self, hour: u8) -> Self {
        self.current_hour = Some(hour);
        self
    }

    /// Sets the current day of week.
    pub fn with_current_day(mut self, day: u8) -> Self {
        self.current_day = Some(day);
        self
    }

    /// Adds a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_match() {
        assert!(ConditionMatch::Matched.is_match());
        assert!(!ConditionMatch::NotMatched.is_match());
        assert!(!ConditionMatch::Unknown.is_match());
    }

    #[test]
    fn test_string_match() {
        assert!(StringMatch::Exact("INVITE".to_string()).matches("INVITE"));
        assert!(!StringMatch::Exact("INVITE".to_string()).matches("BYE"));

        assert!(StringMatch::Prefix("+1".to_string()).matches("+15551234567"));
        assert!(!StringMatch::Prefix("+1".to_string()).matches("+445551234567"));

        assert!(StringMatch::Contains("example".to_string()).matches("sip:user@example.com"));
        assert!(StringMatch::Any.matches("anything"));
    }

    #[test]
    fn test_numeric_op() {
        assert!(NumericOp::Eq.compare(5, 5));
        assert!(NumericOp::Lt.compare(3, 5));
        assert!(NumericOp::Ge.compare(5, 5));
        assert!(NumericOp::Ge.compare(6, 5));
    }

    #[test]
    fn test_condition_always() {
        let ctx = RequestContext::new();
        assert!(Condition::Always.evaluate(&ctx).is_match());
        assert!(!Condition::Never.evaluate(&ctx).is_match());
    }

    #[test]
    fn test_condition_method() {
        let ctx = RequestContext::new().with_method("INVITE");
        assert!(Condition::method("INVITE").evaluate(&ctx).is_match());
        assert!(!Condition::method("BYE").evaluate(&ctx).is_match());
    }

    #[test]
    fn test_condition_caller_prefix() {
        let ctx = RequestContext::new().with_caller_id("+15551234567");
        assert!(Condition::caller_prefix("+1").evaluate(&ctx).is_match());
        assert!(!Condition::caller_prefix("+44").evaluate(&ctx).is_match());
    }

    #[test]
    fn test_condition_all() {
        let ctx = RequestContext::new()
            .with_method("INVITE")
            .with_caller_id("+15551234567");

        let cond = Condition::All(vec![
            Condition::method("INVITE"),
            Condition::caller_prefix("+1"),
        ]);
        assert!(cond.evaluate(&ctx).is_match());

        let cond_fail = Condition::All(vec![
            Condition::method("BYE"),
            Condition::caller_prefix("+1"),
        ]);
        assert!(!cond_fail.evaluate(&ctx).is_match());
    }

    #[test]
    fn test_condition_any() {
        let ctx = RequestContext::new().with_method("INVITE");

        let cond = Condition::Any(vec![Condition::method("INVITE"), Condition::method("BYE")]);
        assert!(cond.evaluate(&ctx).is_match());

        let cond_fail = Condition::Any(vec![Condition::method("BYE"), Condition::method("CANCEL")]);
        assert!(!cond_fail.evaluate(&ctx).is_match());
    }

    #[test]
    fn test_condition_not() {
        let ctx = RequestContext::new().with_method("INVITE");
        let cond = Condition::Not(Box::new(Condition::method("BYE")));
        assert!(cond.evaluate(&ctx).is_match());
    }

    #[test]
    fn test_condition_time_of_day() {
        let mut ctx = RequestContext::new();
        ctx.current_hour = Some(14);

        let cond = Condition::TimeOfDay {
            start_hour: 9,
            end_hour: 17,
        };
        assert!(cond.evaluate(&ctx).is_match());

        ctx.current_hour = Some(22);
        assert!(!cond.evaluate(&ctx).is_match());
    }

    #[test]
    fn test_request_context_builder() {
        let ctx = RequestContext::new()
            .with_source_ip("192.168.1.100")
            .with_method("INVITE")
            .with_caller_id("+15551234567")
            .with_called_number("+15559876543")
            .with_header("User-Agent", "TestPhone/1.0");

        assert_eq!(ctx.source_ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(ctx.method.as_deref(), Some("INVITE"));
        assert!(ctx.headers.contains_key("User-Agent"));
    }
}
