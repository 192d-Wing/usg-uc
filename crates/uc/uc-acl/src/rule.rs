//! ACL rule definitions.

use crate::network::IpNetwork;
use std::net::IpAddr;

/// Rule priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RulePriority(pub u32);

impl RulePriority {
    /// Creates a new priority.
    pub fn new(priority: u32) -> Self {
        Self(priority)
    }

    /// Highest priority (processed first).
    pub fn highest() -> Self {
        Self(0)
    }

    /// Lowest priority (processed last).
    pub fn lowest() -> Self {
        Self(u32::MAX)
    }

    /// Default priority.
    pub fn default_priority() -> Self {
        Self(crate::DEFAULT_PRIORITY)
    }
}

impl Default for RulePriority {
    fn default() -> Self {
        Self::default_priority()
    }
}

impl std::fmt::Display for RulePriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Allow the traffic.
    Allow,
    /// Deny the traffic.
    Deny,
    /// Rate limit the traffic.
    RateLimit {
        /// Requests per second.
        rps: u32,
    },
    /// Log and allow.
    LogAllow,
    /// Log and deny.
    LogDeny,
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::RateLimit { rps } => write!(f, "rate-limit({}rps)", rps),
            Self::LogAllow => write!(f, "log-allow"),
            Self::LogDeny => write!(f, "log-deny"),
        }
    }
}

/// Rule match specification.
#[derive(Debug, Clone)]
pub enum RuleMatch {
    /// Match any.
    Any,
    /// Match source IP.
    SourceIp(IpNetwork),
    /// Match destination IP.
    DestIp(IpNetwork),
    /// Match source and destination IP.
    SourceAndDest {
        /// Source network.
        source: IpNetwork,
        /// Destination network.
        dest: IpNetwork,
    },
    /// Match SIP method.
    SipMethod(String),
    /// Match SIP URI pattern.
    SipUri(String),
    /// Match domain.
    Domain(String),
    /// Match multiple criteria (all must match).
    All(Vec<RuleMatch>),
    /// Match any criteria.
    AnyOf(Vec<RuleMatch>),
}

impl RuleMatch {
    /// Checks if this rule matches the given source IP.
    pub fn matches_source_ip(&self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::SourceIp(net) => net.contains(ip),
            Self::SourceAndDest { source, .. } => source.contains(ip),
            Self::All(rules) => rules.iter().all(|r| r.matches_source_ip(ip)),
            Self::AnyOf(rules) => rules.iter().any(|r| r.matches_source_ip(ip)),
            _ => true, // Other matches don't care about source IP
        }
    }

    /// Checks if this rule matches the given destination IP.
    pub fn matches_dest_ip(&self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::DestIp(net) => net.contains(ip),
            Self::SourceAndDest { dest, .. } => dest.contains(ip),
            Self::All(rules) => rules.iter().all(|r| r.matches_dest_ip(ip)),
            Self::AnyOf(rules) => rules.iter().any(|r| r.matches_dest_ip(ip)),
            _ => true, // Other matches don't care about dest IP
        }
    }

    /// Checks if this rule matches the given SIP method.
    pub fn matches_method(&self, method: &str) -> bool {
        match self {
            Self::Any => true,
            Self::SipMethod(m) => m.eq_ignore_ascii_case(method),
            Self::All(rules) => rules.iter().all(|r| r.matches_method(method)),
            Self::AnyOf(rules) => rules.iter().any(|r| r.matches_method(method)),
            _ => true,
        }
    }

    /// Checks if this rule matches the given domain.
    pub fn matches_domain(&self, domain: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Domain(d) => {
                // Simple domain matching (could be enhanced with wildcards)
                d.eq_ignore_ascii_case(domain)
                    || domain.ends_with(&format!(".{}", d.to_lowercase()))
            }
            Self::All(rules) => rules.iter().all(|r| r.matches_domain(domain)),
            Self::AnyOf(rules) => rules.iter().any(|r| r.matches_domain(domain)),
            _ => true,
        }
    }
}

/// ACL rule.
#[derive(Debug, Clone)]
pub struct AclRule {
    /// Rule ID.
    id: String,
    /// Rule name/description.
    name: String,
    /// Priority (lower = higher priority).
    priority: RulePriority,
    /// Match criteria.
    match_criteria: RuleMatch,
    /// Action to take.
    action: RuleAction,
    /// Whether the rule is enabled.
    enabled: bool,
}

impl AclRule {
    /// Creates a new rule.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        match_criteria: RuleMatch,
        action: RuleAction,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            priority: RulePriority::default(),
            match_criteria,
            action,
            enabled: true,
        }
    }

    /// Creates an allow rule for a source IP/network.
    pub fn allow_source(id: impl Into<String>, source: IpNetwork) -> Self {
        Self::new(
            id,
            format!("Allow {}", source),
            RuleMatch::SourceIp(source),
            RuleAction::Allow,
        )
    }

    /// Creates a deny rule for a source IP/network.
    pub fn deny_source(id: impl Into<String>, source: IpNetwork) -> Self {
        Self::new(
            id,
            format!("Deny {}", source),
            RuleMatch::SourceIp(source),
            RuleAction::Deny,
        )
    }

    /// Creates an allow-all rule.
    pub fn allow_all(id: impl Into<String>) -> Self {
        Self::new(id, "Allow All", RuleMatch::Any, RuleAction::Allow)
    }

    /// Creates a deny-all rule.
    pub fn deny_all(id: impl Into<String>) -> Self {
        Self::new(id, "Deny All", RuleMatch::Any, RuleAction::Deny)
    }

    /// Returns the rule ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the rule name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the priority.
    pub fn priority(&self) -> RulePriority {
        self.priority
    }

    /// Returns the match criteria.
    pub fn match_criteria(&self) -> &RuleMatch {
        &self.match_criteria
    }

    /// Returns the action.
    pub fn action(&self) -> RuleAction {
        self.action
    }

    /// Returns whether the rule is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the priority.
    pub fn with_priority(mut self, priority: RulePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Enables the rule.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the rule.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Checks if this rule matches a request.
    pub fn matches(
        &self,
        source_ip: IpAddr,
        dest_ip: Option<IpAddr>,
        method: Option<&str>,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        // Check source IP
        if !self.match_criteria.matches_source_ip(source_ip) {
            return false;
        }

        // Check dest IP if provided
        if let Some(dest) = dest_ip {
            if !self.match_criteria.matches_dest_ip(dest) {
                return false;
            }
        }

        // Check method if provided
        if let Some(m) = method {
            if !self.match_criteria.matches_method(m) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rule_priority() {
        let high = RulePriority::highest();
        let low = RulePriority::lowest();
        let default = RulePriority::default();

        assert!(high < default);
        assert!(default < low);
    }

    #[test]
    fn test_rule_action_display() {
        assert_eq!(RuleAction::Allow.to_string(), "allow");
        assert_eq!(RuleAction::Deny.to_string(), "deny");
        assert_eq!(
            RuleAction::RateLimit { rps: 100 }.to_string(),
            "rate-limit(100rps)"
        );
    }

    #[test]
    fn test_rule_match_any() {
        let m = RuleMatch::Any;
        assert!(m.matches_source_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(m.matches_method("INVITE"));
    }

    #[test]
    fn test_rule_match_source_ip() {
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        let m = RuleMatch::SourceIp(net);

        assert!(m.matches_source_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!m.matches_source_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_rule_match_method() {
        let m = RuleMatch::SipMethod("INVITE".to_string());
        assert!(m.matches_method("INVITE"));
        assert!(m.matches_method("invite"));
        assert!(!m.matches_method("BYE"));
    }

    #[test]
    fn test_rule_match_domain() {
        let m = RuleMatch::Domain("example.com".to_string());
        assert!(m.matches_domain("example.com"));
        assert!(m.matches_domain("sub.example.com"));
        assert!(!m.matches_domain("other.com"));
    }

    #[test]
    fn test_rule_match_all() {
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        let m = RuleMatch::All(vec![
            RuleMatch::SourceIp(net),
            RuleMatch::SipMethod("INVITE".to_string()),
        ]);

        assert!(m.matches_source_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(m.matches_method("INVITE"));
        assert!(!m.matches_method("BYE"));
    }

    #[test]
    fn test_acl_rule_creation() {
        let net = IpNetwork::parse("10.0.0.0/8").unwrap();
        let rule = AclRule::allow_source("rule-1", net);

        assert_eq!(rule.id(), "rule-1");
        assert_eq!(rule.action(), RuleAction::Allow);
        assert!(rule.is_enabled());
    }

    #[test]
    fn test_acl_rule_matches() {
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        let rule = AclRule::allow_source("rule-1", net);

        assert!(rule.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), None, None));
        assert!(!rule.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, None));
    }

    #[test]
    fn test_acl_rule_disabled() {
        let mut rule = AclRule::allow_all("rule-1");
        rule.disable();

        // Disabled rules never match
        assert!(!rule.matches(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, None));
    }

    #[test]
    fn test_deny_all_rule() {
        let rule = AclRule::deny_all("deny-all");
        assert_eq!(rule.action(), RuleAction::Deny);
        assert!(rule.matches(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, None));
    }

    #[test]
    fn test_rule_priority_setting() {
        let rule = AclRule::allow_all("rule-1").with_priority(RulePriority::new(100));

        assert_eq!(rule.priority().0, 100);
    }
}
