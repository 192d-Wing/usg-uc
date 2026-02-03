//! ACL filter implementation.

use crate::MAX_RULES;
use crate::error::{AclError, AclResult};
use crate::rule::{AclRule, RuleAction};
use std::collections::HashMap;
use std::net::IpAddr;

/// Filter action result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// Allow the traffic.
    Allow,
    /// Deny the traffic.
    Deny,
    /// Rate limit the traffic.
    RateLimit {
        /// Requests per second.
        rps: u32,
    },
}

impl FilterAction {
    /// Returns whether this action allows traffic.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow | Self::RateLimit { .. })
    }

    /// Returns whether this action denies traffic.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl From<RuleAction> for FilterAction {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Allow | RuleAction::LogAllow => FilterAction::Allow,
            RuleAction::Deny | RuleAction::LogDeny => FilterAction::Deny,
            RuleAction::RateLimit { rps } => FilterAction::RateLimit { rps },
        }
    }
}

/// Filter result.
#[derive(Debug)]
pub struct FilterResult {
    /// Action to take.
    action: FilterAction,
    /// ID of the matching rule (if any).
    rule_id: Option<String>,
    /// Whether logging was requested.
    should_log: bool,
}

impl FilterResult {
    /// Creates an allow result.
    pub fn allow() -> Self {
        Self {
            action: FilterAction::Allow,
            rule_id: None,
            should_log: false,
        }
    }

    /// Creates a deny result.
    pub fn deny() -> Self {
        Self {
            action: FilterAction::Deny,
            rule_id: None,
            should_log: false,
        }
    }

    /// Creates a result from a rule.
    pub fn from_rule(rule: &AclRule) -> Self {
        let should_log = matches!(rule.action(), RuleAction::LogAllow | RuleAction::LogDeny);

        Self {
            action: rule.action().into(),
            rule_id: Some(rule.id().to_string()),
            should_log,
        }
    }

    /// Returns the action.
    pub fn action(&self) -> FilterAction {
        self.action
    }

    /// Returns the matching rule ID.
    pub fn rule_id(&self) -> Option<&str> {
        self.rule_id.as_deref()
    }

    /// Returns whether logging was requested.
    pub fn should_log(&self) -> bool {
        self.should_log
    }

    /// Returns whether traffic is allowed.
    pub fn is_allowed(&self) -> bool {
        self.action.is_allow()
    }

    /// Returns whether traffic is denied.
    pub fn is_denied(&self) -> bool {
        self.action.is_deny()
    }
}

/// Default action when no rules match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    /// Allow if no rules match.
    Allow,
    /// Deny if no rules match.
    Deny,
}

/// ACL filter.
#[derive(Debug)]
pub struct AclFilter {
    /// Filter name.
    name: String,
    /// Rules (sorted by priority).
    rules: Vec<AclRule>,
    /// Rule index by ID.
    rule_index: HashMap<String, usize>,
    /// Default action.
    default_action: DefaultAction,
    /// Whether the filter is enabled.
    enabled: bool,
}

impl AclFilter {
    /// Creates a new filter.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rules: Vec::new(),
            rule_index: HashMap::new(),
            default_action: DefaultAction::Deny,
            enabled: true,
        }
    }

    /// Creates a filter with default allow.
    pub fn new_default_allow(name: impl Into<String>) -> Self {
        let mut filter = Self::new(name);
        filter.default_action = DefaultAction::Allow;
        filter
    }

    /// Returns the filter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns whether the filter is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enables the filter.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the filter.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns the default action.
    pub fn default_action(&self) -> DefaultAction {
        self.default_action
    }

    /// Sets the default action.
    pub fn set_default_action(&mut self, action: DefaultAction) {
        self.default_action = action;
    }

    /// Adds a rule.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn add_rule(&mut self, rule: AclRule) -> AclResult<()> {
        if self.rules.len() >= MAX_RULES {
            return Err(AclError::MaxRulesExceeded { max: MAX_RULES });
        }

        if self.rule_index.contains_key(rule.id()) {
            return Err(AclError::DuplicateRule {
                rule_id: rule.id().to_string(),
            });
        }

        let id = rule.id().to_string();
        self.rules.push(rule);

        // Sort by priority
        self.rules.sort_by_key(super::rule::AclRule::priority);

        // Rebuild index
        self.rule_index.clear();
        for (i, r) in self.rules.iter().enumerate() {
            self.rule_index.insert(r.id().to_string(), i);
        }

        // Ensure the rule was indexed
        if !self.rule_index.contains_key(&id) {
            return Err(AclError::InvalidRule {
                reason: "Failed to index rule".to_string(),
            });
        }

        Ok(())
    }

    /// Removes a rule by ID.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn remove_rule(&mut self, id: &str) -> AclResult<AclRule> {
        let idx = self
            .rule_index
            .get(id)
            .copied()
            .ok_or_else(|| AclError::RuleNotFound {
                rule_id: id.to_string(),
            })?;

        let rule = self.rules.remove(idx);

        // Rebuild index
        self.rule_index.clear();
        for (i, r) in self.rules.iter().enumerate() {
            self.rule_index.insert(r.id().to_string(), i);
        }

        Ok(rule)
    }

    /// Gets a rule by ID.
    pub fn get_rule(&self, id: &str) -> Option<&AclRule> {
        self.rule_index.get(id).map(|&idx| &self.rules[idx])
    }

    /// Gets a mutable reference to a rule by ID.
    pub fn get_rule_mut(&mut self, id: &str) -> Option<&mut AclRule> {
        self.rule_index.get(id).map(|&idx| &mut self.rules[idx])
    }

    /// Returns all rules.
    pub fn rules(&self) -> &[AclRule] {
        &self.rules
    }

    /// Filters a request.
    pub fn filter(
        &self,
        source_ip: IpAddr,
        dest_ip: Option<IpAddr>,
        method: Option<&str>,
    ) -> FilterResult {
        if !self.enabled {
            return FilterResult::allow();
        }

        // Find first matching rule
        for rule in &self.rules {
            if rule.matches(source_ip, dest_ip, method) {
                return FilterResult::from_rule(rule);
            }
        }

        // No rule matched, use default
        match self.default_action {
            DefaultAction::Allow => FilterResult::allow(),
            DefaultAction::Deny => FilterResult::deny(),
        }
    }

    /// Quick check if a source IP is allowed.
    pub fn is_allowed(&self, source_ip: IpAddr) -> bool {
        self.filter(source_ip, None, None).is_allowed()
    }
}

impl Default for AclFilter {
    fn default() -> Self {
        Self::new("default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::IpNetwork;
    use crate::rule::RulePriority;
    use std::net::Ipv4Addr;

    #[test]
    fn test_filter_action() {
        assert!(FilterAction::Allow.is_allow());
        assert!(FilterAction::Deny.is_deny());
        assert!(FilterAction::RateLimit { rps: 100 }.is_allow());
    }

    #[test]
    fn test_filter_result() {
        let result = FilterResult::allow();
        assert!(result.is_allowed());
        assert!(result.rule_id().is_none());

        let result = FilterResult::deny();
        assert!(result.is_denied());
    }

    #[test]
    fn test_filter_creation() {
        let filter = AclFilter::new("test-filter");
        assert_eq!(filter.name(), "test-filter");
        assert_eq!(filter.rule_count(), 0);
        assert!(filter.is_enabled());
    }

    #[test]
    fn test_filter_add_rule() {
        let mut filter = AclFilter::new("test");
        let rule = AclRule::allow_all("rule-1");

        filter.add_rule(rule).unwrap();
        assert_eq!(filter.rule_count(), 1);
        assert!(filter.get_rule("rule-1").is_some());
    }

    #[test]
    fn test_filter_duplicate_rule() {
        let mut filter = AclFilter::new("test");
        filter.add_rule(AclRule::allow_all("rule-1")).unwrap();

        // Should fail for duplicate
        assert!(filter.add_rule(AclRule::allow_all("rule-1")).is_err());
    }

    #[test]
    fn test_filter_remove_rule() {
        let mut filter = AclFilter::new("test");
        filter.add_rule(AclRule::allow_all("rule-1")).unwrap();

        let rule = filter.remove_rule("rule-1").unwrap();
        assert_eq!(rule.id(), "rule-1");
        assert_eq!(filter.rule_count(), 0);
    }

    #[test]
    fn test_filter_priority_order() {
        let mut filter = AclFilter::new("test");

        // Add rules in reverse priority order
        filter
            .add_rule(AclRule::deny_all("low").with_priority(RulePriority::new(1000)))
            .unwrap();
        filter
            .add_rule(AclRule::allow_all("high").with_priority(RulePriority::new(100)))
            .unwrap();

        // High priority rule should be first
        assert_eq!(filter.rules()[0].id(), "high");
        assert_eq!(filter.rules()[1].id(), "low");
    }

    #[test]
    fn test_filter_matches_first_rule() {
        let mut filter = AclFilter::new("test");

        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        filter
            .add_rule(
                AclRule::allow_source("allow-local", net).with_priority(RulePriority::new(100)),
            )
            .unwrap();
        filter
            .add_rule(AclRule::deny_all("deny-all").with_priority(RulePriority::new(1000)))
            .unwrap();

        // Local IP should be allowed
        let result = filter.filter(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), None, None);
        assert!(result.is_allowed());
        assert_eq!(result.rule_id(), Some("allow-local"));

        // External IP should be denied
        let result = filter.filter(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, None);
        assert!(result.is_denied());
        assert_eq!(result.rule_id(), Some("deny-all"));
    }

    #[test]
    fn test_filter_default_deny() {
        let filter = AclFilter::new("test");

        // No rules, default is deny
        let result = filter.filter(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, None);
        assert!(result.is_denied());
        assert!(result.rule_id().is_none());
    }

    #[test]
    fn test_filter_default_allow() {
        let filter = AclFilter::new_default_allow("test");

        // No rules, default is allow
        let result = filter.filter(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, None);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_filter_disabled() {
        let mut filter = AclFilter::new("test");
        filter.add_rule(AclRule::deny_all("deny-all")).unwrap();
        filter.disable();

        // Disabled filter allows everything
        let result = filter.filter(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, None);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_filter_is_allowed() {
        let mut filter = AclFilter::new("test");
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        filter
            .add_rule(AclRule::allow_source("allow", net))
            .unwrap();

        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_filter_with_method() {
        use crate::rule::RuleMatch;

        let mut filter = AclFilter::new("test");
        filter
            .add_rule(AclRule::new(
                "deny-register",
                "Deny REGISTER",
                RuleMatch::SipMethod("REGISTER".to_string()),
                RuleAction::Deny,
            ))
            .unwrap();

        // REGISTER should be denied
        let result = filter.filter(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            None,
            Some("REGISTER"),
        );
        assert!(result.is_denied());

        // INVITE should use default (deny since no default-allow)
        let result = filter.filter(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, Some("INVITE"));
        assert!(result.is_denied()); // No matching rule, default deny
    }
}
