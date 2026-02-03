//! Policy rules.

use crate::action::PolicyAction;
use crate::condition::{Condition, RequestContext};

/// Rule priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RulePriority(pub u32);

impl Default for RulePriority {
    fn default() -> Self {
        Self(1000)
    }
}

impl RulePriority {
    /// Creates a high priority rule (processed first).
    pub fn high() -> Self {
        Self(100)
    }

    /// Creates a normal priority rule.
    pub fn normal() -> Self {
        Self(1000)
    }

    /// Creates a low priority rule (processed last).
    pub fn low() -> Self {
        Self(10000)
    }

    /// Creates a custom priority.
    pub fn custom(priority: u32) -> Self {
        Self(priority)
    }
}

/// Policy rule.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Rule ID.
    id: String,
    /// Rule name.
    name: String,
    /// Rule description.
    description: Option<String>,
    /// Rule priority (lower = higher priority).
    priority: RulePriority,
    /// Whether the rule is enabled.
    enabled: bool,
    /// Condition that must match for the rule to apply.
    condition: Condition,
    /// Action to take when the rule matches.
    action: PolicyAction,
}

impl PolicyRule {
    /// Creates a new policy rule.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        condition: Condition,
        action: PolicyAction,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            priority: RulePriority::default(),
            enabled: true,
            condition,
            action,
        }
    }

    /// Creates a rule that always allows.
    pub fn allow_all(id: impl Into<String>) -> Self {
        Self::new(id, "Allow All", Condition::Always, PolicyAction::Allow)
    }

    /// Creates a rule that always denies.
    pub fn deny_all(id: impl Into<String>, status_code: u16, reason: impl Into<String>) -> Self {
        Self::new(
            id,
            "Deny All",
            Condition::Always,
            PolicyAction::deny(status_code, reason),
        )
    }

    /// Sets the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the priority.
    pub fn with_priority(mut self, priority: RulePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Sets whether the rule is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Returns the rule ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the rule name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the rule description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the rule priority.
    pub fn priority(&self) -> RulePriority {
        self.priority
    }

    /// Returns whether the rule is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the condition.
    pub fn condition(&self) -> &Condition {
        &self.condition
    }

    /// Returns the action.
    pub fn action(&self) -> &PolicyAction {
        &self.action
    }

    /// Evaluates the rule against a request context.
    pub fn evaluate(&self, context: &RequestContext) -> Option<&PolicyAction> {
        if !self.enabled {
            return None;
        }
        if self.condition.matches(context) {
            Some(&self.action)
        } else {
            None
        }
    }
}

/// A set of policy rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Rules in the set.
    rules: Vec<PolicyRule>,
    /// Default action when no rules match.
    default_action: PolicyAction,
}

impl RuleSet {
    /// Creates a new empty rule set.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: PolicyAction::Allow,
        }
    }

    /// Creates a rule set with a default deny action.
    pub fn deny_by_default(status_code: u16, reason: impl Into<String>) -> Self {
        Self {
            rules: Vec::new(),
            default_action: PolicyAction::deny(status_code, reason),
        }
    }

    /// Sets the default action.
    pub fn with_default_action(mut self, action: PolicyAction) -> Self {
        self.default_action = action;
        self
    }

    /// Adds a rule to the set.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        // Keep rules sorted by priority
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Removes a rule by ID.
    pub fn remove_rule(&mut self, id: &str) -> Option<PolicyRule> {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            Some(self.rules.remove(pos))
        } else {
            None
        }
    }

    /// Gets a rule by ID.
    pub fn get_rule(&self, id: &str) -> Option<&PolicyRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// Gets a mutable reference to a rule by ID.
    pub fn get_rule_mut(&mut self, id: &str) -> Option<&mut PolicyRule> {
        self.rules.iter_mut().find(|r| r.id == id)
    }

    /// Returns all rules.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Returns the number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns whether the rule set is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns the default action.
    pub fn default_action(&self) -> &PolicyAction {
        &self.default_action
    }

    /// Evaluates all rules against a request context.
    /// Returns the action from the first matching rule, or the default action.
    pub fn evaluate(&self, context: &RequestContext) -> &PolicyAction {
        for rule in &self.rules {
            if let Some(action) = rule.evaluate(context) {
                return action;
            }
        }
        &self.default_action
    }

    /// Evaluates all rules and collects all matching actions.
    /// Useful for logging/auditing purposes.
    pub fn evaluate_all(&self, context: &RequestContext) -> Vec<(&PolicyRule, &PolicyAction)> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if let Some(action) = rule.evaluate(context) {
                matches.push((rule, action));
            }
        }
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::StringMatch;

    fn test_context() -> RequestContext {
        RequestContext::new()
            .with_source_ip("192.168.1.100")
            .with_dest_ip("10.0.0.1")
            .with_method("INVITE")
            .with_from_uri("sip:alice@example.com")
            .with_to_uri("sip:bob@example.com")
    }

    #[test]
    fn test_rule_priority() {
        assert!(RulePriority::high() < RulePriority::normal());
        assert!(RulePriority::normal() < RulePriority::low());
    }

    #[test]
    fn test_policy_rule_creation() {
        let rule = PolicyRule::new(
            "rule-1",
            "Test Rule",
            Condition::Method(StringMatch::Exact("INVITE".to_string())),
            PolicyAction::Allow,
        );

        assert_eq!(rule.id(), "rule-1");
        assert_eq!(rule.name(), "Test Rule");
        assert!(rule.is_enabled());
    }

    #[test]
    fn test_policy_rule_builder() {
        let rule = PolicyRule::new(
            "rule-1",
            "Test Rule",
            Condition::Always,
            PolicyAction::Allow,
        )
        .with_description("A test rule")
        .with_priority(RulePriority::high())
        .with_enabled(false);

        assert_eq!(rule.description(), Some("A test rule"));
        assert_eq!(rule.priority(), RulePriority::high());
        assert!(!rule.is_enabled());
    }

    #[test]
    fn test_policy_rule_evaluate() {
        let rule = PolicyRule::new(
            "invite-allow",
            "Allow INVITE",
            Condition::Method(StringMatch::Exact("INVITE".to_string())),
            PolicyAction::Allow,
        );

        let context = test_context();
        let action = rule.evaluate(&context);
        assert!(action.is_some());
        assert!(matches!(action.unwrap(), PolicyAction::Allow));
    }

    #[test]
    fn test_policy_rule_no_match() {
        let rule = PolicyRule::new(
            "register-allow",
            "Allow REGISTER",
            Condition::Method(StringMatch::Exact("REGISTER".to_string())),
            PolicyAction::Allow,
        );

        let context = test_context(); // INVITE method
        let action = rule.evaluate(&context);
        assert!(action.is_none());
    }

    #[test]
    fn test_policy_rule_disabled() {
        let rule = PolicyRule::new("rule-1", "Disabled Rule", Condition::Always, PolicyAction::Allow)
            .with_enabled(false);

        let context = test_context();
        let action = rule.evaluate(&context);
        assert!(action.is_none());
    }

    #[test]
    fn test_allow_all_rule() {
        let rule = PolicyRule::allow_all("allow-all");
        let context = test_context();
        let action = rule.evaluate(&context);
        assert!(action.is_some());
    }

    #[test]
    fn test_deny_all_rule() {
        let rule = PolicyRule::deny_all("deny-all", 403, "Forbidden");
        let context = test_context();
        let action = rule.evaluate(&context);
        assert!(action.is_some());
        assert!(action.unwrap().is_deny());
    }

    #[test]
    fn test_rule_set_creation() {
        let rule_set = RuleSet::new();
        assert!(rule_set.is_empty());
        assert!(matches!(rule_set.default_action(), PolicyAction::Allow));
    }

    #[test]
    fn test_rule_set_deny_by_default() {
        let rule_set = RuleSet::deny_by_default(403, "Forbidden");
        assert!(rule_set.default_action().is_deny());
    }

    #[test]
    fn test_rule_set_add_rule() {
        let mut rule_set = RuleSet::new();
        rule_set.add_rule(PolicyRule::new(
            "rule-1",
            "Test Rule",
            Condition::Always,
            PolicyAction::Allow,
        ));

        assert_eq!(rule_set.len(), 1);
        assert!(rule_set.get_rule("rule-1").is_some());
    }

    #[test]
    fn test_rule_set_remove_rule() {
        let mut rule_set = RuleSet::new();
        rule_set.add_rule(PolicyRule::new(
            "rule-1",
            "Test Rule",
            Condition::Always,
            PolicyAction::Allow,
        ));

        let removed = rule_set.remove_rule("rule-1");
        assert!(removed.is_some());
        assert!(rule_set.is_empty());
    }

    #[test]
    fn test_rule_set_priority_ordering() {
        let mut rule_set = RuleSet::new();

        rule_set.add_rule(
            PolicyRule::new("low", "Low Priority", Condition::Always, PolicyAction::Allow)
                .with_priority(RulePriority::low()),
        );
        rule_set.add_rule(
            PolicyRule::new(
                "high",
                "High Priority",
                Condition::Always,
                PolicyAction::deny(403, "High"),
            )
            .with_priority(RulePriority::high()),
        );
        rule_set.add_rule(
            PolicyRule::new(
                "normal",
                "Normal Priority",
                Condition::Always,
                PolicyAction::Continue,
            )
            .with_priority(RulePriority::normal()),
        );

        // Rules should be sorted by priority
        let rules = rule_set.rules();
        assert_eq!(rules[0].id(), "high");
        assert_eq!(rules[1].id(), "normal");
        assert_eq!(rules[2].id(), "low");
    }

    #[test]
    fn test_rule_set_evaluate() {
        let mut rule_set = RuleSet::deny_by_default(403, "Forbidden");

        rule_set.add_rule(PolicyRule::new(
            "allow-invite",
            "Allow INVITE",
            Condition::Method(StringMatch::Exact("INVITE".to_string())),
            PolicyAction::Allow,
        ));

        let context = test_context();
        let action = rule_set.evaluate(&context);
        assert!(matches!(action, PolicyAction::Allow));
    }

    #[test]
    fn test_rule_set_evaluate_no_match() {
        let mut rule_set = RuleSet::deny_by_default(403, "Forbidden");

        rule_set.add_rule(PolicyRule::new(
            "allow-register",
            "Allow REGISTER",
            Condition::Method(StringMatch::Exact("REGISTER".to_string())),
            PolicyAction::Allow,
        ));

        let context = test_context(); // INVITE method
        let action = rule_set.evaluate(&context);
        assert!(action.is_deny()); // Default deny
    }

    #[test]
    fn test_rule_set_evaluate_all() {
        let mut rule_set = RuleSet::new();

        rule_set.add_rule(
            PolicyRule::new(
                "log-all",
                "Log All",
                Condition::Always,
                PolicyAction::log("Request received", crate::action::LogLevel::Info),
            )
            .with_priority(RulePriority::high()),
        );

        rule_set.add_rule(
            PolicyRule::new(
                "allow-invite",
                "Allow INVITE",
                Condition::Method(StringMatch::Exact("INVITE".to_string())),
                PolicyAction::Allow,
            )
            .with_priority(RulePriority::normal()),
        );

        let context = test_context();
        let matches = rule_set.evaluate_all(&context);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_rule_set_first_match_wins() {
        let mut rule_set = RuleSet::new();

        rule_set.add_rule(
            PolicyRule::new(
                "deny-first",
                "Deny First",
                Condition::Always,
                PolicyAction::deny(403, "First"),
            )
            .with_priority(RulePriority::high()),
        );

        rule_set.add_rule(
            PolicyRule::new("allow-second", "Allow Second", Condition::Always, PolicyAction::Allow)
                .with_priority(RulePriority::normal()),
        );

        let context = test_context();
        let action = rule_set.evaluate(&context);
        // Should get the deny action (higher priority)
        assert!(action.is_deny());
    }
}
