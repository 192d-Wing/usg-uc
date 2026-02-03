//! Policy engine.

use crate::action::PolicyAction;
use crate::condition::RequestContext;
use crate::error::{PolicyError, PolicyResult};
use crate::rule::{PolicyRule, RuleSet};
use std::collections::HashMap;

/// Policy decision.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The action to take.
    action: PolicyAction,
    /// The rule that matched (if any).
    matched_rule_id: Option<String>,
    /// Additional actions to execute (logging, etc.).
    additional_actions: Vec<PolicyAction>,
}

impl PolicyDecision {
    /// Creates a new policy decision.
    pub fn new(action: PolicyAction, matched_rule_id: Option<String>) -> Self {
        Self {
            action,
            matched_rule_id,
            additional_actions: Vec::new(),
        }
    }

    /// Creates an allow decision.
    pub fn allow() -> Self {
        Self::new(PolicyAction::Allow, None)
    }

    /// Creates a deny decision.
    pub fn deny(status_code: u16, reason: impl Into<String>) -> Self {
        Self::new(PolicyAction::deny(status_code, reason), None)
    }

    /// Adds an additional action.
    pub fn with_additional_action(mut self, action: PolicyAction) -> Self {
        self.additional_actions.push(action);
        self
    }

    /// Returns the primary action.
    pub fn action(&self) -> &PolicyAction {
        &self.action
    }

    /// Returns the matched rule ID.
    pub fn matched_rule_id(&self) -> Option<&str> {
        self.matched_rule_id.as_deref()
    }

    /// Returns the additional actions.
    pub fn additional_actions(&self) -> &[PolicyAction] {
        &self.additional_actions
    }

    /// Returns whether the decision allows the request.
    pub fn is_allowed(&self) -> bool {
        !self.action.is_deny()
    }

    /// Returns whether the decision is terminal.
    pub fn is_terminal(&self) -> bool {
        self.action.is_terminal()
    }
}

/// Policy engine configuration.
#[derive(Debug, Clone)]
pub struct PolicyEngineConfig {
    /// Whether to enable policy evaluation.
    pub enabled: bool,
    /// Default action when no rules match.
    pub default_action: PolicyAction,
    /// Whether to collect all matching rules (for logging).
    pub collect_all_matches: bool,
    /// Maximum number of rules per set.
    pub max_rules_per_set: usize,
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: PolicyAction::Allow,
            collect_all_matches: false,
            max_rules_per_set: 1000,
        }
    }
}

impl PolicyEngineConfig {
    /// Creates a new configuration with a default deny policy.
    pub fn deny_by_default(status_code: u16, reason: impl Into<String>) -> Self {
        Self {
            default_action: PolicyAction::deny(status_code, reason),
            ..Default::default()
        }
    }

    /// Sets whether policy evaluation is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets whether to collect all matching rules.
    pub fn with_collect_all_matches(mut self, collect: bool) -> Self {
        self.collect_all_matches = collect;
        self
    }
}

/// Policy engine.
#[derive(Debug)]
pub struct PolicyEngine {
    /// Configuration.
    config: PolicyEngineConfig,
    /// Named rule sets.
    rule_sets: HashMap<String, RuleSet>,
    /// Global rules applied to all requests.
    global_rules: RuleSet,
    /// Statistics.
    stats: PolicyStats,
}

/// Policy statistics.
#[derive(Debug, Clone, Default)]
pub struct PolicyStats {
    /// Total requests evaluated.
    pub requests_evaluated: u64,
    /// Requests allowed.
    pub requests_allowed: u64,
    /// Requests denied.
    pub requests_denied: u64,
    /// Rules matched.
    pub rules_matched: u64,
    /// Default action taken.
    pub default_actions: u64,
}

impl PolicyEngine {
    /// Creates a new policy engine.
    pub fn new(config: PolicyEngineConfig) -> Self {
        Self {
            config,
            rule_sets: HashMap::new(),
            global_rules: RuleSet::new(),
            stats: PolicyStats::default(),
        }
    }

    /// Creates a policy engine with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PolicyEngineConfig::default())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &PolicyEngineConfig {
        &self.config
    }

    /// Returns the statistics.
    pub fn stats(&self) -> &PolicyStats {
        &self.stats
    }

    /// Resets the statistics.
    pub fn reset_stats(&mut self) {
        self.stats = PolicyStats::default();
    }

    /// Adds a global rule.
    pub fn add_global_rule(&mut self, rule: PolicyRule) -> PolicyResult<()> {
        if self.global_rules.len() >= self.config.max_rules_per_set {
            return Err(PolicyError::TooManyRules {
                count: self.global_rules.len(),
                max: self.config.max_rules_per_set,
            });
        }
        self.global_rules.add_rule(rule);
        Ok(())
    }

    /// Removes a global rule by ID.
    pub fn remove_global_rule(&mut self, id: &str) -> Option<PolicyRule> {
        self.global_rules.remove_rule(id)
    }

    /// Returns the global rules.
    pub fn global_rules(&self) -> &RuleSet {
        &self.global_rules
    }

    /// Creates a new named rule set.
    pub fn create_rule_set(&mut self, name: impl Into<String>) -> PolicyResult<()> {
        let name = name.into();
        if self.rule_sets.contains_key(&name) {
            return Err(PolicyError::RuleSetExists { name });
        }
        self.rule_sets.insert(name, RuleSet::new());
        Ok(())
    }

    /// Removes a named rule set.
    pub fn remove_rule_set(&mut self, name: &str) -> Option<RuleSet> {
        self.rule_sets.remove(name)
    }

    /// Gets a named rule set.
    pub fn get_rule_set(&self, name: &str) -> Option<&RuleSet> {
        self.rule_sets.get(name)
    }

    /// Gets a mutable reference to a named rule set.
    pub fn get_rule_set_mut(&mut self, name: &str) -> Option<&mut RuleSet> {
        self.rule_sets.get_mut(name)
    }

    /// Adds a rule to a named rule set.
    pub fn add_rule_to_set(&mut self, set_name: &str, rule: PolicyRule) -> PolicyResult<()> {
        let rule_set =
            self.rule_sets
                .get_mut(set_name)
                .ok_or_else(|| PolicyError::RuleSetNotFound {
                    name: set_name.to_string(),
                })?;

        if rule_set.len() >= self.config.max_rules_per_set {
            return Err(PolicyError::TooManyRules {
                count: rule_set.len(),
                max: self.config.max_rules_per_set,
            });
        }

        rule_set.add_rule(rule);
        Ok(())
    }

    /// Evaluates a request against all policies.
    pub fn evaluate(&mut self, context: &RequestContext) -> PolicyDecision {
        self.stats.requests_evaluated += 1;

        // If disabled, return default allow
        if !self.config.enabled {
            self.stats.requests_allowed += 1;
            return PolicyDecision::allow();
        }

        // Collect additional actions if configured
        let mut additional_actions = Vec::new();

        // First, evaluate global rules
        if self.config.collect_all_matches {
            for (rule, action) in self.global_rules.evaluate_all(context) {
                if action.is_terminal() {
                    self.stats.rules_matched += 1;
                    let mut decision =
                        PolicyDecision::new(action.clone(), Some(rule.id().to_string()));
                    for a in additional_actions {
                        decision = decision.with_additional_action(a);
                    }
                    self.update_stats(&decision);
                    return decision;
                }
                additional_actions.push(action.clone());
            }
        } else if let Some(action) = self.evaluate_first_match(&self.global_rules, context) {
            self.stats.rules_matched += 1;
            let decision = PolicyDecision::new(action.0.clone(), Some(action.1.to_string()));
            self.update_stats(&decision);
            return decision;
        }

        // Then evaluate named rule sets (in arbitrary order)
        for rule_set in self.rule_sets.values() {
            if self.config.collect_all_matches {
                for (rule, action) in rule_set.evaluate_all(context) {
                    if action.is_terminal() {
                        self.stats.rules_matched += 1;
                        let mut decision =
                            PolicyDecision::new(action.clone(), Some(rule.id().to_string()));
                        for a in additional_actions {
                            decision = decision.with_additional_action(a);
                        }
                        self.update_stats(&decision);
                        return decision;
                    }
                    additional_actions.push(action.clone());
                }
            } else if let Some(action) = self.evaluate_first_match(rule_set, context) {
                self.stats.rules_matched += 1;
                let decision = PolicyDecision::new(action.0.clone(), Some(action.1.to_string()));
                self.update_stats(&decision);
                return decision;
            }
        }

        // No matching rule, use default action
        self.stats.default_actions += 1;
        let mut decision = PolicyDecision::new(self.config.default_action.clone(), None);
        for a in additional_actions {
            decision = decision.with_additional_action(a);
        }
        self.update_stats(&decision);
        decision
    }

    /// Evaluates a request against a specific rule set.
    pub fn evaluate_rule_set(
        &mut self,
        set_name: &str,
        context: &RequestContext,
    ) -> PolicyResult<PolicyDecision> {
        let rule_set =
            self.rule_sets
                .get(set_name)
                .ok_or_else(|| PolicyError::RuleSetNotFound {
                    name: set_name.to_string(),
                })?;

        self.stats.requests_evaluated += 1;

        let action = rule_set.evaluate(context);
        let matched = rule_set
            .rules()
            .iter()
            .find(|r| r.evaluate(context).is_some())
            .map(|r| r.id().to_string());

        if matched.is_some() {
            self.stats.rules_matched += 1;
        } else {
            self.stats.default_actions += 1;
        }

        let decision = PolicyDecision::new(action.clone(), matched);
        self.update_stats(&decision);
        Ok(decision)
    }

    /// Helper to find the first matching rule in a rule set.
    fn evaluate_first_match<'a>(
        &self,
        rule_set: &'a RuleSet,
        context: &RequestContext,
    ) -> Option<(&'a PolicyAction, &'a str)> {
        for rule in rule_set.rules() {
            if let Some(action) = rule.evaluate(context) {
                return Some((action, rule.id()));
            }
        }
        None
    }

    /// Updates statistics based on a decision.
    fn update_stats(&mut self, decision: &PolicyDecision) {
        if decision.is_allowed() {
            self.stats.requests_allowed += 1;
        } else {
            self.stats.requests_denied += 1;
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::LogLevel;
    use crate::condition::{Condition, StringMatch};
    use crate::rule::RulePriority;

    fn test_context() -> RequestContext {
        RequestContext::new()
            .with_source_ip("192.168.1.100")
            .with_method("INVITE")
            .with_from_uri("sip:alice@example.com")
            .with_to_uri("sip:bob@example.com")
    }

    #[test]
    fn test_policy_decision() {
        let decision = PolicyDecision::allow();
        assert!(decision.is_allowed());
        assert!(decision.matched_rule_id().is_none());
    }

    #[test]
    fn test_policy_decision_deny() {
        let decision = PolicyDecision::deny(403, "Forbidden");
        assert!(!decision.is_allowed());
        assert!(decision.is_terminal());
    }

    #[test]
    fn test_policy_decision_with_additional() {
        let decision = PolicyDecision::allow()
            .with_additional_action(PolicyAction::log("test", LogLevel::Info));
        assert_eq!(decision.additional_actions().len(), 1);
    }

    #[test]
    fn test_engine_creation() {
        let engine = PolicyEngine::with_defaults();
        assert!(engine.config().enabled);
        assert_eq!(engine.stats().requests_evaluated, 0);
    }

    #[test]
    fn test_engine_disabled() {
        let config = PolicyEngineConfig::default().with_enabled(false);
        let mut engine = PolicyEngine::new(config);

        let context = test_context();
        let decision = engine.evaluate(&context);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_engine_global_rules() {
        let mut engine = PolicyEngine::with_defaults();

        engine
            .add_global_rule(PolicyRule::new(
                "allow-invite",
                "Allow INVITE",
                Condition::Method(StringMatch::Exact("INVITE".to_string())),
                PolicyAction::Allow,
            ))
            .unwrap();

        let context = test_context();
        let decision = engine.evaluate(&context);
        assert!(decision.is_allowed());
        assert_eq!(decision.matched_rule_id(), Some("allow-invite"));
    }

    #[test]
    fn test_engine_default_action() {
        let config = PolicyEngineConfig::deny_by_default(403, "Forbidden");
        let mut engine = PolicyEngine::new(config);

        let context = test_context();
        let decision = engine.evaluate(&context);
        assert!(!decision.is_allowed());
        assert!(decision.matched_rule_id().is_none());
    }

    #[test]
    fn test_engine_rule_sets() {
        let mut engine = PolicyEngine::with_defaults();

        engine.create_rule_set("inbound").unwrap();
        engine
            .add_rule_to_set(
                "inbound",
                PolicyRule::new(
                    "block-spam",
                    "Block Spam",
                    Condition::FromUri(StringMatch::Contains("spam".to_string())),
                    PolicyAction::deny(403, "Spam blocked"),
                ),
            )
            .unwrap();

        assert!(engine.get_rule_set("inbound").is_some());
    }

    #[test]
    fn test_engine_rule_set_not_found() {
        let mut engine = PolicyEngine::with_defaults();

        let result = engine.add_rule_to_set(
            "nonexistent",
            PolicyRule::new("rule-1", "Test", Condition::Always, PolicyAction::Allow),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_engine_rule_set_exists() {
        let mut engine = PolicyEngine::with_defaults();

        engine.create_rule_set("test").unwrap();
        let result = engine.create_rule_set("test");

        assert!(result.is_err());
    }

    #[test]
    fn test_engine_evaluate_rule_set() {
        let mut engine = PolicyEngine::with_defaults();

        engine.create_rule_set("test").unwrap();
        engine
            .add_rule_to_set(
                "test",
                PolicyRule::new(
                    "allow-all",
                    "Allow All",
                    Condition::Always,
                    PolicyAction::Allow,
                ),
            )
            .unwrap();

        let context = test_context();
        let decision = engine.evaluate_rule_set("test", &context).unwrap();
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_engine_statistics() {
        let mut engine = PolicyEngine::with_defaults();

        engine
            .add_global_rule(PolicyRule::new(
                "allow-all",
                "Allow All",
                Condition::Always,
                PolicyAction::Allow,
            ))
            .unwrap();

        let context = test_context();
        engine.evaluate(&context);
        engine.evaluate(&context);

        assert_eq!(engine.stats().requests_evaluated, 2);
        assert_eq!(engine.stats().requests_allowed, 2);
        assert_eq!(engine.stats().rules_matched, 2);
    }

    #[test]
    fn test_engine_reset_stats() {
        let mut engine = PolicyEngine::with_defaults();

        engine
            .add_global_rule(PolicyRule::new(
                "allow-all",
                "Allow All",
                Condition::Always,
                PolicyAction::Allow,
            ))
            .unwrap();

        let context = test_context();
        engine.evaluate(&context);
        assert_eq!(engine.stats().requests_evaluated, 1);

        engine.reset_stats();
        assert_eq!(engine.stats().requests_evaluated, 0);
    }

    #[test]
    fn test_engine_priority_ordering() {
        let config =
            PolicyEngineConfig::deny_by_default(403, "Default Deny").with_collect_all_matches(true);
        let mut engine = PolicyEngine::new(config);

        // Add a low-priority allow rule
        engine
            .add_global_rule(
                PolicyRule::new(
                    "low-allow",
                    "Low Priority Allow",
                    Condition::Always,
                    PolicyAction::Allow,
                )
                .with_priority(RulePriority::low()),
            )
            .unwrap();

        // Add a high-priority deny rule
        engine
            .add_global_rule(
                PolicyRule::new(
                    "high-deny",
                    "High Priority Deny",
                    Condition::Always,
                    PolicyAction::deny(403, "High priority"),
                )
                .with_priority(RulePriority::high()),
            )
            .unwrap();

        let context = test_context();
        let decision = engine.evaluate(&context);

        // High priority deny should win
        assert!(!decision.is_allowed());
        assert_eq!(decision.matched_rule_id(), Some("high-deny"));
    }

    #[test]
    fn test_engine_remove_global_rule() {
        let mut engine = PolicyEngine::with_defaults();

        engine
            .add_global_rule(PolicyRule::new(
                "rule-1",
                "Test Rule",
                Condition::Always,
                PolicyAction::Allow,
            ))
            .unwrap();

        let removed = engine.remove_global_rule("rule-1");
        assert!(removed.is_some());
        assert!(engine.global_rules().is_empty());
    }

    #[test]
    fn test_engine_remove_rule_set() {
        let mut engine = PolicyEngine::with_defaults();

        engine.create_rule_set("test").unwrap();
        let removed = engine.remove_rule_set("test");

        assert!(removed.is_some());
        assert!(engine.get_rule_set("test").is_none());
    }

    #[test]
    fn test_engine_too_many_rules() {
        let config = PolicyEngineConfig {
            max_rules_per_set: 2,
            ..Default::default()
        };
        let mut engine = PolicyEngine::new(config);

        engine
            .add_global_rule(PolicyRule::new(
                "rule-1",
                "Rule 1",
                Condition::Always,
                PolicyAction::Allow,
            ))
            .unwrap();
        engine
            .add_global_rule(PolicyRule::new(
                "rule-2",
                "Rule 2",
                Condition::Always,
                PolicyAction::Allow,
            ))
            .unwrap();

        let result = engine.add_global_rule(PolicyRule::new(
            "rule-3",
            "Rule 3",
            Condition::Always,
            PolicyAction::Allow,
        ));

        assert!(result.is_err());
    }

    #[test]
    fn test_engine_collect_all_matches() {
        let config = PolicyEngineConfig::default().with_collect_all_matches(true);
        let mut engine = PolicyEngine::new(config);

        // Add logging rule (non-terminal)
        engine
            .add_global_rule(
                PolicyRule::new(
                    "log-all",
                    "Log All",
                    Condition::Always,
                    PolicyAction::log("Request received", LogLevel::Info),
                )
                .with_priority(RulePriority::high()),
            )
            .unwrap();

        // Add allow rule (terminal)
        engine
            .add_global_rule(
                PolicyRule::new(
                    "allow-all",
                    "Allow All",
                    Condition::Always,
                    PolicyAction::Allow,
                )
                .with_priority(RulePriority::normal()),
            )
            .unwrap();

        let context = test_context();
        let decision = engine.evaluate(&context);

        assert!(decision.is_allowed());
        // The log action should be collected as additional
        assert!(!decision.additional_actions().is_empty());
    }
}
