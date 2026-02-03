//! Policy engine integration tests.

use uc_policy::{
    action::{LogLevel, PolicyAction},
    condition::Condition,
    engine::{PolicyEngine, PolicyEngineConfig},
    rule::{PolicyRule, RulePriority, RuleSet},
};

#[test]
fn test_policy_engine_basic() {
    let config = PolicyEngineConfig::default();
    let engine = PolicyEngine::new(config);

    // Engine starts empty
    assert!(engine.stats().requests_evaluated == 0);
}

#[test]
fn test_policy_rule_creation() {
    let rule = PolicyRule::new(
        "test-rule",
        "Test Rule",
        Condition::Always,
        PolicyAction::Allow,
    )
    .with_priority(RulePriority::high());

    assert_eq!(rule.id(), "test-rule");
    assert!(rule.is_enabled());
}

#[test]
fn test_policy_rule_allow_all() {
    let rule = PolicyRule::allow_all("allow-all");
    assert_eq!(rule.id(), "allow-all");
}

#[test]
fn test_rule_set() {
    let mut rule_set = RuleSet::new();

    let rule1 = PolicyRule::new("rule-1", "Rule 1", Condition::Always, PolicyAction::Allow)
        .with_priority(RulePriority::high());

    let rule2 = PolicyRule::new(
        "rule-2",
        "Rule 2",
        Condition::Always,
        PolicyAction::log("test log", LogLevel::Info),
    )
    .with_priority(RulePriority::low());

    rule_set.add_rule(rule1);
    rule_set.add_rule(rule2);

    assert_eq!(rule_set.len(), 2);
}

#[test]
fn test_condition_matching() {
    use uc_policy::condition::RequestContext;

    let ctx = RequestContext::new();

    let always = Condition::Always;
    assert!(always.matches(&ctx));

    let never = Condition::Never;
    assert!(!never.matches(&ctx));
}

#[test]
fn test_policy_action_terminal() {
    assert!(PolicyAction::Allow.is_terminal());
    assert!(PolicyAction::deny(403, "Forbidden").is_terminal());
    assert!(!PolicyAction::log("test", LogLevel::Info).is_terminal());
    assert!(!PolicyAction::Continue.is_terminal());
}

#[test]
fn test_rule_priority() {
    let high = RulePriority::high();
    let normal = RulePriority::normal();
    let low = RulePriority::low();

    // High priority has lower value (evaluated first)
    assert!(high < normal);
    assert!(normal < low);
}
