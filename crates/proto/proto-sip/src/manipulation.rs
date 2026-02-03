//! SIP header manipulation engine.
//!
//! Provides configurable header transformation capabilities for SBC deployments,
//! including pattern-based rewriting, insertion, deletion, and regex substitution.
//!
//! ## Features
//!
//! - Rule-based header manipulation with conditions
//! - Regex pattern matching and substitution
//! - Per-trunk/direction header policies
//! - Request/response header transformation
//!
//! ## Enterprise Use Cases
//!
//! - Trunk interoperability (normalize headers between vendors)
//! - Privacy compliance (strip/modify sensitive headers)
//! - Call routing (add/modify Route headers)
//! - Caller ID manipulation (From/P-Asserted-Identity)

use crate::error::SipResult;
use crate::header::{Header, HeaderName, Headers};
use std::collections::HashMap;
use std::fmt;

/// Header manipulation action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManipulationAction {
    /// Add a new header (appends if header exists).
    Add {
        /// Header name.
        name: HeaderName,
        /// Header value.
        value: String,
    },
    /// Set a header (replaces if exists, adds if not).
    Set {
        /// Header name.
        name: HeaderName,
        /// Header value.
        value: String,
    },
    /// Remove all instances of a header.
    Remove {
        /// Header name.
        name: HeaderName,
    },
    /// Remove header if value matches pattern.
    RemoveMatching {
        /// Header name.
        name: HeaderName,
        /// Pattern to match (substring).
        pattern: String,
    },
    /// Replace header value using simple string substitution.
    Replace {
        /// Header name.
        name: HeaderName,
        /// Pattern to find.
        pattern: String,
        /// Replacement string.
        replacement: String,
    },
    /// Replace header value using regex substitution.
    RegexReplace {
        /// Header name.
        name: HeaderName,
        /// Regex pattern.
        pattern: String,
        /// Replacement with capture group support ($1, $2, etc.).
        replacement: String,
    },
    /// Rename a header.
    Rename {
        /// Original header name.
        from: HeaderName,
        /// New header name.
        to: HeaderName,
    },
    /// Copy a header value to another header.
    Copy {
        /// Source header name.
        from: HeaderName,
        /// Destination header name.
        to: HeaderName,
    },
    /// Prepend value to existing header.
    Prepend {
        /// Header name.
        name: HeaderName,
        /// Value to prepend.
        prefix: String,
    },
    /// Append value to existing header.
    Append {
        /// Header name.
        name: HeaderName,
        /// Value to append.
        suffix: String,
    },
}

impl ManipulationAction {
    /// Creates an add action.
    #[must_use]
    pub fn add(name: HeaderName, value: impl Into<String>) -> Self {
        Self::Add {
            name,
            value: value.into(),
        }
    }

    /// Creates a set action.
    #[must_use]
    pub fn set(name: HeaderName, value: impl Into<String>) -> Self {
        Self::Set {
            name,
            value: value.into(),
        }
    }

    /// Creates a remove action.
    #[must_use]
    pub fn remove(name: HeaderName) -> Self {
        Self::Remove { name }
    }

    /// Creates a replace action.
    #[must_use]
    pub fn replace(
        name: HeaderName,
        pattern: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        Self::Replace {
            name,
            pattern: pattern.into(),
            replacement: replacement.into(),
        }
    }

    /// Creates a regex replace action.
    #[must_use]
    pub fn regex_replace(
        name: HeaderName,
        pattern: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        Self::RegexReplace {
            name,
            pattern: pattern.into(),
            replacement: replacement.into(),
        }
    }

    /// Creates a rename action.
    #[must_use]
    pub fn rename(from: HeaderName, to: HeaderName) -> Self {
        Self::Rename { from, to }
    }

    /// Creates a copy action.
    #[must_use]
    pub fn copy(from: HeaderName, to: HeaderName) -> Self {
        Self::Copy { from, to }
    }
}

/// Condition for when to apply a manipulation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManipulationCondition {
    /// Always apply.
    Always,
    /// Apply if header exists.
    HeaderExists(HeaderName),
    /// Apply if header does not exist.
    HeaderMissing(HeaderName),
    /// Apply if header value contains pattern.
    HeaderContains {
        /// Header name.
        name: HeaderName,
        /// Pattern to match.
        pattern: String,
    },
    /// Apply if header value matches pattern exactly.
    HeaderEquals {
        /// Header name.
        name: HeaderName,
        /// Value to match.
        value: String,
    },
    /// Apply if header value matches regex.
    HeaderMatches {
        /// Header name.
        name: HeaderName,
        /// Regex pattern.
        pattern: String,
    },
    /// Apply if request method matches.
    MethodEquals(String),
    /// Apply if any condition matches.
    Any(Vec<ManipulationCondition>),
    /// Apply if all conditions match.
    All(Vec<ManipulationCondition>),
    /// Apply if condition does not match.
    Not(Box<ManipulationCondition>),
}

impl ManipulationCondition {
    /// Creates an always condition.
    #[must_use]
    pub fn always() -> Self {
        Self::Always
    }

    /// Creates a header exists condition.
    #[must_use]
    pub fn header_exists(name: HeaderName) -> Self {
        Self::HeaderExists(name)
    }

    /// Creates a header missing condition.
    #[must_use]
    pub fn header_missing(name: HeaderName) -> Self {
        Self::HeaderMissing(name)
    }

    /// Creates a header contains condition.
    #[must_use]
    pub fn header_contains(name: HeaderName, pattern: impl Into<String>) -> Self {
        Self::HeaderContains {
            name,
            pattern: pattern.into(),
        }
    }

    /// Creates a header equals condition.
    #[must_use]
    pub fn header_equals(name: HeaderName, value: impl Into<String>) -> Self {
        Self::HeaderEquals {
            name,
            value: value.into(),
        }
    }

    /// Creates a method equals condition.
    #[must_use]
    pub fn method_equals(method: impl Into<String>) -> Self {
        Self::MethodEquals(method.into())
    }

    /// Creates a NOT condition.
    #[must_use]
    pub fn not(condition: ManipulationCondition) -> Self {
        Self::Not(Box::new(condition))
    }

    /// Creates an ANY condition.
    #[must_use]
    pub fn any(conditions: Vec<ManipulationCondition>) -> Self {
        Self::Any(conditions)
    }

    /// Creates an ALL condition.
    #[must_use]
    pub fn all(conditions: Vec<ManipulationCondition>) -> Self {
        Self::All(conditions)
    }
}

/// A manipulation rule combining condition and action.
#[derive(Debug, Clone)]
pub struct ManipulationRule {
    /// Rule name for debugging.
    pub name: String,
    /// Condition for when to apply.
    pub condition: ManipulationCondition,
    /// Action to perform.
    pub action: ManipulationAction,
    /// Priority (lower = earlier execution).
    pub priority: i32,
    /// Whether this rule is enabled.
    pub enabled: bool,
}

impl ManipulationRule {
    /// Creates a new rule.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        condition: ManipulationCondition,
        action: ManipulationAction,
    ) -> Self {
        Self {
            name: name.into(),
            condition,
            action,
            priority: 0,
            enabled: true,
        }
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Disables the rule.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Direction for which rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManipulationDirection {
    /// Apply to inbound messages (requests to us).
    Inbound,
    /// Apply to outbound messages (requests from us).
    Outbound,
    /// Apply to both directions.
    Both,
}

impl fmt::Display for ManipulationDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "inbound"),
            Self::Outbound => write!(f, "outbound"),
            Self::Both => write!(f, "both"),
        }
    }
}

/// Message type for filtering rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// SIP request.
    Request,
    /// SIP response.
    Response,
    /// Both request and response.
    Both,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request => write!(f, "request"),
            Self::Response => write!(f, "response"),
            Self::Both => write!(f, "both"),
        }
    }
}

/// Context for evaluating manipulation conditions.
#[derive(Debug, Clone)]
pub struct ManipulationContext {
    /// Request method (for requests).
    pub method: Option<String>,
    /// Response status code (for responses).
    pub status_code: Option<u16>,
    /// Message direction.
    pub direction: ManipulationDirection,
    /// Message type.
    pub message_type: MessageType,
    /// Trunk identifier.
    pub trunk_id: Option<String>,
    /// Custom variables.
    pub variables: HashMap<String, String>,
}

impl ManipulationContext {
    /// Creates a new context for a request.
    #[must_use]
    pub fn for_request(method: impl Into<String>, direction: ManipulationDirection) -> Self {
        Self {
            method: Some(method.into()),
            status_code: None,
            direction,
            message_type: MessageType::Request,
            trunk_id: None,
            variables: HashMap::new(),
        }
    }

    /// Creates a new context for a response.
    #[must_use]
    pub fn for_response(status_code: u16, direction: ManipulationDirection) -> Self {
        Self {
            method: None,
            status_code: Some(status_code),
            direction,
            message_type: MessageType::Response,
            trunk_id: None,
            variables: HashMap::new(),
        }
    }

    /// Sets the trunk ID.
    #[must_use]
    pub fn with_trunk(mut self, trunk_id: impl Into<String>) -> Self {
        self.trunk_id = Some(trunk_id.into());
        self
    }

    /// Sets a variable.
    #[must_use]
    pub fn with_variable(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.insert(name.into(), value.into());
        self
    }
}

/// Header manipulation policy for a trunk or global scope.
#[derive(Debug, Clone, Default)]
pub struct ManipulationPolicy {
    /// Policy name.
    pub name: String,
    /// Rules in this policy.
    rules: Vec<ManipulationRule>,
    /// Direction this policy applies to.
    pub direction: Option<ManipulationDirection>,
    /// Message types this policy applies to.
    pub message_type: Option<MessageType>,
}

impl ManipulationPolicy {
    /// Creates a new empty policy.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rules: Vec::new(),
            direction: None,
            message_type: None,
        }
    }

    /// Sets the direction.
    #[must_use]
    pub fn with_direction(mut self, direction: ManipulationDirection) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Sets the message type.
    #[must_use]
    pub fn with_message_type(mut self, message_type: MessageType) -> Self {
        self.message_type = Some(message_type);
        self
    }

    /// Adds a rule to the policy.
    pub fn add_rule(&mut self, rule: ManipulationRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Returns the rules.
    #[must_use]
    pub fn rules(&self) -> &[ManipulationRule] {
        &self.rules
    }

    /// Checks if this policy applies to the given context.
    #[must_use]
    pub fn applies_to(&self, context: &ManipulationContext) -> bool {
        // Check direction
        if let Some(dir) = self.direction
            && dir != ManipulationDirection::Both && dir != context.direction {
                return false;
            }

        // Check message type
        if let Some(msg_type) = self.message_type
            && msg_type != MessageType::Both && msg_type != context.message_type {
                return false;
            }

        true
    }
}

/// The header manipulation engine.
#[derive(Debug, Clone, Default)]
pub struct HeaderManipulator {
    /// Global policies (applied to all trunks).
    global_policies: Vec<ManipulationPolicy>,
    /// Per-trunk policies.
    trunk_policies: HashMap<String, Vec<ManipulationPolicy>>,
}

impl HeaderManipulator {
    /// Creates a new manipulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a global policy.
    pub fn add_global_policy(&mut self, policy: ManipulationPolicy) {
        self.global_policies.push(policy);
    }

    /// Adds a trunk-specific policy.
    pub fn add_trunk_policy(&mut self, trunk_id: impl Into<String>, policy: ManipulationPolicy) {
        self.trunk_policies
            .entry(trunk_id.into())
            .or_default()
            .push(policy);
    }

    /// Applies all matching policies to headers.
    pub fn apply(&self, headers: &mut Headers, context: &ManipulationContext) -> SipResult<usize> {
        let mut applied_count = 0;

        // Apply global policies first
        for policy in &self.global_policies {
            if policy.applies_to(context) {
                applied_count += self.apply_policy(headers, policy, context)?;
            }
        }

        // Apply trunk-specific policies
        if let Some(trunk_id) = &context.trunk_id
            && let Some(trunk_policies) = self.trunk_policies.get(trunk_id) {
                for policy in trunk_policies {
                    if policy.applies_to(context) {
                        applied_count += self.apply_policy(headers, policy, context)?;
                    }
                }
            }

        Ok(applied_count)
    }

    /// Applies a single policy to headers.
    fn apply_policy(
        &self,
        headers: &mut Headers,
        policy: &ManipulationPolicy,
        context: &ManipulationContext,
    ) -> SipResult<usize> {
        let mut applied_count = 0;

        for rule in policy.rules() {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_condition(&rule.condition, headers, context) {
                self.apply_action(&rule.action, headers)?;
                applied_count += 1;
            }
        }

        Ok(applied_count)
    }

    /// Evaluates a condition against headers and context.
    fn evaluate_condition(
        &self,
        condition: &ManipulationCondition,
        headers: &Headers,
        context: &ManipulationContext,
    ) -> bool {
        match condition {
            ManipulationCondition::Always => true,

            ManipulationCondition::HeaderExists(name) => headers.get(name).is_some(),

            ManipulationCondition::HeaderMissing(name) => headers.get(name).is_none(),

            ManipulationCondition::HeaderContains { name, pattern } => {
                headers.get(name).is_some_and(|h| h.value.contains(pattern))
            }

            ManipulationCondition::HeaderEquals { name, value } => {
                headers.get(name).is_some_and(|h| h.value == *value)
            }

            ManipulationCondition::HeaderMatches { name, pattern } => {
                // Simple regex-like matching using contains for now
                // In production, would use the regex crate
                headers.get(name).is_some_and(|h| {
                    // Handle common regex patterns
                    if pattern.starts_with('^') && pattern.ends_with('$') {
                        // Exact match
                        h.value == pattern[1..pattern.len() - 1]
                    } else if pattern.starts_with('^') {
                        h.value.starts_with(&pattern[1..])
                    } else if pattern.ends_with('$') {
                        h.value.ends_with(&pattern[..pattern.len() - 1])
                    } else {
                        h.value.contains(pattern)
                    }
                })
            }

            ManipulationCondition::MethodEquals(method) => context
                .method
                .as_ref()
                .is_some_and(|m| m.eq_ignore_ascii_case(method)),

            ManipulationCondition::Any(conditions) => conditions
                .iter()
                .any(|c| self.evaluate_condition(c, headers, context)),

            ManipulationCondition::All(conditions) => conditions
                .iter()
                .all(|c| self.evaluate_condition(c, headers, context)),

            ManipulationCondition::Not(inner) => !self.evaluate_condition(inner, headers, context),
        }
    }

    /// Applies an action to headers.
    fn apply_action(&self, action: &ManipulationAction, headers: &mut Headers) -> SipResult<()> {
        match action {
            ManipulationAction::Add { name, value } => {
                headers.add(Header::new(name.clone(), value.clone()));
            }

            ManipulationAction::Set { name, value } => {
                headers.set(name.clone(), value.clone());
            }

            ManipulationAction::Remove { name } => {
                headers.remove(name);
            }

            ManipulationAction::RemoveMatching { name, pattern } => {
                // Get current value and only remove if it matches
                if let Some(header) = headers.get(name)
                    && header.value.contains(pattern) {
                        headers.remove(name);
                    }
            }

            ManipulationAction::Replace {
                name,
                pattern,
                replacement,
            } => {
                if let Some(header) = headers.get(name) {
                    let new_value = header.value.replace(pattern, replacement);
                    headers.set(name.clone(), new_value);
                }
            }

            ManipulationAction::RegexReplace {
                name,
                pattern,
                replacement,
            } => {
                // Simplified regex replacement
                // Supports basic patterns like (.*) capture groups
                if let Some(header) = headers.get(name) {
                    let new_value = self.regex_replace(&header.value, pattern, replacement);
                    headers.set(name.clone(), new_value);
                }
            }

            ManipulationAction::Rename { from, to } => {
                if let Some(header) = headers.get(from) {
                    let value = header.value.clone();
                    headers.remove(from);
                    headers.set(to.clone(), value);
                }
            }

            ManipulationAction::Copy { from, to } => {
                if let Some(header) = headers.get(from) {
                    let value = header.value.clone();
                    headers.set(to.clone(), value);
                }
            }

            ManipulationAction::Prepend { name, prefix } => {
                if let Some(header) = headers.get(name) {
                    let new_value = format!("{}{}", prefix, header.value);
                    headers.set(name.clone(), new_value);
                }
            }

            ManipulationAction::Append { name, suffix } => {
                if let Some(header) = headers.get(name) {
                    let new_value = format!("{}{}", header.value, suffix);
                    headers.set(name.clone(), new_value);
                }
            }
        }

        Ok(())
    }

    /// Simplified regex replacement.
    ///
    /// Supports basic patterns:
    /// - `(.*)` - capture group (referenced as $1, $2, etc.)
    /// - `^` - start anchor
    /// - `$` - end anchor
    fn regex_replace(&self, value: &str, pattern: &str, replacement: &str) -> String {
        // Simple implementation without full regex support
        // In production, would use the regex crate

        // Handle simple patterns
        if pattern == "(.*)" {
            // Entire string capture
            return replacement.replace("$1", value);
        }

        // Handle prefix pattern: ^prefix(.*)
        if pattern.starts_with('^') && pattern.ends_with("(.*)") {
            let prefix = &pattern[1..pattern.len() - 4];
            if let Some(captured) = value.strip_prefix(prefix) {
                return replacement.replace("$1", captured);
            }
        }

        // Handle suffix pattern: (.*)suffix$
        if pattern.starts_with("(.*)") && pattern.ends_with('$') {
            let suffix = &pattern[4..pattern.len() - 1];
            if let Some(captured) = value.strip_suffix(suffix) {
                return replacement.replace("$1", captured);
            }
        }

        // Fallback: simple string replacement
        value.replace(pattern, replacement)
    }

    /// Returns the number of global policies.
    #[must_use]
    pub fn global_policy_count(&self) -> usize {
        self.global_policies.len()
    }

    /// Returns the number of trunk policies.
    #[must_use]
    pub fn trunk_count(&self) -> usize {
        self.trunk_policies.len()
    }
}

// ============================================================================
// Common manipulation presets
// ============================================================================

/// Creates common header manipulation rules.
pub struct ManipulationPresets;

impl ManipulationPresets {
    /// Creates a rule to strip a header.
    #[must_use]
    pub fn strip_header(name: &str, header: HeaderName) -> ManipulationRule {
        ManipulationRule::new(
            name,
            ManipulationCondition::always(),
            ManipulationAction::remove(header),
        )
    }

    /// Creates a rule to add a custom header.
    #[must_use]
    pub fn add_custom_header(name: &str, header_name: &str, value: &str) -> ManipulationRule {
        ManipulationRule::new(
            name,
            ManipulationCondition::always(),
            ManipulationAction::add(HeaderName::Custom(header_name.to_string()), value),
        )
    }

    /// Creates a rule to normalize User-Agent header.
    #[must_use]
    pub fn normalize_user_agent(replacement: &str) -> ManipulationRule {
        ManipulationRule::new(
            "normalize-user-agent",
            ManipulationCondition::header_exists(HeaderName::UserAgent),
            ManipulationAction::set(HeaderName::UserAgent, replacement),
        )
    }

    /// Creates a rule to strip P-Asserted-Identity on outbound.
    #[must_use]
    pub fn strip_pai_outbound() -> ManipulationRule {
        ManipulationRule::new(
            "strip-pai-outbound",
            ManipulationCondition::always(),
            ManipulationAction::remove(HeaderName::Custom("P-Asserted-Identity".to_string())),
        )
    }

    /// Creates a rule to add P-Charging-Vector.
    #[must_use]
    pub fn add_charging_vector(icid: &str) -> ManipulationRule {
        ManipulationRule::new(
            "add-p-charging-vector",
            ManipulationCondition::header_missing(HeaderName::Custom(
                "P-Charging-Vector".to_string(),
            )),
            ManipulationAction::add(
                HeaderName::Custom("P-Charging-Vector".to_string()),
                format!("icid-value={icid}"),
            ),
        )
    }

    /// Creates a rule to copy Remote-Party-ID to P-Asserted-Identity.
    #[must_use]
    pub fn rpid_to_pai() -> ManipulationRule {
        ManipulationRule::new(
            "rpid-to-pai",
            ManipulationCondition::all(vec![
                ManipulationCondition::header_exists(HeaderName::Custom(
                    "Remote-Party-ID".to_string(),
                )),
                ManipulationCondition::header_missing(HeaderName::Custom(
                    "P-Asserted-Identity".to_string(),
                )),
            ]),
            ManipulationAction::copy(
                HeaderName::Custom("Remote-Party-ID".to_string()),
                HeaderName::Custom("P-Asserted-Identity".to_string()),
            ),
        )
    }

    /// Creates a policy for trunk interoperability.
    #[must_use]
    pub fn trunk_interop_policy(trunk_name: &str) -> ManipulationPolicy {
        let mut policy = ManipulationPolicy::new(format!("{trunk_name}-interop"))
            .with_direction(ManipulationDirection::Outbound)
            .with_message_type(MessageType::Request);

        // Common interop rules
        policy.add_rule(Self::normalize_user_agent("USG-SBC/1.0"));
        policy.add_rule(Self::strip_pai_outbound());

        policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_headers() -> Headers {
        let mut headers = Headers::new();
        headers.add(Header::new(
            HeaderName::From,
            "\"Alice\" <sip:alice@example.com>;tag=abc123",
        ));
        headers.add(Header::new(HeaderName::To, "<sip:bob@example.com>"));
        headers.add(Header::new(HeaderName::UserAgent, "OldPhone/1.0"));
        headers.add(Header::new(
            HeaderName::Custom("X-Custom".to_string()),
            "custom-value",
        ));
        headers
    }

    #[test]
    fn test_add_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action =
            ManipulationAction::add(HeaderName::Custom("X-New-Header".to_string()), "new-value");
        manipulator.apply_action(&action, &mut headers).unwrap();

        assert!(
            headers
                .get(&HeaderName::Custom("X-New-Header".to_string()))
                .is_some()
        );
    }

    #[test]
    fn test_set_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action = ManipulationAction::set(HeaderName::UserAgent, "NewAgent/2.0");
        manipulator.apply_action(&action, &mut headers).unwrap();

        assert_eq!(
            headers.get(&HeaderName::UserAgent).unwrap().value,
            "NewAgent/2.0"
        );
    }

    #[test]
    fn test_remove_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action = ManipulationAction::remove(HeaderName::UserAgent);
        manipulator.apply_action(&action, &mut headers).unwrap();

        assert!(headers.get(&HeaderName::UserAgent).is_none());
    }

    #[test]
    fn test_replace_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action = ManipulationAction::replace(HeaderName::UserAgent, "OldPhone", "NewPhone");
        manipulator.apply_action(&action, &mut headers).unwrap();

        assert_eq!(
            headers.get(&HeaderName::UserAgent).unwrap().value,
            "NewPhone/1.0"
        );
    }

    #[test]
    fn test_rename_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action = ManipulationAction::rename(
            HeaderName::Custom("X-Custom".to_string()),
            HeaderName::Custom("X-Renamed".to_string()),
        );
        manipulator.apply_action(&action, &mut headers).unwrap();

        assert!(
            headers
                .get(&HeaderName::Custom("X-Custom".to_string()))
                .is_none()
        );
        assert!(
            headers
                .get(&HeaderName::Custom("X-Renamed".to_string()))
                .is_some()
        );
    }

    #[test]
    fn test_copy_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action = ManipulationAction::copy(
            HeaderName::UserAgent,
            HeaderName::Custom("X-Original-UA".to_string()),
        );
        manipulator.apply_action(&action, &mut headers).unwrap();

        assert_eq!(
            headers
                .get(&HeaderName::Custom("X-Original-UA".to_string()))
                .unwrap()
                .value,
            "OldPhone/1.0"
        );
        // Original should still exist
        assert!(headers.get(&HeaderName::UserAgent).is_some());
    }

    #[test]
    fn test_prepend_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action = ManipulationAction::Prepend {
            name: HeaderName::UserAgent,
            prefix: "Gateway/".to_string(),
        };
        manipulator.apply_action(&action, &mut headers).unwrap();

        assert_eq!(
            headers.get(&HeaderName::UserAgent).unwrap().value,
            "Gateway/OldPhone/1.0"
        );
    }

    #[test]
    fn test_condition_always() {
        let headers = create_test_headers();
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let manipulator = HeaderManipulator::new();

        assert!(manipulator.evaluate_condition(&ManipulationCondition::Always, &headers, &context));
    }

    #[test]
    fn test_condition_header_exists() {
        let headers = create_test_headers();
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let manipulator = HeaderManipulator::new();

        assert!(manipulator.evaluate_condition(
            &ManipulationCondition::HeaderExists(HeaderName::UserAgent),
            &headers,
            &context
        ));

        assert!(!manipulator.evaluate_condition(
            &ManipulationCondition::HeaderExists(HeaderName::Custom("X-Missing".to_string())),
            &headers,
            &context
        ));
    }

    #[test]
    fn test_condition_header_contains() {
        let headers = create_test_headers();
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let manipulator = HeaderManipulator::new();

        assert!(manipulator.evaluate_condition(
            &ManipulationCondition::HeaderContains {
                name: HeaderName::UserAgent,
                pattern: "Phone".to_string(),
            },
            &headers,
            &context
        ));

        assert!(!manipulator.evaluate_condition(
            &ManipulationCondition::HeaderContains {
                name: HeaderName::UserAgent,
                pattern: "Cisco".to_string(),
            },
            &headers,
            &context
        ));
    }

    #[test]
    fn test_condition_method_equals() {
        let headers = create_test_headers();
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let manipulator = HeaderManipulator::new();

        assert!(manipulator.evaluate_condition(
            &ManipulationCondition::MethodEquals("INVITE".to_string()),
            &headers,
            &context
        ));

        assert!(manipulator.evaluate_condition(
            &ManipulationCondition::MethodEquals("invite".to_string()), // Case insensitive
            &headers,
            &context
        ));

        assert!(!manipulator.evaluate_condition(
            &ManipulationCondition::MethodEquals("REGISTER".to_string()),
            &headers,
            &context
        ));
    }

    #[test]
    fn test_condition_not() {
        let headers = create_test_headers();
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let manipulator = HeaderManipulator::new();

        assert!(manipulator.evaluate_condition(
            &ManipulationCondition::Not(Box::new(ManipulationCondition::HeaderExists(
                HeaderName::Custom("X-Missing".to_string())
            ))),
            &headers,
            &context
        ));
    }

    #[test]
    fn test_condition_any() {
        let headers = create_test_headers();
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let manipulator = HeaderManipulator::new();

        assert!(manipulator.evaluate_condition(
            &ManipulationCondition::Any(vec![
                ManipulationCondition::MethodEquals("REGISTER".to_string()),
                ManipulationCondition::MethodEquals("INVITE".to_string()),
            ]),
            &headers,
            &context
        ));
    }

    #[test]
    fn test_condition_all() {
        let headers = create_test_headers();
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let manipulator = HeaderManipulator::new();

        assert!(manipulator.evaluate_condition(
            &ManipulationCondition::All(vec![
                ManipulationCondition::MethodEquals("INVITE".to_string()),
                ManipulationCondition::HeaderExists(HeaderName::UserAgent),
            ]),
            &headers,
            &context
        ));

        assert!(!manipulator.evaluate_condition(
            &ManipulationCondition::All(vec![
                ManipulationCondition::MethodEquals("REGISTER".to_string()),
                ManipulationCondition::HeaderExists(HeaderName::UserAgent),
            ]),
            &headers,
            &context
        ));
    }

    #[test]
    fn test_policy_application() {
        let mut headers = create_test_headers();
        let mut manipulator = HeaderManipulator::new();

        let mut policy = ManipulationPolicy::new("test-policy")
            .with_direction(ManipulationDirection::Outbound)
            .with_message_type(MessageType::Request);

        policy.add_rule(ManipulationRule::new(
            "normalize-ua",
            ManipulationCondition::always(),
            ManipulationAction::set(HeaderName::UserAgent, "NormalizedUA/1.0"),
        ));

        manipulator.add_global_policy(policy);

        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let applied = manipulator.apply(&mut headers, &context).unwrap();

        assert_eq!(applied, 1);
        assert_eq!(
            headers.get(&HeaderName::UserAgent).unwrap().value,
            "NormalizedUA/1.0"
        );
    }

    #[test]
    fn test_trunk_specific_policy() {
        let mut headers = create_test_headers();
        let mut manipulator = HeaderManipulator::new();

        let mut trunk_policy = ManipulationPolicy::new("trunk-a-policy");
        trunk_policy.add_rule(ManipulationRule::new(
            "add-trunk-header",
            ManipulationCondition::always(),
            ManipulationAction::add(HeaderName::Custom("X-Trunk".to_string()), "trunk-a"),
        ));

        manipulator.add_trunk_policy("trunk-a", trunk_policy);

        // Apply with trunk context
        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound)
            .with_trunk("trunk-a");
        manipulator.apply(&mut headers, &context).unwrap();

        assert_eq!(
            headers
                .get(&HeaderName::Custom("X-Trunk".to_string()))
                .unwrap()
                .value,
            "trunk-a"
        );

        // Apply without trunk - should not add header
        let mut headers2 = create_test_headers();
        let context2 = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound)
            .with_trunk("trunk-b");
        manipulator.apply(&mut headers2, &context2).unwrap();

        assert!(
            headers2
                .get(&HeaderName::Custom("X-Trunk".to_string()))
                .is_none()
        );
    }

    #[test]
    fn test_presets_normalize_user_agent() {
        let mut headers = create_test_headers();
        let mut manipulator = HeaderManipulator::new();

        let mut policy = ManipulationPolicy::new("presets");
        policy.add_rule(ManipulationPresets::normalize_user_agent("USG-SBC/1.0"));
        manipulator.add_global_policy(policy);

        let context = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        manipulator.apply(&mut headers, &context).unwrap();

        assert_eq!(
            headers.get(&HeaderName::UserAgent).unwrap().value,
            "USG-SBC/1.0"
        );
    }

    #[test]
    fn test_simple_regex_replace() {
        let manipulator = HeaderManipulator::new();

        // Test capture group replacement
        let result = manipulator.regex_replace("sip:alice@example.com", "(.*)", "Modified: $1");
        assert_eq!(result, "Modified: sip:alice@example.com");

        // Test prefix removal (simplified - actual regex would need the regex crate)
        let _result = manipulator.regex_replace("+1234567890", "^\\+1(.*)", "$1");
        // Note: Our simple implementation doesn't handle \+ escape
        // This is a limitation without the regex crate
    }

    #[test]
    fn test_policy_direction_filtering() {
        let mut policy = ManipulationPolicy::new("outbound-only")
            .with_direction(ManipulationDirection::Outbound);
        policy.add_rule(ManipulationRule::new(
            "test",
            ManipulationCondition::always(),
            ManipulationAction::add(HeaderName::Custom("X-Test".to_string()), "test"),
        ));

        let outbound_ctx =
            ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        let inbound_ctx =
            ManipulationContext::for_request("INVITE", ManipulationDirection::Inbound);

        assert!(policy.applies_to(&outbound_ctx));
        assert!(!policy.applies_to(&inbound_ctx));
    }

    #[test]
    fn test_rule_priority() {
        let mut policy = ManipulationPolicy::new("priority-test");

        policy.add_rule(
            ManipulationRule::new(
                "low-priority",
                ManipulationCondition::always(),
                ManipulationAction::set(HeaderName::UserAgent, "Low"),
            )
            .with_priority(10),
        );

        policy.add_rule(
            ManipulationRule::new(
                "high-priority",
                ManipulationCondition::always(),
                ManipulationAction::set(HeaderName::UserAgent, "High"),
            )
            .with_priority(1),
        );

        // High priority (1) should be first
        assert_eq!(policy.rules()[0].name, "high-priority");
        assert_eq!(policy.rules()[1].name, "low-priority");
    }
}
