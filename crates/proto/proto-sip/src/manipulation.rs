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

use crate::error::{SipError, SipResult};
use crate::header::{Header, HeaderName, Headers, is_token_byte, parse_content_length};
use crate::header_params::{CSeqHeader, NameAddr, ViaHeader};
use crate::list::split_list_bounded;
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
    /// Convert Remote-Party-ID to a clean RFC 3325 §9.1 P-Asserted-Identity
    /// (name-addr only, at most one sip and one tel, only `screen=yes`
    /// elements) and add `Privacy: id` (plus `user` for name privacy) when
    /// the RPID asks for privacy. See [`crate::privacy::rpid_to_pai`].
    RpidToPai,
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

    /// Creates a Remote-Party-ID to P-Asserted-Identity conversion action.
    #[must_use]
    pub fn rpid_to_pai() -> Self {
        Self::RpidToPai
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
    #[allow(clippy::should_implement_trait)]
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
            && dir != ManipulationDirection::Both
            && dir != context.direction
        {
            return false;
        }

        // Check message type
        if let Some(msg_type) = self.message_type
            && msg_type != MessageType::Both
            && msg_type != context.message_type
        {
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
    ///
    /// Atomic and validated (POAM: POA&M-152): rules run against a working
    /// copy that is only cloned once a rule's condition matches. After each
    /// rule the headers it touched are validated (token name, no CR/LF/NUL
    /// or other CTL except HTAB, length bound, structured re-parse, singleton
    /// cardinality). On the first failure the original `headers` are left
    /// untouched and [`SipError::ManipulationInvalid`] is returned - callers
    /// must fail closed (NIST 800-53 Rev5: SI-10, SI-17, AC-4).
    ///
    /// # Errors
    /// [`SipError::ManipulationInvalid`] naming the rule and header.
    pub fn apply(&self, headers: &mut Headers, context: &ManipulationContext) -> SipResult<usize> {
        let mut applied_count = 0;
        let mut work: Option<Headers> = None;

        let trunk = context
            .trunk_id
            .as_ref()
            .and_then(|t| self.trunk_policies.get(t))
            .into_iter()
            .flatten();
        // Global policies first, then trunk-specific ones.
        for policy in self.global_policies.iter().chain(trunk) {
            if policy.applies_to(context) {
                applied_count += self.apply_policy(headers, &mut work, policy, context)?;
            }
        }

        if let Some(w) = work {
            *headers = w;
        }
        Ok(applied_count)
    }

    /// Applies a single policy to the working copy (cloned from `orig` on
    /// first use).
    fn apply_policy(
        &self,
        orig: &Headers,
        work: &mut Option<Headers>,
        policy: &ManipulationPolicy,
        context: &ManipulationContext,
    ) -> SipResult<usize> {
        let mut applied_count = 0;

        for rule in policy.rules() {
            if !rule.enabled {
                continue;
            }
            let current = work.as_ref().unwrap_or(orig);
            if !self.evaluate_condition(&rule.condition, current, context) {
                continue;
            }
            let w = work.get_or_insert_with(|| orig.clone());
            let within_bound = self.apply_action(&rule.action, w);
            for name in touched(&rule.action) {
                if !within_bound || !validate_header(w, name) {
                    return Err(SipError::ManipulationInvalid {
                        rule: rule.name.clone(),
                        header: name.as_str().to_string(),
                    });
                }
            }
            applied_count += 1;
        }

        Ok(applied_count)
    }

    /// Evaluates a condition against headers and context.
    ///
    /// Header-value conditions are true if ANY instance matches (POAM:
    /// POA&M-152 - a spoofed second instance must trigger a strip rule).
    fn evaluate_condition(
        &self,
        condition: &ManipulationCondition,
        headers: &Headers,
        context: &ManipulationContext,
    ) -> bool {
        let _ = self; // Silence only_used_in_recursion - kept as a method for future caching
        match condition {
            ManipulationCondition::Always => true,

            ManipulationCondition::HeaderExists(name) => headers.get(name).is_some(),

            ManipulationCondition::HeaderMissing(name) => headers.get(name).is_none(),

            ManipulationCondition::HeaderContains { name, pattern } => headers
                .get_all(name)
                .any(|h| h.value.contains(pattern.as_str())),

            ManipulationCondition::HeaderEquals { name, value } => {
                headers.get_all(name).any(|h| h.value == *value)
            }

            ManipulationCondition::HeaderMatches { name, pattern } => headers
                .get_all(name)
                .any(|h| simple_match(&h.value, pattern)),

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

    /// Applies an action to headers, to every instance (POAM: POA&M-152).
    ///
    /// `Set` is the only action that collapses instances (explicit
    /// replace-all is the operator intent).
    ///
    /// Returns `false` if a `Replace`/`RegexReplace`/`Prepend`/`Append`
    /// would grow a value past [`crate::MAX_HEADER_LEN`]; the output length
    /// is computed before any allocation, so a short pattern with a long
    /// replacement cannot amplify memory per message (NIST 800-53 Rev5:
    /// SC-5). The caller then fails the rule closed.
    fn apply_action(&self, action: &ManipulationAction, headers: &mut Headers) -> bool {
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
                headers.retain(|h| !(h.name == *name && h.value.contains(pattern.as_str())));
            }

            ManipulationAction::Replace {
                name,
                pattern,
                replacement,
            } => {
                for h in headers.get_all_mut(name) {
                    match bounded_replace(&h.value, pattern, replacement) {
                        Some(v) => h.value = v,
                        None => return false,
                    }
                }
            }

            ManipulationAction::RegexReplace {
                name,
                pattern,
                replacement,
            } => {
                // Simplified regex replacement
                // Supports basic patterns like (.*) capture groups
                for h in headers.get_all_mut(name) {
                    match self.regex_replace(&h.value, pattern, replacement) {
                        Some(v) => h.value = v,
                        None => return false,
                    }
                }
            }

            ManipulationAction::Rename { from, to } => {
                headers.rename_all(from, to);
            }

            ManipulationAction::Copy { from, to } => {
                let values: Vec<String> = headers.get_all(from).map(|h| h.value.clone()).collect();
                if values.is_empty() {
                    return true;
                }
                let at = headers
                    .iter()
                    .enumerate()
                    .filter(|(_, h)| h.name == *to)
                    .map(|(i, _)| i + 1)
                    .last()
                    .unwrap_or(headers.len());
                for (i, v) in values.into_iter().enumerate() {
                    headers.insert(at + i, Header::new(to.clone(), v));
                }
            }

            ManipulationAction::Prepend { name, prefix } => {
                for h in headers.get_all_mut(name) {
                    if h.value.len().saturating_add(prefix.len()) > crate::MAX_HEADER_LEN {
                        return false;
                    }
                    h.value.insert_str(0, prefix);
                }
            }

            ManipulationAction::Append { name, suffix } => {
                for h in headers.get_all_mut(name) {
                    if h.value.len().saturating_add(suffix.len()) > crate::MAX_HEADER_LEN {
                        return false;
                    }
                    h.value.push_str(suffix);
                }
            }

            ManipulationAction::RpidToPai => {
                crate::privacy::rpid_to_pai(headers);
            }
        }
        true
    }

    /// Simplified regex replacement.
    ///
    /// Supports basic patterns:
    /// - `(.*)` - capture group (referenced as $1, $2, etc.)
    /// - `^` - start anchor
    /// - `$` - end anchor
    ///
    /// Returns `None` if the output would exceed [`crate::MAX_HEADER_LEN`].
    fn regex_replace(&self, value: &str, pattern: &str, replacement: &str) -> Option<String> {
        let _ = self; // Silence unused_self - method may use self in future for caching

        // Simple implementation without full regex support
        // In production, would use the regex crate

        // Handle simple patterns
        if pattern == "(.*)" {
            // Entire string capture
            return bounded_replace(replacement, "$1", value);
        }

        // Handle prefix pattern: ^prefix(.*)
        if let Some(inner) = pattern.strip_prefix('^')
            && let Some(prefix) = inner.strip_suffix("(.*)")
            && let Some(captured) = value.strip_prefix(prefix)
        {
            return bounded_replace(replacement, "$1", captured);
        }

        // Handle suffix pattern: (.*)suffix$
        if let Some(inner) = pattern.strip_prefix("(.*)")
            && let Some(suffix) = inner.strip_suffix('$')
            && let Some(captured) = value.strip_suffix(suffix)
        {
            return bounded_replace(replacement, "$1", captured);
        }

        // Fallback: simple string replacement
        bounded_replace(value, pattern, replacement)
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

/// `str::replace` that computes the output length first and returns `None`
/// (without allocating the result) if it would exceed
/// [`crate::MAX_HEADER_LEN`].
///
/// NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection) - bounds growth
/// before the intermediate string is built (SEC-002).
fn bounded_replace(value: &str, pattern: &str, replacement: &str) -> Option<String> {
    // An empty pattern matches at every char boundary (`str::replace`).
    let matches = if pattern.is_empty() {
        value.chars().count().saturating_add(1)
    } else {
        value.matches(pattern).count()
    };
    let out_len = (value
        .len()
        .saturating_sub(matches.saturating_mul(pattern.len())))
    .saturating_add(matches.saturating_mul(replacement.len()));
    (out_len <= crate::MAX_HEADER_LEN).then(|| value.replace(pattern, replacement))
}

/// `HeaderMatches` pattern semantics (`^x$`, `^x`, `x$`, substring).
fn simple_match(value: &str, pattern: &str) -> bool {
    if let Some(inner) = pattern.strip_prefix('^').and_then(|p| p.strip_suffix('$')) {
        value == inner
    } else if let Some(stripped) = pattern.strip_prefix('^') {
        value.starts_with(stripped)
    } else if let Some(stripped) = pattern.strip_suffix('$') {
        value.ends_with(stripped)
    } else {
        value.contains(pattern)
    }
}

/// Header names an action may modify.
fn touched(action: &ManipulationAction) -> Vec<&HeaderName> {
    match action {
        ManipulationAction::Add { name, .. }
        | ManipulationAction::Set { name, .. }
        | ManipulationAction::Remove { name }
        | ManipulationAction::RemoveMatching { name, .. }
        | ManipulationAction::Replace { name, .. }
        | ManipulationAction::RegexReplace { name, .. }
        | ManipulationAction::Prepend { name, .. }
        | ManipulationAction::Append { name, .. } => vec![name],
        ManipulationAction::Rename { from, to } => vec![from, to],
        ManipulationAction::Copy { to, .. } => vec![to],
        ManipulationAction::RpidToPai => {
            vec![&HeaderName::PAssertedIdentity, &HeaderName::Privacy]
        }
    }
}

/// Every list element of every instance parses with `f` (empty -> false).
fn all_elements(headers: &Headers, name: &HeaderName, f: impl Fn(&str) -> bool) -> bool {
    headers.get_all(name).all(|h| {
        split_list_bounded(&h.value, crate::MAX_LIST_ELEMENTS)
            .is_ok_and(|parts| !parts.is_empty() && parts.iter().all(|p| f(p)))
    })
}

/// Validates every instance of `name` after a manipulation.
///
/// NIST 800-53 Rev5: SI-10 (Information Input Validation) - header
/// injection (CR/LF), grammar and cardinality of SBC-relevant headers.
fn validate_header(headers: &Headers, name: &HeaderName) -> bool {
    let n = name.as_str();
    if n.is_empty() || !n.bytes().all(is_token_byte) {
        return false;
    }
    let count = headers.count(name);
    for h in headers.get_all(name) {
        if h.value.len() > crate::MAX_HEADER_LEN
            || h.value
                .bytes()
                .any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            return false;
        }
    }
    match name {
        HeaderName::From | HeaderName::To => {
            count == 1
                && headers
                    .get_all(name)
                    .all(|h| h.value.parse::<NameAddr>().is_ok())
        }
        HeaderName::CallId => {
            count == 1
                && headers.get_all(name).all(|h| {
                    let v = h.value.trim();
                    !v.is_empty() && !v.bytes().any(|b| b == b' ' || b == b'\t')
                })
        }
        HeaderName::CSeq => {
            count == 1
                && headers
                    .get_all(name)
                    .all(|h| h.value.parse::<CSeqHeader>().is_ok())
        }
        HeaderName::MaxForwards => {
            count <= 1
                && headers
                    .get_all(name)
                    .all(|h| h.value.trim().parse::<u8>().is_ok())
        }
        HeaderName::ContentLength => {
            count <= 1
                && headers
                    .get_all(name)
                    .all(|h| parse_content_length(&h.value).is_ok())
        }
        HeaderName::ContentType => headers.get_all(name).all(|h| {
            h.value
                .split_once('/')
                .is_some_and(|(t, s)| !t.trim().is_empty() && !s.trim().is_empty())
        }),
        HeaderName::Via => all_elements(headers, name, |e| e.parse::<ViaHeader>().is_ok()),
        HeaderName::Contact => all_elements(headers, name, |e| {
            e.trim() == "*" || e.parse::<NameAddr>().is_ok()
        }),
        HeaderName::Route | HeaderName::RecordRoute => {
            all_elements(headers, name, |e| e.parse::<NameAddr>().is_ok())
        }
        _ => true,
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
    ///
    /// RFC 3325 §5: asserted identity MUST NOT leave the trust domain.
    #[must_use]
    pub fn strip_pai_outbound() -> ManipulationRule {
        ManipulationRule::new(
            "strip-pai-outbound",
            ManipulationCondition::always(),
            ManipulationAction::remove(HeaderName::PAssertedIdentity),
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

    /// Creates a rule to convert Remote-Party-ID to P-Asserted-Identity.
    #[must_use]
    pub fn rpid_to_pai() -> ManipulationRule {
        ManipulationRule::new(
            "rpid-to-pai",
            ManipulationCondition::all(vec![
                ManipulationCondition::header_exists(HeaderName::Custom(
                    "Remote-Party-ID".to_string(),
                )),
                ManipulationCondition::header_missing(HeaderName::PAssertedIdentity),
            ]),
            // POA&M-232: previously a verbatim Copy, which put RPID's
            // `party`/`screen`/`privacy` params into PAI (not RFC 3325 §9.1)
            // and dropped the privacy request.
            ManipulationAction::rpid_to_pai(),
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        manipulator.apply_action(&action, &mut headers);

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
        manipulator.apply_action(&action, &mut headers);

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
        manipulator.apply_action(&action, &mut headers);

        assert!(headers.get(&HeaderName::UserAgent).is_none());
    }

    #[test]
    fn test_replace_action() {
        let mut headers = create_test_headers();
        let manipulator = HeaderManipulator::new();

        let action = ManipulationAction::replace(HeaderName::UserAgent, "OldPhone", "NewPhone");
        manipulator.apply_action(&action, &mut headers);

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
        manipulator.apply_action(&action, &mut headers);

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
        manipulator.apply_action(&action, &mut headers);

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
        manipulator.apply_action(&action, &mut headers);

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
        assert_eq!(result.as_deref(), Some("Modified: sip:alice@example.com"));

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

    fn x_foo() -> HeaderName {
        HeaderName::Custom("X-Foo".to_string())
    }

    fn run(
        headers: &mut Headers,
        action: ManipulationAction,
        cond: ManipulationCondition,
    ) -> SipResult<usize> {
        let mut m = HeaderManipulator::new();
        let mut p = ManipulationPolicy::new("p");
        p.add_rule(ManipulationRule::new("r", cond, action));
        m.add_global_policy(p);
        m.apply(
            headers,
            &ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound),
        )
    }

    fn vals(h: &Headers, n: &HeaderName) -> Vec<String> {
        h.get_all(n).map(|h| h.value.clone()).collect()
    }

    fn snapshot(h: &Headers) -> Vec<(String, String)> {
        h.iter()
            .map(|h| (h.name.as_str().to_string(), h.value.clone()))
            .collect()
    }

    // POAM-152: RemoveMatching removes only matching instances, incl. the 2nd.
    #[test]
    fn remove_matching_second_instance() {
        let mut h = Headers::new();
        h.add(Header::new(x_foo(), "ok"));
        h.add(Header::new(x_foo(), "evil"));
        run(
            &mut h,
            ManipulationAction::RemoveMatching {
                name: x_foo(),
                pattern: "evil".into(),
            },
            ManipulationCondition::Always,
        )
        .unwrap();
        assert_eq!(vals(&h, &x_foo()), vec!["ok"]);
    }

    // POAM-152: conditions match any instance.
    #[test]
    fn condition_matches_any_instance() {
        let pai = HeaderName::Custom("P-Asserted-Identity".into());
        let mut h = Headers::new();
        h.add(Header::new(pai.clone(), "<sip:alice@example.com>"));
        h.add(Header::new(pai.clone(), "<sip:+1911@example.com>"));
        let n = run(
            &mut h,
            ManipulationAction::remove(pai.clone()),
            ManipulationCondition::header_contains(pai.clone(), "+1911"),
        )
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(h.count(&pai), 0);
    }

    // POAM-152: per-instance edits keep count and order.
    #[test]
    fn per_instance_edits() {
        let mk = || {
            let mut h = Headers::new();
            for v in ["a1", "a2", "a3"] {
                h.add(Header::new(x_foo(), v));
            }
            h
        };
        let mut h = mk();
        run(
            &mut h,
            ManipulationAction::replace(x_foo(), "a", "b"),
            ManipulationCondition::Always,
        )
        .unwrap();
        assert_eq!(vals(&h, &x_foo()), vec!["b1", "b2", "b3"]);
        let mut h = mk();
        run(
            &mut h,
            ManipulationAction::Prepend {
                name: x_foo(),
                prefix: "p-".into(),
            },
            ManipulationCondition::Always,
        )
        .unwrap();
        assert_eq!(vals(&h, &x_foo()), vec!["p-a1", "p-a2", "p-a3"]);
        let mut h = mk();
        run(
            &mut h,
            ManipulationAction::Append {
                name: x_foo(),
                suffix: "-s".into(),
            },
            ManipulationCondition::Always,
        )
        .unwrap();
        assert_eq!(vals(&h, &x_foo()), vec!["a1-s", "a2-s", "a3-s"]);
        let mut h = mk();
        run(
            &mut h,
            ManipulationAction::set(x_foo(), "one"),
            ManipulationCondition::Always,
        )
        .unwrap();
        assert_eq!(vals(&h, &x_foo()), vec!["one"]);
    }

    // POAM-152: Rename / Copy keep every instance.
    #[test]
    fn rename_and_copy_all_instances() {
        let bar = HeaderName::Custom("X-Bar".into());
        let mut h = Headers::new();
        h.add(Header::new(x_foo(), "1"));
        h.add(Header::new(x_foo(), "2"));
        run(
            &mut h,
            ManipulationAction::copy(x_foo(), bar.clone()),
            ManipulationCondition::Always,
        )
        .unwrap();
        assert_eq!(vals(&h, &bar), vec!["1", "2"]);
        assert_eq!(vals(&h, &x_foo()), vec!["1", "2"]);
        let baz = HeaderName::Custom("X-Baz".into());
        run(
            &mut h,
            ManipulationAction::rename(x_foo(), baz.clone()),
            ManipulationCondition::Always,
        )
        .unwrap();
        assert_eq!(vals(&h, &baz), vec!["1", "2"]);
        assert_eq!(h.count(&x_foo()), 0);
    }

    // POAM-152: invalid output rejected atomically.
    #[test]
    fn invalid_output_rejected_atomically() {
        let mut h = create_test_headers();
        let before = snapshot(&h);
        let e = run(
            &mut h,
            ManipulationAction::regex_replace(HeaderName::UserAgent, "(.*)", "$1\r\nX-Injected: 1"),
            ManipulationCondition::Always,
        )
        .unwrap_err();
        assert!(matches!(e, SipError::ManipulationInvalid { .. }));
        assert_eq!(snapshot(&h), before);

        let e = run(
            &mut h,
            ManipulationAction::replace(HeaderName::From, "<sip:", "<"),
            ManipulationCondition::Always,
        );
        assert!(e.is_err());
        assert_eq!(snapshot(&h), before);

        let e = run(
            &mut h,
            ManipulationAction::copy(HeaderName::From, HeaderName::To),
            ManipulationCondition::Always,
        );
        assert!(e.is_err(), "two To headers must be rejected");
        assert_eq!(snapshot(&h), before);
    }

    // SEC-002: amplifying replace/prepend/append rejected before the
    // oversized value is built; headers untouched.
    #[test]
    fn amplifying_rewrite_rejected_before_growth() {
        let x = HeaderName::Custom("X-Amp".to_string());
        let mut h = create_test_headers();
        h.add(Header::new(x.clone(), "a".repeat(1024)));
        let before = snapshot(&h);
        let big = "b".repeat(1024);
        for action in [
            ManipulationAction::replace(x.clone(), "a", &big),
            ManipulationAction::regex_replace(x.clone(), "a", &big),
            ManipulationAction::regex_replace(x.clone(), "(.*)", "$1".repeat(16)),
            ManipulationAction::replace(x.clone(), "", "z".repeat(8)),
        ] {
            let e = run(&mut h, action, ManipulationCondition::Always).unwrap_err();
            assert!(matches!(e, SipError::ManipulationInvalid { .. }));
            assert_eq!(snapshot(&h), before);
        }
        let long = "p".repeat(crate::MAX_HEADER_LEN);
        for action in [
            ManipulationAction::Prepend {
                name: x.clone(),
                prefix: long.clone(),
            },
            ManipulationAction::Append {
                name: x.clone(),
                suffix: long.clone(),
            },
        ] {
            assert!(run(&mut h, action, ManipulationCondition::Always).is_err());
            assert_eq!(snapshot(&h), before);
        }
        assert_eq!(bounded_replace("aXa", "a", "bb").as_deref(), Some("bbXbb"));
        assert_eq!(bounded_replace("ab", "", "-").as_deref(), Some("-a-b-"));
    }

    // POAM-152: Headers helpers.
    #[test]
    fn headers_helpers() {
        let mut h = Headers::new();
        h.add(Header::new(x_foo(), "1"));
        h.add(Header::new(HeaderName::To, "<sip:b@example.com>"));
        h.add(Header::new(x_foo(), "2"));
        for x in h.get_all_mut(&x_foo()) {
            x.value.push('!');
        }
        assert_eq!(vals(&h, &x_foo()), vec!["1!", "2!"]);
        let bar = HeaderName::Custom("X-Bar".into());
        h.rename_all(&x_foo(), &bar);
        assert_eq!(snapshot(&h)[2], ("X-Bar".to_string(), "2!".to_string()));
        h.retain(|x| x.value != "1!");
        assert_eq!(h.len(), 2);
        h.replace_instances(&bar, vec!["a".into(), "b".into()]);
        assert_eq!(snapshot(&h)[1].1, "a");
        assert_eq!(snapshot(&h)[2].1, "b");
    }

    fn parsed_request(extra: &str) -> crate::message::SipRequest {
        let raw = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n\
             From: <sip:alice@example.org>;tag=abc\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: c1\r\n\
             CSeq: 1 INVITE\r\n\
             Max-Forwards: 70\r\n\
             {extra}\
             Content-Length: 0\r\n\r\n"
        );
        match crate::message::SipMessage::parse(raw.as_bytes()).unwrap() {
            crate::message::SipMessage::Request(r) => r,
            crate::message::SipMessage::Response(_) => unreachable!(),
        }
    }

    /// POA&M-232 regression on a **parsed** message (header names are
    /// normalised by the parser, including odd case).
    #[test]
    fn trunk_interop_strips_pai_from_parsed_message() {
        let mut req = parsed_request(
            "p-asserted-identity: <sip:alice@example.org>\r\n\
             P-Asserted-Identity: <tel:+15550100>\r\n",
        );
        assert_eq!(req.headers.count(&HeaderName::PAssertedIdentity), 2);
        let mut m = HeaderManipulator::new();
        m.add_global_policy(ManipulationPresets::trunk_interop_policy("t1"));
        let ctx = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        m.apply(&mut req.headers, &ctx).unwrap();
        assert!(!req.headers.contains(&HeaderName::PAssertedIdentity));
        assert!(!req.to_string().to_ascii_lowercase().contains("p-asserted"));
    }

    #[test]
    fn rpid_to_pai_preset_on_parsed_message() {
        let mut req = parsed_request(
            "Remote-Party-ID: \"Alice\" <sip:alice@example.org>;party=calling;privacy=full;screen=yes\r\n",
        );
        let mut policy = ManipulationPolicy::new("rpid");
        policy.add_rule(ManipulationPresets::rpid_to_pai());
        let mut m = HeaderManipulator::new();
        m.add_global_policy(policy);
        let ctx = ManipulationContext::for_request("INVITE", ManipulationDirection::Outbound);
        assert_eq!(m.apply(&mut req.headers, &ctx).unwrap(), 1);
        assert_eq!(
            req.headers.get_value(&HeaderName::PAssertedIdentity),
            Some("\"Alice\" <sip:alice@example.org>")
        );
        assert_eq!(req.headers.get_value(&HeaderName::Privacy), Some("id;user"));
        // Existing PAI: the rule's header_missing condition holds it off.
        let mut again = req.clone();
        assert_eq!(m.apply(&mut again.headers, &ctx).unwrap(), 0);
        assert_eq!(again.headers.count(&HeaderName::PAssertedIdentity), 1);
    }
}
