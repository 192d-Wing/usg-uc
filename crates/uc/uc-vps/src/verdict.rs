//! Screening verdicts returned by the VPS engine.

/// What the caller (the SIP stack) should do with the screened attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpsAction {
    /// Let the call proceed to routing.
    Allow,
    /// Reject with a SIP final response.
    Reject {
        /// SIP status code (400-699).
        status_code: u16,
        /// Reason phrase.
        reason: String,
    },
    /// Silently drop the request (no response). Used for blocked flood
    /// sources, where answering spoofed traffic is amplification.
    Drop,
}

/// Which screening stage produced the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictSource {
    /// The VPS is disabled; nothing was evaluated.
    Disabled,
    /// Dynamic blocklist (source IP or caller prefix).
    Blocklist,
    /// Per-source call-attempt rate limit.
    CallRateLimit,
    /// Per-callee concurrency cap.
    ConcurrencyCap,
    /// STIR/SHAKEN screening.
    StirShaken,
    /// A declarative policy rule.
    PolicyRule,
    /// The configured default action.
    Default,
}

/// The result of screening a call attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpsVerdict {
    action: VpsAction,
    source: VerdictSource,
    matched_rule: Option<String>,
}

impl VpsVerdict {
    /// Creates a verdict.
    pub fn new(action: VpsAction, source: VerdictSource, matched_rule: Option<String>) -> Self {
        Self {
            action,
            source,
            matched_rule,
        }
    }

    /// An allow verdict from the given stage.
    pub fn allow(source: VerdictSource) -> Self {
        Self::new(VpsAction::Allow, source, None)
    }

    /// A reject verdict from the given stage.
    pub fn reject(source: VerdictSource, status_code: u16, reason: impl Into<String>) -> Self {
        Self::new(
            VpsAction::Reject {
                status_code,
                reason: reason.into(),
            },
            source,
            None,
        )
    }

    /// A silent-drop verdict from the given stage.
    pub fn drop_silently(source: VerdictSource) -> Self {
        Self::new(VpsAction::Drop, source, None)
    }

    /// Attaches the matched rule ID.
    #[must_use]
    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.matched_rule = Some(rule_id.into());
        self
    }

    /// The action to take.
    pub fn action(&self) -> &VpsAction {
        &self.action
    }

    /// The screening stage that decided.
    pub fn source(&self) -> VerdictSource {
        self.source
    }

    /// The matched rule ID, if a policy rule decided.
    pub fn matched_rule(&self) -> Option<&str> {
        self.matched_rule.as_deref()
    }

    /// Whether the call may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self.action, VpsAction::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdicts() {
        let allow = VpsVerdict::allow(VerdictSource::Default);
        assert!(allow.is_allowed());

        let reject = VpsVerdict::reject(VerdictSource::PolicyRule, 403, "Forbidden")
            .with_rule("block-premium");
        assert!(!reject.is_allowed());
        assert_eq!(reject.matched_rule(), Some("block-premium"));
        assert_eq!(reject.source(), VerdictSource::PolicyRule);

        let drop = VpsVerdict::drop_silently(VerdictSource::CallRateLimit);
        assert!(!drop.is_allowed());
        assert_eq!(*drop.action(), VpsAction::Drop);
    }
}
