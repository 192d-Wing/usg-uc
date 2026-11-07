//! Emergency-number classification (47 CFR 9.16).
//!
//! One predicate shared by VPS screening and the SIP stack's own capacity
//! limits, so both agree on what counts as an emergency call.

use uc_types::DialedNumber;

/// The user part of a dialed callee: the URI user when `dialed` is a SIP
/// or tel URI, else `dialed` itself; URI parameters dropped.
pub(crate) fn dialed_user(dialed: &str) -> &str {
    let user = crate::context::uri_user(dialed).unwrap_or(dialed);
    user.split(';').next().unwrap_or(user)
}

/// Canonical screening key of a number or URI (`uc_types::DialedNumber`
/// rules: separators, `%xx`, `+` and URI parameters removed).
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
pub fn screening_key(dialed: &str) -> String {
    DialedNumber::parse(dialed_user(dialed))
        .screening_key()
        .to_string()
}

/// The configured emergency numbers (`[vps] emergency_numbers`).
///
/// ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmergencyNumbers {
    numbers: Vec<String>,
}

impl EmergencyNumbers {
    /// Builds the classifier from a validated list. Entries are stored in
    /// canonical digit form so matching is one string compare per entry.
    pub fn new(numbers: &[String]) -> Self {
        Self {
            numbers: numbers
                .iter()
                .map(|n| DialedNumber::parse(n))
                .filter_map(|n| n.digits().map(str::to_string))
                .collect(),
        }
    }

    /// Whether `dialed` (a Request-URI, or its user part) is an emergency
    /// number: exact match of the canonical digits (`+`, visual separators,
    /// `%xx` escapes and URI parameters removed). No prefix match.
    pub fn matches(&self, dialed: &str) -> bool {
        self.matches_number(&DialedNumber::parse(dialed_user(dialed)))
    }

    /// [`Self::matches`] for an already canonicalised number (no reparse).
    pub fn matches_number(&self, dialed: &DialedNumber) -> bool {
        dialed
            .digits()
            .is_some_and(|d| self.numbers.iter().any(|entry| entry == d))
    }

    /// The canonical emergency numbers (digits, no `+`).
    pub fn numbers(&self) -> &[String] {
        &self.numbers
    }

    /// Whether the list is empty (no emergency bypass).
    pub fn is_empty(&self) -> bool {
        self.numbers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exactly_without_prefix() {
        let e = EmergencyNumbers::new(&crate::config::default_emergency_numbers());
        assert!(e.matches("911") && e.matches("+1-1-2") && e.matches("tel:933"));
        assert!(!e.matches("9111") && !e.matches("+1911") && !e.matches(""));
        assert!(!e.matches(";911"));
        assert!(e.matches("9-1-1") && e.matches("%39%31%31") && e.matches("911;phone-context=+1"));
        assert!(e.matches_number(&DialedNumber::parse("(911)")));
        assert!(!e.matches_number(&DialedNumber::parse("+1911")));
        assert!(EmergencyNumbers::default().is_empty());
        assert!(!EmergencyNumbers::default().matches("911"));
    }
}
