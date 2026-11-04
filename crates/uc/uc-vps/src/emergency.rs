//! Emergency-number classification (47 CFR 9.16).
//!
//! One predicate shared by VPS screening and the SIP stack's own capacity
//! limits, so both agree on what counts as an emergency call.

/// RFC 3966 §5.1.1 visual separators plus the `+` of a global number,
/// ignored when matching an emergency number.
const fn is_dial_separator(b: u8) -> bool {
    matches!(b, b'+' | b'-' | b'.' | b'(' | b')' | b' ')
}

/// The user part of a dialed callee: the URI user when `dialed` is a SIP
/// or tel URI, else `dialed` itself; URI parameters dropped.
fn dialed_user(dialed: &str) -> &str {
    let user = crate::context::uri_user(dialed).unwrap_or(dialed);
    user.split(';').next().unwrap_or(user)
}

/// Exact match of `dialed` against `entry`, ignoring separators on both
/// sides. No prefix match: `9111` is not `911`.
fn dial_matches(dialed: &str, entry: &str) -> bool {
    let mut d = dialed.bytes().filter(|b| !is_dial_separator(*b));
    let mut e = entry.bytes().filter(|b| !is_dial_separator(*b));
    loop {
        match (d.next(), e.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if x == y => {}
            _ => return false,
        }
    }
}

/// The configured emergency numbers (`[vps] emergency_numbers`).
///
/// ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmergencyNumbers {
    numbers: Vec<String>,
}

impl EmergencyNumbers {
    /// Builds the classifier from a validated list.
    pub fn new(numbers: &[String]) -> Self {
        Self {
            numbers: numbers.to_vec(),
        }
    }

    /// Whether `dialed` (a Request-URI, or its user part) is an emergency
    /// number: exact match after stripping `+`, visual separators and URI
    /// parameters. Allocation-free.
    pub fn matches(&self, dialed: &str) -> bool {
        let user = dialed_user(dialed);
        !user.is_empty() && self.numbers.iter().any(|entry| dial_matches(user, entry))
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
        assert!(EmergencyNumbers::default().is_empty());
        assert!(!EmergencyNumbers::default().matches("911"));
    }
}
