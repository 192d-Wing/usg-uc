//! Telephone number canonicalisation (RFC 8224 §8.3).
//!
//! The same routine is applied to the PASSporT `orig`/`dest` claims when
//! signing and to From/PAI and Request-URI/To when verifying, so both sides
//! compare equal strings.

/// Maximum canonical TN length. E.164 allows 15 digits; SHAKEN permits some
/// non-E.164 strings, so allow headroom while staying bounded.
pub const MAX_TN_LEN: usize = 32;

/// A canonical telephone number: ASCII digits only, no leading `+`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TelephoneNumber(String);

impl TelephoneNumber {
    /// The digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TelephoneNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Canonicalises a telephone number from a bare string, `tel:` URI, or
/// `sip:`/`sips:` URI user part.
///
/// RFC 8224 §8.3: visual separators (`-`, `.`, `(`, `)`, space) are removed
/// and a leading `+` is dropped. Returns `None` if anything other than
/// digits remains, or the result is empty or longer than [`MAX_TN_LEN`].
#[must_use]
pub fn canonicalize_tn(s: &str) -> Option<TelephoneNumber> {
    let s = s.trim();
    let s = s.strip_prefix('<').unwrap_or(s);
    let s = s.strip_suffix('>').unwrap_or(s);
    let lower_prefix = |p: &str| {
        s.get(..p.len())
            .is_some_and(|h| h.eq_ignore_ascii_case(p))
            .then(|| s.get(p.len()..))
            .flatten()
    };
    let sip_user = |rest: &'_ str| -> String {
        let user = rest.split('@').next().unwrap_or("");
        user.split(';').next().unwrap_or("").to_owned()
    };
    let user = lower_prefix("tel:").map_or_else(
        || {
            lower_prefix("sips:")
                .or_else(|| lower_prefix("sip:"))
                .map_or_else(|| s.to_owned(), sip_user)
        },
        |rest| rest.split(';').next().unwrap_or("").to_owned(),
    );
    let user = user.strip_prefix('+').unwrap_or(&user);
    let mut out = String::with_capacity(user.len().min(MAX_TN_LEN));
    for c in user.chars() {
        match c {
            '0'..='9' => {
                if out.len() == MAX_TN_LEN {
                    return None;
                }
                out.push(c);
            }
            '-' | '.' | '(' | ')' | ' ' => {}
            _ => return None,
        }
    }
    (!out.is_empty()).then_some(TelephoneNumber(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Option<String> {
        canonicalize_tn(s).map(|t| t.0)
    }

    #[test]
    fn canonical_forms() {
        assert_eq!(c("+1 (202) 555-0100").as_deref(), Some("12025550100"));
        assert_eq!(c("12025550100").as_deref(), Some("12025550100"));
        assert_eq!(
            c("tel:+1-202-555-0100;phone-context=x").as_deref(),
            Some("12025550100")
        );
        assert_eq!(
            c("<sip:+12025550100@example.invalid;user=phone>").as_deref(),
            Some("12025550100")
        );
        assert_eq!(c("SIPS:+1.202.555.0100@h").as_deref(), Some("12025550100"));
    }

    #[test]
    fn rejects_non_numbers() {
        assert_eq!(c(""), None);
        assert_eq!(c("+"), None);
        assert_eq!(c("sip:alice@example.invalid"), None);
        assert_eq!(c("1202555010x"), None);
        assert_eq!(c(&"1".repeat(MAX_TN_LEN + 1)), None);
        assert!(c(&"1".repeat(MAX_TN_LEN)).is_some());
    }
}
