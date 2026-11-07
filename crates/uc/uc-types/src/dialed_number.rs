//! Canonical dialled / caller number.
//!
//! A single canonicaliser shared by routing (`uc-routing`), voice policy
//! screening (`uc-vps`) and the SBC daemon so that every decision about a
//! call — emergency classification, deny prefixes, caller blocklist,
//! per-callee caps and route-pattern matching — sees the same number.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SI-10**: Information Input Validation (bounded, total canonicaliser
//!   over attacker-controlled Request-URI / From user parts)
//! - **AC-3**: Access Enforcement (deny rules cannot be evaded with visual
//!   separators, `%xx` escapes, `+` or `;phone-context`)
//!
//! ## Rules (applied in order)
//!
//! 1. Cut at the first `;` — drops `;phone-context=` and every other user
//!    parameter (RFC 3966 §5.1.5). The context is not prepended.
//! 2. Percent-decode `%xx` (RFC 3261 §19.1.2). An invalid escape, a control
//!    character or non-ASCII output makes the number [`NumberKind::Opaque`].
//! 3. Strip visual separators `-` `.` `(` `)` and space (RFC 3966 §5.1.1).
//!    If what remains is `+?[0-9*#A-Da-d]{1,32}` the number is
//!    [`NumberKind::Digits`]; a leading `+` marks a global number
//!    (RFC 3966 §5.1.4). A `+` anywhere else makes it opaque.
//! 4. Inputs over 256 bytes, or over 32 digits, are opaque.

// POAM: POA&M-100 phone-context-aware normalisation. `;phone-context` is
// dropped rather than applied, so `555...;phone-context=+44` canonicalises
// as the local number `555...`.

use std::fmt;

/// Maximum raw input length examined, in bytes.
pub const MAX_RAW_LEN: usize = 256;
/// Maximum number of dial digits in a [`NumberKind::Digits`] number.
pub const MAX_DIGITS: usize = 32;

/// Classification of a canonicalised number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NumberKind {
    /// A telephone number made only of dial digits (`0-9 * # A-D`).
    Digits,
    /// A non-telephone user part (e.g. `alice`), kept verbatim (decoded
    /// when the decode was clean). Never matches as digits.
    Opaque,
}

/// A canonicalised dialled or caller number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialedNumber {
    canonical: String,
    global: bool,
    kind: NumberKind,
    /// Opaque only: `canonical` with `+` and visual separators removed
    /// (fail-closed screening key, see [`Self::screening_key`]).
    opaque_screen: String,
    /// Opaque only: the user looks like a telephone number (starts with a
    /// digit, `*`, `#` or `+` after separators) or was oversize, but did not
    /// canonicalise, or is empty. Never routable (see [`Self::is_routable`]).
    numeric_like: bool,
}

fn is_separator(c: u8) -> bool {
    matches!(c, b'-' | b'.' | b'(' | b')' | b' ')
}

fn is_separator_char(c: char) -> bool {
    u8::try_from(c).is_ok_and(is_separator)
}

fn is_dial_digit(c: u8) -> bool {
    c.is_ascii_digit() || matches!(c, b'*' | b'#' | b'A'..=b'D' | b'a'..=b'd')
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode; `None` on invalid escape, control char or non-ASCII.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let c = if b == b'%' {
            let hi = bytes.get(i + 1).copied().and_then(hex_val)?;
            let lo = bytes.get(i + 2).copied().and_then(hex_val)?;
            i += 3;
            (hi << 4) | lo
        } else {
            i += 1;
            b
        };
        if !c.is_ascii() || c.is_ascii_control() {
            return None;
        }
        out.push(char::from(c));
    }
    Some(out)
}

impl DialedNumber {
    /// Canonicalise a SIP/tel user part. Infallible and idempotent:
    /// `parse(parse(x).as_str()) == parse(x)`.
    #[must_use]
    pub fn parse(user: &str) -> Self {
        let opaque = |s: &str| {
            let opaque_screen: String = s
                .chars()
                .filter(|&c| c != '+' && !is_separator_char(c))
                .collect();
            // An empty user (absent, or oversize below) is also never
            // routable: it must not reach a catch-all (SI-10).
            let numeric_like = s.is_empty()
                || opaque_screen
                    .bytes()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit() || matches!(c, b'*' | b'#'))
                || s.trim_start_matches(is_separator_char).starts_with('+');
            Self {
                canonical: s.to_string(),
                global: false,
                kind: NumberKind::Opaque,
                opaque_screen,
                numeric_like,
            }
        };
        if user.len() > MAX_RAW_LEN {
            // Bounded work: oversize input is not examined. SI-10: it is
            // marked non-routable so the empty key can never match a
            // catch-all pattern or the default trunk group.
            return opaque("");
        }
        // RFC 3966 §5.1.5: drop ;phone-context and other parameters.
        let head = user.split(';').next().unwrap_or("");
        // RFC 3261 §19.1.2: escaped characters.
        let Some(decoded) = percent_decode(head) else {
            return opaque(user);
        };
        // A decode that yields `%` or `;` would re-parse differently; keep
        // the raw input so `parse` stays idempotent.
        if decoded.contains(['%', ';']) {
            return opaque(user);
        }
        let mut digits = String::with_capacity(decoded.len());
        let mut global = false;
        for (idx, &c) in decoded.as_bytes().iter().enumerate() {
            if is_separator(c) {
                continue;
            }
            if c == b'+' {
                if idx == 0 {
                    global = true;
                    continue;
                }
                return opaque(&decoded);
            }
            if !is_dial_digit(c) {
                return opaque(&decoded);
            }
            digits.push(char::from(c.to_ascii_uppercase()));
        }
        if digits.is_empty() || digits.len() > MAX_DIGITS {
            return opaque(&decoded);
        }
        let canonical = if global {
            let mut s = String::with_capacity(digits.len() + 1);
            s.push('+');
            s.push_str(&digits);
            s
        } else {
            digits
        };
        Self {
            canonical,
            global,
            kind: NumberKind::Digits,
            opaque_screen: String::new(),
            numeric_like: false,
        }
    }

    /// Routing key: `+15551234567`, `911`, or the opaque user (`alice`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Consumes the number, returning the routing key ([`Self::as_str`]).
    #[must_use]
    pub fn into_string(self) -> String {
        self.canonical
    }

    /// Dial digits without the leading `+`; `None` for opaque numbers.
    #[must_use]
    pub fn digits(&self) -> Option<&str> {
        match self.kind {
            NumberKind::Digits => Some(self.canonical.strip_prefix('+').unwrap_or(&self.canonical)),
            NumberKind::Opaque => None,
        }
    }

    /// Whether the number was written in global (`+`) form.
    #[must_use]
    pub fn is_global(&self) -> bool {
        self.global
    }

    /// Number classification.
    #[must_use]
    pub fn kind(&self) -> NumberKind {
        self.kind
    }

    /// Key used for screening (deny prefixes, blocklist, per-callee caps,
    /// emergency): [`Self::digits`] or, for opaque numbers, the user with
    /// `+` and visual separators removed, so `+1-900...x` still meets a
    /// `1900` deny prefix (fail closed; NIST 800-53 Rev5: AC-3).
    #[must_use]
    pub fn screening_key(&self) -> &str {
        match self.kind {
            NumberKind::Digits => self.digits().unwrap_or(&self.canonical),
            NumberKind::Opaque => &self.opaque_screen,
        }
    }

    /// Whether the number may be routed to a trunk at all.
    ///
    /// `false` for an opaque user that looks like a telephone number
    /// (`+19005551234x`, `1-900-555-1234_`) or was over [`MAX_RAW_LEN`]:
    /// it did not canonicalise, so screening cannot be trusted to have
    /// seen the number a carrier would dial. Such calls are refused as
    /// unroutable rather than matched against digit route patterns
    /// (CWE-180; NIST 800-53 Rev5: AC-3, SI-10). Alias users such as
    /// `alice` stay routable.
    #[must_use]
    pub fn is_routable(&self) -> bool {
        !self.numeric_like
    }
}

impl fmt::Display for DialedNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

/// Canonicalise a configured prefix for screening comparison
/// (`DialedNumber::parse(p).screening_key()`).
#[must_use]
pub fn canonical_prefix(p: &str) -> String {
    DialedNumber::parse(p).screening_key().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn table() {
        let cases: &[(&str, &str, Option<&str>, bool)] = &[
            ("9-1-1", "911", Some("911"), false),
            ("(911)", "911", Some("911"), false),
            (
                "+1 (555) 123-4567",
                "+15551234567",
                Some("15551234567"),
                true,
            ),
            ("%2B15551234567", "+15551234567", Some("15551234567"), true),
            ("555;phone-context=+1", "555", Some("555"), false),
            ("+1+2", "+1+2", None, false),
            ("alice", "alice", None, false),
            ("%0d%0a", "%0d%0a", None, false),
            ("", "", None, false),
            ("*67#a", "*67#A", Some("*67#A"), false),
        ];
        for (input, canon, digits, global) in cases {
            let n = DialedNumber::parse(input);
            assert_eq!(n.as_str(), *canon, "{input}");
            assert_eq!(n.digits(), *digits, "{input}");
            assert_eq!(n.is_global(), *global, "{input}");
        }
        let long = "1".repeat(33);
        assert_eq!(DialedNumber::parse(&long).kind(), NumberKind::Opaque);
        assert_eq!(
            DialedNumber::parse(&"1".repeat(32)).kind(),
            NumberKind::Digits
        );
        let huge = "1".repeat(1000);
        assert_eq!(DialedNumber::parse(&huge).kind(), NumberKind::Opaque);
        assert_eq!(DialedNumber::parse(&huge).digits(), None);
    }

    #[test]
    fn sec001_numeric_looking_opaque_is_unroutable_and_screened() {
        for raw in ["+19005551234x", "1-900-555-1234_", "%2B1900555x", "1%zz"] {
            let n = DialedNumber::parse(raw);
            assert_eq!(n.kind(), NumberKind::Opaque, "{raw}");
            assert!(!n.is_routable(), "{raw}");
        }
        assert!(
            DialedNumber::parse("+19005551234x")
                .screening_key()
                .starts_with(&canonical_prefix("1900"))
        );
        assert!(
            DialedNumber::parse("1-900-555-1234_")
                .screening_key()
                .starts_with(&canonical_prefix("+1-900"))
        );
        // Aliases stay routable; digits are routable.
        assert!(DialedNumber::parse("alice").is_routable());
        assert!(DialedNumber::parse("+15551234567").is_routable());
    }

    #[test]
    fn sec004_oversize_user_is_unroutable() {
        let n = DialedNumber::parse(&"a".repeat(MAX_RAW_LEN + 1));
        assert_eq!(n.as_str(), "");
        assert!(!n.is_routable());
    }

    #[test]
    fn canonical_prefix_strips_plus_and_separators() {
        assert_eq!(canonical_prefix("+1-900"), "1900");
        assert_eq!(canonical_prefix("1900"), "1900");
    }

    #[test]
    fn qa_malformed_and_overlong_escapes_are_opaque() {
        for raw in [
            "%",
            "%2",
            "%zz",
            "1%2G5",
            "%C3%A9",
            "%00",
            "%7F",
            "911%0d%0aVia:x",
            "9\r\n11",
            "%25",
            "%3B911",
            "911%3bphone-context=x",
        ] {
            let n = DialedNumber::parse(raw);
            assert_eq!(n.kind(), NumberKind::Opaque, "{raw}");
            assert_eq!(n.digits(), None, "{raw}");
            // Opaque results stay stable under re-parse.
            assert_eq!(DialedNumber::parse(n.as_str()), n, "{raw}");
        }
        // Overlong escape sequences: valid per-byte, still decoded.
        assert_eq!(DialedNumber::parse("%39%31%31").as_str(), "911");
        assert_eq!(DialedNumber::parse("%2b1555").as_str(), "+1555");
        assert_eq!(DialedNumber::parse("1%2D900").as_str(), "1900");
    }

    #[test]
    fn qa_length_boundaries() {
        let at = "1".repeat(MAX_RAW_LEN - 32) + &"-".repeat(32);
        assert_eq!(at.len(), MAX_RAW_LEN);
        assert_eq!(DialedNumber::parse(&at).kind(), NumberKind::Opaque); // 224 digits
        let mut sep_heavy = "-".repeat(MAX_RAW_LEN - 3);
        sep_heavy.push_str("911");
        assert_eq!(DialedNumber::parse(&sep_heavy).as_str(), "911");
        sep_heavy.insert(0, '-');
        assert_eq!(sep_heavy.len(), MAX_RAW_LEN + 1);
        let over = DialedNumber::parse(&sep_heavy);
        assert_eq!((over.kind(), over.as_str()), (NumberKind::Opaque, ""));
        assert_eq!(
            DialedNumber::parse(&format!("+{}", "1".repeat(32)))
                .digits()
                .map(str::len),
            Some(32)
        );
        assert_eq!(
            DialedNumber::parse(&format!("+{}", "1".repeat(33))).kind(),
            NumberKind::Opaque
        );
    }

    #[test]
    fn qa_plus_phone_context_and_emergency_forms() {
        for raw in [
            "911",
            "9-1-1",
            "(911)",
            "9.1.1",
            " 9 1 1 ",
            "911;user=phone",
            "%39-1-1",
        ] {
            let n = DialedNumber::parse(raw);
            assert_eq!((n.as_str(), n.is_global()), ("911", false), "{raw}");
        }
        let g = DialedNumber::parse("+911");
        assert_eq!(
            (g.as_str(), g.digits(), g.is_global()),
            ("+911", Some("911"), true)
        );
        assert_eq!(g.screening_key(), "911");
        let pc = DialedNumber::parse("+1-555-0100;phone-context=example.com;x=y");
        assert_eq!(pc.as_str(), "+15550100");
        // Only separators / lone plus: no digits, opaque.
        for raw in ["+", "---", "()", ";phone-context=+1", "1+", "++1"] {
            assert_eq!(DialedNumber::parse(raw).kind(), NumberKind::Opaque, "{raw}");
        }
        // Opaque user stays opaque; its screening key drops `+` and
        // separators (SEC-001) and is consistent with `canonical_prefix`.
        let a = DialedNumber::parse("alice.smith");
        assert_eq!(
            (a.kind(), a.screening_key()),
            (NumberKind::Opaque, "alicesmith")
        );
        assert_eq!(canonical_prefix("alice.smith"), "alicesmith");
        assert_eq!(canonical_prefix("%2B1 (900)"), "1900");
        assert_eq!(DialedNumber::parse("+1555").to_string(), "+1555");
    }

    proptest! {
        #[test]
        fn idempotent(s in ".{0,300}") {
            let a = DialedNumber::parse(&s);
            let b = DialedNumber::parse(a.as_str());
            prop_assert_eq!(a, b);
        }

        #[test]
        fn separators_do_not_change_screening_key(
            digits in "[0-9]{1,20}",
            seps in proptest::collection::vec((0usize..20, "[-. ()]"), 0..6)
        ) {
            let mut s = digits.clone();
            for (pos, sep) in seps {
                let p = pos.min(s.len());
                s.insert_str(p, &sep);
            }
            let n = DialedNumber::parse(&s);
            prop_assert_eq!(n.screening_key(), digits.as_str());
        }

        #[test]
        fn no_panic_on_bytes(b in proptest::collection::vec(any::<u8>(), 0..400)) {
            let s = String::from_utf8_lossy(&b);
            let _ = DialedNumber::parse(&s);
        }
    }
}
