//! XML 1.0 escaping for SIPREC metadata.
//!
//! Every attacker-derived string (display names, AORs, Session-IDs, labels)
//! that ends up in an `application/rs-metadata+xml` document goes through
//! [`escape_text`] or [`escape_attr`]. Code points that XML 1.0 §2.2 does not
//! allow are rejected rather than stripped, so the recorder's evidence never
//! silently differs from the value seen on the wire.
//
// NIST 800-53 Rev5: SI-10 (Information Input Validation), SI-15 (Information
// Output Filtering).

use std::borrow::Cow;

use crate::error::{SiprecError, SiprecResult};

/// XML 1.0 §2.2 `Char`: TAB, LF, CR, U+0020..U+D7FF, U+E000..U+FFFD,
/// U+10000..U+10FFFF. Surrogates cannot occur in a Rust `str`.
const fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn escape(input: &str, attr: bool) -> SiprecResult<Cow<'_, str>> {
    let needs = |c: char| {
        matches!(c, '&' | '<' | '>' | '"' | '\'') || (attr && matches!(c, '\t' | '\n' | '\r'))
    };
    if let Some(bad) = input.chars().find(|c| !is_xml_char(*c)) {
        return Err(SiprecError::InvalidMetadata {
            reason: format!(
                "code point U+{:04X} is not allowed in XML 1.0",
                u32::from(bad)
            ),
        });
    }
    if !input.chars().any(needs) {
        return Ok(Cow::Borrowed(input));
    }
    let mut out = String::with_capacity(input.len() + 16);
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 §3.3.3: literal whitespace in attributes is normalized
            // to spaces by the reader; character references survive.
            '\t' if attr => out.push_str("&#9;"),
            '\n' if attr => out.push_str("&#10;"),
            '\r' if attr => out.push_str("&#13;"),
            _ => out.push(c),
        }
    }
    Ok(Cow::Owned(out))
}

/// Escapes a value for use as XML character data.
///
/// # Errors
///
/// [`SiprecError::InvalidMetadata`] if `input` contains a code point that is
/// not allowed in XML 1.0 (e.g. NUL or other C0 controls, U+FFFE, U+FFFF).
pub fn escape_text(input: &str) -> SiprecResult<Cow<'_, str>> {
    escape(input, false)
}

/// Escapes a value for use inside a double- or single-quoted XML attribute.
/// TAB/LF/CR are written as character references so attribute-value
/// normalization does not alter them.
///
/// # Errors
///
/// Same as [`escape_text`].
pub fn escape_attr(input: &str) -> SiprecResult<Cow<'_, str>> {
    escape(input, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_table() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            ("plain", "plain", "plain"),
            ("a&b", "a&amp;b", "a&amp;b"),
            ("<x>", "&lt;x&gt;", "&lt;x&gt;"),
            ("\"q'", "&quot;q&apos;", "&quot;q&apos;"),
            ("Zoë 名前", "Zoë 名前", "Zoë 名前"),
            ("a\tb\nc\r", "a\tb\nc\r", "a&#9;b&#10;c&#13;"),
        ];
        for (input, text, attr) in cases {
            assert_eq!(escape_text(input)?, text, "{input}");
            assert_eq!(escape_attr(input)?, attr, "{input}");
        }
        assert!(matches!(escape_text("plain"), Ok(Cow::Borrowed(_))));
        Ok(())
    }

    #[test]
    fn rejects_illegal_code_points() {
        for bad in ["\0", "a\u{1}", "\u{B}", "\u{1F}", "\u{FFFE}", "\u{FFFF}"] {
            assert!(
                matches!(escape_text(bad), Err(SiprecError::InvalidMetadata { .. })),
                "{bad:?}"
            );
            assert!(escape_attr(bad).is_err(), "{bad:?}");
        }
        assert!(escape_text("\u{10FFFF}\u{E000}\u{D7FF}").is_ok());
    }
}
