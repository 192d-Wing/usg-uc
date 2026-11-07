//! Output encoding for phone provisioning configs.
//!
//! Every operator-sourced string interpolated into a generated config goes
//! through one of these functions, chosen by the context it lands in. Escaping
//! is total (never fails); rejection of bad input happens on write in
//! `sbc-config-store`.
//!
//! ## NIST 800-53 Rev5: SI-15 (Information Output Filtering), SI-10 (Information Input Validation)
//!
//! XML 1.0 §2.2 (Char production), §2.4 (`&`/`<` in character data),
//! §2.5 (`--` in comments), §3.3.3 (attribute-value normalisation).

use std::borrow::Cow;

/// Replacement for characters that may not appear in an XML 1.0 document.
const REPLACEMENT: char = '\u{FFFD}';

/// True for characters XML 1.0 forbids, plus DEL and C1 controls which are
/// legal but confuse firmware parsers. `\t`, `\n`, `\r` are handled per context.
const fn is_illegal(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}'
        | '\u{7F}'..='\u{9F}' | '\u{FFFE}' | '\u{FFFF}')
}

/// Shared single-pass encoder. `map` returns `Some(replacement)` for chars
/// that must change, `None` to copy verbatim.
fn encode(s: &str, map: impl Fn(char) -> Option<&'static str>) -> Cow<'_, str> {
    let Some(first) = s.char_indices().find(|&(_, c)| map(c).is_some()) else {
        return Cow::Borrowed(s);
    };
    let mut out = String::with_capacity(s.len() + 16);
    out.push_str(&s[..first.0]);
    for c in s[first.0..].chars() {
        match map(c) {
            Some(rep) => out.push_str(rep),
            None => out.push(c),
        }
    }
    Cow::Owned(out)
}

const fn text_map(c: char) -> Option<&'static str> {
    match c {
        '&' => Some("&amp;"),
        '<' => Some("&lt;"),
        '>' => Some("&gt;"),
        '"' => Some("&quot;"),
        '\'' => Some("&apos;"),
        // Single-line values must not wrap (line-oriented MPP parsers).
        '\n' | '\r' => Some(" "),
        c if is_illegal(c) => Some("\u{FFFD}"),
        _ => None,
    }
}

/// Escape for XML element character data. Also escapes quotes so it is never
/// wrong inside an attribute; CR/LF become a space.
#[must_use]
pub fn xml_text(s: &str) -> Cow<'_, str> {
    encode(s, text_map)
}

/// Escape for an XML attribute value (double- or single-quoted). Like
/// [`xml_text`] but `\t \n \r` become numeric character references so
/// attribute-value normalisation (XML 1.0 §3.3.3) cannot alter them.
#[must_use]
pub fn xml_attr(s: &str) -> Cow<'_, str> {
    encode(s, |c| match c {
        '\t' => Some("&#9;"),
        '\n' => Some("&#10;"),
        '\r' => Some("&#13;"),
        c => text_map(c),
    })
}

/// Neutralise text for an XML comment body. Comments do not decode entities,
/// so `--` becomes `- -` and a trailing `-` gets a following space
/// (XML 1.0 §2.5). Illegal chars and CR/LF are replaced.
#[must_use]
pub fn xml_comment(s: &str) -> Cow<'_, str> {
    let needs = s.contains("--")
        || s.ends_with('-')
        || s.chars().any(|c| c == '\n' || c == '\r' || is_illegal(c));
    if !needs {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut prev_dash = false;
    for c in s.chars() {
        let c = if c == '\n' || c == '\r' {
            ' '
        } else if is_illegal(c) {
            REPLACEMENT
        } else {
            c
        };
        if c == '-' && prev_dash {
            out.push(' ');
        }
        out.push(c);
        prev_dash = c == '-';
    }
    if prev_dash {
        out.push(' ');
    }
    Cow::Owned(out)
}

/// Escape a sub-field of the Cisco MPP `fnc=..;sub=..;nme=..` micro-format.
/// `;` and `=` are delimiters and are dropped, then the result is XML-escaped.
#[must_use]
pub fn mpp_kv_value(s: &str) -> Cow<'_, str> {
    if s.contains([';', '=']) {
        let stripped: String = s.chars().filter(|&c| c != ';' && c != '=').collect();
        Cow::Owned(xml_text(&stripped).into_owned())
    } else {
        xml_text(s)
    }
}

/// Map a stored transport string onto a closed set of tokens.
/// Anything unrecognised renders as `UDP`.
#[must_use]
pub const fn transport_token(t: &str) -> &'static str {
    if t.eq_ignore_ascii_case("tcp") {
        "TCP"
    } else if t.eq_ignore_ascii_case("tls") {
        "TLS"
    } else {
        "UDP"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn text_table() {
        assert_eq!(xml_text("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(xml_text("a\r\nb"), "a  b");
        assert_eq!(xml_text("a\tb"), "a\tb");
        assert_eq!(xml_text("\0\x1b\u{7f}\u{85}\u{fffe}"), "\u{FFFD}".repeat(5));
    }

    #[test]
    fn attr_table() {
        assert_eq!(xml_attr("x\" y=\"z"), "x&quot; y=&quot;z");
        assert_eq!(xml_attr("\t\n\r"), "&#9;&#10;&#13;");
        assert_eq!(xml_attr("\0"), "\u{FFFD}");
    }

    #[test]
    fn comment_table() {
        assert_eq!(xml_comment("--><x/><!--"), "- -><x/><!- - ");
        assert_eq!(xml_comment("a-"), "a- ");
        assert_eq!(xml_comment("a<b&c"), "a<b&c");
        assert!(!xml_comment("---").contains("--"));
        assert_eq!(xml_comment("a\nb\0"), "a b\u{FFFD}");
    }

    #[test]
    fn kv_table() {
        assert_eq!(mpp_kv_value("x;sub=evil"), "xsubevil");
        assert_eq!(mpp_kv_value("a<b;"), "a&lt;b");
    }

    #[test]
    fn transport_table() {
        assert_eq!(transport_token("tcp"), "TCP");
        assert_eq!(transport_token("TLS"), "TLS");
        assert_eq!(transport_token("udp</x>"), "UDP");
    }

    #[test]
    fn clean_input_is_borrowed() {
        for f in [xml_text, xml_attr, xml_comment, mpp_kv_value] {
            assert!(matches!(f("John Doe 1001"), Cow::Borrowed(_)));
        }
    }

    fn assert_safe(out: &str) {
        assert!(!out.contains('<'), "{out:?}");
        assert!(!out.contains('"'), "{out:?}");
        for (i, _) in out.match_indices('&') {
            let rest = &out[i..];
            assert!(
                [
                    "&amp;", "&lt;", "&gt;", "&quot;", "&apos;", "&#9;", "&#10;", "&#13;"
                ]
                .iter()
                .any(|e| rest.starts_with(e)),
                "{out:?}"
            );
        }
        assert!(!out.chars().any(is_illegal), "{out:?}");
    }

    #[test]
    fn exhaustive_low_chars() {
        for cp in 0u32..=0xFF {
            let c = char::from_u32(cp).unwrap();
            let s = format!("a{c}b");
            assert_safe(&xml_text(&s));
            assert_safe(&xml_attr(&s));
            assert_safe(&mpp_kv_value(&s));
            assert!(!xml_text(&s).contains(['\n', '\r']));
            assert!(!xml_attr(&s).contains(['\t', '\n', '\r']));
            let dashed = format!("{c}{c}-");
            let cm = xml_comment(&dashed);
            assert!(!cm.contains("--") && !cm.ends_with('-'));
            assert!(!cm.chars().any(is_illegal));
        }
    }

    /// Minimal decoder for the entities emitted above.
    fn decode(s: &str) -> String {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&#9;", "\t")
            .replace("&#10;", "\n")
            .replace("&#13;", "\r")
            .replace("&amp;", "&")
    }

    /// Hand-written well-formedness round trip for `<a b="..">..</a>`.
    #[test]
    fn round_trip() {
        let inputs = [
            "x</displayName><proxy>evil.example</proxy><displayName>",
            "x\" reg.1.address=\"evil",
            "&amp; literal",
            "tab\there\nnl",
            "plain",
        ];
        for s in inputs {
            let doc = format!("<a b=\"{}\">{}</a>", xml_attr(s), xml_text(s));
            let body = doc.strip_prefix("<a b=\"").unwrap();
            let q = body.find('"').unwrap();
            let (attr, rest) = body.split_at(q);
            let rest = rest.strip_prefix("\">").unwrap();
            let text = rest.strip_suffix("</a>").unwrap();
            assert!(!attr.contains('<') && !text.contains('<'));
            assert_eq!(decode(attr), s);
            assert_eq!(decode(text), s.replace(['\n', '\r'], " "));
        }
    }
}
