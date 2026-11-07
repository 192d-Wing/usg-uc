//! Comma-separated header list splitting per RFC 3261 §7.3.1.
//!
//! One splitter is shared by Via, Route, Record-Route, Path and Contact so
//! every list header is tokenised the same way.
//!
//! RFC 3261 §7.3.1: multiple header field values may be combined into one
//! field separated by commas. A comma inside a quoted-string (§25.1, with
//! quoted-pair escapes) or inside `<...>` (a URI) is not a separator.
//!
//! NIST 800-53 Rev5: SI-10 (Information Input Validation), SI-16 (Memory
//! Protection) - the scanner walks bytes and only splits on ASCII
//! delimiters, so every slice index is on a UTF-8 char boundary and the
//! splitter cannot panic on multibyte input.

use crate::error::{SipError, SipResult};

/// Scanner state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Normal,
    InQuote,
    InAngle,
}

/// Iterator over the elements of a comma-separated header list.
///
/// Yields trimmed, non-empty elements. Yields one `Err` (and then stops)
/// on an unterminated quoted-string or angle bracket.
#[derive(Debug, Clone)]
pub struct ListSplit<'a> {
    value: &'a str,
    pos: usize,
    done: bool,
}

/// Returns true for LWS bytes (SP / HTAB) per RFC 3261 §25.1.
fn is_lws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Trims SP / HTAB from both ends.
fn trim_lws(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

impl<'a> Iterator for ListSplit<'a> {
    type Item = SipResult<&'a str>;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.value.as_bytes();
        // Power of 10 Rule 2: outer loop advances `pos` on every element and
        // is bounded by `bytes.len()`.
        while !self.done {
            let start = self.pos;
            let mut state = State::Normal;
            let mut i = start;
            let mut escaped = false;
            // Power of 10 Rule 2: bounded by bytes.len().
            while i < bytes.len() {
                let b = bytes[i];
                match state {
                    State::InQuote => {
                        if escaped {
                            escaped = false;
                        } else if b == b'\\' {
                            // RFC 3261 §25.1: quoted-pair = "\" (%x00-09 / %x0B-0C / %x0E-7F)
                            escaped = true;
                        } else if b == b'"' {
                            state = State::Normal;
                        }
                    }
                    State::InAngle => {
                        if b == b'>' {
                            state = State::Normal;
                        }
                    }
                    State::Normal => match b {
                        b'"' => state = State::InQuote,
                        b'<' => state = State::InAngle,
                        b',' => break,
                        _ => {}
                    },
                }
                i += 1;
            }

            if state != State::Normal {
                self.done = true;
                return Some(Err(SipError::ParseError {
                    reason: match state {
                        State::InQuote => "unterminated quoted-string in header list".to_string(),
                        _ => "unterminated angle bracket in header list".to_string(),
                    },
                }));
            }

            // `i` is either bytes.len() or the index of an ASCII ',' so both
            // slice bounds are char boundaries.
            let elem = self.value.get(start..i).map(trim_lws).unwrap_or_default();
            if i >= bytes.len() {
                self.done = true;
            } else {
                self.pos = i + 1;
            }
            if !elem.is_empty() {
                return Some(Ok(elem));
            }
        }
        None
    }
}

/// Splits a comma-separated header field value into its elements.
///
/// Empty elements (`a,,b`) are skipped; each element is LWS-trimmed.
#[must_use]
pub fn split_list(value: &str) -> ListSplit<'_> {
    let start = value.bytes().take_while(|&b| is_lws(b)).count();
    ListSplit {
        value,
        pos: start,
        done: false,
    }
}

/// Splits a header list and enforces a maximum element count.
///
/// NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection).
///
/// # Errors
///
/// Returns [`SipError::ParseError`] on an unterminated quote or angle
/// bracket and [`SipError::LimitExceeded`] if more than `max` elements.
pub fn split_list_bounded(value: &str, max: usize) -> SipResult<Vec<&str>> {
    let mut out = Vec::new();
    for elem in split_list(value) {
        let elem = elem?;
        if out.len() >= max {
            return Err(SipError::LimitExceeded {
                what: "header list elements",
                limit: max,
            });
        }
        out.push(elem);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn split(v: &str) -> Vec<&str> {
        split_list_bounded(v, 64).unwrap()
    }

    #[test]
    fn simple() {
        assert_eq!(split("<sip:a>, <sip:b>"), vec!["<sip:a>", "<sip:b>"]);
    }

    #[test]
    fn multibyte_before_comma_regression() {
        // Used to panic (char index used as byte index).
        let v = "\"Ünïcödé\" <sip:a@example.com>, <sip:b@example.com>";
        assert_eq!(
            split(v),
            vec!["\"Ünïcödé\" <sip:a@example.com>", "<sip:b@example.com>"]
        );
        let v = "Ünï <sip:a>,é<sip:b>";
        assert_eq!(split(v), vec!["Ünï <sip:a>", "é<sip:b>"]);
    }

    #[test]
    fn escaped_quote_and_commas() {
        let v = r#""a \" , b" <sip:x>, "c,d" <sip:y;p=1,2>"#;
        assert_eq!(
            split(v),
            vec![r#""a \" , b" <sip:x>"#, r#""c,d" <sip:y;p=1,2>"#]
        );
    }

    #[test]
    fn comma_inside_angle() {
        assert_eq!(
            split("<sip:a?h=1,2>, <sip:b>"),
            vec!["<sip:a?h=1,2>", "<sip:b>"]
        );
    }

    #[test]
    fn unterminated() {
        assert!(split_list_bounded("\"abc, <sip:a>", 64).is_err());
        assert!(split_list_bounded("<sip:a, sip:b", 64).is_err());
        assert!(split_list_bounded("\"abc\\\"", 64).is_err());
    }

    #[test]
    fn empty_elements() {
        assert_eq!(split(" a,, ,b ,"), vec!["a", "b"]);
        assert_eq!(split(""), Vec::<&str>::new());
        assert_eq!(split(" , "), Vec::<&str>::new());
    }

    #[test]
    fn max_elements() {
        let v = vec!["<sip:a>"; 64].join(",");
        assert_eq!(split_list_bounded(&v, 64).unwrap().len(), 64);
        let v = vec!["<sip:a>"; 65].join(",");
        assert!(matches!(
            split_list_bounded(&v, 64),
            Err(SipError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn star() {
        assert_eq!(split("*"), vec!["*"]);
    }

    #[test]
    fn via_list() {
        assert_eq!(
            split("SIP/2.0/UDP a;branch=z9hG4bK1, SIP/2.0/TCP b"),
            vec!["SIP/2.0/UDP a;branch=z9hG4bK1", "SIP/2.0/TCP b"]
        );
    }
}
