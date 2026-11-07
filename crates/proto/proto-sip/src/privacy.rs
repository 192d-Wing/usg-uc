//! RFC 3323 Privacy header and privacy-service helpers, with the RFC 3325
//! `id` privacy type and trust-domain identity handling.
//!
//! - [`PrivacyHeader`] parses and serialises `Privacy: priv-value *(";"
//!   priv-value)` (RFC 3323 §4.2).
//! - [`apply_privacy`] performs the privacy-service actions a SIP message
//!   layer can do (RFC 3323 §5.1 `header`, §5.3 `user`, RFC 3325 §9.3 `id`)
//!   and honours `critical`.
//! - [`sanitize_inbound_identity`] removes asserted identity received from
//!   outside the trust domain (RFC 3325 §5).
//! - [`rpid_to_pai`] converts Remote-Party-ID (draft-ietf-sip-privacy-04) to
//!   a clean RFC 3325 §9.1 P-Asserted-Identity.
//!
//! Library-only: no daemon path calls these yet.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AC-21 / SC-4**: Identity and header disclosure across trust boundaries
//! - **SI-10**: Privacy, RPID and identity values are grammar-validated and
//!   bounded; output is built from parsed values, never raw input
//! - **SC-5**: At most [`MAX_PRIVACY_VALUES`] Privacy values

use crate::error::SipError;
use crate::header::{Header, HeaderName, Headers, is_token_byte};
use crate::header_params::NameAddr;
use crate::list::split_list_bounded;
use crate::message::SipRequest;
use crate::uri::{SipUri, Uri};
use std::fmt;
use std::str::FromStr;

/// Maximum number of Privacy values accepted (SC-5).
pub const MAX_PRIVACY_VALUES: usize = 16;

/// Display name used for anonymized identities (RFC 3323 §4.1.1.3).
pub const ANONYMOUS_DISPLAY: &str = "Anonymous";

/// URI used for anonymized identities (RFC 3323 §4.1.1.3).
pub const ANONYMOUS_URI: &str = "sip:anonymous@anonymous.invalid";

/// Headers removed for `Privacy: header` (RFC 3323 §5.1). Via,
/// Record-Route and Contact are left to `TopologyHider`.
const HEADER_PRIVACY_STRIP: [HeaderName; 7] = [
    HeaderName::Subject,
    HeaderName::CallInfo,
    HeaderName::Organization,
    HeaderName::UserAgent,
    HeaderName::ReplyTo,
    HeaderName::InReplyTo,
    HeaderName::Warning,
];

/// One `priv-value` (RFC 3323 §4.2, RFC 3325 §9.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrivacyValue {
    /// `none`: privacy services MUST NOT apply privacy.
    None,
    /// `header`: obscure headers that reveal information.
    Header,
    /// `session`: anonymize media.
    Session,
    /// `user`: user-level privacy (anonymous From).
    User,
    /// `id`: RFC 3325 - do not forward asserted identity outside the trust
    /// domain.
    Id,
    /// `critical`: the request MUST be rejected if any requested privacy
    /// cannot be provided.
    Critical,
    /// An extension token (lowercased).
    Other(String),
}

impl PrivacyValue {
    /// Canonical lowercase token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Header => "header",
            Self::Session => "session",
            Self::User => "user",
            Self::Id => "id",
            Self::Critical => "critical",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for PrivacyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PrivacyValue {
    type Err = PrivacyError;

    fn from_str(s: &str) -> Result<Self, PrivacyError> {
        let s = s.trim();
        if s.is_empty() || !s.bytes().all(is_token_byte) {
            return Err(PrivacyError::Malformed(
                "priv-value is not a token".to_string(),
            ));
        }
        let lower = s.to_ascii_lowercase();
        Ok(match lower.as_str() {
            "none" => Self::None,
            "header" => Self::Header,
            "session" => Self::Session,
            "user" => Self::User,
            "id" => Self::Id,
            "critical" => Self::Critical,
            _ => Self::Other(lower),
        })
    }
}

/// Errors from Privacy parsing and the privacy service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyError {
    /// Malformed Privacy value; the caller answers 400.
    #[error("malformed Privacy header: {0}")]
    Malformed(String),
    /// More than [`MAX_PRIVACY_VALUES`] values.
    #[error("too many Privacy values (limit {MAX_PRIVACY_VALUES})")]
    TooMany,
    /// `critical` was requested and these values cannot be satisfied. RFC
    /// 3323 §5.1: the caller rejects the request with 500.
    #[error("requested privacy cannot be satisfied")]
    CannotSatisfy {
        /// The unsatisfied values.
        unsatisfied: Vec<PrivacyValue>,
    },
    /// A header needed by the privacy service is malformed.
    #[error("{0}")]
    Sip(String),
}

impl From<SipError> for PrivacyError {
    fn from(e: SipError) -> Self {
        Self::Sip(e.to_string())
    }
}

/// Parsed Privacy header (de-duplicated, order of first appearance kept).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivacyHeader(Vec<PrivacyValue>);

impl PrivacyHeader {
    /// Creates a header from values, applying the same validation as parsing.
    ///
    /// # Errors
    ///
    /// Returns an error if there are no values, too many, or `none` is
    /// combined with another value.
    pub fn new(values: impl IntoIterator<Item = PrivacyValue>) -> Result<Self, PrivacyError> {
        let mut out = Self::default();
        for v in values {
            out.push(v)?;
        }
        out.finish()
    }

    fn push(&mut self, v: PrivacyValue) -> Result<(), PrivacyError> {
        if !self.0.contains(&v) {
            if self.0.len() >= MAX_PRIVACY_VALUES {
                return Err(PrivacyError::TooMany);
            }
            self.0.push(v);
        }
        Ok(())
    }

    fn finish(self) -> Result<Self, PrivacyError> {
        if self.0.is_empty() {
            return Err(PrivacyError::Malformed("empty Privacy header".to_string()));
        }
        // Orchestrator decision (OQ-1): `none` with anything else is malformed.
        if self.0.len() > 1 && self.0.contains(&PrivacyValue::None) {
            return Err(PrivacyError::Malformed(
                "`none` combined with other values".to_string(),
            ));
        }
        Ok(self)
    }

    fn push_list(&mut self, s: &str) -> Result<(), PrivacyError> {
        for part in s.split(';') {
            self.push(part.parse()?)?;
        }
        Ok(())
    }

    /// Merges every Privacy header instance (and comma lists) in `headers`.
    /// Returns `Ok(None)` when there is no Privacy header.
    ///
    /// # Errors
    ///
    /// Returns an error if any instance is malformed.
    pub fn from_headers(headers: &Headers) -> Result<Option<Self>, PrivacyError> {
        let mut out = Self::default();
        let mut seen = false;
        for h in headers.get_all(&HeaderName::Privacy) {
            seen = true;
            let parts = split_list_bounded(&h.value, crate::MAX_LIST_ELEMENTS)?;
            if parts.is_empty() {
                return Err(PrivacyError::Malformed("empty Privacy header".to_string()));
            }
            for p in parts {
                out.push_list(p)?;
            }
        }
        if seen {
            out.finish().map(Some)
        } else {
            Ok(None)
        }
    }

    /// The values, in order of first appearance.
    #[must_use]
    pub fn values(&self) -> &[PrivacyValue] {
        &self.0
    }

    /// Returns true if `v` was requested.
    #[must_use]
    pub fn contains(&self, v: &PrivacyValue) -> bool {
        self.0.contains(v)
    }

    /// Returns true for `Privacy: none`.
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.contains(&PrivacyValue::None)
    }

    /// Returns true if `critical` was requested.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.contains(&PrivacyValue::Critical)
    }
}

impl FromStr for PrivacyHeader {
    type Err = PrivacyError;

    fn from_str(s: &str) -> Result<Self, PrivacyError> {
        let mut out = Self::default();
        out.push_list(s)?;
        out.finish()
    }
}

impl fmt::Display for PrivacyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, v) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(";")?;
            }
            f.write_str(v.as_str())?;
        }
        Ok(())
    }
}

/// Privacy services the caller provides beyond what [`apply_privacy`] does
/// itself (`header`, `user` and `id` are always performed by it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrivacyCapabilities {
    /// The caller anonymizes media (e.g. anchors and relays RTP). The
    /// message layer cannot, so it defaults to false.
    pub session: bool,
}

/// What [`apply_privacy`] did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivacyOutcome {
    /// `header` was requested: the caller must also run topology hiding
    /// (Via, Record-Route, Contact) per RFC 3323 §5.1.
    pub needs_topology_hiding: bool,
    /// Values that were requested but not provided (no `critical`).
    pub unsatisfied: Vec<PrivacyValue>,
    /// Number of header fields removed.
    pub removed_headers: usize,
    /// The From identity was anonymized.
    pub from_anonymized: bool,
    /// The Privacy header was removed (all satisfied, untrusted egress).
    pub privacy_header_removed: bool,
}

fn remove_counted(headers: &mut Headers, name: &HeaderName) -> usize {
    let n = headers.count(name);
    headers.remove(name);
    n
}

/// Applies the privacy service for `privacy` to an outgoing request.
///
/// - `header` (RFC 3323 §5.1): removes Subject, Call-Info, Organization,
///   User-Agent, Reply-To, In-Reply-To and Warning; sets
///   `needs_topology_hiding`.
/// - `user` (RFC 3323 §4.1.1.3, §5.3): From becomes
///   `Anonymous <sip:anonymous@anonymous.invalid>` with the tag kept.
/// - `id` (RFC 3325 §9.3, §5): removes every P-Asserted-Identity when
///   `egress_trusted` is false.
/// - `session`: satisfied only if `caps.session`.
/// - `critical` (RFC 3323 §5.1): if anything requested is unsatisfied, returns
///   [`PrivacyError::CannotSatisfy`] **without modifying the request**; the
///   caller answers 500.
///
/// When everything is satisfied and the egress is untrusted the Privacy
/// header is removed; toward a trusted next hop it is kept so the next
/// privacy service can act (RFC 3323 §5.1).
///
/// # Errors
///
/// [`PrivacyError::CannotSatisfy`] as above, or [`PrivacyError::Sip`] if From
/// must be anonymized but does not parse.
pub fn apply_privacy(
    req: &mut SipRequest,
    privacy: &PrivacyHeader,
    caps: PrivacyCapabilities,
    egress_trusted: bool,
) -> Result<PrivacyOutcome, PrivacyError> {
    let mut outcome = PrivacyOutcome::default();
    if privacy.is_none() {
        return Ok(outcome);
    }

    let unsatisfied: Vec<PrivacyValue> = privacy
        .values()
        .iter()
        .filter(|v| match v {
            PrivacyValue::Session => !caps.session,
            PrivacyValue::Header
            | PrivacyValue::User
            | PrivacyValue::Id
            | PrivacyValue::Critical
            | PrivacyValue::None => false,
            PrivacyValue::Other(_) => true,
        })
        .cloned()
        .collect();
    if privacy.is_critical() && !unsatisfied.is_empty() {
        return Err(PrivacyError::CannotSatisfy { unsatisfied });
    }

    // Parse before mutating so a malformed From leaves the request intact.
    let anonymous_from = if privacy.contains(&PrivacyValue::User) {
        let from = req
            .headers
            .from_parsed()
            .ok_or_else(|| SipError::InvalidHeader {
                name: "From".to_string(),
                reason: "From cannot be parsed for user privacy".to_string(),
            })?;
        let uri: SipUri = ANONYMOUS_URI.parse()?;
        let mut anon = NameAddr::new(uri).with_display_name(ANONYMOUS_DISPLAY);
        anon.tag = from.tag;
        Some(anon.to_string())
    } else {
        None
    };

    if privacy.contains(&PrivacyValue::Header) {
        for name in &HEADER_PRIVACY_STRIP {
            outcome.removed_headers += remove_counted(&mut req.headers, name);
        }
        outcome.needs_topology_hiding = true;
    }
    if let Some(from) = anonymous_from {
        req.headers.set(HeaderName::From, from);
        outcome.from_anonymized = true;
    }
    if privacy.contains(&PrivacyValue::Id) && !egress_trusted {
        outcome.removed_headers += remove_counted(&mut req.headers, &HeaderName::PAssertedIdentity);
    }

    if unsatisfied.is_empty() && !egress_trusted {
        outcome.removed_headers += remove_counted(&mut req.headers, &HeaderName::Privacy);
        outcome.privacy_header_removed = true;
    }
    outcome.unsatisfied = unsatisfied;
    Ok(outcome)
}

/// RFC 3325 §5: removes P-Asserted-Identity and P-Preferred-Identity
/// received from outside the trust domain. Returns the number removed.
pub fn sanitize_inbound_identity(headers: &mut Headers, ingress_trusted: bool) -> usize {
    if ingress_trusted {
        return 0;
    }
    remove_counted(headers, &HeaderName::PAssertedIdentity)
        + remove_counted(headers, &HeaderName::PPreferredIdentity)
}

/// A Remote-Party-ID element reduced to what PAI may carry.
struct RpidIdentity {
    display: Option<String>,
    uri: Uri,
    /// RPID `privacy=` asked to hide the identity (`full`, `name`, `uri`).
    hide: bool,
    /// RPID `privacy=` asked to hide the display name (`full`, `name`).
    hide_name: bool,
    /// RPID `screen=yes`: the sending network verified the identity.
    screened: bool,
}

/// Parses one RPID element: `[display] <uri> *(;param)`. `None` if it is
/// not a name-addr with a sip/sips/tel URI.
fn parse_rpid(elem: &str) -> Option<RpidIdentity> {
    let elem = elem.trim();
    let open = elem.find('<')?;
    let close = open + elem.get(open..)?.find('>')?;
    let display_raw = elem.get(..open)?.trim();
    let display = if display_raw.is_empty() {
        None
    } else if let Some(inner) = display_raw
        .strip_prefix('"')
        .and_then(|d| d.strip_suffix('"'))
    {
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for c in inner.chars() {
            if escaped {
                out.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                return None;
            } else {
                out.push(c);
            }
        }
        Some(out)
    } else if display_raw
        .split_ascii_whitespace()
        .all(|w| w.bytes().all(is_token_byte))
    {
        Some(display_raw.to_string())
    } else {
        return None;
    };
    // SI-10: no control characters in an emitted display name.
    if display
        .as_deref()
        .is_some_and(|d| d.chars().any(char::is_control))
    {
        return None;
    }
    let uri: Uri = elem.get(open + 1..close)?.parse().ok()?;
    if matches!(uri, Uri::Absolute(_)) {
        return None;
    }
    let mut hide = false;
    let mut hide_name = false;
    let mut screened = false;
    for p in elem.get(close + 1..)?.split(';') {
        let Some((k, v)) = p.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim().trim_matches('"');
        if k.eq_ignore_ascii_case("privacy") {
            if v.eq_ignore_ascii_case("full") || v.eq_ignore_ascii_case("name") {
                hide = true;
                hide_name = true;
            } else if v.eq_ignore_ascii_case("uri") {
                hide = true;
            }
        } else if k.eq_ignore_ascii_case("screen") {
            screened = v.eq_ignore_ascii_case("yes");
        }
    }
    Some(RpidIdentity {
        display,
        uri,
        hide,
        hide_name,
        screened,
    })
}

/// Formats a PAI value as a name-addr with a quoted, escaped display name.
fn format_pai(id: &RpidIdentity) -> String {
    match id.display {
        Some(ref d) => {
            let escaped = d.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\" <{}>", id.uri)
        }
        None => format!("<{}>", id.uri),
    }
}

/// Converts Remote-Party-ID headers to P-Asserted-Identity (RFC 3325 §9.1).
///
/// Each RPID element is parsed; only the display name and URI are emitted
/// (no `party`/`screen`/`privacy` params). At most one sip/sips and one tel
/// PAI are added.
///
/// RFC 3325 §5/§9.1: PAI asserts a network-verified identity, so only RPID
/// elements carrying `screen=yes` are converted. `screen=no` and an absent
/// `screen` (draft-ietf-sip-privacy-04 default `no`) are skipped: a
/// user-provided identity is never promoted to an asserted one.
///
/// Privacy mapping (RFC 3323 §4.2): RPID `privacy=uri` adds `id`;
/// `privacy=name` and `privacy=full` add `id` and `user` (hide the display
/// name in user-populated headers such as From). Values are merged into an
/// existing Privacy header.
///
/// Elements that do not parse are skipped; if none qualify, nothing is
/// added. Remote-Party-ID itself is left unchanged. Returns the number of
/// PAI values added.
pub fn rpid_to_pai(headers: &mut Headers) -> usize {
    let rpid_name = HeaderName::Custom("Remote-Party-ID".to_string());
    let mut sip: Option<RpidIdentity> = None;
    let mut tel: Option<RpidIdentity> = None;
    let mut hide = false;
    let mut hide_name = false;
    let mut seen = 0usize;
    for h in headers.get_all(&rpid_name) {
        let Ok(parts) = split_list_bounded(&h.value, crate::MAX_LIST_ELEMENTS) else {
            continue;
        };
        for p in parts {
            seen += 1;
            if seen > crate::MAX_LIST_ELEMENTS {
                break;
            }
            let Some(id) = parse_rpid(p) else { continue };
            if !id.screened {
                continue;
            }
            hide |= id.hide;
            hide_name |= id.hide_name;
            let slot = if matches!(id.uri, Uri::Tel(_)) {
                &mut tel
            } else {
                &mut sip
            };
            if slot.is_none() {
                *slot = Some(id);
            }
        }
    }
    let mut added = 0;
    for id in [sip, tel].into_iter().flatten() {
        headers.add(Header::new(HeaderName::PAssertedIdentity, format_pai(&id)));
        added += 1;
    }
    if added > 0 && hide {
        let mut wanted = vec![PrivacyValue::Id];
        if hide_name {
            wanted.push(PrivacyValue::User);
        }
        let merged = match PrivacyHeader::from_headers(headers) {
            Ok(Some(p)) if !p.is_none() => {
                let mut vals = p.values().to_vec();
                vals.extend(wanted.iter().cloned());
                PrivacyHeader::new(vals).unwrap_or_else(|_| p.clone())
            }
            // Absent, `none`, or malformed: the RPID asked to hide, so the
            // stronger request wins.
            _ => PrivacyHeader(wanted),
        };
        headers.set(HeaderName::Privacy, merged.to_string());
    }
    added
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::message::SipMessage;

    #[test]
    fn parse_roundtrip_all_values_mixed_case() {
        let p: PrivacyHeader = "Header; SESSION;user;Id;critical".parse().unwrap();
        assert_eq!(
            p.values(),
            [
                PrivacyValue::Header,
                PrivacyValue::Session,
                PrivacyValue::User,
                PrivacyValue::Id,
                PrivacyValue::Critical
            ]
        );
        assert_eq!(p.to_string(), "header;session;user;id;critical");
        assert_eq!(p.to_string().parse::<PrivacyHeader>().unwrap(), p);
        let none: PrivacyHeader = "none".parse().unwrap();
        assert!(none.is_none());
        let ext: PrivacyHeader = "x-foo;id;id".parse().unwrap();
        assert_eq!(ext.to_string(), "x-foo;id");
    }

    #[test]
    fn from_headers_merges_instances_and_commas() {
        let mut h = Headers::new();
        assert_eq!(PrivacyHeader::from_headers(&h).unwrap(), None);
        h.add(Header::new(HeaderName::Privacy, "header;user"));
        h.add(Header::new(HeaderName::Privacy, "id, critical"));
        let p = PrivacyHeader::from_headers(&h).unwrap().unwrap();
        assert_eq!(p.to_string(), "header;user;id;critical");
        assert!(p.is_critical());
    }

    #[test]
    fn from_headers_rejects_malformed_instance_and_split_none() {
        let mut h = Headers::new();
        h.add(Header::new(HeaderName::Privacy, "id"));
        h.add(Header::new(HeaderName::Privacy, "bad token"));
        assert!(PrivacyHeader::from_headers(&h).is_err());

        let mut h = Headers::new();
        h.add(Header::new(HeaderName::Privacy, "none"));
        h.add(Header::new(HeaderName::Privacy, "id"));
        assert!(PrivacyHeader::from_headers(&h).is_err());
    }

    #[test]
    fn parse_rejects_bad_input() {
        for bad in [
            "",
            ";",
            "id;",
            "none;id",
            "id;none",
            "bad token",
            "id\r\nX: y",
        ] {
            assert!(bad.parse::<PrivacyHeader>().is_err(), "{bad:?}");
        }
        let many = (0..=MAX_PRIVACY_VALUES)
            .map(|i| format!("x{i}"))
            .collect::<Vec<_>>()
            .join(";");
        assert_eq!(many.parse::<PrivacyHeader>(), Err(PrivacyError::TooMany));
    }

    fn request() -> SipRequest {
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n\
            From: \"Alice Smith\" <sip:alice@example.org>;tag=abc\r\n\
            To: <sip:bob@example.com>\r\n\
            Call-ID: c1\r\n\
            CSeq: 1 INVITE\r\n\
            Max-Forwards: 70\r\n\
            Subject: secret\r\n\
            User-Agent: X/1\r\n\
            Organization: Org\r\n\
            P-Asserted-Identity: <sip:alice@example.org>\r\n\
            Privacy: header;user;id\r\n\
            Content-Length: 0\r\n\r\n";
        match SipMessage::parse(raw.as_bytes()).unwrap() {
            SipMessage::Request(r) => r,
            SipMessage::Response(_) => unreachable!(),
        }
    }

    #[test]
    fn apply_header_user_id_untrusted() {
        let mut req = request();
        let p = PrivacyHeader::from_headers(&req.headers).unwrap().unwrap();
        let out = apply_privacy(&mut req, &p, PrivacyCapabilities::default(), false).unwrap();
        assert!(out.needs_topology_hiding);
        assert!(out.from_anonymized);
        assert!(out.privacy_header_removed);
        for n in [
            HeaderName::Subject,
            HeaderName::UserAgent,
            HeaderName::Organization,
            HeaderName::PAssertedIdentity,
            HeaderName::Privacy,
        ] {
            assert!(!req.headers.contains(&n), "{n}");
        }
        let from = req.headers.from_parsed().unwrap();
        assert_eq!(from.uri.to_string(), ANONYMOUS_URI);
        assert_eq!(from.display_name.as_deref(), Some(ANONYMOUS_DISPLAY));
        assert_eq!(from.tag.as_deref(), Some("abc"));
        assert!(req.headers.contains(&HeaderName::To));
    }

    #[test]
    fn id_toward_trusted_keeps_pai_and_privacy() {
        let mut req = request();
        let p: PrivacyHeader = "id".parse().unwrap();
        let out = apply_privacy(&mut req, &p, PrivacyCapabilities::default(), true).unwrap();
        assert!(req.headers.contains(&HeaderName::PAssertedIdentity));
        assert!(req.headers.contains(&HeaderName::Privacy));
        assert!(!out.privacy_header_removed);
    }

    #[test]
    fn session_critical_cannot_satisfy_and_leaves_request() {
        let mut req = request();
        let before = req.to_bytes();
        let p: PrivacyHeader = "session;user;critical".parse().unwrap();
        let err = apply_privacy(&mut req, &p, PrivacyCapabilities::default(), false).unwrap_err();
        assert_eq!(
            err,
            PrivacyError::CannotSatisfy {
                unsatisfied: vec![PrivacyValue::Session]
            }
        );
        assert_eq!(req.to_bytes(), before);
    }

    #[test]
    fn session_without_critical_reported_unsatisfied() {
        let mut req = request();
        let p: PrivacyHeader = "session".parse().unwrap();
        let out = apply_privacy(&mut req, &p, PrivacyCapabilities::default(), false).unwrap();
        assert_eq!(out.unsatisfied, vec![PrivacyValue::Session]);
        assert!(req.headers.contains(&HeaderName::Privacy));
    }

    #[test]
    fn none_does_nothing() {
        let mut req = request();
        let p: PrivacyHeader = "none".parse().unwrap();
        let out = apply_privacy(&mut req, &p, PrivacyCapabilities::default(), false).unwrap();
        assert_eq!(out, PrivacyOutcome::default());
        assert!(req.headers.contains(&HeaderName::PAssertedIdentity));
    }

    #[test]
    fn sanitize_inbound_identity_untrusted_only() {
        let mut h = Headers::new();
        h.add(Header::new(HeaderName::PAssertedIdentity, "<sip:a@b>"));
        h.add(Header::new(HeaderName::PPreferredIdentity, "<sip:a@b>"));
        assert_eq!(sanitize_inbound_identity(&mut h, true), 0);
        assert_eq!(sanitize_inbound_identity(&mut h, false), 2);
        assert!(h.is_empty());
    }

    fn rpid_headers(values: &[&str]) -> Headers {
        let mut h = Headers::new();
        for v in values {
            h.add(Header::new(
                HeaderName::Custom("Remote-Party-ID".to_string()),
                *v,
            ));
        }
        h
    }

    #[test]
    fn rpid_params_stripped_from_pai() {
        let mut h = rpid_headers(&[
            "\"Alice\" <sip:+15550100@gw.example.com;user=phone>;party=calling;screen=yes;privacy=off",
        ]);
        assert_eq!(rpid_to_pai(&mut h), 1);
        let pai: Vec<&str> = h
            .get_all(&HeaderName::PAssertedIdentity)
            .map(|x| x.value.as_str())
            .collect();
        assert_eq!(pai, ["\"Alice\" <sip:+15550100@gw.example.com;user=phone>"]);
        assert!(!h.contains(&HeaderName::Privacy));
    }

    #[test]
    fn rpid_privacy_full_adds_privacy_id_and_one_per_scheme() {
        let mut h = rpid_headers(&[
            "<sip:a@example.com>;privacy=full;screen=yes, <sip:b@example.com>;screen=yes",
            "<tel:+15550100>;screen=yes",
        ]);
        h.add(Header::new(HeaderName::Privacy, "header"));
        assert_eq!(rpid_to_pai(&mut h), 2);
        assert_eq!(h.get_value(&HeaderName::Privacy), Some("header;id;user"));
        let pai: Vec<&str> = h
            .get_all(&HeaderName::PAssertedIdentity)
            .map(|x| x.value.as_str())
            .collect();
        assert_eq!(pai, ["<sip:a@example.com>", "<tel:+15550100>"]);
    }

    #[test]
    fn unscreened_rpid_not_asserted() {
        let mut h = rpid_headers(&[
            "<sip:a@example.com>;screen=no;privacy=full",
            "<sip:b@example.com>",
        ]);
        assert_eq!(rpid_to_pai(&mut h), 0);
        assert!(!h.contains(&HeaderName::PAssertedIdentity));
        assert!(!h.contains(&HeaderName::Privacy));
        // A screened element after an unscreened one is still used.
        let mut h = rpid_headers(&[
            "<sip:a@example.com>;screen=no",
            "<sip:b@example.com>;screen=yes;privacy=uri",
        ]);
        assert_eq!(rpid_to_pai(&mut h), 1);
        assert_eq!(
            h.get_value(&HeaderName::PAssertedIdentity),
            Some("<sip:b@example.com>")
        );
        assert_eq!(h.get_value(&HeaderName::Privacy), Some("id"));
    }

    #[test]
    fn malformed_rpid_adds_nothing() {
        let mut h = rpid_headers(&["garbage", "<http://example.com>", "\"x\" <sip:"]);
        assert_eq!(rpid_to_pai(&mut h), 0);
        assert!(!h.contains(&HeaderName::PAssertedIdentity));
    }

    #[test]
    fn rpid_encoded_crlf_cannot_inject() {
        let mut h = rpid_headers(&["\"A\" <sip:a%0d%0aX-Evil:1@example.com>"]);
        rpid_to_pai(&mut h);
        for v in h.get_all(&HeaderName::PAssertedIdentity) {
            assert!(!v.value.contains('\r') && !v.value.contains('\n'));
        }
        let mut h = rpid_headers(&["\"A\u{7}\" <sip:a@example.com>"]);
        assert_eq!(rpid_to_pai(&mut h), 0);
    }
}
