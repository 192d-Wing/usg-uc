//! SIP headers per RFC 3261.
//!
//! This module provides header name constants, header parsing, and header
//! collection management for SIP messages per RFC 3261 Section 20.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All loops have fixed upper bounds (collection sizes)
//! - Functions include debug assertions for invariant checking
//! - No recursion is used

use crate::error::{SipError, SipResult, truncate_for_log};
use crate::header_params::{CSeqHeader, MaxForwardsHeader, NameAddr, ViaHeader};
use crate::list::{split_list, split_list_bounded};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// Common SIP header names per RFC 3261 Section 20 and extensions.
///
/// Equality and hashing are case-insensitive and normalise `Custom`
/// spellings of known names (RFC 3261 §7.3.1: field names are
/// case-insensitive), so `Custom("min-expires") == MinExpires`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HeaderName {
    // Request routing (RFC 3261 Section 20)
    /// Via header (Section 20.42).
    Via,
    /// Route header (Section 20.34).
    Route,
    /// Record-Route header (Section 20.30).
    RecordRoute,
    /// Max-Forwards header (Section 20.22).
    MaxForwards,
    /// Path header (RFC 3327).
    Path,

    // Transaction identification (RFC 3261 Section 20)
    /// Call-ID header (Section 20.8).
    CallId,
    /// `CSeq` header (Section 20.16).
    CSeq,
    /// From header (Section 20.20).
    From,
    /// To header (Section 20.39).
    To,

    // Message body (RFC 3261 Section 20)
    /// Content-Type header (Section 20.15).
    ContentType,
    /// Content-Length header (Section 20.14).
    ContentLength,
    /// Content-Encoding header (Section 20.12).
    ContentEncoding,
    /// Content-Disposition header (Section 20.11).
    ContentDisposition,
    /// Content-Language header (Section 20.13).
    ContentLanguage,

    // Session/dialog (RFC 3261 Section 20)
    /// Contact header (Section 20.10).
    Contact,
    /// Expires header (Section 20.19).
    Expires,
    /// Min-Expires header (Section 20.23).
    MinExpires,

    // Authentication (RFC 3261 Section 20)
    /// WWW-Authenticate header (Section 20.44).
    WwwAuthenticate,
    /// Authorization header (Section 20.7).
    Authorization,
    /// Proxy-Authenticate header (Section 20.27).
    ProxyAuthenticate,
    /// Proxy-Authorization header (Section 20.28).
    ProxyAuthorization,

    // Features (RFC 3261 Section 20)
    /// Allow header (Section 20.5).
    Allow,
    /// Supported header (Section 20.37).
    Supported,
    /// Require header (Section 20.32).
    Require,
    /// Proxy-Require header (Section 20.29).
    ProxyRequire,
    /// Unsupported header (Section 20.40).
    Unsupported,

    // Information (RFC 3261 Section 20)
    /// Accept header (Section 20.1).
    Accept,
    /// Accept-Encoding header (Section 20.2).
    AcceptEncoding,
    /// Accept-Language header (Section 20.3).
    AcceptLanguage,
    /// Alert-Info header (Section 20.4).
    AlertInfo,
    /// Call-Info header (Section 20.9).
    CallInfo,
    /// Date header (Section 20.17).
    Date,
    /// Error-Info header (Section 20.18).
    ErrorInfo,
    /// In-Reply-To header (Section 20.21).
    InReplyTo,
    /// MIME-Version header (Section 20.24).
    MimeVersion,
    /// Organization header (Section 20.25).
    Organization,
    /// Priority header (Section 20.26).
    Priority,
    /// Reply-To header (Section 20.31).
    ReplyTo,
    /// Retry-After header (Section 20.33).
    RetryAfter,
    /// Server header (Section 20.35).
    Server,
    /// Subject header (Section 20.36).
    Subject,
    /// Timestamp header (Section 20.38).
    Timestamp,
    /// User-Agent header (Section 20.41).
    UserAgent,
    /// Warning header (Section 20.43).
    Warning,

    // Event framework (RFC 6665)
    /// Event header.
    Event,
    /// Subscription-State header.
    SubscriptionState,
    /// Allow-Events header.
    AllowEvents,

    // Session timers (RFC 4028)
    /// Session-Expires header.
    SessionExpires,
    /// Min-SE header.
    MinSe,

    // STIR/SHAKEN (RFC 8224)
    /// Identity header.
    Identity,

    // P-headers (RFC 3325, RFC 3455)
    /// P-Asserted-Identity header.
    PAssertedIdentity,
    /// P-Preferred-Identity header.
    PPreferredIdentity,

    // Privacy (RFC 3323)
    /// Privacy header (RFC 3323 §4.2).
    Privacy,

    // Reason header (RFC 3326)
    /// Reason header.
    Reason,

    // Refer (RFC 3515)
    /// Refer-To header.
    ReferTo,
    /// Referred-By header.
    ReferredBy,

    // Replaces (RFC 3891)
    /// Replaces header.
    Replaces,

    // Caller preferences (RFC 3841)
    /// Accept-Contact header.
    AcceptContact,
    /// Reject-Contact header.
    RejectContact,
    /// Request-Disposition header.
    RequestDisposition,

    // Custom/extension header.
    /// Custom header.
    Custom(String),
}

impl HeaderName {
    /// Returns the canonical header name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Via => "Via",
            Self::Route => "Route",
            Self::RecordRoute => "Record-Route",
            Self::MaxForwards => "Max-Forwards",
            Self::Path => "Path",
            Self::CallId => "Call-ID",
            Self::CSeq => "CSeq",
            Self::From => "From",
            Self::To => "To",
            Self::ContentType => "Content-Type",
            Self::ContentLength => "Content-Length",
            Self::ContentEncoding => "Content-Encoding",
            Self::ContentDisposition => "Content-Disposition",
            Self::ContentLanguage => "Content-Language",
            Self::Contact => "Contact",
            Self::Expires => "Expires",
            Self::MinExpires => "Min-Expires",
            Self::WwwAuthenticate => "WWW-Authenticate",
            Self::Authorization => "Authorization",
            Self::ProxyAuthenticate => "Proxy-Authenticate",
            Self::ProxyAuthorization => "Proxy-Authorization",
            Self::Allow => "Allow",
            Self::Supported => "Supported",
            Self::Require => "Require",
            Self::ProxyRequire => "Proxy-Require",
            Self::Unsupported => "Unsupported",
            Self::Accept => "Accept",
            Self::AcceptEncoding => "Accept-Encoding",
            Self::AcceptLanguage => "Accept-Language",
            Self::AlertInfo => "Alert-Info",
            Self::CallInfo => "Call-Info",
            Self::Date => "Date",
            Self::ErrorInfo => "Error-Info",
            Self::InReplyTo => "In-Reply-To",
            Self::MimeVersion => "MIME-Version",
            Self::Organization => "Organization",
            Self::Priority => "Priority",
            Self::ReplyTo => "Reply-To",
            Self::RetryAfter => "Retry-After",
            Self::Server => "Server",
            Self::Subject => "Subject",
            Self::Timestamp => "Timestamp",
            Self::UserAgent => "User-Agent",
            Self::Warning => "Warning",
            Self::Event => "Event",
            Self::SubscriptionState => "Subscription-State",
            Self::AllowEvents => "Allow-Events",
            Self::SessionExpires => "Session-Expires",
            Self::MinSe => "Min-SE",
            Self::Identity => "Identity",
            Self::PAssertedIdentity => "P-Asserted-Identity",
            Self::PPreferredIdentity => "P-Preferred-Identity",
            Self::Privacy => "Privacy",
            Self::Reason => "Reason",
            Self::ReferTo => "Refer-To",
            Self::ReferredBy => "Referred-By",
            Self::Replaces => "Replaces",
            Self::AcceptContact => "Accept-Contact",
            Self::RejectContact => "Reject-Contact",
            Self::RequestDisposition => "Request-Disposition",
            Self::Custom(name) => name,
        }
    }

    /// Returns the compact form if available (RFC 3261 Section 7.3.3).
    #[must_use]
    pub fn compact_form(&self) -> Option<char> {
        match self {
            Self::Via => Some('v'),
            Self::From => Some('f'),
            Self::To => Some('t'),
            Self::CallId => Some('i'),
            Self::Contact => Some('m'),
            Self::ContentType => Some('c'),
            Self::ContentLength => Some('l'),
            Self::Supported => Some('k'),
            Self::Subject => Some('s'),
            Self::ReferTo => Some('r'),
            Self::AllowEvents => Some('u'),
            Self::Event => Some('o'),
            // RFC 3261 §7.3.3 / RFC 4028 / RFC 3892 / RFC 8224 / RFC 3841
            Self::ContentEncoding => Some('e'),
            Self::SessionExpires => Some('x'),
            Self::ReferredBy => Some('b'),
            Self::Identity => Some('y'),
            Self::AcceptContact => Some('a'),
            Self::RejectContact => Some('j'),
            Self::RequestDisposition => Some('d'),
            _ => None,
        }
    }

    /// Returns true if this header may appear multiple times in a message.
    #[must_use]
    pub fn allows_multiple(&self) -> bool {
        matches!(
            self,
            Self::Via
                | Self::Route
                | Self::RecordRoute
                | Self::Path
                | Self::Contact
                | Self::Accept
                | Self::AcceptEncoding
                | Self::AcceptLanguage
                | Self::Allow
                | Self::Supported
                | Self::Require
                | Self::ProxyRequire
                | Self::Unsupported
                | Self::Warning
                | Self::AllowEvents
        )
    }
}

impl PartialEq for HeaderName {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Fast path: two known names compare by discriminant.
            (Self::Custom(_), _) | (_, Self::Custom(_)) => {
                self.as_str().eq_ignore_ascii_case(other.as_str())
            }
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

impl Eq for HeaderName {}

impl Hash for HeaderName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Must agree with `eq`: hash the ASCII-lowercased canonical name.
        let name = self.as_str();
        for b in name.bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
        state.write_usize(name.len());
    }
}

/// Returns true if `b` is a `token` character (RFC 3261 §25.1).
#[must_use]
pub(crate) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

/// Validates a header field value: no CTL except HTAB (RFC 3261 §25.1
/// `TEXT-UTF8`, LWS). Rejecting CR/LF/NUL prevents header injection into
/// re-serialized output and logs.
///
/// NIST 800-53 Rev5: SI-10 (Information Input Validation).
pub(crate) fn validate_header_value(name: &str, value: &str) -> SipResult<()> {
    if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7F) {
        return Err(SipError::InvalidHeader {
            name: truncate_for_log(name),
            reason: "control character in header value".to_string(),
        });
    }
    Ok(())
}

impl HeaderName {
    /// Parses a header field name, normalising known names (including
    /// compact forms, RFC 3261 §7.3.3) to their typed variant.
    ///
    /// # Errors
    ///
    /// Returns [`SipError::InvalidHeader`] if the name is empty or is not a
    /// `token` (RFC 3261 §25.1).
    pub fn from_name(s: &str) -> SipResult<Self> {
        // NIST 800-53 Rev5: SI-10 - header names must be tokens.
        if s.is_empty() || !s.bytes().all(is_token_byte) {
            return Err(SipError::InvalidHeader {
                name: truncate_for_log(s),
                reason: "header name is not a token".to_string(),
            });
        }

        Ok(Self::lookup(s))
    }

    /// Maps an already-validated token to its variant (no token check).
    pub(crate) fn lookup(s: &str) -> Self {
        // Handle compact forms (RFC 3261 Section 7.3.3)
        if s.len() == 1 {
            match s.as_bytes()[0].to_ascii_lowercase() {
                b'v' => return Self::Via,
                b'f' => return Self::From,
                b't' => return Self::To,
                b'i' => return Self::CallId,
                b'm' => return Self::Contact,
                b'c' => return Self::ContentType,
                b'l' => return Self::ContentLength,
                b'k' => return Self::Supported,
                b's' => return Self::Subject,
                b'r' => return Self::ReferTo,
                b'u' => return Self::AllowEvents,
                b'o' => return Self::Event,
                b'e' => return Self::ContentEncoding,
                b'x' => return Self::SessionExpires,
                b'b' => return Self::ReferredBy,
                b'y' => return Self::Identity,
                b'a' => return Self::AcceptContact,
                b'j' => return Self::RejectContact,
                b'd' => return Self::RequestDisposition,
                _ => {}
            }
        }

        // Case-insensitive lookup via static table (zero allocation)
        for &(name, ref variant) in HEADER_NAME_TABLE {
            if s.eq_ignore_ascii_case(name) {
                return variant.clone();
            }
        }
        Self::Custom(s.to_string())
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Static lookup table mapping lowercase header names to `HeaderName` variants.
/// Used by `FromStr` to avoid heap allocation during case-insensitive matching.
const HEADER_NAME_TABLE: &[(&str, HeaderName)] = &[
    ("via", HeaderName::Via),
    ("route", HeaderName::Route),
    ("record-route", HeaderName::RecordRoute),
    ("max-forwards", HeaderName::MaxForwards),
    ("path", HeaderName::Path),
    ("call-id", HeaderName::CallId),
    ("cseq", HeaderName::CSeq),
    ("from", HeaderName::From),
    ("to", HeaderName::To),
    ("content-type", HeaderName::ContentType),
    ("content-length", HeaderName::ContentLength),
    ("content-encoding", HeaderName::ContentEncoding),
    ("content-disposition", HeaderName::ContentDisposition),
    ("content-language", HeaderName::ContentLanguage),
    ("contact", HeaderName::Contact),
    ("expires", HeaderName::Expires),
    ("min-expires", HeaderName::MinExpires),
    ("www-authenticate", HeaderName::WwwAuthenticate),
    ("authorization", HeaderName::Authorization),
    ("proxy-authenticate", HeaderName::ProxyAuthenticate),
    ("proxy-authorization", HeaderName::ProxyAuthorization),
    ("allow", HeaderName::Allow),
    ("supported", HeaderName::Supported),
    ("require", HeaderName::Require),
    ("proxy-require", HeaderName::ProxyRequire),
    ("unsupported", HeaderName::Unsupported),
    ("accept", HeaderName::Accept),
    ("accept-encoding", HeaderName::AcceptEncoding),
    ("accept-language", HeaderName::AcceptLanguage),
    ("alert-info", HeaderName::AlertInfo),
    ("call-info", HeaderName::CallInfo),
    ("date", HeaderName::Date),
    ("error-info", HeaderName::ErrorInfo),
    ("in-reply-to", HeaderName::InReplyTo),
    ("mime-version", HeaderName::MimeVersion),
    ("organization", HeaderName::Organization),
    ("priority", HeaderName::Priority),
    ("reply-to", HeaderName::ReplyTo),
    ("retry-after", HeaderName::RetryAfter),
    ("server", HeaderName::Server),
    ("subject", HeaderName::Subject),
    ("timestamp", HeaderName::Timestamp),
    ("user-agent", HeaderName::UserAgent),
    ("warning", HeaderName::Warning),
    ("event", HeaderName::Event),
    ("subscription-state", HeaderName::SubscriptionState),
    ("allow-events", HeaderName::AllowEvents),
    ("session-expires", HeaderName::SessionExpires),
    ("min-se", HeaderName::MinSe),
    ("identity", HeaderName::Identity),
    ("p-asserted-identity", HeaderName::PAssertedIdentity),
    ("p-preferred-identity", HeaderName::PPreferredIdentity),
    ("privacy", HeaderName::Privacy),
    ("reason", HeaderName::Reason),
    ("refer-to", HeaderName::ReferTo),
    ("referred-by", HeaderName::ReferredBy),
    ("replaces", HeaderName::Replaces),
    ("accept-contact", HeaderName::AcceptContact),
    ("reject-contact", HeaderName::RejectContact),
    ("request-disposition", HeaderName::RequestDisposition),
];

impl FromStr for HeaderName {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        Self::from_name(s)
    }
}

/// A single SIP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Header name.
    pub name: HeaderName,
    /// Header value.
    pub value: String,
}

impl Header {
    /// Creates a new header.
    #[must_use]
    pub fn new(name: HeaderName, value: impl Into<String>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }

    /// Parses a header from a line.
    ///
    /// Format: `Header-Name: value`
    ///
    /// # Errors
    ///
    /// Returns an error if the header line is malformed (missing colon separator).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(line: &str) -> SipResult<Self> {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| SipError::InvalidHeader {
                name: "unknown".to_string(),
                reason: "missing colon separator".to_string(),
            })?;

        // RFC 3261 §25.1: HCOLON = *( SP / HTAB ) ":" SWS
        let name = name.trim_end_matches([' ', '\t']);
        let name = HeaderName::from_name(name)?;
        let value = value.trim_matches([' ', '\t']);
        // NIST 800-53 Rev5: SI-10 - no CTLs (except HTAB) in values.
        validate_header_value(name.as_str(), value)?;

        Ok(Self {
            name,
            value: value.to_string(),
        })
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

/// Collection of SIP headers with structured parsing support.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    headers: Vec<Header>,
}

impl Headers {
    /// Creates an empty headers collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a header.
    pub fn add(&mut self, header: Header) {
        self.headers.push(header);
    }

    /// Sets a header (replaces existing).
    ///
    /// The first occurrence is replaced in place and any further
    /// occurrences are removed, so header order is preserved. If the
    /// header is absent it is appended.
    pub fn set(&mut self, name: HeaderName, value: impl Into<String>) {
        let value = value.into();
        match self.headers.iter().position(|h| h.name == name) {
            Some(idx) => {
                self.headers[idx].value = value;
                let mut seen = 0usize;
                self.headers.retain(|h| {
                    if h.name == name {
                        seen += 1;
                        seen == 1
                    } else {
                        true
                    }
                });
            }
            None => self.add(Header::new(name, value)),
        }
    }

    /// Inserts a header at `idx` (clamped to the current length).
    pub fn insert(&mut self, idx: usize, header: Header) {
        let idx = idx.min(self.headers.len());
        self.headers.insert(idx, header);
    }

    /// Inserts a header before the first header with the same name, or at
    /// index 0 if there is none. O(n).
    pub fn prepend(&mut self, name: HeaderName, value: impl Into<String>) {
        let idx = self
            .headers
            .iter()
            .position(|h| h.name == name)
            .unwrap_or(0);
        self.headers.insert(idx, Header::new(name, value));
    }

    /// Removes and returns the first header with the given name. O(n).
    pub fn remove_first(&mut self, name: &HeaderName) -> Option<Header> {
        let idx = self.headers.iter().position(|h| &h.name == name)?;
        Some(self.headers.remove(idx))
    }

    /// Returns the index of the first header with the given name.
    #[must_use]
    pub fn position(&self, name: &HeaderName) -> Option<usize> {
        self.headers.iter().position(|h| &h.name == name)
    }

    /// Returns the number of headers with the given name.
    #[must_use]
    pub fn count(&self, name: &HeaderName) -> usize {
        self.headers.iter().filter(|h| &h.name == name).count()
    }

    /// Gets the first header with the given name.
    #[must_use]
    pub fn get(&self, name: &HeaderName) -> Option<&Header> {
        self.headers.iter().find(|h| &h.name == name)
    }

    /// Gets all headers with the given name.
    ///
    /// Returns an iterator to avoid allocating a `Vec` on every call.
    pub fn get_all<'a>(&'a self, name: &'a HeaderName) -> impl Iterator<Item = &'a Header> + 'a {
        self.headers.iter().filter(move |h| h.name == *name)
    }

    /// Gets all headers with the given name, mutably, in message order.
    ///
    /// POAM: POA&M-152 - lets callers apply an edit to every instance.
    pub fn get_all_mut<'a>(
        &'a mut self,
        name: &'a HeaderName,
    ) -> impl Iterator<Item = &'a mut Header> + 'a {
        self.headers.iter_mut().filter(move |h| h.name == *name)
    }

    /// Keeps only the headers for which `f` returns true (order preserved).
    pub fn retain(&mut self, f: impl FnMut(&Header) -> bool) {
        self.headers.retain(f);
    }

    /// Renames every instance of `from` to `to` in place (order preserved).
    pub fn rename_all(&mut self, from: &HeaderName, to: &HeaderName) {
        for h in self.headers.iter_mut().filter(|h| h.name == *from) {
            h.name = to.clone();
        }
    }

    /// Replaces every instance of `name` with one header per value in
    /// `values`, positioned where the first original instance was (or
    /// appended if there was none). An empty `values` removes the header.
    ///
    /// POAM: POA&M-151 - per-element rewrite of comma-folded lists.
    pub fn replace_instances(&mut self, name: &HeaderName, values: Vec<String>) {
        let idx = self.position(name).unwrap_or(self.headers.len());
        self.remove(name);
        let idx = idx.min(self.headers.len());
        self.headers.splice(
            idx..idx,
            values.into_iter().map(|v| Header::new(name.clone(), v)),
        );
    }

    /// Gets the first header value with the given name.
    #[must_use]
    pub fn get_value(&self, name: &HeaderName) -> Option<&str> {
        self.get(name).map(|h| h.value.as_str())
    }

    /// Removes all headers with the given name.
    pub fn remove(&mut self, name: &HeaderName) {
        self.headers.retain(|h| &h.name != name);
    }

    /// Returns true if the header exists.
    #[must_use]
    pub fn contains(&self, name: &HeaderName) -> bool {
        self.headers.iter().any(|h| &h.name == name)
    }

    /// Returns the number of headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns true if there are no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Returns an iterator over the headers.
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.headers.iter()
    }

    // ==================== Structured Header Access ====================

    /// Returns the Content-Length if present and well-formed
    /// (`1*DIGIT`, at most 10 digits; RFC 3261 §20.14).
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.get_value(&HeaderName::ContentLength)
            .and_then(|v| parse_content_length(v).ok())
    }

    /// Returns the Call-ID if present.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.get_value(&HeaderName::CallId)
    }

    /// Returns the `CSeq` value as a raw string if present.
    #[must_use]
    pub fn cseq(&self) -> Option<&str> {
        self.get_value(&HeaderName::CSeq)
    }

    /// Returns the `CSeq` as a structured type.
    #[must_use]
    pub fn cseq_parsed(&self) -> Option<CSeqHeader> {
        self.get_value(&HeaderName::CSeq)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the first Via header as a structured type.
    ///
    /// For a combined value (`Via: a, b`) this is the first element.
    #[must_use]
    pub fn via_parsed(&self) -> Option<ViaHeader> {
        let value = self.get_value(&HeaderName::Via)?;
        let first = split_list(value).next()?.ok()?;
        first.parse().ok()
    }

    /// Returns all Via headers as structured types.
    ///
    /// Combined field values (`Via: a, b`, RFC 3261 §7.3.1) yield one
    /// entry per element. Elements that fail to parse are skipped.
    #[must_use]
    pub fn via_all_parsed(&self) -> Vec<ViaHeader> {
        self.list_values(&HeaderName::Via)
            .iter()
            .filter_map(|v| v.parse().ok())
            .collect()
    }

    /// Returns every list element across all fields with this name,
    /// splitting combined comma-separated values (RFC 3261 §7.3.1).
    ///
    /// A field whose value cannot be split (unterminated quote or angle
    /// bracket) is returned whole so that downstream parsing rejects it.
    ///
    /// NIST 800-53 Rev5: SC-5 - at most [`crate::MAX_LIST_ELEMENTS`] elements
    /// are returned in total (same cap as routing/proxy); a field that
    /// exceeds the cap on its own is returned whole so it fails to parse.
    fn list_values(&self, name: &HeaderName) -> Vec<String> {
        let mut out = Vec::new();
        for h in self.get_all(name) {
            if out.len() >= crate::MAX_LIST_ELEMENTS {
                break;
            }
            match split_list_bounded(&h.value, crate::MAX_LIST_ELEMENTS) {
                Ok(parts) => out.extend(parts.into_iter().map(str::to_string)),
                Err(_) => out.push(h.value.clone()),
            }
        }
        out.truncate(crate::MAX_LIST_ELEMENTS);
        out
    }

    /// Returns the From header as a structured type.
    #[must_use]
    pub fn from_parsed(&self) -> Option<NameAddr> {
        self.get_value(&HeaderName::From)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the To header as a structured type.
    #[must_use]
    pub fn to_parsed(&self) -> Option<NameAddr> {
        self.get_value(&HeaderName::To).and_then(|v| v.parse().ok())
    }

    /// Returns the Max-Forwards header as a structured type.
    #[must_use]
    pub fn max_forwards(&self) -> Option<MaxForwardsHeader> {
        self.get_value(&HeaderName::MaxForwards)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the Expires header value if present.
    #[must_use]
    pub fn expires(&self) -> Option<u32> {
        self.get_value(&HeaderName::Expires)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the Contact header as a structured type.
    #[must_use]
    pub fn contact_parsed(&self) -> Option<NameAddr> {
        self.get_value(&HeaderName::Contact)
            .and_then(|v| v.parse().ok())
    }

    /// Returns the From header tag parameter.
    #[must_use]
    pub fn from_tag(&self) -> Option<String> {
        self.from_parsed().and_then(|n| n.tag)
    }

    /// Returns the To header tag parameter.
    #[must_use]
    pub fn to_tag(&self) -> Option<String> {
        self.to_parsed().and_then(|n| n.tag)
    }

    /// Returns the Via branch parameter from the topmost Via header.
    #[must_use]
    pub fn via_branch(&self) -> Option<String> {
        self.via_parsed().and_then(|v| v.branch)
    }

    // ==================== Route Header Access ====================

    /// Returns all Route header values.
    #[must_use]
    pub fn route_values(&self) -> Vec<String> {
        self.list_values(&HeaderName::Route)
    }

    /// Returns all Record-Route header values.
    #[must_use]
    pub fn record_route_values(&self) -> Vec<String> {
        self.list_values(&HeaderName::RecordRoute)
    }

    /// Adds a Route header.
    pub fn add_route(&mut self, value: impl Into<String>) {
        self.add(Header::new(HeaderName::Route, value));
    }

    /// Adds a Record-Route header.
    pub fn add_record_route(&mut self, value: impl Into<String>) {
        self.add(Header::new(HeaderName::RecordRoute, value));
    }

    /// Prepends a Route header (at the beginning of Route headers).
    pub fn prepend_route(&mut self, value: impl Into<String>) {
        let value = value.into();
        // Find position of first Route header or insert at beginning
        let pos = self
            .headers
            .iter()
            .position(|h| h.name == HeaderName::Route);
        let header = Header::new(HeaderName::Route, value);
        match pos {
            Some(idx) => self.headers.insert(idx, header),
            None => self.headers.push(header),
        }
    }

    /// Prepends a Record-Route header (for proxy insertion).
    pub fn prepend_record_route(&mut self, value: impl Into<String>) {
        let value = value.into();
        // Find position of first Record-Route header or insert after Via
        let pos = self
            .headers
            .iter()
            .position(|h| h.name == HeaderName::RecordRoute)
            .or_else(|| {
                // Insert after last Via header
                self.headers
                    .iter()
                    .rposition(|h| h.name == HeaderName::Via)
                    .map(|i| i + 1)
            });
        let header = Header::new(HeaderName::RecordRoute, value);
        match pos {
            Some(idx) => self.headers.insert(idx, header),
            None => self.headers.push(header),
        }
    }

    // ==================== Path Header Access (RFC 3327) ====================

    /// Returns all Path header values.
    ///
    /// Per RFC 3327, Path headers are used by proxies to record the route
    /// that a REGISTER request traversed. The registrar stores this path
    /// for later routing of requests to the registered contact.
    #[must_use]
    pub fn path_values(&self) -> Vec<String> {
        self.list_values(&HeaderName::Path)
    }

    /// Adds a Path header.
    pub fn add_path(&mut self, value: impl Into<String>) {
        self.add(Header::new(HeaderName::Path, value));
    }

    /// Prepends a Path header (for edge proxy insertion per RFC 3327).
    ///
    /// Per RFC 3327 Section 4.1, proxies MUST insert their URI at the
    /// beginning of the Path header list.
    pub fn prepend_path(&mut self, value: impl Into<String>) {
        let value = value.into();
        // Find position of first Path header or insert after Via
        let pos = self
            .headers
            .iter()
            .position(|h| h.name == HeaderName::Path)
            .or_else(|| {
                // Insert after last Via header
                self.headers
                    .iter()
                    .rposition(|h| h.name == HeaderName::Via)
                    .map(|i| i + 1)
            });
        let header = Header::new(HeaderName::Path, value);
        match pos {
            Some(idx) => self.headers.insert(idx, header),
            None => self.headers.push(header),
        }
    }

    // ==================== Mandatory Header Validation ====================

    /// Validates that all mandatory RFC 3261 headers are present for a request.
    ///
    /// RFC 3261 Section 8.1.1 requires: Via, To, From, Call-ID, `CSeq`, Max-Forwards
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - Iterates exactly 6 times (fixed required header count)
    ///
    /// # Errors
    ///
    /// Returns [`SipError::MissingHeader`] if any required header is absent.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate_request_headers(&self) -> SipResult<()> {
        // Power of 10 Rule 2: Fixed-size array ensures bounded iteration
        const REQUIRED_COUNT: usize = 6;
        let required = [
            HeaderName::Via,
            HeaderName::To,
            HeaderName::From,
            HeaderName::CallId,
            HeaderName::CSeq,
            HeaderName::MaxForwards,
        ];

        // Power of 10 Rule 5: Assert array size matches constant
        debug_assert_eq!(
            required.len(),
            REQUIRED_COUNT,
            "required headers count mismatch"
        );

        // Loop bound: exactly REQUIRED_COUNT iterations
        for name in &required {
            if !self.contains(name) {
                return Err(SipError::MissingHeader {
                    name: name.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates that all mandatory RFC 3261 headers are present for a response.
    ///
    /// RFC 3261 Section 8.1.1 requires: Via, To, From, Call-ID, `CSeq`
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - Iterates exactly 5 times (fixed required header count)
    ///
    /// # Errors
    ///
    /// Returns [`SipError::MissingHeader`] if any required header is absent.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate_response_headers(&self) -> SipResult<()> {
        // Power of 10 Rule 2: Fixed-size array ensures bounded iteration
        const REQUIRED_COUNT: usize = 5;
        let required = [
            HeaderName::Via,
            HeaderName::To,
            HeaderName::From,
            HeaderName::CallId,
            HeaderName::CSeq,
        ];

        // Power of 10 Rule 5: Assert array size matches constant
        debug_assert_eq!(
            required.len(),
            REQUIRED_COUNT,
            "required headers count mismatch"
        );

        // Loop bound: exactly REQUIRED_COUNT iterations
        for name in &required {
            if !self.contains(name) {
                return Err(SipError::MissingHeader {
                    name: name.to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Parses a Content-Length value strictly: `1*DIGIT`, at most 10 digits,
/// no sign or embedded whitespace (RFC 3261 §20.14, §25.1).
///
/// NIST 800-53 Rev5: SI-10 - strict framing prevents request smuggling.
///
/// # Errors
///
/// Returns [`SipError::InvalidContentLength`] on any malformed value.
pub(crate) fn parse_content_length(v: &str) -> SipResult<usize> {
    if v.is_empty() {
        return Err(SipError::InvalidContentLength { reason: "empty" });
    }
    if v.len() > 10 {
        return Err(SipError::InvalidContentLength {
            reason: "more than 10 digits",
        });
    }
    if !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SipError::InvalidContentLength {
            reason: "not 1*DIGIT",
        });
    }
    v.parse().map_err(|_| SipError::InvalidContentLength {
        reason: "out of range",
    })
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for header in &self.headers {
            writeln!(f, "{header}")?;
        }
        Ok(())
    }
}

impl IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.headers.into_iter()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.headers.iter()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::method::Method;

    #[test]
    fn test_header_name_from_str() {
        assert_eq!("Via".parse::<HeaderName>().unwrap(), HeaderName::Via);
        assert_eq!("via".parse::<HeaderName>().unwrap(), HeaderName::Via);
        assert_eq!("VIA".parse::<HeaderName>().unwrap(), HeaderName::Via);
    }

    #[test]
    fn test_header_name_compact() {
        assert_eq!("v".parse::<HeaderName>().unwrap(), HeaderName::Via);
        assert_eq!("f".parse::<HeaderName>().unwrap(), HeaderName::From);
        assert_eq!("t".parse::<HeaderName>().unwrap(), HeaderName::To);
        assert_eq!("i".parse::<HeaderName>().unwrap(), HeaderName::CallId);
        assert_eq!("s".parse::<HeaderName>().unwrap(), HeaderName::Subject);
        assert_eq!("o".parse::<HeaderName>().unwrap(), HeaderName::Event);
    }

    #[test]
    fn test_header_parse() {
        let header = Header::parse("Via: SIP/2.0/UDP example.com").unwrap();
        assert_eq!(header.name, HeaderName::Via);
        assert_eq!(header.value, "SIP/2.0/UDP example.com");
    }

    #[test]
    fn test_headers_collection() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        headers.add(Header::new(HeaderName::CallId, "abc123"));
        headers.add(Header::new(HeaderName::ContentLength, "0"));

        assert_eq!(headers.len(), 3);
        assert_eq!(headers.call_id(), Some("abc123"));
        assert_eq!(headers.content_length(), Some(0));
    }

    #[test]
    fn test_headers_multi() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "first"));
        headers.add(Header::new(HeaderName::Via, "second"));

        assert_eq!(headers.get_all(&HeaderName::Via).count(), 2);
    }

    #[test]
    fn test_header_display() {
        let header = Header::new(HeaderName::CallId, "abc123@host");
        assert_eq!(format!("{header}"), "Call-ID: abc123@host");
    }

    #[test]
    fn test_structured_via() {
        let mut headers = Headers::new();
        headers.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776",
        ));

        let via = headers.via_parsed().unwrap();
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.host, "pc33.example.com");
        assert_eq!(via.branch, Some("z9hG4bK776".to_string()));
    }

    #[test]
    fn test_structured_from_to() {
        let mut headers = Headers::new();
        headers.add(Header::new(
            HeaderName::From,
            "\"Alice\" <sip:alice@example.com>;tag=1234",
        ));
        headers.add(Header::new(HeaderName::To, "<sip:bob@example.com>"));

        let from = headers.from_parsed().unwrap();
        assert_eq!(from.display_name, Some("Alice".to_string()));
        assert_eq!(from.tag, Some("1234".to_string()));
        assert_eq!(headers.from_tag(), Some("1234".to_string()));

        let to = headers.to_parsed().unwrap();
        assert!(to.tag.is_none());
        assert!(headers.to_tag().is_none());
    }

    #[test]
    fn test_structured_cseq() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::CSeq, "1 INVITE"));

        let cseq = headers.cseq_parsed().unwrap();
        assert_eq!(cseq.sequence, 1);
        assert_eq!(cseq.method, Method::Invite);
    }

    #[test]
    fn test_structured_max_forwards() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::MaxForwards, "70"));

        let mf = headers.max_forwards().unwrap();
        assert_eq!(mf.value, 70);
    }

    #[test]
    fn test_validate_request_headers() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        headers.add(Header::new(HeaderName::To, "<sip:bob@example.com>"));
        headers.add(Header::new(HeaderName::From, "<sip:alice@example.com>"));
        headers.add(Header::new(HeaderName::CallId, "abc123"));
        headers.add(Header::new(HeaderName::CSeq, "1 INVITE"));
        headers.add(Header::new(HeaderName::MaxForwards, "70"));

        assert!(headers.validate_request_headers().is_ok());
    }

    #[test]
    fn test_validate_request_headers_missing() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        // Missing other required headers

        let result = headers.validate_request_headers();
        assert!(matches!(result, Err(SipError::MissingHeader { .. })));
    }

    #[test]
    fn test_new_headers() {
        assert_eq!(
            "User-Agent".parse::<HeaderName>().unwrap(),
            HeaderName::UserAgent
        );
        assert_eq!("Server".parse::<HeaderName>().unwrap(), HeaderName::Server);
        assert_eq!(
            "Priority".parse::<HeaderName>().unwrap(),
            HeaderName::Priority
        );
        assert_eq!("Reason".parse::<HeaderName>().unwrap(), HeaderName::Reason);
    }

    #[test]
    fn test_path_header() {
        // RFC 3327 Path header support
        assert_eq!("Path".parse::<HeaderName>().unwrap(), HeaderName::Path);
        assert_eq!("path".parse::<HeaderName>().unwrap(), HeaderName::Path);
        assert_eq!(HeaderName::Path.as_str(), "Path");
        assert!(HeaderName::Path.allows_multiple());
    }

    #[test]
    fn test_path_header_methods() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));

        // Add Path headers
        headers.add_path("<sip:edge.example.com;lr>");
        headers.add_path("<sip:proxy.example.com;lr>");

        let paths = headers.path_values();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "<sip:edge.example.com;lr>");
        assert_eq!(paths[1], "<sip:proxy.example.com;lr>");
    }

    #[test]
    fn test_prepend_path() {
        let mut headers = Headers::new();
        headers.add(Header::new(HeaderName::Via, "SIP/2.0/UDP example.com"));
        headers.add_path("<sip:proxy.example.com;lr>");

        // Prepend should insert at the beginning
        headers.prepend_path("<sip:edge.example.com;lr>");

        let paths = headers.path_values();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "<sip:edge.example.com;lr>");
        assert_eq!(paths[1], "<sip:proxy.example.com;lr>");
    }

    #[test]
    fn header_name_eq_hash_normalised() {
        use std::collections::HashSet;
        assert_eq!(
            HeaderName::Custom("min-expires".to_string()),
            HeaderName::MinExpires
        );
        assert_eq!(
            HeaderName::Custom("X-Foo".to_string()),
            HeaderName::Custom("x-foo".to_string())
        );
        assert_ne!(HeaderName::Via, HeaderName::Route);
        let mut set = HashSet::new();
        set.insert(HeaderName::MinExpires);
        assert!(set.contains(&HeaderName::Custom("MIN-EXPIRES".to_string())));
        set.insert(HeaderName::Custom("x-a".to_string()));
        assert!(set.contains(&HeaderName::Custom("X-A".to_string())));
    }

    #[test]
    fn header_name_from_name_validates_token() {
        assert!(HeaderName::from_name("Foo Bar").is_err());
        assert!(HeaderName::from_name("").is_err());
        assert!(HeaderName::from_name("X:Y").is_err());
        let c = HeaderName::from_name("X-Custom").unwrap();
        assert_eq!(c.as_str(), "X-Custom");
    }

    #[test]
    fn new_compact_forms() {
        for (c, n) in [
            ("e", HeaderName::ContentEncoding),
            ("x", HeaderName::SessionExpires),
            ("b", HeaderName::ReferredBy),
            ("y", HeaderName::Identity),
            ("a", HeaderName::AcceptContact),
            ("j", HeaderName::RejectContact),
            ("d", HeaderName::RequestDisposition),
        ] {
            let parsed: HeaderName = c.parse().unwrap();
            assert_eq!(parsed, n);
            assert_eq!(n.compact_form(), c.chars().next());
            let h = Header::parse(&format!("{c}: v")).unwrap();
            assert_eq!(h.to_string(), format!("{}: v", n.as_str()));
        }
    }

    #[test]
    fn header_parse_rejects_ctl() {
        assert!(Header::parse("X-A: a\0b").is_err());
        assert!(Header::parse("X-A: a\r\nInjected: 1").is_err());
        assert!(Header::parse("X-A: a\tb").is_ok());
    }

    #[test]
    fn set_preserves_order_and_dedups() {
        let mut h = Headers::new();
        h.add(Header::new(HeaderName::Via, "v"));
        h.add(Header::new(HeaderName::Expires, "1"));
        h.add(Header::new(HeaderName::CallId, "c"));
        h.add(Header::new(HeaderName::Expires, "2"));
        h.set(HeaderName::Expires, "9");
        let names: Vec<_> = h.iter().map(|x| x.name.as_str().to_string()).collect();
        assert_eq!(names, ["Via", "Expires", "Call-ID"]);
        assert_eq!(h.expires(), Some(9));
        h.set(HeaderName::Date, "d");
        assert_eq!(h.iter().last().unwrap().name, HeaderName::Date);
    }

    #[test]
    fn prepend_insert_remove_first_count() {
        let mut h = Headers::new();
        h.add(Header::new(HeaderName::CallId, "c"));
        h.add(Header::new(HeaderName::Via, "v1"));
        h.prepend(HeaderName::Via, "v0");
        let vals: Vec<_> = h.iter().map(|x| x.value.as_str()).collect();
        assert_eq!(vals, ["c", "v0", "v1"]);
        h.prepend(HeaderName::Route, "r");
        assert_eq!(h.iter().next().unwrap().value, "r");
        h.insert(100, Header::new(HeaderName::Date, "d"));
        assert_eq!(h.iter().last().unwrap().value, "d");
        assert_eq!(h.count(&HeaderName::Via), 2);
        assert_eq!(h.remove_first(&HeaderName::Via).unwrap().value, "v0");
        assert_eq!(h.count(&HeaderName::Via), 1);
        assert!(h.remove_first(&HeaderName::Path).is_none());
    }

    #[test]
    fn combined_via_split() {
        let mut h = Headers::new();
        h.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP a.example.com;branch=z9hG4bK1, SIP/2.0/TCP b.example.com;branch=z9hG4bK2",
        ));
        let vias = h.via_all_parsed();
        assert_eq!(vias.len(), 2);
        assert_eq!(vias[1].host, "b.example.com");
        assert_eq!(h.via_parsed().unwrap().host, "a.example.com");
    }

    #[test]
    fn via_all_parsed_bounded() {
        let one = "SIP/2.0/UDP a.example.com;branch=z9hG4bK1";
        // One field over the cap is returned whole and fails to parse.
        let mut h = Headers::new();
        let combined = vec![one; crate::MAX_LIST_ELEMENTS + 1].join(", ");
        h.add(Header::new(HeaderName::Via, combined));
        assert_eq!(h.via_all_parsed().len(), 0);
        // Many separate fields are capped in total.
        let mut h = Headers::new();
        for _ in 0..crate::MAX_LIST_ELEMENTS + 10 {
            h.add(Header::new(HeaderName::Via, one));
        }
        assert_eq!(h.via_all_parsed().len(), crate::MAX_LIST_ELEMENTS);
    }

    #[test]
    fn route_values_split_combined() {
        let mut h = Headers::new();
        h.add_route("<sip:a;lr>, <sip:b;lr>");
        h.add_route("<sip:c;lr>");
        assert_eq!(h.route_values(), ["<sip:a;lr>", "<sip:b;lr>", "<sip:c;lr>"]);
    }

    #[test]
    fn content_length_strict() {
        let mut h = Headers::new();
        h.add(Header::new(HeaderName::ContentLength, "+5"));
        assert_eq!(h.content_length(), None);
    }
}
