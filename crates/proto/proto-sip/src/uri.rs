//! SIP URI handling per RFC 3261.

use crate::error::{SipError, SipResult};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

/// SIP URI scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UriScheme {
    /// sip: (plaintext).
    Sip,
    /// sips: (secure/TLS).
    Sips,
}

impl UriScheme {
    /// Returns the scheme string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sip => "sip",
            Self::Sips => "sips",
        }
    }

    /// Returns true if this scheme requires TLS.
    #[must_use]
    pub fn requires_tls(&self) -> bool {
        matches!(self, Self::Sips)
    }
}

impl fmt::Display for UriScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for UriScheme {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        match s.to_lowercase().as_str() {
            "sip" => Ok(Self::Sip),
            "sips" => Ok(Self::Sips),
            _ => Err(SipError::InvalidUri {
                reason: format!("unknown scheme: {s}"),
            }),
        }
    }
}

/// SIP URI per RFC 3261.
///
/// Format: `sip:user@host:port;params?headers`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipUri {
    /// URI scheme (sip or sips).
    pub scheme: UriScheme,
    /// User part (optional).
    pub user: Option<String>,
    /// Password (optional, discouraged).
    pub password: Option<String>,
    /// Host (domain or IP).
    pub host: String,
    /// Port (optional).
    pub port: Option<u16>,
    /// URI parameters.
    pub params: Vec<(String, Option<String>)>,
    /// Headers (for Request-URI).
    pub headers: Vec<(String, String)>,
}

impl SipUri {
    /// Creates a new SIP URI.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            scheme: UriScheme::Sip,
            user: None,
            password: None,
            host: host.into(),
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Creates a new SIPS URI (secure).
    #[must_use]
    pub fn new_sips(host: impl Into<String>) -> Self {
        Self {
            scheme: UriScheme::Sips,
            user: None,
            password: None,
            host: host.into(),
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Sets the user part.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Sets the port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Adds a URI parameter.
    #[must_use]
    pub fn with_param(mut self, name: impl Into<String>, value: Option<String>) -> Self {
        self.params.push((name.into(), value));
        self
    }

    /// Gets a URI parameter value.
    #[must_use]
    pub fn get_param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.as_deref())
    }

    /// Returns true if the parameter exists (even without value).
    #[must_use]
    pub fn has_param(&self, name: &str) -> bool {
        self.params
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    /// Returns the transport parameter if set.
    #[must_use]
    pub fn transport(&self) -> Option<&str> {
        self.get_param("transport")
    }

    /// Returns the lr parameter (loose routing).
    #[must_use]
    pub fn is_loose_router(&self) -> bool {
        self.has_param("lr")
    }

    /// Returns the user parameter (e.g., "phone" or "ip") per RFC 3261 Section 19.1.1.
    #[must_use]
    pub fn user_param(&self) -> Option<&str> {
        self.get_param("user")
    }

    /// Returns true if this is a telephone URI (user=phone).
    #[must_use]
    pub fn is_phone(&self) -> bool {
        self.user_param()
            .is_some_and(|u| u.eq_ignore_ascii_case("phone"))
    }

    /// Returns the method parameter if set.
    #[must_use]
    pub fn method_param(&self) -> Option<&str> {
        self.get_param("method")
    }

    /// Returns the ttl parameter (for multicast) per RFC 3261 Section 19.1.1.
    #[must_use]
    pub fn ttl(&self) -> Option<u8> {
        self.get_param("ttl").and_then(|v| v.parse().ok())
    }

    /// Returns the maddr parameter (multicast address) per RFC 3261 Section 19.1.1.
    #[must_use]
    pub fn maddr(&self) -> Option<&str> {
        self.get_param("maddr")
    }

    /// Returns the effective port (default 5060 for sip, 5061 for sips).
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(match self.scheme {
            UriScheme::Sip => 5060,
            UriScheme::Sips => 5061,
        })
    }

    /// Returns the host:port string.
    #[must_use]
    pub fn host_port(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;

        if let Some(ref user) = self.user {
            write!(f, "{user}")?;
            if let Some(ref password) = self.password {
                write!(f, ":{password}")?;
            }
            write!(f, "@")?;
        }

        // Handle IPv6 addresses
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }

        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }

        for (name, value) in &self.params {
            write!(f, ";{name}")?;
            if let Some(v) = value {
                write!(f, "={v}")?;
            }
        }

        if !self.headers.is_empty() {
            write!(f, "?")?;
            for (i, (name, value)) in self.headers.iter().enumerate() {
                if i > 0 {
                    write!(f, "&")?;
                }
                write!(f, "{name}={value}")?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RFC 3261 §25.1 character classes.
//
// POAM: POA&M-150 - the URI parser is a single-pass scanner over the RFC 3261
// §25.1 ABNF. The previous splitter cut `;`/`?` before locating userinfo and
// took the first `@`, so `sip:victim;x=@evil.com` resolved to host `victim`.
// NIST 800-53 Rev5: SI-10 (Information Input Validation).
// ---------------------------------------------------------------------------

/// `unreserved = alphanum / mark` (RFC 3261 §25.1).
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
}

/// `user-unreserved = "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"`.
fn is_user_char(b: u8) -> bool {
    is_unreserved(b) || matches!(b, b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/')
}

/// `password = *( unreserved / escaped / "&" / "=" / "+" / "$" / "," )`.
fn is_password_char(b: u8) -> bool {
    is_unreserved(b) || matches!(b, b'&' | b'=' | b'+' | b'$' | b',')
}

/// `paramchar = param-unreserved / unreserved / escaped`,
/// `param-unreserved = "[" / "]" / "/" / ":" / "&" / "+" / "$"`.
fn is_param_char(b: u8) -> bool {
    is_unreserved(b) || matches!(b, b'[' | b']' | b'/' | b':' | b'&' | b'+' | b'$')
}

/// `hnv-unreserved = "[" / "]" / "/" / "?" / ":" / "+" / "$"`.
fn is_hnv_char(b: u8) -> bool {
    is_unreserved(b) || matches!(b, b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$')
}

fn invalid(reason: &str) -> SipError {
    SipError::InvalidUri {
        reason: reason.to_string(),
    }
}

/// Validates `s` as `*( allowed / escaped )` where `escaped = "%" HEXDIG HEXDIG`.
fn validate_escaped(s: &str, allowed: fn(u8) -> bool, what: &str) -> SipResult<()> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            let ok = b
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
            if !ok {
                return Err(invalid(&format!("bad %-escape in {what}")));
            }
            i += 3;
        } else if allowed(c) {
            i += 1;
        } else {
            return Err(invalid(&format!("illegal character in {what}")));
        }
    }
    Ok(())
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Decodes `%HH` escapes (RFC 3261 §19.1.2). Input must already have passed
/// [`validate_escaped`]; malformed escapes are kept verbatim. Decoded bytes
/// that are not UTF-8 are replaced (U+FFFD) - callers comparing identities
/// should use [`SipUri::equivalent`], which compares raw octets.
fn percent_decode(s: &str) -> Cow<'_, str> {
    if !s.contains('%') {
        return Cow::Borrowed(s);
    }
    match String::from_utf8(percent_decode_bytes(s)) {
        Ok(v) => Cow::Owned(v),
        Err(e) => Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

fn percent_decode_bytes(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = b.get(i + 1..i + 3)
            && h.iter().all(u8::is_ascii_hexdigit)
        {
            out.push(hex_val(h[0]) << 4 | hex_val(h[1]));
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// `reserved = ";" / "/" / "?" / ":" / "@" / "&" / "=" / "+" / "$" / ","`
/// (RFC 3261 §25.1).
const fn is_reserved(b: u8) -> bool {
    matches!(
        b,
        b';' | b'/' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b','
    )
}

/// Canonical form for §19.1.4 comparison: `%HH` of an unreserved octet is
/// decoded; `%HH` of a reserved octet stays escaped (hex upper-cased), so it
/// never equals the literal reserved character.
fn canonical_escaped(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = b.get(i + 1..i + 3)
            && h.iter().all(u8::is_ascii_hexdigit)
        {
            let v = hex_val(h[0]) << 4 | hex_val(h[1]);
            if is_reserved(v) {
                out.push(b'%');
                out.push(h[0].to_ascii_uppercase());
                out.push(h[1].to_ascii_uppercase());
            } else {
                out.push(v);
            }
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Compares two escaped strings per RFC 3261 §19.1.4: "characters other
/// than those in the reserved set are equivalent to their %HEX HEX
/// encoding" - an escaped reserved character is NOT equal to its literal
/// form. `ci` selects ASCII case-insensitive comparison.
fn escaped_eq(a: &str, b: &str, ci: bool) -> bool {
    let (a, b) = (canonical_escaped(a), canonical_escaped(b));
    if ci {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

/// `hostname = *( domainlabel "." ) toplabel [ "." ]` (RFC 3261 §25.1).
fn is_valid_hostname(h: &str) -> bool {
    let h = h.strip_suffix('.').unwrap_or(h);
    if h.is_empty() {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    for l in &labels {
        let b = l.as_bytes();
        let (Some(first), Some(last)) = (b.first(), b.last()) else {
            return false;
        };
        if !first.is_ascii_alphanumeric()
            || !last.is_ascii_alphanumeric()
            || !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        {
            return false;
        }
    }
    // toplabel = ALPHA / ALPHA *( alphanum / "-" ) alphanum
    labels
        .last()
        .and_then(|l| l.as_bytes().first())
        .is_some_and(u8::is_ascii_alphabetic)
}

/// Parses `host [ ":" port ]` (RFC 3261 §25.1). Ports must be `1*DIGIT`,
/// non-zero and fit in `u16`; anything else is rejected instead of being
/// silently dropped (POA&M-150).
fn parse_host_port(host_port: &str) -> SipResult<(String, Option<u16>)> {
    let (host, port_str) = if let Some(inner) = host_port.strip_prefix('[') {
        let (h, after) = inner
            .split_once(']')
            .ok_or_else(|| invalid("invalid IPv6 reference"))?;
        if h.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid("invalid IPv6 reference"));
        }
        let port = match after {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or_else(|| invalid("trailing data after IPv6 reference"))?,
            ),
        };
        (h, port)
    } else {
        let (h, p) = match host_port.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (host_port, None),
        };
        if h.parse::<std::net::Ipv4Addr>().is_err() && !is_valid_hostname(h) {
            return Err(invalid("invalid host"));
        }
        (h, p)
    };
    let port = match port_str {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit()) {
                return Err(invalid("invalid port"));
            }
            match p.parse::<u16>() {
                Ok(0) | Err(_) => return Err(invalid("invalid port")),
                Ok(v) => Some(v),
            }
        }
    };
    Ok((host.to_string(), port))
}

/// uri-parameters that RFC 3261 §19.1.4 gives comparison semantics to; a
/// duplicate would let two components disagree on the effective value.
/// uri-parameters that must match if present in either URI (RFC 3261
/// §19.1.4).
const EQ_MUST_MATCH_PARAMS: [&str; 5] = ["user", "ttl", "method", "maddr", "transport"];

const UNIQUE_PARAMS: [&str; 6] = ["transport", "user", "ttl", "method", "maddr", "lr"];

/// Parses `*( ";" uri-parameter )` (without the leading `;`).
fn parse_uri_params(s: &str) -> SipResult<Vec<(String, Option<String>)>> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for p in s.split(';') {
        if out.len() >= crate::MAX_PARAMS {
            // NIST 800-53 Rev5: SC-5 - bound uri-parameters.
            return Err(SipError::LimitExceeded {
                what: "URI parameters",
                limit: crate::MAX_PARAMS,
            });
        }
        let (name, value) = match p.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (p, None),
        };
        if name.is_empty() || value.is_some_and(str::is_empty) {
            return Err(invalid("empty uri-parameter"));
        }
        validate_escaped(name, is_param_char, "uri-parameter")?;
        if let Some(v) = value {
            validate_escaped(v, is_param_char, "uri-parameter")?;
        }
        if UNIQUE_PARAMS.iter().any(|u| u.eq_ignore_ascii_case(name))
            && out.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            return Err(invalid("duplicate uri-parameter"));
        }
        out.push((name.to_string(), value.map(str::to_string)));
    }
    Ok(out)
}

/// Parses `hname "=" hvalue *( "&" header )` (without the leading `?`).
fn parse_uri_headers(s: &str) -> SipResult<Vec<(String, String)>> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if out.len() >= crate::MAX_PARAMS {
            return Err(SipError::LimitExceeded {
                what: "URI headers",
                limit: crate::MAX_PARAMS,
            });
        }
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| invalid("URI header without '='"))?;
        if k.is_empty() {
            return Err(invalid("empty URI header name"));
        }
        validate_escaped(k, is_hnv_char, "URI header")?;
        validate_escaped(v, is_hnv_char, "URI header")?;
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Shared length / emptiness checks for untrusted URI text.
fn check_len(s: &str) -> SipResult<()> {
    // NIST 800-53 Rev5: SI-10 / SC-5 - untrusted input.
    if s.is_empty() {
        return Err(invalid("empty URI"));
    }
    if s.len() > crate::MAX_URI_LEN {
        return Err(SipError::LimitExceeded {
            what: "URI length",
            limit: crate::MAX_URI_LEN,
        });
    }
    Ok(())
}

/// `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986 §3.1).
fn is_valid_scheme(s: &str) -> bool {
    let b = s.as_bytes();
    b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

impl SipUri {
    /// Returns the user part with `%HH` escapes decoded.
    #[must_use]
    pub fn user_decoded(&self) -> Option<Cow<'_, str>> {
        self.user.as_deref().map(percent_decode)
    }

    /// Returns the password with `%HH` escapes decoded.
    #[must_use]
    pub fn password_decoded(&self) -> Option<Cow<'_, str>> {
        self.password.as_deref().map(percent_decode)
    }

    /// Returns a URI parameter value with `%HH` escapes decoded.
    #[must_use]
    pub fn get_param_decoded(&self, name: &str) -> Option<Cow<'_, str>> {
        self.get_param(name).map(percent_decode)
    }

    /// URI equivalence per RFC 3261 §19.1.4.
    ///
    /// - scheme must match; userinfo is case-sensitive after unescaping;
    /// - host is case-insensitive, IP literals compared as addresses;
    /// - a port present on one side only makes the URIs unequal;
    /// - `user`, `ttl`, `method`, `maddr`, `transport` must match if present
    ///   in either URI; other parameters are compared only if in both;
    /// - URI headers must all match (case-insensitive names).
    ///
    /// POAM: POA&M-154 - not yet used by registrar/dialog/auth comparisons
    /// (IA-2, AC-3); add the control claim once those callers migrate.
    #[must_use]
    pub fn equivalent(&self, other: &SipUri) -> bool {
        if self.scheme != other.scheme || self.port != other.port {
            return false;
        }
        let opt_eq = |a: &Option<String>, b: &Option<String>| match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => escaped_eq(a, b, false),
            _ => false,
        };
        if !opt_eq(&self.user, &other.user) || !opt_eq(&self.password, &other.password) {
            return false;
        }
        let host_eq = match (
            self.host.parse::<std::net::IpAddr>(),
            other.host.parse::<std::net::IpAddr>(),
        ) {
            (Ok(a), Ok(b)) => a == b,
            (Err(_), Err(_)) => escaped_eq(&self.host, &other.host, true),
            _ => false,
        };
        if !host_eq {
            return false;
        }
        let param_eq = |a: &Option<String>, b: &Option<String>| match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => escaped_eq(a, b, true),
            _ => false,
        };
        for (name, value) in &self.params {
            match other.params.iter().find(|(n, _)| escaped_eq(n, name, true)) {
                Some((_, ov)) => {
                    if !param_eq(value, ov) {
                        return false;
                    }
                }
                None if EQ_MUST_MATCH_PARAMS
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(name)) =>
                {
                    return false;
                }
                None => {}
            }
        }
        for (name, _) in &other.params {
            if EQ_MUST_MATCH_PARAMS
                .iter()
                .any(|m| m.eq_ignore_ascii_case(name))
                && !self.params.iter().any(|(n, _)| escaped_eq(n, name, true))
            {
                return false;
            }
        }
        // Headers: every header in either URI must be present in the other
        // with an equal value.
        let hdr_sub = |a: &[(String, String)], b: &[(String, String)]| {
            a.iter().all(|(n, v)| {
                b.iter()
                    .any(|(on, ov)| escaped_eq(n, on, true) && escaped_eq(v, ov, false))
            })
        };
        hdr_sub(&self.headers, &other.headers) && hdr_sub(&other.headers, &self.headers)
    }
}

impl FromStr for SipUri {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        check_len(s)?;
        let (scheme_str, rest) = s
            .split_once(':')
            .ok_or_else(|| invalid("missing scheme separator"))?;
        // RFC 3261 §8.2.2.1: a non-SIP scheme is "unsupported" (416 on the
        // Request-URI), not malformed.
        let scheme = if scheme_str.eq_ignore_ascii_case("sip") {
            UriScheme::Sip
        } else if scheme_str.eq_ignore_ascii_case("sips") {
            UriScheme::Sips
        } else if is_valid_scheme(scheme_str) {
            return Err(SipError::UnsupportedUriScheme {
                scheme: crate::error::truncate_for_log(scheme_str),
            });
        } else {
            return Err(invalid("invalid scheme"));
        };

        // RFC 3261 §25.1: `@` is not allowed unescaped in hostport,
        // uri-parameters or headers, so the userinfo delimiter is the LAST
        // `@`. Everything before it is userinfo (which may legally contain
        // `;`, `?`, `/`, ...).
        let (userinfo, after) = match rest.rfind('@') {
            Some(at) => (Some(&rest[..at]), &rest[at + 1..]),
            None => (None, rest),
        };
        let (user, password) = match userinfo {
            None => (None, None),
            Some(ui) => {
                let (u, p) = match ui.split_once(':') {
                    Some((u, p)) => (u, Some(p)),
                    None => (ui, None),
                };
                if u.is_empty() {
                    return Err(invalid("empty user"));
                }
                validate_escaped(u, is_user_char, "user")?;
                if let Some(p) = p {
                    validate_escaped(p, is_password_char, "password")?;
                }
                (Some(u.to_string()), p.map(str::to_string))
            }
        };

        // hostport ends at the first `;` or `?` (after any IPv6 reference).
        let search_from = if after.starts_with('[') {
            after.find(']').unwrap_or(0)
        } else {
            0
        };
        let hp_end = after[search_from..]
            .find([';', '?'])
            .map_or(after.len(), |i| i + search_from);
        let (host, port) = parse_host_port(&after[..hp_end])?;
        let tail = &after[hp_end..];
        let (params_str, headers_str) = match tail.split_once('?') {
            Some((p, h)) => (p, Some(h)),
            None => (tail, None),
        };
        let params = match params_str.strip_prefix(';') {
            Some(p) => parse_uri_params(p)?,
            None if params_str.is_empty() => Vec::new(),
            None => return Err(invalid("trailing data after host")),
        };
        let headers = match headers_str {
            Some(h) => parse_uri_headers(h)?,
            None => Vec::new(),
        };

        Ok(SipUri {
            scheme,
            user,
            password,
            host,
            port,
            params,
            headers,
        })
    }
}

/// `tel:` URI (RFC 3966), minimally validated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TelUri {
    /// The subscriber number, without visual separators removed.
    pub number: String,
    /// True for a global number (`+` prefix).
    pub global: bool,
    /// Parameters (`;name[=value]`), raw.
    pub params: Vec<(String, Option<String>)>,
}

/// RFC 3966 `phonedigit-hex` plus visual separators.
fn is_tel_number_char(b: u8, global: bool) -> bool {
    b.is_ascii_digit()
        || matches!(b, b'-' | b'.' | b'(' | b')')
        || (!global && (b.is_ascii_hexdigit() || matches!(b, b'*' | b'#')))
}

/// RFC 3966 `paramchar = param-unreserved / unreserved / pct-encoded`.
fn is_tel_param_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'['
                | b']'
                | b'/'
                | b':'
                | b'&'
                | b'+'
                | b'$'
                | b'!'
                | b'\''
                | b'('
                | b')'
                | b'*'
        )
}

impl FromStr for TelUri {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        check_len(s)?;
        let (scheme, rest) = s
            .split_once(':')
            .ok_or_else(|| invalid("missing scheme separator"))?;
        if !scheme.eq_ignore_ascii_case("tel") {
            return Err(invalid("not a tel URI"));
        }
        let (number, params_str) = match rest.split_once(';') {
            Some((n, p)) => (n, Some(p)),
            None => (rest, None),
        };
        let global = number.starts_with('+');
        let digits = number.strip_prefix('+').unwrap_or(number);
        if digits.is_empty() || !digits.bytes().all(|b| is_tel_number_char(b, global)) {
            return Err(invalid("invalid telephone-subscriber"));
        }
        let mut params = Vec::new();
        if let Some(ps) = params_str {
            for p in ps.split(';') {
                if params.len() >= crate::MAX_PARAMS {
                    return Err(SipError::LimitExceeded {
                        what: "URI parameters",
                        limit: crate::MAX_PARAMS,
                    });
                }
                let (n, v) = match p.split_once('=') {
                    Some((n, v)) => (n, Some(v)),
                    None => (p, None),
                };
                if n.is_empty() || v.is_some_and(str::is_empty) {
                    return Err(invalid("empty tel parameter"));
                }
                validate_escaped(n, is_tel_param_char, "tel parameter")?;
                if let Some(v) = v {
                    validate_escaped(v, is_tel_param_char, "tel parameter")?;
                }
                params.push((n.to_string(), v.map(str::to_string)));
            }
        }
        Ok(Self {
            number: number.to_string(),
            global,
            params,
        })
    }
}

impl fmt::Display for TelUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tel:{}", self.number)?;
        for (n, v) in &self.params {
            write!(f, ";{n}")?;
            if let Some(v) = v {
                write!(f, "={v}")?;
            }
        }
        Ok(())
    }
}

/// Any other `absoluteURI` (RFC 3261 §25.1 / RFC 3986 §3), kept opaque.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AbsoluteUri {
    /// Scheme (as received).
    pub scheme: String,
    /// Everything after the first `:`.
    pub rest: String,
}

/// RFC 3986 `reserved / unreserved` (printable ASCII except SP `"` `<` `>`
/// `\` `^` `` ` `` `{` `|` `}` and `%`, which must be an escape).
fn is_uric(b: u8) -> bool {
    b.is_ascii_graphic()
        && !matches!(
            b,
            b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}' | b'%'
        )
}

impl FromStr for AbsoluteUri {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        check_len(s)?;
        let (scheme, rest) = s
            .split_once(':')
            .ok_or_else(|| invalid("missing scheme separator"))?;
        if !is_valid_scheme(scheme) || rest.is_empty() {
            return Err(invalid("invalid absoluteURI"));
        }
        validate_escaped(rest, is_uric, "absoluteURI")?;
        Ok(Self {
            scheme: scheme.to_string(),
            rest: rest.to_string(),
        })
    }
}

impl fmt::Display for AbsoluteUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scheme, self.rest)
    }
}

/// A Request-URI / addr-spec of any scheme (RFC 3261 §25.1
/// `SIP-URI / SIPS-URI / absoluteURI`).
///
/// POAM: POA&M-153 - `NameAddr.uri` and `RequestLine.uri` still hold
/// [`SipUri`]; this type exists so the migration is mechanical.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Uri {
    /// `sip:` / `sips:`.
    Sip(SipUri),
    /// `tel:` (RFC 3966).
    Tel(TelUri),
    /// Any other scheme, opaque.
    Absolute(AbsoluteUri),
}

impl Uri {
    /// Returns the scheme as written (lower-case for sip/sips/tel).
    #[must_use]
    pub fn scheme(&self) -> &str {
        match self {
            Self::Sip(u) => u.scheme.as_str(),
            Self::Tel(_) => "tel",
            Self::Absolute(a) => &a.scheme,
        }
    }

    /// Returns the SIP URI if this is `sip:`/`sips:`.
    #[must_use]
    pub fn as_sip(&self) -> Option<&SipUri> {
        match self {
            Self::Sip(u) => Some(u),
            _ => None,
        }
    }
}

impl FromStr for Uri {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        check_len(s)?;
        let (scheme, _) = s
            .split_once(':')
            .ok_or_else(|| invalid("missing scheme separator"))?;
        if scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips") {
            s.parse().map(Self::Sip)
        } else if scheme.eq_ignore_ascii_case("tel") {
            s.parse().map(Self::Tel)
        } else {
            s.parse().map(Self::Absolute)
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sip(u) => u.fmt(f),
            Self::Tel(u) => u.fmt(f),
            Self::Absolute(u) => u.fmt(f),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_uri() {
        let uri = SipUri::new("example.com");
        assert_eq!(uri.scheme, UriScheme::Sip);
        assert_eq!(uri.host, "example.com");
        assert_eq!(format!("{uri}"), "sip:example.com");
    }

    #[test]
    fn test_uri_with_user() {
        let uri = SipUri::new("example.com").with_user("alice");
        assert_eq!(format!("{uri}"), "sip:alice@example.com");
    }

    #[test]
    fn test_uri_with_port() {
        let uri = SipUri::new("example.com").with_port(5080);
        assert_eq!(format!("{uri}"), "sip:example.com:5080");
    }

    #[test]
    fn test_uri_parse() {
        let uri: SipUri = "sip:alice@example.com:5060".parse().unwrap();
        assert_eq!(uri.scheme, UriScheme::Sip);
        assert_eq!(uri.user, Some("alice".to_string()));
        assert_eq!(uri.host, "example.com");
        assert_eq!(uri.port, Some(5060));
    }

    #[test]
    fn test_uri_parse_params() {
        let uri: SipUri = "sip:alice@example.com;transport=tcp;lr".parse().unwrap();
        assert_eq!(uri.transport(), Some("tcp"));
        assert!(uri.is_loose_router());
    }

    #[test]
    fn test_sips_uri() {
        let uri = SipUri::new_sips("secure.example.com");
        assert_eq!(uri.scheme, UriScheme::Sips);
        assert!(uri.scheme.requires_tls());
        assert_eq!(uri.effective_port(), 5061);
    }

    #[test]
    fn test_ipv6_uri() {
        let uri: SipUri = "sip:alice@[::1]:5060".parse().unwrap();
        assert_eq!(uri.host, "::1");
        assert_eq!(uri.port, Some(5060));
        assert_eq!(format!("{uri}"), "sip:alice@[::1]:5060");
    }

    #[test]
    fn test_roundtrip() {
        let original = "sip:alice@example.com:5060;transport=tcp;lr";
        let uri: SipUri = original.parse().unwrap();
        let formatted = format!("{uri}");
        assert_eq!(formatted, original);
    }

    #[test]
    fn uri_untrusted_input_errors_in_release() {
        assert!("".parse::<SipUri>().is_err());
        let long = format!("sip:{}@example.com", "a".repeat(crate::MAX_URI_LEN));
        assert!(long.parse::<SipUri>().is_err());
        let many = (0..=crate::MAX_PARAMS).fold(String::new(), |mut acc, i| {
            let _ = std::fmt::Write::write_fmt(&mut acc, format_args!(";p{i}"));
            acc
        });
        assert!(
            format!("sip:a@example.com{many}")
                .parse::<SipUri>()
                .is_err()
        );
    }

    #[test]
    fn fuzz_regression_stray_bracket_host_roundtrip() {
        // roundtrip fuzz crash: host ":adch]nparam" re-serialized as
        // "[:adch]nparam]" and re-parsed differently.
        assert!("sip:vivekg@:adch]nparam".parse::<SipUri>().is_err());
        assert!("sip:[::1]junk".parse::<SipUri>().is_err());
        assert!("sip:a@".parse::<SipUri>().is_err());
        let u: SipUri = "sip:a@[2001:db8::1]:5060".parse().unwrap();
        assert_eq!(u.port, Some(5060));
        let again: SipUri = u.to_string().parse().unwrap();
        assert_eq!(again.to_string(), u.to_string());
    }
}
