//! SIP URI handling per RFC 3261.

use crate::error::{SipError, SipResult};
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
        self.params.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
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

impl FromStr for SipUri {
    type Err = SipError;

    /// Parses a SIP URI string.
    ///
    /// # Loop Bounds (Power of 10 Rule 2)
    ///
    /// - `split(';')` bounded by input length
    /// - `split('&')` bounded by input length
    /// - All iterations terminate in O(n) where n = input length
    fn from_str(s: &str) -> SipResult<Self> {
        // Power of 10 Rule 5: Assert precondition
        debug_assert!(!s.is_empty(), "empty URI string");

        // Split scheme
        let (scheme_str, rest) = s.split_once(':').ok_or_else(|| SipError::InvalidUri {
            reason: "missing scheme separator".to_string(),
        })?;

        let scheme: UriScheme = scheme_str.parse()?;

        // Split headers
        let (rest, headers_str) = if let Some((r, h)) = rest.split_once('?') {
            (r, Some(h))
        } else {
            (rest, None)
        };

        // Split params
        // Loop bound: split(';') bounded by rest.len()
        let parts: Vec<&str> = rest.split(';').collect();

        // Power of 10 Rule 5: Assert parts is non-empty
        debug_assert!(!parts.is_empty(), "split always produces at least one element");

        let user_host_port = parts.first().ok_or_else(|| SipError::InvalidUri {
            reason: "missing host".to_string(),
        })?;

        // Parse params
        let params: Vec<(String, Option<String>)> = parts[1..]
            .iter()
            .map(|p| {
                if let Some((name, value)) = p.split_once('=') {
                    (name.to_string(), Some(value.to_string()))
                } else {
                    (p.to_string(), None)
                }
            })
            .collect();

        // Parse user@host:port
        let (user, password, host_port) = if let Some((userinfo, hp)) = user_host_port.split_once('@') {
            let (user, password) = if let Some((u, p)) = userinfo.split_once(':') {
                (Some(u.to_string()), Some(p.to_string()))
            } else {
                (Some(userinfo.to_string()), None)
            };
            (user, password, hp)
        } else {
            (None, None, *user_host_port)
        };

        // Parse host:port (handle IPv6)
        let (host, port) = if host_port.starts_with('[') {
            // IPv6
            if let Some((h, p)) = host_port.split_once(']') {
                let host = h.trim_start_matches('[');
                let port = p.strip_prefix(':').and_then(|p| p.parse().ok());
                (host.to_string(), port)
            } else {
                return Err(SipError::InvalidUri {
                    reason: "invalid IPv6 address".to_string(),
                });
            }
        } else if let Some((h, p)) = host_port.rsplit_once(':') {
            // IPv4 or hostname with port
            if let Ok(port) = p.parse() {
                (h.to_string(), Some(port))
            } else {
                (host_port.to_string(), None)
            }
        } else {
            (host_port.to_string(), None)
        };

        // Parse headers
        let headers = headers_str
            .map(|h| {
                h.split('&')
                    .filter_map(|pair| {
                        pair.split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();

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

#[cfg(test)]
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
}
