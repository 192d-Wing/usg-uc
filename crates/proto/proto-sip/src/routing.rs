//! SIP routing header processing per RFC 3261.
//!
//! This module handles Route and Record-Route header processing for
//! loose routing (RFC 3261 Section 16.12.1).
//!
//! ## Routing Overview
//!
//! - **Record-Route**: Added by proxies to stay in the signaling path
//! - **Route**: Used to specify the path for subsequent requests
//! - **Loose Routing**: Modern routing (;lr parameter) - request target unchanged
//! - **Strict Routing**: Legacy routing - request target modified (deprecated)

use crate::error::{SipError, SipResult};
use crate::header_params::NameAddr;
use crate::uri::SipUri;

/// A Route entry (parsed Route or Record-Route header value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// The route URI.
    uri: SipUri,
    /// Whether this is a loose router (has ;lr parameter).
    loose_route: bool,
}

impl RouteEntry {
    /// Creates a new route entry.
    pub fn new(uri: SipUri) -> Self {
        let loose_route = uri.is_loose_router();

        Self { uri, loose_route }
    }

    /// Creates a loose route entry.
    pub fn loose(mut uri: SipUri) -> Self {
        // Add lr parameter if not present
        if !uri.is_loose_router() {
            uri.params.push(("lr".to_string(), None));
        }

        Self {
            loose_route: true,
            uri,
        }
    }

    /// Returns the URI.
    pub fn uri(&self) -> &SipUri {
        &self.uri
    }

    /// Returns true if this is a loose router.
    pub fn is_loose_route(&self) -> bool {
        self.loose_route
    }

    /// Returns the host portion.
    pub fn host(&self) -> &str {
        &self.uri.host
    }

    /// Returns the port if specified.
    pub fn port(&self) -> Option<u16> {
        self.uri.port
    }

    /// Returns the transport parameter if specified.
    pub fn transport(&self) -> Option<&str> {
        self.uri.transport()
    }
}

impl std::fmt::Display for RouteEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>", self.uri)
    }
}

impl std::str::FromStr for RouteEntry {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        // Handle <uri> format
        let s = s.trim();
        let uri_str = if s.starts_with('<') && s.contains('>') {
            let end = s.find('>').ok_or_else(|| SipError::InvalidHeader {
                name: "Route".to_string(),
                reason: "malformed Route entry".to_string(),
            })?;
            &s[1..end]
        } else {
            s
        };

        let uri: SipUri = uri_str.parse()?;
        Ok(Self::new(uri))
    }
}

/// Route set for a dialog or request.
///
/// The route set determines the path that subsequent requests will take.
#[derive(Debug, Clone, Default)]
pub struct RouteSet {
    /// Ordered list of route entries.
    routes: Vec<RouteEntry>,
}

impl RouteSet {
    /// Creates an empty route set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a route set from Route header values.
    pub fn from_route_headers(headers: &[String]) -> SipResult<Self> {
        let mut routes = Vec::new();

        for header in headers {
            // Route headers can contain multiple comma-separated entries
            for entry in split_header_list(header) {
                let route: RouteEntry = entry.parse()?;
                routes.push(route);
            }
        }

        Ok(Self { routes })
    }

    /// Creates a route set from Record-Route header values.
    ///
    /// Per RFC 3261 Section 12.1.1, the route set is constructed by
    /// copying the Record-Route headers in reverse order.
    pub fn from_record_route_headers(headers: &[String]) -> SipResult<Self> {
        let mut routes = Vec::new();

        // Process in reverse order
        for header in headers.iter().rev() {
            for entry in split_header_list(header).into_iter().rev() {
                let route: RouteEntry = entry.parse()?;
                routes.push(route);
            }
        }

        Ok(Self { routes })
    }

    /// Adds a route entry.
    pub fn push(&mut self, entry: RouteEntry) {
        self.routes.push(entry);
    }

    /// Prepends a route entry.
    pub fn prepend(&mut self, entry: RouteEntry) {
        self.routes.insert(0, entry);
    }

    /// Removes and returns the first route entry.
    pub fn pop_first(&mut self) -> Option<RouteEntry> {
        if self.routes.is_empty() {
            None
        } else {
            Some(self.routes.remove(0))
        }
    }

    /// Returns the first route entry.
    pub fn first(&self) -> Option<&RouteEntry> {
        self.routes.first()
    }

    /// Returns true if the route set is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns the number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns an iterator over the routes.
    pub fn iter(&self) -> impl Iterator<Item = &RouteEntry> {
        self.routes.iter()
    }

    /// Converts to Route header values.
    pub fn to_route_headers(&self) -> Vec<String> {
        self.routes.iter().map(|r| r.to_string()).collect()
    }

    /// Converts to Record-Route header values.
    pub fn to_record_route_headers(&self) -> Vec<String> {
        // For responses, preserve order
        self.routes.iter().map(|r| r.to_string()).collect()
    }
}

impl IntoIterator for RouteSet {
    type Item = RouteEntry;
    type IntoIter = std::vec::IntoIter<RouteEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.routes.into_iter()
    }
}

/// Determines the request target for loose routing.
///
/// Per RFC 3261 Section 16.12.1.1:
/// - If Route header is present and first URI has ;lr parameter:
///   - Request-URI remains unchanged
///   - Route header is popped and used as next hop
/// - If Route header is present and first URI lacks ;lr parameter (strict routing):
///   - First Route entry becomes the Request-URI
///   - Old Request-URI is appended to Route
///
/// # Arguments
///
/// * `request_uri` - The current Request-URI
/// * `route_set` - The route set from Route headers
///
/// # Returns
///
/// A tuple of (next_hop_uri, new_request_uri, remaining_routes)
pub fn compute_request_target(
    request_uri: &SipUri,
    route_set: &RouteSet,
) -> (SipUri, SipUri, RouteSet) {
    if route_set.is_empty() {
        // No routing - use request URI directly
        return (request_uri.clone(), request_uri.clone(), RouteSet::new());
    }

    let first = route_set.first();

    match first {
        Some(entry) if entry.is_loose_route() => {
            // Loose routing: Request-URI unchanged, first Route is next hop
            let mut remaining = route_set.clone();
            let next_hop = remaining.pop_first().map(|e| e.uri.clone());

            (
                next_hop.unwrap_or_else(|| request_uri.clone()),
                request_uri.clone(),
                remaining,
            )
        }
        Some(_entry) => {
            // Strict routing (legacy): First Route becomes Request-URI
            let mut remaining = route_set.clone();
            let first_route = remaining.pop_first();

            if let Some(first) = first_route {
                // Append original Request-URI to end of route set
                remaining.push(RouteEntry::new(request_uri.clone()));

                (first.uri.clone(), first.uri.clone(), remaining)
            } else {
                (request_uri.clone(), request_uri.clone(), RouteSet::new())
            }
        }
        None => (request_uri.clone(), request_uri.clone(), RouteSet::new()),
    }
}

/// Processes incoming Record-Route headers for a UAS.
///
/// Per RFC 3261 Section 12.1.1, the UAS copies Record-Route headers
/// in reverse order to form its route set.
pub fn process_record_route_for_uas(record_routes: &[String]) -> SipResult<RouteSet> {
    RouteSet::from_record_route_headers(record_routes)
}

/// Processes incoming Record-Route headers for a UAC.
///
/// Per RFC 3261 Section 12.1.2, the UAC copies Record-Route headers
/// in order to form its route set (already in correct order from response).
pub fn process_record_route_for_uac(record_routes: &[String]) -> SipResult<RouteSet> {
    let mut routes = Vec::new();

    for header in record_routes {
        for entry in split_header_list(header) {
            let route: RouteEntry = entry.parse()?;
            routes.push(route);
        }
    }

    Ok(RouteSet { routes })
}

/// Constructs Record-Route header for a proxy.
///
/// Per RFC 3261 Section 16.6, a proxy that wishes to stay in the
/// path must add a Record-Route header with its URI.
pub fn create_record_route(proxy_uri: SipUri, loose_route: bool) -> RouteEntry {
    if loose_route {
        RouteEntry::loose(proxy_uri)
    } else {
        RouteEntry::new(proxy_uri)
    }
}

/// Parses a NameAddr from a Route/Record-Route header value.
pub fn parse_route_name_addr(value: &str) -> SipResult<NameAddr> {
    value.parse()
}

/// Splits a comma-separated header list.
///
/// Handles quoted strings properly (commas inside quotes are not separators).
fn split_header_list(header: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut in_angle = false;

    let chars: Vec<char> = header.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        match c {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => in_angle = true,
            '>' if !in_quotes => in_angle = false,
            ',' if !in_quotes && !in_angle => {
                let entry = header[start..i].trim();
                if !entry.is_empty() {
                    result.push(entry);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    // Add last entry
    let entry = header[start..].trim();
    if !entry.is_empty() {
        result.push(entry);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_entry_parse() {
        let entry: RouteEntry = "<sip:proxy.example.com;lr>".parse().unwrap();
        assert!(entry.is_loose_route());
        assert_eq!(entry.host(), "proxy.example.com");
    }

    #[test]
    fn test_route_entry_strict() {
        let entry: RouteEntry = "<sip:proxy.example.com>".parse().unwrap();
        assert!(!entry.is_loose_route());
    }

    #[test]
    fn test_route_entry_display() {
        let uri = "sip:proxy.example.com;lr".parse().unwrap();
        let entry = RouteEntry::new(uri);
        let display = entry.to_string();
        assert!(display.contains("sip:proxy.example.com"));
    }

    #[test]
    fn test_route_set_from_headers() {
        let headers = vec!["<sip:p1.example.com;lr>, <sip:p2.example.com;lr>".to_string()];
        let route_set = RouteSet::from_route_headers(&headers).unwrap();
        assert_eq!(route_set.len(), 2);
        assert!(route_set.first().unwrap().is_loose_route());
    }

    #[test]
    fn test_route_set_from_record_route_reverse() {
        let headers = vec![
            "<sip:p1.example.com;lr>".to_string(),
            "<sip:p2.example.com;lr>".to_string(),
        ];
        let route_set = RouteSet::from_record_route_headers(&headers).unwrap();

        // Should be reversed
        let routes: Vec<_> = route_set.iter().collect();
        assert_eq!(routes[0].host(), "p2.example.com");
        assert_eq!(routes[1].host(), "p1.example.com");
    }

    #[test]
    fn test_compute_request_target_loose_routing() {
        let request_uri: SipUri = "sip:bob@biloxi.example.com".parse().unwrap();

        let mut route_set = RouteSet::new();
        let proxy_uri: SipUri = "sip:ss1.atlanta.example.com;lr".parse().unwrap();
        route_set.push(RouteEntry::new(proxy_uri));

        let (next_hop, new_request_uri, remaining) =
            compute_request_target(&request_uri, &route_set);

        // Loose routing: Request-URI unchanged, proxy is next hop
        assert_eq!(new_request_uri.host, "biloxi.example.com");
        assert_eq!(next_hop.host, "ss1.atlanta.example.com");
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_compute_request_target_strict_routing() {
        let request_uri: SipUri = "sip:bob@biloxi.example.com".parse().unwrap();

        let mut route_set = RouteSet::new();
        // Strict router (no ;lr)
        let proxy_uri: SipUri = "sip:ss1.atlanta.example.com".parse().unwrap();
        route_set.push(RouteEntry::new(proxy_uri));

        let (next_hop, new_request_uri, remaining) =
            compute_request_target(&request_uri, &route_set);

        // Strict routing: First route becomes Request-URI
        assert_eq!(new_request_uri.host, "ss1.atlanta.example.com");
        assert_eq!(next_hop.host, "ss1.atlanta.example.com");
        // Original Request-URI should be appended to remaining routes
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining.first().unwrap().host(), "biloxi.example.com");
    }

    #[test]
    fn test_split_header_list() {
        let header = "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>";
        let parts = split_header_list(header);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "<sip:p1.example.com;lr>");
        assert_eq!(parts[1], "<sip:p2.example.com;lr>");
    }

    #[test]
    fn test_split_header_list_with_quotes() {
        let header = "\"Name, Jr.\" <sip:p1.example.com;lr>, <sip:p2.example.com>";
        let parts = split_header_list(header);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("Name, Jr."));
    }

    #[test]
    fn test_create_record_route() {
        let proxy_uri: SipUri = "sip:proxy.example.com".parse().unwrap();
        let entry = create_record_route(proxy_uri, true);
        assert!(entry.is_loose_route());
    }

    #[test]
    fn test_route_set_operations() {
        let mut route_set = RouteSet::new();
        assert!(route_set.is_empty());

        let uri1: SipUri = "sip:p1.example.com;lr".parse().unwrap();
        let uri2: SipUri = "sip:p2.example.com;lr".parse().unwrap();

        route_set.push(RouteEntry::new(uri1));
        route_set.prepend(RouteEntry::new(uri2));

        assert_eq!(route_set.len(), 2);
        assert_eq!(route_set.first().unwrap().host(), "p2.example.com");

        let first = route_set.pop_first().unwrap();
        assert_eq!(first.host(), "p2.example.com");
        assert_eq!(route_set.len(), 1);
    }

    #[test]
    fn test_to_route_headers() {
        let mut route_set = RouteSet::new();
        let uri: SipUri = "sip:proxy.example.com;lr".parse().unwrap();
        route_set.push(RouteEntry::new(uri));

        let headers = route_set.to_route_headers();
        assert_eq!(headers.len(), 1);
        assert!(headers[0].contains("proxy.example.com"));
    }
}
