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

use crate::MAX_LIST_ELEMENTS;
use crate::error::{SipError, SipResult};
use crate::header::HeaderName;
use crate::header_params::NameAddr;
use crate::list::split_list_bounded;
use crate::message::SipRequest;
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
    #[must_use]
    pub fn new(uri: SipUri) -> Self {
        let loose_route = uri.is_loose_router();

        Self { uri, loose_route }
    }

    /// Creates a loose route entry.
    #[must_use]
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
    #[must_use]
    pub fn uri(&self) -> &SipUri {
        &self.uri
    }

    /// Returns true if this is a loose router.
    #[must_use]
    pub fn is_loose_route(&self) -> bool {
        self.loose_route
    }

    /// Returns the host portion.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.uri.host
    }

    /// Returns the port if specified.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.uri.port
    }

    /// Returns the transport parameter if specified.
    #[must_use]
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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a route set from Route header values.
    ///
    /// # Errors
    /// Returns an error if a value cannot be split or parsed.
    pub fn from_route_headers(headers: &[String]) -> SipResult<Self> {
        let mut routes = Vec::new();

        for header in headers {
            // Route headers can contain multiple comma-separated entries
            for entry in split_list_bounded(header, MAX_LIST_ELEMENTS)? {
                let route: RouteEntry = entry.parse()?;
                routes.push(route);
            }
        }

        Ok(Self { routes })
    }

    /// Creates a route set from Record-Route header values in **reverse**
    /// order, including elements inside a comma-joined header.
    ///
    /// This is the UAC rule: RFC 3261 §12.1.2 - "the route set MUST be set to
    /// the list of URIs in the Record-Route header field from the response,
    /// taken in reverse order".
    ///
    /// # Errors
    /// Returns an error if a value cannot be split or parsed.
    pub fn from_record_route_headers(headers: &[String]) -> SipResult<Self> {
        let mut routes = Vec::new();

        // Process in reverse order
        for header in headers.iter().rev() {
            for entry in split_list_bounded(header, MAX_LIST_ELEMENTS)?
                .into_iter()
                .rev()
            {
                let route: RouteEntry = entry.parse()?;
                routes.push(route);
            }
        }

        Ok(Self { routes })
    }

    /// Creates a route set from Record-Route header values **in order**.
    ///
    /// This is the UAS rule: RFC 3261 §12.1.1 - "the route set MUST be set to
    /// the list of URIs in the Record-Route header field from the request,
    /// taken in order".
    ///
    /// # Errors
    /// Returns an error if a value cannot be split or parsed.
    pub fn from_record_route_headers_in_order(headers: &[String]) -> SipResult<Self> {
        Self::from_route_headers(headers)
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
    #[must_use]
    pub fn first(&self) -> Option<&RouteEntry> {
        self.routes.first()
    }

    /// Returns true if the route set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Returns the number of routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns an iterator over the routes.
    pub fn iter(&self) -> impl Iterator<Item = &RouteEntry> {
        self.routes.iter()
    }

    /// Converts to Route header values.
    #[must_use]
    pub fn to_route_headers(&self) -> Vec<String> {
        self.routes
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    }

    /// Converts to Record-Route header values.
    #[must_use]
    pub fn to_record_route_headers(&self) -> Vec<String> {
        // For responses, preserve order
        self.routes
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
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
/// A tuple of (`next_hop_uri`, `new_request_uri`, `remaining_routes`)
#[must_use]
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

/// Builds the UAS route set from the Record-Route headers of a
/// dialog-creating request.
///
/// RFC 3261 §12.1.1: the UAS route set is the Record-Route URIs **in order**.
/// (POA&M-231: this previously reversed them.)
///
/// # Errors
/// Returns an error if a value cannot be split or parsed.
pub fn process_record_route_for_uas(record_routes: &[String]) -> SipResult<RouteSet> {
    RouteSet::from_record_route_headers_in_order(record_routes)
}

/// Builds the UAC route set from the Record-Route headers of a
/// dialog-creating response.
///
/// RFC 3261 §12.1.2: the UAC route set is the Record-Route URIs in
/// **reverse** order, including elements inside one comma-joined header.
/// (POA&M-231: this previously kept them in order.)
///
/// # Errors
/// Returns an error if a value cannot be split or parsed.
pub fn process_record_route_for_uac(record_routes: &[String]) -> SipResult<RouteSet> {
    RouteSet::from_record_route_headers(record_routes)
}

/// Outcome of RFC 3261 §16.4 route information preprocessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePreprocess {
    /// Preprocessing completed.
    Done {
        /// The Request-URI was ours (previous hop was a strict router) and
        /// was replaced by the last Route value, which was removed.
        restored_from_strict_route: bool,
        /// The topmost Route value was ours and was removed.
        popped_own_route: bool,
    },
    /// The Request-URI is one of our Record-Route URIs but the request has
    /// no Route header to restore it from. Nothing was changed; the caller
    /// decides (typically 404 or 416).
    NoRouteForOwnUri,
}

/// Collects every Route element across all Route headers.
///
/// NIST 800-53 Rev5: SC-5 - fails instead of truncating, so a rewrite can
/// never silently drop routes.
fn route_elements(request: &SipRequest) -> SipResult<Vec<String>> {
    let mut out = Vec::new();
    for h in request.headers.get_all(&HeaderName::Route) {
        for e in split_list_bounded(&h.value, MAX_LIST_ELEMENTS)? {
            if out.len() >= MAX_LIST_ELEMENTS {
                return Err(SipError::LimitExceeded {
                    what: "Route elements",
                    limit: MAX_LIST_ELEMENTS,
                });
            }
            out.push(e.to_string());
        }
    }
    Ok(out)
}

/// RFC 3261 §16.4 route information preprocessing for a proxy.
///
/// Runs before target selection (§16.5). `is_own` must recognise the URIs
/// this proxy places in Record-Route (see `ProxyContext::is_own`):
///
/// 1. If the Request-URI is ours, the previous hop was a strict router:
///    the Request-URI MUST be replaced by the **last** Route value, and that
///    value removed (also when it is part of a comma-joined header).
/// 2. Then, if the **topmost** Route value is ours, it MUST be removed.
///
/// Only values `is_own` recognises are consumed, so an attacker-supplied
/// last Route can become the Request-URI only when the Request-URI was one
/// of our own Record-Route URIs (RFC-mandated); routing policy still applies
/// afterwards. NIST 800-53 Rev5: SC-7 (Boundary Protection), SI-10.
///
/// # Security
///
/// When the Request-URI is one of our Record-Route URIs (strict-route
/// restore), the **last Route value, supplied by the sender**, becomes the
/// new Request-URI. Access control, dial-plan and routing policy MUST be
/// evaluated on the Request-URI *after* this function runs, never on the
/// value as received, or a sender can steer the request past them.
/// NIST 800-53 Rev5: AC-4, SC-7.
///
/// POAM: §16.4 paragraph 3 (`maddr` naming this proxy) is not implemented;
/// a Request-URI with such a `maddr` is forwarded unchanged.
///
/// # Errors
/// Returns an error if a Route value cannot be split or parsed, or there are
/// more than [`MAX_LIST_ELEMENTS`] Route values. The request is not modified
/// on error.
pub fn preprocess_route_information(
    request: &mut SipRequest,
    is_own: &dyn Fn(&SipUri) -> bool,
) -> SipResult<RoutePreprocess> {
    let mut routes = route_elements(request)?;
    let mut new_uri = None;
    let mut changed = false;

    if is_own(&request.uri) {
        let Some(last) = routes.pop() else {
            return Ok(RoutePreprocess::NoRouteForOwnUri);
        };
        let entry: RouteEntry = last.parse()?;
        new_uri = Some(entry.uri);
        changed = true;
    }

    let mut popped_own_route = false;
    if let Some(top) = routes.first() {
        let entry: RouteEntry = top.parse()?;
        if is_own(entry.uri()) {
            routes.remove(0);
            popped_own_route = true;
            changed = true;
        }
    }

    let restored_from_strict_route = new_uri.is_some();
    if let Some(uri) = new_uri {
        request.uri = uri;
    }
    if changed {
        request
            .headers
            .replace_instances(&HeaderName::Route, routes);
    }
    Ok(RoutePreprocess::Done {
        restored_from_strict_route,
        popped_own_route,
    })
}

/// Constructs Record-Route header for a proxy.
///
/// Per RFC 3261 Section 16.6, a proxy that wishes to stay in the
/// path must add a Record-Route header with its URI.
#[must_use]
pub fn create_record_route(proxy_uri: SipUri, loose_route: bool) -> RouteEntry {
    if loose_route {
        RouteEntry::loose(proxy_uri)
    } else {
        RouteEntry::new(proxy_uri)
    }
}

/// Parses a `NameAddr` from a Route/Record-Route header value.
///
/// # Errors
/// Returns an error if the value is not a valid name-addr.
pub fn parse_route_name_addr(value: &str) -> SipResult<NameAddr> {
    value.parse()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        let parts = split_list_bounded(header, MAX_LIST_ELEMENTS).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "<sip:p1.example.com;lr>");
        assert_eq!(parts[1], "<sip:p2.example.com;lr>");
    }

    #[test]
    fn test_split_header_list_with_quotes() {
        let header = "\"Name, Jr.\" <sip:p1.example.com;lr>, <sip:p2.example.com>";
        let parts = split_list_bounded(header, MAX_LIST_ELEMENTS).unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("Name, Jr."));
    }

    #[test]
    fn test_route_set_multibyte_display_name_regression() {
        // Used to panic: char index used to slice by byte.
        // (Route display names are not supported by RouteEntry; must not panic.)
        let header = "\"Ünïcödé\" <sip:p1.example.com;lr>, <sip:p2.example.com;lr>".to_string();
        let _ = RouteSet::from_route_headers(&[header]);
        let header = "<sip:p1.example.com;lr;n=Ünïcödé>, <sip:p2.example.com;lr>".to_string();
        // POAM-150: non-ASCII is not a legal paramchar (RFC 3261 §25.1);
        // rejected without panicking.
        assert!(RouteSet::from_route_headers(&[header]).is_err());
        let header = "<sip:p1.example.com;lr;n=%C3%9C>, <sip:p2.example.com;lr>".to_string();
        let set = RouteSet::from_route_headers(&[header]).unwrap();
        assert_eq!(set.len(), 2);
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

    fn hosts(set: &RouteSet) -> Vec<String> {
        set.iter().map(|e| e.host().to_string()).collect()
    }

    /// RFC 3261 §12.1.1 / §12.1.2 with a 3-hop Record-Route, as separate
    /// headers and as one comma list.
    #[test]
    fn route_set_order_uas_in_order_uac_reversed() {
        let separate = vec![
            "<sip:p1.example.com;lr>".to_string(),
            "<sip:p2.example.com;lr>".to_string(),
            "<sip:p3.example.com;lr>".to_string(),
        ];
        let joined = vec![
            "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>, <sip:p3.example.com;lr>".to_string(),
        ];
        let mixed = vec![
            "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>".to_string(),
            "<sip:p3.example.com;lr>".to_string(),
        ];
        for rr in [&separate, &joined, &mixed] {
            assert_eq!(
                hosts(&process_record_route_for_uas(rr).unwrap()),
                ["p1.example.com", "p2.example.com", "p3.example.com"]
            );
            assert_eq!(
                hosts(&process_record_route_for_uac(rr).unwrap()),
                ["p3.example.com", "p2.example.com", "p1.example.com"]
            );
        }
    }

    fn own(uri: &SipUri) -> bool {
        uri.user.is_none() && uri.host.eq_ignore_ascii_case("me.example.com")
    }

    fn req_with_routes(ruri: &str, routes: &[&str]) -> SipRequest {
        let mut req = SipRequest::new(crate::method::Method::Invite, ruri.parse().unwrap());
        for r in routes {
            req.headers.add_route(*r);
        }
        req
    }

    #[test]
    fn preprocess_strict_router_restores_last_route() {
        let mut req = req_with_routes(
            "sip:me.example.com",
            &["<sip:next.example.com;lr>", "<sip:bob@target.example.com>"],
        );
        let out = preprocess_route_information(&mut req, &own).unwrap();
        assert_eq!(
            out,
            RoutePreprocess::Done {
                restored_from_strict_route: true,
                popped_own_route: false
            }
        );
        assert_eq!(req.uri.host, "target.example.com");
        assert_eq!(req.headers.route_values(), ["<sip:next.example.com;lr>"]);
    }

    #[test]
    fn preprocess_strict_router_last_route_in_comma_list() {
        let mut req = req_with_routes(
            "sip:me.example.com",
            &["<sip:next.example.com;lr>, <sip:bob@target.example.com>"],
        );
        preprocess_route_information(&mut req, &own).unwrap();
        assert_eq!(req.uri.host, "target.example.com");
        assert_eq!(req.headers.route_values(), ["<sip:next.example.com;lr>"]);
    }

    #[test]
    fn preprocess_pops_own_top_route() {
        let mut req = req_with_routes(
            "sip:bob@target.example.com",
            &["<sip:me.example.com;lr>", "<sip:next.example.com;lr>"],
        );
        let out = preprocess_route_information(&mut req, &own).unwrap();
        assert_eq!(
            out,
            RoutePreprocess::Done {
                restored_from_strict_route: false,
                popped_own_route: true
            }
        );
        assert_eq!(req.uri.host, "target.example.com");
        assert_eq!(req.headers.route_values(), ["<sip:next.example.com;lr>"]);
    }

    #[test]
    fn preprocess_pops_own_top_route_inside_comma_list() {
        let mut req = req_with_routes(
            "sip:bob@target.example.com",
            &["<sip:me.example.com;lr>, <sip:next.example.com;lr>"],
        );
        preprocess_route_information(&mut req, &own).unwrap();
        assert_eq!(req.headers.route_values(), ["<sip:next.example.com;lr>"]);
    }

    #[test]
    fn preprocess_foreign_top_route_untouched() {
        let mut req = req_with_routes(
            "sip:bob@target.example.com",
            &["<sip:next.example.com;lr>, <sip:me.example.com;lr>"],
        );
        let out = preprocess_route_information(&mut req, &own).unwrap();
        assert_eq!(
            out,
            RoutePreprocess::Done {
                restored_from_strict_route: false,
                popped_own_route: false
            }
        );
        assert_eq!(req.headers.route_values().len(), 2);
    }

    #[test]
    fn preprocess_own_ruri_without_route() {
        let mut req = req_with_routes("sip:me.example.com", &[]);
        assert_eq!(
            preprocess_route_information(&mut req, &own).unwrap(),
            RoutePreprocess::NoRouteForOwnUri
        );
        assert_eq!(req.uri.host, "me.example.com");
    }

    #[test]
    fn preprocess_bad_route_is_error_and_request_unchanged() {
        let mut req = req_with_routes("sip:me.example.com", &["<sip:a.example.com;lr>", "<bad"]);
        assert!(preprocess_route_information(&mut req, &own).is_err());
        assert_eq!(req.uri.host, "me.example.com");
        assert_eq!(req.headers.count(&HeaderName::Route), 2);
    }
}
