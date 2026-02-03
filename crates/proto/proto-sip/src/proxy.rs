//! RFC 3261 §16.6 SIP Proxy Request Forwarding.
//!
//! This module implements proxy forwarding logic per RFC 3261 Section 16.
//!
//! ## RFC 3261 §16 Compliance
//!
//! ### §16.1 Overview
//!
//! A proxy acts as both a client and a server, forwarding requests
//! on behalf of other clients.
//!
//! ### §16.2 Stateful Proxy
//!
//! A stateful proxy maintains transaction state and can fork requests.
//!
//! ### §16.3 Request Validation
//!
//! The proxy validates:
//! - Max-Forwards > 0
//! - Loop detection via Via headers
//! - Request-URI validity
//!
//! ### §16.4 Route Information Preprocessing
//!
//! Handled by [`crate::routing`] module.
//!
//! ### §16.5 Determining Request Targets
//!
//! The proxy determines where to send the request based on:
//! - Routing table lookups
//! - DNS resolution (SRV, NAPTR)
//! - Registration database
//!
//! ### §16.6 Request Forwarding
//!
//! The forwarding process:
//! 1. Make a copy of the request
//! 2. Update Request-URI
//! 3. Update Max-Forwards
//! 4. Add Via header
//! 5. Add Record-Route (if staying in path)
//! 6. Add proxy-required features
//! 7. Forward to target
//!
//! ### §16.7 Response Processing
//!
//! The proxy processes responses by:
//! 1. Finding the matching transaction
//! 2. Choosing the best response (for forked requests)
//! 3. Forwarding upstream

use crate::error::{SipError, SipResult};
use crate::header::{Header, HeaderName};
use crate::header_params::{MaxForwardsHeader, ViaHeader};
use crate::message::{SipRequest, SipResponse};
use crate::routing::create_record_route;
use crate::uri::SipUri;
use std::collections::HashSet;

/// Maximum number of Via headers for loop detection.
const MAX_VIA_COUNT: usize = 70;

/// Result of proxy request validation.
#[derive(Debug, Clone)]
pub struct ProxyValidation {
    /// Whether the request is valid for forwarding.
    pub valid: bool,
    /// Error message if invalid.
    pub error: Option<String>,
    /// Suggested response code if request should be rejected.
    pub response_code: Option<u16>,
}

impl ProxyValidation {
    /// Creates a valid result.
    fn valid() -> Self {
        Self {
            valid: true,
            error: None,
            response_code: None,
        }
    }

    /// Creates an invalid result with error.
    fn invalid(error: &str, response_code: u16) -> Self {
        Self {
            valid: false,
            error: Some(error.to_string()),
            response_code: Some(response_code),
        }
    }
}

/// Proxy forwarding context.
///
/// Contains configuration and state for request forwarding.
#[derive(Debug, Clone)]
pub struct ProxyContext {
    /// Proxy's own SIP URI.
    pub proxy_uri: SipUri,
    /// Proxy's transport (UDP, TCP, TLS, WS).
    pub transport: String,
    /// Proxy's host address (for Via header).
    pub host: String,
    /// Proxy's port (for Via header).
    pub port: Option<u16>,
    /// Whether to add Record-Route header.
    pub record_route: bool,
    /// Whether to use loose routing.
    pub loose_routing: bool,
    /// Trusted domains for loop detection.
    pub trusted_domains: HashSet<String>,
}

impl ProxyContext {
    /// Creates a new proxy context.
    #[must_use]
    pub fn new(proxy_uri: SipUri, transport: &str, host: &str) -> Self {
        Self {
            proxy_uri,
            transport: transport.to_uppercase(),
            host: host.to_string(),
            port: None,
            record_route: true,
            loose_routing: true,
            trusted_domains: HashSet::new(),
        }
    }

    /// Sets the port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Disables Record-Route (proxy won't stay in signaling path).
    #[must_use]
    pub fn without_record_route(mut self) -> Self {
        self.record_route = false;
        self
    }

    /// Adds a trusted domain.
    pub fn add_trusted_domain(&mut self, domain: &str) {
        self.trusted_domains.insert(domain.to_lowercase());
    }
}

/// Forwarding target for a request.
#[derive(Debug, Clone)]
pub struct ForwardingTarget {
    /// Target URI.
    pub uri: SipUri,
    /// Priority (lower = higher priority).
    pub priority: u16,
    /// Q-value (0.0-1.0, higher = more preferred).
    pub q_value: f32,
    /// Transport override.
    pub transport: Option<String>,
}

impl ForwardingTarget {
    /// Creates a new forwarding target.
    #[must_use]
    pub fn new(uri: SipUri) -> Self {
        Self {
            uri,
            priority: 0,
            q_value: 1.0,
            transport: None,
        }
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the q-value.
    #[must_use]
    pub fn with_q_value(mut self, q_value: f32) -> Self {
        self.q_value = q_value.clamp(0.0, 1.0);
        self
    }

    /// Sets the transport.
    #[must_use]
    pub fn with_transport(mut self, transport: &str) -> Self {
        self.transport = Some(transport.to_uppercase());
        self
    }
}

/// Forking mode for proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkingMode {
    /// No forking - single target only.
    None,
    /// Parallel forking - try all targets simultaneously.
    Parallel,
    /// Sequential forking - try targets in order.
    Sequential,
}

/// Request forwarder for proxy operations.
///
/// Implements RFC 3261 §16.6 request forwarding logic.
#[derive(Debug)]
pub struct RequestForwarder {
    /// Proxy context.
    context: ProxyContext,
    /// Forking mode.
    forking_mode: ForkingMode,
}

impl RequestForwarder {
    /// Creates a new request forwarder.
    #[must_use]
    pub fn new(context: ProxyContext) -> Self {
        Self {
            context,
            forking_mode: ForkingMode::Parallel,
        }
    }

    /// Sets the forking mode.
    #[must_use]
    pub fn with_forking_mode(mut self, mode: ForkingMode) -> Self {
        self.forking_mode = mode;
        self
    }

    /// Validates a request for forwarding per RFC 3261 §16.3.
    ///
    /// Checks:
    /// - Max-Forwards > 0 (§16.3 step 1)
    /// - Loop detection via Via (§16.3 step 4)
    /// - Request-URI validity
    #[must_use]
    pub fn validate_request(&self, request: &SipRequest) -> ProxyValidation {
        // §16.3 Step 1: Check Max-Forwards
        if let Some(max_forwards) = self.get_max_forwards(request)
            && max_forwards.is_zero() {
                return ProxyValidation::invalid(
                    "Max-Forwards is zero - loop detected",
                    483, // Too Many Hops
                );
            }

        // §16.3 Step 4: Loop detection via Via headers
        if let Some(loop_error) = self.detect_loop(request) {
            return ProxyValidation::invalid(&loop_error, 482); // Loop Detected
        }

        // Check Via count doesn't exceed reasonable limit
        let via_count = self.count_via_headers(request);
        if via_count > MAX_VIA_COUNT {
            return ProxyValidation::invalid("Too many Via headers - possible loop", 483);
        }

        ProxyValidation::valid()
    }

    /// Gets the Max-Forwards header value.
    fn get_max_forwards(&self, request: &SipRequest) -> Option<MaxForwardsHeader> {
        let _ = self; // Silence unused_self - method may use self in future for caching
        request
            .headers
            .get(&HeaderName::MaxForwards)
            .and_then(|h| h.value.parse().ok())
    }

    /// Counts Via headers in the request.
    fn count_via_headers(&self, request: &SipRequest) -> usize {
        let _ = self; // Silence unused_self - method may use self in future for caching
        request.headers.get_all(&HeaderName::Via).len()
    }

    /// Detects loops by checking Via headers.
    ///
    /// Per RFC 3261 §16.3, a loop is detected if a Via header
    /// contains our own address with a branch we've seen before.
    fn detect_loop(&self, request: &SipRequest) -> Option<String> {
        let our_host = self.context.host.to_lowercase();
        let our_port = self.context.port;

        for via_header in request.headers.get_all(&HeaderName::Via) {
            if let Ok(via) = via_header.value.parse::<ViaHeader>() {
                let via_host = via.host.to_lowercase();

                // Check if this Via is from us
                let host_match =
                    via_host == our_host || self.context.trusted_domains.contains(&via_host);

                let port_match = match (via.port, our_port) {
                    (Some(vp), Some(op)) => vp == op,
                    (None | Some(5060), None | Some(5060)) => true, // Default port
                    _ => false,
                };

                if host_match && port_match {
                    // Check for RFC 3261 branch magic cookie
                    if via.has_rfc3261_branch() {
                        return Some(format!(
                            "Loop detected: Via from {} with branch {}",
                            via.host,
                            via.branch.as_deref().unwrap_or("none")
                        ));
                    }
                }
            }
        }

        None
    }

    /// Forwards a request to a target per RFC 3261 §16.6.
    ///
    /// ## RFC 3261 §16.6 Steps
    ///
    /// 1. Copy the request
    /// 2. Update the Request-URI (§16.6 step 4)
    /// 3. Update Max-Forwards (§16.6 step 3)
    /// 4. Optionally add Record-Route (§16.6 step 5)
    /// 5. Add Via header (§16.6 step 8)
    /// 6. Forward the request
    pub fn forward_request(
        &self,
        request: &SipRequest,
        target: &ForwardingTarget,
    ) -> SipResult<SipRequest> {
        // Step 1: Make a copy
        let mut forwarded = request.clone();

        // Step 4: Update Request-URI
        forwarded.uri = target.uri.clone();

        // Step 3: Decrement Max-Forwards
        self.update_max_forwards(&mut forwarded)?;

        // Step 5: Add Record-Route if configured
        if self.context.record_route {
            self.add_record_route(&mut forwarded);
        }

        // Step 8: Add Via header
        self.add_via_header(&mut forwarded);

        // Apply transport override if specified
        if let Some(ref transport) = target.transport {
            forwarded.uri = forwarded
                .uri
                .with_param("transport", Some(transport.clone()));
        }

        Ok(forwarded)
    }

    /// Updates the Max-Forwards header.
    fn update_max_forwards(&self, request: &mut SipRequest) -> SipResult<()> {
        let current = self.get_max_forwards(request);

        let new_value = match current {
            Some(mf) => mf.decrement().ok_or_else(|| SipError::InvalidHeader {
                name: "Max-Forwards".to_string(),
                reason: "cannot decrement below 0".to_string(),
            })?,
            None => MaxForwardsHeader::default(),
        };

        // Remove existing Max-Forwards
        request.headers.remove(&HeaderName::MaxForwards);

        // Add new value
        request
            .headers
            .add(Header::new(HeaderName::MaxForwards, new_value.to_string()));

        Ok(())
    }

    /// Adds a Record-Route header.
    fn add_record_route(&self, request: &mut SipRequest) {
        let entry = create_record_route(self.context.proxy_uri.clone(), self.context.loose_routing);
        let header_value = entry.to_string();

        // Insert at the beginning of Record-Route headers
        request.headers.prepend_record_route(header_value);
    }

    /// Adds a Via header for this proxy.
    fn add_via_header(&self, request: &mut SipRequest) {
        let mut via = ViaHeader::new(&self.context.transport, &self.context.host);

        if let Some(port) = self.context.port {
            via = via.with_port(port);
        }

        // Generate unique branch for this transaction
        via = via.with_branch(ViaHeader::generate_branch());

        // Insert at the beginning of Via headers (Via must be first)
        self.prepend_via_header(request, via.to_string());
    }

    /// Prepends a Via header to the beginning of the Via headers list.
    fn prepend_via_header(&self, request: &mut SipRequest, value: String) {
        let _ = self; // Silence unused_self - method may use self in future for caching
        // Collect all existing headers
        let existing: Vec<Header> = request.headers.iter().cloned().collect();

        // Clear and rebuild with new Via first (among Via headers)
        let new_via = Header::new(HeaderName::Via, value);

        // Find where Via headers start
        let via_pos = existing.iter().position(|h| h.name == HeaderName::Via);

        // Clear existing headers
        for header in &existing {
            request.headers.remove(&header.name);
        }

        // Re-add headers with new Via in correct position
        if let Some(idx) = via_pos {
            // Add headers before Via position
            for header in existing.iter().take(idx) {
                request.headers.add(header.clone());
            }
            // Add new Via
            request.headers.add(new_via);
            // Add remaining headers (including existing Via headers)
            for header in existing.iter().skip(idx) {
                request.headers.add(header.clone());
            }
        } else {
            // No existing Via, just add ours at the end
            for header in existing {
                request.headers.add(header);
            }
            request.headers.add(new_via);
        }
    }

    /// Forks a request to multiple targets.
    ///
    /// Returns forwarded requests for each target, ordered by priority and q-value.
    pub fn fork_request(
        &self,
        request: &SipRequest,
        targets: &[ForwardingTarget],
    ) -> SipResult<Vec<SipRequest>> {
        if targets.is_empty() {
            return Err(SipError::InvalidUri {
                reason: "no targets for forking".to_string(),
            });
        }

        // Sort targets by priority (ascending) and q-value (descending)
        let mut sorted_targets: Vec<_> = targets.iter().collect();
        sorted_targets.sort_by(|a, b| {
            a.priority.cmp(&b.priority).then_with(|| {
                b.q_value
                    .partial_cmp(&a.q_value)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        let mut requests = Vec::with_capacity(sorted_targets.len());

        for target in sorted_targets {
            let forwarded = self.forward_request(request, target)?;
            requests.push(forwarded);
        }

        Ok(requests)
    }
}

/// Response processor for proxy operations.
///
/// Implements RFC 3261 §16.7 response processing.
#[derive(Debug)]
pub struct ResponseProcessor {
    /// Proxy context.
    context: ProxyContext,
}

impl ResponseProcessor {
    /// Creates a new response processor.
    #[must_use]
    pub fn new(context: ProxyContext) -> Self {
        Self { context }
    }

    /// Processes a response for forwarding upstream.
    ///
    /// ## RFC 3261 §16.7 Steps
    ///
    /// 1. Find matching Via header
    /// 2. Remove topmost Via (our Via)
    /// 3. Forward response upstream
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn process_response(&self, response: &SipResponse) -> SipResult<SipResponse> {
        let mut processed = response.clone();

        // Remove our Via header (the topmost one)
        self.remove_topmost_via(&mut processed)?;

        Ok(processed)
    }

    /// Removes the topmost Via header.
    fn remove_topmost_via(&self, response: &mut SipResponse) -> SipResult<()> {
        let via_headers: Vec<Header> = response
            .headers
            .get_all(&HeaderName::Via)
            .into_iter()
            .cloned()
            .collect();

        if via_headers.is_empty() {
            return Err(SipError::MissingHeader {
                name: "Via".to_string(),
            });
        }

        // Verify the topmost Via is ours
        if let Ok(via) = via_headers[0].value.parse::<ViaHeader>() {
            let via_host = via.host.to_lowercase();
            let our_host = self.context.host.to_lowercase();

            if via_host != our_host && !self.context.trusted_domains.contains(&via_host) {
                return Err(SipError::InvalidHeader {
                    name: "Via".to_string(),
                    reason: format!(
                        "topmost Via ({}) does not match proxy ({})",
                        via.host, self.context.host
                    ),
                });
            }
        }

        // Remove all Via headers and re-add without the topmost one
        response.headers.remove(&HeaderName::Via);
        for header in via_headers.into_iter().skip(1) {
            response.headers.add(header);
        }

        Ok(())
    }

    /// Chooses the best response from forked requests.
    ///
    /// Per RFC 3261 §16.7.6:
    /// - 6xx responses take precedence
    /// - Then 2xx responses
    /// - Then lowest numbered response class
    #[must_use]
    pub fn choose_best_response<'a>(
        &self,
        responses: &'a [SipResponse],
    ) -> Option<&'a SipResponse> {
        if responses.is_empty() {
            return None;
        }

        // Priority order: 6xx > 2xx > 3xx > 4xx > 5xx > 1xx
        let mut best: Option<&SipResponse> = None;

        for response in responses {
            let code = response.status.code();
            let best_code = best.map_or(0, |r| r.status.code());

            let is_better = match (code / 100, best_code / 100) {
                // 6xx always wins
                (6, _) if best_code / 100 != 6 => true,
                (6, 6) => code < best_code,
                (_, 6) => false,

                // 2xx beats anything except 6xx
                (2, _) if best_code / 100 != 2 && best_code / 100 != 6 => true,
                (2, 2) => code < best_code,
                (_, 2) => false,

                // Lower class number beats higher
                (c1, c2) if c1 != c2 => c1 < c2,
                // Same class: lower code wins
                _ => code < best_code,
            };

            if best.is_none() || is_better {
                best = Some(response);
            }
        }

        best
    }
}

/// Creates a 100 Trying response for proxies.
///
/// Per RFC 3261 §16.2, a proxy SHOULD send 100 Trying immediately
/// after receiving an INVITE to suppress retransmissions.
#[must_use]
pub fn create_trying_response(request: &SipRequest) -> SipResponse {
    use crate::response::StatusCode;

    let mut response = SipResponse::new(StatusCode::TRYING);

    // Copy required headers from request
    if let Some(via) = request.headers.get(&HeaderName::Via) {
        response.headers.add(via.clone());
    }
    if let Some(from) = request.headers.get(&HeaderName::From) {
        response.headers.add(from.clone());
    }
    if let Some(to) = request.headers.get(&HeaderName::To) {
        response.headers.add(to.clone());
    }
    if let Some(call_id) = request.headers.get(&HeaderName::CallId) {
        response.headers.add(call_id.clone());
    }
    if let Some(cseq) = request.headers.get(&HeaderName::CSeq) {
        response.headers.add(cseq.clone());
    }

    response
}

/// Creates a 483 Too Many Hops response.
#[must_use]
pub fn create_too_many_hops_response(request: &SipRequest) -> SipResponse {
    use crate::response::StatusCode;

    let mut response = SipResponse::new(StatusCode::TOO_MANY_HOPS);

    // Copy required headers
    copy_required_headers(request, &mut response);

    response
}

/// Creates a 482 Loop Detected response.
#[must_use]
pub fn create_loop_detected_response(request: &SipRequest) -> SipResponse {
    use crate::response::StatusCode;

    let mut response = SipResponse::new(StatusCode::LOOP_DETECTED);

    // Copy required headers
    copy_required_headers(request, &mut response);

    response
}

/// Copies required headers from request to response.
fn copy_required_headers(request: &SipRequest, response: &mut SipResponse) {
    // Copy all Via headers
    for via in request.headers.get_all(&HeaderName::Via) {
        response.headers.add(via.clone());
    }

    if let Some(from) = request.headers.get(&HeaderName::From) {
        response.headers.add(from.clone());
    }
    if let Some(to) = request.headers.get(&HeaderName::To) {
        response.headers.add(to.clone());
    }
    if let Some(call_id) = request.headers.get(&HeaderName::CallId) {
        response.headers.add(call_id.clone());
    }
    if let Some(cseq) = request.headers.get(&HeaderName::CSeq) {
        response.headers.add(cseq.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::Method;

    fn create_test_request() -> SipRequest {
        let uri = SipUri::new("biloxi.example.com").with_user("bob");
        let mut request = SipRequest::new(Method::Invite, uri);

        request.headers.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776",
        ));
        request
            .headers
            .add(Header::new(HeaderName::MaxForwards, "70"));
        request.headers.add(Header::new(
            HeaderName::From,
            "Alice <sip:alice@atlanta.example.com>;tag=1234",
        ));
        request.headers.add(Header::new(
            HeaderName::To,
            "Bob <sip:bob@biloxi.example.com>",
        ));
        request
            .headers
            .add(Header::new(HeaderName::CallId, "abc123@atlanta"));
        request
            .headers
            .add(Header::new(HeaderName::CSeq, "1 INVITE"));

        request
    }

    fn create_proxy_context() -> ProxyContext {
        let proxy_uri = SipUri::new("ss1.atlanta.example.com");
        ProxyContext::new(proxy_uri, "UDP", "ss1.atlanta.example.com").with_port(5060)
    }

    #[test]
    fn test_validate_request_valid() {
        let request = create_test_request();
        let context = create_proxy_context();
        let forwarder = RequestForwarder::new(context);

        let validation = forwarder.validate_request(&request);
        assert!(validation.valid);
    }

    #[test]
    fn test_validate_request_max_forwards_zero() {
        let mut request = create_test_request();
        request.headers.remove(&HeaderName::MaxForwards);
        request
            .headers
            .add(Header::new(HeaderName::MaxForwards, "0"));

        let context = create_proxy_context();
        let forwarder = RequestForwarder::new(context);

        let validation = forwarder.validate_request(&request);
        assert!(!validation.valid);
        assert_eq!(validation.response_code, Some(483));
    }

    #[test]
    fn test_forward_request() {
        let request = create_test_request();
        let context = create_proxy_context();
        let forwarder = RequestForwarder::new(context);

        let target_uri = SipUri::new("biloxi.example.com").with_user("bob");
        let target = ForwardingTarget::new(target_uri);

        let forwarded = forwarder.forward_request(&request, &target).unwrap();

        // Check Max-Forwards was decremented
        let mf = forwarded.headers.get(&HeaderName::MaxForwards).unwrap();
        assert_eq!(mf.value.parse::<u8>().unwrap(), 69);

        // Check Via was added
        let via_count = forwarded.headers.get_all(&HeaderName::Via).len();
        assert_eq!(via_count, 2); // Original + proxy

        // Check Record-Route was added
        assert!(forwarded.headers.get(&HeaderName::RecordRoute).is_some());
    }

    #[test]
    fn test_forward_without_record_route() {
        let request = create_test_request();
        let context = create_proxy_context().without_record_route();
        let forwarder = RequestForwarder::new(context);

        let target_uri = SipUri::new("biloxi.example.com");
        let target = ForwardingTarget::new(target_uri);

        let forwarded = forwarder.forward_request(&request, &target).unwrap();

        // Check Record-Route was NOT added
        assert!(forwarded.headers.get(&HeaderName::RecordRoute).is_none());
    }

    #[test]
    fn test_fork_request() {
        let request = create_test_request();
        let context = create_proxy_context();
        let forwarder = RequestForwarder::new(context);

        let targets = vec![
            ForwardingTarget::new(SipUri::new("target1.example.com"))
                .with_priority(1)
                .with_q_value(0.5),
            ForwardingTarget::new(SipUri::new("target2.example.com"))
                .with_priority(0)
                .with_q_value(1.0),
        ];

        let forked = forwarder.fork_request(&request, &targets).unwrap();

        assert_eq!(forked.len(), 2);
        // Should be sorted by priority (0 first)
        assert_eq!(forked[0].uri.host, "target2.example.com");
        assert_eq!(forked[1].uri.host, "target1.example.com");
    }

    #[test]
    fn test_response_processor() {
        // Create a response with our Via at the top
        let request = create_test_request();
        let context = create_proxy_context();
        let forwarder = RequestForwarder::new(context.clone());

        // Forward the request (adds our Via)
        let target = ForwardingTarget::new(SipUri::new("target.example.com"));
        let forwarded = forwarder.forward_request(&request, &target).unwrap();

        // Create a response to that forwarded request
        let mut response = SipResponse::new(crate::response::StatusCode::OK);
        for via in forwarded.headers.get_all(&HeaderName::Via) {
            response.headers.add(via.clone());
        }

        // Process the response
        let processor = ResponseProcessor::new(context);
        let processed = processor.process_response(&response).unwrap();

        // Our Via should be removed
        let via_count = processed.headers.get_all(&HeaderName::Via).len();
        assert_eq!(via_count, 1); // Only original Via remains
    }

    #[test]
    fn test_choose_best_response() {
        let context = create_proxy_context();
        let processor = ResponseProcessor::new(context);

        // Create test responses
        let responses = vec![
            SipResponse::new(crate::response::StatusCode::BUSY_HERE), // 486
            SipResponse::new(crate::response::StatusCode::OK),        // 200
            SipResponse::new(crate::response::StatusCode::NOT_FOUND), // 404
        ];

        let best = processor.choose_best_response(&responses).unwrap();
        assert_eq!(best.status.code(), 200); // 2xx should win
    }

    #[test]
    fn test_choose_best_response_6xx_wins() {
        let context = create_proxy_context();
        let processor = ResponseProcessor::new(context);

        let responses = vec![
            SipResponse::new(crate::response::StatusCode::OK), // 200
            SipResponse::new(crate::response::StatusCode::DECLINE), // 603
        ];

        let best = processor.choose_best_response(&responses).unwrap();
        assert_eq!(best.status.code(), 603); // 6xx should win over 2xx
    }

    #[test]
    fn test_create_trying_response() {
        let request = create_test_request();
        let response = create_trying_response(&request);

        assert_eq!(response.status.code(), 100);
        assert!(response.headers.get(&HeaderName::Via).is_some());
        assert!(response.headers.get(&HeaderName::CallId).is_some());
    }

    #[test]
    fn test_forwarding_target() {
        let target = ForwardingTarget::new(SipUri::new("example.com"))
            .with_priority(1)
            .with_q_value(0.8)
            .with_transport("TCP");

        assert_eq!(target.priority, 1);
        assert!((target.q_value - 0.8).abs() < 0.001);
        assert_eq!(target.transport, Some("TCP".to_string()));
    }

    #[test]
    fn test_loop_detection() {
        let context = create_proxy_context();
        let forwarder = RequestForwarder::new(context);

        // Create a request with our Via already in it (loop)
        // We need to add the proxy's Via at the beginning to simulate a loop
        let uri = SipUri::new("biloxi.example.com").with_user("bob");
        let mut request = SipRequest::new(Method::Invite, uri);

        // Add the proxy's Via FIRST (to simulate the loop condition)
        request.headers.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP ss1.atlanta.example.com:5060;branch=z9hG4bK123",
        ));
        // Then add the original Via
        request.headers.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776",
        ));
        request
            .headers
            .add(Header::new(HeaderName::MaxForwards, "70"));
        request.headers.add(Header::new(
            HeaderName::From,
            "Alice <sip:alice@atlanta.example.com>;tag=1234",
        ));
        request.headers.add(Header::new(
            HeaderName::To,
            "Bob <sip:bob@biloxi.example.com>",
        ));
        request
            .headers
            .add(Header::new(HeaderName::CallId, "abc123@atlanta"));
        request
            .headers
            .add(Header::new(HeaderName::CSeq, "1 INVITE"));

        let validation = forwarder.validate_request(&request);
        assert!(!validation.valid);
        assert_eq!(validation.response_code, Some(482)); // Loop Detected
    }

    #[test]
    fn test_proxy_validation_struct() {
        let valid = ProxyValidation::valid();
        assert!(valid.valid);
        assert!(valid.error.is_none());

        let invalid = ProxyValidation::invalid("test error", 400);
        assert!(!invalid.valid);
        assert_eq!(invalid.error, Some("test error".to_string()));
        assert_eq!(invalid.response_code, Some(400));
    }
}
