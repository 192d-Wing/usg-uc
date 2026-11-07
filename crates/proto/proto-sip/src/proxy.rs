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
//! [`crate::routing::preprocess_route_information`] with
//! [`ProxyContext::is_own`]. It is a separate step; the caller runs, in order:
//!
//! 1. [`compute_loop_hash`] on the request **as received**;
//! 2. [`RequestForwarder::validate_request`] (§16.3, loop/spiral check);
//! 3. `preprocess_route_information` (§16.4);
//! 4. target selection (§16.5), including ACL and dial-plan checks;
//! 5. [`RequestForwarder::forward_request_with_loop_hash`] /
//!    [`RequestForwarder::fork_request_with_loop_hash`] with the hash from
//!    step 1, so the branch reflects the request before translation
//!    (§16.6 step 8).
//!
//! # Security
//!
//! Step 3 can replace the Request-URI with the sender-supplied last Route
//! value (§16.4 strict-route restore). ACL, dial-plan and routing policy
//! MUST therefore run on the post-preprocessing Request-URI (step 4), never
//! on the Request-URI as received. NIST 800-53 Rev5: AC-4, SC-7.
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

use crate::MAX_LIST_ELEMENTS;
use crate::error::{SipError, SipResult};
use crate::header::{Header, HeaderName};
use crate::header_params::{MaxForwardsHeader, ViaHeader};
use crate::list::split_list_bounded;
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
    /// Trusted peer domains. Used only to accept a topmost Via on responses;
    /// it is **not** consulted for loop detection ("trusted" is not "me").
    pub trusted_domains: HashSet<String>,
    /// Additional URIs this proxy places in Record-Route (aliases, other
    /// listeners). `proxy_uri` is always treated as ours.
    pub own_uris: Vec<SipUri>,
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
            own_uris: Vec::new(),
        }
    }

    /// Adds a URI this proxy places in Record-Route (RFC 3261 §16.4).
    #[must_use]
    pub fn with_own_uri(mut self, uri: SipUri) -> Self {
        self.own_uris.push(uri);
        self
    }

    /// Returns true if `uri` is one this proxy placed in Record-Route
    /// (RFC 3261 §16.4).
    ///
    /// Matches `proxy_uri` or any `own_uris` entry on: equal user part (so
    /// `sip:bob@<our-host>` is not ours), case-insensitive host, effective
    /// port (5060, or 5061 for `sips:`/`transport=tls`), and `transport` when
    /// both URIs carry one.
    #[must_use]
    pub fn is_own(&self, uri: &SipUri) -> bool {
        std::iter::once(&self.proxy_uri)
            .chain(self.own_uris.iter())
            .any(|own| uri_matches_own(uri, own))
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

/// Effective port of a URI for "is this us" checks.
fn effective_port(uri: &SipUri) -> u16 {
    uri.port.unwrap_or_else(|| {
        if uri.scheme == crate::uri::UriScheme::Sips
            || uri
                .transport()
                .is_some_and(|t| t.eq_ignore_ascii_case("tls"))
        {
            crate::DEFAULT_SIPS_PORT
        } else {
            crate::DEFAULT_SIP_PORT
        }
    })
}

/// See [`ProxyContext::is_own`].
fn uri_matches_own(uri: &SipUri, own: &SipUri) -> bool {
    uri.user == own.user
        && uri.host.eq_ignore_ascii_case(&own.host)
        && effective_port(uri) == effective_port(own)
        && match (uri.transport(), own.transport()) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => true,
        }
}

/// Separator for the loop-hash suffix in branches this proxy emits:
/// `z9hG4bK{rand16hex}.{loophash16hex}`.
const LOOP_HASH_SEP: char = '.';

/// Computes the RFC 3261 §16.6 step 8 loop hash of a request **as received**
/// (before §16.4 preprocessing or Request-URI translation).
///
/// Input fields, NUL-separated, in this order: Request-URI, To tag, From tag,
/// Call-ID, `CSeq` sequence number, every Route value, every Proxy-Require
/// value, every Proxy-Authorization value. If one of them changes when the
/// request comes back, that is a spiral, not a loop (§16.3 item 4).
///
/// The topmost Via suggested by §16.6 step 8 is deliberately **not** hashed:
/// on a real loop the topmost Via is the previous hop's, never the one first
/// received, so hashing it would classify every loop as a spiral.
///
/// FNV-1a 64 is deterministic across nodes and builds. It is not a security
/// boundary: a collision only misclassifies a loop as a spiral, which
/// Max-Forwards (483) still bounds. NIST 800-53 Rev5: SC-5.
#[must_use]
pub fn compute_loop_hash(request: &SipRequest) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for b in bytes.iter().chain(std::iter::once(&0u8)) {
            h ^= u64::from(*b);
            h = h.wrapping_mul(PRIME);
        }
    };
    feed(request.uri.to_string().as_bytes());
    feed(request.headers.to_tag().unwrap_or_default().as_bytes());
    feed(request.headers.from_tag().unwrap_or_default().as_bytes());
    feed(
        request
            .headers
            .call_id()
            .unwrap_or_default()
            .trim()
            .as_bytes(),
    );
    let cseq_num = request
        .headers
        .cseq_parsed()
        .map(|c| c.sequence.to_string())
        .unwrap_or_default();
    feed(cseq_num.as_bytes());
    for name in [
        HeaderName::Route,
        HeaderName::ProxyRequire,
        HeaderName::ProxyAuthorization,
    ] {
        for hdr in request.headers.get_all(&name) {
            feed(hdr.value.trim().as_bytes());
        }
    }
    h
}

/// Extracts the loop hash from a branch emitted by [`RequestForwarder`].
fn branch_loop_hash(branch: &str) -> Option<u64> {
    let rest = branch.strip_prefix(crate::header_params::VIA_BRANCH_MAGIC_COOKIE)?;
    let (_, suffix) = rest.rsplit_once(LOOP_HASH_SEP)?;
    if suffix.len() != 16 {
        return None;
    }
    u64::from_str_radix(suffix, 16).ok()
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
            && max_forwards.is_zero()
        {
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
        request.headers.get_all(&HeaderName::Via).count()
    }

    /// Returns true if a Via sent-by is this proxy's (host + port).
    fn is_our_via(&self, via: &ViaHeader) -> bool {
        let port_match = match (via.port, self.context.port) {
            (Some(vp), Some(op)) => vp == op,
            (None | Some(crate::DEFAULT_SIP_PORT), None | Some(crate::DEFAULT_SIP_PORT)) => true,
            _ => false,
        };
        port_match && via.host.eq_ignore_ascii_case(&self.context.host)
    }

    /// RFC 3261 §16.3 item 4: loop detection that allows spirals.
    ///
    /// For every Via value (all header instances, comma lists split) whose
    /// sent-by is ours, the loop hash in its branch is compared with the
    /// hash of the incoming request. Equal means a loop (482); different
    /// means a spiral (allowed; Max-Forwards still bounds it). A Via of ours
    /// whose branch carries no loop hash is treated as a loop (fail closed).
    /// `trusted_domains` is not consulted: a trusted peer is not this proxy.
    fn detect_loop(&self, request: &SipRequest) -> Option<String> {
        let mut current: Option<u64> = None;
        for via in request.headers.via_all_parsed() {
            if !self.is_our_via(&via) {
                continue;
            }
            let hash = *current.get_or_insert_with(|| compute_loop_hash(request));
            match via.branch.as_deref().and_then(branch_loop_hash) {
                Some(h) if h != hash => {}
                Some(_) => {
                    return Some(format!(
                        "Loop detected: request returned unchanged via {}",
                        via.host
                    ));
                }
                None => {
                    return Some(format!(
                        "Loop detected: own Via from {} without loop hash",
                        via.host
                    ));
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
    ///
    /// # Errors
    ///
    /// Returns an error if request forwarding fails.
    pub fn forward_request(
        &self,
        request: &SipRequest,
        target: &ForwardingTarget,
    ) -> SipResult<SipRequest> {
        self.forward_request_with_loop_hash(request, target, compute_loop_hash(request))
    }

    /// Like [`Self::forward_request`], with the loop hash computed by the
    /// caller from the request as received (before §16.4 preprocessing).
    ///
    /// # Errors
    ///
    /// Returns an error if Max-Forwards cannot be decremented or the CSPRNG
    /// fails.
    pub fn forward_request_with_loop_hash(
        &self,
        request: &SipRequest,
        target: &ForwardingTarget,
        loop_hash: u64,
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
        self.add_via_header(&mut forwarded, loop_hash)?;

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
    ///
    /// RFC 3261 §16.6 step 8: branch = `z9hG4bK{rand16hex}.{loophash16hex}`.
    /// The random part keeps each fork unique; the loop hash lets §16.3
    /// tell a spiral from a loop.
    fn add_via_header(&self, request: &mut SipRequest, loop_hash: u64) -> SipResult<()> {
        let mut via = ViaHeader::new(&self.context.transport, &self.context.host);

        if let Some(port) = self.context.port {
            via = via.with_port(port);
        }

        let mut rand = [0u8; 8];
        getrandom::fill(&mut rand).map_err(|e| SipError::InvalidHeader {
            name: "Via".to_string(),
            reason: format!("CSPRNG failure: {e}"),
        })?;
        let branch = format!(
            "{}{:016x}{LOOP_HASH_SEP}{loop_hash:016x}",
            crate::header_params::VIA_BRANCH_MAGIC_COOKIE,
            u64::from_be_bytes(rand)
        );
        via = via.with_branch(branch);

        // Insert at the beginning of Via headers (Via must be first)
        self.prepend_via_header(request, via.to_string());
        Ok(())
    }

    /// Prepends a Via header to the beginning of the Via headers list.
    ///
    /// RFC 3261 §16.6 step 8: the proxy inserts its Via before the
    /// existing values. One O(n) insert; the order of every other header
    /// is preserved.
    ///
    /// NIST 800-53 Rev5: SC-5 - replaces an O(n²) clone/remove rebuild.
    fn prepend_via_header(&self, request: &mut SipRequest, value: String) {
        let _ = self; // Silence unused_self - method may use self in future for caching
        match request.headers.position(&HeaderName::Via) {
            Some(idx) => request
                .headers
                .insert(idx, Header::new(HeaderName::Via, value)),
            // No existing Via: keep the previous behaviour (append).
            None => request.headers.add(Header::new(HeaderName::Via, value)),
        }
    }

    /// Forks a request to multiple targets.
    ///
    /// Returns forwarded requests for each target, ordered by priority and q-value.
    ///
    /// # Errors
    ///
    /// Returns an error if request forking fails.
    pub fn fork_request(
        &self,
        request: &SipRequest,
        targets: &[ForwardingTarget],
    ) -> SipResult<Vec<SipRequest>> {
        self.fork_request_with_loop_hash(request, targets, compute_loop_hash(request))
    }

    /// Like [`Self::fork_request`], with a caller-supplied loop hash. Every
    /// branch gets a unique random part and the same loop hash.
    ///
    /// # Errors
    ///
    /// Returns an error if there are no targets or forwarding fails.
    pub fn fork_request_with_loop_hash(
        &self,
        request: &SipRequest,
        targets: &[ForwardingTarget],
        loop_hash: u64,
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
            let forwarded = self.forward_request_with_loop_hash(request, target, loop_hash)?;
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
    ///
    /// RFC 3261 §16.7 step 3: remove the topmost Via *value*. If the first
    /// Via field carries a combined list (`Via: a, b`, §7.3.1) only its
    /// first element is removed. Header order is preserved.
    fn remove_topmost_via(&self, response: &mut SipResponse) -> SipResult<()> {
        let idx =
            response
                .headers
                .position(&HeaderName::Via)
                .ok_or_else(|| SipError::MissingHeader {
                    name: "Via".to_string(),
                })?;
        // Validate before mutating so an error leaves the response intact.
        let value = response
            .headers
            .get_value(&HeaderName::Via)
            .unwrap_or_default()
            .to_string();
        let elements = split_list_bounded(&value, MAX_LIST_ELEMENTS)?;
        let Some((topmost, rest)) = elements.split_first() else {
            return Err(SipError::InvalidHeader {
                name: "Via".to_string(),
                reason: "empty Via".to_string(),
            });
        };

        // Verify the topmost Via is ours
        if let Ok(via) = topmost.parse::<ViaHeader>() {
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

        let _ = response.headers.remove_first(&HeaderName::Via);
        if !rest.is_empty() {
            response
                .headers
                .insert(idx, Header::new(HeaderName::Via, rest.join(", ")));
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
/// RFC 3261 §16.2 / §8.2.6.2: copies **all** Via header fields in order
/// (combined lists preserved), From, To (no tag is added), Call-ID and `CSeq`.
/// RFC 3261 §8.2.6.1: a Timestamp in the request MUST be copied (no delay
/// value is added). `Content-Length: 0` is set.
#[must_use]
pub fn create_trying_response(request: &SipRequest) -> SipResponse {
    use crate::response::StatusCode;

    let mut response = SipResponse::new(StatusCode::TRYING);
    copy_required_headers(request, &mut response);
    if let Some(ts) = request.headers.get(&HeaderName::Timestamp) {
        response.headers.add(ts.clone());
    }
    response
        .headers
        .add(Header::new(HeaderName::ContentLength, "0"));
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
#[allow(clippy::similar_names, clippy::unwrap_used, clippy::expect_used)]
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
        let via_count = forwarded.headers.get_all(&HeaderName::Via).count();
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
        let via_count = processed.headers.get_all(&HeaderName::Via).count();
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

        // Our Via with a legacy branch (no loop hash): fail closed, 482.
        let validation = forwarder.validate_request(&request);
        assert!(!validation.valid);
        assert_eq!(validation.response_code, Some(482)); // Loop Detected
    }

    /// Simulates the request coming back to us after `forwarded` went out
    /// via another proxy.
    fn returned(forwarded: &SipRequest) -> SipRequest {
        let mut back = forwarded.clone();
        let idx = back.headers.position(&HeaderName::Via).unwrap();
        back.headers.insert(
            idx,
            Header::new(
                HeaderName::Via,
                "SIP/2.0/UDP other.example.net;branch=z9hG4bKother",
            ),
        );
        back
    }

    #[test]
    fn same_request_back_is_loop() {
        let forwarder = RequestForwarder::new(create_proxy_context());
        let request = create_test_request();
        let target = ForwardingTarget::new(request.uri.clone());
        let fwd = forwarder.forward_request(&request, &target).unwrap();
        let v = forwarder.validate_request(&returned(&fwd));
        assert_eq!(v.response_code, Some(482), "{v:?}");
    }

    #[test]
    fn spiral_with_changed_ruri_allowed() {
        let forwarder = RequestForwarder::new(create_proxy_context());
        let request = create_test_request();
        let target = ForwardingTarget::new(SipUri::new("biloxi.example.com").with_user("bob2"));
        let fwd = forwarder.forward_request(&request, &target).unwrap();
        let v = forwarder.validate_request(&returned(&fwd));
        assert!(v.valid, "{v:?}");
    }

    #[test]
    fn spiral_with_changed_cseq_allowed() {
        let forwarder = RequestForwarder::new(create_proxy_context());
        let request = create_test_request();
        let target = ForwardingTarget::new(request.uri.clone());
        let fwd = forwarder.forward_request(&request, &target).unwrap();
        let mut back = returned(&fwd);
        back.headers.set(HeaderName::CSeq, "2 INVITE");
        assert!(forwarder.validate_request(&back).valid);
    }

    #[test]
    fn own_via_inside_comma_list_detected() {
        let forwarder = RequestForwarder::new(create_proxy_context());
        let request = create_test_request();
        let target = ForwardingTarget::new(request.uri.clone());
        let fwd = forwarder.forward_request(&request, &target).unwrap();
        let mut back = fwd.clone();
        let vias: Vec<String> = back
            .headers
            .get_all(&HeaderName::Via)
            .map(|h| h.value.clone())
            .collect();
        back.headers.replace_instances(
            &HeaderName::Via,
            vec![format!(
                "SIP/2.0/UDP other.example.net;branch=z9hG4bKx, {}",
                vias.join(", ")
            )],
        );
        assert_eq!(forwarder.validate_request(&back).response_code, Some(482));
    }

    #[test]
    fn foreign_via_with_same_branch_ignored() {
        let forwarder = RequestForwarder::new(create_proxy_context());
        let request = create_test_request();
        let target = ForwardingTarget::new(request.uri.clone());
        let fwd = forwarder.forward_request(&request, &target).unwrap();
        let branch = fwd.headers.via_branch().unwrap();
        let mut back = request.clone();
        back.headers.insert(
            0,
            Header::new(
                HeaderName::Via,
                format!("SIP/2.0/UDP elsewhere.example.net;branch={branch}"),
            ),
        );
        assert!(forwarder.validate_request(&back).valid);
    }

    #[test]
    fn trusted_domain_via_is_not_us() {
        let mut ctx = create_proxy_context();
        ctx.add_trusted_domain("pc33.atlanta.example.com");
        let forwarder = RequestForwarder::new(ctx);
        // pc33's legacy branch would be a "loop" if trusted meant "us".
        assert!(forwarder.validate_request(&create_test_request()).valid);
    }

    #[test]
    fn fork_branches_unique_with_shared_loop_hash() {
        let forwarder = RequestForwarder::new(create_proxy_context());
        let request = create_test_request();
        let targets = vec![
            ForwardingTarget::new(SipUri::new("t1.example.com")),
            ForwardingTarget::new(SipUri::new("t2.example.com")),
        ];
        let forks = forwarder.fork_request(&request, &targets).unwrap();
        let branches: Vec<String> = forks
            .iter()
            .map(|r| r.headers.via_branch().unwrap())
            .collect();
        assert_ne!(branches[0], branches[1]);
        let hashes: Vec<u64> = branches
            .iter()
            .map(|b| branch_loop_hash(b).unwrap())
            .collect();
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(hashes[0], compute_loop_hash(&request));
    }

    #[test]
    fn trying_from_parsed_wire_with_separate_via_lines() {
        let raw = "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP p1.example.com;branch=z9hG4bK1\r\n\
            Via: SIP/2.0/TCP p2.example.com;branch=z9hG4bK2;received=192.0.2.2\r\n\
            Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK3\r\n\
            Max-Forwards: 70\r\n\
            From: Alice <sip:alice@atlanta.example.com>;tag=1234\r\n\
            To: Bob <sip:bob@biloxi.example.com>\r\n\
            Call-ID: abc123@atlanta\r\n\
            CSeq: 7 INVITE\r\n\
            Timestamp: 1.5 0.25\r\n\
            Content-Length: 0\r\n\r\n";
        let request = match crate::message::SipMessage::parse(raw.as_bytes()).unwrap() {
            crate::message::SipMessage::Request(r) => r,
            crate::message::SipMessage::Response(_) => unreachable!(),
        };
        let response = create_trying_response(&request);
        let vias: Vec<&str> = response
            .headers
            .get_all(&HeaderName::Via)
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(vias.len(), 3);
        assert!(vias[0].contains("p1.example.com"));
        assert!(vias[1].contains("received=192.0.2.2"));
        assert!(vias[2].contains("pc33.atlanta"));
        assert_eq!(
            response.headers.get_value(&HeaderName::Timestamp),
            Some("1.5 0.25")
        );
        assert_eq!(
            response.headers.get_value(&HeaderName::CSeq),
            Some("7 INVITE")
        );
        assert_eq!(
            response.headers.get_value(&HeaderName::CallId),
            Some("abc123@atlanta")
        );
        assert_eq!(response.headers.to_tag(), None);
        assert_eq!(
            response.headers.get_value(&HeaderName::ContentLength),
            Some("0")
        );

        // No Timestamp in the request means none in the 100.
        let mut no_ts = request.clone();
        no_ts.headers.remove(&HeaderName::Timestamp);
        assert_eq!(
            create_trying_response(&no_ts)
                .headers
                .get_value(&HeaderName::Timestamp),
            None
        );
    }

    #[test]
    fn trying_copies_all_vias_and_timestamp() {
        let mut request = create_test_request();
        request.headers.insert(
            0,
            Header::new(HeaderName::Via, "SIP/2.0/UDP a.example.com;branch=z9hG4bKa"),
        );
        request.headers.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP b.example.com;branch=z9hG4bKb, SIP/2.0/UDP c.example.com;branch=z9hG4bKc",
        ));
        request
            .headers
            .add(Header::new(HeaderName::Timestamp, "54.21"));
        let response = create_trying_response(&request);
        let req_vias: Vec<&str> = request
            .headers
            .get_all(&HeaderName::Via)
            .map(|h| h.value.as_str())
            .collect();
        let resp_vias: Vec<&str> = response
            .headers
            .get_all(&HeaderName::Via)
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(req_vias, resp_vias);
        assert_eq!(resp_vias.len(), 3);
        assert_eq!(
            response.headers.get_value(&HeaderName::Timestamp),
            Some("54.21")
        );
        assert_eq!(response.headers.to_tag(), None);
        assert_eq!(
            response.headers.get_value(&HeaderName::ContentLength),
            Some("0")
        );
    }

    #[test]
    fn is_own_matching() {
        let ctx = ProxyContext::new(
            "sip:ss1.atlanta.example.com;lr".parse().unwrap(),
            "UDP",
            "ss1.atlanta.example.com",
        )
        .with_own_uri("sips:alias.example.com".parse().unwrap());
        assert!(ctx.is_own(&"sip:SS1.atlanta.example.com:5060".parse().unwrap()));
        assert!(ctx.is_own(&"sip:alias.example.com:5061;transport=tls".parse().unwrap()));
        assert!(!ctx.is_own(&"sip:bob@ss1.atlanta.example.com".parse().unwrap()));
        assert!(!ctx.is_own(&"sip:ss1.atlanta.example.com:5070".parse().unwrap()));
        assert!(!ctx.is_own(&"sip:alias.example.com".parse().unwrap()));
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn loop_hash_deterministic(user in "[a-z]{1,10}", call_id in "[a-z0-9]{1,20}", seq in 1u32..) {
                let mut r = create_test_request();
                r.uri = SipUri::new("example.com").with_user(user);
                r.headers.set(HeaderName::CallId, call_id);
                r.headers.set(HeaderName::CSeq, format!("{seq} INVITE"));
                prop_assert_eq!(compute_loop_hash(&r), compute_loop_hash(&r.clone()));
            }
        }
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
