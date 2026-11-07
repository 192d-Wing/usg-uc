//! Topology hiding for SIP messages.
//!
//! This module provides mechanisms to hide internal network topology from
//! external entities per RFC 3323 (Privacy Mechanism) and related security
//! best practices.
//!
//! ## Features
//!
//! - Via header stripping and anonymization
//! - Contact header anonymization
//! - Record-Route manipulation
//! - Call-ID obfuscation
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Core (§16.6 - Request Forwarding)
//! - **RFC 3323**: A Privacy Mechanism for SIP
//! - **RFC 3325**: Private Extensions to SIP for Asserted Identity
//!
//! ## Security Benefits
//!
//! - Prevents internal IP address disclosure
//! - Hides network topology from external parties
//! - Protects against targeted attacks on internal infrastructure

use crate::cidr::{IpCidr, normalize};
use crate::error::{SipError, SipResult};
use crate::header::{HeaderName, Headers};
use crate::header_params::{NameAddr, ViaHeader};
use crate::list::split_list_bounded;
use crate::uri::{SipUri, UriScheme};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::IpAddr;

/// Topology hiding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TopologyHidingMode {
    /// No topology hiding (pass-through).
    None,
    /// Basic hiding - replace internal (configured CIDR / domain) addresses
    /// with the external address. Best effort: public hostnames are left
    /// alone.
    #[default]
    Basic,
    /// Aggressive hiding - every host that is not `external_host` is hidden.
    /// Recommended.
    Aggressive,
}

impl fmt::Display for TopologyHidingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Basic => write!(f, "basic"),
            Self::Aggressive => write!(f, "aggressive"),
        }
    }
}

/// Built-in internal / special-purpose prefixes (RFC 1918, RFC 6598
/// 100.64/10, RFC 6890 loopback / link-local / benchmarking, RFC 4193 ULA,
/// RFC 4291 §2.5.6 link-local).
pub const DEFAULT_INTERNAL_CIDRS: [&str; 12] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// Built-in internal DNS suffixes (matched on a label boundary).
pub const DEFAULT_INTERNAL_DOMAINS: [&str; 5] =
    ["localhost", "local", "internal", "lan", "home.arpa"];

/// Default bound for the Call-ID obfuscation map (NIST 800-53 Rev5: SC-5).
pub const DEFAULT_MAX_CALL_ID_MAPPINGS: usize = 65_536;

/// Default external port for TLS (`transport=tls` / `sips:`) rewrites.
pub const DEFAULT_EXTERNAL_TLS_PORT: u16 = 5061;

fn default_cidrs() -> Vec<IpCidr> {
    DEFAULT_INTERNAL_CIDRS
        .iter()
        .filter_map(|c| c.parse().ok())
        .collect()
}

/// Configuration for topology hiding.
#[derive(Debug, Clone)]
pub struct TopologyHidingConfig {
    /// Hiding mode.
    pub mode: TopologyHidingMode,
    /// External/public hostname to use for anonymization.
    pub external_host: String,
    /// External port (None means use default port).
    pub external_port: Option<u16>,
    /// External port used when the rewritten element is TLS
    /// (`transport=tls`, `sips:`, Via `TLS`), so the return path is not
    /// pointed at a cleartext port (RFC 3261 §26.2, NIST 800-53 Rev5: SC-8).
    pub external_tls_port: u16,
    /// Domain to use for anonymized URIs.
    pub anonymization_domain: String,
    /// Whether to obfuscate Call-ID.
    pub obfuscate_call_id: bool,
    /// Whether to hide Via received/rport parameters.
    pub hide_via_params: bool,
    /// Internal IP prefixes.
    pub internal_cidrs: Vec<IpCidr>,
    /// Internal DNS domains (a host matches `d` or `*.d`).
    pub internal_domains: Vec<String>,
    /// Maximum number of Call-ID mappings kept (FIFO eviction).
    pub max_call_id_mappings: usize,
}

impl Default for TopologyHidingConfig {
    fn default() -> Self {
        Self {
            mode: TopologyHidingMode::Basic,
            external_host: "proxy.example.com".to_string(),
            external_port: None,
            external_tls_port: DEFAULT_EXTERNAL_TLS_PORT,
            anonymization_domain: "anonymous.invalid".to_string(),
            obfuscate_call_id: true,
            hide_via_params: true,
            internal_cidrs: default_cidrs(),
            internal_domains: DEFAULT_INTERNAL_DOMAINS
                .iter()
                .map(|d| (*d).to_string())
                .collect(),
            max_call_id_mappings: DEFAULT_MAX_CALL_ID_MAPPINGS,
        }
    }
}

/// Strips `[...]` and an IPv6 zone id (`%eth0`) from a host.
fn bare_host(host: &str) -> &str {
    let h = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match h.split_once('%') {
        Some((a, _)) if a.contains(':') => a,
        _ => h,
    }
}

impl TopologyHidingConfig {
    /// Creates a new configuration with the given external host.
    #[must_use]
    pub fn new(external_host: impl Into<String>) -> Self {
        Self {
            external_host: external_host.into(),
            ..Default::default()
        }
    }

    /// Sets the hiding mode.
    #[must_use]
    pub fn with_mode(mut self, mode: TopologyHidingMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the external port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.external_port = Some(port);
        self
    }

    /// Sets the external TLS port.
    #[must_use]
    pub fn with_tls_port(mut self, port: u16) -> Self {
        self.external_tls_port = port;
        self
    }

    /// Sets the anonymization domain.
    #[must_use]
    pub fn with_anonymization_domain(mut self, domain: impl Into<String>) -> Self {
        self.anonymization_domain = domain.into();
        self
    }

    /// Sets Call-ID obfuscation.
    #[must_use]
    pub fn with_call_id_obfuscation(mut self, enabled: bool) -> Self {
        self.obfuscate_call_id = enabled;
        self
    }

    /// Adds an internal network in CIDR notation (`10.0.0.0/8`, `fd00::/8`).
    ///
    /// # Errors
    /// Returns an error if `cidr` is not a valid prefix.
    pub fn try_with_internal_network(mut self, cidr: &str) -> SipResult<Self> {
        self.internal_cidrs.push(cidr.parse()?);
        Ok(self)
    }

    /// Adds an internal network prefix.
    #[must_use]
    pub fn with_internal_cidr(mut self, cidr: IpCidr) -> Self {
        self.internal_cidrs.push(cidr);
        self
    }

    /// Adds an internal DNS domain.
    #[must_use]
    pub fn with_internal_domain(mut self, domain: impl Into<String>) -> Self {
        self.internal_domains.push(domain.into());
        self
    }

    /// Sets the Call-ID map bound (minimum 1).
    #[must_use]
    pub fn with_max_call_id_mappings(mut self, max: usize) -> Self {
        self.max_call_id_mappings = max.max(1);
        self
    }

    /// Checks if an address is considered internal.
    ///
    /// IP literals (optionally bracketed, with zone id) are matched against
    /// `internal_cidrs` (IPv4-mapped IPv6 is normalised first); hostnames
    /// match `internal_domains` on a label boundary only, so
    /// `10.example.com` is never "internal" because of `10.0.0.0/8`.
    ///
    /// POAM: POA&M-151. NIST 800-53 Rev5: SC-7.
    #[must_use]
    pub fn is_internal_address(&self, host: &str) -> bool {
        let h = bare_host(host);
        if let Ok(ip) = h.parse::<IpAddr>() {
            let ip = normalize(ip);
            return self.internal_cidrs.iter().any(|c| c.contains(ip));
        }
        let h = h.strip_suffix('.').unwrap_or(h);
        self.internal_domains.iter().any(|d| {
            let d = d.trim_start_matches('.');
            let d = d.strip_suffix('.').unwrap_or(d);
            !d.is_empty()
                && (h.eq_ignore_ascii_case(d)
                    || (h.len() > d.len()
                        && h.as_bytes()[h.len() - d.len() - 1] == b'.'
                        && h[h.len() - d.len()..].eq_ignore_ascii_case(d)))
        })
    }

    /// Returns true if `host` must be hidden under the current mode.
    #[must_use]
    pub fn should_hide(&self, host: &str) -> bool {
        match self.mode {
            TopologyHidingMode::None => false,
            TopologyHidingMode::Basic => self.is_internal_address(host),
            TopologyHidingMode::Aggressive => {
                !bare_host(host).eq_ignore_ascii_case(bare_host(&self.external_host))
            }
        }
    }

    fn port_for(&self, tls: bool) -> Option<u16> {
        if tls {
            Some(self.external_tls_port)
        } else {
            self.external_port
        }
    }
}

fn topo_err(header: &HeaderName, reason: &'static str) -> SipError {
    SipError::TopologyHiding {
        header: header.as_str().to_string(),
        reason,
    }
}

/// Splits every instance of `name` into list elements (RFC 3261 §7.3.1:
/// comma-folded values are equivalent to separate instances). Fails closed.
fn elements(headers: &Headers, name: &HeaderName) -> SipResult<Vec<String>> {
    let mut out = Vec::new();
    for h in headers.get_all(name) {
        let parts = split_list_bounded(&h.value, crate::MAX_LIST_ELEMENTS)
            .map_err(|_| topo_err(name, "unsplittable list"))?;
        out.extend(parts.into_iter().map(str::to_string));
        if out.len() > crate::MAX_LIST_ELEMENTS {
            return Err(topo_err(name, "too many elements"));
        }
    }
    Ok(out)
}

fn parse_vias(headers: &Headers) -> SipResult<Vec<ViaHeader>> {
    elements(headers, &HeaderName::Via)?
        .iter()
        .map(|v| {
            v.parse::<ViaHeader>()
                .map_err(|_| topo_err(&HeaderName::Via, "unparseable element"))
        })
        .collect()
}

fn uri_is_tls(uri: &SipUri) -> bool {
    uri.scheme == UriScheme::Sips
        || uri
            .transport()
            .is_some_and(|t| t.eq_ignore_ascii_case("tls"))
}

fn via_is_tls(via: &ViaHeader) -> bool {
    via.transport.eq_ignore_ascii_case("tls") || via.transport.eq_ignore_ascii_case("wss")
}

/// Bounded, insertion-ordered Call-ID mapping.
#[derive(Debug, Clone, Default)]
struct CallIdMap {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
    order: VecDeque<String>,
}

/// Topology hider for SIP messages.
///
/// Provides methods to anonymize and hide internal topology information
/// from SIP messages before forwarding to external parties. Every rewrite
/// is applied to all instances and all comma-folded elements of a header,
/// and fails closed (`SipError::TopologyHiding`, headers unchanged) if an
/// element cannot be parsed.
#[derive(Debug, Clone)]
pub struct TopologyHider {
    /// Configuration.
    config: TopologyHidingConfig,
    /// Call-ID mapping (bounded, FIFO).
    call_ids: CallIdMap,
}

impl TopologyHider {
    /// Creates a new topology hider with the given configuration.
    #[must_use]
    pub fn new(config: TopologyHidingConfig) -> Self {
        Self {
            config,
            call_ids: CallIdMap::default(),
        }
    }

    /// Creates a topology hider with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(TopologyHidingConfig::default())
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &TopologyHidingConfig {
        &self.config
    }

    // =========================================================================
    // Via Header Manipulation
    // =========================================================================

    /// Strips Via headers that must be hidden under the current mode.
    ///
    /// # RFC 3261 §16.6
    ///
    /// The proxy MUST strip its own Via header from the response. For topology
    /// hiding, we additionally strip Via headers that reveal internal addresses.
    #[must_use]
    pub fn strip_internal_vias(&self, vias: &[ViaHeader]) -> Vec<ViaHeader> {
        vias.iter()
            .filter(|via| !self.config.should_hide(&via.host))
            .cloned()
            .collect()
    }

    /// Clears `received` / `rport` / `maddr` values that disclose topology.
    fn scrub_via_params(&self, via: &mut ViaHeader, host_hidden: bool) {
        if !self.config.hide_via_params {
            return;
        }
        if via
            .received
            .as_ref()
            .is_some_and(|r| host_hidden || self.config.should_hide(r))
        {
            via.received = None;
        }
        if host_hidden {
            via.rport = None;
        }
        if via
            .maddr
            .as_ref()
            .is_some_and(|m| host_hidden || self.config.should_hide(m))
        {
            via.maddr = None;
        }
    }

    /// Anonymizes a Via header by replacing internal addresses.
    ///
    /// Returns None if the Via should be stripped entirely (Aggressive mode).
    #[must_use]
    pub fn anonymize_via(&self, via: &ViaHeader) -> Option<ViaHeader> {
        if self.config.mode == TopologyHidingMode::None {
            return Some(via.clone());
        }
        let hide = self.config.should_hide(&via.host);
        if hide && self.config.mode == TopologyHidingMode::Aggressive {
            return None;
        }
        let mut anonymized = via.clone();
        if hide {
            anonymized.host.clone_from(&self.config.external_host);
            anonymized.port = self.config.port_for(via_is_tls(via));
        }
        self.scrub_via_params(&mut anonymized, hide);
        Some(anonymized)
    }

    /// Rewrites Via headers for an outbound (proxied) request: prepends the
    /// proxy's Via and anonymizes or strips every existing Via element.
    ///
    /// # Errors
    /// [`SipError::TopologyHiding`] if an existing Via element cannot be
    /// parsed; `headers` is left unchanged.
    pub fn rewrite_vias_for_outbound(
        &self,
        headers: &mut Headers,
        proxy_via: &ViaHeader,
    ) -> SipResult<()> {
        let mut out = vec![proxy_via.to_string()];
        if self.config.mode == TopologyHidingMode::None {
            out.extend(headers.get_all(&HeaderName::Via).map(|h| h.value.clone()));
        } else {
            for via in &parse_vias(headers)? {
                if let Some(a) = self.anonymize_via(via) {
                    out.push(a.to_string());
                }
            }
        }
        headers.replace_instances(&HeaderName::Via, out);
        Ok(())
    }

    /// Rewrites Via headers in a header collection for inbound responses.
    ///
    /// This removes the topmost Via (proxy's own) and anonymizes the rest.
    ///
    /// # Errors
    /// Returns an error if there is no Via or one cannot be parsed
    /// (fail closed, `headers` unchanged).
    pub fn rewrite_vias_for_inbound(&self, headers: &mut Headers) -> SipResult<ViaHeader> {
        let vias = parse_vias(headers)?;
        let Some((proxy_via, rest)) = vias.split_first() else {
            return Err(SipError::ParseError {
                reason: "no Via headers in response".to_string(),
            });
        };
        let out = rest
            .iter()
            .filter_map(|v| self.anonymize_via(v))
            .map(|v| v.to_string())
            .collect();
        headers.replace_instances(&HeaderName::Via, out);
        Ok(proxy_via.clone())
    }

    // =========================================================================
    // Contact Header Anonymization
    // =========================================================================

    /// Anonymizes a Contact header by replacing the URI.
    ///
    /// The rewritten URI keeps the scheme, user and the `transport`, `lr`
    /// and `ob` parameters (so `transport=tls` / `sips:` survive - RFC 3261
    /// §26.2, NIST 800-53 Rev5: SC-8) and drops everything else (`maddr`,
    /// `received`, unknown parameters may carry addresses). Header-level
    /// parameters (`expires`, `q`, `+sip.instance`, ...) are preserved.
    #[must_use]
    pub fn anonymize_contact(&self, contact: &NameAddr) -> NameAddr {
        if self.config.mode == TopologyHidingMode::None {
            return contact.clone();
        }
        let mut anonymized = contact.clone();
        let uri = &contact.uri;
        let hide = self.config.should_hide(&uri.host)
            || uri.maddr().is_some_and(|m| self.config.should_hide(m));
        if hide {
            let mut anon_uri = SipUri::new(&self.config.external_host);
            anon_uri.scheme = uri.scheme;
            anon_uri.user.clone_from(&uri.user);
            anon_uri.port = self.config.port_for(uri_is_tls(uri));
            anon_uri.params = uri
                .params
                .iter()
                .filter(|(n, _)| {
                    ["transport", "lr", "ob"]
                        .iter()
                        .any(|k| k.eq_ignore_ascii_case(n))
                })
                .cloned()
                .collect();
            anonymized.uri = anon_uri;
        }
        if self.config.mode == TopologyHidingMode::Aggressive {
            anonymized.display_name = None;
        }
        anonymized
    }

    fn rewritten_contacts(&self, headers: &Headers) -> SipResult<Vec<String>> {
        elements(headers, &HeaderName::Contact)?
            .into_iter()
            .map(|e| {
                // RFC 3261 §10.2.2: REGISTER wildcard passes through.
                if e.trim() == "*" {
                    return Ok(e);
                }
                let na: NameAddr = e
                    .parse()
                    .map_err(|_| topo_err(&HeaderName::Contact, "unparseable element"))?;
                Ok(self.anonymize_contact(&na).to_string())
            })
            .collect()
    }

    /// Rewrites every Contact element (all instances, comma-folded values).
    ///
    /// # Errors
    /// [`SipError::TopologyHiding`] if an element cannot be parsed;
    /// `headers` is left unchanged.
    pub fn rewrite_contacts(&self, headers: &mut Headers) -> SipResult<()> {
        if self.config.mode == TopologyHidingMode::None || !headers.contains(&HeaderName::Contact) {
            return Ok(());
        }
        let out = self.rewritten_contacts(headers)?;
        headers.replace_instances(&HeaderName::Contact, out);
        Ok(())
    }

    // =========================================================================
    // Record-Route Manipulation
    // =========================================================================

    /// Creates an anonymized Record-Route header value.
    ///
    /// Returns a Record-Route URI that uses the external address.
    #[must_use]
    pub fn create_anonymized_record_route(&self, transport: Option<&str>) -> String {
        let mut uri = SipUri::new(&self.config.external_host);
        uri.scheme = UriScheme::Sip;
        let tls = transport.is_some_and(|t| t.eq_ignore_ascii_case("tls"));
        uri.port = self.config.port_for(tls);
        // Add lr parameter for loose routing per RFC 3261
        uri.params.push(("lr".to_string(), None));

        if let Some(t) = transport {
            uri.params
                .push(("transport".to_string(), Some(t.to_string())));
        }

        format!("<{uri}>")
    }

    /// Rewrites every Record-Route element that must be hidden. Each
    /// replaced element keeps its own `transport` (falling back to
    /// `transport`); others are kept verbatim.
    ///
    /// # Errors
    /// [`SipError::TopologyHiding`] if an element cannot be parsed;
    /// `headers` is left unchanged.
    pub fn rewrite_record_routes(
        &self,
        headers: &mut Headers,
        transport: Option<&str>,
    ) -> SipResult<()> {
        if self.config.mode == TopologyHidingMode::None
            || !headers.contains(&HeaderName::RecordRoute)
        {
            return Ok(());
        }
        let out = elements(headers, &HeaderName::RecordRoute)?
            .into_iter()
            .map(|e| {
                let na: NameAddr = e
                    .parse()
                    .map_err(|_| topo_err(&HeaderName::RecordRoute, "unparseable element"))?;
                let hide = self.config.should_hide(&na.uri.host)
                    || na.uri.maddr().is_some_and(|m| self.config.should_hide(m));
                if !hide {
                    return Ok(e);
                }
                let t = na.uri.transport().or(transport);
                let t = if na.uri.scheme == UriScheme::Sips {
                    Some("tls")
                } else {
                    t
                };
                Ok(self.create_anonymized_record_route(t))
            })
            .collect::<SipResult<Vec<_>>>()?;
        headers.replace_instances(&HeaderName::RecordRoute, out);
        Ok(())
    }

    // =========================================================================
    // Call-ID Obfuscation
    // =========================================================================

    /// Generates a random obfuscated Call-ID (128-bit token).
    ///
    /// POAM: POA&M-151 - was an unkeyed `DefaultHasher` of the original, which
    /// let an observer confirm a guessed Call-ID and link calls.
    /// NIST 800-53 Rev5: SC-30 (Concealment and Misdirection).
    fn generate_obfuscated_call_id(&self) -> SipResult<String> {
        use fmt::Write as _;
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| topo_err(&HeaderName::CallId, "entropy unavailable"))?;
        let mut out = String::with_capacity(33 + self.config.anonymization_domain.len());
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
        out.push('@');
        out.push_str(&self.config.anonymization_domain);
        Ok(out)
    }

    /// Obfuscates a Call-ID.
    ///
    /// Returns the obfuscated version and stores the mapping for reverse
    /// lookup. The map holds at most `max_call_id_mappings` entries; the
    /// oldest is evicted first (NIST 800-53 Rev5: SC-5).
    ///
    /// # Errors
    /// [`SipError::TopologyHiding`] if the OS CSPRNG is unavailable.
    pub fn obfuscate_call_id(&mut self, original: &str) -> SipResult<String> {
        if self.config.mode == TopologyHidingMode::None || !self.config.obfuscate_call_id {
            return Ok(original.to_string());
        }
        if let Some(obfuscated) = self.call_ids.forward.get(original) {
            return Ok(obfuscated.clone());
        }
        let mut obfuscated = self.generate_obfuscated_call_id()?;
        while self.call_ids.reverse.contains_key(&obfuscated) {
            obfuscated = self.generate_obfuscated_call_id()?;
        }
        let max = self.config.max_call_id_mappings.max(1);
        while self.call_ids.order.len() >= max {
            if let Some(old) = self.call_ids.order.pop_front()
                && let Some(obf) = self.call_ids.forward.remove(&old)
            {
                self.call_ids.reverse.remove(&obf);
            }
        }
        self.call_ids
            .forward
            .insert(original.to_string(), obfuscated.clone());
        self.call_ids
            .reverse
            .insert(obfuscated.clone(), original.to_string());
        self.call_ids.order.push_back(original.to_string());
        Ok(obfuscated)
    }

    /// Restores an original Call-ID from an obfuscated one.
    ///
    /// Returns None if the Call-ID was not previously obfuscated by this
    /// hider (or has been evicted).
    #[must_use]
    pub fn restore_call_id(&self, obfuscated: &str) -> Option<String> {
        self.call_ids.reverse.get(obfuscated).cloned()
    }

    /// Rewrites the Call-ID header in a header collection.
    ///
    /// # Errors
    /// See [`obfuscate_call_id`](Self::obfuscate_call_id).
    pub fn rewrite_call_id(&mut self, headers: &mut Headers) -> SipResult<()> {
        if self.config.mode == TopologyHidingMode::None || !self.config.obfuscate_call_id {
            return Ok(());
        }
        if let Some(call_id) = headers.get(&HeaderName::CallId) {
            let obfuscated = self.obfuscate_call_id(&call_id.value)?;
            headers.set(HeaderName::CallId, obfuscated);
        }
        Ok(())
    }

    /// Restores the original Call-ID header in a header collection.
    pub fn restore_call_id_header(&self, headers: &mut Headers) {
        if self.config.mode == TopologyHidingMode::None || !self.config.obfuscate_call_id {
            return;
        }

        if let Some(call_id) = headers.get(&HeaderName::CallId)
            && let Some(original) = self.restore_call_id(&call_id.value)
        {
            headers.set(HeaderName::CallId, original);
        }
    }

    // =========================================================================
    // Complete Message Processing
    // =========================================================================

    /// Applies all topology hiding transformations to outbound request
    /// headers. Atomic: on error `headers` is unchanged.
    ///
    /// POAM: POA&M-157 - proxy model only: stripped/rewritten Vias are not
    /// stored, so responses cannot be routed back to internal hops
    /// (RFC 3261 §16.7 step 3, §18.2.2). Requires stateful Via restoration
    /// (keyed by branch) before any proxy-mode caller is wired; the SBC
    /// uses [`hide_b2bua_request`](Self::hide_b2bua_request) only.
    ///
    /// # Errors
    /// [`SipError::TopologyHiding`] (fail closed - do not forward).
    pub fn hide_outbound_request(
        &mut self,
        headers: &mut Headers,
        proxy_via: &ViaHeader,
    ) -> SipResult<()> {
        let mut work = headers.clone();
        self.rewrite_vias_for_outbound(&mut work, proxy_via)?;
        if self.config.mode != TopologyHidingMode::None {
            self.rewrite_contacts(&mut work)?;
            self.rewrite_call_id(&mut work)?;
        }
        // Note: Record-Route is typically added by the proxy, not rewritten here
        *headers = work;
        Ok(())
    }

    /// Applies topology hiding to a **B2BUA-originated** outbound request.
    ///
    /// Unlike [`hide_outbound_request`](Self::hide_outbound_request) (the proxy
    /// model — it strips internal *intermediate* Via headers and prepends the
    /// proxy's own), a B2BUA regenerates each leg and emits a **single
    /// self-generated Via and Contact** already bearing the SBC's address. This
    /// anonymizes those in place — replacing a hidden host with
    /// `external_host` **without ever removing a Via** (which would make
    /// the request invalid) — and anonymizes every Contact element.
    ///
    /// The Call-ID is intentionally left untouched: the B2BUA already emits a
    /// freshly generated per-leg Call-ID (so the internal party's Call-ID is
    /// never disclosed), and that value is the dialog's correlation key —
    /// rewriting the header here would desynchronize response correlation.
    ///
    /// Intended for the outbound leg that crosses to an untrusted (outside)
    /// zone, so the internal signaling address is not disclosed to carriers.
    ///
    /// # Errors
    /// [`SipError::TopologyHiding`] if any Via/Contact/Record-Route element
    /// cannot be parsed (POA&M-151: fail closed, never forward unhidden);
    /// `headers` is left unchanged.
    pub fn hide_b2bua_request(&self, headers: &mut Headers) -> SipResult<()> {
        if self.config.mode == TopologyHidingMode::None {
            return Ok(());
        }
        let mut work = headers.clone();
        if work.contains(&HeaderName::Via) {
            let out = parse_vias(&work)?
                .into_iter()
                .map(|via| {
                    let hide = self.config.should_hide(&via.host);
                    let mut anonymized = via.clone();
                    if hide {
                        anonymized.host.clone_from(&self.config.external_host);
                        anonymized.port = self.config.port_for(via_is_tls(&via));
                    }
                    self.scrub_via_params(&mut anonymized, hide);
                    anonymized.to_string()
                })
                .collect();
            work.replace_instances(&HeaderName::Via, out);
        }
        self.rewrite_contacts(&mut work)?;
        self.rewrite_record_routes(&mut work, None)?;
        *headers = work;
        Ok(())
    }

    /// Applies all topology hiding transformations to inbound response
    /// headers. Atomic: on error `headers` is unchanged.
    ///
    /// # Errors
    /// Returns an error if a Via/Contact element cannot be parsed.
    pub fn hide_inbound_response(&mut self, headers: &mut Headers) -> SipResult<ViaHeader> {
        let mut work = headers.clone();
        let proxy_via = self.rewrite_vias_for_inbound(&mut work)?;
        if self.config.mode != TopologyHidingMode::None {
            self.rewrite_contacts(&mut work)?;
            // Don't rewrite Call-ID on responses - use restore instead
            self.restore_call_id_header(&mut work);
        }
        *headers = work;
        Ok(proxy_via)
    }

    /// Returns the number of stored Call-ID mappings.
    #[must_use]
    pub fn call_id_mapping_count(&self) -> usize {
        self.call_ids.forward.len()
    }

    /// Clears all Call-ID mappings.
    pub fn clear_call_id_mappings(&mut self) {
        self.call_ids = CallIdMap::default();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::header::Header;

    #[test]
    fn test_topology_hiding_mode_display() {
        assert_eq!(TopologyHidingMode::None.to_string(), "none");
        assert_eq!(TopologyHidingMode::Basic.to_string(), "basic");
        assert_eq!(TopologyHidingMode::Aggressive.to_string(), "aggressive");
    }

    #[test]
    fn test_config_internal_address_detection() {
        let config = TopologyHidingConfig::default();

        // RFC 1918 private addresses should be detected
        assert!(config.is_internal_address("10.0.0.1"));
        assert!(config.is_internal_address("10.255.255.255"));
        assert!(config.is_internal_address("172.16.0.1"));
        assert!(config.is_internal_address("172.31.255.255"));
        assert!(config.is_internal_address("192.168.1.100"));
        assert!(config.is_internal_address("192.168.0.1"));

        // Public addresses should not be detected
        assert!(!config.is_internal_address("8.8.8.8"));
        assert!(!config.is_internal_address("203.0.113.1"));
        assert!(!config.is_internal_address("proxy.example.com"));
    }

    #[test]
    fn test_config_builder() {
        let config = TopologyHidingConfig::new("edge.example.com")
            .with_mode(TopologyHidingMode::Aggressive)
            .with_port(5060)
            .with_call_id_obfuscation(false)
            .try_with_internal_network("203.0.113.0/24")
            .unwrap();

        assert_eq!(config.external_host, "edge.example.com");
        assert_eq!(config.mode, TopologyHidingMode::Aggressive);
        assert_eq!(config.external_port, Some(5060));
        assert!(!config.obfuscate_call_id);
        assert!(config.is_internal_address("203.0.113.9"));
    }

    #[test]
    fn test_via_anonymization_basic() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let internal_via = ViaHeader::new("UDP", "192.168.1.100")
            .with_port(5060)
            .with_branch("z9hG4bK123456".to_string());

        let anonymized = hider.anonymize_via(&internal_via);
        assert!(anonymized.is_some());
        let anon = anonymized.unwrap();
        assert_eq!(anon.host, "proxy.example.com");
        assert_eq!(anon.branch, Some("z9hG4bK123456".to_string()));
    }

    #[test]
    fn test_via_anonymization_aggressive() {
        let config = TopologyHidingConfig::new("proxy.example.com")
            .with_mode(TopologyHidingMode::Aggressive);
        let hider = TopologyHider::new(config);

        let internal_via = ViaHeader::new("UDP", "192.168.1.100").with_port(5060);

        // Internal Via should be stripped entirely in aggressive mode
        let anonymized = hider.anonymize_via(&internal_via);
        assert!(anonymized.is_none());

        // POAM-151: Aggressive hides every host that is not external_host.
        let external_via = ViaHeader::new("UDP", "203.0.113.1");
        assert!(hider.anonymize_via(&external_via).is_none());
        let own_via = ViaHeader::new("UDP", "proxy.example.com");
        assert!(hider.anonymize_via(&own_via).is_some());
    }

    #[test]
    fn test_via_no_hiding() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::None);
        let hider = TopologyHider::new(config);

        let internal_via = ViaHeader::new("UDP", "192.168.1.100");

        let anonymized = hider.anonymize_via(&internal_via);
        assert!(anonymized.is_some());
        let anon = anonymized.unwrap();
        assert_eq!(anon.host, "192.168.1.100"); // Should remain unchanged
    }

    #[test]
    fn test_strip_internal_vias() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let vias = vec![
            ViaHeader::new("UDP", "192.168.1.100"), // Internal
            ViaHeader::new("UDP", "10.0.0.1"),      // Internal
            ViaHeader::new("UDP", "203.0.113.1"),   // External
        ];

        let stripped = hider.strip_internal_vias(&vias);
        assert_eq!(stripped.len(), 1);
        assert_eq!(stripped[0].host, "203.0.113.1");
    }

    #[test]
    fn test_contact_anonymization() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let uri = SipUri::new("192.168.1.100");
        let contact = NameAddr::new(uri.clone()).with_display_name("Alice");

        let anonymized = hider.anonymize_contact(&contact);
        assert_eq!(anonymized.uri.host, "proxy.example.com");
        assert_eq!(anonymized.display_name, Some("Alice".to_string())); // Preserved in basic mode
    }

    #[test]
    fn test_contact_anonymization_aggressive() {
        let config = TopologyHidingConfig::new("proxy.example.com")
            .with_mode(TopologyHidingMode::Aggressive);
        let hider = TopologyHider::new(config);

        let uri = SipUri::new("192.168.1.100");
        let contact = NameAddr::new(uri).with_display_name("Alice");

        let anonymized = hider.anonymize_contact(&contact);
        assert_eq!(anonymized.uri.host, "proxy.example.com");
        assert!(anonymized.display_name.is_none()); // Removed in aggressive mode
    }

    #[test]
    fn test_call_id_obfuscation() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::Basic);
        let mut hider = TopologyHider::new(config);

        let original = "abc123@192.168.1.100";
        let obfuscated = hider.obfuscate_call_id(original).unwrap();

        // Should be different from original
        assert_ne!(obfuscated, original);
        // Should end with anonymization domain
        assert!(obfuscated.ends_with("@anonymous.invalid"));

        // Same input should give same output
        let obfuscated2 = hider.obfuscate_call_id(original).unwrap();
        assert_eq!(obfuscated, obfuscated2);

        // Should be able to restore
        let restored = hider.restore_call_id(&obfuscated);
        assert_eq!(restored, Some(original.to_string()));
    }

    #[test]
    fn test_call_id_no_obfuscation() {
        let config =
            TopologyHidingConfig::new("proxy.example.com").with_mode(TopologyHidingMode::None);
        let mut hider = TopologyHider::new(config);

        let original = "abc123@192.168.1.100";
        let result = hider.obfuscate_call_id(original).unwrap();
        assert_eq!(result, original); // Should remain unchanged
    }

    #[test]
    fn test_record_route_creation() {
        let config = TopologyHidingConfig::new("proxy.example.com")
            .with_port(5060)
            .with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);

        let rr = hider.create_anonymized_record_route(Some("tcp"));
        assert!(rr.contains("proxy.example.com"));
        assert!(rr.contains(";lr"));
        assert!(rr.contains("transport=tcp"));
    }

    #[test]
    fn test_hider_creation() {
        let hider = TopologyHider::with_defaults();
        assert_eq!(hider.config().mode, TopologyHidingMode::Basic);
        assert_eq!(hider.call_id_mapping_count(), 0);
    }

    #[test]
    fn test_clear_call_id_mappings() {
        let config = TopologyHidingConfig::default();
        let mut hider = TopologyHider::new(config);

        hider.obfuscate_call_id("call1@example.com").unwrap();
        hider.obfuscate_call_id("call2@example.com").unwrap();
        assert_eq!(hider.call_id_mapping_count(), 2);

        hider.clear_call_id_mappings();
        assert_eq!(hider.call_id_mapping_count(), 0);
    }

    /// Builds a B2BUA-style outbound INVITE header set whose single Via and
    /// Contact bear the SBC's internal pod IP (10.x), plus an internal Call-ID.
    fn b2bua_headers() -> Headers {
        let mut h = Headers::new();
        h.add(Header::new(
            HeaderName::Via,
            "SIP/2.0/UDP 10.2.0.5:5060;branch=z9hG4bK-abc123",
        ));
        h.add(Header::new(HeaderName::Contact, "<sip:sbc@10.2.0.5:5060>"));
        h.add(Header::new(HeaderName::CallId, "call-12345@10.2.0.5"));
        h
    }

    #[test]
    fn test_hide_b2bua_basic_anonymizes_but_keeps_via() {
        let config =
            TopologyHidingConfig::new("sbc.example.com").with_mode(TopologyHidingMode::Basic);
        let hider = TopologyHider::new(config);
        let mut headers = b2bua_headers();

        hider.hide_b2bua_request(&mut headers).unwrap();

        // The sole Via must survive, with its host anonymized and branch kept.
        let vias = headers.via_all_parsed();
        assert_eq!(vias.len(), 1, "the single Via must not be stripped");
        assert_eq!(vias[0].host, "sbc.example.com");
        assert_eq!(vias[0].branch, Some("z9hG4bK-abc123".to_string()));
        // No internal IP leaks anywhere in the Via.
        assert!(
            !headers
                .get(&HeaderName::Via)
                .unwrap()
                .value
                .contains("10.2.0.5")
        );

        // Contact host anonymized (user preserved).
        let contact = headers.contact_parsed().unwrap();
        assert_eq!(contact.uri.host, "sbc.example.com");
        assert_eq!(contact.uri.user, Some("sbc".to_string()));

        // Call-ID is deliberately left untouched (B2BUA already emits a fresh
        // per-leg Call-ID; it is the correlation key and must not be rewritten).
        assert_eq!(
            headers.get(&HeaderName::CallId).unwrap().value,
            "call-12345@10.2.0.5"
        );
    }

    #[test]
    fn test_hide_b2bua_full_mode_keeps_single_via() {
        // "full" maps to Aggressive; the proxy path would STRIP an internal Via,
        // which for a B2BUA's sole Via would produce an invalid request. The
        // B2BUA path must anonymize it instead.
        let config =
            TopologyHidingConfig::new("sbc.example.com").with_mode(TopologyHidingMode::Aggressive);
        let hider = TopologyHider::new(config);
        let mut headers = b2bua_headers();

        hider.hide_b2bua_request(&mut headers).unwrap();

        let vias = headers.via_all_parsed();
        assert_eq!(vias.len(), 1, "aggressive mode must not strip the sole Via");
        assert_eq!(vias[0].host, "sbc.example.com");
        assert!(headers.contact_parsed().is_some());
    }

    #[test]
    fn test_hide_b2bua_none_is_noop() {
        let config =
            TopologyHidingConfig::new("sbc.example.com").with_mode(TopologyHidingMode::None);
        let hider = TopologyHider::new(config);
        let mut headers = b2bua_headers();

        hider.hide_b2bua_request(&mut headers).unwrap();

        assert_eq!(headers.via_all_parsed()[0].host, "10.2.0.5");
        assert_eq!(headers.contact_parsed().unwrap().uri.host, "10.2.0.5");
        assert_eq!(
            headers.get(&HeaderName::CallId).unwrap().value,
            "call-12345@10.2.0.5"
        );
    }

    fn hdrs(list: &[(HeaderName, &str)]) -> Headers {
        let mut h = Headers::new();
        for (n, v) in list {
            h.add(Header::new(n.clone(), *v));
        }
        h
    }

    fn values(h: &Headers, n: &HeaderName) -> Vec<String> {
        h.get_all(n).map(|h| h.value.clone()).collect()
    }

    fn basic() -> TopologyHider {
        TopologyHider::new(TopologyHidingConfig::new("sbc.example.com"))
    }

    fn aggressive() -> TopologyHider {
        TopologyHider::new(
            TopologyHidingConfig::new("sbc.example.com").with_mode(TopologyHidingMode::Aggressive),
        )
    }

    // POAM-151: typed matching, no string prefixes.
    #[test]
    fn internal_classification() {
        let c = TopologyHidingConfig::default();
        for h in [
            "10.0.0.1",
            "172.31.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.1.1",
            "127.0.0.53",
            "[fd12::1]",
            "[fc00::1]",
            "[fe80::1]",
            "fe80::1%eth0",
            "[::1]",
            "[::ffff:10.0.0.1]",
            "host.internal",
            "pbx.local",
            "PBX.LOCAL.",
            "localhost",
        ] {
            assert!(c.is_internal_address(h), "{h} should be internal");
        }
        for h in [
            "10.example.com",
            "fc.example.com",
            "127.example.net",
            "172.32.0.1",
            "100.128.0.1",
            "8.8.8.8",
            "[2001:db8::1]",
            "[fbff::1]",
            "notlocal",
            "evil-internal.com",
        ] {
            assert!(!c.is_internal_address(h), "{h} should be external");
        }
        let c = c.try_with_internal_network("2001:db8::/32").unwrap();
        assert!(c.is_internal_address("[2001:db8::1]"));
        assert!(
            TopologyHidingConfig::default()
                .try_with_internal_network("10.0.0.0/33")
                .is_err()
        );
    }

    // POAM-151: comma-folded and multi-instance Via.
    #[test]
    fn folded_vias_all_hidden() {
        for h in [
            hdrs(&[(
                HeaderName::Via,
                "SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKa, SIP/2.0/UDP 192.168.1.1;branch=z9hG4bKb",
            )]),
            hdrs(&[
                (HeaderName::Via, "SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKa"),
                (HeaderName::Via, "SIP/2.0/UDP 192.168.1.1;branch=z9hG4bKb"),
            ]),
        ] {
            let mut h = h;
            basic().hide_b2bua_request(&mut h).unwrap();
            let v = values(&h, &HeaderName::Via);
            assert_eq!(v.len(), 2);
            assert!(v.iter().all(|v| v.contains("sbc.example.com")), "{v:?}");
            assert!(v[0].contains("z9hG4bKa") && v[1].contains("z9hG4bKb"));
        }
    }

    // POAM-151: comma-folded Contact.
    #[test]
    fn folded_contacts_all_hidden() {
        let mut h = hdrs(&[(HeaderName::Contact, "<sip:a@10.0.0.1>, <sip:b@10.0.0.2>")]);
        basic().rewrite_contacts(&mut h).unwrap();
        let v = values(&h, &HeaderName::Contact);
        assert_eq!(
            v,
            vec!["<sip:a@sbc.example.com>", "<sip:b@sbc.example.com>"]
        );
    }

    // POAM-151: Record-Route per element, mode dependent.
    #[test]
    fn record_route_per_element() {
        let rr = "<sip:10.0.0.1;lr>, <sip:p.example.com;lr>";
        let mut h = hdrs(&[(HeaderName::RecordRoute, rr)]);
        basic().rewrite_record_routes(&mut h, None).unwrap();
        let v = values(&h, &HeaderName::RecordRoute);
        assert_eq!(
            v,
            vec!["<sip:sbc.example.com;lr>", "<sip:p.example.com;lr>"]
        );

        let mut h = hdrs(&[(HeaderName::RecordRoute, rr)]);
        aggressive().rewrite_record_routes(&mut h, None).unwrap();
        let v = values(&h, &HeaderName::RecordRoute);
        assert!(
            v.iter().all(|v| v.starts_with("<sip:sbc.example.com")),
            "{v:?}"
        );

        let mut h = hdrs(&[(HeaderName::RecordRoute, "<sip:10.0.0.1;lr;transport=tls>")]);
        basic().rewrite_record_routes(&mut h, Some("udp")).unwrap();
        assert_eq!(
            values(&h, &HeaderName::RecordRoute),
            vec!["<sip:sbc.example.com:5061;lr;transport=tls>"]
        );
    }

    // POAM-151: fail closed on unparseable elements, headers untouched.
    #[test]
    fn unparseable_elements_fail_closed() {
        let orig = hdrs(&[
            (HeaderName::Via, "SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKa"),
            (HeaderName::Contact, "<sip:a@10.0.0.1>, <garbage"),
        ]);
        let mut h = orig.clone();
        let e = basic().hide_b2bua_request(&mut h).unwrap_err();
        assert!(matches!(e, SipError::TopologyHiding { .. }));
        assert_eq!(
            values(&h, &HeaderName::Contact),
            values(&orig, &HeaderName::Contact)
        );
        assert_eq!(
            values(&h, &HeaderName::Via),
            values(&orig, &HeaderName::Via)
        );

        let mut h = hdrs(&[
            (HeaderName::Via, "SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKa"),
            (HeaderName::Via, "not a via"),
        ]);
        assert!(basic().hide_b2bua_request(&mut h).is_err());
        assert_eq!(h.count(&HeaderName::Via), 2, "Via must not be dropped");
        let mut h2 = h.clone();
        assert!(basic().rewrite_vias_for_inbound(&mut h2).is_err());
        assert_eq!(h2.count(&HeaderName::Via), 2);
    }

    // POAM-151: Contact keeps transport=tls, scheme, header params; drops maddr.
    #[test]
    fn contact_keeps_tls_and_header_params() {
        let mut h = hdrs(&[(
            HeaderName::Contact,
            "<sip:a@10.0.0.1:5061;transport=tls;maddr=10.0.0.1>;expires=60",
        )]);
        basic().rewrite_contacts(&mut h).unwrap();
        let v = h.get_value(&HeaderName::Contact).unwrap();
        assert_eq!(v, "<sip:a@sbc.example.com:5061;transport=tls>;expires=60");

        let mut h = hdrs(&[(HeaderName::Contact, "<sips:a@10.0.0.1>")]);
        basic().rewrite_contacts(&mut h).unwrap();
        assert_eq!(
            h.get_value(&HeaderName::Contact).unwrap(),
            "<sips:a@sbc.example.com:5061>"
        );

        let mut h = hdrs(&[(HeaderName::Contact, "*")]);
        basic().rewrite_contacts(&mut h).unwrap();
        assert_eq!(h.get_value(&HeaderName::Contact).unwrap(), "*");
    }

    // POAM-151: Aggressive hides public hosts too.
    #[test]
    fn aggressive_hides_public() {
        let mut h = hdrs(&[
            (HeaderName::Via, "SIP/2.0/UDP 198.51.100.7;branch=z9hG4bKa"),
            (HeaderName::Contact, "<sip:a@198.51.100.7>"),
        ]);
        aggressive().hide_b2bua_request(&mut h).unwrap();
        assert!(!h.get_value(&HeaderName::Via).unwrap().contains("198.51"));
        assert!(
            !h.get_value(&HeaderName::Contact)
                .unwrap()
                .contains("198.51")
        );
    }

    // POAM-151: random, bounded Call-ID map.
    #[test]
    fn call_id_random_and_bounded() {
        let mut hider = TopologyHider::new(
            TopologyHidingConfig::new("sbc.example.com").with_max_call_id_mappings(3),
        );
        let a = hider.obfuscate_call_id("a@h").unwrap();
        let b = hider.obfuscate_call_id("b@h").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.split('@').next().unwrap().len(), 32);
        assert_eq!(hider.obfuscate_call_id("a@h").unwrap(), a);
        hider.obfuscate_call_id("c@h").unwrap();
        hider.obfuscate_call_id("d@h").unwrap();
        assert_eq!(hider.call_id_mapping_count(), 3);
        assert_eq!(hider.restore_call_id(&a), None, "oldest evicted");
        assert_eq!(hider.restore_call_id(&b).as_deref(), Some("b@h"));
        assert_eq!(hider.restore_call_id("unknown@x"), None);
        // A fresh hider does not reproduce the same token (not a hash).
        let mut other = TopologyHider::new(TopologyHidingConfig::new("sbc.example.com"));
        assert_ne!(other.obfuscate_call_id("b@h").unwrap(), b);
    }

    // POAM-151 (QA): each rewrite entry point fails closed on its own and
    // leaves every instance untouched.
    #[test]
    fn qa_rewrite_entry_points_fail_closed_atomically() {
        let orig = hdrs(&[
            (HeaderName::Contact, "<sip:a@10.0.0.1>"),
            (HeaderName::Contact, "<garbage"),
        ]);
        let mut h = orig.clone();
        assert!(matches!(
            basic().rewrite_contacts(&mut h),
            Err(SipError::TopologyHiding { .. })
        ));
        assert_eq!(
            values(&h, &HeaderName::Contact),
            values(&orig, &HeaderName::Contact)
        );

        let orig = hdrs(&[(HeaderName::RecordRoute, "<sip:10.0.0.1;lr>, <garbage")]);
        let mut h = orig.clone();
        assert!(matches!(
            basic().rewrite_record_routes(&mut h, None),
            Err(SipError::TopologyHiding { .. })
        ));
        assert_eq!(
            values(&h, &HeaderName::RecordRoute),
            values(&orig, &HeaderName::RecordRoute)
        );
    }

    // POAM-151 (QA): IPv4-mapped public address is external; mapped/compat
    // private address is internal; Basic leaves public Contact untouched.
    #[test]
    fn qa_mapped_addresses_and_basic_public_passthrough() {
        let c = TopologyHidingConfig::default();
        assert!(!c.is_internal_address("[::ffff:8.8.8.8]"));
        assert!(c.is_internal_address("[::ffff:192.168.1.1]"));
        assert!(c.is_internal_address("::ffff:172.16.0.1"));
        assert!(!c.is_internal_address("[::ffff:172.32.0.1]"));
        assert!(!c.is_internal_address("10.0.0.1.example.com"));

        let mut h = hdrs(&[(HeaderName::Contact, "<sip:a@198.51.100.7:5060>")]);
        basic().rewrite_contacts(&mut h).unwrap();
        assert_eq!(
            h.get_value(&HeaderName::Contact).unwrap(),
            "<sip:a@198.51.100.7:5060>"
        );
    }

    // POAM-151 (QA): sips Record-Route keeps TLS on the rewritten element.
    #[test]
    fn qa_sips_record_route_stays_tls() {
        let mut h = hdrs(&[(HeaderName::RecordRoute, "<sips:10.0.0.1;lr>")]);
        basic().rewrite_record_routes(&mut h, Some("udp")).unwrap();
        let v = h.get_value(&HeaderName::RecordRoute).unwrap();
        assert!(v.contains("5061") && v.contains("tls"), "{v}");
        assert!(!v.contains("10.0.0.1"));
    }

    // POAM-151 (QA): token is not the legacy unkeyed DefaultHasher output.
    #[test]
    fn qa_call_id_not_default_hasher() {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let mut hider = basic();
        let orig = "secret-call@10.0.0.1";
        let tok = hider.obfuscate_call_id(orig).unwrap();
        let mut d = DefaultHasher::new();
        orig.hash(&mut d);
        let legacy = format!("{:x}", d.finish());
        assert!(!tok.contains(&legacy));
        assert!(!tok.contains("10.0.0.1") && !tok.contains("secret"));
        assert!(tok[..32].bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
