//! SIP DNS resolver per RFC 3263.
//!
//! Implements the full DNS resolution procedure for SIP:
//! 1. NAPTR lookup to determine transport and SRV target
//! 2. SRV lookup to get host and port
//! 3. A/AAAA lookup to get IP addresses
//!
//! ## RFC 3263 Compliance
//!
//! - NAPTR → SRV → A/AAAA resolution chain
//! - Transport preference handling
//! - Fallback when NAPTR is not available
//! - Support for numeric IP addresses (no DNS needed)

use crate::cache::{CacheEntry, DnsCache};
use crate::config::{SipResolverConfig, TransportPref};
use crate::error::{DnsError, DnsResult};
use crate::naptr::{NaptrRecord, NaptrResolver};
use crate::srv::{SrvRecord, SrvResolver};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

#[cfg(feature = "resolver")]
use crate::hickory::HickoryDnsResolver;

/// Transport preference for resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPreference {
    /// Use any available transport (prefer secure).
    #[default]
    Any,
    /// Prefer UDP.
    Udp,
    /// Prefer TCP.
    Tcp,
    /// Require TLS.
    Tls,
    /// Prefer SCTP.
    Sctp,
    /// Prefer WebSocket.
    WebSocket,
    /// Require Secure WebSocket.
    WebSocketSecure,
}

impl TransportPreference {
    /// Converts to TransportPref for internal use.
    #[must_use]
    pub fn to_transport_pref(self) -> Option<TransportPref> {
        match self {
            Self::Any => None,
            Self::Udp => Some(TransportPref::Udp),
            Self::Tcp => Some(TransportPref::Tcp),
            Self::Tls => Some(TransportPref::Tls),
            Self::Sctp => Some(TransportPref::Sctp),
            Self::WebSocket => Some(TransportPref::WebSocket),
            Self::WebSocketSecure => Some(TransportPref::WebSocketSecure),
        }
    }
}

/// A resolved SIP target with address and transport information.
#[derive(Debug, Clone)]
pub struct SipTarget {
    /// Resolved socket address.
    pub address: SocketAddr,
    /// Transport to use.
    pub transport: TransportPref,
    /// Original hostname (for TLS SNI).
    pub hostname: Option<String>,
    /// Priority from SRV (lower is better).
    pub priority: u16,
    /// Weight from SRV (for load balancing).
    pub weight: u16,
}

impl SipTarget {
    /// Creates a new SIP target.
    #[must_use]
    pub fn new(address: SocketAddr, transport: TransportPref) -> Self {
        Self {
            address,
            transport,
            hostname: None,
            priority: 0,
            weight: 0,
        }
    }

    /// Creates a SIP target with full details.
    #[must_use]
    pub fn with_details(
        address: SocketAddr,
        transport: TransportPref,
        hostname: Option<String>,
        priority: u16,
        weight: u16,
    ) -> Self {
        Self {
            address,
            transport,
            hostname,
            priority,
            weight,
        }
    }

    /// Returns true if this target uses a secure transport.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        matches!(
            self.transport,
            TransportPref::Tls | TransportPref::WebSocketSecure
        )
    }
}

/// SIP DNS resolver implementing RFC 3263.
///
/// Resolves SIP URIs to socket addresses using the DNS procedures
/// defined in RFC 3263.
///
/// When the `resolver` feature is enabled, this resolver can perform
/// actual DNS lookups using hickory-resolver. Without the feature,
/// it relies on pre-cached records or returns errors for hostnames.
pub struct SipResolver {
    /// Configuration.
    config: SipResolverConfig,
    /// DNS cache.
    cache: Arc<DnsCache>,
    /// NAPTR resolver (used during NAPTR record processing).
    #[allow(dead_code)]
    naptr_resolver: NaptrResolver,
    /// SRV resolver (used during SRV record processing).
    #[allow(dead_code)]
    srv_resolver: SrvResolver,
    /// Optional hickory DNS resolver for actual DNS queries.
    #[cfg(feature = "resolver")]
    dns_resolver: Option<HickoryDnsResolver>,
}

impl SipResolver {
    /// Creates a new SIP resolver.
    ///
    /// With the `resolver` feature, DNS queries use the host's system DNS
    /// configuration. If that cannot be read the resolver runs with no DNS
    /// backend (numeric/cached targets only) — it never falls back to
    /// hickory's public default resolvers.
    ///
    /// NIST 800-53 Rev5: CM-7 (enterprise resolver, fail-safe).
    #[must_use]
    pub fn new(config: SipResolverConfig, cache: Arc<DnsCache>) -> Self {
        #[cfg(feature = "resolver")]
        let dns_resolver = match HickoryDnsResolver::from_system_conf(Arc::clone(&cache)) {
            Ok(r) => Some(r),
            Err(e) => {
                warn!(
                    error = %e,
                    "system DNS configuration unavailable; SIP resolver running without DNS backend"
                );
                None
            }
        };

        Self {
            config,
            cache,
            naptr_resolver: NaptrResolver::new(),
            srv_resolver: SrvResolver::new(),
            #[cfg(feature = "resolver")]
            dns_resolver,
        }
    }

    /// Creates a SIP resolver with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SipResolverConfig::default(), Arc::new(DnsCache::default()))
    }

    /// Creates a SIP resolver with actual DNS resolution enabled.
    ///
    /// This method is only available when the `resolver` feature is enabled.
    #[cfg(feature = "resolver")]
    #[must_use]
    pub fn with_dns_resolver(
        config: SipResolverConfig,
        cache: Arc<DnsCache>,
        dns_resolver: HickoryDnsResolver,
    ) -> Self {
        Self {
            config,
            cache,
            naptr_resolver: NaptrResolver::new(),
            srv_resolver: SrvResolver::new(),
            dns_resolver: Some(dns_resolver),
        }
    }

    /// Returns whether actual DNS resolution is available.
    #[must_use]
    pub fn has_dns_resolver(&self) -> bool {
        #[cfg(feature = "resolver")]
        {
            self.dns_resolver.is_some()
        }
        #[cfg(not(feature = "resolver"))]
        {
            false
        }
    }

    /// Returns the default transport from configuration.
    fn default_transport(&self) -> TransportPref {
        self.config
            .transport_preference
            .first()
            .copied()
            .unwrap_or(TransportPref::Udp)
    }

    /// Resolves a SIP domain to a list of targets.
    ///
    /// Implements RFC 3263 resolution:
    /// 1. If host is numeric IP, return directly
    /// 2. If port specified, skip SRV lookup
    /// 3. Otherwise: NAPTR → SRV → A/AAAA
    ///
    /// # Errors
    ///
    /// Returns an error if resolution fails.
    pub async fn resolve(
        &self,
        host: &str,
        port: Option<u16>,
        transport: TransportPreference,
    ) -> DnsResult<Vec<SipTarget>> {
        debug!(host = %host, port = ?port, transport = ?transport, "Resolving SIP target");

        // Check if host is a numeric IP
        if let Ok(ip) = host.parse::<IpAddr>() {
            let resolved_transport = transport
                .to_transport_pref()
                .unwrap_or_else(|| self.default_transport());
            let resolved_port =
                port.unwrap_or_else(|| self.config.default_ports.for_transport(resolved_transport));

            return Ok(vec![SipTarget::new(
                SocketAddr::new(ip, resolved_port),
                resolved_transport,
            )]);
        }

        // Check cache first
        let cache_key = format!("sip:{host}:{transport:?}");
        if let Some(CacheEntry::Address(addrs)) = self.cache.get(&cache_key, "SIP").await {
            let resolved_transport = transport
                .to_transport_pref()
                .unwrap_or_else(|| self.default_transport());
            let resolved_port =
                port.unwrap_or_else(|| self.config.default_ports.for_transport(resolved_transport));

            let targets: Vec<SipTarget> = addrs
                .into_iter()
                .map(|ip| SipTarget::new(SocketAddr::new(ip, resolved_port), resolved_transport))
                .collect();

            if !targets.is_empty() {
                trace!(host = %host, count = targets.len(), "Cache hit for SIP resolution");
                return Ok(targets);
            }
        }

        // If port is specified, skip NAPTR/SRV and go directly to A/AAAA
        if let Some(p) = port {
            return self.resolve_with_port(host, p, transport).await;
        }

        // Full RFC 3263 resolution
        self.resolve_full(host, transport).await
    }

    /// Resolves when port is explicitly specified.
    async fn resolve_with_port(
        &self,
        host: &str,
        port: u16,
        transport: TransportPreference,
    ) -> DnsResult<Vec<SipTarget>> {
        let resolved_transport = transport
            .to_transport_pref()
            .unwrap_or_else(|| self.default_transport());

        let addresses = self.resolve_addresses(host).await?;

        let targets: Vec<SipTarget> = addresses
            .into_iter()
            .map(|ip| {
                SipTarget::with_details(
                    SocketAddr::new(ip, port),
                    resolved_transport,
                    Some(host.to_string()),
                    0,
                    0,
                )
            })
            .collect();

        if targets.is_empty() {
            return Err(DnsError::NoRecords {
                domain: host.to_string(),
            });
        }

        Ok(targets)
    }

    /// Full RFC 3263 resolution (NAPTR → SRV → A/AAAA).
    #[allow(clippy::useless_let_if_seq)]
    async fn resolve_full(
        &self,
        host: &str,
        transport: TransportPreference,
    ) -> DnsResult<Vec<SipTarget>> {
        let mut targets = Vec::new();

        // Step 1: Try NAPTR if enabled
        if self.config.use_naptr
            && let Some(naptr_targets) = self.resolve_via_naptr(host, transport).await?
        {
            targets = naptr_targets;
        }

        // Step 2: If no NAPTR results, try SRV directly
        if targets.is_empty()
            && self.config.use_srv
            && let Some(srv_targets) = self.resolve_via_srv(host, transport).await?
        {
            targets = srv_targets;
        }

        // Step 3: If still no results, fall back to A/AAAA
        if targets.is_empty() {
            targets = self.resolve_fallback(host, transport).await?;
        }

        // RFC 2782 / RFC 3263 §4.4: targets are already in RFC 2782 order
        // (priority, then weighted-random within a priority). Only a stable
        // priority sort is safe here; sorting by weight would discard the
        // weighted-random draw.
        targets.sort_by_key(|t| t.priority);

        if targets.is_empty() {
            return Err(DnsError::NoRecords {
                domain: host.to_string(),
            });
        }

        debug!(
            host = %host,
            count = targets.len(),
            "Resolved SIP targets"
        );

        Ok(targets)
    }

    /// Resolves using NAPTR records.
    async fn resolve_via_naptr(
        &self,
        host: &str,
        transport: TransportPreference,
    ) -> DnsResult<Option<Vec<SipTarget>>> {
        // Check cache for NAPTR
        if let Some(CacheEntry::Naptr(records)) = self.cache.get(host, "NAPTR").await {
            return self.process_naptr_records(host, &records, transport).await;
        }

        // Try actual DNS lookup if available
        #[cfg(feature = "resolver")]
        if let Some(ref resolver) = self.dns_resolver {
            match resolver.lookup_naptr(host).await {
                Ok(records) => {
                    return self.process_naptr_records(host, &records, transport).await;
                }
                Err(DnsError::NoRecords { .. }) => {
                    // No NAPTR records, fall through to SRV
                    trace!(host = %host, "No NAPTR records found, trying SRV");
                }
                Err(e) => {
                    warn!(host = %host, error = %e, "NAPTR lookup failed, trying SRV");
                }
            }
        }

        // No NAPTR records or no resolver
        trace!(host = %host, "No NAPTR records, trying SRV");
        Ok(None)
    }

    /// Processes NAPTR records to get SIP targets.
    async fn process_naptr_records(
        &self,
        host: &str,
        records: &[NaptrRecord],
        transport: TransportPreference,
    ) -> DnsResult<Option<Vec<SipTarget>>> {
        // Add records to resolver for selection
        let mut resolver = NaptrResolver::new();
        resolver.add_records(records.to_vec());

        // Select appropriate NAPTR record based on transport preference
        // RFC 3263 §4.1: discard records whose service is not a supported
        // SIP/SIPS service.
        let selected = transport.to_transport_pref().map_or_else(
            || resolver.select_best_sip(),
            |pref| {
                let matching = resolver.select_for_transport(pref);
                matching.into_iter().next()
            },
        );

        let Some(naptr) = selected else {
            return Ok(None);
        };

        // Get transport from NAPTR service
        let naptr_transport = naptr.transport().unwrap_or(TransportPref::Udp);

        // Get SRV target from NAPTR replacement
        let srv_name = &naptr.replacement;

        // Resolve SRV
        let srv_records = self.resolve_srv_records(srv_name).await?;
        if srv_records.is_empty() {
            return Ok(None);
        }

        // RFC 3263 §4.1: the replacement is an SRV name processed per
        // RFC 2782 (weighted order, "." targets dropped).
        self.process_srv_records(host, &srv_records, naptr_transport)
            .await
    }

    /// Resolves using SRV records directly.
    async fn resolve_via_srv(
        &self,
        host: &str,
        transport: TransportPreference,
    ) -> DnsResult<Option<Vec<SipTarget>>> {
        let transport_pref = transport
            .to_transport_pref()
            .unwrap_or_else(|| self.default_transport());

        let srv_name = SrvResolver::sip_srv_name(host, &transport_pref.to_string());

        // Check cache for SRV
        if let Some(CacheEntry::Srv(records)) = self.cache.get(&srv_name, "SRV").await {
            return self
                .process_srv_records(host, &records, transport_pref)
                .await;
        }

        // Try actual DNS lookup if available
        #[cfg(feature = "resolver")]
        if let Some(ref resolver) = self.dns_resolver {
            match resolver.lookup_sip_srv(host, transport_pref).await {
                Ok(records) => {
                    return self
                        .process_srv_records(host, &records, transport_pref)
                        .await;
                }
                Err(DnsError::NoRecords { .. }) => {
                    // No SRV records, fall through to A/AAAA
                    trace!(srv = %srv_name, "No SRV records found, falling back to A/AAAA");
                }
                Err(e) => {
                    warn!(srv = %srv_name, error = %e, "SRV lookup failed, falling back to A/AAAA");
                }
            }
        }

        trace!(srv = %srv_name, "No cached SRV records");
        Ok(None)
    }

    /// Processes SRV records to get SIP targets.
    async fn process_srv_records(
        &self,
        host: &str,
        records: &[SrvRecord],
        transport: TransportPref,
    ) -> DnsResult<Option<Vec<SipTarget>>> {
        if records.is_empty() {
            return Ok(None);
        }

        let mut targets = Vec::new();

        // RFC 2782 / RFC 3263 §4.4: try targets in priority order with
        // weighted-random ordering within each priority.
        for srv in &SrvResolver::order_rfc2782(records) {
            // Use cached addresses if available
            let addresses = if srv.addresses.is_empty() {
                // RFC 3263 §4.4 / RFC 2782: a target that does not resolve
                // is skipped and the next one tried; only if every target
                // fails does the caller fall back.
                match self.resolve_addresses(&srv.target).await {
                    Ok(a) => a,
                    Err(e) => {
                        debug!(target = %srv.target, error = %e, "SRV target unresolvable; trying next");
                        continue;
                    }
                }
            } else {
                srv.addresses.clone()
            };

            for ip in addresses {
                targets.push(SipTarget::with_details(
                    SocketAddr::new(ip, srv.port),
                    transport,
                    Some(host.to_string()),
                    srv.priority,
                    srv.weight,
                ));
            }
        }

        if targets.is_empty() {
            Ok(None)
        } else {
            Ok(Some(targets))
        }
    }

    /// Fallback resolution using A/AAAA records only.
    async fn resolve_fallback(
        &self,
        host: &str,
        transport: TransportPreference,
    ) -> DnsResult<Vec<SipTarget>> {
        let transport_pref = transport
            .to_transport_pref()
            .unwrap_or_else(|| self.default_transport());

        let port = self.config.default_ports.for_transport(transport_pref);
        let addresses = self.resolve_addresses(host).await?;

        let targets: Vec<SipTarget> = addresses
            .into_iter()
            .map(|ip| {
                SipTarget::with_details(
                    SocketAddr::new(ip, port),
                    transport_pref,
                    Some(host.to_string()),
                    0,
                    0,
                )
            })
            .collect();

        Ok(targets)
    }

    /// Resolves SRV records for a given name.
    async fn resolve_srv_records(&self, name: &str) -> DnsResult<Vec<SrvRecord>> {
        // Check cache
        if let Some(CacheEntry::Srv(records)) = self.cache.get(name, "SRV").await {
            return Ok(records);
        }

        // Try actual DNS lookup if available
        #[cfg(feature = "resolver")]
        if let Some(ref resolver) = self.dns_resolver {
            match resolver.lookup_srv(name).await {
                Ok(records) => {
                    return Ok(records);
                }
                Err(DnsError::NoRecords { .. }) => {
                    trace!(name = %name, "No SRV records found");
                }
                Err(e) => {
                    warn!(name = %name, error = %e, "SRV lookup failed");
                }
            }
        }

        Ok(Vec::new())
    }

    /// Resolves A/AAAA records for a hostname.
    async fn resolve_addresses(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        // Check if already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // Check cache
        if let Some(CacheEntry::Address(addrs)) = self.cache.get(host, "A").await {
            return Ok(addrs);
        }

        // Try actual DNS resolution if available
        #[cfg(feature = "resolver")]
        if let Some(ref resolver) = self.dns_resolver {
            return resolver.lookup_addresses(host).await;
        }

        // No DNS resolver available
        warn!(host = %host, "DNS resolution not available (enable 'resolver' feature)");
        Err(DnsError::ResolutionFailed {
            domain: host.to_string(),
            reason: "DNS resolution not available".to_string(),
        })
    }

    /// Caches resolved addresses.
    pub async fn cache_addresses(&self, host: &str, addresses: Vec<IpAddr>, ttl: Duration) {
        self.cache
            .put(host, "A", CacheEntry::Address(addresses), ttl)
            .await;
    }

    /// Caches SRV records.
    pub async fn cache_srv(&self, name: &str, records: Vec<SrvRecord>, ttl: Duration) {
        self.cache
            .put(name, "SRV", CacheEntry::Srv(records), ttl)
            .await;
    }

    /// Caches NAPTR records.
    pub async fn cache_naptr(&self, name: &str, records: Vec<NaptrRecord>, ttl: Duration) {
        self.cache
            .put(name, "NAPTR", CacheEntry::Naptr(records), ttl)
            .await;
    }

    /// Returns the DNS cache.
    #[must_use]
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &SipResolverConfig {
        &self.config
    }
}

impl std::fmt::Debug for SipResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipResolver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_preference_conversion() {
        assert!(TransportPreference::Any.to_transport_pref().is_none());
        assert_eq!(
            TransportPreference::Udp.to_transport_pref(),
            Some(TransportPref::Udp)
        );
        assert_eq!(
            TransportPreference::Tls.to_transport_pref(),
            Some(TransportPref::Tls)
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_sip_target_creation() {
        let addr: SocketAddr = "192.168.1.1:5060".parse().unwrap();
        let target = SipTarget::new(addr, TransportPref::Udp);

        assert_eq!(target.address, addr);
        assert_eq!(target.transport, TransportPref::Udp);
        assert!(!target.is_secure());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_sip_target_secure() {
        let addr: SocketAddr = "192.168.1.1:5061".parse().unwrap();
        let target = SipTarget::new(addr, TransportPref::Tls);

        assert!(target.is_secure());
    }

    /// NIST 800-53 Rev5: CM-7 — with the `resolver` feature the default
    /// constructor wires the system-configured DNS backend (when the host has
    /// one), so RFC 3263 NAPTR/SRV queries are actually issued.
    #[cfg(feature = "resolver")]
    #[test]
    fn test_with_defaults_has_system_dns_backend_outside_runtime() {
        let resolver = SipResolver::with_defaults();
        let system_ok = HickoryDnsResolver::from_system_conf(Arc::new(DnsCache::default())).is_ok();
        assert_eq!(resolver.has_dns_resolver(), system_ok);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_numeric_ip() {
        let resolver = SipResolver::with_defaults();
        let targets = resolver
            .resolve("192.168.1.100", Some(5060), TransportPreference::Udp)
            .await
            .unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].address, "192.168.1.100:5060".parse().unwrap());
        assert_eq!(targets[0].transport, TransportPref::Udp);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_numeric_ipv6() {
        let resolver = SipResolver::with_defaults();
        let targets = resolver
            .resolve("::1", Some(5060), TransportPreference::Tcp)
            .await
            .unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].address, "[::1]:5060".parse().unwrap());
        assert_eq!(targets[0].transport, TransportPref::Tcp);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_numeric_default_port() {
        let resolver = SipResolver::with_defaults();
        let targets = resolver
            .resolve("10.0.0.1", None, TransportPreference::Tls)
            .await
            .unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].address.port(), 5061); // TLS default port
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_with_cached_addresses() {
        let cache = Arc::new(DnsCache::default());
        let resolver = SipResolver::new(SipResolverConfig::default(), cache.clone());

        // Pre-populate cache
        let addrs = vec![
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
        ];
        cache
            .put(
                "sip:example.com:Any",
                "SIP",
                CacheEntry::Address(addrs),
                Duration::from_mins(5),
            )
            .await;

        let targets = resolver
            .resolve("example.com", None, TransportPreference::Any)
            .await
            .unwrap();

        assert_eq!(targets.len(), 2);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_sip_target_with_details() {
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let target = SipTarget::with_details(
            addr,
            TransportPref::Tcp,
            Some("sip.example.com".to_string()),
            10,
            100,
        );

        assert_eq!(target.priority, 10);
        assert_eq!(target.weight, 100);
        assert_eq!(target.hostname, Some("sip.example.com".to_string()));
    }

    /// Fail-safe path (plan Q3): a resolver with no DNS backend must still
    /// serve numeric and cached targets, and must not issue network queries
    /// for uncached names (returns promptly, no panic).
    #[cfg(feature = "resolver")]
    fn no_backend_resolver(cache: Arc<DnsCache>) -> SipResolver {
        SipResolver {
            config: SipResolverConfig::default(),
            cache,
            naptr_resolver: NaptrResolver::new(),
            srv_resolver: SrvResolver::new(),
            dns_resolver: None,
        }
    }

    #[cfg(feature = "resolver")]
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_no_backend_fallback_serves_numeric_and_cached() {
        let cache = Arc::new(DnsCache::default());
        let resolver = no_backend_resolver(Arc::clone(&cache));
        assert!(!resolver.has_dns_resolver());

        let t = resolver
            .resolve("192.0.2.7", None, TransportPreference::Tls)
            .await
            .unwrap();
        assert_eq!(t.len(), 1);
        assert!(t[0].is_secure());

        cache
            .put(
                "sip:cached.example:Any",
                "SIP",
                CacheEntry::Address(vec!["192.0.2.8".parse().unwrap()]),
                Duration::from_mins(5),
            )
            .await;
        let t = resolver
            .resolve("cached.example", None, TransportPreference::Any)
            .await
            .unwrap();
        assert_eq!(t.len(), 1);
    }

    #[cfg(feature = "resolver")]
    #[tokio::test]
    async fn test_no_backend_uncached_name_does_not_hang() {
        let resolver = no_backend_resolver(Arc::new(DnsCache::default()));
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            resolver.resolve("uncached.invalid", None, TransportPreference::Any),
        )
        .await;
        assert!(res.is_ok(), "no-backend resolve must not block on network");
        if let Ok(Ok(targets)) = res {
            assert!(targets.is_empty() || targets.iter().all(|t| t.address.ip().is_loopback()));
        }
    }

    /// Resolver with no network backend in either feature configuration.
    fn offline_resolver(cache: Arc<DnsCache>) -> SipResolver {
        SipResolver {
            config: SipResolverConfig::default(),
            cache,
            naptr_resolver: NaptrResolver::new(),
            srv_resolver: SrvResolver::new(),
            #[cfg(feature = "resolver")]
            dns_resolver: None,
        }
    }

    #[allow(clippy::unwrap_used)]
    fn srv_with_addr(prio: u16, weight: u16, target: &str, ip: &str) -> SrvRecord {
        let mut r = SrvRecord::new("_sip._udp.example.com", prio, weight, 5060, target, 300);
        r.add_address(ip.parse().unwrap());
        r
    }

    /// RFC-001: resolve_full must preserve the RFC 2782 weighted-random
    /// order within a priority. With weights 0 and 1 each record comes
    /// first with probability 1/2, so over 200 runs both orders appear
    /// (failure probability 2^-199). A weight-desc re-sort would always put
    /// the weight-1 target first.
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_preserves_weighted_order() {
        let cache = Arc::new(DnsCache::default());
        let resolver = offline_resolver(Arc::clone(&cache));
        let srv_name = SrvResolver::sip_srv_name("example.com", &TransportPref::Udp.to_string());
        resolver
            .cache_srv(
                &srv_name,
                vec![
                    srv_with_addr(10, 1, "heavy.example.com", "192.0.2.1"),
                    srv_with_addr(10, 0, "light.example.com", "192.0.2.2"),
                    srv_with_addr(20, 100, "backup.example.com", "192.0.2.3"),
                ],
                Duration::from_mins(5),
            )
            .await;

        let (mut heavy_first, mut light_first) = (0, 0);
        for _ in 0..200 {
            let t = resolver
                .resolve("example.com", None, TransportPreference::Udp)
                .await
                .unwrap();
            assert_eq!(t.len(), 3);
            // Priority order is always respected.
            assert_eq!(t[2].address.ip().to_string(), "192.0.2.3");
            match t[0].address.ip().to_string().as_str() {
                "192.0.2.1" => heavy_first += 1,
                "192.0.2.2" => light_first += 1,
                other => unreachable!("unexpected first target {other}"),
            }
        }
        assert!(
            heavy_first > 0 && light_first > 0,
            "{heavy_first}/{light_first}"
        );
    }

    /// RFC-003: an unresolvable SRV target is skipped, not fatal.
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_unresolvable_srv_target_is_skipped() {
        let cache = Arc::new(DnsCache::default());
        let resolver = offline_resolver(Arc::clone(&cache));
        let srv_name = SrvResolver::sip_srv_name("example.com", &TransportPref::Udp.to_string());
        resolver
            .cache_srv(
                &srv_name,
                vec![
                    SrvRecord::new(&srv_name, 10, 0, 5060, "dead.invalid", 300),
                    srv_with_addr(20, 0, "alive.example.com", "192.0.2.9"),
                ],
                Duration::from_mins(5),
            )
            .await;

        let t = resolver
            .resolve("example.com", None, TransportPreference::Udp)
            .await
            .unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].address, "192.0.2.9:5060".parse().unwrap());
        assert_eq!(t[0].priority, 20);
    }

    /// RFC-002: NAPTR→SRV drops "." targets and resolves through RFC 2782.
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_naptr_srv_filters_null_target() {
        let cache = Arc::new(DnsCache::default());
        let resolver = offline_resolver(Arc::clone(&cache));
        resolver
            .cache_naptr(
                "example.com",
                vec![NaptrRecord::new(
                    "example.com",
                    10,
                    10,
                    "s",
                    "SIP+D2U",
                    "",
                    "_sip._udp.example.com",
                    300,
                )],
                Duration::from_mins(5),
            )
            .await;
        resolver
            .cache_srv(
                "_sip._udp.example.com",
                vec![
                    SrvRecord::new("_sip._udp.example.com", 0, 0, 5060, ".", 300),
                    srv_with_addr(10, 0, "ok.example.com", "192.0.2.4"),
                ],
                Duration::from_mins(5),
            )
            .await;
        let t = resolver
            .resolve("example.com", None, TransportPreference::Any)
            .await
            .unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].address, "192.0.2.4:5060".parse().unwrap());
        assert_eq!(t[0].transport, TransportPref::Udp);
    }

    /// RFC-005: with no preference, a non-SIP NAPTR record ordered first is
    /// skipped in favour of the first SIP service.
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_naptr_any_skips_non_sip_service() {
        let cache = Arc::new(DnsCache::default());
        let resolver = offline_resolver(Arc::clone(&cache));
        resolver
            .cache_naptr(
                "example.com",
                vec![
                    NaptrRecord::new(
                        "example.com",
                        1,
                        1,
                        "s",
                        "E2U+email",
                        "",
                        "_x._tcp.example.com",
                        300,
                    ),
                    NaptrRecord::new(
                        "example.com",
                        10,
                        10,
                        "s",
                        "SIPS+D2T",
                        "",
                        "_sips._tcp.example.com",
                        300,
                    ),
                ],
                Duration::from_mins(5),
            )
            .await;
        let mut r = srv_with_addr(10, 0, "tls.example.com", "192.0.2.5");
        r.port = 5061;
        resolver
            .cache_srv("_sips._tcp.example.com", vec![r], Duration::from_mins(5))
            .await;
        let t = resolver
            .resolve("example.com", None, TransportPreference::Any)
            .await
            .unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].transport, TransportPref::Tls);
    }

    /// SEC-1 / RFC 3263 §4.1: a sips: URI (TLS preference) never yields a
    /// non-TLS target, even when NAPTR prefers UDP and an insecure SRV set
    /// exists for the domain.
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_sips_never_downgrades_via_naptr_or_srv() {
        let cache = Arc::new(DnsCache::default());
        let resolver = offline_resolver(Arc::clone(&cache));
        resolver
            .cache_naptr(
                "example.com",
                vec![NaptrRecord::new(
                    "example.com",
                    1,
                    1,
                    "s",
                    "SIP+D2U",
                    "",
                    "_sip._udp.example.com",
                    300,
                )],
                Duration::from_mins(5),
            )
            .await;
        resolver
            .cache_srv(
                "_sip._udp.example.com",
                vec![srv_with_addr(0, 0, "udp.example.com", "192.0.2.6")],
                Duration::from_mins(5),
            )
            .await;

        // No TLS records at all: must fail (or fall back to A with TLS),
        // never return the UDP target.
        if let Ok(t) = resolver
            .resolve("example.com", None, TransportPreference::Tls)
            .await
        {
            assert!(t.iter().all(SipTarget::is_secure));
        }

        // With a TLS SRV set present via the direct SRV step, only TLS
        // targets come back.
        let tls_srv = SrvResolver::sip_srv_name("example.com", &TransportPref::Tls.to_string());
        let mut r = srv_with_addr(10, 0, "tls.example.com", "192.0.2.7");
        r.port = 5061;
        resolver
            .cache_srv(&tls_srv, vec![r], Duration::from_mins(5))
            .await;
        let t = resolver
            .resolve("example.com", None, TransportPreference::Tls)
            .await
            .unwrap();
        assert!(!t.is_empty());
        assert!(t.iter().all(SipTarget::is_secure));
        assert!(t.iter().all(|t| t.address.ip().to_string() == "192.0.2.7"));
    }
}
