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
    #[must_use]
    pub fn new(config: SipResolverConfig, cache: Arc<DnsCache>) -> Self {
        #[cfg(feature = "resolver")]
        let dns_resolver = HickoryDnsResolver::new(Arc::clone(&cache)).ok();

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

        // Sort by priority then weight
        targets.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| b.weight.cmp(&a.weight))
        });

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
        let selected = transport.to_transport_pref().map_or_else(
            || resolver.select_best(),
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

        let mut targets = Vec::new();
        for srv in srv_records {
            let addresses = self.resolve_addresses(&srv.target).await?;
            for ip in addresses {
                targets.push(SipTarget::with_details(
                    SocketAddr::new(ip, srv.port),
                    naptr_transport,
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

        for srv in records {
            // Use cached addresses if available
            let addresses = if srv.addresses.is_empty() {
                self.resolve_addresses(&srv.target).await?
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

    #[test]
    fn test_sip_target_creation() {
        let addr: SocketAddr = "192.168.1.1:5060".parse().unwrap();
        let target = SipTarget::new(addr, TransportPref::Udp);

        assert_eq!(target.address, addr);
        assert_eq!(target.transport, TransportPref::Udp);
        assert!(!target.is_secure());
    }

    #[test]
    fn test_sip_target_secure() {
        let addr: SocketAddr = "192.168.1.1:5061".parse().unwrap();
        let target = SipTarget::new(addr, TransportPref::Tls);

        assert!(target.is_secure());
    }

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
                Duration::from_secs(300),
            )
            .await;

        let targets = resolver
            .resolve("example.com", None, TransportPreference::Any)
            .await
            .unwrap();

        assert_eq!(targets.len(), 2);
    }

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
}
