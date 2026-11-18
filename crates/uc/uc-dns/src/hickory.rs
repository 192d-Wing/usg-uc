//! Hickory DNS resolver integration.
//!
//! This module provides actual DNS resolution using the hickory-resolver crate.
//! It is only available when the `resolver` feature is enabled.

use crate::cache::{CacheEntry, DnsCache};
use crate::config::TransportPref;
use crate::error::{DnsError, DnsResult};
use crate::naptr::NaptrRecord;
use crate::srv::SrvRecord;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::rr::rdata::NAPTR;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// DNS resolver using hickory-resolver for actual DNS queries.
pub struct HickoryDnsResolver {
    /// The underlying resolver.
    resolver: TokioResolver,
    /// DNS cache for caching results.
    cache: Arc<DnsCache>,
    /// Default TTL for cached records when DNS doesn't provide one.
    default_ttl: Duration,
    /// Send NAPTR, SRV and A/AAAA query names fully qualified, so hickory
    /// does not try them once per resolv.conf search domain. Set only by
    /// [`Self::from_system_conf_with_query_limits`]. Cache keys stay in the
    /// caller's (bare) form either way.
    absolute_names: bool,
}

impl HickoryDnsResolver {
    /// Creates a resolver from the operating system's DNS configuration
    /// (`/etc/resolv.conf` on Unix, SystemConfiguration on Apple, the
    /// registry on Windows).
    ///
    /// NIST 800-53 Rev5: CM-7 — queries go to the enterprise resolver the
    /// host is configured for, never a hard-coded public one.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::ResolverInit`] if the system configuration cannot be
    /// read or the resolver cannot be built. Callers must not fall back to
    /// [`Self::new`] (public resolvers) on error.
    // POAM: POA&M-172 - DNS responses are not DNSSEC-validated and are not
    // carried over DoT (SC-20, SC-21, SC-22).
    pub fn from_system_conf(cache: Arc<DnsCache>) -> DnsResult<Self> {
        Self::build_from_system_conf(cache, false, |_| {})
    }

    /// Creates a resolver from the operating system's DNS configuration
    /// (as [`Self::from_system_conf`]) with a per-query time limit.
    ///
    /// `query_timeout` replaces the system timeout (resolv.conf `timeout:`,
    /// 5 s by default) and bounds one query against the whole name-server
    /// pool. `retries` replaces resolv.conf `attempts:`; in hickory 0.26 it
    /// counts re-sends after the first one (`RetryDnsHandle`), so an
    /// unanswered query costs `query_timeout * (retries + 1)`. With the
    /// system defaults (5 s, 2) that is 15 s per query.
    ///
    /// Query names are sent fully qualified (a trailing `.` is appended), so
    /// resolv.conf `search`/`domain` expansion is skipped and each NAPTR, SRV
    /// or SRV-target A/AAAA step costs exactly one query. RFC 3263 §4
    /// resolves the domain of the URI itself, not search-list variants of it.
    ///
    /// NIST 800-53 Rev5: SC-5, SI-17 — an unanswered query fails within a
    /// known time, so the caller's RFC 3263 NAPTR -> SRV -> A/AAAA chain
    /// reaches the next step instead of spending its budget on one query.
    ///
    /// # Errors
    ///
    /// Same as [`Self::from_system_conf`]; callers must not fall back to
    /// [`Self::new`] (public resolvers) on error.
    // POAM: POA&M-172 - DNS responses are not DNSSEC-validated and are not
    // carried over DoT (SC-20, SC-21, SC-22).
    pub fn from_system_conf_with_query_limits(
        cache: Arc<DnsCache>,
        query_timeout: Duration,
        retries: usize,
    ) -> DnsResult<Self> {
        // RFC 3263 §4: one query per step, for the URI's own domain.
        // NIST 800-53 Rev5: SC-5, SI-17
        Self::build_from_system_conf(cache, true, |opts| {
            opts.timeout = query_timeout;
            opts.attempts = retries;
        })
    }

    /// Builds from the system configuration, letting `adjust` override the
    /// system-derived options before the resolver is built.
    fn build_from_system_conf(
        cache: Arc<DnsCache>,
        absolute_names: bool,
        adjust: impl FnOnce(&mut ResolverOpts),
    ) -> DnsResult<Self> {
        let mut builder = TokioResolver::builder(TokioRuntimeProvider::default()).map_err(|e| {
            DnsError::ResolverInit {
                reason: format!("system DNS configuration unavailable: {e}"),
            }
        })?;
        adjust(builder.options_mut());
        let resolver = builder.build().map_err(|e| DnsError::ResolverInit {
            reason: e.to_string(),
        })?;

        Ok(Self {
            resolver,
            cache,
            default_ttl: Duration::from_mins(5),
            absolute_names,
        })
    }

    /// Creates a new resolver with hickory's default configuration.
    ///
    /// Note: hickory's default [`ResolverConfig`] points at public resolvers;
    /// production callers should use [`Self::from_system_conf`].
    ///
    /// # Errors
    ///
    /// Returns an error if the resolver cannot be created.
    // POAM: POA&M-174 - public-resolver constructor kept `pub` because
    // uc-discovery (dns.rs) still calls it; migrate to `from_system_conf`
    // and restrict to `pub(crate)` (CM-7).
    pub fn new(cache: Arc<DnsCache>) -> DnsResult<Self> {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| DnsError::ResolverInit {
            reason: e.to_string(),
        })?;

        Ok(Self {
            resolver,
            cache,
            default_ttl: Duration::from_mins(5),
            absolute_names: false,
        })
    }

    /// Creates a new resolver with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolver cannot be created.
    pub fn with_config(
        config: ResolverConfig,
        opts: ResolverOpts,
        cache: Arc<DnsCache>,
    ) -> DnsResult<Self> {
        Self::build_with_config(config, opts, cache, false)
    }

    /// Builds from an explicit configuration; `absolute_names` as in
    /// [`Self::from_system_conf_with_query_limits`].
    fn build_with_config(
        config: ResolverConfig,
        opts: ResolverOpts,
        cache: Arc<DnsCache>,
        absolute_names: bool,
    ) -> DnsResult<Self> {
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| DnsError::ResolverInit {
                reason: e.to_string(),
            })?;

        Ok(Self {
            resolver,
            cache,
            default_ttl: Duration::from_mins(5),
            absolute_names,
        })
    }

    /// Sets the default TTL for cached records.
    #[must_use]
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Returns the name to put on the wire for `name`: unchanged on the
    /// default backends; fully qualified (one trailing `.`) when
    /// `absolute_names` is set. Names already ending in `.`, IP literals and
    /// the empty name are passed through.
    // RFC 3263 §4: query the URI's domain itself, not search-list expansions.
    // NIST 800-53 Rev5: SC-5, SI-17 (one query per resolution step).
    fn query_name<'a>(&self, name: &'a str) -> Cow<'a, str> {
        if !self.absolute_names
            || name.is_empty()
            || name.ends_with('.')
            || name.parse::<IpAddr>().is_ok()
        {
            Cow::Borrowed(name)
        } else {
            Cow::Owned(format!("{name}."))
        }
    }

    /// Resolves A and AAAA records for a hostname.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub async fn lookup_addresses(&self, host: &str) -> DnsResult<Vec<IpAddr>> {
        // Check if already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // Check cache first
        if let Some(CacheEntry::Address(addrs)) = self.cache.get(host, "A").await {
            trace!(host = %host, count = addrs.len(), "Address cache hit");
            return Ok(addrs);
        }

        debug!(host = %host, "Looking up A/AAAA records");

        // Perform the lookup
        let response = self
            .resolver
            .lookup_ip(self.query_name(host).as_ref())
            .await
            .map_err(|e| DnsError::ResolutionFailed {
                domain: host.to_string(),
                reason: e.to_string(),
            })?;

        let addresses: Vec<IpAddr> = response.iter().collect();

        if addresses.is_empty() {
            return Err(DnsError::NoRecords {
                domain: host.to_string(),
            });
        }

        // Get TTL from response (use first record's TTL)
        let ttl = response
            .as_lookup()
            .answers()
            .first()
            .map_or(self.default_ttl, |r| Duration::from_secs(u64::from(r.ttl)));

        // Cache the result
        self.cache
            .put(host, "A", CacheEntry::Address(addresses.clone()), ttl)
            .await;

        debug!(host = %host, count = addresses.len(), ttl_secs = ttl.as_secs(), "Resolved addresses");
        Ok(addresses)
    }

    /// Resolves SRV records for a service name.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub async fn lookup_srv(&self, name: &str) -> DnsResult<Vec<SrvRecord>> {
        // Check cache first
        if let Some(CacheEntry::Srv(records)) = self.cache.get(name, "SRV").await {
            trace!(name = %name, count = records.len(), "SRV cache hit");
            return Ok(records);
        }

        debug!(name = %name, "Looking up SRV records");

        let response = self
            .resolver
            .lookup(self.query_name(name).as_ref(), RecordType::SRV)
            .await
            .map_err(|e| {
                // NXDOMAIN is not an error for SRV - just means no records
                if e.is_no_records_found() {
                    return DnsError::NoRecords {
                        domain: name.to_string(),
                    };
                }
                DnsError::ResolutionFailed {
                    domain: name.to_string(),
                    reason: e.to_string(),
                }
            })?;

        let mut records = Vec::new();
        let mut min_ttl = self.default_ttl;

        // Get TTL from the lookup records
        let record_ttl = response
            .answers()
            .first()
            .map_or(self.default_ttl, |r| Duration::from_secs(u64::from(r.ttl)));
        if record_ttl < min_ttl {
            min_ttl = record_ttl;
        }

        for record in response.answers() {
            let hickory_resolver::proto::rr::RData::SRV(srv) = &record.data else {
                continue;
            };
            let target = srv.target.to_utf8();
            let target = target.trim_end_matches('.');

            #[allow(clippy::cast_possible_truncation)]
            records.push(SrvRecord::new(
                name,
                srv.priority,
                srv.weight,
                srv.port,
                target,
                min_ttl.as_secs() as u32,
            ));
        }

        if records.is_empty() {
            return Err(DnsError::NoRecords {
                domain: name.to_string(),
            });
        }

        // Cache the result
        self.cache
            .put(name, "SRV", CacheEntry::Srv(records.clone()), min_ttl)
            .await;

        debug!(name = %name, count = records.len(), ttl_secs = min_ttl.as_secs(), "Resolved SRV records");
        Ok(records)
    }

    /// Resolves NAPTR records for a domain.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub async fn lookup_naptr(&self, name: &str) -> DnsResult<Vec<NaptrRecord>> {
        // Check cache first
        if let Some(CacheEntry::Naptr(records)) = self.cache.get(name, "NAPTR").await {
            trace!(name = %name, count = records.len(), "NAPTR cache hit");
            return Ok(records);
        }

        debug!(name = %name, "Looking up NAPTR records");

        // Use generic lookup for NAPTR records
        let response = self
            .resolver
            .lookup(self.query_name(name).as_ref(), RecordType::NAPTR)
            .await
            .map_err(|e| {
                // NXDOMAIN is not an error for NAPTR - just means no records
                if e.is_no_records_found() {
                    return DnsError::NoRecords {
                        domain: name.to_string(),
                    };
                }
                DnsError::ResolutionFailed {
                    domain: name.to_string(),
                    reason: e.to_string(),
                }
            })?;

        let mut records = Vec::new();
        let mut min_ttl = self.default_ttl;

        for record in response.answers() {
            let ttl = Duration::from_secs(u64::from(record.ttl));
            if ttl < min_ttl {
                min_ttl = ttl;
            }

            // Try to extract NAPTR data from the record
            if let hickory_resolver::proto::rr::RData::NAPTR(naptr) = &record.data {
                let naptr: &NAPTR = naptr;
                let replacement = naptr.replacement.to_utf8();
                let replacement = replacement.trim_end_matches('.');

                #[allow(clippy::cast_possible_truncation)]
                records.push(NaptrRecord::new(
                    name,
                    naptr.order,
                    naptr.preference,
                    std::str::from_utf8(&naptr.flags).unwrap_or(""),
                    std::str::from_utf8(&naptr.services).unwrap_or(""),
                    std::str::from_utf8(&naptr.regexp).unwrap_or(""),
                    replacement,
                    ttl.as_secs() as u32,
                ));
            }
        }

        if records.is_empty() {
            return Err(DnsError::NoRecords {
                domain: name.to_string(),
            });
        }

        // Cache the result
        self.cache
            .put(name, "NAPTR", CacheEntry::Naptr(records.clone()), min_ttl)
            .await;

        debug!(name = %name, count = records.len(), ttl_secs = min_ttl.as_secs(), "Resolved NAPTR records");
        Ok(records)
    }

    /// Looks up SRV records for a SIP service.
    ///
    /// Constructs the appropriate SRV name based on transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub async fn lookup_sip_srv(
        &self,
        domain: &str,
        transport: TransportPref,
    ) -> DnsResult<Vec<SrvRecord>> {
        let srv_name = crate::srv::SrvResolver::sip_srv_name(domain, &transport.to_string());
        self.lookup_srv(&srv_name).await
    }

    /// Resolves SRV records and their A/AAAA records.
    ///
    /// Returns SRV records with their addresses pre-resolved.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub async fn lookup_srv_with_addresses(&self, name: &str) -> DnsResult<Vec<SrvRecord>> {
        let mut records = self.lookup_srv(name).await?;

        // Resolve addresses for each target
        for record in &mut records {
            match self.lookup_addresses(&record.target).await {
                Ok(addrs) => {
                    for addr in addrs {
                        record.add_address(addr);
                    }
                }
                Err(e) => {
                    warn!(target = %record.target, error = %e, "Failed to resolve SRV target");
                }
            }
        }

        Ok(records)
    }

    /// Returns the underlying resolver.
    #[must_use]
    pub fn resolver(&self) -> &TokioResolver {
        &self.resolver
    }

    /// Returns the DNS cache.
    #[must_use]
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }
}

impl std::fmt::Debug for HickoryDnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryDnsResolver")
            .field("default_ttl", &self.default_ttl)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolver_creation() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_from_system_conf_uses_host_config_or_resolver_init() {
        let result = HickoryDnsResolver::from_system_conf(Arc::new(DnsCache::default()));
        let host_has_nameserver = std::fs::read_to_string("/etc/resolv.conf")
            .is_ok_and(|c| c.lines().any(|l| l.trim_start().starts_with("nameserver")));
        if host_has_nameserver {
            // A configured host must yield a backend built from its config.
            assert!(result.is_ok(), "system conf present but init failed");
        } else {
            // Otherwise the only acceptable outcome is a ResolverInit error,
            // never a silent fallback to hickory's public resolvers.
            assert!(matches!(result, Err(DnsError::ResolverInit { .. })));
        }
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_localhost() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache).unwrap();

        // localhost should resolve
        let result = resolver.lookup_addresses("localhost").await;
        // This may or may not work depending on system configuration
        // so we just check that it doesn't panic
        let _ = result;
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_ip_passthrough() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache).unwrap();

        // IP addresses should be returned directly
        let result = resolver.lookup_addresses("192.168.1.1").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_resolve_ipv6_passthrough() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache).unwrap();

        let result = resolver.lookup_addresses("::1").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "::1".parse::<IpAddr>().unwrap());
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_caching() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache.clone()).unwrap();

        // Pre-populate cache
        cache
            .put(
                "test.example.com",
                "A",
                CacheEntry::Address(vec!["10.0.0.1".parse().unwrap()]),
                Duration::from_mins(5),
            )
            .await;

        // Should return cached result
        let result = resolver.lookup_addresses("test.example.com").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_srv_caching() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache.clone()).unwrap();

        // Pre-populate cache with SRV records
        let srv_records = vec![
            SrvRecord::new(
                "_sip._udp.example.com",
                10,
                20,
                5060,
                "sip1.example.com",
                300,
            ),
            SrvRecord::new(
                "_sip._udp.example.com",
                20,
                10,
                5060,
                "sip2.example.com",
                300,
            ),
        ];
        cache
            .put(
                "_sip._udp.example.com",
                "SRV",
                CacheEntry::Srv(srv_records),
                Duration::from_mins(5),
            )
            .await;

        // Should return cached result
        let result = resolver.lookup_srv("_sip._udp.example.com").await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].priority, 10);
        assert_eq!(result[1].priority, 20);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn test_naptr_caching() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache.clone()).unwrap();

        // Pre-populate cache with NAPTR records
        let naptr_records = vec![NaptrRecord::new(
            "example.com",
            10,
            10,
            "s",
            "SIP+D2T",
            "",
            "_sip._tcp.example.com",
            300,
        )];
        cache
            .put(
                "example.com",
                "NAPTR",
                CacheEntry::Naptr(naptr_records),
                Duration::from_mins(5),
            )
            .await;

        // Should return cached result
        let result = resolver.lookup_naptr("example.com").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service, "SIP+D2T");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_default_ttl() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache)
            .unwrap()
            .with_default_ttl(Duration::from_mins(10));

        assert_eq!(resolver.default_ttl, Duration::from_mins(10));
    }

    /// SR-45 / RFC-2: the limits replace the system-derived per-query
    /// timeout and retry count. Skipped (no assertion on opts) on a host
    /// without a readable system DNS configuration; the constructor must then
    /// fail with `ResolverInit` exactly as `from_system_conf` does.
    #[test]
    fn test_from_system_conf_with_query_limits_applies_limits() {
        let cache = Arc::new(DnsCache::default());
        let limited = HickoryDnsResolver::from_system_conf_with_query_limits(
            Arc::clone(&cache),
            Duration::from_millis(1500),
            0,
        );
        match (limited, HickoryDnsResolver::from_system_conf(cache)) {
            (Ok(limited), Ok(system)) => {
                let opts = limited.resolver().options();
                assert_eq!(opts.timeout, Duration::from_millis(1500));
                assert_eq!(opts.attempts, 0);
                // Everything else still comes from the system config.
                let sys = system.resolver().options();
                assert_eq!(opts.ndots, sys.ndots);
                assert_eq!(opts.ip_strategy, sys.ip_strategy);
            }
            (limited, system) => assert!(
                matches!(
                    (limited, system),
                    (
                        Err(DnsError::ResolverInit { .. }),
                        Err(DnsError::ResolverInit { .. })
                    )
                ),
                "limited and system constructors must both fail with ResolverInit"
            ),
        }
    }

    /// Query names received by the stub, in arrival order.
    type SeenNames = Arc<std::sync::Mutex<Vec<String>>>;

    /// Local UDP DNS stub on 127.0.0.1 that never answers NAPTR and answers
    /// SRV/A/AAAA for one SIP domain. Returns its address, the count of
    /// NAPTR queries it ignored and every query name it received.
    async fn spawn_stub_dns() -> std::io::Result<(
        std::net::SocketAddr,
        Arc<std::sync::atomic::AtomicUsize>,
        SeenNames,
    )> {
        use hickory_resolver::proto::op::Message;
        use hickory_resolver::proto::rr::rdata::{A, AAAA, SRV};
        use hickory_resolver::proto::rr::{Name, RData, Record};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = sock.local_addr()?;
        let naptr_ignored = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&naptr_ignored);
        let names: SeenNames = Arc::default();
        let names_seen = Arc::clone(&names);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Some(packet) = buf.get(..len) else {
                    continue;
                };
                let Ok(query) = Message::from_vec(packet) else {
                    continue;
                };
                let Some(q) = query.queries.first().cloned() else {
                    continue;
                };
                let name = q.name().clone();
                if let Ok(mut log) = names_seen.lock() {
                    log.push(name.to_ascii().to_ascii_lowercase());
                }
                let rdata = match q.query_type() {
                    RecordType::NAPTR => {
                        seen.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    RecordType::SRV => {
                        let Ok(target) = Name::from_ascii("sip1.example.test.") else {
                            continue;
                        };
                        RData::SRV(SRV::new(10, 100, 5071, target))
                    }
                    RecordType::A => RData::A(A::new(192, 0, 2, 55)),
                    RecordType::AAAA => RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x55)),
                    _ => continue,
                };
                let mut response = query.into_response();
                response.add_answer(Record::from_rdata(name, 60, rdata));
                if let Ok(bytes) = response.to_vec() {
                    let _ = sock.send_to(&bytes, peer).await;
                }
            }
        });
        Ok((addr, naptr_ignored, names))
    }

    /// UDP name-server config for `stub`.
    fn stub_name_server(stub: std::net::SocketAddr) -> hickory_resolver::config::NameServerConfig {
        let mut ns = hickory_resolver::config::NameServerConfig::udp(stub.ip());
        for conn in &mut ns.connections {
            conn.port = stub.port();
        }
        ns
    }

    /// Resolver pointed only at `stub`, with the given per-query limits.
    fn stub_resolver(
        stub: std::net::SocketAddr,
        query_timeout: Duration,
        retries: usize,
    ) -> DnsResult<crate::resolver::SipResolver> {
        let mut opts = ResolverOpts::default();
        opts.timeout = query_timeout;
        opts.attempts = retries;
        let cache = Arc::new(DnsCache::default());
        let backend = HickoryDnsResolver::with_config(
            ResolverConfig::from_name_servers(vec![stub_name_server(stub)]),
            opts,
            Arc::clone(&cache),
        )?;
        Ok(crate::resolver::SipResolver::with_dns_resolver(
            crate::config::SipResolverConfig::default(),
            cache,
            backend,
        ))
    }

    /// SR-45 / RFC-2 (RFC 3263 §4.1, §4.2): through hickory's real retry
    /// path, an unanswered NAPTR query costs one per-query timeout when
    /// `retries` is 0, so SRV is asked next and its target/port is chosen
    /// well inside the soft client's 8 s chain budget. With the system
    /// defaults (5 s, 2 retries) the same NAPTR would cost 15 s.
    #[tokio::test]
    async fn test_rfc2_unanswered_naptr_falls_through_to_srv_within_query_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let (stub, naptr_ignored, _) = spawn_stub_dns().await?;
        let query_timeout = Duration::from_secs(2);
        let resolver = stub_resolver(stub, query_timeout, 0)?;

        let started = std::time::Instant::now();
        let targets = tokio::time::timeout(
            Duration::from_secs(8),
            resolver.resolve(
                "example.test",
                None,
                crate::resolver::TransportPreference::Tls,
            ),
        )
        .await??;
        let elapsed = started.elapsed();

        assert!(naptr_ignored.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        assert!(!targets.is_empty());
        assert!(targets.iter().all(|t| t.address.port() == 5071));
        assert!(
            targets
                .iter()
                .any(|t| t.address.ip() == IpAddr::from([192, 0, 2, 55]))
        );
        assert!(targets.iter().all(|t| t.transport == TransportPref::Tls));
        // NAPTR waited out its one timeout; no re-send was made.
        assert!(
            elapsed >= query_timeout,
            "NAPTR returned early: {elapsed:?}"
        );
        assert!(
            elapsed < query_timeout * 2,
            "NAPTR was re-sent or SRV/A was slow: {elapsed:?}"
        );
        Ok(())
    }

    /// hickory 0.26 `ResolverOpts::attempts` counts re-sends after the first
    /// send: with 2 the unanswered NAPTR costs three timeouts.
    #[tokio::test]
    async fn test_rfc2_retries_count_resends_after_first_send()
    -> Result<(), Box<dyn std::error::Error>> {
        let (stub, _, _) = spawn_stub_dns().await?;
        let query_timeout = Duration::from_millis(300);
        let resolver = stub_resolver(stub, query_timeout, 2)?;

        let started = std::time::Instant::now();
        let targets = resolver
            .resolve(
                "example.test",
                None,
                crate::resolver::TransportPreference::Tls,
            )
            .await?;
        let elapsed = started.elapsed();

        assert!(targets.iter().all(|t| t.address.port() == 5071));
        assert!(
            elapsed >= query_timeout * 3,
            "expected three NAPTR sends, took {elapsed:?}"
        );
        Ok(())
    }

    /// Three resolv.conf-style search domains for the RFC-11 tests.
    fn search_config(
        stub: std::net::SocketAddr,
    ) -> Result<ResolverConfig, Box<dyn std::error::Error>> {
        use hickory_resolver::proto::rr::Name;
        let search = vec![
            Name::from_ascii("corp.test.")?,
            Name::from_ascii("lab.test.")?,
            Name::from_ascii("dev.test.")?,
        ];
        Ok(ResolverConfig::from_parts(
            None,
            search,
            vec![stub_name_server(stub)],
        ))
    }

    /// True if `name` is one of the three search domains appended to a
    /// query name.
    fn is_search_expanded(name: &str) -> bool {
        ["corp.test.", "lab.test.", "dev.test."]
            .iter()
            .any(|suffix| name.ends_with(&format!(".{suffix}")))
    }

    #[test]
    fn test_rfc11_query_name_qualifies_only_when_absolute() -> DnsResult<()> {
        let cache = Arc::new(DnsCache::default());
        let mut resolver = HickoryDnsResolver::with_config(
            ResolverConfig::from_name_servers(Vec::new()),
            ResolverOpts::default(),
            cache,
        )?;
        assert!(!resolver.absolute_names);
        assert_eq!(resolver.query_name("example.test"), "example.test");

        resolver.absolute_names = true;
        assert_eq!(resolver.query_name("example.test"), "example.test.");
        assert_eq!(
            resolver.query_name("_sips._tcp.example.test"),
            "_sips._tcp.example.test."
        );
        // Not doubled.
        assert_eq!(resolver.query_name("example.test."), "example.test.");
        // IP literals and the empty name pass through untouched.
        assert_eq!(resolver.query_name("192.0.2.1"), "192.0.2.1");
        assert_eq!(resolver.query_name("2001:db8::1"), "2001:db8::1");
        assert_eq!(resolver.query_name(""), "");
        Ok(())
    }

    /// The flag is set by the query-limited constructor only.
    #[test]
    fn test_rfc11_absolute_names_set_only_by_query_limited_constructor() {
        let cache = Arc::new(DnsCache::default());
        if let Ok(r) = HickoryDnsResolver::new(Arc::clone(&cache)) {
            assert!(!r.absolute_names);
        }
        if let Ok(r) = HickoryDnsResolver::from_system_conf(Arc::clone(&cache)) {
            assert!(!r.absolute_names);
        }
        if let Ok(r) =
            HickoryDnsResolver::from_system_conf_with_query_limits(cache, Duration::from_secs(2), 0)
        {
            assert!(r.absolute_names);
        }
    }

    /// SR-45 / RFC-11 (RFC 3263 §4): on the query-limited backend, with three
    /// search domains configured and NAPTR unanswered, each step costs one
    /// query for the URI's own domain: NAPTR (2 s timeout), then SRV and the
    /// target's A/AAAA, inside the 8 s chain. The stub never sees a
    /// search-expanded name.
    #[tokio::test]
    async fn test_rfc11_absolute_names_skip_search_expansion()
    -> Result<(), Box<dyn std::error::Error>> {
        let (stub, naptr_ignored, names) = spawn_stub_dns().await?;
        let query_timeout = Duration::from_secs(2);
        let mut opts = ResolverOpts::default();
        opts.timeout = query_timeout;
        opts.attempts = 0;
        let cache = Arc::new(DnsCache::default());
        let backend = HickoryDnsResolver::build_with_config(
            search_config(stub)?,
            opts,
            Arc::clone(&cache),
            true,
        )?;
        let resolver = crate::resolver::SipResolver::with_dns_resolver(
            crate::config::SipResolverConfig::default(),
            Arc::clone(&cache),
            backend,
        );

        let started = std::time::Instant::now();
        let targets = tokio::time::timeout(
            Duration::from_secs(8),
            resolver.resolve(
                "example.test",
                None,
                crate::resolver::TransportPreference::Tls,
            ),
        )
        .await??;
        let elapsed = started.elapsed();

        assert!(naptr_ignored.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        assert!(targets.iter().all(|t| t.address.port() == 5071));
        assert!(
            targets
                .iter()
                .any(|t| t.address.ip() == IpAddr::from([192, 0, 2, 55]))
        );
        // One NAPTR timeout, not one per search domain.
        assert!(
            elapsed < query_timeout * 2,
            "NAPTR was retried per search domain: {elapsed:?}"
        );
        let seen = names.lock().map_or_else(|_| Vec::new(), |n| n.clone());
        assert!(
            !seen.iter().any(|n| is_search_expanded(n)),
            "search-expanded query sent: {seen:?}"
        );
        assert!(seen.iter().any(|n| n == "example.test."));
        assert!(seen.iter().any(|n| n == "_sips._tcp.example.test."));
        assert!(seen.iter().any(|n| n == "sip1.example.test."));

        // Cache keys stay bare, so the SipResolver's own cache checks hit.
        assert!(
            matches!(
                cache.get("_sips._tcp.example.test", "SRV").await,
                Some(CacheEntry::Srv(_))
            ),
            "SRV cached under the bare name"
        );
        assert!(
            matches!(
                cache.get("sip1.example.test", "A").await,
                Some(CacheEntry::Address(_))
            ),
            "target address cached under the bare name"
        );
        Ok(())
    }

    /// RFC-11 scope: the default (`with_config`, as used by `from_system_conf`
    /// and uc-discovery) backend keeps hickory's search-list behaviour; an
    /// unanswered NAPTR is retried under each search domain.
    #[tokio::test]
    async fn test_rfc11_default_backend_keeps_search_expansion()
    -> Result<(), Box<dyn std::error::Error>> {
        let (stub, _, names) = spawn_stub_dns().await?;
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(300);
        opts.attempts = 0;
        let backend = HickoryDnsResolver::with_config(
            search_config(stub)?,
            opts,
            Arc::new(DnsCache::default()),
        )?;
        assert!(!backend.absolute_names);

        let result = backend.lookup_naptr("example.test").await;
        assert!(result.is_err());
        let seen = names.lock().map_or_else(|_| Vec::new(), |n| n.clone());
        assert!(
            seen.iter().any(|n| is_search_expanded(n)),
            "default backend no longer expands search domains: {seen:?}"
        );
        Ok(())
    }
}
