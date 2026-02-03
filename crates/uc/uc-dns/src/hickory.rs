//! Hickory DNS resolver integration.
//!
//! This module provides actual DNS resolution using the hickory-resolver crate.
//! It is only available when the `resolver` feature is enabled.

use crate::cache::{CacheEntry, DnsCache};
use crate::config::TransportPref;
use crate::error::{DnsError, DnsResult};
use crate::naptr::NaptrRecord;
use crate::srv::SrvRecord;
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::rr::rdata::NAPTR;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Type alias for the tokio-based resolver.
type TokioResolver = Resolver<TokioConnectionProvider>;

/// DNS resolver using hickory-resolver for actual DNS queries.
pub struct HickoryDnsResolver {
    /// The underlying resolver.
    resolver: TokioResolver,
    /// DNS cache for caching results.
    cache: Arc<DnsCache>,
    /// Default TTL for cached records when DNS doesn't provide one.
    default_ttl: Duration,
}

impl HickoryDnsResolver {
    /// Creates a new resolver with system configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolver cannot be created.
    pub fn new(cache: Arc<DnsCache>) -> DnsResult<Self> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self {
            resolver,
            cache,
            default_ttl: Duration::from_secs(300),
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
        let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();

        Ok(Self {
            resolver,
            cache,
            default_ttl: Duration::from_secs(300),
        })
    }

    /// Sets the default TTL for cached records.
    #[must_use]
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
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
        let response =
            self.resolver
                .lookup_ip(host)
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
            .record_iter()
            .next()
            .map_or(self.default_ttl, |r| {
                Duration::from_secs(u64::from(r.ttl()))
            });

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

        let response = self.resolver.srv_lookup(name).await.map_err(|e| {
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
            .as_lookup()
            .record_iter()
            .next()
            .map_or(self.default_ttl, |r| {
                Duration::from_secs(u64::from(r.ttl()))
            });
        if record_ttl < min_ttl {
            min_ttl = record_ttl;
        }

        for srv in response.iter() {
            let target = srv.target().to_utf8();
            let target = target.trim_end_matches('.');

            #[allow(clippy::cast_possible_truncation)]
            records.push(SrvRecord::new(
                name,
                srv.priority(),
                srv.weight(),
                srv.port(),
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
            .lookup(name, RecordType::NAPTR)
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

        for record in response.record_iter() {
            let ttl = Duration::from_secs(u64::from(record.ttl()));
            if ttl < min_ttl {
                min_ttl = ttl;
            }

            // Try to extract NAPTR data from the record
            if let Some(naptr) = record.data().as_naptr() {
                let naptr: &NAPTR = naptr;
                let replacement = naptr.replacement().to_utf8();
                let replacement = replacement.trim_end_matches('.');

                #[allow(clippy::cast_possible_truncation)]
                records.push(NaptrRecord::new(
                    name,
                    naptr.order(),
                    naptr.preference(),
                    std::str::from_utf8(naptr.flags()).unwrap_or(""),
                    std::str::from_utf8(naptr.services()).unwrap_or(""),
                    std::str::from_utf8(naptr.regexp()).unwrap_or(""),
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

    #[tokio::test]
    async fn test_resolve_ip_passthrough() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache).unwrap();

        // IP addresses should be returned directly
        let result = resolver.lookup_addresses("192.168.1.1").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_ipv6_passthrough() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache).unwrap();

        let result = resolver.lookup_addresses("::1").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "::1".parse::<IpAddr>().unwrap());
    }

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
                Duration::from_secs(300),
            )
            .await;

        // Should return cached result
        let result = resolver.lookup_addresses("test.example.com").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
    }

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
                Duration::from_secs(300),
            )
            .await;

        // Should return cached result
        let result = resolver.lookup_srv("_sip._udp.example.com").await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].priority, 10);
        assert_eq!(result[1].priority, 20);
    }

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
                Duration::from_secs(300),
            )
            .await;

        // Should return cached result
        let result = resolver.lookup_naptr("example.com").await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service, "SIP+D2T");
    }

    #[test]
    fn test_default_ttl() {
        let cache = Arc::new(DnsCache::default());
        let resolver = HickoryDnsResolver::new(cache)
            .unwrap()
            .with_default_ttl(Duration::from_secs(600));

        assert_eq!(resolver.default_ttl, Duration::from_secs(600));
    }
}
