//! SRV record handling for SIP DNS (RFC 3263).
//!
//! SRV records provide service discovery with priority and weight-based
//! load balancing.

use crate::error::{DnsError, DnsResult};
use std::cmp::Ordering;
use std::net::IpAddr;
use tracing::debug;

/// SRV record per RFC 2782.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Service name (e.g., "_sip._udp.example.com").
    pub name: String,
    /// Priority (lower is preferred).
    pub priority: u16,
    /// Weight for load balancing within same priority.
    pub weight: u16,
    /// Port number.
    pub port: u16,
    /// Target hostname.
    pub target: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// Resolved IP addresses (if available).
    pub addresses: Vec<IpAddr>,
}

impl SrvRecord {
    /// Creates a new SRV record.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        priority: u16,
        weight: u16,
        port: u16,
        target: impl Into<String>,
        ttl: u32,
    ) -> Self {
        Self {
            name: name.into(),
            priority,
            weight,
            port,
            target: target.into(),
            ttl,
            addresses: Vec::new(),
        }
    }

    /// Adds a resolved IP address.
    pub fn add_address(&mut self, addr: IpAddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Returns true if this is a "null" SRV record (target is ".").
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.target == "." || self.target.is_empty()
    }
}

impl Ord for SrvRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower priority first
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => {
                // Higher weight first within same priority
                other.weight.cmp(&self.weight)
            }
            other => other,
        }
    }
}

impl PartialOrd for SrvRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// SRV resolver for SIP services.
#[derive(Debug)]
pub struct SrvResolver {
    /// Cached SRV records by service name.
    records: Vec<SrvRecord>,
}

impl SrvResolver {
    /// Creates a new SRV resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Adds SRV records from a lookup result.
    pub fn add_records(&mut self, records: Vec<SrvRecord>) {
        self.records.extend(records);
        self.records.sort();
    }

    /// Clears all cached records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns the number of cached records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true if no records are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Selects the next target using RFC 2782 weighted selection.
    ///
    /// Within the best priority level, a target is chosen at random with
    /// probability proportional to its weight (zero-weight targets remain
    /// reachable with a small probability).
    #[must_use]
    pub fn select_target(&self) -> Option<&SrvRecord> {
        Self::select_with(&self.records, random_inclusive)
    }

    /// RFC 2782 selection with an injectable RNG: `rng(max)` must return a
    /// uniform value in `0..=max`.
    fn select_with(records: &[SrvRecord], rng: impl FnMut(u32) -> u32) -> Option<&SrvRecord> {
        let valid: Vec<&SrvRecord> = records.iter().filter(|r| !r.is_null()).collect();
        let best = valid.iter().map(|r| r.priority).min()?;
        let tier: Vec<&SrvRecord> = valid.into_iter().filter(|r| r.priority == best).collect();
        pick_weighted(&tier, rng).and_then(|i| tier.get(i).copied())
    }

    /// Selects all targets in RFC 2782 order: ascending priority, and within
    /// each priority a weighted-random permutation.
    #[must_use]
    pub fn select_all(&self) -> Vec<&SrvRecord> {
        order_with(
            self.records.iter().filter(|r| !r.is_null()).collect(),
            random_inclusive,
        )
    }

    /// Orders `records` per RFC 2782 (null targets dropped), returning owned
    /// copies in the order a client should try them.
    #[must_use]
    pub fn order_rfc2782(records: &[SrvRecord]) -> Vec<SrvRecord> {
        order_with(
            records.iter().filter(|r| !r.is_null()).collect(),
            random_inclusive,
        )
        .into_iter()
        .cloned()
        .collect()
    }

    /// Constructs an SRV query name for a SIP domain.
    #[must_use]
    pub fn sip_srv_name(domain: &str, transport: &str) -> String {
        let prefix = match transport.to_uppercase().as_str() {
            "TCP" => "_sip._tcp",
            "TLS" | "SIPS" => "_sips._tcp",
            "SCTP" => "_sip._sctp",
            "WS" => "_sip._ws",
            "WSS" => "_sips._wss",
            // UDP is the default for SIP
            _ => "_sip._udp",
        };
        format!("{prefix}.{domain}")
    }

    /// Parses an SRV record from a DNS response string.
    ///
    /// Format: "priority weight port target"
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid.
    pub fn parse_record(name: &str, data: &str, ttl: u32) -> DnsResult<SrvRecord> {
        let parts: Vec<&str> = data.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(DnsError::InvalidSrv {
                reason: format!("expected 4 parts, got {}", parts.len()),
            });
        }

        let priority = parts[0].parse::<u16>().map_err(|e| DnsError::InvalidSrv {
            reason: format!("invalid priority: {e}"),
        })?;

        let weight = parts[1].parse::<u16>().map_err(|e| DnsError::InvalidSrv {
            reason: format!("invalid weight: {e}"),
        })?;

        let port = parts[2].parse::<u16>().map_err(|e| DnsError::InvalidSrv {
            reason: format!("invalid port: {e}"),
        })?;

        let target = parts[3].trim_end_matches('.').to_string();

        debug!(
            name = %name,
            priority,
            weight,
            port,
            target = %target,
            "Parsed SRV record"
        );

        Ok(SrvRecord::new(name, priority, weight, port, target, ttl))
    }
}

/// Uniform random value in `0..=max` from the thread-local CSPRNG.
fn random_inclusive(max: u32) -> u32 {
    use rand::Rng;
    rand::rng().random_range(0..=max)
}

/// RFC 2782 "Usage rules": pick one index from a single priority tier.
///
/// Zero-weight records are placed first, running sums are computed, a
/// uniform value in `0..=total` is drawn, and the first record whose running
/// sum is `>=` the draw is selected. Weights are summed as `u32` with
/// `saturating_add`, so attacker-supplied weights cannot overflow.
fn pick_weighted(tier: &[&SrvRecord], mut rng: impl FnMut(u32) -> u32) -> Option<usize> {
    if tier.is_empty() {
        return None;
    }
    // Zero weights first (RFC 2782), stable otherwise.
    let mut order: Vec<usize> = (0..tier.len()).collect();
    order.sort_by_key(|&i| tier.get(i).is_some_and(|r| r.weight != 0));
    let total = tier
        .iter()
        .fold(0u32, |acc, r| acc.saturating_add(u32::from(r.weight)));
    let draw = rng(total);
    let mut running = 0u32;
    for &i in &order {
        running = running.saturating_add(tier.get(i).map_or(0, |r| u32::from(r.weight)));
        if running >= draw {
            return Some(i);
        }
    }
    order.last().copied()
}

/// RFC 2782 full ordering: priority ascending, weighted-random within tier.
fn order_with(mut records: Vec<&SrvRecord>, mut rng: impl FnMut(u32) -> u32) -> Vec<&SrvRecord> {
    records.sort_by_key(|r| r.priority);
    let mut out = Vec::with_capacity(records.len());
    let mut start = 0;
    while start < records.len() {
        let prio = records.get(start).map_or(0, |r| r.priority);
        let end = records
            .iter()
            .skip(start)
            .position(|r| r.priority != prio)
            .map_or(records.len(), |n| start + n);
        let mut tier: Vec<&SrvRecord> = records.get(start..end).unwrap_or_default().to_vec();
        while let Some(i) = pick_weighted(&tier, &mut rng) {
            out.push(tier.remove(i));
        }
        start = end;
    }
    out
}

impl Default for SrvResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv_record_creation() {
        let record = SrvRecord::new(
            "_sip._udp.example.com",
            10,
            20,
            5060,
            "sip1.example.com",
            300,
        );
        assert_eq!(record.priority, 10);
        assert_eq!(record.weight, 20);
        assert_eq!(record.port, 5060);
        assert!(!record.is_null());
    }

    #[test]
    fn test_srv_null_record() {
        let record = SrvRecord::new("_sip._udp.example.com", 0, 0, 0, ".", 300);
        assert!(record.is_null());
    }

    #[test]
    fn test_srv_ordering() {
        let r1 = SrvRecord::new("", 10, 20, 5060, "a.example.com", 300);
        let r2 = SrvRecord::new("", 20, 30, 5060, "b.example.com", 300);
        let r3 = SrvRecord::new("", 10, 30, 5060, "c.example.com", 300);

        // r1 < r2 (lower priority)
        assert!(r1 < r2);
        // r3 < r1 (same priority, higher weight)
        assert!(r3 < r1);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_srv_resolver_selection() {
        let mut resolver = SrvResolver::new();
        resolver.add_records(vec![
            SrvRecord::new("", 20, 10, 5060, "backup.example.com", 300),
            SrvRecord::new("", 10, 20, 5060, "primary.example.com", 300),
        ]);

        let target = resolver.select_target();
        assert!(target.is_some());
        // Should select the lower priority (10) first
        assert_eq!(target.unwrap().target, "primary.example.com");
    }

    fn tier() -> Vec<SrvRecord> {
        vec![
            SrvRecord::new("", 10, 10, 5060, "a.test", 300),
            SrvRecord::new("", 10, 30, 5060, "b.test", 300),
            SrvRecord::new("", 10, 60, 5060, "c.test", 300),
            SrvRecord::new("", 20, 100, 5060, "backup.test", 300),
        ]
    }

    #[test]
    fn test_weighted_boundaries() {
        let recs = tier();
        // Running sums: a=10, b=40, c=100 (draw in 0..=100).
        let pick = |d: u32| SrvResolver::select_with(&recs, |_| d).map(|r| r.target.clone());
        assert_eq!(pick(0).as_deref(), Some("a.test"));
        assert_eq!(pick(10).as_deref(), Some("a.test"));
        assert_eq!(pick(11).as_deref(), Some("b.test"));
        assert_eq!(pick(40).as_deref(), Some("b.test"));
        assert_eq!(pick(41).as_deref(), Some("c.test"));
        assert_eq!(pick(100).as_deref(), Some("c.test"));
    }

    #[test]
    fn test_zero_weight_reachable_and_all_zero() {
        let recs = vec![
            SrvRecord::new("", 1, 5, 5060, "w.test", 300),
            SrvRecord::new("", 1, 0, 5060, "z.test", 300),
        ];
        // Zero-weight is ordered first and selected on a draw of 0.
        let r = SrvResolver::select_with(&recs, |_| 0);
        assert_eq!(r.map(|r| r.target.as_str()), Some("z.test"));
        let r = SrvResolver::select_with(&recs, |m| m);
        assert_eq!(r.map(|r| r.target.as_str()), Some("w.test"));

        let zeros = vec![
            SrvRecord::new("", 1, 0, 5060, "x.test", 300),
            SrvRecord::new("", 1, 0, 5060, "y.test", 300),
        ];
        assert!(SrvResolver::select_with(&zeros, |_| 0).is_some());
        let mut r = SrvResolver::new();
        r.add_records(zeros);
        assert_eq!(r.select_all().len(), 2);
    }

    #[allow(clippy::panic)]
    #[test]
    fn test_weighted_distribution() {
        let mut resolver = SrvResolver::new();
        resolver.add_records(tier());
        let (mut a, mut b, mut c) = (0u32, 0u32, 0u32);
        let n = 10_000u32;
        for _ in 0..n {
            match resolver.select_target().map(|r| r.target.as_str()) {
                Some("a.test") => a += 1,
                Some("b.test") => b += 1,
                Some("c.test") => c += 1,
                other => panic!("unexpected selection {other:?}"),
            }
        }
        // Expected shares 10/30/60.
        for (count, expected) in [(a, 0.10_f64), (b, 0.30), (c, 0.60)] {
            let share = f64::from(count) / f64::from(n);
            assert!(
                (share - expected).abs() < 0.03,
                "share {share} vs {expected}"
            );
        }
    }

    #[test]
    fn test_order_respects_priority_and_is_permutation() {
        let recs = tier();
        let mut draws = [100u32, 0, 0].into_iter();
        let ordered = order_with(recs.iter().collect(), |m| draws.next().unwrap_or(m));
        let names: Vec<_> = ordered.iter().map(|r| r.target.as_str()).collect();
        assert_eq!(names, ["c.test", "a.test", "b.test", "backup.test"]);
        let owned = SrvResolver::order_rfc2782(&recs);
        assert_eq!(owned.len(), 4);
        assert_eq!(owned.last().map(|r| r.target.as_str()), Some("backup.test"));
    }

    #[test]
    fn test_sip_srv_name() {
        assert_eq!(
            SrvResolver::sip_srv_name("example.com", "UDP"),
            "_sip._udp.example.com"
        );
        assert_eq!(
            SrvResolver::sip_srv_name("example.com", "TLS"),
            "_sips._tcp.example.com"
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_parse_record() {
        let record =
            SrvResolver::parse_record("_sip._udp.example.com", "10 20 5060 sip.example.com.", 300)
                .unwrap();

        assert_eq!(record.priority, 10);
        assert_eq!(record.weight, 20);
        assert_eq!(record.port, 5060);
        assert_eq!(record.target, "sip.example.com");
    }
}
