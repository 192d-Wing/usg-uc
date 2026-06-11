//! Dynamic blocklist: source IPs and caller-number prefixes.
//!
//! Entries come from static configuration (no expiry) or from runtime
//! mitigation (timed). The mutation API is the surface the phase-3
//! `VpsPolicySync` gRPC service will drive, letting the analytics pod
//! install timed blocks cluster-wide.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Expiry for a blocklist entry. `None` = permanent (static config).
type Expiry = Option<Instant>;

fn is_active(expiry: &Expiry) -> bool {
    expiry.is_none_or(|at| Instant::now() < at)
}

/// Dynamic blocklist of sources and caller prefixes.
#[derive(Debug, Default)]
pub struct Blocklist {
    /// Blocked source IPs.
    sources: HashMap<IpAddr, Expiry>,
    /// Blocked caller-number prefixes.
    caller_prefixes: Vec<(String, Expiry)>,
}

impl Blocklist {
    /// Creates an empty blocklist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Blocks a source IP. `duration` of `None` blocks permanently.
    pub fn block_source(&mut self, source: IpAddr, duration: Option<Duration>) {
        self.sources
            .insert(source, duration.map(|d| Instant::now() + d));
    }

    /// Unblocks a source IP.
    pub fn unblock_source(&mut self, source: IpAddr) {
        self.sources.remove(&source);
    }

    /// Blocks a caller-number prefix. `duration` of `None` blocks
    /// permanently. Re-blocking an existing prefix replaces its expiry.
    pub fn block_caller_prefix(&mut self, prefix: impl Into<String>, duration: Option<Duration>) {
        let prefix = prefix.into();
        let expiry = duration.map(|d| Instant::now() + d);
        if let Some(entry) = self.caller_prefixes.iter_mut().find(|(p, _)| *p == prefix) {
            entry.1 = expiry;
        } else {
            self.caller_prefixes.push((prefix, expiry));
        }
    }

    /// Unblocks a caller-number prefix.
    pub fn unblock_caller_prefix(&mut self, prefix: &str) {
        self.caller_prefixes.retain(|(p, _)| p != prefix);
    }

    /// Whether a source IP is currently blocked.
    pub fn is_source_blocked(&self, source: IpAddr) -> bool {
        self.sources.get(&source).is_some_and(is_active)
    }

    /// Returns the blocking prefix if the caller number is blocked.
    pub fn caller_block_match(&self, caller: &str) -> Option<&str> {
        self.caller_prefixes
            .iter()
            .find(|(prefix, expiry)| is_active(expiry) && caller.starts_with(prefix.as_str()))
            .map(|(prefix, _)| prefix.as_str())
    }

    /// Removes expired entries.
    pub fn cleanup(&mut self) {
        self.sources.retain(|_, expiry| is_active(expiry));
        self.caller_prefixes.retain(|(_, expiry)| is_active(expiry));
    }

    /// Number of active blocked sources.
    pub fn blocked_source_count(&self) -> usize {
        self.sources.values().filter(|e| is_active(e)).count()
    }

    /// Number of active blocked caller prefixes.
    pub fn blocked_prefix_count(&self) -> usize {
        self.caller_prefixes
            .iter()
            .filter(|(_, e)| is_active(e))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn test_source_blocking() {
        let mut bl = Blocklist::new();
        assert!(!bl.is_source_blocked(ip(1)));

        bl.block_source(ip(1), None);
        assert!(bl.is_source_blocked(ip(1)));
        assert!(!bl.is_source_blocked(ip(2)));

        bl.unblock_source(ip(1));
        assert!(!bl.is_source_blocked(ip(1)));
    }

    #[test]
    fn test_timed_block_expires() {
        let mut bl = Blocklist::new();
        bl.block_source(ip(1), Some(Duration::ZERO));
        assert!(!bl.is_source_blocked(ip(1)));

        bl.cleanup();
        assert_eq!(bl.blocked_source_count(), 0);
    }

    #[test]
    fn test_caller_prefix_blocking() {
        let mut bl = Blocklist::new();
        bl.block_caller_prefix("+1900", None);

        assert_eq!(bl.caller_block_match("+19005551234"), Some("+1900"));
        assert_eq!(bl.caller_block_match("+12135551234"), None);

        bl.unblock_caller_prefix("+1900");
        assert_eq!(bl.caller_block_match("+19005551234"), None);
    }

    #[test]
    fn test_reblock_replaces_expiry() {
        let mut bl = Blocklist::new();
        bl.block_caller_prefix("+1900", Some(Duration::ZERO));
        bl.block_caller_prefix("+1900", None);
        assert_eq!(bl.caller_block_match("+19005551234"), Some("+1900"));
        assert_eq!(bl.blocked_prefix_count(), 1);
    }
}
