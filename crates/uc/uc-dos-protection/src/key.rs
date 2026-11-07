//! Rate-limit source keys.
//!
//! An attacker controls the low bits of its source address: a single IPv6
//! end site is routinely delegated a whole /64 (2^64 addresses), and a
//! dual-stack socket reports IPv4 peers as v4-mapped IPv6 (`::ffff:a.b.c.d`).
//! Keying limiter state on the raw address lets one host rotate through
//! fresh buckets and dodge blocks. [`source_key`] collapses both forms.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)

use std::net::{IpAddr, Ipv6Addr};

/// Default IPv6 prefix length used to key per-source limiter state.
pub const DEFAULT_IPV6_PREFIX_LEN: u8 = 64;

/// Normalizes a source address into the key used for per-source state.
///
/// - v4-mapped IPv6 addresses are unmapped to IPv4 (`IpAddr::to_canonical`),
///   so the same host is one key on a dual-stack and a v4-only socket.
/// - IPv6 addresses are masked to the leading `v6_prefix_len` bits
///   (clamped to 128). A length of 0 keys all IPv6 to `::`.
/// - IPv4 addresses are returned unchanged.
///
/// Allocation-free: a branch and a `u128` mask.
#[must_use]
pub fn source_key(ip: IpAddr, v6_prefix_len: u8) -> IpAddr {
    match ip.to_canonical() {
        v4 @ IpAddr::V4(_) => v4,
        IpAddr::V6(v6) => {
            let len = u32::from(v6_prefix_len.min(128));
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn source_key_masks_v6_to_prefix() {
        let a = source_key(v6("2001:db8:1:2:aaaa::1"), 64);
        let b = source_key(v6("2001:db8:1:2:ffff:ffff:ffff:ffff"), 64);
        assert_eq!(a, b);
        assert_eq!(a, v6("2001:db8:1:2::"));
        let c = source_key(v6("2001:db8:1:3::1"), 64);
        assert_ne!(a, c);
        // /128 is identity.
        assert_eq!(
            source_key(v6("2001:db8:1:2:aaaa::1"), 128),
            v6("2001:db8:1:2:aaaa::1")
        );
        // Out-of-range lengths clamp to 128.
        assert_eq!(source_key(v6("2001:db8::1"), 200), v6("2001:db8::1"));
        assert_eq!(source_key(v6("2001:db8::1"), 0), v6("::"));
    }

    #[test]
    fn source_key_unmaps_v4_mapped() {
        let mapped = v6("::ffff:192.0.2.7");
        assert_eq!(
            source_key(mapped, 64),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
        );
    }

    // Table-driven property checks: idempotent, IPv4 unchanged.
    #[test]
    fn source_key_is_idempotent_and_keeps_v4() {
        let samples = [
            "192.0.2.1",
            "198.51.100.255",
            "::ffff:203.0.113.9",
            "2001:db8::1",
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::1",
            "::",
            "::1",
        ];
        for prefix in [32u8, 48, 56, 64, 96, 128] {
            for s in samples {
                let ip = v6_or_v4(s);
                let once = source_key(ip, prefix);
                assert_eq!(source_key(once, prefix), once, "{s}/{prefix}");
                if ip.is_ipv4() {
                    assert_eq!(once, ip);
                }
            }
        }
    }

    fn v6_or_v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
}
