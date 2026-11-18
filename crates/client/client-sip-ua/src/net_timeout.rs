//! Deadlines for name resolution on the signalling path (SR-45).
//!
//! DNS lookups run inside the client event pump; an unanswered query must
//! not stall registration refresh, inbound calls or hang-up.
//!
//! NIST 800-53 Rev5: SC-5 (denial-of-service protection), SI-17 (fail-safe).

use crate::{SipUaError, SipUaResult};
use std::future::Future;
use std::time::Duration;

/// Deadline for one system A/AAAA lookup (fallback, registrar).
pub const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Time limit for one RFC 3263 NAPTR, SRV or A/AAAA query against the
/// system name servers (replaces resolv.conf `timeout:`, 5 s by default).
///
/// Inside this window hickory's UDP client re-sends the query at
/// max(1.2 x decayed SRTT, 333 ms), so under normal SRTT the query tolerates
/// one lost packet.
// NIST 800-53 Rev5: SC-5, SI-17
pub const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Re-sends after a timed-out query (replaces resolv.conf `attempts:`, 2 by
/// default). hickory 0.26 counts this after the first send, so an unanswered
/// query costs `DNS_QUERY_TIMEOUT * (DNS_QUERY_RETRIES + 1)` = 2 s; with the
/// system defaults it cost 5 s * 3 = 15 s.
// NIST 800-53 Rev5: SC-5, SI-17
pub const DNS_QUERY_RETRIES: usize = 0;

/// Deadline for the whole RFC 3263 NAPTR -> SRV -> A/AAAA chain.
///
/// The query-limited backend sends absolute names (no search-domain
/// expansion), so each step is one query bounded at 2 s (A and AAAA are
/// queried concurrently). NAPTR, SRV and the SRV target's A/AAAA all going
/// unanswered cost 6 s, so an unanswered NAPTR still leaves time for SRV and
/// the target lookup (RFC 3263 §4.1, §4.2). The extra 2 s covers one spare
/// query, e.g. a second SRV target whose address lookup is unanswered.
/// Chain plus the A/AAAA fallback (8 s + 5 s = 13 s) stays under Timer B
/// (64*T1 = 32 s); DNS runs before the transaction is created in any case.
// NIST 800-53 Rev5: SC-5, SI-17
pub const DNS_RESOLVE_CHAIN_TIMEOUT: Duration = Duration::from_secs(8);

/// Runs the DNS lookup `lookup` for `host`, bounded by `timeout`.
///
/// The lookup's own `Ok`/`Err` is returned unchanged; only expiry of the
/// deadline is mapped to a [`SipUaError::ConfigError`] naming the host.
// NIST 800-53 Rev5: SC-5, SI-17 (bounded resolution; fail closed).
pub async fn bounded_dns<T, F>(host: &str, timeout: Duration, lookup: F) -> SipUaResult<T>
where
    F: Future<Output = SipUaResult<T>>,
{
    tokio::time::timeout(timeout, lookup).await.map_err(|_| {
        tracing::warn!(host = %host, timeout = ?timeout, "DNS lookup timed out");
        SipUaError::ConfigError(format!("DNS lookup for {host} timed out after {timeout:?}"))
    })?
}

#[cfg(test)]
mod tests {
    use super::{
        DNS_LOOKUP_TIMEOUT, DNS_QUERY_RETRIES, DNS_QUERY_TIMEOUT, DNS_RESOLVE_CHAIN_TIMEOUT,
        bounded_dns,
    };
    use crate::{SipUaError, SipUaResult};
    use std::net::SocketAddr;
    use std::time::Duration;

    #[test]
    fn test_sr45_dns_lookup_timeout_value() {
        assert_eq!(DNS_LOOKUP_TIMEOUT, Duration::from_secs(5));
        assert_eq!(DNS_RESOLVE_CHAIN_TIMEOUT, Duration::from_secs(8));
        assert_eq!(DNS_QUERY_TIMEOUT, Duration::from_secs(2));
        assert_eq!(DNS_QUERY_RETRIES, 0);
    }

    /// RFC-2: three unanswered queries in a row (NAPTR, SRV, A/AAAA) fit in
    /// the chain budget with room for one more, so SRV is always asked after
    /// an unanswered NAPTR.
    #[test]
    fn test_rfc2_chain_budget_covers_three_unanswered_queries() {
        let per_query = DNS_QUERY_TIMEOUT * u32::try_from(DNS_QUERY_RETRIES + 1).unwrap();
        assert!(per_query * 4 <= DNS_RESOLVE_CHAIN_TIMEOUT);
        assert!(DNS_RESOLVE_CHAIN_TIMEOUT + DNS_LOOKUP_TIMEOUT < Duration::from_secs(32));
    }

    /// RFC-2: an RFC 3263 chain slower than the single-lookup budget still
    /// succeeds within the chain budget, where the 5 s budget would have cut
    /// it off.
    #[tokio::test(start_paused = true)]
    async fn test_rfc2_slow_resolve_chain_fits_chain_budget() {
        let addr: SocketAddr = "192.0.2.20:5061".parse().unwrap();
        let chain = || async move {
            tokio::time::sleep(Duration::from_secs(6)).await;
            Ok(vec![addr])
        };
        let ok = bounded_dns("srv.example", DNS_RESOLVE_CHAIN_TIMEOUT, chain())
            .await
            .unwrap();
        assert_eq!(ok, vec![addr]);
        let cut = bounded_dns("srv.example", DNS_LOOKUP_TIMEOUT, chain()).await;
        assert!(
            cut.is_err(),
            "6 s chain must exceed the single-lookup budget"
        );
    }

    /// SR-45: a resolver that never answers fails at the deadline with an
    /// error that names the host and says it timed out. Paused clock: the
    /// runtime auto-advances, so this takes no wall time.
    #[tokio::test(start_paused = true)]
    async fn test_sr45_dns_lookup_that_never_answers_times_out() {
        let started = tokio::time::Instant::now();
        let guard = DNS_LOOKUP_TIMEOUT + Duration::from_secs(1);
        let outcome = tokio::time::timeout(
            guard,
            bounded_dns(
                "stalled.example.invalid",
                DNS_LOOKUP_TIMEOUT,
                std::future::pending::<SipUaResult<Vec<SocketAddr>>>(),
            ),
        )
        .await;
        let Ok(result) = outcome else {
            panic!(
                "SR-45: DNS lookup did not return within {guard:?} (deadline {DNS_LOOKUP_TIMEOUT:?})"
            );
        };
        let Err(err) = result else {
            panic!("a lookup that never answers cannot succeed");
        };
        let text = err.to_string();
        assert!(
            text.contains("stalled.example.invalid"),
            "error must name the host: {text}"
        );
        assert!(
            text.to_ascii_lowercase().contains("timed out"),
            "error must say it timed out: {text}"
        );
        assert!(
            started.elapsed() >= DNS_LOOKUP_TIMEOUT,
            "returned before the deadline: {:?}",
            started.elapsed()
        );
    }

    /// The deadline is per call, not cumulative or tighter than configured:
    /// an answer just inside it is returned unchanged.
    #[tokio::test(start_paused = true)]
    async fn test_sr45_dns_lookup_answer_inside_deadline_passes_through() {
        let addr: SocketAddr = "192.0.2.10:5061".parse().unwrap();
        let lookup = async move {
            tokio::time::sleep(
                DNS_LOOKUP_TIMEOUT
                    .checked_sub(Duration::from_millis(10))
                    .unwrap(),
            )
            .await;
            Ok(vec![addr])
        };
        let result = tokio::time::timeout(
            DNS_LOOKUP_TIMEOUT * 2,
            bounded_dns("ok.example", DNS_LOOKUP_TIMEOUT, lookup),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap(), vec![addr]);
    }

    /// A lookup error is passed through, not replaced by a timeout error.
    #[tokio::test(start_paused = true)]
    async fn test_sr45_dns_lookup_error_passes_through() {
        let lookup =
            async { Err::<Vec<SocketAddr>, _>(SipUaError::ConfigError("nxdomain".into())) };
        let result = bounded_dns("bad.example", DNS_LOOKUP_TIMEOUT, lookup).await;
        let Err(SipUaError::ConfigError(msg)) = result else {
            panic!("expected the lookup's own error");
        };
        assert_eq!(msg, "nxdomain");
    }
}
