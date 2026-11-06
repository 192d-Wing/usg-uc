//! Indexes behind the STIR caller binding for endpoint INVITEs (SEC-008).
//!
//! The attestation decision for a registered endpoint needs two facts per
//! INVITE: which AOR registered from the packet's flow, and which DIDs are
//! provisioned for that AOR's user. Scanning the location service and the
//! DID map for those is O(registrations + DIDs) per INVITE under a lock an
//! unauthenticated sender can reach. These indexes make both O(1):
//!
//! - [`StirFlows`]: received `(ip, port, transport)` of a successful REGISTER
//!   (plus, for TCP/TLS, the [`ConnId`] it arrived on) -> the AORs it bound.
//!   Filled by the registrar path. Entries are hints:
//!   the caller re-checks the AOR's live bindings, so an expired or removed
//!   registration is never trusted even if its entry is still here.
//! - [`DidMap`]: DID -> user, plus user -> canonical TN -> DID.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), IA-3

use proto_stir_shaken::canonicalize_tn;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uc_types::address::TransportType;

/// Most AORs one flow may bind (a multi-line phone registers several).
pub const MAX_AORS_PER_FLOW: usize = 8;

/// The received flow of a REGISTER or INVITE: canonical source IP, source
/// port and the transport the packet actually arrived on.
pub type FlowKey = (IpAddr, u16, TransportType);

/// Builds a [`FlowKey`] (IPv4-mapped IPv6 sources are canonicalised).
#[must_use]
pub fn flow_key(ip: IpAddr, port: u16, transport: TransportType) -> FlowKey {
    (ip.to_canonical(), port, transport)
}

/// Whether a flow on `transport` cannot be source-spoofed off-path: a
/// connection-oriented transport needs a completed handshake, UDP does not
/// (SEC-009).
#[must_use]
pub const fn flow_is_connection_oriented(transport: TransportType) -> bool {
    !matches!(transport, TransportType::Udp)
}

/// Next [`ConnId`] value; starts at 1 and is never reused in a process.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Process-unique id of one accepted or dialled stream (TCP/TLS)
/// connection. A new connection on a reused (CGNAT) `ip:port` always gets a
/// different id, so endpoint authentication cannot carry over to it.
///
/// RFC 5626 §3.1, §5.2: a flow is the connection, not the address.
/// ## NIST 800-53 Rev5: IA-3 (Device Identification and Authentication), SC-23
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(NonZeroU64);

impl ConnId {
    /// Mints a fresh id (u64: cannot practically wrap).
    #[must_use]
    pub fn next() -> Self {
        let v = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        // The counter starts at 1 and never wraps in practice; 0 maps to 1.
        Self(NonZeroU64::new(v).unwrap_or(NonZeroU64::MIN))
    }
}

/// Minimum time between full-table sweeps when the index is full, so a
/// REGISTER flood at capacity costs at most one O(N) sweep per interval
/// instead of one per message (SC-5).
pub const SWEEP_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// One indexed flow: the stream connection it was bound on (`None` for
/// UDP) and the AORs registered from it.
#[derive(Debug)]
struct FlowEntry {
    conn: Option<ConnId>,
    aors: Vec<String>,
}

/// Received flow -> AORs registered from it. Bounded by `cap` flows
/// (`general.max_registrations`); std `HashMap` (keyed `SipHash`).
///
/// For connection-oriented transports the entry also records the
/// [`ConnId`] the REGISTER arrived on; lookups must present the same id, and
/// the entry is dropped when that connection closes ([`Self::unbind_conn`]).
#[derive(Debug, Default)]
pub struct StirFlows {
    by_flow: HashMap<FlowKey, FlowEntry>,
    /// Reverse index: one flow key per live stream connection. Bounded by
    /// `by_flow`.
    by_conn: HashMap<ConnId, FlowKey>,
    last_sweep: Option<Instant>,
}

impl StirFlows {
    /// Flows indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_flow.len()
    }

    /// The AORs registered from `key` (bounded by [`MAX_AORS_PER_FLOW`]).
    /// For a connection-oriented `key` the entry matches only when `conn`
    /// is the connection it was bound on (an entry bound with `None` never
    /// matches: fail-secure). UDP ignores `conn`. Local policy:
    /// authentication of one connection does not carry over to another.
    #[must_use]
    pub fn get(&self, key: &FlowKey, conn: Option<ConnId>) -> Option<&[String]> {
        let entry = self.by_flow.get(key)?;
        if flow_is_connection_oriented(key.2) && (conn.is_none() || entry.conn != conn) {
            return None;
        }
        Some(entry.aors.as_slice())
    }

    /// Records that `aor` registered from `key` on `conn`. When the table is
    /// full, entries for which `live` is false are swept first (at most once
    /// per [`SWEEP_MIN_INTERVAL`]); if it is still full the flow is not
    /// indexed (its caller is then unauthenticated for STIR, never wrongly
    /// authenticated). Returns whether it was indexed.
    pub fn bind(
        &mut self,
        key: FlowKey,
        conn: Option<ConnId>,
        aor: &str,
        cap: usize,
        live: impl FnMut(&FlowKey, &str) -> bool,
    ) -> bool {
        self.bind_at(key, conn, aor, cap, live, Instant::now())
    }

    /// [`Self::bind`] with an injected clock.
    fn bind_at(
        &mut self,
        key: FlowKey,
        conn: Option<ConnId>,
        aor: &str,
        cap: usize,
        mut live: impl FnMut(&FlowKey, &str) -> bool,
        now: Instant,
    ) -> bool {
        if let Some(entry) = self.by_flow.get_mut(&key) {
            if entry.conn == conn {
                if entry.aors.iter().any(|a| a == aor) {
                    return true;
                }
                if entry.aors.len() >= MAX_AORS_PER_FLOW {
                    entry.aors.retain(|a| live(&key, a));
                    if entry.aors.len() >= MAX_AORS_PER_FLOW {
                        return false;
                    }
                }
                entry.aors.push(aor.to_owned());
                return true;
            }
            // The binding moved to another connection: replace the entry
            // wholesale (the old connection's AORs are not inherited). No
            // sweep: the table does not grow (SC-5).
            if let Some(old) = entry.conn {
                self.by_conn.remove(&old);
            }
            entry.conn = conn;
            entry.aors.clear();
            entry.aors.push(aor.to_owned());
            if let Some(c) = conn {
                self.index_conn(c, key);
            }
            return true;
        }
        if self.by_flow.len() >= cap {
            // Only when full, and rate-limited so a flood at capacity cannot
            // force an O(N) sweep per REGISTER (SC-5).
            if self
                .last_sweep
                .is_some_and(|t| now.saturating_duration_since(t) < SWEEP_MIN_INTERVAL)
            {
                return false;
            }
            self.last_sweep = Some(now);
            let by_conn = &mut self.by_conn;
            self.by_flow.retain(|k, e| {
                e.aors.retain(|a| live(k, a));
                let keep = !e.aors.is_empty();
                if !keep && let Some(c) = e.conn {
                    by_conn.remove(&c);
                }
                keep
            });
            if self.by_flow.len() >= cap {
                return false;
            }
        }
        self.by_flow.insert(
            key,
            FlowEntry {
                conn,
                aors: vec![aor.to_owned()],
            },
        );
        if let Some(c) = conn {
            self.index_conn(c, key);
        }
        true
    }

    /// Points `conn` at `key`. A connection has one source address, so a
    /// previous key for `conn` (not expected) is dropped if still its own.
    fn index_conn(&mut self, conn: ConnId, key: FlowKey) {
        if let Some(prev) = self.by_conn.insert(conn, key)
            && prev != key
            && self
                .by_flow
                .get(&prev)
                .is_some_and(|e| e.conn == Some(conn))
        {
            self.by_flow.remove(&prev);
        }
    }

    /// Forgets that `aor` registered from `key` on `conn` (de-registration).
    /// For a connection-oriented `key` the entry is touched only when it was
    /// bound on `conn`, so a de-REGISTER arriving on another connection from
    /// the same address cannot strip the live connection's entry. UDP
    /// ignores `conn`.
    pub fn unbind(&mut self, key: &FlowKey, conn: Option<ConnId>, aor: &str) {
        if let Some(entry) = self.by_flow.get_mut(key) {
            if flow_is_connection_oriented(key.2) && entry.conn != conn {
                return;
            }
            entry.aors.retain(|a| a != aor);
            if entry.aors.is_empty() {
                if let Some(c) = entry.conn {
                    self.by_conn.remove(&c);
                }
                self.by_flow.remove(key);
            }
        }
    }

    /// Whether `conn` has a bound entry (read-only pre-check so a closing
    /// connection that never registered needs no write lock).
    #[must_use]
    pub fn has_conn(&self, conn: ConnId) -> bool {
        self.by_conn.contains_key(&conn)
    }

    /// Drops the entry bound on `conn` (the connection closed). O(1); an
    /// entry since re-bound by a newer connection on the same address is
    /// left in place.
    ///
    /// ## NIST 800-53 Rev5: SC-23 (Session Authenticity), IA-3
    pub fn unbind_conn(&mut self, conn: ConnId) {
        if let Some(key) = self.by_conn.remove(&conn)
            && self.by_flow.get(&key).is_some_and(|e| e.conn == Some(conn))
        {
            self.by_flow.remove(&key);
        }
    }
}

/// DID -> username map for inbound routing, with a reverse index of the
/// canonical TNs provisioned per user for the STIR binding.
#[derive(Debug, Default)]
pub struct DidMap {
    by_did: HashMap<String, String>,
    /// user -> canonical TN -> DID string as provisioned.
    user_tns: HashMap<String, BTreeMap<String, String>>,
}

impl DidMap {
    /// The user a DID routes to.
    #[must_use]
    pub fn get(&self, did: &str) -> Option<&String> {
        self.by_did.get(did)
    }

    /// Adds or replaces a mapping.
    pub fn insert(&mut self, did: String, user: String) {
        self.remove(&did);
        if let Some(tn) = canonicalize_tn(&did) {
            self.user_tns
                .entry(user.clone())
                .or_default()
                .entry(tn.as_str().to_owned())
                .or_insert_with(|| did.clone());
        }
        self.by_did.insert(did, user);
    }

    /// Removes a mapping. Admin path: may scan the user's other DIDs.
    pub fn remove(&mut self, did: &str) {
        let Some(user) = self.by_did.remove(did) else {
            return;
        };
        let Some(tn) = canonicalize_tn(did) else {
            return;
        };
        let tn = tn.as_str();
        let Some(tns) = self.user_tns.get_mut(&user) else {
            return;
        };
        if tns.get(tn).is_some_and(|d| d == did) {
            tns.remove(tn);
            // Another spelling of the same number may still map to the user.
            if let Some(other) = self
                .by_did
                .iter()
                .find(|(d, u)| **u == user && canonicalize_tn(d).is_some_and(|t| t.as_str() == tn))
                .map(|(d, _)| d.clone())
            {
                tns.insert(tn.to_owned(), other);
            }
        }
        if tns.is_empty() {
            self.user_tns.remove(&user);
        }
    }

    /// The DID provisioned for `user` with the lowest canonical TN
    /// (deterministic), as provisioned.
    #[must_use]
    pub fn first_tn_of(&self, user: &str) -> Option<&String> {
        self.user_tns.get(user)?.values().next()
    }

    /// Whether canonical TN `tn` is provisioned for `user`.
    #[must_use]
    pub fn user_has_tn(&self, user: &str, tn: &str) -> bool {
        self.user_tns.get(user).is_some_and(|m| m.contains_key(tn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(port: u16) -> FlowKey {
        flow_key(IpAddr::from([198, 51, 100, 7]), port, TransportType::Tcp)
    }

    #[test]
    fn flows_bounded_and_swept() {
        let mut f = StirFlows::default();
        let c = Some(ConnId::next());
        let t0 = Instant::now();
        assert!(f.bind_at(k(1), c, "sip:a@x", 2, |_, _| true, t0));
        assert!(
            f.bind_at(k(1), c, "sip:a@x", 2, |_, _| true, t0),
            "idempotent"
        );
        let c2 = Some(ConnId::next());
        assert!(f.bind_at(k(2), c2, "sip:b@x", 2, |_, _| true, t0));
        // Full of live entries: refused.
        assert!(!f.bind_at(k(3), None, "sip:c@x", 2, |_, _| true, t0));
        assert_eq!(f.len(), 2);
        // Full, but k(1) is stale: swept (after the rate limit), then indexed.
        let c3 = Some(ConnId::next());
        let t1 = t0 + SWEEP_MIN_INTERVAL;
        assert!(f.bind_at(k(3), c3, "sip:c@x", 2, |key, _| *key != k(1), t1));
        assert!(f.get(&k(1), c).is_none());
        assert_eq!(f.get(&k(3), c3), Some(&["sip:c@x".to_owned()][..]));
        f.unbind(&k(3), c3, "sip:c@x");
        assert!(f.get(&k(3), c3).is_none());
        // Per-flow AOR cap.
        for i in 1..MAX_AORS_PER_FLOW {
            assert!(f.bind_at(k(2), c2, &format!("sip:l{i}@x"), 2, |_, _| true, t1));
        }
        assert!(!f.bind_at(k(2), c2, "sip:extra@x", 2, |_, _| true, t1));
        assert!(
            flow_key(
                IpAddr::V6(std::net::Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped()),
                1,
                TransportType::Tcp
            ) == k(1),
            "mapped v4 canonicalised"
        );
    }

    #[test]
    fn conn_ids_unique() {
        assert_ne!(ConnId::next(), ConnId::next());
    }

    #[test]
    fn stream_lookup_requires_same_conn() {
        let mut f = StirFlows::default();
        let (c1, c2) = (ConnId::next(), ConnId::next());
        assert!(f.bind(k(1), Some(c1), "sip:a@x", 4, |_, _| true));
        assert!(f.get(&k(1), Some(c1)).is_some());
        assert!(f.get(&k(1), Some(c2)).is_none(), "other connection");
        assert!(f.get(&k(1), None).is_none(), "no connection");
    }

    #[test]
    fn stream_entry_without_conn_never_matches() {
        let mut f = StirFlows::default();
        assert!(f.bind(k(1), None, "sip:a@x", 4, |_, _| true));
        assert!(f.get(&k(1), None).is_none());
        assert!(f.get(&k(1), Some(ConnId::next())).is_none());
    }

    #[test]
    fn udp_ignores_conn() {
        let mut f = StirFlows::default();
        let u = flow_key(IpAddr::from([198, 51, 100, 7]), 1, TransportType::Udp);
        assert!(f.bind(u, None, "sip:a@x", 4, |_, _| true));
        assert!(f.get(&u, None).is_some());
    }

    #[test]
    fn unbind_from_other_conn_keeps_live_entry() {
        let mut f = StirFlows::default();
        let (live, other) = (ConnId::next(), ConnId::next());
        assert!(f.bind(k(1), Some(live), "sip:a@x", 4, |_, _| true));
        // De-REGISTER for the same address arriving on another connection.
        f.unbind(&k(1), Some(other), "sip:a@x");
        f.unbind(&k(1), None, "sip:a@x");
        assert_eq!(f.get(&k(1), Some(live)), Some(&["sip:a@x".to_owned()][..]));
        assert!(f.has_conn(live));
        f.unbind(&k(1), Some(live), "sip:a@x");
        assert_eq!(f.len(), 0);
        assert!(!f.has_conn(live));
    }

    #[test]
    fn unbind_conn_only_removes_own_entry() {
        let mut f = StirFlows::default();
        let (c1, c2) = (ConnId::next(), ConnId::next());
        assert!(f.bind(k(1), Some(c1), "sip:a@x", 4, |_, _| true));
        // Same address, new connection rebinds before c1's close lands.
        assert!(f.bind(k(1), Some(c2), "sip:a@x", 4, |_, _| true));
        assert!(f.get(&k(1), Some(c1)).is_none());
        f.unbind_conn(c1);
        assert_eq!(f.get(&k(1), Some(c2)), Some(&["sip:a@x".to_owned()][..]));
        f.unbind_conn(c2);
        assert_eq!(f.len(), 0);
        assert!(f.by_conn.is_empty());
    }

    #[test]
    fn bind_moves_without_sweep() {
        let mut f = StirFlows::default();
        let (c1, c2) = (ConnId::next(), ConnId::next());
        assert!(f.bind(k(1), Some(c1), "sip:a@x", 1, |_, _| true));
        assert!(f.bind(k(1), Some(c1), "sip:b@x", 1, |_, _| true));
        let mut calls = 0;
        assert!(f.bind(k(1), Some(c2), "sip:a@x", 1, |_, _| {
            calls += 1;
            true
        }));
        assert_eq!(calls, 0, "moving a binding never sweeps");
        assert_eq!(
            f.get(&k(1), Some(c2)),
            Some(&["sip:a@x".to_owned()][..]),
            "old connection's AORs not inherited"
        );
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn full_table_sweep_rate_limited() {
        let mut f = StirFlows::default();
        let t0 = Instant::now();
        assert!(f.bind_at(k(1), Some(ConnId::next()), "sip:a@x", 1, |_, _| true, t0));
        // First new flow at capacity sweeps (k(1) live: refused).
        let mut calls = 0;
        assert!(!f.bind_at(
            k(2),
            Some(ConnId::next()),
            "sip:b@x",
            1,
            |_, _| {
                calls += 1;
                true
            },
            t0
        ));
        assert_eq!(calls, 1);
        // Within the interval: no sweep, not indexed, even if k(1) is stale.
        let mut calls = 0;
        let soon = t0 + SWEEP_MIN_INTERVAL / 2;
        assert!(!f.bind_at(
            k(3),
            Some(ConnId::next()),
            "sip:c@x",
            1,
            |_, _| {
                calls += 1;
                false
            },
            soon
        ));
        assert_eq!(calls, 0, "sweep rate-limited");
        // After the interval: swept and indexed.
        let c4 = Some(ConnId::next());
        assert!(f.bind_at(
            k(4),
            c4,
            "sip:d@x",
            1,
            |_, _| false,
            t0 + SWEEP_MIN_INTERVAL
        ));
        assert!(f.get(&k(4), c4).is_some());
        assert_eq!(f.len(), 1);
        assert_eq!(f.by_conn.len(), 1);
    }

    #[test]
    fn did_reverse_index() {
        let mut d = DidMap::default();
        d.insert("+12025550142".into(), "bob".into());
        d.insert("12025550101".into(), "bob".into());
        d.insert("ext".into(), "bob".into());
        assert_eq!(d.get("+12025550142").map(String::as_str), Some("bob"));
        assert!(d.user_has_tn("bob", "12025550142"));
        assert_eq!(
            d.first_tn_of("bob").map(String::as_str),
            Some("12025550101")
        );
        // Same number, other spelling: removing one keeps the other.
        d.insert("+12025550101".into(), "bob".into());
        d.remove("12025550101");
        assert!(d.user_has_tn("bob", "12025550101"));
        assert_eq!(
            d.first_tn_of("bob").map(String::as_str),
            Some("+12025550101")
        );
        // Re-pointing a DID moves it.
        d.insert("+12025550142".into(), "carol".into());
        assert!(!d.user_has_tn("bob", "12025550142"));
        assert!(d.user_has_tn("carol", "12025550142"));
        d.remove("+12025550101");
        assert!(d.first_tn_of("bob").is_none());
    }
}
