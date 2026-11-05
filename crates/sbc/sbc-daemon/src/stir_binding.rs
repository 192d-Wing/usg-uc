//! Indexes behind the STIR caller binding for endpoint INVITEs (SEC-008).
//!
//! The attestation decision for a registered endpoint needs two facts per
//! INVITE: which AOR registered from the packet's flow, and which DIDs are
//! provisioned for that AOR's user. Scanning the location service and the
//! DID map for those is O(registrations + DIDs) per INVITE under a lock an
//! unauthenticated sender can reach. These indexes make both O(1):
//!
//! - [`StirFlows`]: received `(ip, port, transport)` of a successful REGISTER
//!   -> the AORs it bound. Filled by the registrar path. Entries are hints:
//!   the caller re-checks the AOR's live bindings, so an expired or removed
//!   registration is never trusted even if its entry is still here.
//! - [`DidMap`]: DID -> user, plus user -> canonical TN -> DID.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), IA-3

use proto_stir_shaken::canonicalize_tn;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
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

/// Received flow -> AORs registered from it. Bounded by `cap` flows
/// (`general.max_registrations`); std `HashMap` (keyed `SipHash`).
#[derive(Debug, Default)]
pub struct StirFlows {
    by_flow: HashMap<FlowKey, Vec<String>>,
}

impl StirFlows {
    /// Flows indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_flow.len()
    }

    /// The AORs registered from `key` (bounded by [`MAX_AORS_PER_FLOW`]).
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&[String]> {
        self.by_flow.get(key).map(Vec::as_slice)
    }

    /// Records that `aor` registered from `key`. When the table is full,
    /// entries for which `live` is false are swept first; if it is still
    /// full the flow is not indexed (its caller is then unauthenticated for
    /// STIR, never wrongly authenticated). Returns whether it was indexed.
    pub fn bind(
        &mut self,
        key: FlowKey,
        aor: &str,
        cap: usize,
        mut live: impl FnMut(&FlowKey, &str) -> bool,
    ) -> bool {
        if let Some(aors) = self.by_flow.get_mut(&key) {
            if aors.iter().any(|a| a == aor) {
                return true;
            }
            if aors.len() >= MAX_AORS_PER_FLOW {
                aors.retain(|a| live(&key, a));
                if aors.len() >= MAX_AORS_PER_FLOW {
                    return false;
                }
            }
            aors.push(aor.to_owned());
            return true;
        }
        if self.by_flow.len() >= cap {
            // Only when full: amortised over the inserts that filled it.
            self.by_flow.retain(|k, aors| {
                aors.retain(|a| live(k, a));
                !aors.is_empty()
            });
            if self.by_flow.len() >= cap {
                return false;
            }
        }
        self.by_flow.insert(key, vec![aor.to_owned()]);
        true
    }

    /// Forgets that `aor` registered from `key` (de-registration).
    pub fn unbind(&mut self, key: &FlowKey, aor: &str) {
        if let Some(aors) = self.by_flow.get_mut(key) {
            aors.retain(|a| a != aor);
            if aors.is_empty() {
                self.by_flow.remove(key);
            }
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
        assert!(f.bind(k(1), "sip:a@x", 2, |_, _| true));
        assert!(f.bind(k(1), "sip:a@x", 2, |_, _| true), "idempotent");
        assert!(f.bind(k(2), "sip:b@x", 2, |_, _| true));
        // Full of live entries: refused.
        assert!(!f.bind(k(3), "sip:c@x", 2, |_, _| true));
        assert_eq!(f.len(), 2);
        // Full, but k(1) is stale: swept, then indexed.
        assert!(f.bind(k(3), "sip:c@x", 2, |key, _| *key != k(1)));
        assert!(f.get(&k(1)).is_none());
        assert_eq!(f.get(&k(3)), Some(&["sip:c@x".to_owned()][..]));
        f.unbind(&k(3), "sip:c@x");
        assert!(f.get(&k(3)).is_none());
        // Per-flow AOR cap.
        for i in 1..MAX_AORS_PER_FLOW {
            assert!(f.bind(k(2), &format!("sip:l{i}@x"), 2, |_, _| true));
        }
        assert!(!f.bind(k(2), "sip:extra@x", 2, |_, _| true));
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
