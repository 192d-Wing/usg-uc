//! Server-side SIP Digest verification with policy enforcement (RFC 7616,
//! RFC 3261 §22.4).
//!
//! [`DigestVerifier`] is the server half of digest authentication. Unlike the
//! low-level [`crate::auth::verify_credentials`], it never trusts the
//! client's choice of parameters:
//!
//! - the `algorithm` must equal the configured algorithm (no downgrade,
//!   RFC 7616 §3.7);
//! - the `qop` must be one the policy offers, with `cnonce`/`nc` present;
//! - the `uri` must equal the Request-URI under RFC 3261 §19.1.4 rules
//!   (RFC 7616 §3.4.6);
//! - the `nonce` must be one this server issued (HMAC-SHA-384 tag) and must
//!   be younger than the TTL, else the caller re-challenges with
//!   `stale=true` (RFC 7616 §3.3);
//! - `nc` must strictly increase per nonce (RFC 7616 §3.4.5), and is only
//!   committed after the response matched, so a party without the password
//!   cannot burn a victim's nonce counts.
//!
//! Every failure is a reject (fail closed). [`DigestReject`] values are stable
//! reason codes for audit events.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **IA-2(8)**: Replay-resistant authentication (nonce HMAC, TTL, nc)
//! - **IA-5(1)**: Authenticator protection (no algorithm downgrade)
//! - **SC-13**: Cryptographic protection (aws-lc-rs; the FIPS 140-3 module is
//!   used only when the build enables the `aws-lc-rs/fips` feature, e.g. via
//!   the workspace `fips` feature - this crate alone does not enable it)
//! - **SC-23**: Session authenticity (nonce bound to realm and issuer key)
//! - **SC-5**: Bounded nonce tracker; full tracker yields a re-challenge
//!
//! ## CNSA 2.0
//!
//! The nonce MAC is HMAC-SHA-384 (CNSA compliant). SHA-256 and SHA-512/256
//! are what RFC 7616 defines; SIP digest stays under the CNSA exception
//! recorded as POA&M-110.
//!
//! POAM: nc state is node-local. Nonces validate on every node sharing the
//! issuer key, so a credential can be replayed once on a sibling node until
//! nc state is replicated (`uc-state-sync`) or REGISTER flows are sticky.

use crate::auth::{
    AlgorithmHasher, DigestAlgorithm, DigestChallenge, DigestCredentials, DigestHasher, Qop,
    compute_ha2, compute_response,
};
use crate::error::{SipError, SipResult};
use crate::uri::SipUri;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Minimum nonce issuer key length in bytes.
pub const MIN_NONCE_KEY_LEN: usize = 32;

/// Default nonce lifetime.
pub const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(300);

/// Default maximum nonce count accepted before a fresh nonce is required.
pub const DEFAULT_MAX_NC: u32 = 1_000_000;

/// Default bound on nonces tracked for nc replay detection.
pub const DEFAULT_MAX_TRACKED_NONCES: usize = 65_536;

/// Domain separation label for the nonce MAC.
const NONCE_LABEL: &[u8] = b"usg-digest-v1";

/// Bytes of timestamp in a nonce.
const TS_LEN: usize = 8;
/// Bytes of randomness in a nonce.
const RAND_LEN: usize = 16;
/// Bytes of the (truncated) HMAC-SHA-384 tag in a nonce.
const TAG_LEN: usize = 24;
/// Raw nonce length; hex-encoded on the wire.
const NONCE_RAW_LEN: usize = TS_LEN + RAND_LEN + TAG_LEN;

/// Tolerated clock skew for nonces timestamped in the future (seconds).
const MAX_FUTURE_SKEW_SECS: u64 = 5;

/// Server digest policy. The server, not the client, chooses every
/// security-relevant parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestPolicy {
    /// Realm the server challenges with.
    pub realm: String,
    /// The only algorithm accepted (default SHA-256).
    pub algorithm: DigestAlgorithm,
    /// Offered qop values. Non-empty means qop is required and must be one
    /// of these; empty means a credential carrying qop is rejected.
    ///
    /// Without qop there is no nc, so a captured credential replays until
    /// its nonce expires (RFC 2069 compatibility only; keep `nonce_ttl`
    /// short if this is used).
    pub qops: Vec<Qop>,
    /// Nonce lifetime; older nonces yield [`DigestVerdict::Stale`].
    pub nonce_ttl: Duration,
    /// Highest nc accepted before a fresh nonce is required.
    pub max_nc: u32,
    /// Bound on tracked nonces (SC-5).
    pub max_tracked_nonces: usize,
    /// Opaque value sent in challenges; credentials must echo it.
    pub opaque: Option<String>,
}

impl DigestPolicy {
    /// Creates a policy with secure defaults: SHA-256, `qop=auth` required,
    /// 5 minute nonces.
    #[must_use]
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            algorithm: DigestAlgorithm::Sha256,
            qops: vec![Qop::Auth],
            nonce_ttl: DEFAULT_NONCE_TTL,
            max_nc: DEFAULT_MAX_NC,
            max_tracked_nonces: DEFAULT_MAX_TRACKED_NONCES,
            opaque: None,
        }
    }

    /// Sets the accepted algorithm.
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: DigestAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets the offered qop values.
    ///
    /// An empty list is ignored and the current list kept: RFC 2069 mode
    /// (no qop, no nc) has no replay protection inside the nonce TTL, so it
    /// is not supported (RFC 7616 §3.3; NIST 800-53 Rev5: IA-2(8)).
    #[must_use]
    pub fn with_qops(mut self, qops: Vec<Qop>) -> Self {
        if !qops.is_empty() {
            self.qops = qops;
        }
        self
    }

    /// Sets the nonce lifetime.
    #[must_use]
    pub fn with_nonce_ttl(mut self, ttl: Duration) -> Self {
        self.nonce_ttl = ttl;
        self
    }

    /// Sets the maximum accepted nc.
    #[must_use]
    pub fn with_max_nc(mut self, max_nc: u32) -> Self {
        self.max_nc = max_nc;
        self
    }

    /// Sets the nonce tracker bound.
    #[must_use]
    pub fn with_max_tracked_nonces(mut self, max: usize) -> Self {
        self.max_tracked_nonces = max;
        self
    }

    /// Sets the opaque value.
    #[must_use]
    pub fn with_opaque(mut self, opaque: impl Into<String>) -> Self {
        self.opaque = Some(opaque.into());
        self
    }
}

/// Outcome of checking a nonce's MAC and age.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceCheck {
    /// Issued by this key for this realm and within its lifetime.
    Valid {
        /// Issue time, seconds since the Unix epoch.
        issued_secs: u64,
    },
    /// Authentic but older than the TTL.
    Stale,
    /// Not issued by this key/realm, malformed, or from the future.
    Invalid,
}

/// Stateless nonce issuer: `hex(ts_be64 || rand16 || HMAC-SHA-384(key,
/// label || realm || ts || rand)[..24])`.
///
/// Only the derived HMAC key is kept; the raw key bytes are not copied.
/// `Debug` never prints key material.
pub struct NonceIssuer {
    key: aws_lc_rs::hmac::Key,
}

impl fmt::Debug for NonceIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceIssuer")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl NonceIssuer {
    /// Creates an issuer from a secret key of at least
    /// [`MIN_NONCE_KEY_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is shorter than 32 bytes.
    pub fn new(key: &[u8]) -> SipResult<Self> {
        // NIST 800-53 Rev5: SC-12 - refuse weak MAC keys.
        if key.len() < MIN_NONCE_KEY_LEN {
            return Err(SipError::InvalidHeader {
                name: "nonce key".to_string(),
                reason: format!("nonce key must be at least {MIN_NONCE_KEY_LEN} bytes"),
            });
        }
        Ok(Self {
            key: aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA384, key),
        })
    }

    fn tag(&self, realm: &str, ts: &[u8], rand: &[u8]) -> aws_lc_rs::hmac::Tag {
        let mut ctx = aws_lc_rs::hmac::Context::with_key(&self.key);
        ctx.update(NONCE_LABEL);
        ctx.update(&[0]);
        ctx.update(realm.as_bytes());
        ctx.update(&[0]);
        ctx.update(ts);
        ctx.update(rand);
        ctx.sign()
    }

    /// Issues a fresh nonce for `realm` at time `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if `now` is before the Unix epoch or the CSPRNG fails.
    pub fn issue(&self, realm: &str, now: SystemTime) -> SipResult<String> {
        let secs = unix_secs(now).ok_or_else(|| SipError::InvalidHeader {
            name: "nonce".to_string(),
            reason: "clock before Unix epoch".to_string(),
        })?;
        let ts = secs.to_be_bytes();
        let mut rand = [0u8; RAND_LEN];
        getrandom::fill(&mut rand).map_err(|e| SipError::InvalidHeader {
            name: "nonce".to_string(),
            reason: format!("CSPRNG failure: {e}"),
        })?;
        let tag = self.tag(realm, &ts, &rand);
        let mut out = String::with_capacity(NONCE_RAW_LEN * 2);
        for b in ts
            .iter()
            .chain(rand.iter())
            .chain(tag.as_ref().iter().take(TAG_LEN))
        {
            let _ = write!(out, "{b:02x}");
        }
        Ok(out)
    }

    /// Checks that `nonce` was issued by this key for `realm` and is no older
    /// than `ttl`. The tag comparison is constant time.
    #[must_use]
    pub fn check(&self, nonce: &str, realm: &str, now: SystemTime, ttl: Duration) -> NonceCheck {
        let Some(raw) = decode_hex::<NONCE_RAW_LEN>(nonce) else {
            return NonceCheck::Invalid;
        };
        let (ts, rest) = raw.split_at(TS_LEN);
        let (rand, presented_tag) = rest.split_at(RAND_LEN);
        let expected = self.tag(realm, ts, rand);
        let Some(expected_tag) = expected.as_ref().get(..TAG_LEN) else {
            return NonceCheck::Invalid;
        };
        if aws_lc_rs::constant_time::verify_slices_are_equal(expected_tag, presented_tag).is_err() {
            return NonceCheck::Invalid;
        }
        let mut ts_bytes = [0u8; TS_LEN];
        ts_bytes.copy_from_slice(ts);
        let issued_secs = u64::from_be_bytes(ts_bytes);
        let Some(now_secs) = unix_secs(now) else {
            return NonceCheck::Invalid;
        };
        if issued_secs > now_secs.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return NonceCheck::Invalid;
        }
        if now_secs.saturating_sub(issued_secs) > ttl.as_secs() {
            return NonceCheck::Stale;
        }
        NonceCheck::Valid { issued_secs }
    }
}

/// Seconds since the Unix epoch, or `None` before it.
fn unix_secs(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// Decodes exactly `N` bytes of hex (either case); anything else is `None`.
fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; N];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *slot = (nibble(hi)? << 4) | nibble(lo)?;
    }
    Some(out)
}

/// Request fields the credentials are bound to.
#[derive(Debug, Clone, Copy)]
pub struct DigestRequestView<'a> {
    /// SIP method of the request.
    pub method: &'a str,
    /// Request-URI as received.
    pub request_uri: &'a str,
    /// Message body (needed for `qop=auth-int`).
    pub body: Option<&'a [u8]>,
}

/// The stored secret for the user.
#[derive(Clone, Copy)]
pub enum DigestSecret<'a> {
    /// Cleartext password.
    Password(&'a str),
    /// Pre-computed `H(username:realm:password)` for the policy algorithm.
    Ha1(&'a str),
}

impl fmt::Debug for DigestSecret<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(<redacted>)"),
            Self::Ha1(_) => f.write_str("Ha1(<redacted>)"),
        }
    }
}

/// Stable reject reasons (audit codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestReject {
    /// `realm` differs from the policy realm.
    RealmMismatch,
    /// `algorithm` differs from the policy algorithm (downgrade attempt).
    AlgorithmMismatch,
    /// `qop` not offered, or present when the policy offers none.
    QopMismatch,
    /// `qop` present but `cnonce` or `nc` missing.
    MissingQopParams,
    /// `uri` does not equal the Request-URI.
    UriMismatch,
    /// Nonce not issued by this server (forged, other key or realm).
    UnknownNonce,
    /// `nc` not strictly greater than the last accepted value.
    NonceReplay,
    /// `opaque` does not echo the challenge.
    OpaqueMismatch,
    /// Response digest does not match.
    BadResponse,
    /// Credentials could not be evaluated.
    Malformed,
}

impl DigestReject {
    /// Stable reason code string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RealmMismatch => "realm_mismatch",
            Self::AlgorithmMismatch => "algorithm_mismatch",
            Self::QopMismatch => "qop_mismatch",
            Self::MissingQopParams => "missing_qop_params",
            Self::UriMismatch => "uri_mismatch",
            Self::UnknownNonce => "unknown_nonce",
            Self::NonceReplay => "nonce_replay",
            Self::OpaqueMismatch => "opaque_mismatch",
            Self::BadResponse => "bad_response",
            Self::Malformed => "malformed",
        }
    }
}

impl fmt::Display for DigestReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestVerdict {
    /// Authenticated.
    Ok {
        /// Authenticated username.
        username: String,
    },
    /// Nonce expired, nc exhausted or tracker full: answer 401 with a fresh
    /// challenge carrying `stale=true` (RFC 7616 §3.3).
    Stale,
    /// Rejected.
    Reject(DigestReject),
}

/// Per-nonce nc state.
#[derive(Debug, Clone, Copy)]
struct NcEntry {
    issued_secs: u64,
    last_nc: u32,
}

/// Bounded (nonce, username) -> last nc map. Only HMAC-valid nonces whose
/// response verified are inserted.
///
/// Keying by username as well as nonce stops one user's verified use of a
/// nonce from affecting another user's nc state for the same nonce.
#[derive(Debug)]
struct NcTracker {
    entries: HashMap<String, NcEntry>,
    /// Keys in insertion order. Every key in `entries` appears exactly once,
    /// so expired entries are dropped from the front in amortised O(1)
    /// rather than by scanning the map (NIST 800-53 Rev5: SC-5).
    order: VecDeque<String>,
}

/// Result of an nc pre-check.
enum NcCheck {
    Ok,
    Replay,
    Full,
}

/// Unambiguous composite tracker key (length-prefixed username).
fn tracker_key(nonce: &str, username: &str) -> String {
    let mut key = String::with_capacity(nonce.len() + username.len() + 8);
    let _ = write!(key, "{}:{username}{nonce}", username.len());
    key
}

impl NcTracker {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Drops expired entries from the front of the insertion queue. Entries
    /// are inserted roughly in issue order, so this stops at the first live
    /// one; a live entry at the front can delay reclaiming later expired
    /// ones by at most one TTL, which only yields `Full` (a re-challenge).
    fn evict_expired(&mut self, ttl_secs: u64, now_secs: u64) {
        while let Some(front) = self.order.front() {
            match self.entries.get(front) {
                Some(e) if now_secs.saturating_sub(e.issued_secs) <= ttl_secs => break,
                Some(_) => {
                    self.entries.remove(front);
                }
                None => {}
            }
            self.order.pop_front();
        }
    }

    fn check(&mut self, key: &str, nc: u32, policy: &DigestPolicy, now_secs: u64) -> NcCheck {
        if let Some(e) = self.entries.get(key) {
            return if nc > e.last_nc {
                NcCheck::Ok
            } else {
                NcCheck::Replay
            };
        }
        if nc == 0 {
            return NcCheck::Replay;
        }
        if self.entries.len() >= policy.max_tracked_nonces {
            self.evict_expired(policy.nonce_ttl.as_secs(), now_secs);
            // Live entries are never evicted: dropping one would reset its
            // nc and allow replay. A full tracker yields a re-challenge.
            if self.entries.len() >= policy.max_tracked_nonces {
                return NcCheck::Full;
            }
        }
        NcCheck::Ok
    }

    fn commit(&mut self, key: String, issued_secs: u64, nc: u32) {
        if let Some(e) = self.entries.get_mut(&key) {
            e.last_nc = e.last_nc.max(nc);
            return;
        }
        self.order.push_back(key.clone());
        self.entries.insert(
            key,
            NcEntry {
                issued_secs,
                last_nc: nc,
            },
        );
    }
}

/// Server-side digest verifier. `&mut self`, no internal locks; the caller
/// serialises access (e.g. a `Mutex` or per-shard instances).
#[derive(Debug)]
pub struct DigestVerifier {
    policy: DigestPolicy,
    issuer: NonceIssuer,
    tracker: NcTracker,
}

impl DigestVerifier {
    /// Creates a verifier.
    #[must_use]
    pub fn new(mut policy: DigestPolicy, issuer: NonceIssuer) -> Self {
        // Fail closed: an empty qop list (set via the public field) would
        // disable nc replay protection, so fall back to `qop=auth`.
        if policy.qops.is_empty() {
            policy.qops = vec![Qop::Auth];
        }
        Self {
            policy,
            issuer,
            tracker: NcTracker::new(),
        }
    }

    /// Returns the policy.
    #[must_use]
    pub fn policy(&self) -> &DigestPolicy {
        &self.policy
    }

    /// Number of nonces currently tracked for nc replay detection.
    #[must_use]
    pub fn tracked_nonces(&self) -> usize {
        self.tracker.entries.len()
    }

    /// Builds a challenge with a fresh nonce. `algorithm=` is always present.
    ///
    /// # Errors
    ///
    /// Returns an error if a nonce cannot be issued.
    pub fn challenge(&self, now: SystemTime, stale: bool) -> SipResult<DigestChallenge> {
        let nonce = self.issuer.issue(&self.policy.realm, now)?;
        let mut challenge = DigestChallenge::new(self.policy.realm.clone(), nonce)
            .with_algorithm(self.policy.algorithm)
            .with_stale(stale);
        for qop in &self.policy.qops {
            challenge = challenge.with_qop(*qop);
        }
        if let Some(ref opaque) = self.policy.opaque {
            challenge = challenge.with_opaque(opaque.clone());
        }
        Ok(challenge)
    }

    /// Verifies `creds` for `req` against the user's `secret`.
    ///
    /// Checks run in a fixed order and the first failure decides the verdict.
    /// nc is committed only after the response matched.
    pub fn verify(
        &mut self,
        req: DigestRequestView<'_>,
        creds: &DigestCredentials,
        secret: DigestSecret<'_>,
        now: SystemTime,
    ) -> DigestVerdict {
        let policy = &self.policy;

        // a. Realm.
        if creds.realm != policy.realm {
            return DigestVerdict::Reject(DigestReject::RealmMismatch);
        }
        // b. RFC 7616 §3.7: the server's algorithm, never the client's.
        if creds.algorithm != policy.algorithm {
            return DigestVerdict::Reject(DigestReject::AlgorithmMismatch);
        }
        // c. qop must be one we offered (the policy always offers one).
        let qop_params = match creds.qop {
            Some(q) if policy.qops.contains(&q) => match (creds.cnonce.as_deref(), creds.nc) {
                (Some(cnonce), Some(nc)) if !cnonce.is_empty() => Some((q, cnonce, nc)),
                _ => return DigestVerdict::Reject(DigestReject::MissingQopParams),
            },
            _ => return DigestVerdict::Reject(DigestReject::QopMismatch),
        };
        // d. RFC 7616 §3.4.6 / RFC 3261 §22.4: digest-uri equals the
        // Request-URI (RFC 3261 §19.1.4 comparison).
        match (
            creds.uri.parse::<SipUri>(),
            req.request_uri.parse::<SipUri>(),
        ) {
            (Ok(a), Ok(b)) if a.equivalent(&b) => {}
            _ => return DigestVerdict::Reject(DigestReject::UriMismatch),
        }
        // e. Nonce authenticity and age (RFC 7616 §3.3). A stale outcome is
        // only reported after the response verifies (RFC 2617 §3.2.1: stale
        // means the digest was valid), so a wrong password is a plain reject.
        let mut stale = false;
        let mut issued_secs = 0;
        match self
            .issuer
            .check(&creds.nonce, &policy.realm, now, policy.nonce_ttl)
        {
            NonceCheck::Valid { issued_secs: s } => issued_secs = s,
            NonceCheck::Stale => stale = true,
            NonceCheck::Invalid => return DigestVerdict::Reject(DigestReject::UnknownNonce),
        }
        let Some(now_secs) = unix_secs(now) else {
            return DigestVerdict::Reject(DigestReject::Malformed);
        };
        let Some((_, _, nc)) = qop_params else {
            return DigestVerdict::Reject(DigestReject::QopMismatch);
        };
        // RFC 7616 §3.4.5: nc strictly increasing per (nonce, username).
        let key = tracker_key(&creds.nonce, &creds.username);
        if !stale {
            if nc > policy.max_nc {
                stale = true;
            } else {
                match self.tracker.check(&key, nc, policy, now_secs) {
                    NcCheck::Ok => {}
                    NcCheck::Replay => return DigestVerdict::Reject(DigestReject::NonceReplay),
                    NcCheck::Full => stale = true,
                }
            }
        }
        // f. Opaque echo.
        if let Some(ref opaque) = policy.opaque
            && creds.opaque.as_deref() != Some(opaque.as_str())
        {
            return DigestVerdict::Reject(DigestReject::OpaqueMismatch);
        }
        // g. Response with the policy algorithm.
        let Some(expected) = expected_response(policy, &req, creds, secret, qop_params) else {
            return DigestVerdict::Reject(DigestReject::Malformed);
        };
        let presented = creds.response.to_ascii_lowercase();
        if aws_lc_rs::constant_time::verify_slices_are_equal(
            expected.as_bytes(),
            presented.as_bytes(),
        )
        .is_err()
        {
            return DigestVerdict::Reject(DigestReject::BadResponse);
        }
        // h. Valid digest on an unusable nonce: re-challenge, nothing committed.
        if stale {
            return DigestVerdict::Stale;
        }
        // i. Commit nc only after the response matched.
        self.tracker.commit(key, issued_secs, nc);
        DigestVerdict::Ok {
            username: creds.username.clone(),
        }
    }
}

/// Computes the expected response with the policy algorithm.
fn expected_response(
    policy: &DigestPolicy,
    req: &DigestRequestView<'_>,
    creds: &DigestCredentials,
    secret: DigestSecret<'_>,
    qop_params: Option<(Qop, &str, u32)>,
) -> Option<String> {
    let hasher = AlgorithmHasher::for_algorithm(policy.algorithm);
    let base_ha1 = match secret {
        DigestSecret::Password(password) => {
            let mut a1 = String::new();
            let _ = write!(a1, "{}:{}:{password}", creds.username, policy.realm);
            hasher.hash(a1.as_bytes())
        }
        DigestSecret::Ha1(ha1) => ha1.to_ascii_lowercase(),
    };
    let cnonce = qop_params.map(|(_, c, _)| c);
    // RFC 7616 §3.4.2: -sess A1 = H(user:realm:pass):nonce:cnonce.
    let ha1 = if policy.algorithm.is_session() {
        let cnonce = cnonce?;
        let mut a1 = String::new();
        let _ = write!(a1, "{base_ha1}:{}:{cnonce}", creds.nonce);
        hasher.hash(a1.as_bytes())
    } else {
        base_ha1
    };
    let qop = qop_params.map(|(q, _, _)| q);
    let nc = qop_params.map(|(_, _, n)| n);
    let ha2 = compute_ha2(&hasher, req.method, &creds.uri, qop, req.body).ok()?;
    compute_response(&hasher, &ha1, &creds.nonce, nc, cnonce, qop, &ha2).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    const RURI: &str = "sip:registrar.example.com";

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn verifier(policy: DigestPolicy) -> DigestVerifier {
        DigestVerifier::new(policy, NonceIssuer::new(KEY).unwrap())
    }

    fn creds_for(
        challenge: &DigestChallenge,
        algorithm: DigestAlgorithm,
        qop: Option<Qop>,
        uri: &str,
        password: &str,
        nc: u32,
    ) -> DigestCredentials {
        let hasher = AlgorithmHasher::for_algorithm(algorithm);
        let response = crate::auth::compute_digest_response(
            &hasher,
            "alice",
            &challenge.realm,
            password,
            "REGISTER",
            uri,
            &challenge.nonce,
            algorithm,
            qop,
            qop.map(|_| nc),
            qop.map(|_| "cn0nce"),
            None,
        )
        .unwrap();
        let mut c =
            DigestCredentials::new("alice", &challenge.realm, &challenge.nonce, uri, response)
                .with_algorithm(algorithm);
        if let Some(q) = qop {
            c = c.with_qop(q, "cn0nce", nc);
        }
        if let Some(ref o) = challenge.opaque {
            c = c.with_opaque(o.clone());
        }
        c
    }

    fn view() -> DigestRequestView<'static> {
        DigestRequestView {
            method: "REGISTER",
            request_uri: RURI,
            body: None,
        }
    }

    fn setup() -> (DigestVerifier, DigestChallenge) {
        let v = verifier(DigestPolicy::new("example.com"));
        let ch = v.challenge(t(1_000), false).unwrap();
        (v, ch)
    }

    fn ok() -> DigestVerdict {
        DigestVerdict::Ok {
            username: "alice".to_string(),
        }
    }

    fn rej(r: DigestReject) -> DigestVerdict {
        DigestVerdict::Reject(r)
    }

    #[test]
    fn valid_sha256_accepted() {
        let (mut v, ch) = setup();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            ok()
        );
        assert_eq!(v.tracked_nonces(), 1);
    }

    #[test]
    fn challenge_always_names_algorithm_and_qop() {
        let (_, ch) = setup();
        let s = ch.to_string();
        assert!(s.contains("algorithm=SHA-256"), "{s}");
        assert!(s.contains("qop=\"auth\""), "{s}");
        let md5 = DigestChallenge::new("r", "n").to_string();
        assert!(md5.contains("algorithm=MD5"), "{md5}");
    }

    #[test]
    fn realm_mismatch_rejected() {
        let (mut v, mut ch) = setup();
        ch.realm = "other.example.com".to_string();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::RealmMismatch)
        );
    }

    /// A correct MD5 response is still rejected when policy is SHA-256.
    #[test]
    fn algorithm_downgrade_rejected() {
        let (mut v, ch) = setup();
        let c = creds_for(&ch, DigestAlgorithm::Md5, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::AlgorithmMismatch)
        );
    }

    #[test]
    fn qop_omitted_when_required_rejected() {
        let (mut v, ch) = setup();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, None, RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::QopMismatch)
        );
    }

    #[test]
    fn qop_auth_int_not_offered_rejected() {
        let (mut v, ch) = setup();
        let c = creds_for(
            &ch,
            DigestAlgorithm::Sha256,
            Some(Qop::AuthInt),
            RURI,
            "pw",
            1,
        );
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::QopMismatch)
        );
    }

    #[test]
    fn empty_qop_list_fails_closed_to_auth() {
        let mut policy = DigestPolicy::new("example.com").with_qops(vec![]);
        assert_eq!(policy.qops, vec![Qop::Auth]);
        policy.qops.clear();
        let mut v = verifier(policy);
        assert_eq!(v.policy().qops, vec![Qop::Auth]);
        let ch = v.challenge(t(1_000), false).unwrap();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, None, RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::QopMismatch)
        );
    }

    #[test]
    fn stale_only_after_response_verifies() {
        let (mut v, ch) = setup();
        let bad = creds_for(
            &ch,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            RURI,
            "wrong",
            1,
        );
        assert_eq!(
            v.verify(view(), &bad, DigestSecret::Password("pw"), t(1_000 + 301)),
            rej(DigestReject::BadResponse)
        );
        let mut v = verifier(DigestPolicy::new("example.com").with_max_nc(10));
        let ch = v.challenge(t(1_000), false).unwrap();
        let bad = creds_for(
            &ch,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            RURI,
            "wrong",
            11,
        );
        assert_eq!(
            v.verify(view(), &bad, DigestSecret::Password("pw"), t(1_001)),
            rej(DigestReject::BadResponse)
        );
        assert_eq!(v.tracked_nonces(), 0);
    }

    #[test]
    fn nc_tracked_per_nonce_and_username() {
        let policy = DigestPolicy::new("example.com");
        let mut tr = NcTracker::new();
        tr.commit(tracker_key("n1", "alice"), 1_000, 5);
        assert!(matches!(
            tr.check(&tracker_key("n1", "alice"), 5, &policy, 1_001),
            NcCheck::Replay
        ));
        assert!(matches!(
            tr.check(&tracker_key("n1", "bob"), 1, &policy, 1_001),
            NcCheck::Ok
        ));
        // Length prefix keeps (nonce, user) splits distinct.
        assert_ne!(tracker_key("bn", "a"), tracker_key("n", "ab"));
    }

    #[test]
    fn tracker_queue_stays_bounded() {
        let policy = DigestPolicy::new("example.com").with_max_tracked_nonces(4);
        let mut tr = NcTracker::new();
        for i in 0..1_000u64 {
            let key = tracker_key(&format!("n{i}"), "alice");
            if matches!(tr.check(&key, 1, &policy, 1_000 + i * 400), NcCheck::Ok) {
                tr.commit(key, 1_000 + i * 400, 1);
            }
        }
        assert!(tr.entries.len() <= 4);
        assert_eq!(tr.entries.len(), tr.order.len());
    }

    #[test]
    fn missing_cnonce_or_nc_rejected() {
        let (mut v, ch) = setup();
        let mut c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        c.cnonce = None;
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::MissingQopParams)
        );
        let mut c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        c.nc = None;
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::MissingQopParams)
        );
    }

    #[test]
    fn uri_mismatch_rejected() {
        let (mut v, ch) = setup();
        for uri in [
            "sip:bob@registrar.example.com",
            "sip:other.example.com",
            "sips:registrar.example.com",
            "not a uri",
        ] {
            let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), uri, "pw", 1);
            assert_eq!(
                v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
                rej(DigestReject::UriMismatch),
                "{uri}"
            );
        }
    }

    #[test]
    fn uri_equal_under_19_1_4_accepted() {
        let (mut v, ch) = setup();
        let req = DigestRequestView {
            method: "REGISTER",
            request_uri: "sip:%61lice@Registrar.Example.COM",
            body: None,
        };
        let c = creds_for(
            &ch,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            "sip:alice@registrar.example.com",
            "pw",
            1,
        );
        assert_eq!(
            v.verify(req, &c, DigestSecret::Password("pw"), t(1_010)),
            ok()
        );
    }

    #[test]
    fn forged_nonce_rejected() {
        let (mut v, mut ch) = setup();
        let mut bytes = ch.nonce.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        ch.nonce = String::from_utf8(bytes).unwrap();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::UnknownNonce)
        );
        assert_eq!(v.tracked_nonces(), 0);
    }

    #[test]
    fn nonce_from_other_key_or_realm_rejected() {
        let (mut v, _) = setup();
        let other = NonceIssuer::new(&[7u8; 32]).unwrap();
        let mut ch = v.challenge(t(1_000), false).unwrap();
        ch.nonce = other.issue("example.com", t(1_000)).unwrap();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::UnknownNonce)
        );
        let issuer = NonceIssuer::new(KEY).unwrap();
        ch.nonce = issuer.issue("other-realm", t(1_000)).unwrap();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_010)),
            rej(DigestReject::UnknownNonce)
        );
    }

    #[test]
    fn expired_nonce_is_stale() {
        let (mut v, ch) = setup();
        let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_000 + 301)),
            DigestVerdict::Stale
        );
    }

    #[test]
    fn nc_replay_and_decrease_rejected_gap_accepted() {
        let (mut v, ch) = setup();
        let pw = DigestSecret::Password("pw");
        let c1 = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(v.verify(view(), &c1, pw, t(1_001)), ok());
        assert_eq!(
            v.verify(view(), &c1, pw, t(1_002)),
            rej(DigestReject::NonceReplay)
        );
        let c5 = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 5);
        assert_eq!(v.verify(view(), &c5, pw, t(1_003)), ok());
        let c3 = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 3);
        assert_eq!(
            v.verify(view(), &c3, pw, t(1_004)),
            rej(DigestReject::NonceReplay)
        );
    }

    #[test]
    fn wrong_password_does_not_advance_nc() {
        let (mut v, ch) = setup();
        let bad = creds_for(
            &ch,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            RURI,
            "wrong",
            1,
        );
        assert_eq!(
            v.verify(view(), &bad, DigestSecret::Password("pw"), t(1_001)),
            rej(DigestReject::BadResponse)
        );
        assert_eq!(v.tracked_nonces(), 0);
        let good = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &good, DigestSecret::Password("pw"), t(1_002)),
            ok()
        );
    }

    #[test]
    fn nc_above_max_is_stale() {
        let mut v = verifier(DigestPolicy::new("example.com").with_max_nc(10));
        let ch = v.challenge(t(1_000), false).unwrap();
        let c = creds_for(
            &ch,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            RURI,
            "pw",
            11,
        );
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_001)),
            DigestVerdict::Stale
        );
    }

    #[test]
    fn tracker_full_is_stale_then_sweeps_expired() {
        let mut v = verifier(DigestPolicy::new("example.com").with_max_tracked_nonces(1));
        let ch1 = v.challenge(t(1_000), false).unwrap();
        let ch2 = v.challenge(t(1_000), false).unwrap();
        let pw = DigestSecret::Password("pw");
        let c1 = creds_for(
            &ch1,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            RURI,
            "pw",
            1,
        );
        let c2 = creds_for(
            &ch2,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            RURI,
            "pw",
            1,
        );
        assert_eq!(v.verify(view(), &c1, pw, t(1_001)), ok());
        assert_eq!(v.verify(view(), &c2, pw, t(1_002)), DigestVerdict::Stale);
        assert_eq!(v.tracked_nonces(), 1);
        // Once the first nonce expires the tracker makes room.
        let ch3 = v.challenge(t(1_400), false).unwrap();
        let c3 = creds_for(
            &ch3,
            DigestAlgorithm::Sha256,
            Some(Qop::Auth),
            RURI,
            "pw",
            1,
        );
        assert_eq!(v.verify(view(), &c3, pw, t(1_401)), ok());
        assert_eq!(v.tracked_nonces(), 1);
    }

    #[test]
    fn opaque_must_echo() {
        let mut v = verifier(DigestPolicy::new("example.com").with_opaque("op1"));
        let ch = v.challenge(t(1_000), false).unwrap();
        let mut c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        c.opaque = Some("other".to_string());
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_001)),
            rej(DigestReject::OpaqueMismatch)
        );
    }

    #[test]
    fn ha1_secret_path() {
        let (mut v, ch) = setup();
        let ha1 = Sha256DigestHasherForTest::ha1("alice", "example.com", "pw");
        let c = creds_for(&ch, DigestAlgorithm::Sha256, Some(Qop::Auth), RURI, "pw", 1);
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Ha1(&ha1), t(1_001)),
            ok()
        );
    }

    #[test]
    fn session_algorithm_verified() {
        let mut v = verifier(
            DigestPolicy::new("example.com").with_algorithm(DigestAlgorithm::Sha512_256Sess),
        );
        let ch = v.challenge(t(1_000), false).unwrap();
        let c = creds_for(
            &ch,
            DigestAlgorithm::Sha512_256Sess,
            Some(Qop::Auth),
            RURI,
            "pw",
            1,
        );
        assert_eq!(
            v.verify(view(), &c, DigestSecret::Password("pw"), t(1_001)),
            ok()
        );
    }

    #[test]
    fn short_key_rejected_and_debug_redacted() {
        assert!(NonceIssuer::new(&[1u8; 31]).is_err());
        let issuer = NonceIssuer::new(KEY).unwrap();
        let dbg = format!("{issuer:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("0123456789abcdef"));
        assert!(!format!("{:?}", DigestSecret::Password("hunter2")).contains("hunter2"));
    }

    #[test]
    fn malformed_and_future_nonces_invalid() {
        let issuer = NonceIssuer::new(KEY).unwrap();
        let ttl = DEFAULT_NONCE_TTL;
        for n in ["", "zz", "abc", &"g".repeat(NONCE_RAW_LEN * 2)] {
            assert_eq!(issuer.check(n, "r", t(1_000), ttl), NonceCheck::Invalid);
        }
        let future = issuer.issue("r", t(2_000)).unwrap();
        assert_eq!(
            issuer.check(&future, "r", t(1_000), ttl),
            NonceCheck::Invalid
        );
        let n = issuer.issue("r", t(1_000)).unwrap();
        assert_eq!(
            issuer.check(&n.to_uppercase(), "r", t(1_000), ttl),
            NonceCheck::Valid { issued_secs: 1_000 }
        );
    }

    struct Sha256DigestHasherForTest;
    impl Sha256DigestHasherForTest {
        fn ha1(u: &str, r: &str, p: &str) -> String {
            crate::auth::Sha256DigestHasher.hash(format!("{u}:{r}:{p}").as_bytes())
        }
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn random_credentials_never_panic(
                user in "[ -~]{0,40}",
                realm in "[ -~]{0,40}",
                nonce in "[ -~]{0,120}",
                uri in "[ -~]{0,80}",
                resp in "[ -~]{0,80}",
                nc in any::<u32>(),
            ) {
                let mut v = verifier(DigestPolicy::new("example.com"));
                let c = DigestCredentials::new(user, realm, nonce, uri, resp)
                    .with_algorithm(DigestAlgorithm::Sha256)
                    .with_qop(Qop::Auth, "c", nc);
                let _ = v.verify(view(), &c, DigestSecret::Password("pw"), t(1_000));
            }

            #[test]
            fn credentials_display_parse_roundtrip(
                user in "[a-zA-Z0-9._-]{1,20}",
                realm in "[a-zA-Z0-9.]{1,20}",
                nonce in "[a-f0-9]{8,96}",
                resp in "[a-f0-9]{32,64}",
                nc in 1u32..,
            ) {
                let c = DigestCredentials::new(user, realm, nonce, "sip:example.com", resp)
                    .with_algorithm(DigestAlgorithm::Sha512_256)
                    .with_qop(Qop::Auth, "cn", nc);
                let parsed: DigestCredentials = c.to_string().parse().unwrap();
                prop_assert_eq!(parsed, c);
            }
        }
    }
}
