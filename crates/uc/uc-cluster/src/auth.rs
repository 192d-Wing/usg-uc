//! Cluster peer authentication and anti-replay.
//!
//! Every inter-node control message (heartbeats, replication traffic) must be
//! carried in an [`AuthenticatedEnvelope`] and accepted only after
//! [`PeerAuthenticator::verify`] succeeds. The envelope binds the sender,
//! node generation, a per-sender sequence number and a timestamp to the
//! payload with HMAC-SHA-384 under a pre-shared cluster key.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! Library-only (no transport; POA&M-241): the controls below are provided
//! by this module but no wire path uses it yet.
//!
//! - **IA-3**: Device Identification and Authentication (peer nodes are
//!   authenticated by possession of the cluster key)
//! - **SC-8(1)**: Transmission Integrity (HMAC over every field)
//! - **SC-13**: Cryptographic Protection (HMAC-SHA-384 via `uc-crypto`,
//!   CNSA 2.0 minimum MAC)
//! - **SC-23**: Session Authenticity (sequence window, timestamp window and
//!   generation reject replayed or stale messages)
//!
//! POAM: POA&M-241 no transport exists yet, so nothing on the wire uses
//! this envelope; sbc-config must require `cluster.auth` when the cluster
//! is enabled; key distribution and rotation (multiple `key_id`s) are not
//! implemented. First contact after a verifier restart accepts any
//! generation/sequence, so an envelope captured within the timestamp window
//! (30 s default) can be replayed once and becomes the baseline; the
//! transport must add a fresh handshake/nonce on first contact.
//!
//! POAM: POA&M-242 fencing / epoch-based split-brain protection is not
//! provided; `generation` is the intended carrier for a fencing token.

use crate::error::{ClusterError, ClusterResult};
use crate::node::NodeId;
use bytes::Bytes;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

/// Minimum cluster key length in bytes (384 bits, matches the HMAC-SHA-384
/// output size per CNSA 2.0 / FIPS 198-1 guidance).
pub const MIN_KEY_LEN: usize = 48;

/// HMAC-SHA-384 tag length in bytes.
pub const TAG_LEN: usize = 48;

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Default acceptance window for envelope timestamps.
pub const DEFAULT_TIMESTAMP_WINDOW: Duration = Duration::from_secs(30);

/// Width of the per-sender sliding replay window (sequence numbers).
pub const REPLAY_WINDOW: u64 = 64;

/// Maximum payload carried in one envelope.
///
/// NIST 800-53 Rev5: SC-5 (bounded per-message work before MAC verification)
pub const MAX_PAYLOAD_LEN: usize = 4 * 1024 * 1024;

/// Maximum sender node ID length in bytes.
pub const MAX_NODE_ID_LEN: usize = 255;

/// Maximum number of peers an authenticator tracks.
///
/// NIST 800-53 Rev5: SC-5 (bounded replay state)
pub const MAX_PEERS: usize = crate::config::MAX_EXPECTED_NODES as usize;

/// Domain-separation label prefixed to the MAC input.
const MAC_DOMAIN: &[u8] = b"usg-uc/cluster-envelope/v1";

/// Reasons an envelope is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    /// Envelope version is not supported.
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    /// Key identifier does not match the configured key.
    #[error("unknown key id")]
    UnknownKeyId,
    /// Sender is not a configured cluster member.
    #[error("sender is not a configured cluster member")]
    UnknownSender,
    /// Envelope field exceeds a protocol bound.
    #[error("envelope field exceeds protocol bound")]
    Malformed,
    /// MAC verification failed.
    #[error("message authentication failed")]
    BadTag,
    /// Timestamp is outside the acceptance window.
    #[error("timestamp outside acceptance window")]
    StaleTimestamp,
    /// Generation is lower than the last accepted one for the sender.
    #[error("stale sender generation")]
    StaleGeneration,
    /// Sequence number was already seen or is below the replay window.
    #[error("replayed or too-old sequence number")]
    Replayed,
    /// Authenticated sender does not match the identity inside the payload.
    #[error("payload identity does not match authenticated sender")]
    SenderMismatch,
}

/// Pre-shared cluster authentication key (zeroized on drop).
pub struct ClusterAuthKey(Zeroizing<Vec<u8>>);

impl ClusterAuthKey {
    /// Wraps raw key material.
    ///
    /// # Errors
    /// Returns [`ClusterError::ConfigError`] if the key is shorter than
    /// [`MIN_KEY_LEN`] bytes.
    pub fn new(material: Vec<u8>) -> ClusterResult<Self> {
        let material = Zeroizing::new(material);
        if material.len() < MIN_KEY_LEN {
            return Err(ClusterError::ConfigError {
                reason: format!("cluster auth key must be at least {MIN_KEY_LEN} bytes"),
            });
        }
        Ok(Self(material))
    }

    /// Loads raw key material from a file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or the key is too short.
    pub fn from_file(path: impl AsRef<Path>) -> ClusterResult<Self> {
        let material = std::fs::read(path.as_ref()).map_err(|e| ClusterError::ConfigError {
            reason: format!("cannot read cluster auth key file: {}", e.kind()),
        })?;
        Self::new(material)
    }
}

impl std::fmt::Debug for ClusterAuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClusterAuthKey(<redacted>)")
    }
}

/// An authenticated inter-node message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedEnvelope {
    /// Envelope format version.
    pub version: u8,
    /// Identifier of the key that produced `tag`.
    pub key_id: u32,
    /// Sending node.
    pub sender: NodeId,
    /// Sender generation (incremented on restart).
    pub generation: u64,
    /// Per-sender monotonic sequence number.
    pub sequence: u64,
    /// Sender wall-clock time in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Opaque payload (for example a serialized `Heartbeat`).
    pub payload: Bytes,
    /// HMAC-SHA-384 over the canonical encoding of all other fields.
    pub tag: [u8; TAG_LEN],
}

impl AuthenticatedEnvelope {
    /// Canonical, length-prefixed MAC input. Not serde: JSON is not canonical.
    fn mac_input(&self) -> Vec<u8> {
        let sender = self.sender.as_str().as_bytes();
        let mut buf = Vec::with_capacity(MAC_DOMAIN.len() + 41 + sender.len() + self.payload.len());
        buf.extend_from_slice(MAC_DOMAIN);
        buf.push(self.version);
        buf.extend_from_slice(&self.key_id.to_be_bytes());
        buf.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        buf.extend_from_slice(sender);
        buf.extend_from_slice(&self.generation.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u64).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// Per-sender anti-replay state (same design as the SRTP replay window,
/// RFC 3711 §3.3.2).
#[derive(Debug, Clone, Copy)]
struct ReplayState {
    generation: u64,
    highest: u64,
    /// Bit `n` set means `highest - n` was accepted.
    bitmap: u64,
}

impl ReplayState {
    const fn first(generation: u64, sequence: u64) -> Self {
        Self {
            generation,
            highest: sequence,
            bitmap: 1,
        }
    }

    /// Computes the post-acceptance state without mutating `self`.
    fn check(&self, generation: u64, sequence: u64) -> Result<Self, AuthError> {
        if generation < self.generation {
            return Err(AuthError::StaleGeneration);
        }
        if generation > self.generation {
            // Peer restarted: new generation resets the window.
            return Ok(Self::first(generation, sequence));
        }
        let mut next = *self;
        if sequence > self.highest {
            let shift = sequence - self.highest;
            next.bitmap = if shift >= REPLAY_WINDOW {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            next.highest = sequence;
        } else {
            let diff = self.highest - sequence;
            if diff >= REPLAY_WINDOW || self.bitmap & (1u64 << diff) != 0 {
                return Err(AuthError::Replayed);
            }
            next.bitmap |= 1u64 << diff;
        }
        Ok(next)
    }
}

/// Seals and verifies [`AuthenticatedEnvelope`]s for one local node.
///
/// Replay state is kept only for configured members, so an unauthenticated
/// sender can never grow the table.
pub struct PeerAuthenticator {
    key: ClusterAuthKey,
    key_id: u32,
    local_node: NodeId,
    generation: u64,
    window: Duration,
    next_sequence: AtomicU64,
    /// `None` = configured member with no accepted envelope yet.
    /// Never held across an `.await`.
    peers: Mutex<HashMap<NodeId, Option<ReplayState>>>,
}

impl PeerAuthenticator {
    /// Creates an authenticator.
    ///
    /// `generation` must increase on every process restart so peers reset
    /// their replay window for this node.
    ///
    /// # Errors
    /// Returns an error if more than [`MAX_PEERS`] peers are supplied or the
    /// local node ID exceeds [`MAX_NODE_ID_LEN`].
    pub fn new(
        key: ClusterAuthKey,
        key_id: u32,
        local_node: NodeId,
        generation: u64,
        peers: impl IntoIterator<Item = NodeId>,
    ) -> ClusterResult<Self> {
        if local_node.as_str().len() > MAX_NODE_ID_LEN {
            return Err(ClusterError::ConfigError {
                reason: "local node id too long".to_string(),
            });
        }
        let mut map = HashMap::new();
        for peer in peers {
            if map.len() >= MAX_PEERS {
                return Err(ClusterError::ConfigError {
                    reason: format!("more than {MAX_PEERS} cluster peers configured"),
                });
            }
            map.insert(peer, None);
        }
        Ok(Self {
            key,
            key_id,
            local_node,
            generation,
            window: DEFAULT_TIMESTAMP_WINDOW,
            next_sequence: AtomicU64::new(0),
            peers: Mutex::new(map),
        })
    }

    /// Overrides the timestamp acceptance window.
    #[must_use]
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Adds a peer that may send envelopes.
    ///
    /// # Errors
    /// Returns an error if the peer table is full.
    pub fn add_peer(&self, peer: NodeId) -> ClusterResult<()> {
        let mut peers = self.lock_peers();
        if !peers.contains_key(&peer) && peers.len() >= MAX_PEERS {
            return Err(ClusterError::ConfigError {
                reason: format!("more than {MAX_PEERS} cluster peers configured"),
            });
        }
        peers.entry(peer).or_insert(None);
        Ok(())
    }

    /// Removes a peer; its envelopes are rejected afterwards.
    pub fn remove_peer(&self, peer: &NodeId) {
        self.lock_peers().remove(peer);
    }

    /// Seals `payload` for transmission using the current wall clock.
    ///
    /// # Errors
    /// Returns an error if the payload exceeds [`MAX_PAYLOAD_LEN`].
    pub fn seal(&self, payload: Bytes) -> ClusterResult<AuthenticatedEnvelope> {
        self.seal_at(payload, now_ms())
    }

    /// Seals `payload` with an explicit timestamp.
    ///
    /// # Errors
    /// Returns an error if the payload exceeds [`MAX_PAYLOAD_LEN`].
    pub fn seal_at(
        &self,
        payload: Bytes,
        timestamp_ms: u64,
    ) -> ClusterResult<AuthenticatedEnvelope> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(ClusterError::SerializationError {
                reason: "envelope payload too large".to_string(),
            });
        }
        let mut env = AuthenticatedEnvelope {
            version: ENVELOPE_VERSION,
            key_id: self.key_id,
            sender: self.local_node.clone(),
            generation: self.generation,
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            timestamp_ms,
            payload,
            tag: [0u8; TAG_LEN],
        };
        // NIST 800-53 Rev5: SC-13 (HMAC-SHA-384 through uc-crypto / aws-lc-rs)
        env.tag = uc_crypto::hash::hmac_sha384(&self.key.0, &env.mac_input());
        Ok(env)
    }

    /// Verifies an envelope against the current wall clock.
    ///
    /// On success the sender's replay window is advanced; on failure no
    /// state changes.
    ///
    /// # Errors
    /// Returns the [`AuthError`] describing the rejection.
    pub fn verify(&self, env: &AuthenticatedEnvelope) -> Result<(), AuthError> {
        self.verify_at(env, now_ms())
    }

    /// Verifies an envelope against an explicit clock reading.
    ///
    /// # Errors
    /// Returns the [`AuthError`] describing the rejection.
    pub fn verify_at(&self, env: &AuthenticatedEnvelope, now_ms: u64) -> Result<(), AuthError> {
        if env.version != ENVELOPE_VERSION {
            return Err(AuthError::UnsupportedVersion);
        }
        if env.key_id != self.key_id {
            return Err(AuthError::UnknownKeyId);
        }
        if env.payload.len() > MAX_PAYLOAD_LEN || env.sender.as_str().len() > MAX_NODE_ID_LEN {
            return Err(AuthError::Malformed);
        }
        if !self.lock_peers().contains_key(&env.sender) {
            return Err(AuthError::UnknownSender);
        }
        // NIST 800-53 Rev5: IA-3, SC-8(1) (constant-time HMAC-SHA-384 verify)
        if !uc_crypto::hash::verify_hmac_sha384(&self.key.0, &env.mac_input(), &env.tag) {
            return Err(AuthError::BadTag);
        }
        // NIST 800-53 Rev5: SC-23 (freshness)
        let window_ms = u64::try_from(self.window.as_millis()).unwrap_or(u64::MAX);
        if now_ms.abs_diff(env.timestamp_ms) > window_ms {
            return Err(AuthError::StaleTimestamp);
        }
        let mut peers = self.lock_peers();
        // Peer may have been removed between the checks above.
        let slot = peers.get_mut(&env.sender).ok_or(AuthError::UnknownSender)?;
        let next = match slot {
            // POAM: POA&M-241 first-contact replay within the window (see
            // module docs).
            None => ReplayState::first(env.generation, env.sequence),
            Some(state) => state.check(env.generation, env.sequence)?,
        };
        *slot = Some(next);
        Ok(())
    }

    fn lock_peers(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, Option<ReplayState>>> {
        // A poisoned lock only means another thread panicked mid-update of
        // plain-old-data; the map is still structurally valid.
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl std::fmt::Debug for PeerAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerAuthenticator")
            .field("key_id", &self.key_id)
            .field("local_node", &self.local_node)
            .field("generation", &self.generation)
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn key(byte: u8) -> ClusterAuthKey {
        ClusterAuthKey::new(vec![byte; MIN_KEY_LEN]).unwrap()
    }

    fn pair() -> (PeerAuthenticator, PeerAuthenticator) {
        let a = PeerAuthenticator::new(key(7), 1, NodeId::new("a"), 1, [NodeId::new("b")]).unwrap();
        let b = PeerAuthenticator::new(key(7), 1, NodeId::new("b"), 1, [NodeId::new("a")]).unwrap();
        (a, b)
    }

    fn env_with(seq: u64, generation: u64, ts: u64) -> AuthenticatedEnvelope {
        let a = PeerAuthenticator::new(key(7), 1, NodeId::new("a"), generation, []).unwrap();
        a.next_sequence.store(seq, Ordering::Relaxed);
        a.seal_at(Bytes::from_static(b"hb"), ts).unwrap()
    }

    #[test]
    fn key_shorter_than_48_rejected() {
        assert!(ClusterAuthKey::new(vec![1; MIN_KEY_LEN - 1]).is_err());
        assert!(ClusterAuthKey::new(Vec::new()).is_err());
        assert!(ClusterAuthKey::new(vec![1; MIN_KEY_LEN]).is_ok());
    }

    #[test]
    fn key_debug_is_redacted() {
        assert_eq!(format!("{:?}", key(0x41)), "ClusterAuthKey(<redacted>)");
    }

    #[test]
    fn valid_envelope_accepted() {
        let (a, b) = pair();
        let env = a.seal_at(Bytes::from_static(b"payload"), NOW).unwrap();
        assert_eq!(b.verify_at(&env, NOW), Ok(()));
    }

    #[test]
    fn bit_flip_in_each_field_rejected() {
        let (a, _) = pair();
        let base = a.seal_at(Bytes::from_static(b"payload"), NOW).unwrap();
        let mutations: Vec<Box<dyn Fn(&mut AuthenticatedEnvelope)>> = vec![
            Box::new(|e| e.generation ^= 1),
            Box::new(|e| e.sequence ^= 1),
            Box::new(|e| e.timestamp_ms ^= 1),
            Box::new(|e| e.payload = Bytes::from_static(b"paylobd")),
            Box::new(|e| e.tag[0] ^= 1),
            Box::new(|e| e.tag[TAG_LEN - 1] ^= 0x80),
        ];
        for m in &mutations {
            let (_, b) = pair();
            let mut env = base.clone();
            m(&mut env);
            assert_eq!(b.verify_at(&env, NOW), Err(AuthError::BadTag));
        }
        // Sender and key id are checked before the MAC.
        let (_, b) = pair();
        let mut env = base.clone();
        env.key_id ^= 1;
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::UnknownKeyId));
        let mut env = base.clone();
        env.version ^= 1;
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::UnsupportedVersion));
        // Spoofing another configured member fails the MAC.
        b.add_peer(NodeId::new("c")).unwrap();
        let mut env = base;
        env.sender = NodeId::new("c");
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::BadTag));
    }

    #[test]
    fn wrong_key_rejected() {
        let a = PeerAuthenticator::new(key(9), 1, NodeId::new("a"), 1, []).unwrap();
        let (_, b) = pair();
        let env = a.seal_at(Bytes::new(), NOW).unwrap();
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::BadTag));
    }

    #[test]
    fn replayed_sequence_rejected() {
        let (a, b) = pair();
        let env = a.seal_at(Bytes::new(), NOW).unwrap();
        assert_eq!(b.verify_at(&env, NOW), Ok(()));
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::Replayed));
    }

    #[test]
    fn restart_replay_bounded_by_timestamp_window() {
        // SEC-3 / POA&M-241: a fresh verifier (restart) accepts a captured
        // envelope once if it is inside the timestamp window, never twice,
        // and never once the window has passed.
        let (a, _) = pair();
        let env = a.seal_at(Bytes::new(), NOW).unwrap();
        let (_, restarted) = pair();
        assert_eq!(restarted.verify_at(&env, NOW + 1_000), Ok(()));
        assert_eq!(
            restarted.verify_at(&env, NOW + 1_000),
            Err(AuthError::Replayed)
        );
        let (_, late) = pair();
        let window = u64::try_from(late.window.as_millis()).unwrap();
        assert_eq!(
            late.verify_at(&env, NOW + window + 1),
            Err(AuthError::StaleTimestamp)
        );
    }

    #[test]
    fn out_of_window_old_sequence_rejected() {
        let (_, b) = pair();
        assert_eq!(b.verify_at(&env_with(100, 1, NOW), NOW), Ok(()));
        assert_eq!(
            b.verify_at(&env_with(100 - REPLAY_WINDOW, 1, NOW), NOW),
            Err(AuthError::Replayed)
        );
    }

    #[test]
    fn reordered_within_window_accepted_once() {
        let (_, b) = pair();
        assert_eq!(b.verify_at(&env_with(10, 1, NOW), NOW), Ok(()));
        assert_eq!(b.verify_at(&env_with(8, 1, NOW), NOW), Ok(()));
        assert_eq!(b.verify_at(&env_with(9, 1, NOW), NOW), Ok(()));
        assert_eq!(
            b.verify_at(&env_with(8, 1, NOW), NOW),
            Err(AuthError::Replayed)
        );
        assert_eq!(b.verify_at(&env_with(200, 1, NOW), NOW), Ok(()));
        assert_eq!(
            b.verify_at(&env_with(10, 1, NOW), NOW),
            Err(AuthError::Replayed)
        );
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (_, b) = pair();
        assert_eq!(
            b.verify_at(&env_with(0, 1, NOW - 30_001), NOW),
            Err(AuthError::StaleTimestamp)
        );
    }

    #[test]
    fn future_timestamp_rejected() {
        let (_, b) = pair();
        assert_eq!(
            b.verify_at(&env_with(0, 1, NOW + 30_001), NOW),
            Err(AuthError::StaleTimestamp)
        );
    }

    #[test]
    fn rejection_does_not_advance_window() {
        let (_, b) = pair();
        assert!(b.verify_at(&env_with(5, 1, NOW + 60_000), NOW).is_err());
        assert_eq!(b.verify_at(&env_with(5, 1, NOW), NOW), Ok(()));
    }

    #[test]
    fn lower_generation_rejected() {
        let (_, b) = pair();
        assert_eq!(b.verify_at(&env_with(0, 5, NOW), NOW), Ok(()));
        assert_eq!(
            b.verify_at(&env_with(1, 4, NOW), NOW),
            Err(AuthError::StaleGeneration)
        );
    }

    #[test]
    fn higher_generation_resets_window() {
        let (_, b) = pair();
        assert_eq!(b.verify_at(&env_with(500, 1, NOW), NOW), Ok(()));
        assert_eq!(b.verify_at(&env_with(0, 2, NOW), NOW), Ok(()));
        assert_eq!(
            b.verify_at(&env_with(0, 2, NOW), NOW),
            Err(AuthError::Replayed)
        );
    }

    #[test]
    fn unknown_sender_rejected_and_not_tracked() {
        let b = PeerAuthenticator::new(key(7), 1, NodeId::new("b"), 1, []).unwrap();
        let env = env_with(0, 1, NOW);
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::UnknownSender));
        assert!(b.lock_peers().is_empty());
        b.add_peer(NodeId::new("a")).unwrap();
        assert_eq!(b.verify_at(&env, NOW), Ok(()));
        b.remove_peer(&NodeId::new("a"));
        assert_eq!(
            b.verify_at(&env_with(1, 1, NOW), NOW),
            Err(AuthError::UnknownSender)
        );
    }

    #[test]
    fn peer_table_bounded() {
        let peers = (0..=MAX_PEERS).map(|i| NodeId::new(format!("n{i}")));
        assert!(PeerAuthenticator::new(key(1), 1, NodeId::new("x"), 1, peers).is_err());
        let peers = (0..MAX_PEERS).map(|i| NodeId::new(format!("n{i}")));
        let auth = PeerAuthenticator::new(key(1), 1, NodeId::new("x"), 1, peers).unwrap();
        assert!(auth.add_peer(NodeId::new("extra")).is_err());
        assert!(auth.add_peer(NodeId::new("n0")).is_ok());
    }

    #[test]
    fn oversize_payload_rejected() {
        let (a, b) = pair();
        assert!(
            a.seal_at(Bytes::from(vec![0; MAX_PAYLOAD_LEN + 1]), NOW)
                .is_err()
        );
        let mut env = a.seal_at(Bytes::new(), NOW).unwrap();
        env.payload = Bytes::from(vec![0; MAX_PAYLOAD_LEN + 1]);
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::Malformed));
    }

    #[test]
    fn key_file_missing_or_short_rejected() {
        let dir = std::env::temp_dir();
        let missing = dir.join(format!("uc-cluster-qa-missing-{}", std::process::id()));
        assert!(ClusterAuthKey::from_file(&missing).is_err());
        let short = dir.join(format!("uc-cluster-qa-short-{}", std::process::id()));
        std::fs::write(&short, vec![1u8; MIN_KEY_LEN - 1]).unwrap();
        assert!(ClusterAuthKey::from_file(&short).is_err());
        std::fs::write(&short, vec![1u8; MIN_KEY_LEN]).unwrap();
        assert!(ClusterAuthKey::from_file(&short).is_ok());
        let _ = std::fs::remove_file(&short);
    }

    #[test]
    fn unknown_key_id_rejected() {
        let a = PeerAuthenticator::new(key(7), 2, NodeId::new("a"), 1, [NodeId::new("b")]).unwrap();
        let (_, b) = pair();
        let env = a.seal_at(Bytes::from_static(b"hb"), NOW).unwrap();
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::UnknownKeyId));
    }

    #[test]
    fn removed_peer_rejected() {
        let (a, b) = pair();
        b.remove_peer(&NodeId::new("a"));
        let env = a.seal_at(Bytes::from_static(b"hb"), NOW).unwrap();
        assert_eq!(b.verify_at(&env, NOW), Err(AuthError::UnknownSender));
    }
}
