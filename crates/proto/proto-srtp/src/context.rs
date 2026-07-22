//! SRTP cryptographic context.

use crate::error::{SrtpError, SrtpResult};
use crate::key::{SessionKeys, SrtpKeyMaterial};
use crate::{MAX_PACKET_INDEX, SrtpProfile};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use uc_crypto::aead::CachedAeadKey;

/// SRTP direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpDirection {
    /// Inbound (receiving).
    Inbound,
    /// Outbound (sending).
    Outbound,
}

/// SRTP cryptographic context.
///
/// Manages encryption state, packet indices, and replay protection.
///
/// AES key schedules are expanded once at construction and cached in
/// `CachedAeadKey` instances, avoiding ~100ns of key expansion per packet.
pub struct SrtpContext {
    /// Session keys (raw bytes, kept for accessors).
    keys: SessionKeys,
    /// Pre-expanded RTP AES-256-GCM key (cached key schedule).
    cached_rtp_key: CachedAeadKey,
    /// Pre-expanded RTCP AES-256-GCM key (cached key schedule).
    cached_rtcp_key: CachedAeadKey,
    /// SRTP profile.
    profile: SrtpProfile,
    /// Direction.
    direction: SrtpDirection,
    /// SSRC this context is for.
    ssrc: u32,
    /// Current RTP rollover counter (ROC).
    rtp_roc: AtomicU64,
    /// Highest received RTP sequence number.
    rtp_highest_seq: AtomicU64,
    /// RTP packet index counter (for outbound).
    rtp_index: AtomicU64,
    /// RTCP packet index.
    rtcp_index: AtomicU64,
    /// Replay protection window (bitmap-based, no heap allocation).
    replay_window: Mutex<ReplayWindow>,
}

impl SrtpContext {
    /// Creates a new SRTP context.
    ///
    /// ## Errors
    ///
    /// Returns an error if key derivation fails.
    #[allow(clippy::similar_names)]
    pub fn new(
        material: &SrtpKeyMaterial,
        direction: SrtpDirection,
        ssrc: u32,
    ) -> SrtpResult<Self> {
        let keys = SessionKeys::derive(material)?;

        // Pre-expand AES key schedules once (avoids ~100ns per packet).
        let cached_rtp_key = Self::build_cached_key(&keys.rtp_key)?;
        let cached_rtcp_key = Self::build_cached_key(&keys.rtcp_key)?;

        Ok(Self {
            keys,
            cached_rtp_key,
            cached_rtcp_key,
            profile: material.profile(),
            direction,
            ssrc,
            rtp_roc: AtomicU64::new(0),
            rtp_highest_seq: AtomicU64::new(0),
            rtp_index: AtomicU64::new(0),
            rtcp_index: AtomicU64::new(0),
            replay_window: Mutex::new(ReplayWindow::new()),
        })
    }

    /// Builds a `CachedAeadKey` from raw key bytes.
    fn build_cached_key(key_bytes: &[u8]) -> SrtpResult<CachedAeadKey> {
        if key_bytes.len() != 32 {
            return Err(SrtpError::InvalidKey {
                reason: format!("key length {} is not 32 bytes", key_bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key_bytes);
        CachedAeadKey::new(&arr).map_err(|_| SrtpError::InvalidKey {
            reason: "failed to create cached AES-256-GCM key".to_string(),
        })
    }

    /// Returns the SRTP profile.
    #[must_use]
    pub fn profile(&self) -> SrtpProfile {
        self.profile
    }

    /// Returns the direction.
    #[must_use]
    pub fn direction(&self) -> SrtpDirection {
        self.direction
    }

    /// Returns the SSRC.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Returns the RTP encryption key.
    #[must_use]
    pub fn rtp_key(&self) -> &[u8] {
        &self.keys.rtp_key
    }

    /// Returns the RTP salt.
    #[must_use]
    pub fn rtp_salt(&self) -> &[u8] {
        &self.keys.rtp_salt
    }

    /// Returns the cached RTP AEAD key (pre-expanded key schedule).
    #[must_use]
    pub fn cached_rtp_key(&self) -> &CachedAeadKey {
        &self.cached_rtp_key
    }

    /// Returns the cached RTCP AEAD key (pre-expanded key schedule).
    #[must_use]
    pub fn cached_rtcp_key(&self) -> &CachedAeadKey {
        &self.cached_rtcp_key
    }

    /// Returns the RTCP encryption key.
    #[must_use]
    pub fn rtcp_key(&self) -> &[u8] {
        &self.keys.rtcp_key
    }

    /// Returns the RTCP salt.
    #[must_use]
    pub fn rtcp_salt(&self) -> &[u8] {
        &self.keys.rtcp_salt
    }

    /// Gets the next RTP packet index for outbound.
    ///
    /// ## Errors
    ///
    /// Returns an error if the index overflows.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn next_rtp_index(&self) -> SrtpResult<u64> {
        let index = self.rtp_index.fetch_add(1, Ordering::SeqCst);
        if index > MAX_PACKET_INDEX {
            return Err(SrtpError::IndexOverflow);
        }
        Ok(index)
    }

    /// Computes the 48-bit RTP packet index for an inbound `seq`, estimating the
    /// rollover counter (ROC) relative to the highest sequence seen so far.
    ///
    /// This mirrors RFC 3711 §3.3.1 and the libsrtp/pion `srtp_index_guess`
    /// reference so the SBC and its peers agree on the index across reordering
    /// and 16-bit rollover. The delta `seq - highest_seq` is a **signed**
    /// comparison (both promoted to `i32`), *not* a `u16`-wrapping one:
    ///
    /// - `highest_seq < 2^15` and `seq - highest_seq > 2^15` → `seq` is a late
    ///   packet from before the last wrap → `roc - 1`.
    /// - `highest_seq >= 2^15` and `highest_seq - 2^15 > seq` → `seq` has wrapped
    ///   past `0xFFFF` into the next ROC → `roc + 1`.
    /// - otherwise `roc`.
    ///
    /// Using `u16`-wrapping subtraction here instead of the signed form silently
    /// mis-estimates the ROC for a slightly-reordered packet (low half) and for
    /// the last in-order packet before a wrap (high half) — wrong index → wrong
    /// GCM nonce → dropped audio.
    pub fn compute_rtp_index(&self, seq: u16) -> u64 {
        // 2^15 — the half-sequence-space median from RFC 3711 §3.3.1.
        const MEDIAN: i32 = 0x8000;

        let roc = self.rtp_roc.load(Ordering::Acquire);
        let highest_seq = self.rtp_highest_seq.load(Ordering::Acquire) as u16;

        // Signed (i32) delta, matching libsrtp's int-promoted comparison.
        let s = i32::from(seq);
        let s_l = i32::from(highest_seq);

        let v = if s_l < MEDIAN {
            if s - s_l > MEDIAN {
                // `seq` is a late packet from before the last rollover.
                roc.saturating_sub(1)
            } else {
                roc
            }
        } else if s_l - MEDIAN > s {
            // `seq` has wrapped past 0xFFFF into the next rollover.
            roc + 1
        } else {
            roc
        };

        (v << 16) | u64::from(seq)
    }

    /// Advances the receiver's ROC / highest-sequence state to include an
    /// authenticated packet's 48-bit `index` (from [`compute_rtp_index`]).
    ///
    /// Driving this from the full index — rather than re-deriving rollover from
    /// `seq` thresholds — keeps the stored `(roc, highest_seq)` in exact lockstep
    /// with the index estimator, so a wrap is tracked correctly even when packets
    /// are lost across the `0xFFFF` boundary. Only advances on a new maximum;
    /// reordered/older packets leave the state unchanged.
    ///
    /// [`compute_rtp_index`]: Self::compute_rtp_index
    pub fn update_rtp_state(&self, index: u64) {
        let highest_index =
            (self.rtp_roc.load(Ordering::Acquire) << 16) | self.rtp_highest_seq.load(Ordering::Acquire);
        if index > highest_index {
            self.rtp_roc.store(index >> 16, Ordering::Release);
            self.rtp_highest_seq.store(index & 0xFFFF, Ordering::Release);
        }
    }

    /// Gets the next RTCP index for outbound.
    ///
    /// ## Errors
    ///
    /// Returns an error if the index overflows.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn next_rtcp_index(&self) -> SrtpResult<u32> {
        let index = self.rtcp_index.fetch_add(1, Ordering::SeqCst);
        if index > 0x7FFFFFFF {
            return Err(SrtpError::IndexOverflow);
        }
        Ok(index as u32)
    }

    /// Read-only replay check. Call this **before** authenticating the packet:
    /// it reports whether `index` is a replay or too old without mutating the
    /// window. Per RFC 3711 §3.3.2 the replay list must only be advanced after
    /// the packet authenticates — otherwise a forged packet (the RTP header,
    /// and thus its sequence number, is cleartext) could poison the window and
    /// wedge the stream. Pair with [`commit_replay`](Self::commit_replay).
    ///
    /// ## Errors
    ///
    /// Returns an error if replay is detected or the index is outside the window.
    pub fn check_replay(&self, index: u64) -> SrtpResult<()> {
        let window = self
            .replay_window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        window.check(index)
    }

    /// Commits an authenticated packet's `index` to the replay window. Call this
    /// **only after** the AEAD tag verifies (and after a prior
    /// [`check_replay`](Self::check_replay) returned `Ok`).
    pub fn commit_replay(&self, index: u64) {
        let mut window = self
            .replay_window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        window.commit(index);
    }

    /// Computes the nonce for AES-GCM encryption.
    ///
    /// Per RFC 7714, the nonce is:
    /// - 2 zero bytes
    /// - 4 bytes SSRC
    /// - 6 bytes packet index
    ///
    /// This value is then XORed with the session salt.
    #[must_use]
    pub fn compute_nonce(&self, salt: &[u8], ssrc: u32, index: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];

        // Build the initial value
        // Bytes 0-1: zeros
        // Bytes 2-5: SSRC
        nonce[2..6].copy_from_slice(&ssrc.to_be_bytes());
        // Bytes 6-11: 48-bit packet index
        let index_bytes = index.to_be_bytes();
        nonce[6..12].copy_from_slice(&index_bytes[2..8]);

        // XOR with salt
        for (i, byte) in nonce.iter_mut().enumerate() {
            if i < salt.len() {
                *byte ^= salt[i];
            }
        }

        nonce
    }
}

impl std::fmt::Debug for SrtpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpContext")
            .field("profile", &self.profile)
            .field("direction", &self.direction)
            .field("ssrc", &format!("{:#010x}", self.ssrc))
            .field("rtp_index", &self.rtp_index.load(Ordering::Relaxed))
            .field("rtcp_index", &self.rtcp_index.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Bitmap-based replay protection window.
///
/// Uses a 64-bit bitmap to track which of the last 64 packet indices have
/// been received. Bit 0 corresponds to `highest`, bit 1 to `highest - 1`,
/// etc. This replaces the previous `HashSet<u64>` approach, eliminating
/// heap allocation, hashing, and `retain()` iteration on window shifts.
struct ReplayWindow {
    /// Highest valid index seen.
    highest: u64,
    /// Bitmap: bit `(highest - index)` is set for each received index.
    bitmap: u64,
    /// Whether any packet has been received yet.
    initialized: bool,
}

/// Fixed replay window size (64 bits = 64-entry window).
const REPLAY_WINDOW_SIZE: u64 = 64;

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    /// Read-only replay check: is `index` acceptable (new, or in-window and not
    /// yet seen)? Does not mutate — [`commit`](Self::commit) applies the update
    /// once the packet has authenticated.
    fn check(&self, index: u64) -> SrtpResult<()> {
        if !self.initialized || index > self.highest {
            return Ok(());
        }
        let delta = self.highest - index;
        if delta >= REPLAY_WINDOW_SIZE {
            // Too old — outside the window.
            Err(SrtpError::ReplayDetected { index })
        } else if self.bitmap & (1 << delta) != 0 {
            // Already received.
            Err(SrtpError::ReplayDetected { index })
        } else {
            Ok(())
        }
    }

    /// Records an authenticated `index` as received. Must only be called after
    /// [`check`](Self::check) accepted it and the packet authenticated.
    fn commit(&mut self, index: u64) {
        if !self.initialized {
            self.highest = index;
            self.bitmap = 1; // bit 0 = highest
            self.initialized = true;
            return;
        }

        if index > self.highest {
            // New highest — shift bitmap to make room.
            let shift = index - self.highest;
            if shift >= REPLAY_WINDOW_SIZE {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.bitmap |= 1; // Mark new highest as received.
            self.highest = index;
        } else {
            let delta = self.highest - index;
            if delta < REPLAY_WINDOW_SIZE {
                // Within window — mark as received. (Out-of-window indices were
                // already rejected by `check`; guard anyway to avoid a shift overflow.)
                self.bitmap |= 1 << delta;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl ReplayWindow {
        /// Test helper mirroring the old combined check-and-update semantics:
        /// check, and commit only if acceptable. Production splits these so the
        /// window is advanced only after authentication (RFC 3711 §3.3.2).
        fn check_and_commit(&mut self, index: u64) -> SrtpResult<()> {
            self.check(index)?;
            self.commit(index);
            Ok(())
        }
    }

    fn test_context() -> SrtpContext {
        let material =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, vec![1u8; 32], vec![2u8; 12]).unwrap();

        SrtpContext::new(&material, SrtpDirection::Outbound, 0x12345678).unwrap()
    }

    #[test]
    fn test_context_creation() {
        let ctx = test_context();
        assert_eq!(ctx.profile(), SrtpProfile::AeadAes256Gcm);
        assert_eq!(ctx.direction(), SrtpDirection::Outbound);
        assert_eq!(ctx.ssrc(), 0x12345678);
    }

    #[test]
    fn test_rtp_index() {
        let ctx = test_context();
        assert_eq!(ctx.next_rtp_index().unwrap(), 0);
        assert_eq!(ctx.next_rtp_index().unwrap(), 1);
        assert_eq!(ctx.next_rtp_index().unwrap(), 2);
    }

    #[test]
    fn test_compute_nonce() {
        let ctx = test_context();
        let salt = [0u8; 12];
        let nonce = ctx.compute_nonce(&salt, 0x12345678, 0x0102030405);

        // Verify SSRC is in bytes 2-5
        assert_eq!(&nonce[2..6], &[0x12, 0x34, 0x56, 0x78]);
    }

    // Regression for the ROC estimator (RFC 3711 §3.3.1 / libsrtp
    // `srtp_index_guess`). Asserts exact 48-bit indices — a round-trip test
    // alone hides the bug because two endpoints running the same broken
    // estimator agree with each other; only the absolute values (which a
    // compliant peer computes) and reordering expose it.
    #[test]
    fn compute_rtp_index_matches_reference_estimator() {
        // Force the receiver's highest 48-bit index, then estimate `seq`.
        let est = |highest_index: u64, seq: u16| {
            let ctx = test_context();
            ctx.update_rtp_state(highest_index);
            ctx.compute_rtp_index(seq)
        };

        // (highest roc, highest seq, incoming seq) -> expected 48-bit index.
        // In-order, low half.
        assert_eq!(est(0x0001_0100, 0x0101), 0x0001_0101);
        // Slightly reordered in the low half: stays in the same ROC (a u16-wrapping
        // delta would wrongly drop it to roc-1).
        assert_eq!(est(0x0005_0100, 0x00FE), 0x0005_00FE);
        // Last in-order packet before the wrap (high half): still roc.
        assert_eq!(est(0x0003_FFFE, 0xFFFF), 0x0003_FFFF);
        // The wrap itself: 0x0000 after 0xFFFF advances the ROC.
        assert_eq!(est(0x0003_FFFF, 0x0000), 0x0004_0000);
        // Reordered (earlier) packet in the high half: same ROC, not roc+1.
        assert_eq!(est(0x0003_C350, 49998), 0x0003_C34E);
        // Wrap with packet loss across 0xFFFF (first post-wrap seq seen is 0x0500,
        // well above the old 0x1000 rollover threshold): still advances the ROC.
        assert_eq!(est(0x0003_FFF0, 0x0500), 0x0004_0500);
    }

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new();

        // First packet should succeed
        assert!(window.check_and_commit(100).is_ok());

        // Same packet should fail
        assert!(window.check_and_commit(100).is_err());

        // Next packet should succeed
        assert!(window.check_and_commit(101).is_ok());

        // Old packet within window should succeed (first time)
        assert!(window.check_and_commit(99).is_ok());

        // Very old packet should fail
        assert!(window.check_and_commit(0).is_err());
    }

    #[test]
    fn test_replay_window_boundary() {
        let mut window = ReplayWindow::new();

        // Insert packet at index 100
        assert!(window.check_and_commit(100).is_ok());

        // Index 37 = 100 - 63 = exactly at window boundary (valid)
        assert!(window.check_and_commit(37).is_ok());

        // Index 36 = 100 - 64 = just outside window (too old)
        assert!(window.check_and_commit(36).is_err());

        // Large jump: new highest at 200
        assert!(window.check_and_commit(200).is_ok());

        // Old packet 100 is now 100 positions behind — outside 64-bit window
        assert!(window.check_and_commit(100).is_err());

        // Packet 137 = 200 - 63 = exactly at new window boundary (valid)
        assert!(window.check_and_commit(137).is_ok());

        // Duplicate of 137 should fail
        assert!(window.check_and_commit(137).is_err());
    }

    #[test]
    fn test_replay_window_complete_shift() {
        let mut window = ReplayWindow::new();

        // Fill some history
        for i in 0..10 {
            assert!(window.check_and_commit(i).is_ok());
        }

        // Jump beyond the window — all old state should be cleared
        assert!(window.check_and_commit(1000).is_ok());

        // Duplicate of 1000 should fail
        assert!(window.check_and_commit(1000).is_err());

        // Old indices 0-9 are far outside the window
        assert!(window.check_and_commit(5).is_err());

        // Index within the new window (but never seen) should succeed
        assert!(window.check_and_commit(999).is_ok());
        assert!(window.check_and_commit(937).is_ok()); // 1000 - 63
    }
}
