//! FIPS 140-3 approved-service indicator checks for the AES-GCM paths (SR-15).
//!
//! Each check brackets one synchronous call with
//! `FIPS_service_indicator_before_call` / `_after_call` and reads the counter
//! change: `>= 1` means the module flagged the call as an approved service,
//! `0` means it did not. The counter is thread-local, so the parallel test
//! runner is safe. All inputs (keys, nonces, buffers) are built outside the
//! bracket, because `rand::fill` itself counts +1.
//!
//! Without the FIPS build, `before_call` returns 0 and `after_call` returns 1,
//! so every call would look approved. [`indicator_is_discriminating`] is the
//! negative control that makes such a build fail instead of passing.
//!
//! NIST 800-53 Rev5: SC-13, SA-11. POA&M-400 (caller-IV GCM seal).
#![cfg(feature = "fips")]
// aws-lc-rs keeps its indicator wrapper pub(crate); the raw aws-lc FFI is the only route.
#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use uc_crypto::aead::{Aes256GcmKey, CachedAeadKey, KEY_LEN, NONCE_LEN, RandomNonceKey};
use uc_crypto::random;
use uc_crypto::tls12::Tls12GcmSealer;
use zeroize::Zeroizing;

/// Runs `f` and returns its result with the indicator counter change.
fn delta<R>(f: impl FnOnce() -> R) -> (R, u64) {
    // SAFETY: no arguments; both functions only read/advance aws-lc's
    // thread-local service-indicator counter.
    let before = unsafe { aws_lc_fips_sys::FIPS_service_indicator_before_call() };
    let r = f();
    // SAFETY: as above.
    let after = unsafe { aws_lc_fips_sys::FIPS_service_indicator_after_call() };
    (r, after.wrapping_sub(before))
}

fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    Zeroizing::new(random::generate_key_256().unwrap())
}

fn random_nonce() -> [u8; NONCE_LEN] {
    random::generate_nonce().unwrap()
}

/// DTLS-style nonce: 4-byte implicit IV, then epoch (2) || sequence (6).
fn dtls_nonce(iv: [u8; 4], epoch: u16, seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(&iv);
    nonce[4..6].copy_from_slice(&epoch.to_be_bytes());
    nonce[6..].copy_from_slice(&seq.to_be_bytes()[2..]);
    nonce
}

/// Negative control and POA&M-400 pin: AES-GCM seal with a caller-built IV
/// (`CachedAeadKey`, the SRTP path) is not an approved service. A non-FIPS
/// build reports 1 here and fails.
#[test]
fn indicator_is_discriminating() {
    let key = random_key();
    let ck = CachedAeadKey::new(&key).unwrap();
    let nonce = random_nonce();
    let aad = b"hdr".to_vec();
    let pt = b"rtp payload".to_vec();

    let (ct, d) = delta(|| ck.seal(&nonce, &aad, &pt));
    let ct = ct.unwrap();
    assert_eq!(
        d, 0,
        "CachedAeadKey::seal (caller IV) must not count as approved"
    );

    let mut buf = Vec::with_capacity(64);
    let (r, d) = delta(|| ck.seal_into(&nonce, &aad, &pt, &mut buf));
    r.unwrap();
    assert_eq!(d, 0, "CachedAeadKey::seal_into (caller IV)");

    let mut in_place = pt.clone();
    let (r, d) = delta(|| ck.seal_in_place(&nonce, &aad, &mut in_place));
    r.unwrap();
    assert_eq!(d, 0, "CachedAeadKey::seal_in_place (caller IV)");

    // Same key, same bracket helper: the open does count, so a 0 above is
    // the service, not a broken probe.
    let (pt2, d) = delta(|| ck.open(&nonce, &aad, &ct));
    assert_eq!(pt2.unwrap(), pt);
    assert!(d >= 1, "CachedAeadKey::open should be approved, delta={d}");
}

/// HA1 at rest: the module generates the IV, so the seal is approved.
#[test]
fn random_nonce_key_seal_is_approved() {
    let key = random_key();
    let rnk = RandomNonceKey::new(&key).unwrap();
    let aad = b"uc-user-mgmt/digest_ha1/v1:u-1".to_vec();
    let pt = b"ha1 hex".to_vec();

    let (sealed, d) = delta(|| rnk.seal(&aad, &pt));
    let (nonce, ct) = sealed.unwrap();
    assert!(d >= 1, "RandomNonceKey::seal should be approved, delta={d}");
    assert_eq!(rnk.open(&nonce, &aad, &ct).unwrap(), pt);
}

/// Legacy proto-dtls `RecordLayer` and `AssociationRecordLayer` seal through
/// the module's TLS 1.2 GCM construction.
#[test]
fn tls12_sealer_seal_is_approved() {
    let key = random_key();
    let mut sealer = Tls12GcmSealer::new(&key).unwrap();
    let iv: [u8; 4] = random::generate_random::<4>().unwrap();
    let aad = b"record aad".to_vec();
    let pt = b"record".to_vec();

    for seq in [0u64, 1, 2] {
        let nonce = dtls_nonce(iv, 1, seq);
        let (r, d) = delta(|| sealer.seal(&nonce, &aad, &pt));
        r.unwrap();
        assert!(
            d >= 1,
            "Tls12GcmSealer::seal seq {seq} should be approved, delta={d}"
        );
    }
}

/// Every AES-GCM open path is approved.
#[test]
fn opens_are_approved() {
    let key = random_key();
    let opener = Aes256GcmKey::new(*key).unwrap();
    let rnk = RandomNonceKey::new(&key).unwrap();
    let ck = CachedAeadKey::new(&key).unwrap();
    let aad = b"aad".to_vec();
    let pt = b"plaintext".to_vec();
    let (nonce, ct) = rnk.seal(&aad, &pt).unwrap();

    let (r, d) = delta(|| opener.open(&nonce, &aad, &ct));
    assert_eq!(r.unwrap(), pt);
    assert!(d >= 1, "Aes256GcmKey::open should be approved, delta={d}");

    let (r, d) = delta(|| rnk.open(&nonce, &aad, &ct));
    assert_eq!(r.unwrap(), pt);
    assert!(d >= 1, "RandomNonceKey::open should be approved, delta={d}");

    let (r, d) = delta(|| ck.open(&nonce, &aad, &ct));
    assert_eq!(r.unwrap(), pt);
    assert!(d >= 1, "CachedAeadKey::open should be approved, delta={d}");
}

/// TLS 1.3 nonce: the static IV XOR the left-padded 64-bit sequence number
/// (RFC 8446 §5.3). rustls 0.23 builds its TLS 1.2 GCM nonce the same way.
fn xor_nonce(iv: [u8; NONCE_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = iv;
    for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *n ^= s;
    }
    nonce
}

/// rustls record seal. rustls 0.23 (`crypto/aws_lc_rs/tls13.rs`,
/// `tls12.rs`) seals TLS 1.3 and TLS 1.2 records with
/// `TlsRecordSealingKey` under `TlsProtocolId::TLS13`; `TLS12` is the
/// construction behind `Tls12GcmSealer`. Both count as approved.
#[test]
fn rustls_record_seal_is_approved() {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, TlsProtocolId, TlsRecordSealingKey};

    let key = random_key();
    let aad = b"record aad".to_vec();

    let iv = random_nonce();
    let mut k13 = TlsRecordSealingKey::new(&AES_256_GCM, TlsProtocolId::TLS13, &*key).unwrap();
    for seq in [0u64, 1, 2] {
        let nonce = Nonce::assume_unique_for_key(xor_nonce(iv, seq));
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"record");
        let (r, d) = delta(|| k13.seal_in_place_append_tag(nonce, Aad::from(&aad), &mut buf));
        r.unwrap();
        assert!(
            d >= 1,
            "TLS13 record seal seq {seq} should be approved, delta={d}"
        );
    }

    let implicit: [u8; 4] = random::generate_random::<4>().unwrap();
    let mut k12 = TlsRecordSealingKey::new(&AES_256_GCM, TlsProtocolId::TLS12, &*key).unwrap();
    for seq in [0u64, 1, 2] {
        let nonce = Nonce::assume_unique_for_key(dtls_nonce(implicit, 0, seq));
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"record");
        let (r, d) = delta(|| k12.seal_in_place_append_tag(nonce, Aad::from(&aad), &mut buf));
        r.unwrap();
        assert!(
            d >= 1,
            "TLS12 record seal seq {seq} should be approved, delta={d}"
        );
    }
}

/// rustls record open (`TlsRecordOpeningKey`, TLS13 and TLS12 ids).
#[test]
fn rustls_record_open_is_approved() {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, TlsProtocolId, TlsRecordOpeningKey};

    let key = random_key();
    let ck = CachedAeadKey::new(&key).unwrap();
    let aad = b"record aad".to_vec();
    let nonce = random_nonce();
    let ct = ck.seal(&nonce, &aad, b"record").unwrap();

    for id in [TlsProtocolId::TLS13, TlsProtocolId::TLS12] {
        let opener = TlsRecordOpeningKey::new(&AES_256_GCM, id, &*key).unwrap();
        let mut buf = ct.clone();
        let n = Nonce::assume_unique_for_key(nonce);
        let (r, d) = delta(|| {
            opener
                .open_in_place(n, Aad::from(&aad), &mut buf)
                .map(|p| p.to_vec())
        });
        assert_eq!(r.unwrap(), b"record");
        assert!(d >= 1, "{id:?} record open should be approved, delta={d}");
    }
}
