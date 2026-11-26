//! SR-16: `uc_crypto::interop::sha256` (feature `legacy-sha256`,
//! CNSA-EXCEPTION POA&M-211) for the stored API-key digest format.
//!
//! Run: `cargo test -p uc-crypto --features legacy-sha256 --test legacy_sha256`
#![cfg(feature = "legacy-sha256")]
#![allow(missing_docs)]

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[test]
fn sha256_fips_180_4_known_answers() {
    // FIPS 180-4 / NIST CSRC examples.
    assert_eq!(
        hex(&uc_crypto::interop::sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&uc_crypto::interop::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&uc_crypto::interop::sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn api_key_sha256_digest_unchanged() {
    // Same vector as uc-auth `api_key_sha256_digest_unchanged`:
    // printf %s test-api-key-0001 | openssl dgst -sha256
    assert_eq!(
        hex(&uc_crypto::interop::sha256(b"test-api-key-0001")),
        "2809c93358750a2d9574fc2a2c1f3942c2d7c5b0e70ac2f8dc7e1422272f6fd6"
    );
}
