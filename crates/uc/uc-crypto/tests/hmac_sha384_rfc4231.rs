//! SR-16 sanity: `uc_crypto::hash::hmac_sha384` / `verify_hmac_sha384`
//! (the replacement for the `hmac` crate's `Hmac<Sha384>` in uc-auth and
//! sbc-provision-server) against RFC 4231 known answers.
#![allow(missing_docs)]

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[test]
fn hmac_sha384_rfc4231_test_case_2() {
    // RFC 4231 section 4.3: key "Jefe".
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let want = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
                8e2240ca5e69e2c78b3239ecfab21649";
    let mac = uc_crypto::hash::hmac_sha384(key, data);
    assert_eq!(hex(&mac), want);
    assert!(uc_crypto::hash::verify_hmac_sha384(key, data, &mac));
    let mut bad = mac;
    bad[47] ^= 1;
    assert!(!uc_crypto::hash::verify_hmac_sha384(key, data, &bad));
    assert!(!uc_crypto::hash::verify_hmac_sha384(key, data, &mac[..47]));
}

#[test]
fn hmac_sha384_rfc4231_test_case_6() {
    // RFC 4231 section 4.7: 131-byte key 0xaa (longer than the block).
    let key = [0xaa_u8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let want = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f\
                3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952";
    assert_eq!(hex(&uc_crypto::hash::hmac_sha384(&key, data)), want);
}
