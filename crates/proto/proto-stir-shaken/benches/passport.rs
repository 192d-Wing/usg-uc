//! `passport`: per-INVITE STIR/SHAKEN protocol costs (POA&M-38).
//!
//! Real ES256 (aws-lc via `uc-crypto`, the same primitive `uc-sti` uses) so
//! sign/verify numbers reflect production, plus the pure encode/parse cost
//! with a no-op signer to separate JSON/base64 work from ECDSA.
// POAM: no end-to-end INVITE-to-180 bench with STIR enabled (sbc-daemon).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use proto_stir_shaken::{
    Alg, Attestation, CallContext, IdentityHeader, PASSporT, PassportClaims, Signer,
    StirShakenResult, TnAuthEntry, TnAuthScope, VerifiedKey, Verifier, VerifyingKey,
    canonicalize_tn,
};
use std::hint::black_box;
use std::sync::Arc;
use uc_crypto::interop::ecdsa_p256::{self, P256SigningKey};

const X5U: &str = "https://cert.example-carrier.com/sti/2026/shaken-sp-1234.pem";
const NOW: u64 = 1_793_000_000;

struct Es256(P256SigningKey);
impl Signer for Es256 {
    fn alg(&self) -> Alg {
        Alg::Es256
    }
    fn sign(&self, input: &[u8]) -> StirShakenResult<Vec<u8>> {
        Ok(self.0.sign(input).unwrap())
    }
}

/// Fixed 64-byte signature: isolates encode cost from ECDSA.
struct NoopSigner;
impl Signer for NoopSigner {
    fn alg(&self) -> Alg {
        Alg::Es256
    }
    fn sign(&self, _input: &[u8]) -> StirShakenResult<Vec<u8>> {
        Ok(vec![0x5a; 64])
    }
}

#[derive(Debug)]
struct P256Pub(Vec<u8>);
impl VerifyingKey for P256Pub {
    fn alg(&self) -> Alg {
        Alg::Es256
    }
    fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        ecdsa_p256::verify(&self.0, input, signature).is_ok()
    }
}

fn claims() -> PassportClaims {
    PassportClaims {
        attest: Attestation::Full,
        dest: vec![canonicalize_tn("+12025550101").unwrap()],
        iat: NOW,
        orig: canonicalize_tn("+12025550100").unwrap(),
        origid: "123e4567-e89b-12d3-a456-426614174000".into(),
    }
}

fn bench(c: &mut Criterion) {
    let pkcs8 = P256SigningKey::generate_pkcs8().unwrap();
    let signer = Es256(P256SigningKey::from_pkcs8(&pkcs8).unwrap());
    let key = VerifiedKey {
        key: Arc::new(P256Pub(signer.0.public_key_bytes().to_vec())),
        tn_auth: TnAuthScope {
            entries: vec![TnAuthEntry::Spc("1234".into())],
        },
        not_after: u64::MAX,
    };
    let cl = claims();

    c.bench_function("passport_sign_es256", |b| {
        b.iter(|| black_box(PASSporT::sign(black_box(&cl), X5U, &signer).unwrap()));
    });
    c.bench_function("passport_encode_noop_signer", |b| {
        b.iter(|| black_box(PASSporT::sign(black_box(&cl), X5U, &NoopSigner).unwrap()));
    });

    let token = PASSporT::sign(&cl, X5U, &signer).unwrap();
    // Realistic header: full-form token, info, alg, ppt (ATIS-1000074).
    let header = IdentityHeader::shaken(token, X5U.into(), Alg::Es256).to_header_value();
    c.bench_function("identity_header_parse", |b| {
        b.iter(|| black_box(IdentityHeader::parse(black_box(&header)).unwrap()));
    });

    let v = Verifier::default();
    let ctx = CallContext {
        orig: vec![canonicalize_tn("12025550100").unwrap()],
        dest: vec![canonicalize_tn("12025550101").unwrap()],
    };
    c.bench_function("verifier_prepare", |b| {
        b.iter(|| black_box(v.prepare([black_box(header.as_str())]).unwrap().unwrap()));
    });
    let prepared = v.prepare([header.as_str()]).unwrap().unwrap();
    assert!(v.verify(&prepared, &ctx, &key, NOW).attest.is_some());
    c.bench_function("verifier_verify_es256_warm_key", |b| {
        b.iter(|| black_box(v.verify(black_box(&prepared), &ctx, &key, NOW)));
    });
    c.bench_function("verifier_prepare_plus_verify", |b| {
        b.iter(|| {
            let p = v.prepare([black_box(header.as_str())]).unwrap().unwrap();
            black_box(v.verify(&p, &ctx, &key, NOW))
        });
    });

    // Reject cost: what an attacker can make each INVITE spend.
    let oversize = format!("{};info=<{X5U}>", "A".repeat(8 * 1024));
    c.bench_function("reject_oversize_identity", |b| {
        b.iter(|| black_box(v.prepare([black_box(oversize.as_str())]).is_err()));
    });
    // Max-length (just under the 4 KiB cap) token whose base64 is invalid
    // at the very end of the payload: worst-case decode before rejection.
    let mut parts = header.split(';');
    let tok = parts.next().unwrap();
    let (h, rest) = tok.split_once('.').unwrap();
    let pad = 4000usize.saturating_sub(tok.len());
    let bad_tok = format!("{h}.{}{}!.{}", "QUFB".repeat(pad / 4), rest, "x");
    let bad = format!("{bad_tok};info=<{X5U}>;alg=ES256;ppt=\"shaken\"");
    assert!(v.prepare([bad.as_str()]).is_err());
    c.bench_function("reject_malformed_max_token", |b| {
        b.iter(|| black_box(v.prepare([black_box(bad.as_str())]).is_err()));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
