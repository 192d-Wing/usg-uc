# CNSA 2.0 Compliance Documentation

This document details how the USG SBC complies with NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0).

> **Status legend.** *Wired (sbc-daemon | sbc-media-core | soft client)* — a shipped binary has a call site for this (the binary is named). *Library-only* — implemented and tested in a `proto-*`/`uc-*` crate, but no shipped binary calls it. *Planned* — not implemented. A row that says only "Full"/"Complete" describes crate-level capability; the wiring column/annotation says what the running SBC actually does.

Crate names below are the real workspace crates. The cryptographic primitives crate is `uc-crypto` (`crates/uc/uc-crypto`); SRTP is `proto-srtp`; DTLS is `proto-dtls`; TLS is `uc-transport`; STIR/SHAKEN is `proto-stir-shaken`; JWT validation is `proto-jwt`.

## Overview

CNSA 2.0 defines cryptographic algorithms approved for protecting classified information at all classification levels. This project enforces CNSA 2.0 compliance at the type level in `uc-crypto` and `uc-types`, making non-compliant algorithms unrepresentable *in those crates*. Protocol stacks built on third-party libraries (rustls for TLS, `jsonwebtoken` for JWT, the Go DTLS sidecar) are only as restricted as their configuration, and the sections below say exactly how far each is restricted in the shipped binaries.

## Algorithm Requirements

### Approved Algorithms

| Function | Algorithm | Minimum Size | Implementation | Status |
|----------|-----------|--------------|----------------|--------|
| Symmetric Encryption | AES-256-GCM | 256-bit | `uc-crypto::aead::Aes256GcmKey`; SRTP via `proto-srtp` | Wired (sbc-media-core SRTP relay) |
| Hash Functions | SHA-384, SHA-512 | 384-bit | `uc-crypto::hash::{sha384, sha512}` | Wired (sbc-media-core DTLS fingerprints via `proto-dtls`) |
| Digital Signatures | ECDSA P-384 | P-384 | `uc-crypto::ecdsa::P384KeyPair` | Library-only (no shipped caller; TLS/DTLS signatures are done by rustls / the DTLS sidecar) |
| Key Exchange | ECDH P-384 | P-384 | `uc-crypto::ecdh::P384EphemeralKeyPair` | Library-only (no shipped caller) |
| Key Derivation | HKDF-SHA384 | - | `uc-crypto::hkdf::hkdf_sha384` | Library-only (no shipped caller; SRTP uses the RFC 3711 KDF, see below) |
| TLS | TLS 1.3 | - | rustls with aws-lc-rs (`uc-transport::tls`) | Wired (sbc-daemon SIP-TLS listeners, soft client). Protocol version is 1.3 only unless `security.min_tls_version = "1.2"`; cipher suites are **not** restricted (see SIP/TLS). |

### Forbidden Algorithms

The following algorithms are **explicitly forbidden** and not exposed by the `uc-crypto` crate:

| Function | Forbidden | Reason |
|----------|-----------|--------|
| Hash | SHA-256, SHA-1, MD5 | Insufficient security margin |
| Curves | P-256 (secp256r1) | Key size too small |
| Symmetric | AES-128, AES-192, 3DES | Key size too small |
| RSA | Any RSA < 3072 bits | Key size too small |
| JWT | ES256, RS256, PS256, HS256 | Based on forbidden algorithms |

Note: "not exposed by `uc-crypto`" does not mean "not negotiable by the SBC". rustls (TLS) and `jsonwebtoken` (JWT) carry their own algorithm sets; see the protocol sections for what the shipped binaries actually accept.

## Enforcement Strategy

### Type-Level Enforcement

Non-compliant algorithms cannot be represented in the type system:

```rust
// crates/uc/uc-types/src/protocol.rs

/// CNSA 2.0 compliant hash algorithms only.
/// SHA-256 is intentionally not included.
pub enum CnsaHash {
    Sha384,
    Sha512,
}

/// CNSA 2.0 compliant elliptic curves only.
/// P-256 is intentionally not included.
pub enum CnsaCurve {
    P384,
    P521,
}
```

These enums are used by `sbc-config` for `media.srtp.profile`, `media.dtls.fingerprint_hash` and `security.curve`. Note that the TOML values are the Rust variant names (`"Sha384"`, `"P384"`, `"AeadAes256Gcm"`).

### API Design

The `uc-crypto` crate only exposes CNSA 2.0 compliant operations:

```rust
// SHA-384 exposed, SHA-256 NOT exposed
pub fn sha384(data: &[u8]) -> [u8; 48];
pub fn sha512(data: &[u8]) -> [u8; 64];
// No sha256() function exists

// P-384 exposed, P-256 NOT exposed
pub struct P384KeyPair { ... }
pub struct P384EphemeralKeyPair { ... }
// No P256* types exist
```

### Configuration Validation

The `sbc-config` crate validates that configuration does not specify forbidden algorithms (`crates/sbc/sbc-config/src/validate.rs`):

```rust
fn validate_cnsa_curve(curve: CnsaCurve) {
    match curve {
        CnsaCurve::P384 | CnsaCurve::P521 => (),
        // P-256 cannot even be represented
    }
}
```

Status: Wired (sbc-daemon runs `validate_config` at load). `security.min_tls_version` (`"1.3"` default, `"1.2"` allowed) is applied to the SIP-TLS listeners (`uc-transport::tls::create_server_config_with`); the REST HTTPS listener uses rustls defaults regardless. `security.curve` is validated as an enum but **no code checks the key type of the loaded certificate**.

## Protocol-Specific Compliance

### SIP/TLS

- **TLS Version**: Wired (sbc-daemon). SIP-over-TLS listeners are built with `uc_transport::tls::create_server_config_with` — TLS 1.3 only by default, TLS 1.2+1.3 when `security.min_tls_version = "1.2"`. Listeners are skipped (with a warning) when `security.tls_cert_path`/`tls_key_path` are unset.
- **Cipher Suite**: **Not restricted** beyond the protocol version. `create_server_config`/`create_client_config` use `aws_lc_rs::default_provider()` without a `cipher_suites` or `kx_groups` filter, so `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, X25519 and P-256 remain negotiable alongside `TLS_AES_256_GCM_SHA384`/P-384. Restricting to the CNSA suite is Planned.
- **REST HTTPS** (`sbc-daemon/src/api_server.rs`): uses `rustls::ServerConfig::builder()` with the process default provider — TLS 1.2 is permitted (workspace `rustls` enables the `tls12` feature) and suites are unrestricted. Planned: route through `uc-transport::tls`.
- **Certificates**: P-384 ECDSA is the operational requirement, but it is **not enforced**; rustls accepts any certificate/key it can parse (P-256, RSA).
- **Client mTLS**: Wired (sbc-daemon). `security.require_mtls` makes the SIP-TLS listener require a client certificate chaining to `security.tls_ca_path` (WebPKI verifier); `validate_config` rejects the flag without a CA bundle. The gRPC listener enforces its own `[grpc] require_mtls`.
- **Implementation**: rustls with aws-lc-rs backend (`uc-transport`). The soft client (`client-core/src/sip_transport.rs`) also pins TLS 1.3 only.

### SRTP

- **Profile**: Wired (sbc-media-core). `AEAD_AES_256_GCM` (RFC 7714) is the only profile in `proto-srtp::SrtpProfile`; the relay rejects any other DTLS-SRTP profile from the sidecar (`sbc-media-core/src/dtls_relay.rs`).
- **Key Size**: 256-bit master key, 96-bit master salt.
- **KDF**: standard **RFC 3711 §4.3 AES-CM KDF** (AES-256-CM PRF), as required for interoperability with every other SRTP stack. An earlier HKDF-SHA384 derivation was removed because it produced non-interoperable session keys (`proto-srtp/src/key.rs`).
- **Implementation**: `proto-srtp` crate, used by `sbc-media-core` (`srtp_relay.rs`, `media_pipeline.rs`).

### DTLS-SRTP

- **DTLS Version**: **1.2** (RFC 6347). `proto-dtls` implements the DTLS 1.2 record layer only (`proto-dtls/src/record.rs`, `DTLS_1_2_VERSION`). DTLS 1.3 is Planned.
- **Cipher Suite**: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` is the only CNSA-compliant suite in `proto-dtls::cipher_suite` (Library-level filter).
- **Fingerprint Hash**: Wired (sbc-media-core, sbc-daemon). `proto-dtls::fingerprint` supports SHA-384/SHA-512 only; the SBC advertises `a=fingerprint:sha-384 …` in rewritten SDP (`sbc-daemon/src/sdp_dtls.rs`).
- **SBC Identity**: Wired (sbc-media-core). The self-signed DTLS certificate is generated with rcgen `PKCS_ECDSA_P384_SHA384` (`dtls_identity.rs`).
- **Key Exchange / Handshake**: in the shipped SBC the DTLS handshake is performed by an external **Go DTLS-SRTP terminator sidecar** reached over a Unix socket (`sbc-media-core/src/dtls_sidecar.rs`); the Rust relay demuxes records and verifies the negotiated profile and fingerprint. The ECDH curve used inside the sidecar is not verified by Rust code. There is no `webrtc-dtls` dependency.
- **Implementation**: `proto-dtls` (types, fingerprint, 1.2 record layer) + Go sidecar.

### STIR/SHAKEN

- **PASSporT Signing/Verification**: ES384 (ECDSA P-384 with SHA-384); ES256 is rejected (`proto-stir-shaken/src/verification.rs`).
- **Certificate**: P-384 ECDSA
- **Forbidden**: ES256, RS256
- **Implementation**: `proto-stir-shaken` crate — **Library-only**. No `crates/sbc` binary depends on it; the `[stir_shaken]` config section is parsed by `sbc-config` but not used by `sbc-daemon`.

### JWT (OIDC Bearer REGISTER and Management API)

- **Accepted algorithms**: `proto-jwt::validator::ALLOWED_ALGS` = `RS256, PS256, ES256, ES384`. Only symmetric (HS*) algorithms are rejected. This validator **is wired** in `sbc-daemon` for RFC 8898 Bearer REGISTER (`SBC_AUTH_MODE=bearer`) and in `sbc-client-config-server`.
- **CNSA status**: **Non-compliant / Planned.** Restricting the allow-list to ES384 (and ES512) requires the IdP to issue ES384 tokens; until then RS256/ES256 tokens from the IdP are accepted.
- **Implementation**: `proto-jwt` (JWKS cache + `jsonwebtoken`).

## FIPS 140-3 Validation

Wired (all binaries). The cryptographic backend (aws-lc-rs) is FIPS 140-3 validated when compiled with the `fips` feature, which is the default:

```toml
# crates/uc/uc-crypto/Cargo.toml
[features]
default = ["fips"]
fips = ["aws-lc-rs/fips"]
```

The workspace `rustls` dependency also enables its `fips` feature, and `sbc-daemon` installs `rustls::crypto::aws_lc_rs::default_provider()` as the process provider at startup (`sbc-daemon/src/main.rs`).

AWS-LC-FIPS 3.0 includes:

- First FIPS-validated ML-KEM implementation
- AES-256-GCM
- SHA-384/512
- ECDSA/ECDH P-384

## Post-Quantum Preparation

CNSA 2.0 mandates migration to post-quantum algorithms by 2033:

| Function | Current | Future (2033) | Status |
|----------|---------|---------------|--------|
| Key Exchange | ECDH P-384 | ML-KEM-1024 | Planned |
| Signatures | ECDSA P-384 | ML-DSA-87 | Planned |

Current state of the migration path:

- `uc-crypto` declares a `pqc` feature flag, but it is **empty** (`pqc = []`, no code behind it).
- aws-lc-rs includes ML-KEM support; nothing in the workspace calls it yet.
- Key exchange abstractions in `uc-crypto` support algorithm agility (Library-only).

## Verification

### Compile-Time

Non-compliant algorithms cannot compile against `uc-crypto`:

```rust
// This won't compile - Sha256 doesn't exist
let hash = uc_crypto::hash::sha256(data); // ERROR: function not found
```

### Runtime

Configuration is validated at startup (`sbc-config/src/validate.rs`):

```rust
// This will fail validation
config.security.min_tls_version = "1.0"; // Error: CNSA 2.0 violation
```

As noted above, this is a validation-only check; it does not alter the TLS listener configuration.

### Testing

- `uc-crypto`, `proto-srtp`, `proto-dtls` and `uc-transport` carry unit tests (e.g. `uc-transport/src/tls.rs` `test_cnsa_compliant_client_config`, `proto-dtls/src/cipher_suite.rs` `test_cnsa_cipher_suites`).
- There is **no** `tests/compliance/` directory or `cnsa_crypto_vectors.rs` file in the repository; the compliance vector suite is Planned.

## References

- [NSA CNSA 2.0 Fact Sheet](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [NSA CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_FAQ_.PDF)
- [CNSSP 15](https://www.cnss.gov/CNSS/issuances/Policies.cfm) - National Information Assurance Policy
- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) - Stateful Hash-Based Signatures
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (Kyber)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (Dilithium)
