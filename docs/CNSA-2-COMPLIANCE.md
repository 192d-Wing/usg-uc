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
| Symmetric Encryption | AES-256-GCM | 256-bit | `uc-crypto::aead::Aes256GcmKey`; SRTP via `proto-srtp`; HA1 at rest via `uc-user-mgmt` | Wired (sbc-media-core SRTP relay; sbc-api-server `users.digest_ha1`) |
| Hash Functions | SHA-384, SHA-512 | 384-bit | `uc-crypto::hash::{sha384, sha512}` | Wired (sbc-media-core DTLS fingerprints via `proto-dtls`) |
| Digital Signatures | ECDSA P-384 | P-384 | `uc-crypto::ecdsa::P384KeyPair` | Library-only (no shipped caller; TLS/DTLS signatures are done by rustls / the DTLS sidecar) |
| Key Exchange | ECDH P-384 | P-384 | `uc-crypto::ecdh::P384EphemeralKeyPair` | Library-only (no shipped caller) |
| Key Derivation | HKDF-SHA384 | - | `uc-crypto::hkdf::hkdf_sha384` | Library-only (no shipped caller; SRTP uses the RFC 3711 KDF, see below) |
| TLS | TLS 1.3 | - | rustls with aws-lc-rs (`uc-transport::tls`) | Wired (sbc-daemon SIP-TLS listeners, soft client). Protocol version is 1.3 only unless `security.min_tls_version = "1.2"`. SBC configs use `uc_transport::tls::cnsa_provider()`: `TLS_AES_256_GCM_SHA384` (plus `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` on 1.2), ML-KEM-1024 or P-384 (see SIP/TLS). The soft client SIP-TLS (`client-core/src/sip_transport.rs` `create_tls_config`, TLS 1.3 only) and provisioning HTTPS (`client-provisioning/src/http.rs` `build_tls_config`, TLS 1.3 only, via reqwest `use_preconfigured_tls`) also use `cnsa_provider()` (tests `test_tls_config_uses_cnsa_provider`, `tls_config_uses_cnsa_provider`). Exception: the debug-build-only provisioning `CaTrust::Insecure` mode uses reqwest's default rustls provider (not compiled into release builds). The client verifier modes do not use the shared `uc_transport::tls` builders (POA&M-173). |

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

Status: Wired (sbc-daemon runs `validate_config` at load). `security.min_tls_version` (`"1.3"` default, `"1.2"` allowed) is applied to the SIP-TLS listeners (`uc-transport::tls::create_server_config_with`); the daemon REST HTTPS listener is TLS 1.3 only regardless (`uc_transport::tls::create_server_config`). `security.curve` is validated as an enum. **Load-time key curve check:** `uc_transport::tls::load_private_key`, which sbc-daemon uses for SIP-TLS and trunk keys and which the REST `ReloadableTlsAcceptor` uses, rejects RSA and P-256 private keys and accepts only ECDSA P-384 or P-521, at startup and on reload. P-384 is the CNSA ECDSA curve. P-521 is accepted under repository policy and is not a CNSA 2.0 algorithm. **Daemon keys follow `security.curve` (POA&M-166 closed):** the SIP-TLS listener and trunk mTLS client keys load with `load_private_key_with(security.curve)`, so a P-384 configuration rejects a P-521 key and the reverse, and each load is audited as `CryptoKeyOperation` (tests `tls_key_load_enforces_curve_and_audits_outcome`, `qa_tls_key_load_p521_key_curve_matrix`). The daemon REST HTTPS acceptor also passes `security.curve` for an exact match on startup and reload (`ApiServer::build_tls_acceptor`; test `startup_fails_closed_on_bad_api_key_file`). Residual: REST-triggered reloads are not audited (POA&M-193, POA&M-214). The certificate's public key is not checked separately. Tests: `tls::tests::key_file::curve_enforced`, `cert_reload::tests::test_reload_rejects_p256_key_swap`.

## Protocol-Specific Compliance

### SIP/TLS

- **TLS Version**: Wired (sbc-daemon). SIP-over-TLS listeners are built with `uc_transport::tls::create_server_config_with` — TLS 1.3 only by default, TLS 1.2+1.3 when `security.min_tls_version = "1.2"`. Listeners are skipped (with a warning) when `security.tls_cert_path`/`tls_key_path` are unset.
- **Cipher Suite**: Wired (uc-transport). `create_server_config`, `create_server_config_with`, `create_client_config` and `create_client_config_with` all build on `uc_transport::tls::cnsa_provider()`, the aws-lc-rs FIPS provider cut down to `TLS13_AES_256_GCM_SHA384` and, only when TLS 1.2 is enabled, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`. AES-128, ChaCha20-Poly1305 and RSA suites are not offered or accepted.
- **Key Exchange**: `MLKEM1024` (preferred), then `secp384r1`. X25519, P-256 and the X25519/P-256 + ML-KEM-768 hybrids are not offered or accepted. ML-KEM-1024 is the CNSA 2.0 key-establishment algorithm and is FIPS-approved in the aws-lc FIPS module (the configs report `fips() == true`). P-384 is kept so CNSA 1.0 peers still connect (one HelloRetryRequest round trip). The ML-KEM-768 hybrids are excluded because ML-KEM-768 is below CNSA 2.0's category 5 and X25519/P-256 are not CNSA algorithms. TLS 1.2 handshakes use P-384 (ML-KEM is TLS 1.3 only).
- **Signature algorithms**: verification schemes are the provider defaults, so peers whose CA signs with RSA or P-256 still verify. On TLS 1.2 the peer's own certificate must be ECDSA.
- Tests (`uc-transport/src/tls.rs`): `cnsa_provider_lists_only_cnsa_algorithms`, `cnsa_configs_are_fips`, `cnsa_client_and_server_agree_ml_kem_1024`, `cnsa_client_falls_back_to_p384_with_cnsa1_server`, `cnsa_server_accepts_cnsa1_client`, `cnsa_client_rejects_aes128_x25519_server`, `cnsa_client_rejects_x25519_only_server`, `cnsa_server_rejects_aes128_x25519_client`, `cnsa_server_rejects_x25519_only_client`, `tls12_is_limited_to_ecdhe_ecdsa_aes256_over_p384`, `client_config_with_rejects_weak_server_on_tls12`.
- **REST HTTPS** (`sbc-daemon/src/api_server.rs`): Wired (sbc-daemon). `ApiServer::build_tls_acceptor` installs a `ReloadableTlsAcceptor` built with `ReloadableTlsAcceptor::new_with_curve` over `uc_transport::tls::create_server_config`: `cnsa_provider()`, TLS 1.3 only (`security.min_tls_version` does not apply), `TLS13_AES_256_GCM_SHA384`, ML-KEM-1024 or P-384; the key file goes through the checked loader and must match `security.curve`. Startup fails closed if the acceptor cannot be built, and `run_https` refuses to serve without one. Certificate hot reload: a watcher polls the cert and key file metadata (mtime, length) every 30 s by default and reloads on change; a failed reload keeps the previous certificate (no audit record, POA&M-214). HTTP/1.1 only, with connection cap, handshake, idle and connection-age timeouts (see NIST SC-5). Tests (`api_server::rest_tls_tests`): `rest_tls_negotiates_cnsa_suite`, `rest_tls_rejects_non_cnsa_client`, `rest_tls_reload_swaps_cert`, `rest_tls_reload_failure_keeps_old_cert`, `startup_fails_closed_on_bad_api_key_file`, `https_without_acceptor_fails_closed`. The plain-HTTP listener (no TLS configured) is unchanged (POA&M-212).
- **Daemon gRPC / sbc-api channel** (`sbc-daemon/src/grpc_server/mod.rs` `configure_tls`, `sbc-api-server/src/state.rs`): tonic `ServerTlsConfig` / `ClientTlsConfig` with tonic's default rustls suites, so TLS 1.2 and 1.3, AES-128 and X25519 are allowed. This is not the uc-transport config. The Helm `grpcMtls` certificates are ECDSA P-384 (cert-manager), but the negotiated suite is not CNSA-restricted. NIST POA&M-16.
- **CDR syslog (RFC 5425)** (`sbc-daemon/src/cdr.rs` `TlsSyslogConnector`): `uc_transport::tls::create_client_config`, so TLS 1.3 only, `TLS_AES_256_GCM_SHA384`, ML-KEM-1024 or P-384 (POA&M-26 closed; test `cdr::tests::syslog_tls_is_cnsa_only` handshakes with a CNSA collector and fails against an AES-128/X25519 one). No client certificate is sent (NIST POA&M-15).
- **Egress SIP trunk TLS** (`sbc-daemon/src/flows.rs`, `server.rs`; `uc_transport::tls::create_client_config_with`): Wired (sbc-daemon). Server certificates are always verified against `security.trunk_tls_ca_path` (required when any trunk is `tls`) for `tls_server_name` or the trunk host / IP SAN; verification cannot be disabled. `security.min_tls_version` applies (TLS 1.3 only by default). With per-trunk `tls_client_cert = true` the SBC presents `security.tls_cert_path` (optional mTLS). Suites and key-exchange groups are the CNSA set from `uc_transport::tls::cnsa_provider()` (POA&M-26 closed); with `min_tls_version = "1.2"` a 1.2 trunk must offer `ECDHE-ECDSA-AES256-GCM-SHA384`, so it needs an ECDSA certificate. Tests: `flows::tests::tls_flow_dials_verified_trunk`, `tls_flow_never_downgrades_on_verify_failure`, `mtls_and_plain_flows_to_same_trunk_do_not_share_a_connection` (rcgen P-384 test CA; the negotiated suite is not asserted).
- **Certificates**: P-384 ECDSA is the operational requirement, but it is **not enforced**; rustls accepts any certificate/key it can parse (P-256, RSA).
- **Client mTLS**: Wired (sbc-daemon). `security.require_mtls` makes the SIP-TLS listener require a client certificate chaining to `security.tls_ca_path` (WebPKI verifier); `validate_config` rejects the flag without a CA bundle. The gRPC listener enforces its own `[grpc] require_mtls`.
- **Implementation**: rustls with aws-lc-rs backend (`uc-transport`). The soft client (`client-core/src/sip_transport.rs`) also pins TLS 1.3 only and uses `cnsa_provider()`; so does client provisioning HTTPS (`client-provisioning/src/http.rs`), except the debug-only `CaTrust::Insecure` mode.

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

- **CNSA exception (documented, POA&M-27):** SHAKEN mandates ES256 (ECDSA P-256 / SHA-256; RFC 8225 §5.2, ATIS-1000074), and every STI-CA issues P-256 certificates. ES256 lives only in `uc_crypto::interop::ecdsa_p256`, compiled with the `stir-shaken-es256` feature, not re-exported from the CNSA surface. **The feature is not optional for the SBC:** `uc-sti` depends on `uc-crypto` with `stir-shaken-es256` enabled unconditionally (`crates/uc/uc-sti/Cargo.toml`) and `sbc-daemon` always depends on `uc-sti`, so every `sbc-daemon` binary contains the ES256 code, whether or not `[stir_shaken]` is enabled (POA&M-39). At runtime it is reached only when signing or verification is configured; the using modules carry a `CNSA-EXCEPTION` tag (`uc-crypto/src/x509.rs`, `uc-sti/src/cache.rs`, `proto-stir-shaken/src/passport.rs`, `sbc-daemon/src/stir.rs`, `sbc-config`), though `uc-sti/src/signer.rs` does not. It is used for caller-identity signatures only, never for confidentiality. The CNSA `uc_crypto::ecdsa` module still exposes P-384 only.
- **CNSA exception (documented, POA&M-110): SIP digest HA1.** HA1 and digest responses use SHA-256 (RFC 7616, RFC 8760) because SIP phones support nothing CNSA-approved (SHA-512-256 is not CNSA either). Code: `uc-user-mgmt/src/digest.rs` `compute_ha1`, `verify_digest_response`, tagged `CNSA-EXCEPTION` and `// POAM: POA&M-110`. Authentication only, never confidentiality. Stored HA1 values are sealed with AES-256-GCM (see NIST SC-28). Milestone: a CNSA digest algorithm for SIP, or RFC 8898 Bearer replacing digest. The same exception covers `proto-sip` `auth.rs` `Sha256DigestHasher` / `Sha512_256DigestHasher` and `proto-registrar` `authentication.rs` `hash_bytes` (aws-lc-rs; FIPS module only when `aws-lc-rs/fips` is enabled in the build). MD5 is still selectable in those verifiers for interoperability (not the default) and is not CNSA. The proto-sip `DigestVerifier` nonce MAC is HMAC-SHA-384 (POA&M-230). sbc-daemon's REGISTER path uses `DigestVerifier` with algorithm pinned to SHA-256 by default (MD5 credentials rejected as `algorithm_mismatch`) and an HMAC-SHA-384 nonce key generated per process from `uc_crypto::random`; this path is not reachable from shipped configuration (POA&M-270). **UAC side** (SBC trunk registration `sbc-trunk-services`, soft client): the strongest offered challenge is answered with the matching hasher (SHA-512-256 or SHA-256 under POA&M-110). If the peer offers only MD5, MD5 is answered by default (`allow_md5_digest` = true); MD5 is not CNSA and not covered by an exception. The SBC cannot disable this by config (POA&M-255).
- **Provisioning device tokens: HMAC-SHA-384, no exception needed.** `sbc-provision-server/src/token.rs` (`mint_device_token`, `verify_device_token`) computes HMAC-SHA-384 over the normalized MAC with `SBC_PROVISION_SECRET` (hex, at least 32 decoded bytes). Decision: move to SHA-384 instead of recording a CNSA exception. Phones only echo an opaque token that the server minted (`sbc-provision-server --mint-token <MAC>`); no phone computes the HMAC, so there is no interoperability reason to keep SHA-256. HMAC-SHA-256 tokens are rejected. Tests: `sha384_token_roundtrip`, `sha256_legacy_token_rejected`, `mint_token_cli_matches_verifier`. Expiry and per-device revocation remain open (NIST POA&M-120).
- **Management API bearer tokens** (`uc-auth/src/lib.rs`): HMAC-SHA-384 `v2.` tokens; `v1.` (HMAC-SHA-256) tokens are rejected. Tests: `v2_token_roundtrip_sha384`, `v1_token_rejected`. API-key lookup digests are still SHA-256 (NIST POA&M-211).
- **Algorithm confusion:** `ppt=shaken` PASSporTs with any `alg` other than ES256 (including `none` and ES384) are rejected (`proto-stir-shaken/src/passport.rs`).
- **ES384:** reserved for bilateral profiles; `stir_shaken.algorithm = "ES384"` is rejected by validation in this release (POA&M-32).
- **STI certificate chains:** validated with rustls-webpki (aws-lc FIPS provider) to the STI-CR anchors, ECDSA P-256/P-384 signatures only (`uc_crypto::x509`).
- **x5u fetch TLS:** TLS 1.2/1.3 on `uc_transport::tls::cnsa_provider()` (`uc-sti/src/fetch.rs` `tls_config`) against the system web PKI: AES-256-GCM only, ML-KEM-1024 or P-384 only, and on TLS 1.2 `ECDHE-ECDSA-AES256-GCM-SHA384` only (POA&M-40 closed; test `sti_tests::x5u_tls_is_cnsa_only`). A certificate repository that offers only AES-128/ChaCha20, only X25519/P-256, or (on TLS 1.2) only an RSA certificate can no longer be fetched from, and calls signed with its certificates fail verification. The fetched chain's trust still comes from the STI-CR anchors.
- **Implementation**: `proto-stir-shaken` (pure protocol), `uc-sti` (fetch/cache/anchors/signer), `sbc-daemon/src/stir.rs` (call path).

### RADIUS (uc-aaa, dormant)

- **Not CNSA 2.0 compliant, no exception (POA&M-280).** `uc-aaa` RADIUS/UDP (`radius` feature, enabled by no shipped binary) uses MD5 for the Response Authenticator and User-Password hiding and HMAC-MD5 for the Message-Authenticator (RFC 2865, RFC 2869, RFC 3579). Since 2026-11-08 every Access-Accept/Reject/Challenge must carry a valid Message-Authenticator (CVE-2024-3596) and both authenticators are compared in constant time (`uc-aaa/src/radius.rs` `verify_access_response`, `ct_eq`); this hardens the protocol but does not make MD5 acceptable. RadSec (RFC 6614, TLS) is not implemented. Do not enable the feature in a CNSA deployment until RadSec over `cnsa_provider()` exists.

### JWT (OIDC Bearer REGISTER and Management API)

- **Accepted algorithms**: `proto-jwt::validator::ALLOWED_ALGS` = `RS256, PS256, ES256, ES384`. Only symmetric (HS*) algorithms are rejected. This validator **is wired** in `sbc-daemon` for RFC 8898 Bearer REGISTER (`SBC_AUTH_MODE=bearer`) and in `sbc-client-config-server`.
- **CNSA status**: **Non-compliant / Planned.** Restricting the allow-list to ES384 (and ES512) requires the IdP to issue ES384 tokens; until then RS256/ES256 tokens from the IdP are accepted.
- **Implementation**: `proto-jwt` (JWKS cache + `jsonwebtoken`).

### Storage TLS (uc-storage, dormant) - known gap

`uc-storage` Postgres (sqlx) and Redis TLS do **not** use `uc_transport::tls::cnsa_provider()`. Neither driver accepts a custom rustls `ClientConfig`: sqlx hard-codes `aws_lc_rs::default_provider()` and redis uses the process-default provider. Offered suites are the aws-lc-rs defaults (AES-128-GCM and X25519 are offered), so storage TLS is not CNSA 2.0 enforced. Installing `cnsa_provider` process-wide was not done because it would change every other rustls user. Tracked as POA&M-240 (`// POAM: POA&M-240` in `crates/uc/uc-storage/src/redis.rs` and `postgres.rs`). What is enforced: server certificate verification (`verify-full` default; plaintext and unverified modes refused unless `allow_insecure_transport`).

### Syslog TLS (uc-syslog, dormant)

`uc-syslog` `SyslogTransport::Tls` builds its client config with `create_client_config_with` and `cnsa_provider()`: TLS 1.3 only by default, `allow_tls12` adds TLS 1.2 with CNSA suites only. Library-only; not wired into sbc-daemon (POA&M-245). Test: `tls_delivers_octet_counted_frames` (`crates/uc/uc-syslog/src/forwarder.rs`, P-384 CA and leaf).

### Cluster message authentication (uc-cluster, dormant)

HMAC-SHA-384 with a key of at least 48 bytes via `uc_crypto::hash` (aws-lc-rs, constant-time verify). Library-only, no transport (POA&M-241). Tests in `crates/uc/uc-cluster/src/auth.rs`.

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
| Key Exchange | ECDH P-384 | ML-KEM-1024 | Wired for SBC TLS and soft client SIP-TLS / provisioning HTTPS (preferred; P-384 fallback). Not for DTLS-SRTP. |
| Signatures | ECDSA P-384 | ML-DSA-87 | Planned |

Current state of the migration path:

- `uc-crypto` declares a `pqc` feature flag, but it is **empty** (`pqc = []`, no code behind it).
- SBC TLS (SIP-TLS, trunk TLS, CDR syslog, x5u fetch) offers ML-KEM-1024 first through `uc_transport::tls::cnsa_provider()`. DTLS-SRTP and `uc-crypto` do not use ML-KEM yet.
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
