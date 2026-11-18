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
| Digital Signatures | ECDSA P-384 | P-384 | `uc-crypto::ecdsa::P384KeyPair` | Wired (soft client) since feat/client-dtls-wiring (2026-11-17): the `proto-dtls` `DtlsAssociation`, which the soft client runs for every call on a TLS account, signs and verifies with it (scheme `ecdsa_secp384r1_sha384`, 0x0503, only). No SBC binary calls it (SBC TLS/DTLS signatures are done by rustls / the DTLS sidecar). The DTLS sidecar signs and accepts ECDSA P-384/SHA-384 only (see DTLS-SRTP) |
| Key Exchange | ECDH P-384 | P-384 | `uc-crypto::ecdh::P384EphemeralKeyPair` | Wired (soft client) since feat/client-dtls-wiring (2026-11-17), through the `proto-dtls` `DtlsAssociation` (DTLS-SRTP key agreement of every call on a TLS account). No SBC binary calls it. The DTLS sidecar's ECDHE is held to secp384r1 by a wire guard (see DTLS-SRTP) |
| Key Derivation | HKDF-SHA384 | - | `uc-crypto::hkdf::hkdf_sha384` | Library-only (no shipped caller; SRTP uses the RFC 3711 KDF, see below) |
| Key Derivation (DTLS 1.2) | TLS 1.2 PRF with P_SHA384 (RFC 5246 §5), extended master secret (RFC 7627) | - | `uc-crypto::tls12::prf_sha384`, computed by the aws-lc module's TLS KDF, not a hand-composed HMAC loop; labels restricted to the closed set `Tls12Label` (`extended master secret`, `key expansion`, `client finished`, `server finished`, `EXTRACTOR-dtls_srtp`) | Wired (soft client) since feat/client-dtls-wiring (2026-11-17); only caller: `proto-dtls` `key_schedule.rs` / `srtp_export.rs`, driven by the soft client's DTLS driver. Caveat (now for a shipped binary): the module's approved-service indicator is set for this KDF only with the `extended master secret` label; the other four labels compute inside the module without it (NIST POA&M-332). DTLS 1.2 does not use HKDF. Tests `prf_sha384_known_answer`, `prf_sha384_matches_hmac_composition`, `labels_are_the_rfc_strings` (`uc-crypto/src/tls12.rs`) |
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
- **Implementation**: rustls with aws-lc-rs backend (`uc-transport`). The soft client (`client-core/src/sip_transport.rs`) also pins TLS 1.3 only and uses `cnsa_provider()`; so does client provisioning HTTPS (`client-provisioning/src/http.rs`), except the debug-only `CaTrust::Insecure` mode. Default-feature client builds have no non-TLS SIP path (UDP SIP code only with `insecure-transports`; POA&M-318, POA&M-322).

### SRTP

- **Profile**: Wired (sbc-media-core). `AEAD_AES_256_GCM` (RFC 7714) is the only profile in `proto-srtp::SrtpProfile`; the relay rejects any other DTLS-SRTP profile from the sidecar (`sbc-media-core/src/dtls_relay.rs`).
- **Key Size**: 256-bit master key, 96-bit master salt.
- **KDF**: standard **RFC 3711 §4.3 AES-CM KDF** (AES-256-CM PRF), as required for interoperability with every other SRTP stack. An earlier HKDF-SHA384 derivation was removed because it produced non-interoperable session keys (`proto-srtp/src/key.rs`).
- **Implementation**: `proto-srtp` crate, used by `sbc-media-core` (`srtp_relay.rs`, `media_pipeline.rs`).
- **SBC terminate mode (2026-11-17)**: Wired (sbc-media-core); local macOS run, 2026-11-17. Each AES-256-GCM key exported for a call is held by one SRTP context per direction, owned by one relay task (`media_pipeline.rs` `terminate_supervisor`, `srtp_relay.rs` `TerminateRelayLeg`), so the relay does not seal two packets with the same SRTP or SRTCP index under one key (RFC 7714 §8.1 / §9.1). RTCP is relayed only when multiplexed on the media port; no RTP + 1 socket is bound (NIST POA&M-343). Tests: `terminate_egress_srtcp_indices_unique_on_media_port`, `terminate_rtp_plus_one_traffic_not_reemitted`, `terminate_binds_no_rtp_plus_one_port`.
- **Soft client (fix/client-srtp-b2; feat/client-dtls-wiring, 2026-11-17)**: Wired (soft client); tested in local runs and in CI (Ubuntu x86_64). The client's SRTP key type accepts `AEAD_AES_256_GCM` only, with a 32-byte key and 12-byte salt per direction (`client-audio/src/media_security.rs` `SrtpSessionKeys::validate`, test `wrong_lengths_rejected`), and RTP and RTCP are protected with `proto-srtp` when keys are present (tests `srtp_loopback_no_plaintext_on_wire`, `srtcp_round_trip_and_no_plaintext_on_wire`, with test-made keys). Since feat/client-dtls-wiring the keys come from the DTLS-SRTP handshake described under DTLS-SRTP below; a call whose handshake does not complete ends with no audio. SRTP and SRTCP under exported keys were exchanged with pion (`client-core/tests/dtls_interop_pion.rs`) and through the SBC relay and sidecar (`client-integration-tests/tests/dtls_sbc_sidecar.rs`) in local runs on macOS arm64 and in [SRTP audio gate run 44066084371](https://github.com/192d-Wing/usg-uc/actions/runs/44066084371) on the merged PR head (`4dfea0d`, Ubuntu x86_64). The transmit SSRC of an SRTP stream comes from the aws-lc DRBG through `uc-crypto` and is never handed out twice under a key; per-call state keeps one SRTP context per direction across audio pipeline restarts and allows one live transmitter at a time, so an (SSRC, index) pair is not sealed twice under one AES-256-GCM key (RFC 7714 §8.4; `client_audio::SrtpCallState`, `TransmitClaim`; tests `call_state_never_hands_out_an_ssrc_twice`, `second_transmit_claim_is_refused_while_the_first_lives`; remaining limits NIST POA&M-338). Default-feature builds have no plaintext RTP path; `insecure-transports` builds can send plaintext RTP on UDP/TCP accounts.

### SIPREC recording session (sbc-daemon, sbc-media-core)

Wired since SIPREC phase 3, off by default (`[recording]`). Tested against a fake recorder only; no interoperability run against a real SRS.

- **Signaling to the recorder (SRS)**: `sips:` only. The recorder TLS client is built with `uc_transport::tls::create_client_config_with` over `cnsa_provider()` with `MinTlsVersion::V1_3`, whatever `security.min_tls_version` says (`sbc-daemon/src/server.rs` `wire_recording`). Trust anchors come from `recording.srs_tls_ca_file` only; the server name is always verified. Suites and groups are those of the provider (see SIP/TLS above). A recorder limited to TLS 1.2 cannot be used.
- **Recorded media**: each forked stream is SRTP `AEAD_AES_256_GCM` (RFC 7714) with its own 256-bit master key and 96-bit salt from the `uc-crypto` CSPRNG, an SBC-chosen SSRC and an SBC-owned packet counter, so a call party cannot force nonce reuse (`sbc-media-core/src/recording_fork.rs`, `proto-srtp` `protect_rtp_in_place`, `uc-crypto` `seal_in_place`).
- **Key transport**: SDES (`a=crypto:1 AEAD_AES_256_GCM inline:`) inside the recording INVITE. Its confidentiality rests entirely on the TLS 1.3 session to the recorder (RFC 4568 §8.3). No AES-128 or HMAC-SHA1 suite is offered: a recorder that supports only `AES_CM_128_HMAC_SHA1_80` answers 488 (audit reason `srs_not_acceptable_488`) and the call is handled per `recording.on_failure`.
- **Open (NIST POA&M-304)**: ML-KEM hybrid key exchange is not offered toward the recorder; no RFC 3263 NAPTR / SRV resolution. The recorder certificate type is not restricted to P-384 (same as the other TLS clients).
- Tests: `recorder_flow_dials_with_the_srs_ca_and_name`, `recorder_flow_rejects_trunk_ca_certificate_and_wrong_name` (`sbc-daemon/src/flows.rs`), `recording_wires_settings_and_the_recorder_tls_profile` (`server.rs`), `offer_is_srtp_with_one_sdes_line_per_stream` (`uc-siprec`), `hostile_endpoint_cannot_force_a_repeated_ssrc_and_index` (`sbc-integration-tests/tests/siprec_fork.rs`), `test_seal_in_place_known_answer` (`uc-crypto/src/aead.rs`), `in_place_equals_allocating_protect` (`proto-srtp/src/protect.rs`). No test asserts the negotiated TLS version, suite or group of the recorder connection itself; that rests on the shared `cnsa_provider()` tests. There is no RFC 7714 packet-level known-answer test in `proto-srtp`.

### DTLS-SRTP

- **DTLS Version**: **1.2** (RFC 6347). Since feat/client-dtls-handshake Stage 1 (2026-11-16) `proto-dtls` implements a DTLS 1.2 handshake and record layer for DTLS-SRTP (`proto-dtls/src/association.rs` `DtlsAssociation`, sans-I/O, both roles), no longer the record layer only. Since feat/client-dtls-wiring (Stage 2, 2026-11-17) it is **Wired (soft client)**: the soft client drives it on each call's media socket (`client-sip-ua/src/dtls_driver.rs`). No SBC binary uses it. DTLS 1.3 is Planned.
- **`proto-dtls` association profile (Wired, soft client, since 2026-11-17)**: fixed in code, nothing is negotiated beyond it and anything else fails the association: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`; ECDHE on secp384r1; signatures `ecdsa_secp384r1_sha384` only, made and accepted; peer certificate key must be ECDSA P-384; `SRTP_AEAD_AES_256_GCM` only, no MKI; extended master secret required. Key derivation is the TLS 1.2 PRF with SHA-384 (see Approved Algorithms and NIST POA&M-332); SRTP keys are exported with the RFC 5705 exporter over that PRF. Record sealing uses the module's TLS 1.2 AES-256-GCM construction, which refuses a nonce that does not increase (`uc-crypto::tls12::Tls12GcmSealer`, test `sealer_refuses_repeated_or_decreasing_nonce`). The certificate's own signature, chain and validity are not checked; the SDP fingerprint is the trust anchor. Tests (`proto-dtls/tests/negative.rs`): `client_hello_offers_only_the_cnsa_profile`, `server_flight_and_client_proof_use_only_the_cnsa_profile`, `server_refuses_client_offers_outside_the_profile`, `client_refuses_server_selections_outside_the_profile`, `client_refuses_server_key_exchange_signature_schemes_other_than_0x0503`, `client_refuses_server_key_exchange_on_another_curve`, `server_refuses_certificate_verify_schemes_other_than_0x0503`, `client_fails_a_server_certificate_without_a_p384_key`, `server_fails_clients_without_the_aead_256_srtp_profile`; `server_fails_client_without_extended_master_secret`, `client_fails_server_without_extended_master_secret` (`loopback.rs`). Interoperability: pion/dtls v3.1.5 in both roles (`tests/interop_pion.rs`, `#[ignore]`), local runs only when this was written, since then also run by the `SRTP audio gate` workflow (PR #208 head `4dfea0d`, Ubuntu x86_64); no other peer was tested. ECDH and ECDSA on P-384 are the classical CNSA 2.0 transition algorithms; ML-KEM for DTLS needs DTLS 1.3 and is not implemented.
- **Cipher Suite**: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` is the only CNSA-compliant suite in `proto-dtls::cipher_suite` (Library-level filter), and the only suite the `DtlsAssociation` offers or accepts.
- **Fingerprint Hash**: Wired (sbc-media-core, sbc-daemon). `proto-dtls::fingerprint` supports SHA-384/SHA-512 only; the SBC advertises `a=fingerprint:sha-384 …` in rewritten SDP (`sbc-daemon/src/sdp_dtls.rs`).
- **SBC Identity**: Wired (sbc-media-core). The self-signed DTLS certificate is generated with rcgen `PKCS_ECDSA_P384_SHA384` (`dtls_identity.rs`).
- **Key Exchange / Handshake**: in the shipped SBC the DTLS handshake is performed by an external **Go DTLS-SRTP terminator sidecar** reached over a Unix socket (`sbc-media-core/src/dtls_sidecar.rs`); the Rust relay demuxes records and verifies the negotiated profile and fingerprint. The ECDH curve used inside the sidecar is not verified by Rust code; since Stage 1 it is enforced inside the sidecar (next item). There is no `webrtc-dtls` dependency.
- **Go sidecar profile (Wired, SBC; changed 2026-11-16, an SBC behaviour change)**: `sidecar/dtls-terminator/session.go` (`Run`) and `groupguard.go`, pion/dtls v3.1.5 on the Go FIPS module (`GOFIPS140=v1.26.0`, `GODEBUG=fips140=on`). Before this change only the cipher suite, the SRTP profile and the SHA-384 fingerprint were restricted. What is enforced now, and by what:
  - Cipher suite `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` and SRTP profile `AEAD_AES_256_GCM`: pion configuration; the SRTP profile is checked again after the handshake.
  - Signatures the sidecar verifies (the peer's `ServerKeyExchange` or `CertificateVerify`) and its own `ServerKeyExchange`: ECDSA P-384/SHA-384 only, pion configuration (`SignatureSchemes`). pion's default would sign with ECDSA/SHA-256.
  - The sidecar's own `CertificateVerify` (client role): pion would follow the server's `CertificateRequest`, so the wire guard withholds any scheme but ECDSA P-384/SHA-384, sends a fatal `handshake_failure` and aborts. A server that asks for another scheme first is refused, not answered with a scheme further down its list.
  - ECDHE group secp384r1: pion's `EllipticCurves` setting only limits what the sidecar offers as client, so the wire guard enforces the group on the `ServerKeyExchange`. Server role: if pion built one on another group (it follows the first entry of the client's `supported_groups`), it is withheld, a fatal `handshake_failure` is sent and the handshake is aborted. Client role: an inbound `ServerKeyExchange` on another group is dropped unread; a server that insists on one is refused when the handshake deadline expires, and gets no alert.
  - Extended master secret (RFC 7627): required, pion configuration.
  - Peer certificate: SHA-384 SDP fingerprint and an ECDSA P-384 public key, in `VerifyPeerCertificate` (`requireP384Key`). The certificate's own signature algorithm is not checked (chain verification is skipped; the fingerprint is the trust anchor).
  - Restrictions and residuals: (1) a peer that sends `supported_groups` must list secp384r1 first, otherwise the sidecar as server refuses it even though the peer supports the group (NIST POA&M-336); (2) a peer whose first `ServerKeyExchange` fragment is shorter than three bytes, or that sends a fragment starting at offset 1 or 2, is refused, although RFC 6347 §4.2.3 allows such fragments; (3) the guard (`groupguard.go`) is project code on the SBC media path, not part of pion or of any validated module, and depends on how pion v3.1.5 reassembles handshake fragments; `TestPionReassemblyAssumptions` fails if the pion version or that behaviour changes; (4) pion composes the TLS 1.2 PRF in Go on top of the Go module's HMAC, so "all crypto runs in the certified module" holds for the primitives, not for the PRF as a module KDF service (NIST POA&M-332); DTLS's deterministic-IV GCM does not pass Go's stricter `fips140=only` mode; (5) pion's handling of forged epoch-0 datagrams is unchanged (NIST POA&M-335); (6) no peer other than pion was tested against the pinned sidecar.
  - Tests (`session_test.go`, `groupguard_test.go`; local runs with `-race` under `fips140=on`; `.github/workflows/sidecar-dtls.yml` runs `go test -race -v ./...` for `sidecar/**` changes but had not run on the Stage 1 or the Stage 2 change when this was written): `TestDtlsInProfileRawPeerAccepted`, `TestDtlsSha256SignatureRejected`, `TestDtlsP256KeyExchangeRejected`, `TestDtlsServerChoosingNonP384GroupRejected`, `TestDtlsPeerWithoutExtendedMasterSecretRejected`, `TestDtlsP256CertificateRejected`, `TestDtlsCertificateVerifySchemeEnforced`, `TestDtlsClientListingP384SecondIsRefused`, `TestGuardWritePathWithholdsAlertsAndAborts`, `TestGuardReadPathDropsWithoutAborting`, `TestServerKeyExchangeGroupScanner`, `TestCertificateVerifySchemeScanner`, `TestRunRequiresADeadline`, `TestPionReassemblyAssumptions`; `srtp_audio_end_to_end` (`sbc-media-core`) with the rebuilt sidecar and peer.
- **Go sidecar association lifetime (changed 2026-11-17; no change to the cryptographic profile)**: the sidecar now keeps each DTLS association for the whole call instead of closing it after key export (`sidecar/dtls-terminator/service/session.go`, `plaintextgate.go`). `groupguard.go`, `go.mod` and `go.sum` are unchanged; cipher suite, groups, signature schemes, extended master secret and SRTP profile are as above. Consequence for key custody: pion holds the DTLS master secret for the whole call (NIST POA&M-330). See `docs/NIST-800-53-CONTROLS.md` (Go sidecar rows; POA&M-335, -340, -341, -342).
- **Implementation**: `proto-dtls` (types, fingerprint; DTLS 1.2 association, used by the soft client) + Go sidecar (the SBC's DTLS endpoint).
- **Soft client (feat/client-dtls-wiring Stage 2, 2026-11-17)**: Wired (soft client); tested in local runs (macOS arm64) and in CI on the merged PR head (`4dfea0d`, Ubuntu x86_64). A call on a TLS account negotiates exactly the `proto-dtls` association profile above with its peer, in either DTLS role: DTLS 1.2, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, ECDHE on secp384r1, `ecdsa_secp384r1_sha384`, extended master secret required, `SRTP_AEAD_AES_256_GCM`. There is no setting that widens the profile, no retry with other parameters, no SHA-256 and no plaintext fallback: any other outcome ends the call. Tests: `both_roles_reach_ready_with_mirrored_keys`, `fingerprint_mismatch_fails_closed_in_both_roles` (`client-sip-ua/tests/dtls_driver_loopback.rs`), `outbound_call_connects_only_after_the_handshake_in_both_roles` (`client-core/tests/dtls_srtp_call.rs`), interop with pion/dtls v3.1.5 in both roles (`client-core/tests/dtls_interop_pion.rs`) and with the SBC sidecar (`dtls_sbc_sidecar.rs`). The approved-service evidence gap for the TLS 1.2 PRF labels (NIST POA&M-332) now applies to a shipped binary. Interoperability cost of the profile: a peer must support all of it, and the SBC sidecar as server additionally requires secp384r1 first in `supported_groups` (NIST POA&M-336; the client lists only secp384r1).
- **Soft client identity**: one ephemeral self-signed ECDSA P-384 / SHA-384 certificate per process (rcgen `PKCS_ECDSA_P384_SHA384`, `client-sip-ua/src/dtls_identity.rs`), or a user certificate when its exportable PKCS#8 key is P-384, matches the leaf public key, and the certificate is signed with ecdsa-with-SHA384. Tests `generate_p384_identity_with_single_prefix_fingerprint`, `from_user_der_accepts_p384_only`, `from_user_der_requires_matching_key_and_sha384_signature`.
- **Soft client fingerprint hash**: `sha-384` advertised; only `sha-384` / `sha-512` accepted from the peer (`proto-dtls` `from_sdp_strict`). `sha-256` is refused, which is stricter than RFC 8122 and costs interoperability with `sha-256`-only peers. Since 2026-11-17 the certificate the peer presents in the handshake must match one of the accepted fingerprints, and its key must be ECDSA P-384, before any key is exported.
- **Soft client key custody**: SRTP key buffers are `Zeroizing`. The identity key is loaded into one `uc_crypto` key pair shared by reference count with every call's association (no per-call copy; the PKCS#8 bytes are wiped after loading). Not zeroized: the rcgen `KeyPair` copy made while generating or checking the identity; the key pair itself stays in memory for the life of the process (NIST POA&M-330).
- **Soft client test-only keying**: the `proto-dtls` feature `test-placeholder-keying` (random keys, no handshake) is compiled only into proto-dtls's own unit tests and is a `compile_error!` without `debug_assertions`.

### STIR/SHAKEN

- **CNSA exception (documented, POA&M-27):** SHAKEN mandates ES256 (ECDSA P-256 / SHA-256; RFC 8225 §5.2, ATIS-1000074), and every STI-CA issues P-256 certificates. ES256 lives only in `uc_crypto::interop::ecdsa_p256`, compiled with the `stir-shaken-es256` feature, not re-exported from the CNSA surface. **The feature is not optional for the SBC:** `uc-sti` depends on `uc-crypto` with `stir-shaken-es256` enabled unconditionally (`crates/uc/uc-sti/Cargo.toml`) and `sbc-daemon` always depends on `uc-sti`, so every `sbc-daemon` binary contains the ES256 code, whether or not `[stir_shaken]` is enabled (POA&M-39). At runtime it is reached only when signing or verification is configured; the using modules carry a `CNSA-EXCEPTION` tag (`uc-crypto/src/x509.rs`, `uc-sti/src/cache.rs`, `proto-stir-shaken/src/passport.rs`, `sbc-daemon/src/stir.rs`, `sbc-config`), though `uc-sti/src/signer.rs` does not. It is used for caller-identity signatures only, never for confidentiality. The CNSA `uc_crypto::ecdsa` module still exposes P-384 only.
- **CNSA exception (documented, POA&M-110): SIP digest HA1.** HA1 and digest responses use SHA-256 (RFC 7616, RFC 8760) because SIP phones support nothing CNSA-approved (SHA-512-256 is not CNSA either). Code: `uc-user-mgmt/src/digest.rs` `compute_ha1`, `verify_digest_response`, tagged `CNSA-EXCEPTION` and `// POAM: POA&M-110`. Authentication only, never confidentiality. HA1 values in the sbc-api-server `users` table are sealed with AES-256-GCM (see NIST SC-28). The sbc-daemon HA1 credentials file (`[digest_auth] credentials_file`) is not sealed by the SBC; it is protected by file mode and owner checks only (NIST POA&M-312). Milestone: a CNSA digest algorithm for SIP, or RFC 8898 Bearer replacing digest. The same exception covers `proto-sip` `auth.rs` `Sha256DigestHasher` / `Sha512_256DigestHasher` and `proto-registrar` `authentication.rs` `hash_bytes` (aws-lc-rs; FIPS module only when `aws-lc-rs/fips` is enabled in the build). MD5 is still selectable in those library verifiers for interoperability (not the default) and is not CNSA; sbc-daemon has no configuration path to it (below). The proto-sip `DigestVerifier` nonce MAC is HMAC-SHA-384 (POA&M-230). **Live on the SBC when `[digest_auth] require_auth = true` (off by default; NIST POA&M-270 closed 2026-11-10):** sbc-daemon's REGISTER path uses `DigestVerifier` with the algorithm pinned to `digest_auth.algorithm`, SHA-256 by default or SHA-512-256 (the token names FIPS 180-4 SHA-512/256), and an HMAC-SHA-384 nonce key generated per process from `uc_crypto::random`. The server side has no configuration path to MD5: `algorithm = "MD5"` or a `-sess` variant fails the config load, an MD5 line in the credentials file fails the file load, and MD5 credentials on the wire are rejected as `algorithm_mismatch` (tests `digest_auth_algorithm_policy`, `every_malformed_line_rule_is_reported_with_its_line_number`, `digest_register_rejects_each_audited_with_reason`). MD5-only phones therefore cannot register while digest is on. `CNSA-EXCEPTION` comments: `sbc-config/src/schema.rs` (`DigestAuthAlgorithm`), `sbc-daemon/src/server.rs` (`digest_algorithm`), `sbc-daemon/src/sip_stack.rs`. The exception assumes the exchange runs over CNSA TLS; that is not enforced. With `require_auth = true` and a `udp`, `tcp` or `ws` SIP listener the daemon logs a startup warning and starts (NIST POA&M-314). **UAC side** (SBC trunk registration `sbc-trunk-services`, soft client): the strongest offered challenge is answered with the matching hasher (SHA-512-256 or SHA-256 under POA&M-110). If the peer offers only MD5, MD5 is refused unless the policy allows it (NIST POA&M-255 closed): an unset policy allows MD5 only when the transport is TLS (`proto-sip` `resolve_allow_md5`); trunk REGISTER is always UDP, so a trunk needs `"allow_md5_digest": true` in the stored/API trunk JSON, and client UDP/TCP accounts need an explicit `true` (see the NIST IA-5 row for tests). MD5 is not CNSA and not covered by an exception; MD5 answered after an explicit opt-in, or on TLS client accounts with the policy unset, is NIST POA&M-276.
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

Module version facts, recorded 2026-11-16 from the build inputs:

- `Cargo.lock` pins `aws-lc-rs` 1.18.1 and `aws-lc-fips-sys` 0.14.2 (the FIPS build of aws-lc that the `fips` feature links). `aws-lc-sys` 0.45.0, the non-FIPS build, is also in the lock file as a dependency of `aws-lc-rs`.
- The aws-lc source bundled in `aws-lc-fips-sys` 0.14.2 identifies itself as version 4.2.0 (`AWSLC_VERSION_NUMBER_STRING` in its `include/openssl/base.h`).
- Earlier revisions of this document said "AWS-LC-FIPS 3.0". That name was not taken from the build and is withdrawn. This document does not state a CMVP certificate number, and does not state whether the module version built from `aws-lc-fips-sys` 0.14.2 is validated, in process, or covered by an existing certificate: none of that has been verified by the project.
- The Go sidecar selects the Go Cryptographic Module at build time with `GOFIPS140=v1.26.0` and, per its README, refuses to start outside FIPS mode (the test `TestFIPSModeActive` fails when FIPS mode is off). Its CMVP status is likewise not asserted here.

Evidence still needed for the ATO package (NIST POA&M-332 for the TLS 1.2 KDF part): the CMVP certificate and Security Policy that cover the aws-lc module version actually built, including the tested operating environments compared with the deployment targets; the same for the Go module; the CAVP listings for the algorithms used (AES-256-GCM, SHA-384/512, ECDSA and ECDH on P-384, HMAC-SHA-384, TLS v1.2 KDF RFC 7627 with SHA2-384, ML-KEM-1024); and a lab or ISSO statement on the TLS 1.2 PRF labels other than `extended master secret`.

Algorithms this project uses from the aws-lc module: AES-256-GCM, SHA-384/512, HMAC-SHA-384, ECDSA and ECDH on P-384, ML-KEM-1024 (TLS only), the TLS 1.2 KDF (`proto-dtls`, used by the soft client since 2026-11-17), and the module's deterministic random bit generator (`uc-crypto/src/random.rs`, through `aws_lc_rs::rand::SystemRandom`; since 2026-11-17 also the source of the soft client's SRTP transmit SSRC; how it is seeded is described by the module's Security Policy, not by this project). The DTLS, SRTP and SIP protocol logic built on these primitives is project code (or pion, in the sidecar) and is not part of any validated module. `uc_crypto::constant_time::eq` calls an aws-lc comparison routine; no claim is made that it is an approved service.

## Post-Quantum Preparation

CNSA 2.0 mandates migration to post-quantum algorithms by 2033:

| Function | Current | Future (2033) | Status |
|----------|---------|---------------|--------|
| Key Exchange | ECDH P-384 | ML-KEM-1024 | Wired for SBC TLS and soft client SIP-TLS / provisioning HTTPS (preferred; P-384 fallback). Not for DTLS-SRTP. |
| Signatures | ECDSA P-384 | ML-DSA-87 | Planned |

Current state of the migration path:

- `uc-crypto` declares a `pqc` feature flag, but it is **empty** (`pqc = []`, no code behind it).
- SBC TLS (SIP-TLS, trunk TLS, SIPREC recorder TLS, CDR syslog, x5u fetch) offers ML-KEM-1024 first through `uc_transport::tls::cnsa_provider()`. DTLS-SRTP and `uc-crypto` do not use ML-KEM yet.
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
- `proto-dtls` integration tests (`crates/proto/proto-dtls/tests/`, added 2026-11-16) check the DTLS profile on the wire and the refusal of everything outside it; the Go sidecar tests do the same for the SBC's DTLS endpoint. The soft client's DTLS-SRTP tests (added 2026-11-17: `client-sip-ua/tests/dtls_*.rs`, `client-core/tests/dtls_*.rs`, `client-integration-tests/tests/dtls_sbc_sidecar.rs`) were run locally on macOS arm64 only. See DTLS-SRTP above for names and for what was a local run only. Not run locally: the `uc-crypto` doctests (the doctest binary cannot load the FIPS dylib on the development machine); nothing was run on Linux outside CI.
- There is **no** `tests/compliance/` directory or `cnsa_crypto_vectors.rs` file in the repository; the compliance vector suite is Planned.

## References

- [NSA CNSA 2.0 Fact Sheet](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [NSA CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_FAQ_.PDF)
- [CNSSP 15](https://www.cnss.gov/CNSS/issuances/Policies.cfm) - National Information Assurance Policy
- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) - Stateful Hash-Based Signatures
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (Kyber)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (Dilithium)
