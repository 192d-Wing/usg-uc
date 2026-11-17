# CNSA 2.0 Compliance for SIP Soft Client

This document describes the CNSA 2.0 compliance status for the USG SIP Soft Client crates.

## CNSA 2.0 Requirements

| Requirement | Implementation Status |
|-------------|----------------------|
| TLS 1.3 only | Partial. SIP-TLS pins TLS 1.3 (`client-core/src/sip_transport.rs` `create_tls_config`). Default-feature builds compile no UDP SIP socket, receive loop or UDP send (`#[cfg(feature = "insecure-transports")]`; tests `client-core/tests/tls_only_surface.rs`, `test_tls_only_build_never_answers_over_udp`, not run by CI, POA&M-322). Not enforced by the type: `TransportPreference::{Udp,Tcp}` exist in all builds and a non-TLS account is refused by one runtime check; `insecure-transports` / `digest-auth` builds bind a UDP SIP listener for every account (POA&M-318) |
| CNSA TLS suites/groups | ✅ SIP-TLS (`client-core/src/sip_transport.rs` `create_tls_config`) and provisioning HTTPS (`client-provisioning/src/http.rs` `build_tls_config`) use `uc_transport::tls::cnsa_provider()`: `TLS_AES_256_GCM_SHA384`, ML-KEM-1024 / P-384; no AES-128, no X25519. Tests `test_tls_config_uses_cnsa_provider`, `tls_config_uses_cnsa_provider`. The provisioning client is https-only and follows no redirects (`build_http_client`; tests `http_client_refuses_plain_http_without_connecting`, `http_client_does_not_follow_cross_host_redirect`). Exception: debug-build-only provisioning `CaTrust::Insecure` uses reqwest's default provider. Open: POA&M-173 (verifier modes not on the shared builders) |
| AES-256-GCM | Implemented; tested in local runs on macOS arm64 and in CI on Ubuntu x86_64 (merged PR head `4dfea0d`, 2026-11-17). Since feat/client-dtls-wiring (2026-11-17) a call on a TLS account runs a DTLS 1.2 handshake on its media socket and carries SRTP and SRTCP (`AEAD_AES_256_GCM` only, via `proto-srtp`) under the exported keys; the DTLS records themselves use AES-256-GCM. Default-feature (TLS) builds have no plaintext RTP path: a call whose handshake does not complete is ended with no audio. `SrtpSessionKeys::validate` (`client-audio/src/media_security.rs`) rejects any other profile or key/salt length (tests `wrong_lengths_rejected`, `srtp_loopback_no_plaintext_on_wire`, `srtcp_round_trip_and_no_plaintext_on_wire`; with handshake keys: `client-core/tests/dtls_interop_pion.rs`, `client-integration-tests/tests/dtls_sbc_sidecar.rs`) |
| P-384/P-521 curves | ✅ Certificate store prefers P-384. The DTLS identity is an ephemeral self-signed ECDSA P-384 / SHA-384 certificate, or a user P-384 certificate whose public key matches its key and which is signed with ecdsa-with-SHA384 (`client-sip-ua/src/dtls_identity.rs`; tests `generate_p384_identity_with_single_prefix_fingerprint`, `from_user_der_requires_matching_key_and_sha384_signature`). Since 2026-11-17 it is the client's certificate in the DTLS-SRTP handshake, which uses ECDHE on secp384r1 and `ecdsa_secp384r1_sha384` only (P-521 is not offered for DTLS) |
| SHA-384+ hashing | Partial. Certificate thumbprints use SHA-256+. The DTLS `a=fingerprint` we advertise is SHA-384, and only sha-384 / sha-512 remote fingerprints are accepted (sha-256 and weaker are refused, a deliberate deviation from RFC 8122 interoperability; `proto-dtls/src/fingerprint.rs` `from_sdp_strict`, tests `strict_parse_rejects_bad_input`, `sha256_only_rejected_mixed_keeps_cnsa`). Since 2026-11-17 the certificate the peer presents in the DTLS handshake must match an accepted fingerprint before any key is exported (tests `fingerprint_mismatch_fails_closed_in_both_roles`, `fingerprint_mismatch_ends_the_call_and_is_never_connected`). The handshake hash and PRF are SHA-384 |
| No password auth | Partial. Default builds have no password authentication: accounts authenticate by OIDC Bearer token or by mTLS with a software P-384 key. Smart-card (CAC/PIV) authentication is not available (NIST POA&M-371). `digest-auth` test builds add password digest |

## Crate-by-Crate Compliance

### client-types

**Status: ✅ Compliant**

- `TransportPreference` defaults to `TlsOnly` but also has `Udp` and `Tcp` variants (marked not CNSA compliant) in all builds; UDP SIP code exists only with the `insecure-transports` feature
- In default builds `SipAccount` has no password fields; it authenticates by mTLS client certificate with a usable key or by OIDC Bearer token (`digest-auth` adds digest credentials)
- `CertificateConfig` supports smart card certificate selection; a selected card certificate cannot authenticate SIP (NIST POA&M-371)
- `SrtpKeyMaterial` in sensitive.rs requires 32-byte keys (AES-256)
- Memory zeroization for all sensitive data via `zeroize` crate

### client-audio

**Status: SRTP / SRTCP wired with DTLS-SRTP keys since 2026-11-17 (local runs on macOS arm64; CI on Ubuntu x86_64 on the merged PR head `4dfea0d`); open items NIST POA&M-325, -328, -338**

- A pipeline is built only from a `MediaSecurity` value (`src/media_security.rs`). In a default build the only variant is `Srtp`; `Plaintext` exists only with the `insecure-rtp` feature, which `client-core`'s `insecure-transports` enables (`compile_fail` doctest, meaningful only with default features; `ci.yml` step "Doctest client-audio (default features)")
- SRTP and SRTCP encryption/decryption are delegated to proto-srtp, `AEAD_AES_256_GCM` only; `SrtpSessionKeys::validate` requires a 32-byte key and 12-byte salt per direction (test `wrong_lengths_rejected`)
- On a keyed session RTP leaves as SRTP on every transmit path and RTCP as SRTCP; received RTCP is authenticated before parsing (tests `qa_srtp_every_tx_path_encrypted_role_swapped`, `srtcp_tampered_and_plaintext_dropped`). These tests use test-made keys; keys from a real handshake are used in `client-core/tests/dtls_interop_pion.rs` and `client-integration-tests/tests/dtls_sbc_sidecar.rs`
- Keys are held in `Zeroizing` buffers behind private fields, with redacted `Debug` and no `Clone` (test `debug_is_redacted`; zeroization on drop is not observed by a test)
- Per-call SRTP state (`SrtpCallState`, `src/media_security.rs`): the SRTP and SRTCP contexts of both directions, and the transmit SSRC, are kept across audio pipeline restarts under the same keys (re-INVITE, hold and resume), so rollover counters, replay windows and the SRTCP index continue. The first SSRC comes from the aws-lc DRBG through `uc-crypto`; an SSRC is never reused under a key. One live transmitter per call is enforced (`TransmitClaim`: a second claim is refused and no audio starts), which is what keeps an (SSRC, index) pair from being sealed twice under one AES-256-GCM key (RFC 7714 §8.4). Tests `srtp_transmit_survives_pipeline_restarts_for_a_single_context_receiver`, `srtp_replay_across_a_pipeline_restart_is_refused`, `call_state_never_hands_out_an_ssrc_twice`, `second_transmit_claim_is_refused_while_the_first_lives`. The state keeps the transmit master key and salt for the life of the call (wiped on drop)
- After the handshake the audio thread forwards DTLS records from the peer's address to the DTLS driver (token bucket: burst 8, 4 per second; `src/rtp_handler.rs`), so a retransmitted final flight is answered and the peer's `close_notify` or fatal alert ends the call
- Open: SRTCP receive allocates per datagram (NIST POA&M-328); STUN arriving on the media socket is dropped and counted, and a call with no audio thread does not service DTLS after the handshake (NIST POA&M-325); SRTP continuity limits, including one receive context per call and the SSRC kept across a clock-rate change (NIST POA&M-338)

### client-sip-ua

**Status: DTLS-SRTP handshake wired since 2026-11-17 (local runs on macOS arm64; CI on Ubuntu x86_64 on the merged PR head `4dfea0d`); open items NIST POA&M-327, -330, -332, -333, -334**

- DTLS handshake: wired (feat/client-dtls-wiring Stage 2, 2026-11-17). `src/dtls_driver.rs` runs one `proto_dtls::DtlsAssociation` per call on the call's media socket, in either DTLS role; `MediaSession::begin_secure` starts it and `poll_secure` reports keys or a fixed failure cause. One profile, fixed in code, with all cryptography from `uc-crypto` (aws-lc-rs FIPS build): DTLS 1.2, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ECDHE on secp384r1, `ecdsa_secp384r1_sha384`, extended master secret required, SRTP_AEAD_AES_256_GCM. Nothing else is negotiated, there is no retry with other parameters, and every outcome other than success ends the call with no audio (tests `both_roles_reach_ready_with_mirrored_keys`, `fingerprint_mismatch_fails_closed_in_both_roles`, `silent_peer_times_out_at_the_default_budget`, `begin_secure_without_fingerprint_fails_closed`). `src/dtls_handler.rs` is deleted; no client crate uses the legacy `DtlsConnection` / `DtlsSession` (their removal from `proto-dtls` is NIST POA&M-337)
- Evidence and limits (2026-11-17): the client suites and two interoperability tests passed in local runs on macOS arm64 and in CI on Ubuntu x86_64 on the merged PR head (`4dfea0d`; [SRTP audio gate run 44066084371](https://github.com/192d-Wing/usg-uc/actions/runs/44066084371)): pion/dtls v3.1.5 in both roles (`client-core/tests/dtls_interop_pion.rs`) and two client media stacks through the SBC relay and its Go DTLS sidecar (`client-integration-tests/tests/dtls_sbc_sidecar.rs`). Not shown: a call set up by SIP through `sbc-daemon`, the audio pipeline with devices, any other peer, Windows (NIST POA&M-339). Open items of the library that now apply to the shipped client: NIST POA&M-332 (the FIPS module's service indicator covers the TLS 1.2 KDF for the extended master secret only), POA&M-333 (no RFC 8844: the peer is authenticated only as the holder of the key whose fingerprint the SDP carried), POA&M-334 (a spoofed plaintext datagram can still end a handshake in some cases, and after the handshake can starve the forward of the peer's `close_notify`). A re-INVITE that changes fingerprint, setup or remote address starts no new handshake (POA&M-327). The SBC's DTLS endpoint accepts only peers on this same profile that list secp384r1 first in `supported_groups` (NIST POA&M-336); `DtlsAssociation` offers secp384r1 only. Against the SBC the client needs the sidecar of the same change (an older sidecar closes the association right after the handshake and the client then ends the call)
- DTLS identity (`src/dtls_identity.rs`): ephemeral self-signed P-384 / SHA-384, or a user P-384 certificate bound to its key and signed with ecdsa-with-SHA384. The key is loaded into one `uc_crypto` key pair shared by reference count with every call's association (no per-call copy); the PKCS#8 bytes are wiped after loading and `key_der()` is removed. Not zeroized: the rcgen `KeyPair` copy made while generating or checking the identity; the key pair stays in memory for the life of the process (NIST POA&M-330)
- Remote `a=fingerprint`: sha-384 / sha-512 only, parsed strictly (`src/sdp_dtls.rs`, `proto-dtls` `from_sdp_strict`). Since 2026-11-17 the peer's certificate must match one of them in the handshake, and DTLS is accepted only from the one negotiated remote address
- The only DTLS-SRTP profile is SRTP_AEAD_AES_256_GCM (`NegotiatedSrtpKeys`, `src/media_session.rs`); key direction follows the negotiated DTLS role (test `negotiated_keys_follow_role`)
- ICE connectivity uses STUN with MESSAGE-INTEGRITY-SHA256
- SIP digest authentication (RFC 7616/8760) is supported for REGISTER and INVITE (`registration.rs`, `call_agent.rs`); the strongest offered algorithm is used. SHA-256 / SHA-512-256 digest is a CNSA exception (POA&M-110). MD5 (offered alone) is answered only when the account's policy allows it: `allow_md5_digest` explicit `true`, or unset on a TLS-only account (`SipAccount::effective_allow_md5_digest`, `proto_sip::resolve_allow_md5`); UDP/TCP accounts refuse MD5 by default (POA&M-255 closed; tests `allow_md5_digest_settings_and_effective_policy`, `test_unset_md5_policy_follows_transport`, `test_invite_md5_refused_by_default_over_udp`). A legacy saved `true` loads as unset. Multi-realm 401/407 gets one header per realm (POA&M-256 closed). Residual MD5 use: POA&M-276; no expected-realm allow-list: POA&M-277

### client-core

**Status: media secured by DTLS-SRTP since 2026-11-17 (local runs on macOS arm64; CI on Ubuntu x86_64 on the merged PR head `4dfea0d`); fails closed otherwise**

- Certificate store prefers ECDSA P-384 certificates
- mTLS gate (2026-11-17): an mTLS account is registered, refreshed or sent a REGISTER only while the SIP-TLS config holds a client certificate with a usable key (`ClientApp::ensure_registrable`, `SipTransport::has_client_auth`); otherwise nothing is sent. The key must be PKCS#8 ECDSA P-384 matching a leaf signed with ecdsa-with-SHA384; a chain without a key is refused (`ClientCertResolver::with_cert`, `configure_client_auth`). Only a software key is accepted, and no GUI or FFI path installs one. Smart-card certificates are refused (NIST POA&M-371). Tests: `test_sr46_*` in `src/app.rs` and `src/sip_transport.rs`, `tests/smartcard_fail_closed.rs`
- Settings do not store any passwords or shared secrets
- Media gate: `CallManager::media_security_for` (`src/call_manager.rs`) is the one place a call obtains its media security. A TLS account, or a remote that signals `SAVP`/`SAVPF`, requires DTLS-SRTP keys; without them the call is ended (488 to an inbound offer, BYE after an answer). Since 2026-11-17 the call manager starts the DTLS handshake when the remote SDP has passed its checks and reports the call `Connected`, and starts audio, only when the handshake has produced keys; a peer's `close_notify` or fatal alert mid-call stops the audio and ends the call. Tests: `client-core/tests/media_security_gate.rs`, `client-core/tests/dtls_srtp_call.rs`, `test_media_security_for_by_account_and_build`
- SRTP session keys are copied from the DTLS keying material into `Zeroizing` buffers when audio starts and then moved into the audio pipeline (`src/media_security.rs` `srtp_session_keys`). Key copies that are not wiped are listed under NIST POA&M-330

### client-gui-tauri

**Status: smart-card login not available (NIST POA&M-371)**

- No cryptographic operations performed directly
- Certificate selection UI shows CNSA 2.0 compliance info
- No password entry fields. The PIN dialog is checked by CNG on Windows only; elsewhere it returns "not supported". A verified PIN does not enable SIP mTLS

## Cryptographic Algorithm Restrictions

### Prohibited Algorithms
- ❌ AES-128 (use AES-256 only)
- ❌ SHA-256 for key derivation (use SHA-384+)
- ❌ P-256 curves (use P-384 or P-521)
- ❌ RSA < 3072 bits (use ECDSA or RSA-3072+)
- ❌ MD5 (not CNSA; answered for legacy SIP digest only on explicit opt-in or on TLS accounts with the policy unset, see POA&M-276)
- ❌ Password-based authentication (absent from default builds; `digest-auth` test builds only)

### Required Algorithms
- ✅ AES-256-GCM for symmetric encryption
- ✅ ECDSA with P-384 or P-521 for signatures
- ✅ ECDHE with P-384 or P-521 for key exchange
- ✅ SHA-384 or SHA-512 for hashing
- ✅ TLS 1.3 for transport security

## Smart Card Authentication

Planned, not implemented (NIST POA&M-371). CAC, PIV and SIPR token certificates can be listed (Windows certificate store; macOS Keychain identities, `YubiKey`, opt-in PKCS#11; none on Linux), but no card-backed signer exists for SIP-TLS or DTLS on any platform, so a card certificate cannot authenticate the client. The client fails closed: `ClientApp::set_client_certificate` (chain only) always returns an error, and an mTLS account without a usable software key is not registered. Off Windows PIN verification and signing return `NotSupported`.

Password-based SIP digest authentication exists only in `digest-auth` builds (`DigestAuthCredentials` in `client-types/src/account.rs`); see the client-sip-ua section above for the algorithm rules and exceptions.

## Key Management

- SRTP master keys are derived via DTLS-SRTP (RFC 5764 §4.2 exporter over the TLS 1.2 PRF with SHA-384) since 2026-11-17, one association per call. No key, salt or random value is logged (tests `successful_call_writes_one_outcome_record_and_no_secret_as_client`, `..._as_server`)
- SRTP key types accept only 32-byte keys (AES-256) with 12-byte salts
- SRTP key buffers held by the client are `Zeroizing` (wiped on drop), and the per-call SRTP state wipes its transmit key material on drop. Not wiped: the rcgen `KeyPair` copy of the DTLS identity key and the identity key pair itself for the life of the process (NIST POA&M-330), and copies inside `proto-srtp` contexts and aws-lc. Wiping is asserted by type, not observed in memory
- Smart-card private keys are never read by the client. A software mTLS key is held in memory in a `Zeroizing` buffer with a redacted `Debug` (`TransportConfig.client_private_key`; test `test_transport_config_debug_redacts_private_key`); copies inside rustls / aws-lc and rcgen are not wiped (NIST POA&M-330)

## Audit Trail

The client has no audit sink; AU-9 is not claimed. Security events are structured `tracing` records only, including registration refusals (mTLS account without a usable key, non-TLS transport, unknown registration), refused client certificates, and DTLS handshake outcomes. See the NIST soft-client AU-2 / AU-3 / AU-12 row and POA&M-371.

## Testing

CNSA 2.0 compliance can be verified by:
1. Checking that only TLS 1.3 connections are established with CNSA suites and groups (`test_tls_config_uses_cnsa_provider`, `tls_config_uses_cnsa_provider`; config-level assertion, no handshake test)
2. Verifying SRTP uses AEAD_AES_256_GCM (`wrong_lengths_rejected`, `srtp_loopback_no_plaintext_on_wire`, `srtcp_round_trip_and_no_plaintext_on_wire`), that the DTLS-SRTP handshake negotiates it with a peer (`client-core/tests/dtls_interop_pion.rs` and `client-integration-tests/tests/dtls_sbc_sidecar.rs`; both `#[ignore]`, need locally built Go binaries, run locally only so far), and that a TLS call without keys ends with no audio (`client-core/tests/media_security_gate.rs`)
3. Confirming certificate algorithms are P-384/P-521 ECDSA
4. Testing that a smart-card certificate and an mTLS account without a usable key are refused (`client-core/tests/smartcard_fail_closed.rs`; `test_sr46_*` in `client-core/src/app.rs` and `client-core/src/sip_transport.rs`)
