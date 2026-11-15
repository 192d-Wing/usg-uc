# CNSA 2.0 Compliance for SIP Soft Client

This document describes the CNSA 2.0 compliance status for the USG SIP Soft Client crates.

## CNSA 2.0 Requirements

| Requirement | Implementation Status |
|-------------|----------------------|
| TLS 1.3 only | Partial. SIP-TLS pins TLS 1.3 (`client-core/src/sip_transport.rs` `create_tls_config`). Default-feature builds compile no UDP SIP socket, receive loop or UDP send (`#[cfg(feature = "insecure-transports")]`; tests `client-core/tests/tls_only_surface.rs`, `test_tls_only_build_never_answers_over_udp`, not run by CI, POA&M-322). Not enforced by the type: `TransportPreference::{Udp,Tcp}` exist in all builds and a non-TLS account is refused by one runtime check; `insecure-transports` / `digest-auth` builds bind a UDP SIP listener for every account (POA&M-318) |
| CNSA TLS suites/groups | ✅ SIP-TLS (`client-core/src/sip_transport.rs` `create_tls_config`) and provisioning HTTPS (`client-provisioning/src/http.rs` `build_tls_config`) use `uc_transport::tls::cnsa_provider()`: `TLS_AES_256_GCM_SHA384`, ML-KEM-1024 / P-384; no AES-128, no X25519. Tests `test_tls_config_uses_cnsa_provider`, `tls_config_uses_cnsa_provider`. Exception: debug-build-only provisioning `CaTrust::Insecure` uses reqwest's default provider. Open: POA&M-173 (verifier modes not on the shared builders) |
| AES-256-GCM | Partial. No call media is encrypted yet: `proto-dtls` runs no network DTLS handshake, so the client never obtains SRTP keys (Planned, NIST POA&M-324). Default-feature (TLS) builds fail closed instead: they have no plaintext RTP path, and every TLS call is ended by the client after connect with no audio. Implemented for when keys exist: SRTP and SRTCP use `AEAD_AES_256_GCM` only via `proto-srtp`; `SrtpSessionKeys::validate` (`client-audio/src/media_security.rs`) rejects any other profile or key/salt length (tests `wrong_lengths_rejected`, `srtp_loopback_no_plaintext_on_wire`, `srtcp_round_trip_and_no_plaintext_on_wire`, with test-made keys) |
| P-384/P-521 curves | ✅ Certificate store prefers P-384. The DTLS identity is an ephemeral self-signed ECDSA P-384 / SHA-384 certificate, or a user P-384 certificate whose public key matches its key and which is signed with ecdsa-with-SHA384 (`client-sip-ua/src/dtls_identity.rs`; tests `generate_p384_identity_with_single_prefix_fingerprint`, `from_user_der_requires_matching_key_and_sha384_signature`). It is not used in a handshake yet (NIST POA&M-324) |
| SHA-384+ hashing | Partial. Certificate thumbprints use SHA-256+. The DTLS `a=fingerprint` we advertise is SHA-384, and only sha-384 / sha-512 remote fingerprints are accepted (sha-256 and weaker are refused, a deliberate deviation from RFC 8122 interoperability; `proto-dtls/src/fingerprint.rs` `from_sdp_strict`, tests `strict_parse_rejects_bad_input`, `sha256_only_rejected_mixed_keeps_cnsa`). No peer certificate is checked against a fingerprint until the DTLS handshake exists (Planned, NIST POA&M-324) |
| No password auth | ✅ Only smart card (CAC/PIV) authentication supported |

## Crate-by-Crate Compliance

### client-types

**Status: ✅ Compliant**

- `TransportPreference` defaults to `TlsOnly` but also has `Udp` and `Tcp` variants (marked not CNSA compliant) in all builds; UDP SIP code exists only with the `insecure-transports` feature
- `SipAccount` has no password fields - only certificate-based auth
- `CertificateConfig` supports smart card certificate selection
- `SrtpKeyMaterial` in sensitive.rs requires 32-byte keys (AES-256)
- Memory zeroization for all sensitive data via `zeroize` crate

### client-audio

**Status: Partial (fail closed; no keyed media until NIST POA&M-324)**

- A pipeline is built only from a `MediaSecurity` value (`src/media_security.rs`). In a default build the only variant is `Srtp`; `Plaintext` exists only with the `insecure-rtp` feature, which `client-core`'s `insecure-transports` enables (`compile_fail` doctest, meaningful only with default features; `ci.yml` step "Doctest client-audio (default features)")
- SRTP and SRTCP encryption/decryption are delegated to proto-srtp, `AEAD_AES_256_GCM` only; `SrtpSessionKeys::validate` requires a 32-byte key and 12-byte salt per direction (test `wrong_lengths_rejected`)
- On a keyed session RTP leaves as SRTP on every transmit path and RTCP as SRTCP; received RTCP is authenticated before parsing (tests `qa_srtp_every_tx_path_encrypted_role_swapped`, `srtcp_tampered_and_plaintext_dropped`). These tests use test-made keys: no key from a DTLS handshake exists yet
- Keys are held in `Zeroizing` buffers behind private fields, with redacted `Debug` and no `Clone` (test `debug_is_redacted`; zeroization on drop is not observed by a test)
- Open: SRTCP receive allocates per datagram (NIST POA&M-328); DTLS and STUN arriving on the media socket after setup are dropped and counted (NIST POA&M-325)

### client-sip-ua

**Status: Partial (DTLS-SRTP handshake Planned, NIST POA&M-324)**

- DTLS handshake: Planned. `proto-dtls` `DtlsSession::new` returns `HandshakeFailed`, so `MediaSession::establish` always fails and the call fails closed with no audio (test `establish_fails_closed_and_never_rebinds`). The only suite `proto-dtls` defines is TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384; it is not negotiated with any peer yet
- DTLS identity (`src/dtls_identity.rs`): ephemeral self-signed P-384 / SHA-384, or a user P-384 certificate bound to its key and signed with ecdsa-with-SHA384. The key is held in `Zeroizing`; it is copied per call into `proto_dtls::DtlsConfig.private_key` (plain `Vec`, `Debug`/`Clone`) and the rcgen `KeyPair` copy is not zeroized (NIST POA&M-330)
- Remote `a=fingerprint`: sha-384 / sha-512 only, parsed strictly (`src/sdp_dtls.rs`, `proto-dtls` `from_sdp_strict`). Not verified against a peer certificate until NIST POA&M-324
- The only DTLS-SRTP profile is SRTP_AEAD_AES_256_GCM (`NegotiatedSrtpKeys`, `src/media_session.rs`); no keys are negotiated yet
- ICE connectivity uses STUN with MESSAGE-INTEGRITY-SHA256
- SIP digest authentication (RFC 7616/8760) is supported for REGISTER and INVITE (`registration.rs`, `call_agent.rs`); the strongest offered algorithm is used. SHA-256 / SHA-512-256 digest is a CNSA exception (POA&M-110). MD5 (offered alone) is answered only when the account's policy allows it: `allow_md5_digest` explicit `true`, or unset on a TLS-only account (`SipAccount::effective_allow_md5_digest`, `proto_sip::resolve_allow_md5`); UDP/TCP accounts refuse MD5 by default (POA&M-255 closed; tests `allow_md5_digest_settings_and_effective_policy`, `test_unset_md5_policy_follows_transport`, `test_invite_md5_refused_by_default_over_udp`). A legacy saved `true` loads as unset. Multi-realm 401/407 gets one header per realm (POA&M-256 closed). Residual MD5 use: POA&M-276; no expected-realm allow-list: POA&M-277

### client-core

**Status: Partial (media fails closed; see NIST POA&M-324)**

- Certificate store prefers ECDSA P-384 certificates
- Settings do not store any passwords or shared secrets
- Media gate: `CallManager::media_security_for` (`src/call_manager.rs`) is the one place a call obtains its media security. A TLS account, or a remote that signals `SAVP`/`SAVPF`, requires DTLS-SRTP keys; without them the call is ended (488 to an inbound offer, BYE after an answer). Because no DTLS handshake exists, every TLS call currently ends after connect with no audio. Tests: `client-core/tests/media_security_gate.rs`, `test_media_security_for_by_account_and_build`
- SRTP session keys are copied from the DTLS keying material into `Zeroizing` buffers when audio starts and then moved into the audio pipeline (`src/media_security.rs` `srtp_session_keys`). The DTLS identity key is copied per call into a non-zeroized `proto-dtls` config (NIST POA&M-330)

### client-gui-windows

**Status: ✅ Compliant**

- No cryptographic operations performed directly
- Certificate selection UI shows CNSA 2.0 compliance info
- No password entry fields - smart card PIN entry via secure card reader

## Cryptographic Algorithm Restrictions

### Prohibited Algorithms
- ❌ AES-128 (use AES-256 only)
- ❌ SHA-256 for key derivation (use SHA-384+)
- ❌ P-256 curves (use P-384 or P-521)
- ❌ RSA < 3072 bits (use ECDSA or RSA-3072+)
- ❌ MD5 (not CNSA; answered for legacy SIP digest only on explicit opt-in or on TLS accounts with the policy unset, see POA&M-276)
- ❌ Password-based authentication (use PKI only)

### Required Algorithms
- ✅ AES-256-GCM for symmetric encryption
- ✅ ECDSA with P-384 or P-521 for signatures
- ✅ ECDHE with P-384 or P-521 for key exchange
- ✅ SHA-384 or SHA-512 for hashing
- ✅ TLS 1.3 for transport security

## Smart Card Authentication

The soft client ONLY supports smart card-based authentication:

1. **CAC (Common Access Card)** - DoD ID certificates
2. **PIV (Personal Identity Verification)** - Federal civilian certificates
3. **SIPR Token** - Classified network tokens

Password-based SIP digest authentication is also supported (`DigestAuthCredentials` in `client-types/src/account.rs`); see the client-sip-ua section above for the algorithm rules and exceptions.

## Key Management

- SRTP master keys derived via DTLS-SRTP (RFC 5764): Planned (NIST POA&M-324). No DTLS handshake runs, so no SRTP keys are derived; TLS calls fail closed with no audio
- SRTP key types accept only 32-byte keys (AES-256) with 12-byte salts
- SRTP key buffers and the DTLS identity key held by the client are `Zeroizing` (wiped on drop). Not wiped: the per-call copy of the identity key in `proto_dtls::DtlsConfig.private_key` and the rcgen `KeyPair` copy (NIST POA&M-330), and copies inside `proto-srtp` contexts and aws-lc
- Private keys never leave the smart card

## Audit Trail

All security-relevant events are logged:
- Certificate selection
- Registration attempts
- Call establishment/termination
- Authentication failures
- Configuration changes

## Testing

CNSA 2.0 compliance can be verified by:
1. Checking that only TLS 1.3 connections are established with CNSA suites and groups (`test_tls_config_uses_cnsa_provider`, `tls_config_uses_cnsa_provider`; config-level assertion, no handshake test)
2. Verifying SRTP uses AEAD_AES_256_GCM (key-type and loopback tests only: `wrong_lengths_rejected`, `srtp_loopback_no_plaintext_on_wire`, `srtcp_round_trip_and_no_plaintext_on_wire`; no test negotiates SRTP with a peer, NIST POA&M-324), and that a TLS call without keys ends with no audio (`client-core/tests/media_security_gate.rs`)
3. Confirming certificate algorithms are P-384/P-521 ECDSA
4. Testing that password authentication is rejected
