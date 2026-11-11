# CNSA 2.0 Compliance for SIP Soft Client

This document describes the CNSA 2.0 compliance status for the USG SIP Soft Client crates.

## CNSA 2.0 Requirements

| Requirement | Implementation Status |
|-------------|----------------------|
| TLS 1.3 only | Partial. SIP-TLS pins TLS 1.3 (`client-core/src/sip_transport.rs` `create_tls_config`). Default-feature builds compile no UDP SIP socket, receive loop or UDP send (`#[cfg(feature = "insecure-transports")]`; tests `client-core/tests/tls_only_surface.rs`, `test_tls_only_build_never_answers_over_udp`, not run by CI, POA&M-322). Not enforced by the type: `TransportPreference::{Udp,Tcp}` exist in all builds and a non-TLS account is refused by one runtime check; `insecure-transports` / `digest-auth` builds bind a UDP SIP listener for every account (POA&M-318) |
| CNSA TLS suites/groups | ✅ SIP-TLS (`client-core/src/sip_transport.rs` `create_tls_config`) and provisioning HTTPS (`client-provisioning/src/http.rs` `build_tls_config`) use `uc_transport::tls::cnsa_provider()`: `TLS_AES_256_GCM_SHA384`, ML-KEM-1024 / P-384; no AES-128, no X25519. Tests `test_tls_config_uses_cnsa_provider`, `tls_config_uses_cnsa_provider`. Exception: debug-build-only provisioning `CaTrust::Insecure` uses reqwest's default provider. Open: POA&M-173 (verifier modes not on the shared builders) |
| AES-256-GCM | ✅ SRTP uses AES-256-GCM via proto-srtp |
| P-384/P-521 curves | ✅ Certificate store prefers P-384 |
| SHA-384+ hashing | ✅ Certificate thumbprints use SHA-256+, DTLS uses SHA-384 |
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

**Status: ✅ Compliant**

- Audio layer does not handle cryptographic operations directly
- SRTP encryption/decryption delegated to proto-srtp (CNSA 2.0 compliant)

### client-sip-ua

**Status: ✅ Compliant**

- Uses proto-dtls for DTLS handshakes (TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
- Uses proto-srtp with SRTP_AEAD_AES_256_GCM profile only
- ICE connectivity uses STUN with MESSAGE-INTEGRITY-SHA256
- SIP digest authentication (RFC 7616/8760) is supported for REGISTER and INVITE (`registration.rs`, `call_agent.rs`); the strongest offered algorithm is used. SHA-256 / SHA-512-256 digest is a CNSA exception (POA&M-110). MD5 (offered alone) is answered only when the account's policy allows it: `allow_md5_digest` explicit `true`, or unset on a TLS-only account (`SipAccount::effective_allow_md5_digest`, `proto_sip::resolve_allow_md5`); UDP/TCP accounts refuse MD5 by default (POA&M-255 closed; tests `allow_md5_digest_settings_and_effective_policy`, `test_unset_md5_policy_follows_transport`, `test_invite_md5_refused_by_default_over_udp`). A legacy saved `true` loads as unset. Multi-realm 401/407 gets one header per realm (POA&M-256 closed). Residual MD5 use: POA&M-276; no expected-realm allow-list: POA&M-277

### client-core

**Status: ✅ Compliant**

- Certificate store prefers ECDSA P-384 certificates
- Settings do not store any passwords or shared secrets
- All session keys use memory zeroization on drop

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

- SRTP master keys derived via DTLS-SRTP (RFC 5764)
- Keys are 32 bytes (AES-256) with 12-byte salts
- All key material zeroed from memory on session termination
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
2. Verifying SRTP uses AEAD_AES_256_GCM
3. Confirming certificate algorithms are P-384/P-521 ECDSA
4. Testing that password authentication is rejected
