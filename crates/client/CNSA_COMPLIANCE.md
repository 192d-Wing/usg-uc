# CNSA 2.0 Compliance for SIP Soft Client

This document describes the CNSA 2.0 compliance status for the USG SIP Soft Client crates.

## CNSA 2.0 Requirements

| Requirement | Implementation Status |
|-------------|----------------------|
| TLS 1.3 only | ✅ Enforced via `TransportPreference::TlsOnly` |
| AES-256-GCM | ✅ SRTP uses AES-256-GCM via proto-srtp |
| P-384/P-521 curves | ✅ Certificate store prefers P-384 |
| SHA-384+ hashing | ✅ Certificate thumbprints use SHA-256+, DTLS uses SHA-384 |
| No password auth | ✅ Only smart card (CAC/PIV) authentication supported |

## Crate-by-Crate Compliance

### client-types

**Status: ✅ Compliant**

- `TransportPreference` enum only allows `TlsOnly` (TLS 1.3)
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
- No digest authentication support - mutual TLS only

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
- ❌ MD5 (forbidden)
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

Password-based SIP digest authentication is explicitly NOT supported.

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
1. Checking that only TLS 1.3 connections are established
2. Verifying SRTP uses AEAD_AES_256_GCM
3. Confirming certificate algorithms are P-384/P-521 ECDSA
4. Testing that password authentication is rejected
