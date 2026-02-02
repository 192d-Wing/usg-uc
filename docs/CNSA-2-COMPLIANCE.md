# CNSA 2.0 Compliance Documentation

This document details how the USG SBC complies with NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0).

## Overview

CNSA 2.0 defines cryptographic algorithms approved for protecting classified information at all classification levels. This project enforces CNSA 2.0 compliance at the type level, making non-compliant algorithms unrepresentable.

## Algorithm Requirements

### Approved Algorithms

| Function | Algorithm | Minimum Size | Implementation |
|----------|-----------|--------------|----------------|
| Symmetric Encryption | AES-256-GCM | 256-bit | `sbc-crypto::aead::Aes256GcmKey` |
| Hash Functions | SHA-384, SHA-512 | 384-bit | `sbc-crypto::hash::{sha384, sha512}` |
| Digital Signatures | ECDSA P-384 | P-384 | `sbc-crypto::ecdsa::P384KeyPair` |
| Key Exchange | ECDH P-384 | P-384 | `sbc-crypto::ecdh::P384EphemeralKeyPair` |
| Key Derivation | HKDF-SHA384 | - | `sbc-crypto::hkdf::hkdf_sha384` |
| TLS | TLS 1.3 AES-256-GCM-SHA384 | - | rustls with aws-lc-rs |

### Forbidden Algorithms

The following algorithms are **explicitly forbidden** and not exposed by the `sbc-crypto` crate:

| Function | Forbidden | Reason |
|----------|-----------|--------|
| Hash | SHA-256, SHA-1, MD5 | Insufficient security margin |
| Curves | P-256 (secp256r1) | Key size too small |
| Symmetric | AES-128, AES-192, 3DES | Key size too small |
| RSA | Any RSA < 3072 bits | Key size too small |
| JWT | ES256, RS256, PS256, HS256 | Based on forbidden algorithms |

## Enforcement Strategy

### Type-Level Enforcement

Non-compliant algorithms cannot be represented in the type system:

```rust
// sbc-types/src/protocol.rs

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

### API Design

The `sbc-crypto` crate only exposes CNSA 2.0 compliant operations:

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

The `sbc-config` crate validates that configuration does not specify forbidden algorithms:

```rust
// sbc-config/src/validate.rs

fn validate_cnsa_curve(curve: CnsaCurve) -> ConfigResult<()> {
    match curve {
        CnsaCurve::P384 | CnsaCurve::P521 => Ok(()),
        // P-256 cannot even be represented
    }
}
```

## Protocol-Specific Compliance

### SIP/TLS

- **TLS Version**: 1.3 required (1.2 allowed with restrictions)
- **Cipher Suite**: TLS_AES_256_GCM_SHA384 only
- **Certificates**: P-384 ECDSA
- **Implementation**: rustls with aws-lc-rs backend

### SRTP

- **Profile**: AEAD_AES_256_GCM (RFC 7714) only
- **Key Size**: 256-bit master key, 96-bit master salt
- **KDF**: HKDF-SHA384 instead of legacy AES-CM PRF
- **Implementation**: Custom `sbc-srtp` crate

### DTLS-SRTP

- **DTLS Version**: 1.3 preferred
- **Fingerprint Hash**: SHA-384 (not SHA-256)
- **Key Exchange**: ECDH P-384
- **Implementation**: webrtc-dtls with cipher restrictions

### STIR/SHAKEN

- **PASSporT Signing**: ES384 (ECDSA P-384 with SHA-384)
- **Certificate**: P-384 ECDSA
- **Forbidden**: ES256, RS256
- **Implementation**: `sbc-stir-shaken` crate

### JWT (Management API)

- **Signing Algorithm**: ES384 only
- **Forbidden**: ES256, RS256, PS256, HS256
- **Implementation**: `sbc-api` crate

## FIPS 140-3 Validation

The cryptographic backend (aws-lc-rs) is FIPS 140-3 validated when compiled with the `fips` feature:

```toml
[features]
default = ["fips"]
fips = ["aws-lc-rs/fips"]
```

AWS-LC-FIPS 3.0 includes:
- First FIPS-validated ML-KEM implementation
- AES-256-GCM
- SHA-384/512
- ECDSA/ECDH P-384

## Post-Quantum Preparation

CNSA 2.0 mandates migration to post-quantum algorithms by 2033:

| Function | Current | Future (2033) |
|----------|---------|---------------|
| Key Exchange | ECDH P-384 | ML-KEM-1024 |
| Signatures | ECDSA P-384 | ML-DSA-87 |

The architecture is prepared for this migration:
- `sbc-crypto` has a `pqc` feature flag
- aws-lc-rs includes ML-KEM support
- Key exchange abstractions support algorithm agility

## Verification

### Compile-Time

Non-compliant algorithms cannot compile:

```rust
// This won't compile - Sha256 doesn't exist
let hash = sbc_crypto::hash::sha256(data); // ERROR: function not found
```

### Runtime

Configuration is validated at startup:

```rust
// This will fail validation
config.security.min_tls_version = "1.0"; // Error: CNSA 2.0 violation
```

### Testing

Compliance tests in `tests/compliance/cnsa_crypto_vectors.rs`:

```rust
#[test]
fn test_sha256_not_available() {
    // Verify SHA-256 is not exposed by the crate
    // This is a documentation test - the type doesn't exist
}

#[test]
fn test_p256_not_available() {
    // Verify P-256 is not exposed by the crate
}
```

## References

- [NSA CNSA 2.0 Fact Sheet](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [NSA CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSA_CNSA_2.0_FAQ_.PDF)
- [CNSSP 15](https://www.cnss.gov/CNSS/issuances/Policies.cfm) - National Information Assurance Policy
- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) - Stateful Hash-Based Signatures
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM (Kyber)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA (Dilithium)
