# NIST 800-53 Rev5 Control Implementation Matrix

This document maps NIST 800-53 Rev5 security controls to their implementations in the USG SBC codebase.

## Control Families

### AC - Access Control

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| AC-3 | Access Enforcement | Planned | `sbc-acl` crate |
| AC-6 | Least Privilege | Planned | `sbc-acl` crate |

### AU - Audit and Accountability

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| AU-2 | Event Logging | **Implemented** | `sbc-audit::event` - Defines all auditable events |
| AU-3 | Content of Audit Records | **Implemented** | `sbc-audit::record` - Structured audit records with required fields |
| AU-4 | Audit Log Storage Capacity | **Implemented** | `sbc-audit::sink` - Configurable output sinks |
| AU-8 | Time Stamps | **Implemented** | `sbc-audit::record` - UTC timestamps via chrono |
| AU-9 | Protection of Audit Information | **Implemented** | `sbc-audit::record` - SHA-384 hash chain for integrity |
| AU-10 | Non-repudiation | Planned | Cryptographic signing of audit records |

### CM - Configuration Management

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| CM-2 | Baseline Configuration | **Implemented** | `sbc-config::schema` - Typed configuration schema |
| CM-6 | Configuration Settings | **Implemented** | `sbc-config::validate` - Configuration validation |

### IA - Identification and Authentication

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| IA-2 | Identification and Authentication | Planned | `sbc-registrar` crate |
| IA-5 | Authenticator Management | Planned | `sbc-registrar` crate |
| IA-9 | Service Identification | Planned | `sbc-stir-shaken` crate |

### SC - System and Communications Protection

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SC-5 | Denial of Service Protection | Planned | `sbc-dos-protection` crate |
| SC-7 | Boundary Protection | Planned | `sbc-b2bua` topology hiding |
| SC-8 | Transmission Confidentiality | **Implemented** | `sbc-crypto::aead` - AES-256-GCM |
| SC-12 | Cryptographic Key Establishment | **Implemented** | `sbc-crypto::ecdh`, `sbc-crypto::hkdf` |
| SC-13 | Cryptographic Protection | **Implemented** | `sbc-crypto` - CNSA 2.0 algorithms only |
| SC-23 | Session Authenticity | Planned | `sbc-transport` TLS, `sbc-stir-shaken` |

### SI - System and Information Integrity

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SI-3 | Malicious Code Protection | Planned | Input validation |
| SI-4 | System Monitoring | Planned | `sbc-metrics` crate |
| SI-11 | Error Handling | **Implemented** | `sbc-types::error` - Structured errors without info leakage |

### SA - System and Services Acquisition

| Control | Title | Status | Implementation |
|---------|-------|--------|----------------|
| SA-11 | Developer Testing | In Progress | Unit tests with assertions |

## Implementation Notes

### Documenting Controls in Code

All security-relevant code includes NIST control references in doc comments:

```rust
/// NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// Computes SHA-384 hash of the input data.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    // ...
}
```

### Verification

Control implementations are verified through:

1. **Unit Tests**: Each module has tests validating correct behavior
2. **Integration Tests**: Cross-crate tests in `tests/compliance/`
3. **Audit Logging**: All security events are logged per AU-2

## References

- [NIST SP 800-53 Rev5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-53B](https://csrc.nist.gov/publications/detail/sp/800-53b/final) - Control Baselines
