# Contributing Guidelines

This document defines the mandatory rules and standards for contributing to the USG Unified Communications Rust project.

---

## 1. Changelog

Maintain a changelog in accordance with [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/).

- All notable changes must be documented in `CHANGELOG.md`
- Group changes by type: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`
- Keep an `[Unreleased]` section at the top for ongoing work
- Link each version to its git comparison

---

## 2. Versioning

Use [Semantic Versioning 2.0.0](https://semver.org/).

- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible functionality additions
- **PATCH**: Backward-compatible bug fixes

Pre-release versions use format: `X.Y.Z-alpha.N`, `X.Y.Z-beta.N`, `X.Y.Z-rc.N`

---

## 3. Commit Messages

Follow [Conventional Commits v1.0.0](https://www.conventionalcommits.org/).

### Format

```text
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                                           |
| ---------- | ----------------------------------------------------- |
| `feat`     | New feature                                           |
| `fix`      | Bug fix                                               |
| `docs`     | Documentation only                                    |
| `style`    | Formatting, missing semicolons (no code change)       |
| `refactor` | Code change that neither fixes a bug nor adds feature |
| `perf`     | Performance improvement                               |
| `test`     | Adding or correcting tests                            |
| `build`    | Build system or external dependencies                 |
| `ci`       | CI configuration                                      |
| `chore`    | Other changes that don't modify src or test           |
| `security` | Security-related changes                              |

### Examples

```text
feat(oidc): add authorization endpoint

fix(auth): resolve session timeout race condition

docs: update ROADMAP with phase 2 details

security: upgrade aws-lc-rs to patch CVE-2024-XXXX

BREAKING CHANGE: removed deprecated login API
```

---

## 4. Safety-Critical Code Standards

Follow **The Power of 10: Rules for Developing Safety-Critical Code** (NASA/JPL).

### The 10 Rules

1. **Avoid complex flow constructs** - No `goto`, `setjmp`, `longjmp`, or recursion
2. **Fixed upper bound for loops** - All loops must have a determinable maximum iteration count
3. **No dynamic memory after initialization** - Avoid heap allocation after startup where possible
4. **Short functions** - Functions should not exceed 60 lines of code
5. **Low assertion density** - Minimum 2 assertions per function on average
6. **Declare variables at smallest scope** - Minimize variable lifetime and visibility
7. **Check return values** - All non-void function return values must be checked or explicitly ignored with `let _ =`
8. **Limit preprocessor use** - Minimize macro complexity; prefer `const` and `inline fn`
9. **Restrict pointer use** - Limit pointer dereferencing to one level; avoid function pointers where possible
10. **Compile with all warnings enabled** - Use strictest compiler settings; zero warnings policy

### Rust-Specific Adaptations

- Use `#![deny(warnings)]` in `lib.rs` and `main.rs`
- Use `#![forbid(unsafe_code)]` unless absolutely necessary (document exceptions)
- Prefer `Result<T, E>` over panics
- Use `debug_assert!` and `assert!` liberally
- Avoid `unwrap()` and `expect()` in production code paths

---

## 5. Pre-Commit Checks

Run the following commands before every commit:

### Cargo Clippy

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

All Clippy warnings must be resolved. No `#[allow(clippy::*)]` without documented justification.

### Cargo Fmt

```bash
cargo fmt --all --check
```

Code must be formatted. Run `cargo fmt --all` to auto-fix.

### Cargo Audit

```bash
cargo audit
```

No known vulnerabilities allowed in dependencies. If a vulnerability exists:

1. Update the dependency immediately
2. If no patch exists, document the risk and mitigation in `SECURITY.md`

### Pre-Commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

echo "Running cargo fmt..."
cargo fmt --all --check

echo "Running cargo clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Running cargo audit..."
cargo audit

echo "All checks passed!"
```

---

## 6. CNSA 2.0 Compliance

This project **MUST** be compliant with NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0).

### Mandatory Requirements

1. **No curves less than 384 bits** - P-256 and other smaller curves are **FORBIDDEN**
2. **No SHA-256** - Minimum hash algorithm is **SHA-384**
3. **Minimum RSA key size: 3072 bits** (4096 recommended)

### Approved Algorithms (CNSA 2.0)

| Function | Approved Algorithm | Minimum Size |
| -------- | ------------------ | ------------ |
| Encryption | AES | 256-bit |
| Hash | SHA-384, SHA-512 | 384-bit |
| Digital Signature | ECDSA (P-384), RSA | P-384 / 3072-bit |
| Key Exchange | ECDH (P-384), DH | P-384 / 3072-bit |
| Key Wrapping | AES-256 Key Wrap | 256-bit |

### Forbidden Algorithms

The following are **explicitly forbidden**:

- SHA-256 (use SHA-384 or SHA-512)
- P-256 / secp256r1 (use P-384 or P-521)
- RSA < 3072 bits
- AES-128 (use AES-256)
- 3DES
- MD5
- SHA-1

### JWT/JWS Algorithm Restrictions

| Allowed | Forbidden |
| ------- | --------- |
| ES384, ES512 | ES256 |
| RS384, RS512 | RS256 |
| PS384, PS512 | PS256 |
| HS384, HS512 | HS256 |

### Code Enforcement

```rust
/// CNSA 2.0: Only P-384 and P-521 curves are permitted.
/// P-256 is explicitly forbidden per CNSA 2.0 requirements.
pub enum AllowedCurve {
    P384,
    P521,
}

/// CNSA 2.0: Minimum hash is SHA-384.
/// SHA-256 is explicitly forbidden per CNSA 2.0 requirements.
pub enum AllowedHash {
    Sha384,
    Sha512,
}
```

### References

- [NSA CNSA 2.0 Fact Sheet](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [CNSSP 15 - National Information Assurance Policy](https://www.cnss.gov/CNSS/issuances/Policies.cfm)

---

## 7. NIST SP 800-53 Rev 5 Compliance

All security controls from NIST SP 800-53 Revision 5 must be mapped in the Rust code.

### Implementation Requirements

1. **Document control mappings** in code comments:

   ```rust
   /// NIST 800-53 Rev5: IA-5 (Authenticator Management)
   /// Implements password complexity requirements.
   pub fn validate_password_strength(password: &str) -> Result<(), PasswordError> {
       // ...
   }
   ```

2. **Maintain a control matrix** in `docs/NIST-800-53-CONTROLS.md`

3. **Priority control families for identity management**:
   - **AC** - Access Control
   - **AU** - Audit and Accountability
   - **IA** - Identification and Authentication
   - **SC** - System and Communications Protection
   - **SI** - System and Information Integrity

4. **Automated control verification** where possible via tests

---

## 8. Dependency Management

### Latest Versions Required

All dependencies must be the latest stable version.

```bash
# Check for outdated dependencies
cargo outdated

# Update all dependencies
cargo update
```

### Dependency Review Checklist

Before adding a new dependency:

- [ ] Is it actively maintained? (commits in last 6 months)
- [ ] Does it have a security policy?
- [ ] Is it audited or widely used?
- [ ] Does it pass `cargo audit`?
- [ ] Is the license compatible (MIT, Apache-2.0, BSD)?
- [ ] Is it necessary, or can we implement it ourselves?

---

## 9. Rust Toolchain Requirements

### Minimum Supported Rust Version (MSRV)

```toml
# Cargo.toml
[package]
rust-version = "1.92"
```

**MSRV: 1.92** - All code must compile on Rust 1.92 and above.

### Rust Edition

```toml
# Cargo.toml
[package]
edition = "2024"
```

**Edition: 2024** - Use the Rust 2024 edition for all crates.

### Toolchain File

Create `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.92"
components = ["rustfmt", "clippy"]
```

---

## 10. CI/CD Requirements

All pull requests must pass:

1. `cargo build --all-targets`
2. `cargo test --all-targets`
3. `cargo clippy --all-targets --all-features -- -D warnings`
4. `cargo fmt --all --check`
5. `cargo audit`
6. `cargo doc --no-deps`

### Coverage Requirement

Minimum 80% code coverage for merged code.

---

## 11. Documentation Requirements

- All public APIs must have doc comments
- All modules must have module-level documentation
- Examples must compile (`cargo test --doc`)
- Security-relevant code must reference NIST controls

---

## 12. IPv6 First Approach

- All code MUST support IPv6
- All code MUST be enabled for IPv6-Only by default

---

## Quick Reference

```bash
# Format code
cargo fmt --all

# Lint code
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit

# Check for outdated deps
cargo outdated

# Run all tests
cargo test --all-targets

# Build docs
cargo doc --no-deps --open
```
