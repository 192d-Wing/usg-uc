# Changelog

All notable changes to the USG Unified Communications SBC project will be documented in this file.

The format is based on [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial workspace structure with 27 crates organized in 9 layers
- Foundation crates: `sbc-types`, `sbc-crypto`, `sbc-audit`, `sbc-config`
- CNSA 2.0 cryptographic compliance enforcement via `sbc-crypto`
- NIST 800-53 Rev5 audit logging infrastructure via `sbc-audit`
- Project documentation: `CONTRIBUTING.md`, `CHANGELOG.md`
- Compliance documentation: `docs/NIST-800-53-CONTROLS.md`, `docs/CNSA-2-COMPLIANCE.md`

### Security

- Enforced `#![forbid(unsafe_code)]` across all crates (documented exceptions only)
- CNSA 2.0 algorithm restrictions: AES-256 only, SHA-384+ only, P-384+ curves only
- Forbidden algorithms compile-time blocked: SHA-256, P-256, AES-128

[Unreleased]: https://github.com/usg/usg-uc-sbc/compare/v0.1.0...HEAD
