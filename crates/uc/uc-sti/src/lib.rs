//! STIR/SHAKEN services for the SBC.
//!
//! - [`cache::StiCertCache`]: SSRF-safe, bounded, single-flight `x5u`
//!   certificate fetch and cache, validating chains to STI-CR anchors.
//! - [`anchors`]: trust-anchor loading and lock-free reload.
//! - [`policy::AttestationPolicy`]: configuration-driven A/B/C decision.
//! - [`signer::FileSigner`]: file-backed ES256 signing key with startup
//!   self-check.
//! - [`aggregate::FailureAggregator`]: audit flood protection.
//!
//! The protocol layer (`proto-stir-shaken`) stays pure; this crate owns the
//! I/O and crypto bindings.
//!
//! ## CNSA 2.0
//!
//! CNSA-EXCEPTION: ATIS-1000074 mandates ES256 (P-256/SHA-256) for SHAKEN.
//! The ES256 code is `uc_crypto::interop::ecdsa_p256`; it is used only for
//! caller-identity signatures, never for confidentiality.
//!
//! ## NIST 800-53 Rev5
//!
//! IA-9, IA-5(2), SC-5, SC-7, SC-12, SC-13, SC-17, SC-28, AU-2, SI-10.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod aggregate;
pub mod anchors;
pub mod cache;
pub mod error;
pub mod fetch;
mod lru;
pub mod policy;
pub mod signer;
pub mod ssrf;
#[cfg(test)]
mod sti_tests;

pub use error::{FetchError, KeyLoadError};

use proto_stir_shaken::{
    Attestation, IdentityHeader, PASSporT, PassportClaims, Signer, StirShakenResult,
    TelephoneNumber,
};

/// Signs a SHAKEN `PASSporT` and returns the Identity header value.
///
/// RFC 8224 §5: `iat`, `orig`, `dest` from the outgoing request; RFC 8588
/// §5: a fresh UUID `origid` per call.
///
/// # Errors
/// Claim or signing errors from `proto-stir-shaken`.
pub fn sign_identity(
    signer: &dyn Signer,
    x5u: &str,
    attest: Attestation,
    orig: TelephoneNumber,
    dest: TelephoneNumber,
    now: u64,
) -> StirShakenResult<String> {
    let claims = PassportClaims {
        attest,
        dest: vec![dest],
        iat: now,
        orig,
        origid: uuid::Uuid::new_v4().to_string(),
    };
    let token = PASSporT::sign(&claims, x5u, signer)?;
    Ok(IdentityHeader::shaken(token, x5u.to_owned(), signer.alg()).to_header_value())
}

/// Lower-case hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Host part of an `x5u` URL for the CDR (no scheme, port, path).
#[must_use]
pub fn x5u_host(x5u: &str) -> Option<String> {
    let rest = x5u.get(8..).filter(|_| {
        x5u.get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
    })?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        host.split(':').next()?
    };
    (!host.is_empty() && host.len() <= 253).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(
            x5u_host("https://Cert.Example.com:443/a/b.pem").as_deref(),
            Some("cert.example.com")
        );
        assert_eq!(
            x5u_host("https://[2001:db8::1]/a").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(x5u_host("http://x/a"), None);
    }
}
