//! PKCE (RFC 7636) verifier/challenge plus CSPRNG `state`/`nonce` tokens.
//!
//! S256 only — the plain method is never emitted. All random material comes
//! from the FIPS `aws-lc-rs` system RNG, and the access/refresh secrets that
//! flow through the rest of the crate are wrapped in [`zeroize::Zeroizing`].

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

/// A PKCE verifier/challenge pair (S256).
pub struct PkcePair {
    /// The high-entropy secret sent only on the token request.
    pub verifier: Zeroizing<String>,
    /// `base64url(SHA-256(verifier))` — sent on the authorization request.
    pub challenge: String,
}

/// Generates a PKCE pair: a 43-char (256-bit) verifier and its S256
/// challenge. Returns `None` only if the system RNG fails.
#[must_use]
pub fn generate_pkce() -> Option<PkcePair> {
    let verifier = random_b64url(32)?; // 32 bytes → 43 base64url chars
    let hash = digest(&SHA256, verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash.as_ref());
    Some(PkcePair {
        verifier: Zeroizing::new(verifier),
        challenge,
    })
}

/// A random URL-safe token (for OAuth `state` / OIDC `nonce`). `bytes` of
/// entropy, base64url-encoded. Returns `None` if the system RNG fails.
#[must_use]
pub fn random_token(bytes: usize) -> Option<String> {
    random_b64url(bytes)
}

fn random_b64url(bytes: usize) -> Option<String> {
    let mut buf = vec![0u8; bytes];
    SystemRandom::new().fill(&mut buf).ok()?;
    Some(URL_SAFE_NO_PAD.encode(&buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_s256_of_verifier() {
        let pair = generate_pkce().unwrap();
        // Verifier within RFC 7636 length bounds (43..=128).
        assert!((43..=128).contains(&pair.verifier.len()));
        // Recompute the challenge independently.
        let expected = URL_SAFE_NO_PAD.encode(digest(&SHA256, pair.verifier.as_bytes()).as_ref());
        assert_eq!(pair.challenge, expected);
        // base64url, no padding.
        assert!(!pair.challenge.contains('='));
        assert!(!pair.challenge.contains('+'));
        assert!(!pair.challenge.contains('/'));
    }

    #[test]
    fn tokens_are_unique_and_url_safe() {
        let a = random_token(16).unwrap();
        let b = random_token(16).unwrap();
        assert_ne!(a, b);
        assert!(!a.contains('=') && !a.contains('+') && !a.contains('/'));
    }
}
