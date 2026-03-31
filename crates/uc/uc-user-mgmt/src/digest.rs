//! SIP digest authentication helpers (SHA-256 based).

use sha2::{Digest, Sha256};

/// Compute the HA1 component of SIP digest authentication.
///
/// `HA1 = SHA-256(username:realm:password)`
#[must_use]
pub fn compute_ha1(username: &str, realm: &str, password: &str) -> String {
    let input = format!("{username}:{realm}:{password}");
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Verify a SIP digest authentication response (RFC 7616, SHA-256).
///
/// Computes `HA2 = SHA-256(method:uri)` and
/// `expected = SHA-256(ha1:nonce:ha2)`, then compares with the client response.
#[must_use]
pub fn verify_digest_response(
    ha1: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    response: &str,
) -> bool {
    let ha2_input = format!("{method}:{uri}");
    let ha2 = hex::encode(Sha256::digest(ha2_input.as_bytes()));

    let expected_input = format!("{ha1}:{nonce}:{ha2}");
    let expected = hex::encode(Sha256::digest(expected_input.as_bytes()));

    expected == response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ha1() {
        let ha1 = compute_ha1("alice", "example.mil", "secret123");
        // SHA-256 produces a 64-char hex string
        assert_eq!(ha1.len(), 64);
        // Deterministic
        assert_eq!(ha1, compute_ha1("alice", "example.mil", "secret123"));
        // Different inputs produce different outputs
        assert_ne!(ha1, compute_ha1("bob", "example.mil", "secret123"));
    }

    #[test]
    fn test_verify_digest_response() {
        let ha1 = compute_ha1("alice", "example.mil", "secret123");
        let nonce = "abc123nonce";
        let method = "REGISTER";
        let uri = "sip:example.mil";

        // Compute the correct response
        let ha2 = hex::encode(Sha256::digest(format!("{method}:{uri}").as_bytes()));
        let expected = hex::encode(Sha256::digest(
            format!("{ha1}:{nonce}:{ha2}").as_bytes(),
        ));

        assert!(verify_digest_response(&ha1, nonce, method, uri, &expected));
        assert!(!verify_digest_response(&ha1, nonce, method, uri, "wrong"));
    }
}
