//! Cryptographically secure random number generation.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
//!
//! Uses the system's cryptographically secure random number generator
//! via aws-lc-rs, which uses the OS CSPRNG.

use crate::error::{CryptoError, CryptoResult};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Fills a buffer with cryptographically secure random bytes.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// ## Errors
///
/// Returns an error if the system random number generator fails.
///
/// ## Example
///
/// ```
/// use uc_crypto::random::fill_random;
///
/// let mut key = [0u8; 32];
/// fill_random(&mut key).expect("RNG failure");
/// ```
///
/// # Errors
/// Returns an error if the operation fails.
pub fn fill_random(dest: &mut [u8]) -> CryptoResult<()> {
    let rng = SystemRandom::new();
    rng.fill(dest).map_err(|_| CryptoError::RandomFailed)
}

/// Generates a fixed-size array of random bytes.
///
/// ## Errors
///
/// Returns an error if the system random number generator fails.
///
/// ## Example
///
/// ```
/// use uc_crypto::random::generate_random;
///
/// let key: [u8; 32] = generate_random().expect("RNG failure");
/// ```
///
/// # Errors
/// Returns an error if the operation fails.
pub fn generate_random<const N: usize>() -> CryptoResult<[u8; N]> {
    let mut output = [0u8; N];
    fill_random(&mut output)?;
    Ok(output)
}

/// Generates a random nonce for AES-256-GCM (12 bytes).
///
/// ## Errors
///
/// Returns an error if the system random number generator fails.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn generate_nonce() -> CryptoResult<[u8; 12]> {
    generate_random()
}

/// Generates a random 256-bit key.
///
/// ## Errors
///
/// Returns an error if the system random number generator fails.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn generate_key_256() -> CryptoResult<[u8; 32]> {
    generate_random()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        fill_random(&mut buf1).unwrap();
        fill_random(&mut buf2).unwrap();

        // Should be different (with overwhelming probability)
        assert_ne!(buf1, buf2);

        // Should not be all zeros
        assert_ne!(buf1, [0u8; 32]);
    }

    #[test]
    fn test_generate_random() {
        let key1: [u8; 32] = generate_random().unwrap();
        let key2: [u8; 32] = generate_random().unwrap();

        assert_ne!(key1, key2);
        assert_ne!(key1, [0u8; 32]);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();

        assert_eq!(nonce1.len(), 12);
        assert_ne!(nonce1, nonce2);
    }
}
