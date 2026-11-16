//! Constant-time comparison of secret-dependent byte strings.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
//!
//! MAC tags, `Finished` verify data and cookies are compared with the
//! aws-lc routine (`CRYPTO_memcmp` behind
//! `aws_lc_rs::constant_time::verify_slices_are_equal`) instead of a
//! hand-written loop, so the comparison time does not depend on where the
//! inputs differ.

/// Returns true if `a` and `b` have the same length and contents.
///
/// The time taken depends on the lengths only, not on the contents. The
/// lengths themselves are not secret.
#[must_use]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::eq;

    #[test]
    fn equal_and_unequal_inputs() {
        assert!(eq(b"", b""));
        assert!(eq(b"verify data!", b"verify data!"));
        assert!(!eq(b"verify data!", b"verify data?"));
        assert!(!eq(b"Verify data!", b"verify data!"));
        assert!(!eq(b"short", b"shorter"));
        assert!(!eq(b"", b"x"));
    }
}
