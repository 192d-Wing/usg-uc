//! Row origin marker (`updated_by`).
//!
//! Rows written by this site's own API carry `local:<actor>`, where
//! `<actor>` is the writer's canonical principal (`oidc:<sub>@<iss>`,
//! `admin:<subject>`, `apikey:<id>`, `system:<task>`). Rows written before
//! the principal was recorded carry the bare legacy marker `local`. Every
//! other value (`central`, `template`, an operator `sub`) is central origin.
//!
//! The store adds the `local:` prefix itself, so a caller cannot stamp a
//! central origin by choosing its actor string.
//!
//! ## NIST 800-53 Rev5: AU-3, CM-3, CM-5 (change attribution)

/// Legacy local-origin marker, and the prefix of every local principal.
pub const LOCAL_ORIGIN: &str = "local";
/// Longest `updated_by` value written, in bytes: `local:` plus an actor id
/// capped at the audit record's cap, so the row and the audit record name
/// the same actor.
pub const MAX_UPDATED_BY_BYTES: usize =
    LOCAL_ORIGIN.len() + 1 + sbc_http_util::mgmt_audit::MAX_ACTOR_BYTES;

/// The `updated_by` value for a local write by `actor`: `local:<actor>`,
/// with the actor sanitised and capped exactly as the audit record's
/// `admin` field ([`sbc_http_util::mgmt_audit::actor_field`]).
#[must_use]
pub fn local_updated_by(actor: &str) -> String {
    format!(
        "{LOCAL_ORIGIN}:{}",
        sbc_http_util::mgmt_audit::actor_field(actor)
    )
}

/// SQL predicate: `col` marks a local-origin row (legacy `'local'` or a
/// `'local:<actor>'` principal). `col` must be a trusted column reference,
/// never input.
#[must_use]
pub fn is_local_sql(col: &str) -> String {
    format!("({col} = 'local' OR {col} LIKE 'local:%')")
}

/// SQL predicate: `col` marks a central-origin row (the negation of
/// [`is_local_sql`]; `updated_by` is `NOT NULL`).
#[must_use]
pub fn is_central_sql(col: &str) -> String {
    format!("NOT {}", is_local_sql(col))
}

/// True if an `updated_by` value marks a local-origin row.
#[must_use]
pub fn is_local(updated_by: &str) -> bool {
    updated_by == LOCAL_ORIGIN
        || updated_by
            .strip_prefix(LOCAL_ORIGIN)
            .is_some_and(|r| r.starts_with(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_always_added() {
        assert_eq!(local_updated_by("central"), "local:central");
        assert_eq!(local_updated_by(""), "local:");
        assert_eq!(local_updated_by("a\r\nb"), "local:ab");
        assert!(is_local(&local_updated_by("central")));
    }

    #[test]
    fn capped_on_char_boundary() {
        let v = local_updated_by(&"\u{e9}".repeat(300));
        assert!(v.len() <= MAX_UPDATED_BY_BYTES && v.len() >= MAX_UPDATED_BY_BYTES - 1);
        assert!(v.starts_with("local:\u{e9}"));
    }

    #[test]
    fn local_matching() {
        assert!(is_local("local"));
        assert!(is_local("local:admin:admin"));
        assert!(!is_local("localhost"));
        assert!(!is_local("central"));
        assert!(!is_local("site:x"));
        assert_eq!(
            is_local_sql("t.updated_by"),
            "(t.updated_by = 'local' OR t.updated_by LIKE 'local:%')"
        );
    }
}
