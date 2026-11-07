//! Validation rules for route-pattern documents (`/route-patterns`).
//!
//! Kept apart from `sbc.rs` so the handlers carry a single call each.
//!
//! ## NIST 800-53 Rev5: SI-10 (Information Input Validation), CM-6

/// Accepted `pattern_type` values. Must match
/// `uc_routing::DialPattern::from_kind` (case-sensitive). `regex` is not
/// accepted: an invalid regex fails open in the router.
pub const VALID_PATTERN_TYPES: &[&str] = &["exact", "prefix", "wildcard", "any"];

/// Checks `pattern_type`: absent or `null` (the daemon treats it as
/// `prefix`) or one of [`VALID_PATTERN_TYPES`]. Anything else is an error
/// message for a 400, so a mistyped kind (e.g. a mistyped *block*) is
/// refused instead of silently becoming a prefix route.
pub fn validate_pattern_type(body: &serde_json::Value) -> Result<(), String> {
    match body.get("pattern_type") {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(s)) if VALID_PATTERN_TYPES.contains(&s.as_str()) => Ok(()),
        Some(serde_json::Value::String(s)) => Err(format!(
            "unknown pattern_type {s:?}; expected exact, prefix, wildcard or any"
        )),
        Some(_) => Err("pattern_type must be a string".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_absent_null_and_known_kinds() {
        assert!(validate_pattern_type(&json!({})).is_ok());
        assert!(validate_pattern_type(&json!({"pattern_type": null})).is_ok());
        for k in VALID_PATTERN_TYPES {
            assert!(
                validate_pattern_type(&json!({"pattern_type": k})).is_ok(),
                "{k}"
            );
        }
    }

    #[test]
    fn rejects_unknown_wrong_case_and_non_string() {
        for bad in [json!("regex"), json!("Prefix"), json!(5), json!("")] {
            assert!(
                validate_pattern_type(&json!({"pattern_type": bad})).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            validate_pattern_type(&json!({"pattern_type": "regex"})),
            Err(
                "unknown pattern_type \"regex\"; expected exact, prefix, wildcard or any"
                    .to_string()
            )
        );
    }

    #[test]
    fn qa_rejects_padded_array_bool_and_object_kinds() {
        for bad in [
            json!(" prefix"),
            json!("prefix "),
            json!("ANY"),
            json!("bogus"),
            json!(true),
            json!(["prefix"]),
            json!({"k": "prefix"}),
        ] {
            assert!(
                validate_pattern_type(&json!({"pattern_type": bad})).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            validate_pattern_type(&json!({"pattern_type": 5})),
            Err("pattern_type must be a string".to_string())
        );
    }
}
