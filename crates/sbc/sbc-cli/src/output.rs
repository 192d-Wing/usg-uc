//! Output formatting for CLI.
//!
//! In `--json` mode each command emits exactly one parseable JSON
//! document on stdout (via [`print_json`]) and nothing else; all
//! human-oriented formatting is reserved for the text and table modes.

use serde_json::Value;

/// Prints a value as a single pretty-printed JSON document on stdout.
pub fn print_json(value: &Value) {
    // `to_string_pretty` only fails for non-string map keys or failing
    // `Serialize` impls; `Value` has neither, so fall back to compact form.
    let rendered =
        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    println!("{rendered}");
}

/// Renders ordered key/value pairs as aligned plain-text lines.
pub fn format_pairs_text(pairs: &[(String, String)]) -> String {
    let width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    pairs
        .iter()
        .map(|(k, v)| format!("{k:<width$}  {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders ordered key/value pairs as an ASCII table.
pub fn format_pairs_table(pairs: &[(String, String)]) -> String {
    use std::fmt::Write;
    let mut output = String::new();
    let _ = writeln!(output, "+{:-<22}+{:-<42}+", "", "");
    let _ = writeln!(output, "| {:^20} | {:^40} |", "Key", "Value");
    let _ = writeln!(output, "+{:-<22}+{:-<42}+", "", "");
    for (k, v) in pairs {
        let _ = writeln!(output, "| {k:<20} | {v:<40} |");
    }
    let _ = write!(output, "+{:-<22}+{:-<42}+", "", "");
    output
}

/// Flattens a JSON object into ordered key/value display pairs.
///
/// Nested arrays and objects are rendered as compact JSON.
pub fn object_to_pairs(value: &Value) -> Vec<(String, String)> {
    value.as_object().map_or_else(Vec::new, |map| {
        map.iter()
            .map(|(k, v)| (k.clone(), scalar_to_string(v)))
            .collect()
    })
}

/// Renders a scalar JSON value without surrounding quotes.
pub fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_print_json_roundtrip() {
        // Values with quotes/newlines must stay valid JSON via serde_json.
        let value = json!({"message": "line1\nline2 \"quoted\""});
        let rendered = serde_json::to_string_pretty(&value).unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn test_format_pairs_text() {
        let pairs = vec![
            ("status".to_string(), "running".to_string()),
            ("calls_active".to_string(), "3".to_string()),
        ];
        let output = format_pairs_text(&pairs);
        assert!(output.contains("status"));
        assert!(output.contains("running"));
        assert!(output.contains("calls_active"));
    }

    #[test]
    fn test_format_pairs_table() {
        let pairs = vec![("key1".to_string(), "value1".to_string())];
        let output = format_pairs_table(&pairs);
        assert!(output.contains("| key1"));
        assert!(output.contains("value1"));
        assert!(output.contains("+--"));
    }

    #[test]
    fn test_object_to_pairs() {
        let value = json!({"name": "sbc-01", "calls": 42, "tags": ["a", "b"]});
        let pairs = object_to_pairs(&value);
        assert_eq!(pairs.len(), 3);
        assert!(pairs.contains(&("name".to_string(), "sbc-01".to_string())));
        assert!(pairs.contains(&("calls".to_string(), "42".to_string())));
        assert!(pairs.contains(&("tags".to_string(), "[\"a\",\"b\"]".to_string())));
    }

    #[test]
    fn test_object_to_pairs_non_object() {
        assert!(object_to_pairs(&json!([1, 2, 3])).is_empty());
    }

    #[test]
    fn test_scalar_to_string() {
        assert_eq!(scalar_to_string(&json!("text")), "text");
        assert_eq!(scalar_to_string(&json!(7)), "7");
        assert_eq!(scalar_to_string(&json!(null)), "null");
        assert_eq!(scalar_to_string(&json!(true)), "true");
    }
}
