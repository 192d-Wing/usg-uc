//! Bounded label-series key construction shared by [`Counter`](crate::Counter)
//! and [`Gauge`](crate::Gauge).
//!
//! NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection) -- label values may
//! be derived from attacker-influenced input (peer names, response codes), so
//! the number of distinct series per metric and the length of each label
//! value are capped. Excess series fold into a single overflow series so
//! totals stay correct (SI-4: no silently lost counts).

use std::collections::HashMap;

/// Default maximum number of distinct labelled series per metric.
pub const MAX_LABEL_SERIES: usize = 1024;

/// Maximum length in bytes of a single label value; longer values are
/// truncated on a UTF-8 character boundary.
pub const MAX_LABEL_VALUE_LEN: usize = 128;

/// Label value used for every label of the overflow series.
pub const OVERFLOW_LABEL_VALUE: &str = "__overflow__";

/// Truncates `value` to at most [`MAX_LABEL_VALUE_LEN`] bytes.
fn truncate(value: &str) -> &str {
    if value.len() <= MAX_LABEL_VALUE_LEN {
        return value;
    }
    let mut end = MAX_LABEL_VALUE_LEN;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.get(..end).unwrap_or("")
}

/// Builds the normalised (truncated) key for `labels` without any cap check.
pub(crate) fn lookup_key(labels: &[&str]) -> Vec<String> {
    labels.iter().map(|s| truncate(s).to_string()).collect()
}

/// Returns the overflow key for a metric with `arity` labels.
pub(crate) fn overflow_key(arity: usize) -> Vec<String> {
    vec![OVERFLOW_LABEL_VALUE.to_string(); arity]
}

/// Chooses the series key for an update.
///
/// Returns `(key, overflowed)`. The update is redirected to the overflow
/// series when the label arity does not match `arity`, or when the key is
/// new and the map already holds `max_series` distinct (non-overflow) series.
pub(crate) fn series_key<V>(
    map: &HashMap<Vec<String>, V>,
    arity: usize,
    max_series: usize,
    labels: &[&str],
) -> (Vec<String>, bool) {
    if labels.len() != arity {
        return (overflow_key(arity), true);
    }
    let key = lookup_key(labels);
    let overflow = overflow_key(arity);
    // NIST 800-53 Rev5: SI-4 -- the overflow key is reserved; a caller-supplied
    // tuple equal to it is counted as overflow so `overflowed()` is not understated.
    if key == overflow {
        return (overflow, true);
    }
    if map.contains_key(&key) {
        return (key, false);
    }
    let real_series = map.len() - usize::from(map.contains_key(&overflow));
    if real_series >= max_series {
        return (overflow, true);
    }
    (key, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_char_boundary() {
        let long = "é".repeat(100); // 200 bytes
        let t = truncate(&long);
        assert!(t.len() <= MAX_LABEL_VALUE_LEN);
        assert!(long.starts_with(t));
        assert_eq!(truncate("short"), "short");
    }

    #[test]
    fn reserved_overflow_value_counts_as_overflow() {
        let map: HashMap<Vec<String>, u64> = HashMap::new();
        let (key, overflowed) = series_key(&map, 1, 16, &[OVERFLOW_LABEL_VALUE]);
        assert_eq!(key, overflow_key(1));
        assert!(overflowed);
        // Partial match is an ordinary series.
        let (_, overflowed) = series_key(&map, 2, 16, &[OVERFLOW_LABEL_VALUE, "x"]);
        assert!(!overflowed);
    }
}
