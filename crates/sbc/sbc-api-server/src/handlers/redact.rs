//! Trunk credential redaction.
//!
//! Trunk groups are stored as raw JSON (including each trunk's
//! `sip_password`, a carrier credential). The API must never return those
//! in the clear, so responses are redacted to a marker and write handlers
//! restore the stored secret when a client round-trips the marker back
//! (GET → edit → PUT).
//!
//! ## NIST 800-53 Rev5: IA-5 (Authenticator Management)

use serde_json::Value;

/// Marker substituted for trunk SIP passwords in responses.
pub const REDACTED: &str = "***REDACTED***";

/// Redacts every trunk `sip_password` in a trunk-group JSON value.
pub fn trunk_group(group: &mut Value) {
    if let Some(trunks) = group.get_mut("trunks").and_then(|v| v.as_array_mut()) {
        for t in trunks {
            trunk(t);
        }
    }
}

/// Redacts a single trunk's `sip_password`.
pub fn trunk(trunk: &mut Value) {
    if let Some(obj) = trunk.as_object_mut()
        && obj
            .get("sip_password")
            .and_then(|v| v.as_str())
            .is_some_and(|p| !p.is_empty())
    {
        obj.insert("sip_password".to_string(), Value::String(REDACTED.to_string()));
    }
}

/// Returns a redacted clone of a trunk-group value (for read responses).
pub fn redacted(mut group: Value) -> Value {
    trunk_group(&mut group);
    group
}

/// Restores stored passwords for trunks whose incoming `sip_password` is the
/// redaction marker (round-tripped from a redacted GET). `existing` is the
/// currently-stored group, if any.
pub fn restore_passwords(body: &mut Value, existing: Option<&Value>) {
    let Some(trunks) = body.get_mut("trunks").and_then(|v| v.as_array_mut()) else {
        return;
    };
    for t in trunks {
        let is_marker = t
            .get("sip_password")
            .and_then(|v| v.as_str())
            .is_some_and(|p| p == REDACTED);
        if !is_marker {
            continue;
        }
        let id = t.get("id").and_then(|v| v.as_str()).map(String::from);
        let stored = existing
            .and_then(|g| g.get("trunks"))
            .and_then(|v| v.as_array())
            .and_then(|trunks| {
                trunks
                    .iter()
                    .find(|s| s.get("id").and_then(|v| v.as_str()).map(String::from) == id)
            })
            .and_then(|s| s.get("sip_password"))
            .cloned();
        if let Some(obj) = t.as_object_mut() {
            match stored {
                // Restore the real secret.
                Some(pw) => {
                    obj.insert("sip_password".to_string(), pw);
                }
                // Marker with no stored secret — drop it rather than
                // persisting the literal marker as a password.
                None => {
                    obj.remove("sip_password");
                }
            }
        }
    }
}

/// Drops a `sip_password` equal to the marker from a single (new) trunk —
/// there is no stored secret to restore for a brand-new trunk.
pub fn drop_marker_password(trunk: &mut Value) {
    if trunk.get("sip_password").and_then(|v| v.as_str()) == Some(REDACTED) {
        if let Some(obj) = trunk.as_object_mut() {
            obj.remove("sip_password");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_and_restore_roundtrip() {
        let mut group = serde_json::json!({
            "id": "g1",
            "trunks": [{"id": "t1", "sip_password": "secret"}],
        });
        let stored = group.clone();
        trunk_group(&mut group);
        assert_eq!(group["trunks"][0]["sip_password"], REDACTED);

        // Client PUTs the redacted doc back.
        restore_passwords(&mut group, Some(&stored));
        assert_eq!(group["trunks"][0]["sip_password"], "secret");
    }

    #[test]
    fn marker_without_stored_is_dropped() {
        let mut group = serde_json::json!({
            "trunks": [{"id": "t1", "sip_password": REDACTED}],
        });
        restore_passwords(&mut group, None);
        assert!(group["trunks"][0].get("sip_password").is_none());
    }
}
