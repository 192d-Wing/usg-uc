//! Secret redaction shared by the site and central management APIs.
//!
//! Phones and trunk groups are stored as raw JSON, including phone line
//! `sip_password`s, the phone `directory.ldap_password` and each trunk's
//! `sip_password`. The APIs never return those in the clear: responses carry
//! a marker, and write handlers restore the stored secret when a client
//! round-trips the marker back (GET -> edit -> POST/PUT). A marker is only
//! ever resolved against the same row (same line `index`, same trunk `id`);
//! one that has no stored counterpart is cleared, never persisted. A write
//! that keeps a marker while changing where that secret is sent must
//! re-enter it (see [`phone_reentry_field`], [`trunk_group_reentry_field`]).
//!
//! The internal sync path carries the real values; only operator-facing
//! reads redact.
//!
//! ## NIST 800-53 Rev5: IA-5 (Authenticator Management), SI-12

use serde_json::Value;

/// Marker substituted for stored secrets in API responses.
pub const REDACTED: &str = "***REDACTED***";

/// `directory` fields that decide where the LDAP bind password is sent.
const LDAP_DESTINATION_FIELDS: [&str; 4] = ["ldap_server", "ldap_port", "ldap_tls", "ldap_bind_dn"];

/// Phone line fields that decide where, and as whom, a line's SIP password
/// is used.
const LINE_DESTINATION_FIELDS: [&str; 4] = ["sip_username", "sip_server", "sip_port", "transport"];

/// Trunk fields that decide where, and as whom, a trunk's SIP password is
/// used (`protocol` and `transport` are both accepted spellings).
const TRUNK_DESTINATION_FIELDS: [&str; 6] = [
    "host",
    "port",
    "protocol",
    "transport",
    "tls_server_name",
    "sip_username",
];

/// Whether `v` holds a value worth redacting: anything but absent, `null`,
/// `""` or an empty array/object. A secret key is redacted whatever its JSON
/// type, so a mistyped value is never echoed.
fn is_set(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(_) | Value::Number(_)) => true,
    }
}

/// Whether `v` is the redaction marker.
fn is_marker(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str) == Some(REDACTED)
}

/// Replaces a non-empty string `field` of `obj` with the marker.
fn mark(obj: &mut Value, field: &str) {
    if is_set(obj.get(field))
        && let Some(map) = obj.as_object_mut()
    {
        map.insert(field.to_string(), Value::String(REDACTED.to_string()));
    }
}

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
    mark(trunk, "sip_password");
}

/// Returns a redacted clone of a trunk-group value (for read responses).
#[must_use]
pub fn redacted(mut group: Value) -> Value {
    trunk_group(&mut group);
    group
}

/// Restores round-tripped trunk `sip_password` markers from the stored group.
///
/// `existing` is the currently-stored group, if any; `None` (new group,
/// template) drops every marker.
pub fn restore_passwords(body: &mut Value, existing: Option<&Value>) {
    let Some(trunks) = body.get_mut("trunks").and_then(|v| v.as_array_mut()) else {
        return;
    };
    for t in trunks {
        if !is_marker(t.get("sip_password")) {
            continue;
        }
        let id = t.get("id").and_then(|v| v.as_str());
        // Only attempt password restoration when both the incoming and
        // stored trunk have matching non-None ids.
        let stored = id
            .and_then(|trunk_id| {
                existing
                    .and_then(|g| g.get("trunks"))
                    .and_then(|v| v.as_array())
                    .and_then(|trunks| {
                        trunks
                            .iter()
                            .find(|s| s.get("id").and_then(|v| v.as_str()) == Some(trunk_id))
                    })
            })
            .and_then(|s| s.get("sip_password"))
            .filter(|pw| !is_marker(Some(pw)))
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
    if is_marker(trunk.get("sip_password"))
        && let Some(obj) = trunk.as_object_mut()
    {
        obj.remove("sip_password");
    }
}

/// Redacts a phone's line `sip_password`s and `directory.ldap_password`.
/// Empty, `null` and absent values are left as they are.
pub fn phone(phone: &mut Value) {
    if let Some(lines) = phone.get_mut("lines").and_then(Value::as_array_mut) {
        for line in lines {
            mark(line, "sip_password");
        }
    }
    if let Some(dir) = phone.get_mut("directory") {
        mark(dir, "ldap_password");
    }
}

/// Line fields that must match the stored line for a marker to be restored
/// from it. A dashboard that renumbers lines after a removal keeps the
/// marker; without this check it would pick up another line's password.
const LINE_IDENTITY_FIELDS: [&str; 2] = ["sip_username", "directory_number"];

/// The stored line a body line's marker may be restored from: same non-null
/// `index`, and the same `sip_username` and `directory_number` (absent on
/// both counts as the same).
fn stored_line<'a>(existing: Option<&'a Value>, line: &Value) -> Option<&'a Value> {
    let index = line.get("index").filter(|i| !i.is_null())?;
    existing?
        .get("lines")?
        .as_array()?
        .iter()
        .find(|l| l.get("index") == Some(index))
        .filter(|l| {
            LINE_IDENTITY_FIELDS
                .iter()
                .all(|f| l.get(*f) == line.get(*f))
        })
}

/// A stored secret worth restoring: a set value that is not itself the
/// marker.
fn stored_secret(v: Option<&Value>) -> Option<Value> {
    v.filter(|v| is_set(Some(v)) && !is_marker(Some(v)))
        .cloned()
}

/// Restores round-tripped phone secret markers from the stored phone.
///
/// A line marker is restored only from the stored line with the same
/// `index`, `sip_username` and `directory_number`. A marker with no such
/// counterpart becomes `""` for a line (the downstream type needs a string)
/// and `null` for LDAP. Any other value (new secret, `""`, `null`) is kept as
/// sent.
pub fn restore_phone_secrets(body: &mut Value, existing: Option<&Value>) {
    if let Some(lines) = body.get_mut("lines").and_then(Value::as_array_mut) {
        for line in lines {
            if !is_marker(line.get("sip_password")) {
                continue;
            }
            let stored = stored_line(existing, line)
                .and_then(|l| stored_secret(l.get("sip_password")))
                .unwrap_or_else(|| Value::String(String::new()));
            if let Some(obj) = line.as_object_mut() {
                obj.insert("sip_password".to_string(), stored);
            }
        }
    }
    if let Some(dir) = body.get_mut("directory")
        && is_marker(dir.get("ldap_password"))
    {
        let stored = existing
            .and_then(|p| p.get("directory"))
            .and_then(|d| stored_secret(d.get("ldap_password")))
            .unwrap_or(Value::Null);
        if let Some(obj) = dir.as_object_mut() {
            obj.insert("ldap_password".to_string(), stored);
        }
    }
}

/// Normalized MAC (`:`/`-` stripped, lowercase), as the stores key phones.
fn normalized_mac(phone: &Value) -> Option<String> {
    phone
        .get("mac_address")
        .and_then(Value::as_str)
        .map(|m| m.replace([':', '-'], "").to_lowercase())
}

/// The stored element of `existing[array]` whose `key` equals `item[key]`
/// (non-null), if it holds a secret under `secret` and `item[secret]` is the
/// marker.
fn kept_secret_counterpart<'a>(
    item: &Value,
    existing: &'a Value,
    array: &str,
    key: &str,
    secret: &str,
) -> Option<&'a Value> {
    if !is_marker(item.get(secret)) {
        return None;
    }
    let k = item.get(key).filter(|k| !k.is_null())?;
    existing
        .get(array)?
        .as_array()?
        .iter()
        .find(|s| s.get(key) == Some(k))
        .filter(|s| stored_secret(s.get(secret)).is_some())
}

/// The first of `fields` that differs between `a` and `b` (absent on both
/// counts as equal).
fn first_changed<'f>(a: &Value, b: &Value, fields: &[&'f str]) -> Option<&'f str> {
    fields.iter().copied().find(|f| a.get(*f) != b.get(*f))
}

/// Whether the body's LDAP password is the marker and a real one is stored.
fn ldap_marker_restores(body: &Value, existing: &Value) -> bool {
    body.get("directory")
        .is_some_and(|d| is_marker(d.get("ldap_password")))
        && existing
            .get("directory")
            .and_then(|d| stored_secret(d.get("ldap_password")))
            .is_some()
}

/// The destination field a phone write changes while keeping a marker that
/// stands for a stored secret, or `None` if the write may proceed. Such a
/// write must re-enter the secret.
///
/// Checked, in order:
/// - `mac_address` (normalized), when any line or LDAP marker is kept: the
///   phone profile carrying the secrets would go to another device;
/// - per kept line marker, the stored line with the same `index`:
///   `sip_username`, `sip_server`, `sip_port`, `transport`;
/// - with the LDAP marker kept: `ldap_server`, `ldap_port`, `ldap_tls`,
///   `ldap_bind_dn` (simple bind discloses the password to the server).
///
/// The returned name (e.g. `lines[0].sip_server`) carries no value. Call on
/// the body before [`restore_phone_secrets`].
#[must_use]
pub fn phone_reentry_field(body: &Value, existing: Option<&Value>) -> Option<String> {
    // Nothing stored to disclose: restore clears the markers instead.
    let existing = existing?;
    let kept_lines: Vec<(usize, &Value, &Value)> = body
        .get("lines")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(i, l)| {
            kept_secret_counterpart(l, existing, "lines", "index", "sip_password")
                .map(|s| (i, l, s))
        })
        .collect();
    let ldap_kept = ldap_marker_restores(body, existing);
    if (ldap_kept || !kept_lines.is_empty()) && normalized_mac(body) != normalized_mac(existing) {
        return Some("mac_address".to_string());
    }
    for (i, line, stored) in kept_lines {
        if let Some(f) = first_changed(line, stored, &LINE_DESTINATION_FIELDS) {
            return Some(format!("lines[{i}].{f}"));
        }
    }
    if ldap_kept
        && let (Some(dir), Some(stored)) = (body.get("directory"), existing.get("directory"))
        && let Some(f) = first_changed(dir, stored, &LDAP_DESTINATION_FIELDS)
    {
        return Some(format!("directory.{f}"));
    }
    None
}

/// Whether [`phone_reentry_field`] refuses the write.
#[must_use]
pub fn phone_secret_reentry_required(body: &Value, existing: Option<&Value>) -> bool {
    phone_reentry_field(body, existing).is_some()
}

/// The destination field a trunk-group write changes while keeping a marker.
///
/// A trunk `sip_password` marker that stands for a stored secret (trunks
/// match by `id`) with a changed destination returns the field, else `None`.
/// Checked fields are `host`, `port`, `protocol`, `transport`,
/// `tls_server_name` and `sip_username`. The returned name (e.g.
/// `trunks[1].host`) carries no value. Call before [`restore_passwords`].
#[must_use]
pub fn trunk_group_reentry_field(body: &Value, existing: Option<&Value>) -> Option<String> {
    let existing = existing?;
    let trunks = body.get("trunks")?.as_array()?;
    trunks.iter().enumerate().find_map(|(i, t)| {
        let stored = kept_secret_counterpart(t, existing, "trunks", "id", "sip_password")?;
        first_changed(t, stored, &TRUNK_DESTINATION_FIELDS).map(|f| format!("trunks[{i}].{f}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stored_marker_is_never_restored() {
        // A legacy row that holds the literal marker is not copied back.
        let stored = json!({
            "lines": [{"index": 1, "sip_password": REDACTED}],
            "directory": {"ldap_password": REDACTED},
            "trunks": [{"id": "t1", "sip_password": REDACTED}],
        });
        let mut body = stored.clone();
        restore_phone_secrets(&mut body, Some(&stored));
        restore_passwords(&mut body, Some(&stored));
        assert!(!body.to_string().contains(REDACTED), "{body}");
    }

    #[test]
    fn non_string_secret_values_are_redacted() {
        for v in [json!(1234), json!(true), json!(["x"]), json!({"k": "v"})] {
            let mut p = json!({"lines": [{"index": 1, "sip_password": v}],
                               "directory": {"ldap_password": v}});
            phone(&mut p);
            assert_eq!(p["lines"][0]["sip_password"], REDACTED, "{v}");
            assert_eq!(p["directory"]["ldap_password"], REDACTED, "{v}");
            let mut t = json!({"id": "t1", "sip_password": v});
            trunk(&mut t);
            assert_eq!(t["sip_password"], REDACTED, "{v}");
        }
        for v in [json!(null), json!(""), json!([]), json!({})] {
            let mut t = json!({"id": "t1", "sip_password": v});
            trunk(&mut t);
            assert_eq!(t["sip_password"], v);
        }
    }

    fn two_line_phone() -> Value {
        json!({
            "id": "p1",
            "mac_address": "00:11:22:33:44:55",
            "lines": [
                {"index": 1, "sip_username": "1001", "directory_number": "1001",
                 "sip_password": "pw-1001"},
                {"index": 2, "sip_username": "1002", "directory_number": "1002",
                 "sip_password": "pw-1002"},
            ],
            "directory": {"ldap_server": "ldap.example.mil", "ldap_password": "ldap-pw"},
        })
    }

    #[test]
    fn renumbered_line_marker_is_not_restored_from_other_line() {
        // Line 1 removed; the old line 2 is renumbered to index 1.
        let stored = two_line_phone();
        let mut body = json!({"id": "p1", "mac_address": "00:11:22:33:44:55", "lines": [
            {"index": 1, "sip_username": "1002", "directory_number": "1002",
             "sip_password": REDACTED},
        ]});
        restore_phone_secrets(&mut body, Some(&stored));
        assert_eq!(body["lines"][0]["sip_password"], "");
        assert!(!body.to_string().contains("pw-1001"), "{body}");
    }

    #[test]
    fn line_marker_needs_matching_username_and_directory_number() {
        let stored = two_line_phone();
        let line = |user: &str, dn: Option<&str>| {
            let mut l = json!({"index": 1, "sip_username": user, "sip_password": REDACTED});
            if let Some(dn) = dn {
                l["directory_number"] = json!(dn);
            }
            json!({"id": "p1", "lines": [l]})
        };
        let mut same = line("1001", Some("1001"));
        restore_phone_secrets(&mut same, Some(&stored));
        assert_eq!(same["lines"][0]["sip_password"], "pw-1001");

        for mut body in [
            line("9999", Some("1001")),
            line("1001", Some("9999")),
            line("1001", None),
        ] {
            restore_phone_secrets(&mut body, Some(&stored));
            assert_eq!(body["lines"][0]["sip_password"], "", "{body}");
        }
    }

    #[test]
    fn mac_change_with_kept_marker_requires_reentry() {
        let stored = two_line_phone();
        let mut body = stored.clone();
        phone(&mut body);
        // Same MAC in another spelling is not a change.
        body["mac_address"] = json!("00-11-22-33-44-55");
        assert!(!phone_secret_reentry_required(&body, Some(&stored)));
        assert!(!phone_secret_reentry_required(
            &json!({"mac_address": "001122334455", "lines": body["lines"].clone()}),
            Some(&stored)
        ));

        body["mac_address"] = json!("66:77:88:99:aa:bb");
        assert!(phone_secret_reentry_required(&body, Some(&stored)));

        // Only a line marker kept.
        let mut b = body.clone();
        b["directory"]["ldap_password"] = json!("ldap-new");
        assert!(phone_secret_reentry_required(&b, Some(&stored)));
        // Only the LDAP marker kept.
        let mut b = body.clone();
        b["lines"][0]["sip_password"] = json!("n1");
        b["lines"][1]["sip_password"] = json!("n2");
        assert!(phone_secret_reentry_required(&b, Some(&stored)));
        // Every secret re-entered or cleared: allowed.
        b["directory"]["ldap_password"] = Value::Null;
        assert!(!phone_secret_reentry_required(&b, Some(&stored)));
        // A marker that has nothing to restore is not a disclosure.
        let mut b = body.clone();
        b["lines"] = json!([{"index": 9, "sip_username": "other", "sip_password": REDACTED}]);
        b["directory"]["ldap_password"] = Value::Null;
        assert!(!phone_secret_reentry_required(&b, Some(&stored)));
        assert_eq!(
            phone_reentry_field(&body, Some(&stored)).as_deref(),
            Some("mac_address")
        );
    }

    #[test]
    fn line_destination_change_with_marker_names_the_field() {
        let stored = two_line_phone();
        for (field, value) in [
            ("sip_username", json!("2001")),
            ("sip_server", json!("sip.elsewhere.example")),
            ("sip_port", json!(5070)),
            ("transport", json!("udp")),
        ] {
            let mut body = stored.clone();
            phone(&mut body);
            body["lines"][1][field] = value;
            assert_eq!(
                phone_reentry_field(&body, Some(&stored)),
                Some(format!("lines[1].{field}")),
                "{field}"
            );
            // Re-entering that line's password allows the change.
            body["lines"][1]["sip_password"] = json!("pw-new");
            assert_eq!(phone_reentry_field(&body, Some(&stored)), None, "{field}");
        }
        // A directory_number change is not a destination: no refusal, and
        // restore clears the marker instead of copying the secret.
        let mut body = stored.clone();
        phone(&mut body);
        body["lines"][0]["directory_number"] = json!("1009");
        assert_eq!(phone_reentry_field(&body, Some(&stored)), None);
        restore_phone_secrets(&mut body, Some(&stored));
        assert_eq!(body["lines"][0]["sip_password"], "");
    }

    #[test]
    fn trunk_destination_change_with_marker_names_the_field() {
        let stored = json!({"id": "g1", "trunks": [
            {"id": "t1", "host": "a.example.mil", "port": 5061, "protocol": "tls",
             "sip_username": "u1", "sip_password": "trunk-pw"},
            {"id": "t2", "host": "b.example.mil", "sip_password": ""},
        ]});
        let marked = redacted(stored.clone());
        assert_eq!(trunk_group_reentry_field(&marked, Some(&stored)), None);
        assert_eq!(trunk_group_reentry_field(&marked, None), None);
        for (field, value) in [
            ("host", json!("evil.example")),
            ("port", json!(5060)),
            ("protocol", json!("udp")),
            ("transport", json!("udp")),
            ("tls_server_name", json!("other.example")),
            ("sip_username", json!("u2")),
        ] {
            let mut b = marked.clone();
            b["trunks"][0][field] = value;
            assert_eq!(
                trunk_group_reentry_field(&b, Some(&stored)),
                Some(format!("trunks[0].{field}")),
                "{field}"
            );
            b["trunks"][0]["sip_password"] = json!("trunk-new");
            assert_eq!(
                trunk_group_reentry_field(&b, Some(&stored)),
                None,
                "{field}"
            );
        }
        // No stored secret behind the marker (t2), or a new trunk id: allowed.
        let mut b = marked;
        b["trunks"][1]["host"] = json!("c.example.mil");
        b["trunks"][1]["sip_password"] = json!(REDACTED);
        b["trunks"][0]["id"] = json!("t9");
        b["trunks"][0]["host"] = json!("d.example.mil");
        assert_eq!(trunk_group_reentry_field(&b, Some(&stored)), None);
    }

    #[test]
    fn non_object_values_do_not_panic() {
        let mut v = json!({"lines": [1, "x", null], "directory": 7, "trunks": [true]});
        phone(&mut v);
        trunk_group(&mut v);
        restore_phone_secrets(&mut v, Some(&json!([])));
        restore_passwords(&mut v, Some(&json!("x")));
        assert!(!phone_secret_reentry_required(&v, Some(&json!(null))));
    }
}
