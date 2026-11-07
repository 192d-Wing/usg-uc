//! Write-time validation for phone and directory-number records.
//!
//! ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
//!
//! Defence in depth behind the provisioning generators' output encoding
//! (`uc_phone_mgmt::escape`, SI-15): every string is checked for control
//! characters, a byte-length limit, and a per-field character class, and
//! collections are count-limited (SC-5, SC-6) so a single record cannot
//! balloon every phone's config.
//!
//! Errors name the field but never echo the value (SI-11): the value may be
//! a SIP or LDAP password.

use uc_phone_mgmt::model::Phone;

use crate::error::{ConfigStoreError, ConfigStoreResult};
use crate::model::DirectoryNumber;
use crate::phones::PostgresPhoneStore;

/// Maximum speed-dial entries per phone.
pub const MAX_SPEED_DIALS: usize = 100;
/// Maximum BLF entries per phone.
pub const MAX_BLF_ENTRIES: usize = 100;
/// Maximum softkeys per phone.
pub const MAX_SOFTKEYS: usize = 64;
/// Maximum paging groups per phone.
pub const MAX_PAGING_GROUPS: usize = 32;
/// Maximum serialized size of a directory number's `extra` bag.
pub const MAX_DN_EXTRA_BYTES: usize = 16 * 1024;

/// Field character classes.
#[derive(Clone, Copy)]
enum Class {
    /// Any non-control character.
    Free,
    /// Free text without the Cisco MPP `;` / `=` delimiters.
    FreeNoKv,
    /// SIP user part: `[A-Za-z0-9._~!*'()+%-]`, non-empty.
    User,
    /// Hostname / IPv4 / `[IPv6]`, optional `:port`.
    Host,
    /// Dial string: ASCII alphanumerics plus `*#+,.-_`, non-empty.
    Dial,
    /// Dial string or `sip:`/`sips:` URI without parameter/header delimiters.
    Target,
    /// Locale / timezone / ringtone token: `[A-Za-z0-9._/+-]`.
    PathToken,
    /// Identifier token: `[A-Za-z0-9._-]`.
    Token,
}

fn invalid(field: impl Into<String>, reason: &'static str) -> ConfigStoreError {
    ConfigStoreError::Invalid {
        field: field.into(),
        reason,
    }
}

/// Control characters and invisible separators rejected in every field.
const fn is_forbidden(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}' | '\u{2028}' | '\u{2029}' | '\u{FEFF}')
}

fn is_user_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._~!*'()+%-".contains(c)
}

fn is_dial_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "*#+,.-_".contains(c)
}

fn is_uri_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._~!*'()+%@:[]#,-".contains(c)
}

fn valid_port(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 5
        && p.bytes().all(|b| b.is_ascii_digit())
        && p.parse::<u16>().is_ok_and(|n| n != 0)
}

/// `host[:port]` where host is a DNS name / IPv4 (`[A-Za-z0-9.-]`, no
/// leading `-` or `.`) or a bracketed IPv6 literal.
#[must_use]
pub fn is_valid_host_port(s: &str) -> bool {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let (v6, after) = rest.split_at(end);
        let after = &after[1..];
        if v6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        match after.strip_prefix(':') {
            Some(p) => return valid_port(p),
            None => return after.is_empty(),
        }
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host.is_empty() || host.starts_with(['-', '.']) {
        return false;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }
    port.is_none_or(valid_port)
}

fn check(field: &str, v: &str, class: Class, max: usize) -> ConfigStoreResult<()> {
    if v.len() > max {
        return Err(invalid(field, "too long"));
    }
    if v.chars().any(is_forbidden) {
        return Err(invalid(field, "contains control characters"));
    }
    let ok = match class {
        Class::Free => true,
        Class::FreeNoKv => !v.contains([';', '=']),
        Class::User => !v.is_empty() && v.chars().all(is_user_char),
        Class::Host => is_valid_host_port(v),
        Class::Dial => !v.is_empty() && v.chars().all(is_dial_char),
        Class::Target => {
            let body = v
                .strip_prefix("sips:")
                .or_else(|| v.strip_prefix("sip:"))
                .unwrap_or(v);
            !body.is_empty() && body.chars().all(is_uri_char)
        }
        Class::PathToken => {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._/+-".contains(c))
        }
        Class::Token => {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        }
    };
    if ok {
        Ok(())
    } else {
        Err(invalid(
            field,
            "contains characters not allowed for this field",
        ))
    }
}

fn check_opt(field: &str, v: Option<&String>, class: Class, max: usize) -> ConfigStoreResult<()> {
    v.map_or(Ok(()), |v| check(field, v, class, max))
}

/// Validate a phone before it is written.
///
/// # Errors
/// Returns `ConfigStoreError::Invalid` naming the first offending field.
pub fn validate_phone(p: &Phone) -> ConfigStoreResult<()> {
    // POAM: POA&M-121 -- central sync (sbc-config-sync/src/apply.rs:151)
    // writes rows without calling this validator; generators still escape.
    use Class::Free;

    if p.mac_address.len() > 17 || p.mac_address.chars().any(is_forbidden) {
        return Err(invalid("mac_address", "malformed"));
    }
    let mac = PostgresPhoneStore::normalize_mac(&p.mac_address);
    if mac.len() != 12 || !mac.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("mac_address", "malformed"));
    }
    check("id", &p.id, Free, 128)?;
    check("name", &p.name, Free, 64)?;
    check_opt("description", p.description.as_ref(), Free, 256)?;
    for (f, v) in [
        ("device_pool", &p.device_pool),
        ("calling_search_space", &p.calling_search_space),
        ("owner_id", &p.owner_id),
        ("firmware_version", &p.firmware_version),
        ("target_firmware", &p.target_firmware),
        ("ip_address", &p.ip_address),
    ] {
        check_opt(f, v.as_ref(), Free, 128)?;
    }

    // NIST 800-53 Rev5: SC-5 -- bound per-phone collections.
    let max_lines = p.model.max_lines();
    if p.lines.len() > usize::from(max_lines) {
        return Err(invalid("lines", "more lines than the model supports"));
    }
    if p.speed_dials.len() > MAX_SPEED_DIALS {
        return Err(invalid("speed_dials", "too many entries"));
    }
    if p.blf_entries.len() > MAX_BLF_ENTRIES {
        return Err(invalid("blf_entries", "too many entries"));
    }
    if p.softkeys.len() > MAX_SOFTKEYS {
        return Err(invalid("softkeys", "too many entries"));
    }
    if p.paging.groups.len() > MAX_PAGING_GROUPS {
        return Err(invalid("paging.groups", "too many entries"));
    }

    validate_lines(p, max_lines)?;
    validate_keys(p)?;
    validate_settings(p)
}

fn validate_lines(p: &Phone, max_lines: u8) -> ConfigStoreResult<()> {
    use Class::{Dial, Free, Host, Target, User};
    for (n, l) in p.lines.iter().enumerate() {
        let f = |s: &str| format!("lines[{n}].{s}");
        if l.index == 0 || l.index > max_lines {
            return Err(invalid(f("index"), "out of range for model"));
        }
        check(&f("directory_number"), &l.directory_number, Dial, 32)?;
        check(&f("display_name"), &l.display_name, Free, 64)?;
        check_opt(&f("user_id"), l.user_id.as_ref(), User, 64)?;
        check(&f("sip_username"), &l.sip_username, User, 64)?;
        check(&f("sip_password"), &l.sip_password, Free, 128)?;
        check(&f("sip_server"), &l.sip_server, Host, 253)?;
        if !["udp", "tcp", "tls"]
            .iter()
            .any(|t| l.transport.eq_ignore_ascii_case(t))
        {
            return Err(invalid(f("transport"), "must be udp, tcp or tls"));
        }
        check_opt(&f("voicemail_uri"), l.voicemail_uri.as_ref(), Target, 256)?;
        if let Some(cf) = &l.call_forward {
            check_opt(&f("call_forward.all"), cf.all.as_ref(), Target, 256)?;
            check_opt(&f("call_forward.busy"), cf.busy.as_ref(), Target, 256)?;
            check_opt(
                &f("call_forward.no_answer"),
                cf.no_answer.as_ref(),
                Target,
                256,
            )?;
        }
    }
    Ok(())
}

fn validate_keys(p: &Phone) -> ConfigStoreResult<()> {
    use Class::{Dial, Free, FreeNoKv, Host, Target, Token};
    for (n, sd) in p.speed_dials.iter().enumerate() {
        check(&format!("speed_dials[{n}].label"), &sd.label, Free, 64)?;
        check(&format!("speed_dials[{n}].number"), &sd.number, Dial, 32)?;
    }
    for (n, b) in p.blf_entries.iter().enumerate() {
        check(&format!("blf_entries[{n}].label"), &b.label, FreeNoKv, 64)?;
        check(
            &format!("blf_entries[{n}].address"),
            &b.address,
            Target,
            256,
        )?;
    }
    for (n, k) in p.softkeys.iter().enumerate() {
        check(&format!("softkeys[{n}].label"), &k.label, Free, 64)?;
        check_opt(
            &format!("softkeys[{n}].value"),
            k.value.as_ref(),
            Target,
            256,
        )?;
    }
    for (n, g) in p.paging.groups.iter().enumerate() {
        check(&format!("paging.groups[{n}]"), g, Token, 64)?;
    }
    check_opt(
        "paging.multicast_address",
        p.paging.multicast_address.as_ref(),
        Host,
        253,
    )?;

    Ok(())
}

fn validate_settings(p: &Phone) -> ConfigStoreResult<()> {
    use Class::{Dial, Free, Host, PathToken, Token};
    let d = &p.display;
    check_opt("display.language", d.language.as_ref(), PathToken, 64)?;
    check_opt("display.timezone", d.timezone.as_ref(), PathToken, 64)?;
    check_opt("display.ringtone", d.ringtone.as_ref(), PathToken, 64)?;
    check_opt("display.ntp_server", d.ntp_server.as_ref(), Host, 253)?;

    let dir = &p.directory;
    check_opt("directory.ldap_server", dir.ldap_server.as_ref(), Host, 253)?;
    check_opt(
        "directory.ldap_base_dn",
        dir.ldap_base_dn.as_ref(),
        Free,
        512,
    )?;
    check_opt(
        "directory.ldap_bind_dn",
        dir.ldap_bind_dn.as_ref(),
        Free,
        512,
    )?;
    check_opt(
        "directory.ldap_password",
        dir.ldap_password.as_ref(),
        Free,
        128,
    )?;

    let e = &p.emergency;
    check_opt(
        "emergency.emergency_number",
        e.emergency_number.as_ref(),
        Dial,
        32,
    )?;
    check_opt("emergency.elin", e.elin.as_ref(), Dial, 32)?;
    check_opt("emergency.location_id", e.location_id.as_ref(), Token, 64)?;
    Ok(())
}

/// Validate a directory number before it is written.
///
/// # Errors
/// Returns `ConfigStoreError::Invalid` naming the first offending field.
pub fn validate_directory_number(d: &DirectoryNumber) -> ConfigStoreResult<()> {
    check("did", &d.did, Class::Dial, 32)?;
    check_opt("user", d.user.as_ref(), Class::User, 64)?;
    check_opt("partition", d.partition.as_ref(), Class::Token, 64)?;
    check_opt("description", d.description.as_ref(), Class::Free, 256)?;
    // NIST 800-53 Rev5: SC-5 -- bound the forward-compatible JSONB bag.
    let extra_len = serde_json::to_vec(&d.extra).map_or(usize::MAX, |v| v.len());
    if extra_len > MAX_DN_EXTRA_BYTES {
        return Err(invalid("extra", "too large"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use uc_phone_mgmt::model::{BlfEntry, PhoneLine, PhoneModel, SpeedDial};

    const PAYLOAD: &str = "x</displayName><proxy>evil.example</proxy><displayName>";

    fn phone() -> Phone {
        let mut p = Phone::new("aa:bb:cc:dd:ee:ff", PhoneModel::PolycomVVX450, "Lobby");
        p.lines.push(PhoneLine {
            index: 1,
            directory_number: "1001".into(),
            display_name: "John Doe".into(),
            user_id: None,
            sip_username: "1001".into(),
            sip_password: "s3cr3t!".into(),
            sip_server: "sbc.example.com".into(),
            sip_port: 5060,
            transport: "udp".into(),
            voicemail_uri: Some("*97".into()),
            call_forward: None,
        });
        p
    }

    fn field_of(r: ConfigStoreResult<()>) -> String {
        match r {
            Err(ConfigStoreError::Invalid { field, .. }) => field,
            other => format!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn baseline_ok() {
        validate_phone(&phone()).unwrap();
    }

    #[test]
    fn host_class() {
        for ok in ["a.b", "10.0.0.1:5061", "[::1]:5060", "[::1]", "sbc"] {
            assert!(is_valid_host_port(ok), "{ok}");
        }
        for bad in [
            "-a", "a b", "a/b", "a@b", "", "a:0", "a:99999", "[::1", "evil</x>",
        ] {
            assert!(!is_valid_host_port(bad), "{bad}");
        }
    }

    #[test]
    fn control_chars_rejected_in_every_string_field() {
        type Setter = fn(&mut Phone, String);
        let setters: [(&str, Setter); 14] = [
            ("name", |p, v| p.name = v),
            ("lines[0].display_name", |p, v| p.lines[0].display_name = v),
            ("lines[0].sip_username", |p, v| p.lines[0].sip_username = v),
            ("lines[0].sip_password", |p, v| p.lines[0].sip_password = v),
            ("lines[0].sip_server", |p, v| p.lines[0].sip_server = v),
            ("lines[0].directory_number", |p, v| {
                p.lines[0].directory_number = v;
            }),
            ("lines[0].voicemail_uri", |p, v| {
                p.lines[0].voicemail_uri = Some(v);
            }),
            ("description", |p, v| p.description = Some(v)),
            ("display.ntp_server", |p, v| p.display.ntp_server = Some(v)),
            ("display.language", |p, v| p.display.language = Some(v)),
            ("directory.ldap_password", |p, v| {
                p.directory.ldap_password = Some(v);
            }),
            ("directory.ldap_base_dn", |p, v| {
                p.directory.ldap_base_dn = Some(v);
            }),
            ("emergency.emergency_number", |p, v| {
                p.emergency.emergency_number = Some(v);
            }),
            ("emergency.location_id", |p, v| {
                p.emergency.location_id = Some(v);
            }),
        ];
        for (field, set) in setters {
            for bad in ["a\rb", "a\nb", "a\0b", "a\u{2028}b", "a\u{85}b"] {
                let mut p = phone();
                set(&mut p, bad.into());
                assert_eq!(field_of(validate_phone(&p)), field);
            }
        }
    }

    #[test]
    fn length_boundaries() {
        let mut p = phone();
        p.name = "n".repeat(64);
        validate_phone(&p).unwrap();
        p.name.push('n');
        assert_eq!(field_of(validate_phone(&p)), "name");

        let mut p = phone();
        p.lines[0].directory_number = "1".repeat(32);
        validate_phone(&p).unwrap();
        p.lines[0].directory_number.push('1');
        assert_eq!(field_of(validate_phone(&p)), "lines[0].directory_number");
    }

    #[test]
    fn dial_string_allows_pauses_and_letters() {
        let mut p = phone();
        p.speed_dials.push(SpeedDial {
            index: 1,
            label: "Ext".into(),
            number: "+1555,,123#*ab.c-d_e".into(),
        });
        validate_phone(&p).unwrap();
        p.speed_dials[0].number = "1;x=y".into();
        assert_eq!(field_of(validate_phone(&p)), "speed_dials[0].number");
    }

    #[test]
    fn transport_enum() {
        let mut p = phone();
        p.lines[0].transport = "TLS".into();
        validate_phone(&p).unwrap();
        p.lines[0].transport = "udp</x>".into();
        assert_eq!(field_of(validate_phone(&p)), "lines[0].transport");
    }

    #[test]
    fn counts_and_line_index() {
        let mut p = phone();
        p.lines[0].index = 99;
        assert_eq!(field_of(validate_phone(&p)), "lines[0].index");

        let mut p = phone();
        let line = p.lines[0].clone();
        for i in 0..=p.model.max_lines() {
            let mut l = line.clone();
            l.index = i + 1;
            p.lines.push(l);
        }
        assert_eq!(field_of(validate_phone(&p)), "lines");

        let mut p = phone();
        for i in 0..=MAX_BLF_ENTRIES {
            p.blf_entries.push(BlfEntry {
                index: u8::try_from(i % 200).unwrap(),
                label: "b".into(),
                address: "1002".into(),
            });
        }
        assert_eq!(field_of(validate_phone(&p)), "blf_entries");
    }

    #[test]
    fn blf_label_rejects_kv_delimiters() {
        let mut p = phone();
        p.blf_entries.push(BlfEntry {
            index: 1,
            label: "x;sub=evil".into(),
            address: "sip:1002@sbc.example.com".into(),
        });
        assert_eq!(field_of(validate_phone(&p)), "blf_entries[0].label");
        p.blf_entries[0].label = "Boss".into();
        validate_phone(&p).unwrap();
        p.blf_entries[0].address = "sip:1002@h;transport=udp".into();
        assert_eq!(field_of(validate_phone(&p)), "blf_entries[0].address");
    }

    #[test]
    fn mac_must_be_twelve_hex() {
        let mut p = phone();
        p.mac_address = "zz:bb:cc:dd:ee:ff".into();
        assert_eq!(field_of(validate_phone(&p)), "mac_address");
        p.mac_address = "aabbccddeeff".into();
        validate_phone(&p).unwrap();
    }

    /// Documents the layering: free text accepts markup (escaped on output),
    /// structured fields reject it.
    #[test]
    fn backlog_payload_layering() {
        let mut p = phone();
        p.lines[0].display_name = PAYLOAD.into();
        validate_phone(&p).unwrap();

        let mut p = phone();
        p.lines[0].sip_server = PAYLOAD.into();
        assert_eq!(field_of(validate_phone(&p)), "lines[0].sip_server");

        let mut p = phone();
        p.lines[0].sip_username = PAYLOAD.into();
        assert_eq!(field_of(validate_phone(&p)), "lines[0].sip_username");
    }

    #[test]
    fn error_does_not_echo_value() {
        let mut p = phone();
        p.lines[0].sip_password = "hunter2\n".into();
        let msg = validate_phone(&p).unwrap_err().to_string();
        assert!(msg.contains("lines[0].sip_password"));
        assert!(!msg.contains("hunter2"));
    }

    #[test]
    fn directory_number_rules() {
        let mut d = DirectoryNumber {
            did: "+12025550100".into(),
            user: Some("alice".into()),
            partition: Some("internal".into()),
            description: Some("Front desk".into()),
            extra: std::collections::HashMap::new(),
        };
        validate_directory_number(&d).unwrap();
        d.user = Some("a b".into());
        assert_eq!(field_of(validate_directory_number(&d)), "user");
        d.user = None;
        d.did = "1\r\n".into();
        assert_eq!(field_of(validate_directory_number(&d)), "did");
        d.did = "1001".into();
        d.extra
            .insert("blob".into(), serde_json::Value::String("x".repeat(20_000)));
        assert_eq!(field_of(validate_directory_number(&d)), "extra");
    }
}
