//! Per-vendor config-injection tests for the provisioning generators.
//!
//! NIST 800-53 Rev5: SI-15 (Information Output Filtering), SI-10.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use uc_phone_mgmt::cisco_9800::generate_9800_config;
use uc_phone_mgmt::cisco_mpp::generate_mpp_config;
use uc_phone_mgmt::model::{BlfEntry, CallForward, Phone, PhoneLine, PhoneModel, SpeedDial};
use uc_phone_mgmt::poly_edge::generate_edge_config;
use uc_phone_mgmt::polycom_vvx::generate_vvx_config;
use uc_phone_mgmt::teo::generate_teo_config;

const SBC: &str = "sbc.example.com";
const ELEMENT_PAYLOAD: &str = "x</displayName><proxy>evil.example</proxy><displayName>";
const ATTR_PAYLOAD: &str = "x\" reg.1.address=\"evil";
const NL_PAYLOAD: &str = "a\r\n<x>\0";

type Gen = fn(&Phone, &str) -> String;

/// Drop XML comments (their content is inert per XML 1.0 §2.5; comment
/// breakout is covered by `teo_comment_breakout_is_neutralised`).
fn strip_comments(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("<!--") {
        out.push_str(&rest[..i]);
        rest = rest[i..].find("-->").map_or("", |j| &rest[i + j + 3..]);
    }
    out.push_str(rest);
    out
}

fn vendors() -> [(PhoneModel, Gen, &'static str); 5] {
    [
        (
            PhoneModel::PolycomVVX450,
            generate_vvx_config,
            "reg.1.address=",
        ),
        (PhoneModel::PolyEdgeE450, generate_edge_config, "<server>"),
        (PhoneModel::CiscoMPP8851, generate_mpp_config, "_Proxy>"),
        (PhoneModel::Cisco9861, generate_9800_config, "<proxy>"),
        (PhoneModel::Teo7810, generate_teo_config, "<sip_proxy_addr"),
    ]
}

fn phone(model: PhoneModel, f: impl Fn(&mut Phone)) -> Phone {
    let mut p = Phone::new("aa:bb:cc:dd:ee:ff", model, "Test");
    p.lines.push(PhoneLine {
        index: 1,
        directory_number: "1001".into(),
        display_name: "John Doe".into(),
        user_id: None,
        sip_username: "1001".into(),
        sip_password: "secret123".into(),
        sip_server: SBC.into(),
        sip_port: 5060,
        transport: "udp".into(),
        voicemail_uri: Some("*97".into()),
        call_forward: Some(CallForward {
            all: Some("1099".into()),
            busy: Some("1099".into()),
            no_answer: Some("1099".into()),
            no_answer_timeout: 20,
        }),
    });
    p.speed_dials.push(SpeedDial {
        index: 1,
        label: "Desk".into(),
        number: "1000".into(),
    });
    p.blf_entries.push(BlfEntry {
        index: 1,
        label: "Boss".into(),
        address: "1002".into(),
    });
    p.directory.enabled = true;
    p.directory.ldap_server = Some("ldap.example.com".into());
    p.directory.ldap_base_dn = Some("dc=example,dc=com".into());
    p.directory.ldap_bind_dn = Some("cn=ro".into());
    p.directory.ldap_password = Some("pw".into());
    p.display.ntp_server = Some("ntp.example.com".into());
    p.display.language = Some("en".into());
    f(&mut p);
    p
}

/// Set every operator string field on the phone to `v`.
fn poison(p: &mut Phone, v: &str) {
    p.name = v.into();
    let l = &mut p.lines[0];
    l.directory_number = v.into();
    l.display_name = v.into();
    l.sip_username = v.into();
    l.sip_password = v.into();
    l.sip_server = v.into();
    l.voicemail_uri = Some(v.into());
    let cf = l.call_forward.as_mut().unwrap();
    cf.all = Some(v.into());
    cf.busy = Some(v.into());
    cf.no_answer = Some(v.into());
    p.speed_dials[0].label = v.into();
    p.speed_dials[0].number = v.into();
    p.blf_entries[0].label = v.into();
    p.blf_entries[0].address = v.into();
    p.directory.ldap_server = Some(v.into());
    p.directory.ldap_base_dn = Some(v.into());
    p.directory.ldap_bind_dn = Some(v.into());
    p.directory.ldap_password = Some(v.into());
    p.display.ntp_server = Some(v.into());
    p.display.language = Some(v.into());
    p.display.timezone = Some(v.into());
    p.display.ringtone = Some(v.into());
    p.emergency.emergency_number = Some(v.into());
    p.emergency.location_id = Some(v.into());
    p.emergency.elin = Some(v.into());
}

#[test]
fn element_breakout_is_neutralised() {
    for (model, generate, marker) in vendors() {
        let base = generate(&phone(model.clone(), |_| {}), SBC);
        let out = strip_comments(&generate(
            &phone(model, |p| poison(p, ELEMENT_PAYLOAD)),
            SBC,
        ));
        assert!(!out.contains("<proxy>evil"), "{out}");
        assert!(!out.contains("evil.example</"), "{out}");
        assert_eq!(out.matches(marker).count(), base.matches(marker).count());
        assert_eq!(
            out.matches("<proxy>").count(),
            base.matches("<proxy>").count()
        );
    }
}

#[test]
fn attribute_quote_breakout_is_neutralised() {
    for (model, generate, _) in vendors() {
        let out = strip_comments(&generate(&phone(model, |p| poison(p, ATTR_PAYLOAD)), SBC));
        assert!(!out.contains("=\"evil"), "{out}");
    }
}

#[test]
fn newline_and_nul_are_neutralised() {
    for (model, generate, _) in vendors() {
        let out = generate(
            &phone(model, |p| {
                p.lines[0].sip_password = NL_PAYLOAD.into();
                p.lines[0].sip_username = NL_PAYLOAD.into();
            }),
            SBC,
        );
        assert!(!out.contains('\0'));
        assert!(!out.contains('\r'));
        assert!(!out.contains("<x>"));
        assert!(!out.contains("a\n"), "{out}");
    }
}

#[test]
fn mpp_blf_label_cannot_add_sub_field() {
    let out = generate_mpp_config(
        &phone(PhoneModel::CiscoMPP8851, |p| {
            p.blf_entries[0].label = "x;sub=evil".into();
        }),
        SBC,
    );
    let line = out
        .lines()
        .find(|l| l.contains("<Extended_Function_1_>"))
        .unwrap();
    assert_eq!(line.matches("sub=").count(), 1, "{line}");
}

#[test]
fn teo_comment_breakout_is_neutralised() {
    let out = generate_teo_config(
        &phone(PhoneModel::Teo7810, |p| p.name = "--><x/><!--".into()),
        SBC,
    );
    assert_eq!(out.matches("-->").count(), out.matches("<!--").count());
    assert_eq!(out.matches("-->").count(), 1, "{out}");
}

#[test]
fn transport_is_closed_set() {
    for generate in [generate_vvx_config as Gen, generate_edge_config] {
        let out = generate(
            &phone(PhoneModel::PolycomVVX450, |p| {
                p.lines[0].transport = "udp</x>".into();
            }),
            SBC,
        );
        assert!(!out.contains("</x>"));
        assert!(out.contains(">UDP</"));
    }
}

#[test]
fn hostile_sbc_host_is_escaped() {
    for (model, generate, _) in vendors() {
        let out = generate(&phone(model, |_| {}), "h</x><proxy>evil");
        assert!(!out.contains("<proxy>evil"));
    }
}

/// Minimal XML 1.0 well-formedness check: balanced element stack, no raw
/// `<` or `&` outside markup/entities, quoted attributes without raw `<`.
/// VVX is excluded: its `<divert.1.busy.contact="..." />` form is quasi-XML
/// by design (plan.md 1, rejected alternatives).
fn assert_well_formed(xml: &str) {
    let mut stack: Vec<String> = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(['<', '&']) {
        let text = &rest[..i];
        assert!(
            !text.contains('>') || stack.is_empty(),
            "stray '>' in {text:?}"
        );
        rest = &rest[i..];
        if rest.starts_with('&') {
            let end = rest.find(';').expect("unterminated entity");
            let ent = &rest[1..end];
            assert!(
                matches!(ent, "amp" | "lt" | "gt" | "quot" | "apos") || ent.starts_with('#'),
                "bad entity &{ent};"
            );
            rest = &rest[end + 1..];
            continue;
        }
        if let Some(r) = rest.strip_prefix("<!--") {
            let end = r.find("-->").expect("unterminated comment");
            assert!(!r[..end].contains("--"), "'--' inside comment");
            rest = &r[end + 3..];
            continue;
        }
        if let Some(r) = rest.strip_prefix("<?") {
            rest = &r[r.find("?>").expect("unterminated PI") + 2..];
            continue;
        }
        // Element tag: scan honouring quoted attribute values.
        let mut in_q: Option<char> = None;
        let mut end = None;
        for (j, c) in rest.char_indices().skip(1) {
            match (in_q, c) {
                (Some(q), c) if c == q => in_q = None,
                (Some(_), '<') => panic!("raw '<' in attribute: {rest:.80}"),
                (None, '"' | '\'') => in_q = Some(c),
                (None, '<') => panic!("raw '<' in tag: {rest:.80}"),
                (None, '>') => {
                    end = Some(j);
                    break;
                }
                _ => {}
            }
        }
        let end = end.expect("unterminated tag");
        let tag = &rest[1..end];
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '/')
            .collect();
        if tag.starts_with('/') {
            assert_eq!(
                stack.pop().as_deref(),
                Some(name.as_str()),
                "mismatched close"
            );
        } else if !tag.ends_with('/') {
            stack.push(name);
        }
        rest = &rest[end + 1..];
    }
    assert!(stack.is_empty(), "unclosed elements: {stack:?}");
}

#[test]
fn hostile_output_is_well_formed_xml() {
    let payloads = [
        ELEMENT_PAYLOAD,
        ATTR_PAYLOAD,
        NL_PAYLOAD,
        "--><x/><!--",
        "a'b\"c&d<e>f",
        "&amp;&#x3c;&lt;",
        "x-",
        "\u{1b}[2J\u{7f}\u{85}\u{fffe}",
        "]]><![CDATA[",
    ];
    for (model, generate, _) in vendors() {
        if matches!(model, PhoneModel::PolycomVVX450) {
            continue;
        }
        assert_well_formed(&generate(&phone(model.clone(), |_| {}), SBC));
        for v in payloads {
            let out = generate(&phone(model.clone(), |p| poison(p, v)), v);
            assert_well_formed(&out);
        }
    }
}

#[test]
fn vvx_attributes_stay_quoted_under_hostile_input() {
    for v in [ATTR_PAYLOAD, "a'b\"c&d<e>f", NL_PAYLOAD, "--><x/><!--"] {
        let out = strip_comments(&generate_vvx_config(
            &phone(PhoneModel::PolycomVVX450, |p| poison(p, v)),
            v,
        ));
        // Every attribute value is a balanced "..." with no raw '<' inside.
        for line in out.lines() {
            assert_eq!(line.matches('"').count() % 2, 0, "{line}");
            let mut inside = false;
            for c in line.chars() {
                if c == '"' {
                    inside = !inside;
                } else if inside {
                    assert!(c != '<' && c != '\n' && c != '\0', "{line}");
                }
            }
        }
    }
}
