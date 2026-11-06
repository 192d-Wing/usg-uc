//! Call-path routing integration tests: config load of
//! `routing.emergency_trunk_group`, and the canonical number feeding the
//! SBC router's tri-state outcome (blocked never falls through).

use sbc_config::load_from_str;
use uc_routing::{
    CallingSearchSpace, DialPattern, Partition, RoutePattern, SbcRouteOutcome, SbcRouter,
};
use uc_types::DialedNumber;

const GROUPS: &str = r#"
    [[trunk_groups]]
    id = "carriers"
    name = "Carriers"
    [[trunk_groups.trunks]]
    id = "c1"
    host = "192.0.2.10"

    [[trunk_groups]]
    id = "e911"
    name = "E911"
    [[trunk_groups.trunks]]
    id = "psap"
    host = "192.0.2.11"
"#;

#[test]
fn config_with_emergency_trunk_group_loads() {
    let toml = format!(
        "[routing]\ndefault_trunk_group = \"carriers\"\nemergency_trunk_group = \"e911\"\n{GROUPS}"
    );
    let config = load_from_str(&toml).unwrap();
    assert_eq!(
        config
            .routing
            .as_ref()
            .and_then(|r| r.emergency_trunk_group.as_deref()),
        Some("e911")
    );
}

#[test]
fn config_with_unknown_emergency_trunk_group_is_rejected() {
    let toml = format!(
        "[routing]\ndefault_trunk_group = \"carriers\"\nemergency_trunk_group = \"nope\"\n{GROUPS}"
    );
    let err = load_from_str(&toml).unwrap_err().to_string();
    assert!(err.contains("emergency_trunk_group"), "{err}");
}

#[test]
fn canonical_dialled_number_hits_block_in_every_form() {
    let mut sbc = SbcRouter::new();
    sbc.add_partition(Partition::new("pt", "Pt"));
    sbc.add_route_pattern(
        RoutePattern::new("rp-900", DialPattern::prefix("1900"), "pt").with_block(true),
    );
    sbc.add_route_pattern(
        RoutePattern::new("rp-any", DialPattern::Any, "pt").with_route_group("carriers"),
    );
    let mut css = CallingSearchSpace::new("css", "Css");
    css.add_partition("pt");
    sbc.add_css(css);
    for raw in [
        "19005551212",
        "1-900-555-1212",
        "+1 (900) 555-1212",
        "%2B19005551212",
        "19005551212;phone-context=+1",
    ] {
        let dialed = DialedNumber::parse(raw);
        assert!(
            matches!(
                sbc.route(dialed.as_str(), Some("css")),
                SbcRouteOutcome::Blocked { .. }
            ),
            "{raw}"
        );
    }
    let ok = DialedNumber::parse("+1-202-555-0100");
    assert!(matches!(
        sbc.route(ok.as_str(), Some("css")),
        SbcRouteOutcome::Routed(_)
    ));
}

fn dial_plan_toml(pattern_type: &str, extra: &str) -> String {
    format!(
        "[routing]\ndefault_trunk_group = \"carriers\"\n{GROUPS}\n\
         [[dial_plans]]\nid = \"main\"\nname = \"Main\"\nactive = true\n\
         [[dial_plans.entries]]\ndirection = \"inbound\"\npattern_type = \"{pattern_type}\"\n\
         pattern_value = \"1\"\ntrunk_group = \"carriers\"\n{extra}"
    )
}

#[test]
fn qa_unknown_pattern_type_rejected_at_config_load() {
    for bad in ["regex", "bogus", "Prefix", "EXACT", "", " prefix"] {
        let err = load_from_str(&dial_plan_toml(bad, ""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown pattern_type"), "{bad}: {err}");
    }
    for ok in ["exact", "prefix", "wildcard", "any"] {
        assert!(load_from_str(&dial_plan_toml(ok, "")).is_ok(), "{ok}");
    }
}

#[test]
fn qa_source_trunk_trunk_id_resolves_and_unknown_warns() {
    let cfg = load_from_str(&dial_plan_toml("prefix", "source_trunk = \"c1\"\n")).unwrap();
    assert_eq!(
        sbc_config::validate::resolve_source_trunk(&cfg, "c1"),
        Some("carriers")
    );
    assert_eq!(
        sbc_config::validate::routing_warnings(&cfg),
        Vec::<String>::new()
    );
    let cfg = load_from_str(&dial_plan_toml("prefix", "source_trunk = \"ghost\"\n")).unwrap();
    let w = sbc_config::validate::routing_warnings(&cfg);
    assert_eq!(w.len(), 1, "{w:?}");
}

#[test]
fn qa_emergency_forms_are_not_blocked_by_canonical_key_mismatch() {
    // An exact `911` route pattern matches every textual emergency form
    // after canonicalisation; `+1911` does not.
    let mut sbc = SbcRouter::new();
    sbc.add_partition(Partition::new("pt", "Pt"));
    sbc.add_route_pattern(
        RoutePattern::new("rp-911", DialPattern::exact("911"), "pt").with_route_group("e911"),
    );
    let mut css = CallingSearchSpace::new("css", "Css");
    css.add_partition("pt");
    sbc.add_css(css);
    for raw in ["911", "9-1-1", "(911)", "%39%31%31", "911;phone-context=+1"] {
        let n = DialedNumber::parse(raw);
        assert!(
            sbc.route(n.as_str(), Some("css")).routed().is_some(),
            "{raw}"
        );
    }
    for raw in ["+1911", "9111", "alice"] {
        let n = DialedNumber::parse(raw);
        assert!(
            matches!(sbc.route(n.as_str(), Some("css")), SbcRouteOutcome::NoMatch),
            "{raw}"
        );
    }
}
