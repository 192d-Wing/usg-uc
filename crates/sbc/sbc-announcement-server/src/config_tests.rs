//! SR-41 QA: pod configuration (`crate::config`). Parsed through
//! `Config::from_lookup`, the env-free core of `Config::from_env`, so tests
//! do not race on the process environment.
//!
//! ## NIST 800-53 Rev5: CM-6, CM-7, IA-3, SC-5, SC-7

use std::collections::HashMap;
use std::time::Duration;

use crate::config::{Config, MAX_INITIAL_DELAY_MS};

/// Minimal valid loopback configuration plus `extra` overrides (an empty
/// value removes the key).
fn env(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = [
        ("SBC_ANN_GRPC_LISTEN", "127.0.0.1:9095"),
        ("SBC_ANN_ADVERTISED_IP", "203.0.113.9"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        if v.is_empty() {
            m.remove(*k);
        } else {
            m.insert((*k).to_string(), (*v).to_string());
        }
    }
    m
}

fn parse(extra: &[(&str, &str)]) -> Result<Config, String> {
    let m = env(extra);
    Config::from_lookup(|k: &str| m.get(k).cloned())
}

fn err_naming(extra: &[(&str, &str)], needle: &str) {
    match parse(extra) {
        Ok(c) => panic!("{extra:?} must be refused (naming {needle}), got {c:?}"),
        Err(e) => assert!(
            e.contains(needle),
            "{extra:?}: error should name {needle}: {e}"
        ),
    }
}

const TLS: [(&str, &str); 3] = [
    ("SBC_ANN_GRPC_TLS_CERT_FILE", "/etc/ann/tls.crt"),
    ("SBC_ANN_GRPC_TLS_KEY_FILE", "/etc/ann/tls.key"),
    ("SBC_ANN_GRPC_TLS_CLIENT_CA_FILE", "/etc/ann/ca.crt"),
];

#[test]
fn qa_non_loopback_listen_without_tls_fails() {
    // Default listen (0.0.0.0:9095) without certificates: refuse to start.
    err_naming(&[("SBC_ANN_GRPC_LISTEN", "")], "SBC_ANN_GRPC_LISTEN");
    for a in ["0.0.0.0:9095", "[::]:9095", "10.1.2.3:9095"] {
        err_naming(&[("SBC_ANN_GRPC_LISTEN", a)], "SBC_ANN_GRPC_LISTEN");
        // mTLS alone is not enough off loopback: the SAN allow-list is required.
        let mut with_tls: Vec<(&str, &str)> = TLS.to_vec();
        with_tls.push(("SBC_ANN_GRPC_LISTEN", a));
        err_naming(&with_tls, "SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES");
        with_tls.push(("SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES", "sbc-sbc-daemon"));
        let c = parse(&with_tls).unwrap_or_else(|e| panic!("{a} with mTLS: {e}"));
        assert!(c.grpc_tls.is_some());
        assert_eq!(c.allowed_client_names, vec!["sbc-sbc-daemon".to_string()]);
    }
    // Loopback plaintext stays allowed (lab, tests).
    let c = parse(&[]).expect("loopback plaintext");
    assert!(c.grpc_tls.is_none());
}

#[test]
fn qa_tls_partial_set_fails() {
    for drop in 0..3 {
        let mut v: Vec<(&str, &str)> = TLS.to_vec();
        v[drop].1 = "";
        v.push(("SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES", "sbc-sbc-daemon"));
        err_naming(&v, "SBC_ANN_GRPC_TLS");
    }
}

#[test]
fn qa_allow_list_without_tls_fails() {
    err_naming(
        &[("SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES", "sbc-sbc-daemon")],
        "SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES",
    );
}

#[test]
fn qa_caps_parse_and_bounds() {
    let c = parse(&[]).expect("defaults");
    assert_eq!(c.max_plays, 128);
    // Orchestrator decision Q3: default per-destination cap is 32.
    assert_eq!(c.max_plays_per_dest, 32);
    assert_eq!(c.max_play, Duration::from_secs(30));

    let c = parse(&[
        ("SBC_ANN_MAX_PLAYS", "4096"),
        ("SBC_ANN_MAX_PLAYS_PER_DEST", "4096"),
        ("SBC_ANN_MAX_PLAY_SECS", "120"),
    ])
    .expect("upper bounds");
    assert_eq!(
        (c.max_plays, c.max_plays_per_dest, c.max_play),
        (4096, 4096, Duration::from_secs(120))
    );
    let c = parse(&[
        ("SBC_ANN_MAX_PLAYS", "1"),
        ("SBC_ANN_MAX_PLAYS_PER_DEST", "1"),
        ("SBC_ANN_MAX_PLAY_SECS", "1"),
    ])
    .expect("lower bounds");
    assert_eq!(
        (c.max_plays, c.max_plays_per_dest, c.max_play),
        (1, 1, Duration::from_secs(1))
    );

    for v in ["0", "4097", "-1", "abc", "1.5"] {
        err_naming(&[("SBC_ANN_MAX_PLAYS", v)], "SBC_ANN_MAX_PLAYS");
    }
    for v in ["0", "abc"] {
        err_naming(
            &[("SBC_ANN_MAX_PLAYS_PER_DEST", v)],
            "SBC_ANN_MAX_PLAYS_PER_DEST",
        );
    }
    // Per-destination cap may not exceed the global cap.
    err_naming(
        &[
            ("SBC_ANN_MAX_PLAYS", "16"),
            ("SBC_ANN_MAX_PLAYS_PER_DEST", "17"),
        ],
        "SBC_ANN_MAX_PLAYS_PER_DEST",
    );
    // The per-destination default (32) is clamped or refused, never above a
    // smaller global cap.
    if let Ok(c) = parse(&[("SBC_ANN_MAX_PLAYS", "8")]) {
        assert!(c.max_plays_per_dest <= 8, "{c:?}");
    }
    for v in ["0", "121", "abc"] {
        err_naming(&[("SBC_ANN_MAX_PLAY_SECS", v)], "SBC_ANN_MAX_PLAY_SECS");
    }
}

#[test]
fn qa_allow_loopback_dest_flag() {
    assert!(!parse(&[]).expect("default").dest_policy.allow_loopback);
    assert!(
        parse(&[("SBC_ANN_ALLOW_LOOPBACK_DEST", "true")])
            .expect("true")
            .dest_policy
            .allow_loopback
    );
    assert!(
        !parse(&[("SBC_ANN_ALLOW_LOOPBACK_DEST", "false")])
            .expect("false")
            .dest_policy
            .allow_loopback
    );
    for v in ["1", "yes", "on", "maybe"] {
        err_naming(
            &[("SBC_ANN_ALLOW_LOOPBACK_DEST", v)],
            "SBC_ANN_ALLOW_LOOPBACK_DEST",
        );
    }
}

#[test]
fn qa_cidrs_parse_bounded() {
    assert!(parse(&[]).expect("default").dest_policy.allowed.is_empty());
    let c = parse(&[(
        "SBC_ANN_ALLOWED_DEST_CIDRS",
        " 10.0.0.0/8 , 2001:db8::/32 ,",
    )])
    .expect("two CIDRs");
    let got: Vec<String> = c
        .dest_policy
        .allowed
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        got,
        vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()]
    );

    for v in [
        "10.0.0.0/33",
        "garbage",
        "10.0.0.0/8;192.0.2.0/24",
        "2001:db8::/129",
    ] {
        err_naming(
            &[("SBC_ANN_ALLOWED_DEST_CIDRS", v)],
            "SBC_ANN_ALLOWED_DEST_CIDRS",
        );
    }
    let list = |n: usize| -> String {
        (0..n)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect::<Vec<_>>()
            .join(",")
    };
    let ok = list(256);
    assert_eq!(
        parse(&[("SBC_ANN_ALLOWED_DEST_CIDRS", &ok)])
            .expect("256 entries")
            .dest_policy
            .allowed
            .len(),
        256
    );
    let too_many = list(257);
    err_naming(
        &[("SBC_ANN_ALLOWED_DEST_CIDRS", &too_many)],
        "SBC_ANN_ALLOWED_DEST_CIDRS",
    );
}

#[test]
fn qa_default_delay_over_max_fails() {
    assert_eq!(MAX_INITIAL_DELAY_MS, 2000);
    assert_eq!(parse(&[]).expect("default").default_delay_ms, 200);
    assert_eq!(
        parse(&[("SBC_ANN_DEFAULT_DELAY_MS", "2000")])
            .expect("at max")
            .default_delay_ms,
        2000
    );
    // Over the cap, or unparseable: refused, no longer silently ignored.
    for v in ["2001", "4294967295", "abc", "-5"] {
        err_naming(
            &[("SBC_ANN_DEFAULT_DELAY_MS", v)],
            "SBC_ANN_DEFAULT_DELAY_MS",
        );
    }
}
