//! Request-path cost bounds under load (SR-20, SR-21, SR-24).
//!
//! - SR-20: the server transaction maps are capped (503 + Retry-After past
//!   the cap) and the backstop age sweep runs at most once per interval,
//!   so an insert is O(1) whatever the table size.
//! - SR-21: INVITE source admission does not scan the registrations.
//! - SR-24: trunk host names are resolved before the inbound trunk map lock
//!   is taken, so a slow resolver does not stall admission.
//!
//! ## NIST 800-53 Rev5: SC-5

use super::*;

fn src(port: u16) -> SbcSocketAddr {
    SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(198, 51, 100, 20), port)
}

fn flatten(result: ProcessResult) -> Vec<ProcessResult> {
    match result {
        ProcessResult::Multiple(v) => v.into_iter().flat_map(flatten).collect(),
        ProcessResult::NoAction => Vec::new(),
        other => vec![other],
    }
}

/// Status codes of the responses in `result`.
fn statuses(result: ProcessResult) -> Vec<u16> {
    flatten(result)
        .into_iter()
        .filter_map(|r| match r {
            ProcessResult::Response {
                message: SipMessage::Response(resp),
                ..
            } => Some(resp.status.code()),
            _ => None,
        })
        .collect()
}

/// The `Retry-After` of the 503 in `result` (`"none"` when it has none);
/// `None` without a 503.
fn retry_after_503(result: ProcessResult) -> Option<String> {
    flatten(result).into_iter().find_map(|r| match r {
        ProcessResult::Response {
            message: SipMessage::Response(resp),
            ..
        } if resp.status.code() == 503 => Some(
            resp.headers
                .get_value(&HeaderName::RetryAfter)
                .map_or_else(|| "none".to_string(), str::to_string),
        ),
        _ => None,
    })
}

/// A request of `method` to `ruri` from port 5060 of [`src`], branch `n`;
/// `to_tag` makes it in-dialog.
fn request(method: &str, ruri: &str, n: usize, to_tag: Option<&str>) -> Bytes {
    let s = src(5060);
    let to_tag = to_tag.map_or_else(String::new, |t| format!(";tag={t}"));
    let contact = if method == "INVITE" {
        "Contact: <sip:caller@198.51.100.20:5060>\r\n"
    } else {
        ""
    };
    Bytes::from(format!(
        "{method} {ruri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {s};branch=z9hG4bK-load-{n}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:caller@sbc.local>;tag=f-{n}\r\n\
         To: <{ruri}>{to_tag}\r\n\
         Call-ID: load-{n}@test\r\n\
         CSeq: 1 {method}\r\n\
         {contact}\
         Content-Length: 0\r\n\r\n"
    ))
}

fn options(n: usize) -> Bytes {
    request("OPTIONS", "sip:sbc.local", n, None)
}

/// An out-of-dialog MESSAGE (405 from the SBC; opens a server
/// non-INVITE transaction).
fn message(n: usize) -> Bytes {
    request("MESSAGE", "sip:bob@sbc.local", n, None)
}

fn capped_stack(cap: usize) -> SipStack {
    SipStack::new(SipStackConfig {
        max_server_transactions: cap,
        ..SipStackConfig::default()
    })
}

// ----------------------------------------------------------------------
// SR-20: server transaction cap and rate-limited sweep
// ----------------------------------------------------------------------

/// Past the cap a new non-INVITE gets 503 + Retry-After and opens nothing;
/// a retransmission of an open transaction is still answered from it.
#[tokio::test]
async fn non_invite_past_cap_gets_503_with_retry_after() {
    let cap = 8;
    let stack = capped_stack(cap);
    for n in 0..cap {
        let codes = statuses(stack.process_message(&message(n), src(5060), None).await);
        assert_eq!(codes, vec![405], "MESSAGE {n}");
    }
    let r = stack.process_message(&message(cap), src(5060), None).await;
    assert_eq!(
        retry_after_503(r),
        Some(TRANSACTION_TABLE_RETRY_AFTER_SECS.to_string())
    );
    assert_eq!(stack.transactions.read().await.server_non_invite.len(), cap);
    assert_eq!(
        stack
            .routing_counters()
            .transaction_table_full
            .load(Ordering::Relaxed),
        1
    );
    // A retransmission is answered from its transaction, not refused.
    let codes = statuses(stack.process_message(&message(0), src(5060), None).await);
    assert_eq!(codes, vec![405]);
}

/// OPTIONS opens no server transaction, so an OPTIONS flood cannot fill
/// the table, and OPTIONS is still answered when the table is full.
#[tokio::test]
async fn options_open_no_transaction_and_are_answered_when_full() {
    let cap = 4;
    let stack = capped_stack(cap);
    for n in 0..100 {
        let codes = statuses(stack.process_message(&options(n), src(5060), None).await);
        assert_eq!(codes, vec![200], "OPTIONS {n}");
    }
    assert!(stack.transactions.read().await.server_non_invite.is_empty());
    for n in 0..cap {
        stack.process_message(&message(n), src(5060), None).await;
    }
    let codes = statuses(stack.process_message(&options(1000), src(5060), None).await);
    assert_eq!(codes, vec![200]);
    assert_eq!(
        stack
            .routing_counters()
            .transaction_table_full
            .load(Ordering::Relaxed),
        0
    );
}

/// With the non-INVITE map full, a CANCEL and an in-dialog BYE are processed
/// statelessly (their usual answer, here 481), never the table 503.
#[tokio::test]
async fn cancel_and_in_dialog_bye_are_stateless_when_full() {
    let cap = 4;
    let stack = capped_stack(cap);
    for n in 0..cap {
        stack.process_message(&message(n), src(5060), None).await;
    }
    let bye = request("BYE", "sip:callee@sbc.local", 100, Some("t-1"));
    let codes = statuses(stack.process_message(&bye, src(5060), None).await);
    assert!(!codes.contains(&503), "{codes:?}");
    assert!(codes.contains(&481), "{codes:?}");
    let cancel = request("CANCEL", "sip:callee@sbc.local", 101, None);
    let codes = statuses(stack.process_message(&cancel, src(5060), None).await);
    assert!(!codes.contains(&503), "{codes:?}");
    // Neither opened a transaction past the cap.
    assert_eq!(stack.transactions.read().await.server_non_invite.len(), cap);
    assert_eq!(
        stack
            .routing_counters()
            .transaction_table_full
            .load(Ordering::Relaxed),
        2
    );
}

/// Past the INVITE cap a new INVITE gets the table 503; an emergency INVITE
/// still opens its transaction (it uses the emergency headroom).
#[tokio::test]
async fn invite_past_cap_gets_503_but_emergency_uses_headroom() {
    let cap = 4;
    let stack = capped_stack(cap);
    // Unadmitted INVITEs (403) keep their transaction until Timer H.
    for n in 0..cap {
        let inv = request("INVITE", "sip:bob@sbc.local", n, None);
        stack.process_message(&inv, src(5060), None).await;
    }
    assert_eq!(stack.transactions.read().await.server_invite.len(), cap);
    let inv = request("INVITE", "sip:bob@sbc.local", cap, None);
    let r = stack.process_message(&inv, src(5060), None).await;
    assert_eq!(
        retry_after_503(r),
        Some(TRANSACTION_TABLE_RETRY_AFTER_SECS.to_string())
    );
    let sos = request("INVITE", "sip:911@sbc.local", cap + 1, None);
    stack.process_message(&sos, src(5060), None).await;
    assert_eq!(stack.transactions.read().await.server_invite.len(), cap + 1);
    assert_eq!(
        stack
            .routing_counters()
            .transaction_table_full
            .load(Ordering::Relaxed),
        1
    );
}

/// A server non-INVITE transaction created at `created_at`, for the store
/// tests.
fn nict_state(n: usize, created_at: Instant) -> (TransactionKey, ServerNonInviteState) {
    let key = TransactionKey::server(format!("z9hG4bK-sweep-{n}"), "OPTIONS");
    let ingress = Ingress {
        source: src(5060),
        transport: AddrTransport::Udp,
        conn: None,
    };
    (
        key.clone(),
        ServerNonInviteState {
            transaction: ServerNonInviteTransaction::new(key, txn_transport(AddrTransport::Udp)),
            source: src(5060),
            created_at,
            last_response: None,
            opened_by: ingress,
        },
    )
}

/// Scaling check: once the table is past the sweep threshold, any number of
/// inserts within one interval costs one full pass, not one per insert
/// (the pre-fix behaviour was a pass per insert, O(n²) per interval).
#[test]
fn sweep_runs_at_most_once_per_interval() {
    let mut store = TransactionStore::default();
    let t0 = Instant::now();
    let big = TransactionStore::SWEEP_THRESHOLD * 4;
    for n in 0..big {
        let (k, v) = nict_state(n, t0);
        store.server_non_invite.insert(k, v);
    }
    let mut passes = 0;
    for i in 0..10_000_u32 {
        let now = t0 + std::time::Duration::from_micros(u64::from(i) * 50);
        if store.sweep_if_needed_at(now) {
            passes += 1;
        }
    }
    assert_eq!(passes, 1, "10k inserts in 0.5 s: one sweep");
    let later = t0 + TransactionStore::SWEEP_INTERVAL + std::time::Duration::from_millis(1);
    assert!(
        store.sweep_if_needed_at(later),
        "next interval sweeps again"
    );
    assert!(!store.sweep_if_needed_at(later));
}

/// The rate-limited sweep still drops entries past `MAX_AGE` and keeps
/// young ones; below the threshold it does not run.
#[test]
fn sweep_drops_only_stale_entries() {
    let mut store = TransactionStore::default();
    let t0 = Instant::now();
    let n = TransactionStore::SWEEP_THRESHOLD + 1;
    for i in 0..n {
        let (k, v) = nict_state(i, t0);
        store.server_non_invite.insert(k, v);
    }
    // Young: swept but kept.
    assert!(store.sweep_if_needed_at(t0));
    assert_eq!(store.server_non_invite.len(), n);
    let old = t0 + TransactionStore::MAX_AGE + std::time::Duration::from_secs(1);
    assert!(store.sweep_if_needed_at(old));
    assert!(store.server_non_invite.is_empty());
    // Below the threshold: never runs.
    let (k, v) = nict_state(0, t0);
    store.server_non_invite.insert(k, v);
    let much_later = old + TransactionStore::SWEEP_INTERVAL * 2;
    assert!(!store.sweep_if_needed_at(much_later));
    assert_eq!(store.server_non_invite.len(), 1);
}

// ----------------------------------------------------------------------
// SR-21: admission does not scan the registrations
// ----------------------------------------------------------------------

/// A stack holding `n` registrations (bindings and flow index), none of
/// them from [`src`]'s address.
async fn stack_with_registrations(n: u16) -> SipStack {
    let stack = SipStack::new(SipStackConfig::default());
    {
        let mut loc = stack.location_service.write().await;
        for i in 0..n {
            let port = 10_000 + i;
            loc.add_binding(proto_registrar::Binding::new(
                format!("sip:u{i}@sbc.local"),
                format!("sip:u{i}@203.0.113.50:{port};transport=udp"),
                format!("seed-{i}@test"),
                1,
            ))
            .unwrap();
        }
    }
    for i in 0..n {
        let at = SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 50), 10_000 + i);
        stack
            .index_stir_flow(&format!("sip:u{i}@sbc.local"), at, AddrTransport::Udp, None)
            .await;
    }
    stack
}

/// Best-of-five time for `rounds` admissions of an unknown source.
async fn unknown_source_cost(stack: &SipStack, rounds: u32) -> std::time::Duration {
    let ingress = Ingress {
        source: src(40_000),
        transport: AddrTransport::Udp,
        conn: None,
    };
    let mut best = std::time::Duration::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..rounds {
            let a = stack.admit_invite_source(&ingress).await;
            assert!(matches!(a, SourceAdmission::Denied(_)));
        }
        best = best.min(t.elapsed());
    }
    best
}

/// Scaling check: admitting (denying) an unknown source costs about the same
/// with 100 or 20 000 registrations. The pre-fix scan parsed every Contact,
/// a 200x ratio here; the bound leaves a wide margin for timer noise.
#[tokio::test]
async fn unknown_source_admission_cost_is_flat_in_registrations() {
    let small = stack_with_registrations(100).await;
    let large = stack_with_registrations(20_000).await;
    let rounds = 2_000;
    let small_cost = unknown_source_cost(&small, rounds).await;
    let large_cost = unknown_source_cost(&large, rounds).await;
    let ratio = large_cost.as_secs_f64() / small_cost.as_secs_f64().max(1e-9);
    assert!(
        ratio < 20.0,
        "admission cost grew {ratio:.1}x from 100 to 20000 registrations \
         ({small_cost:?} vs {large_cost:?} for {rounds} rounds)"
    );
}

// ----------------------------------------------------------------------
// SR-24: trunk resolution runs before the trunk map lock
// ----------------------------------------------------------------------

/// While a trunk sync's name resolution is blocked, the inbound trunk map
/// is free (admission and the per-user limiter's trunk check proceed); the
/// group's sources land once resolution finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trunk_map_lock_not_held_during_resolution() {
    let stack = Arc::new(SipStack::new(SipStackConfig::default()));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let resolver = move |host: &str| -> Vec<std::net::IpAddr> {
        assert_eq!(host, "slow.carrier.test");
        entered_tx.send(()).unwrap();
        // Blocks like a getaddrinfo waiting on a slow DNS server.
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        vec![std::net::IpAddr::from([203, 0, 113, 77])]
    };
    let sync = {
        let stack = Arc::clone(&stack);
        tokio::spawn(async move {
            stack
                .register_inbound_trunk_with(
                    "slow",
                    None,
                    &[("slow.carrier.test".to_string(), AddrTransport::Udp)],
                    resolver,
                )
                .await;
        })
    };
    tokio::task::spawn_blocking(move || {
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
    })
    .await
    .unwrap();

    // Resolution is in progress: the map is not locked.
    assert!(stack.inbound_trunk_map.try_write().is_ok());
    let ingress = Ingress {
        source: SbcSocketAddr::new_v4(std::net::Ipv4Addr::new(203, 0, 113, 77), 5060),
        transport: AddrTransport::Udp,
        conn: None,
    };
    let admitted = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stack.admit_invite_source(&ingress),
    )
    .await
    .expect("admission does not wait on resolution");
    assert!(matches!(admitted, SourceAdmission::Denied(_)));
    assert!(!sync.is_finished());

    release_tx.send(()).unwrap();
    sync.await.unwrap();
    assert!(matches!(
        stack.admit_invite_source(&ingress).await,
        SourceAdmission::Trunk(..)
    ));
}
