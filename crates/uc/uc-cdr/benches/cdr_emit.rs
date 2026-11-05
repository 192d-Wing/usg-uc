//! `cdr_emit`: the call-path cost of handing a CDR to the writer (plan §4,
//! target < 1 µs per call end), plus the writer-side seal + format cost.
// POAM: PERF-3 no INVITE/BYE-path bench (CdrDraft::record_answer with a
// realistic SDP, emit_call/emit_rejected).
#![allow(missing_docs, clippy::unwrap_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use uc_cdr::{CallRecord, CdrEmitter, CdrEmitterConfig, Disposition, TrunkAttempt, TrunkOutcome};

fn record() -> CallRecord {
    CallRecord {
        a_call_id: "a3c1f0e2-77aa-4d1b@10.0.0.1".into(),
        b_call_ids: vec!["b-1@sbc".into()],
        internal_call_id: "int-1".into(),
        caller: "+12025550100".into(),
        callee_dialed: "+15551234567".into(),
        callee_translated: Some("5551234567".into()),
        source_ip: "10.0.0.1".into(),
        trunk_group: Some("carriers".into()),
        trunks_tried: vec![TrunkAttempt {
            trunk_id: "t1".into(),
            status: TrunkOutcome::Status(200),
            at_ms: 1,
        }],
        final_trunk: Some("t1".into()),
        codec: Some("PCMU".into()),
        disposition: Disposition::Answered,
        final_sip_status: 200,
        ..Default::default()
    }
}

fn bench(c: &mut Criterion) {
    // Ring-only emitter with the max queue so try_send never hits Full
    // during the measurement; this isolates the producer-side cost.
    let em = CdrEmitter::start(
        CdrEmitterConfig {
            file: None,
            queue_capacity: 1_000_000,
            ring_capacity: 0,
            ..CdrEmitterConfig::default()
        },
        Vec::new(),
        None,
    )
    .unwrap();
    let r = record();
    c.bench_function("cdr_emit_try_send", |b| {
        b.iter(|| black_box(em.emit(black_box(r.clone()))));
    });
    c.bench_function("cdr_record_clone_baseline", |b| {
        b.iter(|| black_box(black_box(&r).clone()));
    });
    c.bench_function("cdr_seal_and_json_line", |b| {
        let prev = [0u8; 48];
        b.iter(|| {
            let mut x = r.clone();
            uc_cdr::chain::seal(&mut x, &prev).unwrap();
            black_box(uc_cdr::format::to_json_line(&x).unwrap())
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
