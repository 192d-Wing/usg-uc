# Voice Protection System (VPS) Architecture

Status: Phase 1 implemented (`uc-vps` crate + pre-routing INVITE screening in
`sbc-daemon`). Phases 2–4 are design targets.

## What a VPS is

In the DoD UC context a Voice Protection System (DoDIN APL product category)
is a voice firewall / IPS for the telephony service. It provides:

1. **Inline call policy enforcement** — allow/deny/divert decisions per call
   attempt based on caller, callee, source, time, and trust signals.
2. **TDoS and toll-fraud mitigation** — call-level (not just packet-level)
   rate limiting, concurrency caps, and dynamic blocking.
3. **Media-plane policing** — only relay RTP that matches the negotiated
   session.
4. **Detection, alerting, and compliance reporting** — every decision is
   auditable and feeds CDR analytics.

Because this SBC is a B2BUA that terminates and re-originates every call and
anchors all media, the VPS is implemented *natively* as a screening layer
inside `sbc-daemon` rather than as a separate inline appliance. An optional
standalone deployment mode is a future consideration if independent
certification of the VPS function is required (see "Certification boundary"
below).

## Component overview

```
                       ┌──────────────────────────────────────────┐
                       │                sbc-daemon                │
   SIP (UDP/TCP/TLS)   │  ┌─────────┐   ┌─────────┐   ┌────────┐  │
  ────────────────────▶│  │ packet  │──▶│  VPS    │──▶│ B2BUA/ │  │
   trunks / clients    │  │ rate-   │   │ screen  │   │ routing│  │
                       │  │ limit   │   │ (hook 2)│   │        │  │
                       │  │ (hook 1)│   └────┬────┘   └───┬────┘  │
                       │  └─────────┘        │            │       │
   RTP/SRTP            │  ┌──────────────────┴───┐   ┌────▼────┐  │
  ────────────────────▶│  │ media policing       │   │ CDR +   │  │
                       │  │ (hook 3, phase 2)    │   │ audit   │  │
                       │  └──────────────────────┘   │ (hook 4)│  │
                       └─────────────────────────────┴────┬─────┘ │
                                                          │
                              VpsPolicySync (gRPC, phase 3) ▲
                                                          │
                                              ┌───────────┴────────────┐
                                              │ usg-sbc-vps-analytics  │
                                              │ (CDR stream consumer,  │
                                              │  phase 3)              │
                                              └────────────────────────┘
```

### The four hook points

| # | Hook | Location | Function |
|---|------|----------|----------|
| 1 | Ingress packet | `crates/sbc/sbc-daemon/src/server.rs` (existing `uc-dos-protection` per-IP + global limiters) | Packet-level flood shedding. Pre-dates the VPS; unchanged. |
| 2 | Pre-routing call screening | `crates/sbc/sbc-daemon/src/sip_stack.rs` `handle_invite()`, after admission/loop checks, before destination lookup | `VpsEngine::screen_call()` — blocklist, call-level rate limits, concurrency caps, STIR/SHAKEN screening, declarative policy rules. |
| 3 | Media setup | `crates/sbc/sbc-daemon/src/media_pipeline.rs` (phase 2) | Only relay RTP from the negotiated remote address/port; drop unexpected SSRC/payload types; cap per-call bandwidth to the negotiated codec. |
| 4 | Call teardown / CDR emit | `uc-cdr` record assembly (phase 2) | Stamp the VPS verdict (action, rule ID, verdict source) into the CDR and `uc-audit` stream. |

## The `uc-vps` crate

`crates/uc/uc-vps` composes existing infrastructure rather than reinventing
it:

- **`VpsEngine`** (`engine.rs`) — the single entry point. Evaluation order
  for `screen_call()`:
  1. Dynamic **blocklist** (source IP, caller-number prefix) — feeds from
     config now, from analytics push in phase 3.
  2. **Call-level rate limit** — per-source INVITE CPS token buckets
     (reuses `uc_dos_protection::RateLimiter`). Sustained abuse escalates to
     a timed block; blocked sources get `Drop` (no response — answering a
     spoofed flood is amplification).
  3. **Per-callee concurrency cap** — bounds concurrent calls to any single
     DID (TDoS against a hotline/operator number). Requires
     `call_started()`/`call_ended()` accounting (daemon wiring in phase 2).
  4. **STIR/SHAKEN screening** — for inbound trunk calls, optionally require
     verification at a minimum attestation level (`proto-stir-shaken`
     produces the verdict; the engine consumes it via
     `CallAttempt::stir_shaken`). `log-only` mode for staged rollout;
     `enforce` rejects with 438 Bad Identity-Info.
  5. **Declarative policy rules** — config-defined rules (caller/callee
     prefix, source IP, time-of-day, day-of-week) compiled into
     `uc_policy::PolicyEngine` rules at startup. First match in priority
     order wins.
  6. **Default action** — allow (default) or deny.

- **`CallAttempt`** (`context.rs`) — what the daemon hands the engine:
  source IP, caller/callee numbers, URIs, call direction (trunk-inbound vs.
  internal), STIR/SHAKEN status.

- **`VpsVerdict`** (`verdict.rs`) — what comes back: `Allow`,
  `Reject { status_code, reason }`, or `Drop`, plus the verdict source and
  matched rule ID for logging/CDR stamping.

- **`CallLimiter`** (`call_limiter.rs`) — call-level TDoS counters: INVITE
  CPS per source, REGISTER rate per source, concurrent calls per callee.

- **`Blocklist`** (`blocklist.rs`) — dynamic block entries (source IPs and
  caller-number prefixes) with optional expiry. The mutation API
  (`block_source()`, `block_caller_prefix()`, …) is the surface the phase-3
  `VpsPolicySync` gRPC service will drive.

### Configuration

A `[vps]` section in the SBC config (`sbc-config` re-exports
`uc_vps::VpsConfig`, same pattern as `TelemetryConfig`). Disabled unless
explicitly enabled.

```toml
[vps]
enabled = true
default_action = "allow"

[vps.tdos]
per_source_cps = 5            # INVITE calls/sec per source IP
per_source_burst = 10
register_per_source_rps = 10
register_burst = 20
block_duration_secs = 300     # timed block on sustained abuse
per_callee_max_concurrent = 0 # 0 = unlimited (phase 2 enforcement)

[vps.stir_shaken]
mode = "off"                  # off | log-only | enforce
minimum_attestation = "C"     # A | B | C

[[vps.rules]]
id = "block-premium-rate"
description = "No 900-number calls"
callee_prefix = "1900"
action = "deny"
status_code = 403
reason = "Premium-rate calls are not permitted"

[[vps.rules]]
id = "after-hours-international"
description = "Block international outside duty hours"
callee_prefix = "011"
time_start_hour = 18
time_end_hour = 6
action = "deny"
```

## Phasing

**Phase 1 (this change):**
- `uc-vps` crate: engine, blocklist, call-level limiter, declarative rules,
  STIR/SHAKEN screening logic, config schema + validation.
- `[vps]` config section in `sbc-config`.
- Daemon hook 2: `screen_call()` in `handle_invite()` pre-routing. Verdicts
  are logged with rule ID and verdict source.

**Phase 2 — full enforcement + accounting:**
- Wire `call_started()`/`call_ended()` at B2BUA call creation/teardown so
  per-callee concurrency caps enforce.
- `screen_register()` hook in REGISTER handling.
- Media policing (hook 3): source-address/SSRC/payload-type filtering and
  bandwidth caps in the media pipeline.
- Stamp `VpsVerdict` into `uc-cdr` records and `uc-audit` events.
- Prometheus metrics for screened/rejected counts by verdict source.

**Phase 3 — detection loop:**
- `usg-sbc-vps-analytics` pod consuming the CDR stream: toll-fraud
  signatures (international bursts, sequential-number scanning,
  short-duration call storms), per-DID baselines, after-hours anomaly
  flagging.
- `VpsPolicySync` gRPC service on the daemon (same push pattern as
  `TrunkSync`/`DialPlanSync`) so analytics can install timed blocklist
  entries and threshold overrides. Cluster-wide propagation via
  `uc-storage` (Redis) so all nodes converge.
- Alerting through existing channels: Prometheus alerts, `uc-syslog`,
  `uc-snmp`.

**Phase 4 — management surface:**
- VPS rule CRUD in `sbc-api-server` (Postgres-backed via
  `sbc-config-store`), pushed to daemons over `VpsPolicySync`.
- `sbc-dashboard` panel: screened/blocked call counts, active mitigations,
  rule hit rates.

## Certification boundary

If DoDIN APL listing or JITC testing of the VPS function *independently of
the SBC* is ever required, the same `uc-vps` engine can be hosted in a
standalone stateless SIP proxy pod deployed inline on the outside zone. The
engine API is deliberately transport-agnostic (it sees `CallAttempt`, not
SIP messages) to keep that option open. Until then, the VPS ships as part of
the SBC's security posture under a single ATO.

## NIST 800-53 Rev5 mapping

| Control | VPS function |
|---------|--------------|
| AC-3 (Access Enforcement) | Policy rules, default-deny option |
| AC-4 (Information Flow Enforcement) | Direction-aware screening, trunk vs. internal |
| SC-5 (Denial of Service Protection) | Call-level rate limits, concurrency caps, blocklist |
| SI-4 (System Monitoring) | Verdict logging, phase-3 analytics |
| AU-2 / AU-3 (Audit Events / Content) | Verdict stamping into CDR and audit stream (phase 2) |
