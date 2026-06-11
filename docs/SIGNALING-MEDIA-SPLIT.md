# Signaling / Media Split — Design Exploration

Status: **design exploration** (not scheduled). This document examines
splitting `sbc-daemon` into a signaling pod and N media-relay pods — the
standard carrier SBC scale-out architecture (Kamailio + RTPEngine,
OpenSIPS + MediaProxy, Cisco distributed SBC). It builds on the
already-completed extractions: `sbc-api-server`, `sbc-provision-server`,
`sbc-client-config-server`, `sbc-announcement-server`, and
`sbc-trunk-agent`.

## 1. Why (and why not)

A SIP B2BUA's two halves scale very differently:

| | Signaling | Media relay |
| --- | --- | --- |
| Bottleneck | CPU (parsing, transactions, auth), memory (dialog state) | NIC bandwidth, packets/sec, UDP port space |
| Per-call cost | ~KBs of state, bursts at setup/teardown | ~50 pps × 2 legs × call duration, continuous |
| Placement | Anywhere with the VIP | Wants to be near the network edge / on beefy NICs |
| Capacity ceiling today | Thousands of calls | The single pod's NIC + the 16384–32768 port range (~8 000 RTP/RTCP pairs, in practice far fewer per NIC) |

**Split when** any of these become true:

- Concurrent media sessions approach what one host's NIC / port range
  sustains, while signaling CPU sits idle (or vice versa).
- Media needs to terminate in multiple POPs/zones while one logical
  signaling brain runs centrally.
- Media-pipeline crashes or deploys are taking signaling down with them
  (a relay restart should drop only the calls it carries — and with
  re-INVITE-based re-anchoring, eventually none).

**Don't split before then.** The split adds an RPC on the INVITE hot
path, a distributed failure mode for every call, and a second deployable
that must be version-coordinated with the daemon. A single process doing
both is strictly simpler to operate and debug — which is why the current
`sbc-daemon` shape is right for today's deployments.

## 2. What couples the two halves today

All references are to `crates/sbc/sbc-daemon/src/`.

1. **Call state correlation.** The B2BUA call store and the A-leg/B-leg
   `CallCorrelation` maps (`sip_stack.rs`) are `Arc`-shared in-memory
   `HashMap`s. The media pipeline reads them to associate RTP flows with
   calls; teardown walks them to release ports.
2. **Port allocation.** `RtpPortAllocator` (`media_pipeline.rs`) hands
   out ports from 16384–32768 inside the process. Splitting means each
   relay owns its own range — and the signaling pod must stop caring
   what the numbers are.
3. **SDP rewriting.** The signaling pod rewrites SDP with media
   addresses it currently *owns*. After the split it advertises
   addresses that belong to a relay it picked.
4. **Zone/interface model.** `zone.rs` resolves signaling/media/external
   IPs per zone from the daemon's own interfaces. Relays in other pods
   (or hosts) have different interfaces; zone identity must move into
   the relay's own config.
5. **Config and TLS hot-reload.** One `Arc<RwLock<SbcConfig>>` and one
   SIGHUP. Two deployables means two config surfaces (see §6).
6. **DTLS-SRTP / ICE.** Key negotiation (`proto-dtls`, `ice_agent.rs`)
   terminates where the media socket lives — it moves wholesale into the
   relay.

## 3. Target architecture

```
                    SIP (UDP/TCP/TLS 5060/5061)
  Carriers/Phones ────────────────► sbc-signaling (1..2, act/stby or stateless+store)
                                        │
                                        │ gRPC MediaControl (alloc/modify/release/stats)
                            ┌───────────┼───────────────┐
                            ▼           ▼               ▼
                      sbc-media-1  sbc-media-2  …  sbc-media-N
                       (zone A)     (zone A)        (zone B)
  Caller RTP ◄═══════════► relay ◄═══════════► Callee RTP
```

- **sbc-signaling** — everything that speaks SIP: transactions, dialogs,
  B2BUA, registrar, digest auth, routing (dial plan + CUCM), CDRs,
  DoS protection, the gRPC management surface. No RTP sockets at all.
- **sbc-media** — a thin, dumb, fast RTP/SRTP relay: socket pairs,
  SRTP/DTLS, ICE candidates, codec passthrough (transcoding optional,
  later), per-session stats. No SIP, no routing, no Postgres.

The already-split `sbc-announcement-server` is the architectural
prototype: signaling keeps the SIP dialog, media work happens in another
pod, and the SDP advertises the other pod's address. `sbc-media`
generalizes that from "play a file" to "relay two legs".

### 3.1 MediaControl protocol (signaling → relay, gRPC)

Four RPCs cover the B2BUA lifecycle. All carry `call_id` (the internal
`CallId`, not the SIP Call-ID) for correlation and idempotency keys for
retry safety.

```proto
service MediaControl {
  // INVITE received: allocate the A-leg anchor before answering.
  // Returns the relay's advertised IP + ports to put in rewritten SDP.
  rpc AllocateSession(AllocateRequest) returns (AllocateResponse);

  // SDP answer arrived / re-INVITE: set or update each leg's remote
  // address, codec, SRTP keys, ICE credentials.
  rpc ModifySession(ModifyRequest) returns (ModifyResponse);

  // BYE/CANCEL/error: release ports, emit final stats (for the CDR).
  rpc ReleaseSession(ReleaseRequest) returns (ReleaseStats);

  // Liveness + load. Signaling uses load for placement and uses missed
  // deadlines to mark a relay dead (§5).
  rpc Watch(WatchRequest) returns (stream RelayStatus);
}
```

Design rules learned from RTPEngine's ng-protocol and SIPREC:

- **The relay is per-session stateful but call-dumb**: it knows
  socket pairs, keys, and counters — never SIP semantics. All call
  logic stays in one place (signaling), which is what keeps the
  protocol four verbs instead of forty.
- **Latency budget**: `AllocateSession` sits between receiving the
  INVITE and forwarding it. Same-node gRPC is ~0.2–0.5 ms, cross-node
  <2 ms — acceptable; but the signaling pod must impose a hard deadline
  (~250 ms) and fail the call with 503 + retry on another relay rather
  than hang the transaction.
- **Idempotency**: every RPC carries a `(call_id, cseq-like revision)`
  pair so a retried `Modify` after a timeout cannot regress a session.

### 3.2 Placement and port management

- Each relay owns a **disjoint port range** it announces in `Watch`
  registration (e.g. relay-1: 16384–24575, relay-2: 24576–32767, or
  full range on distinct IPs). Signaling never allocates port numbers —
  it allocates *sessions* and receives endpoints back. The daemon's
  `RtpPortAllocator` moves into the relay unchanged.
- Placement policy in signaling, in order: (1) zone match — the relay
  must front the zones both legs touch; (2) least sessions; (3) sticky
  for re-INVITEs (a session never migrates relays mid-call; re-anchoring
  is a new allocation plus SIP re-INVITE).
- Relays register themselves over `Watch` (relay → signaling on the
  existing 9091 gRPC listener, mirroring `TrunkStatusPublishService`),
  so adding capacity is "start another pod" with zero signaling config.

### 3.3 Call flow (happy path)

```
INVITE (offer) ──► signaling
                   ├─ auth, route                      (unchanged)
                   ├─ AllocateSession(relay R)  ──────► R binds 4 ports
                   ├─ rewrite SDP offer: c= R.ip, m= R.portB
                   └─ forward INVITE to B-leg           (unchanged)
200 OK (answer) ─► signaling
                   ├─ ModifySession: B remote addr/keys ► R
                   ├─ rewrite SDP answer: c= R.ip, m= R.portA
                   └─ forward 200 OK to A-leg
RTP A ◄══════════════════ R ══════════════════► RTP B
BYE ─────────────► signaling
                   ├─ ReleaseSession ──────────► R (returns stats → CDR)
                   └─ forward BYE
```

The SIP side is untouched; only "allocate port" / "learn remote addr" /
"release" change from function calls into RPCs — they are already
discrete steps in `sip_stack.rs` today.

## 4. State: what must become distributed, and what must not

The trap in this split is assuming call state must move to a shared
store. It does not:

- **Session truth lives in exactly one relay** (which sockets, keys,
  counters). Lost only if that relay dies — and then the media is gone
  anyway.
- **Call truth lives in exactly one signaling pod** (dialogs, B2BUA
  state), exactly as today.
- The only *new* shared knowledge is the session↔relay binding, kept in
  the signaling pod's call store as one extra field (`relay_id`,
  `relay_session_id`). No etcd, no Redis, no consensus — provided
  signaling stays single-active (current deployment model; the
  `cluster` feature's state replication is an orthogonal, existing
  concern).
- **Recovery rule**: a restarted relay reports zero sessions on
  re-`Watch`; signaling sweeps its call store and tears down (BYE both
  legs) every call bound to it. A restarted signaling pod orphans relay
  sessions; relays expire any session with no `Modify`/keepalive for N
  seconds (RTPEngine uses the same TTL trick).

## 5. Failure modes

| Failure | Blast radius | Handling |
| --- | --- | --- |
| Relay crash | Calls anchored on it | `Watch` stream breaks → signaling BYEs affected calls (or re-INVITEs to a new relay for re-anchor-capable endpoints — phase 2 polish) |
| Relay unreachable at INVITE | One call attempt | Deadline → try next relay → 503 if none |
| Signaling crash | All calls (same as today) | Unchanged; relays GC sessions via TTL |
| Network partition signaling↔relay | Media keeps flowing! | Calls continue; signaling can't modify/release until heal; sessions GC'd only if signaling also misses TTL refresh — make refresh part of `Watch`, not per-session, so a partition doesn't kill live audio |
| Version skew during rollout | One RPC surface | Proto-governed; additive evolution only, relay advertises capabilities in `Watch` registration |

The partition row is the key operational win of the split done right:
media survives control-plane wobble.

## 6. Configuration and security

- Relay config is small and env-driven like the new pods
  (`sbc-announcement-server` precedent): zone name, bind/advertised IPs,
  port range, signaling gRPC URL. No Postgres, no SBC config file.
- Signaling keeps `SbcConfig` + SIGHUP exactly as now.
- MediaControl carries SRTP master keys → the link must be mTLS (the
  gRPC server already supports mTLS via `tls_ca_path`/`require_mtls`).
  In-cluster, use the same cert distribution as the daemon's existing
  gRPC TLS. NIST mapping: SC-8, SC-12 (key transport), SC-7 (relay is
  the new media boundary).

## 7. Migration plan (each phase shippable, each reversible)

1. **Phase 0 — seam-finding (in-process).** Define a `MediaAnchor`
   trait in the daemon with exactly the four operations of §3.1;
   implement it over the existing `MediaPipeline`. Pure refactor, no
   behavior change; CI proves the seam is real. (~the size of the
   trunk-agent PR)
2. **Phase 1 — protocol + loopback relay.** Add `media_control.proto`;
   implement `sbc-media` as a new crate wrapping today's
   `media_pipeline.rs` + `RtpPortAllocator` + DTLS/ICE; implement a
   `RemoteMediaAnchor` client. Daemon env var `SBC_MEDIA_URL` selects
   remote vs in-process — same fallback pattern as
   `SBC_ANNOUNCEMENT_URL`. Run the relay as a second container on the
   same host (no zone changes needed).
3. **Phase 2 — independent placement.** Relay self-registration
   (`Watch`), placement policy, disjoint port ranges, relay-down sweep.
   First multi-relay deployments; announcement playback can also move
   behind the relay at this point.
4. **Phase 3 — operational hardening.** Re-anchoring via re-INVITE,
   per-relay draining for deploys, load-based placement, cross-zone
   relays, optional transcoding in the relay.

Effort honestly stated: phases 0–1 are weeks, not days; phase 2 is the
long pole (placement + failure sweeps need real soak time). Nothing
here is worth starting until §1's triggers are close.

## 8. Alternatives considered

- **Kernel/XDP forwarding in one pod** (RTPEngine's kernel module
  approach): much higher pps on one host without any distribution.
  Cheaper than the split if the bottleneck is CPU-per-packet rather
  than NIC/ports/zones. Worth measuring first.
- **Off-the-shelf RTPEngine next to the daemon**: fastest path to a
  proven relay, but drops CNSA/FIPS crypto guarantees (`uc-crypto`/
  aws-lc-fips) and adds a C dependency to a pure-Rust, NIST-mapped
  stack. Rejected for this codebase's compliance posture.
- **SIP-layer scale-out** (multiple full daemons behind a dispatcher):
  simplest "more capacity" answer, but multiplies carrier-facing
  identities (per-daemon registration — partially mitigated now by
  `sbc-trunk-agent`) and doesn't put media where the network needs it.

## 9. Decision

Hold until a trigger in §1 fires. When it does, start at Phase 0 — the
`MediaAnchor` trait costs little, de-risks everything after it, and is
the only phase with zero operational consequences.
