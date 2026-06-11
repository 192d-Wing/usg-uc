# Client SIP/RTP RFC Compliance Audit

Audit date: 2026-06-11, on branch `swiftui-app` (after the four live-found fixes:
CANCEL branch reuse, CANCEL/ACK Via verbatim reuse, CANCEL/200 glare ACK+BYE,
To-tag exclusion from CANCEL). Three parallel reviews: SIP core
(transactions/dialogs/transport), SIP flows (registration/offer-answer/transfer),
RTP/RTCP media path. Scope: `crates/client/*`. Findings exclude gaps already
documented in `RFC_COMPLIANCE_GAPS.md`.

Priorities: **P1** = real interop failure with carriers/SBCs (including our own
SBC, which Record-Routes); **P2** = spec violation usually tolerated;
**P3** = hardening.

## P1 — fix before broader interop testing

| # | Finding | RFC § | Where | On-wire consequence |
|---|---------|-------|-------|---------------------|
| 1 | Responses matched to calls by **Call-ID alone**, not (Via branch, CSeq method) | 3261 §17.1.3 | `client-core/call_manager.rs:622-647` | Late/retransmitted responses (BYE 200, CANCEL 481) corrupt the state of newer transactions on the same call; breaks under re-INVITE and races |
| 2 | **No Record-Route → route set** capture; in-dialog BYE/re-INVITE bypass proxies | 3261 §12.1.2, §12.2.1 | `call_agent.rs` + `call_manager.rs` | Any Record-Routing proxy/SBC (including ours) is skipped on BYE/re-INVITE → 481s, policy bypass, broken transfers. Works against BulkVS only because it doesn't Record-Route |
| 3 | **No retransmission absorption** (dup 180s reprocessed; no merged-request detection) | 3261 §17.1.2.2 | `proto-transaction/client.rs` | UDP retransmits double-drive the call state machine; forking proxies stall it |
| 4 | **RFC 3263 ignored**: A/AAAA lookup only, no NAPTR/SRV, hardcoded 5060/5061 | 3263 | `call_agent.rs:2397-2453` | Carriers using SRV load-balancing are misrouted; SRV-only domains fail outright |
| 5 | **423 Interval-Too-Brief not handled** (Min-Expires ignored, no retry) | 3261 §10.2.8 | `registration.rs:424-435` | Registrar demanding longer expiry locks the client out until app restart |
| 6 | **rport/received not honored** on responses (sent, never parsed) | 3581 | `call_agent.rs` (Via construction sites) | Behind NAT, advertised addresses go stale; responses/requests misroute after address change |
| 7 | To-tag captured from 183 but **not from 180** | 3261 §12.1 | `call_agent.rs:772-775, 1040-1042` | 180-then-487 race ACKs with the wrong tag → 481, dialog lingers ~32s |
| 8 | **No audio timestamp advance during DTX** suppression | 3550 §5.1 | `io_thread.rs:673-678` | Speech resumption looks like timestamp rollback; strict jitter buffers/SBCs drop or stall — audible |
| 9 | **Marker bit never set** on talkspurt start (audio) | 3550 §4.4 | `rtp_handler.rs:408-415` | Remote playout-delay reset heuristics misfire after silence |
| 10 | CANCEL/ACK should reuse the INVITE's **Max-Forwards**, not reset to 70 | 3261 §9.1 | `call_agent.rs` request builders | Strict proxies treat mismatched CANCEL as non-matching (same family as the fixed Via bugs) |

## P2 — spec violations usually tolerated

| # | Finding | RFC § | Where |
|---|---------|-------|-------|
| 11 | Unregister sends specific Contact, not `Contact: *` (stale bindings from other instances) | 3261 §10.2.2 | `registration.rs:663-670` |
| 12 | 422 Session-Interval-Too-Small (Min-SE) not handled | 4028 §5.3 | no handler |
| 13 | No CSeq validation on responses (late 200s can confirm wrong request) | 3261 §12.2.1.1 | `call_agent.rs` CSeq sites |
| 14 | Incoming BYE/CANCEL with no matching dialog: no explicit 481 reply | 3261 §8.2.2.2 | `call_manager.rs:1376-1428` |
| 15 | No Retry-After parsing on 503/600 (immediate retry hammering) | 3261 §21.5.2 | no handler |
| 16 | RTCP interval fixed at 5s, not randomized | 3550 §6.3.1 | `rtcp_session.rs:28-29` |
| 17 | RTCP RR interarrival jitter possibly reported in ms, not RTP timestamp units | 3550 §A.8 | `jitter_buffer.rs` / RR builder — verify |
| 18 | SSRC collision detection receiver-side only | 3550 §8.2 | `rtp_handler.rs:868-876` |
| 19 | DTMF send: 4733-only with mic suppressed; no in-band interleave option for event-blind peers | 4733 §2.5.1.3 | `dtmf_sender.rs` / `io_thread.rs:404-408` |
| 20 | ACK-to-2xx not retransmitted when the 200 is retransmitted | 6026 §2 | `call_agent.rs:1122-1137` |

## P3 — hardening

- No RTCP BYE on session end (3550 §6.6) — remote can't distinguish hangup from crash.
- SRTP ROC not preserved across DTLS renegotiation (3711 §3.2.1) — replay window reset.
- Symmetric RTP source filtering absent (4961) — accepts RTP from any source address.
- To-tag silently mutable across 1xx responses — assert/warn once set (3261 §12.1.2).
- Early media on 183+SDP not started until 200 (3960) — functional choice, document it.
- 491 glare response: no auto-retry timer (3261 §14.1).
- Early SDP (183) codec list not validated against the offer (3264 §6).
- ICE candidate trickling unsupported (8838) — document.

## Verified compliant (spot checks)

- CANCEL/200 glare ACK+BYE (§15) — fixed and tested this session.
- G.722 RTP clock = 8000 Hz quirk (3551 §4.5.8).
- RTCP compound packet rules SR/RR+SDES (3550 §6.1).
- Hold via `a=sendonly` (3264 §8.4 / 6337).
- Incoming re-INVITE glare → 491 (3261 §14.1).
- Digest re-challenge bounded (max 2 attempts) with nonce dedup.

## Suggested fix order

1. **Transaction-correct response routing (#1) + retransmission absorption (#3)** — structural; everything else sits on it.
2. **Route-set handling (#2)** — prerequisite for the client working against our own SBC.
3. **Registration robustness (#5, #11)** and **NAT (#6)** — small, high value.
4. **RTP DTX timestamp + marker (#8, #9)** — small fixes in io_thread/rtp_handler.
5. **RFC 3263 DNS (#4)** — self-contained; `uc-dns` already exists in the workspace and may already implement SRV (reuse it).
6. Remaining P2s opportunistically; P3s as a labeled backlog.
