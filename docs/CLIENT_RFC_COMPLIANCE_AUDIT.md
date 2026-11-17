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

Status legend: ✅ fixed (commit) · 📋 documented limitation (accepted, not
planned) · unmarked = open. Wave 1 = 909890cf / 56000e43 / 0642c3be;
wave 2 = b79893b0.

## P1 — fix before broader interop testing

| # | Finding | RFC § | Where | On-wire consequence |
|---|---------|-------|-------|---------------------|
| 1 | Responses matched to calls by **Call-ID alone**, not (Via branch, CSeq method) — ✅ fixed (0642c3be) | 3261 §17.1.3 | `client-core/call_manager.rs:622-647` | Late/retransmitted responses (BYE 200, CANCEL 481) corrupt the state of newer transactions on the same call; breaks under re-INVITE and races |
| 2 | **No Record-Route → route set** capture; in-dialog BYE/re-INVITE bypass proxies — ✅ fixed (b79893b0) | 3261 §12.1.2, §12.2.1 | `call_agent.rs` + `call_manager.rs` | Any Record-Routing proxy/SBC (including ours) is skipped on BYE/re-INVITE → 481s, policy bypass, broken transfers. Works against BulkVS only because it doesn't Record-Route |
| 3 | **No retransmission absorption** (dup 180s reprocessed; no merged-request detection) — ✅ fixed (0642c3be) | 3261 §17.1.2.2 | `proto-transaction/client.rs` | UDP retransmits double-drive the call state machine; forking proxies stall it |
| 4 | **RFC 3263 ignored**: A/AAAA lookup only, no NAPTR/SRV, hardcoded 5060/5061 — ✅ fixed (b79893b0) | 3263 | `call_agent.rs:2397-2453` | Carriers using SRV load-balancing are misrouted; SRV-only domains fail outright |
| 5 | **423 Interval-Too-Brief not handled** (Min-Expires ignored, no retry) — ✅ fixed (909890cf) | 3261 §10.2.8 | `registration.rs:424-435` | Registrar demanding longer expiry locks the client out until app restart |
| 6 | **rport/received** (sent, never parsed) — ✅ learned (b79893b0); **address-rewrite reverted** after live testing — see note below | 3581 | `call_agent.rs` | A UAC honors rport by *sending* `;rport`; the server routes responses to the received source regardless. Rewriting our own Via/Contact to the NAT-learned public address broke carrier media latching (caused total audio loss against BulkVS) and is not required — `public_addr` is now learned for diagnostics only |
| 7 | To-tag captured from 183 but **not from 180** — ✅ fixed (b79893b0) | 3261 §12.1 | `call_agent.rs:772-775, 1040-1042` | 180-then-487 race ACKs with the wrong tag → 481, dialog lingers ~32s |
| 8 | **No audio timestamp advance during DTX** suppression — ✅ fixed (56000e43) | 3550 §5.1 | `io_thread.rs:673-678` | Speech resumption looks like timestamp rollback; strict jitter buffers/SBCs drop or stall — audible |
| 9 | **Marker bit never set** on talkspurt start (audio) — ✅ fixed (56000e43) | 3550 §4.4 | `rtp_handler.rs:408-415` | Remote playout-delay reset heuristics misfire after silence |
| 10 | CANCEL/ACK should reuse the INVITE's **Max-Forwards**, not reset to 70 — ✅ fixed (b79893b0) | 3261 §9.1 | `call_agent.rs` request builders | Strict proxies treat mismatched CANCEL as non-matching (same family as the fixed Via bugs) |

## P2 — spec violations usually tolerated

| # | Finding | RFC § | Where |
|---|---------|-------|-------|
| 11 | Unregister sends specific Contact, not `Contact: *` (stale bindings from other instances) — ✅ fixed (909890cf). Update (fix/client-review-blockers): REGISTER, refresh and un-REGISTER use one per-instance Contact carrying `;rinstance=<128-bit hex>` (`binding_contact`), and un-REGISTER sends that Contact with `Expires: 0`, not `Contact: *`, so other instances of the AOR keep their bindings; stale bindings from earlier runs now expire naturally. Tests `test_two_instances_register_distinct_contacts`, `test_unregister_sends_own_contact_expires_zero`. Not verified against a live or third-party registrar | 3261 §10.2.2 | `client-sip-ua/src/registration.rs` |
| 12 | 422 Session-Interval-Too-Small (Min-SE) not handled — ✅ fixed (422 retry with Session-Expires/Supported: timer, wave 3) | 4028 §5.3 | no handler |
| 13 | No CSeq validation on responses (late 200s can confirm wrong request) — ✅ fixed (0642c3be) | 3261 §12.2.1.1 | `call_agent.rs` CSeq sites |
| 14 | Incoming BYE/CANCEL with no matching dialog: no explicit 481 reply — ✅ fixed (0642c3be) | 3261 §8.2.2.2 | `call_manager.rs:1376-1428` |
| 15 | No Retry-After parsing on 503/600 (immediate retry hammering) — ✅ fixed (909890cf + b79893b0) | 3261 §21.5.2 | no handler |
| 16 | RTCP interval fixed at 5s, not randomized — ✅ fixed (56000e43) | 3550 §6.3.1 | `rtcp_session.rs:28-29` |
| 17 | RTCP RR interarrival jitter possibly reported in ms, not RTP timestamp units — ✅ fixed (56000e43) | 3550 §A.8 | `jitter_buffer.rs` / RR builder — verify |
| 18 | SSRC collision detection receiver-side only — ✅ fixed (56000e43) | 3550 §8.2 | `rtp_handler.rs:868-876` |
| 19 | DTMF send: 4733-only with mic suppressed; no in-band interleave option for event-blind peers — ✅ fixed (56000e43, `dtmf_inband_interleave` flag, default off) | 4733 §2.5.1.3 | `dtmf_sender.rs` / `io_thread.rs:404-408` |
| 20 | ACK-to-2xx not retransmitted when the 200 is retransmitted — ✅ fixed (0642c3be) | 6026 §2 | `call_agent.rs:1122-1137` |

## P3 — hardening

- ✅ fixed (56000e43) — No RTCP BYE on session end (3550 §6.6).
- 📋 documented limitation — SRTP ROC not preserved across DTLS renegotiation (3711 §3.2.1); replay window resets on renegotiation. Accepted until DTLS rekey support is revisited. (2026-11-17: the client now performs one DTLS handshake per call and never renegotiates or rekeys, so a new association mid-call does not arise; a re-INVITE that should start one is NIST POA&M-327. Within one association the rollover counter and replay window are now kept across audio pipeline restarts, see "feat/client-dtls-wiring, Stage 2".)
- ✅ implemented (56000e43) — Symmetric RTP source filtering (4961), **default OFF**: carriers commonly source media from a different IP than the SDP c-line, so this is opt-in deployment hardening, not a safe default.
- ✅ fixed (b79893b0) — To-tag no longer silently mutable across 1xx responses; differing tag on a later 1xx is warned and ignored, only a 2xx finalizes a different tag (3261 §12.1.2).
- 📋 documented limitation — Early media on 183+SDP not started until 200 (3960); deliberate functional choice (no audio before answer).
- ✅ fixed (b79893b0) — 491 glare to a re-INVITE is ACKed and retried once after a 2–4 s backoff (3261 §14.1).
- ✅ fixed (b79893b0) — Early SDP (183) codec list validated against the offer; non-intersecting answers are logged and ignored (3264 §6).
- 📋 documented limitation — ICE candidate trickling unsupported (8838); full-gathering-before-offer only.

## fix/client-review-blockers (2026-11-10)

Changes on this branch, with the gaps they leave. Statuses are from unit
tests only; no live SBC or registrar run.

| Change or gap | RFC § | Where | Tests / tracking |
|---|---|---|---|
| Responses go out on the transport the request arrived on, not the Via text; default-feature builds have no UDP SIP socket | 3261 §18.2.2 | `client-core/src/app.rs` (`SipTransportKind`), `sip_transport.rs` | `test_response_follows_receive_transport_not_via_text`, `test_tls_only_build_never_answers_over_udp` (default-feature CI step, POA&M-322 closed), `client-core/tests/tls_only_surface.rs` |
| `insecure-transports` / `digest-auth` builds bind a UDP SIP listener for every account, including TLS accounts (open) | 3261 §18 | `client-core/src/app.rs` | POA&M-318 |
| TLS reader delivers every complete buffered message before reading again; leading CRLF still a framing error (RFC-013) | 3261 §18.3 | `client-core/src/sip_transport.rs` `TlsReader::recv` | `test_tls_reader_delivers_two_messages_from_one_read`, `test_tls_reader_delivers_three_messages_from_one_read`, `test_tls_reader_reassembles_message_split_across_reads` |
| INVITE with an unsplittable From/Contact, a non-SIP/SIPS Contact, or a From with no SIP/SIPS/`tel:` URI gets 400 with a To tag; no call created | 3261 §21.4.1, §8.2.6.2 | `client-core/src/call_manager.rs` (`reject_malformed_invite`, `contact_target_uri`, `is_usable_caller_uri`) | `test_incoming_invite_with_unparsable_from_or_contact_gets_400`, `test_incoming_invite_with_non_sip_contact_or_uriless_from_gets_400`, `test_split_name_addr_never_panics` |
| `hangup_call` releases local call state (audio, media session, dialog, active slot) and emits `CallEnded` even when the BYE/CANCEL send fails; still returns the error | 3261 §15 | `client-core/src/call_manager.rs` `hangup_call` | `test_hangup_releases_local_state_when_signaling_fails` |
| RTP extension and padding lengths are bounds-checked on the non-SRTP path; a padding count of 0 with P set is still accepted | 3550 §5.1, §5.3.1 | `client-audio/src/rtp_handler.rs` `parse_rtp_fields` | `test_parse_rtp_fields_*`, `test_process_packet_rejects_oversized_extension_length` |
| Received frames longer than one ptime (20 ms) are dropped while `a=maxptime:120` is offered (open) | 3551 §4.2 | `client-audio/src/decode_thread.rs` | POA&M-317 |
| REGISTER responses not matched to the transaction (open) | 3261 §17.1.3 | `client-sip-ua/src/registration.rs` | POA&M-319 |
| Refresh interval taken from the Contact carrying this instance's `rinstance`, falling back to `Expires` (RFC-R2-003 fixed) | 3261 §10.2.4 | `client-sip-ua/src/registration.rs` `extract_expires` | `test_extract_expires_uses_own_contact_when_second`, `test_extract_expires_own_contact_in_comma_list`, `test_extract_expires_no_match_falls_back_to_expires_header`, `test_extract_expires_hostile_values_do_not_panic` (POA&M-320 closed) |

## fix/client-srtp-b2 (2026-11-15)

Review BLOCKER B2 (finding RFC-005 of the 2026-11-10 client review: media
was never SRTP although the SDP said `UDP/TLS/RTP/SAVPF`). The plaintext
path is closed; secure media is not delivered. `proto-dtls` has no network
DTLS handshake, so **every call on a TLS account ends after connect with no
audio** until NIST POA&M-324 is closed. Statuses are from unit and gate
tests only (`client-core/tests/media_security_gate.rs` unless another file
is named). No test uses a real DTLS handshake, and there was no run against
the SBC, its Go DTLS sidecar or any other peer.

**Superseded in part (2026-11-17).** This section records the state after
fix/client-srtp-b2. Since feat/client-dtls-wiring the client performs the
handshake: the rows below on the missing handshake, the unverified peer
certificate, dropped DTLS records, rtcp-mux "not exercised against a peer",
SRTCP reachability and "Connected at the 200" no longer describe the client.
Their current state is in "feat/client-dtls-wiring, Stage 2" below. The
other rows still hold.

| Change or gap | RFC § | Where | Tests / tracking |
|---|---|---|---|
| No audio without DTLS-SRTP keys on a `UDP/TLS/RTP/SAVP(F)` stream; the call is ended (BYE or CANCEL), never downgraded to RTP | 5764 §4.1 | `client-core/src/call_manager.rs` (`media_security_for`, `fail_call_media_security`) | `outbound_establish_error_ends_call_with_bye`, `inbound_accept_then_ack_fails_closed`, `test_media_security_for_by_account_and_build` |
| No DTLS handshake, profile negotiation or key export on the media socket (open) | 6347; 5764 §4.1.2, §4.2 | `proto-dtls/src/session.rs` (`DtlsSession::new` returns `HandshakeFailed`), `client-sip-ua/src/media_session.rs` (`establish`) | `establish_fails_closed_and_never_rebinds`; POA&M-324 |
| Remote offer that cannot be secured gets 488 with `Warning: 399` before ringing; remote answer with the same defect ends the call with BYE; re-offer gets 488, session unchanged | 3264 §5.1, §6, §8; 3261 §20.43 | `client-core/src/media_security.rs` (`preflight`), `call_manager.rs` (`admit_incoming_offer`, `reject_insecure_offer`, `handle_incoming_reinvite`) | `inbound_insecure_offer_gets_488`, `qa_inbound_hostile_dtls_attrs_get_488_no_ring`, `outbound_insecure_answers_end_call`, `qa_outbound_hostile_answers_end_call`, `reinvite_insecure_reoffer_gets_488`, `qa_reinvite_downgraded_dtls_attrs_get_488`, `test_reinvite_offer_without_dtls_preflight_gets_488` |
| `a=fingerprint`: one full `sha-384` value sent; remote values parsed strictly, several allowed. Deviation: only `sha-384` / `sha-512` accepted (CNSA 2.0), so a `sha-256`-only peer is refused | 8122 §5 | `client-sip-ua/src/dtls_identity.rs`, `sdp_dtls.rs`; `proto-dtls/src/fingerprint.rs` (`from_sdp_strict`) | `offer_carries_one_full_sha384_fingerprint`, `sha256_only_rejected_mixed_keeps_cnsa`, `qa_hostile_fingerprint_and_setup_rejected`, `qa_mixed_lists_precedence_and_order`, `strict_parse_rejects_bad_input` |
| Peer certificate is not verified against the signalled fingerprint (open); `verify_any` exists, reached by no network path | 8122 §5; 5763 §5 | `proto-dtls/src/fingerprint.rs`, `handshake.rs` (`process_certificate`) | direct-call tests only: `verify_any_matches_one_of_set`, `test_process_certificate_empty_fingerprint_set_fails`; POA&M-324 |
| `a=setup`: `actpass` in offers, `active`/`passive` in answers by the offer's value, `actpass` in a remote answer is an error, absent means `active`; role kept across re-INVITE; offerless re-INVITE answered with an `actpass` offer | 4145 §4; 5763 §5 | `client-sip-ua/src/sdp_dtls.rs` (`Setup`), `client-core/src/call_manager.rs` | `role_table`, `setup_values`, `duplicate_and_long_setup`, `offer_actpass_answers_active_client`, `offerless_reinvite_200_offers_actpass` |
| Re-INVITE that changes fingerprint or setup does not start a new handshake (open) | 5763 §6.6 | `call_manager.rs` (`handle_incoming_reinvite`) | POA&M-327 |
| Datagrams on the media socket are classified by first byte before any parsing; DTLS and STUN are dropped and counted, not serviced (open: no post-handshake DTLS, no STUN handoff to ICE, no consent freshness) | 7983 §7; 5764 §5.1.2; 7675 | `client-audio/src/rtp_handler.rs` (`classify`, `receive_one`) | `classify_exhaustive_rfc7983`, `receive_drops_dtls_and_stun_and_unmuxed_rtcp`, `receive_consumes_dropped_burst_then_rtp`, `receive_is_time_bounded_under_paced_junk`; POA&M-325 |
| rtcp-mux: offered always, echoed only when offered, required from the peer on DTLS-SRTP calls (488 / BYE without it) because there is no separate RTCP DTLS association; RTCP sent and received on the RTP socket when negotiated. Not exercised against a peer (open pending interop). Packets with payload type 64-95 are treated as RTCP | 5761 §4, §5.1.1 | `client-core/src/media_security.rs`, `client-audio/src/rtp_handler.rs`, `rtcp_session.rs`, `io_thread.rs` | `rejects_missing_rtcp_mux_and_insecure_second_stream`, no-`rtcp-mux` cases in `inbound_insecure_offer_gets_488` / `outbound_insecure_answers_end_call`; POA&M-326 |
| SRTCP: with keys, RTCP is protected before sending and authenticated before parsing; tampered or plaintext RTCP is dropped and counted. Reachable in a default build only once keys exist. Receive allocates per datagram (open) | 3711 §3.4; 7714 §6 | `client-audio/src/rtcp_session.rs` (`set_srtcp`, `ingest`, `transmit`), `proto-srtp/src/protect.rs` (`unprotect_rtcp_sync`) | test-made keys: `srtcp_round_trip_and_no_plaintext_on_wire`, `srtcp_tampered_and_plaintext_dropped`, `unprotect_rtcp_sync_round_trip_and_tamper`; POA&M-328 |
| SRTP on every transmit path (audio, RFC 2198 redundancy, CN, DTMF) of a keyed session; symmetric-RTP latch moves only after a packet authenticates. Reachable in a default build only once keys exist | 3711 §3.3; 7714 §5; 4961 | `client-audio/src/rtp_handler.rs` | test-made keys: `srtp_loopback_no_plaintext_on_wire`, `qa_srtp_every_tx_path_encrypted_role_swapped`, `keyed_latch_moves_only_after_srtp_auth`, `keyed_auth_failure_is_counted_drop_and_does_not_mark_source_seen` |
| Delayed-offer INVITE (no SDP) rejected with 488 on DTLS-SRTP accounts; offer in 200 / answer in ACK not implemented (open) | 3264 §5; 3261 §13.2.1; 5763 §6.4 | `client-core/src/media_security.rs` (`preflight`) | no-body case in `inbound_insecure_offer_gets_488`; POA&M-329 |
| Inbound call reported Connected at the 200, before ACK and media security; no UAS 2xx retransmission (open). Implemented for TLS calls: BYE when no ACK arrives within 64*T1 | 3261 §13.3.1.4 | `client-core/src/call_manager.rs` (`ACK_WAIT_SECURE_MEDIA`, `expire_unacked_secure_calls`) | `test_unacked_tls_call_is_ended_after_64_t1`; POA&M-331 |
| SDP answer still built from a template with one audio m-line, whatever the offer contains (open, not changed here) | 3264 §6 | `client-core/src/call_manager.rs` (SDP templates) | baseline finding RFC-006 (open BLOCKER series) |

## feat/client-dtls-handshake, Stage 1 (2026-11-16)

Library only. `proto-dtls` gained a DTLS 1.2 handshake, `DtlsAssociation`
(`crates/proto/proto-dtls/src/association.rs`): sans-I/O, both roles, CNSA
profile only, tested over loopback, real UDP sockets and against pion/dtls
v3.1.5 in both roles (local runs; `tests/interop_pion.rs` is `#[ignore]`).
**Nothing in `crates/client/*` changed in Stage 1 and nothing in the client
used it then.** (Superseded 2026-11-17: Stage 2 wired it into the client, see
the next section.) At the time, every row of the fix/client-srtp-b2 table
above still described the client: TLS-account calls ended after connect with
no audio, and NIST POA&M-324 stayed open until Stage 2. There was no soft-client run against the SBC, its Go
DTLS sidecar or any other peer.

What the library does per RFC section, and where it deviates, is in
`RFC_COMPLIANCE_GAPS.md` (proto-dtls section). What Stage 2 has to do in the
client, from the Stage 1 reviews:

| Stage 2 obligation or library behaviour the client will inherit | RFC § | Source / tracking |
|---|---|---|
| The SDP offerer must be ready for a `ClientHello` before the answer arrives: buffer a bounded number of DTLS datagrams, create the association when the answer supplies the fingerprints, then replay them. The handshake budget starts when the association is constructed | 5763 §5 | RFC-006 (open) |
| Feed the association only datagrams from the one negotiated remote address and set `AssociationConfig::peer_binding`, so the cookie covers the address; one association per call | 6347 §4.2.1 | RFC-007 (library part done; driver part open) |
| Route first bytes 20-63 on the media socket to the association through a bounded queue instead of dropping them; keep servicing it after `Connected` (the server role answers a retransmitted client `Finished` for 240 s) and call `close()` at call end | 7983 §7; 5764 §5.1.2; 6347 §4.2.4 | POA&M-324, POA&M-325 |
| No media before `Connected`; SRTP key direction from the negotiated role; every `Failed` / `Closed` event goes to the existing fail-closed path | 5764 §4.1, §4.2 | security review, Stage 2 requirements |
| A genuine failure in the plaintext part of the handshake (alert, wrong message, bad certificate or signature) is reported up to one retransmission interval late, and the reported `FailureCause` is the first one remembered, which a spoofed datagram can set. `presented_fingerprint()` is the most recently presented certificate, also unauthenticated before the peer's `Finished`. Logs and audit records must not present either as proof of what the peer sent | 5246 §7.2.2 (deviation) | NIST POA&M-334; AU-2 / AU-3 obligation under POA&M-324 |
| As DTLS client the handshake completes when the server sends no `CertificateRequest`; the client is then not authenticated to the server (`client_certificate_requested()` tells). The audit record must not claim mutual authentication unconditionally | 5246 §7.4.4 | security review |
| `sha-256`-only peers stay refused; extended master secret is required; no MKI; no RFC 8844 | 8122 §5; 7627; 5764 §4.1.3; 8844 | deviations in `RFC_COMPLIANCE_GAPS.md`; POA&M-333 |
| Toward our own SBC: its DTLS endpoint now accepts only this same profile and, as DTLS server, only a client that lists secp384r1 first in `supported_groups`. `DtlsAssociation` offers secp384r1 only. Not yet run end to end | 8422 §5.1.1 | NIST POA&M-336 |
| Still open in the client and not touched: new association on a changed fingerprint or setup (POA&M-327), delayed offer (POA&M-329), STUN handoff and consent freshness (POA&M-325), separate RTCP association (POA&M-326) | 5763 §6.6, §6.4; 7675; 5761 | as listed |

## feat/client-dtls-wiring, Stage 2 (2026-11-17)

The soft client performs DTLS-SRTP. `client-sip-ua/src/dtls_driver.rs` drives
the Stage 1 `DtlsAssociation` on each call's media socket; a call on a TLS
account is reported Connected, and audio starts, only after the handshake has
verified the peer against the SDP fingerprint and exported SRTP keys. Every
other outcome ends the call with no audio. Evidence: the client test suites
and two `#[ignore]` interoperability tests (pion/dtls v3.1.5 in both roles;
two client media stacks through the SBC relay and its Go DTLS sidecar), **in
local runs on macOS arm64 only**. Nothing has run on Linux or in CI on this
change. Not shown: a call set up by SIP through `sbc-daemon`, the audio
pipeline with devices, any other peer, Windows (NIST POA&M-339). The RFC
reviewer cited RFC 7160 §4.1 from memory; the section number was not
re-checked against the RFC text.

| Change, deviation or gap | RFC § | Where | Tests / tracking |
|---|---|---|---|
| DTLS 1.2 handshake on the media socket in either role, one association per call; profile negotiation and key export; key direction by negotiated role | 6347; 5764 §4.1.2, §4.2 | `client-sip-ua/src/dtls_driver.rs`, `media_session.rs` (`begin_secure`, `poll_secure`) | `both_roles_reach_ready_with_mirrored_keys`, `negotiated_keys_follow_role`, `outbound_call_connects_only_after_the_handshake_in_both_roles`, `inbound_call_connects_only_after_ack_and_handshake_in_both_roles`; interop `pion_as_server_we_are_client`, `pion_as_client_we_are_server`, `call_through_the_sbc_stays_up_and_ends_with_close_notify` |
| Peer certificate must match a fingerprint of this dialog's SDP, with proof of possession, before keys are exported; mismatch ends the call | 8122 §5; 5763 §5 | `proto-dtls/src/association.rs`; `client-core/src/call_manager.rs` (`begin_secure_media`) | `fingerprint_mismatch_fails_closed_in_both_roles`, `fingerprint_mismatch_ends_the_call_and_is_never_connected`. No RFC 8844: POA&M-333 |
| Deviation (RFC-005 of the Stage 2 review): the handshake starts at the 200 OK (outbound) or the ACK (inbound), not when a 183 answer makes the fingerprint known. The application is told `Connecting` until it completes | 5763 §5, §6.2 | `client-core/src/call_manager.rs` | recorded deviation; POA&M-331 |
| The offerer accepts a `ClientHello` that arrives before the SDP answer: up to 4 DTLS datagrams read during the ICE checks are kept and replayed once the fingerprint and address are known. The stash is filled before the source is known; only datagrams from the negotiated address are replayed | 5763 §5 | `client-sip-ua/src/ice_handler.rs`, `dtls_driver.rs` (`EarlyDtls`) | `early_client_hello_is_answered_without_retransmission`, `early_client_hello_read_by_the_ice_loop_reaches_the_driver`, `early_dtls_from_another_source_is_not_fed_to_the_driver`; Stage 1 RFC-006 closed; POA&M-334 |
| Demultiplexing on the one media socket (rtcp-mux): the driver reads during the handshake; afterwards the audio thread reads, and forwards DTLS records from the peer's address to the driver (burst 8, then 4 per second) | 7983 §7; 5764 §5.1.2 | `client-sip-ua/src/dtls_driver.rs`, `dtls_forward.rs`; `client-audio/src/rtp_handler.rs` | `demux_table`, `classify_exhaustive_rfc7983`, `flood_from_the_dtls_remote_is_rate_limited_and_never_blocks`, `dtls_from_a_non_negotiated_source_is_dropped_before_the_association` |
| Deviation (RFC-008): DTLS is accepted only from the exact negotiated address. No latching, so a peer behind a symmetric NAT whose DTLS source differs cannot complete the handshake; no normalisation of IPv4-mapped IPv6 addresses, so on a dual-stack socket such a peer is treated as a wrong source (the handshake ends at its budget, fail closed) | 5763 §6.7.1; 7983 | `client-sip-ua/src/dtls_driver.rs` (residual list) | `wrong_source_and_non_dtls_datagrams_do_not_disturb_the_handshake` |
| Gap (RFC-006): STUN on the media socket is dropped and counted during the handshake and after it; no handoff to ICE, no consent freshness. A peer that needs a STUN answer on this 5-tuple before or during DTLS gets none | 8445 §7.3; 7675; 5763 §6.7.1 | `client-sip-ua/src/dtls_driver.rs`, `client-audio/src/rtp_handler.rs` | `receive_drops_dtls_and_stun_and_unmuxed_rtcp`; POA&M-325 |
| Retransmission: 1 s initial timer, doubling; 10 s handshake budget; a due timer is handled before the socket is read, so a datagram flood cannot stop it. After the handshake a retransmitted final flight of the peer is answered | 6347 §4.2.4 | `client-sip-ua/src/dtls_driver.rs` | `handshake_timers_keep_running_under_a_wrong_source_flood`, `silent_peer_times_out_at_the_default_budget`, `lost_final_flight_is_resent_after_the_handoff`, `lost_final_flight_is_answered_through_the_audio_receiver` |
| Closing: one `close_notify` at local hang-up. Peer's authenticated fatal alert mid-call: audio stops, call fails at once. Peer's `close_notify` mid-call: audio stops at once, the call waits up to 1 s for the BYE (then a normal hang-up) and otherwise ends as a media-security failure | 5246 §7.2.1; 5764 §5.1.2 | `client-sip-ua/src/dtls_driver.rs`; `client-core/src/call_manager.rs` (`poll_security_closed`, `CLOSE_NOTIFY_BYE_GRACE`) | `local_close_after_connect_sends_one_close_notify`, `close_notify_without_bye_ends_the_call_after_the_grace_time`, `close_notify_followed_by_bye_is_a_normal_hangup`, `authenticated_fatal_alert_mid_call_ends_the_call_at_once` |
| Gap: a call with no audio thread (no audio device, or audio start failed) has no reader on the socket after the handshake, so post-handshake DTLS is not serviced; a warning is logged | 6347 §4.2.4; 5764 §5.1.2 | `client-core/src/call_manager.rs` (`warn_if_dtls_unserviced`) | POA&M-325 |
| Gap (RFC-004): a re-INVITE that changes fingerprint, setup or the remote transport address starts no new association; for a changed address SRTP is re-pointed under the old keys | 5763 §6.6 | `client-core/src/call_manager.rs` (`reoffer_rejection`) | POA&M-327 |
| SRTP across audio pipeline restarts (re-INVITE, hold and resume) under the same keys: one context per direction is kept for the call. Receive: rollover counter and replay window continue. Transmit: same SSRC, next sequence number, marker bit, continued timestamp; SRTCP index continues. One live transmitter per call is enforced, so no (SSRC, index) pair is sealed twice | 3711 §3.2.3, §3.3.1, §3.3.2; 7714 §8.4 | `client-audio/src/media_security.rs` (`SrtpCallState`, `TransmitClaim`), `rtp_handler.rs` | `srtp_transmit_survives_pipeline_restarts_for_a_single_context_receiver`, `srtp_receive_survives_a_pipeline_restart_after_a_sequence_wrap`, `srtp_replay_across_a_pipeline_restart_is_refused`, `srtcp_replay_across_a_restart_is_refused`, `second_transmitter_is_refused_while_the_first_lives`; through the SBC: `dtls_sbc_sidecar` |
| Deviation: one receive context per call, not per remote SSRC. A peer that restarts its stream with a new SSRC after a sequence wrap is not followed (silent audio; nothing wrongly accepted) | 3711 §3.2.3 | `proto-srtp/src/context.rs`; `client-audio/src/media_security.rs` | POA&M-338 (1) |
| After an SSRC collision the new SSRC gets a new outbound context at rollover 0 (as required), and an RTCP BYE is sent for the abandoned SSRC. A receiver with one context per association (the SBC) that has counted a rollover does not follow the new stream | 3550 §8.2; 3711 §3.2.3 | `client-audio/src/io_thread.rs`, `media_security.rs` (`ssrc_after_collision`) | `ssrc_collision_starts_a_new_outbound_srtp_context`, `bye_for_the_ssrc_abandoned_after_a_collision`; POA&M-338 (2) |
| Deliberate deviation (RFC-014, user decision): a restart that changes the RTP clock rate (8000 to or from 48000) keeps the SSRC; the timestamp continues at the new rate with the marker bit. Reason: a new SSRC would not be followed by the SBC's single-context leg after a rollover | 7160 §4.1 | `client-audio/src/media_security.rs`, `rtp_handler.rs` | `clock_rate_change_keeps_the_ssrc`; POA&M-338 (5) |
| RTCP BYE (RFC-013, fixed): no BYE when a pipeline stops for a restart whose stream continues; BYE at call end. If the restart's start then fails, the call is ended by signalling and no BYE is sent for that SSRC | 3550 §6.3.7, §6.6 | `client-audio/src/rtcp_session.rs` (`finish`), `io_thread.rs` | `no_bye_when_the_stream_continues_after_a_restart`; the I/O-thread wiring has no test (needs audio devices) |
| Sender and receiver report statistics restart in each pipeline although the SSRC continues | 3550 §6.4.1, §6.4.2 | `client-audio/src/rtcp_session.rs` | POA&M-338 (3) |
| rtcp-mux stays required on DTLS-SRTP calls (by design; no separate RTCP association). SRTCP on the RTP socket was exchanged with pion and through the SBC | 5761 §5.1.1; 3711 §3.4 | `client-core/src/media_security.rs` (`preflight`) | `dtls_interop_pion`, `dtls_sbc_sidecar` (local runs); POA&M-326 closing |
| Inbound TLS call: `Connecting` at accept, `Connected` only after the ACK and a completed handshake; BYE when no ACK arrives within 64*T1. Still no UAS 2xx retransmission | 3261 §13.3.1.4 | `client-core/src/call_manager.rs` (`ACK_WAIT_SECURE_MEDIA`) | `inbound_call_connects_only_after_ack_and_handshake_in_both_roles`, `test_unacked_tls_call_is_ended_after_64_t1`; POA&M-331 |
| Toward our own SBC: the client needs the DTLS sidecar of the same change, which keeps the association open for the call; the older sidecar sent `close_notify` after the handshake, which ends a Stage 2 client's call after about 1 s | 5764 §5.1.2 | `sidecar/dtls-terminator/service/session.go` | `dtls_sbc_sidecar`; upgrade order in `docs/SBC-ADMIN-GUIDE.md` |

## Verified compliant (spot checks)

- CANCEL/200 glare ACK+BYE (§15) — fixed and tested this session.
- G.722 RTP clock = 8000 Hz quirk (3551 §4.5.8).
- RTCP compound packet rules SR/RR+SDES (3550 §6.1).
- Hold via `a=sendonly` (3264 §8.4 / 6337).
- Incoming re-INVITE glare → 491 (3261 §14.1).
- Digest re-challenge bounded (max 2 attempts) with nonce dedup.
- RFC 7616 §3.7 / RFC 8760: strongest offered digest algorithm chosen for REGISTER and INVITE (`select_auth_challenges`; tests `test_401_sha256_challenge_preferred_over_md5`, `test_401_md5_only_fails_closed_when_disallowed`). REGISTER 407 is answered with Proxy-Authorization (RFC 3261 §22.3; test `test_407_answered_with_proxy_authorization`).
- RFC 3261 §22.3 / RFC 8760 §2.4: a multi-realm 401/407 gets one Authorization/Proxy-Authorization per realm, strongest permitted algorithm in each (stricter than §2.4 "topmost supported", allowed by its local-policy clause); a realm with no permitted algorithm fails the whole response (tests `test_401_multi_realm_one_header_per_realm`, `test_407_multi_realm_one_header_per_realm`, `test_407_md5_only_realm_fails_closed`, `test_invite_407_multi_realm_one_header_per_realm`; POA&M-256 closed).
- MD5 answered only when `allow_md5_digest` is explicitly `true`, or unset on a TLS-only account (tests `test_unset_md5_policy_follows_transport`, `test_invite_md5_refused_by_default_over_udp`; POA&M-255 closed).
- 📋 documented limitation — residual MD5 after opt-in (POA&M-276); every challenged realm is answered, no expected-realm allow-list (POA&M-277).

## Suggested fix order

1. ✅ **Transaction-correct response routing (#1) + retransmission absorption (#3)** — structural; everything else sits on it.
2. ✅ **Route-set handling (#2)** — prerequisite for the client working against our own SBC.
3. ✅ **Registration robustness (#5, #11)** and **NAT (#6)** — small, high value.
4. ✅ **RTP DTX timestamp + marker (#8, #9)** — small fixes in io_thread/rtp_handler.
5. ✅ **RFC 3263 DNS (#4)** — resolved via `uc-dns` (NAPTR/SRV, `resolver` feature). Before fix/client-cnsa-tls-dns the resolver had no DNS backend, so NAPTR/SRV were never queried. It now uses the system DNS configuration, with RFC 2782 weighted SRV order. No DNSSEC (NIST POA&M-172).
6. ✅ All findings of the 2026-06-11 audit are fixed or accepted as documented limitations (SRTP ROC across DTLS rekey, early-media start, ICE trickling). Later reviews added open items: see "fix/client-review-blockers" and "fix/client-srtp-b2" above (fix/client-srtp-b2 closed the plaintext path; Stage 1 of feat/client-dtls-handshake added the handshake to `proto-dtls` as a library; Stage 2, feat/client-dtls-wiring, wired it into the client on 2026-11-17, with the open items listed in that section).
