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
- 📋 documented limitation — SRTP ROC not preserved across DTLS renegotiation (3711 §3.2.1); replay window resets on renegotiation. Accepted until DTLS rekey support is revisited. (2026-11-15: the client has no DTLS handshake at all, NIST POA&M-324, so this does not arise yet.)
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
6. ✅ All findings of the 2026-06-11 audit are fixed or accepted as documented limitations (SRTP ROC across DTLS rekey, early-media start, ICE trickling). Later reviews added open items: see "fix/client-review-blockers" and "fix/client-srtp-b2" above (no DTLS handshake, so no audio on TLS calls, NIST POA&M-324).
