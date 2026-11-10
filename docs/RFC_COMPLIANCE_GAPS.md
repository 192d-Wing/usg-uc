# RFC Compliance Gaps - USG Unified Communications

This document maps each proto-* crate to its relevant RFCs and identifies specific section gaps.

> **Status legend.** *Wired (sbc-daemon | sbc-media-core | soft client)* — a shipped binary has a call site for this (the binary is named). *Library-only* — implemented and tested in a `proto-*`/`uc-*` crate, but no shipped binary calls it. *Planned* — not implemented. A row that says only "Full"/"Complete" describes crate-level capability; the wiring column/annotation says what the running SBC actually does.

## Status Legend

- **Complete**: Full implementation per RFC (crate-level)
- **Partial**: Core functionality implemented, edge cases missing
- **Missing**: Not implemented

The **Wiring** column says which shipped binary calls the code: `sbc-daemon` (SIP B2BUA, `crates/sbc/sbc-daemon`), `sbc-media-core` (media relay used by `sbc-media` and the daemon, `crates/sbc/sbc-media-core`), `soft client` (`sip-softclient` via `client-core`/`client-sip-ua`/`client-audio`).

---

## proto-sip (RFC 3261 - SIP Core)

### RFC 3261 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §7.1 | Requests | Complete | Wired (sbc-daemon, soft client) | All methods defined in `method.rs`; matched case-sensitively, extension methods kept as received; daemon dispatches REGISTER/INVITE/ACK/BYE/CANCEL/OPTIONS/UPDATE (`sip_stack.rs`) |
| §7.2 | Responses | Complete | Wired (sbc-daemon, soft client) | All status codes in `response.rs` |
| §8.1 | UAC Behavior | Partial | Wired (sbc-daemon, soft client) | Daemon acts as UAC on the B-leg with client transactions and non-2xx ACKs (`sip_stack.rs`); soft client is a full UAC. No redirect following |
| §8.2 | UAS Behavior | Partial | Wired (sbc-daemon, soft client) | Daemon acts as UAS on the A-leg with server transactions (`sip_stack.rs`) Soft client: an INVITE with an unsplittable From or Contact, a non-SIP/SIPS Contact, or a From with no SIP/SIPS/`tel:` URI gets 400 (§21.4.1) with a To tag (§8.2.6.2) and no call (tests `test_incoming_invite_with_unparsable_from_or_contact_gets_400`, `test_incoming_invite_with_non_sip_contact_or_uriless_from_gets_400`); responses are sent on the receiving transport (§18.2.2; `test_response_follows_receive_transport_not_via_text`). Only a usable name-addr split is checked, not full grammar. Other client UAS gaps remain (RFC-016). |
| §10 | Registrations | Partial | Wired (sbc-daemon) | Delegated to proto-registrar (`sip_stack.rs` `handle_register`) |
| §11 | Querying Capabilities | Partial | Wired (sbc-daemon) | Daemon answers OPTIONS with 200 OK + Allow in its own handler (`sip_stack.rs` `handle_options`); proto-sip `options.rs` is Library-only |
| §12 | Dialogs | Partial | Library-only | proto-dialog `Dialog` is imported but the daemon's dialog map is never populated; dialog state lives in proto-b2bua `Call` |
| §13 | Initiating a Session | Partial | Wired (sbc-daemon, soft client) | Daemon relays INVITE as a B2BUA (`sip_stack.rs` `handle_invite`); soft client originates INVITE (`call_agent.rs`) |
| §13.2.2.4 | 3xx Redirect Responses | Complete | Library-only | `redirect.rs`; no caller. Daemon relays 3xx as a non-2xx final; soft client rejects redirects |
| §14 | Modifying an Existing Session | Partial | Wired (sbc-daemon, soft client) | Daemon relays re-INVITE/UPDATE across legs, 491 on glare, 481 for unmatched in-dialog requests (`sip_stack.rs` `handle_in_dialog_request`); relays in-dialog PRACK/INFO/MESSAGE/NOTIFY (POA&M-182, see "Daemon in-dialog non-session relay" below); soft client sends hold/resume re-INVITE |
| §15 | Terminating a Session | Partial | Wired (sbc-daemon, soft client) | Daemon relays BYE/CANCEL to the other leg (`sip_stack.rs` `handle_bye`, `handle_cancel`) |
| §16.4 | Route Information Preprocessing | Partial | Wired (sbc-daemon initial INVITE) | `routing.rs` `preprocess_route_information` (POA&M-231), called by sbc-daemon `preprocess_initial_invite` before ACL/dial plan/STIR (POA&M-236; tests `route_preprocess_strict_route_restores_request_uri`, `route_preprocess_pops_own_loose_route`, `route_preprocess_failures_rejected_and_audited`): strict-route Request-URI restore from the last Route (comma lists handled), pop of our own top Route, 64-element cap, request unchanged on error; tests `preprocess_*` (7). `maddr` (POA&M-235, closed): an own `maddr` received on the indicated port/transport is stripped with its non-default port/transport params (tests `maddr_*`, `qa_maddr_*`, proptest `maddr_strip_idempotent`; daemon `route_preprocess_strips_own_maddr`, `route_preprocess_strips_own_maddr_tls`). Residual: the daemon uses the configured listener port, not the actual local socket port; `wss` uses the TLS port (POA&M-286). ACL, dial plan and routing must run on the Request-URI after preprocessing (documented in `# Security`). The daemon is a B2BUA, not a proxy |
| §16.3 / §16.6 step 8 | Loop detection | Partial | Wired (sbc-daemon, own semantics) | `proxy.rs` `detect_loop`, `compute_loop_hash` (POA&M-231): branch `z9hG4bK{rand}.{loophash}`; every own Via checked; same hash = 482, different hash = spiral, missing hash = 482. Deviation: the hash leaves out the topmost Via (on a real loop it belongs to the previous hop); a spiral that differs only in its upstream Via is treated as a loop. Tests `same_request_back_is_loop`, `spiral_with_changed_ruri_allowed`, `spiral_with_changed_cseq_allowed`, `own_via_inside_comma_list_detected`. **Wired (sbc-daemon initial INVITE, POA&M-236):** `preprocess_initial_invite` runs §16.4 preprocessing after source admission and the Max-Forwards check and before ACL, dial plan, VPS, STIR and emergency classification (tests `route_preprocess_strict_route_restores_request_uri`, `route_preprocess_pops_own_loose_route`, `route_preprocess_failures_rejected_and_audited`, `admission_and_max_forwards_precede_route_preprocess`); "own URI" is our host/port with no user part. Daemon loop semantics differ from `detect_loop`: B-leg branches carry `compute_loop_hash` of the B-leg INVITE as sent; 482 only when an own Via carries a matching hash; an own Via **without** a hash is not a loop (in-dialog and CANCEL branches carry none). Loops via `obfuscate_call_id` or an outbound proxy that pops its Route (Route is hashed) look like spirals and are bounded only by Max-Forwards (POA&M-236 residual). Tests `loop_hash_branch_detects_loop_not_spiral`, `loop_hash_branch_kept_on_failover`, `loop_branch_format_round_trips` |
| §8.2.6.1 / §16.2 | 100 Trying | Complete | Library-only | `proxy.rs` `create_trying_response` copies every Via, From, To, Call-ID, CSeq, Timestamp; Content-Length 0. Tests `trying_copies_all_vias_and_timestamp`, `trying_from_parsed_wire_with_separate_via_lines` |
| §16.6 | Request Forwarding | Partial | Library-only | `proxy.rs`; no caller. Via insert/pop is O(n) and order-preserving; combined Via values handled. Reviewed under POA&M-231 (loop hash in branch, own-URI matching) |
| §16.7 / §18.2.2 | Response routing under proxy-model topology hiding (RFC-003) | Gap | Library-only | `TopologyHider::hide_outbound_request` (proxy model) strips (aggressive) or rewrites (basic) Vias with no stored copy, so responses could not be routed back to internal hops. No daemon caller; the daemon uses only `hide_b2bua_request`, which never strips a Via. Not RFC-conformant for proxy use until branch-keyed Via restoration exists (POA&M-157) |
| §16.12.1 | Loose Routing | Partial | Library-only | `routing.rs`; no caller. Reviewed with §16.4 under POA&M-231 |
| §17 | Transactions | Partial | Wired (sbc-daemon, soft client) | Daemon drives proto-transaction client/server FSMs and timers (`sip_stack.rs` `poll_timers`); soft client drives client FSMs |
| §18 | Transport | Partial | Library-only | `Transport` enum has no caller; sockets are provided by uc-transport |
| §19 | SIP URI | Partial | Wired (sbc-daemon, soft client) | `uri.rs`. §25 grammar, %-escape validation, strict ports, §19.1.4 `SipUri::equivalent`, generic `Uri` and 416 for non-SIP Request-URIs (POA&M-150). `tel:`/absoluteURI in To/From/Contact/Route still fail to parse, because `NameAddr.uri` is `SipUri`; a topology Contact rewrite of such a value would fail closed with 400 (RFC-002, POA&M-153). Callers not yet on `equivalent` (POA&M-154). Advisory (RFC-005, dormant until POA&M-154): `equivalent` decodes `%25` to `%`, so `%253B` and `%3B` compare equal; keep `%25` escaped when comparing |
| §20 | Header Fields | Partial | Wired (sbc-daemon, soft client) | 59 `HeaderName` variants in `header.rs`; names are case-insensitive (`Custom` normalised), compact forms incl. e/x/b/y/a/j/d. Only Via, CSeq, Max-Forwards, Content-Length are grammar-checked at parse time; other headers are checked when a caller parses them |
| §22 | Authentication | Partial | Wired (soft client) | `auth.rs` (RFC 2617, RFC 7616 MD5/SHA-256/SHA-512-256) used by the soft client as UAC. A hasher that does not implement the challenged algorithm now returns `Err` (test `md5_hasher_with_sha256_challenge_fails_closed`); the soft client and `sbc-trunk-services` pick the strongest offered challenge (RFC 7616 §3.7, `select_challenge_from_headers`) and answer with `AlgorithmHasher` (NIST POA&M-234 closed). Multi-realm 401/407 gets one credentials header per realm (RFC 3261 §22.3, RFC 8760 §2.4; POA&M-256 closed, `select_challenges_per_realm_from_headers`). MD5 refused unless allowed by policy (unset allows it only over TLS; trunk REGISTER is UDP so trunks need explicit opt-in; POA&M-255 closed). Gaps: residual MD5 after opt-in (POA&M-276); trunk REGISTER UDP only (POA&M-275); no expected-realm allow-list (POA&M-277). The daemon's REGISTER digest uses `proto_sip::DigestVerifier` (see next table), not proto-registrar's `authentication.rs` |

### proto-sip message layer hardening (Phase 1)

| Item | Status | Notes |
|------|--------|-------|
| §7 / §25.1 CRLF line ends, token names, no CTL in values | Complete | Bare CR/LF rejected; CTLs except HTAB rejected, including escaped CTLs in quoted-pairs (deliberate deviation, RFC 4475 `intmeth`) |
| §7.5 leading CRLF | Complete | Up to 32 skipped |
| §18.3 Content-Length framing | Partial | `Framing::Datagram` truncates / rejects; `Framing::Stream` (TCP/TLS) requires an exact C-L; `Framing::Message` (WS/WSS per RFC 7118 §5, SCTP per RFC 4168) makes C-L optional but exact if present. The soft client uses `Stream` on TCP/TLS. sbc-daemon's stream framer (`next_sip_frame`) now applies the same C-L rules via `SipMessage::stream_message_len`: on TCP/TLS a missing, duplicate, conflicting or malformed C-L (§20.14) gets a 400 and the connection closes; the subsequent parse still uses datagram rules (POA&M-64). Tests `duplicate_cl_gets_400_and_close`, `duplicate_content_length_rejected`, `malformed_content_length_rejected`, `reframing_any_split_is_identical` Soft client: every complete message in the read buffer is delivered before the next socket read (`TlsReader::recv`; tests `test_tls_reader_delivers_two_messages_from_one_read`, `test_tls_reader_delivers_three_messages_from_one_read`, `test_tls_reader_reassembles_message_split_across_reads`). Open: receive loop untested, leading CRLF keep-alive is still a framing error (RFC-013), a framed-but-unparsable message closes the connection, buffer unbounded before header end. |
| §8.1.1.5 CSeq < 2^31, CSeq method = request method | Complete | Exact, case-sensitive comparison (§7.1) |
| §20.22 Max-Forwards 0-255 | Complete (stricter than grammar) | §20.22 grammar is `1*DIGIT`; values above 255 (the §16.6 cap) are rejected as 400-class. Tests `max_forwards_range`, `max_forwards_bounds` |
| Duplicate single-valued headers (RFC 4475 §3.3.8/§3.3.9) | Complete | Call-ID, To, From, CSeq, Max-Forwards, Content-Length |
| §8.2.2 / §16.3 400 for malformed requests | Partial | sbc-daemon sends a sanitized 400 for stream framing errors only (`framing_error_response`, test `framing_error_response_is_minimal_400`); other malformed requests are logged and dropped (POA&M-63) |
| §22 digest verifier | Partial (proto layer) | Reviewed under POA&M-230. `digest_verifier.rs` (feature `digest-auth`): RFC 7616 server verifier with HMAC-SHA-384 nonce, pinned realm/algorithm/qop, digest-uri binding, opaque, nc replay committed after a match, bounded tracker. **Wired (sbc-daemon REGISTER, not reachable from shipped config):** `sip_stack.rs` `verify_register_digest` uses `DigestVerifier` when `require_auth` is set (registrar's own digest then disabled; it stays on if verifier setup fails). No sbc-config credential source exists yet (POA&M-270), so the path runs only in tests (`digest_register_challenge_then_success_audited`, `digest_register_rejects_each_audited_with_reason`, `digest_register_stale_nonce_rechallenges_with_stale_true`, `digest_register_failures_rate_limited`). Every reject gets 401 with a fresh challenge, a valid digest on an expired nonce gets `stale=true`, a valid digest whose user does not own the AOR gets 403 without `WWW-Authenticate` (RFC 3261 §10.3 step 3). **Deliberate deviation:** the daemon sends one challenge for the configured algorithm only (default SHA-256), not one per algorithm (RFC 7616 §3.7, RFC 8760 §2.4 allow several); MD5-only UAs cannot register and are rejected as `algorithm_mismatch`. Open: per-INVITE challenge (POA&M-271), cluster-shared nc (POA&M-272), `userhash` (POA&M-273); `verify` records nc before the response check, so a nonce holder can force `stale=true` re-challenges (proto-sip residual under POA&M-236). proto-registrar `authentication.rs` enforces the same checks; the daemon now uses it only as the fallback when verifier setup fails |
| RFC 3323 `Privacy` / RFC 3325 identity | Partial (proto layer) | `privacy.rs` (POA&M-232): `PrivacyHeader`, `apply_privacy` (`critical` fails closed with 500 before mutation), `sanitize_inbound_identity`, `rpid_to_pai` (only `screen=yes`, library-only). **Wired (sbc-daemon, POA&M-236):** ingress `sanitize_inbound_identity` for every source except trunks in a `trust_domain = true` group (default `false`, fail-closed per RFC 3325 §9.1; registered endpoints and API-registered trunk groups always untrusted, POA&M-287); egress `apply_privacy` after STIR, re-applied per failover; malformed `Privacy` 400; unsatisfiable `critical` 500 with resources released; Identity dropped when From is anonymized toward an untrusted peer. Tests `inbound_identity_sanitized_by_trust_domain`, `egress_privacy_follows_trust_domain`, `egress_privacy_critical_unsatisfied_500_and_malformed_400` |
| RFC 3323 topology hiding | Partial | Reviewed and fixed under POA&M-151 (CIDR matching, per-element rewrite, fail closed). Since POA&M-155, sbc-daemon hides Via/Contact/Record-Route on every request and Contact/Record-Route on every response toward a hidden leg (`SipStack::apply_egress_topology`); response Via is left byte-exact (RFC 3261 §8.2.6.2, §18.2.2); in 3xx only internal redirect targets are rewritten (§8.1.3.4); the SBC Via keeps a bare `rport` (RFC 3581); CANCEL and non-2xx ACK top Via equal the INVITE's (§9.1, §17.1.1.3; tests `th_bye_from_callee_and_cancel_are_hidden`, `th_non2xx_ack_via_matches_invite`). Since POA&M-181: Server/User-Agent/Warning removed and Reason reduced to `protocol;cause` toward hidden legs, SDP `o=` username `-` and address `external_host` (stable across re-offers, RFC 3264 §8), relayed 101-299 to the caller carries an SBC Contact (§12.1.1) (tests `th_residual_headers_scrubbed`, `th_sdp_origin_stable_across_reinvite`, `th_multipart_sdp_origin_scrubbed`, `relayed_2xx_has_sbc_contact`). `topology_hiding.mode` must be `signaling_only` or `full` when enabled (POA&M-183). Open: SDP `c=` is not rewritten when no media relay is anchored (accepted residual, POA&M-215); `message/sipfrag` reduced to its start line toward hidden legs, fail closed (POA&M-251 closed; tests `sipfrag_notify_reduced_to_status_line`, `sipfrag_notify_fails_closed`); other non-SDP bodies (text/plain, application/*) relayed as opaque payload (POA&M-274); proxy-model Via restore missing (POA&M-157) |
| RFC 3327 Path | Partial | Only list splitting fixed (`path_values` splits combined values) |

### sbc-daemon stream and WebSocket transport (RFC 7118, RFC 6455, RFC 3261 §18.3, RFC 5626 §4.4.1)

| Item | Status | Wiring | Notes |
|------|--------|--------|-------|
| RFC 7118 §4 `sip` subprotocol | Complete | Wired (sbc-daemon, plain WS) | `sip` echoed when offered; an upgrade without it gets HTTP 400 (`uc-transport/src/websocket.rs`). Tests `ws_handshake_accepts_sip_subprotocol_and_echoes_it`, `ws_handshake_rejects_missing_subprotocol`, `qa_ws_handshake_selects_sip_from_offer_list`, integration `ws_upgrade_without_sip_subprotocol_is_refused`. `transport.ws_require_sip_subprotocol = false` admits a missing header and is non-conformant (an offer of only other protocols is still refused, `ws_handshake_rejects_non_sip_subprotocol_even_when_not_required`) |
| RFC 7118 §5 one SIP message per WS message | Complete | Wired (sbc-daemon) | C-L optional but exact if present; a WS message without a header terminator is discarded and not joined to the next one (test `ws_partial_message_is_not_spliced`) |
| RFC 6455 §10.4 size limits | Complete | Wired (sbc-daemon) | Message and frame caps 65,535 bytes (`MAX_WS_MESSAGE_SIZE`, `sip_ws_config`). Tests `ws_rejects_message_over_64k`, `qa_ws_message_at_limit_is_delivered`, `qa_ws_fragmented_message_over_limit_rejected`, `ws_message_limit_fits_sip_stream_limit` |
| RFC 3261 §18.3 / §20.14 stream C-L | Complete (framing) | Wired (sbc-daemon) | Missing, duplicate, conflicting or malformed C-L on TCP/TLS: 400 (Via/From/To/Call-ID/CSeq) then close; bad responses are discarded silently. See the §18.3 row above |
| RFC 5626 §4.4.1 CRLF keep-alive pong | Complete | Wired (sbc-daemon, TCP/TLS) | Each CRLFCRLF ping is counted, including one split across reads; one CRLF pong is written per batch of pings read together, not one per ping. Keepalives count only after the first accepted message. Tests `crlf_ping_gets_single_crlf_pong`, `keepalive_counts_pings_and_waits_on_a_lone_crlf`, `crlf_after_first_message_keeps_flow_alive` |

#### RFC 4475 results (`crates/proto/proto-sip/tests/rfc4475.rs`)

| Result | Vectors | Notes |
|--------|---------|-------|
| Pass: valid, accepted | `wsinv`, `esc01`, `escnull`, `esc02`, `lwsdisp`, `longreq`, `dblreq`, `semiuri`, `transports`, `mpart01`, `unreason`, `noreason`, `badbranch`, `unksm2`, `bext01`, `invut`, `regaut01`, `bcast`, `zeromf`, `cparam01`, `cparam02`, `regescrt`, `sdp01` | Round-trip idempotent. `dblreq` with Stream framing is rejected (`dblreq_stream_framing_rejects_trailing_request`) |
| Pass: parse, then 400 | `insuf`, `inv2543` | Rejected by `validate_request_headers`, not the parser |
| Pass: invalid, rejected | `clerr`, `ncl`, `scalar02`, `scalarlg`, `ltgtruri`, `lwsruri`, `lwsstart`, `trws`, `badvers`, `mismatch01`, `mismatch02`, `bigcode`, `multi01`, `mcl01`, `baddn` | `baddn` passes only because the archive copy lacks the final CRLF; with it restored it is accepted (`baddn_with_terminating_crlf_is_known_gap`) |
| Gap (deviation): valid, rejected | `intmeth` | Escaped CTLs in a quoted-pair are rejected on purpose |
| Rejected with 416 (`UnsupportedUriScheme`) | `unkscm`, `novelsc` | parse fails with a 416-mapped error; the SBC answers 416 (POA&M-150) |
| Gap: invalid, accepted | `badinv01`, `quotbal`, `baddate`, `regbadct`, `badaspec` | Via/Contact params, To structure, URI grammar, Date, addr-spec not checked at parse time |
| RFC 4475 torture vectors | Partial | All 49 vectors in `crates/proto/proto-sip/tests/rfc4475.rs` (Datagram framing); see the table below |

### sbc-daemon B2BUA trunk routing (RFC 3263 §4.3, RFC 3261 §8.1.1, §21.5.4)

| Behaviour | Status | Wiring | Notes |
|-----------|--------|--------|-------|
| Failover to next trunk on 503 / timeout / transport error (RFC 3263 §4.3, RFC 3261 §8.1.3.1) | Complete | Wired (sbc-daemon) | `sip_stack.rs` `is_failover_status`, `try_failover`, `on_invite_sent`. 408, Timer B and 503 trigger failover; an unresolvable trunk URI also does. A transport error on the first send of a B-leg INVITE (UDP send error, TCP/TLS connect/handshake/write failure, 30 s send timeout) fails over immediately, once per attempt; with no trunk left the caller gets 503 (§8.1.3.1). Retransmission, ACK, CANCEL and in-dialog send failures are log-only. POA&M-2 closed. Tests `failover_on_503_retries_next_trunk_with_same_sdp`, `timer_b_fails_over_then_408_when_exhausted`, `qa_every_failover_status_moves_call_to_second_trunk`, `send_failure_fails_over_once_without_waiting_for_timer_b`, `send_failure_with_no_trunk_left_answers_503_and_releases`, `qa_send_failure_of_cancel_ack_and_in_dialog_is_log_only`, `slow_first_send_failing_after_timer_a_still_fails_over_once`. The `server.rs` wiring from a real socket error to `on_invite_sent` has no socket-level test |
| Failover on 500/502/504 | Local policy | Wired (sbc-daemon) | Beyond RFC 3263 §4.3; B2BUA policy. Same tests |
| No failover on other 4xx / 6xx, or after 2xx / reliable 18x with SDP | Complete | Wired (sbc-daemon) | Tests `callee_reject_does_not_fail_over`, `qa_client_and_global_errors_never_fail_over`, `no_failover_after_reliable_early_media`, `qa_failover_still_happens_after_unreliable_or_sdp_less_18x`. A reliable 18x **without** SDP does not commit the call; the caller's early dialog with the first trunk is abandoned on failover (RFC-003, RFC 3262) |
| Failover request construction (§8.1.1, §17.1.1) | Complete | Wired (sbc-daemon) | New Call-ID, branch, From tag, CSeq, untagged To; non-2xx ACKed on the failed trunk first. R-URI scheme/host/port/transport, Via transport/sent-by port and Contact scheme come from the target trunk, and the attempt is sent on that trunk's transport (§18.1.1, §19.1.1, §26.2). RFC-005 / POA&M-5 closed |
| Late INVITE 2xx after release (§13.2.2.4, §13.3.1.4, §17.1.1.3) | Partial | Wired (sbc-daemon) | POA&M-185: an unanswered B-leg INVITE is remembered for 32 s (64×T1, at most 4096 records). A matching late 2xx (Call-ID, branch, CSeq, source IP) is ACKed (new branch, Route = Record-Route reversed, at most 16) and the first time each To-tag is seen it is BYE'd (CSeq INVITE+1). **Deviations:** only the first 4 To-tags per call get a BYE, later forks are ACKed only (§13.2.2.4 SHOULD; bounded state, `RELEASED_CALL_MAX_TAGS`); ACK and BYE are sent to the stored B-leg destination and flow, not the next hop derived from Route/Request-URI (§12.2.1.1, B2BUA choice per RFC 7092; Contact supplies only the sanitised Request-URI). Tests `late_2xx_after_cancel_is_acked_and_byed`, `late_2xx_retransmit_reacks_only`, `late_2xx_forked_new_tag_gets_bye`, `late_2xx_wrong_branch_ignored`, `late_2xx_from_wrong_source_ignored`, `late_2xx_after_ttl_ignored`, `late_2xx_from_superseded_failover_attempt_is_byed` |
| Post-announcement BYE transport (§18.1.1, §18.2.2, RFC 5923) | Complete | Wired (sbc-daemon) | POA&M-184: sent on the caller's own transport/connection (`LegFlow::inbound`), Via transport and port from `flow::via_for` (`rport` on UDP only, RFC 3581), tracked as a non-INVITE client transaction (§17.1.2), Request-URI = sanitised caller Contact (§12.2.1.1), destination = the transport source. CSeq is the constant 2, which assumes no other SBC-originated in-dialog request on that dialog. Tests `announcement_bye_uses_caller_flow_tls`, `announcement_bye_udp_has_rport`, `announcement_bye_contact_injection_sanitised` (no real-socket TLS test) |
| Per-connection message order (§18.1.1, §18.2.2) | Partial | Wired (sbc-daemon) | Stream sends go through per-`(transport, dest)` lanes, and an origin reply waits behind a busy lane (`server.rs` `dispatch`, `flows.rs` `lane_busy`; tests `lanes_keep_order_and_isolate_a_stalled_destination`, `origin_reply_waits_for_its_busy_lane`, `invite_failover_follow_up_is_sent_on_its_lane`). Residuals: trunks sharing a host:port share one lane (NIST POA&M-52); UDP receive results are processed on per-message tasks and are not ordered (POA&M-53); a job dropped by a full lane is not sent (an INVITE fails over at once) |
| Trunk 503 Retry-After (§21.5.4, §20.33) | Complete | Wired (sbc-daemon) | **RFC-001 (PR 155) resolved.** `sip_stack.rs` `retry_after_cooldown`: delta-seconds sets the trunk cooldown, honoured down to 1 s and clamped to `general.trunk_retry_after_max_secs` (default 300, 1..=3600); a trailing `( comment )` (nested, quoted-pairs) and `;params` are accepted and ignored; missing, 0 or malformed values (`1e9`, `120x`, `120 abc`, unbalanced comments) fall back to `cooldown_secs`. Applied on failover and on a final 503. Tests `retry_after_cooldown_honoured_clamped_or_fallback`, `failover_503_retry_after_sets_trunk_cooldown`, `final_503_without_failover_honours_retry_after`, `qa_failover_503_retry_after_short_and_with_comment` |
| Relayed downstream 503 when failover is exhausted | Gap | Wired (sbc-daemon) | The last trunk's 503 is relayed unchanged, so an upstream may treat the SBC as overloaded (RFC-002; re-raised as RFC-004, NIST POA&M-58) |
| `sips:` Request-URI forces TLS at trunk egress (§26.2.2) | Complete | Wired (sbc-daemon, uc-routing) | A `sips:` R-URI sets `tls_only` for the call: only `tls` trunks are eligible in every routed group, including cross-group failover, DNS-failure retry and `try_failover` (`route_to_trunk`, `TrunkLease.tls_only`, `Router::*_for_tls`). No TLS trunk: policy 503. Tests `sips_invite_to_mixed_group_never_egresses_clear`, `sips_invite_only_clear_trunks_gets_policy_503`, `tls_only_call_skips_non_tls_without_group_flag` |
| Trunk `require_tls` (local policy, SC-8) | Partial | Wired (sbc-daemon, uc-routing) | Per group (`trunk_groups[].require_tls`) or global (`security.require_tls_trunks`). Per-group scope: a `sip:` call can fall back from a TLS-only group to a plain group later in the route list (NIST POA&M-57). Tests `require_tls_group_skips_udp_tcp_on_primary`, `require_tls_failover_skips_udp_tcp` |
| Default trunk port by transport (§19.1.2, RFC 3263 §4.2) | Complete | Wired (sbc-daemon, API) | An API/synced trunk without a port uses 5061 for `tls` and 5060 otherwise (`trunk_policy::trunk_port`, `TrunkTransport::default_port`); invalid ports are rejected (400) or the trunk is skipped on sync. Tests `port_parsing`, `synced_trunk_port_follows_transport` |
| Policy 503 when no TLS trunk is eligible (RFC 6432) | Complete | Wired (sbc-daemon) | `503` with `Reason: Q.850;cause=79;text="no TLS trunk"` and no `Retry-After` (a retry cannot succeed until configuration changes), unlike the outage 503. Tests `require_tls_all_non_tls_gives_503_no_udp_datagram`, `qa_api_unknown_protocol_trunk_is_skipped_end_to_end` |
| SBC-generated 503 + Retry-After (§21.5.4) | Complete | Wired (sbc-daemon) | All trunks full/down: `503`, `Retry-After: 5` (test `trunk_at_max_calls_is_skipped_then_503_when_all_full`). `general.max_registrations` exceeded: `503`, `Retry-After: 60` (tests `max_registrations_rejects_new_bindings_but_allows_refresh`, `qa_max_registrations_counts_bindings_and_allows_deregistration_forms`) |
| Admission-ceiling 503 (`general.max_calls`, + emergency reserve) | Gap | Wired (sbc-daemon) | The 503 sent when `general.max_calls` (or `max_calls + emergency_reserve_calls` for an emergency call) is reached carries **no `Retry-After`** (§21.5.4 SHOULD), so callers, including emergency callers, may redial at once |
| Translated number in B-leg R-URI user and To (§8.1.1, §25.1) | Complete | Wired (sbc-daemon) | Restricted to unreserved/user-unreserved characters, max 64; otherwise 500. Tests `translated_number_is_on_b_leg_request_uri_and_to`, `qa_header_injection_in_translated_number_is_rejected`, `qa_translated_number_on_failover_invite_wire_bytes` |
| Blocked route pattern answers 403 (§21.4.4) | Complete | Wired (sbc-daemon, uc-routing) | `SbcRouteOutcome::Blocked` ends routing; 403 with no dial-plan or default-group fallback, pattern id only in the audit, not the reason phrase. Test `blocked_route_pattern_answers_403_without_dial_plan_or_default_fallback` |
| Unroutable emergency call answers 503 without Retry-After (§21.5.4, RFC 6881 §5) | Complete | Wired (sbc-daemon) | A retry cannot succeed until configuration changes, so no `Retry-After`. Test `unroutable_emergency_call_gets_503_without_retry_after` |
| Non-routable numeric-looking, empty or oversize R-URI user answers 404 (§21.4.4) | Complete | Wired (sbc-daemon, uc-types) | `DialedNumber::is_routable`; tests `sec001_numeric_looking_opaque_user_is_not_routed`, `sec004_oversize_user_does_not_match_catch_all`. 414 (§21.4.12) for >256 bytes and 484 (§21.4.20) for empty would be more informative (RFC-006, RFC-007, MAY) |
| Dialled-number canonicalisation (§19.1.2 `%xx`, RFC 3966 §5.1.1 visual separators) | Partial | Wired (sbc-daemon, uc-routing, uc-vps) | `uc-types/src/dialed_number.rs`. Invalid escapes become opaque; `%2B` gives a global number |
| RFC 3966 §5.1.5 / §4 `;phone-context` (RFC-002) | Gap | Wired (sbc-daemon) | The context is dropped, so `555;phone-context=+44` and `555;phone-context=example.com` both become local `555` for routing, blocks and emergency classification (e.g. `tel:911;phone-context=+44` is treated as emergency). POA&M-100 |
| Translated local number keeps `;phone-context` (RFC 3966 §5.1.5, RFC-003) | Gap | Wired (sbc-daemon) | When a transform changes the number, the B-leg user carries no `;phone-context`; a non-global result in a `user=phone`/tel R-URI is non-conformant. POA&M-100 |
| RFC 5031 §4 / RFC 6881 §6.2 `urn:service:sos` (RFC-004) | Gap | Wired (sbc-daemon) | Emergency classification uses only the R-URI user digits. A service-URN R-URI is not force-routed, can be blocked (403) and is subject to the per-user limiter. Pre-existing |
| Emergency INVITE exempt from per-user limiter (RFC 6881 §5/§9) | Complete | Wired (sbc-daemon) | `sip_stack.rs` `user_rate_limit` uses the same classifier as `handle_invite`. Only INVITE is exempt. Test `emergency_invite_bypasses_per_user_limiter`. Per-source flood bound open (POA&M-103) |
| Per-user limiter 503 + `Retry-After: 1` (§21.5.4) | Complete | Wired (sbc-daemon) | Keyed on the authenticated AOR (flow bound by REGISTER) or on source /32 or /64 plus canonical From user. The 503 is sent before a server transaction exists, so retransmissions each get a fresh 503 (RFC 3261 §17.2.1, RFC-005, pre-existing). Test `per_user_rate_limit_answers_503_with_retry_after` |

### sbc-daemon CDR (RFC 3326, RFC 3264, RFC 5424 / 5425 / 6587)

Call Detail Records read SIP and SDP facts and ship records to syslog. This code is in `sbc-daemon/src/cdr.rs` and `uc-cdr/src/sink.rs`; it does not use proto-sdp or uc-syslog.

| Behaviour | Status | Wiring | Notes |
|-----------|--------|--------|-------|
| RFC 3326 Reason: every header field, comma-separated values, quoted `text` | Complete | Wired (sbc-daemon) | `sip_stack.rs` `reason_headers()` feeds `CdrEnd::with_reasons`. `split_unquoted` follows the RFC 3261 §25.1 quoted-string and quoted-pair rules for `,` and `;`. The first `protocol=Q.850` cause in 1..=127 wins. Tests `q850_parses_rfc3326_reason`, `q850_from_separate_reason_headers`, `cdr_answered_then_callee_bye_with_q850` |
| RFC 3264 §6 port 0 = rejected stream | Complete | Wired (sbc-daemon) | `media_facts` skips `m=audio 0` and `0/n` and takes the first payload of the first accepted audio stream from the answer. Test `media_facts_skips_rejected_audio_stream` |
| RFC 8866 §5.14 attribute scoping to the m-section; encoding-name case folding | Gap | Wired (sbc-daemon) | `a=rtpmap` / `a=crypto` are not scoped to the chosen m-section. An `a=crypto` under a rejected `m=audio 0` can still be credited. Encoding names keep the received case (RFC-5, NIST POA&M-23) |
| RFC 3551 Table 4 static payload types | Partial | Wired (sbc-daemon) | Only PT 0/8/9/18 are named without `a=rtpmap` (RFC-7, NIST POA&M-23) |
| RFC 3551 §4.2 receive packet size (soft client) | Gap | Wired (soft client) | Received frames longer than one ptime (20 ms) are dropped and counted (`oversized_frames_dropped`, `client-audio/src/decode_thread.rs`) while the SDP offers `a=maxptime:120`; §4.2 SHOULD accept 0-200 ms (POA&M-310) |
| RFC 5424 message format (PRI, VERSION, TIMESTAMP, MSGID, SD, §6.4 BOM) | Complete | Wired (sbc-daemon, opt-in) | PRI = facility * 8 + 6, VERSION 1, UTC timestamp with `Z`, MSGID `CDR`, NILVALUE SD, UTF-8 BOM before the JSON MSG. Header tokens are limited to PRINTUSASCII. Hand-formatted in `uc-cdr`, not via `uc-syslog`. Tests `syslog_octet_counted_rfc5424`, `syslog_sink_octet_counted_frames_via_fake_connector` |
| RFC 6587 §3.4.1 octet-counting framing | Complete | Wired (sbc-daemon, opt-in) | The count is the MSG byte length including the 3 BOM octets. Same tests |
| RFC 5425 TLS transport | Partial | Wired (sbc-daemon, opt-in) | TLS 1.3 only, CNSA 2.0 suite and groups (`uc_transport::tls::create_client_config` / `cnsa_provider`; POA&M-26 closed). The server is authenticated against `cdr.syslog.ca_path` or `security.tls_ca_path`. **Gap:** §4.2 mutual authentication is absent because no client certificate is sent (NIST-06, POA&M-15). Handshake test: `syslog_tls_is_cnsa_only` |
| SIP transport recorded in the CDR | Gap | Wired (sbc-daemon) | SCTP (RFC 4168) A-legs are recorded as `tcp`: schema v1 has no `sctp` value (POA&M-20) |

### uc-syslog (RFC 5424 / 5425 / 6587; library-only)

Not called by any shipped binary (NIST POA&M-245). Added 2026-11-07.

| Behaviour | Status | Wiring | Notes |
|-----------|--------|--------|-------|
| RFC 5424 message format | Partial | Library-only | HOSTNAME, APP-NAME, PROCID and MSGID are inserted verbatim (`uc-syslog/src/formatter.rs`); §6.2 PRINTUSASCII, length limits and NILVALUE for empty fields are not enforced. TLS with RFC 3164 format is refused (`tls_with_bsd_format_rejected`) |
| RFC 6587 / RFC 5425 §4.3 octet counting | Complete | Library-only | TLS frames are `MSG-LEN SP SYSLOG-MSG` (`octet_counted_frame`). Plain TCP keeps LF framing. Tests `tls_octet_counted_framing`, `tls_delivers_octet_counted_frames` |
| RFC 5425 TLS transport | Partial | Library-only | CNSA `cnsa_provider()` client config, TLS 1.3 by default; server path validation against `ca_file` + `server_name`; optional client certificate (§4.2); close_notify via `close()`; port 6514 default. **Gaps:** §5.2.2 end-entity fingerprint matching absent (SHA-1 mandatory-to-implement conflicts with CNSA 2.0; workaround: self-signed cert in `ca_file`); at-least-once delivery on reconnect; no buffering when the collector is down. Tests `untrusted_server_cert_rejected`, `wrong_server_name_rejected`, `half_client_auth_rejected`, `drop_without_close_is_truncation` |

### sbc-daemon STIR/SHAKEN (RFC 8224, 8225, 8226, 8588, ATIS-1000074)

Off by default; enabled per trunk (`stir_shaken.sign` / `verify`). Code: `proto-stir-shaken`, `uc-sti`, `uc-crypto` (`interop::ecdsa_p256`, `x509`), `sbc-daemon/src/stir.rs`, `stir_binding.rs`, `sip_stack.rs`.

| Behaviour | Status | Wiring | Notes |
|-----------|--------|--------|-------|
| RFC 8224 §4.1 Identity header grammar (`info`, `alg`, `ppt`) | Complete | Wired (sbc-daemon) | Duplicate params rejected, unknown ignored, 4 KiB / 16-param caps. Tests `parse_shaken_header`, `rejects`, `qa_stir_malformed_identity_table` |
| RFC 8224 §6.2.2 / §13 response codes 428, 436, 437, 438, 403 Stale Date | Complete | Wired (sbc-daemon), only with `failure_policy = "reject"` (default `mark`) | `Reason: SIP;cause=N;text=".."` added. Tests `codes`, `stir_missing_identity_with_require_is_428`, `qa_stir_stale_iat_rejected_403_stale_date`, `stir_reason_phrases` |
| RFC 8224 §4.1 / §6.1 Date corresponds to `iat` | Complete | Wired (sbc-daemon) | Signer replaces B-leg `Date`. Test `sign_outbound_adds_identity_on_sign_trunks_only` |
| RFC 8224 §8.3 TN canonicalisation | Partial | Wired (sbc-daemon) | Separators and `+` stripped; non-E.164 numbers are not converted to E.164 by local policy (RFC-004, POA&M-44) |
| RFC 8224 §5 / ATIS `orig` source (PAI else From) | Partial | Wired (sbc-daemon) | Signer uses PAI else From; verifier accepts a match on either PAI or From (RFC-005, POA&M-45) |
| RFC 8225 PASSporT encoding (§9 deterministic JSON) and strict decode | Complete | Wired (sbc-daemon) | Tests `sign_decode_roundtrip`, `malformed_cases`, proptests |
| RFC 8225 / ATIS-1000074 ES256 signatures | Complete (CNSA exception) | Wired (sbc-daemon) | ES256 is a CNSA 2.0 deviation (POA&M-27), compiled into every SBC build (POA&M-39). ES384 rejected (POA&M-32) |
| RFC 8226 STI certificate chain and TNAuthList | Partial | Wired (sbc-daemon) | Chain to STI-CR anchors; TN/range scope checked; SPC scope not checked (POA&M-30); **no CRL/OCSP** (POA&M-28) |
| RFC 8588 `attest`, `origid` | Complete | Wired (sbc-daemon) | Policy `uc-sti/src/policy.rs`; UDP-registered endpoints capped at B, A needs a TCP/TLS registration on the same connection (RFC 5626 §3.1/§5.2 flow: `ConnId`, unbound on close; tests `poam36_*`). Not bound to the TLS peer certificate (POA&M-70) |
| RFC 8946 `div` PASSporT | Missing | — | `ppt=div` ignored (test `div_is_ignored`) |
| Replay protection (RFC 8224 §12 guidance) | Missing | — | No replay cache (decision D7, POA&M-43); only `iat` freshness |
| RFC 8224 §7.3 `info` URI dereference (local policy) | Complete | Wired (sbc-daemon) | No wire change. Per-source `x5u` fetch budget `stir_shaken.verification.max_fetches_per_source` (default 4; IPv6 per /64); over budget uses the existing cert-fetch-busy failure path (POA&M-190). Empty `x5u_allow_hosts` with a verifying trunk logs a startup warning; host restriction is ATIS-1000080 / local policy, not an RFC 8224 rule. Sizing: a carrier trunk sending from one IP with many distinct uncached certificates after a restart will see calls beyond the budget marked cert-fetch-busy (degraded verstat, no retry) until certificates are cached; raise the value for such trunks (max `max_concurrent_fetches`). Residual: shared carrier IP, /48 holders, spoofed UDP (POA&M-196). Tests `per_source_fetch_budget`, `allow_list_warning_only_for_open_verify` |
| ATIS-1000074 §5.3.1 `info == x5u`, verstat on PAI else From | Complete | Wired (sbc-daemon) | Tests `verstat_rewrite`, `stir_failed_identity_mark_forwards_with_failed_verstat` |

---

## proto-transaction (RFC 3261 §17 + RFC 3262)

### RFC 3261 §17 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §17.1.1 | INVITE Client Transaction | Complete | Wired (sbc-daemon, soft client) | `client.rs` FSM (`sip_stack.rs`, `call_agent.rs`) |
| §17.1.2 | Non-INVITE Client Transaction | Complete | Wired (sbc-daemon, soft client) | `client.rs` FSM (`sip_stack.rs`, `registration.rs`) |
| §17.1.3 | Matching Responses | Complete | Wired (sbc-daemon) | `TransactionKey::client` |
| §17.1.4 | Handling Transport Errors | Partial | Wired (sbc-daemon), partial | Basic error propagation in the library FSM. sbc-daemon handles a first-send transport error on a B-leg INVITE in `sip_stack.rs` `on_invite_sent` (removes the client transaction, then fails over or answers 503), not through the FSM; other client transactions are not informed of transport errors |
| §17.2.1 | INVITE Server Transaction | Complete | Wired (sbc-daemon) | `server.rs` FSM |
| §17.2.2 | Non-INVITE Server Transaction | Complete | Wired (sbc-daemon) | `server.rs` FSM |
| §17.2.3 | Matching Requests | Complete | Wired (sbc-daemon) | `TransactionKey::server`; retransmissions absorbed |
| §17.2.4 | Handling Transport Errors | Partial | Library-only | Basic error propagation |

Timers: the daemon acts on Timer A/B/E/F/G/H in `poll_timers` and prunes transactions terminated by Timer D/I/J/K. The soft client does not poll transaction timers.

Transport-dependent timers (§17.1.1.2, §17.1.2.2, §17.2.1, §17.2.2): the daemon builds client and server INVITE/non-INVITE transactions as `Reliable` when the request arrived on a connection-oriented transport (TCP/TLS/WS/WSS/SCTP) and `Unreliable` for UDP (`sip_stack.rs` `txn_transport`, `process_message_on`; `server.rs` `stream_connection_loop` passes `transport.transport_type()`). On reliable transports Timer A/E/G do not run, Timer B/F/H still run, and Timer D/I/J/K are 0. Tests: `txn_transport_maps_connection_oriented_to_reliable`, `reliable_invite_client_txn_has_no_timer_a_but_times_out_on_timer_b` (checks the Timer B deadline is at least 31 s out; does not wait for expiry), `udp_invite_client_txn_still_retransmits_timer_a`, `reliable_non_invite_client_txn_has_no_timer_e`, `udp_non_invite_client_txn_still_retransmits_timer_e`, `reliable_server_invite_txn_has_no_timer_g`, `qa_reliable_server_non_invite_txn_has_zero_timer_j`, `qa_udp_server_non_invite_txn_absorbs_retransmit_during_timer_j`. Limits: the `stream_connection_loop` wiring has no end-to-end test (no TCP trunk harness), so a regression there would be caught only by review. Since POA&M-5, every result (including those from `poll_timers` and `on_invite_sent`) carries its leg's flow. Client transactions are opened with the transport the request is actually sent on (the B-leg trunk's protocol, not the caller's), so failover INVITEs, BYEs and 408s use the right timers (§17.1.2.2) and go out on the right transport (§18.1.1, §18.2.2). The SBC Via names that transport and its listener port (§20.42; config validation rejects a `tcp`/`tls` trunk when no `transport.tcp_listen`/`tls_listen` exists, so no port is invented), WS legs name the `ws_listen` port (RFC 7118 §5), UDP Vias carry `;rport` (RFC 3581 §3), TLS trunks get `sips:` URIs (§26.2), and a B-leg CANCEL reuses the current attempt's INVITE Request-URI, including after failover (§9.1). A registered user is reached only over the transport and source the REGISTER arrived on. Limit: a closed accepted connection is not re-opened toward the Via sent-by (§18.2.2 SHOULD). The send fails and is not retried over UDP.

### RFC 3262 Section Mapping (100rel)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §3 | UAS Behavior | Complete | Library-only | `prack.rs` ReliableProvisionalTracker |
| §4 | UAC Behavior | Complete | Library-only | `prack.rs` ClientReliableProvisionalTracker |
| §5 | RSeq Header | Complete | Library-only | RSeq generation |
| §6 | RAck Header | Complete | Library-only | RAck validation |
| §7 | PRACK Processing | Complete | Library-only | State machine |

RFC 3261 §17 is wired into sbc-daemon and the soft client. The `prack.rs` trackers above remain library-only. Since POA&M-182 sbc-daemon relays 100rel/PRACK as a B2BUA without using them (see next section); the daemon's Allow header still omits PRACK (RFC-006 below).

### Daemon in-dialog non-session relay (sbc-daemon, POA&M-182)

| Item | Status | Wiring | Notes |
|------|--------|--------|-------|
| RFC 6086 INFO, RFC 3428 MESSAGE, RFC 6665 NOTIFY in-dialog relay | Partial | Wired (sbc-daemon) | Tagged-To requests relayed to the other leg (`sip_stack.rs` `relay_in_dialog_non_session`), responses relayed back (`handle_relay_response`), 100 absorbed, Timer F gives 408 to the originator. NOTIFY must carry Event and Subscription-State (400 otherwise). 481 for no dialog / From-tag mismatch (RFC 3261 §12.2.2). Out-of-dialog MESSAGE/NOTIFY still 405. Tests `in_dialog_info_relayed_a_to_b_hides_topology`, `in_dialog_message_relayed_b_to_a_hides_topology`, `in_dialog_notify_relayed_keeps_event_and_sbc_contact`, `in_dialog_relay_unknown_dialog_and_tag_mismatch_481`, `out_of_dialog_message_notify_unchanged_405`, `timer_f_on_relayed_info_yields_408` |
| In-dialog CSeq (RFC 3261 §12.2.1.1) | Complete | Wired (sbc-daemon) | CSeq reserved under the correlation write lock for relayed requests, re-INVITE/UPDATE and BYE (`reserve_local_cseq`). Test `concurrent_relays_get_distinct_cseqs` |
| RFC 3262 100rel offered to callee | Partial | Wired (sbc-daemon) | `Supported: 100rel` on the B-leg INVITE only when the caller offered it; `Require: 100rel` when the caller required it (callee 420 relayed). Tests `b_leg_invite_supported_100rel_only_when_caller_offered`, `b_leg_invite_requires_100rel_when_caller_required` |
| RFC 3262 reliable 1xx and PRACK relay | Partial | Wired (sbc-daemon) | Reliable 1xx relayed with `Require: 100rel` and RSeq unchanged when the caller supports 100rel, otherwise stripped (test `reliable_1xx_stripped_when_caller_lacks_100rel`). RSeq tracked per fork (B-leg To-tag, max 8 early dialogs); PRACK RAck strictly parsed (400 if malformed), must name INVITE, the A-leg INVITE CSeq and an RSeq relayed on that fork (481 otherwise), rewritten to the B-leg INVITE CSeq and sent in that fork's early dialog. PRACK from the B leg gets 481. Tests `prack_rack_cseq_rewritten`, `prack_routed_to_forked_early_dialog` |
| RFC-004: 408 from far leg on relayed request | Gap | Wired (sbc-daemon) | A far-leg 408 or 481 to a relayed request releases the call; a local Timer F does not. RFC 5057 requires release only for 481 |
| RFC-005: RFC 6086 Recv-Info negotiation | Gap | Wired (sbc-daemon) | `Recv-Info` crosses only on relayed INFO and its responses, not on the initial INVITE/18x/2xx or re-INVITE/UPDATE, so strict RFC 6086 peers may not send package INFO or may answer 469 |
| RFC-006: Allow omits relayed methods | Gap | Wired (sbc-daemon) | `ALLOWED_METHODS` unchanged by design; Allow does not list PRACK/INFO/MESSAGE/NOTIFY although they are relayed in-dialog |
| RFC-007: PRACK Request-URI in early dialog | Gap | Wired (sbc-daemon) | PRACK uses `build_leg_in_dialog_request`, so the Request-URI is the trunk address, not the remote target from the 1xx Contact (same as §12.2.1.1 gap above / NIST POA&M-54) |
| 2xx from a later fork | Gap | Wired (sbc-daemon) | Pre-existing: the A-leg final 2xx uses the first learned B-leg To-tag (`dialog_to_tag`); a 2xx from a non-first fork is not mapped to its own dialog |
| Non-SDP bodies | Gap | Wired (sbc-daemon) | Relayed as opaque payload, not scrubbed (NIST POA&M-251) |

---

## proto-dialog (RFC 3261 §12 + RFC 3515 + RFC 4028 + RFC 6665)

### RFC 3261 §12 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §12.1.1 | UAS Behavior | Complete | Library-only | Dialog creation from request; daemon dialog map never populated, soft client `dialog` field never assigned. proto-sip `RouteSet` UAS route set keeps Record-Route order (POA&M-231; test `route_set_order_uas_in_order_uac_reversed`) |
| §12.1.2 | UAC Behavior | Complete | Library-only | Dialog creation from response. proto-sip `RouteSet` UAC route set reverses Record-Route, including elements inside one comma-joined header (POA&M-231). proto-dialog `set_route_set` / `ForkContext::receive_*` expect a route set already in sending order (doc only) |
| §12.2.1 | UAC Behavior (In-Dialog) | Complete | Library-only | Request construction; daemon builds in-dialog requests itself (`sip_stack.rs`) |
| §12.2.1.1 | Daemon in-dialog request target and route set | Gap | Wired (sbc-daemon) | Pre-existing: `build_leg_bye` / `build_leg_in_dialog_request` use the peer's socket address as Request-URI (`sips:` on TLS legs since POA&M-5) and send no Route set; the remote target (Contact) and Record-Route are ignored (NIST POA&M-54) |
| §12.2.2 | UAS Behavior (In-Dialog) | Complete | Library-only | Response handling |
| §12.3 | Termination | Complete | Library-only | BYE processing |

### RFC 3515 Section Mapping (REFER)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §2.1 | REFER Method | Complete | Wired (soft client) | Soft client sends REFER (`call_agent.rs`); daemon does not handle REFER |
| §2.2 | Refer-To Header | Complete | Wired (soft client) | `ReferRequest` |
| §2.3 | Referred-By Header | Complete | Wired (soft client) | `ReferRequest::with_referred_by` |
| §2.4 | Implicit Subscription | Complete | Wired (soft client) | `refer.rs`; NOTIFY tracked via `ReferRequest`/`ReferStatus` |
| §3 | NOTIFY Bodies | Partial | Wired (soft client, sbc-daemon relay) | sipfrag parsed by the soft client's own code; sbc-daemon relays in-dialog NOTIFY sipfrag reduced to its start line toward hidden legs (POA&M-251) |

### RFC 4028 Section Mapping (Session Timers)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §4 | Session-Expires Header | Complete | Wired (sbc-daemon, soft client) | Header handled via proto-sip `HeaderName`; daemon relays it across legs (`sip_stack.rs`). proto-dialog `session_timer.rs` itself has no caller |
| §5 | Min-SE Header | Complete | Wired (sbc-daemon, soft client) | Same as §4 |
| §7.1 | UAS Behavior | Complete | Wired (sbc-daemon) | Daemon answers body-less refreshes locally and names the refresher (own code in `sip_stack.rs`) |
| §7.2 | UAC Behavior | Complete | Wired (soft client) | Soft client adopts the negotiated interval (own code in `call_agent.rs`) |
| §9 | 422 Response | Complete | Library-only | `handle_422_response()` has no caller; the soft client handles 422/Min-SE with its own code |

### RFC 6665 Section Mapping (Event Framework)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §4.1 | SUBSCRIBE Processing | Complete | Library-only | `subscription.rs`; daemon has no SUBSCRIBE/NOTIFY dispatch |
| §4.2 | NOTIFY Processing | Complete | Library-only | Notifier implementation |
| §4.3 | Subscription State | Complete | Library-only | State machine |
| §4.4 | Forking | Partial | Library-only | Basic forking support (`forking.rs`) |
| §7.2 | Event Package Registration | Complete | Library-only | `subscription.rs` EventPackageRegistry |

---

## proto-registrar (RFC 3261 §10 + RFC 5626 + RFC 5627)

### RFC 3261 §10 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §10.2 | Constructing the REGISTER | Complete | Wired (sbc-daemon) | Daemon builds `RegisterRequest` from the inbound REGISTER (`sip_stack.rs`) |
| §10.2.1 | Adding Bindings | Complete | Wired (sbc-daemon) | `AuthenticatedRegistrar::process_register` |
| §10.2.2 | Removing Bindings | Complete | Wired (sbc-daemon) | Expires=0 handling |
| §10.2.3 | Fetching Bindings | Complete | Wired (sbc-daemon) | `LocationService::lookup` for call routing |
| §10.3 | Processing REGISTER | Partial | Wired (sbc-daemon) | Full registrar logic incl. 401 challenge; cluster mode uses `AsyncLocationService`. `max_registrations` admission runs after auth (`process_register_with_admission`). Known pre-existing gaps: RFC-R1-01 processing is not atomic (step 8 all-or-nothing); RFC-R1-02 a duplicate contact yields 500; RFC-R1-03 (partly fixed) `expires=0` removal now matches by binding key (`remove_binding_by_key`; tests `expires_zero_outbound_removes_only_outbound`, `expires_zero_plain_removes_only_plain`, `wildcard_removes_shared_uri_bindings`) and a moved flow (same key, new URI) is subject to the Call-ID/CSeq check (test `moved_flow_with_stale_cseq_is_rejected`), but plain `expires=0` removal still has no Call-ID/CSeq ordering check (step 7); RFC-R1-04 `TooManyContacts` yields 500 instead of a 4xx/503 |

### RFC 5626 Section Mapping (Outbound)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §4.2 | Instance-ID | Complete | Wired (sbc-daemon) | Daemon parses `+sip.instance` into the binding |
| §4.3 | Reg-ID | Complete | Wired (sbc-daemon) | Daemon parses `reg-id` into the binding |
| §4.4 | Flow Token | Partial | Library-only | Generation only |
| §4.4.1 | CRLF keep-alive (server pong) | Complete | Wired (sbc-daemon, TCP/TLS) | One CRLF pong per batch of pings; see sbc-daemon stream transport section |
| §5.1 | Outbound Proxy Discovery | Partial | Library-only | Basic support |
| §5.2 | Registrar Flow Maintenance | Complete | Library-only | `outbound.rs` FlowManager; no caller |
| §5.3 | Edge Proxy Routing | Complete | Library-only | Flow token routing; no caller |

### RFC 5627 Section Mapping (GRUU)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §3.1 | Public GRUU | Complete | Library-only | `gruu.rs` generation |
| §3.2 | Temporary GRUU | Complete | Library-only | `gruu.rs` generation |
| §4.1 | Requesting a GRUU | Complete | Library-only | sip.instance handling |
| §4.2 | GRUU in Contact | Complete | Library-only | Response generation |
| §5.1 | Proxy GRUU Routing | Complete | Library-only | `gruu.rs` GruuRouter |

---

## proto-ice (RFC 8445 + RFC 7675)

The soft client gathers candidates, exchanges them in SDP and runs connectivity checks on the media socket (`client-sip-ua/src/ice_handler.rs`: paced checks, retransmission, role conflict, regular and aggressive nomination, answering the peer's checks), falling back to the SDP `c=`/`m=` address on ICE mismatch (RFC 8445 §5.1.1) or failure. STUN servers and the nomination mode come from `[network]` settings (`client-core/src/app.rs`); TURN is not configurable (no password setting). Keepalives (§10) and consent (RFC 7675) still do not run. The SBC does not use ICE: it anchors media and latches symmetrically; the former dead `ice_agent.rs` was removed.

### RFC 8445 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §5.1 | Candidate Types | Complete | Wired (soft client) | `candidate.rs`; host candidates only in practice |
| §5.1.2 | Priority Calculation | Complete | Wired (soft client) | Formula implemented |
| §6.1 | Connectivity Checks | Complete | Library-only | `connectivity.rs` |
| §6.1.2 | Check Procedures | Complete | Library-only | STUN checks |
| §6.1.4 | Triggered Checks | Complete | Library-only | Queue implemented |
| §7.2 | Nominating | Partial | Library-only | USE-CANDIDATE only |
| §7.2.1 | Regular Nomination | Complete | Library-only | Basic nomination |
| §7.2.2 | Aggressive Nomination | Complete | Library-only | `connectivity.rs` |
| §8.1 | Updating States | Complete | Library-only | State machine; soft client only reads the gathering state |
| §9 | Consent | Partial | Library-only | ConsentTracker exists |
| §10 | Keepalives | Complete | Library-only | KeepaliveTracker |
| §11 | ICE Restart | Partial | Library-only | Basic restart |

### RFC 7675 Section Mapping (Consent Freshness)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §3 | Consent Mechanism | Complete | Library-only | STUN Binding |
| §4 | Consent Procedures | Partial | Library-only | Tracking only |
| §4.1 | Consent Check Interval | Complete | Library-only | 5 seconds |
| §4.2 | Consent Timeout | Complete | Library-only | 30 seconds |
| §5.1 | Sending Consent | Complete | Library-only | `create_consent_check()` |
| §5.2 | Receiving Consent | Partial | Library-only | Response handling |
| §6 | Consent Revocation | Complete | Library-only | `consent.rs` |

---

## proto-dtls (RFC 6347 + RFC 5764)

**Entire section Library-only.** `DtlsConnection::handshake` delegates to `session.rs`, which produces placeholder keying material and never drives `handshake.rs`/`record.rs`/`verify.rs`/`srtp_export.rs`; SBC DTLS-SRTP termination is performed by the Go sidecar (`sbc-media-core/src/dtls_sidecar.rs`, `dtls_relay.rs`). The only proto-dtls code on a shipped path is `fingerprint.rs` (`CertificateFingerprint`, used by `sbc-media-core/src/dtls_identity.rs` and the soft client). The soft client's `dtls_handler.rs` does call `DtlsConnection::handshake` and therefore derives SRTP keys from placeholder material.

### RFC 6347 Section Mapping (DTLS 1.2)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §3 | DTLS Overview | Complete | Library-only | Architecture |
| §4.1 | Record Layer | Complete | Library-only | `record.rs` |
| §4.1.1 | Anti-Replay | Complete | Library-only | Sliding window |
| §4.2 | Handshake Protocol | Partial | Library-only | `handshake.rs` |
| §4.2.1 | HelloVerifyRequest | Complete | Library-only | Cookie DoS protection |
| §4.2.4 | CertificateVerify | Complete | Library-only | `verify.rs` |
| §4.2.6 | Finished Validation | Complete | Library-only | `verify.rs` FinishedVerifier |
| §4.3 | Timeout/Retransmission | Partial | Library-only | Basic retransmission |

### RFC 5764 Section Mapping (DTLS-SRTP)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §4.1 | use_srtp Extension | Complete | Library-only | `srtp_export.rs` |
| §4.1.2 | Profile Negotiation | Complete | Library-only | AES-256-GCM only in proto-dtls; sbc-media-core pins the sidecar to AEAD_AES_256_GCM in `dtls_relay.rs` |
| §4.2 | Key Export | Complete | Library-only | HKDF-SHA384 in proto-dtls; production keys are exported by the sidecar |
| §5 | Security Considerations | Partial | Library-only | CNSA 2.0 only |

---

## proto-stun (RFC 5389)

### RFC 5389 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §6 | STUN Message Structure | Complete | Wired (sbc-daemon) | `message.rs`; used by `StunClient::discover_srflx` in `zone.rs` (external IP monitor) |
| §7.1 | Forming a Request | Complete | Wired (sbc-daemon) | StunMessage builder |
| §7.2 | Sending a Request | Complete | Wired (sbc-daemon) | StunClient (`zone.rs`) |
| §7.3 | Receiving a Response | Complete | Wired (sbc-daemon) | Response parsing |
| §10.1 | Short-Term Credential | Partial | Wired (soft client) | USERNAME/INTEGRITY on proto-ice connectivity checks run by `client-sip-ua/src/ice_handler.rs` |
| §10.2 | Long-Term Credential | Complete | Library-only | `credential.rs`; no caller (proto-turn client does not use it) |
| §14 | FINGERPRINT Mechanism | Complete | Library-only | CRC-32; `encode_with_fingerprint` only called in tests |
| §15 | Attribute Definitions | Partial | Wired (sbc-daemon) | Core attributes only |

---

## proto-turn (RFC 5766)

**Entire section Library-only.** No shipped binary calls proto-turn directly; proto-ice's `TurnClient::allocate` path runs only when `IceConfig.turn_servers` is set, which neither the daemon nor the soft client does.

### RFC 5766 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §2 | Overview | Complete | Library-only | Core concepts |
| §5 | Allocations | Complete | Library-only | `allocation.rs` |
| §6 | Creating Allocation | Partial | Library-only | Basic allocation |
| §7 | Refreshing Allocation | Partial | Library-only | Refresh request |
| §8 | Permissions | Partial | Library-only | Permission struct |
| §9 | Send Mechanism | Complete | Library-only | `indication.rs` |
| §10 | Channels | Partial | Library-only | `channel.rs` |
| §11 | ChannelData | Complete | Library-only | Framing |
| §12 | Data Indication | Complete | Library-only | `indication.rs` |

---

## proto-srtp (RFC 3711 + RFC 7714)

### RFC 3711 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §3.1 | SRTP Context | Complete | Wired (sbc-media-core, soft client) | `context.rs` (`media_pipeline.rs`, `client-audio/src/pipeline.rs`) |
| §3.2 | Transform-Independent | Complete | Wired (sbc-media-core, soft client) | Key derivation |
| §3.3 | Transform-Dependent | Partial | Wired (sbc-media-core, soft client) | AES-GCM only |
| §4.1 | Packet Processing | Complete | Wired (sbc-media-core, soft client) | `protect.rs` (`srtp_relay.rs`, `client-audio/src/rtp_handler.rs`) |
| §4.2 | Replay Protection | Complete | Wired (sbc-media-core, soft client) | 64-bit window, checked inside unprotect |
| §6 | Default Transforms | Partial | Wired (sbc-media-core, soft client) | No AES-CM, HMAC-SHA1 |
| §8 | Key Management | Partial | Wired (sbc-media-core) | DTLS-SRTP only; keys from the sidecar |
| §9.1 | Key Derivation | Complete | Wired (sbc-media-core, soft client) | HKDF-SHA384 |
| §9.2 | SRTCP Index | Complete | Wired (sbc-media-core) | Index management (`srtp_relay.rs` `reprotect_rtcp`) |

### RFC 7714 Section Mapping (AES-GCM)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §3 | AES-GCM Cipher | Complete | Wired (sbc-media-core, soft client) | 256-bit only |
| §4 | Nonce Formation | Complete | Wired (sbc-media-core, soft client) | 12-byte nonce |
| §5 | SRTP AEAD | Complete | Wired (sbc-media-core, soft client) | Protection/unprotection |
| §6 | SRTCP AEAD | Complete | Wired (sbc-media-core) | RTCP protection |

### Gap: RFC 3711 §6 - Default Transforms

CNSA 2.0 compliance prohibits AES-128. The following are intentionally not implemented:

- AES_CM_128_HMAC_SHA1_80
- AES_CM_128_HMAC_SHA1_32

This is **by design** for security compliance.

---

## proto-rtp (RFC 3550)

### RFC 3550 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §5.1 | RTP Header | Complete | Wired (sbc-media-core, soft client) | `packet.rs` (`media_pipeline.rs`, `sbc-announcement`, `client-audio/src/rtp_handler.rs`) Soft client non-SRTP path parses with `parse_rtp_fields` (`client-audio/src/rtp_handler.rs`), bounds-checked for §5.1 padding and §5.3.1 extension length (tests `test_parse_rtp_fields_*`, `test_process_packet_rejects_oversized_extension_length`); a padding count of 0 with P set is still accepted. |
| §5.2 | Multiplexing | Partial | Wired (sbc-media-core, soft client) | SSRC handling |
| §5.3 | Profile-Specific | Partial | Wired (soft client) | Basic PT support |
| §6.1 | RTCP Header | Complete | Wired (soft client) | `rtcp.rs` (`client-audio/src/rtcp_session.rs`); sbc-media-core relays SRTCP opaquely |
| §6.4 | SR Report | Complete | Wired (soft client) | Sender Report |
| §6.4.1 | RR Report | Complete | Wired (soft client) | Receiver Report |
| §6.5 | SDES | Complete | Wired (soft client) | Source Description |
| §6.6 | BYE | Complete | Wired (soft client) | Goodbye |
| §6.7 | APP | Complete | Library-only | Application-Specific; no caller |
| §6.3.5 | Timing Rules | Complete | Library-only | `scheduler.rs`; no caller |
| §6.3.7 | Bandwidth | Complete | Library-only | `scheduler.rs`; no caller |
| §7 | Translators/Mixers | Complete | Library-only | `translator.rs`; sbc-media-core relays with its own `srtp_relay.rs` |

---

## proto-sdp (RFC 4566 + RFC 3264)

**Library-only except T.38 (2026-11-08).** The only shipped use of proto-sdp is the sbc-daemon T.38 switchover (`proto-b2bua::sdp_rewrite` stream selection, `sbc-daemon/src/t38.rs`); see "sbc-daemon T.38 fax relay" below. The daemon rewrites SDP with proto-b2bua's string-based `SdpRewriter` plus `sbc-daemon/src/sdp_dtls.rs`; the soft client builds and parses SDP in `client-core/src/call_manager.rs`.

### RFC 4566 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §5.1 | Protocol Version | Complete | Library-only | v= line |
| §5.2 | Origin | Complete | Library-only | o= line |
| §5.3 | Session Name | Complete | Library-only | s= line |
| §5.4 | Session Info | Partial | Library-only | i= line |
| §5.5 | URI | Partial | Library-only | u= line |
| §5.6 | Email | Partial | Library-only | e= line |
| §5.7 | Phone | Partial | Library-only | p= line |
| §5.8 | Connection | Complete | Library-only | c= line |
| §5.9 | Bandwidth | Partial | Library-only | b= line |
| §5.10 | Timing | Complete | Library-only | t= line |
| §5.11 | Repeat Times | Complete | Library-only | `session.rs` RepeatTimes |
| §5.14 | Media | Complete | Library-only | m= line |

### RFC 3264 Section Mapping (Offer/Answer)

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §5 | Generating Offer | Partial | Library-only | Basic generation |
| §6 | Generating Answer | Partial | Library-only | Basic answering |
| §6.1 | Unicast Streams | Partial | Library-only | Basic handling |
| §6.2 | Multicast Streams | Complete | Library-only | `multicast.rs` |
| §8 | Modifying Session | Partial | Library-only | re-INVITE support in proto-sdp; the daemon's re-INVITE/UPDATE SDP relay uses proto-b2bua `SdpRewriter::rewrite_reinvite` |
| §8.2 | Adding Media | Partial | Library-only | Basic support |
| §8.3 | Removing Media | Partial | Library-only | port=0 handling |
| §8.4 | Modifying Media | Complete | Library-only | `offer_answer.rs` |

### sbc-daemon T.38 fax relay (RFC 3362, ITU-T T.38 Annex D, RFC 3264 §8, RFC 3261 §14)

| Item | Status | Wiring | Notes |
|------|--------|--------|-------|
| RFC 3264 §8 port 0 preserved on rewrite | Fixed | Wired (sbc-daemon) | `proto-b2bua/src/sdp_rewrite.rs` `rewrite_connection_and_port` no longer gives declined (port 0) m-lines the anchored port. Affects all calls. Test `test_port_zero_preserved` |
| RFC 3264 §6/§8.2 one anchored stream | Partial | Wired (sbc-daemon) | `select_anchored_stream`, `SdpRewriter::rewrite_with_selection`: m-lines never removed; extra active streams declined in place when an image m-line is involved. Tests `test_selection`, `test_selection_two_images_and_hostile`. Non-T.38 multi-stream still shares one port (POA&M-293) |
| RFC 3362 image/t38 over UDPTL | Partial | Wired (sbc-daemon, off by default) | Audio/T.38 re-INVITE switchover with opaque UDPTL relay on the anchored ports. Tests `t38_switchover_moves_relay_only_after_2xx_and_back`, `audio_to_t38_and_back_relays_opaque_udptl_from_new_ports` (`sbc-integration-tests/tests/t38_switchover.rs`). No UDPTL/IFP inspection; datagrams over 2048 bytes truncated silently (POA&M-290) |
| TCPTL, UDPTL over DTLS (RFC 7345) | Not implemented | — | Refused with 488 `unsupported_transport` (POA&M-291) |
| T.38 Annex D attributes | Partial | Wired (sbc-daemon) | `proto-sdp/src/t38.rs`; offers and answers clamped to `[media.t38]` caps. Answer not checked against the offer (version downgrade, EC fallback) (POA&M-294, still open). `uc-t38` redundancy/FEC dormant (POA&M-292) |
| Remote media node media kind | Implemented | Wired (sbc-daemon / sbc-media-core, `grpc` feature) | `SetMediaKind` RPC with `MediaKind` enum (`media_controller.proto`); remote `update_relay` sends the kind first, then the leg remotes (not atomic, PERF-001). Unknown or UNSPECIFIED kind gets INVALID_ARGUMENT. Against an older media node (UNIMPLEMENTED) the switch fails closed: `RelayUpdateFailed`, call stays on audio; an initial image answer is torn down (BYE both legs). Tests `set_media_kind_unimplemented_fails_closed`, `set_media_kind_unimplemented_fails_closed_every_time`, `set_media_kind_rejects_every_out_of_range_value`, `t38_initial_image_answer_set_media_kind_failure_tears_down`. No end-to-end test of real client against real server |
| CDR fax indicator | Implemented | Wired (sbc-daemon) | CDR schema v3 `media_kinds` (`audio`/`image`, kinds negotiated or attempted). Tests `draft_media_kinds_audio_image_audio`, `t38_initial_image_answer_success_records_image_kind`. This closes only these sub-items of POA&M-294; the Annex D answer-vs-offer check stays open |
| RFC 3261 §14 failed re-INVITE leaves session unchanged | Implemented | Wired (sbc-daemon) | Local refusal 488 (Warning 304/305/399 by reason; 304 also when the call is being recorded), not forwarded; relay moved only after 2xx. Tests `t38_disabled_is_refused_locally_with_488`, `t38_local_reject_reasons`, `t38_remote_rejects_leave_relay_unchanged`, `t38_race_back_to_audio_glare_then_remote_488_keeps_image` |
| RFC 3261 §13.2.2.4/§14.2 unacceptable 2xx answer | Implemented | Wired (sbc-daemon) | ACK then BYE both legs. Test `t38_malformed_answer_byes_both_legs` |
| Media re-latch after remote change | Implemented | Wired (sbc-media-core) | Exact SDP `ip:port` preferred; same-IP other port only after a 500 ms grace (NAT); other IPs dropped. Tests `relay_leg_relatches_on_remote_change_and_counts_udptl`, `relay_leg_relatch_flip_flop_back_to_audio`, `relay_leg_relatch_nat_fallback_after_grace` |
| `media.t38` hot reload | Not implemented | — | Reported restart-required (test `reload_reports_t38_as_restart_required`; POA&M-294) |

### SIPREC session recording client (RFC 7865, RFC 7866; uc-siprec, sbc-daemon, sbc-media-core)

Wired since SIPREC phase 3 (2026-11-09), off by default (`[recording]`). The SBC is a session recording client (SRC) for answered two-party audio calls on the in-process media relay. Code: `uc-siprec` (`metadata.rs`, `src_request.rs`, `rs_answer.rs`), `sbc-daemon/src/recording.rs`, `sbc-daemon/src/sip_stack/recording_session.rs`, `sbc-media-core/src/recording_fork.rs`. Daemon tests are in `sbc-daemon/src/sip_stack/tests/recording.rs`, `tests/recording/qa.rs` (`qa_*`) and `recording.rs`. Every recorder in the tests is played by the test: **no interoperability run against a real SRS has been made**, and no test runs TLS, SIP and media in one process. "CS" is the recorded call, "RS" the recording session, "SRS" the recorder.

| Item | Status | Wiring | Notes |
|------|--------|--------|-------|
| RFC 7865 metadata (complete snapshot) | Partial | Wired (sbc-daemon) | `metadata.rs` `to_rfc7865_xml`; §9 element order; escaping and caps (`xml.rs`); sent once, in the RS INVITE (RFC 7866 §9.1). Unique IDs are base64 of version 4 UUIDs (RFC 7865 §6.10). Participant AOR and display name come from the call's From / To (truncated at 256 bytes; `sip:anonymous@anonymous.invalid` when there is no usable URI). Tests `test_rfc7865_golden`, `tests/hostile_metadata.rs`, `metadata_survives_hostile_identities_and_yields_a_uuid`. No XSD validation; IDs not stable across serializations (POA&M-305) |
| RFC 7865 §5.1.2 partial updates (`datamode` partial); RFC 7866 §9.1 metadata update on change | Not implemented | — | POA&M-305. No update on re-INVITE, hold, transfer or T.38 switch; the SRS keeps the snapshot from the RS INVITE |
| RFC 7866 §6.1.1 SRC-initiated RS (UAC dialog) | Partial | Wired (sbc-daemon) | RS INVITE sent when the CS is answered: `Require: siprec`, `Contact` with `+sip.src`, `Allow: INVITE, ACK, BYE, CANCEL, OPTIONS`, Call-ID `rs-<32 hex>@<domain>`; no header value is copied from a received message. 2xx is ACKed (RFC 3261 §13.2.2.4); BYE when the CS ends (RFC 3261 §15); a pending INVITE is CANCELled only after a provisional (RFC 3261 §9.1) and a late 2xx gets ACK + BYE; no final response within `rs_invite_timeout_ms` or Timer B (RFC 3261 §17.1.1) is a failure. Tests `answered_call_sends_rs_invite_on_the_recorder_flow`, `rs_invite_carries_siprec_headers_metadata_and_srtp_offer`, `rs_ack_bye_and_cancel_are_dialog_correct`, `rs_answer_activates_the_fork_and_call_end_byes_the_srs`, `call_end_while_rs_invite_pending_cancels_and_tears_down_late_2xx`, `rs_invite_timer_b_applies_the_policy`. Gaps: no RS liveness check (session timer / OPTIONS; POA&M-300); the 2xx Contact is not checked for `+sip.srs`; a released pending RS INVITE is not CANCELled when a 1xx arrives late; early media is not recorded (the RS starts at the 200 OK; POA&M-301) |
| RFC 7866 §7.1.1 / §9.1 RS offer body | Implemented | Wired (sbc-daemon) | `src_request.rs` `build_rs_offer`: multipart/mixed, `application/rs-metadata+xml` part with `Content-Disposition: recording-session` (§9.1), one `m=audio` per CS leg with `a=label` (1 = caller's sent media, 2 = callee's) and `a=sendonly` (§7.1.1), `a=rtcp-mux` offered (RFC 5761; no RTCP is sent, see below). Stream 2's payload formats are taken from the offer the SBC sent to the callee, restricted to codecs the answer accepted (RFC 3264 §6.1), so the SDP names the payload types the callee actually sends. Tests `builds_multipart_with_labels_and_disposition`, `forces_sendonly_direction`, `rs_sdp_carries_ports_family_and_formats`, `classify_copies_the_answer_formats` |
| RFC 4568 / RFC 7714 SDES in the RS offer | Implemented | Wired (sbc-daemon) | `RTP/SAVP` plus one `a=crypto:1 AEAD_AES_256_GCM` (RFC 7714 §14.1) per stream from `SdesKey`, sent only over the recorder TLS connection (RFC 4568 §8.3). Only AEAD_AES_256_GCM is offered (CNSA 2.0), so an AES_CM_128-only SRS answers 488 (`srs_not_acceptable_488`, `on_failure` applies). Tests `offer_is_srtp_with_one_sdes_line_per_stream`, `rejects_key_count_mismatch`, `sdes_key_debug_is_redacted_and_split`, `rs_invite_parts_debug_does_not_leak_key`, `rs_offer_keys_are_the_pipeline_keys_in_stream_order` |
| RS answer validation (RFC 3264 §6, §6.1; RFC 4568 §5.1.2, §6.3; RFC 7866 §7.2) | Implemented, stricter than the RFCs | Wired (sbc-daemon) | `rs_answer.rs` `parse_rs_answer`, `recording.rs` `validate_rs_answer`: To tag; SDP body of at most 16 KiB; both m-lines accepted (a declined stream fails the recording rather than recording one leg); `RTP/SAVP`; exactly one `a=crypto` with tag 1 and `AEAD_AES_256_GCM`; `recvonly`; literal unicast address that is not loopback, unspecified or an SBC socket. Deviations: the SRS must accept exactly the offered payload formats of each m-line (RFC 3264 §6.1 allows a subset; the fork copies payload types unchanged, so a format the SRS left out would arrive anyway); an answer with `a=inactive` (SRS pause) is refused (POA&M-308). A defect gets ACK, then BYE, reason `srs_bad_answer`. Tests `rs_answer_defects_are_refused`, `rs_answer_must_accept_every_offered_format`, `rs_answer_with_an_sbc_address_is_refused`, `qa_hostile_rs_2xx_never_activates_the_fork`, `tests/hostile_rs_answer.rs` |
| RFC 7866 §8 send-only media fork (SRC as RTP endpoint) | Partial | Wired (sbc-media-core, in-process relay only) | `recording_fork.rs`: one SRTP stream per CS leg, own socket, own AES-256-GCM context, SBC-chosen SSRC and SBC-owned sequence / packet counter (RFC 7714 §8.1 nonce; reuse rule §8.4); payload type, marker, timestamp, CSRC list and header extension are copied. Works on the opaque RTP relay and the DTLS-terminated relay. Deviations and gaps (POA&M-301): upstream packet loss shows at the SRS as a timestamp gap, not a sequence gap; the stream keeps its SSRC when the call party changes SSRC (RFC 3550 §5.1); no fork on remote gRPC media nodes; SDES / DTLS passthrough, ZRTP, late-offer and T.38 calls are not recordable. Tests `both_legs_are_forked_as_srtp_between_activate_and_stop`, `fork_skips_rtcp_is_send_only_and_stops`, `hostile_endpoint_cannot_force_a_repeated_ssrc_and_index`, `qa_fork_to_an_ipv6_recorder` (`sbc-integration-tests/tests/siprec_fork.rs`), `terminate_relay_leg_forks_decrypted_media`, `qa_real_pipeline_forks_decryptable_media_to_the_fake_srs` |
| RFC 7866 §8.1.1, §8.1.5.1 RTCP toward the SRS | Not implemented | — | POA&M-301. The RS carries RTP without RTCP: no sender reports, no CNAME, no SRTCP. RTCP from the call is not forked, and what the SRS sends to the fork port is never read |
| RFC 7866 §7.1.2 recording indication (`a=record`) | Not implemented | — | POA&M-303. Recording is live without any in-band indication to CS participants; `notice_acknowledged = true` (operator attests out-of-band notice) is the only control |
| RFC 7866 §7.1.3 / §7.3.2 `a=recordpref` | Partial | Wired (sbc-daemon) | Only the opt-out is acted on: `a=recordpref:off` in either leg's SDP, per `recording.recordpref_never` (`ignore`, the default: record anyway; `honour`: no RS, audit `recording_skipped`, CDR `opt_out`). `never` is not an RFC 7866 value and is accepted as a non-standard alias of `off`. A media-level value on the first active `m=audio` overrides the session-level one. `on`, `pause` and `nopreference` have no effect (a participant cannot start or pause recording). Tests `recordpref_values`, `recordpref_media_level_overrides_session_level`, `recordpref_session_and_media_level`, `recordpref_opt_out_is_honoured_or_ignored_by_policy` |
| RFC 7866 §6.2 SRS-initiated requests; metadata snapshot request (§9) | Not implemented (refused) | Wired refusal (sbc-daemon) | POA&M-308. In the RS dialog: BYE gets 200 and ends the recording (policy applies); OPTIONS gets 200 with `Allow`; a re-INVITE gets 488 with a Warning (RFC 3261 §14.2), so a snapshot request is not served and pause / resume is refused; UPDATE and other methods get 405 with `Allow`. Requests not over TLS from the SRS IP with the RS Call-ID and both tags get 481. No persistent RS. Tests `srs_reinvite_gets_488_and_update_405`, `srs_bye_mid_call_applies_the_policy`, `forged_srs_bye_is_481` |
| RS remote target and route set (RFC 3261 §12.1.2, §12.2.1.1) | Deviation, by design | Wired (sbc-daemon) | The next hop of every RS request is the SRS address resolved from `recording.srs_uri` at startup, whatever Contact or Record-Route say. The 2xx Contact becomes the in-dialog Request-URI; a `sip:` Contact is upgraded to `sips:` (user, host and port kept, `transport` dropped). A Record-Route set of more than 16 entries is dropped. An SRS that needs in-dialog requests sent to a different address than its configured one does not work. Tests `srs_contact_never_redirects_the_recording_session`, `remote_target_is_the_contact_upgraded_to_sips`, `qa_oversized_record_route_is_dropped_not_followed` |
| RFC 7866 §12 transport security (§12.1 TLS, §12.2 SRTP) | Partial, with deviations | Wired (sbc-daemon) | `[recording].srs_uri` must be `sips:` (no `maddr`, no `transport`); recorder TLS client with certificate and name validation against `srs_tls_ca_file`; RS responses are accepted only over TLS from the SRS address. Deviations: TLS 1.3 only (the rfc-conformance review reads RFC 7866 §12 as requiring TLS 1.2 support; a TLS 1.2-only SRS fails the handshake, reason `srs_tls`); SRTP `AEAD_AES_256_GCM` only. Not done: RFC 3263 NAPTR / SRV for the SRS (one A / AAAA lookup at startup, first address pinned) and ML-KEM hybrid key exchange (POA&M-304). Tests `recorder_flow_dials_with_the_srs_ca_and_name`, `recorder_flow_rejects_trunk_ca_certificate_and_wrong_name`, `qa_rs_2xx_over_udp_is_ignored` |
| RFC 3261 §15 / §13.3.1.4 BYE toward a caller that has not ACKed | Implemented (recording paths) | Wired (sbc-daemon) | A CS that cannot be recorded under `on_failure = reject` is refused with a final response where possible (488 + `Warning: 399`, or 503 + `Retry-After`, at INVITE; at the callee's 2xx the 2xx is not relayed, the caller gets 488 / 503 and the callee ACK + BYE). When the SBC ends a CS after relaying the 200, the BYE toward a leg that has not ACKed a 2xx from the SBC is held until the ACK or 64*T1, while the 2xx keeps being retransmitted. Tests `answer_dependent_unrecordable_call_is_refused_before_the_200_is_relayed`, `caller_bye_is_held_until_the_caller_acks_the_200`. Not covered: the direct-T.38 teardown after a malformed T.38 answer (not a recording path) still sends the caller's BYE right after the 200 |
| T.38 switch on a recorded CS | Refused or ends the RS | Wired (sbc-daemon) | Under `reject`: 488 locally with `Warning: 304` "Media type not available" (corrected from 305), `media_switchover` reason `recording_active`. Under `continue`: relayed, and on the 2xx the RS is ended with BYE (CDR `partial`); a later switch back to audio is not recorded (POA&M-305). Tests `t38_switch_on_recorded_call_is_refused_under_reject`, `t38_switch_on_recorded_call_ends_the_recording_under_continue` |
| `[recording]` configuration | Implemented | Wired (sbc-config, sbc-daemon) | Validated, default off, restart-required; `enabled = true` accepted (POA&M-302 closed). Keys and defaults: `docs/SBC-ADMIN-GUIDE.md` "Call recording" |
| Interoperability with a third-party SRS | Not tested | — | Includes the AES-256-GCM-only offer, TLS 1.3-only signaling, the exact-format answer rule and the pinned next hop |

---

## Summary: Priority Implementation Order

"Done (library)" means the crate implements the item; "Wired" says whether a shipped binary calls it.

### P0 - Critical (Security/Functionality Breaking)

| Crate | RFC | Section | Gap | Done (library) | Wired |
|-------|-----|---------|-----|----------------|-------|
| proto-dtls | RFC 6347 | §4.2.4 | Certificate verification | Done | Library-only (DTLS termination is the Go sidecar) |
| proto-dtls | RFC 6347 | §4.2.6 | Finished message validation | Done | Library-only |
| proto-ice | RFC 7675 | §6 | Consent revocation action | Done | Library-only |
| proto-turn | RFC 5766 | §9 | Send mechanism | Done | Library-only |
| proto-turn | RFC 5766 | §12 | Data indication | Done | Library-only |

### P1 - High (Major Functionality)

| Crate | RFC | Section | Gap | Done (library) | Wired |
|-------|-----|---------|-----|----------------|-------|
| proto-sip | RFC 3261 | §13.2.2.4 | 3xx redirect handling | Done | Library-only |
| proto-registrar | RFC 5626 | §5.2 | Flow maintenance | Done | Library-only |
| proto-ice | RFC 8445 | §7.2.2 | Aggressive nomination | Done | Library-only |
| proto-sdp | RFC 3264 | §8.4 | Media modification rules | Done | Library-only |
| proto-stun | RFC 5389 | §10.2 | Long-term credential | Done | Library-only |

### P2 - Medium (Feature Completeness)

| Crate | RFC | Section | Gap | Done (library) | Wired |
|-------|-----|---------|-----|----------------|-------|
| proto-registrar | RFC 5627 | §5.1 | Proxy GRUU routing | Done | Library-only |
| proto-rtp | RFC 3550 | §6.3.5 | RTCP timing rules | Done | Library-only |
| proto-dialog | RFC 6665 | §7.2 | Event package validation | Done | Library-only |
| proto-sdp | RFC 4566 | §5.11 | Repeat times (r= line) | Done | Library-only |

### P3 - Low (Edge Cases)

| Crate | RFC | Section | Gap | Done (library) | Wired |
|-------|-----|---------|-----|----------------|-------|
| proto-sdp | RFC 3264 | §6.2 | Multicast streams | Done | Library-only |
| proto-rtp | RFC 3550 | §7 | Translators/mixers | Done | Library-only |
| proto-sip | RFC 3261 | §16.6 | Full proxy forwarding | Done | Library-only |

## uc-codecs / media (2026-11-06 media audit)

| Item | Status | Wired | Notes |
|------|--------|-------|-------|
| ITU-T G.722 conformance vectors (G.191 / App. II) | Gap | uc-codecs (soft client) | Only a self-generated regression vector (`g722_adpcm.rs` `test_self_generated_regression_vector`) and level tests (`test_level_1khz`, `test_level_lower_and_upper_band`). Official vectors not run (POA&M-140) |
| RFC 5761 §4 PT range under rtcp-mux | Deviation | Library-only (negotiation not wired, POA&M-142) | `payload_types::is_dynamic` adopts PTs 64-71/77-95 even with rtcp-mux; only 72-76 are rejected (tests `test_is_dynamic_ranges`, `test_negotiate_rejects_rtcp_colliding_pt`). POA&M-143 |

---

## Document Maintenance

### uc-transport SCTP and uc-aaa RADIUS (library-only, dormant)

Neither feature (`uc-transport` `sctp`, `uc-aaa` `radius`) is enabled by any shipped binary.

| Requirement | Status | Wiring | Notes |
|-------------|--------|--------|-------|
| RFC 9260 §3.2 chunk padding / length | Implemented (decoder) | Library-only | `Chunk::decode` consumes `min(padded_length, remaining)` and hands body decoders exactly `length` bytes; truncated and hostile input returns an error, never panics. Tests: `decode_last_chunk_without_padding`, `decode_padded_chunk_consumes_padding`, `decode_every_prefix_of_valid_chunks`, `decode_every_chunk_type_length_field_fuzz`, proptests in `chunk.rs` / `packet.rs`. |
| RFC 9260 §3.3.4 SACK | Implemented (decoder) | Library-only | Gap-block / duplicate-TSN capacity bounded by bytes present, not wire counts. |
| RFC 6525 §4 / RFC 5061 parameters | Implemented (decoder) | Library-only | RE-CONFIG, ASCONF and ASCONF-ACK parameters shorter than their header are rejected (previously an infinite loop). Test: `asconf_reconfig_zero_length_params_terminate`, `decode_structured_param_fuzz`. |
| RFC 6951 UDP encapsulation | Partial | Library-only | UDP length < 8 rejected (`udp_encap.rs`, test `decode_udp_length_below_header_is_rejected`). Decoder only; no association-level interop test. |
| RFC 2865 §3 Response Authenticator | Implemented | Library-only | Verified with constant-time compare (`radius.rs` `verify_access_response`, `ct_eq`). Tests in `message_authenticator_tests`. |
| RFC 2869 §5.14 / RFC 3579 §3.2 Message-Authenticator, CVE-2024-3596 | Implemented | Library-only | Required on every Access-Accept/Reject/Challenge (exactly one, 16 bytes), checked before the Response Authenticator; sent first in Access-Request. Invalid responses are discarded and the client waits for a valid one until timeout. Tests: `forged_responses_are_discarded_then_valid_accepted`, `only_forged_response_times_out`. |
| RFC 2866 §3 Accounting-Response authenticator | Gap | Library-only | Not verified (POA&M-281). |
| RFC 2865 Identifier | Partial | Library-only | 8-bit, wraps, no in-flight tracking (POA&M-281). |
| RFC 6614 RadSec | Gap | Library-only | Not implemented; RADIUS/UDP MD5 is not CNSA (POA&M-280). |

Last Updated: 2026-11-06

2026-11-06: added the uc-codecs media section (G.722 vectors, RFC 5761 deviation).

2026-11-04: added the sbc-daemon CDR section (RFC 3326, RFC 3264 §6, RFC 5424/5425/6587).

2026-10-11: sbc-daemon now drives the proto-transaction state machines and relays re-INVITE/UPDATE with RFC 4028 session-timer headers; wiring column added.

This document should be updated when:

1. New RFC implementations are added
2. Existing gaps are filled
3. New gaps are discovered during testing
4. A library feature is wired into (or removed from) a shipped binary
