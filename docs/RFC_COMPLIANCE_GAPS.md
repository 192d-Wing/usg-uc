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
| §8.2 | UAS Behavior | Partial | Wired (sbc-daemon, soft client) | Daemon acts as UAS on the A-leg with server transactions (`sip_stack.rs`) |
| §10 | Registrations | Partial | Wired (sbc-daemon) | Delegated to proto-registrar (`sip_stack.rs` `handle_register`) |
| §11 | Querying Capabilities | Partial | Wired (sbc-daemon) | Daemon answers OPTIONS with 200 OK + Allow in its own handler (`sip_stack.rs` `handle_options`); proto-sip `options.rs` is Library-only |
| §12 | Dialogs | Partial | Library-only | proto-dialog `Dialog` is imported but the daemon's dialog map is never populated; dialog state lives in proto-b2bua `Call` |
| §13 | Initiating a Session | Partial | Wired (sbc-daemon, soft client) | Daemon relays INVITE as a B2BUA (`sip_stack.rs` `handle_invite`); soft client originates INVITE (`call_agent.rs`) |
| §13.2.2.4 | 3xx Redirect Responses | Complete | Library-only | `redirect.rs`; no caller. Daemon relays 3xx as a non-2xx final; soft client rejects redirects |
| §14 | Modifying an Existing Session | Partial | Wired (sbc-daemon, soft client) | Daemon relays re-INVITE/UPDATE across legs, 491 on glare, 481 for unmatched in-dialog requests (`sip_stack.rs` `handle_in_dialog_request`); soft client sends hold/resume re-INVITE |
| §15 | Terminating a Session | Partial | Wired (sbc-daemon, soft client) | Daemon relays BYE/CANCEL to the other leg (`sip_stack.rs` `handle_bye`, `handle_cancel`) |
| §16.4 | Route Information Preprocessing | Partial | Library-only | `routing.rs`; the daemon is a B2BUA, not a proxy. Route lists now use the shared byte-indexed splitter (`list.rs`); module otherwise not reviewed (POA&M-65) |
| §16.6 | Request Forwarding | Partial | Library-only | `proxy.rs`; no caller. Via insert/pop is O(n) and order-preserving; combined Via values handled. Module otherwise not reviewed (POA&M-65) |
| §16.7 / §18.2.2 | Response routing under proxy-model topology hiding (RFC-003) | Gap | Library-only | `TopologyHider::hide_outbound_request` (proxy model) strips (aggressive) or rewrites (basic) Vias with no stored copy, so responses could not be routed back to internal hops. No daemon caller; the daemon uses only `hide_b2bua_request`, which never strips a Via. Not RFC-conformant for proxy use until branch-keyed Via restoration exists (POA&M-157) |
| §16.12.1 | Loose Routing | Partial | Library-only | `routing.rs`; no caller. Only the list splitter was reviewed in Phase 1 (POA&M-65) |
| §17 | Transactions | Partial | Wired (sbc-daemon, soft client) | Daemon drives proto-transaction client/server FSMs and timers (`sip_stack.rs` `poll_timers`); soft client drives client FSMs |
| §18 | Transport | Partial | Library-only | `Transport` enum has no caller; sockets are provided by uc-transport |
| §19 | SIP URI | Partial | Wired (sbc-daemon, soft client) | `uri.rs`. §25 grammar, %-escape validation, strict ports, §19.1.4 `SipUri::equivalent`, generic `Uri` and 416 for non-SIP Request-URIs (POA&M-150). `tel:`/absoluteURI in To/From/Contact/Route still fail to parse, because `NameAddr.uri` is `SipUri`; a topology Contact rewrite of such a value would fail closed with 400 (RFC-002, POA&M-153). Callers not yet on `equivalent` (POA&M-154). Advisory (RFC-005, dormant until POA&M-154): `equivalent` decodes `%25` to `%`, so `%253B` and `%3B` compare equal; keep `%25` escaped when comparing |
| §20 | Header Fields | Partial | Wired (sbc-daemon, soft client) | 59 `HeaderName` variants in `header.rs`; names are case-insensitive (`Custom` normalised), compact forms incl. e/x/b/y/a/j/d. Only Via, CSeq, Max-Forwards, Content-Length are grammar-checked at parse time; other headers are checked when a caller parses them |
| §22 | Authentication | Partial | Wired (soft client) | `auth.rs` (RFC 2617) used by the soft client as UAC. The daemon's REGISTER digest challenge/verification is proto-registrar's own code (`authentication.rs`), not `proto_sip::auth` |

### proto-sip message layer hardening (Phase 1)

| Item | Status | Notes |
|------|--------|-------|
| §7 / §25.1 CRLF line ends, token names, no CTL in values | Complete | Bare CR/LF rejected; CTLs except HTAB rejected, including escaped CTLs in quoted-pairs (deliberate deviation, RFC 4475 `intmeth`) |
| §7.5 leading CRLF | Complete | Up to 32 skipped |
| §18.3 Content-Length framing | Partial | `Framing::Datagram` truncates / rejects; `Framing::Stream` (TCP/TLS) requires an exact C-L; `Framing::Message` (WS/WSS per RFC 7118 §5, SCTP per RFC 4168) makes C-L optional but exact if present. The soft client uses `Stream` on TCP/TLS. sbc-daemon's stream framer (`next_sip_frame`) now applies the same C-L rules via `SipMessage::stream_message_len`: on TCP/TLS a missing, duplicate, conflicting or malformed C-L (§20.14) gets a 400 and the connection closes; the subsequent parse still uses datagram rules (POA&M-64). Tests `duplicate_cl_gets_400_and_close`, `duplicate_content_length_rejected`, `malformed_content_length_rejected`, `reframing_any_split_is_identical` |
| §8.1.1.5 CSeq < 2^31, CSeq method = request method | Complete | Exact, case-sensitive comparison (§7.1) |
| §20.22 Max-Forwards 0-255 | Complete (stricter than grammar) | §20.22 grammar is `1*DIGIT`; values above 255 (the §16.6 cap) are rejected as 400-class. Tests `max_forwards_range`, `max_forwards_bounds` |
| Duplicate single-valued headers (RFC 4475 §3.3.8/§3.3.9) | Complete | Call-ID, To, From, CSeq, Max-Forwards, Content-Length |
| §8.2.2 / §16.3 400 for malformed requests | Partial | sbc-daemon sends a sanitized 400 for stream framing errors only (`framing_error_response`, test `framing_error_response_is_minimal_400`); other malformed requests are logged and dropped (POA&M-63) |
| §22 digest verifier | Partial | Not reviewed in Phase 1 (POA&M-65); empty input and parameter caps fixed |
| RFC 3323 topology hiding | Partial | Reviewed and fixed under POA&M-151 (CIDR matching, per-element rewrite, fail closed). Since POA&M-155, sbc-daemon hides Via/Contact/Record-Route on every request and Contact/Record-Route on every response toward a hidden leg (`SipStack::apply_egress_topology`); response Via is left byte-exact (RFC 3261 §8.2.6.2, §18.2.2); in 3xx only internal redirect targets are rewritten (§8.1.3.4); the SBC Via keeps a bare `rport` (RFC 3581); CANCEL and non-2xx ACK top Via equal the INVITE's (§9.1, §17.1.1.3; tests `th_bye_from_callee_and_cancel_are_hidden`, `th_non2xx_ack_via_matches_invite`). Open: Warning/Server/User-Agent/Reason and SDP `o=` not hidden, relayed 2xx carries no Contact (§12.1.1) (POA&M-181); in-dialog PRACK/INFO/MESSAGE/NOTIFY answered 405, not relayed (POA&M-182); proxy-model Via restore missing (POA&M-157) |
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
| RFC 5424 message format (PRI, VERSION, TIMESTAMP, MSGID, SD, §6.4 BOM) | Complete | Wired (sbc-daemon, opt-in) | PRI = facility * 8 + 6, VERSION 1, UTC timestamp with `Z`, MSGID `CDR`, NILVALUE SD, UTF-8 BOM before the JSON MSG. Header tokens are limited to PRINTUSASCII. Hand-formatted in `uc-cdr`, not via `uc-syslog`. Tests `syslog_octet_counted_rfc5424`, `syslog_sink_octet_counted_frames_via_fake_connector` |
| RFC 6587 §3.4.1 octet-counting framing | Complete | Wired (sbc-daemon, opt-in) | The count is the MSG byte length including the 3 BOM octets. Same tests |
| RFC 5425 TLS transport | Partial | Wired (sbc-daemon, opt-in) | TLS 1.3 only, CNSA 2.0 suite and groups (`uc_transport::tls::create_client_config` / `cnsa_provider`; POA&M-26 closed). The server is authenticated against `cdr.syslog.ca_path` or `security.tls_ca_path`. **Gap:** §4.2 mutual authentication is absent because no client certificate is sent (NIST-06, POA&M-15). Handshake test: `syslog_tls_is_cnsa_only` |
| SIP transport recorded in the CDR | Gap | Wired (sbc-daemon) | SCTP (RFC 4168) A-legs are recorded as `tcp`: schema v1 has no `sctp` value (POA&M-20) |

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

RFC 3261 §17 is wired into sbc-daemon and the soft client. RFC 3262 (PRACK/100rel) is implemented in `prack.rs` but no shipped binary sends, accepts, or relays PRACK; the daemon's Allow header omits it.

---

## proto-dialog (RFC 3261 §12 + RFC 3515 + RFC 4028 + RFC 6665)

### RFC 3261 §12 Section Mapping

| Section | Title | Status | Wiring | Notes |
|---------|-------|--------|--------|-------|
| §12.1.1 | UAS Behavior | Complete | Library-only | Dialog creation from request; daemon dialog map never populated, soft client `dialog` field never assigned |
| §12.1.2 | UAC Behavior | Complete | Library-only | Dialog creation from response |
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
| §3 | NOTIFY Bodies | Partial | Wired (soft client) | sipfrag parsed by the soft client's own code |

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
| §5.1 | RTP Header | Complete | Wired (sbc-media-core, soft client) | `packet.rs` (`media_pipeline.rs`, `sbc-announcement`, `client-audio/src/rtp_handler.rs`) |
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

**Entire section Library-only.** No shipped binary calls proto-sdp. The daemon rewrites SDP with proto-b2bua's string-based `SdpRewriter` plus `sbc-daemon/src/sdp_dtls.rs`; the soft client builds and parses SDP in `client-core/src/call_manager.rs`.

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

Last Updated: 2026-11-06

2026-11-06: added the uc-codecs media section (G.722 vectors, RFC 5761 deviation).

2026-11-04: added the sbc-daemon CDR section (RFC 3326, RFC 3264 §6, RFC 5424/5425/6587).

2026-10-11: sbc-daemon now drives the proto-transaction state machines and relays re-INVITE/UPDATE with RFC 4028 session-timer headers; wiring column added.

This document should be updated when:

1. New RFC implementations are added
2. Existing gaps are filled
3. New gaps are discovered during testing
4. A library feature is wired into (or removed from) a shipped binary
