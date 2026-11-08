# Proto-* Crates RFC/Standards Compliance Report

**Generated:** 2026-02-07
**Last Updated:** 2026-10-11 (wiring reconciliation, issue #118)
**Crates Audited:** 13
**Unique RFCs Referenced:** 45+

> **Status legend.** *Wired (sbc-daemon | sbc-media-core | soft client)* — a shipped binary has a call site for this (the binary is named). *Library-only* — implemented and tested in a `proto-*`/`uc-*` crate, but no shipped binary calls it. *Planned* — not implemented. A row that says only "Full"/"Complete" describes crate-level capability; the wiring column/annotation says what the running SBC actually does.

**Dependency facts behind the wiring labels** (from `Cargo.toml`): `sbc-daemon` depends on proto-sip, proto-transaction, proto-dialog, proto-b2bua, proto-registrar, proto-jwt, proto-rtp, proto-srtp, proto-dtls, proto-stun, proto-stir-shaken, `uc-sti` and `sbc-media-core` — but **not** proto-sdp. `sbc-media-core` (linked into `sbc-daemon` and `sbc-media`) depends on proto-dtls, proto-rtp, proto-srtp. `client-sip-ua` lists proto-sdp, proto-registrar, proto-stun and proto-turn but has no source references to them. proto-stir-shaken is used by `sbc-daemon` and `uc-sti`. The SBC does not run ICE (it anchors media and latches symmetrically). SBC DTLS-SRTP termination is a Go sidecar (`sbc-media-core/src/dtls_sidecar.rs`), not proto-dtls.

---

## 1. proto-sip — SIP Message Layer

**Primary Standard:** RFC 3261 (SIP)
**Claimed Compliance:** 100% message layer

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP: Session Initiation Protocol — message layer | **Partial** — strict byte-based message parsing (CRLF, token names, CTL rejection, §18.3 Content-Length framing per transport (datagram / stream / message-framed WS-WSS-SCTP), case-sensitive methods (§7.1) and exact CSeq method match, CSeq/duplicate-header checks, Max-Forwards limited to 0-255 (stricter than the §20.22 `1*DIGIT` grammar), parser limits; RFC 4475 vectors in `tests/rfc4475.rs` with known gaps), URI grammar: §25.1 parser, `%HH` validation, strict ports and 416 for non-SIP Request-URIs (POA&M-150, `tests/uri_abnf.rs`); §19.1.4 comparison implemented as `SipUri::equivalent` but **not used** by registrar/dialog/ACL matching (POA&M-154), so §19.1.4 is not met end to end; `tel:`/absoluteURI in name-addr headers not parsed (POA&M-153), no daemon 400 (POA&M-63). Deviation: every CTL except HTAB is rejected, even inside a quoted-pair (§25.1 allows it; RFC 4475 `intmeth`). sbc-daemon still parses TCP/TLS with datagram rules (POA&M-64); message parsing, URI, headers, methods, Via/From/To/CSeq/Max-Forwards, builder, header manipulation, auth (§22). **Wired (sbc-daemon `sip_stack.rs`; soft client `client-sip-ua`)** |
| **RFC 3261** | SIP — proxy forwarding (§16), routing (§16.12.1), redirect (§13.2.2.4), OPTIONS (§11) modules | **Partial** — `proxy.rs` and `routing.rs` reviewed under POA&M-231 (proto layer only, daemon wiring pending, POA&M-236): §12.1.1 UAS route set in Record-Route order and §12.1.2 UAC route set reversed, including elements inside a comma-joined header (`RouteSet::from_record_route_headers_in_order`; test `route_set_order_uas_in_order_uac_reversed`); §16.4 preprocessing `preprocess_route_information` (strict-route Request-URI restore from the last Route, pop of our own top Route, 64-element cap, request unchanged on error; tests `preprocess_*`, 7 tests) **except** the §16.4 `maddr` MUST, not implemented (`// POAM:` in `routing.rs`, POA&M-235); §16.3 item 4 / §16.6 step 8 spiral-aware loop detection (`compute_loop_hash`, branch `z9hG4bK{rand}.{loophash}`, every own Via checked; same hash = 482, different hash = spiral, missing hash = 482; `ProxyContext::is_own` matches user, host, effective port and transport); **deviation:** the loop hash does not include the topmost Via (it covers R-URI, To/From tags, Call-ID, CSeq number, Route, Proxy-Require, Proxy-Authorization), because on a real loop the received top Via belongs to the previous hop and hashing it would turn every loop into a spiral; a spiral differing only in its upstream Via is reported as a loop (errs toward 482). Tests `same_request_back_is_loop`, `spiral_with_changed_ruri_allowed`, `spiral_with_changed_cseq_allowed`, `own_via_inside_comma_list_detected`, `foreign_via_with_same_branch_ignored`, `trusted_domain_via_is_not_us`, `loop_hash_deterministic`. §8.2.6.1/§16.2 100 Trying copies every Via, From, To (no tag added), Call-ID, CSeq and Timestamp with Content-Length 0 (tests `trying_copies_all_vias_and_timestamp`, `trying_from_parsed_wire_with_separate_via_lines`). `redirect.rs`, `options.rs` not reviewed (POA&M-65). **Library-only** — no shipped binary uses `RequestForwarder`/`RouteSet`/`preprocess_route_information`/`RedirectHandler`/`OptionsCapabilities`; the daemon answers OPTIONS with its own 200 (`sip_stack.rs`) and the client reads Record-Route manually |
| **RFC 2617** | HTTP Digest Authentication | **Full** — HA1/HA2 computation (§3.2.2), digest response, nonce handling. **Wired (sbc-daemon: registrar challenge via proto-registrar, trunk REGISTER via `sbc-trunk-services`; soft client `registration.rs`)** |
| **RFC 7616** | HTTP Digest Access Authentication (MD5, SHA-256, SHA-512-256) | **Partial** — `auth.rs`: `Sha256DigestHasher`, `Sha512_256DigestHasher`, `AlgorithmHasher::for_algorithm`; `DigestHasher::handles` is required and `compute_ha1` / `compute_digest_response` / `create_credentials` / `verify_credentials` return `Err` when the hasher does not implement the challenged algorithm (previously an MD5 hasher silently answered a SHA-256 challenge); challenges always carry `algorithm=`. §3.9.1 vectors: tests `md5_vector`, `sha256_vector`, `sha512_256_response`, `session_variants`, `sha512_256_is_not_truncated_sha512`, `md5_hasher_with_sha256_challenge_fails_closed`. Server verifier `digest_verifier.rs` (feature `digest-auth`, POA&M-230): HMAC-SHA-384 stateless nonce with TTL and future-skew bound, server-pinned realm/algorithm/qop (empty qop list forced back to `auth`), digest-uri equal to the Request-URI under §19.1.4, opaque echo, per-(username, nonce) nc replay tracking committed only after the response matches, bounded tracker, `stale` only for a valid digest; 27 tests incl. `algorithm_downgrade_rejected`, `uri_mismatch_rejected`, `nc_replay_and_decrease_rejected_gap_accepted`, `stale_only_after_response_verifies`, `opaque_must_echo`. **Library-only** (`DigestVerifier` has no caller; POA&M-236). UAC §3.7 selection: `select_challenge` / `select_challenge_from_headers` (returns `ChallengeSelection`) choose the strongest offered algorithm, skip unknown ones and split comma-joined challenges (cap 16); callers `sbc-trunk-services` `registrar.rs`, soft client `registration.rs`, `call_agent.rs` use `AlgorithmHasher` (POA&M-234 closed; tests `auth::tests::select::*`). MD5 is answered by default when it is the only offer (POA&M-255); one answer per 401/407 regardless of realm (POA&M-256). Not implemented: `userhash`, §3.9.2 vector. Deviation: nc must strictly increase per nonce, so out-of-order parallel requests on one nonce are rejected |
| **RFC 3263** | Locating SIP Servers | **Partial** — soft client (`client-sip-ua` `call_agent.rs` `build_resolver`) uses `uc_dns::SipResolver::new`, whose hickory backend reads the host system DNS configuration (`HickoryDnsResolver::from_system_conf`); with no usable system config it runs with no backend (numeric hosts and cache only, never public resolvers). NAPTR → SRV → A/AAAA; SRV targets ordered by RFC 2782 weighted random selection (`SrvResolver::order_rfc2782`), `.` targets filtered, unresolvable targets skipped, `sips:` never downgraded to non-TLS targets. TLS verify name is the registrar-URI domain, not the SRV target (§4.4 / RFC 5922 §4). No DNSSEC (NIST POA&M-172). Tests: `uc-dns` `test_resolve_preserves_weighted_order`, `test_naptr_srv_filters_null_target`, `test_unresolvable_srv_target_is_skipped`, `test_naptr_any_skips_non_sip_service`, `test_sips_never_downgrades_via_naptr_or_srv`, `test_no_backend_fallback_serves_numeric_and_cached`, `test_weighted_distribution`. The NAPTR/SRV path through the real hickory backend has no network test. sbc-daemon/trunk-services use plain `lookup_host` (no SRV/NAPTR) |
| **RFC 3264** | Offer/Answer Model with SDP | Referenced |
| **RFC 3311** | UPDATE Method | Method enum entry. **Wired (sbc-daemon)** — relayed in-dialog via `handle_update` → `handle_in_dialog_request` (`sip_stack.rs`) |
| **RFC 3323** | Privacy Mechanism for SIP | **Partial** — `Privacy` header and privacy service in `privacy.rs` (POA&M-232; proto layer only, daemon wiring pending, POA&M-236): `PrivacyHeader` parse/merge (max 16 values, `none` exclusive), `apply_privacy` (`header` strips 7 headers and sets `needs_topology_hiding`, which the caller must act on; `user` anonymizes From keeping the tag; `id` removes PAI toward untrusted egress; `session` unsatisfiable unless the caller supports it; `critical` with anything unsatisfied returns 500 before any mutation). Tests `parse_rejects_bad_input`, `from_headers_merges_instances_and_commas`, `apply_header_user_id_untrusted`, `session_critical_cannot_satisfy_and_leaves_request`. Topology hiding reviewed under POA&M-151. **Wired (sbc-daemon)** — `SipStack::apply_egress_topology` (`sip_stack.rs`) applies `TopologyHider::hide_b2bua_request` / `hide_b2bua_response_for_status` to every request and response toward a hidden leg (POA&M-155); residual headers and SDP `o=` not hidden (POA&M-181); in-dialog PRACK/INFO/MESSAGE/NOTIFY not relayed (POA&M-182). Other proto-sip modules not reviewed (POA&M-65) |
| **RFC 3325** | P-Asserted-Identity | Header support, topology hiding. **Wired (sbc-daemon)** via topology hider only. Library-only (POA&M-232, daemon wiring pending POA&M-236): `sanitize_inbound_identity` strips PAI/PPI from untrusted ingress (§5; test `sanitize_inbound_identity_untrusted_only`); `rpid_to_pai` / `ManipulationAction::RpidToPai` convert only RPID elements with `screen=yes` into a re-serialized name-addr (one sip, one tel; `privacy=uri` → `Privacy: id`, `name`/`full` → `id;user`); tests `unscreened_rpid_not_asserted`, `rpid_params_stripped_from_pai`, `rpid_encoded_crlf_cannot_inject`, `rpid_to_pai_preset_on_parsed_message`. `strip_pai_outbound` preset acts on parsed `HeaderName::PAssertedIdentity` (test `trunk_interop_strips_pai_from_parsed_message`) |
| **RFC 3326** | Reason Header | Header name defined in proto-sip. **Wired (sbc-daemon, CDR only)**: `sbc-daemon/src/cdr.rs` reads every `Reason` header field (`sip_stack.rs` `reason_headers()`, `CdrEnd::with_reasons`). Splitting on `,` and `;` respects quoted strings and quoted-pairs (RFC 3261 §25.1, `split_unquoted`). The first `protocol=Q.850` cause in 1..=127 is recorded as `q850_cause`. The daemon does not add or rewrite Reason. Tests `q850_parses_rfc3326_reason`, `q850_from_separate_reason_headers`, `cdr_answered_then_callee_bye_with_q850` |
| **RFC 3327** | Path Header | **Partial** — `path_values()` (splits combined values), `prepend_path()`; only list handling was reviewed. **Library-only** — daemon REGISTER handling never reads or inserts Path |
| **RFC 3428** | MESSAGE Method | Method enum entry. Library-only — daemon returns 405 |
| **RFC 3455** | P-Headers | Header names defined. Library-only |
| **RFC 3515** | REFER Method | Method enum entry, header support. **Wired (soft client only)** — `call_agent.rs` sends REFER; daemon returns 405 (not relayed) |
| **RFC 3891** | Replaces Header | Header name defined. Library-only |
| **RFC 3903** | PUBLISH Method | Method enum entry. Library-only — daemon returns 405 |
| **RFC 4028** | Session Timers | Header names (Session-Expires, Min-SE). **Wired (sbc-daemon, relay only)** — `relay_session_timer_request_headers` / `relay_session_timer_response_headers` on INVITE/re-INVITE/UPDATE and their responses (`sip_stack.rs`); no local refresher |
| **RFC 4168** | SCTP Transport for SIP | Transport enum entry. Library-only — `uc-transport` `sctp` feature not enabled by any binary |
| **RFC 4566** | SDP | Referenced |
| **RFC 6086** | INFO Method | Method enum entry. Library-only — daemon returns 405 |
| **RFC 6665** | SIP Events (SUBSCRIBE/NOTIFY) | Method enum entries, header support. Library-only — daemon returns 405; client only reads Subscription-State on REFER NOTIFY |
| **RFC 7118** | WebSocket Transport for SIP | Transport: WS/WSS. Wired (sbc-daemon `transport.ws_listen`, plain WS); WSS planned — the transport does not terminate TLS. §4: `sip` subprotocol required (HTTP 400 otherwise; `ws_require_sip_subprotocol = false` is a non-conformant opt-out). §5: one SIP message per WS message; incomplete messages discarded. RFC 6455 message/frame caps 65,535 bytes. See `docs/RFC_COMPLIANCE_GAPS.md` |
| **RFC 8224** | STIR Identity | Header name defined; reason phrases 428/436/437/438 in `response.rs` (test `stir_reason_phrases`). Wired (sbc-daemon STIR path, off by default) |

### Key Files
- `src/lib.rs` — module exports, max message size
- `src/method.rs` — all SIP methods (core + extensions per §7.1)
- `src/header.rs` — header names per §20, compact forms per §7.3.3
- `src/header_params.rs` — Via (§20.42), From/To (§20.20/20.39), CSeq (§20.16), Max-Forwards (§20.22)
- `src/uri.rs` — SIP URI per §19
- `src/transport.rs` — UDP/TCP/TLS/SCTP/WS/WSS/DTLS
- `src/proxy.rs` — §16.6 request forwarding, §16.7 response processing (library-only)
- `src/routing.rs` — loose routing per §16.12.1, route set per §12.1.1/§12.1.2, §16.4 preprocessing without `maddr` (library-only)
- `src/digest_verifier.rs` — RFC 7616 server-side digest verifier, feature `digest-auth` (library-only)
- `src/privacy.rs` — RFC 3323 privacy service, RFC 3325 inbound identity sanitizing, RPID→PAI (library-only)
- `src/redirect.rs` — §13.2.2.4 redirect handling, Contact q-values per §20.10 (library-only)
- `src/options.rs` — §11 OPTIONS capability querying (library-only)
- `src/auth.rs` — digest auth per RFC 2617 / RFC 7616 / §22 (MD5, SHA-256, SHA-512-256 hashers)
- `src/topology.rs` — topology hiding per RFC 3323/3325
- `src/builder.rs` — request builder with auto-header generation
- `src/manipulation.rs` — header manipulation engine (SBC use; wired in sbc-daemon)

### Gaps
- No `TODO`/`FIXME` related to standards gaps found
- RFC 3261 §16.4 `maddr` check (MUST) not implemented (`// POAM:` in `preprocess_route_information`, NIST POA&M-235)
- `DigestVerifier`, `preprocess_route_information`, loop detection, `apply_privacy`, `sanitize_inbound_identity` have no caller in any shipped binary (NIST POA&M-236); `DigestVerifier` nc state is node-local (`// POAM:` in `digest_verifier.rs`)
- Compact header forms (§7.3.3) supported for core headers (parse-only; the daemon/client framers special-case only `l:`)
- sbc-daemon relays only REGISTER/INVITE/ACK/BYE/CANCEL/OPTIONS/UPDATE; all other methods receive 405
- sbc-daemon trunk failover (RFC 3263 §4.3): 408/Timer B/503 plus local-policy 500/502/504; a transport error on the first send of a B-leg INVITE also fails over immediately; a trunk's 503 `Retry-After` (§21.5.4, §20.33) sets the trunk cooldown, clamped to `general.trunk_retry_after_max_secs` (RFC-001 resolved). See `docs/RFC_COMPLIANCE_GAPS.md`
- sbc-daemon transaction timers follow the receive transport (reliable on TCP/TLS/WS/WSS/SCTP, so no Timer A/E/G there; RFC 3261 §17.1.1.2/§17.1.2.2/§17.2.1/§17.2.2). Timer-loop sends (failover INVITEs, BYEs) still go out on UDP (POA&M-5); the stream-loop wiring has no end-to-end test. See `docs/RFC_COMPLIANCE_GAPS.md`
- sbc-daemon stream framing (RFC 3261 §18.3/§20.14): on TCP/TLS a missing, duplicate, conflicting or malformed Content-Length gets a 400 and the connection closes; the framer shares `SipMessage::stream_message_len` with the parser. Post-framing parse still uses datagram rules (POA&M-64)
- sbc-daemon RFC 5626 §4.4.1: CRLFCRLF pings on TCP/TLS are answered with a CRLF pong, one per batch of pings read together
- The `general.max_calls` admission-ceiling 503 carries no `Retry-After`
- sbc-daemon call-path responses: a blocked route pattern gets 403 with no fallback (RFC 3261 §21.4.4); an emergency call with no route gets 503 without `Retry-After` (`emergency_unrouted`); a numeric-looking malformed, empty or >256-byte R-URI user gets 404
- sbc-daemon per-user limiter: 503 `Retry-After: 1`, keyed on the authenticated AOR or on source /32 or /64 plus canonical From user; trunk sources, ACK and emergency INVITEs are exempt (RFC 6881 §5)
- Open: RFC 3966 `;phone-context` dropped (POA&M-100), translated local numbers lose their context, `urn:service:sos` not classified as emergency (RFC 5031, RFC 6881 §6.2); see `docs/RFC_COMPLIANCE_GAPS.md`
- sbc-daemon trunk TLS policy: a `sips:` Request-URI restricts trunk egress to TLS trunks in every routed group (RFC 3261 §26.2.2); `require_tls` groups / `security.require_tls_trunks` do the same per group (cross-group fallback for `sip:` calls remains, NIST POA&M-57). With no eligible TLS trunk the SBC answers 503 with `Reason: Q.850;cause=79` (RFC 6432) and no `Retry-After`. API trunks without a port default to 5061 for TLS, 5060 otherwise (RFC 3261 §19.1.2 / RFC 3263). Open: the last trunk's 503 is relayed unchanged when failover is exhausted (RFC-004). See `docs/RFC_COMPLIANCE_GAPS.md`

---

## 2. proto-sdp — Session Description Protocol

**Primary Standard:** RFC 8866 (SDP, supersedes RFC 4566)

**Wiring note:** no shipped binary uses proto-sdp. `sbc-daemon` does string-based SDP handling via `proto_b2bua::SdpRewriter` / `extract_media_address` and `sdp_dtls.rs`; `client-sip-ua` lists the dependency but has no call sites. All rows below are **Library-only**.

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 8866** | SDP | **Full** — session, media, attributes, connection, bandwidth (§5.8), repeat times (§5.11), multicast (§5.7). **Library-only** |
| **RFC 3264** | Offer/Answer Model | **Full** — answer generation (§6), direction negotiation (§6.1), hold/resume (§8.4.3), stream disable (§8.4), media modification validation (§8.4), multicast (§6.2). **Library-only** — daemon relays re-INVITE SDP (hold/resume) opaquely |
| **RFC 2365** | Administratively Scoped Multicast | Multicast scope detection. Library-only |
| **RFC 3551** | RTP/AVP Profile | Transport protocol enum. Library-only |
| **RFC 3711** | SRTP | Transport protocol: RTP/SAVP. Library-only |
| **RFC 3890** | TIAS Bandwidth | Bandwidth modifier. Library-only |
| **RFC 4568** | SDP Security Descriptions (SDES) | **Full** — crypto attribute parsing, cipher suites, key params. **Library-only** — shipped media path is DTLS-SRTP only; no `a=crypto` handling in any binary |
| **RFC 4572** | Fingerprint Attribute for DTLS | Referenced |
| **RFC 4585** | RTP/AVPF | Transport protocol enum. Library-only |
| **RFC 5245** | ICE Candidates in SDP | Referenced |
| **RFC 6188** | AES-256-CM | Cipher suite enum. Library-only |
| **RFC 7714** | AES-GCM for SRTP | Cipher suite: AEAD_AES_256_GCM. Library-only |

### Key Files
- `src/lib.rs` — module exports, SDP version constant
- `src/session.rs` — session description, repeat times (§5.11), bandwidth (§5.8)
- `src/media.rs` — media description, transport protocols
- `src/attribute.rs` — SDP attributes per RFC 8866
- `src/offer_answer.rs` — RFC 3264 full implementation
- `src/multicast.rs` — RFC 3264 §6.2 multicast negotiation, RFC 2365 scoping
- `src/srtp.rs` — RFC 4568 SDES crypto attributes

### Gaps
- No `TODO`/`FIXME` found
- Not wired into any shipped binary (see wiring note above)

---

## 3. proto-rtp — RTP/RTCP

**Primary Standard:** RFC 3550 (RTP)

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3550** | RTP — packet format (§5), sequence/jitter tracking (§6.4.1) | **Full**. **Wired (sbc-media-core `media_pipeline.rs`: `RtpHeader::parse`, `SequenceTracker`; sbc-announcement-server: `RtpPacket`; soft client `client-audio`)** |
| **RFC 3550** | RTCP SR/RR (§6.4), SDES, BYE | **Full**. **Wired (soft client only)** — `client-audio/rtcp_session.rs` builds SR/RR; sbc-media-core relays RTCP opaquely (no parsing) |
| **RFC 3550** | Translator/mixer (§7), SSRC collision detection (§8.2), RTCP scheduling (§6.3, A.7), CSRC validation (§5.1), timer reconsideration (§6.3.6) | **Full**. **Library-only** — `RtpTranslator`, `RtpMixer`, `RtcpScheduler`, `SsrcCollisionDetector`, `JitterCalculator` have no call sites in any binary |
| **RFC 3551** | RTP Profile for Audio/Video | **Partial** — standard payload type table (PCMU=0, PCMA=8, G722=9, etc.). **Wired (soft client `payload_types`)**; sbc-media-core uses `uc-codecs` `CodecCapability` instead. Dynamic PTs 64-71/77-95 are adopted under rtcp-mux, against RFC 5761 §4 advice (72-76 rejected; POA&M-143, test `test_is_dynamic_ranges`) |
| **RFC 5761** | Multiplexing RTP/RTCP | Referenced — `rtcp_mux` is an sbc-media-core pipeline config flag, not proto-rtp code |

### Key Files
- `src/lib.rs` — RTP version, payload type constants per RFC 3551
- `src/packet.rs` — RTP header per §5
- `src/rtcp.rs` — RTCP packet types per §6
- `src/translator.rs` — RFC 3550 §7 translator/mixer, CSRC handling, SSRC collision (§8.2) (library-only)
- `src/scheduler.rs` — RTCP scheduling per §6.3/A.7, timer reconsideration (§6.3.6) (library-only)
- `src/sequence.rs` — jitter calculator per §6.4.1

### Key Implementations
- `RtpTranslator` — per §7.1, preserves SSRC (or optional mapping) — library-only
- `RtpMixer` — per §7.1, own SSRC + CSRC list, SR generation per §7.3 — library-only
- `RtcpScheduler` — full §6.3/A.7 algorithm with timer reconsideration — library-only
- `JitterCalculator` — per §6.4.1 — library-only
- `SsrcCollisionDetector` — per §8.2 — library-only

### Gaps
- Mixer/translator reception reports have `jitter`, `last_sr`, `delay_since_last_sr` hardcoded to 0
- Would need per-source JitterCalculator and SR timestamp tracking for full compliance

---

## 4. proto-srtp — Secure RTP

**Primary Standard:** RFC 3711 (SRTP), RFC 7714 (AES-GCM for SRTP)
**Design Goal:** CNSA 2.0 compliance

**Wiring:** **Wired (sbc-media-core, i.e. sbc-daemon and sbc-media; soft client)** — `media_pipeline.rs` `create_srtp_contexts` builds `SrtpContext` with `SrtpProfile::AeadAes256Gcm` from sidecar-exported keys; `srtp_relay.rs` uses `protect_rtcp`/`unprotect_rtcp`; `client-audio/rtp_handler.rs` uses `SrtpProtect`/`SrtpUnprotect`.

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3711** | SRTP | **Partial** (intentional) — packet indexing (§3.3.1), ROC, replay protection (§3.4.1), SRTCP E-flag (§4), key derivation labels. **Intentionally omits** AES-128-CM, HMAC-SHA1, SHA-1 KDF. **Wired (sbc-media-core; soft client)** |
| **RFC 5764** | DTLS-SRTP | Profile ID 0x0008. **Wired (sbc-media-core `dtls_relay.rs`; soft client `media_session.rs`)** |
| **RFC 7714** | AES-GCM for SRTP | **Full** — AES-256-GCM, 96-bit nonce construction, 128-bit tag, AAD. **Wired (sbc-media-core; soft client)** |

### Key Files
- `src/lib.rs` — SrtpProfile enum, profile IDs
- `src/context.rs` — ROC calculation per §3.3.1, nonce construction per RFC 7714, replay protection
- `src/protect.rs` — RTP/SRTCP encrypt/decrypt per RFC 7714
- `src/key.rs` — key derivation labels per §4.3, HKDF-SHA384 KDF

### Intentional Deviations (CNSA 2.0)

| RFC Standard | Deviation | Reason |
|-------------|-----------|--------|
| RFC 3711 KDF (SHA-1 PRF) | HKDF-SHA384 | CNSA 2.0 |
| RFC 3711 cipher (AES-128-CM) | Only AES-256-GCM | CNSA 2.0 |
| RFC 3711 auth (HMAC-SHA1) | GCM AEAD | CNSA 2.0 |

### RFC 7714 Compliance Matrix

| Feature | Requirement | Status |
|---------|-------------|--------|
| Cipher suite | AEAD_AES_256_GCM | **Full** — Wired (sbc-media-core; soft client) |
| Key size | 256 bits | **Full** — Wired (sbc-media-core; soft client) |
| Salt size | 96 bits | **Full** — Wired (sbc-media-core; soft client) |
| Nonce | 2 zero + SSRC(4) + index(6) XOR salt | **Full** — Wired (sbc-media-core; soft client) |
| Tag size | 128 bits | **Full** — Wired (sbc-media-core; soft client) |
| AAD | RTP header / first 8 bytes RTCP | **Full** — Wired (sbc-media-core; soft client) |

### Gaps
- No `TODO`/`FIXME` found — deviations are documented and intentional

---

## 5. proto-stun — STUN

**Primary Standard:** RFC 5389 / RFC 8489

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 5389** | STUN — message format, magic cookie, Binding request/response, retransmission (§7.2.1), FINGERPRINT (CRC32), MESSAGE-INTEGRITY, error codes | **Full**. **Wired (sbc-daemon `zone.rs`: `StunClient::discover_srflx` for external-IP discovery, driven by `runtime.rs` `ExternalIpMonitor`; soft client via proto-ice connectivity checks)** |
| **RFC 5389** | STUN long-term credential mechanism (§10.2) | **Full**. **Library-only** — only exercised by proto-turn `TurnClient`, which no binary configures |
| **RFC 8489** | STUN (updated) | Referenced alongside 5389 |
| **RFC 4013** | SASLprep | Referenced (simplified implementation). Library-only |
| **RFC 5245/8445** | ICE | Attribute types (ICE-CONTROLLING, ICE-CONTROLLED, USE-CANDIDATE, PRIORITY). Wired (soft client only, via proto-ice) |
| **RFC 5766** | TURN | Allocate method. Library-only |

### Key Files
- `src/lib.rs` — STUN magic cookie, message types
- `src/message.rs` — message encoding, MESSAGE-INTEGRITY (HMAC), FINGERPRINT (CRC32)
- `src/attribute.rs` — attribute types per RFC 5389/8489, ICE attributes per RFC 5245/8445
- `src/client.rs` — retransmission per §7.2.1 (500ms initial, 1.6s max, 7 retries)
- `src/credential.rs` — long-term credential (§10.2), nonce lifecycle (library-only)
- `src/error.rs` — error codes per RFC 5389

### Intentional Deviations

| RFC Standard | Deviation | Reason |
|-------------|-----------|--------|
| RFC 5389 (MD5 key derivation) | SHA-384 | CNSA 2.0 |
| RFC 5389 (HMAC-SHA1) | HMAC-SHA256 | RFC 8445 requirement |
| RFC 4013 SASLprep | Simplified | Noted in comments |

---

## 6. proto-turn — TURN Relay

**Primary Standard:** RFC 5766 / RFC 8656

**Wiring note:** **Library-only.** The only caller is proto-ice's `IceAgent` (relay candidate gathering when `IceConfig.turn_servers` is non-empty). The soft client configures STUN servers from settings but no TURN server (the settings schema carries no TURN password), and the SBC does not run ICE. No `proto_turn` references exist in `crates/sbc` or `crates/client`.

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 5766** | TURN | **Full** — allocations, permissions (5min lifetime), channel bindings (10min lifetime), Send/Data indications (§9/§12), ChannelData format, attribute types. **Library-only** |
| **RFC 8656** | TURN (updated) | Referenced, ADDITIONAL-ADDRESS-FAMILY attribute. Library-only |
| **RFC 6156** | TURN IPv6 | REQUESTED-ADDRESS-FAMILY attribute. Library-only |

### Key Files
- `src/lib.rs` — module structure
- `src/allocation.rs` — permission lifetime (5min per §8), channel binding lifetime (10min per §11)
- `src/indication.rs` — Send (§9) and Data (§12) indications, max datagram size
- `src/channel.rs` — ChannelData format per §11.4, max 65531 bytes
- `src/attribute.rs` — TURN attributes per RFC 5766/8656
- `src/client.rs` — allocation flow per §6

### Gaps
- No `TODO`/`FIXME` found
- Not wired into any shipped binary (see wiring note above)

---

## 7. proto-ice — ICE NAT Traversal

**Primary Standard:** RFC 8445 (supersedes RFC 5245)

**Wiring note:** **Wired (soft client only)** — `client-sip-ua/ice_handler.rs` constructs `IceAgent`, gathers host (and, when a STUN server is configured in `[network]` settings, server-reflexive) candidates, and runs connectivity checks with nomination on the media socket; `media_session.rs` falls back to the SDP address on ICE mismatch or failure. The SBC does not run ICE by design (media anchoring with symmetric latching).

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 8445** | ICE | **Full** — candidate types and priority (§5.1.2), pair priority (§6.1.2.3), checklist initialization (§6.1.2.6), connectivity checks (§6-7), role conflict (§7.3.1.1), aggressive nomination (§7.2.2), keepalives (§10), retransmission (§14.3). **Wired (soft client only)**; the SBC does not run ICE |
| **RFC 5245** | ICE (legacy) | Referenced |
| **RFC 7675** | Consent Freshness | **Full** — 5s interval, 30s timeout, consent revocation (§6), MUST cease sending. **Library-only** — `consent.rs` is not driven by `IceAgent` or any binary |
| **RFC 8839** | SDP for ICE | Referenced — soft client parses `a=candidate`/ufrag/pwd itself (`IceHandler::parse_sdp_candidate`, `call_manager.rs`) |

### Key Files
- `src/lib.rs` — type preferences per §5.1.2.2
- `src/agent.rs` — ICE agent, candidate gathering (§5), aggressive nomination (§7.2.2)
- `src/candidate.rs` — candidate priority (§5.1.2.1), foundation (§5.1.1.3)
- `src/checklist.rs` — pair priority (§6.1.2.3), pair state initialization (§6.1.2.6)
- `src/connectivity.rs` — connectivity checks (§6-7), STUN request (§7.1.1), role conflict (§7.3.1.1)
- `src/consent.rs` — RFC 7675 consent freshness, RFC 8445 §10 keepalives (library-only)

### Key Constants
- `INITIAL_RTO`: 500ms per §14.3
- `MAX_RETRANSMISSIONS`: 7 per §14.3
- `CONSENT_FRESHNESS_INTERVAL`: 5s per RFC 7675
- `CONSENT_TIMEOUT`: 30s per RFC 7675
- `KEEPALIVE_INTERVAL`: 15s per §10

### Gaps
- No `TODO`/`FIXME` found
- The SBC does not run ICE (by design: media anchoring with symmetric latching); ICE is a soft-client feature

---

## 8. proto-dtls — DTLS 1.2

**Primary Standard:** RFC 6347

**Wiring note:** the proto-dtls handshake runs only in the **soft client** (`client-sip-ua/dtls_handler.rs`: `DtlsConnection::handshake`, `export_srtp_keying_material`). The SBC terminates DTLS-SRTP through the **Go terminator sidecar** (`sbc-media-core/src/dtls_sidecar.rs`, `media_pipeline.rs` `terminate_leg_dtls` / `start_relay_terminate`); the proto-dtls `start_dtls_handshake`/`complete_dtls_handshake` paths in `media_pipeline.rs` have no callers. sbc-media-core uses proto-dtls only for PEM parsing (`dtls_identity.rs`) and certificate fingerprints.

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 6347** | DTLS 1.2 | **Full** — record layer (§4.1), handshake (§4.2), certificate validation (§4.2.4), Finished message verification (§4.2.6), replay protection, version 0xFEFD. **Wired (soft client only)**; SBC side is Library-only (Go sidecar terminates DTLS) |
| **RFC 5763** | DTLS-SRTP Framework | Referenced — `a=setup` handled by sbc-daemon `sdp_dtls.rs` |
| **RFC 5764** | DTLS-SRTP Key Export | **Full** — exporter label, key material layout (§4.2), `use_srtp` extension. **Wired (soft client only)**; SBC receives SRTP keys from the sidecar |
| **RFC 5705** | TLS Exporters | Key derivation implementation. Wired (soft client only) |
| **RFC 5288** | AES-GCM for TLS | Nonce construction for record encryption. Wired (soft client only) |
| **RFC 4572** | Fingerprint Attribute | Certificate fingerprint module. **Wired (sbc-media-core `dtls_identity.rs`, sbc-daemon `sdp_dtls.rs`; soft client)** |
| **RFC 7627** | Extended Master Secret | Config option. Wired (soft client only) |
| **RFC 7714** | AES-GCM Cipher Suite | `AEAD_AES_256_GCM` support. Wired (soft client only) |

### Key Files
- `src/lib.rs` — cipher suites, SRTP profile negotiation (RFC 5764)
- `src/record.rs` — record format per §4.1, replay protection, nonce per RFC 5288
- `src/handshake.rs` — full handshake per §4.2, certificate validation (§4.2.4), Finished (§4.2.6)
- `src/srtp_export.rs` — RFC 5764 §4.2 key export, RFC 5705 exporter
- `src/verify.rs` — certificate chain validation (§4.2.4), Finished verification (§4.2.6), ServerKeyExchange
- `src/fingerprint.rs` — RFC 4572 certificate fingerprints
- `src/session.rs` — DTLS session, SRTP key export per RFC 5764
- `src/connection.rs` — connection management
- `src/config.rs` — extended master secret (RFC 7627); PEM loading reused by sbc-media-core

---

## 9. proto-transaction — SIP Transaction Layer

**Primary Standard:** RFC 3261 §17

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP Transactions | **Full** — client INVITE (§17.1.1), client non-INVITE (§17.1.2), server INVITE (§17.2.1), server non-INVITE (§17.2.2), transaction matching (§17.1.3), branch magic cookie, Timer T1/T2/T4, 2xx bypass for server INVITE. **Wired (sbc-daemon `sip_stack.rs`: `ServerInviteTransaction`/`ServerNonInviteTransaction`/`ClientInviteTransaction`/`ClientNonInviteTransaction`, `TransactionKey`, timers driven by `poll_timers`; soft client `registration.rs`/`call_agent.rs`)** |
| **RFC 3262** | 100rel / PRACK | **Full** — RSeq/RAck headers, reliable provisional tracking, random initial RSeq (1 to 2^31). **Library-only** — no binary sends or handles PRACK; sbc-daemon returns 405 |
| **RFC 3311** | UPDATE | Non-INVITE transaction machine reuse. **Wired (sbc-daemon)** — `handle_update` opens server/client non-INVITE transactions and relays |
| **RFC 4028** | Session Timers | UPDATE for session timer refresh. **Wired (sbc-daemon, header relay only)** — see §1/§10 |

### Key Files
- `src/lib.rs` — T1 (500ms), T2 (4s), T4 (5s), TransactionKey, branch magic cookie
- `src/client.rs` — client INVITE (§17.1.1), client non-INVITE (§17.1.2), Timer E capping at T2
- `src/server.rs` — server INVITE (§17.2.1), server non-INVITE (§17.2.2), 2xx bypass
- `src/prack.rs` — RFC 3262 100rel, RSeq/RAck, reliable provisional tracking (library-only)

---

## 10. proto-dialog — SIP Dialog Layer

**Primary Standard:** RFC 3261 §12

**Wiring note:** proto-dialog is effectively unused by shipped binaries. sbc-daemon imports `Dialog`/`DialogId` and holds a `DialogStore`, but never populates it (call state lives in the daemon's own call-correlation maps); the soft client's `dialog: Option<Dialog>` is always `None`. Only `refer::ReferRequest`/`ReferStatus` are used (soft client).

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP Dialogs (§12) | **Full** — dialog ID (Call-ID + local/remote tags), state machine. **Library-only** — daemon `DialogStore` never populated; client dialog field never set |
| **RFC 3515** | REFER | **Full** — transfer status, subscription state. **Wired (soft client only)** — `call_agent.rs` `ReferRequest`/`ReferStatus`/sipfrag parsing; daemon does not relay REFER |
| **RFC 3680** | Registration Event Package | Event package entry. Library-only |
| **RFC 3842** | Message Waiting Indication | Event package entry. Library-only |
| **RFC 3856** | Presence Event Package | Event package entry. Library-only |
| **RFC 3857** | Watcher Information | Event package entry. Library-only |
| **RFC 4028** | Session Timers | **Full** — timer tracking, refresh at expires/2 (§5), 422 handling (§8.1.1), Min-SE negotiation. **Library-only** — `session_timer.rs` unused; sbc-daemon only relays Session-Expires/Min-SE/`Require: timer` headers (`sip_stack.rs`) and has no 422 handling |
| **RFC 4235** | Dialog Event Package | Event package entry. Library-only |
| **RFC 4538** | Media Authorization | Event package entry. Library-only |
| **RFC 4575** | Conference Event Package | Event package entry. Library-only |
| **RFC 4730** | KPML | Event package entry. Library-only |
| **RFC 5070** | Consent Event Package | Event package entry. Library-only |
| **RFC 5359** | Line Event Package | Event package entry. Library-only |
| **RFC 5362** | Resource Lists Event Package | Event package entry. Library-only |
| **RFC 5373** | Call Completion | Event package entry. Library-only |
| **RFC 5628** | Media Description Changes | Event package entry. Library-only |
| **RFC 5875** | XCAP Diff Event | Event package entry. Library-only |
| **RFC 6035** | VoIP Metrics (vq-rtcpxr) | Event package entry. Library-only |
| **RFC 6446** | Session Recording | Event package entry. Library-only |
| **RFC 6665** | SIP Events | **Full** — subscription states, termination reasons, IANA event package validation (§7.2). **Library-only** — `subscription.rs` unused; daemon 405s SUBSCRIBE/NOTIFY; client reads Subscription-State header as a string on REFER NOTIFY |
| **RFC 6910** | Auto-Configuration | Event package entry. Library-only |
| **RFC 7614** | Location Conveyance | Event package entry. Library-only |
| **RFC 7840** | Multiple Phone Numbers | Event package entry. Library-only |
| **RFC 8068** | Pending Additions | Event package entry. Library-only |

### Key Files
- `src/lib.rs` — session expires defaults per RFC 4028
- `src/dialog.rs` — dialog state, dialog ID per §12 (library-only)
- `src/session_timer.rs` — RFC 4028 full implementation (library-only)
- `src/refer.rs` — RFC 3515 REFER transfer handling (wired: soft client)
- `src/subscription.rs` — RFC 6665 event framework, 30+ IANA event packages (library-only)
- `src/forking.rs` — RFC 3261 §12.2.2 dialog forking (library-only)

---

## 11. proto-b2bua — Back-to-Back User Agent

**Primary Standard:** RFC 7092

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 7092** | B2BUA Taxonomy | **Full** — mode definitions (§3), SDP rewriting. **Wired (sbc-daemon `sip_stack.rs`: `SdpRewriter::new(B2buaMode::MediaRelay)`, `extract_media_address`, `MediaAddress`, `Call`/`CallConfig`/`CallId`)** |
| **RFC 5853** | SBC Requirements | Referenced |
| **RFC 3960** | Early Media (183) | **Full** — early media handling module. **Library-only** — `early_media.rs` (`EarlyMediaHandler`/`EarlyMediaSession`) has no call sites; sbc-daemon rewrites 183-with-SDP natively in its response path (`sip_stack.rs`) |
| **RFC 3261** | SIP Core | Referenced |
| **RFC 3264** | Offer/Answer | Hold signaling via direction — daemon relays re-INVITE SDP opaquely |
| **RFC 4566** | SDP Format | Referenced for SDP rewrite |

### Key Files
- `src/lib.rs` — B2BUA types per RFC 7092 §3
- `src/mode.rs` — mode-specific behavior per RFC 7092
- `src/sdp_rewrite.rs` — SDP rewriting for media anchoring per RFC 7092 (wired: sbc-daemon)
- `src/early_media.rs` — RFC 3960 early media handling (library-only)

---

## 12. proto-registrar — SIP Registrar

**Primary Standard:** RFC 3261 §10

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP Registrar (§10) | **Full** — binding management, 200 OK response format (§10.3), authentication (§22), Contact formatting, Date header. **Wired (sbc-daemon `sip_stack.rs` `handle_register` → `AuthenticatedRegistrar::process_register`, `LocationService`/`AsyncLocationService`, `Binding`)** |
| **RFC 5626** | SIP Outbound — instance-id / reg-id binding parameters, CRLF keepalive absorption (§3.5.1) | **Full**. **Wired (sbc-daemon)** — `+sip.instance`/`reg-id` parsed into `ContactInfo` and echoed in Contact; TCP framer absorbs double-CRLF pings (`server.rs`) |
| **RFC 5626** | SIP Outbound — flow state machine, §5.2 flow manager, flow maintenance | **Full**. **Library-only** — `outbound.rs` (`OutboundFlowManager`, `Flow`, `FlowState`, `FlowToken`) has no call sites |
| **RFC 5627** | GRUU | **Full** — public/temp GRUU generation, proxy routing (§5.1), multi-flow handling. **Library-only** — `gruu.rs` (`GruuService`) unused; daemon REGISTER 200 carries no pub-gruu/temp-gruu |
| **RFC 3327** | Path Header | **Full** — path storage and routing. **Library-only** — registrar `path` field never populated by the daemon |
| **RFC 3608** | Service-Route | Header in response. Library-only — daemon emits none |
| **RFC 2617** | Digest Auth | Nonce lifecycle management. **Wired (sbc-daemon)** via `AuthenticatedRegistrar` with config-backed password lookup |
| **RFC 7616** | Digest Auth (server side) | **Partial** (POA&M-230) — `authentication.rs` `Authenticator::authenticate` enforces realm, the configured algorithm (default SHA-256), offered qop with cnonce and nc, opaque echo, and digest-uri equal to the Request-URI (§19.1.4 `SipUri::equivalent`); nc is committed only after the response matches; `AuthCredentials::parse` rejects unknown or `-sess` algorithms and unknown qop (client re-challenged) instead of mapping them to MD5; the nonce table is bounded (65,536, oldest evicted, O(1)); with qop disabled a nonce is single-use. Tests `algorithm_downgrade_rejected`, `qop_mismatch_rejected`, `uri_mismatch_rejected_equivalent_accepted`, `bad_response_does_not_consume_nc`, `opaque_must_echo`, `unknown_algorithm_or_qop_is_malformed`, `realm_mismatch_rejected_before_response_check`, `full_table_evicts_oldest_in_order_and_stays_bounded`, `nonce_without_qop_is_single_use`, `digest_response_matches_rfc7616_sha256_vector`. **Gap:** sbc-daemon does not pass the Request-URI (`RegisterRequest::with_request_uri`), so the digest-uri check is skipped on the live path (`// POAM:`, NIST POA&M-233); the daemon digest path itself is enabled only when `require_auth` is set, which no configuration path sets today (NIST IA-2) |

### Key Files
- `src/lib.rs` — default expiration (3600s per RFC 3261), auth module
- `src/registrar.rs` — registration processing per §10.3, Contact formatting, Date header
- `src/binding.rs` — binding state, instance-id/reg-id per RFC 5626, Path per RFC 3327
- `src/location.rs` — location service, instance-id lookup
- `src/async_location.rs` — async location service with RFC 5626 support (wired: sbc-daemon cluster mode)
- `src/outbound.rs` — RFC 5626 §5.2 flow maintenance, keepalive (CRLF per §3.5.1) (library-only)
- `src/gruu.rs` — RFC 5627 GRUU generation and proxy routing (§5.1) (library-only)
- `src/authentication.rs` — RFC 3261 §22 / RFC 2617 / RFC 7616 digest auth
- `src/bearer.rs` — RFC 8898 bearer auth (wired: sbc-daemon `server.rs` with proto-jwt)

---

## 13. proto-stir-shaken — Caller ID Verification

**Primary Standard:** RFC 8224/8225/8226

**Wiring note:** **Wired (sbc-daemon), off by default.** `sbc-daemon` (`src/stir.rs`, `src/sip_stack.rs`) and `uc-sti` use proto-stir-shaken to sign B-leg INVITEs toward `sign = true` trunks and verify Identity on `verify = true` trunks. The crate itself is pure and synchronous; certificate fetch/cache/anchors/signing key live in `uc-sti`, ES256 and X.509 in `uc-crypto` (`interop::ecdsa_p256`, `x509`).

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 8224** | Authenticated Identity Management | **Partial — Wired (sbc-daemon)**. Identity header parse/generate with `info`, `alg`, `ppt` (`identity.rs`; 4 KiB, 16 params); verification service with 428/436/437/438 and 403 Stale Date (`verification.rs` `FailureReason::sip_code`, tests `codes`, `qa_stir_stale_iat_rejected_403_stale_date`); authentication service sets `Date` to match `iat` (`sbc-daemon/src/stir.rs` `sign_outbound`). TN canonicalisation §8.3 strips separators and `+`, but non-E.164 numbers are not converted by local policy (RFC-004, POA&M-44). Verifier accepts `orig` matching PAI or From (RFC-005, POA&M-45). No replay cache (POA&M-43). |
| **RFC 8225** | PASSporT | **Partial — Wired (sbc-daemon)**. Compact form, deterministic §9 JSON, strict decode (duplicate members, `alg=none`, `crit`, `typ` rejected) (`passport.rs`, tests `sign_decode_roundtrip`, `malformed_cases`, proptests). ES256 only for `ppt=shaken` (CNSA exception POA&M-27); ES384 rejected (POA&M-32). |
| **RFC 8226** | Secure Telephone Identity Credentials | **Partial — Wired (sbc-daemon)**. TNAuthList extracted and scope-checked for TN/range (`uc-crypto/src/x509.rs`, test `tn_auth_list_parse_and_scope`); SPC scope not checked against TN ownership (POA&M-30); no CRL/OCSP (POA&M-28). |
| **RFC 8588** | SHAKEN PASSporT extension | **Wired (sbc-daemon)**. `attest` A/B/C and `origid` (required on decode); attestation policy in `uc-sti/src/policy.rs` (test `matrix`). Registered-endpoint A requires the INVITE on the same TCP/TLS connection as the REGISTER, following RFC 5626 §3.1/§5.2 flow semantics (`ConnId`, unbound on close; `sbc-daemon/src/stir_binding.rs`, tests `poam36_*`); not bound to the TLS peer certificate (POA&M-70). |
| **RFC 8946** | `div` PASSporT | **Missing.** `ppt=div` is ignored, not verified (test `div_is_ignored`). |
| ATIS-1000074 | SHAKEN | **Partial — Wired (sbc-daemon)**. `info` must equal `x5u`; `verstat` placed on PAI, else From (`apply_verstat`, test `verstat_rewrite`). |

### Key Files
- `src/canon.rs` — TN canonicalisation (RFC 8224 §8.3)
- `src/jws.rs` — base64url and compact JWS split (4 KiB cap)
- `src/passport.rs` — PASSporT per RFC 8225 / RFC 8588
- `src/identity.rs` — Identity header per RFC 8224
- `src/verification.rs` — verifier, failure reasons and SIP codes, verstat

---

## Cross-Cutting Findings

### Strengths
1. **Excellent RFC citation density** — nearly every public function/struct cites the specific RFC section
2. **CNSA 2.0 consistency** — all crypto crates (SRTP, DTLS, STUN) use AES-256-GCM + SHA-384, documented deviations
3. **Zero `TODO`/`FIXME` for standards gaps** — no deferred compliance work found
4. **Comprehensive test coverage** — all crates have `#[cfg(test)]` modules exercising standards-specific behavior

### Wiring Gaps (crate capability not reached by any shipped binary)
- **proto-sdp**, **proto-turn** — entire crates library-only (proto-stir-shaken is now wired in sbc-daemon)
- **proto-dialog** — only `refer.rs` reaches a binary (soft client); dialog store, session timer, subscriptions, forking unused
- **proto-ice** — soft client only (checks, nomination; STUN via settings); the SBC does not run ICE; RFC 7675 consent and §10 keepalives unused
- **proto-dtls** — soft client only; SBC DTLS termination is the Go sidecar
- **proto-sip** proxy/routing/redirect/options modules, Path header; **proto-transaction** PRACK; **proto-registrar** GRUU/Path/Service-Route/flow manager; **proto-b2bua** early-media module; **proto-rtp** translator/mixer/scheduler/collision detector
- **sbc-daemon** relays only REGISTER/INVITE/ACK/BYE/CANCEL/OPTIONS/UPDATE; REFER, SUBSCRIBE/NOTIFY, PRACK, MESSAGE, INFO, PUBLISH receive 405

### Intentional Deviations (All Documented)

| Crate | RFC Standard | Deviation | Reason |
|-------|-------------|-----------|--------|
| proto-srtp | RFC 3711 KDF (SHA-1) | HKDF-SHA384 | CNSA 2.0 |
| proto-srtp | RFC 3711 cipher | Only AES-256-GCM | CNSA 2.0 |
| proto-stun | RFC 5389 (MD5 key derivation) | SHA-384 | CNSA 2.0 |
| proto-stun | RFC 5389 (HMAC-SHA1) | HMAC-SHA256 | RFC 8445 requirement |
| proto-stun | RFC 4013 SASLprep | Simplified | Noted in comments |

### Potential Improvements
1. **proto-rtp**: Mixer/translator reception reports have `jitter`, `last_sr`, `delay_since_last_sr` hardcoded to 0 — would need per-source JitterCalculator and SR timestamp tracking
2. **proto-stun**: SASLprep (RFC 4013) is simplified — full compliance noted as incomplete in comments

### CDR syslog sink (not a proto-* crate)

`uc-cdr` hand-formats the CDR syslog output. It does not use `uc-syslog` (see below). The format is RFC 5424: PRI = facility * 8 + 6 (informational), VERSION `1`, an RFC 3339 UTC timestamp with milliseconds and `Z`, the sanitised hostname (`node_id`), APP-NAME `usg-sbc`, PROCID `-`, MSGID `CDR`, STRUCTURED-DATA as NILVALUE `-`, and MSG as the UTF-8 BOM (§6.4) followed by the record's canonical JSON. Framing is RFC 6587 octet counting; the count includes the 3 BOM octets. The transport is RFC 5425 over TLS 1.3 only (`uc_transport::tls::create_client_config`). Cipher suites and key-exchange groups are not restricted, so the suite is not CNSA 2.0 enforced (NIST POA&M-26). Gap: RFC 5425 §4.2 mutual authentication is absent because no client certificate is sent (NIST POA&M-15). Tests: `syslog_octet_counted_rfc5424`, `syslog_sink_octet_counted_frames_via_fake_connector`. No test performs a TLS handshake.

### uc-syslog (library-only, not a proto-* crate)

`uc-syslog` is not called by any shipped binary (NIST POA&M-245). Since 2026-11-07 it has an RFC 5425 transport (`SyslogTransport::Tls`): CNSA client config (`cnsa_provider()`, TLS 1.3 by default), server authenticated against `ca_file` and `server_name`, optional client certificate (§4.2), RFC 6587 / RFC 5425 §4.3 octet counting, close_notify via `SyslogForwarder::close()`, default port 6514, TLS with BSD (RFC 3164) format refused. Status: **Partial**. Gaps: no §5.2.2 end-entity fingerprint matching (SHA-1 mandatory-to-implement conflicts with CNSA 2.0; workaround: put the self-signed collector certificate in `ca_file`); RFC 5424 §6.2 header fields (HOSTNAME, APP-NAME, PROCID, MSGID) are not checked for PRINTUSASCII, length or NILVALUE; at-least-once delivery on reconnect; no buffering when the collector is down. UDP and plain TCP (LF framing) remain. Tests: `tls_delivers_octet_counted_frames`, `untrusted_server_cert_rejected`, `wrong_server_name_rejected`, `tls_with_bsd_format_rejected`, `drop_without_close_is_truncation`, `tls_octet_counted_framing`.

### Complete RFC Index

"Shipped in" names the binary with a call site; "library" means no shipped binary calls it. "soft client" = `client-*` crates (Tauri/FFI client).

| RFC | Title | Crate(s) | Shipped in |
|-----|-------|----------|------------|
| RFC 2365 | Administratively Scoped IP Multicast | proto-sdp | library |
| RFC 2617 | HTTP Digest Authentication | proto-sip, proto-registrar | sbc-daemon, soft client |
| RFC 3261 | SIP | proto-sip, proto-transaction, proto-dialog, proto-registrar, proto-b2bua | sbc-daemon, soft client (message layer, transactions, registrar); dialog layer, proxy/routing/redirect/options: library |
| RFC 3262 | 100rel / PRACK | proto-transaction | library |
| RFC 3263 | Locating SIP Servers | proto-sip, uc-dns | soft client (uc-dns system-conf resolver; partial, no DNSSEC) |
| RFC 2782 | DNS SRV | uc-dns | soft client (weighted random order) |
| RFC 3264 | Offer/Answer Model with SDP | proto-sdp, proto-b2bua | library (daemon relays SDP opaquely; its CDR code reads the answer and skips port-0 `m=audio` per §6, see docs/SDP_RFC_Compliance.md) |
| RFC 3311 | UPDATE Method | proto-sip, proto-transaction | sbc-daemon |
| RFC 3323 | Privacy Mechanism for SIP | proto-sip | sbc-daemon (topology hiding); `Privacy` header service: library |
| RFC 3325 | P-Asserted-Identity | proto-sip | sbc-daemon (topology hider); inbound sanitizing, RPID→PAI: library |
| RFC 3326 | Reason Header | proto-sip; sbc-daemon `cdr.rs` | proto-sip + sbc-daemon (CDR Q.850 extraction) |
| RFC 3327 | Path Header | proto-sip, proto-registrar | library |
| RFC 3428 | MESSAGE Method | proto-sip | library |
| RFC 3455 | P-Headers | proto-sip | library |
| RFC 3515 | REFER Method | proto-sip, proto-dialog | soft client |
| RFC 3550 | RTP | proto-rtp | sbc-media-core, sbc-announcement-server, soft client (packet/RTCP SR-RR); translator/mixer/scheduler: library |
| RFC 3551 | RTP Profile for Audio/Video | proto-rtp, proto-sdp | soft client |
| RFC 3608 | Service-Route | proto-registrar | library |
| RFC 3680 | Registration Event Package | proto-dialog | library |
| RFC 3711 | SRTP | proto-srtp, proto-sdp | sbc-media-core, soft client |
| RFC 3842 | Message Waiting Indication | proto-dialog | library |
| RFC 3856 | Presence Event Package | proto-dialog | library |
| RFC 3857 | Watcher Information | proto-dialog | library |
| RFC 3890 | TIAS Bandwidth | proto-sdp | library |
| RFC 3891 | Replaces Header | proto-sip | library |
| RFC 3903 | PUBLISH Method | proto-sip | library |
| RFC 3960 | Early Media | proto-b2bua | library (daemon handles 183 natively) |
| RFC 4013 | SASLprep | proto-stun | library |
| RFC 4028 | Session Timers | proto-sip, proto-dialog, proto-transaction | sbc-daemon (header relay); proto-dialog refresher: library |
| RFC 4168 | SCTP Transport for SIP | proto-sip | library |
| RFC 9260 / RFC 6951 | SCTP / SCTP over UDP (decoder hardening; see `docs/RFC_COMPLIANCE_GAPS.md`) | uc-transport (`sctp` feature) | library, dormant |
| RFC 2865 / 2869 / 3579, CVE-2024-3596 | RADIUS with required Message-Authenticator (POA&M-280/281) | uc-aaa (`radius` feature) | library, dormant |
| RFC 4235 | Dialog Event Package | proto-dialog | library |
| RFC 4347 | DTLS over UDP | proto-sip | library (transport enum only) |
| RFC 4538 | Media Authorization | proto-dialog | library |
| RFC 4566 | SDP | proto-sip, proto-b2bua | sbc-daemon (string-based rewrite) |
| RFC 4568 | SDP Security Descriptions | proto-sdp | library |
| RFC 4572 | Fingerprint Attribute | proto-sdp, proto-dtls | sbc-media-core, sbc-daemon, soft client |
| RFC 4575 | Conference Event Package | proto-dialog | library |
| RFC 4585 | RTP/AVPF | proto-sdp | library |
| RFC 4730 | KPML | proto-dialog | library |
| RFC 5070 | Consent Event Package | proto-dialog | library |
| RFC 5245 | ICE (legacy) | proto-stun, proto-ice | soft client |
| RFC 5288 | AES-GCM for TLS | proto-dtls | soft client |
| RFC 5359 | Line Event Package | proto-dialog | library |
| RFC 5362 | Resource Lists Event Package | proto-dialog | library |
| RFC 5373 | Call Completion | proto-dialog | library |
| RFC 5424 | The Syslog Protocol | uc-cdr (`sink.rs` `SyslogSink`, hand-formatted; not uc-syslog); uc-syslog (formatter, Partial: header fields not sanitised) | sbc-daemon (CDR syslog sink, opt-in); uc-syslog: library |
| RFC 5425 | TLS Transport for Syslog | uc-cdr, sbc-daemon `cdr.rs` `TlsSyslogConnector`; uc-syslog `SyslogTransport::Tls` (Partial: no §5.2.2 fingerprints, POA&M-245) | sbc-daemon (CDR syslog sink, TLS 1.3 only, server-auth only: no client certificate); uc-syslog: library |
| RFC 5389 | STUN | proto-stun | sbc-daemon (zone external-IP discovery), soft client (ICE checks); long-term credentials: library |
| RFC 5626 | SIP Outbound | proto-registrar | sbc-daemon (instance-id/reg-id, CRLF ping); flow manager: library |
| RFC 5627 | GRUU | proto-registrar | library |
| RFC 5628 | Media Description Changes | proto-dialog | library |
| RFC 5705 | TLS Exporters | proto-dtls | soft client |
| RFC 5761 | Multiplexing RTP/RTCP | proto-rtp | sbc-media-core (config flag) |
| RFC 5763 | DTLS-SRTP Framework | proto-dtls | sbc-daemon (`sdp_dtls.rs` a=setup), soft client |
| RFC 5764 | DTLS-SRTP Key Export | proto-srtp, proto-dtls | soft client (export); sbc-media-core (profile/keys from sidecar) |
| RFC 5766 | TURN | proto-turn, proto-stun | library |
| RFC 5853 | SBC Requirements | proto-b2bua | sbc-daemon |
| RFC 5875 | XCAP Diff Event | proto-dialog | library |
| RFC 6035 | VoIP Metrics | proto-dialog | library |
| RFC 6086 | INFO Method | proto-sip | library |
| RFC 6156 | TURN IPv6 | proto-turn | library |
| RFC 6188 | AES-256-CM | proto-sdp | library |
| RFC 6347 | DTLS 1.2 | proto-dtls | soft client (SBC uses Go sidecar) |
| RFC 6446 | Session Recording | proto-dialog | library |
| RFC 6587 | Syslog over TCP (octet-counting framing) | uc-cdr; uc-syslog (octet counting on TLS, LF on plain TCP) | sbc-daemon (CDR syslog sink; octet counting only); uc-syslog: library |
| RFC 6665 | SIP Events | proto-sip, proto-dialog | library |
| RFC 6910 | Auto-Configuration | proto-dialog | library |
| RFC 7092 | B2BUA Taxonomy | proto-b2bua | sbc-daemon |
| RFC 7118 | WebSocket Transport for SIP | proto-sip, uc-transport | sbc-daemon (ws); wss library |
| RFC 7614 | Location Conveyance | proto-dialog | library |
| RFC 7616 | HTTP Digest (SHA-256, SHA-512-256) | proto-sip, proto-registrar | sbc-daemon REGISTER verifier (proto-registrar; digest-uri check pending POA&M-233); proto-sip `DigestVerifier`: library |
| RFC 7627 | Extended Master Secret | proto-dtls | soft client |
| RFC 7675 | Consent Freshness | proto-ice | library |
| RFC 7714 | AES-GCM for SRTP | proto-srtp, proto-sdp, proto-dtls | sbc-media-core, soft client |
| RFC 7840 | Multiple Phone Numbers | proto-dialog | library |
| RFC 8068 | Pending Additions | proto-dialog | library |
| RFC 8224 | STIR Identity | proto-sip, proto-stir-shaken | sbc-daemon (off by default) |
| RFC 8225 | PASSporT | proto-stir-shaken | sbc-daemon (off by default) |
| RFC 8226 | Secure Telephone Identity Credentials | proto-stir-shaken, uc-crypto | sbc-daemon (off by default) |
| RFC 8588 | SHAKEN PASSporT | proto-stir-shaken, uc-sti | sbc-daemon (off by default) |
| RFC 8445 | ICE | proto-stun, proto-ice | soft client (host candidates); sbc-daemon: library |
| RFC 8489 | STUN (updated) | proto-stun | sbc-daemon, soft client |
| RFC 8656 | TURN (updated) | proto-turn | library |
| RFC 8839 | SDP for ICE | proto-ice | soft client (own parsing) |
| RFC 8866 | SDP | proto-sdp | library |
