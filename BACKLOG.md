# Backlog

Deferred work, roughly prioritized. Native-client items reference
[docs/CLIENT-NATIVE-MIGRATION-PLAN.md](docs/CLIENT-NATIVE-MIGRATION-PLAN.md).
Done so far: Phase 0 (shared `client-ffi` core, `AudioBackend` trait, FIPS,
cross-target CI), the macOS SwiftUI client (live-validated + full SIP/RTP RFC
compliance pass — see [docs/CLIENT_RFC_COMPLIANCE_AUDIT.md](docs/CLIENT_RFC_COMPLIANCE_AUDIT.md)),
and the iOS app target (AudioUnit-VPIO backend; builds, registers against
BulkVS in the Simulator).

## Dependency hygiene

- [ ] **GTK3 advisories** (RUSTSEC-2024-0429 glib, RUSTSEC-2024-0370
  proc-macro-error) clear themselves when `client-gui-tauri` is retired for
  the native clients.

## iOS on-device

The Simulator proves signaling but not real audio (its audio stack can't
exercise VPIO hardware AEC) and can't host CallKit/PushKit. These need a real
device and Apple code-signing.

- [ ] **Code signing / provisioning** — Apple Developer team in the xcodegen
  project (`clients/apple/ios/project.yml`); provisioning profile; deploy to a
  device. Prerequisite for everything below.
- [ ] **Real-call audio validation** — exercise the iOS AudioUnit
  VoiceProcessingIO duplex backend (`crates/client/client-audio/src/ios_vpio.rs`)
  on-device: bidirectional audio, hardware AEC, the Bluetooth HFP/A2DP
  rate-mismatch class of bugs, route changes, interruptions (Siri, phone
  calls). The Swift shell already sets AVAudioSession `.playAndRecord` /
  `.voiceChat`.
- [ ] **CallKit** — system call UI, audio-session activation handshake,
  hold/mute coordination, call history integration. Replaces the in-app call
  overlay as the OS-level call surface.
- [ ] **PushKit (VoIP push)** — wake the app for incoming INVITEs in the
  background. Without it, inbound calls only work foregrounded. Depends on the
  server-side push gateway below.
- [ ] **Server-side push gateway** (touches `crates/sbc/*`, not the client) —
  on an inbound INVITE for a mobile registration, fire an APNs VoIP push and
  hold the INVITE per RFC 3261 timers until the device re-registers. Its own
  scope/design doc; the migration plan flags this as Phase 3. Android FCM
  shares this component.
- [ ] **iOS Keychain `CertProvider`** — replace the DEBUG dev-seed +
  encrypted-file credential store with Secure Enclave / Keychain and
  CAC/PIV-derived credentials (Purebred-style) for production mTLS. The
  dev-seed (`DevSeed.swift`, DEBUG-only) is a test stopgap.
- [ ] **App distribution** — TestFlight / MDM; NIAP/STIG evaluation tracked
  under `stigs/`.

## Android on-device

The Android client (PR #18) builds, registers, and places connected calls in
the emulator with the Oboe backend; far-end playback is audibly confirmed. The
emulator can't validate capture (no host mic) or background/incoming-call
behavior.

- [ ] **On-device audio validation** — bidirectional audio through the Oboe
  duplex backend on a physical device: capture (the emulator only ever fed it
  silence — `max_amp=0`), route changes, Bluetooth, `AcousticEchoCanceler`
  (Android's AEC is a separate AudioEffect, not wired — software AEC is on).
- [ ] **ConnectionService (self-managed)** — system call integration + a
  foreground service (`microphone`/`phoneCall` type) during active calls.
- [ ] **FCM high-priority push** — wake the app for incoming INVITEs in the
  background. Shares the server-side push gateway with iOS PushKit (see above).
- [ ] **Android KeyStore `CertProvider`** — hardware-backed keys / derived
  credentials, replacing the DEBUG dev-seed + encrypted-file store.

## Other native clients

- [ ] **Windows-native client** — `uniffi-bindgen-cs` C# bindings + WinUI 3.
  Lightest lift: CPAL/WASAPI audio and the Windows cert store are reused
  unchanged, so it's mostly UI. Retire or Linux-ify the Tauri client once it
  reaches parity (migration plan Phase 5).

## Code audit findings (2026-11-06)

Read-only audits of `crates/proto/proto-sip` and `crates/uc/*`. **LIVE** = called
by a shipped binary (sbc-daemon, sbc-media*, sbc-api-server, client); **DORMANT**
= library code nothing ships yet. Severities are the auditors'; items marked
"(confirmed)" were re-checked in the code. Fix LIVE items first; fix or POA&M
DORMANT items before anyone wires them in.

### Call path: routing, VPS, auth (uc-routing, uc-vps, uc-policy, uc-auth, uc-aaa)

- [x] **MAJOR, LIVE — blocked route pattern falls through to the dial plan
  (confirmed).** `SbcRouter::route` returns `None` for a blocked match
  (`uc-routing/src/sbc_router.rs:186`), and `sip_stack.rs` (~2842-2884) treats
  that as "no match" and tries the dial plan and default trunk group. A blocked
  `1900` prefix still reaches PSTN. Fix: tri-state `Routed`/`Blocked`/`NoMatch`,
  403 on `Blocked`, no fallback; daemon test. `docs/route-patterns.md:67,97`
  overclaims.
  Fixed 2026-11-06 (PR 172):
  `SbcRouteOutcome`, 403, docs corrected. Residual: a `+1900` block
  does not catch national `1900…` (write blocks without `+`).
- [x] **MAJOR, LIVE — dial-plan `direction` / `source_trunk` / `domain_pattern`
  ignored.** Config sets them but the router only calls `DialPlan::match_number`
  (`router.rs:698`); `match_extended` has no callers. Trunk-to-trunk relay into
  outbound-only entries. Fix: pass direction, source trunk and R-URI host into
  `route_for_tls` and use `match_extended`. Admin guide (~227, 243-264) overclaims.
  Fixed 2026-11-06 (PR 172):
  `Router::route_call`; `default_trunk_group` now outbound-only.
  Residual: REST JSON dial plans still carry no filters.
- [x] **MAJOR, LIVE — emergency classification and routing normalise numbers
  differently.** VPS `emergency.rs` strips `+ - . ( )` and spaces; routing uses
  the raw R-URI user. `9-1-1` / `+911` gets `EmergencyBypass` (skips blocklist,
  rate limit, per-callee cap, STIR screening, deny rules, uses the emergency
  reserve) but routes as an ordinary number. Fix: canonicalise `dest_user` once
  (separators, `%xx`, `;phone-context`, E.164 rule) and feed VPS and routing the
  same string; reject or force-route emergency-classified calls that don't hit
  an emergency pattern.
  Fixed 2026-11-06 (PR 172):
  `uc-types::DialedNumber`, `routing.emergency_trunk_group`, 503 on
  unrouted emergency. Residuals: phone-context dropped (POA&M-100),
  `urn:service:sos` not classified, emergency INVITE flood (POA&M-103).
- [x] **MAJOR, LIVE — VPS prefix rules, caller blocklist and per-callee cap
  compare raw strings** (`uc-vps/src/engine.rs:97`, `blocklist.rs:68`,
  `call_limiter`). `+1900…` / `1-900…` evade a `1900` deny; alternate textual
  forms evade the per-callee cap. Fix: same canonicaliser as above, applied to
  configured prefixes at load.
  Fixed 2026-11-06 (PR 172).
- [x] **MAJOR, LIVE — management-API HMAC signing key has no minimum length**
  (`uc-auth/src/lib.rs` `from_env`). Fix: reject < 32 bytes (prefer 48), zeroize,
  bound `SBC_AUTH_TOKEN_TTL_SECS`; consider `iat`/`nbf`, audience, revocation.
  Fixed 2026-11-07 (fix/mgmt-api-hardening): key at least 32 bytes (warn under
  48), zeroized; TTL 60-86400; HMAC-SHA-384 `v2.` tokens with `aud`/`iat`.
  Residuals: no revocation (POA&M-210), SHA-256 API-key digests (POA&M-211).
- [x] **MINOR, LIVE — unknown `pattern_type` silently becomes a prefix**
  (`runtime.rs:876`, `sip_stack.rs:3600`), so a mistyped block does nothing.
  Reject at config load and in the API (400).
  Fixed 2026-11-06 (PR 172):
  `DialPattern::from_kind`, API 400, sync/seed skip.
- [x] **MINOR, LIVE — STI fetch pool can be starved** when
  `stir_shaken.verification.allow_hosts` is empty (`uc-sti/src/cache.rs:368`).
  Require or loudly warn on empty `allow_hosts`; per-source fetch budget.
  Fixed 2026-11-07 (fix/live-batch-190): POA&M-190, per-source budget
  `stir_shaken.verification.max_fetches_per_source` (default 4, IPv6 per /64,
  `get_or_fetch_from`), startup `warn!` on empty `x5u_allow_hosts` (warn, not
  error). Residual: shared carrier IP, /48 holders, spoofed UDP (POA&M-196);
  `busy_source` not exported as a metric.
- [x] **NIT, LIVE — `SbcRouter::route` scans every pattern per partition per
  call.** Index patterns by partition.
  Fixed 2026-11-07 (fix/live-batch-190): POA&M-192, `by_partition` index,
  test `partition_index_matches_linear_reference`. No bench (perf unmeasured).
- [x] **BLOCKER if wired, DORMANT — Diameter accepts everyone** (POA&M-200)
  (`uc-aaa/src/diameter.rs:223-360`, `send_mar` returns accept). Return an error
  or remove; POA&M so nobody enables the `aaa` feature.
  Fixed: UAR/MAR/SAR and the stub `authenticate`/`account` return
  `DiameterError` in both cfgs (fail closed). Real Cx remains unimplemented.
- [ ] **MAJOR, DORMANT — RADIUS:** Message-Authenticator not required on
  responses (BlastRADIUS, CVE-2024-3596); non-constant-time compare despite the
  comment (`radius.rs:563`); 8-bit identifier wraps; shared secret not zeroized;
  UDP+MD5 not CNSA (RadSec only).
- [x] **BLOCKER if used, DORMANT — policy `StringMatch::Regex` always returns
  true** (POA&M-201) (`uc-policy/src/condition.rs:46`). Implement with compiled `regex` or
  remove the variant.
  Fixed: `BoundedRegex` (compiled once, 1 KiB pattern cap, 1 MiB size limits);
  an invalid pattern cannot be constructed.
- [x] **MINOR, DORMANT — routing `DialPattern::Regex` recompiles per match and
  fails open on a bad pattern** (POA&M-205) (`dialplan.rs:119`). Compile once, reject invalid.
  Fixed: `DialPlanEntry` caches a bounded compiled regex; invalid never matches;
  `DialPattern::validate` and `DialPlan::try_add_entry` reject it.

### SIP message layer (proto-sip)

Phase 1 (byte-based parsing, strict header grammar, Content-Length, limits,
semantic 400s, case-insensitive names, compact forms, comma-list splitter,
fuzzing, RFC 4475 tests) is in PR #167. Remaining:

- [x] **BLOCKER, LIVE — URI parser picks the wrong host.** (POA&M-150) Splits on `;`/`?`
  before finding userinfo, first `@` not last: `sip:victim;x=@evil.com` and
  `sip:+1555;phone-context=…@gw` parse with the wrong host. No %-escaping, no
  RFC 3261 §19.1.4 comparison, bad ports dropped silently, `tel:`/absoluteURI
  fail the whole parse (no 416). Rewrite to the §25 ABNF with a generic `Uri`.
- [x] **MAJOR, LIVE — topology hiding leaks.** (POA&M-151) String-prefix internal match
  (`10.` matches `10.example.com`; no IPv6 ULA/link-local, 127/8, 169.254/16,
  100.64/10); comma-folded Via/Contact/Record-Route only partly rewritten;
  unparseable entries kept or Vias dropped; Contact rewrite drops
  `transport=tls`; Call-ID map unbounded with unkeyed hash
  (`topology.rs`). CIDR matching, per-value handling, fail closed, bounded map.
  Fixed for the B-leg initial INVITE only (the sole hider call site); see
  POA&M-155.
- [x] **MAJOR, LIVE — header manipulation collapses multi-instance headers and
  checks only the first instance** (`manipulation.rs:635-712`,
  `Headers::set`); a harmless first copy hides a spoofed second one. Apply
  per instance, validate output. (POA&M-152)
- [ ] **MINOR — `NameAddr.uri` / `RequestLine.uri` still `SipUri`** (POA&M-153):
  `tel:`/absoluteURI inside To/From/Contact/Route still fail to parse. Migrate
  to `proto_sip::Uri` (needs client-core / client-sip-ua changes).
- [ ] **MINOR — URI comparisons not yet on §19.1.4** (POA&M-154): registrar /
  dialog / ACL matching in sbc-trunk-services and uc-acl compare fields or
  strings; switch to `SipUri::equivalent`.
- [x] **MAJOR, LIVE — topology hiding covers only the B-leg initial INVITE**
  (POA&M-155): responses relayed toward the caller (e.g. 200 OK
  `Contact: <sip:10.x>` / Record-Route of the far side) and in-dialog
  (BYE, re-INVITE, UPDATE) or out-of-dialog non-INVITE requests do not call
  the hider (`sip_stack.rs`, `hide_b2bua_request` only call site).
  Fixed (fix/topology-hiding-full-dialog): one egress chokepoint
  (`SipStack::apply_egress_topology`) hides every request and response
  before transaction tracking, on handler, timer, failover, media-failure,
  2xx-expiry and announcement-BYE paths; per-leg flags (caller is a trunk or
  outside `internal_networks`; callee leg toward a trunk or outside
  `internal_networks`, e.g. a remote registered endpoint). New
  `TopologyHider::hide_b2bua_response` leaves Via untouched (RFC 3261
  §8.2.6.2); in 3xx only internal redirect targets are rewritten; the SBC's
  own Via keeps a bare `rport` (RFC 3581). Fail closed: dropped request +
  500 to the originator, final response or reliable (100rel) 1xx replaced
  by 500, unreliable 1xx dropped, 2xx-to-INVITE or reliable 1xx tears the
  call down, failover INVITE fails the call with 503. Residual leaks:
  POA&M-181; in-dialog INFO/PRACK/MESSAGE/NOTIFY are not relayed:
  POA&M-182.
- [x] **MINOR — no topology-hiding / header-manipulation failure metrics**
  (POA&M-156): planned `sbc_topology_hiding_failures_total` (and the
  manipulation equivalent) were dropped; failures are only in the audit
  trail (SI-4, AU-6).
  Partially fixed (fix/topology-hiding-full-dialog): `RoutingCounters`
  `topology_hiding_failures` / `header_manipulation_failures` are counted;
  export deferred to POA&M-180 (not yet observable by operators).
- [x] **MINOR — topology/manipulation failure counters not exported**
  (POA&M-180): `sbc_topology_hiding_failures_total` and
  `sbc_header_manipulation_failures_total` are counted in
  `RoutingCounters` but need two rows in `api_server.rs`
  `ROUTING_METRICS` and its `load()` list to reach `/metrics` (SI-4,
  AU-6).
  Fixed (pr/live-sbc-gaps): exported via `ROUTING_METRICS`, plus
  `sbc_late_invite_2xx_teardown_total` and `sbc_deferred_send_dropped_total`.
- [x] **MINOR, LIVE — residual topology leaks outside Via/Contact/
  Record-Route** (POA&M-181): `Warning`, `Server`, `User-Agent` and
  `Reason` text and the SDP `o=` username may still name internal hosts or
  products toward a hidden leg (SC-7). Also: relayed 2xx to the caller
  carries no Contact at all (RFC 3261 §12.1.1 target), so there is nothing
  to hide but the dialog has no remote target. Marker: `// POAM-181:` at
  `SipStack::apply_egress_topology`.
  Fixed (pr/live-sbc-gaps): headers scrubbed, Reason reduced to
  `protocol;cause`, `o=` rewritten (multipart too, fail closed `sdp-o`),
  SBC Contact on relayed 101-299. Residual `c=`: POA&M-215.
- [ ] **MINOR, ACCEPTED RESIDUAL — SDP `c=` toward a hidden leg without media
  relay** (POA&M-215): the topology scrub does not rewrite `c=`; when no relay
  is anchored the peer's own media address reaches the hidden leg (SC-7).
  Accepted because media must reach it; no test.
- [ ] **MINOR, LIVE — in-dialog PRACK/INFO/MESSAGE/NOTIFY answered 405, not
  relayed** (POA&M-182): `handle_other_request` answers these locally with
  405 instead of relaying them to the other leg (RFC 3262 PRACK, RFC 6086
  INFO, RFC 3428 MESSAGE, RFC 6665 NOTIFY). Not a topology leak (the local
  405 is hidden), but the topology-hiding tests do not and cannot evidence
  hiding of their relay until it exists.
- [x] **MINOR, LIVE — `topology_hiding.mode = "basic"` silently disables
  hiding** (POA&M-183): `topology_config_from` enables the hider only for
  `signaling_only` / `full`; an accepted `basic` value is not enforced and
  not rejected (CM-6, CM-7, SC-7). Fix in sbc-config validation (reject or
  map it).
  Fixed (pr/live-sbc-gaps): enabled requires `signaling_only` or `full`;
  `basic`, `none` and a missing mode are rejected (config and daemon).
- [x] **MINOR, LIVE — post-announcement BYE always plain UDP from :5060 and
  logged in full** (POA&M-184): the BYE after an announcement is sent on an
  ad-hoc UDP socket bound to `:5060` whatever the caller's transport
  (cleartext toward TLS callers, SC-8) and logged in full at `info`.
  Marker: `// POAM-184:` in `sip_stack.rs`.
  Fixed (pr/live-sbc-gaps): queued and sent on the caller's flow by the
  timer loop, tracked transaction, debug summary log only.
- [x] **NIT, LIVE — late INVITE 2xx on a released call is not ACKed**
  (POA&M-185): a 2xx that crosses the SBC's BYE (or arrives after any call
  release) is dropped without ACK+BYE (RFC 3261 §13.2.2.4). Bounded by the
  UAS's 64*T1 retransmit timeout; needs a short-lived released-call record.
  Fixed (pr/live-sbc-gaps): bounded released-call store (4096, 32 s, 4 tags);
  ACK every match, BYE once per To-tag; audited and counted.
- [ ] **MINOR, DORMANT — proxy-model topology hiding has no Via restore**
  (POA&M-157): `TopologyHider::hide_outbound_request` strips/rewrites Vias
  without storing them, so responses could not reach internal hops
  (RFC 3261 §16.7, §18.2.2). No daemon caller today; needs branch-keyed
  Via restoration before proxy use.
- [x] **MAJOR, DORMANT — RFC 3261 §12.1.1/§12.1.2 route-set order swapped**
  (`routing.rs:309,323`); §16.4 route preprocessing missing; loop detection
  rejects spirals and ignores branch hash; 100 Trying copies only the first Via
  and no Timestamp (`proxy.rs`).
  Fixed at the proto layer (POA&M-231): route-set order, §16.4 preprocessing
  (except `maddr`, POA&M-235), loop hash in the branch with spiral detection
  (topmost Via not hashed, documented deviation), 100 Trying copies all Vias
  and Timestamp. Still library-only (POA&M-236).
- [x] **MAJOR, DORMANT — digest auth:** SHA-256/SHA-512-256 listed but hashed
  with MD5; verifier trusts client `algorithm`/`qop` (downgrade), no
  `uri` == Request-URI check, no nonce/nc enforcement (`auth.rs:815`).
  Fixed at the proto layer (POA&M-230): real SHA-256/SHA-512-256 hashers, hashers
  fail closed on an unimplemented algorithm, RFC 7616 `DigestVerifier`
  (`digest_verifier.rs`), and the proto-registrar verifier now pins
  realm/algorithm/qop, checks opaque and nc. Follow-ups POA&M-233, -234, -236.
- [x] **MAJOR, DORMANT — no RFC 3323 `Privacy` header; PAI-stripping presets
  are no-ops on parsed messages** (`strip_pai_outbound`, `rpid_to_pai`).
  Fixed at the proto layer (POA&M-232): `privacy.rs` (`Privacy` header,
  `apply_privacy`, `sanitize_inbound_identity`, `rpid_to_pai` for `screen=yes`
  only); presets match parsed `HeaderName::PAssertedIdentity`. Library-only
  (POA&M-236).
- [ ] **MINOR, LIVE (sbc-daemon) — digest-uri check skipped on REGISTER**
  (POA&M-233): `handle_register` (`sip_stack.rs` ~5826) builds
  `RegisterRequest` without the Request-URI. Call
  `.with_request_uri(req.uri.to_string())`.
- [ ] **MAJOR, LIVE (sbc-trunk-services, client sessions) — UAC digest still
  uses `Md5DigestHasher`** (POA&M-234): `sbc-trunk-services/src/registrar.rs:411`,
  `client-sip-ua/src/registration.rs:957`, `call_agent.rs:1637`. SHA-256
  challenges now error instead of sending a wrong MD5 answer. Switch to
  `AlgorithmHasher::for_algorithm(challenge.algorithm)`.
- [ ] **MINOR, DORMANT — RFC 3261 §16.4 `maddr` not handled** (POA&M-235):
  `// POAM:` in `routing.rs` `preprocess_route_information`.
- [ ] **MAJOR, DORMANT (sbc-daemon wiring) — wire the POA&M-230..232 helpers**
  (POA&M-236): `DigestVerifier` with uc-audit events for digest rejects,
  route preprocessing with ACL/dial plan after preprocessing, loop-hash
  branches, `apply_privacy` / `sanitize_inbound_identity`; cluster-shared nc
  state for `DigestVerifier`. Also RFC 7616 `userhash`.
- [ ] **MINOR — method case rewritten; Call-ID predictable** (timestamp +
  counter); no server-side `received`/`rport` helper; missing status codes;
  `choose_best_response` doesn't follow §16.7; redirect `sips:`→`sip:` recursion.
- [ ] **Docs:** `PROTO_RFC_COMPLIANCE.md` / `docs/RFC_COMPLIANCE_GAPS.md` claim
  RFC 3261 §16.4/§16.6/§19/§20/§22, RFC 3323 and RFC 3327 as Full/Complete.
  Mostly fixed 2026-11-07 (proto-sip phase 1 and PR 179): the RFC 3261, RFC 3323
  and RFC 3327 rows now read Partial. Still open: the proto-registrar section
  (`PROTO_RFC_COMPLIANCE.md:426`) lists RFC 3327 Path as Full although the
  registrar never populates `path`.

### Media (uc-codecs, uc-media-engine, uc-webrtc, uc-t38, uc-siprec)

- [x] **MAJOR, LIVE (client) — Opus "FEC" is plain PLC and over-sized**
  (`uc-codecs/src/opus_ffi.rs:273`, `client-audio/src/decode_thread.rs:969`):
  each lost 20 ms frame is concealed as 60 ms; in-band FEC advertised but never
  used. Decode the next packet with fec=1 sized to the lost frame.
  *Done 2026-11-06 (media audit):* `FfiOpusDecoder::decode_fec` decodes packet
  N+1 with fec=1 sized to the lost frame; CELT-only/too-short sources go to PLC
  (tests `test_decode_fec_returns_exactly_lost_frame`,
  `test_lost_frame_opus_with_next_packet_uses_fec`). Open: POA&M-141 (LBRR flag
  not checked; `fec_recovered` counts FEC-path decodes, not confirmed LBRR).
- [x] **MINOR, LIVE (SBC) — codec negotiation** (`uc-codecs/src/lib.rs:274`)
  ignores channels and remote fmtp, adopts the remote PT only for 96-127 (not
  35-71/77-95), no `telephone-event` default; duplicate
  `MediaSession::negotiate_codecs` keeps the local PT. Delegate to one impl.
  *Done 2026-11-06 in the library:* channels and fmtp intersection
  (`fmtp.rs`), remote non-reserved PT adopted, telephone-event 8k and 48k
  defaults, `MediaSession` delegates (tests `test_negotiate_adopts_unassigned_pt`,
  `test_negotiate_telephone_event_48k`, `test_negotiate_opus_fmtp_intersection`).
  **Not wired**: sbc-daemon does not call either `negotiate_codecs`
  (POA&M-142). PTs 64-71/77-95 accepted under rtcp-mux (POA&M-143).
- [x] **MINOR, LIVE — G.722 levels unverified** (`g722_adpcm.rs:401,540`):
  14-bit clamp with no rescale may clip or lose 6 dB; run ITU-T G.191 vectors.
  Encode/decode return `Ok(0)` on a short buffer and drop an odd last sample.
  *Done 2026-11-06:* level tests (`test_level_1khz`,
  `test_level_lower_and_upper_band`), short buffer and odd length now error
  (`test_buffer_too_small`, `test_odd_length_rejected`), self-generated
  regression vector. Open: official ITU-T G.191 vectors not run (POA&M-140).
- [x] **NIT, LIVE — media-engine stats hard-coded** (`packets_lost`, `jitter_ms`,
  `rtt_ms` = 0); crate docs claim RTP/RTCP/SRTP/transcoding it doesn't do.
  *Done 2026-11-06:* the hard-coded `packets_lost`/`jitter_ms`/`rtt_ms` fields
  were removed from `stream.rs` stats (the crate never sees RTP); crate docs
  corrected (`uc-media-engine/src/lib.rs`).
- [ ] **BLOCKER, DORMANT — T.38 UDPTL/IFP use a home-made wire format**, not
  ASN.1 PER (`uc-t38/src/udptl.rs`, `ifp.rs`); no real gateway interoperates.
  POA&M-204: documented as non-interoperable in crate docs and ROADMAP; the
  ASN.1 PER encoding is still open.
- [x] **BLOCKER, DORMANT — T.38 decode panics on a 5-byte datagram**
  (POA&M-202/203) (`udptl.rs` ~118-137, unchecked `get_u8`). Bounds checks + fuzz target (cheap).
  Fixed: bounds-checked UDPTL/IFP decode, truncation tests for every prefix,
  `uc-t38/fuzz` targets `udptl_decode` and `ifp_decode`.
- [ ] **MAJOR, DORMANT — T.38 redundancy recovery is dead code, FEC a stub, no
  SDP (RFC 4612/6913 attributes), fixed 512-byte buffer.**
- [ ] **MAJOR, DORMANT — SIPREC metadata doesn't follow the RFC 7865 schema**,
  no RFC 7866 SRC signalling, and display names/AORs are written into the XML
  unescaped (injection into recorder evidence) (`uc-siprec/src/metadata.rs:474-532`).
- [ ] **MAJOR, DORMANT — WebRTC SDP munging:** only the first m-section gets
  `a=mid`; keeps `RTP/AVP` and adds no fingerprint/setup/ICE; data-channel
  removal changes the m-line count and orphans attributes
  (`uc-webrtc/src/sdp_munge.rs`). Rebuild on proto-sdp.
- [ ] **MINOR, DORMANT — trickle ICE:** no ufrag/generation check, unbounded
  candidate lists, `add_candidate` inserts before the target m-line.
- [ ] **NIT — `start_dtls_handshake` in sbc-media-core uses a zeroed placeholder
  cert** (no callers); delete or wire the real identity.
- [ ] **Docs:** ROADMAP marks T.38, SIPREC and trickle ICE as implemented;
  `docs/SDP_RFC_Compliance.md` says uc-webrtc/uc-siprec use proto-sdp; RFC 3551
  "Full" and RFC 7587 "FEC support" overclaim.
  Partial (POA&M-204/206): ROADMAP T.38, SIPREC and trickle ICE marks changed
  to ⚠️ partial; `docs/architecture.md` caveats added; `SDP_RFC_Compliance.md`
  no longer says uc-webrtc/uc-siprec use proto-sdp. RFC 7587 is already
  ⚠️ Partial there (POA&M-141/142) and no RFC 3551 "Full" claim remains in
  `docs/`. Still open: historical CHANGELOG entries (T.38, RFC 6733, RFC 7865).

### Transport, crypto, DNS, ACL (uc-transport, uc-crypto, uc-dns, uc-discovery, uc-dos-protection, uc-acl)

uc-transport TCP/TLS/WS, uc-dos-protection and uc-crypto are LIVE; uc-dns is
LIVE in the client only; uc-transport SCTP, cert hot-reload, uc-discovery and
uc-acl are DORMANT. Every uc-transport TLS config path uses `cnsa_provider`.

- [x] **BLOCKER, LIVE — global rate limiter blacklists innocent sources
  (confirmed).** `rate_limit_allows` (`sbc-daemon/src/server.rs:1591`) checks
  the shared global limiter first; past 2× `global_rps` it calls
  `block(source)` on whoever sent the current packet
  (`uc-dos-protection/src/limiter.rs:383`). One flooding host blocks every
  trunk and phone that sends in that second for 60 s; per-IP limits never get a
  chance. The `blocked` map is uncapped and never swept (`cleanup()` unused),
  so spoofed sources grow it without bound. Fix: per-IP first, never `block`
  from a global limiter, cap and sweep `blocked`.
  fixed: per-IP checked first, global limiter never blocks, `blocked` capped (`max_blocked_sources`) and swept (fix/transport-dos-audit).
- [x] **BLOCKER, LIVE (when `ws_listen` set) — WebSocket upgrade runs inline in
  the accept loop with no timeout** (`uc-transport/src/websocket.rs:412`,
  `server.rs:1687`). One TCP connect that never sends a request stops the WS
  listener for everyone. Split accept/handshake like `TlsListener`, 10 s timeout
  after taking the connection permit.
  fixed: WS handshake spawned off the accept loop under `handshake_timeout_secs`, after admission (fix/transport-dos-audit).
- [x] **MAJOR, LIVE — WebSocket uses tungstenite defaults (64 MiB messages,
  16 MiB frames)** (`websocket.rs:142`); the 64 KiB SIP limit is checked only
  after a full message arrives. Set `WebSocketConfig` limits; require the `sip`
  subprotocol (RFC 7118 §4).
  fixed: messages/frames capped at 65,535 bytes; `sip` subprotocol required, HTTP 400 otherwise (fix/transport-dos-audit).
- [x] **MAJOR, LIVE — one 10,000-connection pool shared by TCP/TLS/WS, no
  per-source cap or accept rate limit; a bare CRLF resets the 300 s idle timer**
  (`server.rs:1348,1786`). One IP can hold every slot, blocking trunk mTLS.
  Per-IP cap, per-listener pools, CRLF doesn't count as activity.
  fixed: per-source cap, per-listener pools plus `max_connections_total`, first-message deadline, wall-clock idle, CRLF counts only after a first accepted message (residual POA&M-94) (fix/transport-dos-audit).
- [x] **MAJOR, LIVE — rate limiter keys IPv6 per /128 and rejects every new
  source when the 65,536-entry table is full** (`limiter.rs`). A /64 gets 2^64
  buckets; a spoofed or rotated flood locks out all untracked legitimate
  sources. Key IPv6 by /64, unmap v4-mapped, overflow bucket instead of reject.
  fixed: IPv6 keyed per `ipv6_prefix_len` (default /64), v4-mapped unmapped, shared overflow bucket past the cap (fix/transport-dos-audit).
- [x] **MAJOR, LIVE — per-user rate limiter keyed on the unauthenticated From
  user, before auth, and rejects past 65,536 keys** (`sip_stack.rs:3256`).
  Targeted lockout via spoofed `From: victim`, or 503 for every new user after a
  spray. Key on authenticated identity (or source /64 + user) after auth.
  Fixed 2026-11-06 (PR 172):
  `user_limiter.rs`, AOR or /32,/64 + user keying, overflow
  allowed untracked. Residuals: POA&M-101 (burst fixed 2.0), POA&M-102 (no From
  user skips limiter), POA&M-103 (emergency bypass, no per-source alarm).
- [x] **MAJOR, LIVE — every rate-limited packet writes an audit record**
  (`server.rs:41,1607,1627`), so a flood fills the audit queue and drops
  security records. Aggregate per (source, limit) and emit on state change.
  fixed: rate-limit audit aggregated per (source, limit) per interval, block/unblock on transition, per-interval cap (fix/transport-dos-audit).
- [x] **MAJOR, LIVE — REST API TLS is not CNSA and cert hot-reload is dead code**
  (`sbc-daemon/src/api_server.rs:1174` uses the default provider;
  `ReloadableTlsAcceptor` never installed, `runtime.rs:564`). No TLS handshake
  timeout or connection cap on the API port either. Install the reloadable CNSA
  acceptor, timeout + semaphore; POA&M row (CNSA doc :106 discloses the gap).
  Fixed 2026-11-07 (fix/mgmt-api-hardening): reloadable `cnsa_provider` TLS 1.3
  acceptor with `security.curve`, 30 s file-poll reload, connection cap,
  handshake/idle/age timeouts, HTTP/1.1 only. Residuals: plain-HTTP listener
  unbounded (POA&M-212), unauthenticated without `SBC_API_TOKEN` (POA&M-213),
  reloads not audited (POA&M-214).
- [x] **MAJOR, LIVE (client) — soft client TLS uses the default aws-lc provider,
  not `cnsa_provider()`** (`client-core/src/sip_transport.rs:722`).
  Fixed: SIP-TLS and provisioning HTTPS use `cnsa_provider()` (debug-only provisioning Insecure mode excepted); verifier builders tracked as POA&M-173 (fix/client-cnsa-tls-dns).
- [x] **MAJOR, LIVE — `Aes256GcmKey` and `P384KeyPair` don't zeroize their
  secrets** (`uc-crypto/src/aead.rs:33`, `ecdsa.rs:23`: `ZeroizeOnDrop` with the
  only secret field `#[zeroize(skip)]`); `open()` leaves an unwiped plaintext
  copy. Remove the skips, add a test; rustdoc overclaims.
  fixed: key array wiped on drop, PKCS#8 held in `Zeroizing`, `open()` returns the in-place buffer and wipes it on failure; opaque aws-lc objects documented as relying on aws-lc cleanse (POA&M-160, -161, -162; fix/crypto-key-zeroize).
- [x] **MINOR, LIVE — `load_private_key` doesn't check key file mode, owner or
  symlinks** (`uc-transport/src/tls.rs` ~336). Reuse uc-sti's `FileSigner` checks.
  fixed: fail closed (boundary device) — `O_NOFOLLOW`, fd-based fstat, regular
  file, `mode & 0o077 == 0`, owner == euid, 64 KiB cap, zeroized read buffer;
  RSA/P-256 keys rejected, `load_private_key_with` gives an exact curve match
  (POA&M-164, fix/crypto-key-zeroize). Residual: symlinked parent dirs and
  copies inside rustls/aws-lc not wiped (POA&M-165). Non-unix builds refuse key loading (fail closed).
- [x] **MINOR, LIVE — `security.curve` isn't passed to TLS key loading**
  (POA&M-166). `sbc-daemon/src/server.rs:1162,1303` call `load_private_key`,
  which accepts P-384 or P-521; switch to
  `load_private_key_with(path, security.curve)` so a P-384 config rejects a
  P-521 key (and vice versa). Also emit a `CryptoKeyOperation` audit event
  (AU-2, AU-12) with outcome on TLS key load and on every cert reload,
  pass or fail (uc-transport has no audit sink).
  Fixed 2026-11-07 (fix/live-batch-190): daemon SIP-TLS listener and trunk
  mTLS keys use `load_private_key_with(security.curve)` and emit
  `CryptoKeyOperation` (outcome, sanitized reason); gRPC `ReloadTls` audited.
  The REST/API acceptor and REST reload path are NOT covered (SEC-003):
  no curve pin, no audit (POA&M-193). SIP TLS not hot-reloadable (POA&M-194).
  Curve pin for the REST acceptor added 2026-11-07 (fix/mgmt-api-hardening);
  REST reload audit still open (POA&M-193, POA&M-214).
- [x] **MINOR, LIVE (client) — uc-dns resolver built without a DNS backend**
  (`uc-dns/src/resolver.rs:163`, `client-sip-ua/src/call_agent.rs:3144`), so
  NAPTR/SRV are never queried; RFC 3263 isn't actually done.
  Fixed: system-conf hickory backend, no-backend fail-safe instead of public resolvers; no DNSSEC (POA&M-172); public `new` kept for uc-discovery (POA&M-174) (fix/client-cnsa-tls-dns).
- [x] **NIT, LIVE — stream framer `parse_content_length`: first CL wins,
  malformed becomes 0, duplicates not rejected** (`server.rs:2303`); can disagree
  with proto-sip on message boundaries.
  fixed: framer uses `SipMessage::stream_message_len`; bad CL gets 400 and close on TCP/TLS (fix/transport-dos-audit).
- [x] **NIT, LIVE (client) — uc-dns cache eviction is an O(n) scan per insert;
  SRV weighting always picks the median** (`cache.rs:139`, `srv.rs:160`).
  Fixed: O(log n) indexed eviction; RFC 2782 weighted random SRV order (fix/client-cnsa-tls-dns).
- [ ] **MAJOR, DORMANT — SCTP `Chunk::decode` panics on a padded last chunk**
  (`uc-transport/src/sctp/chunk.rs:311`, `split_to(padded_length)` past the
  buffer). Clamp and fuzz before enabling the `sctp` feature.
- [ ] **MINOR, DORMANT — `TlsListener::accept` handshakes inline with no
  timeout** (`tls.rs:711`); the daemon doesn't use it. Remove or add a timeout.
- [ ] **MINOR, DORMANT — ENUM `apply_regexp` ignores the pattern and returns the
  DNS-supplied replacement** (`uc-dns/src/enum.rs:153`). Implement RFC 6116 or delete.
- [ ] **MINOR, DORMANT — uc-acl doesn't unmap `::ffff:a.b.c.d`** (v4 deny rules
  miss on dual-stack sockets) and treats `RateLimit` as Allow
  (`uc-acl/src/network.rs`, `filter.rs:20`).
- [ ] **MINOR, DORMANT — uc-discovery gossip accepts Join/Update/Leave
  unauthenticated, unbounded members** (`gossip.rs:224`). Auth + cap before wiring.
- [x] **Docs:** uc-crypto zeroize rustdoc.
  fixed: crate/struct docs state what is wiped, what relies on aws-lc and what is not covered (POA&M-163, fix/crypto-key-zeroize).
- [ ] **Docs:** PROTO_RFC_COMPLIANCE.md:26,508 (client
  SRV via uc-dns) and :43 (RFC 7118 "Wired"); ROADMAP.md:466 (ENUM done); SC-5
  row presents the limiters without caveats; CNSA doc :113 (client) reads as
  compliant. No fuzz targets anywhere in the repo for the stream framer, SCTP,
  NAPTR/SRV or ACL parsing.
  Partly fixed (fix/client-cnsa-tls-dns): PROTO_RFC_COMPLIANCE.md :26/:508 client SRV and the CNSA :113 client TLS text now match the code; the rest remains.

### Data and operations (uc-cdr, uc-storage, uc-audit, uc-syslog, uc-cluster, uc-state-sync, uc-api, uc-phone-mgmt, uc-user-mgmt, uc-metrics, uc-health, uc-telemetry, uc-snmp)

The shipped image builds `sbc-daemon` with `grpc` only, so uc-cluster,
uc-storage and uc-state-sync (behind `cluster`) are DORMANT; uc-api, uc-syslog
and uc-snmp have no callers. uc-cdr was checked and found clean.

- [x] **MAJOR, LIVE — phone-config generators don't escape interpolated values**
  (`uc-phone-mgmt/src/cisco_9800.rs`, `polycom_vvx.rs`, `cisco_mpp.rs`,
  `poly_edge.rs`; only `teo.rs` escapes). A display name like
  `x</displayName><proxy>evil.example</proxy>…` re-points every phone on the
  template. Shared XML/attribute escaping, field validation in sbc-config-store,
  per-vendor injection tests. Fixed 2026-11-06 (phone-cfg-escape): `escape.rs`
  in all generators, store validation on phone/DN upsert (NIST SI-15, SI-10;
  open POA&M-121, POA&M-122, POA&M-123).
- [x] **MAJOR, LIVE — digest HA1 stored in plaintext** in `users.digest_ha1`;
  sbc-api-server uses `PostgresUserStore` and never wraps it in
  `EncryptedUserStore` (`sbc-api-server/src/state.rs:144`). `decrypt_ha1`
  also passes plaintext through, so DB write access can plant a known HA1
  (`uc-user-mgmt/src/encrypt.rs:89`). Wrap with a file/secret key, fail closed,
  drop the pass-through, re-encrypt existing rows. Fixed 2026-11-06 (ha1-users-authz): `EncryptedUserStore`
  with `SBC_USER_HA1_KEY_FILE`, no pass-through, startup re-encrypt (NIST SC-28,
  SC-12; POA&M-111).
- [x] **MAJOR, LIVE — `/users` create/update/delete need only authentication**,
  no permission (an `auditor` token can create accounts) and no audit event
  (`sbc-api-server/src/handlers/mod.rs:114`, `handlers/users.rs`). Add
  `users:admin`/`users:read` and AC-2 audit records; 403 tests. Resolve the
  contradiction between `state.rs:45-47` (daemon uses this table for digest) and
  the IA-2 row (never populated). Fixed 2026-11-06 (ha1-users-authz): `users:read`/`users:admin`,
  `AccountManagement` audit (NIST AC-2, AC-3, AC-6). Contradiction: the IA-2 row
  was correct (the daemon does not read this table); the `state.rs` comment was
  wrong and is fixed.
- [x] **MAJOR, LIVE — uc-audit sink write failures are silent**
  (`uc-audit/src/sink.rs:77`): ENOSPC loses every later record while `audit`
  health stays Healthy and `sbc_audit_records_dropped` stays 0. Make `write`
  fallible, count failures, report Unhealthy (as uc-cdr does). Fixed 2026-11-06
  (uc-audit-integrity): `io::Result` writes, `sbc_audit_write_failures`,
  Unhealthy while failing (NIST AU-5).
- [x] **MAJOR, LIVE — uc-audit hash chain restarts at zero on every process
  start**, has no file verifier, and the file is umask-mode (typically 0644)
  (`uc-audit/src/lib.rs:75`, `sink.rs:57`). Resume from the file tail like
  uc-cdr, 0600/0640 file and 0750 dir, `sbc-cli audit verify`; POA&M for a keyed
  chain (HMAC-SHA-384 or ML-DSA-87). Fixed 2026-11-06 (uc-audit-integrity):
  resume from tail, 0640/0750, symlink and writable-dir refusal,
  `sbc-cli audit verify [--require-anchor]`; keyed chain is POA&M-130, residual
  open race POA&M-131 (NIST AU-9).
- [x] **MAJOR, LIVE — SHA-256 HA1 not listed as a CNSA exception**
  (`uc-user-mgmt/src/digest.rs`). Fixed 2026-11-06 (ha1-users-authz): POA&M-110,
  `CNSA-EXCEPTION` marker, CNSA-2-COMPLIANCE.md.
- [x] **MAJOR, LIVE — HMAC-SHA256 provisioning tokens not listed as a CNSA
  exception** (`sbc-provision-server/src/main.rs:314`; split from the HA1 item
  above). Record as an exception with POA&M, or move the HMAC to SHA-384.
  Fixed 2026-11-07 (fix/mgmt-api-hardening): moved to HMAC-SHA-384 with a hex
  secret of at least 32 bytes and `--mint-token`; no exception needed.
  Expiry/revocation remain POA&M-120.
- [x] **MINOR, LIVE — dropped audit records leave no trace in the chain**
  (sequence assigned in the writer). Emit an `AuditRecordsDropped{count}` record.
  Fixed 2026-11-06 (uc-audit-integrity): markers for queue-full, sink-write
  failure and torn tail (NIST AU-5).
- [x] **MINOR, LIVE — sbc-api-server and central-config-api audit only to
  tracing** (no FileSink option). Add an audit path or document log shipping.
  Fixed 2026-11-06 (uc-audit-integrity): `SBC_API_AUDIT_PATH` /
  `CENTRAL_API_AUDIT_PATH`, fail closed at startup.
- [x] **MINOR, LIVE — raw DB/user-mgmt errors returned to clients**, including on
  unauthenticated `/readyz` (`handlers/users.rs`, `handlers/system.rs:50`).
  Fixed 2026-11-06 (ha1-users-authz): fixed messages (NIST SI-11).
- [x] **MINOR, LIVE — `User` `Debug` prints `digest_ha1`** (`uc-user-mgmt/src/model.rs`).
  Fixed 2026-11-06 (ha1-users-authz): redacting `Debug`.
- [x] **MINOR, LIVE — `list_users` binds LIMIT/OFFSET as text** (Postgres rejects
  it) and `GET /users` is unbounded (`postgres.rs:279`). Fixed 2026-11-06 (ha1-users-authz): i64 binds,
  default 100 / max 1000 (NIST SC-5). The Postgres bind test is `#[ignore]` and
  not run.
- [x] **MINOR, LIVE — provisioning device token is a static HMAC(secret, MAC)**
  in the URL query: never expires, can't be revoked per device, lands in access
  logs (`sbc-provision-server/src/main.rs:309`).
  Log exposure fixed 2026-11-06 (phone-cfg-escape): span drops the query.
  Expiry, revocation and token-in-URL remain as POA&M-120.
- [x] **MINOR, LIVE — `[telemetry.otlp]` accepted but ignored** (feature off),
  and `tls`/`headers` never applied even with it on. Reject or require https.
  Fixed 2026-11-07 (fix/live-batch-190): POA&M-191, rejected at config load
  (requires sbc-config `telemetry` feature, which the daemon enables). No
  exporter exists (POA&M-195).
- [x] **MINOR, LIVE — unenforced config keys accepted** (`monitoring.snmp`,
  `monitoring.syslog`, possibly `metrics_bind`, `per_call_metrics`,
  `scrape_interval_secs`; `sbc-config/src/schema.rs:1173`). Verify and reject.
  Fixed 2026-11-07 (fix/live-batch-190): POA&M-191, every key verified
  unread; whole `[monitoring]` table rejected at load, `deny_unknown_fields`;
  Helm no longer renders it. Residual: Helm `-metrics` Service on 9090 has no
  listener (docs note only); POA&M-195.
- [ ] **NIT, LIVE — audit timestamp taken on caller thread, sequence in writer**
  (order can differ); **metric label map unbounded** (no labelled series yet).
  Timestamp half fixed by #174 (writer assigns both); regression test
  `timestamps_non_decreasing_in_sequence_order` added 2026-11-07
  (fix/live-batch-190). Metric label map half still open.
- [x] **MAJOR, DORMANT — uc-storage ignores `ssl_mode` and Redis `tls`**
  (default `Prefer`), and logs/Debug-prints URLs with embedded passwords
  (`uc-storage/src/config.rs`, `postgres.rs:37`, `redis.rs:33`). Apply TLS,
  reject Prefer/Disable, redact.
  Fixed 2026-11-07 (branch pr/data-plane-dormant-security-271dfc): default `verify-full`; `disable`/`prefer`/`require`
  and `redis://` refused unless `allow_insecure_transport`; Redis `tls`
  applied; passwords redacted in logs, Debug and errors. Open: CNSA-pinned
  suites (POA&M-240), `Serialize` still emits the password (POA&M-247).
  **Caller change needed (sbc-config/sbc-daemon):** document and pass
  `storage.postgres.ssl_root_cert`, `allow_insecure_transport` and Redis
  `tls`; existing non-TLS deployments now fail at startup.
- [ ] **MAJOR, DORMANT — cluster/state-sync have no peer authentication**, no
  transport, replayable heartbeats, no fencing/epoch (split-brain), and
  `SnapshotReader::add_chunk` accepts duplicate/out-of-range chunks
  (`uc-cluster/src/membership.rs:230`, `uc-state-sync/src/snapshot.rs:200`).
  Required before any cluster transport is wired.
  Library half fixed 2026-11-07 (branch pr/data-plane-dormant-security-271dfc): HMAC-SHA-384
  `PeerAuthenticator` with timestamp window and sequence/generation replay
  window; only authenticated heartbeat/replication entry points are public;
  `add_chunk` rejects duplicate, out-of-range, changed-total and oversize
  input. Open: no transport or key rotation, first-contact replay after
  restart (POA&M-241); no fencing/epoch (POA&M-242); rejections not audited.
  **Caller change needed:** sbc-config `cluster.auth { key_file, key_id }`,
  required (fail closed) when `cluster.enabled`; sbc-daemon loads
  `ClusterAuthKey::from_file`, builds `PeerAuthenticator` with a per-boot
  generation, keeps peers in step with membership; any transport uses only
  `handle_authenticated_heartbeat` / `open_message`.
- [ ] **MAJOR, DORMANT — `PkiValidator` validates nothing**
  (`uc-user-mgmt/src/pki.rs`): substring-matches `CN=` in the DER; any self-signed
  cert authenticates. Replace with webpki chain validation or delete; POA&M.
  Fail-closed half done 2026-11-07 (branch pr/data-plane-dormant-security-271dfc): `extract_identity` always
  errors; substring parser removed. Open: full RFC 5280 validator (webpki,
  client-auth EKU, CRL deny-on-unknown, SAN/EDIPI parser) (POA&M-243).
- [ ] **MAJOR, DORMANT — uc-api claims AC-3/CM-6/AU-2** but `with_permission` is
  unenforced metadata and `/config` has no permission. Mark library-only or delete.
  Library half fixed 2026-11-07 (branch pr/data-plane-dormant-security-271dfc): default-deny `Route::authorize` /
  `Router::authorize`; every route has a permission (`/config` read/admin);
  claims now library-only. **Caller change needed:** sbc-daemon must call
  `Router::authorize` (POA&M-244).
- [ ] **MINOR, DORMANT — uc-syslog is UDP/plain TCP only** (claims AU-9);
  **uc-snmp is v2c with default `public` and malformed BER**. Remove or fix
  (v3 authPriv only; uc-cdr `SyslogSink` is the live RFC 5425 path).
  Syslog half fixed 2026-11-07 (branch pr/data-plane-dormant-security-271dfc): RFC 5425 TLS with `cnsa_provider()`
  and octet counting (library-only). Open: §5.2.2 fingerprints, RFC 5424
  header sanitising, buffering (POA&M-245). **Caller change needed:** a
  daemon `tls` syslog config if uc-syslog is ever wired. uc-snmp half open
  (POA&M-246).
- [ ] **MINOR, DORMANT — audit hex deserialiser panics on odd-length/multibyte
  input** (`uc-audit/src/record.rs:128`); **digest verify not constant-time,
  ignores qop/cnonce/nc and realm** (`uc-user-mgmt/src/digest.rs`).
  Hex half fixed 2026-11-06 (uc-audit-integrity): `hex::decode`, error not
  panic (verified 2026-11-07). The digest half stays open.
- [x] **NIT, DORMANT — Redis `KEYS`** (`uc-storage/src/redis.rs:159`); use `SCAN`.
  Fixed 2026-11-07 (branch pr/data-plane-dormant-security-271dfc): `SCAN` COUNT 1000, capped at 100,000 keys.
- [ ] **Docs (`docs/NIST-800-53-CONTROLS.md`):** AU-9 and AU-5 rows overclaim
  uc-audit; SC-13 omits the SHA-256 uses; IA-5 omits the live plaintext HA1 (no
  SC-28 row); SI-11 claims no leakage; AC-2 account management unmentioned.
  AU-5/AU-9 uc-audit rows corrected 2026-11-06 (uc-audit-integrity); the
  other parts stay open.
  Crate-level annotations with no backing code: uc-api, uc-syslog, uc-storage,
  uc-cluster, uc-state-sync, uc-snmp, uc-telemetry — mark library-only.
  uc-api, uc-syslog, uc-storage, uc-cluster, uc-state-sync and uc-user-mgmt PKI
  headers and register rows done 2026-11-07 (branch pr/data-plane-dormant-security-271dfc) (POA&M-240..247).
  uc-snmp and uc-telemetry headers, SC-13/IA-5/SI-11/AC-2 parts stay open.

## RFC compliance — accepted limitations

From the compliance audit; revisit if a deployment requires them.

- [ ] SRTP ROC preservation across DTLS renegotiation (RFC 3711 §3.2.1).
- [ ] Early-media start on 183+SDP (RFC 3960) — currently no audio before answer.
- [ ] ICE candidate trickling (RFC 8838) — full-gathering-before-offer only.

## Housekeeping

- [ ] v0.2.0 workspace version bumps are parked in a `git stash` (release work);
  land them on the release branch when cutting v0.2.0.
