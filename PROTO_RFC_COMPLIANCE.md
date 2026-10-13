# Proto-* Crates RFC/Standards Compliance Report

**Generated:** 2026-02-07
**Last Updated:** 2026-10-11 (wiring reconciliation, issue #118)
**Crates Audited:** 13
**Unique RFCs Referenced:** 45+

> **Status legend.** *Wired (sbc-daemon | sbc-media-core | soft client)* — a shipped binary has a call site for this (the binary is named). *Library-only* — implemented and tested in a `proto-*`/`uc-*` crate, but no shipped binary calls it. *Planned* — not implemented. A row that says only "Full"/"Complete" describes crate-level capability; the wiring column/annotation says what the running SBC actually does.

**Dependency facts behind the wiring labels** (from `Cargo.toml`): `sbc-daemon` depends on proto-sip, proto-transaction, proto-dialog, proto-b2bua, proto-registrar, proto-jwt, proto-rtp, proto-srtp, proto-dtls, proto-stun and `sbc-media-core` — but **not** proto-sdp or proto-stir-shaken. `sbc-media-core` (linked into `sbc-daemon` and `sbc-media`) depends on proto-dtls, proto-rtp, proto-srtp. `client-sip-ua` lists proto-sdp, proto-registrar, proto-stun and proto-turn but has no source references to them. Nothing depends on proto-stir-shaken. The SBC does not run ICE (it anchors media and latches symmetrically). SBC DTLS-SRTP termination is a Go sidecar (`sbc-media-core/src/dtls_sidecar.rs`), not proto-dtls.

---

## 1. proto-sip — SIP Message Layer

**Primary Standard:** RFC 3261 (SIP)
**Claimed Compliance:** 100% message layer

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP: Session Initiation Protocol — message layer | **Full** — message parsing, URI, headers, methods, Via/From/To/CSeq/Max-Forwards, builder, header manipulation, auth (§22). **Wired (sbc-daemon `sip_stack.rs`; soft client `client-sip-ua`)** |
| **RFC 3261** | SIP — proxy forwarding (§16), routing (§16.12.1), redirect (§13.2.2.4), OPTIONS (§11) modules | **Full** — `proxy.rs`, `routing.rs`, `redirect.rs`, `options.rs`. **Library-only** — no shipped binary uses `RequestForwarder`/`RouteSet`/`RedirectHandler`/`OptionsCapabilities`; the daemon answers OPTIONS with its own 200 (`sip_stack.rs`) and the client reads Record-Route manually |
| **RFC 2617** | HTTP Digest Authentication | **Full** — HA1/HA2 computation (§3.2.2), digest response, nonce handling. **Wired (sbc-daemon: registrar challenge via proto-registrar, trunk REGISTER via `sbc-trunk-services`; soft client `registration.rs`)** |
| **RFC 3263** | Locating SIP Servers | Referenced — soft client resolves SRV via `uc-dns`; sbc-daemon/trunk-services use plain `lookup_host` (no SRV/NAPTR) |
| **RFC 3264** | Offer/Answer Model with SDP | Referenced |
| **RFC 3311** | UPDATE Method | Method enum entry. **Wired (sbc-daemon)** — relayed in-dialog via `handle_update` → `handle_in_dialog_request` (`sip_stack.rs`) |
| **RFC 3323** | Privacy Mechanism for SIP | **Implemented** — topology hiding module. **Wired (sbc-daemon)** — `TopologyHider::hide_b2bua_request` on external B-leg (`sip_stack.rs`) |
| **RFC 3325** | P-Asserted-Identity | Header support, topology hiding. **Wired (sbc-daemon)** via topology hider only |
| **RFC 3326** | Reason Header | Header name defined. Library-only |
| **RFC 3327** | Path Header | **Full** — `path_headers()`, `prepend_path()`, validation. **Library-only** — daemon REGISTER handling never reads or inserts Path |
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
| **RFC 7118** | WebSocket Transport for SIP | Transport: WS/WSS. Library-only — `uc-transport` `websocket` feature not enabled by any binary |
| **RFC 8224** | STIR Identity | Header name defined. Library-only |

### Key Files
- `src/lib.rs` — module exports, max message size
- `src/method.rs` — all SIP methods (core + extensions per §7.1)
- `src/header.rs` — header names per §20, compact forms per §7.3.3
- `src/header_params.rs` — Via (§20.42), From/To (§20.20/20.39), CSeq (§20.16), Max-Forwards (§20.22)
- `src/uri.rs` — SIP URI per §19
- `src/transport.rs` — UDP/TCP/TLS/SCTP/WS/WSS/DTLS
- `src/proxy.rs` — §16.6 request forwarding, §16.7 response processing (library-only)
- `src/routing.rs` — loose routing per §16.12.1, Record-Route per §12.1 (library-only)
- `src/redirect.rs` — §13.2.2.4 redirect handling, Contact q-values per §20.10 (library-only)
- `src/options.rs` — §11 OPTIONS capability querying (library-only)
- `src/auth.rs` — digest auth per RFC 2617 / §22
- `src/topology.rs` — topology hiding per RFC 3323/3325
- `src/builder.rs` — request builder with auto-header generation
- `src/manipulation.rs` — header manipulation engine (SBC use; wired in sbc-daemon)

### Gaps
- No `TODO`/`FIXME` related to standards gaps found
- Compact header forms (§7.3.3) supported for core headers (parse-only; the daemon/client framers special-case only `l:`)
- sbc-daemon relays only REGISTER/INVITE/ACK/BYE/CANCEL/OPTIONS/UPDATE; all other methods receive 405

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
| **RFC 3551** | RTP Profile for Audio/Video | **Full** — standard payload type table (PCMU=0, PCMA=8, G722=9, etc.). **Wired (soft client `payload_types`)**; sbc-media-core uses `uc-codecs` `CodecCapability` instead |
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

### Key Files
- `src/lib.rs` — default expiration (3600s per RFC 3261), auth module
- `src/registrar.rs` — registration processing per §10.3, Contact formatting, Date header
- `src/binding.rs` — binding state, instance-id/reg-id per RFC 5626, Path per RFC 3327
- `src/location.rs` — location service, instance-id lookup
- `src/async_location.rs` — async location service with RFC 5626 support (wired: sbc-daemon cluster mode)
- `src/outbound.rs` — RFC 5626 §5.2 flow maintenance, keepalive (CRLF per §3.5.1) (library-only)
- `src/gruu.rs` — RFC 5627 GRUU generation and proxy routing (§5.1) (library-only)
- `src/authentication.rs` — RFC 3261 §22 / RFC 2617 digest auth
- `src/bearer.rs` — RFC 8898 bearer auth (wired: sbc-daemon `server.rs` with proto-jwt)

---

## 13. proto-stir-shaken — Caller ID Verification

**Primary Standard:** RFC 8224/8225/8226

**Wiring note:** **Library-only.** No crate in the workspace depends on proto-stir-shaken (workspace member only); sbc-daemon neither signs nor verifies Identity headers.

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 8224** | Authenticated Identity Management | **Full** — SIP Identity header parsing/generation. **Library-only** |
| **RFC 8225** | PASSporT | **Full** — JWT-like token, compact form, x5u certificate URL. **Library-only** |
| **RFC 8226** | Secure Telephone Identity Credentials | Referenced. Library-only |

### Key Files
- `src/lib.rs` — attestation levels (A/B/C), RFC listing
- `src/passport.rs` — PASSporT per RFC 8225
- `src/identity.rs` — Identity header per RFC 8224, ES384 algorithm

---

## Cross-Cutting Findings

### Strengths
1. **Excellent RFC citation density** — nearly every public function/struct cites the specific RFC section
2. **CNSA 2.0 consistency** — all crypto crates (SRTP, DTLS, STUN) use AES-256-GCM + SHA-384, documented deviations
3. **Zero `TODO`/`FIXME` for standards gaps** — no deferred compliance work found
4. **Comprehensive test coverage** — all crates have `#[cfg(test)]` modules exercising standards-specific behavior

### Wiring Gaps (crate capability not reached by any shipped binary)
- **proto-sdp**, **proto-turn**, **proto-stir-shaken** — entire crates library-only
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

### Complete RFC Index

"Shipped in" names the binary with a call site; "library" means no shipped binary calls it. "soft client" = `client-*` crates (Tauri/FFI client).

| RFC | Title | Crate(s) | Shipped in |
|-----|-------|----------|------------|
| RFC 2365 | Administratively Scoped IP Multicast | proto-sdp | library |
| RFC 2617 | HTTP Digest Authentication | proto-sip, proto-registrar | sbc-daemon, soft client |
| RFC 3261 | SIP | proto-sip, proto-transaction, proto-dialog, proto-registrar, proto-b2bua | sbc-daemon, soft client (message layer, transactions, registrar); dialog layer, proxy/routing/redirect/options: library |
| RFC 3262 | 100rel / PRACK | proto-transaction | library |
| RFC 3263 | Locating SIP Servers | proto-sip | soft client (via uc-dns) |
| RFC 3264 | Offer/Answer Model with SDP | proto-sdp, proto-b2bua | library (daemon relays SDP opaquely) |
| RFC 3311 | UPDATE Method | proto-sip, proto-transaction | sbc-daemon |
| RFC 3323 | Privacy Mechanism for SIP | proto-sip | sbc-daemon |
| RFC 3325 | P-Asserted-Identity | proto-sip | sbc-daemon (topology hider) |
| RFC 3326 | Reason Header | proto-sip | library |
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
| RFC 6665 | SIP Events | proto-sip, proto-dialog | library |
| RFC 6910 | Auto-Configuration | proto-dialog | library |
| RFC 7092 | B2BUA Taxonomy | proto-b2bua | sbc-daemon |
| RFC 7118 | WebSocket Transport for SIP | proto-sip | library |
| RFC 7614 | Location Conveyance | proto-dialog | library |
| RFC 7627 | Extended Master Secret | proto-dtls | soft client |
| RFC 7675 | Consent Freshness | proto-ice | library |
| RFC 7714 | AES-GCM for SRTP | proto-srtp, proto-sdp, proto-dtls | sbc-media-core, soft client |
| RFC 7840 | Multiple Phone Numbers | proto-dialog | library |
| RFC 8068 | Pending Additions | proto-dialog | library |
| RFC 8224 | STIR Identity | proto-sip, proto-stir-shaken | library |
| RFC 8225 | PASSporT | proto-stir-shaken | library |
| RFC 8226 | Secure Telephone Identity Credentials | proto-stir-shaken | library |
| RFC 8445 | ICE | proto-stun, proto-ice | soft client (host candidates); sbc-daemon: library |
| RFC 8489 | STUN (updated) | proto-stun | sbc-daemon, soft client |
| RFC 8656 | TURN (updated) | proto-turn | library |
| RFC 8839 | SDP for ICE | proto-ice | soft client (own parsing) |
| RFC 8866 | SDP | proto-sdp | library |
