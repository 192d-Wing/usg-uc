# Proto-* Crates RFC/Standards Compliance Report

**Generated:** 2026-02-07
**Crates Audited:** 13
**Unique RFCs Referenced:** 45+

---

## 1. proto-sip — SIP Message Layer

**Primary Standard:** RFC 3261 (SIP)
**Claimed Compliance:** 100% message layer

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP: Session Initiation Protocol | **Full** — message parsing, URI, headers, methods, Via/From/To/CSeq/Max-Forwards, proxy forwarding (§16), redirect (§13.2.2.4), OPTIONS (§11), routing (§16.12.1), auth (§22) |
| **RFC 2617** | HTTP Digest Authentication | **Full** — HA1/HA2 computation (§3.2.2), digest response, nonce handling |
| **RFC 3263** | Locating SIP Servers | Referenced |
| **RFC 3264** | Offer/Answer Model with SDP | Referenced |
| **RFC 3311** | UPDATE Method | Method enum entry |
| **RFC 3323** | Privacy Mechanism for SIP | **Implemented** — topology hiding module |
| **RFC 3325** | P-Asserted-Identity | Header support, topology hiding |
| **RFC 3326** | Reason Header | Header name defined |
| **RFC 3327** | Path Header | **Full** — `path_headers()`, `prepend_path()`, validation |
| **RFC 3428** | MESSAGE Method | Method enum entry |
| **RFC 3455** | P-Headers | Header names defined |
| **RFC 3515** | REFER Method | Method enum entry, header support |
| **RFC 3891** | Replaces Header | Header name defined |
| **RFC 3903** | PUBLISH Method | Method enum entry |
| **RFC 4028** | Session Timers | Header names (Session-Expires, Min-SE) |
| **RFC 4168** | SCTP Transport for SIP | Transport enum entry |
| **RFC 4566** | SDP | Referenced |
| **RFC 6086** | INFO Method | Method enum entry |
| **RFC 6665** | SIP Events (SUBSCRIBE/NOTIFY) | Method enum entries, header support |
| **RFC 7118** | WebSocket Transport for SIP | Transport: WS/WSS |
| **RFC 8224** | STIR Identity | Header name defined |

### Key Files
- `src/lib.rs` — module exports, max message size
- `src/method.rs` — all SIP methods (core + extensions per §7.1)
- `src/header.rs` — header names per §20, compact forms per §7.3.3
- `src/header_params.rs` — Via (§20.42), From/To (§20.20/20.39), CSeq (§20.16), Max-Forwards (§20.22)
- `src/uri.rs` — SIP URI per §19
- `src/transport.rs` — UDP/TCP/TLS/SCTP/WS/WSS/DTLS
- `src/proxy.rs` — §16.6 request forwarding, §16.7 response processing
- `src/routing.rs` — loose routing per §16.12.1, Record-Route per §12.1
- `src/redirect.rs` — §13.2.2.4 redirect handling, Contact q-values per §20.10
- `src/options.rs` — §11 OPTIONS capability querying
- `src/auth.rs` — digest auth per RFC 2617 / §22
- `src/topology.rs` — topology hiding per RFC 3323/3325
- `src/builder.rs` — request builder with auto-header generation
- `src/manipulation.rs` — header manipulation engine (SBC use)

### Gaps
- No `TODO`/`FIXME` related to standards gaps found
- Compact header forms (§7.3.3) supported for core headers

---

## 2. proto-sdp — Session Description Protocol

**Primary Standard:** RFC 8866 (SDP, supersedes RFC 4566)

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 8866** | SDP | **Full** — session, media, attributes, connection, bandwidth (§5.8), repeat times (§5.11), multicast (§5.7) |
| **RFC 3264** | Offer/Answer Model | **Full** — answer generation (§6), direction negotiation (§6.1), hold/resume (§8.4.3), stream disable (§8.4), media modification validation (§8.4), multicast (§6.2) |
| **RFC 2365** | Administratively Scoped Multicast | Multicast scope detection |
| **RFC 3551** | RTP/AVP Profile | Transport protocol enum |
| **RFC 3711** | SRTP | Transport protocol: RTP/SAVP |
| **RFC 3890** | TIAS Bandwidth | Bandwidth modifier |
| **RFC 4568** | SDP Security Descriptions (SDES) | **Full** — crypto attribute parsing, cipher suites, key params |
| **RFC 4572** | Fingerprint Attribute for DTLS | Referenced |
| **RFC 4585** | RTP/AVPF | Transport protocol enum |
| **RFC 5245** | ICE Candidates in SDP | Referenced |
| **RFC 6188** | AES-256-CM | Cipher suite enum |
| **RFC 7714** | AES-GCM for SRTP | Cipher suite: AEAD_AES_256_GCM |

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

---

## 3. proto-rtp — RTP/RTCP

**Primary Standard:** RFC 3550 (RTP)

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3550** | RTP | **Full** — packet format (§5), RTCP types, SR/RR (§6.4), SDES, BYE, jitter calc, translator/mixer (§7), SSRC collision detection (§8.2), RTCP scheduling (§6.3, A.7), CSRC validation (max 15 per §5.1), timer reconsideration (§6.3.6) |
| **RFC 3551** | RTP Profile for Audio/Video | **Full** — standard payload type table (PCMU=0, PCMA=8, G722=9, etc.) |
| **RFC 5761** | Multiplexing RTP/RTCP | Referenced |

### Key Files
- `src/lib.rs` — RTP version, payload type constants per RFC 3551
- `src/packet.rs` — RTP header per §5
- `src/rtcp.rs` — RTCP packet types per §6
- `src/translator.rs` — RFC 3550 §7 translator/mixer, CSRC handling, SSRC collision (§8.2)
- `src/scheduler.rs` — RTCP scheduling per §6.3/A.7, timer reconsideration (§6.3.6)
- `src/sequence.rs` — jitter calculator per §6.4.1

### Key Implementations
- `RtpTranslator` — per §7.1, preserves SSRC (or optional mapping)
- `RtpMixer` — per §7.1, own SSRC + CSRC list, SR generation per §7.3
- `RtcpScheduler` — full §6.3/A.7 algorithm with timer reconsideration
- `JitterCalculator` — per §6.4.1
- `SsrcCollisionDetector` — per §8.2

### Gaps
- Mixer/translator reception reports have `jitter`, `last_sr`, `delay_since_last_sr` hardcoded to 0
- Would need per-source JitterCalculator and SR timestamp tracking for full compliance

---

## 4. proto-srtp — Secure RTP

**Primary Standard:** RFC 3711 (SRTP), RFC 7714 (AES-GCM for SRTP)
**Design Goal:** CNSA 2.0 compliance

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3711** | SRTP | **Partial** (intentional) — packet indexing (§3.3.1), ROC, replay protection (§3.4.1), SRTCP E-flag (§4), key derivation labels. **Intentionally omits** AES-128-CM, HMAC-SHA1, SHA-1 KDF |
| **RFC 5764** | DTLS-SRTP | Profile ID 0x0008 |
| **RFC 7714** | AES-GCM for SRTP | **Full** — AES-256-GCM, 96-bit nonce construction, 128-bit tag, AAD |

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
| Cipher suite | AEAD_AES_256_GCM | **Full** |
| Key size | 256 bits | **Full** |
| Salt size | 96 bits | **Full** |
| Nonce | 2 zero + SSRC(4) + index(6) XOR salt | **Full** |
| Tag size | 128 bits | **Full** |
| AAD | RTP header / first 8 bytes RTCP | **Full** |

### Gaps
- No `TODO`/`FIXME` found — deviations are documented and intentional

---

## 5. proto-stun — STUN

**Primary Standard:** RFC 5389 / RFC 8489

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 5389** | STUN | **Full** — message format, magic cookie, credential mechanism (§10.2), error codes, retransmission (§7.2.1), FINGERPRINT (CRC32), MESSAGE-INTEGRITY |
| **RFC 8489** | STUN (updated) | Referenced alongside 5389 |
| **RFC 4013** | SASLprep | Referenced (simplified implementation) |
| **RFC 5245/8445** | ICE | Attribute types (ICE-CONTROLLING, ICE-CONTROLLED, USE-CANDIDATE, PRIORITY) |
| **RFC 5766** | TURN | Allocate method |

### Key Files
- `src/lib.rs` — STUN magic cookie, message types
- `src/message.rs` — message encoding, MESSAGE-INTEGRITY (HMAC), FINGERPRINT (CRC32)
- `src/attribute.rs` — attribute types per RFC 5389/8489, ICE attributes per RFC 5245/8445
- `src/client.rs` — retransmission per §7.2.1 (500ms initial, 1.6s max, 7 retries)
- `src/credential.rs` — long-term credential (§10.2), nonce lifecycle
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

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 5766** | TURN | **Full** — allocations, permissions (5min lifetime), channel bindings (10min lifetime), Send/Data indications (§9/§12), ChannelData format, attribute types |
| **RFC 8656** | TURN (updated) | Referenced, ADDITIONAL-ADDRESS-FAMILY attribute |
| **RFC 6156** | TURN IPv6 | REQUESTED-ADDRESS-FAMILY attribute |

### Key Files
- `src/lib.rs` — module structure
- `src/allocation.rs` — permission lifetime (5min per §8), channel binding lifetime (10min per §11)
- `src/indication.rs` — Send (§9) and Data (§12) indications, max datagram size
- `src/channel.rs` — ChannelData format per §11.4, max 65531 bytes
- `src/attribute.rs` — TURN attributes per RFC 5766/8656
- `src/client.rs` — allocation flow per §6

### Gaps
- No `TODO`/`FIXME` found

---

## 7. proto-ice — ICE NAT Traversal

**Primary Standard:** RFC 8445 (supersedes RFC 5245)

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 8445** | ICE | **Full** — candidate types and priority (§5.1.2), pair priority (§6.1.2.3), checklist initialization (§6.1.2.6), connectivity checks (§6-7), role conflict (§7.3.1.1), aggressive nomination (§7.2.2), consent freshness (§9), keepalives (§10), retransmission (§14.3) |
| **RFC 5245** | ICE (legacy) | Referenced |
| **RFC 7675** | Consent Freshness | **Full** — 5s interval, 30s timeout, consent revocation (§6), MUST cease sending |
| **RFC 8839** | SDP for ICE | Referenced |

### Key Files
- `src/lib.rs` — type preferences per §5.1.2.2
- `src/agent.rs` — ICE agent, candidate gathering (§5), aggressive nomination (§7.2.2)
- `src/candidate.rs` — candidate priority (§5.1.2.1), foundation (§5.1.1.3)
- `src/checklist.rs` — pair priority (§6.1.2.3), pair state initialization (§6.1.2.6)
- `src/connectivity.rs` — connectivity checks (§6-7), STUN request (§7.1.1), role conflict (§7.3.1.1)
- `src/consent.rs` — RFC 7675 consent freshness, RFC 8445 §10 keepalives

### Key Constants
- `INITIAL_RTO`: 500ms per §14.3
- `MAX_RETRANSMISSIONS`: 7 per §14.3
- `CONSENT_FRESHNESS_INTERVAL`: 5s per RFC 7675
- `CONSENT_TIMEOUT`: 30s per RFC 7675
- `KEEPALIVE_INTERVAL`: 15s per §10

### Gaps
- No `TODO`/`FIXME` found

---

## 8. proto-dtls — DTLS 1.2

**Primary Standard:** RFC 6347

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 6347** | DTLS 1.2 | **Full** — record layer (§4.1), handshake (§4.2), certificate validation (§4.2.4), Finished message verification (§4.2.6), replay protection, version 0xFEFD |
| **RFC 5763** | DTLS-SRTP Framework | Referenced |
| **RFC 5764** | DTLS-SRTP Key Export | **Full** — exporter label, key material layout (§4.2), `use_srtp` extension |
| **RFC 5705** | TLS Exporters | Key derivation implementation |
| **RFC 5288** | AES-GCM for TLS | Nonce construction for record encryption |
| **RFC 4572** | Fingerprint Attribute | Certificate fingerprint module |
| **RFC 7627** | Extended Master Secret | Config option |
| **RFC 7714** | AES-GCM Cipher Suite | `AEAD_AES_256_GCM` support |

### Key Files
- `src/lib.rs` — cipher suites, SRTP profile negotiation (RFC 5764)
- `src/record.rs` — record format per §4.1, replay protection, nonce per RFC 5288
- `src/handshake.rs` — full handshake per §4.2, certificate validation (§4.2.4), Finished (§4.2.6)
- `src/srtp_export.rs` — RFC 5764 §4.2 key export, RFC 5705 exporter
- `src/verify.rs` — certificate chain validation (§4.2.4), Finished verification (§4.2.6), ServerKeyExchange
- `src/fingerprint.rs` — RFC 4572 certificate fingerprints
- `src/session.rs` — DTLS session, SRTP key export per RFC 5764
- `src/connection.rs` — connection management
- `src/config.rs` — extended master secret (RFC 7627)

---

## 9. proto-transaction — SIP Transaction Layer

**Primary Standard:** RFC 3261 §17

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP Transactions | **Full** — client INVITE (§17.1.1), client non-INVITE (§17.1.2), server INVITE (§17.2.1), server non-INVITE (§17.2.2), transaction matching (§17.1.3), branch magic cookie, Timer T1/T2/T4, 2xx bypass for server INVITE |
| **RFC 3262** | 100rel / PRACK | **Full** — RSeq/RAck headers, reliable provisional tracking, random initial RSeq (1 to 2^31) |
| **RFC 3311** | UPDATE | Non-INVITE transaction machine reuse |
| **RFC 4028** | Session Timers | UPDATE for session timer refresh |

### Key Files
- `src/lib.rs` — T1 (500ms), T2 (4s), T4 (5s), TransactionKey, branch magic cookie
- `src/client.rs` — client INVITE (§17.1.1), client non-INVITE (§17.1.2), Timer E capping at T2
- `src/server.rs` — server INVITE (§17.2.1), server non-INVITE (§17.2.2), 2xx bypass
- `src/prack.rs` — RFC 3262 100rel, RSeq/RAck, reliable provisional tracking

---

## 10. proto-dialog — SIP Dialog Layer

**Primary Standard:** RFC 3261 §12

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP Dialogs (§12) | **Full** — dialog ID (Call-ID + local/remote tags), state machine |
| **RFC 3515** | REFER | **Full** — transfer status, subscription state |
| **RFC 3680** | Registration Event Package | Event package entry |
| **RFC 3842** | Message Waiting Indication | Event package entry |
| **RFC 3856** | Presence Event Package | Event package entry |
| **RFC 3857** | Watcher Information | Event package entry |
| **RFC 4028** | Session Timers | **Full** — timer tracking, refresh at expires/2 (§5), 422 handling (§8.1.1), Min-SE negotiation |
| **RFC 4235** | Dialog Event Package | Event package entry |
| **RFC 4538** | Media Authorization | Event package entry |
| **RFC 4575** | Conference Event Package | Event package entry |
| **RFC 4730** | KPML | Event package entry |
| **RFC 5070** | Consent Event Package | Event package entry |
| **RFC 5359** | Line Event Package | Event package entry |
| **RFC 5362** | Resource Lists Event Package | Event package entry |
| **RFC 5373** | Call Completion | Event package entry |
| **RFC 5628** | Media Description Changes | Event package entry |
| **RFC 5875** | XCAP Diff Event | Event package entry |
| **RFC 6035** | VoIP Metrics (vq-rtcpxr) | Event package entry |
| **RFC 6446** | Session Recording | Event package entry |
| **RFC 6665** | SIP Events | **Full** — subscription states, termination reasons, IANA event package validation (§7.2) |
| **RFC 6910** | Auto-Configuration | Event package entry |
| **RFC 7614** | Location Conveyance | Event package entry |
| **RFC 7840** | Multiple Phone Numbers | Event package entry |
| **RFC 8068** | Pending Additions | Event package entry |

### Key Files
- `src/lib.rs` — session expires defaults per RFC 4028
- `src/dialog.rs` — dialog state, dialog ID per §12
- `src/session_timer.rs` — RFC 4028 full implementation
- `src/refer.rs` — RFC 3515 REFER transfer handling
- `src/subscription.rs` — RFC 6665 event framework, 30+ IANA event packages
- `src/forking.rs` — RFC 3261 §12.2.2 dialog forking

---

## 11. proto-b2bua — Back-to-Back User Agent

**Primary Standard:** RFC 7092

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 7092** | B2BUA Taxonomy | **Full** — mode definitions (§3), SDP rewriting |
| **RFC 5853** | SBC Requirements | Referenced |
| **RFC 3960** | Early Media (183) | **Full** — early media handling module |
| **RFC 3261** | SIP Core | Referenced |
| **RFC 3264** | Offer/Answer | Hold signaling via direction |
| **RFC 4566** | SDP Format | Referenced for SDP rewrite |

### Key Files
- `src/lib.rs` — B2BUA types per RFC 7092 §3
- `src/mode.rs` — mode-specific behavior per RFC 7092
- `src/sdp_rewrite.rs` — SDP rewriting for media anchoring per RFC 7092
- `src/early_media.rs` — RFC 3960 early media handling

---

## 12. proto-registrar — SIP Registrar

**Primary Standard:** RFC 3261 §10

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 3261** | SIP Registrar (§10) | **Full** — binding management, 200 OK response format (§10.3), authentication (§22), Contact formatting, Date header |
| **RFC 5626** | SIP Outbound | **Full** — instance-id, reg-id, flow maintenance, keepalive (CRLF per §3.5.1), flow state machine, §5.2 flow manager |
| **RFC 5627** | GRUU | **Full** — public/temp GRUU generation, proxy routing (§5.1), multi-flow handling |
| **RFC 3327** | Path Header | **Full** — path storage and routing |
| **RFC 3608** | Service-Route | Header in response |
| **RFC 2617** | Digest Auth | Nonce lifecycle management |

### Key Files
- `src/lib.rs` — default expiration (3600s per RFC 3261), auth module
- `src/registrar.rs` — registration processing per §10.3, Contact formatting, Date header
- `src/binding.rs` — binding state, instance-id/reg-id per RFC 5626, Path per RFC 3327
- `src/location.rs` — location service, instance-id lookup
- `src/async_location.rs` — async location service with RFC 5626 support
- `src/outbound.rs` — RFC 5626 §5.2 flow maintenance, keepalive (CRLF per §3.5.1)
- `src/gruu.rs` — RFC 5627 GRUU generation and proxy routing (§5.1)
- `src/authentication.rs` — RFC 3261 §22 / RFC 2617 digest auth

---

## 13. proto-stir-shaken — Caller ID Verification

**Primary Standard:** RFC 8224/8225/8226

### RFCs Referenced

| RFC | Title | Status |
|-----|-------|--------|
| **RFC 8224** | Authenticated Identity Management | **Full** — SIP Identity header parsing/generation |
| **RFC 8225** | PASSporT | **Full** — JWT-like token, compact form, x5u certificate URL |
| **RFC 8226** | Secure Telephone Identity Credentials | Referenced |

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

| RFC | Title | Crate(s) |
|-----|-------|----------|
| RFC 2365 | Administratively Scoped IP Multicast | proto-sdp |
| RFC 2617 | HTTP Digest Authentication | proto-sip, proto-registrar |
| RFC 3261 | SIP | proto-sip, proto-transaction, proto-dialog, proto-registrar, proto-b2bua |
| RFC 3262 | 100rel / PRACK | proto-transaction |
| RFC 3263 | Locating SIP Servers | proto-sip |
| RFC 3264 | Offer/Answer Model with SDP | proto-sdp, proto-b2bua |
| RFC 3311 | UPDATE Method | proto-sip, proto-transaction |
| RFC 3323 | Privacy Mechanism for SIP | proto-sip |
| RFC 3325 | P-Asserted-Identity | proto-sip |
| RFC 3326 | Reason Header | proto-sip |
| RFC 3327 | Path Header | proto-sip, proto-registrar |
| RFC 3428 | MESSAGE Method | proto-sip |
| RFC 3455 | P-Headers | proto-sip |
| RFC 3515 | REFER Method | proto-sip, proto-dialog |
| RFC 3550 | RTP | proto-rtp |
| RFC 3551 | RTP Profile for Audio/Video | proto-rtp, proto-sdp |
| RFC 3608 | Service-Route | proto-registrar |
| RFC 3680 | Registration Event Package | proto-dialog |
| RFC 3711 | SRTP | proto-srtp, proto-sdp |
| RFC 3842 | Message Waiting Indication | proto-dialog |
| RFC 3856 | Presence Event Package | proto-dialog |
| RFC 3857 | Watcher Information | proto-dialog |
| RFC 3890 | TIAS Bandwidth | proto-sdp |
| RFC 3891 | Replaces Header | proto-sip |
| RFC 3903 | PUBLISH Method | proto-sip |
| RFC 3960 | Early Media | proto-b2bua |
| RFC 4013 | SASLprep | proto-stun |
| RFC 4028 | Session Timers | proto-sip, proto-dialog, proto-transaction |
| RFC 4168 | SCTP Transport for SIP | proto-sip |
| RFC 4235 | Dialog Event Package | proto-dialog |
| RFC 4347 | DTLS over UDP | proto-sip |
| RFC 4538 | Media Authorization | proto-dialog |
| RFC 4566 | SDP | proto-sip, proto-b2bua |
| RFC 4568 | SDP Security Descriptions | proto-sdp |
| RFC 4572 | Fingerprint Attribute | proto-sdp, proto-dtls |
| RFC 4575 | Conference Event Package | proto-dialog |
| RFC 4585 | RTP/AVPF | proto-sdp |
| RFC 4730 | KPML | proto-dialog |
| RFC 5070 | Consent Event Package | proto-dialog |
| RFC 5245 | ICE (legacy) | proto-stun, proto-ice |
| RFC 5288 | AES-GCM for TLS | proto-dtls |
| RFC 5359 | Line Event Package | proto-dialog |
| RFC 5362 | Resource Lists Event Package | proto-dialog |
| RFC 5373 | Call Completion | proto-dialog |
| RFC 5389 | STUN | proto-stun |
| RFC 5626 | SIP Outbound | proto-registrar |
| RFC 5627 | GRUU | proto-registrar |
| RFC 5628 | Media Description Changes | proto-dialog |
| RFC 5705 | TLS Exporters | proto-dtls |
| RFC 5761 | Multiplexing RTP/RTCP | proto-rtp |
| RFC 5763 | DTLS-SRTP Framework | proto-dtls |
| RFC 5764 | DTLS-SRTP Key Export | proto-srtp, proto-dtls |
| RFC 5766 | TURN | proto-turn, proto-stun |
| RFC 5853 | SBC Requirements | proto-b2bua |
| RFC 5875 | XCAP Diff Event | proto-dialog |
| RFC 6035 | VoIP Metrics | proto-dialog |
| RFC 6086 | INFO Method | proto-sip |
| RFC 6156 | TURN IPv6 | proto-turn |
| RFC 6188 | AES-256-CM | proto-sdp |
| RFC 6347 | DTLS 1.2 | proto-dtls |
| RFC 6446 | Session Recording | proto-dialog |
| RFC 6665 | SIP Events | proto-sip, proto-dialog |
| RFC 6910 | Auto-Configuration | proto-dialog |
| RFC 7092 | B2BUA Taxonomy | proto-b2bua |
| RFC 7118 | WebSocket Transport for SIP | proto-sip |
| RFC 7614 | Location Conveyance | proto-dialog |
| RFC 7627 | Extended Master Secret | proto-dtls |
| RFC 7675 | Consent Freshness | proto-ice |
| RFC 7714 | AES-GCM for SRTP | proto-srtp, proto-sdp, proto-dtls |
| RFC 7840 | Multiple Phone Numbers | proto-dialog |
| RFC 8068 | Pending Additions | proto-dialog |
| RFC 8224 | STIR Identity | proto-sip, proto-stir-shaken |
| RFC 8225 | PASSporT | proto-stir-shaken |
| RFC 8226 | Secure Telephone Identity Credentials | proto-stir-shaken |
| RFC 8445 | ICE | proto-stun, proto-ice |
| RFC 8489 | STUN (updated) | proto-stun |
| RFC 8656 | TURN (updated) | proto-turn |
| RFC 8839 | SDP for ICE | proto-ice |
| RFC 8866 | SDP | proto-sdp |
