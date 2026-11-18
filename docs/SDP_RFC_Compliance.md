# SDP RFC Compliance Tracking

This document tracks RFC compliance for the Session Description Protocol (SDP) implementation in the USG SIP Client.

## Executive Summary

**Current Status**: Partial. The SDP generation items of the 2026-02-07 review are done; since 2026-11-17 the DTLS-SRTP attributes drive a real handshake; the remaining DTLS-SRTP items below are open.
**Last Updated**: 2026-11-17

The client implements SDP for audio-only calls in two modes: plain RTP (`RTP/AVP`, only in `insecure-transports` builds on UDP/TCP accounts) and DTLS-SRTP with ICE (`UDP/TLS/RTP/SAVPF`, TLS accounts). By-design exclusions are SDES and TCP candidates.

**Status (2026-11-17, feat/client-dtls-wiring; corrects the 2026-11-15 note that the DTLS-SRTP mode was signalling only).** The client offers and checks `a=fingerprint`, `a=setup` and `a=rtcp-mux`, and since 2026-11-17 acts on them: a call on a TLS account runs a DTLS 1.2 handshake on its media socket in the role `a=setup` gives it, the peer's certificate must match an `a=fingerprint` of this dialog's SDP, and audio starts as SRTP under the exported keys. A call whose handshake does not complete is ended with no audio; plaintext RTP is never sent on a stream signalled as SAVPF. Evidence is local test runs and the CI runs on PR #208's merged head, on Ubuntu x86_64 (see `docs/NIST-800-53-CONTROLS.md`, "Soft client media security"). Open items: no new handshake when a re-INVITE changes fingerprint, setup or the remote transport address (POA&M-327), delayed-offer INVITEs rejected (POA&M-329), no RFC 8844 binding of the fingerprint (POA&M-333), and the answer still built from a template (RFC 3264 §6, baseline finding RFC-006). See "RFC 8122" and "RFC 5763 / RFC 4145 / RFC 5761" below.

---

## Core SDP Specifications

### RFC 8866 - SDP: Session Description Protocol ✅ COMPLIANT

**Status**: Fully compliant for audio-only SIP
**Priority**: HIGH
**Link**: <https://datatracker.ietf.org/doc/html/rfc8866>

#### Implemented ✅

- **Section 5.1 (Protocol Version)**: `v=0` - Correctly implemented
- **Section 5.2 (Origin)**: `o=- <sess-id> <sess-version> IN {IP4|IP6} <address>` - **FIXED 2026-02-07**
- **Section 5.2 (Origin), SBC topology hiding (POA&M-181)**: toward a hidden leg, sbc-daemon rewrites the relayed `o=` line to `- <sess-id> <sess-version> IN <IP4|IP6> <topology_hiding.external_host>`. sess-id and sess-version are kept byte-exact and the address is the same for every message on the leg, so RFC 3264 §8 version comparison still works (test `th_sdp_origin_stable_across_reinvite`); addrtype follows the host (IPv6 literal gives `IP6`). `application/sdp` parts inside `multipart/*` are rewritten too. A malformed `o=`, missing `c=` or unwalkable multipart fails closed (`sip.topology_hiding.failed:sdp-o`). Tests: `th_sdp_origin_username_and_addr_hidden`, `th_sdp_origin_malformed_fails_closed`, `th_multipart_sdp_origin_scrubbed`, `qa_sdp_origin_media_level_c_and_ttl_and_lf`. `c=` is not rewritten by this step; without a media relay the peer's address passes through (accepted residual POA&M-215).
    - Uses NTP-like timestamp format (high 32 bits: seconds, low 32 bits: fractional)
    - Session version tracked per call and increments on modifications
    - IPv4 and IPv6 support working
- **Section 5.3 (Session Name)**: `s=USG SIP Client` - Implemented
- **Section 5.4 (Session Information)**: Not used (optional)
- **Section 5.7 (Connection Data)**: `c=IN {IP4|IP6} <address>` - **FIXED 2026-02-07**
    - Session-level connection line present
    - Dynamic IPv4/IPv6 detection via `sdp_addr_type()` helper
- **Section 5.8 (Bandwidth)**: `b=AS:<kbps>` - **FIXED 2026-02-07**
    - Plain RTP templates: `b=AS:80` (G.711 64 kbps + IP/UDP/RTP overhead)
    - SRTP templates: `b=AS:100` (Opus variable rate + SRTP + overhead)
- **Section 5.9 (Timing)**: `t=0 0` - Permanent session (correct for SIP)
- **Section 5.13 (Attributes - ptime)**: `a=ptime:20` - **FIXED 2026-02-07**
    - Added to all SDP templates
- **Section 5.13 (Attributes - maxptime)**: `a=maxptime:120` - **FIXED 2026-02-07**
    - Added to all SDP templates (Opus supports up to 120ms frames)
    - Receive limit (fix/client-review-blockers): the soft client decodes only frames up to one ptime (20 ms); longer received frames are dropped and counted in `oversized_frames_dropped` (`client-audio/src/decode_thread.rs`). The offered `a=maxptime:120` is therefore not honoured on receive, and RFC 3551 §4.2 (accept 0-200 ms) is not met (POA&M-317)
- **Section 5.14 (Media Descriptions)**: `m=audio <port> <proto> <fmt-list>` - Implemented
    - Plain RTP: `m=audio <port> RTP/AVP 9 0 8 13 101 121` (`insecure-transports` builds, UDP/TCP accounts)
    - Secure RTP: `m=audio <port> UDP/TLS/RTP/SAVPF 111 9 0 8 13 101 121` (TLS accounts; media flows as SRTP once the DTLS handshake has completed)
    - Received SDP on a TLS account: every active `m=` section must be `UDP/TLS/RTP/SAVP(F)`, otherwise 488 (offer) or BYE (answer); a port-0 section is ignored (`client-sip-ua/src/sdp_dtls.rs` `all_active_media_dtls_srtp`, test `all_active_media_checked`)
    - Explicit `a=sendrecv` (or `a=sendonly`/`a=recvonly` for hold) - **FIXED 2026-02-07**

#### Not Implemented (Optional, Not Needed) ℹ️

- **Section 5.4 (Session Information)**: `i=` - Not needed for SIP
- **Section 5.5 (URI)**: `u=` - Not needed
- **Section 5.6 (Email)**: `e=` - Not needed
- **Section 5.10 (Repeat Times)**: `r=` - Not applicable (permanent session)
- **Section 5.11 (Time Zones)**: `z=` - Not applicable
- **Section 5.12 (Encryption Keys)**: `k=` - Using DTLS instead (correct)

---

### RFC 3264 - Offer/Answer Model with SDP ⚠️ PARTIAL

**Status**: Partial. Open: the answer is built from a template with one audio m-line, so its m-line count does not follow the offer (§6; baseline finding RFC-006, not fixed by fix/client-srtp-b2); a delayed-offer INVITE (no SDP) is rejected with 488 on DTLS-SRTP accounts (§5, NIST POA&M-329).
**Priority**: HIGH
**Link**: <https://datatracker.ietf.org/doc/html/rfc3264>

#### Implemented ✅

- **Section 5 (Generating the Initial Offer)**
    - Offers multiple codecs: PCMU(0), PCMA(8), Opus(111 for ICE), telephone-event(101)
    - Proper m= line construction
    - Connection address included with IPv4/IPv6 support

- **Section 6 (Generating the Answer)**
    - Parser correctly extracts first codec from answer
    - Parser detects telephone-event support
    - Remote media address extraction working
    - **Answer validation** - **FIXED 2026-02-07**
        - Validates codec in answer is in our offer (RFC 3264 Section 6.1)
        - Rejects answer if codec not offered

- **Section 8 (Modifying the Session)**
    - Re-INVITE with updated SDP for hold/resume supported
    - Session version increments correctly - **FIXED 2026-02-07**

- **Section 8.4 (Putting a Stream on Hold)**
    - Hold uses re-INVITE with `a=sendonly`
    - Resume uses re-INVITE with `a=sendrecv`
    - Verified correct implementation

- **Section 8 (SBC rewrite, sbc-daemon via proto-b2bua)** - **FIXED 2026-11-08**
    - `rewrite_connection_and_port` preserves port 0 on declined m-lines; previously it re-enabled them (test `test_port_zero_preserved`)
    - Only one active m-line is anchored; when an image m-line is involved, extra active streams are declined in place (tests `test_selection`, `test_selection_two_images_and_hostile`). Non-T.38 multi-stream SDP still shares one port (POA&M-293)

- **Sections 5.1 / 6 (transport profile), soft client, fix/client-srtp-b2 (2026-11-15)**
    - A remote offer whose profile cannot be secured is refused with 488 and `Warning: 399 usg-client "SRTP/DTLS required"` before any ringing: on a TLS account anything other than `UDP/TLS/RTP/SAVP(F)` on an active stream, a missing or unusable `a=fingerprint` / `a=setup`, or a missing `a=rtcp-mux`; on a non-TLS account an offer asking for `SAVP`/`SAVPF` (tests `inbound_insecure_offer_gets_488`, `qa_inbound_hostile_dtls_attrs_get_488_no_ring`, `udp_account::initial_invite_asking_for_srtp_gets_488` in `client-core/tests/media_security_gate.rs`)
    - A remote answer with the same defects ends the call with BYE (tests `outbound_insecure_answers_end_call`, `qa_outbound_hostile_answers_end_call`)
    - A re-INVITE re-offer with the same defects gets 488 and the session is unchanged (§8; tests `reinvite_insecure_reoffer_gets_488`, `qa_reinvite_downgraded_dtls_attrs_get_488`)
    - The preflight uses the first audio section with a non-zero port (§5.1 / §6; test `selects_first_active_audio_section`). Codec negotiation and remote-address parsing still read the SDP separately and may pick another section when the first audio section is disabled
    - An answer echoes `a=rtcp-mux` only when the offer carried it

#### Notes

- **Section 5.1 (Unicast Streams - Connection Address)**: Uses configured `local_media_addr` without STUN validation. Works correctly in practice with direct and NAT-forwarded setups. STUN-based address discovery could be added in future for complex NAT scenarios.

---

### RFC 4733 - RTP Payload for DTMF (telephone-event) ⚠️ PARTIAL

**Status**: Compliant in the soft client SDP templates (8 kHz). SBC: `uc-codecs` negotiation now registers `telephone-event/8000` and `telephone-event/48000` (PT 110) and answers each on its own PT, so the 8 kHz-only gap is closed in the library: telephone-event is offered at 8 kHz (PT 101) and 48 kHz (PT 110) (tests `test_negotiate_telephone_event`, `test_negotiate_telephone_event_48k`), but sbc-daemon does not call this negotiation (POA&M-142), so it is not in effect on the SBC.
**Priority**: MEDIUM
**Link**: <https://datatracker.ietf.org/doc/html/rfc4733>

#### Implemented ✅

- **Section 2.3.1 (Event Codes)**: Event codes 0-15 for DTMF
- **Section 2.3.3 (Payload Format)**: 4-byte format correctly encoded/decoded
- **Section 2.5 (Procedures - Multiple Packets)**: Same timestamp for all packets in event
- **Section 2.5.1.1 (Duration)**: Duration increments correctly, end bit set on final packets
- **Section 2.5 (receive, soft client)**: received events are bounded per call in `client-audio/src/decode_thread.rs`: at most 8 scheduled events (oldest dropped), a new event more than 32,000 timestamp units from the playout position is rejected (4 s at 8 kHz, 0.67 s with Opus; the playout position follows the audio codec's RTP clock, G.722 at 8000 Hz per RFC 3551 §4.5.2), digit notifications go through a bounded channel. Tests `test_sr48_*`, `test_rfc1_*`. Deviations (NIST POA&M-378): with Opus only `telephone-event/8000` is offered and event timestamps are compared on the 48 kHz audio clock (§2.1, RFC 7160); events longer than 40,000 units are discarded, below the 65,535 a segment may reach (§2.5.1.3). Local runs on macOS arm64 only
- **Section 3 (SDP)**: `a=rtpmap:101 telephone-event/8000` and `a=fmtp:101 0-15`
- **Conditional Sending**: Only sends RFC 4733 if negotiated in SDP

#### Notes

- Also implements in-band DTMF (ITU-T Q.23) for maximum compatibility
- Dual-mode approach ensures DTMF works with all providers

---

## Media Transport RFCs

### RFC 3550 - RTP: A Transport Protocol for Real-Time Applications ✅ COMPLIANT

**Status**: Fully compliant
**Priority**: HIGH
**Link**: <https://datatracker.ietf.org/doc/html/rfc3550>

#### Implemented ✅

- RTP packet format with proper headers
- **SSRC randomness** (Section 5.1) - **FIXED 2026-02-07**
    - Uses multi-source entropy: timestamp + thread ID + stack address (ASLR) + process ID
    - Mixed with splitmix64 for uniform distribution
    - Sequence number initialization also randomized
- Timestamp generation for audio samples
- Payload types: 0 (PCMU), 8 (PCMA), 9 (G722), 111 (Opus), 101 (telephone-event)
- **RTCP** (RFC 3550 Section 6) - **VERIFIED 2026-02-07**
    - Compound RTCP packets: SR/RR + SDES (per RFC 3550 Section 6.1)
    - Sender Reports (SR) with NTP timestamp and RTP timestamp
    - Receiver Reports (RR) with fraction lost, cumulative lost, jitter
    - SDES with CNAME for SSRC binding
    - 5-second transmission interval (within RFC 3550 Section 6.2 guidelines)
    - Handles incoming SR for round-trip time estimation

---

### RFC 5245 - ICE: Interactive Connectivity Establishment ⚠️ PARTIAL

**Status**: ICE implementation exists, SDP attributes compliant
**Priority**: MEDIUM
**Link**: <https://datatracker.ietf.org/doc/html/rfc5245>

#### Implemented ✅

- `a=ice-ufrag:` and `a=ice-pwd:` in SDP offers
- `a=candidate:` lines generated
- ICE credentials parsing from SDP answers
- `a=ice-options:` included

#### Notes

- ICE candidate gathering and connectivity checks are handled by the external `str0m` library
- Full ICE compliance depends on the library implementation
- Plain RTP mode (BulkVS) bypasses ICE entirely

---

### RFC 8122 - Connection-Oriented Media over TLS in SDP ⚠️ PARTIAL

**Status**: Partial. Fingerprints are generated and parsed, and since 2026-11-17 the peer's certificate is verified against them in the DTLS handshake (local test runs and CI on Ubuntu x86_64). Partial because only `sha-384` / `sha-512` are accepted (deviation), a changed fingerprint in a re-INVITE starts no new association (NIST POA&M-327), and RFC 8844 is not implemented (NIST POA&M-333). Corrected 2026-11-15: this section previously said "fully compliant" and showed a `sha-256` fingerprint, which the client neither sends nor accepts.
**Priority**: MEDIUM
**Link**: <https://datatracker.ietf.org/doc/html/rfc8122>

#### Implemented ✅

- **Protocol identifier**: `UDP/TLS/RTP/SAVPF` on TLS accounts
- **Section 5 (Fingerprint Attribute), generated**: `a=fingerprint:sha-384 <hash>`, the SHA-384 fingerprint of the client's DTLS identity certificate (`client-sip-ua/src/dtls_identity.rs`), exactly one hash prefix; an empty or malformed value is never emitted (the offer fails instead). Test `offer_carries_one_full_sha384_fingerprint`
- **Section 5 (Fingerprint Attribute), parsed**: `client-sip-ua/src/sdp_dtls.rs` `parse_dtls_params` with `proto-dtls` `from_sdp_strict`. Media level overrides session level; at most 8 fingerprints per level and 256 bytes per value; strict `XX:XX` grammar and exact digest length. Tests `media_level_overrides_session_level`, `multiple_fingerprints_and_case`, `malformed_and_caps_rejected`, `qa_hostile_fingerprint_and_setup_rejected`, `qa_mixed_lists_precedence_and_order`

#### Deviation (CNSA 2.0)

- Only `sha-384` and `sha-512` fingerprints are accepted. `sha-256` (the RFC 8122 §5 interoperable default), `sha-1`, `sha-224` and `md5` values are ignored; an SDP with no accepted fingerprint is refused (488 for an offer, BYE for an answer). This is deliberate and costs interoperability with peers that offer only `sha-256`. Tests `sha256_only_rejected_mixed_keeps_cnsa`, `qa_inbound_mixed_hash_list_with_cnsa_entry_rings`

#### Not Implemented

- **Verification** (since 2026-11-17): the fingerprints accepted from this dialog's SDP are given to the `proto-dtls` `DtlsAssociation` when the call's handshake starts (`client-sip-ua/src/dtls_driver.rs`); the peer's leaf certificate must match one of them, carry an ECDSA P-384 key, and the peer must prove possession of the key, before SRTP keys are exported. A mismatch ends the call and it is never reported Connected. Certificate chain and validity are not checked: the fingerprint is the trust anchor, and it is as trustworthy as the signalling path that carried it. Tests `fingerprint_mismatch_fails_closed_in_both_roles`, `fingerprint_mismatch_ends_the_call_and_is_never_connected`
- **Fingerprint, setup or remote address change in a re-INVITE** does not start a new DTLS association; the existing association and keys are kept (NIST POA&M-327)

---

### RFC 5763 / RFC 4145 / RFC 5761 - DTLS-SRTP setup role and rtcp-mux ⚠️ PARTIAL

**Status**: Partial (added 2026-11-15, fix/client-srtp-b2; the role drives a handshake since 2026-11-17, feat/client-dtls-wiring)
**Priority**: HIGH
**Link**: <https://datatracker.ietf.org/doc/html/rfc5763>

#### Implemented ✅

- **`a=setup` (RFC 4145 §4, RFC 5763 §5)**: offers carry `actpass`. Answers carry `active` (to `actpass` or `passive`) or `passive` (to `active`). `holdconn`, an unknown value, a value longer than 16 bytes, conflicting duplicate lines, and `actpass` in a remote answer are rejected. An absent `a=setup` is read as `active`. A re-INVITE answer keeps the established role; the 200 to an offerless re-INVITE is an offer and carries `actpass`. Tests `role_table`, `setup_values`, `duplicate_and_long_setup` (`client-sip-ua/src/sdp_dtls.rs`), `inbound_accept_then_ack_fails_closed`, `offerless_reinvite_200_offers_actpass`. Since 2026-11-17 the negotiated role is the DTLS role of the call's handshake (`active` sends the `ClientHello`) and is locked once the handshake has started; as offerer the client accepts a `ClientHello` that arrives before the SDP answer (tests `outbound_call_connects_only_after_the_handshake_in_both_roles`, `inbound_call_connects_only_after_ack_and_handshake_in_both_roles`, `early_client_hello_is_answered_without_retransmission`)
- **`a=rtcp-mux` (RFC 5761 §5.1.1)**: always offered; echoed in an answer only when the offer had it; required from the remote side on DTLS-SRTP calls, because by design there is no separate DTLS association for RTCP; SRTCP on the RTP socket was exchanged with pion and through the SBC in local runs (NIST POA&M-326, closing). Test `rejects_missing_rtcp_mux_and_insecure_second_stream`

#### Not Implemented

- The handshake starts at the 200 OK (outbound) or the ACK (inbound), not when a 183 answer makes the fingerprint known (recorded deviation from RFC 5763 §5; NIST POA&M-331)
- A re-INVITE that changes `a=setup`, `a=fingerprint` or the remote transport address starts no new DTLS association (RFC 5763 §6.6; NIST POA&M-327)
- Delayed offer: an INVITE without SDP is rejected with 488 on DTLS-SRTP accounts (RFC 5763 §6.4; NIST POA&M-329)

---

## Additional Related RFCs

### RFC 4568 - SDP Security Descriptions ❌ NOT IMPLEMENTED for call legs (by design)

**Status**: Not implemented for call legs (using DTLS-SRTP instead). Used only on the SIPREC recording session, see below.
**Priority**: LOW
**Link**: <https://datatracker.ietf.org/doc/html/rfc4568>

**Decision**: Not implementing `a=crypto` (SDES) as we use DTLS-SRTP which is more secure. SDES sends keying material in the signaling path which is a known security concern.

---

**Exception (SIPREC recording session, 2026-11-09)**: the recording session toward the recorder (SRS) offers SDES, because that is what recorders accept. The offer is built by `uc-siprec` `build_rs_offer` and sent only over the recorder TLS 1.3 connection (RFC 4568 §8.3). Call legs are unchanged: `a=crypto` on a call leg is passed through, never generated or consumed by the SBC, and such a call is not recordable.

### RFC 7866 / RFC 4574 - SDP on the SIPREC recording session ⚠️ PARTIAL

**Status**: Wired in `sbc-daemon` (off by default); tested against a fake recorder only
**Link**: <https://datatracker.ietf.org/doc/html/rfc7866>

Recording session offer (`sbc-daemon/src/recording.rs` `build_rs_sdp`, `uc-siprec/src/src_request.rs` `build_rs_offer`):

- Two `m=audio <port> RTP/SAVP` lines, one per call leg, each with `a=label` (RFC 4574; `1` = caller's sent media, `2` = callee's) and `a=sendonly` (RFC 7866 §7.1.1).
- One `a=crypto:1 AEAD_AES_256_GCM inline:...` per m-line (RFC 4568, RFC 7714 §14.1). No other suite is offered.
- `a=rtcp-mux` (RFC 5761). No RTCP is sent (POA&M-301).
- Payload formats, `a=rtpmap`, `a=fmtp` and `a=ptime` are copied from the call's negotiated SDP (bounded: 32 formats, 64 attributes of at most 256 bytes per m-line). Stream 2 uses the payload types of the offer the SBC sent to the callee, restricted to the codecs in the answer.
- `c=` is the `recording.srs_zone` media address, or the SBC's source address toward the recorder.

Recording session answer rules (`uc-siprec/src/rs_answer.rs` `parse_rs_answer`, `recording.rs` `validate_rs_answer`); any violation fails the recording (`srs_bad_answer`):

- Same number of m-lines, each `audio`, non-zero port, `RTP/SAVP`.
- Exactly one `a=crypto` with tag 1 and `AEAD_AES_256_GCM`, no negotiated session parameter.
- Direction `recvonly` (RFC 7866 §7.2); `a=inactive` is refused (POA&M-308).
- Literal `IN IP4` / `IN IP6` unicast connection address, not loopback, unspecified or an SBC socket.
- Exactly the offered payload formats per m-line (stricter than RFC 3264 §6.1).
- Body of at most 16 KiB.

Attributes on call legs:

- `a=recordpref` (RFC 7866 §7.1.3, ABNF §7.3.2): only `off` (and the non-standard alias `never`) is acted on, per `recording.recordpref_never` (default `ignore`). A media-level value on the first active `m=audio` overrides the session-level one (`has_recordpref_never`).
- `a=record` (RFC 7866 §7.1.2): **not sent** to call participants (POA&M-303).
- `a=zrtp-hash`, a keying attribute or SRTP profile on a call whose SRTP the SBC does not terminate (SDES or DTLS passthrough), or no usable audio m-line make the call "not recordable" (`recording.rs` `offer_recordable`, `classify`, `still_recordable`).

Tests: `rs_sdp_carries_ports_family_and_formats`, `offer_is_srtp_with_one_sdes_line_per_stream`, `rs_answer_defects_are_refused`, `rs_answer_must_accept_every_offered_format`, `recordpref_media_level_overrides_session_level`, `zrtp_is_not_recordable`, `offer_recordable_rules_out_what_no_answer_can_fix`, `uc-siprec/tests/hostile_rs_answer.rs`.

---

### RFC 6544 - ICE for TCP Candidates ❌ NOT IMPLEMENTED (by design)

**Status**: Not implemented (UDP only)
**Priority**: LOW
**Link**: <https://datatracker.ietf.org/doc/html/rfc6544>

**Decision**: Not needed for current use case (plain RTP uses UDP, SRTP uses UDP with ICE).

---

### RFC 7587 - RTP Payload Format for Opus ⚠️ PARTIAL

**Status**: SDP parameters present (2026-02-07). In-band FEC: since 2026-11-06 the soft client decodes packet N+1 with fec=1 sized to the lost frame (`uc-codecs/src/opus_ffi.rs` `decode_fec`; tests `test_decode_fec_returns_exactly_lost_frame`, `test_lost_frame_opus_with_next_packet_uses_fec`). The LBRR flag is not checked, so a SILK/Hybrid packet without LBRR is still decoded on the FEC path and counted in `fec_recovered` (POA&M-141). SBC fmtp answering (`fmtp.rs` `intersect_opus`, test `test_negotiate_opus_fmtp_intersection`) is not wired into sbc-daemon (POA&M-142). Known limitation (RFC-008): client-audio `CodecPipeline::from_payload_type` hard-codes static PT to codec and maps 96-127 to Opus; it is reached only from tests today.
**Priority**: MEDIUM
**Link**: <https://datatracker.ietf.org/doc/html/rfc7587>

#### Implemented ✅

- `a=rtpmap:111 opus/48000/2` - Correct format (48000 Hz clock rate, 2 channels per RFC 7587 Section 7)
- `a=fmtp:111 minptime=20;useinbandfec=1;stereo=1` - **FIXED 2026-02-07**
    - `minptime=20`: Minimum packet time (matches `a=ptime:20`)
    - `useinbandfec=1`: Advertises Opus in-band FEC; receiver-side recovery is limited as described above (POA&M-141)
    - `stereo=1`: Enables stereo decoding capability
- `a=maxptime:120` - Maximum packet time for Opus (offered; the receiver drops frames longer than 20 ms, POA&M-317)

---

### RFC 3362 / ITU-T T.38 Annex D - T.38 Fax over SDP ⚠️ PARTIAL

**Status**: Partial (sbc-daemon relay, off by default: `media.t38.enabled = false`)
**Link**: <https://datatracker.ietf.org/doc/html/rfc3362>

- `proto-sdp`: `m=image ... udptl t38` (`media.rs`, test `test_image_udptl`); Annex D attributes in `t38.rs` (`T38Params`; tests `parse_full_annex_d`, `round_trip`, `rejects_bad_values`, `clamp_only_lowers`, `table_round_trip`)
- sbc-daemon: audio/T.38 re-INVITE switchover, attributes clamped to `[media.t38]` caps, UDPTL relayed opaquely (tests `t38_switchover_moves_relay_only_after_2xx_and_back`, `audio_to_t38_and_back_relays_opaque_udptl_from_new_ports`)
- Not implemented: `TCPTL` and UDPTL over DTLS (POA&M-291); answer-vs-offer Annex D negotiation (POA&M-294, open; its CDR `media_kinds` and gRPC relay-update sub-items are done: a remote node gets one atomic `UpdateRelay`, and a node without it makes the switch fail closed); UDPTL/IFP inspection and ASN.1 PER (POA&M-290); `uc-t38` redundancy/FEC (POA&M-292)
- Advisory (not a POA&M): the T.38 path parses each SDP body 3-4 times per message (PERF-003); bounded per-re-INVITE cost, deferred

### RFC 7742 - WebRTC Video Processing and Codec Requirements ℹ️ N/A

**Status**: Not applicable (audio-only client)
**Link**: <https://datatracker.ietf.org/doc/html/rfc7742>

---

## Proto-SDP Library Crate (`crates/proto/proto-sdp`)

### RFC 8866 Parser/Generator ✅ COMPLIANT

**Status**: Fully compliant for all SDP line types
**Updated**: 2026-11-08

**Input validation (POA&M-283)**: each line must be `<type>=<value>` with
`<type>` exactly one ASCII letter (§5), checked on bytes. Lines that do not
match, including lines starting with a multibyte UTF-8 character, are a parse
error rather than a panic. UTF-8 in values is accepted. Typed time values
(§5.10) are digits only with an optional `d`/`h`/`m`/`s` unit, and values that
overflow u64 are rejected. Leading and trailing whitespace on a line is trimmed,
which is more lenient than §5 requires. Number of lines, media sections and
attributes is not capped (POA&M-285). Tests:
`proto-sdp/tests/parser_totality.rs`, including no-panic proptests over
arbitrary input.

The `proto-sdp` crate provides structured SDP parsing and generation used by `client-sip-ua` and integration tests. Since 2026-11-08 the dormant `uc-webrtc` munger (`uc-webrtc/src/sdp_munge.rs`) parses and renders SDP with `proto-sdp` (per-m-section `a=mid`, `UDP/TLS/RTP/SAVPF`, DTLS fingerprint/setup, ICE credentials, BUNDLE; tests in `sdp_munge.rs`). It works around two proto-sdp gaps: no `UDP/DTLS/SCTP`-family transport token, (POA&M-283). Its ASCII `x=` line pre-check predates the proto-sdp parser fix and is kept as defence in depth. `uc-siprec` only wraps `proto_sdp::SdpError` (`uc-siprec/src/error.rs`). Both crates are dormant (POA&M-206).

#### Implemented ✅

- **All required lines**: `v=`, `o=`, `s=`, `t=` - parsed and generated
- **All optional lines**: `i=`, `u=`, `e=`, `p=`, `c=`, `b=`, `z=`, `k=`, `a=`, `m=` - **FIXED 2026-02-07**
    - `b=` (Bandwidth, §5.8): Session-level and media-level bandwidth parsing/generation via `BandwidthInfo` struct
    - `z=` (Time Zones, §5.11): Parsed and round-tripped as raw string
    - `k=` (Encryption Key, §5.12): Parsed at session and media level (deprecated but preserved)
    - `i=` (Media Information, §5.4): Now stored on `MediaDescription` instead of being silently dropped
- **Repeat times** (`r=` §5.10-5.11): Full structured parsing with compact time values (`7d`, `1h`, etc.)
- **Offer/Answer model** (RFC 3264): `generate_answer()`, `validate_answer()`, hold/resume/disable/enable
- **Multicast** (RFC 8866 §5.7): IPv4/IPv6 multicast address parsing, TTL, address count
- **SRTP-SDES** (RFC 4568): `CryptoAttribute` parsing/generation, cipher suite negotiation

#### Security Fixes

- **SRTP keying material PRNG** - **FIXED 2026-02-07**
    - Before: Timestamp-based pseudo-random generation (predictable, unsuitable for crypto)
    - After: `getrandom::fill()` using OS CSPRNG
    - Impact: Keying material now cryptographically random per NIST SP 800-90A

#### Code Quality Fixes (2026-02-07)

- Updated all RFC 4566 references to RFC 8866 (the current standard)
- Removed 16+ duplicate `# Errors` doc comment blocks
- Exported `BandwidthInfo` from crate root

---

## Implementation Files

### Core SDP Files

| File | Purpose |
|------|---------|
| `crates/client/client-core/src/call_manager.rs` | SDP generation (4 templates), SDP parsing, session ID/version tracking |
| `crates/client/client-audio/src/rtp_handler.rs` | RTP/SSRC handling, entropy-based random generation |
| `crates/client/client-audio/src/rtcp_session.rs` | RTCP SR/RR/SDES compound packets |
| `crates/client/client-sip-ua/src/media_session.rs` | ICE/DTLS SDP attributes |
| `crates/client/client-sip-ua/src/sdp_dtls.rs` | `a=fingerprint` / `a=setup` / `a=rtcp-mux` parsing, active-media checks |
| `crates/client/client-core/src/media_security.rs` | Remote-SDP media-security preflight (488 / BYE causes) |
| `crates/client/client-sip-ua/src/call_agent.rs` | SIP INVITE/re-INVITE |

### sbc-daemon CDR SDP reader (bypasses proto-sdp)

| File | Purpose |
|------|---------|
| `crates/sbc/sbc-daemon/src/cdr.rs` (`media_facts`) | Reads the codec and SRTP suite for Call Detail Records. This is a second SDP consumer, separate from proto-sdp and the client parsers |

`media_facts` is called only on the 2xx answer body (`CdrDraft::record_answer`). It reads at most `MAX_SDP_SCAN` (16 KiB), never modifies the SDP and does not affect relaying. It takes the first payload type of the first accepted `m=audio` line. It skips port `0` and `0/n` per RFC 3264 §6 (test `media_facts_skips_rejected_audio_stream`), and names the codec from `a=rtpmap` and the SRTP suite from `a=crypto`, or reports `DTLS-SRTP` for a `UDP/TLS/RTP/SAVP` profile (test `media_facts_reads_codec_and_srtp`). Known limitations, tracked as NIST POA&M-23:

- RFC-5: attributes are not scoped to the chosen m-section, so an `a=crypto` under a rejected `m=audio 0` can still be credited. Encoding names keep the received case (RFC 8866 §5.14).
- RFC-7: only static PTs 0/8/9/18 are named when there is no `a=rtpmap` (RFC 3551 Table 4 defines more).

### Proto-SDP Library Files

| File | Purpose |
|------|---------|
| `crates/proto/proto-sdp/src/session.rs` | SDP session parsing/generation, `BandwidthInfo`, `Timing`, `RepeatTimes` |
| `crates/proto/proto-sdp/src/media.rs` | `MediaDescription` with b=/i=/k= support |
| `crates/proto/proto-sdp/src/attribute.rs` | SDP attribute types and parsing |
| `crates/proto/proto-sdp/src/srtp.rs` | SRTP-SDES crypto attributes, key generation (CSPRNG) |
| `crates/proto/proto-sdp/src/offer_answer.rs` | RFC 3264 offer/answer model |
| `crates/proto/proto-sdp/src/multicast.rs` | Multicast address parsing and negotiation |

---

## Priority Action Items

### HIGH Priority 🔴 - **ALL COMPLETED** ✅

1. ✅ **Session ID Uniqueness** (RFC 8866 Section 5.2) - **COMPLETED 2026-02-07**
    - Fix: Implemented NTP-like timestamp (high 32: seconds, low 32: fractional)
    - Result: Collision risk eliminated

2. ✅ **Session Version Tracking** (RFC 8866 Section 5.2, RFC 3264 Section 8.2) - **COMPLETED 2026-02-07**
    - Fix: Added `sdp_session_ids` and `sdp_session_versions` HashMaps per call
    - Result: Session version persists and increments on re-INVITE

3. ✅ **Answer Validation** (RFC 3264 Section 6.1) - **COMPLETED 2026-02-07**
    - Fix: Added `is_codec_offered()` validation in `handle_sdp_answer()`
    - Result: Rejects answers with codecs not in offer

### MEDIUM Priority 🟡 - **ALL COMPLETED** ✅

1. ✅ **Add ptime Attribute** (RFC 8866 Section 5.13) - **COMPLETED 2026-02-07**
    - Fix: Added `a=ptime:20` to all four SDP templates
    - Result: Packet time explicitly declared

2. ✅ **Explicit Media Direction** (RFC 8866 Section 5.14, RFC 3264) - **COMPLETED 2026-02-07**
    - Fix: Already present - `a=sendrecv` in initial, `a={direction}` in re-INVITE
    - Result: Direction always explicit

3. ✅ **IPv6 Support** (RFC 8866 Section 5.7) - **COMPLETED 2026-02-07**
    - Fix: Added `sdp_addr_type()` helper; all 4 SDP templates use dynamic `IN {IP4|IP6}`
    - Result: Both IPv4 and IPv6 addresses supported in SDP generation

4. ✅ **Opus SDP Parameters** (RFC 7587) - **COMPLETED 2026-02-07**
    - Fix: Added `a=fmtp:111 minptime=20;useinbandfec=1;stereo=1` to SRTP templates
    - Result: Opus fmtp parameters advertised; FEC decode limits tracked in POA&M-141

5. ✅ **maxptime Attribute** (RFC 8866 Section 5.13) - **COMPLETED 2026-02-07**
    - Fix: Added `a=maxptime:120` to all four SDP templates
    - Result: Maximum packet time declared for Opus compatibility
    - Limit: declared only; received frames over one ptime (20 ms) are dropped (POA&M-317)

### LOW Priority 🟢 - **ALL COMPLETED** ✅

1. ✅ **Bandwidth Hints** (RFC 8866 Section 5.8) - **COMPLETED 2026-02-07**
    - Fix: Added `b=AS:80` (plain RTP) and `b=AS:100` (SRTP) to all SDP templates
    - Result: QoS hints available for network elements

2. ✅ **SSRC Randomness** (RFC 3550 Section 5.1) - **COMPLETED 2026-02-07**
    - Fix: Replaced time-based PRNG with multi-source entropy + splitmix64 mixing
    - Result: Cryptographically better SSRC distribution, collision risk minimized

3. ✅ **RTCP Verification** (RFC 3550 Section 6) - **VERIFIED 2026-02-07**
    - Review: Full compound RTCP (SR/RR + SDES) implemented in `rtcp_session.rs`
    - Result: Confirmed compliant with 5-second interval, NTP timestamps, loss statistics

---

## Testing Requirements

### SDP Generation Tests ✅

- [x] Session ID uniqueness across multiple calls (NTP-like timestamp)
- [x] Session version increments on re-INVITE (HashMap tracking)
- [x] IPv6 address handling (`sdp_addr_type()` helper)
- [x] Codec negotiation validation (`is_codec_offered()`)
- [x] telephone-event detection accuracy
- [x] Multiple codec preference handling

### SDP Parsing Tests ✅

- [x] Unknown codec handling (returns `None`)
- [x] Missing required fields (parser handles gracefully)
- [x] IPv6 parsing (`c=IN IP6` supported)

### Interoperability Tests

- [x] BulkVS (plain RTP, no ICE, in-band DTMF)
- [ ] Twilio, Vonage, etc. (untested but expected to work)
- [x] ICE vs non-ICE scenarios (conditional SDP paths)
- [x] All supported codecs (PCMU, PCMA, G.722, Opus)
- [x] DTMF with RFC 4733 and in-band (dual-mode)

---

## Compliance Summary Table

| RFC | Title | Status | Compliance % |
|-----|-------|--------|--------------|
| RFC 8866 | SDP: Session Description Protocol | ✅ Compliant | 100% |
| RFC 3264 | Offer/Answer Model with SDP | ⚠️ Partial (answer from template, RFC-006; delayed offer rejected, POA&M-329) | n/a |
| RFC 4733 | RTP Payload for DTMF | ⚠️ Partial (SBC negotiation not wired, POA&M-142) | n/a |
| RFC 3550 | RTP Transport Protocol | ✅ Compliant | 98% |
| RFC 5245 | ICE | ⚠️ Partial (external lib) | 70% |
| RFC 8122 | DTLS in SDP | ⚠️ Partial (sha-384/512 only; peer certificate verified against the fingerprint since 2026-11-17, local test runs and CI; no new association on a changed fingerprint, POA&M-327; no RFC 8844, POA&M-333) | n/a |
| RFC 5763 / 4145 / 5761 | DTLS-SRTP setup role, rtcp-mux | ⚠️ Partial (role drives the handshake since 2026-11-17; handshake starts at 200 / ACK, POA&M-331; no new association on re-INVITE, POA&M-327; delayed offer rejected, POA&M-329) | n/a |
| RFC 7587 | RTP Payload for Opus | ⚠️ Partial (POA&M-141, POA&M-142) | n/a |
| RFC 4568 | SDP Security Descriptions | ❌ Not implemented for call legs (by design); used on the SIPREC recording session only | n/a |
| RFC 7866 | SIPREC SDP (`a=label`, `a=recordpref`, `a=record`) | ⚠️ Partial (no `a=record`, POA&M-303) | n/a |

**Overall Compliance**: no single figure is given since 2026-11-15. The earlier "~98%" predates the fix/client-srtp-b2 review, which found that the DTLS-SRTP path carried no secured media; see the status correction at the top. Since 2026-11-17 the DTLS-SRTP path carries secured media (local test runs and CI).

---

## Notes and Decisions

### Design Decisions

1. **No SDES (RFC 4568)**: DTLS-SRTP is the only secure-media keying the client signals; an `RTP/SAVP` + `a=crypto` offer is refused with 488. DTLS-SRTP carries the media since 2026-11-17 (feat/client-dtls-wiring)
2. **No TCP Candidates (RFC 6544)**: UDP-only for simplicity
3. **Audio-Only**: Video support not in scope
4. **Permanent Sessions**: `t=0 0` appropriate for SIP (not scheduling-based)

### Known Limitations

1. **Multiple Media Streams**: Only single audio stream supported - not needed for current use case
2. **ICE Candidate Gathering**: Delegated to `str0m` library - compliance depends on library

### Compatibility Notes

- **BulkVS**: Works with plain RTP, no ICE, in-band DTMF (no telephone-event)
- **Modern SIP (TLS accounts)**: ICE/DTLS-SRTP is signalled with Opus, and since 2026-11-17 media flows as SRTP once the DTLS handshake has completed; a peer must support the CNSA DTLS profile (`sha-384` fingerprint, P-384, AES-256-GCM, extended master secret). Tested against pion and this project's SBC only, in local runs
- **DTMF**: Dual-mode (RFC 4733 + in-band) ensures compatibility with all providers

---

## Change Log

| Date | Change | Author |
|------|--------|--------|
| 2026-02-07 | Initial compliance review and tracking document created | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: Session ID now uses NTP-like timestamp format | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: Session version tracking per call with proper increments | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: Answer validation rejects codecs not in offer | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: Added `a=ptime:20` to all SDP templates | Claude Sonnet 4.5 |
| 2026-02-07 | **VERIFIED**: Explicit direction attributes already present | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: IPv6 support in SDP generation (all 4 templates) | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: Opus fmtp parameters (`minptime`, `useinbandfec`, `stereo`) | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: Added `a=maxptime:120` to all SDP templates | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: Bandwidth hints `b=AS:` in all SDP templates | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: SSRC randomness with multi-source entropy + splitmix64 | Claude Sonnet 4.5 |
| 2026-02-07 | **VERIFIED**: RTCP fully implemented (SR/RR/SDES compound packets) | Claude Sonnet 4.5 |
| 2026-02-07 | Updated compliance: Overall (90%→98%), all action items completed | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: proto-sdp: Added b=/z=/k= line parsing and media-level i= support | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: proto-sdp: Replaced weak PRNG with OS CSPRNG for SRTP keying material | Claude Sonnet 4.5 |
| 2026-11-07 | sbc-daemon: `o=` rewritten toward hidden legs (POA&M-181); `c=` residual recorded as POA&M-215 | compliance-scribe |
| 2026-11-09 | SIPREC phase 3: recording session SDP (SDES offer, `a=label`, answer rules, `a=recordpref` handling; no `a=record`) | compliance-scribe |
| 2026-11-15 | fix/client-srtp-b2: status correction (DTLS-SRTP is signalling only, POA&M-324); RFC 8122 lowered to Partial (sha-384/512 only, no verification); RFC 3264 lowered to Partial (RFC-006, POA&M-329); added RFC 5763 / 4145 / 5761 section; m-line examples corrected | compliance-scribe |
| 2026-11-16 | feat/client-dtls-handshake Stage 1: no SDP behaviour change and no status change; RFC 8122 verification note updated (library `DtlsAssociation` exists, client not wired, POA&M-324) | compliance-scribe |
| 2026-11-17 | feat/client-dtls-wiring Stage 2: no change to the SDP the client sends or accepts; the DTLS-SRTP attributes now drive a handshake on the media socket and the peer certificate is verified against `a=fingerprint`; status notes for RFC 8122 and RFC 5763 / 4145 / 5761 updated; open items POA&M-327, -329, -331, -333 | compliance-scribe |
| 2026-11-17 | docs/poam-324-326-ci-evidence: evidence notes updated for the green CI runs on PR #208's head (`4dfea0d`, Ubuntu x86_64); no status change | Claude Opus 5.5 |
| 2026-02-07 | **FIXED**: proto-sdp: Updated RFC 4566 references to RFC 8866 | Claude Sonnet 4.5 |
| 2026-02-07 | **FIXED**: proto-sdp: Removed duplicate doc comments, exported BandwidthInfo | Claude Sonnet 4.5 |

---

## References

- RFC 8866: <https://datatracker.ietf.org/doc/html/rfc8866>
- RFC 3264: <https://datatracker.ietf.org/doc/html/rfc3264>
- RFC 4733: <https://datatracker.ietf.org/doc/html/rfc4733>
- RFC 3550: <https://datatracker.ietf.org/doc/html/rfc3550>
- RFC 5245: <https://datatracker.ietf.org/doc/html/rfc5245>
- RFC 8122: <https://datatracker.ietf.org/doc/html/rfc8122>
- RFC 7587: <https://datatracker.ietf.org/doc/html/rfc7587>

---

*This document should be updated as SDP implementation evolves. Each fix should be marked complete with date and commit reference.*
