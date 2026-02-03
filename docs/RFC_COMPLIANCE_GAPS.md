# RFC Compliance Gaps - USG Unified Communications

This document maps each proto-* crate to its relevant RFCs and identifies specific section gaps.

## Status Legend

- **Complete**: Full implementation per RFC
- **Partial**: Core functionality implemented, edge cases missing
- **Missing**: Not implemented

---

## proto-sip (RFC 3261 - SIP Core)

### RFC 3261 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §7.1 | Requests | Complete | All methods defined in `method.rs` |
| §7.2 | Responses | Complete | All status codes in `response.rs` |
| §8.1 | UAC Behavior | Partial | Message construction only |
| §8.2 | UAS Behavior | Partial | Message parsing only |
| §10 | Registrations | Partial | Delegated to proto-registrar |
| §11 | Querying Capabilities | Missing | OPTIONS processing logic |
| §12 | Dialogs | Partial | Delegated to proto-dialog |
| §13 | Initiating a Session | Partial | INVITE construction only |
| §13.2.2.4 | 3xx Redirect Responses | **Missing** | No redirect handling |
| §14 | Modifying an Existing Session | Partial | re-INVITE parsing only |
| §15 | Terminating a Session | Partial | BYE construction only |
| §16.4 | Route Information Preprocessing | Complete | `routing.rs` |
| §16.6 | Request Forwarding | Complete | `proxy.rs` |
| §16.12.1 | Loose Routing | Complete | `routing.rs` |
| §17 | Transactions | Partial | Delegated to proto-transaction |
| §18 | Transport | Partial | Enum defined, no socket impl |
| §19 | SIP URI | Complete | `uri.rs` |
| §20 | Header Fields | Complete | All 44 headers in `header.rs` |
| §22 | Authentication | Complete | `auth.rs` (RFC 2617) |

### Critical Gap: §13.2.2.4 - Redirect Responses

**RFC Text**: "If the response is a 3xx, the UAC SHOULD use the Contact header field URIs to retry the request."

**Implementation Needed**:
```rust
// proto-sip/src/redirect.rs
pub struct RedirectHandler {
    max_redirects: u8,
    current_count: u8,
}

impl RedirectHandler {
    pub fn process_3xx(&mut self, response: &SipResponse) -> RedirectAction {
        // Extract Contact headers
        // Validate redirect count
        // Return RedirectAction::Retry(uri) or RedirectAction::TooManyRedirects
    }
}
```

---

## proto-transaction (RFC 3261 §17 + RFC 3262)

### RFC 3261 §17 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §17.1.1 | INVITE Client Transaction | Complete | `client.rs` FSM |
| §17.1.2 | Non-INVITE Client Transaction | Complete | `client.rs` FSM |
| §17.1.3 | Matching Responses | Complete | TransactionKey |
| §17.1.4 | Handling Transport Errors | Partial | Basic error propagation |
| §17.2.1 | INVITE Server Transaction | Complete | `server.rs` FSM |
| §17.2.2 | Non-INVITE Server Transaction | Complete | `server.rs` FSM |
| §17.2.3 | Matching Requests | Complete | TransactionKey |
| §17.2.4 | Handling Transport Errors | Partial | Basic error propagation |

### RFC 3262 Section Mapping (100rel)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §3 | UAS Behavior | Complete | `prack.rs` ReliableProvisionalTracker |
| §4 | UAC Behavior | Complete | `prack.rs` ClientReliableProvisionalTracker |
| §5 | RSeq Header | Complete | RSeq generation |
| §6 | RAck Header | Complete | RAck validation |
| §7 | PRACK Processing | Complete | State machine |

**No gaps identified in proto-transaction.**

---

## proto-dialog (RFC 3261 §12 + RFC 3515 + RFC 4028 + RFC 6665)

### RFC 3261 §12 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §12.1.1 | UAS Behavior | Complete | Dialog creation from request |
| §12.1.2 | UAC Behavior | Complete | Dialog creation from response |
| §12.2.1 | UAC Behavior (In-Dialog) | Complete | Request construction |
| §12.2.2 | UAS Behavior (In-Dialog) | Complete | Response handling |
| §12.3 | Termination | Complete | BYE processing |

### RFC 3515 Section Mapping (REFER)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §2.1 | REFER Method | Complete | Method defined |
| §2.2 | Refer-To Header | Complete | Header parsing |
| §2.3 | Referred-By Header | Complete | Header parsing |
| §2.4 | Implicit Subscription | Complete | `refer.rs` |
| §3 | NOTIFY Bodies | Partial | sipfrag parsing basic |

### RFC 4028 Section Mapping (Session Timers)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §4 | Session-Expires Header | Complete | Parsing/generation |
| §5 | Min-SE Header | Complete | Parsing/generation |
| §7.1 | UAS Behavior | Complete | Refresher negotiation |
| §7.2 | UAC Behavior | Complete | Session refresh |
| §9 | 422 Response | Complete | `handle_422_response()` |

### RFC 6665 Section Mapping (Event Framework)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §4.1 | SUBSCRIBE Processing | Complete | `subscription.rs` |
| §4.2 | NOTIFY Processing | Complete | Notifier implementation |
| §4.3 | Subscription State | Complete | State machine |
| §4.4 | Forking | Partial | Basic forking support |
| §7.2 | Event Package Registration | **Missing** | No IANA validation |

### Gap: RFC 6665 §7.2 - Event Package Validation

**RFC Text**: "Event packages MUST be registered with IANA."

**Implementation Needed**: Validate event packages against known IANA registrations.

---

## proto-registrar (RFC 3261 §10 + RFC 5626 + RFC 5627)

### RFC 3261 §10 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §10.2 | Constructing the REGISTER | Complete | Request building |
| §10.2.1 | Adding Bindings | Complete | Binding management |
| §10.2.2 | Removing Bindings | Complete | Expires=0 handling |
| §10.2.3 | Fetching Bindings | Complete | Query support |
| §10.3 | Processing REGISTER | Complete | Full registrar logic |

### RFC 5626 Section Mapping (Outbound)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §4.2 | Instance-ID | Complete | Binding tracking |
| §4.3 | Reg-ID | Complete | Registration ID |
| §4.4 | Flow Token | Partial | Generation only |
| §5.1 | Outbound Proxy Discovery | **Missing** | No discovery |
| §5.2 | Registrar Flow Maintenance | **Missing** | No keepalive |
| §5.3 | Edge Proxy Routing | **Missing** | No flow routing |

### RFC 5627 Section Mapping (GRUU)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §3.1 | Public GRUU | Complete | `gruu.rs` generation |
| §3.2 | Temporary GRUU | Complete | `gruu.rs` generation |
| §4.1 | Requesting a GRUU | Complete | sip.instance handling |
| §4.2 | GRUU in Contact | **Missing** | Not added to responses |
| §5.1 | Proxy GRUU Routing | **Missing** | No routing logic |

### Critical Gap: RFC 5626 §5.2 - Flow Maintenance

**RFC Text**: "The edge proxy MUST send periodic keepalives on the flow."

**Implementation Needed**:
```rust
// proto-registrar/src/outbound.rs
pub struct OutboundFlowManager {
    flows: HashMap<FlowToken, FlowState>,
    keepalive_interval: Duration,
}

impl OutboundFlowManager {
    pub fn maintain_flow(&mut self, token: &FlowToken) -> FlowAction {
        // Send STUN keepalive or CRLF ping
    }
}
```

---

## proto-ice (RFC 8445 + RFC 7675)

### RFC 8445 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §5.1 | Candidate Types | Complete | `candidate.rs` |
| §5.1.2 | Priority Calculation | Complete | Formula implemented |
| §6.1 | Connectivity Checks | Complete | `connectivity.rs` |
| §6.1.2 | Check Procedures | Complete | STUN checks |
| §6.1.4 | Triggered Checks | Complete | Queue implemented |
| §7.2 | Nominating | Partial | USE-CANDIDATE only |
| §7.2.1 | Regular Nomination | Complete | Basic nomination |
| §7.2.2 | Aggressive Nomination | **Missing** | Not implemented |
| §8.1 | Updating States | Complete | State machine |
| §9 | Consent | Partial | ConsentTracker exists |
| §10 | Keepalives | Complete | KeepaliveTracker |
| §11 | ICE Restart | Partial | Basic restart |

### RFC 7675 Section Mapping (Consent Freshness)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §3 | Consent Mechanism | Complete | STUN Binding |
| §4 | Consent Procedures | Partial | Tracking only |
| §4.1 | Consent Check Interval | Complete | 5 seconds |
| §4.2 | Consent Timeout | Complete | 30 seconds |
| §5.1 | Sending Consent | Complete | `create_consent_check()` |
| §5.2 | Receiving Consent | Partial | Response handling |
| §6 | Consent Revocation | **Missing** | No revocation action |

### Critical Gap: RFC 7675 §6 - Consent Revocation

**RFC Text**: "When consent expires, the agent MUST cease transmission immediately."

**Implementation Needed**:
```rust
// Update consent.rs
impl ConsentTracker {
    pub fn check_consent(&self) -> ConsentResult {
        match self.state {
            ConsentState::Expired => ConsentResult::MustStop,
            ConsentState::Fresh => ConsentResult::Continue,
            _ => ConsentResult::Pending,
        }
    }
}
```

### Gap: RFC 8445 §7.2.2 - Aggressive Nomination

**RFC Text**: "With aggressive nomination, the controlling agent includes the USE-CANDIDATE attribute in every check."

---

## proto-dtls (RFC 6347 + RFC 5764)

### RFC 6347 Section Mapping (DTLS 1.2)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §3 | DTLS Overview | Complete | Architecture |
| §4.1 | Record Layer | Complete | `record.rs` |
| §4.1.1 | Anti-Replay | Complete | Sliding window |
| §4.2 | Handshake Protocol | Partial | `handshake.rs` |
| §4.2.1 | HelloVerifyRequest | Complete | Cookie DoS protection |
| §4.2.4 | CertificateVerify | **Missing** | No signature verification |
| §4.2.6 | Finished Validation | **Missing** | TODO in code |
| §4.3 | Timeout/Retransmission | Partial | Basic retransmission |

### RFC 5764 Section Mapping (DTLS-SRTP)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §4.1 | use_srtp Extension | Complete | `srtp_export.rs` |
| §4.1.2 | Profile Negotiation | Complete | AES-256-GCM only |
| §4.2 | Key Export | Complete | HKDF-SHA384 |
| §5 | Security Considerations | Partial | CNSA 2.0 only |

### Critical Gap: RFC 6347 §4.2.4 - Certificate Verification

**RFC Text**: "The server MUST validate the client's certificate if requested."

**Code TODO Location**: `handshake.rs:330`

```rust
// TODO: Implement
fn verify_certificate_chain(certs: &[Certificate]) -> DtlsResult<()> {
    // 1. Verify certificate signatures
    // 2. Check certificate validity period
    // 3. Validate trust chain to root CA
    // 4. Check revocation status (CRL/OCSP)
}
```

### Critical Gap: RFC 6347 §4.2.6 - Finished Validation

**RFC Text**: "Each party MUST verify the Finished message."

**Code TODO Locations**: `handshake.rs:383`, `handshake.rs:471`

```rust
// TODO: Implement
fn verify_finished(
    received: &[u8],
    handshake_hash: &[u8],
    master_secret: &[u8],
    is_client: bool,
) -> DtlsResult<()> {
    let expected = prf_sha384(
        master_secret,
        if is_client { b"client finished" } else { b"server finished" },
        handshake_hash,
        12,
    )?;
    if received != expected {
        return Err(DtlsError::HandshakeFailed { reason: "Finished mismatch" });
    }
    Ok(())
}
```

---

## proto-stun (RFC 5389)

### RFC 5389 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §6 | STUN Message Structure | Complete | `message.rs` |
| §7.1 | Forming a Request | Complete | StunMessage builder |
| §7.2 | Sending a Request | Complete | StunClient |
| §7.3 | Receiving a Response | Complete | Response parsing |
| §10.1 | Short-Term Credential | Partial | USERNAME/INTEGRITY |
| §10.2 | Long-Term Credential | **Missing** | No implementation |
| §14 | FINGERPRINT Mechanism | Complete | CRC-32 |
| §15 | Attribute Definitions | Partial | Core attributes only |

### Gap: RFC 5389 §10.2 - Long-Term Credential

**RFC Text**: "The long-term credential mechanism is used for persistent authentication."

**Implementation Needed**:
```rust
pub struct LongTermCredential {
    username: String,
    realm: String,
    password: String,
}

impl LongTermCredential {
    pub fn compute_key(&self) -> [u8; 16] {
        // MD5(username:realm:password)
    }
}
```

---

## proto-turn (RFC 5766)

### RFC 5766 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §2 | Overview | Complete | Core concepts |
| §5 | Allocations | Complete | `allocation.rs` |
| §6 | Creating Allocation | Partial | Basic allocation |
| §7 | Refreshing Allocation | Partial | Refresh request |
| §8 | Permissions | Partial | Permission struct |
| §9 | Send Mechanism | **Missing** | No Send indication |
| §10 | Channels | Partial | `channel.rs` |
| §11 | ChannelData | Complete | Framing |
| §12 | Data Indication | **Missing** | No Data indication |

### Critical Gap: RFC 5766 §9 - Send Mechanism

**RFC Text**: "Send indication is used to send data through the allocation."

**Implementation Needed**:
```rust
// proto-turn/src/send.rs
pub struct SendIndication {
    xor_peer_address: SocketAddr,
    data: Vec<u8>,
}

impl TurnClient {
    pub fn send_data(&mut self, peer: SocketAddr, data: &[u8]) -> TurnResult<()> {
        // Build Send indication
        // Include XOR-PEER-ADDRESS and DATA attributes
    }
}
```

---

## proto-srtp (RFC 3711 + RFC 7714)

### RFC 3711 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §3.1 | SRTP Context | Complete | `context.rs` |
| §3.2 | Transform-Independent | Complete | Key derivation |
| §3.3 | Transform-Dependent | Partial | AES-GCM only |
| §4.1 | Packet Processing | Complete | `protect.rs` |
| §4.2 | Replay Protection | Complete | 64-bit window |
| §6 | Default Transforms | Partial | No AES-CM, HMAC-SHA1 |
| §8 | Key Management | Partial | DTLS-SRTP only |
| §9.1 | Key Derivation | Complete | HKDF-SHA384 |
| §9.2 | SRTCP Index | Complete | Index management |

### RFC 7714 Section Mapping (AES-GCM)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §3 | AES-GCM Cipher | Complete | 256-bit only |
| §4 | Nonce Formation | Complete | 12-byte nonce |
| §5 | SRTP AEAD | Complete | Protection/unprotection |
| §6 | SRTCP AEAD | Complete | RTCP protection |

### Gap: RFC 3711 §6 - Default Transforms

CNSA 2.0 compliance prohibits AES-128. The following are intentionally not implemented:
- AES_CM_128_HMAC_SHA1_80
- AES_CM_128_HMAC_SHA1_32

This is **by design** for security compliance.

---

## proto-rtp (RFC 3550)

### RFC 3550 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §5.1 | RTP Header | Complete | `packet.rs` |
| §5.2 | Multiplexing | Partial | SSRC handling |
| §5.3 | Profile-Specific | Partial | Basic PT support |
| §6.1 | RTCP Header | Complete | `rtcp.rs` |
| §6.4 | SR Report | Complete | Sender Report |
| §6.4.1 | RR Report | Complete | Receiver Report |
| §6.5 | SDES | Complete | Source Description |
| §6.6 | BYE | Complete | Goodbye |
| §6.7 | APP | Complete | Application-Specific |
| §6.3.5 | Timing Rules | Complete | `scheduler.rs` |
| §6.3.7 | Bandwidth | Complete | `scheduler.rs` |
| §7 | Translators/Mixers | Complete | `translator.rs` |

### Gap: RFC 3550 §6.3.5 - RTCP Timing Rules

**RFC Text**: "RTCP packets SHOULD be sent with randomized intervals."

**Implementation Needed**:
```rust
pub struct RtcpScheduler {
    rtcp_bw: u32,           // 5% of session bandwidth
    members: u32,           // Number of participants
    we_sent: bool,          // Did we send RTP?
    avg_rtcp_size: f64,     // Average RTCP packet size
    initial: bool,          // First RTCP?
}

impl RtcpScheduler {
    pub fn compute_interval(&self) -> Duration {
        // Per RFC 3550 Appendix A.7
    }
}
```

---

## proto-sdp (RFC 4566 + RFC 3264)

### RFC 4566 Section Mapping

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §5.1 | Protocol Version | Complete | v= line |
| §5.2 | Origin | Complete | o= line |
| §5.3 | Session Name | Complete | s= line |
| §5.4 | Session Info | Partial | i= line |
| §5.5 | URI | Partial | u= line |
| §5.6 | Email | Partial | e= line |
| §5.7 | Phone | Partial | p= line |
| §5.8 | Connection | Complete | c= line |
| §5.9 | Bandwidth | Partial | b= line |
| §5.10 | Timing | Complete | t= line |
| §5.11 | Repeat Times | **Missing** | r= line |
| §5.14 | Media | Complete | m= line |

### RFC 3264 Section Mapping (Offer/Answer)

| Section | Title | Status | Notes |
|---------|-------|--------|-------|
| §5 | Generating Offer | Partial | Basic generation |
| §6 | Generating Answer | Partial | Basic answering |
| §6.1 | Unicast Streams | Partial | Basic handling |
| §6.2 | Multicast Streams | Complete | `multicast.rs` |
| §8 | Modifying Session | Partial | re-INVITE support |
| §8.2 | Adding Media | Partial | Basic support |
| §8.3 | Removing Media | Partial | port=0 handling |
| §8.4 | Modifying Media | **Missing** | No modification rules |

### Critical Gap: RFC 3264 §8.4 - Modifying Media

**RFC Text**: "When modifying a session, the offerer MUST follow specific rules for changing media."

**Implementation Needed**:
```rust
pub struct OfferAnswerNegotiator {
    current_session: SessionDescription,
}

impl OfferAnswerNegotiator {
    pub fn create_modified_offer(&self, changes: &MediaChanges) -> SdpResult<SessionDescription> {
        // Ensure same number of m= lines
        // Follow direction rules (sendrecv -> recvonly, etc.)
        // Handle codec changes per §8.4.3
    }
}
```

---

## Summary: Priority Implementation Order

### P0 - Critical (Security/Functionality Breaking) ✅ COMPLETE

| Crate | RFC | Section | Gap | Status |
|-------|-----|---------|-----|--------|
| proto-dtls | RFC 6347 | §4.2.4 | Certificate verification | ✅ Done |
| proto-dtls | RFC 6347 | §4.2.6 | Finished message validation | ✅ Done |
| proto-ice | RFC 7675 | §6 | Consent revocation action | ✅ Done |
| proto-turn | RFC 5766 | §9 | Send mechanism | ✅ Done |
| proto-turn | RFC 5766 | §12 | Data indication | ✅ Done |

### P1 - High (Major Functionality) ✅ COMPLETE

| Crate | RFC | Section | Gap | Status |
|-------|-----|---------|-----|--------|
| proto-sip | RFC 3261 | §13.2.2.4 | 3xx redirect handling | ✅ Done |
| proto-registrar | RFC 5626 | §5.2 | Flow maintenance | ✅ Done |
| proto-ice | RFC 8445 | §7.2.2 | Aggressive nomination | ✅ Done |
| proto-sdp | RFC 3264 | §8.4 | Media modification rules | ✅ Done |
| proto-stun | RFC 5389 | §10.2 | Long-term credential | ✅ Done |

### P2 - Medium (Feature Completeness) ✅ COMPLETE

| Crate | RFC | Section | Gap | Status |
|-------|-----|---------|-----|--------|
| proto-registrar | RFC 5627 | §5.1 | Proxy GRUU routing | ✅ Done |
| proto-rtp | RFC 3550 | §6.3.5 | RTCP timing rules | ✅ Done |
| proto-dialog | RFC 6665 | §7.2 | Event package validation | ✅ Done |
| proto-sdp | RFC 4566 | §5.11 | Repeat times (r= line) | ✅ Done |

### P3 - Low (Edge Cases) ✅ COMPLETE

| Crate | RFC | Section | Gap | Status |
|-------|-----|---------|-----|--------|
| proto-sdp | RFC 3264 | §6.2 | Multicast streams | ✅ Done |
| proto-rtp | RFC 3550 | §7 | Translators/mixers | ✅ Done |
| proto-sip | RFC 3261 | §16.6 | Full proxy forwarding | ✅ Done |

---

## Document Maintenance

Last Updated: 2026-02-03

This document should be updated when:
1. New RFC implementations are added
2. Existing gaps are filled
3. New gaps are discovered during testing
