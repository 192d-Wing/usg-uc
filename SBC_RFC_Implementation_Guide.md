# SIP-Based Session Border Controller (SBC) RFC Implementation Guide

## Overview

This document provides a comprehensive summary of RFCs required for implementing a CNSA 2.0 compliant SIP-based Session Border Controller (SBC). It includes core specifications, SBC-specific functionality, security protocols, and SRTP key exchange mechanisms.

---

## Table of Contents

1. [Core SIP RFCs](#1-core-sip-rfcs)
2. [SBC-Specific Functionality RFCs](#2-sbc-specific-functionality-rfcs)
3. [Security RFCs](#3-security-rfcs)
4. [SRTP Key Exchange RFCs](#4-srtp-key-exchange-rfcs)
5. [RFC Dependencies](#5-rfc-dependencies)
6. [Implementation Priority Order](#6-implementation-priority-order)
7. [CNSA 2.0 Cryptographic Considerations](#7-cnsa-20-cryptographic-considerations)

---

## 1. Core SIP RFCs

### RFC 3261 - SIP: Session Initiation Protocol

**Title:** SIP: Session Initiation Protocol

**Status:** Standards Track (Core)

**Summary:** Defines the application-layer control (signaling) protocol for creating, modifying, and terminating sessions with one or more participants, including Internet telephone calls, multimedia distribution, and multimedia conferences.

**Key SBC Implementation Requirements:**
- **User Agent Server (UAS) Core:** Must implement all UAS processing functions for handling incoming requests
- **User Agent Client (UAC) Core:** Must implement all UAC processing functions for generating requests
- **Proxy Core:** Must implement stateful proxy functionality for routing requests
- **Transaction Layer:** Must maintain transaction state machines for both client and server transactions
- **Transport Layer:** Must support UDP, TCP, and TLS transports
- **Dialog Management:** Must properly maintain dialog state for INVITE-initiated sessions
- **Header Processing:** Must correctly parse and generate all mandatory SIP headers (Via, From, To, Call-ID, CSeq, Contact, Max-Forwards)
- **Authentication:** Must support Digest authentication (RFC 2617) for both client and server roles
- **Registration:** Must handle REGISTER requests and maintain binding tables
- **Response Handling:** Must generate and process all response classes (1xx, 2xx, 3xx, 4xx, 5xx, 6xx)

**CNSA 2.0 Notes:**
- TLS cipher suites must use AES-256-GCM only
- Certificate validation must use SHA-384 or SHA-512 for fingerprints
- RSA and ECDSA certificates will need migration to ML-DSA-87 by 2035

---

### RFC 3263 - Locating SIP Servers

**Title:** Session Initiation Protocol (SIP): Locating SIP Servers

**Status:** Standards Track

**Summary:** Defines DNS procedures for determining the location of SIP servers including transport protocols supported.

**Key SBC Implementation Requirements:**
- **NAPTR Lookup:** Must perform NAPTR queries to determine available transports and services
- **SRV Lookup:** Must perform SRV queries to determine server addresses and ports
- **A/AAAA Lookup:** Must resolve hostnames to IPv4/IPv6 addresses
- **Transport Selection:** Must implement transport preference ordering (TLS > TCP > UDP for SIPS URIs)
- **Failover:** Must implement failover to backup servers based on SRV priority/weight
- **Load Balancing:** Must respect SRV weight values for load distribution
- **Deterministic Ordering:** For stateless proxies, must define deterministic ordering for equal-priority SRV records
- **SIPS URI Handling:** Must enforce TLS-only transport for SIPS URIs

**CNSA 2.0 Notes:**
- DNSSEC validation SHOULD be implemented for DNS security
- Consider using DNS-over-TLS (DoT) or DNS-over-HTTPS (DoH) for DNS query confidentiality

---

### RFC 3264 - SDP Offer/Answer Model

**Title:** An Offer/Answer Model with Session Description Protocol (SDP)

**Status:** Standards Track

**Summary:** Defines the mechanism for two entities to negotiate a common view of a multimedia session using SDP.

**Key SBC Implementation Requirements:**
- **Offer Generation:** Must generate valid SDP offers compliant with RFC 4566
- **Answer Generation:** Must generate valid SDP answers that are compatible with received offers
- **Media Negotiation:** Must implement codec negotiation matching offerer/answerer capabilities
- **Port Handling:** Must correctly handle port zero (stream rejection)
- **Glare Handling:** Must detect and resolve glare conditions (simultaneous offers)
- **Re-INVITE Processing:** Must handle session modification via re-INVITE
- **Hold/Resume:** Must implement call hold (sendonly/recvonly/inactive) and resume
- **Attribute Matching:** Must preserve session-level vs media-level attribute semantics

**CNSA 2.0 Notes:**
- SDP fingerprint attributes (for DTLS-SRTP) must use SHA-384 or SHA-512, NOT SHA-256

---

### RFC 4566 - SDP: Session Description Protocol

**Title:** SDP: Session Description Protocol

**Status:** Standards Track

**Summary:** Defines the format for describing multimedia sessions for announcement, invitation, and initiation purposes.

**Key SBC Implementation Requirements:**
- **Parser Implementation:** Must parse all mandatory SDP fields (v=, o=, s=, c=, t=, m=)
- **Generator Implementation:** Must generate compliant SDP messages
- **Media Description:** Must support audio, video, and application media types
- **Connection Data:** Must handle both IPv4 and IPv6 connection addresses
- **Bandwidth:** Must parse and honor bandwidth (b=) restrictions
- **Encryption Keys:** Must support key attributes (a=crypto, a=fingerprint)
- **RTP Payload Types:** Must correctly map payload types to codecs
- **Attribute Processing:** Must handle both session-level and media-level attributes
- **UTF-8 Support:** Must properly handle UTF-8 encoding

**CNSA 2.0 Notes:**
- All cryptographic parameters in SDP must comply with CNSA 2.0 requirements

---

### RFC 3550 - RTP: A Transport Protocol for Real-Time Applications

**Title:** RTP: A Transport Protocol for Real-Time Applications

**Status:** Standards Track

**Summary:** Defines the real-time transport protocol for end-to-end delivery of data with real-time characteristics including payload type identification, sequence numbering, timestamping, and delivery monitoring.

**Key SBC Implementation Requirements:**
- **RTP Header Processing:** Must parse and generate 12-byte minimum RTP headers
- **Sequence Number Handling:** Must track sequence numbers for reordering/loss detection
- **Timestamp Processing:** Must handle timestamps for synchronization
- **SSRC Management:** Must track synchronization source identifiers
- **CSRC Lists:** Must handle contributing source identifiers for mixers
- **Payload Type Mapping:** Must correctly map payload types to codecs
- **RTCP Processing:** Must implement Sender Reports (SR), Receiver Reports (RR), SDES, BYE, APP packets
- **RTCP Bandwidth:** Should limit RTCP to 5% of session bandwidth
- **Media Relay:** As a B2BUA, must implement RTP relay/proxy functionality
- **Jitter Buffer:** May implement jitter buffer for quality improvement

**CNSA 2.0 Notes:**
- RTP payloads must be encrypted using SRTP with AES-256-GCM

---

### RFC 3711 - SRTP: The Secure Real-time Transport Protocol

**Title:** The Secure Real-time Transport Protocol (SRTP)

**Status:** Standards Track

**Summary:** Defines the SRTP profile of RTP providing confidentiality, message authentication, and replay protection.

**Key SBC Implementation Requirements:**
- **Encryption:** Must implement AES-128 and AES-256 counter mode encryption
- **Authentication:** Must implement HMAC-SHA1 for packet authentication (80-bit or 32-bit tags)
- **Replay Protection:** Must implement replay list/bitmap for replay attack prevention
- **Key Derivation:** Must implement the SRTP key derivation function from master keys
- **Master Key Management:** Must securely handle master key and master salt
- **Cryptographic Context:** Must maintain per-stream cryptographic contexts
- **SRTCP:** Must implement Secure RTCP with mandatory fields (index, encrypt-flag, auth tag)
- **ROC Handling:** Must track and synchronize rollover counter
- **MKI Support:** Should support Master Key Identifier for key switching

**CNSA 2.0 Notes:**
- **CRITICAL:** Must use AES-256-GCM (AEAD_AES_256_GCM) exclusively
- **CRITICAL:** HMAC-SHA1 authentication is NOT compliant with CNSA 2.0; use AES-GCM authenticated encryption
- Must use 256-bit master keys minimum
- Consider implementing RFC 7714 (AES-GCM for SRTP) for CNSA 2.0 compliance

---

## 2. SBC-Specific Functionality RFCs

### RFC 5853 - Requirements from SIP SBC Deployments (Informational)

**Title:** Requirements from Session Initiation Protocol (SIP) Session Border Control (SBC) Deployments

**Status:** Informational

**Summary:** Describes functions commonly implemented in SBCs and explores underlying requirements that led to these practices.

**Key SBC Implementation Requirements:**
- **Topology Hiding:** Strip/modify Via, Record-Route headers; replace Contact URIs; modify Call-IDs
- **Media Traffic Management:** Control codecs, enforce policies, implement lawful intercept hooks
- **NAT Traversal:** Handle endpoints behind NAT, maintain NAT bindings
- **Access Control:** Implement ACLs for signaling and media
- **DoS Protection:** Rate limiting, connection throttling, anomaly detection
- **Interworking:** Protocol translation, codec transcoding when necessary
- **Security Gateway:** Terminate and re-originate encrypted sessions
- **Call Admission Control:** Prevent over-subscription of resources

---

### RFC 7092 - A Taxonomy of SIP Back-to-Back User Agents

**Title:** A Taxonomy of Session Initiation Protocol (SIP) Back-to-Back User Agents

**Status:** Informational

**Summary:** Identifies common B2BUA roles to provide taxonomy for other documents.

**Key SBC Implementation Requirements:**
- **Signaling-only B2BUA:** May operate only on signaling without media path insertion
- **SDP-Modifying Signaling-only B2BUA:** Modifies SDP but not in media path
- **Media Relay B2BUA:** Terminates and re-originates RTP without payload inspection
- **Media-aware B2BUA:** Inspects RTP headers/RTCP without codec processing
- **Media Termination B2BUA:** Full media termination including codec processing
- **Role Selection:** Must clearly define which B2BUA role(s) are implemented
- **Header Manipulation:** Based on role, modify/strip/add appropriate headers

---

### RFC 8445 - ICE: Interactive Connectivity Establishment

**Title:** Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal

**Status:** Standards Track (Obsoletes RFC 5245)

**Summary:** Defines the ICE protocol for NAT traversal in UDP-based multimedia sessions.

**Key SBC Implementation Requirements:**
- **Full ICE Implementation:** Should implement full ICE agent (not lite) for maximum compatibility
- **Candidate Gathering:** Must gather host, server-reflexive, and relay candidates
- **STUN Client:** Must implement STUN Binding requests for connectivity checks
- **TURN Client:** Should implement TURN for relay candidate allocation
- **Candidate Prioritization:** Must implement candidate priority formula
- **Connectivity Checks:** Must perform STUN-based connectivity checks on candidate pairs
- **Nomination:** Must implement regular nomination (aggressive nomination deprecated)
- **ICE Restart:** Must support ICE restart via new credentials
- **Trickle ICE:** Should support trickle ICE for faster setup (RFC 8838)
- **Lite Implementation Option:** May implement ICE-lite for server-side deployment

**CNSA 2.0 Notes:**
- STUN message integrity should use stronger algorithms when available

---

### RFC 5245 - ICE (Original, Obsoleted)

**Title:** Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal for Offer/Answer Protocols

**Status:** Obsoleted by RFC 8445

**Summary:** Original ICE specification, now replaced by RFC 8445.

**Implementation Note:** Implement RFC 8445 instead; understand RFC 5245 for legacy interoperability only.

---

### RFC 8839 - SDP Offer/Answer Procedures for ICE

**Title:** Session Description Protocol (SDP) Offer/Answer Procedures for Interactive Connectivity Establishment (ICE)

**Status:** Standards Track (Obsoletes RFC 5245 Section 15)

**Summary:** Defines SDP attributes and offer/answer procedures for ICE.

**Key SBC Implementation Requirements:**
- **ice-ufrag Attribute:** Must generate and parse ICE username fragment
- **ice-pwd Attribute:** Must generate and parse ICE password
- **candidate Attribute:** Must generate and parse candidate lines with all components
- **ice-options Attribute:** Must support ICE extensions signaling (trickle, ice2)
- **ice-lite Attribute:** Must support signaling lite implementation
- **ice-mismatch Attribute:** Must detect and signal ICE mismatch conditions
- **remote-candidates Attribute:** Must support for controlling agent role
- **ice-pacing Attribute:** Should support pacing interval configuration
- **ICE Restart Detection:** Must detect restart via changed credentials

---

### RFC 5626 - Managing Client-Initiated Connections in SIP (SIP Outbound)

**Title:** Managing Client-Initiated Connections in the Session Initiation Protocol (SIP)

**Status:** Standards Track

**Summary:** Defines behaviors allowing requests to be delivered on existing connections established by User Agents.

**Key SBC Implementation Requirements:**
- **Edge Proxy Role:** Must function as edge proxy for outbound connections
- **Flow Token:** Must generate and process flow tokens in URIs
- **Connection Persistence:** Must maintain persistent TCP/TLS connections from UAs
- **Keep-Alive Processing:** Must process STUN keep-alives or CRLF keep-alives
- **Flow Failure Detection:** Must detect and handle connection failures
- **ob Parameter:** Must process "ob" URI parameter in Contact/Path headers
- **430 Response:** Must generate "430 Flow Failed" response when appropriate
- **Path Header:** Must add Path header with flow token for registrations
- **Multiple Flows:** Should support multiple outbound flows per registration

---

### RFC 5761 - Multiplexing RTP and RTCP on a Single Port

**Title:** Multiplexing RTP Data and Control Packets on a Single Port

**Status:** Standards Track

**Summary:** Describes multiplexing RTP and RTCP on a single UDP port and its signaling.

**Key SBC Implementation Requirements:**
- **Packet Demultiplexing:** Must distinguish RTP from RTCP based on payload type field
- **rtcp-mux Attribute:** Must support SDP "a=rtcp-mux" attribute
- **Negotiation:** Must properly negotiate mux capability via offer/answer
- **Payload Type Constraints:** Must ensure RTP PT values don't conflict with RTCP types (64-95)
- **Unicast Sessions:** Should support mux for unicast to ease NAT traversal
- **Backward Compatibility:** Must fall back to separate ports when peer doesn't support mux

---

## 3. Security RFCs

### RFC 5630 - The Use of the SIPS URI Scheme

**Title:** The Use of the SIPS URI Scheme in the Session Initiation Protocol (SIP)

**Status:** Standards Track

**Summary:** Clarifies the meaning and usage of SIPS URI scheme and TLS in SIP.

**Key SBC Implementation Requirements:**
- **SIPS Enforcement:** Must use TLS for all hops when SIPS URI is used
- **TLS-Only:** SIPS implies TLS-only, not "best-effort TLS"
- **Certificate Validation:** Must validate server certificates for outbound TLS
- **Mutual TLS:** Should support mutual TLS for server-to-server connections
- **No transport=tls:** Must not use deprecated "transport=tls" parameter
- **Last-Hop Exception:** Must NOT use RFC 3261 last-hop exception for SIPS
- **Request-URI Preservation:** Must maintain SIPS scheme when forwarding

**CNSA 2.0 Notes:**
- TLS 1.3 only (TLS 1.2 acceptable during transition)
- Cipher suites: TLS_AES_256_GCM_SHA384 only
- Certificates: minimum P-384 curves (transitioning to ML-DSA-87)
- NO SHA-256 - use SHA-384 minimum

---

### RFC 4474 - SIP Identity (Obsoleted)

**Title:** Enhancements for Authenticated Identity Management in the Session Initiation Protocol (SIP)

**Status:** Obsoleted by RFC 8224

**Summary:** Original SIP identity mechanism using Identity and Identity-Info headers.

**Implementation Note:** Implement RFC 8224 instead; understand RFC 4474 for legacy compatibility only.

---

### RFC 8224 - Authenticated Identity Management in SIP

**Title:** Authenticated Identity Management in the Session Initiation Protocol (SIP)

**Status:** Standards Track (Obsoletes RFC 4474)

**Summary:** Defines mechanism for securely identifying originators of SIP requests using PASSporT tokens.

**Key SBC Implementation Requirements:**
- **Authentication Service (AS):** May act as authentication service to sign PASSporT tokens
- **Verification Service (VS):** Must act as verification service to validate Identity headers
- **Identity Header:** Must parse and validate Identity header containing PASSporT
- **PASSporT Processing:** Must implement PASSporT encoding/decoding (RFC 8225)
- **Certificate Handling:** Must retrieve and validate certificates from info parameter URL
- **Date Validation:** Must validate PASSporT timestamp within acceptable skew
- **Origination Identifier Validation:** Must validate calling party identity against PASSporT
- **438 Response:** Must generate "438 Invalid Identity Header" for validation failures
- **428 Response:** Must generate "428 Use Identity Header" when identity required but absent

**CNSA 2.0 Notes:**
- PASSporT signatures must transition to ML-DSA-87
- ES384 (ECDSA with P-384 and SHA-384) acceptable during transition
- NO ES256 (P-256/SHA-256)

---

### RFC 8225 - PASSporT: Personal Assertion Token

**Title:** PASSporT: Personal Assertion Token

**Status:** Standards Track

**Summary:** Defines JSON Web Token format for secure telephone identity assertion.

**Key SBC Implementation Requirements:**
- **JWT Processing:** Must implement JWT parsing and generation
- **PASSporT Claims:** Must handle "orig", "dest", "iat" claims
- **JWS Signatures:** Must validate ES256 and ES384 signatures
- **Certificate Chain Validation:** Must validate certificate chain to trusted root
- **Telephony Number Format:** Must handle E.164 telephone numbers in claims

**CNSA 2.0 Notes:**
- Use ES384 (P-384 + SHA-384) or ES512 (P-521 + SHA-512)
- Transition to ML-DSA-87 based signatures
- NO ES256

---

### RFC 5763 - DTLS-SRTP Framework

**Title:** Framework for Establishing a Secure Real-time Transport Protocol (SRTP) Security Context Using Datagram Transport Layer Security (DTLS)

**Status:** Standards Track

**Summary:** Specifies using SIP to establish SRTP security context using DTLS.

**Key SBC Implementation Requirements:**
- **Fingerprint Attribute:** Must generate and parse "a=fingerprint" SDP attribute
- **Setup Attribute:** Must handle "a=setup" attribute (active/passive/actpass/holdconn)
- **DTLS Role Negotiation:** Must negotiate DTLS client/server roles via SDP
- **Hash Algorithm:** Must support fingerprint hash algorithms (SHA-256, SHA-384, SHA-512)
- **Certificate Binding:** Must validate that DTLS certificate matches SDP fingerprint
- **SIP Identity Integration:** Should use RFC 8224 to protect fingerprint integrity

**CNSA 2.0 Notes:**
- **CRITICAL:** Fingerprint hash must be SHA-384 or SHA-512, NOT SHA-256
- DTLS certificates must use P-384 minimum (transitioning to ML-KEM/ML-DSA)

---

### RFC 5764 - DTLS Extension for SRTP Keys

**Title:** Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)

**Status:** Standards Track

**Summary:** Defines DTLS extension to establish keys for SRTP/SRTCP.

**Key SBC Implementation Requirements:**
- **DTLS-SRTP Extension:** Must implement use_srtp DTLS extension
- **SRTP Protection Profiles:** Must negotiate SRTP protection profiles
- **Key Export:** Must implement SRTP key material export from DTLS
- **Demultiplexing:** Must demultiplex DTLS, SRTP, STUN on same port
- **DTLS Version:** Must support DTLS 1.2, should support DTLS 1.3
- **Alert Handling:** Must properly handle DTLS alerts

**CNSA 2.0 Notes:**
- Use SRTP_AEAD_AES_256_GCM protection profile
- DTLS cipher suites must use AES-256-GCM only
- Key exchange must use P-384 ECDHE minimum (transitioning to ML-KEM-1024)

---

## 4. SRTP Key Exchange RFCs

### RFC 4568 - SDP Security Descriptions (SDES)

**Title:** Session Description Protocol (SDP) Security Descriptions for Media Streams

**Status:** Standards Track

**Summary:** Defines SDP crypto attribute for negotiating SRTP keying material.

**Key SBC Implementation Requirements:**
- **Crypto Attribute Parsing:** Must parse "a=crypto" attribute with all components
- **Crypto Suite Support:** Must support standard crypto suites (AES_CM_128_HMAC_SHA1_80, etc.)
- **Inline Key:** Must parse and generate inline keying material (base64 encoded)
- **Key Parameters:** Must handle session parameters (lifetime, MKI, etc.)
- **Offer/Answer:** Must implement SDES negotiation per offer/answer model
- **Multiple Crypto Lines:** Must handle multiple crypto attribute offers
- **Tag Matching:** Must match crypto tags between offer and answer

**CNSA 2.0 Notes:**
- **CRITICAL:** SDES inherently insecure without TLS protection of signaling
- If using SDES, MUST use SIPS (TLS) for signaling
- Crypto suite must be AEAD_AES_256_GCM
- **Recommendation:** Prefer DTLS-SRTP over SDES for CNSA 2.0 compliance

---

### RFC 5763/5764 - DTLS-SRTP

(See Security RFCs section above for detailed requirements)

**Summary for Key Exchange Context:**
- Preferred key exchange mechanism for CNSA 2.0 compliance
- Key exchange occurs on media path, independent of signaling
- Provides perfect forward secrecy
- Integrates with SIP Identity for fingerprint protection

---

### RFC 6189 - ZRTP: Media Path Key Agreement

**Title:** ZRTP: Media Path Key Agreement for Unicast Secure RTP

**Status:** Informational

**Summary:** Defines Diffie-Hellman key agreement protocol for SRTP in the media path.

**Key SBC Implementation Requirements:**
- **ZRTP Messages:** Must implement Hello, HelloACK, Commit, DHPart1/2, Confirm1/2, Conf2ACK
- **DH Key Exchange:** Must implement Diffie-Hellman key exchange
- **SAS Calculation:** Must calculate and optionally display Short Authentication String
- **Key Continuity:** Should implement key continuity using cached shared secrets
- **ZID Management:** Must generate and maintain unique 96-bit ZRTP ID
- **Perfect Forward Secrecy:** Must destroy session keys after call
- **MitM Detection:** Should implement SAS verification mechanism

**CNSA 2.0 Notes:**
- DH groups must use P-384 minimum (DH3k not CNSA compliant)
- Hash algorithms must be SHA-384 or SHA-512
- ZRTP may need extensions for post-quantum key exchange (ML-KEM-1024)
- Symmetric cipher must be AES-256

---

## 5. RFC Dependencies

### Dependency Graph

```
                        ┌─────────────┐
                        │  RFC 3261   │ (SIP Core)
                        │   (Base)    │
                        └──────┬──────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │  RFC 3263   │     │  RFC 4566   │     │  RFC 5626   │
    │  (DNS)      │     │   (SDP)     │     │ (Outbound)  │
    └─────────────┘     └──────┬──────┘     └─────────────┘
                               │
                        ┌──────┴──────┐
                        │  RFC 3264   │
                        │(Offer/Answer)│
                        └──────┬──────┘
                               │
     ┌─────────────────────────┼─────────────────────────┐
     │                         │                         │
     ▼                         ▼                         ▼
┌─────────────┐          ┌─────────────┐          ┌─────────────┐
│  RFC 3550   │          │  RFC 8445   │          │  RFC 4568   │
│   (RTP)     │          │   (ICE)     │          │   (SDES)    │
└──────┬──────┘          └──────┬──────┘          └─────────────┘
       │                        │
       ▼                        ▼
┌─────────────┐          ┌─────────────┐
│  RFC 3711   │          │  RFC 8839   │
│  (SRTP)     │          │ (SDP-ICE)   │
└──────┬──────┘          └─────────────┘
       │
       ├────────────────────────┐
       │                        │
       ▼                        ▼
┌─────────────┐          ┌─────────────┐
│  RFC 5763   │          │  RFC 6189   │
│(DTLS-SRTP   │          │   (ZRTP)    │
│ Framework)  │          └─────────────┘
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  RFC 5764   │
│(DTLS-SRTP)  │
└─────────────┘
```

### Security Stack Dependencies

```
┌─────────────┐     ┌─────────────┐
│  RFC 5630   │     │  RFC 8224   │
│   (SIPS)    │     │(SIP Identity)│
└──────┬──────┘     └──────┬──────┘
       │                   │
       │                   ▼
       │            ┌─────────────┐
       │            │  RFC 8225   │
       │            │ (PASSporT)  │
       └─────┬──────┴─────────────┘
             │
             ▼
       TLS/DTLS Layer
```

---

## 6. Implementation Priority Order

### Phase 1: Foundation (Required First)

| Priority | RFC | Title | Rationale |
|----------|-----|-------|-----------|
| 1.1 | RFC 3261 | SIP Core | Foundational protocol - nothing works without this |
| 1.2 | RFC 4566 | SDP | Session description required for all media negotiation |
| 1.3 | RFC 3264 | Offer/Answer | Mandatory for SIP session establishment |
| 1.4 | RFC 3263 | DNS Procedures | Required for server location and failover |
| 1.5 | RFC 3550 | RTP | Required for media transport |

### Phase 2: Security Baseline (Critical for CNSA 2.0)

| Priority | RFC | Title | Rationale |
|----------|-----|-------|-----------|
| 2.1 | RFC 5630 | SIPS/TLS | TLS required for signaling security |
| 2.2 | RFC 3711 | SRTP | Media encryption baseline |
| 2.3 | RFC 5763 | DTLS-SRTP Framework | Preferred key exchange for CNSA 2.0 |
| 2.4 | RFC 5764 | DTLS-SRTP | Complete DTLS-SRTP implementation |

### Phase 3: SBC Core Functions

| Priority | RFC | Title | Rationale |
|----------|-----|-------|-----------|
| 3.1 | RFC 7092 | B2BUA Taxonomy | Defines SBC architectural role |
| 3.2 | RFC 5853 | SBC Requirements | Defines required SBC functions |
| 3.3 | RFC 5761 | RTP/RTCP Mux | Simplifies NAT traversal |
| 3.4 | RFC 5626 | SIP Outbound | Client connection management |

### Phase 4: NAT Traversal

| Priority | RFC | Title | Rationale |
|----------|-----|-------|-----------|
| 4.1 | RFC 8445 | ICE | NAT traversal protocol |
| 4.2 | RFC 8839 | SDP for ICE | ICE SDP procedures |
| 4.3 | RFC 5245 | ICE (Legacy) | Legacy interoperability only |

### Phase 5: Enhanced Security

| Priority | RFC | Title | Rationale |
|----------|-----|-------|-----------|
| 5.1 | RFC 8224 | SIP Identity | Caller authentication |
| 5.2 | RFC 8225 | PASSporT | Identity token format |
| 5.3 | RFC 4474 | Legacy Identity | Legacy interoperability |

### Phase 6: Alternative Key Exchange (Optional)

| Priority | RFC | Title | Rationale |
|----------|-----|-------|-----------|
| 6.1 | RFC 4568 | SDES | Alternative to DTLS-SRTP (less secure) |
| 6.2 | RFC 6189 | ZRTP | End-to-end encryption option |

---

## 7. CNSA 2.0 Cryptographic Considerations

### Algorithm Requirements Summary

| Function | CNSA 2.0 Requirement | NOT Allowed | Notes |
|----------|---------------------|-------------|-------|
| Symmetric Encryption | AES-256 only | AES-128 | Use GCM mode |
| Hash Functions | SHA-384, SHA-512 | SHA-256, SHA-1 | SHA3-384/512 for hardware only |
| Key Exchange | ML-KEM-1024 | RSA, DH, ECDH (P-256) | P-384 ECDHE acceptable during transition |
| Digital Signatures | ML-DSA-87 | RSA, ECDSA (P-256) | P-384 ECDSA acceptable during transition |
| TLS Version | TLS 1.3 (TLS 1.2 acceptable) | TLS 1.1 and below | |
| DTLS Version | DTLS 1.3 (DTLS 1.2 acceptable) | DTLS 1.0 | |

### Protocol-Specific Requirements

#### TLS/DTLS Configuration
```
Cipher Suites (Priority Order):
1. TLS_AES_256_GCM_SHA384 (TLS 1.3)
2. TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (TLS 1.2 transition)

Key Exchange:
- Current: ECDHE with P-384 curve
- Target (by 2035): ML-KEM-1024

Certificates:
- Current: ECDSA with P-384
- Target (by 2035): ML-DSA-87
```

#### SRTP Configuration
```
Protection Profiles:
- REQUIRED: SRTP_AEAD_AES_256_GCM (RFC 7714)
- NOT ALLOWED: SRTP_AES_256_CM_HMAC_SHA1_80 (uses SHA-1)
- NOT ALLOWED: SRTP_AES_128_CM_HMAC_SHA1_80

Key Derivation:
- Use HKDF-SHA384 where possible
```

#### SDP Fingerprint
```
Allowed:
- a=fingerprint:sha-384 <hash>
- a=fingerprint:sha-512 <hash>

NOT Allowed:
- a=fingerprint:sha-256 <hash>
- a=fingerprint:sha-1 <hash>
```

#### PASSporT/STIR Signatures
```
Current (Transition):
- ES384 (ECDSA P-384 with SHA-384)
- ES512 (ECDSA P-521 with SHA-512)

NOT Allowed:
- ES256 (ECDSA P-256 with SHA-256)

Target (by 2035):
- ML-DSA-87 based signatures
```

### Migration Timeline

| Milestone | Date | Requirement |
|-----------|------|-------------|
| Begin transition | 2025 | Support CNSA 2.0 algorithms |
| Support & Prefer | 2026-2027 | CNSA 2.0 preferred for network equipment |
| Exclusive Use | 2030 | VPNs, routers exclusively CNSA 2.0 |
| Full Compliance | 2033 | All NSS cryptography quantum-resistant |
| Legacy Removal | 2035 | All classical algorithms removed |

### Implementation Recommendations

1. **Immediate Actions:**
   - Remove AES-128 from all configurations
   - Remove SHA-256 from fingerprints and signatures
   - Implement AES-256-GCM for SRTP
   - Configure TLS 1.3 with AES-256-GCM-SHA384

2. **Short-term (by 2026):**
   - Implement P-384 based ECDHE and ECDSA
   - Update certificate infrastructure for P-384
   - Implement SHA-384 for all hashing operations

3. **Medium-term (by 2030):**
   - Implement hybrid key exchange (classical + post-quantum)
   - Begin ML-KEM-1024 integration for key exchange
   - Begin ML-DSA-87 integration for signatures

4. **Long-term (by 2035):**
   - Complete migration to post-quantum algorithms
   - Remove all classical asymmetric cryptography

---

## Sources

### Core SIP RFCs
- [RFC 3261 - SIP Core](https://datatracker.ietf.org/doc/html/rfc3261)
- [RFC 3263 - Locating SIP Servers](https://datatracker.ietf.org/doc/html/rfc3263)
- [RFC 3264 - SDP Offer/Answer](https://datatracker.ietf.org/doc/html/rfc3264)
- [RFC 4566 - SDP](https://datatracker.ietf.org/doc/html/rfc4566)
- [RFC 3550 - RTP](https://datatracker.ietf.org/doc/html/rfc3550)
- [RFC 3711 - SRTP](https://datatracker.ietf.org/doc/html/rfc3711)

### SBC-Specific RFCs
- [RFC 5853 - SBC Requirements](https://datatracker.ietf.org/doc/html/rfc5853)
- [RFC 7092 - B2BUA Taxonomy](https://datatracker.ietf.org/doc/html/rfc7092)
- [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
- [RFC 8839 - SDP for ICE](https://datatracker.ietf.org/doc/rfc8839/)
- [RFC 5626 - SIP Outbound](https://datatracker.ietf.org/doc/html/rfc5626)
- [RFC 5761 - RTP/RTCP Mux](https://datatracker.ietf.org/doc/html/rfc5761)

### Security RFCs
- [RFC 5630 - SIPS URI](https://datatracker.ietf.org/doc/html/rfc5630)
- [RFC 8224 - SIP Identity](https://datatracker.ietf.org/doc/html/rfc8224)
- [RFC 8225 - PASSporT](https://www.rfc-editor.org/rfc/rfc8224)
- [RFC 5763 - DTLS-SRTP Framework](https://datatracker.ietf.org/doc/html/rfc5763)
- [RFC 5764 - DTLS-SRTP](https://datatracker.ietf.org/doc/html/rfc5764)

### Key Exchange RFCs
- [RFC 4568 - SDES](https://datatracker.ietf.org/doc/html/rfc4568)
- [RFC 6189 - ZRTP](https://datatracker.ietf.org/doc/rfc6189/)

### CNSA 2.0 References
- [NSA CNSA 2.0 Algorithms](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)
- [SafeLogic CNSA 2.0 Compliance Guide](https://www.safelogic.com/compliance/cnsa-2)
- [Wikipedia - CNSA](https://en.wikipedia.org/wiki/Commercial_National_Security_Algorithm_Suite)
