# USG Unified Communications SBC - Roadmap

This document outlines the development roadmap for the USG Session Border Controller.

## Completed Phases

### ✅ Phase 1-2: Foundation & Transport

- Workspace structure with 27 crates in 9 layers
- Foundation crates: `sbc-types`, `sbc-crypto`, `sbc-audit`, `sbc-config`
- CNSA 2.0 cryptographic compliance enforcement
- NIST 800-53 Rev5 audit logging infrastructure
- Transport crates: `sbc-transport`, `sbc-dtls`

### ✅ Phase 3: Protocol Core

- `proto-sip`: RFC 3261 SIP message parsing and generation (standalone, reusable)
- `sbc-sdp`: SDP offer/answer model
- `sbc-rtp`: RTP packet handling
- `sbc-srtp`: Custom CNSA 2.0 compliant SRTP (AES-256-GCM, SHA-384 KDF)

### ✅ Phase 4: NAT/ICE

- `sbc-stun`: STUN client/server
- `sbc-turn`: TURN relay
- `sbc-ice`: Full ICE implementation (RFC 8445)

### ✅ Phase 5: Media Engine

- `sbc-codecs`: Opus, G.711 (pure Rust), G.722 codec support
- `sbc-media-engine`: Media relay and pass-through modes

### ✅ Phase 6: SIP Application (Extracted to proto-* crates)

- `proto-sip`: RFC 3261 SIP parsing, RFC 2617 digest auth, RFC 3327 Path header
- `proto-transaction`: RFC 3261 §17 transaction FSM, CSeq validation, RFC 3311 UPDATE
- `proto-dialog`: RFC 3261 §12 dialogs, RFC 3515 REFER, RFC 4028 session timers, forking support
- `proto-b2bua`: RFC 7092 B2BUA modes, RFC 5853 SBC, SDP rewriting, topology hiding
- `proto-registrar`: RFC 3261 §10 registration, RFC 5626 outbound, RFC 5627 GRUU
- `sbc-transaction`, `sbc-dialog`, `sbc-b2bua`, `sbc-registrar`: Thin wrappers re-exporting proto-* crates

### ✅ Phase 7: Security Services

- `sbc-stir-shaken`: STIR/SHAKEN with ES384 only (CNSA 2.0)
- `sbc-acl`: Access control lists with CIDR network matching
- `sbc-dos-protection`: Token bucket rate limiting

### ✅ Phase 8: Orchestration & Management

- `sbc-policy`: Policy engine with conditions, actions, rules
- `sbc-routing`: Dial plans, trunk management, LCR, failover
- `sbc-cdr`: Call Detail Records with JSON/CSV export
- `sbc-api`: REST API framework
- `sbc-metrics`: Prometheus metrics
- `sbc-health`: Kubernetes liveness/readiness probes

### ✅ Phase 9: Binaries & Integration

- `sbc-daemon`: Main SBC daemon
- `sbc-cli`: Command-line interface
- `sbc-integration-tests`: Cross-crate integration tests

**Current Status**: 1000+ tests passing, Phases 1-19 and 21 complete, ready for Phase 22 (High Availability & Clustering)

---

## Completed Development Phases

### ✅ Phase 10: Async Runtime Integration

**Goal**: Wire up tokio async runtime for real network I/O

- ✅ Add tokio dependency to sbc-daemon
- ✅ Implement async transport listeners (UDP)
- ✅ Create async event loop for message processing
- ✅ Add Unix signal handling (SIGTERM, SIGINT, SIGHUP)
- ✅ Implement async health check polling

### ✅ Phase 11: SIP Stack Integration

**Goal**: Connect SIP components into working call flow

- ✅ Integrate proto-sip with transport layer
- ✅ Wire sbc-transaction for request/response handling
- ✅ Connect sbc-dialog for call state management
- ✅ Enable sbc-b2bua for call bridging
- ✅ Integrate sbc-registrar for user registration

### ✅ Phase 12: Media Pipeline

**Goal**: Enable RTP/SRTP media relay

- ✅ Connect sbc-rtp with UDP transport
- ✅ Integrate sbc-srtp for encrypted media
- ✅ Wire sbc-media-engine for relay/pass-through
- ✅ Add DTLS-SRTP key exchange via sbc-dtls
- ✅ Enable codec transcoding via sbc-codecs

### ✅ Phase 13: ICE/NAT Traversal

**Goal**: Full NAT traversal support

- ✅ Integrate sbc-stun for connectivity checks
- ✅ Enable sbc-turn for relay allocation
- ✅ Connect sbc-ice for candidate gathering/selection
- ✅ Add ICE-lite mode for server-side optimization

### ✅ Phase 14: REST API Server

**Goal**: HTTP management interface

- ✅ Add HTTP server to sbc-daemon (axum)
- ✅ Expose sbc-api routes for management
- ✅ Implement sbc-metrics Prometheus endpoint
- ✅ Add sbc-health HTTP probes (/healthz, /readyz)
- [ ] Enable sbc-cdr export endpoints (future)

### ✅ Phase 15: Production Hardening

**Goal**: Production-ready deployment

- ✅ Implement graceful shutdown with connection draining
- ✅ Add configuration hot-reload via SIGHUP
- ✅ Enable TLS for API server (HTTPS with CNSA 2.0 compliant config)
- ✅ Implement rate limiting per sbc-dos-protection
- [ ] Add distributed tracing (OpenTelemetry) (future)
- [ ] Enable TLS certificate rotation (future)

### ✅ Phase 16: Deployment & Operations

**Goal**: Container and orchestration support

- ✅ Create multi-stage Dockerfile (non-root, minimal runtime)
- ✅ Add Kubernetes manifests (Namespace, Deployment, Service, ConfigMap, RBAC, PDB, NetworkPolicy)
- ✅ Create Helm chart for parameterized deployment
- ✅ Add Prometheus ServiceMonitor
- ✅ Document operational runbook

---

## Completed Development Phase

### ✅ Phase 17: Complete Stub Implementations

**Goal**: Make placeholder implementations functional

**DTLS Integration** (sbc-dtls) ✅

- ✅ Custom DTLS 1.2 implementation with aws-lc-rs (replaced webrtc-dtls)
- ✅ DTLS record layer with AES-256-GCM encryption
- ✅ Full handshake state machine (client and server)
- ✅ TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite (0xC02C)
- ✅ P-384 ECDHE key exchange
- ✅ TLS 1.2 PRF with HMAC-SHA384
- ✅ SRTP keying material export (RFC 5764)
- ✅ Anti-replay protection with sliding window
- ✅ Cookie-based DoS protection (HelloVerifyRequest)

**ICE Candidate Gathering** (sbc-ice) ✅

- ✅ STUN client implementation for server-reflexive candidates
- ✅ TURN client implementation for relay candidates
- ✅ Candidate gathering state machine in ICE agent
- ✅ TURN authentication support

**Codec Implementations** (sbc-codecs) ✅

- ✅ G.722 ADPCM encoder/decoder (pure Rust implementation)
- ✅ QMF filter banks for sub-band splitting
- ✅ Opus FFI bindings (optional `opus-ffi` feature via audiopus)
- ✅ Fixed clippy warnings across codec modules

---

## Future Development Phases

### ✅ Phase 18: RFC Compliance Completion

**Goal**: Complete remaining RFC compliance gaps

**Reliable Provisional Responses** (RFC 3262) ✅

- ✅ 100rel extension support in proto-transaction
- ✅ PRACK method transaction state machine (ReliableProvisionalTracker)
- ✅ RAck header parsing and validation
- ✅ Provisional response retransmission with T1/T2 timers

**Event Framework** (RFC 6665) ✅

- ✅ SUBSCRIBE/NOTIFY dialog support in proto-dialog
- ✅ Subscription and Notifier state management
- ✅ Event package definitions (presence, dialog, message-summary, refer, reg)
- ✅ SubscriptionStateHeader parsing and formatting

**REGISTER Response** (RFC 3261 §10.3) ✅

- ✅ format_contacts() echoes registered contacts with expiry
- ✅ remaining_seconds() for binding time-to-expiry
- ✅ Service-Route header support in RegisterResponse
- ✅ Path header support in RegisterRequest/Response

**Early Media** (RFC 3960) ✅

- ✅ EarlyMediaHandler for 183 Session Progress
- ✅ EarlyMediaMode: None, LocalRingback, Relay, Gate
- ✅ Per-leg early media session tracking
- ✅ Mode-based early media disposition

**ICE Connectivity Checks** (RFC 8445 §6.2) ✅

- ✅ STUN-based connectivity check implementation in proto-ice
- ✅ ConnectivityChecker with triggered check queue
- ✅ IceStunServer for Binding request/response handling
- ✅ USE-CANDIDATE nomination and role conflict (487) handling
- ✅ CheckResult states: Success, Failure, Timeout, RoleConflict, InvalidCredentials

**ICE Consent & Keepalives** (RFC 8445 §9-10, RFC 7675) ✅

- ✅ ConsentTracker with 5-second check interval
- ✅ 30-second consent timeout per RFC 7675
- ✅ KeepaliveTracker with 15-second STUN Binding indications
- ✅ ConsentKeepaliveManager combining consent and keepalive logic
- ✅ ConsentState: Pending, Granted, Expired

**DTLS-SRTP Key Export** (RFC 5764) ✅

- ✅ SrtpKeyExporter for keying material derivation
- ✅ EXTRACTOR-dtls_srtp label per RFC 5764 §4.2
- ✅ 88-byte keying material layout (2×32 keys + 2×12 salts)
- ✅ UseSrtpExtension encode/decode for use_srtp negotiation
- ✅ HKDF-SHA384 PRF for CNSA 2.0 compliance

### ✅ Phase 18.5: RFC Compliance Gap Resolution

**Goal**: Address critical and high priority RFC compliance gaps

**P0 Critical - DTLS Security** (RFC 6347 §4.2.4, §4.2.6) ✅

- ✅ Certificate chain verification with trusted CA store
- ✅ Self-signed certificate fingerprint validation for WebRTC
- ✅ Finished message verification with PRF-based verify_data
- ✅ CNSA 2.0 compliant (SHA-384, P-384/P-521 only)

**P0 Critical - ICE Consent** (RFC 7675 §6) ✅

- ✅ Consent revocation with explicit state management
- ✅ Revocation reasons (UserInitiated, SecurityConcern, etc.)
- ✅ Immediate media transmission stop on revocation

**P0 Critical - TURN Indications** (RFC 5766 §9, §12) ✅

- ✅ Send indication for client-to-peer data
- ✅ Data indication for peer-to-client data
- ✅ XOR-PEER-ADDRESS and DATA attribute handling

**P0 Critical - SIP Redirect** (RFC 3261 §13.2.2.4) ✅

- ✅ 3xx response processing with Contact parsing
- ✅ Priority-based target selection (q-value)
- ✅ Loop detection and max redirect limits

**P1 High - Flow Maintenance** (RFC 5626 §5.2) ✅

- ✅ Multi-transport keepalive (STUN, CRLF, WebSocket)
- ✅ Flow state machine (Active, Probing, Suspect, Failed)
- ✅ Flow token generation and tracking

**P1 High - Aggressive Nomination** (RFC 8445 §7.2.2) ✅

- ✅ USE-CANDIDATE in every check for controlling agent
- ✅ Configuration flag and automatic application
- ✅ Explicit nomination control methods

**P1 High - Media Modification** (RFC 3264 §8.4) ✅

- ✅ Offer/answer validation rules
- ✅ Direction negotiation table
- ✅ Hold/resume support
- ✅ Stream enable/disable (port=0)

**P1 High - Long-Term Credential** (RFC 5389 §10.2) ✅

- ✅ Challenge-response authentication flow
- ✅ Nonce generation with HMAC signatures
- ✅ Stale nonce detection and refresh
- ✅ CNSA 2.0 compliant (SHA-384 instead of MD5)

### ✅ Phase 18.6: P2 Medium Priority RFC Compliance

**Goal**: Address medium priority RFC compliance gaps for feature completeness

**P2 Medium - Proxy GRUU Routing** (RFC 5627 §5.1) ✅

- ✅ GruuRouter for GRUU-based request routing
- ✅ AOR and instance-id extraction from GRUU
- ✅ Lowest reg-id selection for multiple flows
- ✅ Path header forwarding support
- ✅ Routing result types: Resolved, Expired, NotFound

**P2 Medium - RTCP Timing Rules** (RFC 3550 §6.3.5) ✅

- ✅ RtcpScheduler implementing Appendix A.7 algorithm
- ✅ Deterministic interval based on bandwidth/members
- ✅ [0.5, 1.5] randomization per RFC 3550 §6.3.5
- ✅ Sender/receiver bandwidth separation (25%/75%)
- ✅ Timer reconsideration for membership changes

**P2 Medium - Event Package Validation** (RFC 6665 §7.2) ✅

- ✅ EventPackageRegistry with IANA registrations
- ✅ Validation result types: Valid, UnregisteredAllowed, Invalid
- ✅ Custom package extension support
- ✅ Strict vs permissive validation modes

**P2 Medium - SDP Repeat Times** (RFC 4566 §5.11) ✅

- ✅ RepeatTimes (r= line) support
- ✅ TimeValue with compact notation (d/h/m/s)
- ✅ Parsing and generation roundtrip
- ✅ Validation (interval, duration, offsets)

### ✅ Phase 18.7: P3 Low Priority RFC Compliance

**Goal**: Address low priority RFC compliance gaps (edge cases)

**P3 Low - Multicast Streams** (RFC 3264 §6.2) ✅

- ✅ MulticastAddress struct with IPv4/IPv6 scope detection
- ✅ MulticastNegotiator for offer/answer multicast validation
- ✅ MulticastScope enum (NodeLocal to Global)
- ✅ is_multicast_address() and is_multicast_media() helpers
- ✅ TTL validation and administrative scope checking

**P3 Low - Translators/Mixers** (RFC 3550 §7) ✅

- ✅ RtpTranslator for SSRC-preserving packet forwarding
- ✅ RtpMixer for multi-source mixing with CSRC list
- ✅ SsrcCollisionDetector for loop prevention
- ✅ TranslatorRtcpBuilder for combined RTCP reports
- ✅ MAX_CSRC_COUNT constant (15) per RFC 3550
- ✅ validate_csrc_list() for CSRC validation

**P3 Low - Proxy Forwarding** (RFC 3261 §16.6) ✅

- ✅ ProxyContext for proxy configuration
- ✅ RequestForwarder with full §16.6 compliance
- ✅ Max-Forwards validation and decrement
- ✅ Via header insertion at correct position
- ✅ Record-Route header insertion
- ✅ Loop detection via Via inspection
- ✅ ResponseProcessor for upstream forwarding
- ✅ ForkingMode enum (None, Parallel, Sequential)
- ✅ Best response selection (6xx > 2xx > 3xx priority)

### ✅ Phase 19: SIP Authentication & Security

**Goal**: Production-grade SIP security

**SIP Digest Authentication** (RFC 3261 Section 22) ✅

- ✅ HTTP Digest computation (MD5, SHA-256, SHA-512-256) in proto-sip
- ✅ Nonce generation and validation in proto-registrar
- ✅ qop=auth and qop=auth-int support
- ✅ Authentication state management with nonce count tracking
- ✅ Stale nonce detection and renewal
- ✅ AuthenticatedRegistrar combining registrar + authenticator

**Topology Hiding** (RFC 3323/RFC 5765) ✅

- ✅ TopologyHidingConfig in proto-b2bua
- ✅ TopologyHider in proto-sip with Basic/Aggressive modes
- ✅ Via header stripping/rewriting implementation
- ✅ Contact header anonymization
- ✅ Record-Route manipulation with external host substitution
- ✅ Call-ID obfuscation with bidirectional mapping

**SRTP-SDES Key Exchange** (RFC 4568) ✅

- ✅ Parse crypto attributes from SDP (CryptoAttribute struct)
- ✅ CipherSuite enum (AES_CM_128_HMAC_SHA1_80/32, AEAD_AES_128/256_GCM)
- ✅ KeyParams with master key/salt extraction
- ✅ SrtpNegotiator for cipher suite selection
- ✅ DTLS-SRTP vs SDES protocol detection helpers

### ⏳ Phase 20: WebRTC & Modern Transports

**Goal**: WebRTC gateway support

**WebSocket SIP Transport** (RFC 7118)

- [ ] Add WebSocket listener to sbc-transport
- [ ] Implement SIP-over-WebSocket framing
- [ ] Add secure WebSocket (WSS) support
- [ ] Handle WebSocket ping/pong keepalives

**WebRTC Gateway**

- [ ] SIP-to-WebRTC call bridging
- [ ] SDP munging for WebRTC compatibility
- [ ] ICE candidate trickling support
- [ ] SRTP-to-DTLS-SRTP interworking

### ✅ Phase 21: Advanced SBC Features

**Goal**: Enterprise-grade SBC functionality

**Header Manipulation Engine**

- ✅ Configurable header rewrite rules (`proto-sip/manipulation.rs`)
- ✅ Regular expression substitution (basic pattern support)
- ✅ Header insertion/deletion policies
- ✅ Per-trunk header manipulation

**Call Recording & Forking** (RFC 7865/7866)

- ✅ SIPREC support for call recording (`uc-siprec` crate)
- ✅ Media forking to recording server
- ✅ Metadata generation for recordings (XML per RFC 7865)

**QoS & Traffic Management**

- ✅ DSCP marking for SIP/RTP packets (`uc-transport/qos.rs`)
- ✅ Bandwidth management per trunk
- ✅ Call admission control by capacity (`uc-policy/cac.rs`)

**DNS Integration** (Deferred to Phase 22)

- [ ] ENUM lookup (RFC 6116)
- [ ] DNS SRV for SIP routing (RFC 3263)
- [ ] NAPTR records support
- [ ] DNS caching and TTL management

### ⏳ Phase 22: High Availability & Clustering

**Goal**: Carrier-grade reliability

**State Replication**

- [ ] Call state synchronization between nodes
- [ ] Registration database replication
- [ ] Distributed rate limiting state

**Geographic Redundancy**

- [ ] Active-active clustering
- [ ] Session takeover on failover
- [ ] Load balancing strategies

**External Integrations**

- [ ] RADIUS/Diameter for AAA
- [ ] External database backends (PostgreSQL, Redis)
- [ ] SNMP traps and monitoring
- [ ] Syslog forwarding

### ⏳ Phase 23: Specialized Protocols

**Goal**: Complete protocol coverage

**T.38 Fax Relay** (RFC 4612)

- [ ] T.38 over UDP/TCP
- [ ] Audio-to-T.38 gateway
- [ ] Error correction modes

**SIP over SCTP** (RFC 4168)

- [ ] SCTP transport support
- [ ] Multi-homing for reliability

---

## Known TODOs in Code

| Location | Description | Priority | Status |
|----------|-------------|----------|--------|
| `proto-dtls/connection.rs` | DTLS handshake is placeholder | High | ✅ Done |
| `proto-dtls/connection.rs` | send/recv not implemented | High | ✅ Done |
| `proto-ice/agent.rs` | Server-reflexive/relay gathering | High | ✅ Done |
| `uc-codecs/opus.rs` | Opus encode/decode stubs | Medium | ✅ Done |
| `uc-codecs/g722.rs` | G.722 encode/decode stubs | Medium | ✅ Done |
| `proto-dtls/verify.rs` | Certificate validation | Medium | ✅ Done |
| `proto-dtls/verify.rs` | Signature verification | Medium | ✅ Done |
| `proto-registrar/authentication.rs` | Digest authentication | High | ✅ Done |
| Various crates (73 files) | Cleanup clippy warning allows (cosmetic) | Low | ✅ Done |

---

## RFC Compliance Status

| RFC | Title | Status |
|-----|-------|--------|
| RFC 2474 | Differentiated Services | ✅ Implemented (DSCP marking) |
| RFC 2617 | HTTP Digest Authentication | ✅ Implemented (MD5, SHA-256, SHA-512-256) |
| RFC 3261 | SIP Core | ✅ Enhanced (~98% compliant, redirect + proxy forwarding) |
| RFC 3264 | Offer/Answer | ✅ Enhanced (media modification, multicast streams) |
| RFC 3550 | RTP | ✅ Enhanced (RTCP timing, translators/mixers) |
| RFC 3711 | SRTP | ✅ Implemented (CNSA 2.0) |
| RFC 4412 | SIP Priority | ✅ Implemented (emergency call priority) |
| RFC 4566 | SDP | ✅ Enhanced (repeat times r= line) |
| RFC 4568 | SDES Key Exchange | ✅ Implemented (crypto attribute parsing) |
| RFC 4594 | DSCP Configuration | ✅ Implemented (QoS policy manager) |
| RFC 5389 | STUN | ✅ Enhanced (long-term credential) |
| RFC 5626 | SIP Outbound | ✅ Enhanced (flow maintenance) |
| RFC 5627 | GRUU | ✅ Enhanced (proxy GRUU routing) |
| RFC 5764 | DTLS-SRTP | ✅ Implemented (key export) |
| RFC 5766 | TURN | ✅ Enhanced (Send/Data indications) |
| RFC 5853 | SBC Requirements | ✅ Implemented |
| RFC 6347 | DTLS 1.2 | ✅ Enhanced (certificate verification, Finished validation) |
| RFC 6665 | SIP Events | ✅ Enhanced (event package validation) |
| RFC 7092 | B2BUA Taxonomy | ✅ Implemented |
| RFC 7675 | STUN Consent | ✅ Enhanced (consent revocation) |
| RFC 7865 | SIPREC Metadata | ✅ Implemented (recording metadata XML) |
| RFC 7866 | SIPREC Protocol | ✅ Implemented (session recording) |
| RFC 8445 | ICE | ✅ Enhanced (aggressive nomination, consent, keepalives) |
| RFC 8224 | STIR | ✅ Implemented (ES384) |
| RFC 8225 | PASSporT | ✅ Implemented (ES384) |

---

## Security Compliance

### CNSA 2.0

- ✅ AES-256-GCM only (AES-128 forbidden)
- ✅ SHA-384/SHA-512 only (SHA-256 forbidden)
- ✅ P-384/P-521 curves only (P-256 forbidden)
- ✅ ES384 for STIR/SHAKEN (ES256 forbidden)
- ✅ TLS 1.3 with TLS_AES_256_GCM_SHA384

### NIST 800-53 Rev5

- ✅ AU-2: Event Logging
- ✅ CM-2: Baseline Configuration
- ✅ CM-6: Configuration Settings
- ✅ CM-7: Least Functionality
- ✅ SC-5: DoS Protection
- ✅ SC-7: Boundary Protection
- ✅ SC-13: Cryptographic Protection
- ✅ IA-9: Service Identification (STIR/SHAKEN)
- ✅ IR-4: Incident Handling

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
