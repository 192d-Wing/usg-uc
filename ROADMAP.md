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

**Current Status**: 1000+ tests passing, Phase 18 complete + proto-* crate extraction with RFC compliance + P0/P1 compliance gaps addressed

---

## Completed Development Phases

### ✅ Phase 10: Async Runtime Integration
**Goal**: Wire up tokio async runtime for real network I/O

- [x] Add tokio dependency to sbc-daemon
- [x] Implement async transport listeners (UDP)
- [x] Create async event loop for message processing
- [x] Add Unix signal handling (SIGTERM, SIGINT, SIGHUP)
- [x] Implement async health check polling

### ✅ Phase 11: SIP Stack Integration
**Goal**: Connect SIP components into working call flow

- [x] Integrate proto-sip with transport layer
- [x] Wire sbc-transaction for request/response handling
- [x] Connect sbc-dialog for call state management
- [x] Enable sbc-b2bua for call bridging
- [x] Integrate sbc-registrar for user registration

### ✅ Phase 12: Media Pipeline
**Goal**: Enable RTP/SRTP media relay

- [x] Connect sbc-rtp with UDP transport
- [x] Integrate sbc-srtp for encrypted media
- [x] Wire sbc-media-engine for relay/pass-through
- [x] Add DTLS-SRTP key exchange via sbc-dtls
- [x] Enable codec transcoding via sbc-codecs

### ✅ Phase 13: ICE/NAT Traversal
**Goal**: Full NAT traversal support

- [x] Integrate sbc-stun for connectivity checks
- [x] Enable sbc-turn for relay allocation
- [x] Connect sbc-ice for candidate gathering/selection
- [x] Add ICE-lite mode for server-side optimization

### ✅ Phase 14: REST API Server
**Goal**: HTTP management interface

- [x] Add HTTP server to sbc-daemon (axum)
- [x] Expose sbc-api routes for management
- [x] Implement sbc-metrics Prometheus endpoint
- [x] Add sbc-health HTTP probes (/healthz, /readyz)
- [ ] Enable sbc-cdr export endpoints (future)

### ✅ Phase 15: Production Hardening
**Goal**: Production-ready deployment

- [x] Implement graceful shutdown with connection draining
- [x] Add configuration hot-reload via SIGHUP
- [x] Enable TLS for API server (HTTPS with CNSA 2.0 compliant config)
- [x] Implement rate limiting per sbc-dos-protection
- [ ] Add distributed tracing (OpenTelemetry) (future)
- [ ] Enable TLS certificate rotation (future)

### ✅ Phase 16: Deployment & Operations
**Goal**: Container and orchestration support

- [x] Create multi-stage Dockerfile (non-root, minimal runtime)
- [x] Add Kubernetes manifests (Namespace, Deployment, Service, ConfigMap, RBAC, PDB, NetworkPolicy)
- [x] Create Helm chart for parameterized deployment
- [x] Add Prometheus ServiceMonitor
- [x] Document operational runbook

---

## Current Development Phase

### 🔄 Phase 17: Complete Stub Implementations

**Goal**: Make placeholder implementations functional

**DTLS Integration** (sbc-dtls) ✅

- [x] Custom DTLS 1.2 implementation with aws-lc-rs (replaced webrtc-dtls)
- [x] DTLS record layer with AES-256-GCM encryption
- [x] Full handshake state machine (client and server)
- [x] TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite (0xC02C)
- [x] P-384 ECDHE key exchange
- [x] TLS 1.2 PRF with HMAC-SHA384
- [x] SRTP keying material export (RFC 5764)
- [x] Anti-replay protection with sliding window
- [x] Cookie-based DoS protection (HelloVerifyRequest)

**ICE Candidate Gathering** (sbc-ice) ✅

- [x] STUN client implementation for server-reflexive candidates
- [x] TURN client implementation for relay candidates
- [x] Candidate gathering state machine in ICE agent
- [x] TURN authentication support

**Codec Implementations** (sbc-codecs) ✅

- [x] G.722 ADPCM encoder/decoder (pure Rust implementation)
- [x] QMF filter banks for sub-band splitting
- [x] Opus FFI bindings (optional `opus-ffi` feature via audiopus)
- [x] Fixed clippy warnings across codec modules

---

## Future Development Phases

### ✅ Phase 18: RFC Compliance Completion

**Goal**: Complete remaining RFC compliance gaps

**Reliable Provisional Responses** (RFC 3262) ✅

- [x] 100rel extension support in proto-transaction
- [x] PRACK method transaction state machine (ReliableProvisionalTracker)
- [x] RAck header parsing and validation
- [x] Provisional response retransmission with T1/T2 timers

**Event Framework** (RFC 6665) ✅

- [x] SUBSCRIBE/NOTIFY dialog support in proto-dialog
- [x] Subscription and Notifier state management
- [x] Event package definitions (presence, dialog, message-summary, refer, reg)
- [x] SubscriptionStateHeader parsing and formatting

**REGISTER Response** (RFC 3261 §10.3) ✅

- [x] format_contacts() echoes registered contacts with expiry
- [x] remaining_seconds() for binding time-to-expiry
- [x] Service-Route header support in RegisterResponse
- [x] Path header support in RegisterRequest/Response

**Early Media** (RFC 3960) ✅

- [x] EarlyMediaHandler for 183 Session Progress
- [x] EarlyMediaMode: None, LocalRingback, Relay, Gate
- [x] Per-leg early media session tracking
- [x] Mode-based early media disposition

**ICE Connectivity Checks** (RFC 8445 §6.2) ✅

- [x] STUN-based connectivity check implementation in proto-ice
- [x] ConnectivityChecker with triggered check queue
- [x] IceStunServer for Binding request/response handling
- [x] USE-CANDIDATE nomination and role conflict (487) handling
- [x] CheckResult states: Success, Failure, Timeout, RoleConflict, InvalidCredentials

**ICE Consent & Keepalives** (RFC 8445 §9-10, RFC 7675) ✅

- [x] ConsentTracker with 5-second check interval
- [x] 30-second consent timeout per RFC 7675
- [x] KeepaliveTracker with 15-second STUN Binding indications
- [x] ConsentKeepaliveManager combining consent and keepalive logic
- [x] ConsentState: Pending, Granted, Expired

**DTLS-SRTP Key Export** (RFC 5764) ✅

- [x] SrtpKeyExporter for keying material derivation
- [x] EXTRACTOR-dtls_srtp label per RFC 5764 §4.2
- [x] 88-byte keying material layout (2×32 keys + 2×12 salts)
- [x] UseSrtpExtension encode/decode for use_srtp negotiation
- [x] HKDF-SHA384 PRF for CNSA 2.0 compliance

### ✅ Phase 18.5: RFC Compliance Gap Resolution

**Goal**: Address critical and high priority RFC compliance gaps

**P0 Critical - DTLS Security** (RFC 6347 §4.2.4, §4.2.6) ✅

- [x] Certificate chain verification with trusted CA store
- [x] Self-signed certificate fingerprint validation for WebRTC
- [x] Finished message verification with PRF-based verify_data
- [x] CNSA 2.0 compliant (SHA-384, P-384/P-521 only)

**P0 Critical - ICE Consent** (RFC 7675 §6) ✅

- [x] Consent revocation with explicit state management
- [x] Revocation reasons (UserInitiated, SecurityConcern, etc.)
- [x] Immediate media transmission stop on revocation

**P0 Critical - TURN Indications** (RFC 5766 §9, §12) ✅

- [x] Send indication for client-to-peer data
- [x] Data indication for peer-to-client data
- [x] XOR-PEER-ADDRESS and DATA attribute handling

**P0 Critical - SIP Redirect** (RFC 3261 §13.2.2.4) ✅

- [x] 3xx response processing with Contact parsing
- [x] Priority-based target selection (q-value)
- [x] Loop detection and max redirect limits

**P1 High - Flow Maintenance** (RFC 5626 §5.2) ✅

- [x] Multi-transport keepalive (STUN, CRLF, WebSocket)
- [x] Flow state machine (Active, Probing, Suspect, Failed)
- [x] Flow token generation and tracking

**P1 High - Aggressive Nomination** (RFC 8445 §7.2.2) ✅

- [x] USE-CANDIDATE in every check for controlling agent
- [x] Configuration flag and automatic application
- [x] Explicit nomination control methods

**P1 High - Media Modification** (RFC 3264 §8.4) ✅

- [x] Offer/answer validation rules
- [x] Direction negotiation table
- [x] Hold/resume support
- [x] Stream enable/disable (port=0)

**P1 High - Long-Term Credential** (RFC 5389 §10.2) ✅

- [x] Challenge-response authentication flow
- [x] Nonce generation with HMAC signatures
- [x] Stale nonce detection and refresh
- [x] CNSA 2.0 compliant (SHA-384 instead of MD5)

### ⏳ Phase 19: SIP Authentication & Security
**Goal**: Production-grade SIP security

**SIP Digest Authentication** (RFC 3261 Section 22)

- [x] HTTP Digest computation (MD5, SHA-256, SHA-512-256) in proto-sip
- [ ] Nonce generation and validation in proto-registrar
- [ ] qop=auth and qop=auth-int support
- [ ] Authentication state management

**Topology Hiding** (RFC 5765)

- [x] TopologyHidingConfig in proto-b2bua
- [ ] Via header stripping/rewriting implementation
- [ ] Contact header anonymization
- [ ] Record-Route manipulation
- [ ] Call-ID obfuscation

**SRTP-SDES Key Exchange** (RFC 4568)

- [ ] Parse crypto attributes from SDP
- [ ] Generate SRTP keys from SDES
- [ ] Support fallback from DTLS-SRTP to SDES

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

### ⏳ Phase 21: Advanced SBC Features
**Goal**: Enterprise-grade SBC functionality

**Header Manipulation Engine**
- [ ] Configurable header rewrite rules
- [ ] Regular expression substitution
- [ ] Header insertion/deletion policies
- [ ] Per-trunk header manipulation

**Call Recording & Forking** (RFC 7866)
- [ ] SIPREC support for call recording
- [ ] Media forking to recording server
- [ ] Metadata generation for recordings

**QoS & Traffic Management**
- [ ] DSCP marking for SIP/RTP packets
- [ ] Bandwidth management per trunk
- [ ] Call admission control by capacity

**DNS Integration**
- [ ] ENUM lookup (RFC 6116)
- [ ] DNS SRV for SIP routing (RFC 3263)
- [ ] NAPTR records support
- [ ] DNS caching and TTL management

### ⏳ Phase 21: High Availability & Clustering
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

### ⏳ Phase 22: Specialized Protocols
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
| `sbc-dtls/connection.rs` | DTLS handshake is placeholder | High | Done |
| `sbc-dtls/connection.rs` | send/recv not implemented | High | Done |
| `sbc-ice/agent.rs` | Server-reflexive/relay gathering | High | Done |
| `sbc-codecs/opus.rs` | Opus encode/decode stubs | Medium | Done |
| `sbc-codecs/g722.rs` | G.722 encode/decode stubs | Medium | Done |
| `sbc-dtls/handshake.rs` | Certificate validation | Medium | Pending |
| `sbc-dtls/handshake.rs` | Signature verification | Medium | Pending |
| `sbc-registrar/registrar.rs` | Digest authentication | High | Pending |

---

## RFC Compliance Status

| RFC | Title | Status |
|-----|-------|--------|
| RFC 3261 | SIP Core | ✅ Enhanced (~95% compliant, redirect handling) |
| RFC 3264 | Offer/Answer | ✅ Enhanced (media modification rules) |
| RFC 4566 | SDP | ✅ Implemented |
| RFC 3550 | RTP | ✅ Implemented |
| RFC 3711 | SRTP | ✅ Implemented (CNSA 2.0) |
| RFC 5389 | STUN | ✅ Enhanced (long-term credential) |
| RFC 5626 | SIP Outbound | ✅ Enhanced (flow maintenance) |
| RFC 5764 | DTLS-SRTP | ✅ Implemented (key export) |
| RFC 5766 | TURN | ✅ Enhanced (Send/Data indications) |
| RFC 5853 | SBC Requirements | ✅ Implemented |
| RFC 6347 | DTLS 1.2 | ✅ Enhanced (certificate verification, Finished validation) |
| RFC 7092 | B2BUA Taxonomy | ✅ Implemented |
| RFC 7675 | STUN Consent | ✅ Enhanced (consent revocation) |
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
