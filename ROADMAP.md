# USG Unified Communications SBC - Roadmap

This document outlines the development roadmap for the USG Session Border Controller.

## Completed Phases

### ✅ Phase 1-2: Foundation & Transport
- Workspace structure with 28 crates in 9 layers
- Foundation crates: `sbc-types`, `sbc-crypto`, `sbc-audit`, `sbc-config`
- CNSA 2.0 cryptographic compliance enforcement
- NIST 800-53 Rev5 audit logging infrastructure
- Transport crates: `sbc-transport`, `sbc-dtls`

### ✅ Phase 3: Protocol Core
- `sbc-sip`: SIP message parsing and generation
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

### ✅ Phase 6: SIP Application
- `sbc-transaction`: SIP transaction state machine
- `sbc-dialog`: SIP dialog management with session timers
- `sbc-b2bua`: B2BUA core per RFC 7092
- `sbc-registrar`: SIP registration with B2BUA and proxy modes

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

**Current Status**: 909 tests passing, Phase 17 in progress

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

- [x] Integrate sbc-sip with transport layer
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

### ⏳ Phase 18: SIP Authentication & Security
**Goal**: Production-grade SIP security

**SIP Digest Authentication** (RFC 3261 Section 22)
- [ ] Implement HTTP Digest authentication for SIP
- [ ] Add nonce generation and validation
- [ ] Support qop=auth and qop=auth-int
- [ ] Add authentication state to registrar

**Topology Hiding** (RFC 5765)
- [ ] Via header stripping/rewriting
- [ ] Contact header anonymization
- [ ] Record-Route manipulation
- [ ] Call-ID obfuscation

**SRTP-SDES Key Exchange** (RFC 4568)
- [ ] Parse crypto attributes from SDP
- [ ] Generate SRTP keys from SDES
- [ ] Support fallback from DTLS-SRTP to SDES

### ⏳ Phase 19: WebRTC & Modern Transports
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

### ⏳ Phase 20: Advanced SBC Features
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
| RFC 3261 | SIP Core | ✅ Implemented |
| RFC 4566 | SDP | ✅ Implemented |
| RFC 3264 | Offer/Answer | ✅ Implemented |
| RFC 3550 | RTP | ✅ Implemented |
| RFC 3711 | SRTP | ✅ Implemented (CNSA 2.0) |
| RFC 5853 | SBC Requirements | ✅ Implemented |
| RFC 7092 | B2BUA Taxonomy | ✅ Implemented |
| RFC 8445 | ICE | ✅ Implemented |
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
