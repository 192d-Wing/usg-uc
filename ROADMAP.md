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

**Current Status**: 1750+ tests passing, Phases 1-25 complete, Phase 15 fully complete, Phase 22 storage backends complete, Phase 24.30-24.38 complete, Phase 25 100% RFC 9260 compliance achieved, Enterprise Features in progress

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
- ✅ CDR export endpoints (list, export, stats, search, purge)

### ✅ Phase 15: Production Hardening

**Goal**: Production-ready deployment

- ✅ Implement graceful shutdown with connection draining
- ✅ Add configuration hot-reload via SIGHUP
- ✅ Enable TLS for API server (HTTPS with CNSA 2.0 compliant config)
- ✅ Implement rate limiting per sbc-dos-protection
- ✅ Add distributed tracing (OpenTelemetry) via `uc-telemetry` crate
- ✅ Enable TLS certificate rotation via `ReloadableTlsAcceptor`

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

### ✅ Phase 20: WebRTC & Modern Transports

**Goal**: WebRTC gateway support

**New Crate**: `uc-webrtc`

**WebSocket SIP Transport** (RFC 7118)

- ✅ WebSocket transport in `uc-transport/websocket.rs`
- ✅ SIP-over-WebSocket framing (text frames for SIP messages)
- ✅ Secure WebSocket (WSS) support
- ✅ WebSocket ping/pong keepalives
- ✅ WebSocketListener for accepting connections

**WebRTC Gateway** (`uc-webrtc` crate)

- ✅ `WebRtcGateway` for SIP-to-WebRTC call bridging
- ✅ `SdpMunger` for WebRTC SDP compatibility
- ✅ `TrickleIce` for ICE candidate trickling (RFC 8838)
- ✅ `WebRtcSession` and `SessionManager` for session tracking
- ✅ DTLS-SRTP support via existing `proto-dtls` integration

**Tests**: 24 new tests across WebRTC components

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

**DNS Integration** (`uc-dns` crate) ✅

- ✅ ENUM lookup (RFC 6116) with number-to-domain conversion
- ✅ DNS SRV for SIP routing (RFC 3263) with weighted selection
- ✅ NAPTR records support for transport selection
- ✅ DNS caching with TTL management
- ✅ SIP resolver combining NAPTR → SRV → A/AAAA lookups
- ✅ Hickory-resolver integration for actual DNS queries (optional `resolver` feature)

### ✅ Phase 22: High Availability & Clustering

**Goal**: Carrier-grade reliability

**New Crates**

- ✅ `uc-cluster`: Core clustering primitives (nodes, membership, failover, quorum)
- ✅ `uc-discovery`: Service discovery (static, DNS SRV/A, Kubernetes)
- ✅ `uc-storage`: Storage backends (in-memory, Redis, PostgreSQL)
- ✅ `uc-state-sync`: State replication engine with CRDTs
- ✅ `uc-aaa`: AAA integration (RADIUS and Diameter clients)
- ✅ `uc-snmp`: SNMP trap generation
- ✅ `uc-syslog`: RFC 5424 syslog forwarding

**Cluster Management**

- ✅ `NodeId`, `NodeRole` (Primary/Secondary/Witness), `NodeState` types
- ✅ `ClusterMembership` with quorum policies (Majority, All, Count, Weighted)
- ✅ `FailoverCoordinator` with automatic and manual failover
- ✅ `SessionTakeoverHandler` trait for session migration
- ✅ Heartbeat-based health monitoring with suspect/dead thresholds
- ✅ Failover strategies: PreferSameZone, PreferSameRegion, LeastLoaded, Priority

**Service Discovery**

- ✅ `StaticDiscovery` for configured peer lists
- ✅ `DnsDiscovery` with SRV and A/AAAA lookup via hickory-resolver
- ✅ `KubernetesDiscovery` with Kubernetes Endpoints API (feature-gated)
- ✅ `GossipProtocol` for SWIM-style failure detection
- ✅ Weighted peer selection per RFC 2782

**Storage Backends**

- ✅ `StorageBackend` trait with get/set/delete/keys/increment
- ✅ `InMemoryBackend` with TTL support and pattern matching
- ✅ `RedisBackend` with bb8 connection pooling (feature = "redis")
- ✅ `PostgresBackend` with sqlx and auto-migration (feature = "postgres")
- ✅ `AsyncLocationService` in proto-registrar for cache-aside storage integration

**State Synchronization**

- ✅ CRDT implementations: `GCounter`, `PNCounter`, `LWWRegister`
- ✅ `StateReplicator` with sync/async/semi-sync modes
- ✅ `ReplicationMessage` protocol for wire format
- ✅ `StateSnapshot` for bulk state transfer with chunking

**External Integrations**

- ✅ `RadiusClient` for RADIUS authentication and accounting (using `radius-proto` from usg-radius)
- ✅ `DiameterClient` for Diameter authentication (3GPP Cx/Dx interface for IMS)
  - RFC 6733 Diameter base protocol
  - 3GPP TS 29.228/229 Cx/Dx interface for HSS communication
  - Capabilities Exchange (CER/CEA), Watchdog (DWR/DWA)
  - User-Authorization (UAR/UAA), Multimedia-Auth (MAR/MAA), Server-Assignment (SAR/SAA)
  - Feature-gated with `diameter` feature flag
- ✅ `SnmpTrapSender` with 14 trap types
- ✅ `SyslogForwarder` with RFC 5424 and BSD format support

**Configuration Integration**

- ✅ `sbc-config` feature flags: cluster, aaa, snmp, syslog
- ✅ Cluster API routes in `uc-api` (status, members, failover, drain, sync)

**Integration Tests** (`sbc-integration-tests`)

- ✅ Storage backend tests (basic ops, TTL, keys pattern, increment, health)
- ✅ Discovery tests (static discovery, health check, peer metadata)
- ✅ Membership tests (create, add/remove node, get node, view version)
- ✅ Registrar tests (AsyncLocationService CRUD, cache reload, health)
- ✅ End-to-end tests (cluster formation, registration flow, shared storage)
- ✅ Feature flags: `cluster`, `redis`, `postgres`

**Tests**: 125 new tests across Phase 22 crates + 23 integration tests

### ✅ Phase 23: Specialized Protocols

**Goal**: Complete protocol coverage

**New Crate**: `uc-t38`

**T.38 Fax Relay** (RFC 4612)

- ✅ T.38 over UDPTL transport with redundancy/FEC
- ✅ Audio-to-T.38 gateway with signal detection (CNG/CED)
- ✅ Error correction modes (none, redundancy, FEC)
- ✅ IFP packet encoding/decoding per ITU-T T.38
- ✅ T.30 signal handling (all phases A-E)
- ✅ T38Session management with state machine
- ✅ Goertzel algorithm for tone detection

**SIP over SCTP** (RFC 4168, RFC 9260)

- ✅ Pure Rust SCTP implementation in `uc-transport/sctp/`:
  - `chunk.rs`: All RFC 9260 chunk types (DATA, INIT, SACK, etc.)
  - `packet.rs`: Packet encoding with CRC32c checksum
  - `state.rs`: Full RFC 9260 Section 4 state machine
  - `mod.rs`: Public API (SctpAssociation, SctpListener, SctpConfig)
- ✅ Multi-homing support (add_peer_address, set_primary_path)
- ✅ Multi-stream support (StreamId, send_on_stream)
- ✅ SctpConfig with full SCTP parameters
- ✅ SctpAssociation implementing Transport + StreamTransport traits
- ✅ TransportType::Sctp added to uc-types
- ✅ 4-way handshake state machine (INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK)
- ✅ Graceful shutdown and abort handling
- ✅ DATA retransmission with T3-rtx timer integration
- ✅ Selective acknowledgment via gap ack block processing
- ✅ Fast retransmit for chunks with 3+ miss indications
- ✅ Flow control enforcement (peer rwnd and cwnd checks)
- ✅ Heartbeat sending with RTT timestamps
- ✅ Message fragmentation/reassembly based on path MTU
- ✅ Cryptographically secure random (rand crate)
- ✅ SctpAssociation stub deprecated in favor of ConnectedSctpAssociation
- ✅ UDP encapsulation for NAT traversal (RFC 6951)
  - `use_udp_encapsulation` and `udp_encap_config` in ConnectedSctpConfig
  - Builder methods: `with_udp_encapsulation()`, `with_udp_encap_ports()`
  - Automatic encapsulation/decapsulation in I/O paths
  - 8-byte overhead per packet for UDP header
- ✅ ECNE/CWR chunks for ECN support (RFC 9260 §3.3.11-12)
  - `EcneChunk`: echoes CE marks from IP header
  - `CwrChunk`: acknowledges congestion window reduction
  - Full encode/decode support in Chunk enum
- ✅ Comprehensive RFC 9260 compliance tests (76 tests in sctp_rfc9260_compliance.rs)

**Tests**: 25 new tests (T.38 crate), 137+ tests (SCTP)

### ✅ Phase 25: SCTP RFC 9260 Full Compliance

**Goal**: Complete RFC 9260 compliance for production-grade SCTP

**Critical Priority - Security & Correctness** ✅

- ✅ Verification tag validation (RFC 9260 §8.5.1)
  - Validate V-tag on all received packets
  - Reject packets with incorrect V-tag (except INIT/ABORT)
  - Proper V-tag handling during shutdown with T-bit support
  - `VerificationTagError` enum for detailed error reporting
- ✅ Cookie security hardening (RFC 9260 §5.1.3)
  - HMAC-SHA384 for cookie MAC (CNSA 2.0 compliant)
  - 48-byte cryptographically secure secret key
  - Cookie lifespan enforcement
  - Stale cookie detection and handling
- ✅ ERROR chunk handling (RFC 9260 §3.3.10)
  - Full ERROR chunk processing with all 14 cause codes
  - Error cause code parsing (Invalid Stream, Missing Parameter, etc.)
  - Graceful degradation on non-fatal errors (no association abort)
- ✅ ECN integration in congestion control (RFC 9260 §7.2.5)
  - Process ECNE chunks to reduce cwnd
  - Send CWR chunks to acknowledge ECN
  - `on_ecn_ce_received()` in CongestionController
  - Less aggressive than timeout (cwnd = ssthresh, not MTU)
- ✅ Per-path congestion control (RFC 9260 §7.1)
  - Separate cwnd/ssthresh per destination address via PathManager
  - Path-specific RTT estimation via RtoCalculator
  - Multi-homed congestion management with failover support

**Medium Priority - Protocol Features**

- ✅ ASCONF chunks for dynamic address config (RFC 5061)
  - ADD-IP and DELETE-IP parameter handling
  - SET-PRIMARY-ADDRESS support
  - ASCONF-ACK response generation
  - Serial number tracking for request/response correlation
- ✅ Forward TSN / Partial Reliability (RFC 3758)
  - PR-SCTP extension support
  - FORWARD-TSN chunk processing
  - Timed reliability and limited retransmissions
  - Per-stream sequence number advancement
- ✅ Stream Reset / RE-CONFIG (RFC 6525)
  - Outgoing/Incoming SSN Reset
  - Add/Delete streams dynamically
  - RE-CONFIG chunk encode/decode
  - Request/response sequence number tracking
- ✅ Path MTU Discovery (RFC 9260 §8.4)
  - PMTU probing with PAD chunks
  - ICMP Packet Too Big handling
  - Dynamic fragmentation threshold adjustment
  - `start_pmtu_probe()`, `on_pmtu_probe_success/failure()` methods
- ✅ T2-shutdown timer implementation (RFC 9260 §9.2)
  - Timer for SHUTDOWN-ACK retransmission
  - Proper shutdown state machine timing
  - Already implemented via existing T2-shutdown timer infrastructure
- ✅ Automatic heartbeat sending (RFC 9260 §8.3)
  - Periodic HEARTBEAT on idle paths
  - Configurable heartbeat interval
  - RTT update from HEARTBEAT-ACK
  - `should_send_heartbeat()` with timer integration
- ✅ Duplicate TSN detection (RFC 9260 §6.2)
  - Track received TSNs for duplicate detection
  - Report duplicates in SACK
  - Prevent replay attacks
- ✅ Full parameter validation (RFC 9260 §5.1.2)
  - Validate all INIT/INIT-ACK parameters
  - Unknown parameter handling (skip/report/abort)
  - Mandatory parameter presence checks
- ✅ Immediate flag handling (RFC 9260 §6.8)
  - I-bit in DATA chunks for immediate delivery
  - Skip bundling for immediate data
  - User-configurable immediate mode

**Lower Priority - Optimizations**

- ✅ SACK bundling optimization (RFC 9260 §6.2)
  - Bundle SACK with DATA when possible
  - Delayed SACK timer (T4-sack, 200ms default)
  - Immediate SACK for gap detection and every-other-DATA rule
  - `on_data_received()`, `should_send_sack()`, `try_bundle_sack()` methods
- ✅ Heartbeat bundling (RFC 9260 §8.3)
  - Bundle HEARTBEAT with DATA chunks
  - Reduce overhead on busy associations
  - `restart_heartbeat_timer()` tracks last data sent
- ✅ PAD chunk support (RFC 4820 / RFC 9260 §3.3.14)
  - `PadChunk` struct for PMTU probing
  - Arbitrary padding size support
  - Encode/decode roundtrip verified
- ✅ AUTH chunk support (RFC 4895)
  - `AuthChunk` struct with shared key ID and HMAC
  - `HmacId` enum: Reserved, Sha1, Sha256
  - HMAC length helpers per algorithm
  - Encode/decode roundtrip verified

### 🚧 Phase 24: SIP Soft Client (In Progress)

**Goal**: Native Windows SIP soft client for enterprise/government use

**New Crates** (`crates/client/`)

- 🚧 `client-types`: Shared types (CallState, SipAccount, AudioConfig, Contact)
- 🚧 `client-audio`: CPAL audio I/O, jitter buffer, RTP/SRTP pipeline
- 🚧 `client-sip-ua`: SIP User Agent (registration, call control, ICE/DTLS)
- 🚧 `client-core`: Application logic, settings persistence, event coordination
- 🚧 `client-gui-windows`: Windows GUI (egui), system tray, notifications

**Key Features**

- ✅ Smart card authentication only (CAC/PIV/SIPR token via mutual TLS)
- ✅ NO password-based digest auth (CNSA 2.0 compliance)
- ✅ TLS 1.3 only for signaling
- 🚧 CPAL for cross-platform audio I/O
- 🚧 Jitter buffer with adaptive sizing
- 🚧 ICE/STUN/TURN NAT traversal
- 🚧 DTLS-SRTP with AES-256-GCM
- 🚧 egui-based Windows GUI
- 🚧 System tray and Windows notifications
- 🚧 Certificate selection from Windows Certificate Store

**Phase 24.1: Foundation** ✅

- ✅ `client-types` crate with all shared types
- ✅ `CallState` enum (Idle → Dialing → Ringing → Connected → Terminated)
- ✅ `SipAccount` with `CertificateConfig` (no password fields)
- ✅ `CertificateSelectionMode`: PromptUser, SpecificCertificate, AutoSelect
- ✅ `RegistrationState` with smart card states (WaitingForPin, SmartCardNotPresent)
- ✅ `AudioConfig` with device selection and jitter buffer settings
- ✅ `Contact` and `CallHistoryEntry` for persistence
- ✅ Crate skeletons for client-audio, client-sip-ua, client-core, client-gui

**Phase 24.2: SIP User Agent** ✅

- ✅ `RegistrationAgent` using `proto-transaction::ClientNonInviteTransaction`
  - State management: Unregistered → Registering → Registered
  - Handles 200 OK, 401/407 rejection, 403, 423 responses
  - Registration refresh before expiry
- ✅ `CallAgent` using `proto-transaction::ClientInviteTransaction`
  - Outbound call flow: make_call → Dialing → Ringing → Connected
  - Hangup handling: CANCEL for pending, BYE for connected
  - SDP offer/answer event emission
  - Response handling for all status codes
- ✅ Mutual TLS client authentication (mTLS only, no digest auth)
- 🚧 Windows CryptoAPI integration for smart card certificates (Phase 24.4)

**Tests**: 10 new tests (client-sip-ua crate)

**Phase 24.3: Secure Media** ✅

- ✅ `IceHandler` for ICE candidate gathering via `proto-ice`
  - Host, server-reflexive (STUN), and relay (TURN) candidates
  - SDP candidate formatting and parsing
  - ICE role handling (controlling/controlled)
- ✅ `DtlsHandler` for DTLS handshake via `proto-dtls`
  - SRTP key derivation via DTLS-SRTP
  - Certificate fingerprint handling for SDP
  - Support for client and server roles
- ✅ `MediaSession` coordinated secure media pipeline
  - Orchestrates ICE + DTLS + SRTP setup
  - RtpPacket encryption/decryption
  - UDP socket management for media
  - State machine for session lifecycle
- ✅ All components use CNSA 2.0 compliant cryptography (AES-256-GCM, P-384, SHA-384)

**Tests**: 20 total tests (client-sip-ua crate)

**Phase 24.4: Application Core** ✅

- ✅ `settings.rs` - TOML-based settings persistence
  - GeneralSettings, NetworkSettings, UiSettings configuration
  - SettingsManager with atomic save (temp + rename)
  - Platform-specific paths via `directories` crate
- ✅ `contact_manager.rs` - Contact and call history storage
  - JSON-based ContactStore with CRUD operations
  - Contact search by name, phone number, or SIP URI
  - Call history with automatic trimming
- ✅ `call_manager.rs` - Call coordination
  - Bridges SIP UA and media sessions
  - SDP offer generation with ICE credentials
  - Integration with contact manager for history
- ✅ `app.rs` - Main application coordinator (ClientApp)
  - Account registration management
  - Event broadcasting to GUI
  - Graceful shutdown handling
- 🚧 Windows CryptoAPI integration for smart card certificates (Phase 24.5 or later)

**Tests**: 19 total tests (client-core crate)

**Phase 24.5: GUI Implementation** ✅

- ✅ egui-based main window with dark theme
- ✅ Dialer view with number pad and URI input
- ✅ Active call view with mute/hold/hangup controls and duration timer
- ✅ Contacts list view with search and favorites
- ✅ Settings view with Account, Audio, General, and About tabs
- ✅ System tray integration with show/exit menu items
- ✅ Event-driven architecture connecting GUI to client-core

**Phase 24.6: Polish & Security Hardening** ✅

- ✅ Windows toast notifications (NotificationManager with winrt-notification)
- ✅ Certificate store access (CertificateStore with auto-select for P-384)
- ✅ Memory zeroization (SmartCardPin, SessionToken, SrtpKeyMaterial)
- ✅ CNSA 2.0 compliance audit (CNSA_COMPLIANCE.md documentation)
- ✅ Sensitive types with [REDACTED] debug output

**Tests**: 69 total tests (client crates)

**Phase 24.7: Deployment & Packaging** ✅

- ✅ WiX v4.x installer configuration (usg-sip-client.wxs)
- ✅ MSI installer with registry entries and URI handlers
- ✅ PowerShell build script (build-installer.ps1)
- ✅ CNSA 2.0 compliant code signing (SHA-384)
- ✅ Application manifest (DPI awareness, UAC, visual styles)
- ✅ Build.rs for Windows resource embedding
- ✅ Portable ZIP package option
- ✅ Default settings configuration (default-settings.toml)
- ✅ License agreement (license.rtf)

**Phase 24.8: Audio Pipeline** ✅

- ✅ `client-audio` crate with full audio pipeline implementation
- ✅ `device.rs` - Audio device enumeration and management (CPAL 0.17)
  - Cross-platform input/output device listing
  - Device selection by name with fallback to default
  - Stream configuration for 8/16/48 kHz sample rates
- ✅ `jitter_buffer.rs` - Adaptive jitter buffer for RTP reordering
  - BTreeMap-based packet ordering by sequence number
  - Adaptive depth adjustment (40-200ms)
  - Packet loss detection and PLC signaling
  - Jitter calculation and statistics
- ✅ `stream.rs` - CPAL audio capture/playback streams
  - Ring buffer-based producer/consumer (ringbuf 0.4)
  - Support for i16 and f32 sample formats
  - Automatic mono mixdown from stereo
  - Non-blocking read/write operations
- ✅ `codec.rs` - Codec encode/decode pipeline
  - Unified CodecPipeline wrapper for G.711, G.722, Opus
  - Codec negotiation from local preferences and remote capabilities
  - Payload type mapping and SDP capability generation
- ✅ `rtp_handler.rs` - RTP packet send/receive
  - RtpTransmitter with sequence number and timestamp management
  - RtpReceiver with jitter buffer integration
  - SRTP encryption/decryption via proto-srtp
  - RTP statistics tracking
- ✅ `pipeline.rs` - Main audio pipeline coordinator
  - Orchestrates capture → encode → RTP → decode → playback
  - SRTP context management (separate TX/RX contexts)
  - Mute control and pipeline state management
  - Pipeline statistics aggregation

**Tests**: 72 total tests (client crates)

**Phase 24.9: Audio Integration** ✅

- ✅ `audio_session.rs` - Audio session management bridging media and audio
  - AudioSession coordinates MediaSession SRTP with AudioPipeline
  - AudioSessionConfig for flexible configuration
  - AudioSessionConfigBuilder for fluent API
  - 20ms audio processing loop with proper timing
  - Mute control propagation to audio pipeline
  - Statistics reporting every 5 seconds
- ✅ CallManager audio integration
  - Audio session lifecycle tied to call state (start on Connected, stop on Terminated)
  - Mute toggle updates both CallManager and AudioSession
  - Preferred codec configuration
  - Audio statistics access via `audio_stats()` method
- ✅ Event system for audio session events
  - Started, Stopped, StatsUpdate, Error events
  - Integration with application event loop

**Tests**: 76 total tests (client crates)

**Phase 24.10: Windows CryptoAPI Integration** ✅

- ✅ `cert_store.rs` - Windows Certificate Store access via CryptoAPI
  - `CertOpenStore` for system certificate store access (CERT_SYSTEM_STORE_CURRENT_USER)
  - `CertEnumCertificatesInStore` for certificate enumeration
  - Certificate parsing with full metadata extraction:
    - Subject CN and full X.500 DN
    - Issuer CN
    - Validity dates (NotBefore, NotAfter)
    - SHA-1 thumbprint via `CERT_HASH_PROP_ID`
    - Key algorithm detection (ECDSA P-256/P-384/P-521, RSA)
    - EC curve OID parsing from algorithm parameters
  - Time validity check via `CertVerifyTimeValidity`
  - Smart card reader detection via `CERT_KEY_PROV_INFO_PROP_ID`
    - Container name parsing for reader identification
    - Provider name detection for "Smart Card"/"Minidriver"
  - Cross-platform support:
    - Full Windows CryptoAPI implementation
    - Stub certificates for non-Windows development
  - CNSA 2.0 compliance:
    - Auto-select prefers ECDSA P-384 certificates
    - Key algorithm filtering for Client Authentication

**Tests**: 109 total tests (client crates)

**Phase 24.11: Certificate Selection UI** ✅

- ✅ New Security tab in Settings view
  - Smart card reader detection and display
  - Certificate list with detailed information
  - Visual indicators for key algorithm (P-384/P-256/RSA badges)
  - Smart card indicator (\u{1F4B3}) for certificates on smart cards
  - Validity status indicators (valid/expired)
- ✅ Certificate selection functionality
  - Manual certificate selection by thumbprint
  - Auto-select mode (prefers ECDSA P-384 for CNSA 2.0)
  - Refresh certificates button
- ✅ Certificate information display
  - Subject CN and issuer CN
  - Validity period (not before/not after)
  - Reader name for smart card certificates
  - Key algorithm with CNSA 2.0 compliance indication
- ✅ Integration with CertificateStore
  - `list_smart_card_readers()` method added
  - Real-time certificate loading with spinner
  - Error handling for certificate store access
- ✅ CNSA 2.0 compliance guidance in UI
  - P-384 certificates highlighted as preferred
  - RSA certificates marked as not recommended for government use

**Tests**: 109 total tests (client crates)

**Phase 24.12: Certificate Authentication Integration** ✅

- ✅ Certificate export functionality in CertificateStore
  - `get_certificate_chain()` - retrieves DER-encoded certificate chain
  - `has_private_key()` - verifies private key availability
  - Windows CryptoAPI: extracts raw certificate bytes from CERT_CONTEXT
  - Non-Windows: stub certificate generation for testing
- ✅ UseCertificate action in Settings UI
  - "Use Selected Certificate" button with lock icon
  - Verifies private key exists before configuration
  - Retrieves and stores certificate chain
- ✅ ClientApp certificate integration
  - `set_client_certificate()` for mTLS configuration
  - `client_certificate_thumbprint()` accessor
  - `has_client_certificate()` check
  - Certificate chain passed to CallManager DTLS credentials
- ✅ CallManager DTLS credential wiring
  - Certificate chain stored for MediaSession creation
  - Ready for DTLS handshake with smart card certificates
- ✅ Pending certificate support in GUI
  - Stores cert chain/thumbprint when ClientApp not initialized
  - Applies certificate when connecting

**Tests**: 109 total tests (client crates)

**Phase 24.13: PIN Entry UI** ✅

- ✅ PIN dialog implementation in client-gui
  - Modal dialog with masked password input
  - Lock icon and clear visual feedback
  - PIN attempt counter with lockout warning
  - Enter key submission support
  - Focus management for keyboard-first input
- ✅ PinOperation enum for tracking PIN context
  - `UseCertificate { thumbprint }` - certificate selection
  - `Register { account_id }` - SIP registration signing
  - `SignCall { call_id }` - DTLS call establishment
- ✅ Integration with CertStoreError::PinRequired
  - Automatic PIN dialog on smart card operations
  - Handles PinRequired and PinIncorrect errors
  - Smart card not present detection
- ✅ AppEvent extensions for async PIN handling
  - `PinRequired { operation, thumbprint }` event
  - `PinCompleted { success, error }` event
  - `PinOperationType` enum exported from client-core
- ✅ SettingsAction::PinRequired for Settings UI integration

**Tests**: 109+ total tests (client crates)

**Phase 24.14: SIP Transport Layer** ✅

- ✅ SipTransport module in client-core
  - TLS 1.3 connection management (CNSA 2.0 compliant)
  - Async send/receive for SIP messages
  - Connection pooling by peer address
  - Automatic reconnection on connection loss
- ✅ Message framing and parsing
  - SIP header detection with `\r\n\r\n` boundary
  - Content-Length header extraction (standard and compact form)
  - Complete message reassembly from stream
- ✅ TransportEvent enum for event-driven architecture
  - `ResponseReceived` - SIP response from peer
  - `RequestReceived` - incoming SIP request
  - `Connected` - TLS connection established
  - `Disconnected` - connection lost with reason
  - `Error` - transport-level errors
- ✅ Integration with ClientApp
  - SendRequest events routed to transport
  - Transport responses routed back to agents
  - Event polling with borrow-safe implementation
- ✅ InsecureCertVerifier for development
  - Accepts all certificates during development
  - Production deployment requires proper CA validation
- ✅ Unit tests for transport functionality
  - Header parsing tests
  - Content-Length extraction tests
  - Transport creation and shutdown tests
  - Event serialization tests

**Tests**: 45+ unit tests in client-core

**Phase 24.15: Call Signaling Integration** ✅

- ✅ CallManager call event polling
  - `poll_call_events()` method to retrieve pending events
  - `call_event_rx` receiver now stored and used
- ✅ Call request routing through SipTransport
  - INVITE, BYE, CANCEL, ACK sent via TLS transport
  - `handle_call_agent_event()` in ClientApp
- ✅ Call response routing from transport
  - CSeq-based routing to appropriate agent
  - REGISTER responses to RegistrationAgent
  - INVITE/BYE/CANCEL responses to CallManager
- ✅ Incoming request handling
  - `handle_sip_request()` in CallManager
  - Routes INVITE, BYE, CANCEL to appropriate handlers
  - `handle_incoming_invite()`, `handle_incoming_bye()`, `handle_incoming_cancel()`
- ✅ SIP Call-ID correlation
  - `find_call_by_sip_id()` in CallAgent
  - Maps SIP Call-ID header to application call ID

**Tests**: 45 unit tests in client-core

**Phase 24.16: Production Certificate Validation & mTLS** ✅

- ✅ Certificate verification modes
  - `Insecure` - Accept all certificates (development only)
  - `System` - Use OS trusted CA store via rustls-native-certs
  - `Custom` - Use user-provided CA certificates
- ✅ System CA loading
  - Windows: Windows Certificate Store (ROOT)
  - macOS: Keychain
  - Linux: /etc/ssl/certs
  - Handles partial load errors gracefully
- ✅ mTLS client authentication
  - `ClientCertResolver` for TLS handshake
  - Certificate chain configuration
  - Private key support for software certificates
  - Smart card certificate support (without private key)
- ✅ ClientApp integration
  - `set_client_certificate()` - configure cert chain
  - `set_client_certificate_with_key()` - full mTLS with private key
  - `set_verification_mode()` - change verification mode
  - `set_trusted_ca_certs()` - configure custom CAs
- ✅ Transport configuration
  - `TransportConfig` for builder pattern
  - Hot-reload of TLS configuration
  - Connection pooling compatible with config changes

**Tests**: 55 unit tests in client-core

**Phase 24.17: Response Sending for Incoming Calls** ✅

- ✅ `send_response()` method in SipTransport
  - Send SIP responses over existing TLS connections
  - Proper serialization and logging
- ✅ `build_response_from_request()` helper function
  - Copy Via, From, To, Call-ID, CSeq headers per RFC 3261 §8.2.6
  - To-tag generation for dialog establishment
  - Content-Length header handling
- ✅ `generate_tag()` for dialog To/From tags
- ✅ Incoming call handling in CallManager
  - `IncomingCallInfo` struct for tracking pending incoming calls
  - `handle_incoming_invite_from()` with source address
  - Automatic 100 Trying and 180 Ringing responses
  - 486 Busy Here when already in a call
- ✅ Accept/Reject incoming calls
  - `accept_incoming_call()` sends 200 OK with SDP answer
  - `reject_incoming_call()` sends 486 Busy or 603 Decline
  - `has_incoming_call()` and `incoming_calls()` accessors
- ✅ Helper functions for SIP header parsing
  - `parse_from_header()` extracts display name and URI
  - `extract_username_from_sip_uri()` extracts username
- ✅ CallEndReason::LocalReject for rejected incoming calls
- ✅ CallManagerEvent::SendResponse for transport-layer routing

**Tests**: 66 unit tests in client-core

**Phase 24.18: Incoming Call UI** ✅

- ✅ Incoming call dialog
  - Modal dialog with caller display name and SIP URI
  - Phone icon and "Incoming Call" header
  - Centered anchor with consistent styling
- ✅ Accept/Reject buttons
  - Green "Accept" button with circle emoji
  - Red "Reject" button with circle emoji
  - CallAction::Accept and CallAction::Reject variants
- ✅ IncomingCallAlert tracking
  - Stores call_id, remote_uri, remote_display_name
  - Dialog shows on IncomingCall event
  - Dialog clears on CallEnded event
- ✅ ClientApp integration
  - `accept_incoming_call()` calls CallManager
  - `reject_incoming_call()` calls CallManager
  - Transitions to Call view on accept
- ✅ System toast notifications (existing)
  - notify_incoming_call() already implemented
- ✅ Audio ringtone support (Phase 24.24)
  - Configurable ringtone file
  - Ring on default audio device
- ✅ Auto-answer option (Phase 24.24)
  - Settings flag for auto-answer
  - Configurable delay before auto-answer

**Phase 24.19: Full End-to-End Call Testing** ✅

- ✅ Integration test infrastructure
  - Mock SIP server with INVITE helpers (create_invite_request, basic_sdp_offer)
  - Provisional response generators (100 Trying, 180 Ringing)
  - Final response generators (486 Busy, 603 Decline, 200 OK)
  - BYE request/response generators for call termination
  - Unique test ID generation for SIP branches and tags
- ✅ Test scenarios
  - Incoming call accept and reject (6 tests)
  - Incoming INVITE handling with provisional responses
  - Error handling for nonexistent calls
  - Incoming call list tracking
  - Mock server format validation (7 tests)
- 🚧 Future test scenarios
  - Outbound call establishment and teardown
  - Call failure handling (4xx, 5xx responses)
  - mTLS authentication end-to-end
  - Performance testing (call setup latency, audio throughput)

**Phase 24.20: Audio Pipeline Activation** ✅

- ✅ MediaSession accessors for audio integration
  - `remote_addr()` - Get remote media address after ICE
  - `local_addr()` - Get local media address
  - `is_ready()` - Check if session ready for RTP
  - `srtp_contexts()` - Get SRTP contexts for direct audio handling
- ✅ Wire audio to call state
  - Start audio on CallState::Connected using real remote address
  - Stop audio on CallState::Terminated
  - Fallback to local address if media not ready (with warning)
- 🚧 Future enhancements
  - Codec negotiation integration from SDP answer
  - ✅ DTMF support (RFC 4733 RTP telephone events) - Phase 24.25
  - ✅ Audio device change handling during call - Phase 24.26

**Phase 24.21: GUI Certificate Verification Mode** ✅

- ✅ `ServerCertVerificationMode` type in client-types
  - System (default), Custom, Insecure modes
  - Serializable with serde for settings persistence
  - Helper methods: `label()`, `is_insecure()`, `custom_ca_path()`
- ✅ Settings UI for verification mode
  - Dropdown for Insecure/System/Custom modes
  - Custom CA file path input field
  - Warning dialog for Insecure mode with confirmation
  - Visual warning banner when insecure mode active
- ✅ Settings persistence via `NetworkSettings`
  - `server_cert_verification` field in settings.toml
- 🚧 Future enhancements
  - Display loaded CA certificate information
  - Certificate chain visualization
  - TLS version in status bar

**Phase 24.22: Hold/Resume** ✅

- ✅ Send re-INVITE with hold SDP
  - CallAgent `hold_call()` method with `a=sendonly` direction
  - CallAgent `build_reinvite_request_static()` for re-INVITE construction
  - ClientInviteTransaction for tracking re-INVITE response
- ✅ Resume with re-INVITE
  - CallAgent `resume_call()` method with `a=sendrecv` direction
  - Shared `send_reinvite()` helper for both operations
- ✅ Hold/Resume in CallManager
  - `hold_call()` generates hold SDP and pauses audio
  - `resume_call()` generates resume SDP and restores audio
  - `toggle_hold()` switches between Connected and OnHold states
  - `generate_sdp_with_direction()` helper for SDP generation
- ✅ Hold/Resume UI integration
  - `toggle_hold()` method in ClientApp
  - Hold action handler in GUI app.rs
  - Status messages for hold/resume feedback

**Phase 24.23: Future Enhancements** ✅

- ✅ Visual indicator for held calls
  - Prominent orange hold banner in call view
  - Orange duration text styling when on hold
  - Pause icon (⏸) in the banner
- ✅ Multiple held calls support (call waiting)
  - `CallFocus` enum (Active, Held, Ringing) in client-types
  - `focused_call_id` + `active_calls: Vec<String>` in CallManager
  - `max_concurrent_calls` configuration (default: 2)
  - Auto-hold current call when making/accepting second call
  - `SwitchTo` action in CallAction enum
  - Call tabs UI showing all active calls with state indicators
  - Tab colors: green=focused, orange=held
  - `switch_to_call()` in ClientApp and CallManager
- ✅ Music on Hold (MOH)
  - `hound` dependency for WAV file reading
  - `FileAudioSource` for loading WAV with mono conversion and resampling
  - Continuous looping playback
  - `moh_file_path` in AudioConfig, PipelineConfig, AudioSessionConfig
  - `set_moh_active()`, `is_moh_active()`, `has_moh()`, `process_moh_frame()` in pipeline
  - MOH activates automatically on hold, deactivates on resume

**Phase 24.24: Audio Ringtone & Auto-Answer** ✅

- ✅ Ringtone playback for incoming calls
  - `RingtonePlayer` struct in client-audio/ringtone.rs
  - WAV file loading via `FileAudioSource` with resampling
  - Default dual-tone (440Hz + 480Hz) when no custom ringtone configured
  - Ring buffer-based audio streaming to output device
  - Configurable ring device (separate from speaker)
  - `ringtone_file_path` in AudioConfig
  - Ringtone starts on IncomingCall event, stops on accept/reject/end
- ✅ Auto-answer option
  - `auto_answer_enabled` and `auto_answer_delay_secs` in GeneralSettings
  - Timer-based auto-answer with configurable delay (0-30 seconds)
  - Ringtone plays during delay period
  - Auto-answer processed in GUI update loop
- ✅ Settings UI for ringtone and auto-answer
  - Auto-answer checkbox with delay slider
  - Ring device dropdown
  - Ringtone file browser (WAV format)
  - Ring volume slider
  - Supported format info display

**Phase 24.25: DTMF Support (RFC 4733)** ✅

- ✅ DTMF types in client-types
  - `DtmfDigit` enum (0-9, *, #, A-D)
  - `DtmfEvent` struct with digit, end flag, volume, duration
  - RFC 4733 event codes (0-15)
  - Encode/decode methods for 4-byte payload format
  - Duration conversion helpers (ms ↔ timestamp units)
- ✅ RTP transmission in client-audio
  - `DTMF_PAYLOAD_TYPE` (101) and `DTMF_CLOCK_RATE` (8000 Hz)
  - `send_dtmf()` method in RtpTransmitter
  - Marker bit for start of event, end bit for final packets
  - 3x redundant end packets for reliability
- ✅ AudioPipeline DTMF support
  - Full event lifecycle: initial packet, continuation every 20ms, end packets
  - Duration tracking with incrementing timestamp
- ✅ Call manager integration
  - `send_dtmf()` in AudioSession, CallManager, ClientApp
  - Default 100ms tone duration
- ✅ Dialpad UI in call view
  - Toggle button to show/hide dialpad
  - Phone-style 4x3 grid (1-9, *, 0, #)
  - Click-to-send DTMF digits
  - Status message shows sent digit

**Phase 24.26: Audio Device Hot-Switching** ✅

- ✅ Device switching in AudioPipeline
  - `switch_input_device()` - Change microphone mid-call
  - `switch_output_device()` - Change speaker mid-call
  - Recreates audio streams without stopping RTP
  - Device manager updates preserved
- ✅ Full stack integration
  - AudioSession: `switch_input_device()`, `switch_output_device()`, device name accessors
  - CallManager: Routes device changes to active call's session
  - ClientApp: Public API for GUI access
- ✅ Call view audio menu
  - "Audio Devices" toggle button (mutually exclusive with dialpad)
  - Microphone dropdown with available devices
  - Speaker dropdown with available devices
  - Device lists refreshed when entering call view
  - Status messages for device changes

**Phase 24.27: Codec Negotiation from SDP** ✅

- ✅ SDP codec parsing in CallManager
  - `parse_codec_from_sdp()` extracts negotiated codec from SDP answer
  - Parses m=audio line for first payload type
  - Maps static payload types (0=PCMU, 8=PCMA, 9=G722)
  - Looks up dynamic payload types via rtpmap attributes
- ✅ Negotiated codec storage
  - `negotiated_codecs: HashMap<String, CodecPreference>` per call
  - Stored when SDP answer received in `handle_sdp_answer()`
  - Cleaned up on call termination or hangup
- ✅ Audio session codec integration
  - `start_audio_session()` uses negotiated codec when available
  - Falls back to `preferred_codec` if no negotiation occurred
  - Logging indicates which codec is being used
- ✅ Unit tests for SDP codec parsing
  - Tests for PCMU, PCMA, G722, Opus detection
  - Tests for missing m=audio line handling

**Phase 24.28: Call Transfer Support (RFC 3515 REFER)** ✅

- ✅ REFER method support in CallAgent
  - `transfer_call()` method validates call state (Connected or OnHold)
  - `send_refer()` builds and sends REFER request with Refer-To header
  - `build_refer_request_static()` constructs RFC 3515 compliant REFER
  - Refer-To header contains transfer target URI
  - Referred-By header identifies the transferring party
  - Sets call state to `CallState::Transferring` during transfer
- ✅ CallManager transfer API
  - `transfer_call()` transfers currently focused call
  - `transfer_call_by_id()` transfers specific call by ID
  - Routes transfer requests to CallAgent
- ✅ ClientApp transfer integration
  - `transfer_call()` public API for GUI access
  - Error handling with user-friendly messages
- ✅ Transfer UI in call view
  - `CallAction::Transfer` variant for transfer action
  - Transfer button in call controls
  - Modal transfer dialog with SIP URI input field
  - Transfer and Cancel buttons
  - Enter key support for quick transfer
  - Status messages for transfer progress/failure

**Phase 24.29: NOTIFY Handling for REFER (RFC 3515)** ✅

- ✅ NOTIFY request handling in CallAgent
  - `handle_notify()` processes incoming NOTIFY for REFER subscriptions
  - Event header validation (Event: refer)
  - Subscription-State header parsing for final status detection
  - Automatic 200 OK response generation
- ✅ Sipfrag body parsing
  - `parse_sipfrag()` extracts SIP status code from NOTIFY body
  - Format: "SIP/2.0 <status-code> <reason-phrase>"
  - Maps to ReferStatus (Trying, Ringing, Success, Failed)
- ✅ ReferRequest tracking in CallSession
  - Tracks implicit subscription state per RFC 3515
  - Updates status from NOTIFY messages
  - Subscription expiration tracking
- ✅ Transfer progress events
  - `CallEvent::TransferProgress` variant in call_agent
  - `CallManagerEvent::TransferProgress` for manager layer
  - `AppEvent::TransferProgress` for GUI layer
  - Status code, success flag, and final indicator
- ✅ GUI transfer progress display
  - Real-time status messages during transfer
  - Shows "Trying", "Ringing", "Success", or "Failed"
  - Final result message on transfer completion
- ✅ ReferStatus re-export from client-sip-ua
  - Public access to `proto_dialog::refer::ReferStatus`

**Phase 24.30: PIN Handling & Smart Card Signing** ✅

- ✅ `SignatureAlgorithm` enum for signing operations
  - EcdsaSha384 (CNSA 2.0 compliant)
  - EcdsaSha256, RsaSha384, RsaSha256 variants
- ✅ `sign_data()` method in CertificateStore
  - Acquires private key via CryptAcquireCertificatePrivateKey
  - Signs data using NCryptSignHash (Windows CryptoNG)
  - Supports ECDSA and RSA algorithms with PKCS#1 padding
  - Handles PIN-protected smart card keys
  - Maps Windows error codes to CertStoreError variants
- ✅ `verify_pin()` method for PIN validation
  - Verifies PIN correctness without signing
  - Detects SmartCardNotPresent, PinIncorrect, PinRequired errors
  - Uses NCryptSetProperty to set smart card PIN
- ✅ GUI PIN dialog integration
  - `use_certificate_with_pin()` verifies PIN before configuring certificate
  - Handles specific CertStoreError cases with appropriate UI messages
  - PIN attempt tracking with lockout warning
- ✅ Non-Windows stub implementations for testing
  - Deterministic fake signatures based on algorithm
  - PIN validation accepts 4+ digit PINs

**Tests**: 14 cert_store tests (client-core crate)

**Phase 24.31: Settings Persistence** ✅

- ✅ `SettingsAction::Save` handler in GUI
  - Persist settings changes to TOML via SettingsManager
  - Atomic save with temp file + rename
  - Status message on save success/failure
  - Sync settings with ClientApp if available
- ✅ `SettingsAction::Discard` handler
  - Reload settings from disk via load_from_settings()
  - Reset dirty flag via clear_dirty()
- ✅ Settings dirty tracking
  - Mark settings dirty on any change
  - Prompt on exit if unsaved changes
  - Cancel close and show confirmation dialog
  - Save/Discard/Cancel options in dialog
- ✅ Settings view bidirectional data flow
  - load_from_settings(): Load settings into view fields
  - collect_settings(): Collect view state for saving
  - Proper field mapping for General, Audio, Network, UI settings

**Phase 24.32: Account Registration UI** ✅

- ✅ `SettingsAction::Register` handler
  - Wire Register button to ClientApp::register_account()
  - Show registration progress spinner during registration
  - Display registration success/failure status via AppEvent
  - Validate required fields before registration
  - build_account() creates SipAccount from view state
- ✅ `SettingsAction::Unregister` handler
  - Wire Unregister button to ClientApp::unregister()
  - Update UI state on completion
  - Error handling with status messages

**Phase 24.33: Contact Management UI** ✅

- ✅ Add Contact dialog
  - Modal dialog with name, SIP URI, organization, notes fields
  - Validation for required fields (name, SIP URI format)
  - Save to ContactManager on confirm
- ✅ Edit Contact dialog
  - Pre-populate fields from existing contact
  - Update contact on save
- ✅ Delete Contact confirmation
  - Confirmation dialog before deletion
  - Remove from ContactManager on confirm
- ✅ Favorites toggle
  - Toggle favorite status on contact row
  - Context menu option to add/remove favorite
  - Persist to contact store
- ✅ ContactManager integration
  - Load contacts from ContactManager on startup
  - ContactsAction handlers for all CRUD operations
  - Auto-save on contact modifications

**Phase 24.34: Server Certificate Verification** ✅

- ✅ Apply verification mode to transport
  - Convert ServerCertVerificationMode to CertVerificationMode
  - Load CA certificates from PEM/DER files
  - Apply to SipTransport via ClientApp::set_verification_mode
  - Rebuild TLS config when mode changes
- ✅ Custom CA file browser
  - Use rfd crate for native file dialog
  - Filter to .pem/.crt/.cer/.der files
  - Validate CA certificate on selection
  - Display certificate count after loading
- ✅ Certificate info display
  - Show number of loaded CA certificates
  - Green indicator when certificates loaded successfully
- ✅ PEM/DER certificate loading
  - Support for both PEM and DER formats
  - Manual PEM parsing with base64 decoding
  - Added `load_certs_from_pem_file` utility function

**Phase 24.35: Platform-Specific UI Architecture** ✅

- ✅ Rename `client-gui` to `client-gui-windows`
  - Binary: `sip-softclient-windows`
  - Add `#![cfg(target_os = "windows")]` attribute
  - Make `winrt-notification` unconditional dependency
  - Remove cross-platform fallback notification code
- ✅ Update workspace references
  - Cargo.toml workspace member path
  - Workspace dependency declaration
- ✅ Platform-specific UI crate structure (planned)
  - `client-gui-windows`: Windows desktop (native-windows-gui, winrt-notification)
  - `client-gui-macos`: macOS desktop (planned)
  - `client-gui-linux`: Linux desktop (planned)
  - `client-gui-android`: Android mobile (planned)
  - `client-gui-ios`: iOS mobile (planned)
- ✅ Shared cross-platform crates
  - `client-types`: Data types and models (no platform deps)
  - `client-core`: App logic, transport, contacts (Windows CryptoAPI optional)
  - `client-sip-ua`: SIP protocol (no platform deps)
  - `client-audio`: Audio pipeline (cpal for platform abstraction)

**Phase 24.36: Windows UI Optimization** ✅

- ✅ Centralized styling module (`style.rs`)
  - Color palette constants (primary, danger, warning, success, muted)
  - Call state colors, registration status colors
  - Certificate quality colors for CNSA 2.0 compliance indicators
  - Base sizes and font sizes for consistent UI
- ✅ DPI-aware responsive scaling
  - `UiScale` struct with `from_ctx()` for automatic DPI detection
  - Scaled sizes: buttons, spacing, fonts, input fields
  - Helper methods: `dialpad_button()`, `button_height()`, `spacing_*()`, `font_*()`
- ✅ Global keyboard shortcuts
  - Navigation: Alt+D (Dialer), Alt+K (Contacts), Alt+S (Settings)
  - Call controls: Alt+H/Escape (Hangup), Alt+M (Mute), Alt+O (Hold)
  - Incoming calls: Alt+A (Accept), Alt+R (Reject)
  - Settings: Ctrl+S (Save), F5 (Refresh certificates)
  - Dialer: Alt+C (Call), Enter (Call)
- ✅ Styled text helpers
  - `heading()`, `subheading()`, `body()`, `secondary()`, `small()`, `display()`
  - `button_text()`, `dialpad_text()` for consistent button labels
- ✅ Button helpers
  - `primary_button()`, `danger_button()`, `warning_button()`, `secondary_button()`
- ✅ Theme management
  - `apply_dark_theme()` for consistent visuals
  - `dialog_window()` helper for modal dialogs
- ✅ Fixed hardcoded domain in dialer
  - Added `set_default_domain()` method
  - Domain now comes from account settings

**Phase 24.37: Native Windows GUI Migration** ✅

- ✅ Migration from egui/eframe to native-windows-gui (NWG)
  - Replaced egui with native Win32 controls via native-windows-gui 1.0
  - Removed egui/eframe and tray-icon dependencies from Cargo.toml
  - True Windows native appearance with system theming
- ✅ Main application window (`app.rs`)
  - `nwg::Window` with proper sizing (420x640)
  - `nwg::TabsContainer` for navigation between views
  - `nwg::StatusBar` for status messages
  - `nwg::AnimationTimer` (100ms) for event polling
  - RefCell-based state management for interior mutability
- ✅ Dialer view with native controls
  - `nwg::TextInput` for number/SIP URI input
  - 12 `nwg::Button` controls for dialpad (0-9, *, #)
  - Call, Clear, Backspace action buttons
  - SIP URI formatting (sip:/sips: prefix handling)
- ✅ Call view with native controls
  - `nwg::Label` for caller info, status, duration
  - Mute, Hold, Transfer, Hangup buttons
  - `nwg::ComboBox` for audio device selection (input/output)
  - Duration formatting (MM:SS or HH:MM:SS)
- ✅ Contacts view with native list control
  - `nwg::ListBox` for contact display
  - `nwg::TextInput` for search filtering
  - Add, Call, Edit, Delete, Favorite action buttons
  - Alphabetical sorting by name
  - Favorite indicator (*) prefix in list
- ✅ Settings view with native form controls
  - Account settings (display name, SIP URI, registrar)
  - Certificate `nwg::ListBox` with selection
  - Register/Unregister/Save/Discard buttons
  - Settings persistence (load/collect methods)
- ✅ System tray integration using NWG
  - `nwg::TrayNotification` for tray icon
  - `nwg::Menu` with popup context menu
  - Show, Hide, Exit menu items
  - Tray click shows window
  - Removed `tray-icon` crate dependency
- ✅ Windows toast notifications
  - Kept `winrt-notification` for native toasts (independent of GUI)
  - Incoming call, missed call, registration status notifications
- ✅ Event-driven architecture
  - Direct method calls instead of Action enums
  - NWG event handlers bound via `nwg::bind_event_handler`
  - Timer-based polling for SIP events

### 🚧 Enterprise Management Features (In Progress)

**Goal**: Enterprise-level management capabilities for the SBC

**Multi-Format Configuration Support** (`sbc-config`) ✅

- ✅ `serde_yaml_ng` dependency for YAML parsing
- ✅ `ConfigFormat` enum: `Toml`, `Yaml`
- ✅ `ConfigFormat::from_extension()` auto-detects format from file extension
- ✅ `load_from_file_with_format()` for explicit format loading
- ✅ `load_from_str_with_format()` for parsing strings with specified format
- ✅ Backward compatible: existing TOML workflows unchanged
- ✅ 20 tests passing

**gRPC Management API** (`sbc-grpc-api` new crate) ✅

- ✅ Protocol Buffer definitions for enterprise management
- ✅ `config.proto`: ConfigService (GetConfig, UpdateConfig, ValidateConfig, ReloadConfig)
- ✅ `call.proto`: CallService (ListCalls, GetCall, TerminateCall, GetCallStats)
- ✅ `registration.proto`: RegistrationService (ListRegistrations, GetRegistration)
- ✅ `system.proto`: SystemService (GetVersion, GetStats, GetMetrics, ReloadTls, GetTlsStatus, Shutdown)
- ✅ `health.proto`: Standard gRPC health protocol (Check, Watch)
- ✅ `cluster.proto`: ClusterService (GetClusterStatus, ListNodes, GetNodeStatus, InitiateFailover) - feature-gated
- ✅ Built with tonic 0.14 and prost 0.14
- ✅ 4 tests passing

**gRPC Server Implementation** (`sbc-daemon`) ✅

- ✅ `grpc_server` module with service implementations
- ✅ `GrpcServer` struct for lifecycle management
- ✅ `ConfigServiceImpl`, `SystemServiceImpl`, `HealthServiceImpl`
- ✅ `CallServiceImpl`: ListCalls, GetCall, TerminateCall, GetCallStats, WatchCalls
- ✅ `RegistrationServiceImpl`: ListRegistrations, GetRegistration, DeleteRegistration, GetRegistrationStats
- ✅ TLS/mTLS support via `ServerTlsConfig`
- ✅ Feature-gated behind `grpc` feature flag
- ✅ Integrated into Runtime with graceful shutdown
- ✅ Default port 9090 (alongside REST API on 8080)
- ✅ 57 tests passing

**Configuration Schema** (`sbc-config/schema.rs`) ✅

- ✅ `GrpcConfig` struct:
  - `enabled`: Enable/disable gRPC server
  - `listen_addr`: Bind address (default: 0.0.0.0:9090)
  - `tls_cert_path`, `tls_key_path`, `tls_ca_path`: TLS configuration
  - `require_mtls`: Mutual TLS requirement
  - `max_connections`: Connection limit
  - `request_timeout_secs`: Request timeout
  - `enable_reflection`: gRPC reflection service

**ClusterService gRPC** (`sbc-daemon`, cluster feature) ✅

- ✅ `ClusterServiceImpl`: GetClusterStatus, ListNodes, GetNodeStatus, DrainNode, WatchCluster RPCs
- ✅ InitiateFailover and UndoFailover RPCs (stubs pending FailoverCoordinator integration)
- ✅ NodeRole and NodeState mapping to protobuf enums
- ✅ ClusterHealth aggregation from storage, discovery, and location services
- ✅ Feature-gated behind `cluster` feature flag
- ✅ Runtime integration passes ClusterManager to GrpcServer when cluster enabled
- ✅ 61 tests passing with cluster feature

**Pending**

- 🚧 gRPC reflection service
- 🚧 Integration tests for gRPC services
- 🚧 Full FailoverCoordinator integration for InitiateFailover/UndoFailover

---

**Phase 24.38: Button Event Handlers & Custom Dialogs** ✅

- ✅ Button event handlers for all views
  - Dialer: dialpad digits (0-9, *, #), Call, Clear, Backspace
  - Call: Mute, Hold, Transfer, Hangup, Keypad, audio device selection
  - Contacts: Add, Call, Edit, Favorite, Delete, search text filtering
  - Settings: Register, Unregister, Refresh Certs, Use Cert, Save, Discard
- ✅ Custom dialogs module (`dialogs/`)
  - `TransferDialog`: Modal SIP URI input for call transfers
  - `ContactDialog`: Add/edit contact with name, SIP URI, favorite checkbox
  - `PinDialog`: Masked PIN entry for smart card authentication
  - `DtmfDialog`: Non-modal dialpad for DTMF tones during calls
- ✅ App handler methods wired to dialogs and core functionality
  - DTMF support via `send_dtmf()` for RFC 4733 telephone events
  - Transfer support via `transfer_call()` for RFC 3515 REFER

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
| Various crates (10 files) | Power of 10 Rule 4: Refactor functions >60 lines | Medium | ✅ Done |

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
| RFC 9260 | SCTP | ✅ Complete (100% compliant - all chunks, state machine, timers, congestion control) |
| RFC 4168 | SIP over SCTP | 🚧 Partial (transport layer complete) |
| RFC 6951 | UDP Encapsulation for SCTP | ✅ Implemented |
| RFC 3758 | PR-SCTP | ✅ Implemented (FORWARD-TSN chunk) |
| RFC 5061 | SCTP Dynamic Address | ✅ Implemented (ASCONF/ASCONF-ACK chunks) |
| RFC 6525 | SCTP Stream Reset | ✅ Implemented (RE-CONFIG chunk) |
| RFC 4895 | SCTP Authentication | ✅ Implemented (AUTH chunk encode/decode) |
| RFC 4820 | SCTP PAD Chunk | ✅ Implemented (PMTU probing support) |

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
