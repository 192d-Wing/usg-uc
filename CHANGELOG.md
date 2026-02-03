# Changelog

All notable changes to the USG Unified Communications SBC project will be documented in this file.

The format is based on [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Crate Extraction: Complete proto-* Stack

- Extracted all SIP application crates into standalone `proto-*` crates for reuse:
  - `proto-sip`: RFC 3261 SIP protocol parsing and generation
  - `proto-transaction`: RFC 3261 §17 transaction state machine
  - `proto-dialog`: RFC 3261 §12 dialog management, RFC 3515 REFER, RFC 4028 session timers
  - `proto-b2bua`: RFC 7092 B2BUA taxonomy, RFC 5853 SBC requirements
  - `proto-registrar`: RFC 3261 §10 registration, RFC 5626 outbound, RFC 5627 GRUU
- All proto-* crates are standalone with minimal dependencies (no SBC-specific code)
- Designed for reuse by SBC and future Call Manager projects
- Publishable to crates.io as independent libraries

#### RFC Compliance Improvements

**proto-transaction (RFC 3261 §17)**

- CSeq validation for transaction matching (RFC 3261 §17.1.3):
  - `CSeqTracker` struct for tracking sequence numbers and methods
  - `CSeqValidation` enum: Valid, Retransmission, TooLow, MethodMismatch
  - Request validation with `validate()` and response correlation with `validate_response()`
- RFC 3261 branch magic cookie constant (`RFC3261_BRANCH_MAGIC = "z9hG4bK"`)
- UPDATE method transaction support (RFC 3311) using non-INVITE state machine

**proto-sip (RFC 3261, RFC 3327)**

- Path header support (RFC 3327) for proxy routing:
  - `HeaderName::Path` variant with `allows_multiple() = true`
  - Helper methods: `path_values()`, `add_path()`, `prepend_path()`
- Routing module (`routing.rs`) with Route/Record-Route processing:
  - `process_record_route()` for UAC/UAS route set construction
  - `construct_request_route()` for in-dialog request routing
  - Loose routing (`lr` parameter) detection and handling

**proto-dialog (RFC 3261 §12, RFC 3515, RFC 4028)**

- Multi-dialog forking support (RFC 3261 §12.2.2):
  - `ForkKey` struct for matching forked responses by Call-ID and local tag
  - `ForkedDialogSet` for managing parallel early dialogs from proxy forking
  - Methods: `receive_provisional()`, `receive_2xx()`, `receive_error()`
  - Auto-termination of non-confirmed dialogs when one is confirmed
  - `dialogs_to_terminate()` returns list of dialogs needing BYE/CANCEL
- Enhanced REFER support (RFC 3515):
  - `ReferHandler` for transfer request management
  - `ReferSubscriptionState`: Pending, Active, Terminated
  - Implicit subscription lifecycle tracking
- Session timer improvements (RFC 4028):
  - `SessionTimerNegotiation` for offer/answer session timer handling
  - `handle_422_response()` for Min-SE negotiation
  - `RefresherRole` enum: UAC, UAS, Unspecified

**proto-b2bua (RFC 7092, RFC 5853)**

- B2BUA mode characteristics (`mode.rs`):
  - `ModeCharacteristics` with SDP modification, media handling, topology hiding per mode
  - `SdpModification`: Passthrough, RewriteConnection, FullModification
  - `MediaHandling`: None, Relay, Inspect, Terminate
  - `TopologyHiding`: None, SignalingOnly, Full
- SDP rewriting for media anchoring (`sdp_rewrite.rs`):
  - `SdpRewriter` with mode-based SDP modification
  - `rewrite_offer_for_b_leg()` and `rewrite_answer_for_a_leg()`
  - Connection (`c=`) and media port (`m=`) rewriting
  - IPv4 and IPv6 address support
  - Hold/Resume SDP direction handling: `rewrite_for_hold()`, `rewrite_for_resume()`
- Helper functions: `extract_media_address()`, `is_hold_sdp()`, `is_connection_hold()`
- `SdpRewriteContext` for per-leg address management

**proto-registrar (RFC 3261 §10, RFC 5626, RFC 5627)**

- GRUU service (RFC 5627):
  - `GruuService` for pub-gruu and temp-gruu generation
  - `GruuEntry` with instance association and expiration
  - Lookup methods: `lookup_by_gruu()`, `lookup_by_contact()`
  - GRUU parameter formatting in Contact header
- Outbound support improvements (RFC 5626):
  - Instance-ID and Reg-ID parameter handling
  - Outbound binding key generation: `{aor}:{instance_id}:{reg_id}`
  - Flow token support for connection reuse

#### Crate Extraction: proto-sip

- Extracted `sbc-sip` into standalone `proto-sip` crate for reuse
  - `proto-sip`: RFC 3261 compliant SIP protocol parsing and generation
  - Standalone crate with no SBC-specific dependencies (only `thiserror`, `bytes`)
  - Designed for reuse by SBC and future Call Manager projects
  - Publishable to crates.io as independent library

#### RFC 3261 Compliance Improvements (proto-sip)

- Structured header parsing module (`header_params.rs`):
  - `ViaHeader`: Parsed Via with transport, host, port, branch, received, rport, ttl, maddr
  - `NameAddr`: Parsed From/To/Contact with display-name, URI, tag, parameters
  - `CSeqHeader`: Parsed CSeq with sequence number and method
  - `MaxForwardsHeader`: Parsed Max-Forwards with decrement logic
  - Via branch magic cookie validation (`z9hG4bK` prefix)
  - Random tag and branch generation utilities
- Extension method support per RFC 3261 Section 7.1:
  - `Method::Extension(String)` variant for custom methods
  - Unknown methods now parse successfully instead of error
  - `is_extension()` and `is_rfc3261_core()` classification methods
- Mandatory header validation:
  - `Headers::validate_request_headers()` - Via, To, From, Call-ID, CSeq, Max-Forwards
  - `Headers::validate_response_headers()` - Via, To, From, Call-ID, CSeq
- New header convenience methods:
  - `via_parsed()`, `via_all_parsed()`, `via_branch()`
  - `from_parsed()`, `to_parsed()`, `from_tag()`, `to_tag()`
  - `cseq_parsed()`, `max_forwards()`, `contact_parsed()`, `expires()`
- Additional RFC 3261 Section 20 headers:
  - Content-Disposition, Content-Language, Min-Expires
  - Accept, Accept-Encoding, Accept-Language
  - Alert-Info, Call-Info, Date, Error-Info, In-Reply-To
  - MIME-Version, Organization, Priority, Reply-To, Retry-After
  - Server, Subject, Timestamp, User-Agent, Warning
  - Allow-Events, Session-Expires, Min-SE
  - P-Asserted-Identity, P-Preferred-Identity, Reason
  - Refer-To, Referred-By, Replaces
- Additional compact form support: Subject (s), Refer-To (r), Allow-Events (u), Event (o)
- URI parameter accessors: `user_param()`, `is_phone()`, `method_param()`, `ttl()`, `maddr()`
- `HeaderName::allows_multiple()` for multi-value header validation

#### SIP Authentication (RFC 2617)

- New authentication module (`auth.rs`):
  - `DigestChallenge`: Parsed WWW-Authenticate/Proxy-Authenticate headers
  - `DigestCredentials`: Parsed Authorization/Proxy-Authorization headers
  - `DigestAlgorithm`: MD5, SHA-256, SHA-512-256 support
  - `Qop`: Quality of Protection (auth, auth-int)
  - Stale nonce detection support
  - Round-trip parsing and generation

#### Message Builder Utilities

- New builder module (`builder.rs`):
  - `RequestBuilder`: Fluent API for constructing SIP requests
  - `ResponseBuilder`: Fluent API for constructing SIP responses
  - Automatic header generation (Content-Length, Via branch, tags)
  - Convenience methods: `invite()`, `register()`, `ok()`, `unauthorized()`
  - Auto-copy headers from request to response
  - SDP body helpers with Content-Type
- ID generation utilities:
  - `generate_call_id()`: Thread-safe unique Call-ID generation
  - `generate_branch()`: RFC 3261 compliant branch with magic cookie
  - `generate_tag()`: Unique tag generation for From/To headers

#### Transport Definitions (RFC 3261, RFC 7118)

- New transport module (`transport.rs`):
  - `Transport` enum: UDP, TCP, TLS, SCTP, WS, WSS, DTLS-UDP
  - Transport validation and properties
  - `is_reliable()`, `is_secure()`, `default_port()`
  - RFC 3261 core transport identification

#### Safety-Critical Code Compliance

- NASA "Power of 10" rules compliance documentation
- Debug assertions for invariant checking (Rule 5)
- Loop bounds documentation (Rule 2)
- All functions have bounded execution

### Removed

- `sbc-sip` crate (replaced by `proto-sip`)

### Changed

- `sbc-daemon`: Now depends on `proto-sip` instead of `sbc-sip`
- `sbc-transaction`: Now depends on `proto-sip` instead of `sbc-sip`
- `sbc-dialog`: Now depends on `proto-sip` instead of `sbc-sip`
- `sbc-dtls/cipher_suite.rs`: Rewritten for CNSA 2.0 compliance (only AES-256-GCM-SHA384)
- `sbc-dtls/Cargo.toml`: Removed webrtc-dtls dependency
- `sbc-codecs/g722.rs`: Now uses pure Rust ADPCM implementation via `G722AdpcmCodec`

---

#### Phase 17: Complete Stub Implementations

- Custom DTLS 1.2 implementation with aws-lc-rs replacing webrtc-dtls
  - `sbc-dtls/record.rs`: DTLS record layer with AES-256-GCM encryption
  - `sbc-dtls/handshake.rs`: Full handshake state machine (client and server)
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite (0xC02C)
  - P-384 ECDHE key exchange via `sbc-crypto`
  - TLS 1.2 PRF using HMAC-SHA384
  - SRTP keying material export per RFC 5764
  - Anti-replay protection with 64-bit sliding window
  - Cookie-based DoS protection (HelloVerifyRequest)
- STUN client implementation for server-reflexive candidate gathering
- TURN client implementation for relay candidate gathering
- ICE candidate gathering state machine updates
- G.722 ADPCM codec (pure Rust implementation)
  - QMF filter banks for sub-band splitting
  - Lower and higher band ADPCM encoding/decoding
- Opus FFI bindings via optional `opus-ffi` feature (audiopus crate)
- HMAC-SHA384 functions in `sbc-crypto/hkdf.rs` for TLS PRF

### Fixed

- Clippy warnings in `sbc-codecs` (format strings, bool_to_int_with_if, similar_names)
- Thread safety for `G722Codec` using `Mutex` instead of `RefCell`

---

#### Phase 1-2: Foundation & Transport
- Initial workspace structure with 27 crates organized in 9 layers
- Foundation crates: `sbc-types`, `sbc-crypto`, `sbc-audit`, `sbc-config`
- CNSA 2.0 cryptographic compliance enforcement via `sbc-crypto`
- NIST 800-53 Rev5 audit logging infrastructure via `sbc-audit`
- Transport crates: `sbc-transport`, `sbc-dtls`
- Project documentation: `CONTRIBUTING.md`, `CHANGELOG.md`
- Compliance documentation: `docs/NIST-800-53-CONTROLS.md`, `docs/CNSA-2-COMPLIANCE.md`

#### Phase 3: Protocol Core
- `sbc-sip`: SIP message parsing and generation
- `sbc-sdp`: SDP offer/answer model
- `sbc-rtp`: RTP packet handling
- `sbc-srtp`: Custom CNSA 2.0 compliant SRTP (AES-256-GCM, SHA-384 KDF)

#### Phase 4: NAT/ICE
- `sbc-stun`: STUN client/server
- `sbc-turn`: TURN relay
- `sbc-ice`: Full ICE implementation

#### Phase 5: Media Engine
- `sbc-codecs`: Opus, G.711 (pure Rust), G.722 codec support
- `sbc-media-engine`: Media relay and pass-through modes

#### Phase 6: SIP Application
- `sbc-transaction`: SIP transaction state machine
- `sbc-dialog`: SIP dialog management with session timers
- `sbc-b2bua`: B2BUA core per RFC 7092
- `sbc-registrar`: SIP registration with B2BUA and proxy modes

#### Phase 7: Security Services
- `sbc-stir-shaken`: STIR/SHAKEN with ES384 only (no ES256 per CNSA 2.0)
- `sbc-acl`: Access control lists with CIDR network matching
- `sbc-dos-protection`: Token bucket rate limiting with per-IP tracking

#### Phase 8: Orchestration & Management
- `sbc-policy`: Policy engine with conditions, actions, rules, and priority ordering
- `sbc-routing`: Dial plans, trunk management, LCR, and failover routing
- `sbc-cdr`: Call Detail Records with JSON/CSV export
- `sbc-api`: REST API framework with request/response types and routing
- `sbc-metrics`: Prometheus metrics (counters, gauges, histograms)
- `sbc-health`: Kubernetes liveness/readiness probes and health checks

#### Phase 9: Binaries & Integration
- `sbc-daemon`: Main SBC daemon with configuration loading, health checks, and graceful shutdown
- `sbc-cli`: Command-line interface with status, config, calls, health, and metrics commands
- `sbc-integration-tests`: Integration test suite for cross-crate testing

#### Phase 10: Async Runtime Integration

- Tokio async runtime integration in `sbc-daemon`
- Async UDP transport listeners with `sbc-transport` integration
- Unix signal handling with tokio (SIGTERM, SIGINT, SIGHUP)
- Async event loop for message processing with per-transport receive tasks
- Graceful shutdown with broadcast-based notification
- Health check polling loop with configurable interval
- Structured logging via tracing and tracing-subscriber

#### Phase 11: SIP Stack Integration

- SipStack module coordinating `sbc-sip`, `sbc-transaction`, `sbc-dialog`, `sbc-b2bua`, and `sbc-registrar`
- ProcessResult enum for message routing decisions (Response, Forward, NoAction, Error)
- SIP method handlers: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS
- SIP processing integrated into transport receive loop
- Transaction, dialog, and call state management structures
- Support for both B2BUA registrar and proxy modes

#### Phase 12: Media Pipeline Integration

- MediaPipeline module coordinating `sbc-rtp`, `sbc-srtp`, `sbc-dtls`, `sbc-media-engine`, and `sbc-codecs`
- RTP/SRTP packet processing with relay and pass-through modes
- DTLS-SRTP key exchange for secure media transport
- Codec negotiation via CodecRegistry
- Session management with A-leg/B-leg addressing
- RTP sequence tracking and statistics

#### Phase 13: ICE/NAT Traversal Integration

- IceManager module coordinating `sbc-ice`, `sbc-stun`, and `sbc-turn`
- ICE session lifecycle management (create, gather, check, close)
- Candidate gathering with host and server-reflexive candidates
- Connectivity check state machine integration
- ICE-lite mode for server-side optimization
- STUN binding request/response processing
- ICE restart support for mid-session renegotiation
- Session statistics and monitoring

#### Phase 14: REST API Server

- ApiServer module providing HTTP management interface via axum
- Liveness probe endpoint (`GET /healthz`)
- Readiness probe endpoint (`GET /readyz`)
- Health status endpoint (`GET /api/v1/system/health`)
- Prometheus metrics endpoint (`GET /api/v1/system/metrics`)
- Server statistics endpoint (`GET /api/v1/system/stats`)
- Version endpoint (`GET /api/v1/system/version`)
- Calls listing endpoint (`GET /api/v1/calls`)
- Registrations listing endpoint (`GET /api/v1/registrations`)
- Graceful shutdown integration with SIP server
- JSON serialization for all API responses

#### Phase 15: Production Hardening

- Graceful shutdown with connection draining
  - ConnectionTracker for active calls, transactions, and registrations
  - Configurable drain timeout with periodic polling
  - DrainResult reporting with statistics
  - ForcedShutdown phase when timeout exceeded
- Configuration hot-reload via SIGHUP
  - Async config reload loop monitoring shutdown signal
  - ConfigReloadResult with change detection
  - Section-level change tracking (general, transport, media, security, logging)
- HTTPS support for API server
  - TLS 1.3 with CNSA 2.0 compliant cipher suites
  - Certificate and key loading from PEM files
  - tokio-rustls integration for async TLS
- Rate limiting integration with sbc-dos-protection
  - Per-IP token bucket rate limiting for SIP messages
  - Configurable via rate_limit section in config
  - RateLimitAction handling (Allow, Throttle, Reject, Block)
  - rate_limited counter in server statistics

#### Phase 16: Deployment & Operations

- Multi-stage Dockerfile for optimized container images
  - Rust 1.85 builder stage with cmake, pkg-config, libssl-dev
  - Minimal debian:bookworm-slim runtime image
  - Non-root user (UID 1000) for security
  - Health check via `sbc-cli health --quiet`
  - Exposed ports: SIP (5060/udp, 5060/tcp, 5061/tcp), API (8080, 8443), RTP (16384-16484/udp)
- Kubernetes manifests for production deployment
  - Namespace with Pod Security Standards (restricted)
  - Deployment with security context (non-root, read-only filesystem, dropped capabilities)
  - Services: LoadBalancer for SIP, ClusterIP for API and metrics
  - RBAC with minimal ServiceAccount permissions
  - PodDisruptionBudget (minAvailable: 1)
  - NetworkPolicies for defense in depth
- Helm chart for parameterized deployment
  - Configurable replicas, resources, and autoscaling
  - HorizontalPodAutoscaler support
  - ServiceMonitor for Prometheus Operator integration
  - Full config.toml templating from values.yaml
  - Network policies and security contexts
- Operational runbook documentation
  - Deployment procedures (Docker, Kubernetes, Helm)
  - Configuration hot-reload instructions
  - Graceful shutdown procedures
  - Monitoring and alerting guidance
  - Troubleshooting guide
  - Incident response procedures (P1-P4)
  - CNSA 2.0 compliance checklist
  - Maintenance procedures (certificate rotation, upgrades, backup/recovery)

### Security

- Enforced `#![forbid(unsafe_code)]` across all crates (documented exceptions only)
- CNSA 2.0 algorithm restrictions: AES-256 only, SHA-384+ only, P-384+ curves only
- Forbidden algorithms compile-time blocked: SHA-256, P-256, AES-128
- STIR/SHAKEN uses ES384 exclusively (ES256 forbidden)
- Container security: non-root user, read-only filesystem, dropped capabilities
- Kubernetes Pod Security Standards: restricted profile enforced
- Network segmentation via NetworkPolicies

[Unreleased]: https://github.com/usg/usg-uc-sbc/compare/v0.1.0...HEAD
