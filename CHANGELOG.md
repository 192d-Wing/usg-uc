# Changelog

All notable changes to the USG Unified Communications SBC project will be documented in this file.

The format is based on [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Changed

- `sbc-dtls/cipher_suite.rs`: Rewritten for CNSA 2.0 compliance (only AES-256-GCM-SHA384)
- `sbc-dtls/Cargo.toml`: Removed webrtc-dtls dependency
- `sbc-codecs/g722.rs`: Now uses pure Rust ADPCM implementation via `G722AdpcmCodec`

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
