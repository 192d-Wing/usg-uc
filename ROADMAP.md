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

**Current Status**: 854 tests passing, all phases complete

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

## Future Development Phases

### ⏳ Phase 17: Advanced Features
**Goal**: Enterprise features

- [ ] High availability with state replication
- [ ] Geographic redundancy support
- [ ] Advanced call routing (time-of-day, caller-based)
- [ ] Integration with external databases
- [ ] SNMP monitoring support

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
