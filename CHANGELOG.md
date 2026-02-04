# Changelog

All notable changes to the USG Unified Communications SBC project will be documented in this file.

The format is based on [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 15: Production Hardening (Completed)

**New Crate**: `uc-telemetry`

- OpenTelemetry distributed tracing integration
  - `TelemetryConfig` with builder pattern for traces, metrics, OTLP
  - `TelemetryProvider` managing tracer and meter providers
  - `SpanContext` with W3C Trace Context (traceparent) support
  - Standard SIP/VoIP span attributes (call_id, sip_method, etc.)
  - OTLP exporter support (optional `otlp` feature)
  - Tracing crate integration (optional `tracing` feature)
  - 18 tests passing

**TLS Certificate Rotation** (`uc-transport/cert_reload.rs`)

- `ReloadableTlsAcceptor` for hot certificate reloading
  - Uses `arc-swap` for lock-free atomic acceptor swapping
  - New connections use updated certificates
  - Existing connections continue with original certificates
  - `reload()` method for programmatic reload
  - `try_reload()` for signal handler use (logs errors)
  - Reload metrics: count and timestamp tracking
  - `CertReloadStats` for monitoring
  - 7 tests passing

#### Phase 22: High Availability - Storage Backends (Completed)

**Redis Backend** (`uc-storage/redis.rs`)

- Full `StorageBackend` implementation with bb8 connection pooling
  - All trait methods: get, set, delete, keys, increment
  - Extended methods: exists, set_nx, mget, mset, mdelete, ttl, expire, persist
  - Connection pool configuration (max size, idle timeout)
  - Health check via PING command
  - 20 tests (11 require running Redis server)

**PostgreSQL Backend** (`uc-storage/postgres.rs`)

- Full `StorageBackend` implementation with sqlx
  - Auto-migration: creates `kv_store` and `kv_counters` tables
  - TTL via `expires_at` TIMESTAMPTZ column
  - Pattern matching via `glob_to_like()` conversion
  - Connection pool configuration via `PgPoolOptions`
  - Health check via connection acquisition
  - 21 tests (11 require running PostgreSQL server)

**DNS-based Service Discovery** (`uc-discovery/dns.rs`)

- `DnsDiscovery` provider using hickory-resolver
  - SRV record lookup with address resolution
  - A/AAAA record lookup for simple discovery
  - `sort_peers()` for priority/weight ordering
  - `select_weighted_peer()` per RFC 2782
  - Health check via localhost resolution
  - Integration with `uc-dns` crate
  - 8 tests (2 require network)

**Kubernetes Service Discovery** (`uc-discovery/kubernetes.rs`)

- `KubernetesDiscovery` provider using kube-rs
  - In-cluster and kubeconfig client initialization
  - Kubernetes Endpoints API for service discovery
  - Named port and numeric port resolution
  - Metadata enrichment (pod name, node name, namespace, service)
  - Ready/not-ready endpoint distinction with priority weighting
  - Health check via namespace list API
  - 7 unit tests + integration tests (require K8s cluster)

**Registrar Storage Integration** (`proto-registrar`)

- `StorableBinding` DTO for serializing SIP bindings
  - Converts `std::time::Instant` to Unix timestamps
  - Full round-trip support with `to_binding()` conversion
  - Serializable binding state for external storage
- `AsyncLocationService` cache-aside wrapper
  - Wraps synchronous `LocationService` for async storage access
  - Cache-first reads with storage fallback
  - Write-through to storage with TTL (expires + 60s buffer)
  - Key format: `sip:binding:{aor}:{binding_key}`
  - `sync_cache()` for cache warming from storage
  - Health check via storage backend ping
  - Storage feature flag (`storage`) for optional dependency
  - 6 tests for StorableBinding + AsyncLocationService

**Cluster Integration Tests** (`sbc-integration-tests`)

- Comprehensive integration test suite for clustering infrastructure
  - Storage tests: basic operations, TTL, keys pattern, increment, health check
  - Discovery tests: static discovery, empty peers, health check, peer metadata
  - Membership tests: creation, add/remove node, get node, view version
  - Registrar tests: AsyncLocationService CRUD, cache reload, health check
  - End-to-end tests: cluster formation, registration flow, shared storage
  - 23 integration tests total
  - Feature flags: `cluster`, `redis`, `postgres`

**Dependencies Added**

- `arc-swap` 1.7: Lock-free atomic pointer swapping
- `chrono` 0.4: Timestamp handling for PostgreSQL TTL
- `bb8` 0.8: Connection pooling for Redis
- `bb8-redis` 0.18: Redis backend for bb8
- `redis` 0.27: Redis client
- `sqlx` 0.8: PostgreSQL async driver

#### Phase 24: SIP Soft Client (In Progress)

**New Crates** (`crates/client/`)

- `client-types`: Shared types for SIP soft client
  - `CallState` enum with full call lifecycle (Idle → Dialing → Ringing → Connected → Terminated)
  - `CallInfo` and `CallHistoryEntry` for call tracking and persistence
  - `CallFailureReason` and `CallEndReason` for detailed call disposition
  - `SipAccount` with smart card certificate configuration (NO password fields)
  - `CertificateConfig` for smart card (CAC/PIV) certificate selection
  - `CertificateSelectionMode`: PromptUser, SpecificCertificate, AutoSelect
  - `CertificateInfo` for certificate details (thumbprint, subject, issuer, validity)
  - `RegistrationState` with smart card states (WaitingForPin, SmartCardNotPresent, CertificateInvalid)
  - `TransportPreference::TlsOnly` (CNSA 2.0 - no UDP/TCP fallback)
  - `AudioConfig` with device selection and jitter buffer settings
  - `AudioDevice` and `AudioStatistics` for audio monitoring
  - `CodecPreference` enum: Opus, G722, G711Ulaw, G711Alaw
  - `Contact` and `PhoneNumber` types for contact management
  - `ClientError` and `ClientResult` error handling

- `client-audio`: Audio pipeline skeleton (CPAL integration planned)
  - `AudioError` and `AudioResult` types

- `client-sip-ua`: SIP User Agent implementation
  - `SipUaError` with smart card error types (SmartCardNotPresent, CertificateError)
  - `SipUaResult` type
  - `RegistrationAgent` for SIP REGISTER transactions
    - State management: Unregistered → Registering → Registered
    - Handles 200 OK, 401/407 rejection (mTLS only), 403, 423 responses
    - Registration refresh before expiry
    - `RegistrationEvent` for state changes and request sending
  - `CallAgent` for INVITE/BYE/CANCEL/ACK transactions
    - Outbound call flow: make_call → Dialing → Ringing → Connected
    - Hangup: CANCEL for pending calls, BYE for connected
    - SDP offer/answer event emission
    - Response handling for 1xx, 2xx, 3xx, 4xx-6xx status codes
    - Proper ACK generation for all final responses
    - `CallEvent` for state changes, SDP handling, request sending
  - `IceHandler` for ICE candidate gathering
    - Host, server-reflexive (STUN), and relay (TURN) candidates
    - SDP candidate formatting using `Candidate::to_sdp()`
    - SDP candidate parsing using `Candidate::from_sdp()`
    - ICE role handling (controlling/controlled)
    - `IceEvent` for state changes, candidates, connectivity
  - `DtlsHandler` for DTLS handshake
    - SRTP key derivation via DTLS-SRTP
    - Certificate fingerprint handling for SDP
    - Support for client and server roles
    - `DtlsEvent` for state changes, handshake completion
  - `MediaSession` coordinated secure media pipeline
    - Orchestrates ICE + DTLS + SRTP setup
    - `MediaSessionState`: New, Gathering, Connecting, Securing, Active, Closing, Closed, Failed
    - RtpPacket encryption via `SrtpProtect`
    - RtpPacket decryption via `SrtpUnprotect`
    - UDP socket management for media
    - `MediaSessionEvent` for state changes, candidates, credentials, ready notification

- `client-core`: Application core (Phase 24.4 Complete)
  - `settings.rs`: TOML-based settings persistence
    - `Settings`, `GeneralSettings`, `NetworkSettings`, `UiSettings` structs
    - `SettingsManager` with atomic save (temp file + rename)
    - Platform-specific paths via `directories` crate
    - Account management with set/get/remove operations
    - 6 tests passing
  - `contact_manager.rs`: JSON-based contact and call history storage
    - `ContactStore` with HashMap-based contact storage
    - `ContactManager` with CRUD operations
    - Contact search by name, phone number, or SIP URI
    - Partial phone number matching (suffix matching)
    - Call history with automatic trimming (max 1000 entries)
    - 8 tests passing
  - `call_manager.rs`: Call coordination between SIP UA and media
    - `CallManager` bridging CallAgent, MediaSession, and ContactManager
    - make_call/hangup with proper state tracking
    - SDP offer generation with ICE credentials
    - ICE credential parsing from SDP answers
    - Call history integration
    - Mute toggle support
    - 5 tests passing
  - `app.rs`: Main application coordinator
    - `ClientApp` managing registration, calls, settings, contacts
    - `AppState`: Starting, Ready, Registering, Registered, InCall, ShuttingDown
    - `AppEvent`: RegistrationStateChanged, CallStateChanged, IncomingCall, CallEnded, Error
    - Account registration via RegistrationAgent
    - Event broadcasting to GUI
    - Graceful shutdown with state persistence
  - `AppError` and `AppResult` types

- `client-gui`: Windows GUI implementation (Phase 24.5 Complete)
  - Main window with dark theme and navigation bar (Dialer, Call, Contacts, Settings)
  - `app.rs`: Main GUI application coordinator
    - `SipClientApp` implementing `eframe::App`
    - `ActiveView` enum for navigation state
    - Event-driven architecture connecting to client-core
    - Registration status indicator in navigation bar
    - Error dialog for user notifications
  - `views/dialer.rs`: Phone dialer view
    - Number pad with digits 0-9, *, #
    - URI input field with backspace and clear
    - Auto-formatting for sips: URIs
    - `DialerAction::Call(String)` for call initiation
  - `views/call.rs`: Active call view
    - Duration timer with mm:ss display
    - Remote party info display
    - Mute/Hold/Hangup button controls
    - `CallAction` enum: Hangup, Mute, Hold
    - Visual call state feedback
  - `views/contacts.rs`: Contacts list view
    - Search filtering by name or SIP URI
    - Favorites section with star indicators
    - Avatar initials display
    - Context menu with call/edit/delete options
    - `ContactsAction` enum: Call, Edit, Delete
  - `views/settings.rs`: Settings view
    - Tabbed interface: Account, Audio, General, About
    - Account configuration with smart card info
    - Audio device selection (input/output)
    - General settings (startup behavior, audio preferences)
    - About tab with version info
    - `SettingsAction` enum: Save, Register, Unregister
  - `tray.rs`: System tray integration
    - `SystemTray` with tray-icon crate
    - Menu items: Show window, Exit
    - `TrayAction` enum for event handling
    - Icon generation for tray display
  - `notifications.rs`: Windows toast notifications (Phase 24.6)
    - `NotificationManager` for toast notifications
    - `NotificationType` enum: IncomingCall, MissedCall, CallEnded, Error, RegistrationChanged
    - Uses `winrt-notification` on Windows
    - Integrated with app event handling

- `client-core`: Certificate store and security (Phase 24.6)
  - `cert_store.rs`: Certificate store access
    - `CertificateStore` for Windows Certificate Store
    - `CertStoreError` error types
    - Auto-select prefers ECDSA P-384 (CNSA 2.0)
    - Find by thumbprint, list, refresh operations
    - Stub data for cross-platform development
    - 8 tests for certificate operations

- `client-types`: Sensitive data types (Phase 24.6)
  - `sensitive.rs`: Memory-safe credential storage
    - `SmartCardPin` with zeroize-on-drop
    - `SessionToken` for SRTP/session secrets
    - `SrtpKeyMaterial` for SRTP master keys
    - `SensitiveString` for general sensitive data
    - All types implement Debug with [REDACTED]
    - 7 tests for sensitive types

**Phase 24.7: Deployment & Packaging**

- `crates/client/installer/` directory for Windows packaging
  - `usg-sip-client.wxs` - WiX v4.x MSI installer configuration
    - Program Files installation with proper permissions
    - Start Menu and Desktop shortcuts
    - Registry entries for uninstall
    - SIP/SIPS URI handler registration for click-to-call
    - Upgrade support via UpgradeCode
  - `build-installer.ps1` - PowerShell build script
    - Debug and Release build modes
    - CNSA 2.0 compliant code signing (SHA-384)
    - MSI creation via WiX Toolset
    - Portable ZIP package creation
  - `resources/license.rtf` - License agreement for installer
  - `resources/default-settings.toml` - Default configuration
  - `README.md` - Installer documentation

- `crates/client/client-gui/` Windows integration
  - `app.manifest` - Windows application manifest
    - UAC settings (asInvoker - no elevation required)
    - DPI awareness (Per-Monitor V2)
    - Visual styles (Common Controls 6)
    - Windows version compatibility (Windows 7+)
  - `build.rs` - Build script for Windows resources
    - Version info resource generation
    - Manifest embedding
    - Icon embedding support

**CNSA 2.0 Compliance Documentation**

- `CNSA_COMPLIANCE.md` in crates/client/
  - Algorithm restrictions (AES-256, P-384, SHA-384)
  - Crate-by-crate compliance status
  - Smart card authentication requirements
  - Key management practices

**Phase 24.8: Audio Pipeline**

- `client-audio` crate fully implemented
  - `device.rs`: Audio device enumeration and management (CPAL 0.17)
    - Cross-platform input/output device listing via `DeviceManager`
    - Device selection by name with fallback to default
    - Stream configuration for 8/16/48 kHz sample rates
    - Deprecated CPAL API workarounds
  - `jitter_buffer.rs`: Adaptive jitter buffer for RTP reordering
    - BTreeMap-based packet ordering by sequence number
    - `BufferedPacket` with sequence, timestamp, payload type, and data
    - Adaptive depth adjustment (40-200ms min/max)
    - Packet loss detection with `JitterBufferResult::Lost`
    - Jitter calculation per RFC 3550
    - `JitterBufferStats` for monitoring
  - `stream.rs`: CPAL audio capture/playback streams
    - `CaptureStream` for microphone input
    - `PlaybackStream` for speaker output
    - Ring buffer-based producer/consumer (ringbuf 0.4)
    - Support for i16 and f32 sample formats
    - Automatic mono mixdown from stereo
    - Non-blocking read/write operations
  - `codec.rs`: Codec encode/decode pipeline
    - `CodecPipeline` wrapper for G.711, G.722, Opus
    - Codec negotiation via `negotiate_codec()`
    - Payload type mapping and SDP capability generation
    - PLC (packet loss concealment) via silence generation
  - `rtp_handler.rs`: RTP packet send/receive
    - `RtpTransmitter` with sequence number and timestamp management
    - `RtpReceiver` with jitter buffer integration
    - SRTP encryption via `SrtpProtect` wrapper
    - SRTP decryption via `SrtpUnprotect` wrapper
    - Separate TX/RX contexts (different SSRCs and directions)
    - `RtpStats` for packet and byte counting
  - `pipeline.rs`: Main audio pipeline coordinator
    - `AudioPipeline` orchestrating full audio path
    - Capture → Encode → RTP TX / RTP RX → Decode → Playback
    - `PipelineConfig` for codec, port, SRTP keys, mute settings
    - `PipelineState`: Stopped, Starting, Running, Stopping
    - SRTP context setup with `SrtpKeyMaterial`
    - Mute control and pipeline statistics aggregation

**Phase 24.9: Audio Integration**

- `client-core` audio session management
  - `audio_session.rs`: Bridge between MediaSession and AudioPipeline
    - `AudioSession` coordinates SRTP keys with audio pipeline
    - `AudioSessionConfig` for flexible configuration
    - `AudioSessionConfigBuilder` for fluent API
    - 20ms audio processing loop via `tokio::time::interval`
    - Proper tick behavior (`MissedTickBehavior::Skip`)
    - Statistics reporting every 5 seconds
    - `AudioSessionEvent`: Started, Stopped, StatsUpdate, Error
  - `CallManager` audio integration
    - Audio session starts on `CallState::Connected`
    - Audio session stops on `CallState::Terminated`
    - `toggle_mute()` propagates to audio session
    - `audio_stats()` for real-time pipeline statistics
    - `set_preferred_codec()` for codec selection
  - 4 new tests for AudioSession

**Phase 24.10: Windows CryptoAPI Integration**

- `client-core` certificate store implementation
  - `cert_store.rs`: Full Windows CryptoAPI integration
    - `CertificateStore` for managing certificates from Windows Certificate Store
    - `CertificateInfo` with subject, issuer, validity dates, thumbprint, key algorithm
    - `CertOpenStore` for MY (Personal) certificate store access
    - `CertEnumCertificatesInStore` for certificate enumeration
    - `CertGetNameStringW` / `CertNameToStrW` for name extraction
    - `CertGetCertificateContextProperty` for smart card detection
    - `CertVerifyTimeValidity` for validity checking
    - EC curve OID parsing (P-256, P-384, P-521 detection)
    - Smart card reader detection via `CERT_KEY_PROV_INFO_PROP_ID`
    - CNSA 2.0 preference: prioritizes P-384 certificates
  - Cross-platform support
    - Full Windows implementation with `#[cfg(windows)]`
    - Stub certificate data for non-Windows platforms (development/testing)
    - `list_smart_card_readers()` returns detected readers on Windows
  - 7 tests for certificate store functionality

**Phase 24.11: Certificate Selection UI**

- `client-gui` security settings implementation
  - `settings.rs`: New Security tab in Settings view
    - Smart card reader detection and display
    - Certificate list with detailed information
    - Key algorithm badges (P-384 green, P-256 yellow, RSA red)
    - Smart card indicator for certificates on hardware tokens
    - Validity status indicators (valid/expired)
  - Certificate selection functionality
    - Manual certificate selection by thumbprint
    - Auto-select mode toggle (prefers ECDSA P-384)
    - Refresh certificates button with loading spinner
  - Certificate information display
    - Subject CN and issuer CN
    - Validity period (not before/not after)
    - Reader name for smart card certificates
- `client-core` certificate store updates
  - `list_smart_card_readers()` method for reader enumeration
- `app.rs` integration
  - `RefreshCertificates` and `SelectCertificate` actions
  - Real-time certificate loading from CertificateStore
  - Error handling with status message display

**Phase 24.12: Certificate Authentication Integration**

- `client-core` certificate export functionality
  - `cert_store.rs`: Certificate chain export methods
    - `get_certificate_chain()` retrieves DER-encoded certificates
    - `has_private_key()` verifies private key availability
    - Windows: extracts raw bytes from CERT_CONTEXT
    - Non-Windows: stub certificate for testing
  - `app.rs`: Certificate authentication support
    - `set_client_certificate()` for mTLS configuration
    - `client_certificate_thumbprint()` accessor
    - `has_client_certificate()` check
    - Certificate chain passed to CallManager
- `client-gui` certificate usage
  - `settings.rs`: UseCertificate action
    - "Use Selected Certificate" button
    - Private key verification before use
    - Status message feedback
  - `app.rs`: Certificate configuration flow
    - Pending certificate storage for delayed init
    - Certificate chain retrieval and validation

**Phase 24.13: PIN Entry UI**

- `client-gui` PIN dialog implementation
  - `app.rs`: Modal PIN dialog for smart card authentication
    - Masked password input field
    - Lock icon with clear visual styling
    - PIN attempt counter with lockout warning (max 3 attempts)
    - Enter key submission support
    - Focus management for keyboard-first input
    - Cancel button for user abort
  - `PinOperation` enum for tracking PIN context
    - `UseCertificate { thumbprint }` - certificate selection
    - `Register { account_id }` - SIP registration signing
    - `SignCall { call_id }` - DTLS call establishment
  - PIN dialog state management
    - `show_pin_dialog`, `pin_input`, `pin_error` fields
    - `pin_operation` for operation context
    - `pin_attempts` for retry tracking
  - Methods: `show_pin_dialog_for()`, `submit_pin()`, `cancel_pin()`, `use_certificate_with_pin()`
- `client-gui` Settings integration
  - `settings.rs`: `SettingsAction::PinRequired { thumbprint }` variant
- `client-core` async event support
  - `app.rs`: PIN-related AppEvent variants
    - `PinRequired { operation, thumbprint }` - trigger PIN dialog
    - `PinCompleted { success, error }` - report PIN result
  - `PinOperationType` enum: CertificateSelection, Registration, CallEstablishment
  - Exported in `lib.rs` for GUI access
- Integration with CertStoreError
  - Automatic PIN dialog on `CertStoreError::PinRequired`
  - Handles `CertStoreError::PinIncorrect` with error display
  - Smart card not present detection via `CertStoreError::SmartCardNotPresent`

**Security**

- Smart card authentication ONLY (CAC/PIV/SIPR token)
- NO password-based digest authentication
- Mutual TLS with client certificates from Windows Certificate Store
- TLS 1.3 only for signaling (CNSA 2.0 compliance)

**Dependencies Added**

- `cpal` 0.17: Cross-platform audio I/O
- `ringbuf` 0.4: Lock-free ring buffers for audio threads
- `egui` 0.33: Immediate mode GUI
- `eframe` 0.33: egui framework with wgpu backend
- `directories` 6: Platform-specific config paths
- `tray-icon` 0.21: System tray integration
- `rfd` 0.17: Native file dialogs
- `winrt-notification` 0.5: Windows toast notifications
- `windows` 0.62: Windows CryptoAPI for smart card access
- `uuid` 1.16: UUID generation for call IDs

#### CDR Export Endpoints

**uc-api - CDR Export Routes (NIST 800-53: AU-2, AU-3, AU-9)**

- New CDR management routes (`/api/v1/cdrs/*`):
  - `GET /` - List CDRs with pagination and filtering
  - `GET /:id` - Get specific CDR by call ID
  - `GET /export` - Bulk export CDRs in JSON or CSV format
  - `GET /stats` - Get CDR statistics and summary metrics
  - `GET /search` - Search CDRs by caller, callee, or criteria
  - `GET /correlation/:correlation_id` - Get related calls by correlation ID
  - `DELETE /purge` - Purge CDRs older than specified date

- CDR API types (`cdr.rs`):
  - `CdrQueryParams` with filtering: time range, caller, callee, status, trunk, direction, duration, IPs
  - `CdrExportFormat` enum: Json, Csv with content type and extension helpers
  - `CdrExportRequest` with filters, format, header inclusion, field selection, limit
  - `CdrStats` with totals, ASR, failure rate, calls by status/cause/trunk
  - `CdrSearchResult` for search response items
  - `CdrPurgeRequest` / `CdrPurgeResponse` for maintenance operations
  - Query parameter parsing from HTTP query strings

- Permissions: `cdr:read`, `cdr:export`, `cdr:admin`
- `SbcRoutes::cdrs()` added to `SbcRoutes::all()` aggregate

**Tests**: 11 new tests for CDR routes and types

#### DNS Integration

**uc-dns - DNS Resolution for SIP (New Crate)**

- New crate for DNS-based SIP routing:
  - `SipResolver` implementing RFC 3263 NAPTR → SRV → A/AAAA resolution chain
  - `SipTarget` with address, transport, hostname, priority, weight
  - `TransportPreference` enum: Any, Udp, Tcp, Tls, Sctp, WebSocket, WebSocketSecure
  - Support for numeric IP addresses (bypass DNS)
  - Cache-aware resolution with configurable TTL

- `SrvResolver` for SRV record handling (RFC 2782):
  - `SrvRecord` with priority, weight, port, target, addresses
  - Weighted selection algorithm per RFC 2782
  - `sip_srv_name()` for constructing SRV query names
  - SRV record parsing from DNS response strings

- `NaptrResolver` for NAPTR record handling (RFC 3403):
  - `NaptrRecord` with order, preference, flags, service, regexp, replacement
  - `NaptrService` enum: SipUdp, SipTcp, SipsTcp, SipSctp, SipWs, SipsWs
  - Transport selection from NAPTR service field
  - NAPTR record parsing from DNS response strings

- `EnumResolver` for ENUM lookup (RFC 6116):
  - E.164 number to ENUM domain conversion
  - `EnumResult` with number, URI, service, order, preference
  - NAPTR regexp application for URI derivation
  - Multi-domain support (e164.arpa, e164.org)

- `DnsCache` for TTL-based caching:
  - `CachedRecord<T>` with TTL tracking, expiration, age
  - `CacheEntry` enum: Address, Srv, Naptr, Enum, Negative
  - Configurable min/max TTL bounds
  - Negative cache for NXDOMAIN responses
  - LRU-style eviction when at capacity
  - `CacheStats` for utilization monitoring

- Configuration structures:
  - `DnsConfig` with server addresses, timeout, retries, cache settings
  - `SipResolverConfig` with transport preferences, NAPTR/SRV flags
  - `EnumConfig` with domain suffixes, preferred services
  - `TransportPref` with `naptr_service()` and `srv_prefix()` methods
  - `DefaultPorts` for transport-specific default ports

- Hickory-resolver integration (optional `resolver` feature):
  - `HickoryDnsResolver` for actual DNS queries using hickory-resolver 0.25
  - A/AAAA lookup with `lookup_addresses()`
  - SRV lookup with `lookup_srv()` and `lookup_sip_srv()`
  - NAPTR lookup with `lookup_naptr()`
  - Combined SRV + address resolution with `lookup_srv_with_addresses()`
  - Integration with `SipResolver` for full RFC 3263 resolution
  - TTL-based caching with hickory responses
  - IP passthrough for numeric addresses

**Tests**: 46 tests for DNS crate (38 base + 8 hickory integration)

#### Phase 23: Specialized Protocols

**uc-t38 - T.38 Fax Relay (RFC 4612)**

- New crate for T.38 real-time fax relay:
  - `UdptlTransport` for UDP Transport Layer with error correction
  - `UdptlPacket` encode/decode with redundancy and FEC support
  - `ErrorCorrectionMode` enum: None, Redundancy, Fec
  - `IfpPacket` per ITU-T T.38 with 16 data types
  - `T30Indication` for fax signal indications (CNG, CED, training, etc.)
  - `DataType` enum with V.21, V.27ter, V.29, V.17, V.34 support
  - `SignalDetector` with Goertzel algorithm for CNG/CED tone detection
  - `T30Signal` enum with 22 T.30 signal types
  - `FaxPhase` enum: PhaseA through PhaseE
  - `T38Session` with full state machine and session statistics
  - `T38SessionManager` for multi-session management
  - `T38Config` with UDPTL, session, and error correction settings
  - Auto-switch from audio to T.38 on CNG/CED detection

**uc-transport - SCTP Transport (RFC 4168)**

- New feature `sctp` for SCTP transport support:
  - `SctpAssociation` implementing `Transport` and `StreamTransport` traits
  - `SctpState` enum: Closed, CookieWait, CookieEchoed, Established, ShutdownPending, ShutdownSent, ShutdownAckSent
  - `SctpConfig` with full SCTP parameters (streams, retransmissions, heartbeat, RTO, MTU)
  - `StreamId` for multi-stream support
  - Multi-homing with `add_peer_address()` and `set_primary_path()`
  - `SctpListener` for accepting incoming associations (stub)

**uc-types - Transport Type Extension**

- Added `TransportType::Sctp` variant for SCTP transport

**Tests**: 25 new tests for T.38 crate

#### Phase 20: WebRTC & Modern Transports

**uc-transport - WebSocket Transport (RFC 7118)**

- New WebSocket transport module (`websocket.rs`):
  - `WebSocketTransport` implementing `Transport` and `StreamTransport` traits
  - `WebSocketListener` for accepting incoming connections
  - `WebSocketState` enum: Connecting, Open, Closing, Closed
  - SIP-over-WebSocket framing (text frames for SIP messages)
  - Binary frame support for SDP bodies
  - Ping/pong keepalive handling
  - Secure WebSocket (WSS) support with TLS
  - `SIP_SUBPROTOCOL` constant ("sip") per RFC 7118
- New feature flag `websocket` with dependencies:
  - `tokio-tungstenite` for WebSocket protocol
  - `futures-util` for stream combinators

**uc-webrtc - WebRTC Gateway (New Crate)**

- New crate for SIP-to-WebRTC interworking:
  - `WebRtcGateway` for SIP-to-WebRTC call bridging
  - `GatewayResponse` with session ID, SDP, ICE credentials, DTLS fingerprint
  - `GatewayStats` for monitoring (sessions created/completed/failed, active sessions)
  - Session creation from SIP calls
  - Bidirectional SDP processing (SIP-to-WebRTC, WebRTC-to-SIP)
  - ICE candidate handling for remote candidates

- `WebRtcSession` session management:
  - `WebRtcSessionState` enum: New, HaveLocalDescription, HaveRemoteDescription, Connecting, DtlsHandshaking, Connected, Disconnected, Failed, Closed
  - Local and remote SDP storage
  - ICE candidate tracking (local and remote)
  - ICE credentials (ufrag, pwd) management
  - DTLS fingerprint storage
  - SIP Call-ID association
  - Session age and idle time tracking
  - `SessionManager` for multi-session management with configurable limits

- `SdpMunger` for SDP transformation:
  - `WebRtcSdpMode` enum: SipToWebRtc, WebRtcToSip
  - RTP-to-SRTP profile conversion (RTP/AVP to RTP/SAVPF)
  - ICE credential extraction from SDP
  - DTLS fingerprint extraction
  - Configurable SDP transformation rules

- `TrickleIce` for ICE candidate trickling (RFC 8838):
  - `TrickleCandidate` with candidate string, m-line index, mid, ufrag
  - `TrickleState` enum: Idle, Gathering, Receiving, Complete
  - Local and remote candidate management
  - Broadcast channel for new candidate notifications
  - End-of-candidates indicator support
  - `TrickleManager` for multi-session trickle ICE handling

- Configuration structures:
  - `WebRtcConfig` with enabled flag and sub-configs
  - `IceConfig` for ICE parameters (STUN servers, trickle, lite mode)
  - `DtlsConfig` for DTLS parameters (fingerprint algorithm, role)
  - `SessionConfig` for session limits (max sessions, idle timeout)
  - `SdpConfig` for SDP transformation options

**Tests**: 24 new tests across WebRTC components

#### Phase 22: High Availability & Clustering

**uc-cluster - Core Clustering Primitives**

- New crate for cluster management:
  - `NodeId`, `NodeRole` (Primary/Secondary/Witness), `NodeState` types
  - `ClusterNode` with endpoints, health score, zone/region awareness
  - `ClusterMembership` manager with add/remove/get node operations
  - `QuorumPolicy` enum: Majority, All, Count, Weighted
  - `HealthChecker` with heartbeat tracking and suspect/dead thresholds
  - `HealthStatus` enum: Healthy, Suspect, Dead
  - `FailoverCoordinator` with automatic and manual failover
  - `SessionTakeoverHandler` trait for session migration
  - `FailoverPhase` enum for failover state tracking
  - `TakeoverResult` with transfer statistics
  - Failover strategies: PreferSameZone, PreferSameRegion, LeastLoaded, Priority

**uc-discovery - Service Discovery**

- New crate for peer discovery:
  - `DiscoveryProvider` trait with async discover method
  - `StaticDiscovery` for configured peer lists
  - `DnsDiscovery` stub for DNS SRV/A lookup (feature-gated)
  - `KubernetesDiscovery` stub for K8s API (feature-gated)
  - `GossipProtocol` for SWIM-style failure detection
  - `MemberStatus` enum: Alive, Suspect, Dead
  - `GossipMessage` variants: Ping, Ack, PingReq, Membership

**uc-storage - Storage Backends**

- New crate for pluggable storage:
  - `StorageBackend` trait with get/set/delete/keys/increment
  - `InMemoryBackend` with TTL support and glob-style pattern matching
  - `RedisBackend` stub (feature-gated)
  - `PostgresBackend` stub (feature-gated)
  - `StorageManager` with health checking

**uc-state-sync - State Replication Engine**

- New crate for distributed state:
  - CRDT implementations: `GCounter`, `PNCounter`, `LWWRegister`
  - `Replicable` trait for state that can be replicated
  - `StateReplicator` with configurable replication modes
  - `ReplicationMode` enum: Sync, Async, SemiSync
  - `ReplicationMessage` protocol for wire format
  - `StateSnapshot` for bulk state transfer
  - `SnapshotWriter` and `SnapshotReader` for chunked transfers
  - `EntryType` enum: KeyValue, Registration, CallState, Crdt, Config

**uc-aaa - AAA Integration**

- New crate for authentication/authorization/accounting:
  - `AaaProvider` trait with authenticate/authorize/accounting methods
  - `RadiusClient` for RADIUS server communication
  - `AuthRequest` and `AuthResponse` types
  - `AccountingRecord` for CDR-style accounting
  - `AccountingType` enum: Start, Stop, Interim

**uc-snmp - SNMP Trap Generation**

- New crate for SNMP monitoring:
  - `TrapSender` for SNMPv2c trap generation
  - `SnmpTrap` struct with OID, values, and timestamp
  - `TrapType` enum with 14 trap types:
    - NodeUp, NodeDown, NodeDegraded
    - CallStart, CallEnd, CallFailed
    - RegistrationAdded, RegistrationRemoved, RegistrationExpired
    - QuorumLost, QuorumRestored
    - HighCpuUsage, HighMemoryUsage
    - CertificateExpiring

**uc-syslog - Syslog Forwarding**

- New crate for log forwarding:
  - `SyslogForwarder` with UDP and TCP transport
  - `SyslogMessage` with RFC 5424 and BSD format support
  - `Severity` enum: Emergency through Debug
  - `Facility` enum: Kern, User, Mail, Daemon, Auth, Syslog, etc.
  - Automatic hostname and process ID detection

**sbc-config - Configuration Integration**

- Feature flags for optional clustering components:
  - `cluster` feature enables uc-cluster, uc-discovery, uc-storage, uc-state-sync
  - `aaa` feature enables uc-aaa
  - `snmp` feature enables uc-snmp
  - `syslog` feature enables uc-syslog
  - `full` feature enables all optional features
- `MonitoringConfig` struct with metrics endpoint and per-call metrics options
- Re-exports for cluster config types when features enabled

**uc-api - Cluster API Endpoints**

- New cluster management routes (`/api/v1/cluster/*`):
  - `GET /status` - Cluster status and quorum information
  - `GET /members` - List all cluster members
  - `GET /members/:id` - Get specific member details
  - `POST /failover` - Initiate automatic failover
  - `POST /failover/manual` - Manual failover to specific target
  - `POST /drain` - Drain sessions for maintenance
  - `POST /rejoin` - Rejoin cluster after maintenance
  - `GET /state/sync-status` - State synchronization status
  - `POST /state/force-sync` - Force state synchronization
  - `GET /state/snapshot` - Get current state snapshot
  - `POST /state/snapshot/restore` - Restore from snapshot
- `SbcRoutes::all()` method combining all route groups

#### P0 Critical RFC Compliance Gaps

**proto-dtls (RFC 6347 §4.2.4, §4.2.6)**

- DTLS certificate verification (`verify.rs`):
  - `DtlsCertificateVerifier` with RFC 6347 §4.2.4 compliant verification
  - `CertificateChainValidator` for X.509 chain validation
  - `verify_certificate_chain()` with trusted CA store
  - `verify_self_signed()` for fingerprint-based WebRTC validation
  - `VerificationMode` enum: FullChain, FingerprintOnly, SelfSignedAllowed
  - `CertificateInfo` extraction (subject, issuer, validity, fingerprint)
  - CNSA 2.0 compliant: SHA-384 fingerprints, P-384/P-521 curves only

- DTLS Finished message validation:
  - `verify_finished_message()` per RFC 6347 §4.2.6
  - PRF-based verify_data computation with HMAC-SHA384
  - Handshake transcript hashing for verification
  - `FinishedMessageError` variants for specific failure modes

**proto-ice (RFC 7675 §6)**

- ICE consent revocation (`consent.rs`):
  - `revoke_consent()` for explicit consent withdrawal per RFC 7675 §6
  - `ConsentState::Revoked` for distinguishing revocation from expiration
  - `ConsentRevocationReason` enum: UserInitiated, SecurityConcern, SessionTerminating, MediaTimeout, PolicyViolation
  - `is_revoked()` and `revocation_reason()` accessors
  - Revoked state immediately stops all media transmission

**proto-turn (RFC 5766 §9, §12)**

- TURN Send/Data indications (`indication.rs`):
  - `SendIndication` struct per RFC 5766 §9
  - `DataIndication` struct per RFC 5766 §12
  - XOR-PEER-ADDRESS and DATA attribute handling
  - `encode()` methods for wire format generation
  - Indication class (0x10) message type handling

**proto-sip (RFC 3261 §13.2.2.4)**

- SIP redirect handling (`redirect.rs`):
  - `RedirectHandler` for 3xx response processing
  - `RedirectContact` with q-value priority parsing
  - `RedirectResult` enum: Redirect, TooManyRedirects, Failure, NoAlternatives
  - `process_redirect_response()` for 300-305 handling
  - `select_next_target()` with priority-based selection
  - Loop detection via visited URI tracking
  - Configurable max_redirects limit

#### P1 High Priority RFC Compliance Gaps

**proto-registrar (RFC 5626 §5.2)**

- SIP Outbound flow maintenance (`outbound.rs`):
  - `FlowTransport` enum: Udp, Tcp, Tls, WebSocket, WebSocketSecure
  - `FlowState` enum: Active, Probing, Suspect, Failed, Recovering
  - `FlowId` and `FlowToken` types for flow identification
  - `Flow` struct with keepalive tracking and health monitoring
  - `OutboundFlowManager` for multi-flow management
  - `FlowAction` enum for keepalive actions (STUN, CRLF, WebSocket ping)
  - Transport-specific keepalive selection per RFC 5626
  - Configurable intervals and failure thresholds

**proto-ice (RFC 8445 §7.2.2)**

- ICE aggressive nomination support:
  - `IceConfig.aggressive_nomination` flag (was already present)
  - `IceAgent::aggressive_nomination()` accessor
  - `IceAgent::should_nominate_check()` - determines USE-CANDIDATE inclusion
  - `IceAgent::create_connectivity_check()` - auto-applies nomination strategy
  - `IceAgent::create_connectivity_check_with_nomination()` - explicit control
  - Controlling agent only: controlled agents cannot nominate
  - Exported `IceConfig` from lib.rs

**proto-sdp (RFC 3264 §8.4)**

- SDP offer/answer media modification rules (`offer_answer.rs`):
  - `MediaModificationValidator` for RFC 3264 compliance validation
  - `MediaModification` and `MediaModificationType` for change description
  - `generate_answer()` - creates answer from offer with capability matching
  - `validate_answer()` - validates answer against offer
  - `compute_answer_direction()` - direction negotiation per §6.1
  - `hold_media_stream()` / `resume_media_stream()` - call hold support
  - `disable_media_stream()` / `enable_media_stream()` - port=0 handling
  - `LocalCapabilities` and `LocalMediaCapability` for endpoint configuration
  - `NegotiationResult` and `MediaNegotiationResult` for validation results
  - `HoldType` enum: SendOnly, Inactive

**proto-stun (RFC 5389 §10.2)**

- STUN long-term credential mechanism (`credential.rs`):
  - `LongTermCredentials` for client-side authentication
  - `LongTermCredentialValidator` for server-side validation
  - `AuthResult` enum: Success, ChallengeRequired, Failed, StaleNonce
  - `update_from_challenge()` for 401 response handling
  - `compute_key()` using SHA-384 (CNSA 2.0 compliant deviation from MD5)
  - `generate_nonce()` with HMAC-SHA384 signatures and timestamps
  - `validate_nonce()` with expiration checking
  - `create_challenge_response()` for 401 generation
  - `create_stale_nonce_response()` for 438 generation
  - Configurable nonce lifetime (default 10 minutes per RFC 5389)

#### Phase 19: SIP Authentication & Security

**proto-registrar (RFC 3261 §22)**

- SIP Digest authentication (`authentication.rs`):
  - `Authenticator` struct with nonce generation/validation
  - `NonceState` with expiration tracking and nonce count validation
  - `AuthChallenge` for 401/407 response generation
  - `AuthCredentials` with full digest auth parameter parsing
  - `AuthResult` enum: Success, ChallengeRequired, StaleNonce, Failed
  - `AuthAlgorithm` enum: MD5, SHA256, SHA512_256
  - `AuthQop` enum: Auth, AuthInt (integrity protection)
  - `AuthenticatedRegistrar` combining Registrar + Authenticator
  - Password lookup callback pattern for credential retrieval
  - Nonce count (nc) tracking for replay attack prevention
  - Stale nonce detection and renewal with opaque parameter

**proto-sip (RFC 3323/RFC 5765)**

- Topology hiding (`topology.rs`):
  - `TopologyHider` for SIP message anonymization
  - `TopologyHidingConfig` with external host and mode settings
  - `TopologyHidingMode` enum: None, Basic, Aggressive
  - Via header stripping for internal network addresses
  - `anonymize_via()` with received/rport parameter hiding
  - Contact header anonymization with external URI substitution
  - Record-Route rewriting with anonymized record routes
  - Call-ID obfuscation with bidirectional mapping
  - `obfuscate_call_id()` / `restore_call_id()` for symmetric operation
  - Internal network detection via configurable prefixes (RFC 1918)
  - `hide_outbound_request()` and `hide_inbound_response()` convenience methods

**proto-sdp (RFC 4568)**

- SRTP-SDES key exchange (`srtp.rs`):
  - `CryptoAttribute` parsing per RFC 4568 format
  - `CipherSuite` enum: AES_CM_128_HMAC_SHA1_80/32, F8_128_HMAC_SHA1_80, AEAD_AES_128/256_GCM
  - `KeyParams` with base64 keying material, lifetime, MKI support
  - `master_key()` and `master_salt()` extraction per cipher suite
  - `SessionParams` for KDR, UNENCRYPTED_SRTP/SRTCP, FEC options
  - `FecOrder` enum: FecSrtp, SrtpFec
  - `SrtpNegotiator` for cipher suite selection with preferences
  - `extract_crypto_attributes()` for SDP parsing
  - `supports_sdes()` and `uses_dtls_srtp()` protocol detection helpers
  - `generate_keying_material()` for SRTP key generation

#### P3 Low Priority RFC Compliance Gaps

**proto-sdp (RFC 3264 §6.2)**

- Multicast stream negotiation (`multicast.rs`):
  - `MulticastAddress` struct with IPv4/IPv6 scope detection
  - `MulticastNegotiator` for offer/answer multicast validation
  - `MulticastScope` enum: NodeLocal, LinkLocal, RealmLocal, AdminLocal, SiteLocal, Organization, Global
  - `MulticastValidation` struct with TTL and scope validation results
  - `is_multicast_address()` for detecting multicast addresses
  - `is_multicast_media()` for checking if media description uses multicast
  - TTL validation for IPv4 multicast
  - Administrative scope checking for IPv6 multicast

**proto-rtp (RFC 3550 §7)**

- RTP translators and mixers (`translator.rs`):
  - `RtpTranslator` for SSRC-preserving packet forwarding
  - `RtpMixer` for multi-source mixing with CSRC list management
  - `SourceState` for tracking per-source RTP state (sequence, timestamp, packets)
  - `SsrcCollisionDetector` for loop prevention
  - `TranslatorRtcpBuilder` for combined RTCP reports from multiple sources
  - `CsrcValidation` struct for CSRC list validation results
  - `validate_csrc_list()` function for RFC compliance checking
  - `MAX_CSRC_COUNT` constant (15) per RFC 3550

**proto-sip (RFC 3261 §16.6)**

- SIP proxy request forwarding (`proxy.rs`):
  - `ProxyContext` for proxy configuration (URI, transport, host, port)
  - `ProxyValidation` struct for request validation results
  - `ForwardingTarget` with priority, q-value, and transport override
  - `ForkingMode` enum: None, Parallel, Sequential
  - `RequestForwarder` implementing full RFC 3261 §16.6 compliance:
    - Max-Forwards validation and decrement (§16.3, §16.6 step 3)
    - Via header insertion at correct position (§16.6 step 8)
    - Record-Route header insertion (§16.6 step 5)
    - Loop detection via Via headers (§16.3 step 4)
    - Request forking with priority/q-value ordering
  - `ResponseProcessor` for upstream forwarding:
    - Topmost Via removal (§16.7)
    - Best response selection for forked requests (6xx > 2xx > 3xx priority)
  - Helper functions: `create_trying_response()`, `create_too_many_hops_response()`, `create_loop_detected_response()`

#### Phase 21: Advanced SBC Features

**proto-sip Header Manipulation Engine**

- Header manipulation engine (`manipulation.rs`):
  - `ManipulationAction` enum: Add, Set, Remove, RemoveMatching, Replace, RegexReplace, Rename, Copy, Prepend, Append
  - `ManipulationCondition` enum: Always, HeaderExists, HeaderMissing, HeaderContains, HeaderEquals, HeaderMatches, MethodEquals, Any, All, Not
  - `ManipulationRule` with priority ordering and enable/disable
  - `ManipulationPolicy` per-direction and per-message-type policies
  - `HeaderManipulator` with global and per-trunk policy management
  - `ManipulationContext` for request/response/trunk filtering
  - `ManipulationPresets` for common rules (normalize UA, strip PAI, RPID-to-PAI)
  - Basic regex pattern matching (^anchor, $anchor, capture groups)
  - Exported from lib.rs for public API access

**uc-siprec - SIPREC Call Recording (RFC 7865/7866)**

New crate for session recording:
- `config.rs` - Recording configuration:
  - `SrsEndpoint` for recording server (primary/backup, weight, health)
  - `RecordingMode` enum: Selective, AllCalls, OnDemand, Disabled
  - `RecordingTrigger` conditions (trunk, caller/callee pattern, header match, time window)
  - `RecordingMediaOptions` for audio/video/DTMF settings
  - `RecordingConfig` with max sessions, retry, exempt trunks

- `metadata.rs` - Recording metadata per RFC 7865:
  - `RecordingMetadata` top-level container
  - `SessionMetadata` with recording session ID, state, timestamps
  - `Participant` with AoR, display name, role, join/leave times
  - `MediaStream` with codec, SSRC, direction, participant association
  - `ParticipantRole` enum: Caller, Callee, Observer, Supervisor
  - `StreamDirection` enum: Send, Receive, SendReceive, Inactive
  - `to_xml()` method for RFC 7865 compliant XML generation

- `forking.rs` - Media forking:
  - `MediaForker` for RTP stream duplication management
  - `StreamFork` with source/dest/fork addresses and SSRC
  - `ForkingMode` enum: BothDirections, InboundOnly, OutboundOnly, Disabled
  - `ForkerState` lifecycle: Uninitialized, Initialized, Active, Paused, Stopped, Error
  - Packet/byte counting statistics per stream

- `session.rs` - Recording session management:
  - `RecordingSession` with full lifecycle state machine
  - `RecordingSessionState`: Created, Inviting, Proceeding, Active, OnHold, Terminating, Terminated, Failed
  - `SessionRecordingClient` (SRC) for managing recording sessions
  - `RecordingContext` for trigger evaluation
  - `SessionRecordingEvent` for session lifecycle notifications
  - Participant and stream management

**uc-transport QoS Module (RFC 2474/4594)**

- QoS DSCP marking (`qos.rs`):
  - `DscpValue` enum with all standard classes: BE, CS1-7, AF11-43, EF
  - `to_tos()` conversion (DSCP << 2)
  - `TrafficType` classification: VoiceMedia, VideoMedia, VoiceSignaling, VideoSignaling, Management
  - `QosConfig` with traffic type and enable flag
  - `TrunkQosPolicy` for per-trunk signaling/media QoS settings
  - `QosPolicyManager` with global defaults and trunk overrides
  - `apply_dscp()` for IPv4 (`IP_TOS`) and IPv6 (`IPV6_TCLASS`) sockets
  - Preset configs: `voice_signaling()`, `voice_media()`, `video_signaling()`, `video_media()`

**uc-policy Call Admission Control**

- CAC and bandwidth management (`cac.rs`):
  - `CallAdmissionController` central admission control:
    - Per-trunk and global session limits
    - Bandwidth tracking with codec estimation
    - Call rate limiting (CPS)
    - Emergency call bypass per RFC 4412
  - `TrunkCacLimits` configuration:
    - `max_sessions`, `max_bandwidth_kbps`, `max_cps`
    - `emergency_reserve_percent` for priority calls
    - `allowed_codecs` for codec restriction
  - `AdmissionDecision` enum: Admitted, Rejected, Queued
  - `RejectionReason` enum: MaxSessionsExceeded, BandwidthExceeded, RateLimitExceeded, TrunkDisabled, CodecNotAllowed
  - `CallPriority` per RFC 4412: Emergency, Critical, Priority, Normal, NonUrgent, BestEffort
  - `CodecBandwidth` estimates (G.711: 90kbps, G.729: 32kbps, G.722: 90kbps, Opus: 50kbps)
  - `TrunkStats` with session/bandwidth utilization metrics
  - Commit/release call tracking for real-time counters

#### P2 Medium Priority RFC Compliance Gaps

**proto-registrar (RFC 5627 §5.1)**

- Proxy GRUU routing (`gruu.rs`):
  - `GruuRouter` for RFC 5627 §5.1 compliant GRUU routing
  - `GruuRoutingResult` enum: Resolved, RegistrationExpired, NotFound, NotAGruu
  - `route()` - resolves GRUU URI to routing target
  - `route_to_binding()` - returns full Binding for GRUU
  - `is_gruu_active()` - checks if GRUU has active registration
  - `get_aor_for_gruu()` - extracts AOR for authorization
  - `extract_gruu_info()` - parses GRUU type (public vs temporary)
  - Path header forwarding for outbound flows
  - Lowest reg-id selection per RFC 5627 §5.1 for multiple flows

**proto-rtp (RFC 3550 §6.3.5)**

- RTCP transmission scheduling (`scheduler.rs`):
  - `RtcpScheduler` implementing RFC 3550 Appendix A.7 algorithm
  - `SessionParams` for bandwidth, members, senders configuration
  - `compute_deterministic_interval()` based on RTCP bandwidth and participants
  - `compute_interval()` with [0.5, 1.5] randomization per §6.3.5
  - Sender/receiver bandwidth separation (25%/75%) per §6.3.1
  - Initial interval halving per §6.3.6
  - Timer reconsideration for membership changes
  - `IntervalBounds` for interval validation
  - Constants: `RTCP_MIN_INTERVAL_SECS`, `RTCP_BANDWIDTH_FRACTION`, `RTCP_COMPENSATION_FACTOR`

**proto-dialog (RFC 6665 §7.2)**

- Event package validation (`subscription.rs`):
  - `EventPackageRegistry` for IANA registration validation per RFC 6665 §7.2
  - `EventPackageValidation` enum: Valid, UnregisteredAllowed, Invalid
  - `IANA_REGISTERED_EVENT_PACKAGES` constant with all known packages
  - `validate()` - validates event type against registry
  - `is_iana_registered()` - checks IANA registration status
  - `add_custom_package()` / `remove_custom_package()` - extension support
  - Strict mode (rejects unregistered) vs permissive mode (warns only)
  - Case-insensitive validation
  - Convenience functions: `validate_event_package()`, `is_event_package_registered()`

**proto-sdp (RFC 4566 §5.11)**

- Repeat times r= line support (`session.rs`):
  - `RepeatTimes` struct per RFC 4566 §5.11
  - `TimeValue` with compact notation support (d/h/m/s suffixes)
  - `Timing` extended with `repeat_times` field
  - `RepeatTimes::parse()` / `to_string()` for r= line handling
  - `TimeValue::from_days()`, `from_hours()`, `from_minutes()`, `from_seconds()`
  - `TimeValue::to_compact_string()` for efficient encoding
  - `RepeatTimes::daily()` / `weekly()` convenience constructors
  - `is_valid()` validation (interval, duration, offsets)
  - Full SDP parsing/generation roundtrip support
  - Exported `Origin`, `Timing`, `RepeatTimes`, `TimeValue` from lib.rs

#### RFC Compliance Gaps - Phase 18 Completion

**proto-ice (RFC 8445 §6.2, §9-10, RFC 7675)**

- ICE connectivity check implementation (`connectivity.rs`):
  - `ConnectivityCheck` struct for STUN-based connectivity verification
  - `ConnectivityChecker` with triggered check queue per RFC 8445 §6.1.4
  - `IceStunServer` for processing STUN Binding requests/responses
  - `CheckResult` states: Success, Failure, Timeout, RoleConflict, InvalidCredentials
  - USE-CANDIDATE nomination for controlled/controlling role
  - Role conflict handling with 487 error response
  - Transaction ID generation and tracking

- ICE consent and keepalive implementation (`consent.rs`):
  - `ConsentTracker` with 5-second check interval per RFC 7675
  - 30-second consent timeout with automatic expiration
  - `KeepaliveTracker` with 15-second STUN Binding indications
  - `ConsentKeepaliveManager` combining consent and keepalive logic
  - `ConsentState` enum: Pending, Granted, Expired
  - `ConsentKeepaliveAction` enum for poll-based state machine

**proto-dtls (RFC 5764)**

- SRTP keying material export (`srtp_export.rs`):
  - `SrtpKeyExporter` for DTLS-SRTP key derivation
  - `EXTRACTOR-dtls_srtp` exporter label per RFC 5764 §4.2
  - 88-byte keying material layout (2×32-byte keys + 2×12-byte salts)
  - `UseSrtpExtension` encode/decode for use_srtp TLS extension
  - HKDF-SHA384 PRF for CNSA 2.0 compliant key derivation
  - Support for AEAD_AES_256_GCM profile (profile ID 0x0008)

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

**proto-transaction (RFC 3261 §17, RFC 3262)**

- CSeq validation for transaction matching (RFC 3261 §17.1.3):
  - `CSeqTracker` struct for tracking sequence numbers and methods
  - `CSeqValidation` enum: Valid, Retransmission, TooLow, MethodMismatch
  - Request validation with `validate()` and response correlation with `validate_response()`
- RFC 3261 branch magic cookie constant (`RFC3261_BRANCH_MAGIC = "z9hG4bK"`)
- UPDATE method transaction support (RFC 3311) using non-INVITE state machine
- Reliable provisional responses (RFC 3262 - 100rel):
  - `RAck` header parsing and formatting
  - `ReliableProvisionalTracker` for UAS-side PRACK management
  - `ClientReliableProvisionalTracker` for UAC-side tracking
  - RSeq sequence management with T1/T2 retransmission timers
  - `supports_100rel()` and `requires_100rel()` header parsing

**proto-sip (RFC 3261, RFC 3327)**

- Path header support (RFC 3327) for proxy routing:
  - `HeaderName::Path` variant with `allows_multiple() = true`
  - Helper methods: `path_values()`, `add_path()`, `prepend_path()`
- Routing module (`routing.rs`) with Route/Record-Route processing:
  - `process_record_route()` for UAC/UAS route set construction
  - `construct_request_route()` for in-dialog request routing
  - Loose routing (`lr` parameter) detection and handling

**proto-dialog (RFC 3261 §12, RFC 3515, RFC 4028, RFC 6665)**

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
- Event notification framework (RFC 6665):
  - `EventPackage` for event type identification (presence, dialog, message-summary)
  - `Subscription` for subscriber-side subscription management
  - `Notifier` for server-side subscription handling
  - `SubscriptionState`: Pending, Active, Terminated
  - `SubscriptionStateHeader` parsing and formatting
  - `TerminationReason` enum for subscription termination causes

**proto-b2bua (RFC 7092, RFC 5853, RFC 3960)**

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
- Early media handling (RFC 3960):
  - `EarlyMediaHandler` for 183 Session Progress with SDP
  - `EarlyMediaMode`: None, LocalRingback, Relay, Gate
  - `EarlyMediaSession` for per-leg early media state
  - `EarlyMediaAction` enum for handler responses
  - `is_early_media_response()` and `should_setup_early_media()` helpers

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
- Power of 10 Rule 4 compliance: Refactored 10 functions exceeding 60 lines into smaller helpers:
  - `uc-policy/condition.rs`: Extracted `match_ip()`, `match_optional_string()`, `evaluate_all()`, `evaluate_any()` helpers
  - `proto-sdp/session.rs`: Created `SdpParseState` struct with 13 helper methods for SDP parsing
  - `proto-sip/auth.rs`: Extracted `get_required_param()`, `filter_extra_params()` for digest auth parsing
  - `proto-sip/uri.rs`: Extracted `parse_uri_params()`, `parse_user_info()`, `parse_host_port()`, `parse_uri_headers()`
  - `proto-sip/header_params.rs`: Extracted `parse_quoted_display_name()`, `extract_display_name()`, `extract_uri_and_params()`, `parse_nameaddr_params()`
  - `uc-cdr/format.rs`: Extracted `add_required_fields()`, `add_optional_fields()`, `add_timing_fields()`, `format_custom_fields()`
  - `uc-transport/tcp.rs`: Extracted `create_tcp_socket()`, `configure_socket_options()`, `bind_and_listen()`, `socket_to_tokio_listener()`
  - `proto-ice/candidate.rs`: Extracted `parse_sdp_core_fields()`, `parse_sdp_transport()`, `parse_sdp_address()`, `parse_sdp_optional_fields()`, `parse_related_address()`
  - `proto-rtp/packet.rs`: Extracted `parse_first_byte()`, `parse_second_byte()`, `parse_csrc_list()`, `parse_extension_header()`
  - `uc-routing/router.rs`: Extracted `resolve_trunk_group()`, `select_trunk_from_group()`

### Fixed

- Comprehensive clippy lint fixes across 73 files in proto-*, uc-*, and sbc-daemon crates:
  - Added `#[allow(clippy::unwrap_used, clippy::expect_used)]` to test modules
  - Fixed `Attestation::from_str()` to use `Attestation::parse()` in proto-stir-shaken
  - Fixed type mismatches for `&NameAddr` and `&Candidate` parameters
  - Removed `.unwrap()` calls on unit type returns
  - Added numeric literal separators (e.g., `604_800`, `0x1234_5678`)
  - Fixed float comparisons to use epsilon-based comparison
  - Added `Default` implementations for types with `new()` constructors
  - Converted constant assertions to `const _: () = { assert!(...) };` blocks
  - Fixed similar variable name warnings with `#[allow(clippy::similar_names)]`
  - Fixed wildcard patterns in match arms
  - Added crate-level allows for `significant_drop_tightening`, `future_not_send`, `unused_async`
  - Converted `match` expressions to `let...else` where appropriate
  - Fixed cast truncation warnings with explicit `#[allow]` attributes
  - Fixed enum variant name warnings with `#[allow(clippy::enum_variant_names)]`
  - Fixed struct field name warnings with `#[allow(clippy::struct_field_names)]`

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
