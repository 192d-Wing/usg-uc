//! Media pipeline for RTP/SRTP processing.
//!
//! This module integrates the media layer components:
//! - `proto-rtp` for RTP packet handling
//! - `proto-srtp` for SRTP encryption/decryption
//! - `proto-dtls` for DTLS-SRTP key exchange
//! - `sbc-media-engine` for media relay/pass-through
//! - `sbc-codecs` for codec negotiation
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality (SRTP encryption)
//! - **SC-12**: Cryptographic Key Establishment (DTLS-SRTP)
//! - **SC-13**: Cryptographic Protection (CNSA 2.0)

use proto_dtls::{DtlsConfig, DtlsConnection, DtlsRole, DtlsState, SrtpKeyingMaterial};
use proto_rtp::{RtpHeader, RtpPacket, SequenceTracker};
use proto_srtp::{
    SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile, SrtpProtect, SrtpUnprotect,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};
use uc_codecs::{CodecCapability, CodecRegistry};
use uc_media_engine::session::SessionState;
use uc_media_engine::{MediaMode, MediaSession, MediaSessionConfig};
use uc_types::address::SbcSocketAddr;

/// Media pipeline configuration.
#[derive(Debug, Clone)]
pub struct MediaPipelineConfig {
    /// Default media mode for new sessions.
    pub default_mode: MediaMode,
    /// Whether SRTP is required.
    pub srtp_required: bool,
    /// Whether RTCP multiplexing is enabled.
    pub rtcp_mux: bool,
    /// Local codecs in preference order.
    pub local_codecs: Vec<CodecCapability>,
    /// Minimum RTP port for allocation.
    pub rtp_port_min: u16,
    /// Maximum RTP port for allocation.
    pub rtp_port_max: u16,
}

impl Default for MediaPipelineConfig {
    fn default() -> Self {
        Self {
            default_mode: MediaMode::Relay,
            srtp_required: true,
            rtcp_mux: true,
            local_codecs: vec![
                CodecCapability::opus(111),
                CodecCapability::g722(),
                CodecCapability::pcmu(),
                CodecCapability::pcma(),
            ],
            rtp_port_min: 16_384,
            rtp_port_max: 32_768,
        }
    }
}

/// Allocates RTP port pairs (even=RTP, odd=RTCP) from a configured range.
pub struct RtpPortAllocator {
    /// Next port to try.
    next_port: AtomicU16,
    /// Minimum port in range.
    min_port: u16,
    /// Maximum port in range.
    max_port: u16,
    /// Currently allocated ports.
    allocated: RwLock<std::collections::HashSet<u16>>,
}

impl RtpPortAllocator {
    /// Creates a new port allocator.
    pub fn new(min_port: u16, max_port: u16) -> Self {
        // Ensure min_port is even for RTP convention
        let min_port = if min_port % 2 == 0 { min_port } else { min_port + 1 };
        Self {
            next_port: AtomicU16::new(min_port),
            min_port,
            max_port,
            allocated: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Allocates an even-numbered RTP port. Returns (rtp_port, rtcp_port).
    pub async fn allocate_pair(&self) -> Result<(u16, u16), MediaPipelineError> {
        let mut allocated = self.allocated.write().await;
        let range_size = (self.max_port - self.min_port) / 2;

        for _ in 0..range_size {
            let port = self.next_port.fetch_add(2, Ordering::Relaxed);
            // Wrap around
            let port = self.min_port + ((port - self.min_port) % (self.max_port - self.min_port));
            // Ensure even
            let port = if port % 2 == 0 { port } else { port + 1 };

            if port + 1 >= self.max_port {
                continue;
            }

            if !allocated.contains(&port) {
                allocated.insert(port);
                allocated.insert(port + 1);
                return Ok((port, port + 1));
            }
        }

        Err(MediaPipelineError::PortExhausted)
    }

    /// Releases a port pair back to the pool.
    pub async fn release_pair(&self, rtp_port: u16) {
        let mut allocated = self.allocated.write().await;
        allocated.remove(&rtp_port);
        allocated.remove(&(rtp_port + 1));
    }
}

/// Media pipeline manages RTP/SRTP processing for all calls.
pub struct MediaPipeline {
    /// Configuration.
    config: MediaPipelineConfig,
    /// Codec registry for negotiation.
    codec_registry: CodecRegistry,
    /// Active media sessions by call ID.
    sessions: RwLock<HashMap<String, MediaSessionContext>>,
    /// DTLS connections by local address.
    dtls_connections: RwLock<HashMap<String, DtlsConnectionContext>>,
    /// RTP sequence trackers by SSRC.
    sequence_trackers: RwLock<HashMap<u32, SequenceTracker>>,
    /// Port allocator for RTP/RTCP ports.
    port_allocator: RtpPortAllocator,
}

/// Context for an active media session.
struct MediaSessionContext {
    /// The media session.
    session: MediaSession,
    /// SRTP context for outbound packets (A-leg).
    srtp_outbound_a: Option<SrtpContext>,
    /// SRTP context for inbound packets (A-leg).
    srtp_inbound_a: Option<SrtpContext>,
    /// SRTP context for outbound packets (B-leg).
    srtp_outbound_b: Option<SrtpContext>,
    /// SRTP context for inbound packets (B-leg).
    srtp_inbound_b: Option<SrtpContext>,
    /// A-leg remote address.
    a_leg_remote: Option<SbcSocketAddr>,
    /// B-leg remote address.
    b_leg_remote: Option<SbcSocketAddr>,
    /// A-leg SSRC.
    a_leg_ssrc: u32,
    /// B-leg SSRC.
    b_leg_ssrc: u32,
    /// A-leg local RTP port.
    a_leg_local_port: u16,
    /// B-leg local RTP port.
    b_leg_local_port: u16,
    /// Relay task handles (aborted on stop).
    relay_handles: Vec<JoinHandle<()>>,
    /// Shutdown sender for relay tasks.
    relay_shutdown: Option<tokio::sync::watch::Sender<bool>>,
}

/// Allocated port info returned from `create_session`.
#[derive(Debug, Clone)]
pub struct AllocatedPorts {
    /// A-leg RTP port.
    pub a_leg_rtp_port: u16,
    /// B-leg RTP port.
    pub b_leg_rtp_port: u16,
}

/// Context for a DTLS connection.
struct DtlsConnectionContext {
    /// The DTLS connection.
    connection: DtlsConnection,
    /// Associated call ID.
    call_id: String,
    /// Whether keying material has been exported.
    keys_exported: bool,
}

/// Result of processing an RTP packet.
#[derive(Debug)]
pub enum RtpProcessResult {
    /// Forward the packet to the destination.
    Forward {
        /// Processed packet data.
        data: Vec<u8>,
        /// Destination address.
        destination: SbcSocketAddr,
    },
    /// Packet was consumed (e.g., RTCP).
    Consumed,
    /// Error processing packet.
    Error {
        /// Error reason.
        reason: String,
    },
}

impl MediaPipeline {
    /// Creates a new media pipeline.
    pub fn new(config: MediaPipelineConfig) -> Self {
        let mut codec_registry = CodecRegistry::new();

        // Register local codecs
        for codec in &config.local_codecs {
            codec_registry.register(codec.clone());
        }

        info!(
            default_mode = ?config.default_mode,
            srtp_required = config.srtp_required,
            codec_count = config.local_codecs.len(),
            "Media pipeline created"
        );

        let port_allocator = RtpPortAllocator::new(config.rtp_port_min, config.rtp_port_max);

        Self {
            config,
            codec_registry,
            sessions: RwLock::new(HashMap::new()),
            dtls_connections: RwLock::new(HashMap::new()),
            sequence_trackers: RwLock::new(HashMap::new()),
            port_allocator,
        }
    }

    /// Creates a new media session for a call, allocating RTP port pairs.
    ///
    /// Returns the allocated ports so the SIP stack can use them in SDP.
    pub async fn create_session(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        let mode = mode.unwrap_or(self.config.default_mode);

        let mut config = MediaSessionConfig::new(call_id)
            .with_mode(mode)
            .with_srtp(self.config.srtp_required);

        for codec in &self.config.local_codecs {
            config = config.with_codec(codec.clone());
        }

        let session = MediaSession::new(config);

        // Allocate port pairs for A-leg and B-leg
        let (a_rtp, _a_rtcp) = self.port_allocator.allocate_pair().await?;
        let (b_rtp, _b_rtcp) = self.port_allocator.allocate_pair().await?;

        let a_leg_ssrc = generate_ssrc();
        let b_leg_ssrc = generate_ssrc();

        let context = MediaSessionContext {
            session,
            srtp_outbound_a: None,
            srtp_inbound_a: None,
            srtp_outbound_b: None,
            srtp_inbound_b: None,
            a_leg_remote: None,
            b_leg_remote: None,
            a_leg_ssrc,
            b_leg_ssrc,
            a_leg_local_port: a_rtp,
            b_leg_local_port: b_rtp,
            relay_handles: Vec::new(),
            relay_shutdown: None,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(call_id.to_string(), context);

        info!(
            call_id = %call_id,
            mode = ?mode,
            a_leg_port = a_rtp,
            b_leg_port = b_rtp,
            "Media session created with ports"
        );

        Ok(AllocatedPorts {
            a_leg_rtp_port: a_rtp,
            b_leg_rtp_port: b_rtp,
        })
    }

    /// Negotiates codecs with remote offer.
    pub async fn negotiate_codecs(
        &self,
        call_id: &str,
        remote_codecs: &[CodecCapability],
    ) -> Result<Vec<CodecCapability>, MediaPipelineError> {
        let negotiated = self.codec_registry.negotiate(remote_codecs);

        if negotiated.is_empty() {
            warn!(call_id = %call_id, "Codec negotiation failed - no common codecs");
            return Err(MediaPipelineError::CodecNegotiationFailed);
        }

        debug!(
            call_id = %call_id,
            negotiated_count = negotiated.len(),
            first_codec = %negotiated[0].name,
            "Codecs negotiated"
        );

        Ok(negotiated)
    }

    /// Initiates DTLS handshake for a leg.
    pub async fn start_dtls_handshake(
        &self,
        call_id: &str,
        local_addr: SbcSocketAddr,
        remote_addr: SbcSocketAddr,
        role: DtlsRole,
    ) -> Result<(), MediaPipelineError> {
        let config = DtlsConfig::new(role).with_identity(vec![vec![0u8; 32]], vec![0u8; 32]); // Placeholder cert

        let connection = DtlsConnection::new(config, local_addr, remote_addr)
            .map_err(|e| MediaPipelineError::DtlsHandshakeFailed(e.to_string()))?;

        let context = DtlsConnectionContext {
            connection,
            call_id: call_id.to_string(),
            keys_exported: false,
        };

        let key = format!("{call_id}:{local_addr}");
        let mut connections = self.dtls_connections.write().await;
        connections.insert(key.clone(), context);

        info!(
            call_id = %call_id,
            local_addr = %local_addr,
            role = ?role,
            "DTLS handshake initiated"
        );

        Ok(())
    }

    /// Completes DTLS handshake and exports SRTP keys.
    pub async fn complete_dtls_handshake(
        &self,
        call_id: &str,
        local_addr: &SbcSocketAddr,
        is_a_leg: bool,
        role: DtlsRole,
    ) -> Result<(), MediaPipelineError> {
        let key = format!("{call_id}:{local_addr}");

        let mut connections = self.dtls_connections.write().await;
        let context = connections
            .get_mut(&key)
            .ok_or(MediaPipelineError::DtlsConnectionNotFound)?;

        // Check if already connected
        if context.connection.state() != DtlsState::Connected {
            return Err(MediaPipelineError::DtlsHandshakeFailed(
                "Not connected".to_string(),
            ));
        }

        // Export keying material
        let keying_material = context
            .connection
            .export_srtp_keying_material()
            .await
            .map_err(|e| MediaPipelineError::SrtpKeyExportFailed(e.to_string()))?;

        context.keys_exported = true;

        // Get SSRC from session
        let sessions = self.sessions.read().await;
        let ssrc = sessions.get(call_id).map_or(0x1234_5678, |s| {
            if is_a_leg { s.a_leg_ssrc } else { s.b_leg_ssrc }
        });
        drop(sessions);

        // Create SRTP contexts
        let (outbound_ctx, inbound_ctx) =
            self.create_srtp_contexts(&keying_material, role, ssrc)?;

        // Store in session
        let mut sessions = self.sessions.write().await;
        if let Some(session_ctx) = sessions.get_mut(call_id) {
            if is_a_leg {
                session_ctx.srtp_outbound_a = Some(outbound_ctx);
                session_ctx.srtp_inbound_a = Some(inbound_ctx);
            } else {
                session_ctx.srtp_outbound_b = Some(outbound_ctx);
                session_ctx.srtp_inbound_b = Some(inbound_ctx);
            }
        }

        info!(
            call_id = %call_id,
            is_a_leg = is_a_leg,
            "DTLS handshake complete, SRTP keys exported"
        );

        Ok(())
    }

    /// Creates SRTP contexts from DTLS keying material.
    fn create_srtp_contexts(
        &self,
        keying: &SrtpKeyingMaterial,
        role: DtlsRole,
        ssrc: u32,
    ) -> Result<(SrtpContext, SrtpContext), MediaPipelineError> {
        // Create key material for outbound (local -> remote)
        let outbound_key = keying.local_key(role).to_vec();
        let outbound_salt = keying.local_salt(role).to_vec();

        let outbound_material =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, outbound_key, outbound_salt)
                .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        let outbound = SrtpContext::new(&outbound_material, SrtpDirection::Outbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        // Create key material for inbound (remote -> local)
        let inbound_key = keying.remote_key(role).to_vec();
        let inbound_salt = keying.remote_salt(role).to_vec();

        let inbound_material =
            SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, inbound_key, inbound_salt)
                .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        let inbound = SrtpContext::new(&inbound_material, SrtpDirection::Inbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        Ok((outbound, inbound))
    }

    /// Processes an incoming RTP packet.
    pub async fn process_rtp_packet(
        &self,
        call_id: &str,
        data: &[u8],
        _source: SbcSocketAddr,
        is_a_leg: bool,
    ) -> RtpProcessResult {
        let sessions = self.sessions.read().await;
        let Some(session_ctx) = sessions.get(call_id) else {
            return RtpProcessResult::Error {
                reason: "Session not found".to_string(),
            };
        };

        // Determine destination based on leg
        let destination = if is_a_leg {
            match &session_ctx.b_leg_remote {
                Some(addr) => *addr,
                None => {
                    return RtpProcessResult::Error {
                        reason: "B-leg not connected".to_string(),
                    };
                }
            }
        } else {
            match &session_ctx.a_leg_remote {
                Some(addr) => *addr,
                None => {
                    return RtpProcessResult::Error {
                        reason: "A-leg not connected".to_string(),
                    };
                }
            }
        };

        // Check media mode
        match session_ctx.session.mode() {
            MediaMode::PassThrough => {
                // Pass-through mode: forward without modification
                trace!(call_id = %call_id, "RTP pass-through");
                RtpProcessResult::Forward {
                    data: data.to_vec(),
                    destination,
                }
            }
            MediaMode::Relay | MediaMode::EarlyRelay => {
                // Relay mode: decrypt, process, encrypt
                let processed = self.relay_rtp_packet(session_ctx, data, is_a_leg).await;

                match processed {
                    Ok(packet_data) => RtpProcessResult::Forward {
                        data: packet_data,
                        destination,
                    },
                    Err(e) => RtpProcessResult::Error {
                        reason: e.to_string(),
                    },
                }
            }
        }
    }

    /// Relays an RTP packet (decrypt from one leg, encrypt for other).
    async fn relay_rtp_packet(
        &self,
        session_ctx: &MediaSessionContext,
        data: &[u8],
        is_a_leg: bool,
    ) -> Result<Vec<u8>, MediaPipelineError> {
        // Get appropriate SRTP contexts
        let (inbound_ctx, outbound_ctx) = if is_a_leg {
            (&session_ctx.srtp_inbound_a, &session_ctx.srtp_outbound_b)
        } else {
            (&session_ctx.srtp_inbound_b, &session_ctx.srtp_outbound_a)
        };

        // Decrypt incoming packet (if SRTP)
        let packet = if let Some(ctx) = inbound_ctx {
            let unprotect = SrtpUnprotect::new(ctx);
            unprotect
                .unprotect_rtp(data)
                .map_err(|e| MediaPipelineError::DecryptionFailed(e.to_string()))?
        } else {
            // Parse as unencrypted RTP
            let (header, header_size) = RtpHeader::parse(data)
                .map_err(|e| MediaPipelineError::DecryptionFailed(e.to_string()))?;
            RtpPacket::new(header, data[header_size..].to_vec())
        };

        // Track sequence for the packet
        let mut trackers = self.sequence_trackers.write().await;
        let tracker = trackers
            .entry(packet.header.ssrc)
            .or_insert_with(SequenceTracker::new);

        let is_valid = tracker.update(packet.header.sequence_number);
        if !is_valid {
            warn!(
                ssrc = packet.header.ssrc,
                seq = packet.header.sequence_number,
                "Duplicate or old packet"
            );
        }
        drop(trackers);

        // Encrypt outgoing packet (if SRTP)
        let ciphertext = if let Some(ctx) = outbound_ctx {
            let protect = SrtpProtect::new(ctx);
            protect
                .protect_rtp(&packet)
                .map_err(|e| MediaPipelineError::EncryptionFailed(e.to_string()))?
                .to_vec()
        } else {
            // Return as unencrypted
            packet.to_bytes().to_vec()
        };

        trace!(
            is_a_leg = is_a_leg,
            size = ciphertext.len(),
            "RTP packet relayed"
        );

        Ok(ciphertext)
    }

    /// Sets the remote address for a leg.
    pub async fn set_remote_address(
        &self,
        call_id: &str,
        is_a_leg: bool,
        address: SbcSocketAddr,
    ) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let session_ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        if is_a_leg {
            session_ctx.a_leg_remote = Some(address);
        } else {
            session_ctx.b_leg_remote = Some(address);
        }

        debug!(
            call_id = %call_id,
            is_a_leg = is_a_leg,
            address = %address,
            "Remote address set"
        );

        Ok(())
    }

    /// Starts RTP relay for a call. Binds UDP sockets and spawns relay tasks.
    ///
    /// Must be called after both `set_remote_address` calls (A-leg and B-leg).
    pub async fn start_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        let a_remote = ctx
            .a_leg_remote
            .ok_or(MediaPipelineError::BindFailed("A-leg remote not set".into()))?;
        let b_remote = ctx
            .b_leg_remote
            .ok_or(MediaPipelineError::BindFailed("B-leg remote not set".into()))?;

        // Bind UDP sockets
        let a_bind = format!("0.0.0.0:{}", ctx.a_leg_local_port);
        let b_bind = format!("0.0.0.0:{}", ctx.b_leg_local_port);

        let a_socket = Arc::new(
            UdpSocket::bind(&a_bind)
                .await
                .map_err(|e| MediaPipelineError::BindFailed(format!("{a_bind}: {e}")))?,
        );
        let b_socket = Arc::new(
            UdpSocket::bind(&b_bind)
                .await
                .map_err(|e| MediaPipelineError::BindFailed(format!("{b_bind}: {e}")))?,
        );

        // Shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn A→B relay task
        let a_sock = Arc::clone(&a_socket);
        let b_sock = Arc::clone(&b_socket);
        let b_addr: std::net::SocketAddr = b_remote.into();
        let call_id_ab = call_id.to_string();
        let mut shutdown_ab = shutdown_rx.clone();

        let handle_ab = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    result = a_sock.recv_from(&mut buf) => {
                        match result {
                            Ok((n, _src)) => {
                                if let Err(e) = b_sock.send_to(&buf[..n], b_addr).await {
                                    debug!(error = %e, call_id = %call_id_ab, "A→B relay send error");
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, call_id = %call_id_ab, "A→B relay recv error");
                                break;
                            }
                        }
                    }
                    _ = shutdown_ab.changed() => {
                        debug!(call_id = %call_id_ab, "A→B relay shutdown");
                        break;
                    }
                }
            }
        });

        // Spawn B→A relay task
        let a_sock = Arc::clone(&a_socket);
        let b_sock = Arc::clone(&b_socket);
        let a_addr: std::net::SocketAddr = a_remote.into();
        let call_id_ba = call_id.to_string();
        let mut shutdown_ba = shutdown_rx;

        let handle_ba = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    result = b_sock.recv_from(&mut buf) => {
                        match result {
                            Ok((n, _src)) => {
                                if let Err(e) = a_sock.send_to(&buf[..n], a_addr).await {
                                    debug!(error = %e, call_id = %call_id_ba, "B→A relay send error");
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, call_id = %call_id_ba, "B→A relay recv error");
                                break;
                            }
                        }
                    }
                    _ = shutdown_ba.changed() => {
                        debug!(call_id = %call_id_ba, "B→A relay shutdown");
                        break;
                    }
                }
            }
        });

        ctx.relay_handles = vec![handle_ab, handle_ba];
        ctx.relay_shutdown = Some(shutdown_tx);

        info!(
            call_id = %call_id,
            a_leg_port = ctx.a_leg_local_port,
            b_leg_port = ctx.b_leg_local_port,
            a_remote = %a_remote,
            b_remote = %b_remote,
            "RTP relay started"
        );

        Ok(())
    }

    /// Stops the RTP relay for a call and releases ports.
    pub async fn stop_relay(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        // Signal shutdown
        if let Some(tx) = ctx.relay_shutdown.take() {
            let _ = tx.send(true);
        }

        // Abort relay tasks
        for handle in ctx.relay_handles.drain(..) {
            handle.abort();
        }

        // Release ports
        self.port_allocator.release_pair(ctx.a_leg_local_port).await;
        self.port_allocator.release_pair(ctx.b_leg_local_port).await;

        info!(call_id = %call_id, "RTP relay stopped");
        Ok(())
    }

    /// Removes a media session.
    pub async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(call_id).is_some() {
            info!(call_id = %call_id, "Media session removed");
            Ok(())
        } else {
            Err(MediaPipelineError::SessionNotFound)
        }
    }

    /// Returns session statistics.
    pub async fn get_session_stats(&self, call_id: &str) -> Option<SessionStats> {
        let sessions = self.sessions.read().await;
        sessions.get(call_id).map(|ctx| SessionStats {
            call_id: call_id.to_string(),
            state: ctx.session.state(),
            mode: ctx.session.mode(),
            srtp_enabled: ctx.session.srtp_enabled(),
            has_a_leg: ctx.a_leg_remote.is_some(),
            has_b_leg: ctx.b_leg_remote.is_some(),
        })
    }

    /// Returns the number of active sessions.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

/// Generates a random SSRC.
#[allow(clippy::cast_possible_truncation)]
fn generate_ssrc() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_nanos() as u32) ^ (now.as_secs() as u32)
}

/// Session statistics.
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Call identifier.
    pub call_id: String,
    /// Session state.
    pub state: SessionState,
    /// Media mode.
    pub mode: MediaMode,
    /// Whether SRTP is enabled.
    pub srtp_enabled: bool,
    /// Whether A-leg is connected.
    pub has_a_leg: bool,
    /// Whether B-leg is connected.
    pub has_b_leg: bool,
}

/// Media pipeline errors.
#[derive(Debug)]
pub enum MediaPipelineError {
    /// Session not found.
    SessionNotFound,
    /// Codec negotiation failed.
    CodecNegotiationFailed,
    /// DTLS connection not found.
    DtlsConnectionNotFound,
    /// DTLS handshake failed.
    DtlsHandshakeFailed(String),
    /// SRTP key export failed.
    SrtpKeyExportFailed(String),
    /// SRTP context creation failed.
    SrtpContextCreationFailed(String),
    /// Encryption failed.
    EncryptionFailed(String),
    /// Decryption failed.
    DecryptionFailed(String),
    /// RTP port range exhausted.
    PortExhausted,
    /// Failed to bind UDP socket.
    BindFailed(String),
}

impl std::fmt::Display for MediaPipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "Media session not found"),
            Self::CodecNegotiationFailed => write!(f, "Codec negotiation failed"),
            Self::DtlsConnectionNotFound => write!(f, "DTLS connection not found"),
            Self::DtlsHandshakeFailed(e) => write!(f, "DTLS handshake failed: {e}"),
            Self::SrtpKeyExportFailed(e) => write!(f, "SRTP key export failed: {e}"),
            Self::SrtpContextCreationFailed(e) => write!(f, "SRTP context creation failed: {e}"),
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {e}"),
            Self::DecryptionFailed(e) => write!(f, "Decryption failed: {e}"),
            Self::PortExhausted => write!(f, "RTP port range exhausted"),
            Self::BindFailed(e) => write!(f, "Failed to bind UDP socket: {e}"),
        }
    }
}

impl std::error::Error for MediaPipelineError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MediaPipelineConfig::default();
        assert!(config.srtp_required);
        assert!(config.rtcp_mux);
        assert!(!config.local_codecs.is_empty());
    }

    #[test]
    fn test_media_pipeline_creation() {
        let config = MediaPipelineConfig::default();
        let pipeline = MediaPipeline::new(config);

        // Verify codec registry was populated
        assert!(pipeline.codec_registry.find_by_name("PCMU").is_some());
        assert!(pipeline.codec_registry.find_by_name("PCMA").is_some());
    }

    #[tokio::test]
    async fn test_create_session() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline.create_session("test-call-1", None).await.unwrap();

        assert_eq!(pipeline.active_session_count().await, 1);
    }

    #[tokio::test]
    async fn test_remove_session() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline.create_session("test-call-1", None).await.unwrap();

        pipeline.remove_session("test-call-1").await.unwrap();
        assert_eq!(pipeline.active_session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_not_found() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        let result = pipeline.remove_session("nonexistent").await;
        assert!(matches!(result, Err(MediaPipelineError::SessionNotFound)));
    }

    #[tokio::test]
    async fn test_codec_negotiation() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        let remote_codecs = vec![CodecCapability::pcmu(), CodecCapability::pcma()];

        let negotiated = pipeline
            .negotiate_codecs("test-call", &remote_codecs)
            .await
            .unwrap();

        assert!(!negotiated.is_empty());
    }

    #[tokio::test]
    async fn test_codec_negotiation_failure() {
        // Config with only Opus
        let config = MediaPipelineConfig {
            local_codecs: vec![CodecCapability::opus(111)],
            ..Default::default()
        };
        let pipeline = MediaPipeline::new(config);

        // Remote only supports G.711
        let remote_codecs = vec![CodecCapability::pcmu()];

        let result = pipeline.negotiate_codecs("test-call", &remote_codecs).await;

        assert!(matches!(
            result,
            Err(MediaPipelineError::CodecNegotiationFailed)
        ));
    }

    #[tokio::test]
    async fn test_set_remote_address() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline.create_session("test-call", None).await.unwrap();

        let addr = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        pipeline
            .set_remote_address("test-call", true, addr)
            .await
            .unwrap();

        let stats = pipeline.get_session_stats("test-call").await.unwrap();
        assert!(stats.has_a_leg);
        assert!(!stats.has_b_leg);
    }

    #[tokio::test]
    async fn test_session_stats() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());

        pipeline
            .create_session("test-call", Some(MediaMode::Relay))
            .await
            .unwrap();

        let stats = pipeline.get_session_stats("test-call").await.unwrap();
        assert_eq!(stats.call_id, "test-call");
        assert!(matches!(stats.mode, MediaMode::Relay));
        assert!(stats.srtp_enabled);
    }

    #[test]
    fn test_generate_ssrc() {
        let ssrc1 = generate_ssrc();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let ssrc2 = generate_ssrc();
        // SSRCs should be different (high probability)
        assert_ne!(ssrc1, ssrc2);
    }
}
