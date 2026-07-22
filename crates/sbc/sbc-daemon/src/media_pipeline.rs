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

use crate::dtls_relay::{EstablishedLeg, establish_srtp_leg};
use crate::dtls_sidecar::{Role, SidecarReader, SidecarWriter};
use crate::srtp_relay::{TerminateRelayLeg, forward_dtls_to_sidecar, pump_sidecar_dtls_to_peer};
use proto_srtp::{
    SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile, SrtpProtect, SrtpUnprotect,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
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
    /// Whether the SBC terminates DTLS-SRTP (vs. relaying it opaquely). When
    /// true, each terminated leg drives a DTLS handshake via the sidecar and
    /// the relay does SRTP protect/unprotect; the two `dtls_*` fields below
    /// must be set.
    pub terminate_dtls: bool,
    /// Path to the DTLS terminator sidecar's Unix socket (terminate mode).
    pub dtls_sidecar_socket: Option<std::path::PathBuf>,
    /// The SBC's own SDP fingerprint (published by the sidecar), used to verify
    /// the sidecar's live identity on each per-leg connection (terminate mode).
    pub dtls_fingerprint: Option<String>,
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
            terminate_dtls: false,
            dtls_sidecar_socket: None,
            dtls_fingerprint: None,
        }
    }
}

/// Allocates RTP port pairs (even=RTP, odd=RTCP) from a configured range.
pub struct RtpPortAllocator {
    /// Monotonically increasing pair index (modulo the usable pair count).
    /// u32 so the u16 wraparound of long-running allocation cannot
    /// underflow/overflow the port arithmetic.
    next_index: AtomicU32,
    /// Minimum port in range.
    min_port: u16,
    /// Maximum port in range.
    max_port: u16,
    /// Currently allocated ports.
    allocated: RwLock<std::collections::HashSet<u16>>,
}

impl RtpPortAllocator {
    /// Creates a new port allocator.
    ///
    /// A reversed range is swapped (with a warning) rather than panicking
    /// in the port arithmetic later.
    pub fn new(min_port: u16, max_port: u16) -> Self {
        let (min_port, max_port) = if min_port <= max_port {
            (min_port, max_port)
        } else {
            warn!(min_port, max_port, "RTP port range reversed, swapping");
            (max_port, min_port)
        };
        // Ensure min_port is even for RTP convention
        let min_port = if min_port.is_multiple_of(2) {
            min_port
        } else {
            min_port.saturating_add(1)
        };
        Self {
            next_index: AtomicU32::new(0),
            min_port,
            max_port,
            allocated: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Number of usable (RTP, RTCP) port pairs in the range.
    fn pair_count(&self) -> u32 {
        if self.max_port <= self.min_port {
            return 0;
        }
        // Each pair occupies (even, even+1); both ends inclusive.
        (u32::from(self.max_port) - u32::from(self.min_port)).div_ceil(2)
    }

    /// Allocates an even-numbered RTP port. Returns (rtp_port, rtcp_port).
    // rtp/rtcp are the standard protocol names for the port pair.
    #[allow(clippy::similar_names)]
    pub async fn allocate_pair(&self) -> Result<(u16, u16), MediaPipelineError> {
        let mut allocated = self.allocated.write().await;
        let pairs = self.pair_count();
        if pairs == 0 {
            return Err(MediaPipelineError::PortExhausted);
        }

        for _ in 0..pairs {
            let index = self.next_index.fetch_add(1, Ordering::Relaxed) % pairs;
            // index < pairs guarantees rtp <= max_port - 1, so rtcp fits
            // without overflow.
            #[allow(clippy::cast_possible_truncation)]
            let rtp = self.min_port + (index as u16) * 2;
            let rtcp = rtp + 1;

            if !allocated.contains(&rtp) {
                allocated.insert(rtp);
                allocated.insert(rtcp);
                return Ok((rtp, rtcp));
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
    sequence_trackers: RwLock<HashMap<u32, TrackedSequence>>,
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
    /// A-leg local RTCP port (RTP port + 1; serviced for non-muxed endpoints).
    a_leg_rtcp_port: u16,
    /// B-leg local RTCP port (RTP port + 1; serviced for non-muxed endpoints).
    b_leg_rtcp_port: u16,
    /// A-leg bind IP (from zone, or 0.0.0.0).
    a_leg_bind_ip: std::net::IpAddr,
    /// B-leg bind IP (from zone, or 0.0.0.0).
    b_leg_bind_ip: std::net::IpAddr,
    /// Relay task handles (aborted on stop).
    relay_handles: Vec<JoinHandle<()>>,
    /// Shutdown sender for relay tasks.
    relay_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Shared A-leg target address (read by relay tasks, updated by `set_remote_address`).
    a_leg_target: Option<Arc<std::sync::RwLock<std::net::SocketAddr>>>,
    /// Shared B-leg target address (read by relay tasks, updated by `set_remote_address`).
    b_leg_target: Option<Arc<std::sync::RwLock<std::net::SocketAddr>>>,
    /// Transcoder for codec conversion (if A-leg and B-leg use different codecs).
    transcoder: Option<Transcoder>,
    /// A-leg negotiated codec.
    a_leg_codec: Option<NegotiatedCodec>,
    /// B-leg negotiated codec.
    b_leg_codec: Option<NegotiatedCodec>,
    /// Live A-leg sidecar DTLS session halves (terminate mode). Held for the
    /// whole call so the DTLS association is not torn down at key export
    /// (deferred finding #2); dropped with the session at teardown.
    dtls_sidecar_a: Option<(SidecarReader, SidecarWriter)>,
    /// Live B-leg sidecar DTLS session halves (terminate mode).
    dtls_sidecar_b: Option<(SidecarReader, SidecarWriter)>,
}

/// Allocated port info returned from `create_session`.
#[derive(Debug, Clone)]
pub struct AllocatedPorts {
    /// A-leg RTP port.
    pub a_leg_rtp_port: u16,
    /// B-leg RTP port.
    pub b_leg_rtp_port: u16,
}

/// Negotiated codec info for one leg.
#[derive(Debug, Clone)]
pub struct NegotiatedCodec {
    /// Codec name (PCMU, PCMA, G722, opus).
    pub name: String,
    /// RTP payload type.
    pub payload_type: u8,
    /// Clock rate in Hz.
    pub clock_rate: u32,
}

/// Transcoder for converting between different codecs in the relay path.
///
/// When A-leg and B-leg negotiate different codecs, the transcoder
/// decodes incoming RTP payload to PCM and re-encodes for the outgoing leg.
struct Transcoder {
    /// A-leg codec info.
    a_codec: NegotiatedCodec,
    /// B-leg codec info.
    b_codec: NegotiatedCodec,
    /// G.722 encoder for A-leg direction (if needed).
    g722_enc_a: Option<uc_codecs::g722_adpcm::G722Encoder>,
    /// G.722 decoder for A-leg direction (if needed).
    g722_dec_a: Option<uc_codecs::g722_adpcm::G722Decoder>,
    /// G.722 encoder for B-leg direction (if needed).
    g722_enc_b: Option<uc_codecs::g722_adpcm::G722Encoder>,
    /// G.722 decoder for B-leg direction (if needed).
    g722_dec_b: Option<uc_codecs::g722_adpcm::G722Decoder>,
}

impl Transcoder {
    /// Creates a transcoder for the given codec pair.
    fn new(a_codec: NegotiatedCodec, b_codec: NegotiatedCodec) -> Self {
        let g722_enc_a = if b_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Encoder::new())
        } else {
            None
        };
        let g722_dec_a = if a_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Decoder::new())
        } else {
            None
        };
        let g722_enc_b = if a_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Encoder::new())
        } else {
            None
        };
        let g722_dec_b = if b_codec.name == "G722" {
            Some(uc_codecs::g722_adpcm::G722Decoder::new())
        } else {
            None
        };

        Self {
            a_codec,
            b_codec,
            g722_enc_a,
            g722_dec_a,
            g722_enc_b,
            g722_dec_b,
        }
    }

    /// Transcodes RTP payload from one codec to another.
    ///
    /// `is_a_leg`: true = packet from A-leg (decode with a_codec, encode with b_codec)
    ///             false = packet from B-leg (decode with b_codec, encode with a_codec)
    ///
    /// Returns (transcoded_payload, outbound_payload_type).
    #[allow(clippy::cast_possible_truncation)]
    fn transcode(
        &mut self,
        payload: &[u8],
        is_a_leg: bool,
    ) -> Result<(Vec<u8>, u8), MediaPipelineError> {
        // Clone codec info to avoid borrow conflicts with &mut self
        let (in_name, in_rate, out_name, out_rate, out_pt) = if is_a_leg {
            (
                self.a_codec.name.clone(),
                self.a_codec.clock_rate,
                self.b_codec.name.clone(),
                self.b_codec.clock_rate,
                self.b_codec.payload_type,
            )
        } else {
            (
                self.b_codec.name.clone(),
                self.b_codec.clock_rate,
                self.a_codec.name.clone(),
                self.a_codec.clock_rate,
                self.a_codec.payload_type,
            )
        };

        // Decode to PCM
        let mut pcm = vec![0i16; payload.len() * 6];
        let pcm_samples = self.decode_payload(payload, &mut pcm, &in_name, is_a_leg)?;

        // Resample if clock rates differ
        let resampled;
        let pcm_out = if in_rate == out_rate {
            &pcm[..pcm_samples]
        } else {
            resampled = resample_linear(&pcm[..pcm_samples], in_rate, out_rate);
            &resampled
        };

        // Encode to output codec
        let mut output = vec![0u8; pcm_out.len() * 2];
        let encoded_len = self.encode_payload(pcm_out, &mut output, &out_name, !is_a_leg)?;

        output.truncate(encoded_len);
        Ok((output, out_pt))
    }

    /// Decodes payload bytes to PCM samples.
    fn decode_payload(
        &mut self,
        payload: &[u8],
        output: &mut [i16],
        codec_name: &str,
        is_a_leg: bool,
    ) -> Result<usize, MediaPipelineError> {
        match codec_name {
            "PCMU" => {
                let n = payload.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Ulaw::decode_sample(payload[i]);
                }
                Ok(n)
            }
            "PCMA" => {
                let n = payload.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Alaw::decode_sample(payload[i]);
                }
                Ok(n)
            }
            "G722" => {
                let decoder = if is_a_leg {
                    self.g722_dec_a.as_mut()
                } else {
                    self.g722_dec_b.as_mut()
                };
                decoder.map_or_else(
                    || {
                        Err(MediaPipelineError::DecryptionFailed(
                            "G.722 decoder not initialized".into(),
                        ))
                    },
                    |dec| Ok(dec.decode(payload, output)),
                )
            }
            _ => Err(MediaPipelineError::DecryptionFailed(format!(
                "Unsupported codec for transcoding: {codec_name}"
            ))),
        }
    }

    /// Encodes PCM samples to codec payload.
    fn encode_payload(
        &mut self,
        pcm: &[i16],
        output: &mut [u8],
        codec_name: &str,
        is_a_leg: bool,
    ) -> Result<usize, MediaPipelineError> {
        match codec_name {
            "PCMU" => {
                let n = pcm.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Ulaw::encode_sample(pcm[i]);
                }
                Ok(n)
            }
            "PCMA" => {
                let n = pcm.len().min(output.len());
                for i in 0..n {
                    output[i] = uc_codecs::G711Alaw::encode_sample(pcm[i]);
                }
                Ok(n)
            }
            "G722" => {
                let encoder = if is_a_leg {
                    self.g722_enc_a.as_mut()
                } else {
                    self.g722_enc_b.as_mut()
                };
                encoder.map_or_else(
                    || {
                        Err(MediaPipelineError::EncryptionFailed(
                            "G.722 encoder not initialized".into(),
                        ))
                    },
                    |enc| Ok(enc.encode(pcm, output)),
                )
            }
            _ => Err(MediaPipelineError::EncryptionFailed(format!(
                "Unsupported codec for transcoding: {codec_name}"
            ))),
        }
    }
}

/// Linear interpolation resampler for integer sample rate ratios.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn resample_linear(input: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
    if from_rate == to_rate || input.is_empty() {
        return input.to_vec();
    }

    let ratio = f64::from(to_rate) / f64::from(from_rate);
    let out_len = (input.len() as f64 * ratio) as usize;
    let mut output = Vec::with_capacity(out_len);

    for i in 0..out_len {
        let src_pos = i as f64 / ratio;
        let idx = src_pos as usize;
        let frac = src_pos - idx as f64;

        let sample = if idx + 1 < input.len() {
            let s0 = f64::from(input[idx]);
            let s1 = f64::from(input[idx + 1]);
            frac.mul_add(s1 - s0, s0) as i16
        } else {
            input[input.len() - 1]
        };

        output.push(sample);
    }

    output
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
        self.create_session_with_zones(call_id, mode, None, None)
            .await
    }

    /// Creates a new media session with zone-specific bind IPs.
    pub async fn create_session_with_zones(
        &self,
        call_id: &str,
        mode: Option<MediaMode>,
        a_leg_media_ip: Option<std::net::IpAddr>,
        b_leg_media_ip: Option<std::net::IpAddr>,
    ) -> Result<AllocatedPorts, MediaPipelineError> {
        let mode = mode.unwrap_or(self.config.default_mode);

        let mut config = MediaSessionConfig::new(call_id)
            .with_mode(mode)
            .with_srtp(self.config.srtp_required);

        for codec in &self.config.local_codecs {
            config = config.with_codec(codec.clone());
        }

        let session = MediaSession::new(config);

        // Allocate port pairs for A-leg and B-leg. The RTCP port (RTP + 1) is
        // serviced for non-muxed endpoints; muxed RTCP shares the RTP port and
        // rides the RTP relay opaquely.
        let (a_rtp, a_rtcp) = self.port_allocator.allocate_pair().await?;
        let (b_rtp, b_rtcp) = match self.port_allocator.allocate_pair().await {
            Ok(pair) => pair,
            Err(e) => {
                self.port_allocator.release_pair(a_rtp).await;
                return Err(e);
            }
        };

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
            a_leg_rtcp_port: a_rtcp,
            b_leg_rtcp_port: b_rtcp,
            a_leg_bind_ip: a_leg_media_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            b_leg_bind_ip: b_leg_media_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            relay_handles: Vec::new(),
            relay_shutdown: None,
            a_leg_target: None,
            b_leg_target: None,
            transcoder: None,
            a_leg_codec: None,
            b_leg_codec: None,
            dtls_sidecar_a: None,
            dtls_sidecar_b: None,
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

    /// Terminates DTLS-SRTP for one leg via the Go terminator sidecar.
    ///
    /// Drives the DTLS handshake over `media_socket` (the caller owns the socket
    /// and hands it off for the handshake), derives the leg's SRTP contexts, and
    /// stores them plus the live sidecar session halves in the session. The
    /// halves are kept for the whole call so the DTLS association is not torn
    /// down at key export (deferred review finding #2); they drop at teardown.
    ///
    /// `signaling_peer` is the peer's SDP media address (the destination for the
    /// first outbound flight, before the peer's source is latched);
    /// `peer_fingerprint` is the peer's `a=fingerprint`; `role` is the SBC's
    /// DTLS role for this leg (derived from `a=setup`).
    ///
    /// # Errors
    /// Terminate mode not configured (`dtls_sidecar_socket` / `dtls_fingerprint`
    /// unset), the handshake fails, or SRTP context creation fails.
    pub async fn terminate_leg_dtls(
        &self,
        call_id: &str,
        is_a_leg: bool,
        media_socket: &UdpSocket,
        signaling_peer: std::net::SocketAddr,
        peer_fingerprint: &str,
        role: Role,
    ) -> Result<(), MediaPipelineError> {
        let sidecar_socket = self.config.dtls_sidecar_socket.as_ref().ok_or_else(|| {
            MediaPipelineError::DtlsHandshakeFailed(
                "terminate mode: no DTLS sidecar socket configured".to_string(),
            )
        })?;
        let own_fingerprint = self.config.dtls_fingerprint.as_deref().ok_or_else(|| {
            MediaPipelineError::DtlsHandshakeFailed(
                "terminate mode: no DTLS fingerprint configured".to_string(),
            )
        })?;

        let leg = establish_srtp_leg(
            media_socket,
            signaling_peer,
            sidecar_socket,
            own_fingerprint,
            peer_fingerprint,
            role,
        )
        .await
        .map_err(|e| MediaPipelineError::DtlsHandshakeFailed(e.to_string()))?;

        // SSRC for this leg (falls back if the session vanished mid-handshake;
        // the store below then fails cleanly with DtlsConnectionNotFound).
        let ssrc = {
            let sessions = self.sessions.read().await;
            sessions.get(call_id).map_or(0x1234_5678, |s| {
                if is_a_leg { s.a_leg_ssrc } else { s.b_leg_ssrc }
            })
        };

        let outbound = SrtpContext::new(&leg.outbound, SrtpDirection::Outbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;
        let inbound = SrtpContext::new(&leg.inbound, SrtpDirection::Inbound, ssrc)
            .map_err(|e| MediaPipelineError::SrtpContextCreationFailed(e.to_string()))?;

        let mut sessions = self.sessions.write().await;
        let session_ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::DtlsConnectionNotFound)?;
        if is_a_leg {
            session_ctx.srtp_outbound_a = Some(outbound);
            session_ctx.srtp_inbound_a = Some(inbound);
            session_ctx.dtls_sidecar_a = Some((leg.reader, leg.writer));
        } else {
            session_ctx.srtp_outbound_b = Some(outbound);
            session_ctx.srtp_inbound_b = Some(inbound);
            session_ctx.dtls_sidecar_b = Some((leg.reader, leg.writer));
        }

        info!(
            call_id = %call_id,
            is_a_leg,
            ssrc,
            "DTLS-SRTP leg terminated via sidecar"
        );
        Ok(())
    }

    /// Test-only: whether a leg has both SRTP contexts and the live sidecar
    /// halves stored (i.e. `terminate_leg_dtls` completed for it).
    #[cfg(test)]
    async fn test_leg_srtp_active(&self, call_id: &str, is_a_leg: bool) -> bool {
        let sessions = self.sessions.read().await;
        sessions.get(call_id).is_some_and(|s| {
            if is_a_leg {
                s.srtp_outbound_a.is_some()
                    && s.srtp_inbound_a.is_some()
                    && s.dtls_sidecar_a.is_some()
            } else {
                s.srtp_outbound_b.is_some()
                    && s.srtp_inbound_b.is_some()
                    && s.dtls_sidecar_b.is_some()
            }
        })
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
            // Parse as unencrypted RTP. Guard the payload slice: never trust
            // the parser's header_size against attacker-controlled input.
            let (header, header_size) = RtpHeader::parse(data)
                .map_err(|e| MediaPipelineError::DecryptionFailed(e.to_string()))?;
            let payload = data.get(header_size..).ok_or_else(|| {
                MediaPipelineError::DecryptionFailed(format!(
                    "RTP header size {header_size} exceeds packet length {}",
                    data.len()
                ))
            })?;
            RtpPacket::new(header, payload.to_vec())
        };

        // Track sequence for the packet. The map is keyed by the
        // attacker-controlled SSRC, so it is bounded: idle entries are
        // evicted once the soft cap is reached, and brand-new SSRCs are
        // rejected at the hard cap (random-SSRC floods previously grew
        // this map without limit).
        let mut trackers = self.sequence_trackers.write().await;
        let now = std::time::Instant::now();
        if trackers.len() >= SSRC_TRACKER_SOFT_CAP && !trackers.contains_key(&packet.header.ssrc) {
            trackers.retain(|_, t| now.duration_since(t.last_seen) < SSRC_TRACKER_IDLE_TIMEOUT);
            if trackers.len() >= SSRC_TRACKER_HARD_CAP {
                return Err(MediaPipelineError::DecryptionFailed(
                    "SSRC tracker capacity exceeded".to_string(),
                ));
            }
        }
        let tracker = trackers
            .entry(packet.header.ssrc)
            .or_insert_with(TrackedSequence::new);
        tracker.last_seen = now;

        let is_valid = tracker.inner.update(packet.header.sequence_number);
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
            if let Some(ref target) = session_ctx.a_leg_target
                && let Ok(mut guard) = target.write()
            {
                *guard = address.into();
            }
        } else {
            session_ctx.b_leg_remote = Some(address);
            if let Some(ref target) = session_ctx.b_leg_target
                && let Ok(mut guard) = target.write()
            {
                *guard = address.into();
            }
        }

        debug!(
            call_id = %call_id,
            is_a_leg = is_a_leg,
            address = %address,
            "Remote address set"
        );

        Ok(())
    }

    /// Sets the negotiated codecs for a call. Creates a transcoder if they differ.
    pub async fn set_negotiated_codecs(
        &self,
        call_id: &str,
        a_codec: NegotiatedCodec,
        b_codec: NegotiatedCodec,
    ) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        let needs_transcoding = a_codec.name != b_codec.name;

        if needs_transcoding {
            info!(
                call_id = %call_id,
                a_codec = %a_codec.name,
                b_codec = %b_codec.name,
                "Transcoding enabled"
            );
            ctx.transcoder = Some(Transcoder::new(a_codec.clone(), b_codec.clone()));
        } else {
            debug!(
                call_id = %call_id,
                codec = %a_codec.name,
                "Same codec on both legs, no transcoding needed"
            );
        }

        ctx.a_leg_codec = Some(a_codec);
        ctx.b_leg_codec = Some(b_codec);

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
            .ok_or_else(|| MediaPipelineError::BindFailed("A-leg remote not set".into()))?;
        let b_remote = ctx
            .b_leg_remote
            .ok_or_else(|| MediaPipelineError::BindFailed("B-leg remote not set".into()))?;

        // Bind UDP sockets to zone-specific media IPs
        let a_bind = format!("{}:{}", ctx.a_leg_bind_ip, ctx.a_leg_local_port);
        let b_bind = format!("{}:{}", ctx.b_leg_bind_ip, ctx.b_leg_local_port);

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

        // Per-leg send targets, shared between the two directions so that
        // symmetric-RTP latching on one leg redirects the opposite
        // direction's sends (RFC 4961: reply to where media actually
        // arrives from, not where SDP claimed it would).
        let a_addr: std::net::SocketAddr = a_remote.into();
        let b_addr: std::net::SocketAddr = b_remote.into();
        let a_target = Arc::new(std::sync::RwLock::new(a_addr));
        let b_target = Arc::new(std::sync::RwLock::new(b_addr));

        // Spawn A→B RTP relay task
        let handle_ab = tokio::spawn(relay_leg(
            Arc::clone(&a_socket),
            Arc::clone(&b_socket),
            a_addr,
            Arc::clone(&a_target),
            Arc::clone(&b_target),
            call_id.to_string(),
            "A→B",
            RelayKind::Rtp,
            shutdown_rx.clone(),
        ));

        // Spawn B→A RTP relay task
        let handle_ba = tokio::spawn(relay_leg(
            Arc::clone(&b_socket),
            Arc::clone(&a_socket),
            b_addr,
            Arc::clone(&b_target),
            Arc::clone(&a_target),
            call_id.to_string(),
            "B→A",
            RelayKind::Rtp,
            shutdown_rx.clone(),
        ));

        let mut relay_handles = vec![handle_ab, handle_ba];

        // RTCP relay for non-muxed endpoints: forward the RTP-port+1 pair so
        // sender/receiver reports traverse the SBC. Muxed RTCP already rides the
        // RTP relay above. Best-effort — a port-overflow or bind failure disables
        // RTCP forwarding for this call but leaves audio untouched. RTCP remotes
        // default to the RTP remote's port + 1 and then latch symmetrically.
        let rtcp_started = if let (Some(a_rtcp_rport), Some(b_rtcp_rport)) =
            (a_addr.port().checked_add(1), b_addr.port().checked_add(1))
        {
            let a_rtcp_bind = format!("{}:{}", ctx.a_leg_bind_ip, ctx.a_leg_rtcp_port);
            let b_rtcp_bind = format!("{}:{}", ctx.b_leg_bind_ip, ctx.b_leg_rtcp_port);
            match (
                UdpSocket::bind(&a_rtcp_bind).await,
                UdpSocket::bind(&b_rtcp_bind).await,
            ) {
                (Ok(a_rtcp_sock), Ok(b_rtcp_sock)) => {
                    let a_rtcp_sock = Arc::new(a_rtcp_sock);
                    let b_rtcp_sock = Arc::new(b_rtcp_sock);
                    let a_rtcp_addr = std::net::SocketAddr::new(a_addr.ip(), a_rtcp_rport);
                    let b_rtcp_addr = std::net::SocketAddr::new(b_addr.ip(), b_rtcp_rport);
                    let a_rtcp_target = Arc::new(std::sync::RwLock::new(a_rtcp_addr));
                    let b_rtcp_target = Arc::new(std::sync::RwLock::new(b_rtcp_addr));

                    relay_handles.push(tokio::spawn(relay_leg(
                        Arc::clone(&a_rtcp_sock),
                        Arc::clone(&b_rtcp_sock),
                        a_rtcp_addr,
                        Arc::clone(&a_rtcp_target),
                        Arc::clone(&b_rtcp_target),
                        call_id.to_string(),
                        "A→B",
                        RelayKind::Rtcp,
                        shutdown_rx.clone(),
                    )));
                    relay_handles.push(tokio::spawn(relay_leg(
                        b_rtcp_sock,
                        a_rtcp_sock,
                        b_rtcp_addr,
                        b_rtcp_target,
                        a_rtcp_target,
                        call_id.to_string(),
                        "B→A",
                        RelayKind::Rtcp,
                        shutdown_rx,
                    )));
                    true
                }
                (a_res, b_res) => {
                    warn!(
                        call_id = %call_id,
                        a_err = ?a_res.err(),
                        b_err = ?b_res.err(),
                        "RTCP relay sockets failed to bind (audio unaffected)"
                    );
                    false
                }
            }
        } else {
            false
        };

        ctx.relay_handles = relay_handles;
        ctx.relay_shutdown = Some(shutdown_tx);
        ctx.a_leg_target = Some(a_target);
        ctx.b_leg_target = Some(b_target);

        info!(
            call_id = %call_id,
            a_leg_port = ctx.a_leg_local_port,
            b_leg_port = ctx.b_leg_local_port,
            a_rtcp_port = ctx.a_leg_rtcp_port,
            b_rtcp_port = ctx.b_leg_rtcp_port,
            rtcp_started,
            a_remote = %a_remote,
            b_remote = %b_remote,
            "Media relay started"
        );

        Ok(())
    }

    /// Starts a DTLS-SRTP **terminating** relay for a call: drives the DTLS
    /// handshake on each leg's media socket (via the sidecar), and once both
    /// complete, relays media by unprotecting on the ingress leg and
    /// re-protecting for the egress leg — the SBC is a crypto endpoint on both
    /// legs.
    ///
    /// The handshakes can take seconds, so they run in a spawned supervisor and
    /// this returns promptly (like `start_relay`); media flows once both legs
    /// are established. Call teardown (`stop_relay`) signals the shutdown watch,
    /// which stops the supervisor's relay/DTLS tasks and drops the sidecar
    /// connections.
    ///
    /// # Errors
    /// Terminate mode not configured, missing remotes, or socket bind failure.
    pub async fn start_relay_terminate(
        &self,
        call_id: &str,
        a_leg: LegDtlsParams,
        b_leg: LegDtlsParams,
    ) -> Result<(), MediaPipelineError> {
        let sidecar_socket = self.config.dtls_sidecar_socket.clone().ok_or_else(|| {
            MediaPipelineError::DtlsHandshakeFailed("no DTLS sidecar socket configured".into())
        })?;
        let own_fingerprint = self.config.dtls_fingerprint.clone().ok_or_else(|| {
            MediaPipelineError::DtlsHandshakeFailed("no DTLS fingerprint configured".into())
        })?;

        let mut sessions = self.sessions.write().await;
        let ctx = sessions
            .get_mut(call_id)
            .ok_or(MediaPipelineError::SessionNotFound)?;

        let a_remote: std::net::SocketAddr = ctx
            .a_leg_remote
            .ok_or_else(|| MediaPipelineError::BindFailed("A-leg remote not set".into()))?
            .into();
        let b_remote: std::net::SocketAddr = ctx
            .b_leg_remote
            .ok_or_else(|| MediaPipelineError::BindFailed("B-leg remote not set".into()))?
            .into();
        let a_bind = format!("{}:{}", ctx.a_leg_bind_ip, ctx.a_leg_local_port);
        let b_bind = format!("{}:{}", ctx.b_leg_bind_ip, ctx.b_leg_local_port);
        let a_ssrc = ctx.a_leg_ssrc;
        let b_ssrc = ctx.b_leg_ssrc;

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

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let a_target = Arc::new(std::sync::RwLock::new(a_remote));
        let b_target = Arc::new(std::sync::RwLock::new(b_remote));

        let supervisor = tokio::spawn(terminate_supervisor(TerminateSetup {
            call_id: call_id.to_string(),
            sidecar_socket,
            own_fingerprint,
            a_socket,
            b_socket,
            a_remote,
            b_remote,
            a_ssrc,
            b_ssrc,
            a_leg,
            b_leg,
            a_target: Arc::clone(&a_target),
            b_target: Arc::clone(&b_target),
            shutdown: shutdown_rx,
        }));

        // The supervisor handle stands in for the relay tasks it spawns; those
        // stop via the shutdown watch (task abort does not cascade to children).
        ctx.relay_handles = vec![supervisor];
        ctx.relay_shutdown = Some(shutdown_tx);
        ctx.a_leg_target = Some(a_target);
        ctx.b_leg_target = Some(b_target);

        info!(call_id = %call_id, "DTLS-SRTP terminating relay starting (handshakes in progress)");
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

        // Release ports and zero them so remove_session won't double-release
        self.port_allocator.release_pair(ctx.a_leg_local_port).await;
        self.port_allocator.release_pair(ctx.b_leg_local_port).await;
        ctx.a_leg_local_port = 0;
        ctx.b_leg_local_port = 0;

        info!(call_id = %call_id, "RTP relay stopped");
        Ok(())
    }

    /// Removes a media session, stopping any running relay tasks, releasing
    /// allocated ports, and cleaning up associated DTLS connections.
    pub async fn remove_session(&self, call_id: &str) -> Result<(), MediaPipelineError> {
        let mut sessions = self.sessions.write().await;
        if let Some(mut ctx) = sessions.remove(call_id) {
            // Stop relay tasks (mirrors stop_relay logic)
            if let Some(tx) = ctx.relay_shutdown.take() {
                let _ = tx.send(true);
            }
            for handle in ctx.relay_handles.drain(..) {
                handle.abort();
            }

            // Release allocated port pairs (skip if already released by stop_relay)
            if ctx.a_leg_local_port != 0 {
                self.port_allocator.release_pair(ctx.a_leg_local_port).await;
            }
            if ctx.b_leg_local_port != 0 {
                self.port_allocator.release_pair(ctx.b_leg_local_port).await;
            }

            // Drop sessions lock before acquiring dtls_connections lock
            drop(sessions);

            // Remove DTLS connections keyed by this call_id
            let mut connections = self.dtls_connections.write().await;
            connections.retain(|key, _| !key.starts_with(&format!("{call_id}:")));

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

    /// Returns a reference to the port allocator.
    pub fn port_allocator(&self) -> &RtpPortAllocator {
        &self.port_allocator
    }
}

/// Soft cap on tracked SSRCs: eviction of idle entries starts here.
const SSRC_TRACKER_SOFT_CAP: usize = 4096;
/// Hard cap on tracked SSRCs: new SSRCs are rejected beyond this.
const SSRC_TRACKER_HARD_CAP: usize = 8192;
/// Idle eviction window for SSRC trackers.
const SSRC_TRACKER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

/// A sequence tracker with a last-activity timestamp for idle eviction.
struct TrackedSequence {
    inner: SequenceTracker,
    last_seen: std::time::Instant,
}

impl TrackedSequence {
    fn new() -> Self {
        Self {
            inner: SequenceTracker::new(),
            last_seen: std::time::Instant::now(),
        }
    }
}

/// Which stream a relay leg carries. RTP legs feed the "audio flowing" metric
/// and log; RTCP legs are counted separately so control traffic doesn't inflate
/// the audio signal.
#[derive(Clone, Copy)]
enum RelayKind {
    Rtp,
    Rtcp,
}

impl RelayKind {
    /// Uppercase protocol label for logs.
    fn label(self) -> &'static str {
        match self {
            Self::Rtp => "RTP",
            Self::Rtcp => "RTCP",
        }
    }
}

/// Process-global count of RTP packets forwarded across all relay legs. A
/// working relay increments this; a black-holed one never does. Exposed for
/// observability and as the media "did audio actually flow" signal.
static RTP_PACKETS_RELAYED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Process-global count of RTCP packets forwarded (non-muxed endpoints only;
/// muxed RTCP rides the RTP relay and counts as RTP).
static RTCP_PACKETS_RELAYED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Returns the total RTP packets forwarded by the media relay since start.
#[must_use]
pub fn rtp_packets_relayed() -> u64 {
    RTP_PACKETS_RELAYED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Returns the total RTCP packets forwarded by the media relay since start.
#[must_use]
pub fn rtcp_packets_relayed() -> u64 {
    RTCP_PACKETS_RELAYED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Per-leg DTLS parameters for a terminating relay ([`MediaPipeline::start_relay_terminate`]).
pub struct LegDtlsParams {
    /// The peer's SDP `a=fingerprint`, verified during the handshake.
    pub peer_fingerprint: String,
    /// The SBC's DTLS role for this leg (derived from `a=setup`).
    pub role: Role,
}

/// Everything the terminate supervisor owns for one call (bundled so the spawn
/// and the supervisor signature stay manageable).
struct TerminateSetup {
    call_id: String,
    sidecar_socket: std::path::PathBuf,
    own_fingerprint: String,
    a_socket: Arc<UdpSocket>,
    b_socket: Arc<UdpSocket>,
    a_remote: std::net::SocketAddr,
    b_remote: std::net::SocketAddr,
    a_ssrc: u32,
    b_ssrc: u32,
    a_leg: LegDtlsParams,
    b_leg: LegDtlsParams,
    a_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    b_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

/// Drives both legs' DTLS handshakes concurrently, then spawns the bidirectional
/// SRTP relay and the post-handshake DTLS pump tasks. If either handshake fails,
/// no media is relayed (fail-closed). All spawned tasks stop on the shutdown
/// watch (task abort does not cascade to children, so teardown signals it).
async fn terminate_supervisor(s: TerminateSetup) {
    let (a_res, b_res) = tokio::join!(
        establish_srtp_leg(
            &s.a_socket,
            s.a_remote,
            &s.sidecar_socket,
            &s.own_fingerprint,
            &s.a_leg.peer_fingerprint,
            s.a_leg.role,
        ),
        establish_srtp_leg(
            &s.b_socket,
            s.b_remote,
            &s.sidecar_socket,
            &s.own_fingerprint,
            &s.b_leg.peer_fingerprint,
            s.b_leg.role,
        ),
    );
    let (a_est, b_est) = match (a_res, b_res) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            warn!(
                call_id = %s.call_id,
                a_err = ?a.err(), b_err = ?b.err(),
                "DTLS termination handshake failed; media not relayed"
            );
            return;
        }
    };

    let EstablishedLeg {
        inbound: a_in,
        outbound: a_out,
        reader: a_reader,
        writer: a_writer,
    } = a_est;
    let EstablishedLeg {
        inbound: b_in,
        outbound: b_out,
        reader: b_reader,
        writer: b_writer,
    } = b_est;

    // Four SRTP contexts. The ssrc only seeds per-stream replay state — the AEAD
    // nonce uses the packet's SSRC (see proto-srtp) — so the leg ssrc is fine.
    let ctxs = (
        SrtpContext::new(&a_in, SrtpDirection::Inbound, s.a_ssrc),
        SrtpContext::new(&a_out, SrtpDirection::Outbound, s.a_ssrc),
        SrtpContext::new(&b_in, SrtpDirection::Inbound, s.b_ssrc),
        SrtpContext::new(&b_out, SrtpDirection::Outbound, s.b_ssrc),
    );
    let (a_ingress, a_egress, b_ingress, b_egress) = match ctxs {
        (Ok(ai), Ok(ae), Ok(bi), Ok(be)) => (ai, ae, bi, be),
        _ => {
            warn!(call_id = %s.call_id, "SRTP context creation failed; media not relayed");
            return;
        }
    };

    // Peer→sidecar DTLS (post-handshake rekey) demuxed by each relay leg.
    let (a_dtls_tx, a_dtls_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let (b_dtls_tx, b_dtls_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

    // A→B: unprotect A's media, re-protect for B.
    tokio::spawn(
        TerminateRelayLeg {
            recv_sock: Arc::clone(&s.a_socket),
            send_sock: Arc::clone(&s.b_socket),
            ingress: a_ingress,
            egress: b_egress,
            expected_remote: s.a_remote,
            recv_target: Arc::clone(&s.a_target),
            forward_target: Arc::clone(&s.b_target),
            dtls_out: Some(a_dtls_tx),
            call_id: s.call_id.clone(),
            direction: "A→B",
        }
        .run(s.shutdown.clone()),
    );
    // B→A: unprotect B's media, re-protect for A.
    tokio::spawn(
        TerminateRelayLeg {
            recv_sock: Arc::clone(&s.b_socket),
            send_sock: Arc::clone(&s.a_socket),
            ingress: b_ingress,
            egress: a_egress,
            expected_remote: s.b_remote,
            recv_target: Arc::clone(&s.b_target),
            forward_target: Arc::clone(&s.a_target),
            dtls_out: Some(b_dtls_tx),
            call_id: s.call_id.clone(),
            direction: "B→A",
        }
        .run(s.shutdown.clone()),
    );

    // Post-handshake DTLS pumps own the sidecar halves, keeping each association
    // open for the whole call (finding #2).
    tokio::spawn(forward_dtls_to_sidecar(
        a_dtls_rx,
        a_writer,
        s.shutdown.clone(),
    ));
    tokio::spawn(forward_dtls_to_sidecar(
        b_dtls_rx,
        b_writer,
        s.shutdown.clone(),
    ));
    tokio::spawn(pump_sidecar_dtls_to_peer(
        a_reader,
        Arc::clone(&s.a_socket),
        Arc::clone(&s.a_target),
        s.shutdown.clone(),
    ));
    tokio::spawn(pump_sidecar_dtls_to_peer(
        b_reader,
        Arc::clone(&s.b_socket),
        Arc::clone(&s.b_target),
        s.shutdown.clone(),
    ));

    info!(call_id = %s.call_id, "DTLS-SRTP termination established; relaying media");
}

/// One direction of the media relay (RTP or RTCP, per `kind`) with source
/// validation and symmetric latching.
///
/// Before latching, only packets whose source IP matches the SDP-negotiated
/// remote are forwarded (the port may differ behind NAT). The first accepted
/// packet latches the exact source: subsequent packets must match it, and the
/// opposite direction's send target is updated so replies go to where media
/// actually arrives from (RFC 4961 symmetric RTP). Packets from any other
/// source are dropped and counted — an off-path attacker who learns the media
/// port can no longer inject into or overwrite the stream.
///
/// `call_id` + `direction` are carried for structured logging/metrics; the
/// socket/target set is inherent to a bidirectional forwarder.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection), SC-8
#[allow(clippy::too_many_arguments)]
async fn relay_leg(
    recv_sock: Arc<UdpSocket>,
    send_sock: Arc<UdpSocket>,
    expected_remote: std::net::SocketAddr,
    recv_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    forward_target: Arc<std::sync::RwLock<std::net::SocketAddr>>,
    call_id: String,
    direction: &'static str,
    kind: RelayKind,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut buf = [0u8; 2048];
    let mut latched: Option<std::net::SocketAddr> = None;
    let mut dropped: u64 = 0;
    let mut forwarded: u64 = 0;

    loop {
        tokio::select! {
            result = recv_sock.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        let acceptable = latched.map_or_else(
                            || src.ip() == expected_remote.ip(),
                            |latched_src| src == latched_src,
                        );
                        if !acceptable {
                            dropped += 1;
                            if dropped == 1 || dropped.is_multiple_of(1000) {
                                warn!(
                                    call_id = %call_id,
                                    direction,
                                    kind = kind.label(),
                                    source = %src,
                                    expected = %expected_remote,
                                    dropped,
                                    "Dropping packet from unexpected source"
                                );
                            }
                            continue;
                        }

                        if latched.is_none() {
                            latched = Some(src);
                            if src != expected_remote {
                                debug!(
                                    call_id = %call_id,
                                    direction,
                                    sdp_remote = %expected_remote,
                                    actual = %src,
                                    "Symmetric RTP latch"
                                );
                            }
                            if let Ok(mut target) = recv_target.write() {
                                *target = src;
                            }
                        }

                        let dest = match forward_target.read() {
                            Ok(guard) => *guard,
                            Err(_) => continue,
                        };
                        match send_sock.send_to(&buf[..n], dest).await {
                            Ok(_) => {
                                forwarded += 1;
                                // Count + log once, the moment traffic actually
                                // flows. Fires inside the loop (relay tasks are
                                // abort()ed on teardown, so post-loop code can't
                                // be relied on). The RTP first-forward line is the
                                // "audio is relaying" signal the CI gate greps for;
                                // RTCP is counted separately so it doesn't inflate
                                // the audio metric.
                                match kind {
                                    RelayKind::Rtp => {
                                        RTP_PACKETS_RELAYED
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        if forwarded == 1 {
                                            info!(
                                                call_id = %call_id,
                                                direction,
                                                "RTP relay forwarding media"
                                            );
                                        }
                                    }
                                    RelayKind::Rtcp => {
                                        RTCP_PACKETS_RELAYED
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        if forwarded == 1 {
                                            debug!(
                                                call_id = %call_id,
                                                direction,
                                                "RTCP relay forwarding"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, call_id = %call_id, direction, "Relay send error");
                            }
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, call_id = %call_id, direction, "Relay recv error");
                        break;
                    }
                }
            }
            _ = shutdown.changed() => {
                debug!(call_id = %call_id, direction, "Relay shutdown");
                break;
            }
        }
    }

    // Emit the per-leg forwarded count at info so operators (and the CI harness)
    // can confirm media actually flowed rather than black-holed.
    info!(
        call_id = %call_id,
        direction,
        kind = kind.label(),
        forwarded,
        dropped,
        "Relay leg finished"
    );
}

/// Generates a random SSRC.
///
/// Cryptographically random — a timestamp-derived SSRC is predictable and
/// collision-prone, aiding RTP injection.
fn generate_ssrc() -> u32 {
    rand::random::<u32>()
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

    /// The relay must latch to the first valid source and drop packets from
    /// any other source (RTP injection defense).
    #[tokio::test]
    async fn test_relay_leg_drops_unexpected_sources() {
        let relay_in = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_out = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let legit = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let relay_addr = relay_in.local_addr().unwrap();
        let expected = legit.local_addr().unwrap();
        let recv_target = Arc::new(std::sync::RwLock::new(expected));
        let forward_target = Arc::new(std::sync::RwLock::new(receiver.local_addr().unwrap()));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let _task = tokio::spawn(relay_leg(
            relay_in,
            relay_out,
            expected,
            recv_target,
            forward_target,
            "test-call".to_string(),
            "A→B",
            RelayKind::Rtp,
            shutdown_rx,
        ));

        let mut buf = [0u8; 64];

        // First packet from the negotiated source latches and forwards.
        legit.send_to(b"one", relay_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("legit packet must be forwarded")
        .unwrap();
        assert_eq!(&buf[..n], b"one");

        // Attacker (same IP, different port — post-latch) must be dropped:
        // the next packet the receiver sees is the second legit one.
        attacker.send_to(b"evil", relay_addr).await.unwrap();
        legit.send_to(b"two", relay_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("second legit packet must be forwarded")
        .unwrap();
        assert_eq!(&buf[..n], b"two", "injected packet must not be relayed");
    }

    /// End-to-end relay: the full path the SIP call flow drives
    /// (`create_session` → `set_remote_address` both legs → `start_relay`) must
    /// forward RTP in BOTH directions. This is the audio gate — it fails if the
    /// relay is not actually wired to move packets caller ⇄ SBC ⇄ callee.
    #[tokio::test]
    async fn test_full_relay_forwards_both_directions() {
        use std::time::Duration;
        use tokio::time::timeout;

        // Stand-ins for the caller (A leg) and callee (B leg) endpoints.
        let caller = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caller_addr = caller.local_addr().unwrap();
        let callee_addr = callee.local_addr().unwrap();

        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            ..Default::default()
        });
        // Bind the relay's sockets on loopback so 127.0.0.1:<port> reaches them.
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ports = pipeline
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        // A-leg remote = caller, B-leg remote = callee.
        pipeline
            .set_remote_address("call", true, SbcSocketAddr::from(caller_addr))
            .await
            .unwrap();
        pipeline
            .set_remote_address("call", false, SbcSocketAddr::from(callee_addr))
            .await
            .unwrap();
        let relayed_before = rtp_packets_relayed();
        pipeline.start_relay("call").await.unwrap();

        let a_relay = format!("127.0.0.1:{}", ports.a_leg_rtp_port);
        let b_relay = format!("127.0.0.1:{}", ports.b_leg_rtp_port);
        let mut buf = [0u8; 64];

        // Caller → SBC A-leg port → forwarded to the callee.
        caller.send_to(b"rtp-a2b", &a_relay).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), callee.recv_from(&mut buf))
            .await
            .expect("callee must receive the relayed A→B packet")
            .unwrap();
        assert_eq!(&buf[..n], b"rtp-a2b");

        // Callee → SBC B-leg port → forwarded to the caller.
        callee.send_to(b"rtp-b2a", &b_relay).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), caller.recv_from(&mut buf))
            .await
            .expect("caller must receive the relayed B→A packet")
            .unwrap();
        assert_eq!(&buf[..n], b"rtp-b2a");

        // The relay metric must have counted both forwarded packets (fetch_add
        // lands just after send_to; give it a moment before reading).
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            rtp_packets_relayed() >= relayed_before + 2,
            "rtp_packets_relayed must count forwarded packets"
        );

        pipeline.stop_relay("call").await.unwrap();
    }

    #[tokio::test]
    async fn test_rtcp_relay_forwards_non_muxed() {
        use std::time::Duration;
        use tokio::time::timeout;

        // Stand-ins for the caller (A leg) and callee (B leg) endpoints. Their
        // RTCP is modeled on the same sockets; the relay accepts the first RTCP
        // packet by source IP, then latches the exact source (symmetric RTCP).
        let caller = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caller_addr = caller.local_addr().unwrap();
        let callee_addr = callee.local_addr().unwrap();

        // Distinct port range from the other relay test: start_relay now binds
        // the RTCP pair too, so two default-range relays running concurrently
        // would fight over the same 127.0.0.1 ports.
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            rtp_port_min: 40_000,
            rtp_port_max: 40_200,
            ..Default::default()
        });
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let ports = pipeline
            .create_session_with_zones(
                "rtcp-call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();
        pipeline
            .set_remote_address("rtcp-call", true, SbcSocketAddr::from(caller_addr))
            .await
            .unwrap();
        pipeline
            .set_remote_address("rtcp-call", false, SbcSocketAddr::from(callee_addr))
            .await
            .unwrap();

        let rtcp_before = rtcp_packets_relayed();
        pipeline.start_relay("rtcp-call").await.unwrap();

        // RTCP relay sockets live at RTP port + 1.
        let a_rtcp = format!("127.0.0.1:{}", ports.a_leg_rtp_port + 1);
        let b_rtcp = format!("127.0.0.1:{}", ports.b_leg_rtp_port + 1);
        let mut buf = [0u8; 64];

        // The B→A RTCP send target defaults to callee_rtp_port+1; latch it to the
        // callee's real socket first by sending a report from the callee side.
        callee.send_to(b"rtcp-b0", &b_rtcp).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Caller RTCP → SBC A-leg RTCP port → forwarded to the latched callee.
        caller.send_to(b"rtcp-a2b", &a_rtcp).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(2), callee.recv_from(&mut buf))
            .await
            .expect("callee must receive the relayed A→B RTCP packet")
            .unwrap();
        assert_eq!(&buf[..n], b"rtcp-a2b");

        // RTCP counts on its own metric, never the RTP "audio flowing" one.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            rtcp_packets_relayed() > rtcp_before,
            "rtcp_packets_relayed must count forwarded RTCP"
        );

        pipeline.stop_relay("rtcp-call").await.unwrap();
    }

    /// Port allocator must survive index wraparound and tiny/reversed ranges.
    // rtp/rtcp are the standard protocol names for the port pair.
    #[allow(clippy::similar_names)]
    #[tokio::test]
    async fn test_port_allocator_bounds() {
        // Reversed range is swapped, not panicked on.
        let allocator = RtpPortAllocator::new(20010, 20000);
        let (rtp, rtcp) = allocator.allocate_pair().await.unwrap();
        assert!(rtp >= 20000 && rtcp <= 20010);

        // Exhausting a tiny range fails cleanly and recovers after release.
        let allocator = RtpPortAllocator::new(30000, 30003);
        let (p1, _) = allocator.allocate_pair().await.unwrap();
        let (p2, _) = allocator.allocate_pair().await.unwrap();
        assert_ne!(p1, p2);
        assert!(allocator.allocate_pair().await.is_err());
        allocator.release_pair(p1).await;
        assert_eq!(allocator.allocate_pair().await.unwrap().0, p1);

        // Top-of-range allocation never overflows u16.
        let allocator = RtpPortAllocator::new(65532, 65535);
        let (rtp, rtcp) = allocator.allocate_pair().await.unwrap();
        assert_eq!((rtp, rtcp), (65532, 65533));
        let (rtp, rtcp) = allocator.allocate_pair().await.unwrap();
        assert_eq!((rtp, rtcp), (65534, 65535));
        assert!(allocator.allocate_pair().await.is_err());
    }

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
    fn test_transcoder_pcmu_to_pcma() {
        let a_codec = NegotiatedCodec {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
        };
        let b_codec = NegotiatedCodec {
            name: "PCMA".to_string(),
            payload_type: 8,
            clock_rate: 8000,
        };

        let mut transcoder = Transcoder::new(a_codec, b_codec);

        // Create a PCMU payload (160 bytes = 20ms @ 8kHz)
        let pcmu_payload: Vec<u8> = (0..160).map(|i| (i % 256) as u8).collect();

        // Transcode A→B (PCMU → PCMA)
        let (output, pt) = transcoder.transcode(&pcmu_payload, true).unwrap();
        assert_eq!(pt, 8, "Output should be PCMA payload type");
        assert_eq!(output.len(), 160, "Same frame size for G.711");

        // Transcode B→A (PCMA → PCMU)
        let (output2, pt2) = transcoder.transcode(&output, false).unwrap();
        assert_eq!(pt2, 0, "Output should be PCMU payload type");
        assert_eq!(output2.len(), 160);
    }

    #[test]
    fn test_resample_linear() {
        // 8kHz to 16kHz (2x upsample)
        let input: Vec<i16> = vec![0, 1000, 2000, 3000, 4000];
        let output = resample_linear(&input, 8000, 16_000);
        assert_eq!(output.len(), 10);
        assert_eq!(output[0], 0);
        // Interpolated values should be between samples
        assert!(output[1] > 0 && output[1] < 1000);
    }

    #[tokio::test]
    async fn test_set_negotiated_codecs_same() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());
        pipeline.create_session("test-call", None).await.unwrap();

        let codec = NegotiatedCodec {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
        };

        pipeline
            .set_negotiated_codecs("test-call", codec.clone(), codec)
            .await
            .unwrap();

        // No transcoder should be created for same codec
        let sessions = pipeline.sessions.read().await;
        let ctx = sessions.get("test-call").unwrap();
        assert!(ctx.transcoder.is_none());
    }

    #[tokio::test]
    async fn test_set_negotiated_codecs_different() {
        let pipeline = MediaPipeline::new(MediaPipelineConfig::default());
        pipeline.create_session("test-call", None).await.unwrap();

        let a_codec = NegotiatedCodec {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
        };
        let b_codec = NegotiatedCodec {
            name: "PCMA".to_string(),
            payload_type: 8,
            clock_rate: 8000,
        };

        pipeline
            .set_negotiated_codecs("test-call", a_codec, b_codec)
            .await
            .unwrap();

        // Transcoder should be created
        let sessions = pipeline.sessions.read().await;
        let ctx = sessions.get("test-call").unwrap();
        assert!(ctx.transcoder.is_some());
    }

    #[test]
    fn test_generate_ssrc() {
        let ssrc1 = generate_ssrc();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let ssrc2 = generate_ssrc();
        // SSRCs should be different (high probability)
        assert_ne!(ssrc1, ssrc2);
    }

    // Drives terminate_leg_dtls end-to-end over a mock sidecar + UDP peer and
    // asserts the leg's SRTP contexts and live sidecar halves are stored.
    #[tokio::test]
    async fn terminate_leg_stores_srtp_contexts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        async fn wr<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
            let n = 1 + body.len();
            let mut f = Vec::with_capacity(2 + n);
            f.extend_from_slice(&(n as u16).to_be_bytes());
            f.push(t);
            f.extend_from_slice(body);
            w.write_all(&f).await.unwrap();
        }
        async fn rd<R: AsyncReadExt + Unpin>(r: &mut R) -> u8 {
            let mut h = [0u8; 2];
            r.read_exact(&mut h).await.unwrap();
            let n = usize::from(u16::from_be_bytes(h));
            let mut b = vec![0u8; n];
            r.read_exact(&mut b).await.unwrap();
            b[0]
        }

        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let sock = std::env::temp_dir().join(format!("usg-mp-term-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let fp = "sha-384 SIDECAR";

        let sock2 = sock.clone();
        let sidecar = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.into_split();
            wr(&mut w, 1, fp.as_bytes()).await; // Hello
            assert_eq!(rd(&mut r).await, 2); // Start
            assert_eq!(rd(&mut r).await, 3); // forwarded peer DTLS
            wr(&mut w, 3, b"srv").await; // Dtls
            let mut ready = vec![0u8, 8]; // profile 8 = AEAD_AES_256_GCM
            ready.extend_from_slice(&[7u8; 88]);
            wr(&mut w, 4, &ready).await; // Ready
            let _ = std::fs::remove_file(&sock2);
        });

        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(sock.clone()),
            dtls_fingerprint: Some(fp.to_string()),
            ..Default::default()
        });
        pipeline
            .create_session_with_zones("call", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();

        // Peer's first DTLS record (first byte 22 = handshake).
        peer.send_to(&[22u8, 1, 2], relay_addr).await.unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pipeline.terminate_leg_dtls(
                "call",
                true,
                &relay,
                peer_addr,
                "sha-384 PEER",
                Role::Server,
            ),
        )
        .await
        .expect("terminate timed out")
        .expect("terminate failed");

        assert!(pipeline.test_leg_srtp_active("call", true).await);
        assert!(!pipeline.test_leg_srtp_active("call", false).await);
        sidecar.await.unwrap();
    }

    #[tokio::test]
    async fn terminate_leg_errors_without_sidecar_config() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = relay.local_addr().unwrap();
        // terminate_dtls set but no socket/fingerprint configured.
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            terminate_dtls: true,
            ..Default::default()
        });
        pipeline
            .create_session_with_zones("call", Some(MediaMode::Relay), None, None)
            .await
            .unwrap();
        let err = pipeline
            .terminate_leg_dtls("call", true, &relay, peer, "sha-384 PEER", Role::Server)
            .await
            .unwrap_err();
        assert!(matches!(err, MediaPipelineError::DtlsHandshakeFailed(_)));
    }

    // End-to-end terminate relay over a mock sidecar (no real DTLS): both legs
    // "handshake" (the mock returns known SRTP keys after one pumped record),
    // then real SRTP media protected by peer A crosses the SBC and is recovered
    // by peer B. Exercises start_relay_terminate + the supervisor + both
    // TerminateRelayLeg tasks with the crypto wired end to end.
    #[tokio::test]
    async fn terminate_relay_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        async fn wr<W: AsyncWriteExt + Unpin>(w: &mut W, t: u8, body: &[u8]) {
            let n = 1 + body.len();
            let mut f = Vec::with_capacity(2 + n);
            f.extend_from_slice(&(n as u16).to_be_bytes());
            f.push(t);
            f.extend_from_slice(body);
            w.write_all(&f).await.unwrap();
        }
        async fn rd<R: AsyncReadExt + Unpin>(r: &mut R) {
            let mut h = [0u8; 2];
            r.read_exact(&mut h).await.unwrap();
            let mut b = vec![0u8; usize::from(u16::from_be_bytes(h))];
            r.read_exact(&mut b).await.unwrap();
        }
        fn srtp_ctx(key: &[u8], salt: &[u8], dir: SrtpDirection, ssrc: u32) -> SrtpContext {
            let m = SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.to_vec(), salt.to_vec())
                .unwrap();
            SrtpContext::new(&m, dir, ssrc).unwrap()
        }

        let fp = "sha-384 SIDECAR";
        // Known exported keying material (RFC 5764 layout), generated at runtime.
        let blob: Vec<u8> = (0..88).map(|_| rand::random::<u8>()).collect();
        let client_key = blob[0..32].to_vec();
        let server_key = blob[32..64].to_vec();
        let client_salt = blob[64..76].to_vec();
        let server_salt = blob[76..88].to_vec();

        // One mock sidecar UDS, accepts both legs' connections; each returns the
        // same Ready(blob) after Hello/Start/one Dtls.
        let sock = std::env::temp_dir().join(format!("usg-e2e-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let blob2 = blob.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let blob = blob2.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    wr(&mut w, 1, fp.as_bytes()).await; // Hello
                    rd(&mut r).await; // Start
                    rd(&mut r).await; // forwarded DTLS trigger
                    let mut ready = vec![0u8, 8];
                    ready.extend_from_slice(&blob);
                    wr(&mut w, 4, &ready).await; // Ready(profile=8, keys)
                    // Hold the connection open for the call.
                    let mut sink = [0u8; 64];
                    let _ = r.read(&mut sink).await;
                });
            }
        });

        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        // Unique high port range per run so parallel pipeline tests (which all
        // default to 16384) don't collide on bind.
        let port_base = 24_000_u16.wrapping_add((rand::random::<u16>() % 8_000) & !1);
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(sock.clone()),
            dtls_fingerprint: Some(fp.to_string()),
            rtp_port_min: port_base,
            rtp_port_max: port_base + 200,
            ..Default::default()
        });
        let ports = pipeline
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        let peer_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_relay = format!("127.0.0.1:{}", ports.a_leg_rtp_port);
        let b_relay = format!("127.0.0.1:{}", ports.b_leg_rtp_port);
        pipeline
            .set_remote_address("call", true, peer_a.local_addr().unwrap().into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("call", false, peer_b.local_addr().unwrap().into())
            .await
            .unwrap();

        // SBC is DTLS server on both legs: each peer (DTLS client) protects with
        // the client_write key; the SBC re-protects for the far peer with the
        // server_write key, which that peer unprotects.
        pipeline
            .start_relay_terminate(
                "call",
                LegDtlsParams {
                    peer_fingerprint: "sha-384 A".into(),
                    role: Role::Server,
                },
                LegDtlsParams {
                    peer_fingerprint: "sha-384 B".into(),
                    role: Role::Server,
                },
            )
            .await
            .unwrap();

        // Trigger both handshakes (a DTLS-classified record on each media port).
        peer_a.send_to(&[22u8, 1, 2], &a_relay).await.unwrap();
        peer_b.send_to(&[22u8, 1, 2], &b_relay).await.unwrap();

        let media_ssrc = 0x0001_2345;
        let peer_a_send = srtp_ctx(
            &client_key,
            &client_salt,
            SrtpDirection::Outbound,
            media_ssrc,
        );
        let peer_b_recv = srtp_ctx(
            &server_key,
            &server_salt,
            SrtpDirection::Inbound,
            media_ssrc,
        );

        // Retry A→B media until it crosses (handshakes may still be completing).
        let payload = vec![0x5Au8; 160];
        let mut buf = [0u8; 512];
        let mut received = None;
        for i in 0..40u32 {
            let pkt = RtpPacket::new(
                RtpHeader::new(0, 100 + i as u16, 900, media_ssrc),
                payload.clone(),
            );
            let srtp = SrtpProtect::new(&peer_a_send).protect_rtp(&pkt).unwrap();
            peer_a.send_to(&srtp, &a_relay).await.unwrap();
            if let Ok(Ok((n, _))) = tokio::time::timeout(
                std::time::Duration::from_millis(150),
                peer_b.recv_from(&mut buf),
            )
            .await
            {
                received = Some(n);
                break;
            }
        }
        let n = received.expect("peer B never received terminated media");
        let out = SrtpUnprotect::new(&peer_b_recv)
            .unprotect_rtp(&buf[..n])
            .unwrap();
        assert_eq!(out.payload.as_ref(), payload.as_slice());

        let _ = pipeline.stop_relay("call").await;
        let _ = std::fs::remove_file(&sock);
    }

    // ---- srtp-audio gate (real DTLS handshake, real SRTP media) ----------
    // Spawns the REAL Go sidecar + two REAL DTLS-SRTP media peers and drives a
    // terminated call: each peer completes a real DTLS handshake with the SBC
    // (pumped through the Rust relay to the sidecar), then sends SRTP media that
    // the SBC decrypts on ingress and re-encrypts on egress for the far peer.
    // Both peers must recover relayed audio. Ignored by default (needs the built
    // binaries); the srtp-audio CI job runs it with SIDECAR_BIN + PEER_BIN set.
    //
    // The SBC is the DTLS *client* on both legs so the peers (servers) don't send
    // to the SBC's media port before start_relay_terminate binds it (which would
    // draw ICMP-unreachable and abort their handshake).
    struct PeerProc {
        child: tokio::process::Child,
        fingerprint: String,
        local: std::net::SocketAddr,
        lines: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    }

    async fn read_peer_header(bin: &str, sbc_port: u16, sbc_fp: &str, ssrc: u32) -> PeerProc {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        let mut child = Command::new(bin)
            .args([
                "-role",
                "server",
                "-remote",
                &format!("127.0.0.1:{sbc_port}"),
                "-peer-fp",
                sbc_fp,
                "-count",
                "40",
                "-ssrc",
                &ssrc.to_string(),
            ])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn peer");
        let stdout = child.stdout.take().expect("peer stdout");
        let mut lines = BufReader::new(stdout).lines();
        let mut fp: Option<String> = None;
        let mut local: Option<std::net::SocketAddr> = None;
        while fp.is_none() || local.is_none() {
            let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line())
                .await
                .expect("timeout reading peer header")
                .expect("peer stdout io")
                .expect("peer closed stdout before header");
            if let Some(v) = line.strip_prefix("FINGERPRINT ") {
                fp = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("LOCAL ") {
                local = Some(v.parse().expect("parse LOCAL addr"));
            }
        }
        PeerProc {
            child,
            fingerprint: fp.unwrap(),
            local: local.unwrap(),
            lines,
        }
    }

    async fn peer_received(peer: &mut PeerProc) -> usize {
        loop {
            let line =
                tokio::time::timeout(std::time::Duration::from_secs(35), peer.lines.next_line())
                    .await
                    .expect("timeout awaiting peer RESULT")
                    .expect("peer stdout io")
                    .expect("peer closed stdout before RESULT");
            if let Some(rest) = line.strip_prefix("RESULT ") {
                // "sent=40 received=NN profile=8"
                for tok in rest.split_whitespace() {
                    if let Some(n) = tok.strip_prefix("received=") {
                        return n.parse().expect("parse received count");
                    }
                }
            }
        }
    }

    #[tokio::test]
    #[ignore = "spawns the real sidecar + peer binaries; run via the srtp-audio CI job with SIDECAR_BIN + PEER_BIN set"]
    async fn srtp_audio_end_to_end_real() {
        use tokio::process::Command;

        // Surfaces the relay's warnings (e.g. an SRTP unprotect failure) if the
        // gate ever fails in CI. Quiet by default; raise with RUST_LOG.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("sbc_daemon=warn")),
            )
            .with_test_writer()
            .try_init();

        let sidecar_bin = std::env::var("SIDECAR_BIN").expect("SIDECAR_BIN not set");
        let peer_bin = std::env::var("PEER_BIN").expect("PEER_BIN not set");

        let tmp = std::env::temp_dir();
        let pid = std::process::id();
        let uds = tmp.join(format!("srtp-audio-{pid}.sock"));
        let fp_file = tmp.join(format!("srtp-audio-{pid}.fp"));
        let _ = std::fs::remove_file(&uds);
        let _ = std::fs::remove_file(&fp_file);

        // 1. Real sidecar.
        let mut sidecar = Command::new(&sidecar_bin)
            .args([
                "-socket",
                uds.to_str().unwrap(),
                "-fingerprint-file",
                fp_file.to_str().unwrap(),
            ])
            .env("GODEBUG", "fips140=on")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sidecar");

        // Wait for the sidecar to publish its fingerprint + bind the socket.
        let mut sbc_fp = String::new();
        for _ in 0..200 {
            if let Ok(s) = std::fs::read_to_string(&fp_file)
                && !s.trim().is_empty()
                && uds.exists()
            {
                sbc_fp = s.trim().to_string();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(!sbc_fp.is_empty(), "sidecar never published a fingerprint");

        // 2. Terminate-mode pipeline (unique high port range to avoid collisions).
        let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let port_base = 26_000_u16.wrapping_add((rand::random::<u16>() % 6_000) & !1);
        let pipeline = MediaPipeline::new(MediaPipelineConfig {
            srtp_required: false,
            terminate_dtls: true,
            dtls_sidecar_socket: Some(uds.clone()),
            dtls_fingerprint: Some(sbc_fp.clone()),
            rtp_port_min: port_base,
            rtp_port_max: port_base + 200,
            ..Default::default()
        });
        let ports = pipeline
            .create_session_with_zones(
                "call",
                Some(MediaMode::Relay),
                Some(loopback),
                Some(loopback),
            )
            .await
            .unwrap();

        // 3. Two real peers (DTLS servers), each pointed at its SBC media leg.
        let mut a = read_peer_header(&peer_bin, ports.a_leg_rtp_port, &sbc_fp, 0x1111_1111).await;
        let mut b = read_peer_header(&peer_bin, ports.b_leg_rtp_port, &sbc_fp, 0x2222_2222).await;

        // 4. Point the relay at each peer, then terminate (SBC = DTLS client).
        pipeline
            .set_remote_address("call", true, a.local.into())
            .await
            .unwrap();
        pipeline
            .set_remote_address("call", false, b.local.into())
            .await
            .unwrap();
        pipeline
            .start_relay_terminate(
                "call",
                LegDtlsParams {
                    peer_fingerprint: a.fingerprint.clone(),
                    role: Role::Client,
                },
                LegDtlsParams {
                    peer_fingerprint: b.fingerprint.clone(),
                    role: Role::Client,
                },
            )
            .await
            .unwrap();

        // 5. Both peers must recover relayed audio (SBC decrypted + re-encrypted).
        let recv_a = peer_received(&mut a).await;
        let recv_b = peer_received(&mut b).await;
        let _ = a.child.wait().await;
        let _ = b.child.wait().await;
        let _ = pipeline.stop_relay("call").await;
        let _ = sidecar.kill().await;
        let _ = std::fs::remove_file(&uds);
        let _ = std::fs::remove_file(&fp_file);

        eprintln!("srtp-audio gate: peer A received {recv_a}, peer B received {recv_b}");
        assert!(recv_a > 0, "peer A recovered no relayed audio");
        assert!(recv_b > 0, "peer B recovered no relayed audio");
    }
}
