//! Main audio pipeline coordinating capture, playback, codec, and RTP.
//!
//! The pipeline is a **setup coordinator** — it creates all the audio
//! components and spawns two dedicated `std::thread`s for processing:
//!
//! - **I/O thread**: RTP receive, microphone capture, encode, RTP send
//! - **Decode thread**: jitter buffer → decode → resample → playback ring buffer
//!
//! The CPAL playback callback runs on a real-time OS thread and reads
//! from the ring buffer lock-free. No tokio in the audio path.

use crate::aec::{AecConfig, AecReference};
use crate::audio_processing::{AgcConfig, NoiseGateConfig};
use crate::codec::CodecPipeline;
use crate::comfort_noise::ComfortNoiseConfig;
use crate::decode_thread::{self, DecodeThreadConfig, DecodeThreadHandle};
use crate::device::DeviceManager;
use crate::drift_compensator::DriftConfig;
use crate::file_source::FileAudioSource;
use crate::io_thread::{self, IoThreadConfig, IoThreadHandle};
use crate::jitter_buffer::{JitterBufferConfig, SharedJitterBuffer};
use crate::noise_shaper::NoiseShaperConfig;
use crate::postfilter::PostfilterConfig;
use crate::rtp_handler::{RtpReceiver, RtpStats, RtpTransmitter, generate_ssrc};
use crate::stream::PlaybackStream;
use crate::vad::VadConfig;
use crate::{AudioError, AudioResult};
use client_types::DtmfDigit;
use client_types::audio::CodecPreference;
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Audio pipeline state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineState {
    /// Pipeline is stopped.
    Stopped,
    /// Pipeline is starting up.
    Starting,
    /// Pipeline is running.
    Running,
    /// Pipeline is stopping.
    Stopping,
}

/// Bundled configuration for all audio processing components.
///
/// Each sub-config has a `Default` impl matching the original hardcoded constants,
/// so `AudioProcessingConfig::default()` produces identical behavior to before.
/// Use named constructors like `low_latency()` or `bluetooth()` for presets.
#[derive(Debug, Clone)]
pub struct AudioProcessingConfig {
    /// Automatic gain control settings.
    pub agc: AgcConfig,
    /// Noise gate settings.
    pub noise_gate: NoiseGateConfig,
    /// Voice activity detection settings.
    pub vad: VadConfig,
    /// Acoustic echo cancellation settings.
    pub aec: AecConfig,
    /// Encoder-side noise shaper settings (G.711 only).
    pub noise_shaper: NoiseShaperConfig,
    /// Decoder-side postfilter settings.
    pub postfilter: PostfilterConfig,
    /// Comfort noise generation settings.
    pub comfort_noise: ComfortNoiseConfig,
    /// Clock drift compensation settings.
    pub drift: DriftConfig,
    /// Jitter buffer adaptive algorithm settings.
    pub jitter_buffer: JitterBufferConfig,
}

impl Default for AudioProcessingConfig {
    fn default() -> Self {
        Self {
            agc: AgcConfig::default(),
            noise_gate: NoiseGateConfig::default(),
            vad: VadConfig::default(),
            aec: AecConfig::default(),
            noise_shaper: NoiseShaperConfig::default(),
            postfilter: PostfilterConfig::default(),
            comfort_noise: ComfortNoiseConfig::default(),
            drift: DriftConfig::default(),
            jitter_buffer: JitterBufferConfig::default(),
        }
    }
}

impl AudioProcessingConfig {
    /// Preset for low-latency scenarios (e.g., headset, low-jitter network).
    pub fn low_latency() -> Self {
        Self {
            drift: DriftConfig {
                dead_zone_ms: 2.0,
                ..DriftConfig::default()
            },
            jitter_buffer: JitterBufferConfig {
                jitter_margin_ms: 10.0,
                adapt_smoothing: 0.25,
                ..JitterBufferConfig::default()
            },
            ..Self::default()
        }
    }

    /// Preset for Bluetooth HFP headsets (noisier input, higher thresholds).
    pub fn bluetooth() -> Self {
        Self {
            agc: AgcConfig {
                max_gain: 6.0,
                ..AgcConfig::default()
            },
            noise_gate: NoiseGateConfig {
                threshold: 200.0,
                ..NoiseGateConfig::default()
            },
            vad: VadConfig {
                speech_threshold_ratio: 3.0,
                hangover_frames: 30,
                ..VadConfig::default()
            },
            aec: AecConfig {
                filter_length_ms: 64,
                ..AecConfig::default()
            },
            ..Self::default()
        }
    }

    /// Preset for USB headsets (close-talking mic, short echo path).
    pub fn usb_headset() -> Self {
        Self {
            agc: AgcConfig {
                max_gain: 3.0,
                ..AgcConfig::default()
            },
            noise_gate: NoiseGateConfig {
                threshold: 100.0,
                ..NoiseGateConfig::default()
            },
            aec: AecConfig {
                filter_length_ms: 64,
                ..AecConfig::default()
            },
            ..Self::default()
        }
    }

    /// Preset for conference speakerphones (long echo path, room noise).
    pub fn speakerphone() -> Self {
        Self {
            noise_gate: NoiseGateConfig {
                threshold: 250.0,
                ..NoiseGateConfig::default()
            },
            vad: VadConfig {
                speech_threshold_ratio: 3.5,
                hangover_frames: 35,
                ..VadConfig::default()
            },
            aec: AecConfig {
                filter_length_ms: 256,
                ..AecConfig::default()
            },
            ..Self::default()
        }
    }

    /// Returns the appropriate preset for a detected device category.
    pub fn for_device_category(category: client_types::audio::DeviceCategory) -> Self {
        use client_types::audio::DeviceCategory;
        match category {
            DeviceCategory::Bluetooth => Self::bluetooth(),
            DeviceCategory::UsbHeadset => Self::usb_headset(),
            DeviceCategory::Speakerphone => Self::speakerphone(),
            DeviceCategory::BuiltInSpeaker
            | DeviceCategory::BuiltInMic
            | DeviceCategory::Unknown => Self::default(),
        }
    }
}

/// Configuration for the audio pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Codec preference.
    pub codec: CodecPreference,
    /// Local RTP port.
    pub local_port: u16,
    /// Remote RTP address.
    pub remote_addr: SocketAddr,
    /// Jitter buffer depth in milliseconds.
    pub jitter_buffer_ms: u32,
    /// SRTP master key (32 bytes for AES-256).
    pub srtp_master_key: Option<Vec<u8>>,
    /// SRTP master salt (12 bytes).
    pub srtp_master_salt: Option<Vec<u8>>,
    /// Whether transmit is muted.
    pub muted: bool,
    /// Music on Hold file path (optional).
    pub moh_file_path: Option<String>,
    /// DTMF telephone-event payload type from SDP (`None` = use default 101).
    pub dtmf_payload_type: Option<u8>,
    /// DTMF volume level for RFC 4733 packets (0-63, default 10).
    pub dtmf_volume: u8,
    /// Inter-digit pause in milliseconds (default 100).
    pub dtmf_inter_digit_pause_ms: u32,
    /// RFC 2198 redundancy payload type from SDP (`None` = disabled).
    pub redundancy_pt: Option<u8>,
    /// Whether acoustic echo cancellation is enabled.
    pub echo_cancellation: bool,
    /// Audio processing component configuration.
    pub audio: AudioProcessingConfig,
    /// Negotiated RTP header extensions (id, URI) from SDP `a=extmap`.
    ///
    /// When non-empty, the RTP transmitter includes a one-byte extension
    /// header in outgoing packets, and the receiver can interpret extension
    /// elements in incoming packets.
    pub extension_ids: Vec<(u8, String)>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            codec: CodecPreference::G711Ulaw,
            local_port: 0, // Auto-assign
            remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            jitter_buffer_ms: 40,
            srtp_master_key: None,
            srtp_master_salt: None,
            muted: false,
            moh_file_path: None,
            dtmf_payload_type: None,
            dtmf_volume: 10,
            dtmf_inter_digit_pause_ms: 100,
            redundancy_pt: None,
            echo_cancellation: true,
            audio: AudioProcessingConfig::default(),
            extension_ids: Vec::new(),
        }
    }
}

/// Statistics for the audio pipeline.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    /// RTP transmission statistics.
    pub tx_stats: RtpStats,
    /// RTP reception statistics.
    pub rx_stats: RtpStats,
    /// Jitter buffer statistics.
    pub jitter_stats: crate::jitter_buffer::JitterBufferStats,
    /// Capture underruns (not enough samples).
    pub capture_underruns: u64,
    /// Playback underruns (buffer empty).
    pub playback_underruns: u64,
    /// Round-trip time in milliseconds (from RTCP).
    pub rtt_ms: Option<f32>,
    /// Active codec name.
    pub codec_name: String,
    /// Frames recovered via FEC (Opus inband FEC).
    pub fec_recovered_frames: u64,
    /// Frames generated by PLC (WSOLA concealment).
    pub plc_generated_frames: u64,
    /// Frames recovered via RFC 2198 redundancy.
    pub redundancy_recovered_frames: u64,
    /// DTMF events received from remote.
    pub dtmf_events_received: u64,
    /// DTMF events sent to remote.
    pub dtmf_events_sent: u64,
    /// Malformed DTMF packets (invalid event code, duration, or impossible jumps).
    pub dtmf_malformed: u64,
    /// Current AGC gain (linear, 1.0 = unity).
    pub agc_current_gain: f32,
    /// AEC ERLE estimate in dB (Echo Return Loss Enhancement).
    pub aec_erle_db: f32,
}

/// Estimated call quality report derived from pipeline statistics.
///
/// Uses the E-model (ITU-T G.107 simplified) to estimate Mean Opinion Score (MOS).
#[derive(Debug, Clone, Copy)]
pub struct CallQualityReport {
    /// Estimated MOS (1.0-4.5). Higher is better.
    pub mos: f32,
    /// Packet loss percentage (0.0-100.0).
    pub loss_pct: f32,
    /// Average jitter in milliseconds.
    pub jitter_ms: f32,
    /// Round-trip time in milliseconds.
    pub rtt_ms: f32,
}

impl CallQualityReport {
    /// Computes a quality report from pipeline statistics.
    ///
    /// Uses a simplified E-model: `R = 93.2 - Id - Ie`, where:
    /// - `Id` accounts for delay (RTT/2 as one-way)
    /// - `Ie` accounts for equipment impairment (loss + codec)
    ///
    /// R is then converted to MOS via the standard formula.
    pub fn from_stats(stats: &PipelineStats) -> Self {
        let total_expected = stats.jitter_stats.packets_played
            + stats.jitter_stats.packets_lost;
        #[allow(clippy::cast_precision_loss)]
        let loss_pct = if total_expected > 0 {
            (stats.jitter_stats.packets_lost as f64 / total_expected as f64 * 100.0) as f32
        } else {
            0.0
        };

        let jitter_ms = stats.jitter_stats.average_jitter_ms;
        let rtt_ms = stats.rtt_ms.unwrap_or(0.0);

        // Simplified E-model (ITU-T G.107/G.113)
        let one_way_delay = rtt_ms / 2.0;
        let id = if one_way_delay > 177.3 {
            0.024 * one_way_delay + 0.11 * (one_way_delay - 177.3)
        } else {
            0.024 * one_way_delay
        };
        // Equipment impairment (G.113 Appendix I for G.711):
        // Ie=0 (codec impairment), Bpl=25.1 (packet loss robustness)
        // Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl + Bpl)
        let ie_eff = 95.0 * loss_pct / (loss_pct + 25.1);
        let r = (93.2 - id - ie_eff).clamp(0.0, 100.0);

        // R to MOS conversion (ITU-T G.107)
        let mos = if r < 6.5 {
            1.0
        } else if r > 100.0 {
            4.5
        } else {
            1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6
        };

        Self {
            mos,
            loss_pct,
            jitter_ms,
            rtt_ms,
        }
    }
}

/// Audio pipeline coordinating the full audio path.
///
/// Creates all audio components on `start()`, spawns the I/O and decode
/// threads, and joins them on `stop()`. No async methods.
pub struct AudioPipeline {
    /// Device manager for audio device selection.
    device_manager: DeviceManager,
    /// Current pipeline state.
    state: PipelineState,
    /// Handle to the running decode thread.
    decode_thread: Option<DecodeThreadHandle>,
    /// Handle to the running I/O thread.
    io_thread: Option<IoThreadHandle>,
    /// Whether TX is muted.
    muted: Arc<AtomicBool>,
    /// Running flag for background threads.
    running: Arc<AtomicBool>,
    /// Shared statistics (written by I/O thread, read by UI).
    stats: Arc<Mutex<PipelineStats>>,
    /// Whether MOH is currently active.
    moh_active: Arc<AtomicBool>,
    /// Whether MOH audio was loaded.
    has_moh_audio: bool,
    /// Playback underrun counter shared with CPAL callback.
    playback_underruns: Option<Arc<AtomicU64>>,
    /// Decode thread metrics (FEC, PLC, DTMF counters).
    decode_metrics: Option<Arc<decode_thread::DecodeMetrics>>,
    /// Local RTP port (set after start).
    local_port: Option<u16>,
    /// SSRC being used for transmission.
    ssrc: Option<u32>,
    /// Receiver for DTMF digits detected by the decode thread.
    /// Wrapped in Mutex for Sync (needed by async Tauri command handlers).
    dtmf_rx: Option<Mutex<std::sync::mpsc::Receiver<DtmfDigit>>>,
}

impl AudioPipeline {
    /// Creates a new audio pipeline.
    pub fn new() -> Self {
        Self {
            device_manager: DeviceManager::new(),
            state: PipelineState::Stopped,
            decode_thread: None,
            io_thread: None,
            muted: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(PipelineStats::default())),
            moh_active: Arc::new(AtomicBool::new(false)),
            has_moh_audio: false,
            playback_underruns: None,
            decode_metrics: None,
            local_port: None,
            ssrc: None,
            dtmf_rx: None,
        }
    }

    /// Returns a reference to the device manager.
    pub const fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Returns a mutable reference to the device manager.
    pub const fn device_manager_mut(&mut self) -> &mut DeviceManager {
        &mut self.device_manager
    }

    /// Starts the audio pipeline with the given configuration.
    ///
    /// Creates the UDP socket, CPAL streams, jitter buffer, and spawns
    /// the I/O and decode threads. Returns the local RTP port.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn start(&mut self, config: PipelineConfig) -> AudioResult<u16> {
        use ringbuf::traits::Producer;

        if self.state != PipelineState::Stopped {
            return Err(AudioError::ConfigError(
                "Pipeline already running".to_string(),
            ));
        }

        self.state = PipelineState::Starting;
        info!("Starting audio pipeline: codec={:?}", config.codec);

        // Create a temporary codec to query parameters
        let temp_codec = CodecPipeline::new(config.codec)?;
        let clock_rate = temp_codec.clock_rate();
        #[allow(clippy::cast_possible_truncation)]
        let samples_per_frame = temp_codec.samples_per_frame() as u32;
        let payload_type = temp_codec.payload_type();
        drop(temp_codec);

        // Bind std::net::UdpSocket (blocking)
        let local_port_cfg = config.local_port;
        let bind_addr = format!("0.0.0.0:{local_port_cfg}");
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| AudioError::StreamError(format!("Failed to bind socket: {e}")))?;

        let local_port = socket
            .local_addr()
            .map_err(|e| AudioError::StreamError(format!("Failed to get local address: {e}")))?
            .port();

        // Set recv_timeout for the I/O thread (5ms — quick return if no packet)
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(5)))
            .map_err(|e| AudioError::StreamError(format!("Failed to set recv timeout: {e}")))?;

        debug!("Bound RTP socket to port {}", local_port);

        let socket = Arc::new(socket);

        // Create shared jitter buffer (used by I/O thread and decode thread)
        let jitter_buffer = SharedJitterBuffer::with_config(
            clock_rate,
            samples_per_frame,
            config.jitter_buffer_ms,
            config.audio.jitter_buffer.clone(),
        );

        // Create transmitter
        let ssrc = generate_ssrc();
        let mut transmitter = RtpTransmitter::new(
            socket.clone(),
            config.remote_addr,
            ssrc,
            payload_type,
            samples_per_frame,
        );

        // Apply negotiated DTMF payload type (if different from default 101)
        if let Some(pt) = config.dtmf_payload_type {
            transmitter.set_dtmf_payload_type(pt);
        }

        // Enable RFC 2198 redundancy if negotiated in SDP
        if let Some(pt) = config.redundancy_pt {
            transmitter.enable_redundancy(pt);
        }

        // Create receiver
        let mut receiver = RtpReceiver::new(socket, jitter_buffer.clone());

        // Enable RFC 2198 redundancy reception if negotiated in SDP
        if let Some(pt) = config.redundancy_pt {
            receiver.set_redundancy_pt(pt);
        }

        // Set local SSRC on receiver for collision detection (RFC 3550 §8.2)
        receiver.set_local_ssrc(ssrc);

        // Set negotiated RTP header extensions on both transmitter and receiver
        if !config.extension_ids.is_empty() {
            transmitter.set_extension_map(config.extension_ids.clone());
            receiver.set_extension_map(config.extension_ids.clone());
        }

        // Set up SRTP if keys are provided
        if let (Some(key), Some(salt)) = (&config.srtp_master_key, &config.srtp_master_salt) {
            let key_material =
                SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.clone(), salt.clone())
                    .map_err(|e| {
                        AudioError::SrtpError(format!("Failed to create SRTP key material: {e}"))
                    })?;

            let tx_context = SrtpContext::new(&key_material, SrtpDirection::Outbound, ssrc)
                .map_err(|e| {
                    AudioError::SrtpError(format!("Failed to create TX SRTP context: {e}"))
                })?;
            transmitter.set_srtp(tx_context);

            let rx_context =
                SrtpContext::new(&key_material, SrtpDirection::Inbound, 0).map_err(|e| {
                    AudioError::SrtpError(format!("Failed to create RX SRTP context: {e}"))
                })?;
            receiver.set_srtp(rx_context);

            debug!("SRTP enabled for audio pipeline");
        }

        // Start capture stream
        let capture = crate::stream::CaptureStream::new(&self.device_manager)?;
        let capture_rate = capture.sample_rate();

        // Start playback stream and split off the producer
        let playback = PlaybackStream::new(&self.device_manager)?;
        let device_rate = playback.sample_rate();

        info!(
            "Audio rates: capture={}Hz, playback={}Hz, codec={}Hz",
            capture_rate, device_rate, clock_rate
        );
        if capture_rate != device_rate {
            warn!(
                "Capture rate ({}) != playback rate ({}), capture may be misaligned!",
                capture_rate, device_rate
            );
        }
        let (playback_handle, mut producer, underrun_counter) = playback.take_producer();

        // Pre-fill the playback ring buffer with silence so the CPAL callback
        // has a cushion from the first callback.
        let prefill_ms = 100;
        #[allow(clippy::cast_possible_truncation)]
        let prefill_samples = (device_rate * prefill_ms / 1000) as usize;
        let silence = vec![0i16; prefill_samples];
        producer.push_slice(&silence);
        debug!(
            "Pre-filled playback buffer with {}ms of silence",
            prefill_ms
        );

        // Load MOH if configured
        let moh_source = config.moh_file_path.as_ref().and_then(|moh_path| {
            let mut source = FileAudioSource::new(clock_rate);
            match source.load(moh_path) {
                Ok(()) => {
                    info!("MOH loaded: {:.2}s", source.duration_secs());
                    Some(source)
                }
                Err(e) => {
                    warn!("Failed to load MOH file: {e}");
                    None
                }
            }
        });
        let has_moh = moh_source.is_some();

        // Set running flag
        self.muted.store(config.muted, Ordering::Relaxed);
        self.moh_active.store(false, Ordering::Relaxed);
        self.running.store(true, Ordering::Relaxed);

        // Create AEC reference buffer (shared between decode and I/O threads)
        let aec_ref = if config.echo_cancellation {
            let aec = AecReference::new(clock_rate, 300); // 300ms buffer
            info!("AEC enabled: created reference buffer at {}Hz", clock_rate);
            Some(aec)
        } else {
            None
        };

        // Create DTMF receive notification channel
        let (dtmf_rx_tx, dtmf_rx_rx) = std::sync::mpsc::channel();

        // Spawn decode thread
        let decode_config = DecodeThreadConfig {
            codec: config.codec,
            device_rate,
            dtmf_payload_type: config.dtmf_payload_type.unwrap_or(crate::rtp_handler::DTMF_PAYLOAD_TYPE),
            aec_ref: aec_ref.clone(),
            drift: config.audio.drift.clone(),
            postfilter: config.audio.postfilter.clone(),
            comfort_noise: config.audio.comfort_noise.clone(),
            dtmf_rx_tx: Some(dtmf_rx_tx),
        };
        let decode_metrics = decode_thread::DecodeMetrics::new();
        let decode_handle = decode_thread::spawn(
            decode_config,
            producer,
            playback_handle,
            jitter_buffer,
            self.running.clone(),
            underrun_counter.clone(),
            decode_metrics.clone(),
        );

        // Create RTCP socket (bound to any available port)
        let rtcp_socket = UdpSocket::bind("0.0.0.0:0")
            .map(|s| {
                // Non-blocking is fine — we only send, never recv
                let _ = s.set_nonblocking(true);
                Arc::new(s)
            })
            .ok();

        // Remote RTCP address: remote RTP port + 1 (RFC 3550 §11)
        let rtcp_remote_addr = Some(SocketAddr::new(
            config.remote_addr.ip(),
            config.remote_addr.port() + 1,
        ));

        if rtcp_socket.is_some() {
            debug!("RTCP socket created for reports to {:?}", rtcp_remote_addr);
        }

        // Spawn I/O thread (uses capture rate for mic read sizing)
        let io_config = IoThreadConfig {
            codec: config.codec,
            capture_rate,
            rtcp_socket,
            rtcp_remote_addr,
            local_ssrc: ssrc,
            dtmf_volume: config.dtmf_volume,
            dtmf_inter_digit_pause_ms: config.dtmf_inter_digit_pause_ms,
            aec_ref,
            agc: config.audio.agc,
            noise_gate: config.audio.noise_gate,
            vad: config.audio.vad,
            aec: config.audio.aec,
            noise_shaper: config.audio.noise_shaper,
        };
        // Give the I/O thread a sender to the decode thread so it can
        // trigger a playback stream refresh after input device switches
        // (handles macOS Bluetooth HFP→A2DP profile changes).
        let decode_cmd_tx = Some(decode_handle.cmd_sender());
        let io_handle = io_thread::spawn(
            io_config,
            transmitter,
            receiver,
            capture,
            moh_source,
            self.muted.clone(),
            self.moh_active.clone(),
            self.stats.clone(),
            self.running.clone(),
            decode_cmd_tx,
        );

        // Store handles (playback_handle is owned by the decode thread)
        self.decode_thread = Some(decode_handle);
        self.io_thread = Some(io_handle);
        self.playback_underruns = Some(underrun_counter);
        self.decode_metrics = Some(decode_metrics);
        self.has_moh_audio = has_moh;
        self.local_port = Some(local_port);
        self.ssrc = Some(ssrc);
        self.dtmf_rx = Some(Mutex::new(dtmf_rx_rx));

        self.state = PipelineState::Running;
        info!("Audio pipeline started on port {}", local_port);

        Ok(local_port)
    }

    /// Stops the audio pipeline.
    pub fn stop(&mut self) {
        if self.state == PipelineState::Stopped {
            return;
        }

        info!("Stopping audio pipeline");
        self.state = PipelineState::Stopping;

        // Signal threads to stop
        self.running.store(false, Ordering::Relaxed);

        // Join I/O thread first (it owns the socket and capture)
        if let Some(mut handle) = self.io_thread.take() {
            handle.stop();
        }

        // Join decode thread
        if let Some(mut handle) = self.decode_thread.take() {
            handle.stop();
        }

        // CPAL playback stream is owned by the decode thread and
        // dropped when it exits — no explicit stop needed here.

        self.has_moh_audio = false;
        self.playback_underruns = None;
        self.decode_metrics = None;
        self.local_port = None;
        self.ssrc = None;

        self.state = PipelineState::Stopped;
        info!("Audio pipeline stopped");
    }

    /// Sends a DTMF digit using RFC 4733 telephone-event and/or in-band tones.
    ///
    /// The command is sent to the I/O thread via a channel; the actual
    /// packet sequence is generated there.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to send
    /// * `duration_ms` - Duration in milliseconds
    /// * `use_rfc2833` - Whether to send RFC 2833 packets (if false, in-band only)
    pub fn send_dtmf(
        &self,
        digit: DtmfDigit,
        duration_ms: u32,
        use_rfc2833: bool,
    ) -> AudioResult<()> {
        let io = self
            .io_thread
            .as_ref()
            .ok_or_else(|| AudioError::ConfigError("Pipeline not running".to_string()))?;

        io.send_dtmf(digit, duration_ms, use_rfc2833);
        Ok(())
    }

    /// Sets the mute state for transmission.
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
        debug!("Audio mute: {}", muted);
    }

    /// Returns whether transmission is muted.
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    /// Sets the Music on Hold active state.
    pub fn set_moh_active(&self, active: bool) {
        self.moh_active.store(active, Ordering::Relaxed);
        debug!("MOH active: {}", active);
    }

    /// Drains all received DTMF digits from the decode thread.
    ///
    /// Returns an iterator of `DtmfDigit` values. Call this periodically
    /// (e.g., from a timer or event loop) to process incoming DTMF events.
    pub fn drain_received_dtmf(&self) -> Vec<DtmfDigit> {
        self.dtmf_rx
            .as_ref()
            .and_then(|m| m.lock().ok())
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default()
    }

    /// Returns whether Music on Hold is currently active.
    pub fn is_moh_active(&self) -> bool {
        self.moh_active.load(Ordering::Relaxed)
    }

    /// Returns whether MOH audio has been loaded.
    pub const fn has_moh(&self) -> bool {
        self.has_moh_audio
    }

    /// Returns the current pipeline state.
    pub const fn state(&self) -> PipelineState {
        self.state
    }

    /// Returns whether the pipeline is running.
    pub fn is_running(&self) -> bool {
        self.state == PipelineState::Running
    }

    /// Returns the pipeline statistics.
    pub fn stats(&self) -> PipelineStats {
        let mut stats = self
            .stats
            .lock()
            .map_or_else(|_| PipelineStats::default(), |s| s.clone());
        // Merge in the CPAL callback underrun count
        if let Some(ref counter) = self.playback_underruns {
            stats.playback_underruns = counter.load(Ordering::Relaxed);
        }
        // Merge decode-thread metrics
        if let Some(ref m) = self.decode_metrics {
            stats.fec_recovered_frames = m.fec_recovered.load(Ordering::Relaxed);
            stats.plc_generated_frames = m.plc_generated.load(Ordering::Relaxed);
            stats.dtmf_events_received = m.dtmf_received.load(Ordering::Relaxed);
            stats.dtmf_malformed = m.dtmf_malformed.load(Ordering::Relaxed);
        }
        stats
    }

    /// Returns the local RTP port.
    pub const fn local_port(&self) -> Option<u16> {
        self.local_port
    }

    /// Returns the SSRC being used for transmission.
    pub const fn ssrc(&self) -> Option<u32> {
        self.ssrc
    }

    /// Switches the input (microphone) device.
    ///
    /// If the pipeline is running, hot-swaps the capture stream on the I/O
    /// thread. Also stores the preference for future pipeline starts.
    #[allow(clippy::needless_pass_by_value)]
    pub fn switch_input_device(&mut self, device_name: Option<String>) -> AudioResult<()> {
        info!("Setting input device to: {:?}", device_name);
        self.device_manager.set_input_device(device_name.clone());
        if let Some(ref io) = self.io_thread {
            io.switch_input_device(device_name);
        }
        Ok(())
    }

    /// Switches the output (speaker) device.
    ///
    /// If the pipeline is running, hot-swaps the playback stream on the
    /// decode thread. Also stores the preference for future pipeline starts.
    #[allow(clippy::needless_pass_by_value)]
    pub fn switch_output_device(&mut self, device_name: Option<String>) -> AudioResult<()> {
        info!("Setting output device to: {:?}", device_name);
        self.device_manager.set_output_device(device_name.clone());
        if let Some(ref decode) = self.decode_thread {
            decode.switch_output_device(device_name);
        }
        Ok(())
    }

    /// Returns the current input device name.
    pub fn input_device_name(&self) -> Option<&str> {
        self.device_manager.input_device_name()
    }

    /// Returns the current output device name.
    pub fn output_device_name(&self) -> Option<&str> {
        self.device_manager.output_device_name()
    }
}

impl Default for AudioPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AudioPipeline {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Resample audio using linear interpolation with cross-frame continuity.
///
/// For `VoIP` (G.711 at 8kHz ↔ device at 48kHz), the codec already band-limits
/// to 4kHz, so linear interpolation is clean for upsampling and simple
/// averaging-decimation works for downsampling.
///
/// The `prev_sample` parameter provides the last input sample from the previous
/// frame, enabling smooth interpolation across frame boundaries.
///
/// `output` must have exactly the desired number of output samples. Uses
/// integer-ratio linear interpolation, integer-ratio averaging, or
/// Catmull-Rom cubic for arbitrary ratios.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::suboptimal_flops
)]
pub(crate) fn resample_into(input: &[i16], output: &mut [i16], prev_sample: i16) {
    let in_len = input.len();
    let output_len = output.len();

    if in_len == output_len {
        output.copy_from_slice(input);
        return;
    }

    // Fast path: integer ratio upsampling
    if output_len > in_len && output_len.is_multiple_of(in_len) {
        let ratio = output_len / in_len;
        let mut pos = 0;
        for i in 0..in_len {
            let s0 = if i == 0 {
                i32::from(prev_sample)
            } else {
                i32::from(input[i - 1])
            };
            let s1 = i32::from(input[i]);
            for j in 0..ratio {
                let t = (j + 1) as i32;
                let sample = s0 + (s1 - s0) * t / ratio as i32;
                output[pos] = sample as i16;
                pos += 1;
            }
        }
        return;
    }

    // Fast path: integer ratio downsampling
    if in_len > output_len && in_len.is_multiple_of(output_len) {
        let ratio = in_len / output_len;
        for i in 0..output_len {
            let start = i * ratio;
            let sum: i32 = input[start..start + ratio]
                .iter()
                .map(|&s| i32::from(s))
                .sum();
            output[i] = (sum / ratio as i32) as i16;
        }
        return;
    }

    // General case: Catmull-Rom cubic interpolation
    let step = in_len as f64 / output_len as f64;

    let sample_at = |idx: i32| -> f64 {
        if idx < 0 {
            f64::from(prev_sample)
        } else if (idx as usize) < in_len {
            f64::from(input[idx as usize])
        } else {
            f64::from(input[in_len - 1])
        }
    };

    for i in 0..output_len {
        let pos = i as f64 * step;
        let idx = pos.floor() as i32;
        let t = pos - f64::from(idx);

        let p0 = sample_at(idx - 1);
        let p1 = sample_at(idx);
        let p2 = sample_at(idx + 1);
        let p3 = sample_at(idx + 2);

        let t2 = t * t;
        let t3 = t2 * t;
        let sample = 0.5
            * ((2.0 * p1)
                + (-p0 + p2) * t
                + (2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3) * t2
                + (-p0 + 3.0 * p1 - 3.0 * p2 + p3) * t3);

        output[i] = sample
            .round()
            .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert_eq!(config.codec, CodecPreference::G711Ulaw);
        assert_eq!(config.jitter_buffer_ms, 40);
        assert!(!config.muted);
    }

    #[test]
    fn test_pipeline_state() {
        let pipeline = AudioPipeline::new();
        assert_eq!(pipeline.state(), PipelineState::Stopped);
        assert!(!pipeline.is_running());
    }

    #[test]
    fn test_pipeline_mute() {
        let pipeline = AudioPipeline::new();
        assert!(!pipeline.is_muted());

        pipeline.set_muted(true);
        assert!(pipeline.is_muted());

        pipeline.set_muted(false);
        assert!(!pipeline.is_muted());
    }

    #[test]
    fn test_pipeline_stats_default() {
        let stats = PipelineStats::default();
        assert_eq!(stats.capture_underruns, 0);
        assert_eq!(stats.playback_underruns, 0);
        assert_eq!(stats.fec_recovered_frames, 0);
        assert_eq!(stats.plc_generated_frames, 0);
        assert_eq!(stats.dtmf_events_received, 0);
        assert_eq!(stats.dtmf_events_sent, 0);
    }

    #[test]
    fn test_call_quality_report_perfect() {
        // No loss, no jitter, no RTT → near-perfect MOS
        let stats = PipelineStats {
            jitter_stats: crate::jitter_buffer::JitterBufferStats {
                packets_played: 1000,
                packets_lost: 0,
                average_jitter_ms: 0.0,
                ..Default::default()
            },
            rtt_ms: Some(20.0),
            ..Default::default()
        };
        let report = CallQualityReport::from_stats(&stats);
        assert!(
            report.mos > 4.0,
            "Perfect conditions should give MOS > 4.0, got {}",
            report.mos
        );
        assert!(report.loss_pct < 0.01);
    }

    #[test]
    fn test_call_quality_report_lossy() {
        // 10% loss → degraded MOS
        let stats = PipelineStats {
            jitter_stats: crate::jitter_buffer::JitterBufferStats {
                packets_played: 900,
                packets_lost: 100,
                average_jitter_ms: 30.0,
                ..Default::default()
            },
            rtt_ms: Some(100.0),
            ..Default::default()
        };
        let report = CallQualityReport::from_stats(&stats);
        assert!(
            report.mos < 3.5,
            "10% loss should degrade MOS below 3.5, got {}",
            report.mos
        );
        assert!((report.loss_pct - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_audio_processing_config_presets() {
        let default = AudioProcessingConfig::default();
        let low_lat = AudioProcessingConfig::low_latency();
        let bt = AudioProcessingConfig::bluetooth();

        // Low-latency should have tighter dead zone
        assert!(low_lat.drift.dead_zone_ms < default.drift.dead_zone_ms);
        // Bluetooth should have higher noise gate threshold
        assert!(bt.noise_gate.threshold > default.noise_gate.threshold);
    }
}
