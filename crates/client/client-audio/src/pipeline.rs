//! Main audio pipeline coordinating capture, playback, codec, and RTP.
//!
//! This module provides the `AudioPipeline` which orchestrates the full
//! audio path from microphone capture through encoding, RTP transmission,
//! reception, decoding, and speaker playback.

use crate::codec::CodecPipeline;
use crate::device::DeviceManager;
use crate::file_source::FileAudioSource;
use crate::jitter_buffer::JitterBufferResult;
use crate::rtp_handler::{RtpReceiver, RtpStats, RtpTransmitter, generate_ssrc};
use crate::stream::{CaptureStream, PlaybackStream};
use crate::{AudioError, AudioResult};
use client_types::audio::CodecPreference;
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

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
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            codec: CodecPreference::G711Ulaw,
            local_port: 0, // Auto-assign
            remote_addr: "0.0.0.0:0".parse().unwrap(),
            jitter_buffer_ms: 60,
            srtp_master_key: None,
            srtp_master_salt: None,
            muted: false,
            moh_file_path: None,
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
}

/// Audio pipeline coordinating the full audio path.
pub struct AudioPipeline {
    /// Device manager for audio device selection.
    device_manager: DeviceManager,
    /// Pipeline configuration.
    config: PipelineConfig,
    /// Current pipeline state.
    state: PipelineState,
    /// Codec pipeline for encode/decode.
    codec: Option<CodecPipeline>,
    /// RTP transmitter.
    transmitter: Option<RtpTransmitter>,
    /// RTP receiver.
    receiver: Option<RtpReceiver>,
    /// UDP socket for RTP.
    socket: Option<Arc<UdpSocket>>,
    /// Capture stream.
    capture: Option<CaptureStream>,
    /// Playback stream.
    playback: Option<PlaybackStream>,
    /// Whether TX is muted.
    muted: AtomicBool,
    /// Running flag for background tasks.
    running: Arc<AtomicBool>,
    /// Statistics.
    stats: Arc<std::sync::Mutex<PipelineStats>>,
    /// Music on Hold audio source.
    moh_source: Option<FileAudioSource>,
    /// Whether MOH is currently active (call on hold).
    moh_active: AtomicBool,
}

impl AudioPipeline {
    /// Creates a new audio pipeline.
    pub fn new() -> Self {
        Self {
            device_manager: DeviceManager::new(),
            config: PipelineConfig::default(),
            state: PipelineState::Stopped,
            codec: None,
            transmitter: None,
            receiver: None,
            socket: None,
            capture: None,
            playback: None,
            muted: AtomicBool::new(false),
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(std::sync::Mutex::new(PipelineStats::default())),
            moh_source: None,
            moh_active: AtomicBool::new(false),
        }
    }

    /// Returns a reference to the device manager.
    pub fn device_manager(&self) -> &DeviceManager {
        &self.device_manager
    }

    /// Returns a mutable reference to the device manager.
    pub fn device_manager_mut(&mut self) -> &mut DeviceManager {
        &mut self.device_manager
    }

    /// Starts the audio pipeline with the given configuration.
    pub async fn start(&mut self, config: PipelineConfig) -> AudioResult<u16> {
        if self.state != PipelineState::Stopped {
            return Err(AudioError::ConfigError(
                "Pipeline already running".to_string(),
            ));
        }

        self.state = PipelineState::Starting;
        info!("Starting audio pipeline: codec={:?}", config.codec);

        // Create codec pipeline
        let codec = CodecPipeline::new(config.codec)?;
        let clock_rate = codec.clock_rate();
        let samples_per_frame = codec.samples_per_frame() as u32;
        let payload_type = codec.payload_type();

        // Bind UDP socket
        let bind_addr = format!("0.0.0.0:{}", config.local_port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| AudioError::StreamError(format!("Failed to bind socket: {e}")))?;

        let local_port = socket
            .local_addr()
            .map_err(|e| AudioError::StreamError(format!("Failed to get local address: {e}")))?
            .port();

        debug!("Bound RTP socket to port {}", local_port);

        let socket = Arc::new(socket);

        // Create transmitter
        let ssrc = generate_ssrc();
        let mut transmitter = RtpTransmitter::new(
            socket.clone(),
            config.remote_addr,
            ssrc,
            payload_type,
            samples_per_frame,
        );

        // Create receiver
        let mut receiver = RtpReceiver::new(
            socket.clone(),
            clock_rate,
            samples_per_frame,
            config.jitter_buffer_ms,
        );

        // Set up SRTP if keys are provided
        if let (Some(key), Some(salt)) = (&config.srtp_master_key, &config.srtp_master_salt) {
            // Create key material
            let key_material =
                SrtpKeyMaterial::new(SrtpProfile::AeadAes256Gcm, key.clone(), salt.clone())
                    .map_err(|e| {
                        AudioError::SrtpError(format!("Failed to create SRTP key material: {e}"))
                    })?;

            // Create outbound context for transmitter
            let tx_context = SrtpContext::new(&key_material, SrtpDirection::Outbound, ssrc)
                .map_err(|e| {
                    AudioError::SrtpError(format!("Failed to create TX SRTP context: {e}"))
                })?;
            transmitter.set_srtp(Arc::new(Mutex::new(tx_context)));

            // Create inbound context for receiver (SSRC will be learned from first packet)
            let rx_context =
                SrtpContext::new(&key_material, SrtpDirection::Inbound, 0).map_err(|e| {
                    AudioError::SrtpError(format!("Failed to create RX SRTP context: {e}"))
                })?;
            receiver.set_srtp(Arc::new(Mutex::new(rx_context)));

            debug!("SRTP enabled for audio pipeline");
        }

        // Start capture stream
        let capture = CaptureStream::new(&self.device_manager)?;

        // Start playback stream
        let playback = PlaybackStream::new(&self.device_manager)?;

        // Load MOH if configured
        let moh_source = if let Some(ref moh_path) = config.moh_file_path {
            let mut source = FileAudioSource::new(clock_rate);
            match source.load(moh_path) {
                Ok(()) => {
                    info!("MOH loaded: {:.2}s", source.duration_secs());
                    Some(source)
                }
                Err(e) => {
                    warn!("Failed to load MOH file: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Store components
        self.codec = Some(codec);
        self.transmitter = Some(transmitter);
        self.receiver = Some(receiver);
        self.socket = Some(socket);
        self.capture = Some(capture);
        self.playback = Some(playback);
        self.moh_source = moh_source;
        self.moh_active.store(false, Ordering::Relaxed);
        self.config = config;
        self.muted.store(self.config.muted, Ordering::Relaxed);
        self.running.store(true, Ordering::Relaxed);

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
        self.running.store(false, Ordering::Relaxed);

        // Stop capture
        if let Some(ref capture) = self.capture {
            capture.stop();
        }

        // Stop playback
        if let Some(ref playback) = self.playback {
            playback.stop();
        }

        // Clear components
        self.capture = None;
        self.playback = None;
        self.transmitter = None;
        self.receiver = None;
        self.socket = None;
        self.codec = None;

        self.state = PipelineState::Stopped;
        info!("Audio pipeline stopped");
    }

    /// Processes one frame of audio (capture -> encode -> send).
    ///
    /// This should be called at regular intervals (e.g., every 20ms for G.711).
    pub async fn process_capture_frame(&mut self) -> AudioResult<()> {
        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Pipeline not started".to_string()))?;

        let capture = self
            .capture
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Capture stream not available".to_string()))?;

        let transmitter = self
            .transmitter
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Transmitter not available".to_string()))?;

        // Read captured samples
        let samples_needed = codec.samples_per_frame();
        let mut pcm = vec![0i16; samples_needed];
        let samples_read = capture.read(&mut pcm);

        if samples_read < samples_needed {
            // Not enough samples - pad with silence
            trace!(
                "Capture underrun: got {} samples, needed {}",
                samples_read, samples_needed
            );
            if let Ok(mut stats) = self.stats.lock() {
                stats.capture_underruns += 1;
            }
            pcm[samples_read..].fill(0);
        }

        // Skip encoding/sending if muted
        if self.muted.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Encode
        let encoded = codec.encode(&pcm)?;

        // Send
        transmitter.send(encoded).await?;

        Ok(())
    }

    /// Processes received packets and outputs to playback.
    pub fn process_playback_frame(&mut self) -> AudioResult<()> {
        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Pipeline not started".to_string()))?;

        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Receiver not available".to_string()))?;

        let playback = self
            .playback
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Playback stream not available".to_string()))?;

        // Get packet from jitter buffer
        match receiver.get_packet() {
            JitterBufferResult::Packet(packet) => {
                // Decode and play
                let pcm = codec.decode(&packet.payload)?;
                playback.write(pcm);
            }
            JitterBufferResult::Lost { .. } => {
                // Generate PLC
                let samples = codec.samples_per_frame();
                let mut plc = vec![0i16; samples];
                codec.generate_plc(&mut plc);
                playback.write(&plc);

                if let Ok(mut stats) = self.stats.lock() {
                    stats.playback_underruns += 1;
                }
            }
            JitterBufferResult::Empty | JitterBufferResult::NotReady => {
                // No audio to play - output silence
                let samples = codec.samples_per_frame();
                let silence = vec![0i16; samples];
                playback.write(&silence);
            }
        }

        Ok(())
    }

    /// Receives any pending RTP packets.
    pub async fn receive_packets(&mut self) -> AudioResult<()> {
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Receiver not available".to_string()))?;

        // Receive all available packets
        loop {
            match receiver.receive().await {
                Ok(true) => continue, // Got a packet, try for more
                Ok(false) => break,   // No more packets
                Err(e) => {
                    warn!("RTP receive error: {}", e);
                    break;
                }
            }
        }

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
    ///
    /// When MOH is active, `process_moh_frame` will send MOH audio instead of
    /// using the microphone capture.
    pub fn set_moh_active(&self, active: bool) {
        self.moh_active.store(active, Ordering::Relaxed);
        debug!("MOH active: {}", active);
    }

    /// Returns whether Music on Hold is currently active.
    pub fn is_moh_active(&self) -> bool {
        self.moh_active.load(Ordering::Relaxed)
    }

    /// Returns whether MOH audio has been loaded.
    pub fn has_moh(&self) -> bool {
        self.moh_source.as_ref().is_some_and(|s| s.is_loaded())
    }

    /// Processes one frame of MOH audio (read file -> encode -> send).
    ///
    /// This should be called instead of `process_capture_frame` when the call
    /// is on hold and we want to send MOH to the remote party.
    pub async fn process_moh_frame(&mut self) -> AudioResult<()> {
        let moh_source = match self.moh_source.as_mut() {
            Some(source) if source.is_loaded() => source,
            _ => return Ok(()), // No MOH configured, do nothing
        };

        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Pipeline not started".to_string()))?;

        let transmitter = self
            .transmitter
            .as_mut()
            .ok_or_else(|| AudioError::ConfigError("Transmitter not available".to_string()))?;

        // Read samples from MOH file
        let samples_needed = codec.samples_per_frame();
        let mut pcm = vec![0i16; samples_needed];
        moh_source.read(&mut pcm);

        // Encode
        let encoded = codec.encode(&pcm)?;

        // Send
        transmitter.send(encoded).await?;

        Ok(())
    }

    /// Returns the current pipeline state.
    pub fn state(&self) -> PipelineState {
        self.state
    }

    /// Returns whether the pipeline is running.
    pub fn is_running(&self) -> bool {
        self.state == PipelineState::Running
    }

    /// Returns the pipeline statistics.
    pub fn stats(&self) -> PipelineStats {
        let mut stats = self.stats.lock().map(|s| s.clone()).unwrap_or_default();

        // Update from transmitter
        if let Some(ref tx) = self.transmitter {
            stats.tx_stats = tx.stats();
        }

        // Update from receiver
        if let Some(ref rx) = self.receiver {
            stats.rx_stats = rx.stats();
            stats.jitter_stats = rx.jitter_buffer_stats();
        }

        stats
    }

    /// Returns the local RTP port.
    pub fn local_port(&self) -> Option<u16> {
        self.socket
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
    }

    /// Returns the SSRC being used for transmission.
    pub fn ssrc(&self) -> Option<u32> {
        self.transmitter.as_ref().map(|tx| tx.ssrc())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert_eq!(config.codec, CodecPreference::G711Ulaw);
        assert_eq!(config.jitter_buffer_ms, 60);
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
    }
}
