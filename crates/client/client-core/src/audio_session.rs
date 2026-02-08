//! Audio session management for call audio.
//!
//! This module bridges the media session (ICE/DTLS/SRTP) with the
//! audio pipeline (capture/encode/transmit/receive/decode/playback).
//!
//! The audio pipeline manages its own I/O and decode threads internally.
//! `AudioSession` is a thin wrapper providing start/stop lifecycle,
//! mute/MOH control, and event notifications.

use crate::{AppError, AppResult};
use client_audio::{AudioPipeline, PipelineConfig, PipelineState, PipelineStats};
use client_sip_ua::{MediaSession, MediaSessionState};
use client_types::DtmfDigit;
use client_types::audio::CodecPreference;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Configuration for an audio session.
#[derive(Debug, Clone)]
pub struct AudioSessionConfig {
    /// Local RTP port (0 for auto-assign).
    pub local_port: u16,
    /// Remote RTP address.
    pub remote_addr: SocketAddr,
    /// Preferred codec.
    pub codec: CodecPreference,
    /// Jitter buffer depth in milliseconds.
    pub jitter_buffer_ms: u32,
    /// SRTP master key.
    pub srtp_key: Option<Vec<u8>>,
    /// SRTP master salt.
    pub srtp_salt: Option<Vec<u8>>,
    /// Music on Hold file path (optional).
    pub moh_file_path: Option<String>,
    /// DTMF telephone-event payload type from SDP (`None` = use default 101).
    pub dtmf_payload_type: Option<u8>,
    /// DTMF volume level for RFC 4733 packets (0-63, default 10).
    pub dtmf_volume: u8,
    /// Inter-digit pause in milliseconds (default 100).
    pub dtmf_inter_digit_pause_ms: u32,
}

impl Default for AudioSessionConfig {
    fn default() -> Self {
        Self {
            local_port: 0,
            remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            codec: CodecPreference::G711Ulaw,
            jitter_buffer_ms: 60,
            srtp_key: None,
            srtp_salt: None,
            moh_file_path: None,
            dtmf_payload_type: None,
            dtmf_volume: 10,
            dtmf_inter_digit_pause_ms: 100,
        }
    }
}

/// Events emitted by the audio session.
#[derive(Debug, Clone)]
pub enum AudioSessionEvent {
    /// Audio session started.
    Started {
        /// Local RTP port.
        local_port: u16,
    },
    /// Audio session stopped.
    Stopped,
    /// Audio statistics update.
    StatsUpdate(PipelineStats),
    /// Error occurred.
    Error(String),
}

/// Audio session coordinates the audio pipeline with a media session.
///
/// The pipeline manages its own I/O and decode threads internally.
/// `AudioSession` is a thin wrapper that provides start/stop lifecycle
/// and mute/MOH control via atomic flags.
pub struct AudioSession {
    /// Audio pipeline (owned directly — no mutex needed).
    pipeline: AudioPipeline,
    /// Event sender.
    event_tx: mpsc::Sender<AudioSessionEvent>,
}

impl AudioSession {
    /// Creates a new audio session.
    pub fn new(event_tx: mpsc::Sender<AudioSessionEvent>) -> Self {
        Self {
            pipeline: AudioPipeline::new(),
            event_tx,
        }
    }

    /// Starts the audio session from media session SRTP keys.
    ///
    /// This extracts the SRTP keys from the established media session
    /// and configures the audio pipeline.
    pub async fn start_from_media_session(
        &mut self,
        media_session: &MediaSession,
        remote_addr: SocketAddr,
        codec: CodecPreference,
    ) -> AppResult<u16> {
        if media_session.state() != MediaSessionState::Active {
            return Err(AppError::Audio("Media session not active".to_string()));
        }

        info!(
            remote = %remote_addr,
            codec = ?codec,
            "Starting audio session from media session"
        );

        let config = AudioSessionConfig {
            local_port: 0,
            remote_addr,
            codec,
            jitter_buffer_ms: 60,
            srtp_key: None,
            srtp_salt: None,
            moh_file_path: None,
            dtmf_payload_type: None,
            dtmf_volume: 10,
            dtmf_inter_digit_pause_ms: 100,
        };

        self.start(config).await
    }

    /// Starts the audio session with the given configuration.
    pub async fn start(&mut self, config: AudioSessionConfig) -> AppResult<u16> {
        if self.pipeline.is_running() {
            return Err(AppError::Audio("Audio session already running".to_string()));
        }

        info!(
            remote = %config.remote_addr,
            codec = ?config.codec,
            "Starting audio session"
        );

        // Configure pipeline
        let pipeline_config = PipelineConfig {
            codec: config.codec,
            local_port: config.local_port,
            remote_addr: config.remote_addr,
            jitter_buffer_ms: config.jitter_buffer_ms,
            srtp_master_key: config.srtp_key,
            srtp_master_salt: config.srtp_salt,
            muted: self.pipeline.is_muted(),
            moh_file_path: config.moh_file_path,
            dtmf_payload_type: config.dtmf_payload_type,
            dtmf_volume: config.dtmf_volume,
            dtmf_inter_digit_pause_ms: config.dtmf_inter_digit_pause_ms,
        };

        // Start pipeline (sync — pipeline spawns its own threads)
        let local_port = self
            .pipeline
            .start(pipeline_config)
            .map_err(|e| AppError::Audio(e.to_string()))?;

        // Notify started
        let _ = self
            .event_tx
            .send(AudioSessionEvent::Started { local_port })
            .await;

        info!(local_port = local_port, "Audio session started");

        Ok(local_port)
    }

    /// Stops the audio session.
    pub async fn stop(&mut self) -> AppResult<()> {
        if !self.pipeline.is_running() {
            return Ok(());
        }

        info!("Stopping audio session");

        // Stop pipeline (sync — pipeline joins its threads)
        self.pipeline.stop();

        // Notify stopped
        let _ = self.event_tx.send(AudioSessionEvent::Stopped).await;

        info!("Audio session stopped");

        Ok(())
    }

    /// Sets the mute state.
    pub fn set_muted(&self, muted: bool) {
        self.pipeline.set_muted(muted);
        debug!(muted = muted, "Audio session mute state changed");
    }

    /// Returns whether the session is muted.
    pub fn is_muted(&self) -> bool {
        self.pipeline.is_muted()
    }

    /// Sets the Music on Hold active state.
    ///
    /// When MOH is active, the audio pipeline will send MOH audio instead
    /// of capturing from the microphone.
    pub fn set_moh_active(&self, active: bool) {
        self.pipeline.set_moh_active(active);
        debug!(active = active, "Audio session MOH state changed");
    }

    /// Returns whether Music on Hold is currently active.
    pub fn is_moh_active(&self) -> bool {
        self.pipeline.is_moh_active()
    }

    /// Returns whether MOH audio has been loaded.
    pub const fn has_moh(&self) -> bool {
        self.pipeline.has_moh()
    }

    /// Sends a DTMF digit via RFC 2833 telephone-event and/or in-band tones.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to send (0-9, *, #, A-D)
    /// * `duration_ms` - Duration of the tone in milliseconds (typical: 100ms)
    /// * `use_rfc2833` - Whether to send RFC 2833 packets (if false, in-band only)
    pub fn send_dtmf(
        &self,
        digit: DtmfDigit,
        duration_ms: u32,
        use_rfc2833: bool,
    ) -> AppResult<()> {
        if !self.pipeline.is_running() {
            return Err(AppError::Audio("Audio session not running".to_string()));
        }

        self.pipeline
            .send_dtmf(digit, duration_ms, use_rfc2833)
            .map_err(|e| AppError::Audio(e.to_string()))
    }

    /// Returns whether the session is running.
    pub fn is_running(&self) -> bool {
        self.pipeline.is_running()
    }

    /// Returns the current pipeline statistics.
    pub fn stats(&self) -> PipelineStats {
        self.pipeline.stats()
    }

    /// Returns the local RTP port.
    pub const fn local_port(&self) -> Option<u16> {
        self.pipeline.local_port()
    }

    /// Returns the pipeline state.
    pub const fn pipeline_state(&self) -> PipelineState {
        self.pipeline.state()
    }

    /// Switches the input (microphone) device during an active call.
    ///
    /// # Arguments
    /// * `device_name` - Name of the new input device, or None for default
    pub fn switch_input_device(&mut self, device_name: Option<String>) -> AppResult<()> {
        self.pipeline
            .switch_input_device(device_name)
            .map_err(|e| AppError::Audio(e.to_string()))
    }

    /// Switches the output (speaker) device during an active call.
    ///
    /// # Arguments
    /// * `device_name` - Name of the new output device, or None for default
    pub fn switch_output_device(&mut self, device_name: Option<String>) -> AppResult<()> {
        self.pipeline
            .switch_output_device(device_name)
            .map_err(|e| AppError::Audio(e.to_string()))
    }

    /// Returns the current input device name.
    pub fn input_device_name(&self) -> Option<&str> {
        self.pipeline.input_device_name()
    }

    /// Returns the current output device name.
    pub fn output_device_name(&self) -> Option<&str> {
        self.pipeline.output_device_name()
    }
}

impl Drop for AudioSession {
    fn drop(&mut self) {
        self.pipeline.stop();
    }
}

/// Builder for audio session configuration.
pub struct AudioSessionConfigBuilder {
    config: AudioSessionConfig,
}

impl AudioSessionConfigBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: AudioSessionConfig::default(),
        }
    }

    /// Sets the local RTP port.
    #[must_use]
    pub const fn local_port(mut self, port: u16) -> Self {
        self.config.local_port = port;
        self
    }

    /// Sets the remote RTP address.
    #[must_use]
    pub const fn remote_addr(mut self, addr: SocketAddr) -> Self {
        self.config.remote_addr = addr;
        self
    }

    /// Sets the preferred codec.
    #[must_use]
    pub const fn codec(mut self, codec: CodecPreference) -> Self {
        self.config.codec = codec;
        self
    }

    /// Sets the jitter buffer depth.
    #[must_use]
    pub const fn jitter_buffer_ms(mut self, ms: u32) -> Self {
        self.config.jitter_buffer_ms = ms;
        self
    }

    /// Sets the SRTP master key.
    #[must_use]
    pub fn srtp_key(mut self, key: Vec<u8>) -> Self {
        self.config.srtp_key = Some(key);
        self
    }

    /// Sets the SRTP master salt.
    #[must_use]
    pub fn srtp_salt(mut self, salt: Vec<u8>) -> Self {
        self.config.srtp_salt = Some(salt);
        self
    }

    /// Sets the Music on Hold file path.
    #[must_use]
    pub fn moh_file(mut self, path: String) -> Self {
        self.config.moh_file_path = Some(path);
        self
    }

    /// Sets the DTMF telephone-event payload type.
    #[must_use]
    pub const fn dtmf_payload_type(mut self, pt: u8) -> Self {
        self.config.dtmf_payload_type = Some(pt);
        self
    }

    /// Sets the effective media addresses.
    #[must_use]
    pub fn effective_media_addrs(self, _addrs: Vec<SocketAddr>) -> Self {
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> AudioSessionConfig {
        self.config
    }
}

impl Default for AudioSessionConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audio_session_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let session = AudioSession::new(tx);

        assert!(!session.is_running());
        assert!(!session.is_muted());
    }

    #[tokio::test]
    async fn test_audio_session_mute() {
        let (tx, _rx) = mpsc::channel(10);
        let session = AudioSession::new(tx);

        assert!(!session.is_muted());
        session.set_muted(true);
        assert!(session.is_muted());
        session.set_muted(false);
        assert!(!session.is_muted());
    }

    #[test]
    fn test_audio_session_config_default() {
        let config = AudioSessionConfig::default();
        assert_eq!(config.local_port, 0);
        assert_eq!(config.jitter_buffer_ms, 60);
        assert_eq!(config.codec, CodecPreference::G711Ulaw);
    }

    #[test]
    fn test_audio_session_config_builder() {
        let remote: SocketAddr = "192.168.1.100:16000".parse().unwrap();

        let config = AudioSessionConfigBuilder::new()
            .local_port(16384)
            .remote_addr(remote)
            .codec(CodecPreference::Opus)
            .jitter_buffer_ms(80)
            .srtp_key(vec![0x42; 32])
            .srtp_salt(vec![0x24; 12])
            .build();

        assert_eq!(config.local_port, 16384);
        assert_eq!(config.remote_addr, remote);
        assert_eq!(config.codec, CodecPreference::Opus);
        assert_eq!(config.jitter_buffer_ms, 80);
        assert!(config.srtp_key.is_some());
        assert!(config.srtp_salt.is_some());
    }
}
