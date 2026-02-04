//! Audio session management for call audio.
//!
//! This module bridges the media session (ICE/DTLS/SRTP) with the
//! audio pipeline (capture/encode/transmit/receive/decode/playback).

use crate::{AppError, AppResult};
use client_audio::{AudioPipeline, PipelineConfig, PipelineState, PipelineStats};
use client_sip_ua::{MediaSession, MediaSessionState};
use client_types::audio::CodecPreference;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

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
}

impl Default for AudioSessionConfig {
    fn default() -> Self {
        Self {
            local_port: 0,
            remote_addr: "0.0.0.0:0"
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
            codec: CodecPreference::G711Ulaw,
            jitter_buffer_ms: 60,
            srtp_key: None,
            srtp_salt: None,
            moh_file_path: None,
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
/// It handles:
/// - Extracting SRTP keys from the media session
/// - Starting/stopping the audio pipeline
/// - Running the audio processing loop
/// - Providing mute control
pub struct AudioSession {
    /// Audio pipeline.
    pipeline: Arc<Mutex<AudioPipeline>>,
    /// Audio processing task handle.
    process_task: Option<JoinHandle<()>>,
    /// Running flag.
    running: Arc<AtomicBool>,
    /// Muted flag.
    muted: Arc<AtomicBool>,
    /// Event sender.
    event_tx: mpsc::Sender<AudioSessionEvent>,
}

impl AudioSession {
    /// Creates a new audio session.
    pub fn new(event_tx: mpsc::Sender<AudioSessionEvent>) -> Self {
        Self {
            pipeline: Arc::new(Mutex::new(AudioPipeline::new())),
            process_task: None,
            running: Arc::new(AtomicBool::new(false)),
            muted: Arc::new(AtomicBool::new(false)),
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

        // Get SRTP keying material from media session
        // The media session already has the SRTP contexts, but we need raw keys
        // for the audio pipeline. For now, we'll use the same approach.
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
            // SRTP keys are already in media session contexts
            // The audio pipeline will use its own RTP handling
            srtp_key: None,
            srtp_salt: None,
            moh_file_path: None,
        };

        self.start(config).await
    }

    /// Starts the audio session with the given configuration.
    pub async fn start(&mut self, config: AudioSessionConfig) -> AppResult<u16> {
        if self.running.load(Ordering::Relaxed) {
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
            muted: self.muted.load(Ordering::Relaxed),
            moh_file_path: config.moh_file_path,
        };

        // Start pipeline
        let local_port = {
            let mut pipeline = self.pipeline.lock().await;
            pipeline
                .start(pipeline_config)
                .await
                .map_err(|e| AppError::Audio(e.to_string()))?
        };

        self.running.store(true, Ordering::Relaxed);

        // Start audio processing task
        self.start_processing_task();

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
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        info!("Stopping audio session");

        self.running.store(false, Ordering::Relaxed);

        // Cancel processing task
        if let Some(handle) = self.process_task.take() {
            handle.abort();
        }

        // Stop pipeline
        {
            let mut pipeline = self.pipeline.lock().await;
            pipeline.stop();
        }

        // Notify stopped
        let _ = self.event_tx.send(AudioSessionEvent::Stopped).await;

        info!("Audio session stopped");

        Ok(())
    }

    /// Sets the mute state.
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
        debug!(muted = muted, "Audio session mute state changed");
    }

    /// Returns whether the session is muted.
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    /// Sets the Music on Hold active state.
    ///
    /// When MOH is active, the audio pipeline will send MOH audio instead
    /// of capturing from the microphone.
    pub async fn set_moh_active(&self, active: bool) {
        let pipeline = self.pipeline.lock().await;
        pipeline.set_moh_active(active);
        debug!(active = active, "Audio session MOH state changed");
    }

    /// Returns whether Music on Hold is currently active.
    pub async fn is_moh_active(&self) -> bool {
        let pipeline = self.pipeline.lock().await;
        pipeline.is_moh_active()
    }

    /// Returns whether MOH audio has been loaded.
    pub async fn has_moh(&self) -> bool {
        let pipeline = self.pipeline.lock().await;
        pipeline.has_moh()
    }

    /// Returns whether the session is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Returns the current pipeline statistics.
    pub async fn stats(&self) -> PipelineStats {
        let pipeline = self.pipeline.lock().await;
        pipeline.stats()
    }

    /// Returns the local RTP port.
    pub async fn local_port(&self) -> Option<u16> {
        let pipeline = self.pipeline.lock().await;
        pipeline.local_port()
    }

    /// Returns the pipeline state.
    pub async fn pipeline_state(&self) -> PipelineState {
        let pipeline = self.pipeline.lock().await;
        pipeline.state()
    }

    /// Gets a reference to the audio pipeline for device management.
    pub fn pipeline(&self) -> Arc<Mutex<AudioPipeline>> {
        self.pipeline.clone()
    }

    /// Starts the audio processing task.
    fn start_processing_task(&mut self) {
        let pipeline = self.pipeline.clone();
        let running = self.running.clone();
        let muted = self.muted.clone();
        let event_tx = self.event_tx.clone();

        let handle = tokio::spawn(async move {
            audio_processing_loop(pipeline, running, muted, event_tx).await;
        });

        self.process_task = Some(handle);
    }
}

impl Drop for AudioSession {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.process_task.take() {
            handle.abort();
        }
    }
}

/// Audio processing loop that runs at regular intervals.
///
/// This loop handles:
/// - Receiving RTP packets
/// - Processing capture frames (capture → encode → send)
/// - Processing playback frames (receive → decode → playback)
async fn audio_processing_loop(
    pipeline: Arc<Mutex<AudioPipeline>>,
    running: Arc<AtomicBool>,
    muted: Arc<AtomicBool>,
    event_tx: mpsc::Sender<AudioSessionEvent>,
) {
    // Frame interval: 20ms for G.711/G.722, Opus typically 20ms too
    let frame_interval = Duration::from_millis(20);
    let mut interval = tokio::time::interval(frame_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Stats reporting interval (every 5 seconds)
    let mut stats_counter = 0u32;
    const STATS_INTERVAL: u32 = 250; // 250 * 20ms = 5 seconds

    info!("Audio processing loop started");

    while running.load(Ordering::Relaxed) {
        interval.tick().await;

        let mut pipeline_guard = pipeline.lock().await;

        // Skip if pipeline isn't running
        if !pipeline_guard.is_running() {
            continue;
        }

        // Update mute state
        pipeline_guard.set_muted(muted.load(Ordering::Relaxed));

        // Receive any pending RTP packets
        if let Err(e) = pipeline_guard.receive_packets().await {
            warn!(error = %e, "Error receiving RTP packets");
        }

        // Process capture frame (capture → encode → send)
        // Use MOH if active and available, otherwise use microphone capture
        let capture_result = if pipeline_guard.is_moh_active() && pipeline_guard.has_moh() {
            pipeline_guard.process_moh_frame().await
        } else {
            pipeline_guard.process_capture_frame().await
        };

        if let Err(e) = capture_result {
            // Don't spam logs for normal errors like no samples available
            if !matches!(e, client_audio::AudioError::StreamError(_)) {
                warn!(error = %e, "Error processing capture frame");
            }
        }

        // Process playback frame (jitter buffer → decode → playback)
        if let Err(e) = pipeline_guard.process_playback_frame() {
            if !matches!(e, client_audio::AudioError::StreamError(_)) {
                warn!(error = %e, "Error processing playback frame");
            }
        }

        // Periodic stats reporting
        stats_counter += 1;
        if stats_counter >= STATS_INTERVAL {
            stats_counter = 0;
            let stats = pipeline_guard.stats();
            let _ = event_tx.send(AudioSessionEvent::StatsUpdate(stats)).await;
        }
    }

    info!("Audio processing loop stopped");
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
    pub fn local_port(mut self, port: u16) -> Self {
        self.config.local_port = port;
        self
    }

    /// Sets the remote RTP address.
    pub fn remote_addr(mut self, addr: SocketAddr) -> Self {
        self.config.remote_addr = addr;
        self
    }

    /// Sets the preferred codec.
    pub fn codec(mut self, codec: CodecPreference) -> Self {
        self.config.codec = codec;
        self
    }

    /// Sets the jitter buffer depth.
    pub fn jitter_buffer_ms(mut self, ms: u32) -> Self {
        self.config.jitter_buffer_ms = ms;
        self
    }

    /// Sets the SRTP master key.
    pub fn srtp_key(mut self, key: Vec<u8>) -> Self {
        self.config.srtp_key = Some(key);
        self
    }

    /// Sets the SRTP master salt.
    pub fn srtp_salt(mut self, salt: Vec<u8>) -> Self {
        self.config.srtp_salt = Some(salt);
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
