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

use crate::codec::CodecPipeline;
use crate::decode_thread::{self, DecodeThreadConfig, DecodeThreadHandle};
use crate::device::DeviceManager;
use crate::file_source::FileAudioSource;
use crate::io_thread::{self, IoThreadConfig, IoThreadHandle};
use crate::jitter_buffer::SharedJitterBuffer;
use crate::rtp_handler::{RtpReceiver, RtpStats, RtpTransmitter, generate_ssrc};
use crate::stream::{PlaybackStream, PlaybackStreamHandle};
use crate::{AudioError, AudioResult};
use client_types::audio::CodecPreference;
use client_types::DtmfDigit;
use proto_srtp::{SrtpContext, SrtpDirection, SrtpKeyMaterial, SrtpProfile};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Handle to the CPAL playback stream (keeps it alive).
    playback_handle: Option<PlaybackStreamHandle>,
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
    /// Local RTP port (set after start).
    local_port: Option<u16>,
    /// SSRC being used for transmission.
    ssrc: Option<u32>,
}

impl AudioPipeline {
    /// Creates a new audio pipeline.
    pub fn new() -> Self {
        Self {
            device_manager: DeviceManager::new(),
            state: PipelineState::Stopped,
            decode_thread: None,
            io_thread: None,
            playback_handle: None,
            muted: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(PipelineStats::default())),
            moh_active: Arc::new(AtomicBool::new(false)),
            has_moh_audio: false,
            local_port: None,
            ssrc: None,
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
    ///
    /// Creates the UDP socket, CPAL streams, jitter buffer, and spawns
    /// the I/O and decode threads. Returns the local RTP port.
    pub fn start(&mut self, config: PipelineConfig) -> AudioResult<u16> {
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
        let samples_per_frame = temp_codec.samples_per_frame() as u32;
        let payload_type = temp_codec.payload_type();
        drop(temp_codec);

        // Bind std::net::UdpSocket (blocking)
        let bind_addr = format!("0.0.0.0:{}", config.local_port);
        let socket = UdpSocket::bind(&bind_addr)
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
        let jitter_buffer =
            SharedJitterBuffer::new(clock_rate, samples_per_frame, config.jitter_buffer_ms);

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
        let mut receiver = RtpReceiver::new(socket, jitter_buffer.clone());

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
            transmitter.set_srtp(Arc::new(Mutex::new(tx_context)));

            let rx_context =
                SrtpContext::new(&key_material, SrtpDirection::Inbound, 0).map_err(|e| {
                    AudioError::SrtpError(format!("Failed to create RX SRTP context: {e}"))
                })?;
            receiver.set_srtp(Arc::new(Mutex::new(rx_context)));

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
        let (playback_handle, mut producer) = playback.take_producer();

        // Pre-fill the playback ring buffer with silence so the CPAL callback
        // has a cushion from the first callback.
        let prefill_ms = 100;
        let prefill_samples = (device_rate * prefill_ms / 1000) as usize;
        let silence = vec![0i16; prefill_samples];
        use ringbuf::traits::Producer;
        producer.push_slice(&silence);
        debug!(
            "Pre-filled playback buffer with {}ms of silence",
            prefill_ms
        );

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
        let has_moh = moh_source.is_some();

        // Set running flag
        self.muted.store(config.muted, Ordering::Relaxed);
        self.moh_active.store(false, Ordering::Relaxed);
        self.running.store(true, Ordering::Relaxed);

        // Spawn decode thread
        let decode_config = DecodeThreadConfig {
            codec: config.codec,
            device_rate,
        };
        let decode_handle = decode_thread::spawn(
            decode_config,
            producer,
            jitter_buffer,
            self.running.clone(),
        );

        // Spawn I/O thread (uses capture rate for mic read sizing)
        let io_config = IoThreadConfig {
            codec: config.codec,
            capture_rate,
        };
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
        );

        // Store handles
        self.decode_thread = Some(decode_handle);
        self.io_thread = Some(io_handle);
        self.playback_handle = Some(playback_handle);
        self.has_moh_audio = has_moh;
        self.local_port = Some(local_port);
        self.ssrc = Some(ssrc);

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

        // Stop CPAL playback stream
        if let Some(ref handle) = self.playback_handle {
            handle.stop();
        }
        self.playback_handle = None;

        self.has_moh_audio = false;
        self.local_port = None;
        self.ssrc = None;

        self.state = PipelineState::Stopped;
        info!("Audio pipeline stopped");
    }

    /// Sends a DTMF digit using RFC 4733 telephone-event.
    ///
    /// The command is sent to the I/O thread via a channel; the actual
    /// packet sequence is generated there.
    pub fn send_dtmf(&self, digit: DtmfDigit, duration_ms: u32) -> AudioResult<()> {
        let io = self
            .io_thread
            .as_ref()
            .ok_or_else(|| AudioError::ConfigError("Pipeline not running".to_string()))?;

        io.send_dtmf(digit, duration_ms);
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

    /// Returns whether Music on Hold is currently active.
    pub fn is_moh_active(&self) -> bool {
        self.moh_active.load(Ordering::Relaxed)
    }

    /// Returns whether MOH audio has been loaded.
    pub fn has_moh(&self) -> bool {
        self.has_moh_audio
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
        self.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Returns the local RTP port.
    pub fn local_port(&self) -> Option<u16> {
        self.local_port
    }

    /// Returns the SSRC being used for transmission.
    pub fn ssrc(&self) -> Option<u32> {
        self.ssrc
    }

    /// Switches the input (microphone) device.
    ///
    /// Updates the device manager selection. Takes effect on next pipeline start.
    pub fn switch_input_device(&mut self, device_name: Option<String>) -> AudioResult<()> {
        info!("Setting input device to: {:?}", device_name);
        self.device_manager.set_input_device(device_name);
        Ok(())
    }

    /// Switches the output (speaker) device.
    ///
    /// Updates the device manager selection. Takes effect on next pipeline start.
    pub fn switch_output_device(&mut self, device_name: Option<String>) -> AudioResult<()> {
        info!("Setting output device to: {:?}", device_name);
        self.device_manager.set_output_device(device_name);
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
/// For VoIP (G.711 at 8kHz ↔ device at 48kHz), the codec already band-limits
/// to 4kHz, so linear interpolation is clean for upsampling and simple
/// averaging-decimation works for downsampling.
///
/// The `prev_sample` parameter provides the last input sample from the previous
/// frame, enabling smooth interpolation across frame boundaries. Without this,
/// upsampling creates a step discontinuity every 20ms (50 Hz artifact) because
/// the last few output samples hold the final input value flat, then the next
/// frame jumps to its first sample.
pub(crate) fn resample(input: &[i16], output_len: usize, prev_sample: i16) -> Vec<i16> {
    if input.len() == output_len {
        return input.to_vec();
    }

    let in_len = input.len();

    // Fast path: integer ratio upsampling (common case: 6:1 for 8kHz→48kHz)
    if output_len > in_len && output_len % in_len == 0 {
        let ratio = output_len / in_len;
        let mut output = Vec::with_capacity(output_len);
        for i in 0..in_len {
            // Interpolate from previous sample toward current sample.
            // At i=0, use prev_sample from the previous frame for continuity.
            let s0 = if i == 0 { prev_sample as i32 } else { input[i - 1] as i32 };
            let s1 = input[i] as i32;
            for j in 0..ratio {
                // t ranges from 1/ratio to ratio/ratio (=1.0), so the last
                // output sample in each group exactly equals input[i].
                let t = (j + 1) as i32;
                let sample = s0 + (s1 - s0) * t / ratio as i32;
                output.push(sample as i16);
            }
        }
        return output;
    }

    // Fast path: integer ratio downsampling (common case: 6:1 for 48kHz→8kHz)
    if in_len > output_len && in_len % output_len == 0 {
        let ratio = in_len / output_len;
        let mut output = Vec::with_capacity(output_len);
        for i in 0..output_len {
            let start = i * ratio;
            let sum: i32 = input[start..start + ratio].iter().map(|&s| s as i32).sum();
            output.push((sum / ratio as i32) as i16);
        }
        return output;
    }

    // General case: Catmull-Rom cubic interpolation for non-integer ratios.
    // Uses 4 input points per output sample for smooth curves, eliminating
    // the imaging artifacts of linear interpolation on large upsampling
    // ratios (e.g., 160→882 for 8kHz→44.1kHz, 5.5x).
    let mut output = Vec::with_capacity(output_len);
    let step = in_len as f64 / output_len as f64;

    // Helper to fetch input sample with boundary clamping.
    // Index -1 maps to prev_sample for cross-frame continuity.
    let sample_at = |idx: i32| -> f64 {
        if idx < 0 {
            prev_sample as f64
        } else if (idx as usize) < in_len {
            input[idx as usize] as f64
        } else {
            input[in_len - 1] as f64
        }
    };

    for i in 0..output_len {
        let pos = i as f64 * step;
        let idx = pos.floor() as i32;
        let t = pos - idx as f64;

        // Four points for Catmull-Rom: p0, p1, p2, p3
        let p0 = sample_at(idx - 1);
        let p1 = sample_at(idx);
        let p2 = sample_at(idx + 1);
        let p3 = sample_at(idx + 2);

        // Catmull-Rom spline formula
        let t2 = t * t;
        let t3 = t2 * t;
        let sample = 0.5
            * ((2.0 * p1)
                + (-p0 + p2) * t
                + (2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3) * t2
                + (-p0 + 3.0 * p1 - 3.0 * p2 + p3) * t3);

        // Clamp to i16 range to prevent overflow from cubic overshoot
        output.push(sample.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16);
    }

    output
}

/// Fade out from `last_sample` to silence over the entire buffer for smooth PLC.
pub(crate) fn fade_out(buffer: &mut [i16], last_sample: i16) {
    let len = buffer.len();
    if len == 0 || last_sample == 0 {
        return;
    }
    for i in 0..len {
        let t = 1.0 - (i as f32 / len as f32);
        buffer[i] = (last_sample as f32 * t).round() as i16;
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
