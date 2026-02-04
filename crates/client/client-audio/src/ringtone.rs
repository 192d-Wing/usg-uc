//! Ringtone playback for incoming calls.
//!
//! This module provides a `RingtonePlayer` that can play WAV files
//! on a specified output device (ring device) when incoming calls arrive.

use crate::device::DeviceManager;
use crate::file_source::FileAudioSource;
use crate::{AudioError, AudioResult};
use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::{SampleFormat, Stream, StreamConfig};
use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer, Split};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info};

/// Default sample rate for ringtone playback.
const RINGTONE_SAMPLE_RATE: u32 = 48000;

/// Ring buffer size in samples (~500ms at 48kHz).
const RING_BUFFER_SIZE: usize = 48000;

/// Ringtone player for incoming call alerts.
///
/// Plays a WAV file in a loop on the configured ring device
/// until stopped. If no ringtone file is configured, generates
/// a simple sine wave tone.
pub struct RingtonePlayer {
    /// Audio source for the ringtone file.
    source: Option<FileAudioSource>,
    /// Volume level (0.0 - 1.0).
    volume: f32,
    /// Whether currently playing.
    is_playing: Arc<AtomicBool>,
    /// Whether to use default tone instead of file.
    use_default_tone: bool,
    /// Ring device name (None = default output).
    ring_device: Option<String>,
    /// The playback stream handle.
    stream: Option<Stream>,
    /// Producer for feeding audio to the stream.
    producer: Option<ringbuf::HeapProd<i16>>,
    /// Sample rate of the output device.
    sample_rate: u32,
}

impl RingtonePlayer {
    /// Creates a new ringtone player.
    pub fn new() -> Self {
        Self {
            source: None,
            volume: 1.0,
            is_playing: Arc::new(AtomicBool::new(false)),
            use_default_tone: true,
            ring_device: None,
            stream: None,
            producer: None,
            sample_rate: RINGTONE_SAMPLE_RATE,
        }
    }

    /// Sets the volume level (0.0 - 1.0).
    pub fn set_volume(&mut self, volume: f32) {
        self.volume = volume.clamp(0.0, 1.0);
    }

    /// Sets the ring device name.
    pub fn set_ring_device(&mut self, device: Option<String>) {
        self.ring_device = device;
    }

    /// Loads a ringtone from a WAV file.
    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> AudioResult<()> {
        let path = path.as_ref();
        info!(path = %path.display(), "Loading ringtone file");

        let mut source = FileAudioSource::new(RINGTONE_SAMPLE_RATE);
        source.load(path)?;

        self.source = Some(source);
        self.use_default_tone = false;

        info!("Ringtone loaded successfully");
        Ok(())
    }

    /// Clears the loaded ringtone and uses default tone.
    pub fn use_default(&mut self) {
        self.source = None;
        self.use_default_tone = true;
    }

    /// Returns whether a ringtone file is loaded.
    pub fn has_ringtone(&self) -> bool {
        self.source.as_ref().is_some_and(|s| s.is_loaded())
    }

    /// Starts playing the ringtone.
    pub fn start(&mut self) -> AudioResult<()> {
        if self.is_playing.load(Ordering::Relaxed) {
            debug!("Ringtone already playing");
            return Ok(());
        }

        info!("Starting ringtone playback");

        // Reset source position if using file
        if let Some(ref mut source) = self.source {
            source.reset();
        }

        // Get the output device
        let device_manager = DeviceManager::new();
        let device = if let Some(ref name) = self.ring_device {
            device_manager.get_output_device_by_name(name)?
        } else {
            device_manager.get_output_device()?
        };

        let config = device_manager.get_output_config(&device)?;
        self.sample_rate = config.sample_rate;

        // Create ring buffer
        let ring = HeapRb::<i16>::new(RING_BUFFER_SIZE);
        let (producer, consumer) = ring.split();

        // Build the output stream
        let is_playing = self.is_playing.clone();
        let stream = build_ringtone_stream(&device, &config, consumer, is_playing.clone())?;

        stream
            .play()
            .map_err(|e| AudioError::StreamError(format!("Failed to start ringtone stream: {e}")))?;

        self.stream = Some(stream);
        self.producer = Some(producer);
        self.is_playing.store(true, Ordering::Relaxed);

        // Pre-fill the buffer with initial audio
        self.prefill_buffer();

        debug!("Ringtone playback started");
        Ok(())
    }

    /// Pre-fills the audio buffer with initial data.
    fn prefill_buffer(&mut self) {
        let volume = self.volume;
        let sample_rate = self.sample_rate;
        let has_source = self.has_ringtone();

        if let Some(ref mut producer) = self.producer {
            // Pre-fill the buffer with ~100ms of audio
            let mut buffer = vec![0i16; 4800]; // 100ms at 48kHz

            if has_source {
                if let Some(ref mut source) = self.source {
                    source.read(&mut buffer);
                    // Apply volume
                    for sample in &mut buffer {
                        *sample = ((*sample as f32) * volume) as i16;
                    }
                }
            } else {
                // Generate default tone (440Hz + 480Hz)
                generate_ringtone_pattern(&mut buffer, sample_rate, volume);
            }

            let _ = producer.push_slice(&buffer);
        }
    }

    /// Processes a frame of ringtone audio.
    /// Call this periodically (e.g., every 20ms) while the ringtone is playing.
    pub fn process_frame(&mut self) {
        if !self.is_playing.load(Ordering::Relaxed) {
            return;
        }

        let producer = match self.producer.as_mut() {
            Some(p) => p,
            None => return,
        };

        // Check if we need more data
        if producer.vacant_len() < 960 {
            return; // Buffer is full enough
        }

        let mut buffer = vec![0i16; 960]; // 20ms at 48kHz

        if let Some(ref mut source) = self.source {
            source.read(&mut buffer);
            // Apply volume
            for sample in &mut buffer {
                *sample = ((*sample as f32) * self.volume) as i16;
            }
        } else {
            // Generate default tone
            generate_ringtone_pattern(&mut buffer, self.sample_rate, self.volume);
        }

        let _ = producer.push_slice(&buffer);
    }

    /// Stops the ringtone.
    pub fn stop(&mut self) {
        if !self.is_playing.load(Ordering::Relaxed) {
            return;
        }

        info!("Stopping ringtone playback");
        self.is_playing.store(false, Ordering::Relaxed);

        // Drop the stream to stop playback
        self.stream = None;
        self.producer = None;

        debug!("Ringtone stopped");
    }

    /// Returns whether the ringtone is currently playing.
    pub fn is_playing(&self) -> bool {
        self.is_playing.load(Ordering::Relaxed)
    }
}

impl Default for RingtonePlayer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RingtonePlayer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Builds the output stream for ringtone playback.
fn build_ringtone_stream(
    device: &cpal::Device,
    config: &StreamConfig,
    mut consumer: ringbuf::HeapCons<i16>,
    is_playing: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = config.channels as usize;

    // Get the sample format
    let supported_config = device
        .default_output_config()
        .map_err(|e| AudioError::StreamError(format!("Failed to get config: {e}")))?;

    match supported_config.sample_format() {
        SampleFormat::I16 => {
            let stream = device
                .build_output_stream(
                    config,
                    move |data: &mut [i16], _: &cpal::OutputCallbackInfo| {
                        if !is_playing.load(Ordering::Relaxed) {
                            data.fill(0);
                            return;
                        }

                        if channels == 1 {
                            let read = consumer.pop_slice(data);
                            data[read..].fill(0);
                        } else {
                            for chunk in data.chunks_mut(channels) {
                                if let Some(sample) = consumer.try_pop() {
                                    chunk.fill(sample);
                                } else {
                                    chunk.fill(0);
                                }
                            }
                        }
                    },
                    move |err| {
                        error!("Ringtone stream error: {}", err);
                    },
                    None,
                )
                .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;
            Ok(stream)
        }
        SampleFormat::F32 => {
            let stream = device
                .build_output_stream(
                    config,
                    move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                        if !is_playing.load(Ordering::Relaxed) {
                            data.fill(0.0);
                            return;
                        }

                        if channels == 1 {
                            for sample in data.iter_mut() {
                                *sample = consumer
                                    .try_pop()
                                    .map(|s| s as f32 / i16::MAX as f32)
                                    .unwrap_or(0.0);
                            }
                        } else {
                            for chunk in data.chunks_mut(channels) {
                                let sample = consumer
                                    .try_pop()
                                    .map(|s| s as f32 / i16::MAX as f32)
                                    .unwrap_or(0.0);
                                chunk.fill(sample);
                            }
                        }
                    },
                    move |err| {
                        error!("Ringtone stream error: {}", err);
                    },
                    None,
                )
                .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;
            Ok(stream)
        }
        format => Err(AudioError::StreamError(format!(
            "Unsupported sample format: {:?}",
            format
        ))),
    }
}

/// Generates a ringtone pattern (ring-pause-ring-pause).
///
/// Uses a two-tone pattern similar to standard phone rings:
/// - 440Hz + 480Hz combined for 2 seconds
/// - 4 seconds of silence
fn generate_ringtone_pattern(buffer: &mut [i16], sample_rate: u32, volume: f32) {
    // Simple approach: generate continuous tone for now
    // A more sophisticated version would track pattern state
    let freq1 = 440.0f32;
    let freq2 = 480.0f32;

    for (i, sample) in buffer.iter_mut().enumerate() {
        let t = i as f32 / sample_rate as f32;
        let s1 = (2.0 * std::f32::consts::PI * freq1 * t).sin();
        let s2 = (2.0 * std::f32::consts::PI * freq2 * t).sin();
        let mixed = (s1 + s2) * 0.3 * volume; // 0.3 to reduce amplitude
        *sample = (mixed * i16::MAX as f32) as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ringtone_player_new() {
        let player = RingtonePlayer::new();
        assert!(!player.is_playing());
        assert!(!player.has_ringtone());
    }

    #[test]
    fn test_ringtone_player_volume() {
        let mut player = RingtonePlayer::new();
        player.set_volume(0.5);
        assert!((player.volume - 0.5).abs() < 0.001);

        // Clamp to 1.0
        player.set_volume(2.0);
        assert!((player.volume - 1.0).abs() < 0.001);

        // Clamp to 0.0
        player.set_volume(-1.0);
        assert!((player.volume - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_ringtone_pattern_generation() {
        let mut buffer = [0i16; 480];
        generate_ringtone_pattern(&mut buffer, 48000, 1.0);

        // Should have non-zero samples (sine wave)
        let has_audio = buffer.iter().any(|&s| s != 0);
        assert!(has_audio);
    }

    #[test]
    fn test_ringtone_pattern_volume() {
        let mut buffer_full = [0i16; 480];
        let mut buffer_half = [0i16; 480];

        generate_ringtone_pattern(&mut buffer_full, 48000, 1.0);
        generate_ringtone_pattern(&mut buffer_half, 48000, 0.5);

        // Half volume should have smaller amplitude
        let max_full = buffer_full.iter().map(|s| s.abs()).max().unwrap_or(0);
        let max_half = buffer_half.iter().map(|s| s.abs()).max().unwrap_or(0);

        assert!(max_half < max_full);
    }
}
