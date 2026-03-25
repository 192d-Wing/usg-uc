//! macOS Voice Processing I/O (VPIO) capture stream.
//!
//! Uses CoreAudio's `kAudioUnitSubType_VoiceProcessingIO` audio unit which
//! provides hardware-level acoustic echo cancellation. The OS knows exactly
//! what audio is being played to the speaker and cancels it from the mic
//! input, enabling full-duplex conversation without half-duplex suppression.
//!
//! This module is only compiled on macOS (`#[cfg(target_os = "macos")]`).

use crate::stream::Sample;
use crate::{AudioError, AudioResult};
use coreaudio::audio_unit::render_callback::{self, data};
use coreaudio::audio_unit::{AudioUnit, Element, IOType, Scope};
use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer, Split};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info};

/// CoreAudio property: enable/disable I/O on a bus.
const KAUDIO_OUTPUT_UNIT_PROPERTY_ENABLE_IO: u32 = 2003;

/// Ring buffer capacity in milliseconds (matches CaptureStream).
const RING_BUFFER_DURATION_MS: u32 = 500;

/// Capture stream using macOS Voice Processing I/O.
///
/// Drop-in replacement for `CaptureStream` when using built-in MacBook
/// mic + speakers. Provides hardware AEC via the OS.
pub struct VpioCaptureStream {
    /// The CoreAudio VPIO audio unit (owns the real-time callback).
    _audio_unit: AudioUnit,
    /// Consumer end of the ring buffer for reading captured audio.
    consumer: ringbuf::HeapCons<Sample>,
    /// Whether the stream is currently running.
    is_running: Arc<AtomicBool>,
    /// Actual sample rate negotiated with the hardware.
    sample_rate: u32,
    /// Set to `true` if an error occurs in the callback.
    device_error: Arc<AtomicBool>,
}

#[allow(unsafe_code)]
impl VpioCaptureStream {
    /// Creates and starts a VPIO capture stream on the default input device.
    ///
    /// The VPIO audio unit handles:
    /// - Acoustic echo cancellation (hardware-level)
    /// - Automatic gain control
    /// - Noise suppression
    pub fn new() -> AudioResult<Self> {
        info!("Creating VPIO capture stream (hardware AEC)");

        // Create VoiceProcessingIO audio unit.
        // AudioUnit::new() auto-initializes, but we need to set properties
        // BEFORE initialization. So: create → uninitialize → configure → reinitialize.
        let mut audio_unit = AudioUnit::new(IOType::VoiceProcessingIO)
            .map_err(|e| AudioError::StreamError(format!("Failed to create VPIO unit: {e}")))?;

        // Uninitialize so we can configure I/O before re-initialization
        audio_unit
            .uninitialize()
            .map_err(|e| AudioError::StreamError(format!("Failed to uninitialize VPIO: {e}")))?;

        // Enable input on bus 1 (mic → app)
        let enable_input: u32 = 1;
        audio_unit
            .set_property(
                KAUDIO_OUTPUT_UNIT_PROPERTY_ENABLE_IO,
                Scope::Input,
                Element::Input,
                Some(&enable_input),
            )
            .map_err(|e| AudioError::StreamError(format!("Failed to enable VPIO input: {e}")))?;

        // Request 48kHz to match playback rate (avoids capture/playback rate mismatch).
        // Set on both input and output scopes. If VPIO rejects it, we'll use whatever it gives us.
        let desired_rate: f64 = 48_000.0;
        // kAudioUnitProperty_SampleRate = 2
        let rate_id: u32 = 2;
        if let Err(e) =
            audio_unit.set_property(rate_id, Scope::Output, Element::Input, Some(&desired_rate))
        {
            info!("VPIO rejected 48kHz on input scope: {e}, will use device default");
        }
        if let Err(e) =
            audio_unit.set_property(rate_id, Scope::Input, Element::Output, Some(&desired_rate))
        {
            info!("VPIO rejected 48kHz on output scope: {e}, will use device default");
        }

        // Re-initialize with input enabled and sample rate set
        audio_unit
            .initialize()
            .map_err(|e| AudioError::StreamError(format!("Failed to initialize VPIO: {e}")))?;

        // Get the actual input stream format (VPIO decides the format)
        let stream_format = audio_unit
            .input_stream_format()
            .map_err(|e| AudioError::StreamError(format!("Failed to get VPIO format: {e}")))?;

        let sample_rate = stream_format.sample_rate as u32;
        let channels = stream_format.channels as usize;
        info!(
            sample_rate = sample_rate,
            channels = channels,
            format = ?stream_format.sample_format,
            "VPIO input stream format"
        );

        // Create ring buffer (same sizing as CaptureStream)
        let ring_capacity = (sample_rate * RING_BUFFER_DURATION_MS / 1000) as usize;
        let rb = HeapRb::new(ring_capacity);
        let (producer, consumer) = rb.split();

        let is_running = Arc::new(AtomicBool::new(true));
        let device_error = Arc::new(AtomicBool::new(false));

        // Set up input callback — VPIO delivers echo-cancelled mic audio here
        let is_running_cb = is_running.clone();
        let mut producer = producer;

        audio_unit
            .set_input_callback(move |args: render_callback::Args<data::Interleaved<f32>>| {
                if !is_running_cb.load(Ordering::Relaxed) {
                    return Err(());
                }

                // Convert f32 samples to i16 and push to ring buffer.
                // Mix to mono if multi-channel.
                let samples = args.data.buffer;
                if channels == 1 {
                    for s in samples.iter() {
                        #[allow(clippy::cast_possible_truncation)]
                        let sample = (*s * 32767.0_f32).clamp(-32768.0, 32767.0) as i16;
                        let _ = producer.try_push(sample);
                    }
                } else {
                    for chunk in samples.chunks(channels) {
                        let sum: f32 = chunk.iter().copied().sum();
                        let mono = sum / channels as f32;
                        #[allow(clippy::cast_possible_truncation)]
                        let sample = (mono * 32767.0_f32).clamp(-32768.0, 32767.0) as i16;
                        let _ = producer.try_push(sample);
                    }
                }

                Ok(())
            })
            .map_err(|e| {
                AudioError::StreamError(format!("Failed to set VPIO input callback: {e}"))
            })?;

        // Start the audio unit
        audio_unit
            .start()
            .map_err(|e| AudioError::StreamError(format!("Failed to start VPIO: {e}")))?;

        info!(
            sample_rate = sample_rate,
            "VPIO capture stream started (hardware AEC active)"
        );

        Ok(Self {
            _audio_unit: audio_unit,
            consumer,
            is_running,
            sample_rate,
            device_error,
        })
    }

    /// Reads captured audio samples into the provided buffer.
    pub fn read(&mut self, buffer: &mut [Sample]) -> usize {
        self.consumer.pop_slice(buffer)
    }

    /// Returns the number of samples available to read.
    pub fn available(&self) -> usize {
        self.consumer.occupied_len()
    }

    /// Returns whether the stream is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    /// Returns the sample rate of the stream.
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Returns `true` if an error occurred.
    pub fn has_error(&self) -> bool {
        self.device_error.load(Ordering::Relaxed)
    }

    /// Stops the capture stream.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        debug!("VPIO capture stream stopped");
    }
}

impl Drop for VpioCaptureStream {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Returns `true` if VPIO should be used for the current device setup.
///
/// VPIO is beneficial when using built-in speakers + built-in mic (laptop use).
/// For headsets, USB audio, or Bluetooth, CPAL is fine (no acoustic echo path).
pub fn should_use_vpio(input_device_name: Option<&str>) -> bool {
    let name = match input_device_name {
        Some(n) => n.to_lowercase(),
        None => return true, // Default device on MacBook = built-in mic
    };

    // Use VPIO for built-in mics (where speaker-to-mic coupling causes echo)
    name.contains("macbook")
        || name.contains("built-in")
        || name.contains("internal")
        || name == "default"
}
