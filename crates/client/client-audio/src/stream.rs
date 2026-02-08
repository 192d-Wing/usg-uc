//! Audio capture and playback streams using CPAL.
//!
//! This module provides high-level wrappers around CPAL streams for
//! capturing microphone input and playing back received audio.

use crate::device::DeviceManager;
use crate::{AudioError, AudioResult};
use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::{SampleFormat, Stream};
use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer, Split};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{debug, error, info};

/// Helper to get device name (cpal 0.17 deprecated `name()`).
#[allow(deprecated)]
fn get_device_name(device: &cpal::Device) -> String {
    device.name().unwrap_or_else(|_| "Unknown".to_string())
}

/// Ring buffer capacity in milliseconds.
/// 500ms bounds worst-case latency while giving enough headroom
/// for decode thread scheduling and device switch transitions.
const RING_BUFFER_DURATION_MS: u32 = 500;

/// Audio sample type used internally.
pub type Sample = i16;

/// Handle to a capture (input) audio stream.
pub struct CaptureStream {
    /// The underlying CPAL stream.
    _stream: Stream,
    /// Consumer end of the ring buffer for reading captured audio.
    consumer: ringbuf::HeapCons<Sample>,
    /// Whether the stream is currently running.
    is_running: Arc<AtomicBool>,
    /// Sample rate of the stream.
    sample_rate: u32,
    /// Set to `true` by the CPAL error callback when the device disconnects or errors.
    device_error: Arc<AtomicBool>,
}

impl CaptureStream {
    /// Creates and starts a new capture stream.
    pub fn new(device_manager: &DeviceManager) -> AudioResult<Self> {
        let device = device_manager.get_input_device()?;
        let config = device_manager.get_input_config(&device)?;

        info!(
            "Starting capture stream: device={}, rate={}, channels={}",
            get_device_name(&device),
            config.sample_rate,
            config.channels
        );

        let sample_rate = config.sample_rate;

        // Create ring buffer scaled to actual sample rate (~2 seconds)
        #[allow(clippy::cast_possible_truncation)]
        let ring_size = (sample_rate * RING_BUFFER_DURATION_MS / 1000) as usize;
        let ring = HeapRb::<Sample>::new(ring_size);
        let (producer, consumer) = ring.split();

        let is_running = Arc::new(AtomicBool::new(true));
        let is_running_clone = is_running.clone();
        let device_error = Arc::new(AtomicBool::new(false));
        let device_error_clone = device_error.clone();

        // Get the sample format
        let supported_config = device
            .default_input_config()
            .map_err(|e| AudioError::StreamError(format!("Failed to get config: {e}")))?;

        let stream = match supported_config.sample_format() {
            SampleFormat::I16 => build_input_stream_i16(
                &device,
                &config,
                producer,
                is_running_clone,
                device_error_clone,
            )?,
            SampleFormat::F32 => build_input_stream_f32(
                &device,
                &config,
                producer,
                is_running_clone,
                device_error_clone,
            )?,
            format => {
                return Err(AudioError::StreamError(format!(
                    "Unsupported sample format: {format:?}"
                )));
            }
        };

        stream
            .play()
            .map_err(|e| AudioError::StreamError(format!("Failed to start stream: {e}")))?;

        debug!("Capture stream started");

        Ok(Self {
            _stream: stream,
            consumer,
            is_running,
            sample_rate,
            device_error,
        })
    }

    /// Reads captured audio samples into the provided buffer.
    ///
    /// Returns the number of samples read.
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

    /// Returns `true` if the CPAL error callback has fired (device disconnect/error).
    pub fn has_error(&self) -> bool {
        self.device_error.load(Ordering::Relaxed)
    }

    /// Stops the capture stream.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        debug!("Capture stream stopped");
    }
}

/// Build input stream for i16 samples.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn build_input_stream_i16(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    mut producer: ringbuf::HeapProd<Sample>,
    is_running: Arc<AtomicBool>,
    device_error: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = usize::from(config.channels);

    let stream = device
        .build_input_stream(
            config,
            move |data: &[i16], _: &cpal::InputCallbackInfo| {
                if !is_running.load(Ordering::Relaxed) {
                    return;
                }

                // Convert to mono if needed
                if channels == 1 {
                    let _ = producer.push_slice(data);
                } else {
                    // Mix down to mono
                    for chunk in data.chunks(channels) {
                        let sum: i32 = chunk.iter().map(|&s| i32::from(s)).sum();
                        let mono = (sum / channels as i32) as i16;
                        let _ = producer.try_push(mono);
                    }
                }
            },
            move |err| {
                error!("Capture stream error (device may have disconnected): {err}");
                device_error.store(true, Ordering::Relaxed);
            },
            None,
        )
        .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;

    Ok(stream)
}

/// Build input stream for f32 samples.
#[allow(clippy::cast_precision_loss)]
fn build_input_stream_f32(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    mut producer: ringbuf::HeapProd<Sample>,
    is_running: Arc<AtomicBool>,
    device_error: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = usize::from(config.channels);

    let stream = device
        .build_input_stream(
            config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                if !is_running.load(Ordering::Relaxed) {
                    return;
                }

                // Convert f32 to i16 and mix to mono if needed
                if channels == 1 {
                    for &sample in data {
                        let _ = producer.try_push(f32_to_i16(sample));
                    }
                } else {
                    for chunk in data.chunks(channels) {
                        let sum: f32 = chunk.iter().sum();
                        let mono = sum / channels as f32;
                        let _ = producer.try_push(f32_to_i16(mono));
                    }
                }
            },
            move |err| {
                error!("Capture stream error (device may have disconnected): {err}");
                device_error.store(true, Ordering::Relaxed);
            },
            None,
        )
        .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;

    Ok(stream)
}

/// Handle to a playback (output) audio stream.
pub struct PlaybackStream {
    /// The underlying CPAL stream.
    _stream: Stream,
    /// Producer end of the ring buffer for writing audio to play.
    producer: ringbuf::HeapProd<Sample>,
    /// Whether the stream is currently running.
    is_running: Arc<AtomicBool>,
    /// Sample rate of the stream.
    sample_rate: u32,
    /// Counter for CPAL callback underruns (callbacks where ring buffer was empty).
    underrun_count: Arc<AtomicU64>,
    /// Set to `true` by the CPAL error callback when the device disconnects or errors.
    device_error: Arc<AtomicBool>,
}

impl PlaybackStream {
    /// Creates and starts a new playback stream.
    pub fn new(device_manager: &DeviceManager) -> AudioResult<Self> {
        let device = device_manager.get_output_device()?;
        let config = device_manager.get_output_config(&device)?;

        info!(
            "Starting playback stream: device={}, rate={}, channels={}",
            get_device_name(&device),
            config.sample_rate,
            config.channels
        );

        let sample_rate = config.sample_rate;

        // Create ring buffer scaled to actual sample rate (~2 seconds)
        #[allow(clippy::cast_possible_truncation)]
        let ring_size = (sample_rate * RING_BUFFER_DURATION_MS / 1000) as usize;
        let ring = HeapRb::<Sample>::new(ring_size);
        let (producer, consumer) = ring.split();

        let is_running = Arc::new(AtomicBool::new(true));
        let is_running_clone = is_running.clone();
        let underrun_count = Arc::new(AtomicU64::new(0));
        let underrun_clone = underrun_count.clone();
        let device_error = Arc::new(AtomicBool::new(false));
        let device_error_clone = device_error.clone();

        // Get the sample format
        let supported_config = device
            .default_output_config()
            .map_err(|e| AudioError::StreamError(format!("Failed to get config: {e}")))?;

        let stream = match supported_config.sample_format() {
            SampleFormat::I16 => build_output_stream_i16(
                &device,
                &config,
                consumer,
                is_running_clone,
                underrun_clone,
                device_error_clone,
            )?,
            SampleFormat::F32 => build_output_stream_f32(
                &device,
                &config,
                consumer,
                is_running_clone,
                underrun_clone,
                device_error_clone,
            )?,
            format => {
                return Err(AudioError::StreamError(format!(
                    "Unsupported sample format: {format:?}"
                )));
            }
        };

        stream
            .play()
            .map_err(|e| AudioError::StreamError(format!("Failed to start stream: {e}")))?;

        debug!("Playback stream started");

        Ok(Self {
            _stream: stream,
            producer,
            is_running,
            sample_rate,
            underrun_count,
            device_error,
        })
    }

    /// Writes audio samples for playback.
    ///
    /// Returns the number of samples written.
    pub fn write(&mut self, samples: &[Sample]) -> usize {
        self.producer.push_slice(samples)
    }

    /// Returns the number of samples that can be written without blocking.
    pub fn available(&self) -> usize {
        self.producer.vacant_len()
    }

    /// Returns the number of samples currently buffered for playback.
    pub fn buffered(&self) -> usize {
        self.producer.occupied_len()
    }

    /// Returns whether the stream is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    /// Returns the sample rate of the stream.
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Returns `true` if the CPAL error callback has fired (device disconnect/error).
    pub fn has_error(&self) -> bool {
        self.device_error.load(Ordering::Relaxed)
    }

    /// Stops the playback stream.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        debug!("Playback stream stopped");
    }

    /// Splits the playback stream into a handle, ring buffer producer, and underrun counter.
    ///
    /// The producer can be moved to the decode thread while the CPAL stream
    /// (and its consumer) continues running. The underrun counter is shared
    /// with the CPAL callback and tracks how many callbacks had buffer underruns.
    /// After calling this, use the returned producer directly instead of `write()`.
    #[allow(clippy::used_underscore_binding)]
    pub fn take_producer(
        self,
    ) -> (
        PlaybackStreamHandle,
        ringbuf::HeapProd<Sample>,
        Arc<AtomicU64>,
    ) {
        let handle = PlaybackStreamHandle {
            _stream: self._stream,
            is_running: self.is_running,
            sample_rate: self.sample_rate,
            device_error: self.device_error,
        };
        (handle, self.producer, self.underrun_count)
    }
}

/// Handle to a running playback stream after the producer has been extracted.
///
/// Holds the CPAL stream alive and provides stop/metadata functionality.
/// The ring buffer producer has been moved to the decode thread.
pub struct PlaybackStreamHandle {
    /// The underlying CPAL stream (kept alive).
    _stream: Stream,
    /// Whether the stream is currently running.
    is_running: Arc<AtomicBool>,
    /// Sample rate of the stream.
    sample_rate: u32,
    /// Set to `true` by the CPAL error callback when the device disconnects or errors.
    device_error: Arc<AtomicBool>,
}

impl PlaybackStreamHandle {
    /// Returns the sample rate of the stream.
    pub const fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Returns whether the stream is running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    /// Returns `true` if the CPAL error callback has fired (device disconnect/error).
    pub fn has_error(&self) -> bool {
        self.device_error.load(Ordering::Relaxed)
    }

    /// Stops the playback stream.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        debug!("Playback stream stopped");
    }
}

/// Build output stream for i16 samples.
#[allow(clippy::cast_possible_truncation)]
fn build_output_stream_i16(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    mut consumer: ringbuf::HeapCons<Sample>,
    is_running: Arc<AtomicBool>,
    underrun_count: Arc<AtomicU64>,
    device_error: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = usize::from(config.channels);
    let mut last_sample: i16 = 0;

    let stream = device
        .build_output_stream(
            config,
            move |data: &mut [i16], _: &cpal::OutputCallbackInfo| {
                if !is_running.load(Ordering::Relaxed) {
                    data.fill(0);
                    return;
                }

                let mut had_underrun = false;

                // Fill with samples from ring buffer, holding last value on underrun
                // to avoid hard silence transitions that cause clicks.
                if channels == 1 {
                    let read = consumer.pop_slice(data);
                    if read > 0 {
                        last_sample = data[read - 1];
                    }
                    if read < data.len() {
                        had_underrun = true;
                    }
                    // Hold last sample instead of hard zero on underrun
                    for s in &mut data[read..] {
                        *s = last_sample;
                        // Decay toward zero to avoid DC offset
                        last_sample = (i32::from(last_sample) * 255 / 256) as i16;
                    }
                } else {
                    for chunk in data.chunks_mut(channels) {
                        if let Some(sample) = consumer.try_pop() {
                            last_sample = sample;
                            chunk.fill(sample);
                        } else {
                            had_underrun = true;
                            chunk.fill(last_sample);
                            last_sample = (i32::from(last_sample) * 255 / 256) as i16;
                        }
                    }
                }

                if had_underrun {
                    underrun_count.fetch_add(1, Ordering::Relaxed);
                }
            },
            move |err| {
                error!("Playback stream error (device may have disconnected): {err}");
                device_error.store(true, Ordering::Relaxed);
            },
            None,
        )
        .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;

    Ok(stream)
}

/// Build output stream for f32 samples.
fn build_output_stream_f32(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    mut consumer: ringbuf::HeapCons<Sample>,
    is_running: Arc<AtomicBool>,
    underrun_count: Arc<AtomicU64>,
    device_error: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = usize::from(config.channels);
    let mut last_sample: f32 = 0.0;

    let stream = device
        .build_output_stream(
            config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if !is_running.load(Ordering::Relaxed) {
                    data.fill(0.0);
                    return;
                }

                let mut had_underrun = false;

                // Fill with samples from ring buffer, holding last value on underrun
                if channels == 1 {
                    for sample in data.iter_mut() {
                        if let Some(s) = consumer.try_pop() {
                            last_sample = i16_to_f32(s);
                        } else {
                            had_underrun = true;
                            // Decay toward zero
                            last_sample *= 255.0 / 256.0;
                        }
                        *sample = last_sample;
                    }
                } else {
                    for chunk in data.chunks_mut(channels) {
                        if let Some(s) = consumer.try_pop() {
                            last_sample = i16_to_f32(s);
                        } else {
                            had_underrun = true;
                            last_sample *= 255.0 / 256.0;
                        }
                        chunk.fill(last_sample);
                    }
                }

                if had_underrun {
                    underrun_count.fetch_add(1, Ordering::Relaxed);
                }
            },
            move |err| {
                error!("Playback stream error (device may have disconnected): {err}");
                device_error.store(true, Ordering::Relaxed);
            },
            None,
        )
        .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;

    Ok(stream)
}

/// Convert f32 sample to i16.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn f32_to_i16(sample: f32) -> i16 {
    let clamped = sample.clamp(-1.0, 1.0);
    (clamped * f32::from(i16::MAX)) as i16
}

/// Convert i16 sample to f32.
#[inline]
fn i16_to_f32(sample: i16) -> f32 {
    f32::from(sample) / f32::from(i16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f32_to_i16_conversion() {
        assert_eq!(f32_to_i16(0.0), 0);
        assert_eq!(f32_to_i16(1.0), i16::MAX);
        assert_eq!(f32_to_i16(-1.0), -i16::MAX);
        assert_eq!(f32_to_i16(0.5), i16::MAX / 2);
    }

    #[test]
    fn test_i16_to_f32_conversion() {
        assert!((i16_to_f32(0) - 0.0).abs() < 0.001);
        assert!((i16_to_f32(i16::MAX) - 1.0).abs() < 0.001);
        assert!((i16_to_f32(-i16::MAX) - -1.0).abs() < 0.001);
    }

    #[test]
    fn test_f32_clamping() {
        // Values outside [-1, 1] should be clamped
        assert_eq!(f32_to_i16(2.0), i16::MAX);
        assert_eq!(f32_to_i16(-2.0), -i16::MAX);
    }
}
