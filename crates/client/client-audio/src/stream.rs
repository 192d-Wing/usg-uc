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
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info};

/// Helper to get device name (cpal 0.17 deprecated name()).
#[allow(deprecated)]
fn get_device_name(device: &cpal::Device) -> String {
    device.name().unwrap_or_else(|_| "Unknown".to_string())
}

/// Size of the ring buffer in samples (enough for ~500ms at 48kHz).
const RING_BUFFER_SIZE: usize = 48000;

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

        // Create ring buffer for passing samples from callback to consumer
        let ring = HeapRb::<Sample>::new(RING_BUFFER_SIZE);
        let (producer, consumer) = ring.split();

        let is_running = Arc::new(AtomicBool::new(true));
        let is_running_clone = is_running.clone();

        // Get the sample format
        let supported_config = device
            .default_input_config()
            .map_err(|e| AudioError::StreamError(format!("Failed to get config: {e}")))?;

        let stream = match supported_config.sample_format() {
            SampleFormat::I16 => {
                build_input_stream_i16(&device, &config, producer, is_running_clone)?
            }
            SampleFormat::F32 => {
                build_input_stream_f32(&device, &config, producer, is_running_clone)?
            }
            format => {
                return Err(AudioError::StreamError(format!(
                    "Unsupported sample format: {:?}",
                    format
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
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Stops the capture stream.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        debug!("Capture stream stopped");
    }
}

/// Build input stream for i16 samples.
fn build_input_stream_i16(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    mut producer: ringbuf::HeapProd<Sample>,
    is_running: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = config.channels as usize;

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
                error!("Capture stream error: {}", err);
            },
            None,
        )
        .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;

    Ok(stream)
}

/// Build input stream for f32 samples.
fn build_input_stream_f32(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    mut producer: ringbuf::HeapProd<Sample>,
    is_running: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = config.channels as usize;

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
                error!("Capture stream error: {}", err);
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

        // Create ring buffer for passing samples from producer to callback
        let ring = HeapRb::<Sample>::new(RING_BUFFER_SIZE);
        let (producer, consumer) = ring.split();

        let is_running = Arc::new(AtomicBool::new(true));
        let is_running_clone = is_running.clone();

        // Get the sample format
        let supported_config = device
            .default_output_config()
            .map_err(|e| AudioError::StreamError(format!("Failed to get config: {e}")))?;

        let stream = match supported_config.sample_format() {
            SampleFormat::I16 => {
                build_output_stream_i16(&device, &config, consumer, is_running_clone)?
            }
            SampleFormat::F32 => {
                build_output_stream_f32(&device, &config, consumer, is_running_clone)?
            }
            format => {
                return Err(AudioError::StreamError(format!(
                    "Unsupported sample format: {:?}",
                    format
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
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Stops the playback stream.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        debug!("Playback stream stopped");
    }
}

/// Build output stream for i16 samples.
fn build_output_stream_i16(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    mut consumer: ringbuf::HeapCons<Sample>,
    is_running: Arc<AtomicBool>,
) -> AudioResult<Stream> {
    let channels = config.channels as usize;
    let mut last_sample: i16 = 0;

    let stream = device
        .build_output_stream(
            config,
            move |data: &mut [i16], _: &cpal::OutputCallbackInfo| {
                if !is_running.load(Ordering::Relaxed) {
                    data.fill(0);
                    return;
                }

                // Fill with samples from ring buffer, holding last value on underrun
                // to avoid hard silence transitions that cause clicks.
                if channels == 1 {
                    let read = consumer.pop_slice(data);
                    if read > 0 {
                        last_sample = data[read - 1];
                    }
                    // Hold last sample instead of hard zero on underrun
                    for s in &mut data[read..] {
                        *s = last_sample;
                        // Decay toward zero to avoid DC offset
                        last_sample = (last_sample as i32 * 255 / 256) as i16;
                    }
                } else {
                    for chunk in data.chunks_mut(channels) {
                        if let Some(sample) = consumer.try_pop() {
                            last_sample = sample;
                            chunk.fill(sample);
                        } else {
                            chunk.fill(last_sample);
                            last_sample = (last_sample as i32 * 255 / 256) as i16;
                        }
                    }
                }
            },
            move |err| {
                error!("Playback stream error: {}", err);
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
) -> AudioResult<Stream> {
    let channels = config.channels as usize;
    let mut last_sample: f32 = 0.0;

    let stream = device
        .build_output_stream(
            config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if !is_running.load(Ordering::Relaxed) {
                    data.fill(0.0);
                    return;
                }

                // Fill with samples from ring buffer, holding last value on underrun
                if channels == 1 {
                    for sample in data.iter_mut() {
                        if let Some(s) = consumer.try_pop() {
                            last_sample = i16_to_f32(s);
                        } else {
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
                            last_sample *= 255.0 / 256.0;
                        }
                        chunk.fill(last_sample);
                    }
                }
            },
            move |err| {
                error!("Playback stream error: {}", err);
            },
            None,
        )
        .map_err(|e| AudioError::StreamError(format!("Failed to build stream: {e}")))?;

    Ok(stream)
}

/// Convert f32 sample to i16.
#[inline]
fn f32_to_i16(sample: f32) -> i16 {
    let clamped = sample.clamp(-1.0, 1.0);
    (clamped * i16::MAX as f32) as i16
}

/// Convert i16 sample to f32.
#[inline]
fn i16_to_f32(sample: i16) -> f32 {
    sample as f32 / i16::MAX as f32
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
