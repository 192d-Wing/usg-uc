//! File-based audio source for Music on Hold.
//!
//! This module provides a `FileAudioSource` that can load WAV files,
//! resample them to the target sample rate, and provide audio frames
//! for transmission during call hold.

use crate::{AudioError, AudioResult};
use std::path::Path;
use tracing::{debug, info};

/// Audio source that reads from a WAV file.
///
/// Supports mono or stereo WAV files at any sample rate, with automatic
/// conversion to mono at the target sample rate. Loops continuously when
/// reaching the end of the file.
pub struct FileAudioSource {
    /// Audio samples converted to target format.
    samples: Vec<i16>,
    /// Current read position in the samples buffer.
    position: usize,
    /// Target sample rate for output.
    target_sample_rate: u32,
    /// Original file sample rate.
    file_sample_rate: u32,
    /// Whether the source has loaded audio.
    loaded: bool,
}

impl FileAudioSource {
    /// Creates a new empty file audio source.
    #[must_use]
    pub const fn new(target_sample_rate: u32) -> Self {
        Self {
            samples: Vec::new(),
            position: 0,
            target_sample_rate,
            file_sample_rate: 0,
            loaded: false,
        }
    }

    /// Loads audio from a WAV file.
    ///
    /// The audio is converted to mono at the target sample rate.
    #[allow(clippy::cast_precision_loss)]
    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> AudioResult<()> {
        let path = path.as_ref();
        info!(path = %path.display(), "Loading MOH audio file");

        let reader = hound::WavReader::open(path)
            .map_err(|e| AudioError::StreamError(format!("Failed to open WAV file: {e}")))?;

        let spec = reader.spec();
        self.file_sample_rate = spec.sample_rate;

        debug!(
            "WAV file: {} Hz, {} channels, {} bits",
            spec.sample_rate, spec.channels, spec.bits_per_sample
        );

        // Read all samples
        #[allow(clippy::cast_possible_truncation)]
        let raw_samples: Vec<i32> = match spec.sample_format {
            hound::SampleFormat::Int => reader
                .into_samples::<i32>()
                .filter_map(std::result::Result::ok)
                .collect(),
            hound::SampleFormat::Float => reader
                .into_samples::<f32>()
                .filter_map(std::result::Result::ok)
                .map(|s| (s * 32767.0) as i32)
                .collect(),
        };

        if raw_samples.is_empty() {
            return Err(AudioError::StreamError(
                "WAV file contains no samples".to_string(),
            ));
        }

        // Convert to mono if stereo
        let mono_samples: Vec<i16> = if spec.channels == 2 {
            raw_samples
                .chunks(2)
                .map(|chunk| {
                    let left = chunk.first().copied().unwrap_or(0);
                    let right = chunk.get(1).copied().unwrap_or(0);
                    // Average both channels, normalize to i16 range
                    let mixed = i32::midpoint(left, right);
                    Self::normalize_sample(mixed, spec.bits_per_sample)
                })
                .collect()
        } else {
            raw_samples
                .iter()
                .map(|&s| Self::normalize_sample(s, spec.bits_per_sample))
                .collect()
        };

        // Resample to target rate if needed
        let resampled = if spec.sample_rate == self.target_sample_rate {
            mono_samples
        } else {
            Self::resample(&mono_samples, spec.sample_rate, self.target_sample_rate)
        };

        info!(
            "Loaded {} samples ({:.2} seconds at {} Hz)",
            resampled.len(),
            resampled.len() as f32 / self.target_sample_rate as f32,
            self.target_sample_rate
        );

        self.samples = resampled;
        self.position = 0;
        self.loaded = true;

        Ok(())
    }

    /// Normalizes a sample to i16 range based on the original bit depth.
    #[allow(clippy::cast_possible_truncation)]
    const fn normalize_sample(sample: i32, bits: u16) -> i16 {
        match bits {
            8 => ((sample - 128) * 256) as i16,
            24 => (sample >> 8) as i16,
            32 => (sample >> 16) as i16,
            // 16-bit and anything else passes through
            _ => sample as i16,
        }
    }

    /// Simple linear resampling from source rate to target rate.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn resample(samples: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
        if from_rate == to_rate {
            return samples.to_vec();
        }

        let ratio = f64::from(from_rate) / f64::from(to_rate);
        let output_len = (samples.len() as f64 / ratio).ceil() as usize;
        let mut output = Vec::with_capacity(output_len);

        for i in 0..output_len {
            let src_pos = i as f64 * ratio;
            let src_idx = src_pos as usize;
            let frac = src_pos - src_idx as f64;

            // Linear interpolation
            let sample = if src_idx + 1 < samples.len() {
                let s0 = f64::from(samples[src_idx]);
                let s1 = f64::from(samples[src_idx + 1]);
                frac.mul_add(s1 - s0, s0) as i16
            } else if src_idx < samples.len() {
                samples[src_idx]
            } else {
                0
            };

            output.push(sample);
        }

        output
    }

    /// Reads samples from the source into the buffer.
    ///
    /// Loops back to the beginning when reaching the end of the file.
    /// Returns the number of samples written.
    pub fn read(&mut self, buffer: &mut [i16]) -> usize {
        if !self.loaded || self.samples.is_empty() {
            buffer.fill(0);
            return 0;
        }

        let mut written = 0;
        while written < buffer.len() {
            let remaining_in_file = self.samples.len() - self.position;
            let to_write = (buffer.len() - written).min(remaining_in_file);

            buffer[written..written + to_write]
                .copy_from_slice(&self.samples[self.position..self.position + to_write]);

            self.position += to_write;
            written += to_write;

            // Loop back to beginning
            if self.position >= self.samples.len() {
                self.position = 0;
            }
        }

        written
    }

    /// Resets playback to the beginning.
    pub const fn reset(&mut self) {
        self.position = 0;
    }

    /// Returns whether audio has been loaded.
    #[must_use]
    pub const fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Returns the duration of the loaded audio in seconds.
    #[allow(clippy::cast_precision_loss)]
    pub fn duration_secs(&self) -> f32 {
        if self.loaded && self.target_sample_rate > 0 {
            self.samples.len() as f32 / self.target_sample_rate as f32
        } else {
            0.0
        }
    }
}

impl Default for FileAudioSource {
    fn default() -> Self {
        Self::new(8000) // G.711 rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_source_new() {
        let source = FileAudioSource::new(8000);
        assert!(!source.is_loaded());
        assert!(source.duration_secs().abs() < f32::EPSILON);
    }

    #[test]
    fn test_file_source_read_empty() {
        let mut source = FileAudioSource::new(8000);
        let mut buffer = [0i16; 160];
        let read = source.read(&mut buffer);
        assert_eq!(read, 0);
        assert!(buffer.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_normalize_sample() {
        // 16-bit should pass through
        assert_eq!(FileAudioSource::normalize_sample(1000, 16), 1000);
        assert_eq!(FileAudioSource::normalize_sample(-1000, 16), -1000);

        // 8-bit conversion (0-255 -> -128 to 127, then * 256)
        assert_eq!(FileAudioSource::normalize_sample(128, 8), 0);
        assert_eq!(FileAudioSource::normalize_sample(255, 8), 32512);

        // 24-bit shift
        assert_eq!(FileAudioSource::normalize_sample(0x007F_0000, 24), 0x7F00);
    }

    #[test]
    fn test_resample_passthrough() {
        let samples = vec![1000i16, 2000, 3000, 4000];
        let result = FileAudioSource::resample(&samples, 8000, 8000);
        assert_eq!(result, samples);
    }

    #[test]
    fn test_resample_downsample() {
        // Downsampling from 16000 to 8000 should halve the number of samples
        let samples: Vec<i16> = (0..100).collect();
        let result = FileAudioSource::resample(&samples, 16000, 8000);
        assert!(result.len() < samples.len());
        // Should be roughly half
        assert!(result.len() >= 45 && result.len() <= 55);
    }

    #[test]
    fn test_resample_upsample() {
        // Upsampling from 8000 to 16000 should double the number of samples
        let samples: Vec<i16> = (0..100).collect();
        let result = FileAudioSource::resample(&samples, 8000, 16000);
        assert!(result.len() > samples.len());
        // Should be roughly double
        assert!(result.len() >= 195 && result.len() <= 205);
    }
}
