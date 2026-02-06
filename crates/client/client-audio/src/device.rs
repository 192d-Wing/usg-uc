//! Audio device enumeration and management.
//!
//! This module provides cross-platform audio device discovery and selection
//! using the CPAL library.

use crate::{AudioError, AudioResult};
use client_types::audio::{AudioDevice, AudioDeviceType};
use cpal::traits::{DeviceTrait, HostTrait};
use tracing::{debug, info, warn};

/// Helper to get device name (cpal 0.17 deprecated `name()` in favor of `id()`/`description()`).
#[allow(deprecated)]
fn get_device_name(device: &cpal::Device) -> Option<String> {
    device.name().ok()
}

/// Supported sample rate for `VoIP` audio (narrowband).
pub const SAMPLE_RATE_8KHZ: u32 = 8000;

/// Supported sample rate for `VoIP` audio (wideband).
pub const SAMPLE_RATE_16KHZ: u32 = 16000;

/// Supported sample rate for `VoIP` audio (super-wideband).
pub const SAMPLE_RATE_48KHZ: u32 = 48000;

/// Default sample rate for audio streams.
pub const DEFAULT_SAMPLE_RATE: u32 = SAMPLE_RATE_48KHZ;

/// VoIP-friendly sample rates in preference order.
///
/// These rates produce integer resampling ratios with common `VoIP` codecs
/// (G.711 at 8kHz, G.722 at 16kHz), which use the fast-path integer
/// resampler for best audio quality. Non-integer ratios (e.g., 44100Hz)
/// fall back to cubic interpolation which is good but not ideal.
///
/// Preference: 48kHz (6:1) > 16kHz (2:1) > 8kHz (1:1) > 32kHz (4:1) > 24kHz (3:1)
const VOIP_PREFERRED_RATES: &[u32] = &[48000, 16000, 8000, 32000, 24000];

/// Number of audio channels (mono for `VoIP`).
pub const CHANNELS: u16 = 1;

/// Audio device manager for enumerating and selecting audio devices.
#[derive(Debug)]
pub struct DeviceManager {
    /// Selected input device name.
    input_device_name: Option<String>,
    /// Selected output device name.
    output_device_name: Option<String>,
}

impl DeviceManager {
    /// Creates a new device manager with default device selection.
    pub const fn new() -> Self {
        Self {
            input_device_name: None,
            output_device_name: None,
        }
    }

    /// Lists all available input (capture) devices.
    pub fn list_input_devices(&self) -> AudioResult<Vec<AudioDevice>> {
        let host = cpal::default_host();
        let devices = host.input_devices().map_err(|e| {
            AudioError::StreamError(format!("Failed to enumerate input devices: {e}"))
        })?;

        let default_name = host
            .default_input_device()
            .and_then(|d| get_device_name(&d));

        let mut result = Vec::new();
        for device in devices {
            if let Some(name) = get_device_name(&device) {
                let is_default = default_name.as_ref().is_some_and(|n| n == &name);

                let (channels, sample_rates) = get_device_info(&device);

                result.push(AudioDevice {
                    name: name.clone(),
                    display_name: name,
                    is_default,
                    device_type: AudioDeviceType::Input,
                    channels,
                    sample_rates,
                });
            }
        }

        debug!("Found {} input devices", result.len());
        Ok(result)
    }

    /// Lists all available output (playback) devices.
    pub fn list_output_devices(&self) -> AudioResult<Vec<AudioDevice>> {
        let host = cpal::default_host();
        let devices = host.output_devices().map_err(|e| {
            AudioError::StreamError(format!("Failed to enumerate output devices: {e}"))
        })?;

        let default_name = host
            .default_output_device()
            .and_then(|d| get_device_name(&d));

        let mut result = Vec::new();
        for device in devices {
            if let Some(name) = get_device_name(&device) {
                let is_default = default_name.as_ref().is_some_and(|n| n == &name);

                let (channels, sample_rates) = get_device_info(&device);

                result.push(AudioDevice {
                    name: name.clone(),
                    display_name: name,
                    is_default,
                    device_type: AudioDeviceType::Output,
                    channels,
                    sample_rates,
                });
            }
        }

        debug!("Found {} output devices", result.len());
        Ok(result)
    }

    /// Sets the input device by name.
    pub fn set_input_device(&mut self, name: Option<String>) {
        info!("Setting input device: {:?}", name);
        self.input_device_name = name;
    }

    /// Sets the output device by name.
    pub fn set_output_device(&mut self, name: Option<String>) {
        info!("Setting output device: {:?}", name);
        self.output_device_name = name;
    }

    /// Gets the currently selected input device.
    pub fn get_input_device(&self) -> AudioResult<cpal::Device> {
        let host = cpal::default_host();

        if let Some(ref name) = self.input_device_name {
            // Find device by name
            let devices = host.input_devices().map_err(|e| {
                AudioError::StreamError(format!("Failed to enumerate devices: {e}"))
            })?;

            for device in devices {
                if get_device_name(&device).is_some_and(|device_name| &device_name == name) {
                    debug!("Using input device: {}", name);
                    return Ok(device);
                }
            }

            warn!("Input device '{}' not found, using default", name);
        }

        // Fall back to default device
        host.default_input_device().ok_or(AudioError::NoInputDevice)
    }

    /// Gets the currently selected output device.
    pub fn get_output_device(&self) -> AudioResult<cpal::Device> {
        let host = cpal::default_host();

        if let Some(ref name) = self.output_device_name {
            // Find device by name
            let devices = host.output_devices().map_err(|e| {
                AudioError::StreamError(format!("Failed to enumerate devices: {e}"))
            })?;

            for device in devices {
                if get_device_name(&device).is_some_and(|device_name| &device_name == name) {
                    debug!("Using output device: {}", name);
                    return Ok(device);
                }
            }

            warn!("Output device '{}' not found, using default", name);
        }

        // Fall back to default device
        host.default_output_device()
            .ok_or(AudioError::NoOutputDevice)
    }

    /// Gets the supported stream configuration for an input device.
    ///
    /// Tries VoIP-friendly sample rates in preference order to get an
    /// integer resampling ratio with common codecs (8kHz, 16kHz).
    pub fn get_input_config(&self, device: &cpal::Device) -> AudioResult<cpal::StreamConfig> {
        let default_config = device
            .default_input_config()
            .map_err(|e| AudioError::StreamError(format!("Failed to get default config: {e}")))?;

        // Use the device's native channel count to avoid mismatches.
        // The stream callback handles stereo→mono mixdown.
        let device_channels = default_config.channels();

        // Collect supported rate ranges for the device's channel count
        let supported_ranges: Vec<_> = device
            .supported_input_configs()
            .map_err(|e| AudioError::StreamError(format!("Failed to get supported configs: {e}")))?
            .filter(|r| r.channels() == device_channels)
            .collect();

        // Try VoIP-friendly rates in preference order
        for &rate in VOIP_PREFERRED_RATES {
            if supported_ranges
                .iter()
                .any(|r| r.min_sample_rate() <= rate && r.max_sample_rate() >= rate)
            {
                info!(
                    "Input config: {}Hz, {} channels (VoIP-optimized)",
                    rate, device_channels
                );
                return Ok(cpal::StreamConfig {
                    channels: device_channels,
                    sample_rate: rate,
                    buffer_size: cpal::BufferSize::Default,
                });
            }
        }

        // Fall back to default config
        info!(
            "Input config: {}Hz, {} channels (device default)",
            default_config.sample_rate(),
            device_channels
        );
        Ok(cpal::StreamConfig {
            channels: device_channels,
            sample_rate: default_config.sample_rate(),
            buffer_size: cpal::BufferSize::Default,
        })
    }

    /// Gets the supported stream configuration for an output device.
    ///
    /// Tries VoIP-friendly sample rates in preference order to get an
    /// integer resampling ratio with common codecs (8kHz, 16kHz).
    pub fn get_output_config(&self, device: &cpal::Device) -> AudioResult<cpal::StreamConfig> {
        let default_config = device
            .default_output_config()
            .map_err(|e| AudioError::StreamError(format!("Failed to get default config: {e}")))?;

        // Use the device's native channel count to avoid mismatches
        // (e.g., Bluetooth devices that only support stereo).
        // The stream callback handles mono↔stereo expansion.
        let device_channels = default_config.channels();

        // Collect supported rate ranges for the device's channel count
        let supported_ranges: Vec<_> = device
            .supported_output_configs()
            .map_err(|e| AudioError::StreamError(format!("Failed to get supported configs: {e}")))?
            .filter(|r| r.channels() == device_channels)
            .collect();

        // Try VoIP-friendly rates in preference order
        for &rate in VOIP_PREFERRED_RATES {
            if supported_ranges
                .iter()
                .any(|r| r.min_sample_rate() <= rate && r.max_sample_rate() >= rate)
            {
                info!(
                    "Output config: {}Hz, {} channels (VoIP-optimized)",
                    rate, device_channels
                );
                return Ok(cpal::StreamConfig {
                    channels: device_channels,
                    sample_rate: rate,
                    buffer_size: cpal::BufferSize::Default,
                });
            }
        }

        // Fall back to default config
        info!(
            "Output config: {}Hz, {} channels (device default)",
            default_config.sample_rate(),
            device_channels
        );
        Ok(cpal::StreamConfig {
            channels: device_channels,
            sample_rate: default_config.sample_rate(),
            buffer_size: cpal::BufferSize::Default,
        })
    }

    /// Returns the name of the selected input device.
    pub fn input_device_name(&self) -> Option<&str> {
        self.input_device_name.as_deref()
    }

    /// Returns the name of the selected output device.
    pub fn output_device_name(&self) -> Option<&str> {
        self.output_device_name.as_deref()
    }

    /// Gets an output device by name, falling back to default if not found.
    pub fn get_output_device_by_name(&self, name: &str) -> AudioResult<cpal::Device> {
        let host = cpal::default_host();

        let devices = host
            .output_devices()
            .map_err(|e| AudioError::StreamError(format!("Failed to enumerate devices: {e}")))?;

        for device in devices {
            if get_device_name(&device).is_some_and(|device_name| device_name == name) {
                debug!("Using output device: {}", name);
                return Ok(device);
            }
        }

        warn!("Output device '{}' not found, using default", name);
        host.default_output_device()
            .ok_or(AudioError::NoOutputDevice)
    }
}

/// Gets device information (channels and sample rates).
fn get_device_info(device: &cpal::Device) -> (u16, Vec<u32>) {
    let mut channels = 1u16;
    let mut sample_rates = Vec::new();

    // Try input config first, then output
    if let Ok(configs) = device.supported_input_configs() {
        for config in configs {
            channels = channels.max(config.channels());
            let min = config.min_sample_rate();
            let max = config.max_sample_rate();
            // Add common sample rates within range
            for rate in [8000, 16000, 44100, 48000] {
                if rate >= min && rate <= max && !sample_rates.contains(&rate) {
                    sample_rates.push(rate);
                }
            }
        }
    } else if let Ok(configs) = device.supported_output_configs() {
        for config in configs {
            channels = channels.max(config.channels());
            let min = config.min_sample_rate();
            let max = config.max_sample_rate();
            for rate in [8000, 16000, 44100, 48000] {
                if rate >= min && rate <= max && !sample_rates.contains(&rate) {
                    sample_rates.push(rate);
                }
            }
        }
    }

    sample_rates.sort_unstable();
    (channels, sample_rates)
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_manager_creation() {
        let manager = DeviceManager::new();
        assert!(manager.input_device_name().is_none());
        assert!(manager.output_device_name().is_none());
    }

    #[test]
    fn test_set_devices() {
        let mut manager = DeviceManager::new();
        manager.set_input_device(Some("Test Input".to_string()));
        manager.set_output_device(Some("Test Output".to_string()));

        assert_eq!(manager.input_device_name(), Some("Test Input"));
        assert_eq!(manager.output_device_name(), Some("Test Output"));
    }

    #[test]
    fn test_list_input_devices() {
        let manager = DeviceManager::new();
        // This may fail on CI without audio hardware, so we just check it doesn't panic
        let result = manager.list_input_devices();
        // Result may be empty or error on headless systems
        if let Ok(devices) = result {
            for device in &devices {
                assert_eq!(device.device_type, AudioDeviceType::Input);
            }
        }
    }

    #[test]
    fn test_list_output_devices() {
        let manager = DeviceManager::new();
        // This may fail on CI without audio hardware, so we just check it doesn't panic
        let result = manager.list_output_devices();
        // Result may be empty or error on headless systems
        if let Ok(devices) = result {
            for device in &devices {
                assert_eq!(device.device_type, AudioDeviceType::Output);
            }
        }
    }

    #[test]
    fn test_default_device_manager() {
        let manager = DeviceManager::default();
        assert!(manager.input_device_name().is_none());
    }
}
