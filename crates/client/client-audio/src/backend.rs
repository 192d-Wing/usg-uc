//! Platform audio backend abstraction.
//!
//! Device I/O (microphone capture and speaker playback) sits behind the
//! [`CaptureSource`], [`PlaybackSink`], and [`PlaybackHandle`] traits so the
//! DSP core (codecs, jitter buffer, AEC, resampler, PLC, DTMF) never touches
//! a concrete device API. The I/O and decode threads hold trait objects and
//! interact with devices exclusively through these traits.
//!
//! ## Current backends
//!
//! Desktop platforms use the CPAL-based implementations in [`crate::stream`]:
//!
//! - Capture: [`CaptureBackend`], which selects macOS VPIO (hardware AEC)
//!   for the built-in mic and falls back to CPAL otherwise. The VPIO
//!   selection logic lives inside [`CaptureBackend::new`].
//! - Playback: [`PlaybackStream`] / [`PlaybackStreamHandle`].
//!
//! ## Adding a platform backend (iOS / Android)
//!
//! Future mobile backends — iOS `AudioUnit` VPIO
//! (`kAudioUnitSubType_VoiceProcessingIO`) and Android Oboe/AAudio — plug in
//! here: implement [`CaptureSource`] and [`PlaybackSink`] over the platform
//! callback API (feeding the same ring-buffer boundary CPAL uses today) and
//! return them from [`create_capture`] / [`create_playback`] under the
//! appropriate `cfg(target_os = ...)`. The DSP core and the I/O/decode
//! threads require no changes.

use crate::AudioResult;
use crate::device::DeviceManager;
use crate::stream::{CaptureBackend, PlaybackStream, PlaybackStreamHandle, Sample};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

/// A source of captured (microphone) audio samples.
///
/// Implementations are backed by a platform audio callback that fills a ring
/// buffer; the I/O thread pulls samples from it at frame intervals.
pub trait CaptureSource: Send {
    /// Reads captured audio samples into `buf`.
    ///
    /// Returns the number of samples read (may be less than `buf.len()` on
    /// capture underrun).
    fn read(&mut self, buf: &mut [i16]) -> usize;

    /// Returns the number of samples available to read.
    fn available(&self) -> usize;

    /// Returns the capture sample rate in Hz.
    fn sample_rate(&self) -> u32;

    /// Returns whether the stream is running.
    fn is_running(&self) -> bool;

    /// Returns `true` if the device errored (e.g., disconnect).
    fn has_error(&self) -> bool;

    /// Stops the capture stream.
    fn stop(&self);

    /// Returns `true` if hardware echo cancellation (VPIO) is active.
    ///
    /// When this returns `true`, the pipeline skips software AEC.
    fn is_vpio(&self) -> bool {
        false
    }
}

/// A freshly created playback (speaker) stream, prior to producer hand-off.
///
/// The decode thread takes ownership of the ring-buffer producer via
/// [`PlaybackSink::take_producer`]; the platform audio callback keeps the
/// consumer and drains it in real time.
pub trait PlaybackSink: Send {
    /// Returns the playback sample rate in Hz.
    fn sample_rate(&self) -> u32;

    /// Splits the sink into a handle, ring-buffer producer, and underrun counter.
    ///
    /// The producer is moved to the decode thread while the platform stream
    /// (and its consumer) continues running. The underrun counter is shared
    /// with the platform audio callback and tracks how many callbacks had
    /// buffer underruns.
    fn take_producer(
        self: Box<Self>,
    ) -> (
        Box<dyn PlaybackHandle>,
        ringbuf::HeapProd<Sample>,
        Arc<AtomicU64>,
    );
}

/// Handle to a running playback stream after the producer has been extracted.
///
/// Keeps the platform stream alive and provides stop/metadata functionality.
pub trait PlaybackHandle: Send {
    /// Returns the playback sample rate in Hz.
    fn sample_rate(&self) -> u32;

    /// Returns whether the stream is running.
    fn is_running(&self) -> bool;

    /// Returns `true` if the device errored (e.g., disconnect).
    fn has_error(&self) -> bool;

    /// Stops the playback stream.
    fn stop(&self);
}

impl CaptureSource for CaptureBackend {
    fn read(&mut self, buf: &mut [i16]) -> usize {
        Self::read(self, buf)
    }

    fn available(&self) -> usize {
        Self::available(self)
    }

    fn sample_rate(&self) -> u32 {
        Self::sample_rate(self)
    }

    fn is_running(&self) -> bool {
        Self::is_running(self)
    }

    fn has_error(&self) -> bool {
        Self::has_error(self)
    }

    fn stop(&self) {
        Self::stop(self);
    }

    fn is_vpio(&self) -> bool {
        Self::is_vpio(self)
    }
}

impl PlaybackSink for PlaybackStream {
    fn sample_rate(&self) -> u32 {
        Self::sample_rate(self)
    }

    fn take_producer(
        self: Box<Self>,
    ) -> (
        Box<dyn PlaybackHandle>,
        ringbuf::HeapProd<Sample>,
        Arc<AtomicU64>,
    ) {
        let (handle, producer, underruns) = Self::take_producer(*self);
        (Box::new(handle), producer, underruns)
    }
}

impl PlaybackHandle for PlaybackStreamHandle {
    fn sample_rate(&self) -> u32 {
        Self::sample_rate(self)
    }

    fn is_running(&self) -> bool {
        Self::is_running(self)
    }

    fn has_error(&self) -> bool {
        Self::has_error(self)
    }

    fn stop(&self) {
        Self::stop(self);
    }
}

/// Creates the platform capture backend for the current target.
///
/// Today this wraps [`CaptureBackend::new`] (CPAL, with macOS VPIO selection
/// kept inside it). iOS (`AudioUnit` VPIO) and Android (Oboe) backends plug
/// in here behind `cfg(target_os = ...)` without touching the DSP core.
pub fn create_capture(device_manager: &DeviceManager) -> AudioResult<Box<dyn CaptureSource>> {
    Ok(Box::new(CaptureBackend::new(device_manager)?))
}

/// Creates the platform playback backend for the current target.
///
/// Today this wraps [`PlaybackStream::new`] (CPAL). iOS (`AudioUnit`) and
/// Android (Oboe) backends plug in here behind `cfg(target_os = ...)`
/// without touching the DSP core.
pub fn create_playback(device_manager: &DeviceManager) -> AudioResult<Box<dyn PlaybackSink>> {
    Ok(Box::new(PlaybackStream::new(device_manager)?))
}
