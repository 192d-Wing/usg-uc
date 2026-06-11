//! Android Oboe / AAudio duplex audio backend.
//!
//! On Android, microphone capture and speaker playback run through the
//! [Oboe](https://github.com/google/oboe) library (the `oboe` / `oboe-sys`
//! crates, which bundle and build Oboe's C++ source via the NDK). Oboe selects
//! the best low-latency native API available at runtime — **AAudio** on
//! Android 8.1+ and **OpenSL ES** on older devices — and exposes both as a
//! single callback-driven stream API.
//!
//! ## Duplex structure
//!
//! Unlike the iOS `VoiceProcessingIO` unit (one physical duplex audio unit),
//! Oboe models input and output as **two independent callback streams**. This
//! module pairs them inside a single [`OboeDuplexUnit`]:
//!
//! - **Input stream** (`Direction::Input`): a real-time input callback pushes
//!   captured mono `i16` PCM into the *capture ring buffer* that the I/O thread
//!   drains via [`CaptureSource::read`](crate::backend::CaptureSource::read).
//! - **Output stream** (`Direction::Output`): a real-time output callback
//!   drains the *playback ring buffer* (filled by the decode thread through
//!   [`PlaybackSink::take_producer`](crate::backend::PlaybackSink::take_producer))
//!   into the speaker buffer.
//!
//! Both callbacks are allocation-free and only touch their owned lock-free
//! ring-buffer endpoints and a few atomics, matching the real-time constraints
//! Oboe imposes on the audio callback.
//!
//! ## Sample format
//!
//! Streams are requested as **mono `i16`** at 48 kHz with
//! [`PerformanceMode::LowLatency`]. Oboe may negotiate a different sample rate;
//! the actual rate is read back from the opened stream and reported uniformly
//! to both directions. If a device rejects `i16`, Oboe falls back internally;
//! the callbacks always receive `i16` because the stream frame type is fixed at
//! compile time, so no `f32 ↔ i16` conversion is required on the hot path. (The
//! desktop/iOS backends convert from `f32` because their native APIs deliver
//! float; Oboe lets us request `i16` directly.)
//!
//! ## Duplex sharing
//!
//! [`create_capture`](crate::backend::create_capture) and
//! [`create_playback`](crate::backend::create_playback) are invoked
//! independently by the I/O and decode threads (and re-invoked on device
//! changes). A process-wide [`Weak`] owner ([`SHARED_UNIT`]) hands out the same
//! [`OboeDuplexUnit`] to both sides via an [`Arc`]; the two Oboe streams are
//! created and started once, on first use, and torn down only when **both** the
//! capture source and the playback sink have been dropped.
//!
//! ## Acoustic echo cancellation
//!
//! Oboe itself does **not** perform AEC. Android's hardware/platform AEC is a
//! separate `android.media.audiofx.AcousticEchoCanceler` `AudioEffect` attached
//! to the input session from the Java/Kotlin side, which this Rust backend does
//! not wire up. [`OboeCapture::is_vpio`] therefore returns `false` so the
//! pipeline keeps its **software AEC** active.
//!
//! ## App-shell responsibilities (NOT handled here)
//!
//! This module does not request permissions or configure the platform audio
//! routing. Before any call starts audio, the Android app shell MUST:
//!
//! - hold the **`RECORD_AUDIO`** runtime permission (capture fails / yields
//!   silence without it), and
//! - set `AudioManager` mode to **`MODE_IN_COMMUNICATION`** (and route to the
//!   appropriate device, e.g. earpiece/speaker/Bluetooth SCO) so the platform
//!   applies voice-call signal processing and echo-friendly routing.
//!
//! The Rust side assumes both are already in effect.

use crate::backend::{PlaybackHandle, PlaybackSink};
use crate::stream::Sample;
use crate::{AudioError, AudioResult};
use oboe::{
    AudioInputCallback, AudioInputStreamSafe, AudioOutputCallback, AudioOutputStreamSafe,
    AudioStream, AudioStreamAsync, AudioStreamBase, AudioStreamBuilder, DataCallbackResult, Input,
    Mono, Output, PerformanceMode, SharingMode,
};
use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer, Split};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tracing::{debug, info};

/// Ring buffer capacity in milliseconds (matches the CPAL / iOS-VPIO paths).
const RING_BUFFER_DURATION_MS: u32 = 500;

/// Default hardware sample rate request (Hz).
///
/// Oboe may negotiate a different rate; the actual negotiated rate is read back
/// from each opened stream and used everywhere.
const DESIRED_SAMPLE_RATE: i32 = 48_000;

/// Shared owner of the single Android duplex Oboe unit.
///
/// A [`Weak`] so the streams are dropped (and Oboe stops/closes them) once both
/// the capture and playback handles release their [`Arc`]. The next `create_*`
/// call rebuilds the unit.
static SHARED_UNIT: Mutex<Weak<OboeDuplexUnit>> = Mutex::new(Weak::new());

/// Returns the shared duplex Oboe unit, creating and starting it if needed.
///
/// Both [`create_android_capture`] and [`create_android_playback`] call this so
/// the two directions share one paired set of Oboe streams.
// The guard is held across `OboeDuplexUnit::new()` so two threads cannot race
// to build two units for the one physical device pair.
#[allow(clippy::significant_drop_tightening)]
fn shared_unit() -> AudioResult<Arc<OboeDuplexUnit>> {
    let mut guard = SHARED_UNIT.lock().map_err(|_| {
        AudioError::StreamError("Android Oboe shared-unit lock poisoned".to_string())
    })?;

    if let Some(existing) = guard.upgrade() {
        return Ok(existing);
    }

    let unit = Arc::new(OboeDuplexUnit::new()?);
    *guard = Arc::downgrade(&unit);
    Ok(unit)
}

/// Real-time input callback: pushes captured mono `i16` PCM into the capture
/// ring buffer the I/O thread reads.
///
/// Allocation-free: copies the delivered frames into the lock-free ring buffer
/// it owns and returns. On overflow (I/O thread momentarily behind) the excess
/// frames are dropped, matching the CPAL/iOS behaviour.
struct CaptureCallback {
    /// Producer end of the capture ring buffer (mic → app).
    producer: ringbuf::HeapProd<Sample>,
    /// Cleared by [`OboeDuplexUnit::stop`] to make the callback go silent.
    is_running: Arc<AtomicBool>,
    /// Set if Oboe reports an unrecoverable error on the input stream.
    device_error: Arc<AtomicBool>,
}

impl AudioInputCallback for CaptureCallback {
    type FrameType = (i16, Mono);

    fn on_audio_ready(
        &mut self,
        _stream: &mut dyn AudioInputStreamSafe,
        frames: &[i16],
    ) -> DataCallbackResult {
        if !self.is_running.load(Ordering::Relaxed) {
            return DataCallbackResult::Stop;
        }
        // Mono i16 frames map 1:1 to pipeline samples; batch-push into the ring.
        let _ = self.producer.push_slice(frames);
        DataCallbackResult::Continue
    }

    fn on_error_after_close(&mut self, _stream: &mut dyn AudioInputStreamSafe, error: oboe::Error) {
        self.device_error.store(true, Ordering::Relaxed);
        debug!(?error, "Android Oboe input stream error");
    }
}

/// Real-time output callback: drains the playback ring buffer into the speaker
/// buffer, holding/decaying the last sample on underrun to avoid clicks.
///
/// Allocation-free; mirrors the underrun handling of the CPAL and iOS paths.
struct PlaybackCallback {
    /// Consumer end of the playback ring buffer (app → speaker).
    consumer: ringbuf::HeapCons<Sample>,
    /// Cleared by [`OboeDuplexUnit::stop`] to make the callback emit silence.
    is_running: Arc<AtomicBool>,
    /// Set if Oboe reports an unrecoverable error on the output stream.
    device_error: Arc<AtomicBool>,
    /// Count of callbacks that underran the playback ring buffer.
    underrun_count: Arc<AtomicU64>,
    /// Last emitted sample, held (and decayed) across underruns.
    last_sample: i16,
}

impl AudioOutputCallback for PlaybackCallback {
    type FrameType = (i16, Mono);

    fn on_audio_ready(
        &mut self,
        _stream: &mut dyn AudioOutputStreamSafe,
        frames: &mut [i16],
    ) -> DataCallbackResult {
        if !self.is_running.load(Ordering::Relaxed) {
            frames.fill(0);
            return DataCallbackResult::Stop;
        }

        let read = self.consumer.pop_slice(frames);
        if read > 0 {
            self.last_sample = frames[read - 1];
        }
        if read < frames.len() {
            self.underrun_count.fetch_add(1, Ordering::Relaxed);
            // Hold and decay the last sample toward zero to avoid DC offset and
            // hard click artifacts on underrun.
            for s in &mut frames[read..] {
                *s = self.last_sample;
                self.last_sample = decay(self.last_sample);
            }
        }
        DataCallbackResult::Continue
    }

    fn on_error_after_close(
        &mut self,
        _stream: &mut dyn AudioOutputStreamSafe,
        error: oboe::Error,
    ) {
        self.device_error.store(true, Ordering::Relaxed);
        debug!(?error, "Android Oboe output stream error");
    }
}

/// Concrete Oboe input stream type produced by the builder for our frame type.
type OboeInputStream = AudioStreamAsync<Input, CaptureCallback>;

/// Concrete Oboe output stream type produced by the builder for our frame type.
type OboeOutputStream = AudioStreamAsync<Output, PlaybackCallback>;

/// The shared Android duplex Oboe unit.
///
/// Owns the paired input and output Oboe streams plus the ring-buffer endpoints
/// the callbacks do not hold:
/// - the **capture** consumer, read by the I/O thread via [`OboeCapture`];
/// - the **playback** producer, handed to the decode thread via
///   [`OboePlayback::take_producer`].
///
/// Both streams are started in [`OboeDuplexUnit::new`] and stopped/closed on
/// `Drop`.
struct OboeDuplexUnit {
    /// The Oboe input stream. Guarded by a `Mutex` only so the type is `Sync`
    /// for the static owner; locked exclusively during construction/teardown,
    /// never on the real-time audio path (the callback owns its ring endpoint).
    input_stream: Mutex<OboeInputStream>,
    /// The Oboe output stream. Same locking discipline as `input_stream`.
    output_stream: Mutex<OboeOutputStream>,
    /// Consumer end of the capture ring buffer (mic → app), read by the I/O
    /// thread. `Mutex` for `Sync`; only the single capture reader locks it.
    capture_consumer: Mutex<ringbuf::HeapCons<Sample>>,
    /// Producer end of the playback ring buffer (app → speaker), taken once by
    /// the decode thread. `None` after [`OboePlayback::take_producer`].
    playback_producer: Mutex<Option<ringbuf::HeapProd<Sample>>>,
    /// Negotiated sample rate (Hz), shared by both directions.
    sample_rate: u32,
    /// `true` while the unit is running.
    is_running: Arc<AtomicBool>,
    /// Set to `true` if either callback observes an error condition.
    device_error: Arc<AtomicBool>,
    /// Count of output callbacks that underran the playback ring buffer.
    underrun_count: Arc<AtomicU64>,
}

impl OboeDuplexUnit {
    /// Creates, configures, and starts the paired input + output Oboe streams.
    ///
    /// Assumes the app shell already holds `RECORD_AUDIO` and has set the
    /// `AudioManager` mode to `MODE_IN_COMMUNICATION` (see module docs).
    fn new() -> AudioResult<Self> {
        info!("Creating Android duplex Oboe unit (capture + playback)");

        let is_running = Arc::new(AtomicBool::new(true));
        let device_error = Arc::new(AtomicBool::new(false));
        let underrun_count = Arc::new(AtomicU64::new(0));

        // --- Input (capture) stream --------------------------------------
        let in_ring_capacity = ring_capacity_for(DESIRED_SAMPLE_RATE);
        let (capture_producer, capture_consumer) = HeapRb::<Sample>::new(in_ring_capacity).split();

        let input_cb = CaptureCallback {
            producer: capture_producer,
            is_running: is_running.clone(),
            device_error: device_error.clone(),
        };

        let mut input_stream = AudioStreamBuilder::default()
            .set_direction::<Input>()
            .set_performance_mode(PerformanceMode::LowLatency)
            .set_sharing_mode(SharingMode::Shared)
            .set_format::<i16>()
            .set_channel_count::<Mono>()
            .set_sample_rate(DESIRED_SAMPLE_RATE)
            .set_callback(input_cb)
            .open_stream()
            .map_err(|e| {
                AudioError::StreamError(format!("Failed to open Android Oboe input stream: {e}"))
            })?;

        #[allow(clippy::cast_sign_loss)]
        let capture_rate = input_stream.get_sample_rate() as u32;

        // --- Output (playback) stream ------------------------------------
        let out_ring_capacity = ring_capacity_for(DESIRED_SAMPLE_RATE);
        let (playback_producer, playback_consumer) =
            HeapRb::<Sample>::new(out_ring_capacity).split();

        let output_cb = PlaybackCallback {
            consumer: playback_consumer,
            is_running: is_running.clone(),
            device_error: device_error.clone(),
            underrun_count: underrun_count.clone(),
            last_sample: 0,
        };

        let mut output_stream = AudioStreamBuilder::default()
            .set_direction::<Output>()
            .set_performance_mode(PerformanceMode::LowLatency)
            .set_sharing_mode(SharingMode::Shared)
            .set_format::<i16>()
            .set_channel_count::<Mono>()
            .set_sample_rate(DESIRED_SAMPLE_RATE)
            .set_callback(output_cb)
            .open_stream()
            .map_err(|e| {
                AudioError::StreamError(format!("Failed to open Android Oboe output stream: {e}"))
            })?;

        #[allow(clippy::cast_sign_loss)]
        let playback_rate = output_stream.get_sample_rate() as u32;

        // Start both streams. On failure, the already-opened streams are
        // dropped (closed) as they go out of scope.
        input_stream.request_start().map_err(|e| {
            AudioError::StreamError(format!("Failed to start Android Oboe input stream: {e}"))
        })?;
        output_stream.request_start().map_err(|e| {
            AudioError::StreamError(format!("Failed to start Android Oboe output stream: {e}"))
        })?;

        // The pipeline assumes a single shared rate for both directions. Oboe
        // negotiates each stream independently; we report the input (capture)
        // rate, which the resampler keys off, and log any mismatch.
        if capture_rate != playback_rate {
            info!(
                capture_rate,
                playback_rate, "Android Oboe negotiated differing capture/playback rates"
            );
        }
        let sample_rate = capture_rate;

        info!(
            sample_rate,
            "Android Oboe duplex unit started (software AEC active)"
        );

        Ok(Self {
            input_stream: Mutex::new(input_stream),
            output_stream: Mutex::new(output_stream),
            capture_consumer: Mutex::new(capture_consumer),
            playback_producer: Mutex::new(Some(playback_producer)),
            sample_rate,
            is_running,
            device_error,
            underrun_count,
        })
    }

    /// Reads captured samples into `buf`, returning the number read.
    fn read_capture(&self, buf: &mut [Sample]) -> usize {
        self.capture_consumer
            .lock()
            .map_or(0, |mut c| c.pop_slice(buf))
    }

    /// Returns the number of captured samples available to read.
    fn capture_available(&self) -> usize {
        self.capture_consumer.lock().map_or(0, |c| c.occupied_len())
    }

    /// Takes the playback producer for hand-off to the decode thread.
    ///
    /// Returns `None` if it was already taken.
    fn take_playback_producer(&self) -> Option<ringbuf::HeapProd<Sample>> {
        self.playback_producer
            .lock()
            .ok()
            .and_then(|mut p| p.take())
    }

    /// Signals the callbacks to stop and stops the underlying Oboe streams.
    fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        if let Ok(mut s) = self.input_stream.lock() {
            let _ = s.request_stop();
        }
        if let Ok(mut s) = self.output_stream.lock() {
            let _ = s.request_stop();
        }
    }
}

impl Drop for OboeDuplexUnit {
    fn drop(&mut self) {
        self.stop();
        debug!("Android Oboe duplex unit dropped");
    }
}

/// Android capture source backed by the shared duplex Oboe unit.
///
/// Implements [`crate::backend::CaptureSource`]; reports `is_vpio() == false`
/// (Oboe does no AEC) so the pipeline keeps software AEC active.
pub struct OboeCapture {
    /// Shared duplex unit (kept alive while capturing).
    unit: Arc<OboeDuplexUnit>,
}

impl OboeCapture {
    /// Reads captured audio samples into `buf`; returns the count read.
    pub fn read(&mut self, buf: &mut [Sample]) -> usize {
        self.unit.read_capture(buf)
    }

    /// Returns the number of captured samples available to read.
    pub fn available(&self) -> usize {
        self.unit.capture_available()
    }

    /// Returns the negotiated capture sample rate in Hz.
    pub fn sample_rate(&self) -> u32 {
        self.unit.sample_rate
    }

    /// Returns whether the capture stream is running.
    pub fn is_running(&self) -> bool {
        self.unit.is_running.load(Ordering::Relaxed)
    }

    /// Returns `true` if a device error was observed.
    pub fn has_error(&self) -> bool {
        self.unit.device_error.load(Ordering::Relaxed)
    }

    /// Stops the capture stream (and the shared duplex unit).
    pub fn stop(&self) {
        self.unit.stop();
    }
}

/// Android playback sink backed by the shared duplex Oboe unit.
///
/// Implements [`PlaybackSink`]; [`take_producer`](PlaybackSink::take_producer)
/// hands the output callback's ring-buffer producer to the decode thread.
pub struct OboePlayback {
    /// Shared duplex unit (kept alive until the producer is taken).
    unit: Arc<OboeDuplexUnit>,
}

impl OboePlayback {
    /// Returns the negotiated playback sample rate in Hz.
    pub fn sample_rate(&self) -> u32 {
        self.unit.sample_rate
    }
}

impl PlaybackSink for OboePlayback {
    fn sample_rate(&self) -> u32 {
        self.unit.sample_rate
    }

    fn take_producer(
        self: Box<Self>,
    ) -> (
        Box<dyn PlaybackHandle>,
        ringbuf::HeapProd<Sample>,
        Arc<AtomicU64>,
    ) {
        let underruns = self.unit.underrun_count.clone();
        // The producer was created in `OboeDuplexUnit::new`; it is present
        // unless a prior hand-off already took it. If somehow absent, fall back
        // to a detached ring so the decode thread still has a valid producer
        // (its output is simply not rendered).
        let producer = self.unit.take_playback_producer().unwrap_or_else(|| {
            HeapRb::<Sample>::new(ring_capacity_for(DESIRED_SAMPLE_RATE).max(1))
                .split()
                .0
        });
        let handle = OboePlaybackHandle {
            unit: self.unit.clone(),
        };
        (Box::new(handle), producer, underruns)
    }
}

/// Handle to the running Android playback after the producer hand-off.
///
/// Keeps the shared duplex unit alive and provides stop/metadata.
pub struct OboePlaybackHandle {
    /// Shared duplex unit (kept alive for the call's duration).
    unit: Arc<OboeDuplexUnit>,
}

impl PlaybackHandle for OboePlaybackHandle {
    fn sample_rate(&self) -> u32 {
        self.unit.sample_rate
    }

    fn is_running(&self) -> bool {
        self.unit.is_running.load(Ordering::Relaxed)
    }

    fn has_error(&self) -> bool {
        self.unit.device_error.load(Ordering::Relaxed)
    }

    fn stop(&self) {
        self.unit.stop();
    }
}

/// Creates the Android Oboe capture source over the shared duplex unit.
pub fn create_android_capture() -> AudioResult<OboeCapture> {
    Ok(OboeCapture {
        unit: shared_unit()?,
    })
}

/// Creates the Android Oboe playback sink over the shared duplex unit.
pub fn create_android_playback() -> AudioResult<OboePlayback> {
    Ok(OboePlayback {
        unit: shared_unit()?,
    })
}

/// Ring-buffer capacity (in samples) for [`RING_BUFFER_DURATION_MS`] at `rate`.
#[allow(clippy::cast_sign_loss)]
const fn ring_capacity_for(rate: i32) -> usize {
    (rate as usize * RING_BUFFER_DURATION_MS as usize) / 1000
}

/// Decays an `i16` sample toward zero (used to soften playback underruns).
#[inline]
#[allow(clippy::cast_possible_truncation)]
const fn decay(sample: i16) -> i16 {
    (sample as i32 * 255 / 256) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_capacity_scales_with_rate() {
        assert_eq!(ring_capacity_for(48_000), 24_000);
        assert_eq!(ring_capacity_for(8_000), 4_000);
    }

    #[test]
    fn decay_moves_toward_zero() {
        assert_eq!(decay(0), 0);
        assert!(decay(1000) < 1000);
        assert!(decay(1000) >= 0);
        assert!(decay(-1000) > -1000);
        assert!(decay(-1000) <= 0);
    }

    #[test]
    fn decay_endpoints_stable() {
        // Small magnitudes decay all the way to zero without overshoot.
        assert_eq!(decay(1), 0);
        assert_eq!(decay(-1), 0);
    }
}
