//! iOS Voice Processing I/O (VPIO) duplex audio backend.
//!
//! On iOS, both microphone capture **and** speaker playback go through a
//! single `CoreAudio` `kAudioUnitSubType_VoiceProcessingIO` audio unit (the
//! voice-processing variant of `RemoteIO`). Routing both directions through
//! the same unit is what enables the OS to perform hardware acoustic echo
//! cancellation (AEC): the unit knows exactly what is being rendered to the
//! speaker and removes it from the captured microphone signal, giving
//! full-duplex conversation without software AEC.
//!
//! ## Bus / element layout
//!
//! A `VoiceProcessingIO` unit (like `RemoteIO`) has two elements:
//!
//! - **Element 0 (bus 0) — output**: audio flows *app → hardware speaker*.
//!   We install a *render callback* on the input scope of element 0; the OS
//!   pulls playback PCM from it. The callback drains the playback ring buffer
//!   that the decode thread fills.
//! - **Element 1 (bus 1) — input**: audio flows *hardware mic → app*. We
//!   install an *input callback* on element 1; it pushes echo-cancelled
//!   captured PCM into the capture ring buffer that the I/O thread reads.
//!
//! Input must be explicitly enabled on element 1 (output is enabled by
//! default).
//!
//! ## Sample format
//!
//! Both directions are configured as **interleaved mono `f32`** at the
//! hardware sample rate, and converted to/from the pipeline's `i16` mono
//! samples exactly as the macOS [`crate::vpio`] backend does
//! (`f32 ↔ i16`, clamped).
//!
//! ## Duplex sharing
//!
//! `create_capture` and `create_playback` are invoked independently by the
//! I/O and decode threads (and re-invoked on device changes). Since there is
//! only one physical duplex unit, a process-wide shared owner
//! ([`shared_unit`]) hands out the same [`IosVpioUnit`] to both sides via an
//! [`Arc`]. The unit is created (and started) once, on first use, and is torn
//! down only when **both** the capture source and the playback sink have been
//! dropped.
//!
//! ## `AVAudioSession` requirement (app shell responsibility)
//!
//! This module does **NOT** configure or activate the audio session. Before
//! any call starts audio, the Swift app shell MUST configure `AVAudioSession`:
//!
//! - category `.playAndRecord`
//! - mode `.voiceChat`
//! - activate the session (`setActive(true)`)
//!
//! The Rust side assumes the session is already configured and active; without
//! it, unit creation/start will fail or produce silence. `coreaudio-rs`'s iOS
//! input-callback path also reads the session's current hardware buffer
//! duration and sample rate, which requires an active session.

use crate::backend::{PlaybackHandle, PlaybackSink};
use crate::stream::Sample;
use crate::{AudioError, AudioResult};
use coreaudio::audio_unit::audio_format::LinearPcmFlags;
use coreaudio::audio_unit::render_callback::{self, data};
use coreaudio::audio_unit::{AudioUnit, Element, IOType, SampleFormat, Scope, StreamFormat};
use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer, Split};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tracing::{debug, info};

/// `CoreAudio` property: enable/disable I/O on a bus.
/// (`kAudioOutputUnitProperty_EnableIO`)
const KAUDIO_OUTPUT_UNIT_PROPERTY_ENABLE_IO: u32 = 2003;

/// Ring buffer capacity in milliseconds (matches the CPAL/macOS-VPIO paths).
const RING_BUFFER_DURATION_MS: u32 = 500;

/// Default hardware sample rate request (Hz).
///
/// VPIO typically negotiates 48 kHz on modern iOS hardware; we read back the
/// actual negotiated rate after initialization and use that everywhere.
const DESIRED_SAMPLE_RATE: f64 = 48_000.0;

/// Shared owner of the single iOS duplex VPIO unit.
///
/// A [`Weak`] so the unit is dropped (and the `CoreAudio` unit stopped) once
/// both the capture and playback handles release their [`Arc`]. The next
/// `create_*` call rebuilds it.
static SHARED_UNIT: Mutex<Weak<IosVpioUnit>> = Mutex::new(Weak::new());

/// Returns the shared duplex VPIO unit, creating and starting it if needed.
///
/// Both [`create_ios_capture`] and [`create_ios_playback`] call this so the
/// two directions share one physical unit (required for hardware AEC).
// The guard is intentionally held across `IosVpioUnit::new()` so two threads
// cannot race to build two units for the one physical device.
#[allow(clippy::significant_drop_tightening)]
fn shared_unit() -> AudioResult<Arc<IosVpioUnit>> {
    let mut guard = SHARED_UNIT
        .lock()
        .map_err(|_| AudioError::StreamError("iOS VPIO shared-unit lock poisoned".to_string()))?;

    if let Some(existing) = guard.upgrade() {
        return Ok(existing);
    }

    let unit = Arc::new(IosVpioUnit::new()?);
    *guard = Arc::downgrade(&unit);
    Ok(unit)
}

/// Builds an interleaved mono `f32` linear-PCM stream format at `sample_rate`.
const fn mono_f32_format(sample_rate: f64) -> StreamFormat {
    StreamFormat {
        sample_rate,
        sample_format: SampleFormat::F32,
        // Interleaved (NON_INTERLEAVED clear); packing is added by `to_asbd`.
        flags: LinearPcmFlags::IS_FLOAT,
        channels: 1,
    }
}

/// The shared iOS duplex `VoiceProcessingIO` unit.
///
/// Owns the `CoreAudio` audio unit plus both ring-buffer endpoints:
/// - the **capture** consumer, read by the I/O thread via [`IosVpioCapture`];
/// - the **playback** producer, handed to the decode thread via
///   [`IosVpioPlayback::take_producer`].
///
/// The unit is started in [`IosVpioUnit::new`] and stopped on `Drop`.
struct IosVpioUnit {
    /// The `CoreAudio` VPIO unit. Owns the real-time input/render callbacks.
    ///
    /// Guarded by a `Mutex` only so the type is `Sync` for the static owner;
    /// it is locked exclusively during construction/teardown, never on the
    /// real-time audio path (the callbacks own their ring-buffer endpoints
    /// directly and do not touch this field).
    audio_unit: Mutex<AudioUnit>,
    /// Consumer end of the capture ring buffer (mic → app), read by the
    /// I/O thread. `Mutex` for `Sync`; only the single capture reader locks it.
    capture_consumer: Mutex<ringbuf::HeapCons<Sample>>,
    /// Producer end of the playback ring buffer (app → speaker), taken once by
    /// the decode thread. `None` after [`IosVpioPlayback::take_producer`].
    playback_producer: Mutex<Option<ringbuf::HeapProd<Sample>>>,
    /// Negotiated hardware sample rate (Hz), shared by both directions.
    sample_rate: u32,
    /// `true` while the unit is running.
    is_running: Arc<AtomicBool>,
    /// Set to `true` if a callback observes an error condition.
    device_error: Arc<AtomicBool>,
    /// Count of render callbacks that underran the playback ring buffer.
    underrun_count: Arc<AtomicU64>,
}

// SAFETY: `AudioUnit` wraps a raw `CoreAudio` instance pointer. The audio unit
// and its callbacks are owned exclusively by this struct; the real-time
// callbacks operate only on the ring-buffer endpoints (themselves `Send`),
// and the `AudioUnit` handle itself is only accessed under its `Mutex` during
// construction and teardown. Sharing the `Arc<IosVpioUnit>` across the I/O and
// decode threads is therefore sound.
#[allow(unsafe_code)]
unsafe impl Send for IosVpioUnit {}
#[allow(unsafe_code)]
unsafe impl Sync for IosVpioUnit {}

#[allow(unsafe_code)]
impl IosVpioUnit {
    /// Creates, configures, and starts the duplex VPIO unit.
    ///
    /// Assumes `AVAudioSession` has already been configured and activated by
    /// the app shell (see the module-level documentation).
    fn new() -> AudioResult<Self> {
        info!("Creating iOS duplex VPIO unit (hardware AEC, capture + playback)");

        // Create the VoiceProcessingIO unit. `new()` auto-initializes, but we
        // must configure I/O enable + stream formats before initialization, so
        // uninitialize → configure → reinitialize.
        let mut audio_unit = AudioUnit::new(IOType::VoiceProcessingIO)
            .map_err(|e| AudioError::StreamError(format!("Failed to create iOS VPIO unit: {e}")))?;

        audio_unit.uninitialize().map_err(|e| {
            AudioError::StreamError(format!("Failed to uninitialize iOS VPIO: {e}"))
        })?;

        // Enable input on element 1 (mic → app). Output on element 0 is
        // enabled by default on a RemoteIO/VPIO unit.
        let enable: u32 = 1;
        audio_unit
            .set_property(
                KAUDIO_OUTPUT_UNIT_PROPERTY_ENABLE_IO,
                Scope::Input,
                Element::Input,
                Some(&enable),
            )
            .map_err(|e| {
                AudioError::StreamError(format!("Failed to enable iOS VPIO input: {e}"))
            })?;

        // Request 48 kHz on both elements; VPIO may override. We re-read the
        // negotiated rate after initialization.
        let desired = mono_f32_format(DESIRED_SAMPLE_RATE);
        // Format the app receives from the input element (mic side): output
        // scope of element 1.
        if let Err(e) = audio_unit.set_stream_format(desired, Scope::Output, Element::Input) {
            info!("iOS VPIO rejected requested input format: {e}, using device default");
        }
        // Format the app supplies to the output element (speaker side): input
        // scope of element 0.
        if let Err(e) = audio_unit.set_stream_format(desired, Scope::Input, Element::Output) {
            info!("iOS VPIO rejected requested output format: {e}, using device default");
        }

        audio_unit
            .initialize()
            .map_err(|e| AudioError::StreamError(format!("Failed to initialize iOS VPIO: {e}")))?;

        // Read back the negotiated input format (authoritative sample rate).
        let in_fmt = audio_unit.input_stream_format().map_err(|e| {
            AudioError::StreamError(format!("Failed to get iOS VPIO input format: {e}"))
        })?;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let sample_rate = in_fmt.sample_rate as u32;
        let capture_channels = in_fmt.channels as usize;

        let out_fmt = audio_unit.output_stream_format().map_err(|e| {
            AudioError::StreamError(format!("Failed to get iOS VPIO output format: {e}"))
        })?;
        let playback_channels = out_fmt.channels as usize;

        info!(
            sample_rate = sample_rate,
            capture_channels = capture_channels,
            playback_channels = playback_channels,
            "iOS VPIO duplex stream format negotiated"
        );

        // Allocate ring buffers (same sizing as the CPAL/macOS paths).
        let ring_capacity = (sample_rate * RING_BUFFER_DURATION_MS / 1000) as usize;
        let (capture_producer, capture_consumer) = HeapRb::<Sample>::new(ring_capacity).split();
        let (playback_producer, playback_consumer) = HeapRb::<Sample>::new(ring_capacity).split();

        let is_running = Arc::new(AtomicBool::new(true));
        let device_error = Arc::new(AtomicBool::new(false));
        let underrun_count = Arc::new(AtomicU64::new(0));

        Self::install_input_callback(
            &mut audio_unit,
            capture_producer,
            capture_channels,
            &is_running,
        )?;
        Self::install_render_callback(
            &mut audio_unit,
            playback_consumer,
            playback_channels,
            &is_running,
            &underrun_count,
        )?;

        audio_unit
            .start()
            .map_err(|e| AudioError::StreamError(format!("Failed to start iOS VPIO: {e}")))?;

        info!(
            sample_rate = sample_rate,
            "iOS VPIO duplex unit started (hardware AEC active)"
        );

        Ok(Self {
            audio_unit: Mutex::new(audio_unit),
            capture_consumer: Mutex::new(capture_consumer),
            playback_producer: Mutex::new(Some(playback_producer)),
            sample_rate,
            is_running,
            device_error,
            underrun_count,
        })
    }

    /// Installs the mic-side input callback (element 1) that pushes captured,
    /// echo-cancelled PCM into the capture ring buffer.
    ///
    /// The callback is allocation-free: it converts `f32 → i16` in place and
    /// pushes into the lock-free ring buffer it owns.
    fn install_input_callback(
        audio_unit: &mut AudioUnit,
        mut producer: ringbuf::HeapProd<Sample>,
        channels: usize,
        is_running: &Arc<AtomicBool>,
    ) -> AudioResult<()> {
        let is_running = is_running.clone();
        audio_unit
            .set_input_callback(move |args: render_callback::Args<data::Interleaved<f32>>| {
                if !is_running.load(Ordering::Relaxed) {
                    return Err(());
                }
                let samples = args.data.buffer;
                if channels == 1 {
                    for &s in samples.iter() {
                        let _ = producer.try_push(f32_to_i16(s));
                    }
                } else {
                    for chunk in samples.chunks(channels) {
                        let sum: f32 = chunk.iter().copied().sum();
                        #[allow(clippy::cast_precision_loss)]
                        let mono = sum / channels as f32;
                        let _ = producer.try_push(f32_to_i16(mono));
                    }
                }
                Ok(())
            })
            .map_err(|e| {
                AudioError::StreamError(format!("Failed to set iOS VPIO input callback: {e}"))
            })
    }

    /// Installs the speaker-side render callback (element 0) that fills the
    /// output buffer from the playback ring buffer (`i16 → f32`).
    ///
    /// Allocation-free: on underrun it holds/decays the last sample to avoid
    /// click artifacts, matching the CPAL playback path.
    fn install_render_callback(
        audio_unit: &mut AudioUnit,
        mut consumer: ringbuf::HeapCons<Sample>,
        channels: usize,
        is_running: &Arc<AtomicBool>,
        underrun_count: &Arc<AtomicU64>,
    ) -> AudioResult<()> {
        let is_running = is_running.clone();
        let underrun_count = underrun_count.clone();
        let mut last_sample: f32 = 0.0;
        audio_unit
            .set_render_callback(move |args: render_callback::Args<data::Interleaved<f32>>| {
                let buffer = args.data.buffer;
                if !is_running.load(Ordering::Relaxed) {
                    buffer.fill(0.0);
                    return Ok(());
                }

                let mut had_underrun = false;
                for frame in buffer.chunks_mut(channels) {
                    if let Some(s) = consumer.try_pop() {
                        last_sample = i16_to_f32(s);
                    } else {
                        had_underrun = true;
                        // Decay toward zero to avoid DC offset / hard clicks.
                        last_sample *= 255.0 / 256.0;
                    }
                    frame.fill(last_sample);
                }

                if had_underrun {
                    underrun_count.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            })
            .map_err(|e| {
                AudioError::StreamError(format!("Failed to set iOS VPIO render callback: {e}"))
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

    /// Signals the callbacks to stop and stops the underlying unit.
    fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
        if let Ok(mut unit) = self.audio_unit.lock() {
            let _ = unit.stop();
        }
    }
}

impl Drop for IosVpioUnit {
    fn drop(&mut self) {
        self.stop();
        debug!("iOS VPIO duplex unit dropped");
    }
}

/// iOS capture source backed by the shared duplex VPIO unit.
///
/// Implements [`crate::backend::CaptureSource`]; reports `is_vpio() == true`
/// so the pipeline skips software AEC (the unit does it in hardware).
pub struct IosVpioCapture {
    /// Shared duplex unit (kept alive while capturing).
    unit: Arc<IosVpioUnit>,
}

impl IosVpioCapture {
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

/// iOS playback sink backed by the shared duplex VPIO unit.
///
/// Implements [`PlaybackSink`]; [`take_producer`](PlaybackSink::take_producer)
/// hands the render-callback's ring-buffer producer to the decode thread.
pub struct IosVpioPlayback {
    /// Shared duplex unit (kept alive until the producer is taken).
    unit: Arc<IosVpioUnit>,
}

impl IosVpioPlayback {
    /// Returns the negotiated playback sample rate in Hz.
    pub fn sample_rate(&self) -> u32 {
        self.unit.sample_rate
    }
}

impl PlaybackSink for IosVpioPlayback {
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
        // The producer was created in `IosVpioUnit::new`; it is present unless
        // a prior hand-off already took it. If somehow absent, fall back to a
        // detached ring so the decode thread still has a valid producer (its
        // output is simply not rendered).
        let producer = self.unit.take_playback_producer().unwrap_or_else(|| {
            let ring_capacity = (self.unit.sample_rate * RING_BUFFER_DURATION_MS / 1000) as usize;
            HeapRb::<Sample>::new(ring_capacity.max(1)).split().0
        });
        let handle = IosVpioPlaybackHandle {
            unit: self.unit.clone(),
        };
        (Box::new(handle), producer, underruns)
    }
}

/// Handle to the running iOS playback after the producer hand-off.
///
/// Keeps the shared duplex unit alive and provides stop/metadata.
pub struct IosVpioPlaybackHandle {
    /// Shared duplex unit (kept alive for the call's duration).
    unit: Arc<IosVpioUnit>,
}

impl PlaybackHandle for IosVpioPlaybackHandle {
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

/// Creates the iOS VPIO capture source over the shared duplex unit.
pub fn create_ios_capture() -> AudioResult<IosVpioCapture> {
    Ok(IosVpioCapture {
        unit: shared_unit()?,
    })
}

/// Creates the iOS VPIO playback sink over the shared duplex unit.
pub fn create_ios_playback() -> AudioResult<IosVpioPlayback> {
    Ok(IosVpioPlayback {
        unit: shared_unit()?,
    })
}

/// Converts an `f32` sample in `[-1.0, 1.0]` to `i16` (clamped).
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn f32_to_i16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * f32::from(i16::MAX)) as i16
}

/// Converts an `i16` sample to `f32` in `[-1.0, 1.0]`.
#[inline]
fn i16_to_f32(sample: i16) -> f32 {
    f32::from(sample) / f32::from(i16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_i16_roundtrip_endpoints() {
        assert_eq!(f32_to_i16(0.0), 0);
        assert_eq!(f32_to_i16(1.0), i16::MAX);
        assert_eq!(f32_to_i16(-1.0), -i16::MAX);
    }

    #[test]
    fn f32_to_i16_clamps_out_of_range() {
        assert_eq!(f32_to_i16(2.0), i16::MAX);
        assert_eq!(f32_to_i16(-2.0), -i16::MAX);
    }

    #[test]
    fn i16_to_f32_endpoints() {
        assert!((i16_to_f32(0) - 0.0).abs() < 0.001);
        assert!((i16_to_f32(i16::MAX) - 1.0).abs() < 0.001);
        assert!((i16_to_f32(-i16::MAX) + 1.0).abs() < 0.001);
    }

    #[test]
    fn mono_f32_format_is_interleaved_mono_float() {
        let fmt = mono_f32_format(48_000.0);
        assert_eq!(fmt.channels, 1);
        assert!((fmt.sample_rate - 48_000.0).abs() < f64::EPSILON);
        assert!(fmt.flags.contains(LinearPcmFlags::IS_FLOAT));
        assert!(!fmt.flags.contains(LinearPcmFlags::IS_NON_INTERLEAVED));
    }
}
