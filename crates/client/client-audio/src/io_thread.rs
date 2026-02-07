//! Dedicated I/O thread for RTP receive, mic capture, and RTP send.
//!
//! This thread handles all network and capture I/O on a dedicated
//! `std::thread`, avoiding tokio cooperative scheduling delays.
//! It reads from the capture ring buffer (filled by CPAL callback),
//! resamples, encodes, and sends via the UDP socket. Simultaneously,
//! it receives RTP packets from the socket and pushes them into the
//! shared jitter buffer for the decode thread.

use crate::audio_processing::AudioProcessor;
use crate::codec::CodecPipeline;
use crate::decode_thread::DecodeCommand;
use crate::file_source::FileAudioSource;
use crate::pipeline::{PipelineStats, resample};
use crate::rtcp_session::RtcpSession;
use crate::rtp_handler::{RtpReceiver, RtpTransmitter};
use crate::stream::CaptureStream;
use crate::vad::{VadDecision, VoiceActivityDetector};
use client_types::{CodecPreference, DtmfDigit, DtmfEvent};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};
use crate::dtmf_tones::DtmfToneGenerator;

/// DTMF command sent from the main thread to the I/O thread.
pub struct DtmfCommand {
    /// The DTMF digit to send.
    pub digit: DtmfDigit,
    /// Duration of the tone in milliseconds.
    pub duration_ms: u32,
    /// Whether to send RFC 2833 telephone-event packets (true) or in-band only (false).
    pub use_rfc2833: bool,
}

/// Command sent from the main thread to the I/O thread.
pub enum IoCommand {
    /// Send a DTMF digit.
    Dtmf(DtmfCommand),
    /// Switch the capture (input) device. `None` = system default.
    SwitchInputDevice(Option<String>),
}

/// Handle to the running I/O thread.
///
/// When dropped, signals the thread to stop and joins it.
pub struct IoThreadHandle {
    /// The thread join handle.
    thread: Option<thread::JoinHandle<()>>,
    /// Shared running flag.
    running: Arc<AtomicBool>,
    /// Channel to send commands to the I/O thread.
    cmd_tx: mpsc::Sender<IoCommand>,
}

impl IoThreadHandle {
    /// Sends a DTMF digit via the I/O thread.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to send
    /// * `duration_ms` - Duration in milliseconds
    /// * `use_rfc2833` - Whether to send RFC 2833 packets (if false, in-band only)
    pub fn send_dtmf(&self, digit: DtmfDigit, duration_ms: u32, use_rfc2833: bool) {
        let cmd = DtmfCommand {
            digit,
            duration_ms,
            use_rfc2833,
        };
        if let Err(e) = self.cmd_tx.send(IoCommand::Dtmf(cmd)) {
            warn!("Failed to send DTMF command: {e}");
        }
    }

    /// Switches the capture (input) device during an active call.
    pub fn switch_input_device(&self, device_name: Option<String>) {
        if let Err(e) = self.cmd_tx.send(IoCommand::SwitchInputDevice(device_name)) {
            warn!("Failed to send device switch command: {e}");
        }
    }

    /// Stops the I/O thread and waits for it to finish.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.thread.take()
            && let Err(e) = handle.join()
        {
            warn!("I/O thread panicked: {e:?}");
        }
    }
}

impl Drop for IoThreadHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Configuration for the I/O thread.
pub struct IoThreadConfig {
    /// Codec preference for creating the encode pipeline.
    pub codec: CodecPreference,
    /// Capture (microphone) sample rate (e.g., 16000 for Bluetooth HFP).
    pub capture_rate: u32,
    /// RTCP socket (bound to local port, for sending RTCP reports).
    pub rtcp_socket: Option<Arc<UdpSocket>>,
    /// Remote RTCP address (remote RTP port + 1).
    pub rtcp_remote_addr: Option<SocketAddr>,
    /// Local SSRC (for RTCP reports).
    pub local_ssrc: u32,
}

/// Spawns the I/O thread.
///
/// # Arguments
/// * `config` - I/O thread configuration
/// * `transmitter` - RTP transmitter for sending packets
/// * `receiver` - RTP receiver for receiving packets
/// * `capture` - Capture stream for reading microphone audio
/// * `moh_source` - Optional Music on Hold audio source
/// * `muted` - Shared mute flag
/// * `moh_active` - Shared MOH active flag
/// * `stats` - Shared statistics
/// * `running` - Shared flag to signal shutdown
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    config: IoThreadConfig,
    transmitter: RtpTransmitter,
    receiver: RtpReceiver,
    capture: CaptureStream,
    moh_source: Option<FileAudioSource>,
    muted: Arc<AtomicBool>,
    moh_active: Arc<AtomicBool>,
    stats: Arc<Mutex<PipelineStats>>,
    running: Arc<AtomicBool>,
    decode_cmd_tx: Option<mpsc::Sender<DecodeCommand>>,
) -> IoThreadHandle {
    let running_clone = running.clone();
    let (cmd_tx, cmd_rx) = mpsc::channel();

    let handle = thread::Builder::new()
        .name("audio-io".to_string())
        .spawn(move || {
            info!("I/O thread started");
            io_loop(
                config,
                transmitter,
                receiver,
                capture,
                moh_source,
                muted,
                moh_active,
                stats,
                &running_clone,
                cmd_rx,
                decode_cmd_tx,
            );
            info!("I/O thread exited");
        });

    let thread = match handle {
        Ok(h) => Some(h),
        Err(e) => {
            warn!("Failed to spawn I/O thread: {e}");
            None
        }
    };

    IoThreadHandle {
        thread,
        running,
        cmd_tx,
    }
}

/// Main I/O loop.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]
fn io_loop(
    config: IoThreadConfig,
    mut transmitter: RtpTransmitter,
    mut receiver: RtpReceiver,
    mut capture: CaptureStream,
    mut moh_source: Option<FileAudioSource>,
    muted: Arc<AtomicBool>,
    moh_active: Arc<AtomicBool>,
    stats: Arc<Mutex<PipelineStats>>,
    running: &AtomicBool,
    cmd_rx: mpsc::Receiver<IoCommand>,
    decode_cmd_tx: Option<mpsc::Sender<DecodeCommand>>,
) {
    // Create codec pipeline for encoding (each thread owns its own)
    let mut codec = match CodecPipeline::new(config.codec) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create codec in I/O thread: {e}");
            return;
        }
    };

    let codec_clock_rate = codec.clock_rate();
    let codec_samples = codec.samples_per_frame();
    let mut capture_rate = config.capture_rate;
    // Number of samples per frame at the capture device rate
    #[allow(clippy::cast_possible_truncation)]
    let mut capture_device_samples =
        (codec_samples as u32 * capture_rate / codec_clock_rate) as usize;
    let capture_interval = Duration::from_millis(u64::from(codec.frame_duration_ms()));

    debug!(
        "I/O thread: codec={}, codec_rate={}, capture_rate={}, \
         capture_samples={}, capture_interval={}ms",
        codec.name(),
        codec_clock_rate,
        capture_rate,
        capture_device_samples,
        capture_interval.as_millis()
    );

    // Audio processing (AGC + noise gate) for capture path
    let mut audio_processor = AudioProcessor::new();
    // Voice activity detection for discontinuous transmission
    let mut vad = VoiceActivityDetector::new();

    // RTCP session (optional — created if RTCP socket is provided)
    let mut rtcp_session =
        config
            .rtcp_socket
            .zip(config.rtcp_remote_addr)
            .map(|(socket, remote_addr)| {
                let cname = format!("usg-uc-{}", config.local_ssrc);
                RtcpSession::new(socket, remote_addr, config.local_ssrc, cname)
            });

    let mut last_capture = Instant::now();
    let mut stats_update_counter: u32 = 0;

    // Pending input device switch: CaptureStream creation runs on a
    // background thread so the I/O loop continues receiving RTP.
    // Without this, the 200-500ms CaptureStream::new() call blocks RTP
    // reception, draining the jitter buffer and causing robotic playback.
    let mut pending_capture_rx: Option<mpsc::Receiver<Result<CaptureStream, String>>> = None;

    // DTX warmup: always send RTP for the first few seconds of a call.
    // Bluetooth HFP profile negotiation can take 3-8 seconds, during which
    // the mic captures all zeros. If DTX suppresses those, we send no RTP
    // and the remote side (symmetric RTP) won't send either → dead air.
    let dtx_warmup_duration = Duration::from_secs(5);
    let mut dtx_warmup_start = Instant::now();
    let mut prev_moh_active = false;

    // Diagnostic counters (logged every ~2 seconds)
    let mut diag_frames_captured: u64 = 0;
    let mut diag_capture_underruns: u64 = 0;
    let mut diag_dtx_frames: u64 = 0;
    let mut diag_last_samples_read: usize = 0;
    let mut diag_max_amplitude: i16 = 0;
    let mut diag_timer = Instant::now();

    while running.load(Ordering::Relaxed) {
        // 1. Receive one RTP packet (blocking with 5ms timeout on socket).
        //    No burst drain — the main loop runs every ~5ms so burst packets
        //    are naturally picked up across iterations without stalling.
        match receiver.receive() {
            Ok(true | false) => {
                // Packet received and buffered, or timeout — no packet available
            }
            Err(e) => {
                trace!("RTP receive error: {e}");
            }
        }

        // 2. Capture and send audio at frame intervals.
        //    Uses additive timing to maintain exact cadence (e.g., every 20ms)
        //    regardless of processing time or recv_timeout jitter.
        if last_capture.elapsed() >= capture_interval {
            last_capture += capture_interval;
            // If we've fallen behind by more than 2 frame intervals (e.g.,
            // after a stall), reset to avoid burst-sending a backlog of frames.
            if last_capture.elapsed() > capture_interval * 2 {
                last_capture = Instant::now();
            }

            let current_moh = moh_active.load(Ordering::Relaxed);
            if prev_moh_active && !current_moh {
                // MOH just deactivated (resume from hold) — reset DTX warmup
                // to force-send frames, ensuring the remote side's jitter
                // buffer refills before DTX kicks in again.
                dtx_warmup_start = Instant::now();
                info!("Hold ended, resetting DTX warmup to force-send frames");
            }
            prev_moh_active = current_moh;

            if current_moh {
                // Music on Hold mode
                process_moh_frame(&mut codec, &mut transmitter, &mut moh_source);
            } else if !muted.load(Ordering::Relaxed) {
                // Normal capture mode
                let in_warmup = dtx_warmup_start.elapsed() < dtx_warmup_duration;
                let (samples_read, max_amp, dtx) = process_capture_frame(
                    &mut codec,
                    &mut transmitter,
                    &mut capture,
                    &mut audio_processor,
                    &mut vad,
                    capture_device_samples,
                    codec_samples,
                    &stats,
                    in_warmup,
                );
                diag_frames_captured += 1;
                diag_last_samples_read = samples_read;
                if max_amp > diag_max_amplitude {
                    diag_max_amplitude = max_amp;
                }
                if samples_read < capture_device_samples {
                    diag_capture_underruns += 1;
                }
                if dtx {
                    diag_dtx_frames += 1;
                }
            }
        }

        // 3. Check for commands (DTMF, device switch)
        if let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                IoCommand::Dtmf(dtmf_cmd) => {
                    handle_dtmf(&mut transmitter, &mut codec, dtmf_cmd);
                }
                IoCommand::SwitchInputDevice(device_name) => {
                    info!(
                        "I/O thread: switching input device to {:?} (async)",
                        device_name
                    );
                    // Spawn CaptureStream creation on a background thread so
                    // the I/O loop keeps receiving RTP during the switch.
                    let (tx, rx) = mpsc::channel();
                    thread::Builder::new()
                        .name("capture-switch".to_string())
                        .spawn(move || {
                            let mut dm = crate::device::DeviceManager::new();
                            dm.set_input_device(device_name);
                            let result = CaptureStream::new(&dm).map_err(|e| e.to_string());
                            let _ = tx.send(result);
                        })
                        .ok();
                    pending_capture_rx = Some(rx);
                }
            }
        }

        // 3b. Check if async capture switch completed
        if let Some(ref rx) = pending_capture_rx
            && let Ok(result) = rx.try_recv()
        {
            pending_capture_rx = None;
            match result {
                Ok(new_capture) => {
                    capture.stop();
                    let new_rate = new_capture.sample_rate();
                    if new_rate != capture_rate {
                        let old_rate = capture_rate;
                        capture_rate = new_rate;
                        #[allow(clippy::cast_possible_truncation)]
                        {
                            capture_device_samples = (codec_samples as u32 * capture_rate
                                / codec_clock_rate)
                                as usize;
                        }
                        info!(
                            "I/O thread: capture rate changed {}→{}Hz, \
                             frame size now {} samples (codec {}Hz)",
                            old_rate, capture_rate, capture_device_samples, codec_clock_rate
                        );
                    }
                    capture = new_capture;

                    // Reset processing state for clean transition:
                    // - AGC gain tuned for old device would mis-amplify new device
                    // - Frame timer prevents burst-sending backed-up frames
                    // - DTX warmup ensures continuous RTP through the switch
                    audio_processor.reset();
                    last_capture = Instant::now();
                    dtx_warmup_start = Instant::now();
                    info!("I/O thread: input device switched successfully");

                    // Refresh the playback stream: on macOS, switching away
                    // from a Bluetooth mic triggers an HFP→A2DP profile change
                    // that alters the output device's sample rate. By this point
                    // (~200-500ms after the switch started), the profile change
                    // has completed and the decode thread will pick up the new rate.
                    if let Some(ref tx) = decode_cmd_tx {
                        info!("I/O thread: requesting playback stream refresh");
                        let _ = tx.send(DecodeCommand::SwitchOutputDevice(None));
                    }
                }
                Err(e) => {
                    warn!("I/O thread: failed to switch input device: {e}");
                }
            }
        }

        // 4. RTCP: send periodic Sender/Receiver Reports
        if let Some(ref mut rtcp) = rtcp_session {
            // Propagate remote SSRC learned from received RTP packets
            if let Some(remote_ssrc) = receiver.remote_ssrc() {
                rtcp.set_remote_ssrc(remote_ssrc);
            }
            let tx = transmitter.stats();
            let rx = receiver.stats();
            let jb = receiver.jitter_buffer_stats();
            rtcp.maybe_send_report(&tx, &rx, &jb);
        }

        // 5. Periodically update shared stats
        stats_update_counter += 1;
        if stats_update_counter >= 100 {
            stats_update_counter = 0;
            update_stats(&transmitter, &receiver, &stats);
        }

        // 6. Diagnostic logging every ~2 seconds
        if diag_timer.elapsed() >= Duration::from_secs(2) {
            let tx_stats = transmitter.stats();
            info!(
                "IO diag: frames_captured={}, underruns={}, dtx={}, last_read={}/{}, \
                 max_amp={}, tx_pkts={}, rx_pkts={}, jb_depth={}ms, \
                 muted={}, moh={}",
                diag_frames_captured,
                diag_capture_underruns,
                diag_dtx_frames,
                diag_last_samples_read,
                capture_device_samples,
                diag_max_amplitude,
                tx_stats.packets_sent,
                receiver.stats().packets_received,
                receiver.jitter_buffer_stats().current_depth_ms,
                muted.load(Ordering::Relaxed),
                moh_active.load(Ordering::Relaxed),
            );
            diag_max_amplitude = 0;
            diag_dtx_frames = 0;
            diag_timer = Instant::now();
        }
    }

    // Final stats update on exit
    update_stats(&transmitter, &receiver, &stats);
    capture.stop();
    debug!("I/O thread cleanup complete");
}

/// Processes one frame of microphone capture.
///
/// Returns (`samples_read`, `max_amplitude`, `dtx_suppressed`) for diagnostics.
#[allow(clippy::too_many_arguments)]
fn process_capture_frame(
    codec: &mut CodecPipeline,
    transmitter: &mut RtpTransmitter,
    capture: &mut CaptureStream,
    audio_processor: &mut AudioProcessor,
    vad: &mut VoiceActivityDetector,
    device_samples: usize,
    codec_samples: usize,
    stats: &Arc<Mutex<PipelineStats>>,
    skip_dtx: bool,
) -> (usize, i16, bool) {
    // Read captured samples at device rate
    let mut device_pcm = vec![0i16; device_samples];
    let samples_read = capture.read(&mut device_pcm);

    if samples_read < device_samples {
        trace!(
            "Capture underrun: got {} samples, needed {}",
            samples_read, device_samples
        );
        if let Ok(mut s) = stats.lock() {
            s.capture_underruns += 1;
        }
        device_pcm[samples_read..].fill(0);
    }

    // Apply audio processing (noise gate + AGC) at device rate
    audio_processor.process(&mut device_pcm[..samples_read]);

    // Track max amplitude for diagnostics AFTER processing
    // Use saturating_abs() because i16::MIN.abs() overflows in debug mode
    let max_amp = device_pcm[..samples_read]
        .iter()
        .map(|s| s.saturating_abs())
        .max()
        .unwrap_or(0);

    // Voice activity detection — skip encode+send during silence (DTX).
    // During warmup, always send even if VAD says silence, to ensure the
    // remote side receives our RTP and starts sending back.
    if !skip_dtx && vad.detect(&device_pcm[..samples_read]) == VadDecision::Silence {
        return (samples_read, max_amp, true);
    }

    // Resample from device rate to codec rate (no cross-frame needed for downsampling)
    let codec_pcm = if device_samples == codec_samples {
        device_pcm
    } else {
        resample(&device_pcm, codec_samples, 0)
    };

    // Encode
    let encoded = match codec.encode(&codec_pcm) {
        Ok(e) => e.to_vec(),
        Err(e) => {
            warn!("Encode error: {e}");
            return (samples_read, max_amp, false);
        }
    };

    // Send
    if let Err(e) = transmitter.send(&encoded) {
        trace!("RTP send error: {e}");
    }

    (samples_read, max_amp, false)
}

/// Processes one frame of Music on Hold audio.
fn process_moh_frame(
    codec: &mut CodecPipeline,
    transmitter: &mut RtpTransmitter,
    moh_source: &mut Option<FileAudioSource>,
) {
    let source = match moh_source.as_mut() {
        Some(s) if s.is_loaded() => s,
        _ => return,
    };

    let samples_needed = codec.samples_per_frame();
    let mut pcm = vec![0i16; samples_needed];
    source.read(&mut pcm);

    let encoded = match codec.encode(&pcm) {
        Ok(e) => e.to_vec(),
        Err(e) => {
            warn!("MOH encode error: {e}");
            return;
        }
    };

    if let Err(e) = transmitter.send(&encoded) {
        trace!("MOH send error: {e}");
    }
}

/// Handles a DTMF command by sending RFC 2833 and/or in-band tones.
///
/// Sends DTMF using one or both methods based on negotiation:
/// 1. RFC 2833 (RFC 4733) telephone-event packets (out-of-band) - if supported
/// 2. In-band audio tones (ITU-T Q.23 dual-tone frequencies) - always sent
///
/// This ensures DTMF works with providers that support RFC 2833
/// as well as those that only support in-band DTMF.
#[allow(clippy::needless_pass_by_value)]
fn handle_dtmf(transmitter: &mut RtpTransmitter, codec: &mut CodecPipeline, cmd: DtmfCommand) {
    let method = if cmd.use_rfc2833 {
        "RFC2833 + in-band"
    } else {
        "in-band only"
    };
    info!(
        "Sending DTMF digit '{}' for {}ms ({})",
        cmd.digit, cmd.duration_ms, method
    );

    let duration = DtmfEvent::duration_from_ms(cmd.duration_ms);
    let codec_sample_rate = 8000; // G.711 is 8kHz
    let packet_interval_ms = 20u32;
    let samples_per_packet = (codec_sample_rate * packet_interval_ms / 1000) as usize;

    // Create in-band tone generator
    let mut tone_gen = DtmfToneGenerator::new(cmd.digit, codec_sample_rate);

    // Send initial RFC 2833 packet with marker bit (if supported)
    if cmd.use_rfc2833 {
        let event = DtmfEvent::new(cmd.digit, 0);
        if let Err(e) = transmitter.send_dtmf(&event, true) {
            warn!("RFC2833 start send error: {e}");
        }
    }

    // Send continuation packets every 20ms with in-band audio (and RFC 2833 if supported)
    let num_packets = cmd.duration_ms / packet_interval_ms;

    for i in 0..num_packets {
        // Generate in-band DTMF tone samples
        let mut tone_samples = vec![0i16; samples_per_packet];
        tone_gen.generate_samples(&mut tone_samples);

        // Encode the tone samples using the active codec
        match codec.encode(&tone_samples) {
            Ok(encoded) => {
                // Send as regular RTP audio packet (in-band)
                if let Err(e) = transmitter.send(&encoded) {
                    trace!("In-band DTMF send error: {e}");
                }
            }
            Err(e) => {
                warn!("DTMF encode error: {e}");
            }
        }

        // Also send RFC 2833 continuation packet (out-of-band) if supported
        if cmd.use_rfc2833 && i > 0 {
            let elapsed = DtmfEvent::duration_from_ms(i * packet_interval_ms);
            let event = DtmfEvent::new(cmd.digit, elapsed);
            if let Err(e) = transmitter.send_dtmf(&event, false) {
                trace!("RFC2833 continuation send error: {e}");
            }
        }

        thread::sleep(Duration::from_millis(u64::from(packet_interval_ms)));
    }

    // Send RFC 2833 end packets (3x for reliability per RFC 4733) if supported
    if cmd.use_rfc2833 {
        for _ in 0..3 {
            let event = DtmfEvent::with_end(cmd.digit, duration);
            if let Err(e) = transmitter.send_dtmf(&event, false) {
                trace!("RFC2833 end send error: {e}");
            }
        }
    }

    debug!("DTMF digit '{}' sent successfully", cmd.digit);
}

/// Updates shared statistics from transmitter and receiver.
fn update_stats(
    transmitter: &RtpTransmitter,
    receiver: &RtpReceiver,
    stats: &Arc<Mutex<PipelineStats>>,
) {
    if let Ok(mut s) = stats.lock() {
        s.tx_stats = transmitter.stats();
        s.rx_stats = receiver.stats();
        s.jitter_stats = receiver.jitter_buffer_stats();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtmf_command() {
        let cmd = DtmfCommand {
            digit: DtmfDigit::Five,
            duration_ms: 100,
            use_rfc2833: true,
        };
        assert_eq!(cmd.duration_ms, 100);
    }
}
