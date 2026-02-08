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
use crate::comfort_noise::encode_cn_payload;
use crate::decode_thread::DecodeCommand;
use crate::dtmf_sender::DtmfSender;
use crate::file_source::FileAudioSource;
use crate::pipeline::{PipelineStats, resample_into};
use crate::rtcp_session::RtcpSession;
use crate::rtp_handler::{RtpReceiver, RtpTransmitter};
use crate::stream::CaptureStream;
use crate::noise_shaper::{CompandingLaw, NoiseShaper};
use crate::vad::{VadDecision, VoiceActivityDetector};
use client_types::{CodecPreference, DtmfDigit};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

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
    /// DTMF volume level for RFC 4733 packets (0-63, default 10).
    pub dtmf_volume: u8,
    /// Inter-digit pause in milliseconds (default 100).
    pub dtmf_inter_digit_pause_ms: u32,
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
            crate::thread_priority::set_realtime_priority("I/O");
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
    let codec_name = codec.name().to_string();
    let codec_samples = codec.samples_per_frame();

    // Store codec name in shared stats (constant for the call duration)
    if let Ok(mut s) = stats.lock() {
        s.codec_name = codec_name.clone();
    }
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

    // Encoder-side noise shaping (G.711 Appendix III)
    let noise_shaper_law = match config.codec {
        CodecPreference::G711Ulaw => Some(CompandingLaw::MuLaw),
        CodecPreference::G711Alaw => Some(CompandingLaw::ALaw),
        _ => None,
    };
    let mut noise_shaper = NoiseShaper::new_optional(noise_shaper_law);

    // RTCP session (optional — created if RTCP socket is provided)
    let mut rtcp_session =
        config
            .rtcp_socket
            .zip(config.rtcp_remote_addr)
            .map(|(socket, remote_addr)| {
                let cname = format!("usg-uc-{}", config.local_ssrc);
                RtcpSession::new(socket, remote_addr, config.local_ssrc, codec_clock_rate, cname)
            });

    // Non-blocking DTMF sender state machine
    let mut dtmf_sender = DtmfSender::new(config.dtmf_volume, u64::from(config.dtmf_inter_digit_pause_ms));

    // Pre-allocated scratch buffers — reused every frame to avoid heap allocs.
    let mut capture_pcm = vec![0i16; capture_device_samples];
    let mut codec_pcm_buf = vec![0i16; codec_samples];
    let mut moh_pcm = vec![0i16; codec_samples];

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
    let mut was_speech_last_frame = false;

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

        // SSRC collision handling (RFC 3550 §8.2): if the receiver
        // detected that the remote's SSRC matches our local SSRC,
        // regenerate ours so both sides have unique identifiers.
        if receiver.ssrc_collision_detected() {
            let new_ssrc = crate::rtp_handler::generate_ssrc();
            transmitter.change_ssrc(new_ssrc);
            receiver.set_local_ssrc(new_ssrc);
            receiver.clear_ssrc_collision();
            if let Some(ref mut rtcp) = rtcp_session {
                rtcp.set_local_ssrc(new_ssrc);
            }
            warn!("SSRC collision resolved: new local SSRC={:#010x}", new_ssrc);
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
                process_moh_frame(&mut codec, &mut transmitter, &mut moh_source, &mut moh_pcm);
            } else if !muted.load(Ordering::Relaxed) && !dtmf_sender.is_inband_active() {
                // Normal capture mode
                let in_warmup = dtx_warmup_start.elapsed() < dtx_warmup_duration;
                let (samples_read, max_amp, dtx, noise_floor) = process_capture_frame(
                    &mut codec,
                    &mut transmitter,
                    &mut capture,
                    &mut audio_processor,
                    &mut vad,
                    &mut noise_shaper,
                    &mut capture_pcm,
                    &mut codec_pcm_buf,
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
                    // Send one CN packet at the speech→silence transition (RFC 3389)
                    if let Some(nf) = noise_floor
                        && was_speech_last_frame
                    {
                        let cn_payload = encode_cn_payload(nf);
                        if let Err(e) = transmitter.send_cn(&cn_payload) {
                            trace!("CN send error: {e}");
                        }
                    }
                    was_speech_last_frame = false;
                } else {
                    was_speech_last_frame = true;
                }
            }
        }

        // 3. Check for commands (DTMF, device switch)
        if let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                IoCommand::Dtmf(dtmf_cmd) => {
                    if !dtmf_sender.enqueue(dtmf_cmd) {
                        warn!("DTMF digit dropped (queue full)");
                    }
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

        // 3b. Poll DTMF state machine (non-blocking, sends at most one packet)
        if let Some(inband_frame) = dtmf_sender.poll(&mut transmitter, &mut codec)
            && let Err(e) = transmitter.send(&inband_frame)
        {
            trace!("In-band DTMF send error: {e}");
        }

        // 3c. Check if async capture switch completed
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
                            capture_device_samples =
                                (codec_samples as u32 * capture_rate / codec_clock_rate) as usize;
                        }
                        capture_pcm.resize(capture_device_samples, 0);
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

        // 4. RTCP: receive incoming SR and send periodic SR/RR reports
        if let Some(ref mut rtcp) = rtcp_session {
            // Receive incoming RTCP (non-blocking, parses SR for DLSR/RTT)
            rtcp.try_receive();
            // Propagate remote SSRC learned from received RTP packets
            if let Some(remote_ssrc) = receiver.remote_ssrc() {
                rtcp.set_remote_ssrc(remote_ssrc);
            }
            // Feed RTCP RTT measurement to jitter buffer for adaptive depth
            if let Some(rtt) = rtcp.rtt_ms() {
                receiver.set_rtt_hint_ms(rtt);
            }
            let tx = transmitter.stats();
            let jb = receiver.jitter_buffer_stats();
            rtcp.maybe_send_report(&tx, &jb);
        }

        // 5. Periodically update shared stats
        stats_update_counter += 1;
        if stats_update_counter >= 100 {
            stats_update_counter = 0;
            update_stats(&transmitter, &receiver, &rtcp_session, &stats);
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
    update_stats(&transmitter, &receiver, &rtcp_session, &stats);
    capture.stop();
    debug!("I/O thread cleanup complete");
}

/// Processes one frame of microphone capture.
///
/// Returns (`samples_read`, `max_amplitude`, `dtx_suppressed`, `noise_floor`).
/// When DTX suppresses the frame, `noise_floor` carries the VAD's estimate
/// so the caller can send an RFC 3389 CN packet at the speech→silence transition.
///
/// `device_pcm` and `codec_pcm_buf` are pre-allocated buffers (caller manages lifetimes).
#[allow(clippy::too_many_arguments)]
fn process_capture_frame(
    codec: &mut CodecPipeline,
    transmitter: &mut RtpTransmitter,
    capture: &mut CaptureStream,
    audio_processor: &mut AudioProcessor,
    vad: &mut VoiceActivityDetector,
    noise_shaper: &mut NoiseShaper,
    device_pcm: &mut [i16],
    codec_pcm_buf: &mut [i16],
    stats: &Arc<Mutex<PipelineStats>>,
    skip_dtx: bool,
) -> (usize, i16, bool, Option<f32>) {
    let device_samples = device_pcm.len();
    let codec_samples = codec_pcm_buf.len();
    device_pcm.fill(0);

    // Read captured samples at device rate
    let samples_read = capture.read(device_pcm);

    if samples_read < device_samples {
        trace!(
            "Capture underrun: got {} samples, needed {}",
            samples_read, device_samples
        );
        if let Ok(mut s) = stats.lock() {
            s.capture_underruns += 1;
        }
    }

    // Apply audio processing (noise gate + AGC) at device rate
    audio_processor.process(&mut device_pcm[..samples_read]);

    // Track max amplitude for diagnostics AFTER processing
    let max_amp = device_pcm[..samples_read]
        .iter()
        .map(|s| s.saturating_abs())
        .max()
        .unwrap_or(0);

    // Voice activity detection — skip encode+send during silence (DTX).
    // During warmup, always send even if VAD says silence, to ensure the
    // remote side receives our RTP and starts sending back.
    if !skip_dtx && vad.detect(&device_pcm[..samples_read]) == VadDecision::Silence {
        return (samples_read, max_amp, true, Some(vad.noise_floor()));
    }

    // Resample from device rate to codec rate (zero-alloc)
    let codec_pcm: &mut [i16] = if device_samples == codec_samples {
        &mut device_pcm[..codec_samples]
    } else {
        resample_into(device_pcm, codec_pcm_buf, 0);
        codec_pcm_buf
    };

    // Noise shaping (G.711 only — reshapes quantization noise before encoding)
    noise_shaper.process(codec_pcm);

    // Encode and send — codec.encode() returns &[u8] borrowing its internal
    // buffer, passed directly to send() without .to_vec().
    match codec.encode(codec_pcm) {
        Ok(encoded) => {
            if let Err(e) = transmitter.send(encoded) {
                trace!("RTP send error: {e}");
            }
        }
        Err(e) => {
            warn!("Encode error: {e}");
            return (samples_read, max_amp, false, None);
        }
    }

    (samples_read, max_amp, false, None)
}

/// Processes one frame of Music on Hold audio.
///
/// `pcm` is a pre-allocated buffer of `codec.samples_per_frame()` elements.
fn process_moh_frame(
    codec: &mut CodecPipeline,
    transmitter: &mut RtpTransmitter,
    moh_source: &mut Option<FileAudioSource>,
    pcm: &mut [i16],
) {
    let source = match moh_source.as_mut() {
        Some(s) if s.is_loaded() => s,
        _ => return,
    };

    pcm.fill(0);
    source.read(pcm);

    // codec.encode() returns &[u8] borrowing its internal buffer —
    // pass directly to send() without .to_vec().
    match codec.encode(pcm) {
        Ok(encoded) => {
            if let Err(e) = transmitter.send(encoded) {
                trace!("MOH send error: {e}");
            }
        }
        Err(e) => {
            warn!("MOH encode error: {e}");
        }
    }
}

/// Updates shared statistics from transmitter and receiver.
fn update_stats(
    transmitter: &RtpTransmitter,
    receiver: &RtpReceiver,
    rtcp_session: &Option<RtcpSession>,
    stats: &Arc<Mutex<PipelineStats>>,
) {
    if let Ok(mut s) = stats.lock() {
        s.tx_stats = transmitter.stats();
        s.rx_stats = receiver.stats();
        s.jitter_stats = receiver.jitter_buffer_stats();
        s.rtt_ms = rtcp_session.as_ref().and_then(RtcpSession::rtt_ms);
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
