//! SBC Announcement Server.
//!
//! Plays pre-recorded audio announcements to callers via RTP when
//! routes are unavailable or other error conditions occur. The SBC
//! answers the call with a 200 OK, streams PCMU audio, then sends BYE.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-6**: Audit Review (logged announcement events)
//! - **SC-7**: Boundary Protection (controlled call termination)

use bytes::Bytes;
use proto_rtp::RtpHeader;
use proto_rtp::RtpPacket;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use uc_codecs::G711Ulaw;

/// PCMU payload type per RFC 3551.
const PCMU_PAYLOAD_TYPE: u8 = 0;
/// PCMU clock rate.
const PCMU_CLOCK_RATE: u32 = 8000;
/// Packet duration in milliseconds (20ms standard).
const PTIME_MS: u32 = 20;
/// Samples per packet at 8kHz / 20ms.
const SAMPLES_PER_PACKET: usize = 160;
/// Timestamp increment per packet.
const TIMESTAMP_INCREMENT: u32 = SAMPLES_PER_PACKET as u32;

/// Pre-built announcement types.
#[derive(Debug, Clone, Copy)]
pub enum AnnouncementType {
    /// "The number you have dialed is not in service."
    NumberNotInService,
    /// "All circuits are busy. Please try again later."
    AllCircuitsBusy,
    /// Silence (used for testing).
    Silence,
}

/// An announcement server that streams RTP audio to callers.
pub struct AnnouncementServer;

impl AnnouncementServer {
    /// Plays an announcement to the given destination.
    ///
    /// Binds a local UDP socket, streams PCMU RTP packets with the
    /// announcement audio, then returns when playback is complete.
    /// Binds an announcement socket and returns (socket, actual_port).
    /// Call this before building the SDP so the port is known.
    pub async fn bind_socket(preferred_port: u16) -> Result<(UdpSocket, u16), String> {
        // Try binding to the preferred port first, fall back to OS-assigned
        let bind_addr = if preferred_port > 0 {
            format!("0.0.0.0:{preferred_port}")
        } else {
            "0.0.0.0:0".to_string()
        };
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| format!("Bind to {bind_addr} failed: {e}"))?;
        let port = socket.local_addr().map_err(|e| e.to_string())?.port();
        Ok((socket, port))
    }

    /// Plays an announcement on an already-bound socket.
    pub async fn play_on_socket(
        announcement: AnnouncementType,
        socket: UdpSocket,
        destination: SocketAddr,
        ssrc: u32,
    ) -> Result<(), String> {
        // Ensure destination is IPv4 (not IPv6-mapped) for IPv4 sockets
        let destination = match destination {
            SocketAddr::V6(v6) => {
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
                } else {
                    destination
                }
            }
            other => other,
        };

        let samples = generate_announcement(announcement);
        let total_packets = samples.len() / SAMPLES_PER_PACKET;

        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
        info!(
            announcement = ?announcement,
            destination = %destination,
            local_addr = %local_addr,
            total_packets,
            duration_ms = total_packets as u32 * PTIME_MS,
            "Starting announcement playback"
        );

        let mut seq: u16 = 0;
        let mut timestamp: u32 = 0;

        for chunk in samples.chunks(SAMPLES_PER_PACKET) {
            // Encode PCM samples to PCMU
            let payload: Vec<u8> = chunk
                .iter()
                .map(|&s| G711Ulaw::encode_sample(s))
                .collect();

            let header = RtpHeader::new(PCMU_PAYLOAD_TYPE, seq, timestamp, ssrc);
            let packet = RtpPacket::new(header, Bytes::from(payload));
            let packet_bytes = packet.to_bytes();

            if let Err(e) = socket.send_to(&packet_bytes, destination).await {
                warn!(error = %e, seq, "Failed to send RTP packet");
            }

            seq = seq.wrapping_add(1);
            timestamp = timestamp.wrapping_add(TIMESTAMP_INCREMENT);

            // Pace packets at 20ms intervals
            tokio::time::sleep(Duration::from_millis(u64::from(PTIME_MS))).await;
        }

        debug!(
            packets_sent = total_packets,
            "Announcement playback complete"
        );

        Ok(())
    }
}

/// Generates PCM 16-bit signed samples at 8kHz for the given announcement.
fn generate_announcement(announcement: AnnouncementType) -> Vec<i16> {
    match announcement {
        AnnouncementType::NumberNotInService => generate_number_not_in_service(),
        AnnouncementType::AllCircuitsBusy => generate_all_circuits_busy(),
        AnnouncementType::Silence => vec![0i16; PCMU_CLOCK_RATE as usize * 2], // 2 seconds
    }
}

/// Generates the classic "number not in service" announcement:
/// Three SIT tones (Special Information Tones per Bellcore GR-674)
/// followed by synthesized speech approximation.
///
/// SIT tone sequence (intercept): 985.2 Hz, 1428.5 Hz, 1776.7 Hz
/// Each tone: 276ms + 276ms + 380ms
fn generate_number_not_in_service() -> Vec<i16> {
    let sample_rate = PCMU_CLOCK_RATE as f64;
    let mut samples = Vec::new();

    // === SIT Tones (Special Information Tones) ===
    // Intercept pattern: indicates number is not in service
    let sit_tones = [
        (985.2, 0.276),   // First tone
        (1428.5, 0.276),  // Second tone
        (1776.7, 0.380),  // Third tone
    ];

    for &(freq, duration) in &sit_tones {
        let num_samples = (sample_rate * duration) as usize;
        for i in 0..num_samples {
            let t = i as f64 / sample_rate;
            let sample = (t * freq * 2.0 * std::f64::consts::PI).sin() * 16000.0;
            samples.push(sample as i16);
        }
    }

    // Brief pause after SIT (200ms)
    samples.extend(vec![0i16; (sample_rate * 0.2) as usize]);

    // === Synthesized speech approximation ===
    // We approximate speech with a sequence of formant-like tones
    // that sound like "We're sorry, the number you have dialed
    // is not in service. Please check the number and dial again."
    //
    // Each "syllable" is a pair of formants mixed together with
    // amplitude envelope to approximate natural speech rhythm.

    // Word-level timing: short bursts of complex tones with pauses
    let speech_segments = [
        // "We're" - high front vowel
        SpeechSegment { f1: 270.0, f2: 2300.0, duration: 0.18, amplitude: 0.6 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.06, amplitude: 0.0 }, // pause
        // "sorry"
        SpeechSegment { f1: 700.0, f2: 1200.0, duration: 0.15, amplitude: 0.5 },
        SpeechSegment { f1: 270.0, f2: 2300.0, duration: 0.15, amplitude: 0.5 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.15, amplitude: 0.0 }, // pause
        // "the"
        SpeechSegment { f1: 500.0, f2: 1500.0, duration: 0.08, amplitude: 0.4 },
        // "number"
        SpeechSegment { f1: 500.0, f2: 1800.0, duration: 0.15, amplitude: 0.5 },
        SpeechSegment { f1: 300.0, f2: 1700.0, duration: 0.12, amplitude: 0.4 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.06, amplitude: 0.0 },
        // "you have"
        SpeechSegment { f1: 300.0, f2: 2300.0, duration: 0.10, amplitude: 0.4 },
        SpeechSegment { f1: 700.0, f2: 1100.0, duration: 0.12, amplitude: 0.5 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.06, amplitude: 0.0 },
        // "dialed"
        SpeechSegment { f1: 400.0, f2: 2100.0, duration: 0.15, amplitude: 0.5 },
        SpeechSegment { f1: 500.0, f2: 1800.0, duration: 0.12, amplitude: 0.4 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.15, amplitude: 0.0 }, // longer pause
        // "is not"
        SpeechSegment { f1: 400.0, f2: 2000.0, duration: 0.08, amplitude: 0.4 },
        SpeechSegment { f1: 600.0, f2: 1200.0, duration: 0.12, amplitude: 0.5 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.06, amplitude: 0.0 },
        // "in service"
        SpeechSegment { f1: 400.0, f2: 2200.0, duration: 0.08, amplitude: 0.4 },
        SpeechSegment { f1: 300.0, f2: 1600.0, duration: 0.18, amplitude: 0.5 },
        SpeechSegment { f1: 400.0, f2: 2000.0, duration: 0.12, amplitude: 0.4 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.25, amplitude: 0.0 }, // sentence pause
        // "Please check"
        SpeechSegment { f1: 270.0, f2: 2300.0, duration: 0.15, amplitude: 0.5 },
        SpeechSegment { f1: 500.0, f2: 1900.0, duration: 0.12, amplitude: 0.4 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.06, amplitude: 0.0 },
        // "the number"
        SpeechSegment { f1: 500.0, f2: 1500.0, duration: 0.08, amplitude: 0.4 },
        SpeechSegment { f1: 500.0, f2: 1800.0, duration: 0.15, amplitude: 0.5 },
        SpeechSegment { f1: 300.0, f2: 1700.0, duration: 0.12, amplitude: 0.4 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.06, amplitude: 0.0 },
        // "and dial"
        SpeechSegment { f1: 700.0, f2: 1100.0, duration: 0.10, amplitude: 0.4 },
        SpeechSegment { f1: 400.0, f2: 2100.0, duration: 0.15, amplitude: 0.5 },
        SpeechSegment { f1: 500.0, f2: 1800.0, duration: 0.12, amplitude: 0.4 },
        SpeechSegment { f1: 0.0,   f2: 0.0,    duration: 0.06, amplitude: 0.0 },
        // "again"
        SpeechSegment { f1: 500.0, f2: 1700.0, duration: 0.12, amplitude: 0.4 },
        SpeechSegment { f1: 270.0, f2: 2300.0, duration: 0.18, amplitude: 0.5 },
    ];

    for seg in &speech_segments {
        let num_samples = (sample_rate * seg.duration) as usize;
        for i in 0..num_samples {
            let t = i as f64 / sample_rate;
            // Amplitude envelope: fade in/out over 5ms
            let fade_samples = (sample_rate * 0.005) as usize;
            let env = if i < fade_samples {
                i as f64 / fade_samples as f64
            } else if i > num_samples - fade_samples {
                (num_samples - i) as f64 / fade_samples as f64
            } else {
                1.0
            };

            if seg.amplitude == 0.0 {
                samples.push(0);
            } else {
                // Mix two formant frequencies
                let s1 = (t * seg.f1 * 2.0 * std::f64::consts::PI).sin();
                let s2 = (t * seg.f2 * 2.0 * std::f64::consts::PI).sin() * 0.3;
                // Add fundamental pitch (~120Hz male voice)
                let fundamental = (t * 120.0 * 2.0 * std::f64::consts::PI).sin() * 0.4;
                let mixed = (s1 + s2 + fundamental) * seg.amplitude * env * 12000.0;
                samples.push(mixed.clamp(-32000.0, 32000.0) as i16);
            }
        }
    }

    // Trailing silence (500ms)
    samples.extend(vec![0i16; (sample_rate * 0.5) as usize]);

    // Repeat the SIT tones one more time
    for &(freq, duration) in &sit_tones {
        let num_samples = (sample_rate * duration) as usize;
        for i in 0..num_samples {
            let t = i as f64 / sample_rate;
            let sample = (t * freq * 2.0 * std::f64::consts::PI).sin() * 16000.0;
            samples.push(sample as i16);
        }
    }

    // Final silence (300ms)
    samples.extend(vec![0i16; (sample_rate * 0.3) as usize]);

    samples
}

/// Generates "all circuits busy" announcement with SIT tones.
fn generate_all_circuits_busy() -> Vec<i16> {
    let sample_rate = PCMU_CLOCK_RATE as f64;
    let mut samples = Vec::new();

    // Reorder busy SIT: 985.2 Hz, 1428.5 Hz, 1776.7 Hz (same tones, shorter)
    let sit_tones = [
        (985.2, 0.276),
        (1428.5, 0.276),
        (1776.7, 0.380),
    ];

    for &(freq, duration) in &sit_tones {
        let num_samples = (sample_rate * duration) as usize;
        for i in 0..num_samples {
            let t = i as f64 / sample_rate;
            let sample = (t * freq * 2.0 * std::f64::consts::PI).sin() * 16000.0;
            samples.push(sample as i16);
        }
    }

    // Pause
    samples.extend(vec![0i16; (sample_rate * 0.2) as usize]);

    // Busy tone: 480 + 620 Hz, 0.5s on / 0.5s off, repeated 3 times
    for _ in 0..3 {
        let on_samples = (sample_rate * 0.5) as usize;
        for i in 0..on_samples {
            let t = i as f64 / sample_rate;
            let s1 = (t * 480.0 * 2.0 * std::f64::consts::PI).sin();
            let s2 = (t * 620.0 * 2.0 * std::f64::consts::PI).sin();
            let mixed = (s1 + s2) * 12000.0;
            samples.push(mixed as i16);
        }
        samples.extend(vec![0i16; (sample_rate * 0.5) as usize]);
    }

    samples
}

/// A segment of synthesized speech with two formant frequencies.
struct SpeechSegment {
    f1: f64,
    f2: f64,
    duration: f64,
    amplitude: f64,
}

/// Builds a minimal SDP offer for announcement playback (PCMU only).
pub fn build_announcement_sdp(local_ip: &str, rtp_port: u16) -> String {
    format!(
        "v=0\r\n\
         o=sbc-announcement 0 0 IN IP4 {local_ip}\r\n\
         s=Announcement\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=ptime:20\r\n\
         a=sendonly\r\n"
    )
}

/// Extracts the RTP destination (IP:port) from a remote SDP answer/offer.
/// Looks for `c=IN IP4 <ip>` and `m=audio <port>`.
pub fn extract_rtp_dest_from_sdp(sdp: &str) -> Option<SocketAddr> {
    let mut ip = None;
    let mut port = None;

    for line in sdp.lines() {
        if line.starts_with("c=IN IP4 ") {
            ip = line.strip_prefix("c=IN IP4 ").map(|s| s.trim().to_string());
        } else if line.starts_with("m=audio ") {
            port = line
                .split_whitespace()
                .nth(1)
                .and_then(|p| p.parse::<u16>().ok());
        }
    }

    match (ip, port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}").parse().ok(),
        _ => None,
    }
}
