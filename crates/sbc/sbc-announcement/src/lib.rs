//! SBC announcement playback engine.
//!
//! Plays pre-recorded audio announcements to callers via RTP when
//! routes are unavailable or other error conditions occur. The SBC
//! answers the call with a 200 OK, streams PCMU audio, then sends BYE.
//!
//! Extracted from `sbc-daemon` so the same engine backs both the
//! daemon's in-process fallback path and the `sbc-announcement-server`
//! pod (gRPC-fronted playback in its own container).
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-6**: Audit Review (logged announcement events)
//! - **SC-7**: Boundary Protection (controlled call termination)

pub mod limits;

use bytes::Bytes;
use include_dir::{Dir, include_dir};
use ipnet::IpNet;
use proto_rtp::RtpHeader;
use proto_rtp::RtpPacket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use uc_codecs::G711Ulaw;

/// Returns `true` if `ip` must not be used as an RTP/media or ICE
/// candidate destination.
///
/// Rejects unspecified (`0.0.0.0`, `::`), IPv4 limited broadcast,
/// loopback, multicast, and link-local addresses, which could be used to
/// probe the pod's local network or amplify traffic (SSRF-like
/// redirection). The address is canonicalized first so IPv4-mapped IPv6
/// forms (e.g. `::ffff:127.0.0.1`, `::ffff:224.0.0.1`) cannot slip past
/// the IPv4-oriented checks, and the IPv4 address embedded in a NAT64 or
/// 6to4 address ([`embedded_ipv4`]) gets the same checks.
///
/// Shared by `sbc-announcement-server` (gRPC `rtp_destination`) and the
/// daemon's ICE agent (remote candidate addresses) so the two guards
/// can't drift apart.
///
/// ## NIST 800-53 Rev5 Controls
///
/// - **SC-7**: Boundary Protection
#[must_use]
pub const fn is_disallowed_media_ip(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    let embedded_bad = match embedded_ipv4(ip) {
        Some(v4) => v4_disallowed(v4),
        None => false,
    };
    embedded_bad
        || ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(v4) if v4_disallowed(v4))
        || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
}

/// The IPv4 classes [`is_disallowed_media_ip`] refuses.
const fn v4_disallowed(v4: Ipv4Addr) -> bool {
    v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_link_local()
}

/// The IPv4 address a NAT64 or 6to4 gateway would forward `ip` to:
/// - `64:ff9b::/96` (RFC 6052 well-known prefix): the last 32 bits;
/// - `64:ff9b:1::/48` (RFC 8215 local-use): the last 32 bits, i.e. the
///   /96 layout. Other RFC 6052 prefix lengths inside it are not decoded;
/// - `2002::/16` (6to4, RFC 3056): bits 16..48.
///
/// `None` for any other address (an IPv4-mapped address is canonicalized
/// by the callers instead).
#[must_use]
pub const fn embedded_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    let s = v6.segments();
    let o = v6.octets();
    let well_known = s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0;
    if s[0] == 0x0064 && s[1] == 0xff9b && (well_known || s[2] == 1) {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

/// `SBC_*_ALLOWED_DEST_CIDRS`-style list: comma-separated CIDRs, at most
/// [`MAX_DEST_CIDRS`], each truncated to its network; empty means no CIDR
/// restriction.
///
/// # Errors
/// A message naming `var` and the offending entry.
pub fn parse_allowed_cidrs(var: &str, raw: Option<&str>) -> Result<Vec<IpNet>, String> {
    let mut out = Vec::new();
    for entry in raw.unwrap_or_default().split(',').map(str::trim) {
        if entry.is_empty() {
            continue;
        }
        if out.len() == MAX_DEST_CIDRS {
            return Err(format!("{var} has more than {MAX_DEST_CIDRS} entries"));
        }
        let net: IpNet = entry
            .parse()
            .map_err(|_| format!("{var} entry {entry:?} is not a CIDR (a.b.c.d/n or x::/n)"))?;
        out.push(net.trunc());
    }
    Ok(out)
}

/// Most entries in a destination CIDR allow-list.
pub const MAX_DEST_CIDRS: usize = 256;

/// `dest` as a socket bound to `local` can address it: an IPv4 socket
/// needs an IPv4 (or v4-mapped) destination; an IPv6 socket addresses an
/// IPv4 destination in v4-mapped form (dual-stack).
///
/// # Errors
/// [`DestinationRefusal::AddressFamily`] for an IPv6 destination on an
/// IPv4 socket.
pub const fn destination_for_socket(
    local: SocketAddr,
    dest: SocketAddr,
) -> Result<SocketAddr, DestinationRefusal> {
    let ip = dest.ip().to_canonical();
    match (local, ip) {
        (SocketAddr::V4(_), IpAddr::V4(_)) | (SocketAddr::V6(_), IpAddr::V6(_)) => {
            Ok(SocketAddr::new(ip, dest.port()))
        }
        (SocketAddr::V4(_), IpAddr::V6(_)) => Err(DestinationRefusal::AddressFamily),
        (SocketAddr::V6(_), IpAddr::V4(v4)) => Ok(SocketAddr::new(
            IpAddr::V6(v4.to_ipv6_mapped()),
            dest.port(),
        )),
    }
}

/// Why [`DestinationPolicy::check`] refused an RTP destination. `Display`
/// names the class only, never the address, so it is safe to return to the
/// peer and to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationRefusal {
    /// `0.0.0.0` or `::`.
    Unspecified,
    /// Loopback without the lab flag.
    Loopback,
    /// IPv4 or IPv6 multicast.
    Multicast,
    /// IPv4 limited broadcast, or the network or broadcast address of a
    /// listed IPv4 CIDR of /30 or shorter.
    Broadcast,
    /// IPv4 or IPv6 link-local.
    LinkLocal,
    /// Port 0.
    PortZero,
    /// Outside every configured media CIDR.
    NotInAllowList,
    /// The media socket cannot address this family (IPv6 destination on
    /// an IPv4 socket).
    AddressFamily,
}

impl std::fmt::Display for DestinationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unspecified => "unspecified address",
            Self::Loopback => "loopback address",
            Self::Multicast => "multicast address",
            Self::Broadcast => "broadcast address",
            Self::LinkLocal => "link-local address",
            Self::PortZero => "port 0",
            Self::NotInAllowList => "outside the allowed media networks",
            Self::AddressFamily => "address family not reachable from the media socket",
        })
    }
}

impl std::error::Error for DestinationRefusal {}

/// Where the announcement pod may send RTP.
///
/// Refuses the [`is_disallowed_media_ip`] classes (loopback only when
/// `allow_loopback` is set, for labs and tests) and port 0. With a
/// non-empty `allowed` list the destination must be inside a listed CIDR
/// and must not be the network or broadcast address of a listed IPv4 CIDR
/// of /30 or shorter. An empty list means no CIDR restriction: subnet
/// broadcasts of unknown networks cannot be detected then.
///
/// The canonical IP is checked, so a v4-mapped IPv6 address gets the same
/// verdict as its IPv4 form. The IPv4 address embedded in a NAT64 or 6to4
/// address ([`embedded_ipv4`]) gets the class checks too and, with an
/// allow-list, must itself be inside a listed CIDR.
///
/// ## NIST 800-53 Rev5: SC-7, SI-10; SC-7(5) when the allow-list is set
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationPolicy {
    /// Admit loopback destinations (lab only).
    pub allow_loopback: bool,
    /// Permitted media networks; empty = no CIDR restriction.
    pub allowed: Vec<IpNet>,
}

impl DestinationPolicy {
    /// Checks one destination.
    ///
    /// # Errors
    /// The refused class.
    pub fn check(&self, dest: SocketAddr) -> Result<(), DestinationRefusal> {
        let ip = dest.ip().to_canonical();
        let embedded = embedded_ipv4(ip).map(IpAddr::V4);
        self.class(ip)?;
        if let Some(v4) = embedded {
            self.class(v4)?;
        }
        if dest.port() == 0 {
            return Err(DestinationRefusal::PortZero);
        }
        if self.allowed.is_empty() {
            return Ok(());
        }
        self.listed(ip)?;
        if let Some(v4) = embedded {
            self.listed(v4)?;
        }
        Ok(())
    }

    /// The special address classes.
    const fn class(&self, ip: IpAddr) -> Result<(), DestinationRefusal> {
        if ip.is_unspecified() {
            return Err(DestinationRefusal::Unspecified);
        }
        if matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()) {
            return Err(DestinationRefusal::Broadcast);
        }
        if ip.is_multicast() {
            return Err(DestinationRefusal::Multicast);
        }
        if matches!(ip, IpAddr::V4(v4) if v4.is_link_local())
            || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
        {
            return Err(DestinationRefusal::LinkLocal);
        }
        if ip.is_loopback() && !self.allow_loopback {
            return Err(DestinationRefusal::Loopback);
        }
        Ok(())
    }

    /// Inside a listed CIDR, and not the network or broadcast address of a
    /// listed IPv4 CIDR of /30 or shorter.
    fn listed(&self, ip: IpAddr) -> Result<(), DestinationRefusal> {
        let mut inside = false;
        for net in self.allowed.iter().filter(|n| n.contains(&ip)) {
            inside = true;
            // RFC 3021: /31 and /32 have no network or broadcast address.
            if let IpNet::V4(v4) = net
                && v4.prefix_len() <= 30
                && (IpAddr::V4(v4.network()) == ip || IpAddr::V4(v4.broadcast()) == ip)
            {
                return Err(DestinationRefusal::Broadcast);
            }
        }
        if inside {
            Ok(())
        } else {
            Err(DestinationRefusal::NotInAllowList)
        }
    }
}

/// Most RTP packets one announcement sends (60 s at 20 ms), a backstop
/// against an oversized embedded file.
///
/// ## NIST 800-53 Rev5: SC-5
pub const MAX_ANNOUNCEMENT_PACKETS: usize = 3000;

/// Embedded audio files from the project's `audio_files`/ directory.
/// Files should be raw PCM: signed 16-bit little-endian, mono, 8000Hz.
static AUDIO_FILES: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../../audio_files");

/// PCMU payload type per RFC 3551.
const PCMU_PAYLOAD_TYPE: u8 = 0;
/// PCMU clock rate.
const PCMU_CLOCK_RATE: u32 = 8000;
/// Packet duration in milliseconds (20ms standard).
const PTIME_MS: u32 = 20;
/// Samples per packet at 8kHz / 20ms.
const SAMPLES_PER_PACKET: usize = 160;
/// Timestamp increment per packet.
// SAMPLES_PER_PACKET is 160, which always fits in u32.
#[allow(clippy::cast_possible_truncation)]
const TIMESTAMP_INCREMENT: u32 = SAMPLES_PER_PACKET as u32;

/// Pre-built announcement types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Binds an announcement socket and returns (socket, `actual_port`).
    /// Call this before building the SDP so the port is known.
    /// `bind_ip` specifies the zone media IP to bind to (None = 0.0.0.0).
    ///
    /// # Errors
    /// Returns an error when the socket cannot be bound to the requested
    /// address/port.
    pub async fn bind_socket(
        preferred_port: u16,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<(UdpSocket, u16), String> {
        let ip = bind_ip.map_or_else(|| "0.0.0.0".to_string(), |ip| ip.to_string());
        let bind_addr = if preferred_port > 0 {
            format!("{ip}:{preferred_port}")
        } else {
            format!("{ip}:0")
        };
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .map_err(|e| format!("Bind to {bind_addr} failed: {e}"))?;
        let port = socket.local_addr().map_err(|e| e.to_string())?.port();
        Ok((socket, port))
    }

    /// Plays an announcement on an already-bound socket.
    ///
    /// Streams PCMU RTP packets with the announcement audio at 20ms
    /// pacing (at most [`MAX_ANNOUNCEMENT_PACKETS`]), then returns the
    /// number of packets sent.
    ///
    /// # Errors
    /// Returns an error when the socket's local address cannot be read,
    /// when the socket cannot address the destination's family, or on the
    /// first permanent send error. Transient send failures skip the packet.
    pub async fn play_on_socket(
        announcement: AnnouncementType,
        socket: UdpSocket,
        destination: SocketAddr,
        ssrc: u32,
    ) -> Result<u64, String> {
        let samples = generate_announcement(announcement);
        debug!(announcement = ?announcement, "Announcement selected");
        play_samples_on_socket(&samples, socket, destination, ssrc).await
    }
}

/// Streams `samples` as PCMU RTP at 20 ms pacing, at most
/// [`MAX_ANNOUNCEMENT_PACKETS`] packets; returns the number sent.
///
/// # Errors
/// As [`AnnouncementServer::play_on_socket`].
pub(crate) async fn play_samples_on_socket(
    samples: &[i16],
    socket: UdpSocket,
    destination: SocketAddr,
    ssrc: u32,
) -> Result<u64, String> {
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
    // An IPv6 destination on an IPv4 socket can never be sent to; refuse it
    // up front instead of failing every packet.
    let destination = destination_for_socket(local_addr, destination).map_err(|e| e.to_string())?;

    // NIST 800-53 Rev5: SC-5 -- bounded whatever the sample source.
    let total_packets = (samples.len() / SAMPLES_PER_PACKET).min(MAX_ANNOUNCEMENT_PACKETS);

    info!(
        destination = %destination,
        local_addr = %local_addr,
        total_packets,
        duration_ms = total_packets as u64 * u64::from(PTIME_MS),
        "Starting announcement playback"
    );

    let mut seq: u16 = 0;
    let mut timestamp: u32 = 0;
    let mut sent: u64 = 0;
    let mut dropped: u64 = 0;
    // Pace on a fixed 20 ms grid (no drift from send time); a late tick
    // delays the rest rather than bursting to catch up.
    let mut pace = tokio::time::interval(Duration::from_millis(u64::from(PTIME_MS)));
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    for chunk in samples
        .chunks(SAMPLES_PER_PACKET)
        .take(MAX_ANNOUNCEMENT_PACKETS)
    {
        pace.tick().await;

        // Encode PCM samples to PCMU
        let payload: Vec<u8> = chunk.iter().map(|&s| G711Ulaw::encode_sample(s)).collect();

        let header = RtpHeader::new(PCMU_PAYLOAD_TYPE, seq, timestamp, ssrc);
        let packet = RtpPacket::new(header, Bytes::from(payload));
        let packet_bytes = packet.to_bytes();

        match socket.send_to(&packet_bytes, destination).await {
            Ok(_) => sent += 1,
            Err(e) if is_transient_send_error(&e) => {
                dropped += 1;
                debug!(error = %e, seq, "RTP packet not sent (transient)");
            }
            Err(e) => {
                // A permanent error (unreachable network, bad address)
                // fails every packet: stop rather than log each one.
                warn!(error = %e, sent, "Announcement RTP send failed; playback stopped");
                return Err(format!(
                    "RTP send failed after {sent} packets: {:?}",
                    e.kind()
                ));
            }
        }

        seq = seq.wrapping_add(1);
        timestamp = timestamp.wrapping_add(TIMESTAMP_INCREMENT);
    }

    if dropped > 0 {
        warn!(sent, dropped, "Announcement packets dropped on send");
    }
    debug!(packets_sent = sent, "Announcement playback complete");

    Ok(sent)
}

/// Send errors worth skipping one packet for (buffer pressure, an ICMP
/// port-unreachable reported on a later send); anything else is permanent.
fn is_transient_send_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    // ENOBUFS: Linux 105, Windows WSAENOBUFS 10055, BSD/macOS 55.
    #[cfg(target_os = "linux")]
    const ENOBUFS: i32 = 105;
    #[cfg(windows)]
    const ENOBUFS: i32 = 10055;
    #[cfg(not(any(target_os = "linux", windows)))]
    const ENOBUFS: i32 = 55;
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::ConnectionRefused
    ) || e.raw_os_error() == Some(ENOBUFS)
}

/// Loads an embedded PCM file as 16-bit signed samples.
/// Falls back to synthesized tones if the file is not found.
fn load_pcm_file(filename: &str) -> Option<Vec<i16>> {
    AUDIO_FILES.get_file(filename).map(|file| {
        let bytes = file.contents();
        // Parse as signed 16-bit little-endian samples
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
            .collect()
    })
}

/// Generates PCM 16-bit signed samples at 8kHz for the given announcement.
fn generate_announcement(announcement: AnnouncementType) -> Vec<i16> {
    match announcement {
        AnnouncementType::NumberNotInService => load_pcm_file("Not_in_service.pcm").map_or_else(
            || {
                warn!(
                    "Not_in_service.pcm not found in embedded audio_files, using synthesized tones"
                );
                generate_number_not_in_service()
            },
            |samples| {
                info!(
                    samples = samples.len(),
                    duration_ms = samples.len() * 1000 / PCMU_CLOCK_RATE as usize,
                    "Loaded embedded PCM: Not_in_service.pcm"
                );
                samples
            },
        ),
        AnnouncementType::AllCircuitsBusy => {
            load_pcm_file("All_circuits_busy.pcm").unwrap_or_else(generate_all_circuits_busy)
        }
        AnnouncementType::Silence => vec![0i16; PCMU_CLOCK_RATE as usize * 2],
    }
}

/// Generates the classic "number not in service" announcement:
/// Three SIT tones (Special Information Tones per Bellcore GR-674)
/// followed by synthesized speech approximation.
///
/// SIT tone sequence (intercept): 985.2 Hz, 1428.5 Hz, 1776.7 Hz
/// Each tone: 276ms + 276ms + 380ms
// Tone-generation math intentionally casts between f64 sample math and
// integer sample counts/values; durations and amplitudes are bounded.
#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn generate_number_not_in_service() -> Vec<i16> {
    let sample_rate = f64::from(PCMU_CLOCK_RATE);
    let mut samples = Vec::new();

    // === SIT Tones (Special Information Tones) ===
    // Intercept pattern: indicates number is not in service
    let sit_tones = [
        (985.2, 0.276),  // First tone
        (1428.5, 0.276), // Second tone
        (1776.7, 0.380), // Third tone
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
        SpeechSegment {
            f1: 270.0,
            f2: 2300.0,
            duration: 0.18,
            amplitude: 0.6,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.06,
            amplitude: 0.0,
        }, // pause
        // "sorry"
        SpeechSegment {
            f1: 700.0,
            f2: 1200.0,
            duration: 0.15,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 270.0,
            f2: 2300.0,
            duration: 0.15,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.15,
            amplitude: 0.0,
        }, // pause
        // "the"
        SpeechSegment {
            f1: 500.0,
            f2: 1500.0,
            duration: 0.08,
            amplitude: 0.4,
        },
        // "number"
        SpeechSegment {
            f1: 500.0,
            f2: 1800.0,
            duration: 0.15,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 300.0,
            f2: 1700.0,
            duration: 0.12,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.06,
            amplitude: 0.0,
        },
        // "you have"
        SpeechSegment {
            f1: 300.0,
            f2: 2300.0,
            duration: 0.10,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 700.0,
            f2: 1100.0,
            duration: 0.12,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.06,
            amplitude: 0.0,
        },
        // "dialed"
        SpeechSegment {
            f1: 400.0,
            f2: 2100.0,
            duration: 0.15,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 500.0,
            f2: 1800.0,
            duration: 0.12,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.15,
            amplitude: 0.0,
        }, // longer pause
        // "is not"
        SpeechSegment {
            f1: 400.0,
            f2: 2000.0,
            duration: 0.08,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 600.0,
            f2: 1200.0,
            duration: 0.12,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.06,
            amplitude: 0.0,
        },
        // "in service"
        SpeechSegment {
            f1: 400.0,
            f2: 2200.0,
            duration: 0.08,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 300.0,
            f2: 1600.0,
            duration: 0.18,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 400.0,
            f2: 2000.0,
            duration: 0.12,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.25,
            amplitude: 0.0,
        }, // sentence pause
        // "Please check"
        SpeechSegment {
            f1: 270.0,
            f2: 2300.0,
            duration: 0.15,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 500.0,
            f2: 1900.0,
            duration: 0.12,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.06,
            amplitude: 0.0,
        },
        // "the number"
        SpeechSegment {
            f1: 500.0,
            f2: 1500.0,
            duration: 0.08,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 500.0,
            f2: 1800.0,
            duration: 0.15,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 300.0,
            f2: 1700.0,
            duration: 0.12,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.06,
            amplitude: 0.0,
        },
        // "and dial"
        SpeechSegment {
            f1: 700.0,
            f2: 1100.0,
            duration: 0.10,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 400.0,
            f2: 2100.0,
            duration: 0.15,
            amplitude: 0.5,
        },
        SpeechSegment {
            f1: 500.0,
            f2: 1800.0,
            duration: 0.12,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 0.0,
            f2: 0.0,
            duration: 0.06,
            amplitude: 0.0,
        },
        // "again"
        SpeechSegment {
            f1: 500.0,
            f2: 1700.0,
            duration: 0.12,
            amplitude: 0.4,
        },
        SpeechSegment {
            f1: 270.0,
            f2: 2300.0,
            duration: 0.18,
            amplitude: 0.5,
        },
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
// Tone-generation math intentionally casts between f64 sample math and
// integer sample counts/values; durations and amplitudes are bounded.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn generate_all_circuits_busy() -> Vec<i16> {
    let sample_rate = f64::from(PCMU_CLOCK_RATE);
    let mut samples = Vec::new();

    // Reorder busy SIT: 985.2 Hz, 1428.5 Hz, 1776.7 Hz (same tones, shorter)
    let sit_tones = [(985.2, 0.276), (1428.5, 0.276), (1776.7, 0.380)];

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
#[must_use]
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
#[must_use]
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_silence_generation() {
        let samples = generate_announcement(AnnouncementType::Silence);
        assert_eq!(samples.len(), PCMU_CLOCK_RATE as usize * 2);
        assert!(samples.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_build_announcement_sdp() {
        let sdp = build_announcement_sdp("192.0.2.10", 16400);
        assert!(sdp.contains("c=IN IP4 192.0.2.10\r\n"));
        assert!(sdp.contains("m=audio 16400 RTP/AVP 0\r\n"));
        assert!(sdp.contains("a=sendonly"));
    }

    #[test]
    fn test_extract_rtp_dest_from_sdp() {
        let sdp = "v=0\r\nc=IN IP4 203.0.113.5\r\nm=audio 49170 RTP/AVP 0\r\n";
        let dest = extract_rtp_dest_from_sdp(sdp).unwrap();
        assert_eq!(dest.to_string(), "203.0.113.5:49170");
        assert!(extract_rtp_dest_from_sdp("v=0\r\n").is_none());
    }

    #[test]
    fn test_is_disallowed_media_ip() {
        let bad = |s: &str| is_disallowed_media_ip(s.parse::<IpAddr>().unwrap());
        // Loopback / multicast / link-local in native forms.
        assert!(bad("127.0.0.1"));
        assert!(bad("::1"));
        assert!(bad("224.0.0.1"));
        assert!(bad("ff02::1"));
        assert!(bad("169.254.10.20"));
        assert!(bad("fe80::1"));
        // IPv4-mapped IPv6 must not bypass the IPv4-oriented checks.
        assert!(bad("::ffff:127.0.0.1"));
        assert!(bad("::ffff:169.254.10.20"));
        assert!(bad("::ffff:224.0.0.1"));
        // Ordinary routable addresses are allowed.
        assert!(!bad("203.0.113.5"));
        assert!(!bad("8.8.8.8"));
        assert!(!bad("2001:db8::1"));
    }
}

/// SR-41: destination policy and playback bound (QA-first).
///
/// ## NIST 800-53 Rev5: SC-7, SC-5, SI-10
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod qa_sr41_tests {
    use super::*;
    use ipnet::IpNet;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|n| n.parse().unwrap()).collect()
    }

    fn open() -> DestinationPolicy {
        DestinationPolicy {
            allow_loopback: false,
            allowed: Vec::new(),
        }
    }

    #[test]
    fn qa_disallowed_rejects_unspecified_v4_v6_and_mapped() {
        for s in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            assert!(is_disallowed_media_ip(ip(s)), "{s} must be refused");
        }
    }

    #[test]
    fn qa_disallowed_rejects_limited_broadcast() {
        assert!(is_disallowed_media_ip(ip("255.255.255.255")));
        assert!(is_disallowed_media_ip(ip("::ffff:255.255.255.255")));
        // Only the limited broadcast; a neighbouring unicast stays allowed.
        assert!(!is_disallowed_media_ip(ip("255.255.255.254")));
    }

    #[test]
    fn qa_policy_loopback_only_with_lab_flag() {
        let strict = open();
        for d in ["127.0.0.1:4000", "[::1]:4000", "[::ffff:127.0.0.1]:4000"] {
            assert_eq!(
                strict.check(sa(d)),
                Err(DestinationRefusal::Loopback),
                "{d}"
            );
        }
        let lab = DestinationPolicy {
            allow_loopback: true,
            allowed: Vec::new(),
        };
        for d in ["127.0.0.1:4000", "[::1]:4000", "[::ffff:127.0.0.1]:4000"] {
            assert_eq!(lab.check(sa(d)), Ok(()), "{d}");
        }
        // The lab flag relaxes loopback only.
        assert_eq!(
            lab.check(sa("224.0.0.1:4000")),
            Err(DestinationRefusal::Multicast)
        );
        assert_eq!(
            lab.check(sa("0.0.0.0:4000")),
            Err(DestinationRefusal::Unspecified)
        );
        assert_eq!(
            lab.check(sa("169.254.1.1:4000")),
            Err(DestinationRefusal::LinkLocal)
        );
    }

    #[test]
    fn qa_policy_classes_named() {
        let p = open();
        let cases = [
            ("0.0.0.0:4000", DestinationRefusal::Unspecified),
            ("[::]:4000", DestinationRefusal::Unspecified),
            ("255.255.255.255:4000", DestinationRefusal::Broadcast),
            ("224.0.0.1:4000", DestinationRefusal::Multicast),
            ("[ff02::1]:4000", DestinationRefusal::Multicast),
            ("169.254.10.20:4000", DestinationRefusal::LinkLocal),
            ("[fe80::1]:4000", DestinationRefusal::LinkLocal),
            ("[::ffff:224.0.0.1]:4000", DestinationRefusal::Multicast),
        ];
        for (d, want) in cases {
            assert_eq!(p.check(sa(d)), Err(want), "{d}");
        }
        assert_eq!(p.check(sa("203.0.113.5:4000")), Ok(()));
        assert_eq!(p.check(sa("[2001:db8::1]:4000")), Ok(()));
    }

    #[test]
    fn qa_policy_allow_list_contains_and_excludes() {
        let p = DestinationPolicy {
            allow_loopback: false,
            allowed: nets(&["10.0.0.0/8", "2001:db8::/32"]),
        };
        assert_eq!(p.check(sa("10.1.2.3:4000")), Ok(()));
        assert_eq!(p.check(sa("[2001:db8::5]:4000")), Ok(()));
        // The v4-mapped form is checked as its IPv4 address.
        assert_eq!(p.check(sa("[::ffff:10.1.2.3]:4000")), Ok(()));
        for d in [
            "11.0.0.1:4000",
            "[2001:db9::1]:4000",
            "[::ffff:11.0.0.1]:4000",
        ] {
            assert_eq!(
                p.check(sa(d)),
                Err(DestinationRefusal::NotInAllowList),
                "{d}"
            );
        }
        // Special classes are refused even inside a listed CIDR.
        let wide = DestinationPolicy {
            allow_loopback: false,
            allowed: nets(&["0.0.0.0/0"]),
        };
        assert_eq!(
            wide.check(sa("224.0.0.1:4000")),
            Err(DestinationRefusal::Multicast)
        );
        assert_eq!(
            wide.check(sa("127.0.0.1:4000")),
            Err(DestinationRefusal::Loopback)
        );
        // An empty list means no CIDR restriction.
        assert_eq!(open().check(sa("8.8.8.8:4000")), Ok(()));
    }

    #[test]
    fn qa_policy_refuses_cidr_network_and_broadcast() {
        let p = DestinationPolicy {
            allow_loopback: false,
            allowed: nets(&[
                "192.0.2.0/24",
                "203.0.113.4/30",
                "198.51.100.0/31",
                "198.51.100.9/32",
            ]),
        };
        // /24: network and subnet broadcast refused, hosts allowed.
        assert!(p.check(sa("192.0.2.0:4000")).is_err());
        assert_eq!(
            p.check(sa("192.0.2.255:4000")),
            Err(DestinationRefusal::Broadcast)
        );
        assert_eq!(p.check(sa("192.0.2.1:4000")), Ok(()));
        assert_eq!(p.check(sa("192.0.2.254:4000")), Ok(()));
        // /30: the boundary case still has a network and broadcast address.
        assert!(p.check(sa("203.0.113.4:4000")).is_err());
        assert_eq!(
            p.check(sa("203.0.113.7:4000")),
            Err(DestinationRefusal::Broadcast)
        );
        assert_eq!(p.check(sa("203.0.113.5:4000")), Ok(()));
        // /31 (RFC 3021) and /32 have no network/broadcast address.
        assert_eq!(p.check(sa("198.51.100.0:4000")), Ok(()));
        assert_eq!(p.check(sa("198.51.100.1:4000")), Ok(()));
        assert_eq!(p.check(sa("198.51.100.9:4000")), Ok(()));
        // Mapped form of a subnet broadcast is refused too.
        assert!(p.check(sa("[::ffff:192.0.2.255]:4000")).is_err());
    }

    #[test]
    fn qa_policy_refuses_port_zero() {
        assert_eq!(
            open().check(sa("203.0.113.5:0")),
            Err(DestinationRefusal::PortZero)
        );
        assert_eq!(
            open().check(sa("[2001:db8::1]:0")),
            Err(DestinationRefusal::PortZero)
        );
    }

    #[test]
    fn qa_policy_refusal_display_omits_address() {
        let p = DestinationPolicy {
            allow_loopback: false,
            allowed: nets(&["10.0.0.0/8", "192.0.2.0/24"]),
        };
        for d in [
            "198.18.7.9:4711",
            "127.0.0.1:4711",
            "224.0.0.9:4711",
            "169.254.7.9:4711",
            "0.0.0.0:4711",
            "192.0.2.255:4711",
            "10.7.7.9:0",
        ] {
            let addr = sa(d);
            let shown = p.check(addr).unwrap_err().to_string();
            assert!(!shown.is_empty(), "{d}");
            let ip_s = addr.ip().to_string();
            assert!(!shown.contains(&ip_s), "{d}: {shown:?} echoes the address");
            assert!(!shown.contains("4711"), "{d}: {shown:?} echoes the port");
        }
    }

    /// The engine sends at most `MAX_ANNOUNCEMENT_PACKETS` whatever the
    /// sample source length (paused clock: no real 60 s wait).
    #[tokio::test(start_paused = true)]
    async fn qa_play_on_socket_caps_packets() {
        assert_eq!(MAX_ANNOUNCEMENT_PACKETS, 3000);
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let samples = vec![0i16; (MAX_ANNOUNCEMENT_PACKETS + 50) * SAMPLES_PER_PACKET];
        let sent = play_samples_on_socket(&samples, tx, dest, 0x1234)
            .await
            .unwrap();
        assert_eq!(sent, MAX_ANNOUNCEMENT_PACKETS as u64);
        drop(rx);
    }

    proptest! {
        /// A v4-mapped IPv6 destination gets the same verdict as its IPv4 form.
        #[test]
        fn prop_policy_mapped_equals_v4(
            octets in any::<[u8; 4]>(),
            port in 0u16..=u16::MAX,
            allow_loopback in any::<bool>(),
            with_list in any::<bool>(),
        ) {
            let v4 = std::net::Ipv4Addr::from(octets);
            let mapped = IpAddr::V6(v4.to_ipv6_mapped());
            let allowed = if with_list {
                nets(&["10.0.0.0/8", "192.0.2.0/24", "127.0.0.0/8"])
            } else {
                Vec::new()
            };
            let p = DestinationPolicy { allow_loopback, allowed };
            prop_assert_eq!(
                p.check(SocketAddr::new(IpAddr::V4(v4), port)),
                p.check(SocketAddr::new(mapped, port))
            );
            prop_assert_eq!(
                is_disallowed_media_ip(IpAddr::V4(v4)),
                is_disallowed_media_ip(mapped)
            );
        }
    }
}

/// SR-41 fix round 1: NAT64/6to4 embedded IPv4, socket family, send errors.
///
/// ## NIST 800-53 Rev5: SC-7, SI-10
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod sr41_fix_tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn embedded_ipv4_decoded() {
        let e = |s: &str| embedded_ipv4(s.parse().unwrap());
        assert_eq!(e("64:ff9b::c000:201"), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(e("64:ff9b:1::c000:201"), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(e("2002:c000:201::1"), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(e("64:ff9b:2::1"), None);
        assert_eq!(e("2001:db8::1"), None);
        assert_eq!(e("192.0.2.1"), None);
    }

    #[test]
    fn nat64_and_6to4_special_classes_refused() {
        let open = DestinationPolicy::default();
        for (d, want) in [
            ("[64:ff9b::7f00:1]:4000", DestinationRefusal::Loopback),
            ("[64:ff9b::e000:1]:4000", DestinationRefusal::Multicast),
            ("[64:ff9b::ffff:ffff]:4000", DestinationRefusal::Broadcast),
            ("[64:ff9b:1::a9fe:101]:4000", DestinationRefusal::LinkLocal),
            ("[2002:7f00:1::1]:4000", DestinationRefusal::Loopback),
            ("[2002::1]:4000", DestinationRefusal::Unspecified),
        ] {
            assert_eq!(open.check(sa(d)), Err(want), "{d}");
            assert!(is_disallowed_media_ip(sa(d).ip()), "{d}");
        }
        assert_eq!(open.check(sa("[64:ff9b::c000:201]:4000")), Ok(()));
        assert!(!is_disallowed_media_ip(sa("[2002:c000:201::1]:4000").ip()));
    }

    #[test]
    fn embedded_ipv4_must_be_listed_too() {
        let p = DestinationPolicy {
            allow_loopback: false,
            allowed: parse_allowed_cidrs("V", Some("64:ff9b::/96, 192.0.2.0/24")).unwrap(),
        };
        assert_eq!(p.check(sa("[64:ff9b::c000:201]:4000")), Ok(()));
        assert_eq!(
            p.check(sa("[64:ff9b::a00:1]:4000")),
            Err(DestinationRefusal::NotInAllowList)
        );
        assert_eq!(
            p.check(sa("[64:ff9b::c000:2ff]:4000")),
            Err(DestinationRefusal::Broadcast)
        );
    }

    #[test]
    fn allowed_cidrs_parse_and_bound() {
        assert_eq!(parse_allowed_cidrs("V", None).unwrap().len(), 0);
        let got = parse_allowed_cidrs("V", Some(" 10.1.2.3/8 ,2001:db8::/32,")).unwrap();
        let got: Vec<String> = got.iter().map(ToString::to_string).collect();
        assert_eq!(got, ["10.0.0.0/8", "2001:db8::/32"]);
        assert!(parse_allowed_cidrs("V", Some("x")).is_err_and(|e| e.contains('V')));
        let many: Vec<String> = (0..=MAX_DEST_CIDRS)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        assert!(parse_allowed_cidrs("V", Some(&many.join(","))).is_err());
    }

    #[test]
    fn socket_family_mapping() {
        let v4 = sa("0.0.0.0:0");
        let v6 = sa("[::]:0");
        assert_eq!(
            destination_for_socket(v4, sa("[::ffff:192.0.2.1]:5")),
            Ok(sa("192.0.2.1:5"))
        );
        assert_eq!(
            destination_for_socket(v4, sa("[2001:db8::1]:5")),
            Err(DestinationRefusal::AddressFamily)
        );
        assert_eq!(
            destination_for_socket(v6, sa("192.0.2.1:5")),
            Ok(sa("[::ffff:192.0.2.1]:5"))
        );
        assert_eq!(
            destination_for_socket(v6, sa("[2001:db8::1]:5")),
            Ok(sa("[2001:db8::1]:5"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_destination_on_ipv4_socket_fails_fast() {
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let samples = vec![0i16; 10 * SAMPLES_PER_PACKET];
        let r = play_samples_on_socket(&samples, tx, sa("[2001:db8::1]:4000"), 1).await;
        assert!(r.is_err_and(|e| !e.contains("2001:db8")));
    }

    #[test]
    fn transient_send_errors() {
        use std::io::{Error, ErrorKind};
        assert!(is_transient_send_error(&Error::from(ErrorKind::WouldBlock)));
        assert!(is_transient_send_error(&Error::from(
            ErrorKind::ConnectionRefused
        )));
        assert!(!is_transient_send_error(&Error::from(
            ErrorKind::PermissionDenied
        )));
        assert!(!is_transient_send_error(&Error::from(
            ErrorKind::InvalidInput
        )));
    }
}
