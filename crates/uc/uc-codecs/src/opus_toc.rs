//! Opus packet TOC (table-of-contents) parsing per RFC 6716 §3.1.
//!
//! Pure, allocation-free helpers used to size loss-concealment and in-band
//! FEC decodes without handing an attacker-chosen frame size to libopus.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SI-10**: Information Input Validation (RTP payloads are untrusted)

/// Opus coding mode signalled by the TOC `config` field (RFC 6716 §3.1, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusMode {
    /// SILK-only (configs 0-11).
    Silk,
    /// Hybrid SILK+CELT (configs 12-15).
    Hybrid,
    /// CELT-only (configs 16-31).
    Celt,
}

/// Maximum Opus packet duration in 48 kHz samples per channel (120 ms).
// RFC 6716 §3.2.5: "the total duration contained within a packet MUST NOT exceed 120 ms".
const MAX_PACKET_SAMPLES_48K: usize = 5760;

/// Sample rates libopus can decode at (RFC 6716 §2, `opus_decoder_create`).
const VALID_RATES: [u32; 5] = [8000, 12000, 16000, 24000, 48000];

/// Returns the coding mode for a TOC byte.
pub fn mode(toc: u8) -> OpusMode {
    match toc >> 3 {
        0..=11 => OpusMode::Silk,
        12..=15 => OpusMode::Hybrid,
        _ => OpusMode::Celt,
    }
}

/// Returns the per-frame duration of a TOC byte in 48 kHz samples per channel.
///
/// RFC 6716 §3.1 Table 2.
fn frame_samples_48k(toc: u8) -> usize {
    let config = toc >> 3;
    match config {
        // SILK-only: 10, 20, 40, 60 ms per bandwidth (NB/MB/WB).
        0..=11 => [480, 960, 1920, 2880][(config & 0x3) as usize],
        // Hybrid: 10, 20 ms per bandwidth (SWB/FB).
        12..=15 => [480, 960][(config & 0x1) as usize],
        // CELT-only: 2.5, 5, 10, 20 ms per bandwidth (NB/WB/SWB/FB).
        _ => [120, 240, 480, 960][(config & 0x3) as usize],
    }
}

/// Converts a 48 kHz sample count to `rate`. Returns `None` for unsupported rates.
fn scale_to_rate(samples_48k: usize, rate: u32) -> Option<usize> {
    if !VALID_RATES.contains(&rate) {
        return None;
    }
    // All valid rates divide 48000 and every frame size is a multiple of 120,
    // so this division is exact.
    Some(samples_48k * rate as usize / 48000)
}

/// Returns the per-frame duration of a TOC byte, in samples per channel at `rate`.
pub fn samples_per_frame(toc: u8, rate: u32) -> Option<usize> {
    scale_to_rate(frame_samples_48k(toc), rate)
}

/// Returns the number of Opus frames in `packet` (RFC 6716 §3.2).
///
/// Returns `None` for an empty packet, a code-3 packet without its frame
/// count byte, a zero frame count, or a total duration over 120 ms.
pub fn frame_count(packet: &[u8]) -> Option<usize> {
    let toc = *packet.first()?;
    let count = match toc & 0x3 {
        // RFC 6716 §3.2.2: code 0, one frame.
        0 => 1,
        // RFC 6716 §3.2.3 / §3.2.4: codes 1 and 2, two frames.
        1 | 2 => 2,
        // RFC 6716 §3.2.5: code 3, M frames signalled in the second byte.
        _ => {
            let m = (*packet.get(1)? & 0x3F) as usize;
            if m == 0 {
                return None;
            }
            m
        }
    };
    if count * frame_samples_48k(toc) > MAX_PACKET_SAMPLES_48K {
        return None;
    }
    Some(count)
}

/// Returns the total duration of `packet`, in samples per channel at `rate`.
///
/// Returns `None` for malformed packets or unsupported rates.
pub fn packet_samples_per_channel(packet: &[u8], rate: u32) -> Option<usize> {
    let toc = *packet.first()?;
    let frames = frame_count(packet)?;
    scale_to_rate(frames * frame_samples_48k(toc), rate)
}

/// Returns true if `samples_per_channel` is a decodable Opus frame size at
/// `rate`: 2.5, 5, 10, 20, 40 or 60 ms (RFC 6716 §2.1.4).
pub fn is_valid_frame_size(samples_per_channel: usize, rate: u32) -> bool {
    [120usize, 240, 480, 960, 1920, 2880]
        .iter()
        .any(|&s| scale_to_rate(s, rate) == Some(samples_per_channel))
}

/// Returns true if `next_packet` can carry in-band FEC (LBRR) data that
/// libopus will use to rebuild a lost frame of `lost_samples_per_channel`.
///
/// RFC 6716 §2.1.7 / §4.2.4: LBRR exists only in SILK and Hybrid modes.
/// libopus also falls back to PLC when the lost frame is shorter than one
/// frame of the next packet, so that case is rejected here too.
pub fn may_carry_fec(next_packet: &[u8], lost_samples_per_channel: usize, rate: u32) -> bool {
    let Some(&toc) = next_packet.first() else {
        return false;
    };
    if mode(toc) == OpusMode::Celt || frame_count(next_packet).is_none() {
        return false;
    }
    samples_per_frame(toc, rate).is_some_and(|s| s <= lost_samples_per_channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modes() {
        assert_eq!(mode(0), OpusMode::Silk);
        assert_eq!(mode(11 << 3), OpusMode::Silk);
        assert_eq!(mode(12 << 3), OpusMode::Hybrid);
        assert_eq!(mode(15 << 3), OpusMode::Hybrid);
        assert_eq!(mode(16 << 3), OpusMode::Celt);
        assert_eq!(mode(31 << 3), OpusMode::Celt);
    }

    #[test]
    fn test_table_all_configs_and_codes() {
        // RFC 6716 §3.1 Table 2, in ms * 10.
        let expected_ms10: [usize; 32] = [
            100, 200, 400, 600, 100, 200, 400, 600, 100, 200, 400, 600, // SILK
            100, 200, 100, 200, // Hybrid
            25, 50, 100, 200, 25, 50, 100, 200, 25, 50, 100, 200, 25, 50, 100, 200, // CELT
        ];
        for config in 0u8..32 {
            let per_frame = expected_ms10[config as usize] * 48 / 10;
            for code in 0u8..4 {
                let toc = (config << 3) | code;
                assert_eq!(samples_per_frame(toc, 48000), Some(per_frame));
                // Code 3 with 2 frames in the count byte.
                let pkt = [toc, 2, 0, 0];
                let frames = match code {
                    0 => 1,
                    _ => 2,
                };
                let total = frames * per_frame;
                let got = packet_samples_per_channel(&pkt, 48000);
                if total <= MAX_PACKET_SAMPLES_48K {
                    assert_eq!(got, Some(total), "config {config} code {code}");
                } else {
                    assert_eq!(got, None);
                }
            }
        }
    }

    #[test]
    fn test_rate_scaling() {
        let toc = 1 << 3; // SILK NB 20 ms
        assert_eq!(samples_per_frame(toc, 8000), Some(160));
        assert_eq!(samples_per_frame(toc, 16000), Some(320));
        assert_eq!(samples_per_frame(16 << 3, 8000), Some(20)); // 2.5 ms
        assert_eq!(samples_per_frame(toc, 44100), None);
    }

    #[test]
    fn test_code3_limits() {
        let toc = (19 << 3) | 3; // CELT FB 20 ms, code 3
        assert_eq!(frame_count(&[toc]), None, "missing count byte");
        assert_eq!(frame_count(&[toc, 0]), None, "zero frames");
        assert_eq!(frame_count(&[toc, 6]), Some(6)); // 120 ms
        assert_eq!(frame_count(&[toc, 7]), None, "over 120 ms");
        assert_eq!(frame_count(&[]), None);
    }

    #[test]
    fn test_valid_frame_sizes() {
        assert!(is_valid_frame_size(960, 48000));
        assert!(is_valid_frame_size(120, 48000));
        assert!(is_valid_frame_size(2880, 48000));
        assert!(!is_valid_frame_size(961, 48000));
        assert!(!is_valid_frame_size(5760, 48000));
        assert!(is_valid_frame_size(160, 8000));
        assert!(!is_valid_frame_size(0, 48000));
    }

    #[test]
    fn test_may_carry_fec() {
        let silk20 = [1 << 3, 0xAA];
        let celt20 = [19 << 3, 0xAA];
        let hybrid10 = [12 << 3, 0xAA];
        assert!(may_carry_fec(&silk20, 960, 48000));
        assert!(!may_carry_fec(&silk20, 480, 48000), "lost frame shorter");
        assert!(!may_carry_fec(&celt20, 960, 48000), "CELT has no LBRR");
        assert!(may_carry_fec(&hybrid10, 960, 48000));
        assert!(!may_carry_fec(&[], 960, 48000));
    }

    #[test]
    fn test_never_panics_on_arbitrary_bytes() {
        // Exhaustive over 2-byte prefixes plus a simple LCG for longer inputs.
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let pkt = [a, b];
                let _ = packet_samples_per_channel(&pkt, 48000);
                let _ = may_carry_fec(&pkt, 960, 48000);
                let _ = packet_samples_per_channel(&pkt[..1], 16000);
            }
        }
        let mut state: u32 = 0x1234_5678;
        let mut buf = [0u8; 64];
        for _ in 0..10_000 {
            for byte in &mut buf {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            let len = (state as usize) % buf.len();
            if let Some(n) = packet_samples_per_channel(&buf[..len], 48000) {
                assert!(n <= MAX_PACKET_SAMPLES_48K);
            }
        }
    }

    // QA: malformed TOC / mismatched FEC durations.
    #[test]
    fn test_qa_fec_duration_mismatch() {
        let silk40 = [3 << 3, 0xAA]; // SILK WB? config 3 = SILK NB 60 ms
        let silk_nb40 = [2 << 3, 0xAA]; // config 2 = SILK NB 40 ms
        assert_eq!(samples_per_frame(silk_nb40[0], 48000), Some(1920));
        assert!(
            !may_carry_fec(&silk_nb40, 960, 48000),
            "40 ms next vs 20 ms lost"
        );
        assert!(may_carry_fec(&silk_nb40, 1920, 48000));
        assert!(
            !may_carry_fec(&silk40, 1920, 48000),
            "60 ms next vs 40 ms lost"
        );
        // 20 ms next frame covers the first part of a 60 ms loss.
        assert!(may_carry_fec(&[1 << 3, 0xAA], 2880, 48000));
        // Hybrid 10 ms next vs 20 ms lost is fine; vs 5 ms lost is not.
        assert!(!may_carry_fec(&[12 << 3, 0xAA], 240, 48000));
    }

    #[test]
    fn test_qa_malformed_toc_in_fec_source() {
        let code3 = (1 << 3) | 3; // SILK NB 20 ms, code 3
        assert!(!may_carry_fec(&[code3], 960, 48000), "missing count byte");
        assert!(!may_carry_fec(&[code3, 0], 960, 48000), "zero frames");
        assert!(
            !may_carry_fec(&[code3, 7], 960, 48000),
            "140 ms > 120 ms cap"
        );
        assert!(may_carry_fec(&[code3, 6], 960, 48000));
        assert_eq!(packet_samples_per_channel(&[], 48000), None);
        assert_eq!(packet_samples_per_channel(&[code3], 48000), None);
        // Unsupported decode rate.
        assert_eq!(packet_samples_per_channel(&[1 << 3], 44100), None);
        assert!(!may_carry_fec(&[1 << 3, 0xAA], 882, 44100));
    }
}
