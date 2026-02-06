//! DTMF (Dual-Tone Multi-Frequency) types for telephone signaling.
//!
//! This module provides types for DTMF digit representation and
//! RFC 4733 telephone-event RTP payload encoding.

use serde::{Deserialize, Serialize};

/// DTMF digit representation.
///
/// Supports standard DTMF tones (0-9, A-D, *, #) as defined in RFC 4733.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DtmfDigit {
    /// Digit 0.
    Zero,
    /// Digit 1.
    One,
    /// Digit 2.
    Two,
    /// Digit 3.
    Three,
    /// Digit 4.
    Four,
    /// Digit 5.
    Five,
    /// Digit 6.
    Six,
    /// Digit 7.
    Seven,
    /// Digit 8.
    Eight,
    /// Digit 9.
    Nine,
    /// Star (*).
    Star,
    /// Pound/Hash (#).
    Pound,
    /// Letter A.
    A,
    /// Letter B.
    B,
    /// Letter C.
    C,
    /// Letter D.
    D,
}

impl DtmfDigit {
    /// Returns the RFC 4733 event code for this digit.
    ///
    /// Event codes:
    /// - 0-9: digits 0-9
    /// - 10: * (star)
    /// - 11: # (pound)
    /// - 12-15: A, B, C, D
    #[must_use]
    pub const fn event_code(&self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
            Self::Nine => 9,
            Self::Star => 10,
            Self::Pound => 11,
            Self::A => 12,
            Self::B => 13,
            Self::C => 14,
            Self::D => 15,
        }
    }

    /// Creates a DTMF digit from an RFC 4733 event code.
    #[must_use]
    pub const fn from_event_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Zero),
            1 => Some(Self::One),
            2 => Some(Self::Two),
            3 => Some(Self::Three),
            4 => Some(Self::Four),
            5 => Some(Self::Five),
            6 => Some(Self::Six),
            7 => Some(Self::Seven),
            8 => Some(Self::Eight),
            9 => Some(Self::Nine),
            10 => Some(Self::Star),
            11 => Some(Self::Pound),
            12 => Some(Self::A),
            13 => Some(Self::B),
            14 => Some(Self::C),
            15 => Some(Self::D),
            _ => None,
        }
    }

    /// Creates a DTMF digit from a character.
    #[must_use]
    pub const fn from_char(c: char) -> Option<Self> {
        match c {
            '0' => Some(Self::Zero),
            '1' => Some(Self::One),
            '2' => Some(Self::Two),
            '3' => Some(Self::Three),
            '4' => Some(Self::Four),
            '5' => Some(Self::Five),
            '6' => Some(Self::Six),
            '7' => Some(Self::Seven),
            '8' => Some(Self::Eight),
            '9' => Some(Self::Nine),
            '*' => Some(Self::Star),
            '#' => Some(Self::Pound),
            'A' | 'a' => Some(Self::A),
            'B' | 'b' => Some(Self::B),
            'C' | 'c' => Some(Self::C),
            'D' | 'd' => Some(Self::D),
            _ => None,
        }
    }

    /// Returns the character representation of this digit.
    #[must_use]
    pub const fn to_char(&self) -> char {
        match self {
            Self::Zero => '0',
            Self::One => '1',
            Self::Two => '2',
            Self::Three => '3',
            Self::Four => '4',
            Self::Five => '5',
            Self::Six => '6',
            Self::Seven => '7',
            Self::Eight => '8',
            Self::Nine => '9',
            Self::Star => '*',
            Self::Pound => '#',
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
        }
    }
}

impl std::fmt::Display for DtmfDigit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_char())
    }
}

impl TryFrom<char> for DtmfDigit {
    type Error = ();

    fn try_from(c: char) -> Result<Self, Self::Error> {
        Self::from_char(c).ok_or(())
    }
}

/// RFC 4733 telephone-event RTP payload.
///
/// This structure represents the 4-byte payload format for DTMF events:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfEvent {
    /// The DTMF digit being signaled.
    pub digit: DtmfDigit,
    /// End-of-event flag. Set to true for the final packet(s) of an event.
    pub end: bool,
    /// Volume level (0-63, where 0 is loudest, 63 is -63 dBm0).
    pub volume: u8,
    /// Duration of the event in timestamp units (typically 8000 Hz clock).
    pub duration: u16,
}

impl DtmfEvent {
    /// Default DTMF volume level (-10 dBm0, commonly used).
    pub const DEFAULT_VOLUME: u8 = 10;

    /// Minimum recommended DTMF duration in milliseconds.
    pub const MIN_DURATION_MS: u32 = 40;

    /// Typical DTMF duration in milliseconds.
    pub const TYPICAL_DURATION_MS: u32 = 100;

    /// Creates a new DTMF event.
    #[must_use]
    pub const fn new(digit: DtmfDigit, duration: u16) -> Self {
        Self {
            digit,
            end: false,
            volume: Self::DEFAULT_VOLUME,
            duration,
        }
    }

    /// Creates a DTMF event with the end flag set.
    #[must_use]
    pub const fn with_end(digit: DtmfDigit, duration: u16) -> Self {
        Self {
            digit,
            end: true,
            volume: Self::DEFAULT_VOLUME,
            duration,
        }
    }

    /// Encodes the event to 4 bytes per RFC 4733.
    #[must_use]
    pub const fn encode(&self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0] = self.digit.event_code();
        bytes[1] = if self.end { 0x80 } else { 0x00 } | (self.volume & 0x3F);
        let duration_bytes = self.duration.to_be_bytes();
        bytes[2] = duration_bytes[0];
        bytes[3] = duration_bytes[1];
        bytes
    }

    /// Decodes a 4-byte RFC 4733 payload.
    #[must_use]
    pub fn decode(bytes: &[u8; 4]) -> Option<Self> {
        let digit = DtmfDigit::from_event_code(bytes[0])?;
        let end = (bytes[1] & 0x80) != 0;
        let volume = bytes[1] & 0x3F;
        let duration = u16::from_be_bytes([bytes[2], bytes[3]]);

        Some(Self {
            digit,
            end,
            volume,
            duration,
        })
    }

    /// Converts duration in milliseconds to timestamp units at 8000 Hz.
    #[must_use]
    pub fn duration_from_ms(ms: u32) -> u16 {
        // 8000 samples/sec * ms / 1000 = 8 * ms
        #[allow(clippy::cast_possible_truncation)] // value clamped to u16::MAX
        let result = (8 * ms).min(u32::from(u16::MAX)) as u16;
        result
    }

    /// Converts duration in timestamp units to milliseconds.
    #[must_use]
    #[allow(clippy::cast_lossless)] // u16 -> u32 widening; u32::from() not const-stable yet
    pub const fn duration_to_ms(&self) -> u32 {
        self.duration as u32 / 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtmf_digit_event_codes() {
        assert_eq!(DtmfDigit::Zero.event_code(), 0);
        assert_eq!(DtmfDigit::Nine.event_code(), 9);
        assert_eq!(DtmfDigit::Star.event_code(), 10);
        assert_eq!(DtmfDigit::Pound.event_code(), 11);
        assert_eq!(DtmfDigit::A.event_code(), 12);
        assert_eq!(DtmfDigit::D.event_code(), 15);
    }

    #[test]
    fn test_dtmf_digit_from_event_code() {
        assert_eq!(DtmfDigit::from_event_code(0), Some(DtmfDigit::Zero));
        assert_eq!(DtmfDigit::from_event_code(10), Some(DtmfDigit::Star));
        assert_eq!(DtmfDigit::from_event_code(15), Some(DtmfDigit::D));
        assert_eq!(DtmfDigit::from_event_code(16), None);
    }

    #[test]
    fn test_dtmf_digit_from_char() {
        assert_eq!(DtmfDigit::from_char('5'), Some(DtmfDigit::Five));
        assert_eq!(DtmfDigit::from_char('*'), Some(DtmfDigit::Star));
        assert_eq!(DtmfDigit::from_char('#'), Some(DtmfDigit::Pound));
        assert_eq!(DtmfDigit::from_char('A'), Some(DtmfDigit::A));
        assert_eq!(DtmfDigit::from_char('a'), Some(DtmfDigit::A));
        assert_eq!(DtmfDigit::from_char('X'), None);
    }

    #[test]
    fn test_dtmf_digit_to_char() {
        assert_eq!(DtmfDigit::Five.to_char(), '5');
        assert_eq!(DtmfDigit::Star.to_char(), '*');
        assert_eq!(DtmfDigit::Pound.to_char(), '#');
        assert_eq!(DtmfDigit::B.to_char(), 'B');
    }

    #[test]
    fn test_dtmf_event_encode_decode() {
        let event = DtmfEvent::new(DtmfDigit::Five, 800);
        let encoded = event.encode();
        let decoded = DtmfEvent::decode(&encoded).unwrap();

        assert_eq!(decoded.digit, DtmfDigit::Five);
        assert!(!decoded.end);
        assert_eq!(decoded.volume, DtmfEvent::DEFAULT_VOLUME);
        assert_eq!(decoded.duration, 800);
    }

    #[test]
    fn test_dtmf_event_with_end() {
        let event = DtmfEvent::with_end(DtmfDigit::Star, 1600);
        let encoded = event.encode();
        let decoded = DtmfEvent::decode(&encoded).unwrap();

        assert_eq!(decoded.digit, DtmfDigit::Star);
        assert!(decoded.end);
        assert_eq!(decoded.duration, 1600);
    }

    #[test]
    fn test_dtmf_duration_conversion() {
        // 100ms at 8000 Hz = 800 samples
        assert_eq!(DtmfEvent::duration_from_ms(100), 800);

        let event = DtmfEvent::new(DtmfDigit::One, 800);
        assert_eq!(event.duration_to_ms(), 100);
    }

    #[test]
    fn test_dtmf_event_encode_format() {
        // Test specific byte format per RFC 4733
        let event = DtmfEvent {
            digit: DtmfDigit::Five, // event code 5
            end: true,
            volume: 10,
            duration: 0x0320, // 800
        };

        let encoded = event.encode();
        assert_eq!(encoded[0], 5); // event
        assert_eq!(encoded[1], 0x8A); // E=1, volume=10
        assert_eq!(encoded[2], 0x03); // duration high byte
        assert_eq!(encoded[3], 0x20); // duration low byte
    }
}
