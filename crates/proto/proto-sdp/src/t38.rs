//! T.38 fax relay SDP attributes (ITU-T T.38 Annex D, RFC 3362, RFC 4612).
//!
//! Typed view of the `T38*` attributes carried on an `m=image ... t38`
//! media description. Parsing is total: duplicates, out-of-range numbers and
//! non-ASCII values are rejected with an [`SdpError`], never a panic.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SI-10**: Information Input Validation (attacker-supplied SDP values
//!   are range-checked before the SBC forwards them)
//! - **SC-5**: Denial-of-Service Protection ([`T38Params::clamp`] lowers
//!   buffer and datagram sizes a far gateway is asked to commit to)
//!
//! ## RFC / ITU-T Compliance
//!
//! - **ITU-T T.38 Annex D**: SDP attribute names and values
//! - **RFC 3362**: `image/t38` media type registration
//! - **RFC 4612**: MIME parameters equivalent to the Annex D attributes

use crate::attribute::{Attribute, AttributeName};
use crate::error::{SdpError, SdpResult};
use crate::media::MediaDescription;

/// Highest T.38 version defined (ITU-T T.38 (2010) is version 3).
pub const T38_MAX_VERSION: u8 = 3;

/// Highest `T38MaxBitRate` value accepted (V.34 half-duplex, 33.6 kbit/s).
pub const T38_MAX_BIT_RATE: u32 = 33_600;

/// `T38FaxRateManagement` values (ITU-T T.38 Annex D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum T38RateManagement {
    /// `localTCF`: TCF generated locally by the receiving gateway.
    LocalTcf,
    /// `transferredTCF`: TCF transferred end to end.
    TransferredTcf,
}

impl T38RateManagement {
    /// Annex D spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LocalTcf => "localTCF",
            Self::TransferredTcf => "transferredTCF",
        }
    }

    /// Parses an Annex D value (case-insensitive, interop practice).
    #[must_use]
    pub const fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("localTCF") {
            Some(Self::LocalTcf)
        } else if s.eq_ignore_ascii_case("transferredTCF") {
            Some(Self::TransferredTcf)
        } else {
            None
        }
    }
}

/// `T38FaxUdpEC` error-correction mode (ITU-T T.38 Annex D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum T38UdpEc {
    /// `t38UDPRedundancy`.
    Redundancy,
    /// `t38UDPFEC`.
    Fec,
    /// `t38UDPNoEC` (also the meaning when the attribute is absent).
    NoEc,
}

impl T38UdpEc {
    /// Annex D spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Redundancy => "t38UDPRedundancy",
            Self::Fec => "t38UDPFEC",
            Self::NoEc => "t38UDPNoEC",
        }
    }

    /// Parses an Annex D value (case-insensitive, interop practice).
    #[must_use]
    pub const fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("t38UDPRedundancy") {
            Some(Self::Redundancy)
        } else if s.eq_ignore_ascii_case("t38UDPFEC") {
            Some(Self::Fec)
        } else if s.eq_ignore_ascii_case("t38UDPNoEC") {
            Some(Self::NoEc)
        } else {
            None
        }
    }
}

/// Typed T.38 Annex D parameters of one `m=image` media description.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct T38Params {
    /// `T38FaxVersion` (0..=3).
    pub version: Option<u8>,
    /// `T38MaxBitRate` in bit/s (<= 33600).
    pub max_bit_rate: Option<u32>,
    /// `T38FaxFillBitRemoval`.
    pub fill_bit_removal: bool,
    /// `T38FaxTranscodingMMR`.
    pub transcoding_mmr: bool,
    /// `T38FaxTranscodingJBIG`.
    pub transcoding_jbig: bool,
    /// `T38FaxRateManagement`.
    pub rate_management: Option<T38RateManagement>,
    /// `T38FaxMaxBuffer` in octets.
    pub max_buffer: Option<u32>,
    /// `T38FaxMaxDatagram` in octets.
    pub max_datagram: Option<u16>,
    /// `T38FaxUdpEC`.
    pub udp_ec: Option<T38UdpEc>,
    /// Unknown `T38*` attributes, preserved verbatim for interop.
    pub other: Vec<Attribute>,
}

/// Known Annex D attribute keys, lower-cased for matching.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Version,
    MaxBitRate,
    FillBitRemoval,
    TranscodingMmr,
    TranscodingJbig,
    RateManagement,
    MaxBuffer,
    MaxDatagram,
    UdpEc,
}

impl Key {
    const ALL: [Self; 9] = [
        Self::Version,
        Self::MaxBitRate,
        Self::FillBitRemoval,
        Self::TranscodingMmr,
        Self::TranscodingJbig,
        Self::RateManagement,
        Self::MaxBuffer,
        Self::MaxDatagram,
        Self::UdpEc,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Version => "T38FaxVersion",
            Self::MaxBitRate => "T38MaxBitRate",
            Self::FillBitRemoval => "T38FaxFillBitRemoval",
            Self::TranscodingMmr => "T38FaxTranscodingMMR",
            Self::TranscodingJbig => "T38FaxTranscodingJBIG",
            Self::RateManagement => "T38FaxRateManagement",
            Self::MaxBuffer => "T38FaxMaxBuffer",
            Self::MaxDatagram => "T38FaxMaxDatagram",
            Self::UdpEc => "T38FaxUdpEC",
        }
    }

    fn lookup(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name().eq_ignore_ascii_case(name))
    }
}

/// Returns true if `name` is a T.38 attribute name (`T38` prefix, any case).
#[must_use]
pub fn is_t38_attribute_name(name: &str) -> bool {
    name.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("t38"))
}

/// Lowers `value` to `cap`; true if it changed.
const fn lower_u32(value: &mut Option<u32>, cap: u32) -> bool {
    match value {
        Some(v) if *v > cap => {
            *v = cap;
            true
        }
        _ => false,
    }
}

fn invalid(name: &str, reason: &str) -> SdpError {
    SdpError::InvalidAttribute {
        name: name.to_string(),
        reason: reason.to_string(),
    }
}

/// Parses a decimal value made only of ASCII digits (SI-10: no sign, no
/// whitespace inside, no non-ASCII).
fn parse_uint<T: std::str::FromStr>(name: &str, value: Option<&str>) -> SdpResult<T> {
    let v = value.map(str::trim).unwrap_or_default();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(name, "expected unsigned decimal value"));
    }
    v.parse::<T>()
        .map_err(|_| invalid(name, "value out of range"))
}

/// Boolean flag: bare flag means true; `:0` / `:1` are also accepted.
fn parse_flag(name: &str, value: Option<&str>) -> SdpResult<bool> {
    match value.map(str::trim) {
        None | Some("1") => Ok(true),
        Some("0") => Ok(false),
        Some(_) => Err(invalid(name, "expected flag, 0 or 1")),
    }
}

impl T38Params {
    /// Extracts the T.38 parameters from a media description.
    ///
    /// # Errors
    /// Returns [`SdpError::InvalidAttribute`] for a duplicate known attribute,
    /// a non-ASCII or non-numeric value, or a value out of range.
    pub fn from_media(media: &MediaDescription) -> SdpResult<Self> {
        let mut params = Self::default();
        let mut seen = [false; Key::ALL.len()];

        for attr in &media.attributes {
            let AttributeName::Custom(name) = &attr.name else {
                continue;
            };
            if !is_t38_attribute_name(name) {
                continue;
            }
            // SI-10: reject non-ASCII anywhere in a T.38 attribute.
            if !name.is_ascii() || attr.value.as_deref().is_some_and(|v| !v.is_ascii()) {
                return Err(invalid(name, "non-ASCII T.38 attribute"));
            }
            let Some(key) = Key::lookup(name) else {
                params.other.push(attr.clone());
                continue;
            };
            let slot = Key::ALL.iter().position(|k| *k == key).unwrap_or(0);
            if seen.get(slot).copied().unwrap_or(false) {
                return Err(invalid(name, "duplicate T.38 attribute"));
            }
            if let Some(s) = seen.get_mut(slot) {
                *s = true;
            }
            let value = attr.value.as_deref();
            match key {
                Key::Version => {
                    let v: u8 = parse_uint(name, value)?;
                    if v > T38_MAX_VERSION {
                        return Err(invalid(name, "unknown T.38 version"));
                    }
                    params.version = Some(v);
                }
                Key::MaxBitRate => {
                    let v: u32 = parse_uint(name, value)?;
                    if v > T38_MAX_BIT_RATE {
                        return Err(invalid(name, "bit rate above 33600"));
                    }
                    params.max_bit_rate = Some(v);
                }
                Key::FillBitRemoval => params.fill_bit_removal = parse_flag(name, value)?,
                Key::TranscodingMmr => params.transcoding_mmr = parse_flag(name, value)?,
                Key::TranscodingJbig => params.transcoding_jbig = parse_flag(name, value)?,
                Key::RateManagement => {
                    let v = value.map(str::trim).unwrap_or_default();
                    params.rate_management = Some(
                        T38RateManagement::parse(v)
                            .ok_or_else(|| invalid(name, "unknown rate management"))?,
                    );
                }
                Key::MaxBuffer => params.max_buffer = Some(parse_uint(name, value)?),
                Key::MaxDatagram => params.max_datagram = Some(parse_uint(name, value)?),
                Key::UdpEc => {
                    let v = value.map(str::trim).unwrap_or_default();
                    params.udp_ec = Some(
                        T38UdpEc::parse(v)
                            .ok_or_else(|| invalid(name, "unknown error correction"))?,
                    );
                }
            }
        }
        Ok(params)
    }

    /// Effective error-correction mode: an absent `T38FaxUdpEC` means
    /// `t38UDPNoEC` (ITU-T T.38 Annex D).
    #[must_use]
    pub fn effective_udp_ec(&self) -> T38UdpEc {
        self.udp_ec.unwrap_or(T38UdpEc::NoEc)
    }

    /// Lowers `T38MaxBitRate`, `T38FaxMaxDatagram` and `T38FaxMaxBuffer` to the
    /// given caps. Values are only ever lowered, which keeps an answer within
    /// the offer (ITU-T T.38 Annex D). Absent values are left absent.
    ///
    /// Returns true if anything changed.
    // NIST 800-53 Rev5: SC-5 (a peer cannot make a far gateway commit to
    // oversized buffers or datagrams through the SBC)
    pub const fn clamp(&mut self, max_bit_rate: u32, max_datagram: u16, max_buffer: u32) -> bool {
        let rate = lower_u32(&mut self.max_bit_rate, max_bit_rate);
        let datagram = match &mut self.max_datagram {
            Some(v) if *v > max_datagram => {
                *v = max_datagram;
                true
            }
            _ => false,
        };
        let buffer = lower_u32(&mut self.max_buffer, max_buffer);
        rate | datagram | buffer
    }

    /// Returns the attributes in Annex D casing, known attributes first, then
    /// unknown `T38*` attributes verbatim. False flags are omitted.
    #[must_use]
    pub fn to_attributes(&self) -> Vec<Attribute> {
        let mut out = Vec::new();
        let custom = |k: Key| AttributeName::Custom(k.name().to_string());
        if let Some(v) = self.version {
            out.push(Attribute::new(custom(Key::Version), v.to_string()));
        }
        if let Some(v) = self.max_bit_rate {
            out.push(Attribute::new(custom(Key::MaxBitRate), v.to_string()));
        }
        if self.fill_bit_removal {
            out.push(Attribute::flag(custom(Key::FillBitRemoval)));
        }
        if self.transcoding_mmr {
            out.push(Attribute::flag(custom(Key::TranscodingMmr)));
        }
        if self.transcoding_jbig {
            out.push(Attribute::flag(custom(Key::TranscodingJbig)));
        }
        if let Some(v) = self.rate_management {
            out.push(Attribute::new(custom(Key::RateManagement), v.as_str()));
        }
        if let Some(v) = self.max_buffer {
            out.push(Attribute::new(custom(Key::MaxBuffer), v.to_string()));
        }
        if let Some(v) = self.max_datagram {
            out.push(Attribute::new(custom(Key::MaxDatagram), v.to_string()));
        }
        if let Some(v) = self.udp_ec {
            out.push(Attribute::new(custom(Key::UdpEc), v.as_str()));
        }
        out.extend(self.other.iter().cloned());
        out
    }

    /// Replaces every `T38*` attribute of `media` with [`Self::to_attributes`],
    /// keeping all other attributes in place.
    pub fn write_attributes(&self, media: &mut MediaDescription) {
        media.attributes.retain(|a| match &a.name {
            AttributeName::Custom(n) => !is_t38_attribute_name(n),
            _ => true,
        });
        media.attributes.extend(self.to_attributes());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::session::SessionDescription;

    const FULL: &str = "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=image 5000 udptl t38\r\n\
a=T38FaxVersion:0\r\n\
a=T38MaxBitRate:14400\r\n\
a=T38FaxFillBitRemoval\r\n\
a=T38FaxTranscodingMMR:0\r\n\
a=T38FaxTranscodingJBIG:1\r\n\
a=T38FaxRateManagement:transferredTCF\r\n\
a=T38FaxMaxBuffer:262\r\n\
a=T38FaxMaxDatagram:176\r\n\
a=T38FaxUdpEC:t38UDPRedundancy\r\n\
a=T38VendorInfo:0 0 0\r\n";

    fn media_with(attrs: &[&str]) -> MediaDescription {
        let mut m = MediaDescription::parse_mline("image 5000 udptl t38").unwrap();
        for a in attrs {
            m.add_attribute(Attribute::parse(a).unwrap());
        }
        m
    }

    #[test]
    fn parse_full_annex_d() {
        let sdp = FULL.parse::<SessionDescription>().unwrap();
        let p = T38Params::from_media(&sdp.media[0]).unwrap();
        assert_eq!(p.version, Some(0));
        assert_eq!(p.max_bit_rate, Some(14400));
        assert!(p.fill_bit_removal);
        assert!(!p.transcoding_mmr);
        assert!(p.transcoding_jbig);
        assert_eq!(p.rate_management, Some(T38RateManagement::TransferredTcf));
        assert_eq!(p.max_buffer, Some(262));
        assert_eq!(p.max_datagram, Some(176));
        assert_eq!(p.udp_ec, Some(T38UdpEc::Redundancy));
        assert_eq!(p.other.len(), 1);
    }

    #[test]
    fn round_trip() {
        let sdp = FULL.parse::<SessionDescription>().unwrap();
        let p = T38Params::from_media(&sdp.media[0]).unwrap();
        let mut m = media_with(&["sendrecv"]);
        p.write_attributes(&mut m);
        let again = T38Params::from_media(&m).unwrap();
        assert_eq!(p, again);
        assert!(m.get_attribute(&AttributeName::Sendrecv).is_some());
        let text = m.to_string();
        assert!(
            text.contains("a=T38FaxFillBitRemoval\r\n")
                || text.contains("a=T38FaxFillBitRemoval\n")
        );
        assert!(!text.contains("TranscodingMMR"));
    }

    #[test]
    fn case_insensitive_names_and_values() {
        let p = T38Params::from_media(&media_with(&[
            "t38faxversion:1",
            "T38FAXUDPEC:T38UDPFEC",
            "t38faxratemanagement:LOCALTCF",
        ]))
        .unwrap();
        assert_eq!(p.version, Some(1));
        assert_eq!(p.udp_ec, Some(T38UdpEc::Fec));
        assert_eq!(p.rate_management, Some(T38RateManagement::LocalTcf));
        // Output uses Annex D casing.
        assert!(
            p.to_attributes()
                .iter()
                .any(|a| a.name.as_str() == "T38FaxUdpEC")
        );
    }

    #[test]
    fn absent_ec_means_no_ec() {
        let p = T38Params::from_media(&media_with(&[])).unwrap();
        assert_eq!(p.effective_udp_ec(), T38UdpEc::NoEc);
    }

    #[test]
    fn rejects_bad_values() {
        let bad: &[&[&str]] = &[
            &["T38FaxVersion:0", "T38FaxVersion:1"],
            &["T38FaxVersion:4"],
            &["T38FaxVersion:-1"],
            &["T38MaxBitRate:33601"],
            &["T38MaxBitRate:99999999999999999999"],
            &["T38MaxBitRate:abc"],
            &["T38MaxBitRate:"],
            &["T38FaxMaxDatagram:65536"],
            &["T38FaxMaxBuffer:1\u{0661}"],
            &["T38FaxFillBitRemoval:2"],
            &["T38FaxUdpEC:t38UDPMagic"],
            &["T38FaxRateManagement:other"],
            &["T38Vendor\u{00e9}:x"],
            &["t38faxudpec:t38UDPFEC", "T38FaxUdpEC:t38UDPNoEC"],
        ];
        for attrs in bad {
            assert!(
                T38Params::from_media(&media_with(attrs)).is_err(),
                "accepted {attrs:?}"
            );
        }
    }

    #[test]
    fn clamp_only_lowers() {
        let mut p = T38Params {
            max_bit_rate: Some(33600),
            max_datagram: Some(100),
            max_buffer: None,
            ..T38Params::default()
        };
        assert!(p.clamp(14400, 1400, 4096));
        assert_eq!(p.max_bit_rate, Some(14400));
        assert_eq!(p.max_datagram, Some(100));
        assert_eq!(p.max_buffer, None);
        assert!(!p.clamp(14400, 1400, 4096));
    }

    #[test]
    fn table_round_trip() {
        for version in 0..=T38_MAX_VERSION {
            for ec in [T38UdpEc::Redundancy, T38UdpEc::Fec, T38UdpEc::NoEc] {
                for flags in 0u8..8 {
                    let p = T38Params {
                        version: Some(version),
                        max_bit_rate: Some(9600),
                        fill_bit_removal: flags & 1 != 0,
                        transcoding_mmr: flags & 2 != 0,
                        transcoding_jbig: flags & 4 != 0,
                        rate_management: Some(T38RateManagement::LocalTcf),
                        max_buffer: Some(2000),
                        max_datagram: Some(400),
                        udp_ec: Some(ec),
                        other: Vec::new(),
                    };
                    let mut m = media_with(&[]);
                    p.write_attributes(&mut m);
                    assert_eq!(T38Params::from_media(&m).unwrap(), p);
                }
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn proptest_round_trip(
            version in proptest::option::of(0u8..=T38_MAX_VERSION),
            rate in proptest::option::of(0u32..=T38_MAX_BIT_RATE),
            flags in 0u8..8,
            buf in proptest::option::of(proptest::num::u32::ANY),
            dgram in proptest::option::of(proptest::num::u16::ANY),
            ec in proptest::option::of(0u8..3),
        ) {
            let p = T38Params {
                version,
                max_bit_rate: rate,
                fill_bit_removal: flags & 1 != 0,
                transcoding_mmr: flags & 2 != 0,
                transcoding_jbig: flags & 4 != 0,
                rate_management: None,
                max_buffer: buf,
                max_datagram: dgram,
                udp_ec: ec.map(|e| match e {
                    0 => T38UdpEc::Redundancy,
                    1 => T38UdpEc::Fec,
                    _ => T38UdpEc::NoEc,
                }),
                other: Vec::new(),
            };
            let mut m = media_with(&[]);
            p.write_attributes(&mut m);
            proptest::prop_assert_eq!(T38Params::from_media(&m).unwrap(), p);
        }

        #[test]
        fn proptest_never_panics(name in "[Tt]38[A-Za-z]{0,20}", value in "\\PC{0,20}") {
            let _ = T38Params::from_media(&media_with(&[&format!("{name}:{value}")]));
        }
    }
}
