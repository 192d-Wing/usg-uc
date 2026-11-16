//! Hello extension codec (RFC 5246 §7.4.1.4).
//!
//! Only the extensions the CNSA profile uses are decoded; all others are
//! skipped (their bytes are still covered by the handshake transcript) and
//! the first such type is reported, so a client can refuse a `ServerHello`
//! that carries an extension it did not offer (RFC 5246 §7.4.1.4).
//!
//! | Extension | Type | Reference |
//! |---|---|---|
//! | `supported_groups` | 10 | RFC 8422 §5.1.1 |
//! | `ec_point_formats` | 11 | RFC 8422 §5.1.2 |
//! | `signature_algorithms` | 13 | RFC 5246 §7.4.1.4.1 |
//! | `use_srtp` | 14 | RFC 5764 §4.1.1 |
//! | `extended_master_secret` | 23 | RFC 7627 §5.1 |
//! | `renegotiation_info` | 0xFF01 | RFC 5746 §3.2 |

#![deny(clippy::indexing_slicing)]

use super::reader::{Reader, put_u16, put_vec8, put_vec16, u16_list, u16_list_bytes};
use super::{WireError, WireResult};

/// `supported_groups` extension type.
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
/// `ec_point_formats` extension type.
pub const EXT_EC_POINT_FORMATS: u16 = 11;
/// `signature_algorithms` extension type.
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
/// `use_srtp` extension type.
pub const EXT_USE_SRTP: u16 = 14;
/// `extended_master_secret` extension type.
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/// `renegotiation_info` extension type.
pub const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;

/// `use_srtp` extension body (RFC 5764 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UseSrtp {
    /// SRTP protection profile identifiers.
    pub profiles: Vec<u16>,
    /// Master key identifier (`srtp_mki`).
    pub mki: Vec<u8>,
}

/// The decoded extensions of a `ClientHello` or `ServerHello`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions {
    /// `supported_groups`: named group identifiers.
    pub supported_groups: Option<Vec<u16>>,
    /// `ec_point_formats`.
    pub ec_point_formats: Option<Vec<u8>>,
    /// `signature_algorithms`: signature scheme identifiers.
    pub signature_algorithms: Option<Vec<u16>>,
    /// `use_srtp`.
    pub use_srtp: Option<UseSrtp>,
    /// `extended_master_secret` present.
    pub extended_master_secret: bool,
    /// `renegotiation_info`: the `renegotiated_connection` value.
    pub renegotiation_info: Option<Vec<u8>>,
    /// Type of the first extension in the block that this codec does not
    /// decode, if there was one. Set by [`Extensions::parse`] only; never
    /// encoded.
    pub first_unknown: Option<u16>,
}

impl Extensions {
    /// Parses the optional extensions block at the end of a hello message.
    /// `r` must be positioned after the compression field; an empty rest
    /// means "no extensions".
    ///
    /// # Errors
    /// Returns an error if the block is truncated, has trailing bytes, holds
    /// a duplicate of a known extension, or a known extension is malformed.
    pub fn parse(r: &mut Reader<'_>) -> WireResult<Self> {
        let mut ext = Self::default();
        if r.is_empty() {
            return Ok(ext);
        }
        let mut block = Reader::new(r.vec16()?);
        r.finish()?;
        while !block.is_empty() {
            let ext_type = block.u16()?;
            let mut body = Reader::new(block.vec16()?);
            match ext_type {
                EXT_SUPPORTED_GROUPS => {
                    let list = u16_list(body.vec16()?)?;
                    body.finish()?;
                    set_once(&mut ext.supported_groups, list)?;
                }
                EXT_EC_POINT_FORMATS => {
                    let list = body.vec8()?.to_vec();
                    body.finish()?;
                    set_once(&mut ext.ec_point_formats, list)?;
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    let list = u16_list(body.vec16()?)?;
                    body.finish()?;
                    set_once(&mut ext.signature_algorithms, list)?;
                }
                EXT_USE_SRTP => {
                    let profiles = u16_list(body.vec16()?)?;
                    let mki = body.vec8()?.to_vec();
                    body.finish()?;
                    set_once(&mut ext.use_srtp, UseSrtp { profiles, mki })?;
                }
                EXT_EXTENDED_MASTER_SECRET => {
                    body.finish()?;
                    if ext.extended_master_secret {
                        return Err(WireError::Malformed);
                    }
                    ext.extended_master_secret = true;
                }
                EXT_RENEGOTIATION_INFO => {
                    let value = body.vec8()?.to_vec();
                    body.finish()?;
                    set_once(&mut ext.renegotiation_info, value)?;
                }
                unknown => {
                    ext.first_unknown.get_or_insert(unknown);
                }
            }
        }
        Ok(ext)
    }

    /// Appends the extensions block (with its two-byte length). Nothing is
    /// written when no extension is set.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if a list does not fit its length prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        let mut block = Vec::new();
        if let Some(value) = &self.renegotiation_info {
            let mut body = Vec::new();
            put_vec8(&mut body, value)?;
            put_ext(&mut block, EXT_RENEGOTIATION_INFO, &body)?;
        }
        if let Some(groups) = &self.supported_groups {
            let mut body = Vec::new();
            put_vec16(&mut body, &u16_list_bytes(groups))?;
            put_ext(&mut block, EXT_SUPPORTED_GROUPS, &body)?;
        }
        if let Some(formats) = &self.ec_point_formats {
            let mut body = Vec::new();
            put_vec8(&mut body, formats)?;
            put_ext(&mut block, EXT_EC_POINT_FORMATS, &body)?;
        }
        if let Some(schemes) = &self.signature_algorithms {
            let mut body = Vec::new();
            put_vec16(&mut body, &u16_list_bytes(schemes))?;
            put_ext(&mut block, EXT_SIGNATURE_ALGORITHMS, &body)?;
        }
        if let Some(use_srtp) = &self.use_srtp {
            let mut body = Vec::new();
            put_vec16(&mut body, &u16_list_bytes(&use_srtp.profiles))?;
            put_vec8(&mut body, &use_srtp.mki)?;
            put_ext(&mut block, EXT_USE_SRTP, &body)?;
        }
        if self.extended_master_secret {
            put_ext(&mut block, EXT_EXTENDED_MASTER_SECRET, &[])?;
        }
        if block.is_empty() {
            return Ok(());
        }
        put_vec16(out, &block)
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> WireResult<()> {
    if slot.is_some() {
        return Err(WireError::Malformed);
    }
    *slot = Some(value);
    Ok(())
}

fn put_ext(block: &mut Vec<u8>, ext_type: u16, body: &[u8]) -> WireResult<()> {
    put_u16(block, ext_type);
    put_vec16(block, body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn full() -> Extensions {
        Extensions {
            supported_groups: Some(vec![24]),
            ec_point_formats: Some(vec![0]),
            signature_algorithms: Some(vec![0x0503]),
            use_srtp: Some(UseSrtp {
                profiles: vec![0x0008],
                mki: Vec::new(),
            }),
            extended_master_secret: true,
            renegotiation_info: Some(Vec::new()),
            first_unknown: None,
        }
    }

    fn encoded(ext: &Extensions) -> Vec<u8> {
        let mut out = Vec::new();
        ext.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trip() {
        for ext in [full(), Extensions::default()] {
            let bytes = encoded(&ext);
            assert_eq!(Extensions::parse(&mut Reader::new(&bytes)).unwrap(), ext);
        }
    }

    #[test]
    fn truncation_at_every_offset_is_an_error() {
        let bytes = encoded(&full());
        for cut in 1..bytes.len() {
            assert!(Extensions::parse(&mut Reader::new(&bytes[..cut])).is_err());
        }
    }

    #[test]
    fn unknown_extensions_are_skipped_and_duplicates_rejected() {
        // server_name (0) with an opaque body, then extended_master_secret.
        let block = [0, 0, 0, 2, 0xAA, 0xBB, 0, 23, 0, 0];
        let mut bytes = vec![0, 10];
        bytes.extend_from_slice(&block);
        let ext = Extensions::parse(&mut Reader::new(&bytes)).unwrap();
        assert!(ext.extended_master_secret);

        let dup = [0, 8, 0, 23, 0, 0, 0, 23, 0, 0];
        assert_eq!(
            Extensions::parse(&mut Reader::new(&dup)),
            Err(WireError::Malformed)
        );
    }

    #[test]
    fn malformed_bodies_are_rejected() {
        // use_srtp with an odd profile list length.
        let bad = [0, 8, 0, 14, 0, 4, 0, 1, 8, 0];
        assert!(Extensions::parse(&mut Reader::new(&bad)).is_err());
        // extended_master_secret with a body.
        let bad = [0, 5, 0, 23, 0, 1, 0];
        assert!(Extensions::parse(&mut Reader::new(&bad)).is_err());
        // Trailing bytes after the block.
        let bad = [0, 4, 0, 23, 0, 0, 9];
        assert_eq!(
            Extensions::parse(&mut Reader::new(&bad)),
            Err(WireError::TrailingBytes)
        );
    }
}
