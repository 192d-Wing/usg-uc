//! Bounds-checked cursor over peer-supplied bytes, and length-prefixed writers.
//!
//! ## NIST 800-53 Rev5: SI-10 (Information Input Validation)

#![deny(clippy::indexing_slicing)]

use super::{WireError, WireResult};

/// Forward-only reader. Every accessor checks the remaining length.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    consumed: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, consumed: 0 }
    }

    /// Bytes not yet read.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// Bytes read so far.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// True when nothing is left.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Takes the next `n` bytes.
    ///
    /// # Errors
    /// [`WireError::Truncated`] if fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize) -> WireResult<&'a [u8]> {
        let (head, tail) = self.buf.split_at_checked(n).ok_or(WireError::Truncated)?;
        self.buf = tail;
        self.consumed += n;
        Ok(head)
    }

    /// Takes the next `N` bytes as an array.
    ///
    /// # Errors
    /// [`WireError::Truncated`] if fewer than `N` bytes remain.
    pub fn array<const N: usize>(&mut self) -> WireResult<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| WireError::Truncated)
    }

    /// Takes everything that is left.
    pub const fn rest(&mut self) -> &'a [u8] {
        let rest = self.buf;
        self.consumed += rest.len();
        self.buf = &[];
        rest
    }

    /// Reads one byte.
    ///
    /// # Errors
    /// [`WireError::Truncated`] at end of input.
    pub fn u8(&mut self) -> WireResult<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `uint16`.
    ///
    /// # Errors
    /// [`WireError::Truncated`] at end of input.
    pub fn u16(&mut self) -> WireResult<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `uint24`.
    ///
    /// # Errors
    /// [`WireError::Truncated`] at end of input.
    pub fn u24(&mut self) -> WireResult<u32> {
        let [a, b, c] = self.array()?;
        Ok(u32::from_be_bytes([0, a, b, c]))
    }

    /// Reads a big-endian `uint48`.
    ///
    /// # Errors
    /// [`WireError::Truncated`] at end of input.
    pub fn u48(&mut self) -> WireResult<u64> {
        let bytes: [u8; 6] = self.array()?;
        Ok(bytes
            .iter()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
    }

    /// Reads a vector with a one-byte length prefix.
    ///
    /// # Errors
    /// [`WireError::Truncated`] if the prefix or the body is cut short.
    pub fn vec8(&mut self) -> WireResult<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    /// Reads a vector with a two-byte length prefix.
    ///
    /// # Errors
    /// [`WireError::Truncated`] if the prefix or the body is cut short.
    pub fn vec16(&mut self) -> WireResult<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    /// Reads a vector with a three-byte length prefix.
    ///
    /// # Errors
    /// [`WireError::Truncated`] if the prefix or the body is cut short.
    pub fn vec24(&mut self) -> WireResult<&'a [u8]> {
        let len = usize::try_from(self.u24()?).map_err(|_| WireError::Truncated)?;
        self.take(len)
    }

    /// Requires that all input was consumed.
    ///
    /// # Errors
    /// [`WireError::TrailingBytes`] if bytes remain.
    pub const fn finish(&self) -> WireResult<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// Decodes a list of big-endian `uint16` values that fills `bytes` exactly.
///
/// # Errors
/// [`WireError::Malformed`] if the length is odd.
pub fn u16_list(bytes: &[u8]) -> WireResult<Vec<u16>> {
    let (pairs, tail) = bytes.as_chunks::<2>();
    if !tail.is_empty() {
        return Err(WireError::Malformed);
    }
    Ok(pairs.iter().map(|p| u16::from_be_bytes(*p)).collect())
}

/// Appends a big-endian `uint16`.
pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Appends a big-endian `uint24`.
///
/// # Errors
/// [`WireError::Oversized`] if `value` does not fit in 24 bits.
pub fn put_u24(out: &mut Vec<u8>, value: usize) -> WireResult<()> {
    let value = u32::try_from(value).map_err(|_| WireError::Oversized)?;
    match value.to_be_bytes() {
        [0, a, b, c] => {
            out.extend_from_slice(&[a, b, c]);
            Ok(())
        }
        _ => Err(WireError::Oversized),
    }
}

/// Appends `body` with a one-byte length prefix.
///
/// # Errors
/// [`WireError::Oversized`] if `body` is longer than 255 bytes.
pub fn put_vec8(out: &mut Vec<u8>, body: &[u8]) -> WireResult<()> {
    out.push(u8::try_from(body.len()).map_err(|_| WireError::Oversized)?);
    out.extend_from_slice(body);
    Ok(())
}

/// Appends `body` with a two-byte length prefix.
///
/// # Errors
/// [`WireError::Oversized`] if `body` is longer than 65,535 bytes.
pub fn put_vec16(out: &mut Vec<u8>, body: &[u8]) -> WireResult<()> {
    put_u16(
        out,
        u16::try_from(body.len()).map_err(|_| WireError::Oversized)?,
    );
    out.extend_from_slice(body);
    Ok(())
}

/// Appends `body` with a three-byte length prefix.
///
/// # Errors
/// [`WireError::Oversized`] if `body` does not fit in 24 bits of length.
pub fn put_vec24(out: &mut Vec<u8>, body: &[u8]) -> WireResult<()> {
    put_u24(out, body.len())?;
    out.extend_from_slice(body);
    Ok(())
}

/// Encodes a list of `uint16` values as bytes (no length prefix).
#[must_use]
pub fn u16_list_bytes(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn reads_integers_and_tracks_position() {
        let mut r = Reader::new(&[1, 0, 2, 0, 0, 3, 0, 0, 0, 0, 0, 4, 9]);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 2);
        assert_eq!(r.u24().unwrap(), 3);
        assert_eq!(r.u48().unwrap(), 4);
        assert_eq!(r.consumed(), 12);
        assert_eq!(r.finish(), Err(WireError::TrailingBytes));
        assert_eq!(r.rest(), &[9]);
        assert!(r.finish().is_ok());
        assert_eq!(r.u8(), Err(WireError::Truncated));
    }

    #[test]
    fn vectors_are_bounds_checked() {
        assert_eq!(Reader::new(&[2, 1]).vec8(), Err(WireError::Truncated));
        assert_eq!(Reader::new(&[0, 2, 1]).vec16(), Err(WireError::Truncated));
        assert_eq!(
            Reader::new(&[0, 0, 2, 1]).vec24(),
            Err(WireError::Truncated)
        );
        assert_eq!(
            Reader::new(&[0xFF, 0xFF, 0xFF]).vec24(),
            Err(WireError::Truncated)
        );
        assert_eq!(Reader::new(&[1, 7]).vec8().unwrap(), &[7]);
        assert_eq!(Reader::new(&[]).take(1), Err(WireError::Truncated));
        assert_eq!(Reader::new(&[]).take(0).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn writers_round_trip_and_reject_oversize() {
        let mut out = Vec::new();
        put_vec8(&mut out, &[1, 2]).unwrap();
        put_vec16(&mut out, &[3]).unwrap();
        put_vec24(&mut out, &[4]).unwrap();
        let mut r = Reader::new(&out);
        assert_eq!(r.vec8().unwrap(), &[1, 2]);
        assert_eq!(r.vec16().unwrap(), &[3]);
        assert_eq!(r.vec24().unwrap(), &[4]);
        assert_eq!(put_vec8(&mut out, &[0; 256]), Err(WireError::Oversized));
        assert_eq!(put_u24(&mut out, 1 << 24), Err(WireError::Oversized));
        assert_eq!(u16_list(&[0, 1, 2]), Err(WireError::Malformed));
        assert_eq!(
            u16_list(&u16_list_bytes(&[7, 0xC02C])).unwrap(),
            vec![7, 0xC02C]
        );
    }
}
