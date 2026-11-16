//! DTLS 1.2 handshake message codecs (RFC 6347 §4.2.2, RFC 5246 §7.4,
//! RFC 8422 §5).
//!
//! Each message has `parse(body)` and `encode(&self, out)`, where the body is
//! the reassembled message without its 12-byte handshake header.

#![deny(clippy::indexing_slicing)]

use super::extensions::Extensions;
use super::reader::{
    Reader, put_u16, put_u24, put_vec8, put_vec16, put_vec24, u16_list, u16_list_bytes,
};
use super::{WireError, WireResult};

/// Length of the DTLS handshake header.
pub const HANDSHAKE_HEADER_LEN: usize = 12;
/// Length of a hello `Random`.
pub const RANDOM_LEN: usize = 32;
/// Length of `verify_data` in `Finished`.
pub const VERIFY_DATA_LEN: usize = 12;
/// `ECCurveType` `named_curve` (RFC 8422 §5.4).
pub const CURVE_TYPE_NAMED: u8 = 3;

/// `hello_request`.
pub const HT_HELLO_REQUEST: u8 = 0;
/// `client_hello`.
pub const HT_CLIENT_HELLO: u8 = 1;
/// `server_hello`.
pub const HT_SERVER_HELLO: u8 = 2;
/// `hello_verify_request`.
pub const HT_HELLO_VERIFY_REQUEST: u8 = 3;
/// `certificate`.
pub const HT_CERTIFICATE: u8 = 11;
/// `server_key_exchange`.
pub const HT_SERVER_KEY_EXCHANGE: u8 = 12;
/// `certificate_request`.
pub const HT_CERTIFICATE_REQUEST: u8 = 13;
/// `server_hello_done`.
pub const HT_SERVER_HELLO_DONE: u8 = 14;
/// `certificate_verify`.
pub const HT_CERTIFICATE_VERIFY: u8 = 15;
/// `client_key_exchange`.
pub const HT_CLIENT_KEY_EXCHANGE: u8 = 16;
/// `finished`.
pub const HT_FINISHED: u8 = 20;

/// DTLS handshake header (RFC 6347 §4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeHeader {
    /// Handshake message type.
    pub msg_type: u8,
    /// Length of the whole message body.
    pub length: u32,
    /// Message sequence number.
    pub message_seq: u16,
    /// Offset of this fragment in the body.
    pub fragment_offset: u32,
    /// Length of this fragment.
    pub fragment_length: u32,
}

impl HandshakeHeader {
    /// Header of an unfragmented message, the form that enters the
    /// handshake transcript (RFC 6347 §4.2.6).
    ///
    /// # Errors
    /// [`WireError::Oversized`] if `body_len` does not fit in 24 bits.
    pub fn unfragmented(msg_type: u8, message_seq: u16, body_len: usize) -> WireResult<Self> {
        let length = u32::try_from(body_len).map_err(|_| WireError::Oversized)?;
        if length >= 1 << 24 {
            return Err(WireError::Oversized);
        }
        Ok(Self {
            msg_type,
            length,
            message_seq,
            fragment_offset: 0,
            fragment_length: length,
        })
    }

    /// Reads a header. Field relationships are checked by the reassembler.
    ///
    /// # Errors
    /// [`WireError::Truncated`] if fewer than 12 bytes remain.
    pub fn parse(r: &mut Reader<'_>) -> WireResult<Self> {
        Ok(Self {
            msg_type: r.u8()?,
            length: r.u24()?,
            message_seq: r.u16()?,
            fragment_offset: r.u24()?,
            fragment_length: r.u24()?,
        })
    }

    /// Appends the header.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if a field does not fit in 24 bits.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        out.push(self.msg_type);
        put_u24(
            out,
            usize::try_from(self.length).map_err(|_| WireError::Oversized)?,
        )?;
        put_u16(out, self.message_seq);
        put_u24(
            out,
            usize::try_from(self.fragment_offset).map_err(|_| WireError::Oversized)?,
        )?;
        put_u24(
            out,
            usize::try_from(self.fragment_length).map_err(|_| WireError::Oversized)?,
        )
    }
}

/// `ClientHello` (RFC 6347 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// `client_version`.
    pub version: u16,
    /// `random`.
    pub random: [u8; RANDOM_LEN],
    /// `session_id` (0..32 bytes).
    pub session_id: Vec<u8>,
    /// `cookie` (0..255 bytes).
    pub cookie: Vec<u8>,
    /// `cipher_suites`.
    pub cipher_suites: Vec<u16>,
    /// `compression_methods`.
    pub compression_methods: Vec<u8>,
    /// Extensions.
    pub extensions: Extensions,
}

/// The parts of a `ClientHello` body around its cookie, borrowed from the
/// input. The stateless cookie is computed over `before` and `after`.
#[derive(Debug, Clone, Copy)]
pub struct ClientHelloParts<'a> {
    /// `client_version`, `random` and `session_id`.
    pub before: &'a [u8],
    /// The cookie value.
    pub cookie: &'a [u8],
    /// Everything after the cookie.
    pub after: &'a [u8],
}

impl ClientHello {
    /// Parses a `ClientHello` body.
    ///
    /// # Errors
    /// Returns an error if the body is truncated or malformed.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let version = r.u16()?;
        let random = r.array()?;
        let session_id = r.vec8()?;
        if session_id.len() > 32 {
            return Err(WireError::Malformed);
        }
        let cookie = r.vec8()?;
        let cipher_suites = u16_list(r.vec16()?)?;
        let compression_methods = r.vec8()?;
        if cipher_suites.is_empty() || compression_methods.is_empty() {
            return Err(WireError::Malformed);
        }
        let extensions = Extensions::parse(&mut r)?;
        Ok(Self {
            version,
            random,
            session_id: session_id.to_vec(),
            cookie: cookie.to_vec(),
            cipher_suites,
            compression_methods: compression_methods.to_vec(),
            extensions,
        })
    }

    /// Splits a `ClientHello` body around the cookie without copying.
    ///
    /// # Errors
    /// Returns an error if the fields up to the cookie are truncated.
    pub fn split_cookie(body: &[u8]) -> WireResult<ClientHelloParts<'_>> {
        let mut r = Reader::new(body);
        r.u16()?;
        r.take(RANDOM_LEN)?;
        r.vec8()?;
        let before = body.get(..r.consumed()).ok_or(WireError::Truncated)?;
        let cookie = r.vec8()?;
        let after = r.rest();
        Ok(ClientHelloParts {
            before,
            cookie,
            after,
        })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if a field does not fit its length prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        put_u16(out, self.version);
        out.extend_from_slice(&self.random);
        put_vec8(out, &self.session_id)?;
        put_vec8(out, &self.cookie)?;
        put_vec16(out, &u16_list_bytes(&self.cipher_suites))?;
        put_vec8(out, &self.compression_methods)?;
        self.extensions.encode(out)
    }
}

/// `ServerHello` (RFC 5246 §7.4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// `server_version`.
    pub version: u16,
    /// `random`.
    pub random: [u8; RANDOM_LEN],
    /// `session_id` (0..32 bytes).
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected compression method.
    pub compression_method: u8,
    /// Extensions.
    pub extensions: Extensions,
}

impl ServerHello {
    /// Parses a `ServerHello` body.
    ///
    /// # Errors
    /// Returns an error if the body is truncated or malformed.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let version = r.u16()?;
        let random = r.array()?;
        let session_id = r.vec8()?;
        if session_id.len() > 32 {
            return Err(WireError::Malformed);
        }
        let cipher_suite = r.u16()?;
        let compression_method = r.u8()?;
        let extensions = Extensions::parse(&mut r)?;
        Ok(Self {
            version,
            random,
            session_id: session_id.to_vec(),
            cipher_suite,
            compression_method,
            extensions,
        })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if a field does not fit its length prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        put_u16(out, self.version);
        out.extend_from_slice(&self.random);
        put_vec8(out, &self.session_id)?;
        put_u16(out, self.cipher_suite);
        out.push(self.compression_method);
        self.extensions.encode(out)
    }
}

/// `HelloVerifyRequest` (RFC 6347 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloVerifyRequest {
    /// `server_version`.
    pub version: u16,
    /// Cookie (0..255 bytes).
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    /// Parses a `HelloVerifyRequest` body.
    ///
    /// # Errors
    /// Returns an error if the body is truncated or has trailing bytes.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let version = r.u16()?;
        let cookie = r.vec8()?.to_vec();
        r.finish()?;
        Ok(Self { version, cookie })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if the cookie is longer than 255 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        put_u16(out, self.version);
        put_vec8(out, &self.cookie)
    }
}

/// `Certificate` (RFC 5246 §7.4.2): a list of DER certificates, leaf first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMsg {
    /// DER certificates, sender's certificate first.
    pub chain: Vec<Vec<u8>>,
}

impl CertificateMsg {
    /// Parses a `Certificate` body. An empty list is valid on the wire.
    ///
    /// # Errors
    /// Returns an error if the body is truncated, has trailing bytes or
    /// holds an empty certificate entry.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let mut list = Reader::new(r.vec24()?);
        r.finish()?;
        let mut chain = Vec::new();
        while !list.is_empty() {
            let cert = list.vec24()?;
            if cert.is_empty() {
                return Err(WireError::Malformed);
            }
            chain.push(cert.to_vec());
        }
        Ok(Self { chain })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if the chain does not fit its length prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        let mut list = Vec::new();
        for cert in &self.chain {
            put_vec24(&mut list, cert)?;
        }
        put_vec24(out, &list)
    }
}

/// `ServerECDHParams` with a named curve (RFC 8422 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdheParams {
    /// `NamedCurve` identifier.
    pub named_curve: u16,
    /// Ephemeral public key (`ECPoint`).
    pub public: Vec<u8>,
}

impl EcdheParams {
    /// Reads the parameters, leaving `r` at the signature.
    ///
    /// # Errors
    /// Returns an error if truncated, not a named curve, or the point is empty.
    pub fn parse(r: &mut Reader<'_>) -> WireResult<Self> {
        if r.u8()? != CURVE_TYPE_NAMED {
            return Err(WireError::Malformed);
        }
        let named_curve = r.u16()?;
        let public = r.vec8()?;
        if public.is_empty() {
            return Err(WireError::Malformed);
        }
        Ok(Self {
            named_curve,
            public: public.to_vec(),
        })
    }

    /// Appends the parameters. These bytes are also what the server signs.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if the point is longer than 255 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        out.push(CURVE_TYPE_NAMED);
        put_u16(out, self.named_curve);
        put_vec8(out, &self.public)
    }
}

/// `DigitallySigned` (RFC 5246 §4.7): a signature scheme and a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigitallySigned {
    /// `SignatureAndHashAlgorithm` as one 16-bit value.
    pub scheme: u16,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

impl DigitallySigned {
    /// Reads the structure.
    ///
    /// # Errors
    /// Returns an error if truncated or the signature is empty.
    pub fn parse(r: &mut Reader<'_>) -> WireResult<Self> {
        let scheme = r.u16()?;
        let signature = r.vec16()?;
        if signature.is_empty() {
            return Err(WireError::Malformed);
        }
        Ok(Self {
            scheme,
            signature: signature.to_vec(),
        })
    }

    /// Appends the structure.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if the signature does not fit its prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        put_u16(out, self.scheme);
        put_vec16(out, &self.signature)
    }
}

/// `ServerKeyExchange` for ECDHE (RFC 8422 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyExchange {
    /// ECDHE parameters.
    pub params: EcdheParams,
    /// Signature over `client_random || server_random || params`.
    pub signed: DigitallySigned,
}

impl ServerKeyExchange {
    /// Parses a `ServerKeyExchange` body.
    ///
    /// # Errors
    /// Returns an error if the body is truncated, malformed or has trailing bytes.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let params = EcdheParams::parse(&mut r)?;
        let signed = DigitallySigned::parse(&mut r)?;
        r.finish()?;
        Ok(Self { params, signed })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if a field does not fit its length prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        self.params.encode(out)?;
        self.signed.encode(out)
    }
}

/// `CertificateRequest` (RFC 5246 §7.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    /// `certificate_types`.
    pub certificate_types: Vec<u8>,
    /// `supported_signature_algorithms`.
    pub signature_algorithms: Vec<u16>,
    /// `certificate_authorities`, undecoded.
    pub certificate_authorities: Vec<u8>,
}

impl CertificateRequest {
    /// Parses a `CertificateRequest` body.
    ///
    /// # Errors
    /// Returns an error if the body is truncated, malformed or has trailing bytes.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let certificate_types = r.vec8()?.to_vec();
        let signature_algorithms = u16_list(r.vec16()?)?;
        let certificate_authorities = r.vec16()?.to_vec();
        r.finish()?;
        Ok(Self {
            certificate_types,
            signature_algorithms,
            certificate_authorities,
        })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if a field does not fit its length prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        put_vec8(out, &self.certificate_types)?;
        put_vec16(out, &u16_list_bytes(&self.signature_algorithms))?;
        put_vec16(out, &self.certificate_authorities)
    }
}

/// `CertificateVerify` (RFC 5246 §7.4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    /// Signature over the handshake messages so far.
    pub signed: DigitallySigned,
}

impl CertificateVerify {
    /// Parses a `CertificateVerify` body.
    ///
    /// # Errors
    /// Returns an error if the body is truncated, malformed or has trailing bytes.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let signed = DigitallySigned::parse(&mut r)?;
        r.finish()?;
        Ok(Self { signed })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if the signature does not fit its prefix.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        self.signed.encode(out)
    }
}

/// `ClientKeyExchange` for ECDHE (RFC 8422 §5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyExchange {
    /// Ephemeral public key (`ECPoint`).
    pub public: Vec<u8>,
}

impl ClientKeyExchange {
    /// Parses a `ClientKeyExchange` body.
    ///
    /// # Errors
    /// Returns an error if the body is truncated, empty or has trailing bytes.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let public = r.vec8()?;
        r.finish()?;
        if public.is_empty() {
            return Err(WireError::Malformed);
        }
        Ok(Self {
            public: public.to_vec(),
        })
    }

    /// Appends the message body.
    ///
    /// # Errors
    /// [`WireError::Oversized`] if the point is longer than 255 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> WireResult<()> {
        put_vec8(out, &self.public)
    }
}

/// `Finished` (RFC 5246 §7.4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// `verify_data`.
    pub verify_data: [u8; VERIFY_DATA_LEN],
}

impl Finished {
    /// Parses a `Finished` body, which must be exactly 12 bytes.
    ///
    /// # Errors
    /// Returns an error if the body is not exactly 12 bytes.
    pub fn parse(body: &[u8]) -> WireResult<Self> {
        let mut r = Reader::new(body);
        let verify_data = r.array()?;
        r.finish()?;
        Ok(Self { verify_data })
    }

    /// Appends the message body.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.verify_data);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::super::extensions::UseSrtp;
    use super::*;

    fn extensions() -> Extensions {
        Extensions {
            supported_groups: Some(vec![24]),
            ec_point_formats: Some(vec![0]),
            signature_algorithms: Some(vec![0x0503]),
            use_srtp: Some(UseSrtp {
                profiles: vec![8],
                mki: Vec::new(),
            }),
            extended_master_secret: true,
            renegotiation_info: Some(Vec::new()),
            first_unknown: None,
        }
    }

    fn client_hello() -> ClientHello {
        ClientHello {
            version: 0xFEFD,
            random: [7; RANDOM_LEN],
            session_id: Vec::new(),
            cookie: vec![1, 2, 3],
            cipher_suites: vec![0xC02C],
            compression_methods: vec![0],
            extensions: extensions(),
        }
    }

    /// Round trip, then truncation at every offset must be an error.
    fn check<T: PartialEq + std::fmt::Debug>(
        value: &T,
        bytes: &[u8],
        parse: fn(&[u8]) -> WireResult<T>,
    ) {
        assert_eq!(&parse(bytes).unwrap(), value);
        for cut in 0..bytes.len() {
            assert!(parse(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(parse(&extra).is_err());
    }

    #[test]
    fn handshake_header_round_trip() {
        let h = HandshakeHeader {
            msg_type: HT_CERTIFICATE,
            length: 0x01_0203,
            message_seq: 5,
            fragment_offset: 0x00_0100,
            fragment_length: 0x00_0080,
        };
        let mut out = Vec::new();
        h.encode(&mut out).unwrap();
        assert_eq!(out.len(), HANDSHAKE_HEADER_LEN);
        assert_eq!(HandshakeHeader::parse(&mut Reader::new(&out)).unwrap(), h);
        for cut in 0..out.len() {
            assert!(HandshakeHeader::parse(&mut Reader::new(&out[..cut])).is_err());
        }
        assert!(HandshakeHeader::unfragmented(1, 0, 1 << 24).is_err());
    }

    #[test]
    fn client_hello_round_trip_and_truncation() {
        let ch = client_hello();
        let mut bytes = Vec::new();
        ch.encode(&mut bytes).unwrap();
        // A hello cut exactly before the extensions block is a valid hello
        // without extensions, so that one prefix parses.
        let mut no_ext = Vec::new();
        ClientHello {
            extensions: Extensions::default(),
            ..ch.clone()
        }
        .encode(&mut no_ext)
        .unwrap();
        assert_eq!(&parse_ok(&bytes), &ch);
        for cut in 0..bytes.len() {
            if cut == no_ext.len() {
                assert!(ClientHello::parse(&bytes[..cut]).is_ok());
            } else {
                assert!(ClientHello::parse(&bytes[..cut]).is_err(), "cut at {cut}");
            }
        }
    }

    fn parse_ok(bytes: &[u8]) -> ClientHello {
        ClientHello::parse(bytes).unwrap()
    }

    #[test]
    fn client_hello_split_cookie() {
        let ch = client_hello();
        let mut bytes = Vec::new();
        ch.encode(&mut bytes).unwrap();
        let parts = ClientHello::split_cookie(&bytes).unwrap();
        assert_eq!(parts.cookie, &[1, 2, 3]);
        assert_eq!(parts.before.len(), 2 + RANDOM_LEN + 1);
        assert_eq!(
            parts.before.len() + 1 + parts.cookie.len() + parts.after.len(),
            bytes.len()
        );
        assert!(ClientHello::split_cookie(&bytes[..37]).is_err());
    }

    #[test]
    fn client_hello_rejects_empty_lists_and_long_session_id() {
        let mut ch = client_hello();
        ch.cipher_suites.clear();
        let mut bytes = Vec::new();
        ch.encode(&mut bytes).unwrap();
        assert!(ClientHello::parse(&bytes).is_err());

        let mut ch = client_hello();
        ch.session_id = vec![0; 33];
        let mut bytes = Vec::new();
        ch.encode(&mut bytes).unwrap();
        assert!(ClientHello::parse(&bytes).is_err());
    }

    #[test]
    fn server_hello_round_trip() {
        let sh = ServerHello {
            version: 0xFEFD,
            random: [9; RANDOM_LEN],
            session_id: vec![1; 32],
            cipher_suite: 0xC02C,
            compression_method: 0,
            extensions: extensions(),
        };
        let mut bytes = Vec::new();
        sh.encode(&mut bytes).unwrap();
        assert_eq!(ServerHello::parse(&bytes).unwrap(), sh);
        assert!(ServerHello::parse(&bytes[..20]).is_err());
    }

    #[test]
    fn simple_messages_round_trip_and_truncate() {
        let hvr = HelloVerifyRequest {
            version: 0xFEFF,
            cookie: vec![5; 32],
        };
        let mut b = Vec::new();
        hvr.encode(&mut b).unwrap();
        check(&hvr, &b, HelloVerifyRequest::parse);

        let cert = CertificateMsg {
            chain: vec![vec![0x30, 1, 2], vec![0x30, 3]],
        };
        let mut b = Vec::new();
        cert.encode(&mut b).unwrap();
        check(&cert, &b, CertificateMsg::parse);

        let ske = ServerKeyExchange {
            params: EcdheParams {
                named_curve: 24,
                public: vec![4; 97],
            },
            signed: DigitallySigned {
                scheme: 0x0503,
                signature: vec![0x30; 70],
            },
        };
        let mut b = Vec::new();
        ske.encode(&mut b).unwrap();
        check(&ske, &b, ServerKeyExchange::parse);

        let req = CertificateRequest {
            certificate_types: vec![64],
            signature_algorithms: vec![0x0503],
            certificate_authorities: Vec::new(),
        };
        let mut b = Vec::new();
        req.encode(&mut b).unwrap();
        check(&req, &b, CertificateRequest::parse);

        let cv = CertificateVerify {
            signed: DigitallySigned {
                scheme: 0x0503,
                signature: vec![1; 96],
            },
        };
        let mut b = Vec::new();
        cv.encode(&mut b).unwrap();
        check(&cv, &b, CertificateVerify::parse);

        let cke = ClientKeyExchange {
            public: vec![4; 97],
        };
        let mut b = Vec::new();
        cke.encode(&mut b).unwrap();
        check(&cke, &b, ClientKeyExchange::parse);

        let fin = Finished {
            verify_data: [3; VERIFY_DATA_LEN],
        };
        let mut b = Vec::new();
        fin.encode(&mut b);
        check(&fin, &b, Finished::parse);
    }

    #[test]
    fn empty_certificate_list_parses_and_empty_entry_does_not() {
        assert_eq!(
            CertificateMsg::parse(&[0, 0, 0]).unwrap().chain,
            Vec::<Vec<u8>>::new()
        );
        assert!(CertificateMsg::parse(&[0, 0, 3, 0, 0, 0]).is_err());
    }

    #[test]
    fn key_exchange_rejects_other_curve_types_and_empty_signature() {
        // explicit_prime (1) instead of named_curve.
        assert!(ServerKeyExchange::parse(&[1, 0, 24, 1, 4, 5, 3, 0, 1, 0]).is_err());
        // Empty signature.
        assert!(ServerKeyExchange::parse(&[3, 0, 24, 1, 4, 5, 3, 0, 0]).is_err());
    }
}
