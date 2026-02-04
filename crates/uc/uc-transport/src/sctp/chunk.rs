//! SCTP chunk encoding and decoding (RFC 9260 Section 3).
//!
//! This module implements all SCTP chunk types defined in RFC 9260,
//! plus common extensions for SIP signaling.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{TransportError, TransportResult};

/// Minimum chunk header size (type + flags + length).
pub const CHUNK_HEADER_SIZE: usize = 4;

/// Maximum chunk data size (65535 - 4 byte header).
pub const MAX_CHUNK_DATA_SIZE: usize = 65531;

// =============================================================================
// Chunk Type
// =============================================================================

/// SCTP Chunk Types (RFC 9260 Section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChunkType {
    /// Payload Data (DATA).
    Data = 0,
    /// Initiation (INIT).
    Init = 1,
    /// Initiation Acknowledgement (INIT ACK).
    InitAck = 2,
    /// Selective Acknowledgement (SACK).
    Sack = 3,
    /// Heartbeat Request (HEARTBEAT).
    Heartbeat = 4,
    /// Heartbeat Acknowledgement (HEARTBEAT ACK).
    HeartbeatAck = 5,
    /// Abort (ABORT).
    Abort = 6,
    /// Shutdown (SHUTDOWN).
    Shutdown = 7,
    /// Shutdown Acknowledgement (SHUTDOWN ACK).
    ShutdownAck = 8,
    /// Operation Error (ERROR).
    Error = 9,
    /// State Cookie (COOKIE ECHO).
    CookieEcho = 10,
    /// Cookie Acknowledgement (COOKIE ACK).
    CookieAck = 11,
    /// Reserved for Explicit Congestion Notification Echo (ECNE).
    Ecne = 12,
    /// Reserved for Congestion Window Reduced (CWR).
    Cwr = 13,
    /// Shutdown Complete (SHUTDOWN COMPLETE).
    ShutdownComplete = 14,
    /// Authentication Chunk (RFC 4895).
    Auth = 15,
    /// Padding Chunk (RFC 4820).
    Pad = 0x84,
    /// Forward TSN (RFC 3758).
    ForwardTsn = 0xC0,
    /// Address Configuration Change (RFC 5061).
    Asconf = 0xC1,
    /// Address Configuration Acknowledgement (RFC 5061).
    AsconfAck = 0x80,
    /// Stream Reconfiguration (RFC 6525).
    ReConfig = 130,
}

impl ChunkType {
    /// Creates a ChunkType from a raw byte value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Data),
            1 => Some(Self::Init),
            2 => Some(Self::InitAck),
            3 => Some(Self::Sack),
            4 => Some(Self::Heartbeat),
            5 => Some(Self::HeartbeatAck),
            6 => Some(Self::Abort),
            7 => Some(Self::Shutdown),
            8 => Some(Self::ShutdownAck),
            9 => Some(Self::Error),
            10 => Some(Self::CookieEcho),
            11 => Some(Self::CookieAck),
            12 => Some(Self::Ecne),
            13 => Some(Self::Cwr),
            14 => Some(Self::ShutdownComplete),
            15 => Some(Self::Auth),
            0x84 => Some(Self::Pad),
            0xC0 => Some(Self::ForwardTsn),
            0xC1 => Some(Self::Asconf),
            0x80 => Some(Self::AsconfAck),
            130 => Some(Self::ReConfig),
            _ => None,
        }
    }

    /// Returns true if this chunk type cannot be bundled with other chunks.
    ///
    /// Per RFC 9260 Section 6.10:
    /// - INIT, INIT ACK, and SHUTDOWN COMPLETE MUST NOT be bundled.
    #[must_use]
    pub const fn must_not_bundle(&self) -> bool {
        matches!(self, Self::Init | Self::InitAck | Self::ShutdownComplete)
    }

    /// Returns the action to take for unknown chunk types based on high bits.
    ///
    /// Per RFC 9260 Section 3.2, the two high-order bits determine handling:
    /// - 00: Stop processing, report in ERROR chunk
    /// - 01: Stop processing, do not report
    /// - 10: Skip this chunk, report in ERROR chunk
    /// - 11: Skip this chunk, do not report
    #[must_use]
    pub fn unknown_action(chunk_type: u8) -> UnknownChunkAction {
        match (chunk_type >> 6) & 0x03 {
            0b00 => UnknownChunkAction::StopAndReport,
            0b01 => UnknownChunkAction::StopSilently,
            0b10 => UnknownChunkAction::SkipAndReport,
            0b11 => UnknownChunkAction::SkipSilently,
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for ChunkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data => write!(f, "DATA"),
            Self::Init => write!(f, "INIT"),
            Self::InitAck => write!(f, "INIT-ACK"),
            Self::Sack => write!(f, "SACK"),
            Self::Heartbeat => write!(f, "HEARTBEAT"),
            Self::HeartbeatAck => write!(f, "HEARTBEAT-ACK"),
            Self::Abort => write!(f, "ABORT"),
            Self::Shutdown => write!(f, "SHUTDOWN"),
            Self::ShutdownAck => write!(f, "SHUTDOWN-ACK"),
            Self::Error => write!(f, "ERROR"),
            Self::CookieEcho => write!(f, "COOKIE-ECHO"),
            Self::CookieAck => write!(f, "COOKIE-ACK"),
            Self::Ecne => write!(f, "ECNE"),
            Self::Cwr => write!(f, "CWR"),
            Self::ShutdownComplete => write!(f, "SHUTDOWN-COMPLETE"),
            Self::Auth => write!(f, "AUTH"),
            Self::Pad => write!(f, "PAD"),
            Self::ForwardTsn => write!(f, "FORWARD-TSN"),
            Self::Asconf => write!(f, "ASCONF"),
            Self::AsconfAck => write!(f, "ASCONF-ACK"),
            Self::ReConfig => write!(f, "RE-CONFIG"),
        }
    }
}

/// Action to take for unknown chunk types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownChunkAction {
    /// Stop processing and report in ERROR chunk.
    StopAndReport,
    /// Stop processing silently.
    StopSilently,
    /// Skip this chunk and report in ERROR chunk.
    SkipAndReport,
    /// Skip this chunk silently.
    SkipSilently,
}

// =============================================================================
// Chunk Enum
// =============================================================================

/// An SCTP chunk.
#[derive(Debug, Clone, PartialEq)]
pub enum Chunk {
    /// Payload Data chunk.
    Data(DataChunk),
    /// Initiation chunk.
    Init(InitChunk),
    /// Initiation Acknowledgement chunk.
    InitAck(InitAckChunk),
    /// Selective Acknowledgement chunk.
    Sack(SackChunk),
    /// Heartbeat Request chunk.
    Heartbeat(HeartbeatChunk),
    /// Heartbeat Acknowledgement chunk.
    HeartbeatAck(HeartbeatAckChunk),
    /// Abort chunk.
    Abort(AbortChunk),
    /// Shutdown chunk.
    Shutdown(ShutdownChunk),
    /// Shutdown Acknowledgement chunk.
    ShutdownAck(ShutdownAckChunk),
    /// Operation Error chunk.
    Error(ErrorChunk),
    /// Cookie Echo chunk.
    CookieEcho(CookieEchoChunk),
    /// Cookie Acknowledgement chunk.
    CookieAck(CookieAckChunk),
    /// Shutdown Complete chunk.
    ShutdownComplete(ShutdownCompleteChunk),
    /// Explicit Congestion Notification Echo chunk.
    Ecne(EcneChunk),
    /// Congestion Window Reduced chunk.
    Cwr(CwrChunk),
    /// Forward TSN chunk (RFC 3758).
    ForwardTsn(ForwardTsnChunk),
    /// Reconfiguration chunk (RFC 6525).
    ReConfig(ReConfigChunk),
    /// Address Configuration Change chunk (RFC 5061).
    Asconf(AsconfChunk),
    /// Address Configuration Acknowledgement chunk (RFC 5061).
    AsconfAck(AsconfAckChunk),
    /// Padding chunk (RFC 4820).
    Pad(PadChunk),
    /// Authentication chunk (RFC 4895).
    Auth(AuthChunk),
    /// Unknown chunk (preserved for forwarding/error reporting).
    Unknown(UnknownChunk),
}

impl Chunk {
    /// Returns the chunk type.
    #[must_use]
    pub fn chunk_type(&self) -> ChunkType {
        match self {
            Self::Data(_) => ChunkType::Data,
            Self::Init(_) => ChunkType::Init,
            Self::InitAck(_) => ChunkType::InitAck,
            Self::Sack(_) => ChunkType::Sack,
            Self::Heartbeat(_) => ChunkType::Heartbeat,
            Self::HeartbeatAck(_) => ChunkType::HeartbeatAck,
            Self::Abort(_) => ChunkType::Abort,
            Self::Shutdown(_) => ChunkType::Shutdown,
            Self::ShutdownAck(_) => ChunkType::ShutdownAck,
            Self::Error(_) => ChunkType::Error,
            Self::CookieEcho(_) => ChunkType::CookieEcho,
            Self::CookieAck(_) => ChunkType::CookieAck,
            Self::ShutdownComplete(_) => ChunkType::ShutdownComplete,
            Self::Ecne(_) => ChunkType::Ecne,
            Self::Cwr(_) => ChunkType::Cwr,
            Self::ForwardTsn(_) => ChunkType::ForwardTsn,
            Self::ReConfig(_) => ChunkType::ReConfig,
            Self::Asconf(_) => ChunkType::Asconf,
            Self::AsconfAck(_) => ChunkType::AsconfAck,
            Self::Pad(_) => ChunkType::Pad,
            Self::Auth(_) => ChunkType::Auth,
            Self::Unknown(u) => ChunkType::from_u8(u.chunk_type).unwrap_or(ChunkType::Data),
        }
    }

    /// Encodes the chunk to bytes.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::Data(c) => c.encode(buf),
            Self::Init(c) => c.encode(buf),
            Self::InitAck(c) => c.encode(buf),
            Self::Sack(c) => c.encode(buf),
            Self::Heartbeat(c) => c.encode(buf),
            Self::HeartbeatAck(c) => c.encode(buf),
            Self::Abort(c) => c.encode(buf),
            Self::Shutdown(c) => c.encode(buf),
            Self::ShutdownAck(c) => c.encode(buf),
            Self::Error(c) => c.encode(buf),
            Self::CookieEcho(c) => c.encode(buf),
            Self::CookieAck(c) => c.encode(buf),
            Self::ShutdownComplete(c) => c.encode(buf),
            Self::Ecne(c) => c.encode(buf),
            Self::Cwr(c) => c.encode(buf),
            Self::ForwardTsn(c) => c.encode(buf),
            Self::ReConfig(c) => c.encode(buf),
            Self::Asconf(c) => c.encode(buf),
            Self::AsconfAck(c) => c.encode(buf),
            Self::Pad(c) => c.encode(buf),
            Self::Auth(c) => c.encode(buf),
            Self::Unknown(c) => c.encode(buf),
        }
    }

    /// Decodes a chunk from bytes.
    pub fn decode(buf: &mut Bytes) -> TransportResult<Self> {
        if buf.remaining() < CHUNK_HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: "Chunk too short for header".to_string(),
            });
        }

        let chunk_type = buf[0];
        let flags = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        if length < CHUNK_HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: format!("Invalid chunk length: {length}"),
            });
        }

        if buf.remaining() < length {
            return Err(TransportError::ReceiveFailed {
                reason: format!(
                    "Insufficient data for chunk: need {length}, have {}",
                    buf.remaining()
                ),
            });
        }

        // Extract the full chunk including header
        let chunk_data = buf.split_to(padded_length(length));

        match ChunkType::from_u8(chunk_type) {
            Some(ChunkType::Data) => Ok(Self::Data(DataChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::Init) => Ok(Self::Init(InitChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::InitAck) => Ok(Self::InitAck(InitAckChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::Sack) => Ok(Self::Sack(SackChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::Heartbeat) => Ok(Self::Heartbeat(HeartbeatChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::HeartbeatAck) => Ok(Self::HeartbeatAck(
                HeartbeatAckChunk::decode_body(flags, &chunk_data)?,
            )),
            Some(ChunkType::Abort) => Ok(Self::Abort(AbortChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::Shutdown) => Ok(Self::Shutdown(ShutdownChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::ShutdownAck) => Ok(Self::ShutdownAck(ShutdownAckChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::Error) => Ok(Self::Error(ErrorChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::CookieEcho) => Ok(Self::CookieEcho(CookieEchoChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::CookieAck) => Ok(Self::CookieAck(CookieAckChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::ShutdownComplete) => Ok(Self::ShutdownComplete(
                ShutdownCompleteChunk::decode_body(flags, &chunk_data)?,
            )),
            Some(ChunkType::Ecne) => Ok(Self::Ecne(EcneChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::Cwr) => Ok(Self::Cwr(CwrChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::ForwardTsn) => Ok(Self::ForwardTsn(ForwardTsnChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::ReConfig) => Ok(Self::ReConfig(ReConfigChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::Asconf) => {
                Ok(Self::Asconf(AsconfChunk::decode_body(flags, &chunk_data)?))
            }
            Some(ChunkType::AsconfAck) => Ok(Self::AsconfAck(AsconfAckChunk::decode_body(
                flags,
                &chunk_data,
            )?)),
            Some(ChunkType::Pad) => Ok(Self::Pad(PadChunk::decode_body(flags, &chunk_data)?)),
            Some(ChunkType::Auth) => Ok(Self::Auth(AuthChunk::decode_body(flags, &chunk_data)?)),
            _ => Ok(Self::Unknown(UnknownChunk {
                chunk_type,
                flags,
                data: chunk_data.slice(CHUNK_HEADER_SIZE..length),
            })),
        }
    }
}

// =============================================================================
// DATA Chunk (RFC 9260 Section 3.3.1)
// =============================================================================

/// DATA chunk for payload data.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0    | Reserved|I|U|B|E|         Length              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              TSN                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Stream Identifier        |   Stream Sequence Number      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Payload Protocol Identifier                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                            User Data                          /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DataChunk {
    /// Transmission Sequence Number.
    pub tsn: u32,
    /// Stream Identifier.
    pub stream_id: u16,
    /// Stream Sequence Number (for ordered delivery).
    pub ssn: u16,
    /// Payload Protocol Identifier.
    pub ppid: u32,
    /// User data payload.
    pub data: Bytes,
    /// I bit: Immediate acknowledgement requested.
    pub immediate: bool,
    /// U bit: Unordered delivery.
    pub unordered: bool,
    /// B bit: Beginning of fragmented message.
    pub beginning: bool,
    /// E bit: End of fragmented message.
    pub ending: bool,
}

impl DataChunk {
    /// DATA chunk header size (excluding user data).
    pub const HEADER_SIZE: usize = 16;

    /// Creates a new DATA chunk.
    #[must_use]
    pub fn new(tsn: u32, stream_id: u16, ssn: u16, ppid: u32, data: Bytes) -> Self {
        Self {
            tsn,
            stream_id,
            ssn,
            ppid,
            data,
            immediate: false,
            unordered: false,
            beginning: true,
            ending: true,
        }
    }

    /// Sets the immediate flag.
    #[must_use]
    pub const fn with_immediate(mut self, immediate: bool) -> Self {
        self.immediate = immediate;
        self
    }

    /// Sets the unordered flag.
    #[must_use]
    pub const fn with_unordered(mut self, unordered: bool) -> Self {
        self.unordered = unordered;
        self
    }

    /// Sets the fragmentation flags.
    #[must_use]
    pub const fn with_fragment(mut self, beginning: bool, ending: bool) -> Self {
        self.beginning = beginning;
        self.ending = ending;
        self
    }

    fn flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.immediate {
            flags |= 0x08;
        }
        if self.unordered {
            flags |= 0x04;
        }
        if self.beginning {
            flags |= 0x02;
        }
        if self.ending {
            flags |= 0x01;
        }
        flags
    }

    fn encode(&self, buf: &mut BytesMut) {
        let length = Self::HEADER_SIZE + self.data.len();
        buf.put_u8(ChunkType::Data as u8);
        buf.put_u8(self.flags());
        buf.put_u16(length as u16);
        buf.put_u32(self.tsn);
        buf.put_u16(self.stream_id);
        buf.put_u16(self.ssn);
        buf.put_u32(self.ppid);
        buf.put_slice(&self.data);
        // Pad to 4-byte boundary
        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < Self::HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: "DATA chunk too short".to_string(),
            });
        }

        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let tsn = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
        let stream_id = u16::from_be_bytes([chunk_data[8], chunk_data[9]]);
        let ssn = u16::from_be_bytes([chunk_data[10], chunk_data[11]]);
        let ppid = u32::from_be_bytes([
            chunk_data[12],
            chunk_data[13],
            chunk_data[14],
            chunk_data[15],
        ]);
        let data_len = length.saturating_sub(Self::HEADER_SIZE);
        let data = chunk_data.slice(Self::HEADER_SIZE..Self::HEADER_SIZE + data_len);

        Ok(Self {
            tsn,
            stream_id,
            ssn,
            ppid,
            data,
            immediate: (flags & 0x08) != 0,
            unordered: (flags & 0x04) != 0,
            beginning: (flags & 0x02) != 0,
            ending: (flags & 0x01) != 0,
        })
    }
}

// =============================================================================
// INIT Chunk (RFC 9260 Section 3.3.2)
// =============================================================================

/// INIT chunk for association initiation.
#[derive(Debug, Clone, PartialEq)]
pub struct InitChunk {
    /// Initiate Tag.
    pub initiate_tag: u32,
    /// Advertised Receiver Window Credit.
    pub a_rwnd: u32,
    /// Number of Outbound Streams.
    pub num_outbound_streams: u16,
    /// Number of Inbound Streams.
    pub num_inbound_streams: u16,
    /// Initial TSN.
    pub initial_tsn: u32,
    /// Optional/Variable-length parameters.
    pub params: Vec<InitParam>,
}

impl InitChunk {
    /// INIT chunk header size (excluding parameters).
    pub const HEADER_SIZE: usize = 20;

    /// Creates a new INIT chunk.
    #[must_use]
    pub fn new(
        initiate_tag: u32,
        a_rwnd: u32,
        num_outbound_streams: u16,
        num_inbound_streams: u16,
        initial_tsn: u32,
    ) -> Self {
        Self {
            initiate_tag,
            a_rwnd,
            num_outbound_streams,
            num_inbound_streams,
            initial_tsn,
            params: Vec::new(),
        }
    }

    /// Adds an IPv4 address parameter.
    #[must_use]
    pub fn with_ipv4_address(mut self, addr: Ipv4Addr) -> Self {
        self.params.push(InitParam::Ipv4Address(addr));
        self
    }

    /// Adds an IPv6 address parameter.
    #[must_use]
    pub fn with_ipv6_address(mut self, addr: Ipv6Addr) -> Self {
        self.params.push(InitParam::Ipv6Address(addr));
        self
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u8(ChunkType::Init as u8);
        buf.put_u8(0); // flags
        buf.put_u16(0); // length placeholder
        buf.put_u32(self.initiate_tag);
        buf.put_u32(self.a_rwnd);
        buf.put_u16(self.num_outbound_streams);
        buf.put_u16(self.num_inbound_streams);
        buf.put_u32(self.initial_tsn);

        for param in &self.params {
            param.encode(buf);
        }

        let length = buf.len() - start;
        let length_bytes = (length as u16).to_be_bytes();
        buf[start + 2] = length_bytes[0];
        buf[start + 3] = length_bytes[1];

        // Pad to 4-byte boundary
        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < Self::HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: "INIT chunk too short".to_string(),
            });
        }

        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let initiate_tag =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
        let a_rwnd =
            u32::from_be_bytes([chunk_data[8], chunk_data[9], chunk_data[10], chunk_data[11]]);
        let num_outbound_streams = u16::from_be_bytes([chunk_data[12], chunk_data[13]]);
        let num_inbound_streams = u16::from_be_bytes([chunk_data[14], chunk_data[15]]);
        let initial_tsn = u32::from_be_bytes([
            chunk_data[16],
            chunk_data[17],
            chunk_data[18],
            chunk_data[19],
        ]);

        let mut params = Vec::new();
        let mut offset = Self::HEADER_SIZE;
        let params_end = length.min(chunk_data.len());

        while offset + 4 <= params_end {
            if let Some((param, consumed)) = InitParam::decode(&chunk_data[offset..params_end]) {
                params.push(param);
                offset += consumed;
            } else {
                break;
            }
        }

        Ok(Self {
            initiate_tag,
            a_rwnd,
            num_outbound_streams,
            num_inbound_streams,
            initial_tsn,
            params,
        })
    }
}

/// INIT chunk parameters.
#[derive(Debug, Clone, PartialEq)]
pub enum InitParam {
    /// IPv4 Address.
    Ipv4Address(Ipv4Addr),
    /// IPv6 Address.
    Ipv6Address(Ipv6Addr),
    /// State Cookie (only in INIT-ACK).
    Cookie(Bytes),
    /// Cookie Preservative.
    CookiePreservative(u32),
    /// Hostname Address.
    HostnameAddress(String),
    /// Supported Address Types.
    SupportedAddressTypes(Vec<u16>),
    /// ECN Capable.
    EcnCapable,
    /// Forward TSN Supported.
    ForwardTsnSupported,
    /// Unknown parameter.
    Unknown {
        /// Parameter type code.
        param_type: u16,
        /// Parameter data.
        data: Bytes,
    },
}

impl InitParam {
    // Parameter type codes
    const IPV4_ADDRESS: u16 = 5;
    const IPV6_ADDRESS: u16 = 6;
    const STATE_COOKIE: u16 = 7;
    const COOKIE_PRESERVATIVE: u16 = 9;
    const HOSTNAME_ADDRESS: u16 = 11;
    const SUPPORTED_ADDRESS_TYPES: u16 = 12;
    const ECN_CAPABLE: u16 = 0x8000;
    const FORWARD_TSN_SUPPORTED: u16 = 0xC000;

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::Ipv4Address(addr) => {
                buf.put_u16(Self::IPV4_ADDRESS);
                buf.put_u16(8);
                buf.put_slice(&addr.octets());
            }
            Self::Ipv6Address(addr) => {
                buf.put_u16(Self::IPV6_ADDRESS);
                buf.put_u16(20);
                buf.put_slice(&addr.octets());
            }
            Self::Cookie(cookie) => {
                let length = 4 + cookie.len();
                buf.put_u16(Self::STATE_COOKIE);
                buf.put_u16(length as u16);
                buf.put_slice(cookie);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::CookiePreservative(lifespan) => {
                buf.put_u16(Self::COOKIE_PRESERVATIVE);
                buf.put_u16(8);
                buf.put_u32(*lifespan);
            }
            Self::HostnameAddress(hostname) => {
                let length = 4 + hostname.len();
                buf.put_u16(Self::HOSTNAME_ADDRESS);
                buf.put_u16(length as u16);
                buf.put_slice(hostname.as_bytes());
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::SupportedAddressTypes(types) => {
                let length = 4 + types.len() * 2;
                buf.put_u16(Self::SUPPORTED_ADDRESS_TYPES);
                buf.put_u16(length as u16);
                for t in types {
                    buf.put_u16(*t);
                }
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::EcnCapable => {
                buf.put_u16(Self::ECN_CAPABLE);
                buf.put_u16(4);
            }
            Self::ForwardTsnSupported => {
                buf.put_u16(Self::FORWARD_TSN_SUPPORTED);
                buf.put_u16(4);
            }
            Self::Unknown { param_type, data } => {
                let length = 4 + data.len();
                buf.put_u16(*param_type);
                buf.put_u16(length as u16);
                buf.put_slice(data);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
        }
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        let param_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if length < 4 || data.len() < length {
            return None;
        }

        let padded = padded_length(length);
        let consumed = padded.min(data.len());

        let param = match param_type {
            Self::IPV4_ADDRESS if length == 8 => {
                let addr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Self::Ipv4Address(addr)
            }
            Self::IPV6_ADDRESS if length == 20 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                Self::Ipv6Address(Ipv6Addr::from(octets))
            }
            Self::STATE_COOKIE => {
                let cookie = Bytes::copy_from_slice(&data[4..length]);
                Self::Cookie(cookie)
            }
            Self::COOKIE_PRESERVATIVE if length == 8 => {
                let lifespan = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                Self::CookiePreservative(lifespan)
            }
            Self::HOSTNAME_ADDRESS => {
                let hostname = String::from_utf8_lossy(&data[4..length]).to_string();
                Self::HostnameAddress(hostname)
            }
            Self::SUPPORTED_ADDRESS_TYPES => {
                let mut types = Vec::new();
                let mut offset = 4;
                while offset + 2 <= length {
                    types.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
                    offset += 2;
                }
                Self::SupportedAddressTypes(types)
            }
            Self::ECN_CAPABLE => Self::EcnCapable,
            Self::FORWARD_TSN_SUPPORTED => Self::ForwardTsnSupported,
            _ => Self::Unknown {
                param_type,
                data: Bytes::copy_from_slice(&data[4..length]),
            },
        };

        Some((param, consumed))
    }
}

// =============================================================================
// INIT ACK Chunk (RFC 9260 Section 3.3.3)
// =============================================================================

/// INIT ACK chunk for association initiation acknowledgement.
#[derive(Debug, Clone, PartialEq)]
pub struct InitAckChunk {
    /// Initiate Tag.
    pub initiate_tag: u32,
    /// Advertised Receiver Window Credit.
    pub a_rwnd: u32,
    /// Number of Outbound Streams.
    pub num_outbound_streams: u16,
    /// Number of Inbound Streams.
    pub num_inbound_streams: u16,
    /// Initial TSN.
    pub initial_tsn: u32,
    /// Optional/Variable-length parameters (including State Cookie).
    pub params: Vec<InitParam>,
}

impl InitAckChunk {
    /// INIT ACK chunk header size (excluding parameters).
    pub const HEADER_SIZE: usize = 20;

    /// Creates a new INIT ACK chunk from an INIT chunk.
    #[must_use]
    pub fn from_init(
        init: &InitChunk,
        local_tag: u32,
        local_a_rwnd: u32,
        local_initial_tsn: u32,
        cookie: Bytes,
    ) -> Self {
        let num_outbound = init.num_inbound_streams.min(init.num_outbound_streams);
        let num_inbound = init.num_outbound_streams.min(init.num_inbound_streams);

        Self {
            initiate_tag: local_tag,
            a_rwnd: local_a_rwnd,
            num_outbound_streams: num_outbound,
            num_inbound_streams: num_inbound,
            initial_tsn: local_initial_tsn,
            params: vec![InitParam::Cookie(cookie)],
        }
    }

    /// Returns the state cookie if present.
    #[must_use]
    pub fn cookie(&self) -> Option<&Bytes> {
        self.params.iter().find_map(|p| {
            if let InitParam::Cookie(c) = p {
                Some(c)
            } else {
                None
            }
        })
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u8(ChunkType::InitAck as u8);
        buf.put_u8(0); // flags
        buf.put_u16(0); // length placeholder
        buf.put_u32(self.initiate_tag);
        buf.put_u32(self.a_rwnd);
        buf.put_u16(self.num_outbound_streams);
        buf.put_u16(self.num_inbound_streams);
        buf.put_u32(self.initial_tsn);

        for param in &self.params {
            param.encode(buf);
        }

        let length = buf.len() - start;
        let length_bytes = (length as u16).to_be_bytes();
        buf[start + 2] = length_bytes[0];
        buf[start + 3] = length_bytes[1];

        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < Self::HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: "INIT-ACK chunk too short".to_string(),
            });
        }

        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let initiate_tag =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
        let a_rwnd =
            u32::from_be_bytes([chunk_data[8], chunk_data[9], chunk_data[10], chunk_data[11]]);
        let num_outbound_streams = u16::from_be_bytes([chunk_data[12], chunk_data[13]]);
        let num_inbound_streams = u16::from_be_bytes([chunk_data[14], chunk_data[15]]);
        let initial_tsn = u32::from_be_bytes([
            chunk_data[16],
            chunk_data[17],
            chunk_data[18],
            chunk_data[19],
        ]);

        let mut params = Vec::new();
        let mut offset = Self::HEADER_SIZE;
        let params_end = length.min(chunk_data.len());

        while offset + 4 <= params_end {
            if let Some((param, consumed)) = InitParam::decode(&chunk_data[offset..params_end]) {
                params.push(param);
                offset += consumed;
            } else {
                break;
            }
        }

        Ok(Self {
            initiate_tag,
            a_rwnd,
            num_outbound_streams,
            num_inbound_streams,
            initial_tsn,
            params,
        })
    }
}

// =============================================================================
// SACK Chunk (RFC 9260 Section 3.3.4)
// =============================================================================

/// SACK chunk for selective acknowledgement.
#[derive(Debug, Clone, PartialEq)]
pub struct SackChunk {
    /// Cumulative TSN Ack.
    pub cumulative_tsn_ack: u32,
    /// Advertised Receiver Window Credit.
    pub a_rwnd: u32,
    /// Gap Ack Blocks.
    pub gap_ack_blocks: Vec<GapAckBlock>,
    /// Duplicate TSNs.
    pub dup_tsns: Vec<u32>,
}

/// Gap Ack Block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapAckBlock {
    /// Start offset from Cumulative TSN Ack.
    pub start: u16,
    /// End offset from Cumulative TSN Ack.
    pub end: u16,
}

impl SackChunk {
    /// SACK chunk minimum header size.
    pub const HEADER_SIZE: usize = 16;

    /// Creates a new SACK chunk.
    #[must_use]
    pub fn new(cumulative_tsn_ack: u32, a_rwnd: u32) -> Self {
        Self {
            cumulative_tsn_ack,
            a_rwnd,
            gap_ack_blocks: Vec::new(),
            dup_tsns: Vec::new(),
        }
    }

    /// Adds a gap ack block.
    pub fn add_gap_block(&mut self, start: u16, end: u16) {
        self.gap_ack_blocks.push(GapAckBlock { start, end });
    }

    /// Adds a duplicate TSN.
    pub fn add_dup_tsn(&mut self, tsn: u32) {
        self.dup_tsns.push(tsn);
    }

    fn encode(&self, buf: &mut BytesMut) {
        let length = Self::HEADER_SIZE + self.gap_ack_blocks.len() * 4 + self.dup_tsns.len() * 4;

        buf.put_u8(ChunkType::Sack as u8);
        buf.put_u8(0); // flags
        buf.put_u16(length as u16);
        buf.put_u32(self.cumulative_tsn_ack);
        buf.put_u32(self.a_rwnd);
        buf.put_u16(self.gap_ack_blocks.len() as u16);
        buf.put_u16(self.dup_tsns.len() as u16);

        for gap in &self.gap_ack_blocks {
            buf.put_u16(gap.start);
            buf.put_u16(gap.end);
        }

        for tsn in &self.dup_tsns {
            buf.put_u32(*tsn);
        }

        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < Self::HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: "SACK chunk too short".to_string(),
            });
        }

        let cumulative_tsn_ack =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
        let a_rwnd =
            u32::from_be_bytes([chunk_data[8], chunk_data[9], chunk_data[10], chunk_data[11]]);
        let num_gap_blocks = u16::from_be_bytes([chunk_data[12], chunk_data[13]]) as usize;
        let num_dup_tsns = u16::from_be_bytes([chunk_data[14], chunk_data[15]]) as usize;

        let mut gap_ack_blocks = Vec::with_capacity(num_gap_blocks);
        let mut offset = Self::HEADER_SIZE;

        for _ in 0..num_gap_blocks {
            if offset + 4 > chunk_data.len() {
                break;
            }
            let start = u16::from_be_bytes([chunk_data[offset], chunk_data[offset + 1]]);
            let end = u16::from_be_bytes([chunk_data[offset + 2], chunk_data[offset + 3]]);
            gap_ack_blocks.push(GapAckBlock { start, end });
            offset += 4;
        }

        let mut dup_tsns = Vec::with_capacity(num_dup_tsns);
        for _ in 0..num_dup_tsns {
            if offset + 4 > chunk_data.len() {
                break;
            }
            let tsn = u32::from_be_bytes([
                chunk_data[offset],
                chunk_data[offset + 1],
                chunk_data[offset + 2],
                chunk_data[offset + 3],
            ]);
            dup_tsns.push(tsn);
            offset += 4;
        }

        Ok(Self {
            cumulative_tsn_ack,
            a_rwnd,
            gap_ack_blocks,
            dup_tsns,
        })
    }
}

// =============================================================================
// HEARTBEAT Chunk (RFC 9260 Section 3.3.5)
// =============================================================================

/// HEARTBEAT chunk for path liveness detection.
#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatChunk {
    /// Heartbeat information (opaque to the peer).
    pub info: Bytes,
}

impl HeartbeatChunk {
    /// Creates a new HEARTBEAT chunk.
    #[must_use]
    pub fn new(info: Bytes) -> Self {
        Self { info }
    }

    fn encode(&self, buf: &mut BytesMut) {
        // Heartbeat Info parameter: type=1, length=4+info.len()
        let param_length = 4 + self.info.len();
        let chunk_length = CHUNK_HEADER_SIZE + param_length;

        buf.put_u8(ChunkType::Heartbeat as u8);
        buf.put_u8(0); // flags
        buf.put_u16(chunk_length as u16);
        buf.put_u16(1); // Heartbeat Info parameter type
        buf.put_u16(param_length as u16);
        buf.put_slice(&self.info);

        let padding = padding_needed(chunk_length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;

        if length <= CHUNK_HEADER_SIZE + 4 || chunk_data.len() < length {
            return Ok(Self { info: Bytes::new() });
        }

        // Skip parameter header (4 bytes) to get the info
        let param_length = u16::from_be_bytes([chunk_data[6], chunk_data[7]]) as usize;
        let info_length = param_length.saturating_sub(4).min(chunk_data.len() - 8);
        let info = chunk_data.slice(8..8 + info_length);

        Ok(Self { info })
    }
}

/// HEARTBEAT ACK chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatAckChunk {
    /// Heartbeat information (echoed back).
    pub info: Bytes,
}

impl HeartbeatAckChunk {
    /// Creates a HEARTBEAT ACK from a HEARTBEAT.
    #[must_use]
    pub fn from_heartbeat(heartbeat: &HeartbeatChunk) -> Self {
        Self {
            info: heartbeat.info.clone(),
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        let param_length = 4 + self.info.len();
        let chunk_length = CHUNK_HEADER_SIZE + param_length;

        buf.put_u8(ChunkType::HeartbeatAck as u8);
        buf.put_u8(0);
        buf.put_u16(chunk_length as u16);
        buf.put_u16(1); // Heartbeat Info parameter type
        buf.put_u16(param_length as u16);
        buf.put_slice(&self.info);

        let padding = padding_needed(chunk_length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;

        if length <= CHUNK_HEADER_SIZE + 4 || chunk_data.len() < length {
            return Ok(Self { info: Bytes::new() });
        }

        let param_length = u16::from_be_bytes([chunk_data[6], chunk_data[7]]) as usize;
        let info_length = param_length.saturating_sub(4).min(chunk_data.len() - 8);
        let info = chunk_data.slice(8..8 + info_length);

        Ok(Self { info })
    }
}

// =============================================================================
// ABORT Chunk (RFC 9260 Section 3.3.7)
// =============================================================================

/// ABORT chunk for association abort.
#[derive(Debug, Clone, PartialEq)]
pub struct AbortChunk {
    /// T bit: TCB destroyed.
    pub tcb_destroyed: bool,
    /// Error causes.
    pub causes: Vec<ErrorCause>,
}

impl AbortChunk {
    /// Creates a new ABORT chunk.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tcb_destroyed: false,
            causes: Vec::new(),
        }
    }

    /// Adds an error cause.
    pub fn add_cause(&mut self, cause: ErrorCause) {
        self.causes.push(cause);
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u8(ChunkType::Abort as u8);
        buf.put_u8(if self.tcb_destroyed { 0x01 } else { 0x00 });
        buf.put_u16(0); // length placeholder

        for cause in &self.causes {
            cause.encode(buf);
        }

        let length = buf.len() - start;
        let length_bytes = (length as u16).to_be_bytes();
        buf[start + 2] = length_bytes[0];
        buf[start + 3] = length_bytes[1];

        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let tcb_destroyed = (flags & 0x01) != 0;

        let mut causes = Vec::new();
        let mut offset = CHUNK_HEADER_SIZE;
        let causes_end = length.min(chunk_data.len());

        while offset + 4 <= causes_end {
            if let Some((cause, consumed)) = ErrorCause::decode(&chunk_data[offset..causes_end]) {
                causes.push(cause);
                offset += consumed;
            } else {
                break;
            }
        }

        Ok(Self {
            tcb_destroyed,
            causes,
        })
    }
}

impl Default for AbortChunk {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SHUTDOWN Chunk (RFC 9260 Section 3.3.8)
// =============================================================================

/// SHUTDOWN chunk for graceful shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownChunk {
    /// Cumulative TSN Ack.
    pub cumulative_tsn_ack: u32,
}

impl ShutdownChunk {
    /// Creates a new SHUTDOWN chunk.
    #[must_use]
    pub const fn new(cumulative_tsn_ack: u32) -> Self {
        Self { cumulative_tsn_ack }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(ChunkType::Shutdown as u8);
        buf.put_u8(0);
        buf.put_u16(8);
        buf.put_u32(self.cumulative_tsn_ack);
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "SHUTDOWN chunk too short".to_string(),
            });
        }

        let cumulative_tsn_ack =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);

        Ok(Self { cumulative_tsn_ack })
    }
}

// =============================================================================
// SHUTDOWN ACK Chunk (RFC 9260 Section 3.3.9)
// =============================================================================

/// SHUTDOWN ACK chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShutdownAckChunk;

impl ShutdownAckChunk {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(ChunkType::ShutdownAck as u8);
        buf.put_u8(0);
        buf.put_u16(4);
    }

    fn decode_body(_flags: u8, _chunk_data: &Bytes) -> TransportResult<Self> {
        Ok(Self)
    }
}

// =============================================================================
// ERROR Chunk (RFC 9260 Section 3.3.10)
// =============================================================================

/// ERROR chunk for reporting errors.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorChunk {
    /// Error causes.
    pub causes: Vec<ErrorCause>,
}

impl ErrorChunk {
    /// Creates a new ERROR chunk.
    #[must_use]
    pub fn new() -> Self {
        Self { causes: Vec::new() }
    }

    /// Adds an error cause.
    pub fn add_cause(&mut self, cause: ErrorCause) {
        self.causes.push(cause);
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u8(ChunkType::Error as u8);
        buf.put_u8(0);
        buf.put_u16(0); // length placeholder

        for cause in &self.causes {
            cause.encode(buf);
        }

        let length = buf.len() - start;
        let length_bytes = (length as u16).to_be_bytes();
        buf[start + 2] = length_bytes[0];
        buf[start + 3] = length_bytes[1];

        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;

        let mut causes = Vec::new();
        let mut offset = CHUNK_HEADER_SIZE;
        let causes_end = length.min(chunk_data.len());

        while offset + 4 <= causes_end {
            if let Some((cause, consumed)) = ErrorCause::decode(&chunk_data[offset..causes_end]) {
                causes.push(cause);
                offset += consumed;
            } else {
                break;
            }
        }

        Ok(Self { causes })
    }
}

impl Default for ErrorChunk {
    fn default() -> Self {
        Self::new()
    }
}

/// Error cause codes (RFC 9260 Section 3.3.10).
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorCause {
    /// Invalid Stream Identifier.
    InvalidStreamIdentifier {
        /// The invalid stream identifier.
        stream_id: u16,
    },
    /// Missing Mandatory Parameter.
    MissingMandatoryParameter {
        /// List of missing parameter type codes.
        param_types: Vec<u16>,
    },
    /// Stale Cookie Error.
    StaleCookieError {
        /// Measure of staleness in microseconds.
        measure: u32,
    },
    /// Out of Resource.
    OutOfResource,
    /// Unresolvable Address.
    UnresolvableAddress {
        /// The unresolvable address parameter.
        address: Bytes,
    },
    /// Unrecognized Chunk Type.
    UnrecognizedChunkType {
        /// The unrecognized chunk.
        chunk: Bytes,
    },
    /// Invalid Mandatory Parameter.
    InvalidMandatoryParameter,
    /// Unrecognized Parameters.
    UnrecognizedParameters {
        /// The unrecognized parameters.
        params: Bytes,
    },
    /// No User Data.
    NoUserData {
        /// TSN of the DATA chunk with no user data.
        tsn: u32,
    },
    /// Cookie Received While Shutting Down.
    CookieReceivedWhileShuttingDown,
    /// Restart of an Association with New Addresses.
    RestartWithNewAddresses {
        /// The new addresses.
        addresses: Bytes,
    },
    /// User Initiated Abort.
    UserInitiatedAbort {
        /// Optional abort reason.
        reason: Bytes,
    },
    /// Protocol Violation.
    ProtocolViolation {
        /// Additional information about the violation.
        info: Bytes,
    },
    /// Unknown error cause.
    Unknown {
        /// Error cause code.
        cause_code: u16,
        /// Error cause data.
        data: Bytes,
    },
}

impl ErrorCause {
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::InvalidStreamIdentifier { stream_id } => {
                buf.put_u16(1);
                buf.put_u16(8);
                buf.put_u16(*stream_id);
                buf.put_u16(0); // reserved
            }
            Self::MissingMandatoryParameter { param_types } => {
                let length = 8 + param_types.len() * 2;
                buf.put_u16(2);
                buf.put_u16(length as u16);
                buf.put_u32(param_types.len() as u32);
                for t in param_types {
                    buf.put_u16(*t);
                }
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::StaleCookieError { measure } => {
                buf.put_u16(3);
                buf.put_u16(8);
                buf.put_u32(*measure);
            }
            Self::OutOfResource => {
                buf.put_u16(4);
                buf.put_u16(4);
            }
            Self::UnresolvableAddress { address } => {
                let length = 4 + address.len();
                buf.put_u16(5);
                buf.put_u16(length as u16);
                buf.put_slice(address);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::UnrecognizedChunkType { chunk } => {
                let length = 4 + chunk.len();
                buf.put_u16(6);
                buf.put_u16(length as u16);
                buf.put_slice(chunk);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::InvalidMandatoryParameter => {
                buf.put_u16(7);
                buf.put_u16(4);
            }
            Self::UnrecognizedParameters { params } => {
                let length = 4 + params.len();
                buf.put_u16(8);
                buf.put_u16(length as u16);
                buf.put_slice(params);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::NoUserData { tsn } => {
                buf.put_u16(9);
                buf.put_u16(8);
                buf.put_u32(*tsn);
            }
            Self::CookieReceivedWhileShuttingDown => {
                buf.put_u16(10);
                buf.put_u16(4);
            }
            Self::RestartWithNewAddresses { addresses } => {
                let length = 4 + addresses.len();
                buf.put_u16(11);
                buf.put_u16(length as u16);
                buf.put_slice(addresses);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::UserInitiatedAbort { reason } => {
                let length = 4 + reason.len();
                buf.put_u16(12);
                buf.put_u16(length as u16);
                buf.put_slice(reason);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::ProtocolViolation { info } => {
                let length = 4 + info.len();
                buf.put_u16(13);
                buf.put_u16(length as u16);
                buf.put_slice(info);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::Unknown { cause_code, data } => {
                let length = 4 + data.len();
                buf.put_u16(*cause_code);
                buf.put_u16(length as u16);
                buf.put_slice(data);
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
        }
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        let cause_code = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if length < 4 || data.len() < length {
            return None;
        }

        let padded = padded_length(length);
        let consumed = padded.min(data.len());

        let cause = match cause_code {
            1 if length >= 8 => {
                let stream_id = u16::from_be_bytes([data[4], data[5]]);
                Self::InvalidStreamIdentifier { stream_id }
            }
            2 if length >= 8 => {
                let count = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
                let mut param_types = Vec::with_capacity(count.min(100));
                let mut offset = 8;
                for _ in 0..count {
                    if offset + 2 > length {
                        break;
                    }
                    param_types.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
                    offset += 2;
                }
                Self::MissingMandatoryParameter { param_types }
            }
            3 if length >= 8 => {
                let measure = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                Self::StaleCookieError { measure }
            }
            4 => Self::OutOfResource,
            5 => Self::UnresolvableAddress {
                address: Bytes::copy_from_slice(&data[4..length]),
            },
            6 => Self::UnrecognizedChunkType {
                chunk: Bytes::copy_from_slice(&data[4..length]),
            },
            7 => Self::InvalidMandatoryParameter,
            8 => Self::UnrecognizedParameters {
                params: Bytes::copy_from_slice(&data[4..length]),
            },
            9 if length >= 8 => {
                let tsn = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                Self::NoUserData { tsn }
            }
            10 => Self::CookieReceivedWhileShuttingDown,
            11 => Self::RestartWithNewAddresses {
                addresses: Bytes::copy_from_slice(&data[4..length]),
            },
            12 => Self::UserInitiatedAbort {
                reason: Bytes::copy_from_slice(&data[4..length]),
            },
            13 => Self::ProtocolViolation {
                info: Bytes::copy_from_slice(&data[4..length]),
            },
            _ => Self::Unknown {
                cause_code,
                data: Bytes::copy_from_slice(&data[4..length]),
            },
        };

        Some((cause, consumed))
    }
}

// =============================================================================
// COOKIE ECHO Chunk (RFC 9260 Section 3.3.11)
// =============================================================================

/// COOKIE ECHO chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct CookieEchoChunk {
    /// State cookie.
    pub cookie: Bytes,
}

impl CookieEchoChunk {
    /// Creates a new COOKIE ECHO chunk.
    #[must_use]
    pub fn new(cookie: Bytes) -> Self {
        Self { cookie }
    }

    fn encode(&self, buf: &mut BytesMut) {
        let length = CHUNK_HEADER_SIZE + self.cookie.len();
        buf.put_u8(ChunkType::CookieEcho as u8);
        buf.put_u8(0);
        buf.put_u16(length as u16);
        buf.put_slice(&self.cookie);

        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let cookie_len = length
            .saturating_sub(CHUNK_HEADER_SIZE)
            .min(chunk_data.len() - CHUNK_HEADER_SIZE);
        let cookie = chunk_data.slice(CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + cookie_len);
        Ok(Self { cookie })
    }
}

// =============================================================================
// COOKIE ACK Chunk (RFC 9260 Section 3.3.12)
// =============================================================================

/// COOKIE ACK chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CookieAckChunk;

impl CookieAckChunk {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(ChunkType::CookieAck as u8);
        buf.put_u8(0);
        buf.put_u16(4);
    }

    fn decode_body(_flags: u8, _chunk_data: &Bytes) -> TransportResult<Self> {
        Ok(Self)
    }
}

// =============================================================================
// SHUTDOWN COMPLETE Chunk (RFC 9260 Section 3.3.13)
// =============================================================================

/// SHUTDOWN COMPLETE chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownCompleteChunk {
    /// T bit: TCB destroyed.
    pub tcb_destroyed: bool,
}

impl ShutdownCompleteChunk {
    /// Creates a new SHUTDOWN COMPLETE chunk.
    #[must_use]
    pub const fn new(tcb_destroyed: bool) -> Self {
        Self { tcb_destroyed }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(ChunkType::ShutdownComplete as u8);
        buf.put_u8(if self.tcb_destroyed { 0x01 } else { 0x00 });
        buf.put_u16(4);
    }

    fn decode_body(flags: u8, _chunk_data: &Bytes) -> TransportResult<Self> {
        Ok(Self {
            tcb_destroyed: (flags & 0x01) != 0,
        })
    }
}

impl Default for ShutdownCompleteChunk {
    fn default() -> Self {
        Self::new(false)
    }
}

// =============================================================================
// ECNE Chunk (RFC 9260 Section 3.3.11)
// =============================================================================

/// Explicit Congestion Notification Echo (ECNE) chunk.
///
/// Used to echo back CE (Congestion Experienced) marks received in
/// the IP header of DATA chunks, as part of ECN support.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 12   |   Flags = 0   |         Length = 8            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Lowest TSN Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcneChunk {
    /// Lowest TSN Number: The lowest TSN number that was received with
    /// the CE bit set in the IP header.
    pub lowest_tsn: u32,
}

impl EcneChunk {
    /// Creates a new ECNE chunk.
    #[must_use]
    pub const fn new(lowest_tsn: u32) -> Self {
        Self { lowest_tsn }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(ChunkType::Ecne as u8);
        buf.put_u8(0);
        buf.put_u16(8);
        buf.put_u32(self.lowest_tsn);
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "ECNE chunk too short".to_string(),
            });
        }

        let lowest_tsn =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);

        Ok(Self { lowest_tsn })
    }
}

// =============================================================================
// CWR Chunk (RFC 9260 Section 3.3.12)
// =============================================================================

/// Congestion Window Reduced (CWR) chunk.
///
/// Used to acknowledge that the sender has reduced its congestion window
/// in response to an ECNE chunk.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 13   |   Flags = 0   |         Length = 8            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Lowest TSN Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CwrChunk {
    /// Lowest TSN Number: The lowest TSN number that the sender of
    /// the CWR chunk received with the CE bit set.
    pub lowest_tsn: u32,
}

impl CwrChunk {
    /// Creates a new CWR chunk.
    #[must_use]
    pub const fn new(lowest_tsn: u32) -> Self {
        Self { lowest_tsn }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(ChunkType::Cwr as u8);
        buf.put_u8(0);
        buf.put_u16(8);
        buf.put_u32(self.lowest_tsn);
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "CWR chunk too short".to_string(),
            });
        }

        let lowest_tsn =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);

        Ok(Self { lowest_tsn })
    }
}

// =============================================================================
// FORWARD-TSN Chunk (RFC 3758 Section 3.2)
// =============================================================================

/// Stream information for FORWARD-TSN (RFC 3758).
///
/// Indicates the new stream sequence number for a given stream after
/// skipping undeliverable DATA chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardTsnStream {
    /// Stream ID.
    pub stream_id: u16,
    /// New stream sequence number.
    pub ssn: u16,
}

impl ForwardTsnStream {
    /// Creates a new forward TSN stream entry.
    #[must_use]
    pub const fn new(stream_id: u16, ssn: u16) -> Self {
        Self { stream_id, ssn }
    }
}

/// Forward TSN (FORWARD-TSN) chunk (RFC 3758 Section 3.2).
///
/// The FORWARD TSN chunk is used by the sender to inform the receiver
/// that it may skip TSNs that have not been received. This is used for
/// partial reliability where data may be abandoned after timeouts.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 192  |  Flags = 0x00 |         Length                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      New Cumulative TSN                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Stream-1              |       Stream Sequence-1       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               /
/// /                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Stream-N              |       Stream Sequence-N       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardTsnChunk {
    /// New Cumulative TSN: The new cumulative TSN that the receiver should
    /// advance to. All TSNs up to and including this one can be skipped.
    pub new_cumulative_tsn: u32,
    /// Stream information for each stream with skipped data.
    pub streams: Vec<ForwardTsnStream>,
}

impl ForwardTsnChunk {
    /// Creates a new FORWARD-TSN chunk.
    #[must_use]
    pub fn new(new_cumulative_tsn: u32) -> Self {
        Self {
            new_cumulative_tsn,
            streams: Vec::new(),
        }
    }

    /// Creates a FORWARD-TSN chunk with stream information.
    #[must_use]
    pub fn with_streams(new_cumulative_tsn: u32, streams: Vec<ForwardTsnStream>) -> Self {
        Self {
            new_cumulative_tsn,
            streams,
        }
    }

    /// Adds stream information to the chunk.
    pub fn add_stream(&mut self, stream_id: u16, ssn: u16) {
        self.streams.push(ForwardTsnStream::new(stream_id, ssn));
    }

    fn encode(&self, buf: &mut BytesMut) {
        let length = 8 + self.streams.len() * 4; // header(4) + tsn(4) + streams(4 each)

        buf.put_u8(ChunkType::ForwardTsn as u8);
        buf.put_u8(0);
        buf.put_u16(length as u16);
        buf.put_u32(self.new_cumulative_tsn);

        for stream in &self.streams {
            buf.put_u16(stream.stream_id);
            buf.put_u16(stream.ssn);
        }

        // Add padding if needed
        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "FORWARD-TSN chunk too short".to_string(),
            });
        }

        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let new_cumulative_tsn =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);

        let mut streams = Vec::new();
        let mut offset = 8;

        // Parse stream entries (4 bytes each: stream_id(2) + ssn(2))
        while offset + 4 <= length && offset + 4 <= chunk_data.len() {
            let stream_id = u16::from_be_bytes([chunk_data[offset], chunk_data[offset + 1]]);
            let ssn = u16::from_be_bytes([chunk_data[offset + 2], chunk_data[offset + 3]]);
            streams.push(ForwardTsnStream::new(stream_id, ssn));
            offset += 4;
        }

        Ok(Self {
            new_cumulative_tsn,
            streams,
        })
    }
}

// =============================================================================
// RE-CONFIG Chunk (RFC 6525)
// =============================================================================

/// RE-CONFIG parameter types (RFC 6525 Section 4).
#[derive(Debug, Clone, PartialEq)]
pub enum ReConfigParam {
    /// Outgoing SSN Reset Request (Section 4.1).
    OutgoingSsnReset {
        /// Request sequence number.
        req_seq_num: u32,
        /// Response sequence number.
        resp_seq_num: u32,
        /// Last assigned TSN.
        last_tsn: u32,
        /// Stream IDs to reset (empty = all outgoing streams).
        stream_ids: Vec<u16>,
    },
    /// Incoming SSN Reset Request (Section 4.2).
    IncomingSsnReset {
        /// Request sequence number.
        req_seq_num: u32,
        /// Stream IDs to reset.
        stream_ids: Vec<u16>,
    },
    /// SSN/TSN Reset Request (Section 4.3).
    SsnTsnReset {
        /// Request sequence number.
        req_seq_num: u32,
    },
    /// RE-CONFIG Response (Section 4.4).
    Response {
        /// Response sequence number (matches request seq num).
        resp_seq_num: u32,
        /// Result of the request.
        result: ReConfigResult,
        /// Sender's next TSN (for SSN/TSN reset).
        sender_next_tsn: Option<u32>,
        /// Receiver's next TSN (for SSN/TSN reset).
        receiver_next_tsn: Option<u32>,
    },
    /// Add Outgoing Streams Request (Section 4.5).
    AddOutgoingStreams {
        /// Request sequence number.
        req_seq_num: u32,
        /// Number of new outgoing streams.
        num_streams: u16,
    },
    /// Add Incoming Streams Request (Section 4.6).
    AddIncomingStreams {
        /// Request sequence number.
        req_seq_num: u32,
        /// Number of new incoming streams.
        num_streams: u16,
    },
}

/// RE-CONFIG response result codes (RFC 6525 Section 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReConfigResult {
    /// Success - Nothing to do.
    SuccessNothingToDo = 0,
    /// Success - Performed.
    SuccessPerformed = 1,
    /// Denied.
    Denied = 2,
    /// Error - Wrong SSN.
    ErrorWrongSsn = 3,
    /// Error - Request already in progress.
    ErrorAlreadyInProgress = 4,
    /// Error - Bad Sequence Number.
    ErrorBadSeqNum = 5,
    /// In progress.
    InProgress = 6,
}

impl ReConfigResult {
    /// Creates a result from a raw value.
    fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::SuccessNothingToDo,
            1 => Self::SuccessPerformed,
            2 => Self::Denied,
            3 => Self::ErrorWrongSsn,
            4 => Self::ErrorAlreadyInProgress,
            5 => Self::ErrorBadSeqNum,
            6 => Self::InProgress,
            _ => Self::Denied, // Unknown treated as denied
        }
    }

    /// Returns true if this is a success result.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::SuccessNothingToDo | Self::SuccessPerformed)
    }
}

impl ReConfigParam {
    // Parameter type codes (RFC 6525 Section 4)
    const OUTGOING_SSN_RESET: u16 = 13;
    const INCOMING_SSN_RESET: u16 = 14;
    const SSN_TSN_RESET: u16 = 15;
    const RESPONSE: u16 = 16;
    const ADD_OUTGOING_STREAMS: u16 = 17;
    const ADD_INCOMING_STREAMS: u16 = 18;

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::OutgoingSsnReset {
                req_seq_num,
                resp_seq_num,
                last_tsn,
                stream_ids,
            } => {
                let length = 16 + stream_ids.len() * 2;
                buf.put_u16(Self::OUTGOING_SSN_RESET);
                buf.put_u16(length as u16);
                buf.put_u32(*req_seq_num);
                buf.put_u32(*resp_seq_num);
                buf.put_u32(*last_tsn);
                for sid in stream_ids {
                    buf.put_u16(*sid);
                }
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::IncomingSsnReset {
                req_seq_num,
                stream_ids,
            } => {
                let length = 8 + stream_ids.len() * 2;
                buf.put_u16(Self::INCOMING_SSN_RESET);
                buf.put_u16(length as u16);
                buf.put_u32(*req_seq_num);
                for sid in stream_ids {
                    buf.put_u16(*sid);
                }
                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
            Self::SsnTsnReset { req_seq_num } => {
                buf.put_u16(Self::SSN_TSN_RESET);
                buf.put_u16(8);
                buf.put_u32(*req_seq_num);
            }
            Self::Response {
                resp_seq_num,
                result,
                sender_next_tsn,
                receiver_next_tsn,
            } => {
                let has_tsns = sender_next_tsn.is_some() && receiver_next_tsn.is_some();
                let length = if has_tsns { 20 } else { 12 };
                buf.put_u16(Self::RESPONSE);
                buf.put_u16(length as u16);
                buf.put_u32(*resp_seq_num);
                buf.put_u32(*result as u32);
                if let (Some(sender), Some(receiver)) = (sender_next_tsn, receiver_next_tsn) {
                    buf.put_u32(*sender);
                    buf.put_u32(*receiver);
                }
            }
            Self::AddOutgoingStreams {
                req_seq_num,
                num_streams,
            } => {
                buf.put_u16(Self::ADD_OUTGOING_STREAMS);
                buf.put_u16(12);
                buf.put_u32(*req_seq_num);
                buf.put_u16(*num_streams);
                buf.put_u16(0); // Reserved
            }
            Self::AddIncomingStreams {
                req_seq_num,
                num_streams,
            } => {
                buf.put_u16(Self::ADD_INCOMING_STREAMS);
                buf.put_u16(12);
                buf.put_u32(*req_seq_num);
                buf.put_u16(*num_streams);
                buf.put_u16(0); // Reserved
            }
        }
    }

    fn decode(data: &[u8]) -> TransportResult<(Self, usize)> {
        if data.len() < 4 {
            return Err(TransportError::ReceiveFailed {
                reason: "RE-CONFIG parameter too short".to_string(),
            });
        }

        let param_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < length {
            return Err(TransportError::ReceiveFailed {
                reason: "RE-CONFIG parameter truncated".to_string(),
            });
        }

        let param = match param_type {
            Self::OUTGOING_SSN_RESET if length >= 16 => {
                let req_seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let resp_seq_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                let last_tsn = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
                let mut stream_ids = Vec::new();
                let mut offset = 16;
                while offset + 2 <= length {
                    stream_ids.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
                    offset += 2;
                }
                Self::OutgoingSsnReset {
                    req_seq_num,
                    resp_seq_num,
                    last_tsn,
                    stream_ids,
                }
            }
            Self::INCOMING_SSN_RESET if length >= 8 => {
                let req_seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let mut stream_ids = Vec::new();
                let mut offset = 8;
                while offset + 2 <= length {
                    stream_ids.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
                    offset += 2;
                }
                Self::IncomingSsnReset {
                    req_seq_num,
                    stream_ids,
                }
            }
            Self::SSN_TSN_RESET if length >= 8 => {
                let req_seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                Self::SsnTsnReset { req_seq_num }
            }
            Self::RESPONSE if length >= 12 => {
                let resp_seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let result = ReConfigResult::from_u32(u32::from_be_bytes([
                    data[8], data[9], data[10], data[11],
                ]));
                let (sender_next_tsn, receiver_next_tsn) = if length >= 20 {
                    (
                        Some(u32::from_be_bytes([data[12], data[13], data[14], data[15]])),
                        Some(u32::from_be_bytes([data[16], data[17], data[18], data[19]])),
                    )
                } else {
                    (None, None)
                };
                Self::Response {
                    resp_seq_num,
                    result,
                    sender_next_tsn,
                    receiver_next_tsn,
                }
            }
            Self::ADD_OUTGOING_STREAMS if length >= 12 => {
                let req_seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let num_streams = u16::from_be_bytes([data[8], data[9]]);
                Self::AddOutgoingStreams {
                    req_seq_num,
                    num_streams,
                }
            }
            Self::ADD_INCOMING_STREAMS if length >= 12 => {
                let req_seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let num_streams = u16::from_be_bytes([data[8], data[9]]);
                Self::AddIncomingStreams {
                    req_seq_num,
                    num_streams,
                }
            }
            _ => {
                return Err(TransportError::ReceiveFailed {
                    reason: format!("Unknown RE-CONFIG parameter type: {param_type}"),
                });
            }
        };

        Ok((param, padded_length(length)))
    }
}

/// Reconfiguration (RE-CONFIG) chunk (RFC 6525 Section 3.1).
///
/// Used to reset streams, add streams, or reset TSN during an association.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type = 130    |  Chunk Flags  |         Chunk Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                  Re-configuration Parameter(s)                /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ReConfigChunk {
    /// RE-CONFIG parameters.
    pub params: Vec<ReConfigParam>,
}

impl ReConfigChunk {
    /// Creates a new empty RE-CONFIG chunk.
    #[must_use]
    pub fn new() -> Self {
        Self { params: Vec::new() }
    }

    /// Adds a parameter to the chunk.
    pub fn add_param(&mut self, param: ReConfigParam) {
        self.params.push(param);
    }

    /// Creates an outgoing SSN reset request.
    #[must_use]
    pub fn outgoing_ssn_reset(
        req_seq_num: u32,
        resp_seq_num: u32,
        last_tsn: u32,
        stream_ids: Vec<u16>,
    ) -> Self {
        let mut chunk = Self::new();
        chunk.add_param(ReConfigParam::OutgoingSsnReset {
            req_seq_num,
            resp_seq_num,
            last_tsn,
            stream_ids,
        });
        chunk
    }

    /// Creates an incoming SSN reset request.
    #[must_use]
    pub fn incoming_ssn_reset(req_seq_num: u32, stream_ids: Vec<u16>) -> Self {
        let mut chunk = Self::new();
        chunk.add_param(ReConfigParam::IncomingSsnReset {
            req_seq_num,
            stream_ids,
        });
        chunk
    }

    /// Creates a response.
    #[must_use]
    pub fn response(resp_seq_num: u32, result: ReConfigResult) -> Self {
        let mut chunk = Self::new();
        chunk.add_param(ReConfigParam::Response {
            resp_seq_num,
            result,
            sender_next_tsn: None,
            receiver_next_tsn: None,
        });
        chunk
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u8(ChunkType::ReConfig as u8);
        buf.put_u8(0);
        buf.put_u16(0); // Length placeholder

        for param in &self.params {
            param.encode(buf);
        }

        // Update length
        let length = buf.len() - start;
        let length_bytes = (length as u16).to_be_bytes();
        buf[start + 2] = length_bytes[0];
        buf[start + 3] = length_bytes[1];

        // Add chunk padding if needed
        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < 4 {
            return Err(TransportError::ReceiveFailed {
                reason: "RE-CONFIG chunk too short".to_string(),
            });
        }

        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let mut params = Vec::new();
        let mut offset = 4;

        while offset < length && offset < chunk_data.len() {
            let (param, consumed) = ReConfigParam::decode(&chunk_data[offset..])?;
            params.push(param);
            offset += consumed;
        }

        Ok(Self { params })
    }
}

impl Default for ReConfigChunk {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ASCONF Chunk (RFC 5061 Section 4.1)
// =============================================================================

/// ASCONF parameter types (RFC 5061).
#[derive(Debug, Clone, PartialEq)]
pub enum AsconfParam {
    /// Add IP Address (RFC 5061 Section 4.2.1).
    AddIp {
        /// Correlation ID for matching with ASCONF-ACK.
        correlation_id: u32,
        /// IPv4 address to add.
        ipv4: Option<std::net::Ipv4Addr>,
        /// IPv6 address to add.
        ipv6: Option<std::net::Ipv6Addr>,
    },
    /// Delete IP Address (RFC 5061 Section 4.2.2).
    DeleteIp {
        /// Correlation ID for matching with ASCONF-ACK.
        correlation_id: u32,
        /// IPv4 address to delete.
        ipv4: Option<std::net::Ipv4Addr>,
        /// IPv6 address to delete.
        ipv6: Option<std::net::Ipv6Addr>,
    },
    /// Set Primary Address (RFC 5061 Section 4.2.4).
    SetPrimaryAddress {
        /// Correlation ID for matching with ASCONF-ACK.
        correlation_id: u32,
        /// IPv4 address to set as primary.
        ipv4: Option<std::net::Ipv4Addr>,
        /// IPv6 address to set as primary.
        ipv6: Option<std::net::Ipv6Addr>,
    },
}

impl AsconfParam {
    // Parameter type codes (RFC 5061)
    const ADD_IP: u16 = 0xC001;
    const DELETE_IP: u16 = 0xC002;
    const SET_PRIMARY: u16 = 0xC004;
    // Address parameter types
    const IPV4_ADDRESS: u16 = 5;
    const IPV6_ADDRESS: u16 = 6;

    /// Returns the correlation ID for this parameter.
    #[must_use]
    pub fn correlation_id(&self) -> u32 {
        match self {
            Self::AddIp { correlation_id, .. }
            | Self::DeleteIp { correlation_id, .. }
            | Self::SetPrimaryAddress { correlation_id, .. } => *correlation_id,
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::AddIp {
                correlation_id,
                ipv4,
                ipv6,
            } => {
                Self::encode_address_param(buf, Self::ADD_IP, *correlation_id, *ipv4, *ipv6);
            }
            Self::DeleteIp {
                correlation_id,
                ipv4,
                ipv6,
            } => {
                Self::encode_address_param(buf, Self::DELETE_IP, *correlation_id, *ipv4, *ipv6);
            }
            Self::SetPrimaryAddress {
                correlation_id,
                ipv4,
                ipv6,
            } => {
                Self::encode_address_param(buf, Self::SET_PRIMARY, *correlation_id, *ipv4, *ipv6);
            }
        }
    }

    fn encode_address_param(
        buf: &mut BytesMut,
        param_type: u16,
        correlation_id: u32,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) {
        // Calculate length: 4 (header) + 4 (correlation_id) + address param
        let addr_len = if ipv4.is_some() {
            8
        } else if ipv6.is_some() {
            20
        } else {
            0
        };
        let length = 4 + 4 + addr_len;

        buf.put_u16(param_type);
        buf.put_u16(length as u16);
        buf.put_u32(correlation_id);

        if let Some(addr) = ipv4 {
            buf.put_u16(Self::IPV4_ADDRESS);
            buf.put_u16(8);
            buf.put_slice(&addr.octets());
        } else if let Some(addr) = ipv6 {
            buf.put_u16(Self::IPV6_ADDRESS);
            buf.put_u16(20);
            buf.put_slice(&addr.octets());
        }

        // Add padding if needed
        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode(data: &[u8]) -> TransportResult<(Self, usize)> {
        if data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "ASCONF parameter too short".to_string(),
            });
        }

        let param_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let correlation_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        if data.len() < length {
            return Err(TransportError::ReceiveFailed {
                reason: "ASCONF parameter truncated".to_string(),
            });
        }

        // Decode address if present
        let (ipv4, ipv6) = if length > 8 {
            Self::decode_address(&data[8..length])?
        } else {
            (None, None)
        };

        let param = match param_type {
            Self::ADD_IP => Self::AddIp {
                correlation_id,
                ipv4,
                ipv6,
            },
            Self::DELETE_IP => Self::DeleteIp {
                correlation_id,
                ipv4,
                ipv6,
            },
            Self::SET_PRIMARY => Self::SetPrimaryAddress {
                correlation_id,
                ipv4,
                ipv6,
            },
            _ => {
                return Err(TransportError::ReceiveFailed {
                    reason: format!("Unknown ASCONF parameter type: {param_type:#x}"),
                });
            }
        };

        let padded_len = padded_length(length);
        Ok((param, padded_len))
    }

    fn decode_address(
        data: &[u8],
    ) -> TransportResult<(Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
        if data.len() < 4 {
            return Ok((None, None));
        }

        let addr_type = u16::from_be_bytes([data[0], data[1]]);
        // addr_len is available but we use fixed offsets for IPv4/IPv6
        let _addr_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        match addr_type {
            Self::IPV4_ADDRESS if data.len() >= 8 => {
                let octets: [u8; 4] = data[4..8].try_into().unwrap();
                Ok((Some(std::net::Ipv4Addr::from(octets)), None))
            }
            Self::IPV6_ADDRESS if data.len() >= 20 => {
                let octets: [u8; 16] = data[4..20].try_into().unwrap();
                Ok((None, Some(std::net::Ipv6Addr::from(octets))))
            }
            _ => Ok((None, None)),
        }
    }
}

/// Address Configuration Change (ASCONF) chunk (RFC 5061).
///
/// Used to dynamically add or delete IP addresses from an association,
/// or to set a new primary address.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type = 0xC1   |  Chunk Flags  |      Chunk Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Serial Number                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Address Parameter                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     ASCONF Parameter #1                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                             ....                              /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     ASCONF Parameter #N                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AsconfChunk {
    /// Serial Number: Monotonically increasing number to detect duplicates.
    pub serial_number: u32,
    /// Address of the sender (IPv4 or IPv6).
    pub sender_ipv4: Option<std::net::Ipv4Addr>,
    /// Address of the sender (IPv6).
    pub sender_ipv6: Option<std::net::Ipv6Addr>,
    /// ASCONF parameters (ADD-IP, DELETE-IP, SET-PRIMARY).
    pub params: Vec<AsconfParam>,
}

impl AsconfChunk {
    /// Creates a new ASCONF chunk.
    #[must_use]
    pub fn new(serial_number: u32) -> Self {
        Self {
            serial_number,
            sender_ipv4: None,
            sender_ipv6: None,
            params: Vec::new(),
        }
    }

    /// Sets the sender's IPv4 address.
    #[must_use]
    pub fn with_sender_ipv4(mut self, addr: std::net::Ipv4Addr) -> Self {
        self.sender_ipv4 = Some(addr);
        self
    }

    /// Sets the sender's IPv6 address.
    #[must_use]
    pub fn with_sender_ipv6(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.sender_ipv6 = Some(addr);
        self
    }

    /// Adds an ADD-IP parameter.
    pub fn add_ip(
        &mut self,
        correlation_id: u32,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) {
        self.params.push(AsconfParam::AddIp {
            correlation_id,
            ipv4,
            ipv6,
        });
    }

    /// Adds a DELETE-IP parameter.
    pub fn delete_ip(
        &mut self,
        correlation_id: u32,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) {
        self.params.push(AsconfParam::DeleteIp {
            correlation_id,
            ipv4,
            ipv6,
        });
    }

    /// Adds a SET-PRIMARY-ADDRESS parameter.
    pub fn set_primary(
        &mut self,
        correlation_id: u32,
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) {
        self.params.push(AsconfParam::SetPrimaryAddress {
            correlation_id,
            ipv4,
            ipv6,
        });
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();

        buf.put_u8(ChunkType::Asconf as u8);
        buf.put_u8(0); // flags
        buf.put_u16(0); // length placeholder
        buf.put_u32(self.serial_number);

        // Encode sender address
        if let Some(addr) = self.sender_ipv4 {
            buf.put_u16(AsconfParam::IPV4_ADDRESS);
            buf.put_u16(8);
            buf.put_slice(&addr.octets());
        } else if let Some(addr) = self.sender_ipv6 {
            buf.put_u16(AsconfParam::IPV6_ADDRESS);
            buf.put_u16(20);
            buf.put_slice(&addr.octets());
        }

        // Encode parameters
        for param in &self.params {
            param.encode(buf);
        }

        // Update length
        let length = buf.len() - start;
        let length_bytes = (length as u16).to_be_bytes();
        buf[start + 2] = length_bytes[0];
        buf[start + 3] = length_bytes[1];

        // Add padding
        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < 12 {
            return Err(TransportError::ReceiveFailed {
                reason: "ASCONF chunk too short".to_string(),
            });
        }

        let serial_number =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);

        // Decode sender address
        let addr_type = u16::from_be_bytes([chunk_data[8], chunk_data[9]]);
        let addr_len = u16::from_be_bytes([chunk_data[10], chunk_data[11]]) as usize;

        let (sender_ipv4, sender_ipv6, params_offset) = match addr_type {
            5 if chunk_data.len() >= 16 => {
                // IPv4
                let octets: [u8; 4] = chunk_data[12..16].try_into().unwrap();
                (Some(std::net::Ipv4Addr::from(octets)), None, 16)
            }
            6 if chunk_data.len() >= 28 => {
                // IPv6
                let octets: [u8; 16] = chunk_data[12..28].try_into().unwrap();
                (None, Some(std::net::Ipv6Addr::from(octets)), 28)
            }
            _ => (None, None, 8 + padded_length(addr_len)),
        };

        // Decode ASCONF parameters
        let mut params = Vec::new();
        let mut offset = params_offset;
        while offset < chunk_data.len() - 4 {
            // Need at least 4 bytes for param header
            match AsconfParam::decode(&chunk_data[offset..]) {
                Ok((param, consumed)) => {
                    params.push(param);
                    offset += consumed;
                }
                Err(_) => break,
            }
        }

        Ok(Self {
            serial_number,
            sender_ipv4,
            sender_ipv6,
            params,
        })
    }
}

// =============================================================================
// ASCONF-ACK Chunk (RFC 5061 Section 4.1.1)
// =============================================================================

/// ASCONF-ACK response parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum AsconfAckParam {
    /// Success Indication - request was processed successfully.
    Success {
        /// Correlation ID from the original request.
        correlation_id: u32,
    },
    /// Error Cause Indication - request failed.
    ErrorCause {
        /// Correlation ID from the original request.
        correlation_id: u32,
        /// Error cause code.
        error_code: u16,
        /// Additional error information.
        error_info: Bytes,
    },
}

impl AsconfAckParam {
    const SUCCESS_INDICATION: u16 = 0xC003;
    const ERROR_CAUSE_INDICATION: u16 = 0xC005;

    /// Returns the correlation ID.
    #[must_use]
    pub fn correlation_id(&self) -> u32 {
        match self {
            Self::Success { correlation_id } | Self::ErrorCause { correlation_id, .. } => {
                *correlation_id
            }
        }
    }

    /// Returns true if this is a success response.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::Success { correlation_id } => {
                buf.put_u16(Self::SUCCESS_INDICATION);
                buf.put_u16(8);
                buf.put_u32(*correlation_id);
            }
            Self::ErrorCause {
                correlation_id,
                error_code,
                error_info,
            } => {
                let length = 8 + 4 + error_info.len();
                buf.put_u16(Self::ERROR_CAUSE_INDICATION);
                buf.put_u16(length as u16);
                buf.put_u32(*correlation_id);
                buf.put_u16(*error_code);
                buf.put_u16(error_info.len() as u16);
                buf.put_slice(error_info);

                let padding = padding_needed(length);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
            }
        }
    }

    fn decode(data: &[u8]) -> TransportResult<(Self, usize)> {
        if data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "ASCONF-ACK parameter too short".to_string(),
            });
        }

        let param_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let correlation_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let param = match param_type {
            Self::SUCCESS_INDICATION => Self::Success { correlation_id },
            Self::ERROR_CAUSE_INDICATION if length >= 12 => {
                let error_code = u16::from_be_bytes([data[8], data[9]]);
                let error_len = u16::from_be_bytes([data[10], data[11]]) as usize;
                let error_info = if length > 12 && data.len() >= 12 + error_len {
                    Bytes::copy_from_slice(&data[12..12 + error_len])
                } else {
                    Bytes::new()
                };
                Self::ErrorCause {
                    correlation_id,
                    error_code,
                    error_info,
                }
            }
            _ => Self::Success { correlation_id }, // Treat unknown as success
        };

        let padded_len = padded_length(length);
        Ok((param, padded_len))
    }
}

/// Address Configuration Acknowledgement (ASCONF-ACK) chunk (RFC 5061).
///
/// Sent in response to an ASCONF chunk to indicate success or failure
/// of each requested operation.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type = 0x80   |  Chunk Flags  |      Chunk Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Serial Number                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 ASCONF-ACK Parameter #1                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                             ....                              /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 ASCONF-ACK Parameter #N                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AsconfAckChunk {
    /// Serial Number: Must match the ASCONF being acknowledged.
    pub serial_number: u32,
    /// Response parameters for each ASCONF parameter.
    pub params: Vec<AsconfAckParam>,
}

impl AsconfAckChunk {
    /// Creates a new ASCONF-ACK chunk.
    #[must_use]
    pub fn new(serial_number: u32) -> Self {
        Self {
            serial_number,
            params: Vec::new(),
        }
    }

    /// Adds a success response for the given correlation ID.
    pub fn add_success(&mut self, correlation_id: u32) {
        self.params.push(AsconfAckParam::Success { correlation_id });
    }

    /// Adds an error response for the given correlation ID.
    pub fn add_error(&mut self, correlation_id: u32, error_code: u16, error_info: Bytes) {
        self.params.push(AsconfAckParam::ErrorCause {
            correlation_id,
            error_code,
            error_info,
        });
    }

    /// Returns true if all responses are successful.
    #[must_use]
    pub fn all_success(&self) -> bool {
        self.params.iter().all(AsconfAckParam::is_success)
    }

    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();

        buf.put_u8(ChunkType::AsconfAck as u8);
        buf.put_u8(0); // flags
        buf.put_u16(0); // length placeholder
        buf.put_u32(self.serial_number);

        for param in &self.params {
            param.encode(buf);
        }

        // Update length
        let length = buf.len() - start;
        let length_bytes = (length as u16).to_be_bytes();
        buf[start + 2] = length_bytes[0];
        buf[start + 3] = length_bytes[1];

        // Add padding
        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "ASCONF-ACK chunk too short".to_string(),
            });
        }

        let serial_number =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);

        // Decode response parameters
        let mut params = Vec::new();
        let mut offset = 8;
        while offset < chunk_data.len() - 4 {
            match AsconfAckParam::decode(&chunk_data[offset..]) {
                Ok((param, consumed)) => {
                    params.push(param);
                    offset += consumed;
                }
                Err(_) => break,
            }
        }

        Ok(Self {
            serial_number,
            params,
        })
    }
}

// =============================================================================
// PAD Chunk (RFC 4820 / RFC 9260 §3.3.14)
// =============================================================================

/// PAD chunk for path MTU discovery (RFC 4820).
///
/// The PAD chunk is used to pad a packet to a specific size for PMTU probing.
/// Receivers MUST silently ignore the padding data.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type = 0x84   |   Flags = 0   |             Length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                          Padding Data                         /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PadChunk {
    /// Padding data (arbitrary bytes, typically zeros).
    pub padding: Bytes,
}

impl PadChunk {
    /// Creates a new PAD chunk with the specified padding size.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            padding: Bytes::from(vec![0u8; size]),
        }
    }

    /// Creates a PAD chunk from raw padding data.
    #[must_use]
    pub fn from_bytes(padding: Bytes) -> Self {
        Self { padding }
    }

    /// Returns the total chunk size including header.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        CHUNK_HEADER_SIZE + self.padding.len()
    }

    fn encode(&self, buf: &mut BytesMut) {
        let length = CHUNK_HEADER_SIZE + self.padding.len();

        buf.put_u8(ChunkType::Pad as u8);
        buf.put_u8(0); // flags
        buf.put_u16(length as u16);
        buf.put_slice(&self.padding);

        // Add padding if needed for 4-byte alignment
        let pad = padding_needed(length);
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        if chunk_data.len() < CHUNK_HEADER_SIZE {
            return Err(TransportError::ReceiveFailed {
                reason: "PAD chunk too short".to_string(),
            });
        }

        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let padding_len = length.saturating_sub(CHUNK_HEADER_SIZE);

        let padding = if padding_len > 0 && chunk_data.len() >= CHUNK_HEADER_SIZE + padding_len {
            chunk_data.slice(CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + padding_len)
        } else {
            Bytes::new()
        };

        Ok(Self { padding })
    }
}

// =============================================================================
// AUTH Chunk (RFC 4895)
// =============================================================================

/// HMAC identifier for AUTH chunk (RFC 4895 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HmacId {
    /// Reserved value (not valid for use).
    Reserved = 0,
    /// HMAC-SHA-1 (RFC 2104).
    Sha1 = 1,
    /// HMAC-SHA-256 (RFC 4231).
    Sha256 = 3,
}

impl HmacId {
    /// Creates an HmacId from a raw u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Reserved),
            1 => Some(Self::Sha1),
            3 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Returns the HMAC output length in bytes.
    #[must_use]
    pub const fn hmac_length(self) -> usize {
        match self {
            Self::Reserved => 0,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

/// AUTH chunk for SCTP authentication (RFC 4895 §4.1).
///
/// The AUTH chunk provides authentication of SCTP packets using shared
/// key and HMAC algorithms. It MUST be the first chunk if present.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type = 0x0F   |   Flags = 0   |             Length            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Shared Key Identifier      |        HMAC Identifier        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                             HMAC                              /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AuthChunk {
    /// Shared Key Identifier - identifies the shared key and HMAC algorithm.
    pub shared_key_id: u16,
    /// HMAC Identifier - identifies the HMAC algorithm used.
    pub hmac_id: u16,
    /// HMAC value computed over the SCTP packet.
    pub hmac: Bytes,
}

impl AuthChunk {
    /// Creates a new AUTH chunk.
    #[must_use]
    pub fn new(shared_key_id: u16, hmac_id: HmacId, hmac: Bytes) -> Self {
        Self {
            shared_key_id,
            hmac_id: hmac_id as u16,
            hmac,
        }
    }

    /// Returns the HMAC identifier as an enum.
    #[must_use]
    pub fn hmac_algorithm(&self) -> Option<HmacId> {
        HmacId::from_u16(self.hmac_id)
    }

    fn encode(&self, buf: &mut BytesMut) {
        let length = CHUNK_HEADER_SIZE + 4 + self.hmac.len(); // header + key_id + hmac_id + hmac

        buf.put_u8(ChunkType::Auth as u8);
        buf.put_u8(0); // flags
        buf.put_u16(length as u16);
        buf.put_u16(self.shared_key_id);
        buf.put_u16(self.hmac_id);
        buf.put_slice(&self.hmac);

        // Add padding if needed for 4-byte alignment
        let pad = padding_needed(length);
        for _ in 0..pad {
            buf.put_u8(0);
        }
    }

    fn decode_body(_flags: u8, chunk_data: &Bytes) -> TransportResult<Self> {
        // Minimum: header (4) + shared_key_id (2) + hmac_id (2) = 8 bytes
        if chunk_data.len() < 8 {
            return Err(TransportError::ReceiveFailed {
                reason: "AUTH chunk too short".to_string(),
            });
        }

        let length = u16::from_be_bytes([chunk_data[2], chunk_data[3]]) as usize;
        let shared_key_id = u16::from_be_bytes([chunk_data[4], chunk_data[5]]);
        let hmac_id = u16::from_be_bytes([chunk_data[6], chunk_data[7]]);

        let hmac_len = length.saturating_sub(8);
        let hmac = if hmac_len > 0 && chunk_data.len() >= 8 + hmac_len {
            chunk_data.slice(8..8 + hmac_len)
        } else {
            Bytes::new()
        };

        Ok(Self {
            shared_key_id,
            hmac_id,
            hmac,
        })
    }
}

// =============================================================================
// Unknown Chunk
// =============================================================================

/// Unknown chunk type (preserved for error reporting).
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownChunk {
    /// Chunk type byte.
    pub chunk_type: u8,
    /// Chunk flags.
    pub flags: u8,
    /// Chunk data (excluding header).
    pub data: Bytes,
}

impl UnknownChunk {
    fn encode(&self, buf: &mut BytesMut) {
        let length = CHUNK_HEADER_SIZE + self.data.len();
        buf.put_u8(self.chunk_type);
        buf.put_u8(self.flags);
        buf.put_u16(length as u16);
        buf.put_slice(&self.data);

        let padding = padding_needed(length);
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Returns the padding needed to reach 4-byte alignment.
#[inline]
const fn padding_needed(length: usize) -> usize {
    (4 - (length % 4)) % 4
}

/// Returns the length padded to 4-byte alignment.
#[inline]
const fn padded_length(length: usize) -> usize {
    (length + 3) & !3
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_type_display() {
        assert_eq!(ChunkType::Data.to_string(), "DATA");
        assert_eq!(ChunkType::Init.to_string(), "INIT");
        assert_eq!(ChunkType::Sack.to_string(), "SACK");
    }

    #[test]
    fn test_chunk_type_from_u8() {
        assert_eq!(ChunkType::from_u8(0), Some(ChunkType::Data));
        assert_eq!(ChunkType::from_u8(1), Some(ChunkType::Init));
        assert_eq!(ChunkType::from_u8(255), None);
    }

    #[test]
    fn test_must_not_bundle() {
        assert!(ChunkType::Init.must_not_bundle());
        assert!(ChunkType::InitAck.must_not_bundle());
        assert!(ChunkType::ShutdownComplete.must_not_bundle());
        assert!(!ChunkType::Data.must_not_bundle());
        assert!(!ChunkType::Sack.must_not_bundle());
    }

    #[test]
    fn test_unknown_action() {
        // 00xxxxxx - stop and report
        assert_eq!(
            ChunkType::unknown_action(0x00),
            UnknownChunkAction::StopAndReport
        );
        // 01xxxxxx - stop silently
        assert_eq!(
            ChunkType::unknown_action(0x40),
            UnknownChunkAction::StopSilently
        );
        // 10xxxxxx - skip and report
        assert_eq!(
            ChunkType::unknown_action(0x80),
            UnknownChunkAction::SkipAndReport
        );
        // 11xxxxxx - skip silently
        assert_eq!(
            ChunkType::unknown_action(0xC0),
            UnknownChunkAction::SkipSilently
        );
    }

    #[test]
    fn test_data_chunk_roundtrip() {
        let data = DataChunk::new(12345, 0, 1, 0x03000000, Bytes::from("Hello, SCTP!"))
            .with_immediate(true)
            .with_unordered(false);

        let mut buf = BytesMut::new();
        data.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Data(d) = decoded {
            assert_eq!(d.tsn, 12345);
            assert_eq!(d.stream_id, 0);
            assert_eq!(d.ssn, 1);
            assert_eq!(d.ppid, 0x03000000);
            assert_eq!(d.data, Bytes::from("Hello, SCTP!"));
            assert!(d.immediate);
            assert!(!d.unordered);
            assert!(d.beginning);
            assert!(d.ending);
        } else {
            panic!("Expected DATA chunk");
        }
    }

    #[test]
    fn test_init_chunk_roundtrip() {
        let init = InitChunk::new(0xABCD1234, 65535, 10, 10, 1000)
            .with_ipv4_address(Ipv4Addr::new(192, 168, 1, 1));

        let mut buf = BytesMut::new();
        init.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Init(i) = decoded {
            assert_eq!(i.initiate_tag, 0xABCD1234);
            assert_eq!(i.a_rwnd, 65535);
            assert_eq!(i.num_outbound_streams, 10);
            assert_eq!(i.num_inbound_streams, 10);
            assert_eq!(i.initial_tsn, 1000);
            assert_eq!(i.params.len(), 1);
        } else {
            panic!("Expected INIT chunk");
        }
    }

    #[test]
    fn test_sack_chunk_roundtrip() {
        let mut sack = SackChunk::new(12345, 32768);
        sack.add_gap_block(2, 5);
        sack.add_gap_block(10, 15);
        sack.add_dup_tsn(12340);

        let mut buf = BytesMut::new();
        sack.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Sack(s) = decoded {
            assert_eq!(s.cumulative_tsn_ack, 12345);
            assert_eq!(s.a_rwnd, 32768);
            assert_eq!(s.gap_ack_blocks.len(), 2);
            assert_eq!(s.gap_ack_blocks[0].start, 2);
            assert_eq!(s.gap_ack_blocks[0].end, 5);
            assert_eq!(s.dup_tsns.len(), 1);
            assert_eq!(s.dup_tsns[0], 12340);
        } else {
            panic!("Expected SACK chunk");
        }
    }

    #[test]
    fn test_shutdown_chunk_roundtrip() {
        let shutdown = ShutdownChunk::new(54321);

        let mut buf = BytesMut::new();
        shutdown.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Shutdown(s) = decoded {
            assert_eq!(s.cumulative_tsn_ack, 54321);
        } else {
            panic!("Expected SHUTDOWN chunk");
        }
    }

    #[test]
    fn test_cookie_echo_roundtrip() {
        let cookie = CookieEchoChunk::new(Bytes::from("secret-cookie-data"));

        let mut buf = BytesMut::new();
        cookie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::CookieEcho(c) = decoded {
            assert_eq!(c.cookie, Bytes::from("secret-cookie-data"));
        } else {
            panic!("Expected COOKIE ECHO chunk");
        }
    }

    #[test]
    fn test_padding_needed() {
        assert_eq!(padding_needed(0), 0);
        assert_eq!(padding_needed(1), 3);
        assert_eq!(padding_needed(2), 2);
        assert_eq!(padding_needed(3), 1);
        assert_eq!(padding_needed(4), 0);
        assert_eq!(padding_needed(5), 3);
    }

    #[test]
    fn test_padded_length() {
        assert_eq!(padded_length(0), 0);
        assert_eq!(padded_length(1), 4);
        assert_eq!(padded_length(2), 4);
        assert_eq!(padded_length(3), 4);
        assert_eq!(padded_length(4), 4);
        assert_eq!(padded_length(5), 8);
    }

    #[test]
    fn test_ecne_chunk_creation() {
        let ecne = EcneChunk::new(12345);
        assert_eq!(ecne.lowest_tsn, 12345);
    }

    #[test]
    fn test_ecne_chunk_roundtrip() {
        let ecne = EcneChunk::new(0xDEADBEEF);

        let mut buf = BytesMut::new();
        ecne.encode(&mut buf);

        // Verify chunk header
        assert_eq!(buf[0], ChunkType::Ecne as u8); // Type = 12
        assert_eq!(buf[1], 0); // Flags = 0
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 8); // Length = 8

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Ecne(e) = decoded {
            assert_eq!(e.lowest_tsn, 0xDEADBEEF);
        } else {
            panic!("Expected ECNE chunk, got {:?}", decoded);
        }
    }

    #[test]
    fn test_cwr_chunk_creation() {
        let cwr = CwrChunk::new(54321);
        assert_eq!(cwr.lowest_tsn, 54321);
    }

    #[test]
    fn test_cwr_chunk_roundtrip() {
        let cwr = CwrChunk::new(0xCAFEBABE);

        let mut buf = BytesMut::new();
        cwr.encode(&mut buf);

        // Verify chunk header
        assert_eq!(buf[0], ChunkType::Cwr as u8); // Type = 13
        assert_eq!(buf[1], 0); // Flags = 0
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 8); // Length = 8

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Cwr(c) = decoded {
            assert_eq!(c.lowest_tsn, 0xCAFEBABE);
        } else {
            panic!("Expected CWR chunk, got {:?}", decoded);
        }
    }

    #[test]
    fn test_ecne_cwr_chunk_types() {
        let ecne = Chunk::Ecne(EcneChunk::new(100));
        let cwr = Chunk::Cwr(CwrChunk::new(200));

        assert_eq!(ecne.chunk_type(), ChunkType::Ecne);
        assert_eq!(cwr.chunk_type(), ChunkType::Cwr);
    }

    #[test]
    fn test_ecne_too_short() {
        // Create a buffer that's too short for ECNE
        let mut buf = BytesMut::new();
        buf.put_u8(ChunkType::Ecne as u8);
        buf.put_u8(0);
        buf.put_u16(4); // Length only 4 (just header, no TSN)

        let mut bytes = buf.freeze();
        let result = Chunk::decode(&mut bytes);

        assert!(result.is_err());
    }

    #[test]
    fn test_cwr_too_short() {
        // Create a buffer that's too short for CWR
        let mut buf = BytesMut::new();
        buf.put_u8(ChunkType::Cwr as u8);
        buf.put_u8(0);
        buf.put_u16(4); // Length only 4 (just header, no TSN)

        let mut bytes = buf.freeze();
        let result = Chunk::decode(&mut bytes);

        assert!(result.is_err());
    }

    #[test]
    fn test_asconf_chunk_creation() {
        let mut asconf =
            AsconfChunk::new(12345).with_sender_ipv4(std::net::Ipv4Addr::new(192, 168, 1, 1));

        asconf.add_ip(1, Some(std::net::Ipv4Addr::new(10, 0, 0, 1)), None);
        asconf.delete_ip(2, Some(std::net::Ipv4Addr::new(10, 0, 0, 2)), None);

        assert_eq!(asconf.serial_number, 12345);
        assert_eq!(
            asconf.sender_ipv4,
            Some(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(asconf.params.len(), 2);
    }

    #[test]
    fn test_asconf_chunk_roundtrip() {
        let mut asconf =
            AsconfChunk::new(999).with_sender_ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        asconf.add_ip(1, Some(std::net::Ipv4Addr::new(192, 168, 0, 1)), None);

        let mut buf = BytesMut::new();
        Chunk::Asconf(asconf.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Asconf(a) = decoded {
            assert_eq!(a.serial_number, 999);
            assert_eq!(a.sender_ipv4, Some(std::net::Ipv4Addr::new(127, 0, 0, 1)));
            assert_eq!(a.params.len(), 1);
        } else {
            panic!("Expected ASCONF chunk");
        }
    }

    #[test]
    fn test_asconf_ack_chunk_creation() {
        let mut ack = AsconfAckChunk::new(12345);
        ack.add_success(1);
        ack.add_success(2);
        ack.add_error(3, 1, Bytes::from("test error"));

        assert_eq!(ack.serial_number, 12345);
        assert_eq!(ack.params.len(), 3);
        assert!(!ack.all_success());
    }

    #[test]
    fn test_asconf_ack_chunk_all_success() {
        let mut ack = AsconfAckChunk::new(100);
        ack.add_success(1);
        ack.add_success(2);

        assert!(ack.all_success());
    }

    #[test]
    fn test_asconf_ack_chunk_roundtrip() {
        let mut ack = AsconfAckChunk::new(555);
        ack.add_success(1);
        ack.add_success(2);

        let mut buf = BytesMut::new();
        Chunk::AsconfAck(ack.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::AsconfAck(a) = decoded {
            assert_eq!(a.serial_number, 555);
            assert_eq!(a.params.len(), 2);
            assert!(a.all_success());
        } else {
            panic!("Expected ASCONF-ACK chunk");
        }
    }

    #[test]
    fn test_asconf_param_correlation_id() {
        let param = AsconfParam::AddIp {
            correlation_id: 42,
            ipv4: Some(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            ipv6: None,
        };
        assert_eq!(param.correlation_id(), 42);

        let param = AsconfParam::DeleteIp {
            correlation_id: 99,
            ipv4: None,
            ipv6: Some(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        };
        assert_eq!(param.correlation_id(), 99);
    }

    #[test]
    fn test_chunk_type_asconf() {
        assert_eq!(ChunkType::from_u8(0xC1), Some(ChunkType::Asconf));
        assert_eq!(ChunkType::from_u8(0x80), Some(ChunkType::AsconfAck));
        assert_eq!(ChunkType::Asconf.to_string(), "ASCONF");
        assert_eq!(ChunkType::AsconfAck.to_string(), "ASCONF-ACK");
    }

    #[test]
    fn test_forward_tsn_chunk_creation() {
        let ftsn = ForwardTsnChunk::new(12345);
        assert_eq!(ftsn.new_cumulative_tsn, 12345);
        assert!(ftsn.streams.is_empty());
    }

    #[test]
    fn test_forward_tsn_chunk_with_streams() {
        let streams = vec![
            ForwardTsnStream::new(0, 10),
            ForwardTsnStream::new(1, 20),
            ForwardTsnStream::new(2, 30),
        ];
        let ftsn = ForwardTsnChunk::with_streams(1000, streams);

        assert_eq!(ftsn.new_cumulative_tsn, 1000);
        assert_eq!(ftsn.streams.len(), 3);
        assert_eq!(ftsn.streams[0].stream_id, 0);
        assert_eq!(ftsn.streams[0].ssn, 10);
        assert_eq!(ftsn.streams[1].stream_id, 1);
        assert_eq!(ftsn.streams[1].ssn, 20);
    }

    #[test]
    fn test_forward_tsn_chunk_add_stream() {
        let mut ftsn = ForwardTsnChunk::new(5000);
        ftsn.add_stream(0, 100);
        ftsn.add_stream(3, 50);

        assert_eq!(ftsn.streams.len(), 2);
        assert_eq!(ftsn.streams[0].stream_id, 0);
        assert_eq!(ftsn.streams[0].ssn, 100);
        assert_eq!(ftsn.streams[1].stream_id, 3);
        assert_eq!(ftsn.streams[1].ssn, 50);
    }

    #[test]
    fn test_forward_tsn_chunk_roundtrip() {
        let mut ftsn = ForwardTsnChunk::new(99999);
        ftsn.add_stream(0, 5);
        ftsn.add_stream(1, 10);
        ftsn.add_stream(2, 15);

        let mut buf = BytesMut::new();
        Chunk::ForwardTsn(ftsn.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::ForwardTsn(f) = decoded {
            assert_eq!(f.new_cumulative_tsn, 99999);
            assert_eq!(f.streams.len(), 3);
            assert_eq!(f.streams[0].stream_id, 0);
            assert_eq!(f.streams[0].ssn, 5);
            assert_eq!(f.streams[1].stream_id, 1);
            assert_eq!(f.streams[1].ssn, 10);
            assert_eq!(f.streams[2].stream_id, 2);
            assert_eq!(f.streams[2].ssn, 15);
        } else {
            panic!("Expected FORWARD-TSN chunk");
        }
    }

    #[test]
    fn test_forward_tsn_chunk_roundtrip_no_streams() {
        let ftsn = ForwardTsnChunk::new(50000);

        let mut buf = BytesMut::new();
        Chunk::ForwardTsn(ftsn.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::ForwardTsn(f) = decoded {
            assert_eq!(f.new_cumulative_tsn, 50000);
            assert!(f.streams.is_empty());
        } else {
            panic!("Expected FORWARD-TSN chunk");
        }
    }

    #[test]
    fn test_chunk_type_forward_tsn() {
        assert_eq!(ChunkType::from_u8(0xC0), Some(ChunkType::ForwardTsn));
        assert_eq!(ChunkType::ForwardTsn.to_string(), "FORWARD-TSN");
    }

    #[test]
    fn test_reconfig_chunk_creation() {
        let chunk = ReConfigChunk::new();
        assert!(chunk.params.is_empty());
    }

    #[test]
    fn test_reconfig_outgoing_ssn_reset() {
        let chunk = ReConfigChunk::outgoing_ssn_reset(100, 99, 5000, vec![0, 1, 2]);

        assert_eq!(chunk.params.len(), 1);
        if let ReConfigParam::OutgoingSsnReset {
            req_seq_num,
            resp_seq_num,
            last_tsn,
            stream_ids,
        } = &chunk.params[0]
        {
            assert_eq!(*req_seq_num, 100);
            assert_eq!(*resp_seq_num, 99);
            assert_eq!(*last_tsn, 5000);
            assert_eq!(*stream_ids, vec![0, 1, 2]);
        } else {
            panic!("Expected OutgoingSsnReset");
        }
    }

    #[test]
    fn test_reconfig_incoming_ssn_reset() {
        let chunk = ReConfigChunk::incoming_ssn_reset(200, vec![5, 10]);

        assert_eq!(chunk.params.len(), 1);
        if let ReConfigParam::IncomingSsnReset {
            req_seq_num,
            stream_ids,
        } = &chunk.params[0]
        {
            assert_eq!(*req_seq_num, 200);
            assert_eq!(*stream_ids, vec![5, 10]);
        } else {
            panic!("Expected IncomingSsnReset");
        }
    }

    #[test]
    fn test_reconfig_response() {
        let chunk = ReConfigChunk::response(100, ReConfigResult::SuccessPerformed);

        assert_eq!(chunk.params.len(), 1);
        if let ReConfigParam::Response {
            resp_seq_num,
            result,
            sender_next_tsn,
            receiver_next_tsn,
        } = &chunk.params[0]
        {
            assert_eq!(*resp_seq_num, 100);
            assert_eq!(*result, ReConfigResult::SuccessPerformed);
            assert!(sender_next_tsn.is_none());
            assert!(receiver_next_tsn.is_none());
        } else {
            panic!("Expected Response");
        }
    }

    #[test]
    fn test_reconfig_result_is_success() {
        assert!(ReConfigResult::SuccessNothingToDo.is_success());
        assert!(ReConfigResult::SuccessPerformed.is_success());
        assert!(!ReConfigResult::Denied.is_success());
        assert!(!ReConfigResult::InProgress.is_success());
    }

    #[test]
    fn test_reconfig_outgoing_ssn_reset_roundtrip() {
        let chunk = ReConfigChunk::outgoing_ssn_reset(1000, 999, 50000, vec![0, 1, 2, 3]);

        let mut buf = BytesMut::new();
        Chunk::ReConfig(chunk.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::ReConfig(rc) = decoded {
            assert_eq!(rc.params.len(), 1);
            if let ReConfigParam::OutgoingSsnReset {
                req_seq_num,
                resp_seq_num,
                last_tsn,
                stream_ids,
            } = &rc.params[0]
            {
                assert_eq!(*req_seq_num, 1000);
                assert_eq!(*resp_seq_num, 999);
                assert_eq!(*last_tsn, 50000);
                assert_eq!(*stream_ids, vec![0, 1, 2, 3]);
            } else {
                panic!("Expected OutgoingSsnReset");
            }
        } else {
            panic!("Expected ReConfig chunk");
        }
    }

    #[test]
    fn test_reconfig_response_roundtrip() {
        let chunk = ReConfigChunk::response(555, ReConfigResult::Denied);

        let mut buf = BytesMut::new();
        Chunk::ReConfig(chunk.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::ReConfig(rc) = decoded {
            assert_eq!(rc.params.len(), 1);
            if let ReConfigParam::Response {
                resp_seq_num,
                result,
                ..
            } = &rc.params[0]
            {
                assert_eq!(*resp_seq_num, 555);
                assert_eq!(*result, ReConfigResult::Denied);
            } else {
                panic!("Expected Response");
            }
        } else {
            panic!("Expected ReConfig chunk");
        }
    }

    #[test]
    fn test_chunk_type_reconfig() {
        assert_eq!(ChunkType::from_u8(130), Some(ChunkType::ReConfig));
        assert_eq!(ChunkType::ReConfig.to_string(), "RE-CONFIG");
    }

    #[test]
    fn test_pad_chunk_creation() {
        let pad = PadChunk::new(100);
        assert_eq!(pad.padding.len(), 100);
        assert!(pad.padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_pad_chunk_from_bytes() {
        let data = Bytes::from(vec![1, 2, 3, 4, 5]);
        let pad = PadChunk::from_bytes(data.clone());
        assert_eq!(pad.padding, data);
    }

    #[test]
    fn test_pad_chunk_size() {
        let pad = PadChunk::new(100);
        assert_eq!(pad.chunk_size(), CHUNK_HEADER_SIZE + 100);
    }

    #[test]
    fn test_pad_chunk_roundtrip() {
        let pad = PadChunk::new(50);

        let mut buf = BytesMut::new();
        Chunk::Pad(pad.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Pad(p) = decoded {
            assert_eq!(p.padding.len(), 50);
        } else {
            panic!("Expected PAD chunk");
        }
    }

    #[test]
    fn test_pad_chunk_roundtrip_unaligned() {
        // Test with size that requires padding for 4-byte alignment
        let pad = PadChunk::new(17);

        let mut buf = BytesMut::new();
        Chunk::Pad(pad.clone()).encode(&mut buf);

        // Should be padded to 4-byte boundary
        assert_eq!(buf.len() % 4, 0);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Pad(p) = decoded {
            assert_eq!(p.padding.len(), 17);
        } else {
            panic!("Expected PAD chunk");
        }
    }

    #[test]
    fn test_chunk_type_pad() {
        assert_eq!(ChunkType::from_u8(0x84), Some(ChunkType::Pad));
        assert_eq!(ChunkType::Pad.to_string(), "PAD");
    }

    #[test]
    fn test_auth_chunk_creation() {
        let hmac = Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let auth = AuthChunk::new(1, HmacId::Sha256, hmac.clone());

        assert_eq!(auth.shared_key_id, 1);
        assert_eq!(auth.hmac_id, HmacId::Sha256 as u16);
        assert_eq!(auth.hmac, hmac);
    }

    #[test]
    fn test_auth_chunk_hmac_algorithm() {
        let auth = AuthChunk::new(1, HmacId::Sha1, Bytes::new());
        assert_eq!(auth.hmac_algorithm(), Some(HmacId::Sha1));

        let auth = AuthChunk::new(2, HmacId::Sha256, Bytes::new());
        assert_eq!(auth.hmac_algorithm(), Some(HmacId::Sha256));
    }

    #[test]
    fn test_auth_chunk_roundtrip() {
        let hmac = Bytes::from(vec![0xaa; 32]); // SHA-256 HMAC length
        let auth = AuthChunk::new(42, HmacId::Sha256, hmac.clone());

        let mut buf = BytesMut::new();
        Chunk::Auth(auth.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Auth(a) = decoded {
            assert_eq!(a.shared_key_id, 42);
            assert_eq!(a.hmac_id, HmacId::Sha256 as u16);
            assert_eq!(a.hmac, hmac);
        } else {
            panic!("Expected AUTH chunk");
        }
    }

    #[test]
    fn test_auth_chunk_roundtrip_sha1() {
        let hmac = Bytes::from(vec![0xbb; 20]); // SHA-1 HMAC length
        let auth = AuthChunk::new(100, HmacId::Sha1, hmac.clone());

        let mut buf = BytesMut::new();
        Chunk::Auth(auth.clone()).encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Chunk::decode(&mut bytes).unwrap();

        if let Chunk::Auth(a) = decoded {
            assert_eq!(a.shared_key_id, 100);
            assert_eq!(a.hmac_id, HmacId::Sha1 as u16);
            assert_eq!(a.hmac, hmac);
        } else {
            panic!("Expected AUTH chunk");
        }
    }

    #[test]
    fn test_hmac_id_from_u16() {
        assert_eq!(HmacId::from_u16(0), Some(HmacId::Reserved));
        assert_eq!(HmacId::from_u16(1), Some(HmacId::Sha1));
        assert_eq!(HmacId::from_u16(3), Some(HmacId::Sha256));
        assert_eq!(HmacId::from_u16(2), None); // Not defined
        assert_eq!(HmacId::from_u16(255), None);
    }

    #[test]
    fn test_hmac_id_length() {
        assert_eq!(HmacId::Reserved.hmac_length(), 0);
        assert_eq!(HmacId::Sha1.hmac_length(), 20);
        assert_eq!(HmacId::Sha256.hmac_length(), 32);
    }

    #[test]
    fn test_chunk_type_auth() {
        assert_eq!(ChunkType::from_u8(15), Some(ChunkType::Auth));
        assert_eq!(ChunkType::Auth.to_string(), "AUTH");
    }
}
