//! UDPTL (UDP Transport Layer) for T.38.
//!
//! Provides a UDPTL-style transport with redundancy or FEC.
//!
//! **Not interoperable** (POA&M-204): the wire format is project-specific and
//! is NOT the ITU-T T.38 §9 / Annex UDPTL ASN.1 PER encoding.

use crate::config::{ErrorCorrectionMode, UdptlConfig};
use crate::error::{T38Error, T38Result};
use crate::ifp::IfpPacket;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Maximum UDPTL packet size.
pub const MAX_UDPTL_SIZE: usize = 512;

/// UDPTL packet with error correction.
#[derive(Debug, Clone)]
pub struct UdptlPacket {
    /// Sequence number.
    pub seq_num: u16,
    /// Primary IFP packet.
    pub primary: IfpPacket,
    /// Error correction data.
    pub error_correction: ErrorCorrectionData,
}

/// Error correction data for UDPTL.
#[derive(Debug, Clone)]
pub enum ErrorCorrectionData {
    /// No error correction.
    None,
    /// Redundancy: previous IFP packets.
    Redundancy(Vec<Bytes>),
    /// Forward Error Correction.
    Fec {
        /// Span (number of packets covered).
        span: u8,
        /// FEC data entries.
        entries: Vec<Bytes>,
    },
}

impl UdptlPacket {
    /// Creates a new UDPTL packet with redundancy.
    #[must_use]
    pub fn with_redundancy(seq_num: u16, primary: IfpPacket, redundant: Vec<Bytes>) -> Self {
        Self {
            seq_num,
            primary,
            error_correction: ErrorCorrectionData::Redundancy(redundant),
        }
    }

    /// Creates a new UDPTL packet without error correction.
    #[must_use]
    pub fn new(seq_num: u16, primary: IfpPacket) -> Self {
        Self {
            seq_num,
            primary,
            error_correction: ErrorCorrectionData::None,
        }
    }

    /// Encodes the UDPTL packet to bytes.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Lengths are bounded by protocol limits
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(MAX_UDPTL_SIZE);

        // Sequence number (16 bits)
        buf.put_u16(self.seq_num);

        // Primary IFP packet
        let ifp_data = self.primary.encode();
        buf.put_u16(ifp_data.len() as u16);
        buf.put_slice(&ifp_data);

        // Error correction
        match &self.error_correction {
            ErrorCorrectionData::None => {
                buf.put_u8(0); // Type: none
            }
            ErrorCorrectionData::Redundancy(packets) => {
                buf.put_u8(1); // Type: redundancy
                buf.put_u8(packets.len() as u8);
                for packet in packets {
                    buf.put_u16(packet.len() as u16);
                    buf.put_slice(packet);
                }
            }
            ErrorCorrectionData::Fec { span, entries } => {
                buf.put_u8(2); // Type: FEC
                buf.put_u8(*span);
                buf.put_u8(entries.len() as u8);
                for entry in entries {
                    buf.put_u16(entry.len() as u16);
                    buf.put_slice(entry);
                }
            }
        }

        buf.freeze()
    }

    /// Decodes a UDPTL packet from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn decode(mut data: Bytes) -> T38Result<Self> {
        // NIST 800-53 Rev5: SI-10, SC-5 -- POA&M-202 fixed: every read below is bounds-checked; truncated or
        // malformed datagrams are rejected, never a panic.
        // NIST 800-53 Rev5: SI-10 (input validation), SC-5 (DoS protection)
        if data.len() < 4 {
            return Err(invalid_udptl("packet too short"));
        }

        let seq_num = data.get_u16();

        // Primary IFP packet
        let ifp_len = data.get_u16() as usize;
        if data.len() < ifp_len {
            return Err(invalid_udptl("IFP length exceeds packet"));
        }
        let ifp_data = data.split_to(ifp_len);
        let primary = IfpPacket::decode(ifp_data)?;

        // Error correction (optional)
        let error_correction = if data.is_empty() {
            ErrorCorrectionData::None
        } else {
            let ec_type = data.get_u8();
            match ec_type {
                0 => ErrorCorrectionData::None,
                1 => {
                    // Redundancy
                    if data.is_empty() {
                        return Err(invalid_udptl("missing redundancy count"));
                    }
                    let count = data.get_u8() as usize;
                    ErrorCorrectionData::Redundancy(decode_entries(&mut data, count)?)
                }
                2 => {
                    // FEC
                    if data.len() < 2 {
                        return Err(invalid_udptl("missing FEC span/count"));
                    }
                    let span = data.get_u8();
                    let count = data.get_u8() as usize;
                    let entries = decode_entries(&mut data, count)?;
                    ErrorCorrectionData::Fec { span, entries }
                }
                _ => return Err(invalid_udptl("unknown error correction type")),
            }
        };

        Ok(Self {
            seq_num,
            primary,
            error_correction,
        })
    }
}

/// Builds an [`T38Error::InvalidUdptlPacket`] error.
fn invalid_udptl(reason: &str) -> T38Error {
    T38Error::InvalidUdptlPacket {
        reason: reason.to_string(),
    }
}

/// Decodes `count` length-prefixed (u16) entries, rejecting truncation.
///
/// The preallocation is capped by the bytes actually present (each entry
/// needs at least its 2-byte length) so an attacker-supplied `count` cannot
/// amplify allocation.
// NIST 800-53 Rev5: SC-5 (DoS protection), SI-10 (input validation)
fn decode_entries(data: &mut Bytes, count: usize) -> T38Result<Vec<Bytes>> {
    let mut entries = Vec::with_capacity(count.min(data.len() / 2));
    for _ in 0..count {
        if data.len() < 2 {
            return Err(invalid_udptl("truncated error correction entry length"));
        }
        let len = data.get_u16() as usize;
        if data.len() < len {
            return Err(invalid_udptl("error correction entry exceeds packet"));
        }
        entries.push(data.split_to(len));
    }
    Ok(entries)
}

/// UDPTL transport for T.38 sessions.
pub struct UdptlTransport {
    /// UDP socket.
    socket: Arc<UdpSocket>,
    /// Remote address.
    remote_addr: SocketAddr,
    /// Configuration (reserved for future use).
    #[allow(dead_code)]
    config: UdptlConfig,
    /// Error correction mode.
    ec_mode: ErrorCorrectionMode,
    /// Redundancy count.
    redundancy_count: u8,
    /// Sent packets history for redundancy.
    sent_history: Mutex<VecDeque<Bytes>>,
    /// Current sequence number.
    seq_num: Mutex<u16>,
    /// Received sequence numbers for reordering.
    received_seqs: Mutex<VecDeque<u16>>,
}

impl UdptlTransport {
    /// Creates a new UDPTL transport.
    ///
    /// # Errors
    ///
    /// Returns an error if socket binding fails.
    pub async fn bind(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: UdptlConfig,
        ec_mode: ErrorCorrectionMode,
        redundancy_count: u8,
    ) -> T38Result<Self> {
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| T38Error::TransportError {
                reason: format!("bind failed: {e}"),
            })?;

        socket
            .connect(remote_addr)
            .await
            .map_err(|e| T38Error::TransportError {
                reason: format!("connect failed: {e}"),
            })?;

        debug!(local = %local_addr, remote = %remote_addr, "UDPTL transport created");

        Ok(Self {
            socket: Arc::new(socket),
            remote_addr,
            config,
            ec_mode,
            redundancy_count,
            sent_history: Mutex::new(VecDeque::with_capacity(16)),
            seq_num: Mutex::new(0),
            received_seqs: Mutex::new(VecDeque::with_capacity(64)),
        })
    }

    /// Sends an IFP packet.
    ///
    /// # Errors
    ///
    /// Returns an error if sending fails.
    pub async fn send(&self, ifp: IfpPacket) -> T38Result<()> {
        let mut seq = self.seq_num.lock().await;
        let current_seq = *seq;
        *seq = seq.wrapping_add(1);
        drop(seq);

        // Build redundancy data
        let mut redundant = Vec::new();
        if self.ec_mode == ErrorCorrectionMode::Redundancy {
            let history = self.sent_history.lock().await;
            for packet in history.iter().rev().take(self.redundancy_count as usize) {
                redundant.push(packet.clone());
            }
        }

        // Create UDPTL packet
        let packet = if redundant.is_empty() {
            UdptlPacket::new(current_seq, ifp.clone())
        } else {
            UdptlPacket::with_redundancy(current_seq, ifp.clone(), redundant)
        };

        let data = packet.encode();

        // Store in history
        {
            let mut history = self.sent_history.lock().await;
            history.push_back(ifp.encode());
            while history.len() > 16 {
                history.pop_front();
            }
            drop(history);
        }

        // Send
        self.socket
            .send(&data)
            .await
            .map_err(|e| T38Error::TransportError {
                reason: format!("send failed: {e}"),
            })?;

        debug!(seq = current_seq, len = data.len(), "Sent UDPTL packet");

        Ok(())
    }

    /// Receives a UDPTL packet.
    ///
    /// # Errors
    ///
    /// Returns an error if receiving fails.
    pub async fn recv(&self) -> T38Result<IfpPacket> {
        let mut buf = vec![0u8; MAX_UDPTL_SIZE];

        let len = self
            .socket
            .recv(&mut buf)
            .await
            .map_err(|e| T38Error::TransportError {
                reason: format!("recv failed: {e}"),
            })?;

        let data = Bytes::copy_from_slice(&buf[..len]);
        let packet = UdptlPacket::decode(data)?;

        // Track sequence for reordering detection
        {
            let mut seqs = self.received_seqs.lock().await;
            seqs.push_back(packet.seq_num);
            while seqs.len() > 64 {
                seqs.pop_front();
            }
            drop(seqs);
        }

        debug!(seq = packet.seq_num, "Received UDPTL packet");

        Ok(packet.primary)
    }

    /// Returns the local address.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }

    /// Returns the remote address.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Attempts to recover a lost packet using redundancy data.
    pub fn recover_packet(
        &self,
        target_seq: u16,
        error_correction: &ErrorCorrectionData,
    ) -> Option<IfpPacket> {
        match error_correction {
            ErrorCorrectionData::Redundancy(packets) => {
                // Redundant packets are in reverse order (most recent first)
                for (i, data) in packets.iter().enumerate() {
                    // Calculate the sequence number this redundant packet represents
                    #[allow(clippy::cast_possible_truncation)]
                    let redundant_seq = target_seq.wrapping_sub(i as u16 + 1);
                    if redundant_seq == target_seq
                        && let Ok(ifp) = IfpPacket::decode(data.clone())
                    {
                        debug!(seq = target_seq, "Recovered packet from redundancy");
                        return Some(ifp);
                    }
                }
                None
            }
            ErrorCorrectionData::Fec {
                span: _,
                entries: _,
            } => {
                // FEC recovery would require XOR operations across span
                warn!("FEC recovery not yet implemented");
                None
            }
            ErrorCorrectionData::None => None,
        }
    }
}

impl std::fmt::Debug for UdptlTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdptlTransport")
            .field("remote_addr", &self.remote_addr)
            .field("ec_mode", &self.ec_mode)
            .field("redundancy_count", &self.redundancy_count)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ifp::DataType;

    #[test]
    fn test_udptl_packet_encode_decode() {
        let ifp = IfpPacket::new(1, DataType::V21, vec![0x01, 0x02]);
        let packet = UdptlPacket::new(42, ifp);

        let encoded = packet.encode();
        let decoded = UdptlPacket::decode(encoded).expect("decode failed");

        assert_eq!(decoded.seq_num, 42);
        assert_eq!(decoded.primary.data_type, DataType::V21);
    }

    #[test]
    fn test_udptl_packet_with_redundancy() {
        let ifp = IfpPacket::new(3, DataType::V21, vec![0x03]);
        let redundant = vec![Bytes::from_static(&[0x01]), Bytes::from_static(&[0x02])];
        let packet = UdptlPacket::with_redundancy(3, ifp, redundant);

        let encoded = packet.encode();
        let decoded = UdptlPacket::decode(encoded).expect("decode failed");

        assert_eq!(decoded.seq_num, 3);
        if let ErrorCorrectionData::Redundancy(packets) = &decoded.error_correction {
            assert_eq!(packets.len(), 2);
        } else {
            panic!("expected redundancy data");
        }
    }

    /// Decodes every strict prefix of `full`; must never panic and must
    /// reject every prefix except the one ending exactly after the primary
    /// IFP (which is a valid packet without error correction).
    fn assert_truncations_rejected(full: &Bytes, primary_end: usize) {
        for n in 0..full.len() {
            let result = UdptlPacket::decode(full.slice(..n));
            if n == primary_end {
                assert!(result.is_ok(), "prefix {n} is a valid no-EC packet");
            } else {
                assert!(result.is_err(), "prefix {n} of {} accepted", full.len());
            }
        }
    }

    // NIST 800-53 Rev5: SI-10 -- POA&M-202: truncated datagrams are rejected, never panic.
    #[test]
    fn test_decode_truncated_redundancy() {
        let primary = IfpPacket::new(7, DataType::V21, vec![1, 2, 3]);
        let primary_end = 4 + primary.encode().len();
        let packet = UdptlPacket::with_redundancy(
            7,
            primary,
            vec![Bytes::from_static(&[9, 9]), Bytes::from_static(&[8, 8, 8])],
        );
        let full = packet.encode();
        assert!(UdptlPacket::decode(full.clone()).is_ok());
        assert_truncations_rejected(&full, primary_end);
    }

    #[test]
    fn test_decode_truncated_fec() {
        let primary = IfpPacket::new(3, DataType::V21, vec![4, 5]);
        let primary_end = 4 + primary.encode().len();
        let packet = UdptlPacket {
            seq_num: 3,
            primary,
            error_correction: ErrorCorrectionData::Fec {
                span: 3,
                entries: vec![Bytes::from_static(&[1, 2, 3]), Bytes::from_static(&[4])],
            },
        };
        let full = packet.encode();
        assert!(UdptlPacket::decode(full.clone()).is_ok());
        assert_truncations_rejected(&full, primary_end);
    }

    #[test]
    fn test_decode_rejects_bad_ec() {
        let primary = IfpPacket::new(1, DataType::V21, vec![1]).encode();
        let mut buf = BytesMut::new();
        buf.put_u16(1);
        buf.put_u16(u16::try_from(primary.len()).unwrap());
        buf.put_slice(&primary);
        // Unknown EC type.
        let mut unknown = buf.clone();
        unknown.put_u8(9);
        assert!(UdptlPacket::decode(unknown.freeze()).is_err());
        // Redundancy claiming 255 entries with none present.
        let mut huge = buf;
        huge.put_u8(1);
        huge.put_u8(255);
        assert!(UdptlPacket::decode(huge.freeze()).is_err());
    }
}
