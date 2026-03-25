//! UDPTL (UDP Transport Layer) for T.38.
//!
//! Implements the UDPTL transport protocol per ITU-T T.38 Annex D,
//! providing reliability through redundancy or FEC.

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
        if data.len() < 4 {
            return Err(T38Error::InvalidUdptlPacket {
                reason: "packet too short".to_string(),
            });
        }

        let seq_num = data.get_u16();

        // Primary IFP packet
        let ifp_len = data.get_u16() as usize;
        if data.len() < ifp_len {
            return Err(T38Error::InvalidUdptlPacket {
                reason: "IFP length exceeds packet".to_string(),
            });
        }
        let ifp_data = data.split_to(ifp_len);
        let primary = IfpPacket::decode(ifp_data)?;

        // Error correction (optional)
        let error_correction = if data.is_empty() {
            ErrorCorrectionData::None
        } else {
            let ec_type = data.get_u8();
            match ec_type {
                1 => {
                    // Redundancy
                    let count = data.get_u8() as usize;
                    let mut packets = Vec::with_capacity(count);
                    for _ in 0..count {
                        if data.len() < 2 {
                            break;
                        }
                        let len = data.get_u16() as usize;
                        if data.len() < len {
                            break;
                        }
                        packets.push(data.split_to(len));
                    }
                    ErrorCorrectionData::Redundancy(packets)
                }
                2 => {
                    // FEC
                    let span = data.get_u8();
                    let count = data.get_u8() as usize;
                    let mut entries = Vec::with_capacity(count);
                    for _ in 0..count {
                        if data.len() < 2 {
                            break;
                        }
                        let len = data.get_u16() as usize;
                        if data.len() < len {
                            break;
                        }
                        entries.push(data.split_to(len));
                    }
                    ErrorCorrectionData::Fec { span, entries }
                }
                _ => ErrorCorrectionData::None,
            }
        };

        Ok(Self {
            seq_num,
            primary,
            error_correction,
        })
    }
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
}
