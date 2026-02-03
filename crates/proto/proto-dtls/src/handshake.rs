//! DTLS handshake implementation.
//!
//! Implements the DTLS 1.2 handshake per RFC 6347 with CNSA 2.0 compliance.
//!
//! ## Supported Cipher Suite
//!
//! `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C)
//! - ECDHE with P-384 for key exchange
//! - ECDSA with P-384 for authentication
//! - AES-256-GCM for encryption
//! - SHA-384 for PRF
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-12**: Cryptographic Key Establishment
//! - **SC-13**: Cryptographic Protection

use crate::error::{DtlsError, DtlsResult};
use crate::record::{ContentType, DTLS_1_2_VERSION, RECORD_HEADER_LEN, RecordLayer};
use crate::verify::{
    CertificateValidationResult, CertificateValidator, FinishedVerifier, ServerKeyExchangeVerifier,
};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use tracing::debug;
use uc_crypto::aead::Aes256GcmKey;
use uc_crypto::ecdh::P384EphemeralKeyPair;
use uc_crypto::hkdf;

/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` cipher suite ID.
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xC02C;

/// DTLS handshake message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// Client hello.
    ClientHello = 1,
    /// Server hello.
    ServerHello = 2,
    /// Hello verify request (DTLS).
    HelloVerifyRequest = 3,
    /// Certificate.
    Certificate = 11,
    /// Server key exchange.
    ServerKeyExchange = 12,
    /// Certificate request.
    CertificateRequest = 13,
    /// Server hello done.
    ServerHelloDone = 14,
    /// Certificate verify.
    CertificateVerify = 15,
    /// Client key exchange.
    ClientKeyExchange = 16,
    /// Finished.
    Finished = 20,
}

impl TryFrom<u8> for HandshakeType {
    type Error = DtlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::HelloVerifyRequest),
            11 => Ok(Self::Certificate),
            12 => Ok(Self::ServerKeyExchange),
            13 => Ok(Self::CertificateRequest),
            14 => Ok(Self::ServerHelloDone),
            15 => Ok(Self::CertificateVerify),
            16 => Ok(Self::ClientKeyExchange),
            20 => Ok(Self::Finished),
            _ => Err(DtlsError::HandshakeFailed {
                reason: format!("unknown handshake type: {value}"),
            }),
        }
    }
}

/// DTLS handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state.
    Start,
    /// Waiting for `ClientHello`.
    WaitClientHello,
    /// Waiting for `HelloVerifyRequest`.
    WaitHelloVerifyRequest,
    /// Waiting for `ServerHello`.
    WaitServerHello,
    /// Waiting for Certificate.
    WaitCertificate,
    /// Waiting for `ServerKeyExchange`.
    WaitServerKeyExchange,
    /// Waiting for `ServerHelloDone`.
    WaitServerHelloDone,
    /// Waiting for `ClientKeyExchange`.
    WaitClientKeyExchange,
    /// Waiting for `CertificateVerify`.
    WaitCertificateVerify,
    /// Waiting for `ChangeCipherSpec`.
    WaitChangeCipherSpec,
    /// Waiting for Finished.
    WaitFinished,
    /// Handshake complete.
    Complete,
    /// Handshake failed.
    Failed,
}

/// Handshake message header.
#[derive(Debug, Clone)]
pub struct HandshakeHeader {
    /// Message type.
    pub msg_type: HandshakeType,
    /// Total length of the message.
    pub length: u32,
    /// Message sequence number.
    pub message_seq: u16,
    /// Fragment offset.
    pub fragment_offset: u32,
    /// Fragment length.
    pub fragment_length: u32,
}

impl HandshakeHeader {
    /// Header size in bytes.
    pub const SIZE: usize = 12;

    /// Parses a handshake header.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> DtlsResult<Self> {
        if data.len() < Self::SIZE {
            return Err(DtlsError::HandshakeFailed {
                reason: "handshake header too short".to_string(),
            });
        }

        let msg_type = HandshakeType::try_from(data[0])?;
        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let message_seq = u16::from_be_bytes([data[4], data[5]]);
        let fragment_offset = u32::from_be_bytes([0, data[6], data[7], data[8]]);
        let fragment_length = u32::from_be_bytes([0, data[9], data[10], data[11]]);

        Ok(Self {
            msg_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
        })
    }

    /// Serializes the header.
    #[must_use] 
    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.msg_type as u8;
        let len_bytes = self.length.to_be_bytes();
        buf[1..4].copy_from_slice(&len_bytes[1..4]);
        buf[4..6].copy_from_slice(&self.message_seq.to_be_bytes());
        let frag_off_bytes = self.fragment_offset.to_be_bytes();
        buf[6..9].copy_from_slice(&frag_off_bytes[1..4]);
        let frag_len_bytes = self.fragment_length.to_be_bytes();
        buf[9..12].copy_from_slice(&frag_len_bytes[1..4]);
        buf
    }
}

/// DTLS handshake context.
pub struct Handshake {
    /// Whether we are the client.
    is_client: bool,
    /// Current state.
    state: HandshakeState,
    /// Record layer.
    record_layer: RecordLayer,
    /// Local ECDHE key pair (consumed on key agreement).
    local_ecdhe: Option<P384EphemeralKeyPair>,
    /// Local ECDHE public key bytes (stored separately since key is ephemeral).
    local_ecdhe_public: Option<Vec<u8>>,
    /// Peer's ECDHE public key.
    peer_ecdhe_public: Option<Vec<u8>>,
    /// Pre-master secret.
    premaster_secret: Option<Vec<u8>>,
    /// Client random.
    client_random: [u8; 32],
    /// Server random.
    server_random: [u8; 32],
    /// Master secret.
    master_secret: Option<[u8; 48]>,
    /// Handshake message sequence.
    message_seq: u16,
    /// Local certificate chain.
    local_cert_chain: Vec<Vec<u8>>,
    /// Local private key (for signing).
    local_private_key: Vec<u8>,
    /// Handshake hash (for Finished message).
    handshake_hash: Vec<u8>,
    /// Cookie from `HelloVerifyRequest`.
    cookie: Vec<u8>,
    /// Peer certificate chain (received during handshake).
    peer_cert_chain: Vec<Vec<u8>>,
    /// Peer's public key extracted from certificate.
    peer_public_key: Option<Vec<u8>>,
    /// ECDH params (for signature verification).
    ecdh_params: Option<Vec<u8>>,
    /// Expected certificate fingerprint (for DTLS-SRTP).
    expected_fingerprint: Option<[u8; 48]>,
    /// Whether to allow self-signed certificates.
    allow_self_signed: bool,
}

impl Handshake {
    /// Creates a new handshake context.
    pub fn new(
        is_client: bool,
        cert_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> DtlsResult<Self> {
        // Generate client/server random
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];

        if is_client {
            uc_crypto::random::fill_random(&mut client_random).map_err(|e| {
                DtlsError::HandshakeFailed {
                    reason: format!("failed to generate client random: {e}"),
                }
            })?;
        } else {
            uc_crypto::random::fill_random(&mut server_random).map_err(|e| {
                DtlsError::HandshakeFailed {
                    reason: format!("failed to generate server random: {e}"),
                }
            })?;
        }

        let state = if is_client {
            HandshakeState::Start
        } else {
            HandshakeState::WaitClientHello
        };

        Ok(Self {
            is_client,
            state,
            record_layer: RecordLayer::new(),
            local_ecdhe: None,
            local_ecdhe_public: None,
            peer_ecdhe_public: None,
            premaster_secret: None,
            client_random,
            server_random,
            master_secret: None,
            message_seq: 0,
            local_cert_chain: cert_chain,
            local_private_key: private_key,
            handshake_hash: Vec::new(),
            cookie: Vec::new(),
            peer_cert_chain: Vec::new(),
            peer_public_key: None,
            ecdh_params: None,
            expected_fingerprint: None,
            allow_self_signed: true, // Default for DTLS-SRTP
        })
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Performs the handshake.
    ///
    /// ## Errors
    ///
    /// Returns an error if the handshake fails.
    pub async fn perform(
        &mut self,
        socket: &Arc<UdpSocket>,
        handshake_timeout: Duration,
    ) -> DtlsResult<()> {
        let result = if self.is_client {
            self.perform_client_handshake(socket, handshake_timeout)
                .await
        } else {
            self.perform_server_handshake(socket, handshake_timeout)
                .await
        };

        if result.is_err() {
            self.state = HandshakeState::Failed;
        }

        result
    }

    /// Performs client-side handshake.
    async fn perform_client_handshake(
        &mut self,
        socket: &Arc<UdpSocket>,
        handshake_timeout: Duration,
    ) -> DtlsResult<()> {
        debug!("Starting client handshake");

        // Send ClientHello
        let client_hello = self.build_client_hello();
        self.send_handshake_message(socket, HandshakeType::ClientHello, &client_hello)
            .await?;
        self.state = HandshakeState::WaitHelloVerifyRequest;

        // Receive HelloVerifyRequest or ServerHello
        let msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;

        if msg.0 == HandshakeType::HelloVerifyRequest {
            // Extract cookie and resend ClientHello
            self.process_hello_verify_request(&msg.1)?;

            let client_hello_with_cookie = self.build_client_hello();
            self.send_handshake_message(
                socket,
                HandshakeType::ClientHello,
                &client_hello_with_cookie,
            )
            .await?;

            // Wait for ServerHello
            let server_hello_msg = self
                .recv_handshake_message(socket, handshake_timeout)
                .await?;
            if server_hello_msg.0 != HandshakeType::ServerHello {
                return Err(DtlsError::HandshakeFailed {
                    reason: format!("expected ServerHello, got {:?}", server_hello_msg.0),
                });
            }
            self.process_server_hello(&server_hello_msg.1)?;
        } else if msg.0 == HandshakeType::ServerHello {
            self.process_server_hello(&msg.1)?;
        } else {
            return Err(DtlsError::HandshakeFailed {
                reason: format!(
                    "expected HelloVerifyRequest or ServerHello, got {:?}",
                    msg.0
                ),
            });
        }

        self.state = HandshakeState::WaitCertificate;

        // Receive Certificate
        let cert_msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if cert_msg.0 != HandshakeType::Certificate {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected Certificate, got {:?}", cert_msg.0),
            });
        }
        // Validate certificate chain per RFC 6347 §4.2.4
        self.process_certificate(&cert_msg.1)?;

        // Receive ServerKeyExchange
        let ske_msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if ske_msg.0 != HandshakeType::ServerKeyExchange {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected ServerKeyExchange, got {:?}", ske_msg.0),
            });
        }
        self.process_server_key_exchange(&ske_msg.1)?;

        // Receive ServerHelloDone
        let shd_msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if shd_msg.0 != HandshakeType::ServerHelloDone {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected ServerHelloDone, got {:?}", shd_msg.0),
            });
        }

        // Generate and send ClientKeyExchange
        let cke = self.build_client_key_exchange()?;
        self.send_handshake_message(socket, HandshakeType::ClientKeyExchange, &cke)
            .await?;

        // Derive keys
        self.derive_keys()?;

        // Send ChangeCipherSpec
        self.send_change_cipher_spec(socket).await?;

        // Activate cipher
        self.activate_cipher()?;

        // Send Finished
        let finished = self.build_finished()?;
        self.send_handshake_message(socket, HandshakeType::Finished, &finished)
            .await?;

        self.state = HandshakeState::WaitChangeCipherSpec;

        // Receive ChangeCipherSpec
        let ccs = self.recv_record(socket, handshake_timeout).await?;
        if ccs.0 != ContentType::ChangeCipherSpec {
            return Err(DtlsError::HandshakeFailed {
                reason: "expected ChangeCipherSpec".to_string(),
            });
        }

        // Receive Finished
        let fin_msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if fin_msg.0 != HandshakeType::Finished {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected Finished, got {:?}", fin_msg.0),
            });
        }
        // Verify Finished message per RFC 6347 §4.2.6
        self.verify_finished(&fin_msg.1, false)?; // false = this is server's Finished

        self.state = HandshakeState::Complete;
        debug!("Client handshake complete");

        Ok(())
    }

    /// Performs server-side handshake.
    async fn perform_server_handshake(
        &mut self,
        socket: &Arc<UdpSocket>,
        handshake_timeout: Duration,
    ) -> DtlsResult<()> {
        debug!("Starting server handshake");

        // Receive ClientHello
        let ch_msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if ch_msg.0 != HandshakeType::ClientHello {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected ClientHello, got {:?}", ch_msg.0),
            });
        }
        self.process_client_hello(&ch_msg.1)?;

        // Send HelloVerifyRequest with cookie
        let hvr = self.build_hello_verify_request()?;
        self.send_handshake_message(socket, HandshakeType::HelloVerifyRequest, &hvr)
            .await?;

        // Receive ClientHello with cookie
        let ch_msg2 = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if ch_msg2.0 != HandshakeType::ClientHello {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected ClientHello, got {:?}", ch_msg2.0),
            });
        }
        self.verify_client_hello_cookie(&ch_msg2.1)?;

        // Send ServerHello
        let sh = self.build_server_hello();
        self.send_handshake_message(socket, HandshakeType::ServerHello, &sh)
            .await?;

        // Send Certificate
        let cert = self.build_certificate();
        self.send_handshake_message(socket, HandshakeType::Certificate, &cert)
            .await?;

        // Send ServerKeyExchange
        let ske = self.build_server_key_exchange()?;
        self.send_handshake_message(socket, HandshakeType::ServerKeyExchange, &ske)
            .await?;

        // Send ServerHelloDone
        self.send_handshake_message(socket, HandshakeType::ServerHelloDone, &[])
            .await?;

        self.state = HandshakeState::WaitClientKeyExchange;

        // Receive ClientKeyExchange
        let cke_msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if cke_msg.0 != HandshakeType::ClientKeyExchange {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected ClientKeyExchange, got {:?}", cke_msg.0),
            });
        }
        self.process_client_key_exchange(&cke_msg.1)?;

        // Derive keys
        self.derive_keys()?;

        self.state = HandshakeState::WaitChangeCipherSpec;

        // Receive ChangeCipherSpec
        let ccs = self.recv_record(socket, handshake_timeout).await?;
        if ccs.0 != ContentType::ChangeCipherSpec {
            return Err(DtlsError::HandshakeFailed {
                reason: "expected ChangeCipherSpec".to_string(),
            });
        }

        // Activate read cipher
        // Note: In a real implementation, we'd have separate read/write cipher activation
        self.activate_cipher()?;

        // Receive Finished
        let fin_msg = self
            .recv_handshake_message(socket, handshake_timeout)
            .await?;
        if fin_msg.0 != HandshakeType::Finished {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("expected Finished, got {:?}", fin_msg.0),
            });
        }
        // Verify Finished message per RFC 6347 §4.2.6
        self.verify_finished(&fin_msg.1, true)?; // true = this is client's Finished

        // Send ChangeCipherSpec
        self.send_change_cipher_spec(socket).await?;

        // Send Finished
        let finished = self.build_finished()?;
        self.send_handshake_message(socket, HandshakeType::Finished, &finished)
            .await?;

        self.state = HandshakeState::Complete;
        debug!("Server handshake complete");

        Ok(())
    }

    /// Builds a `ClientHello` message.
    fn build_client_hello(&self) -> Vec<u8> {
        let mut msg = Vec::new();

        // Client version (DTLS 1.2)
        msg.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());

        // Client random (32 bytes)
        msg.extend_from_slice(&self.client_random);

        // Session ID (empty for new session)
        msg.push(0);

        // Cookie length is always <= 255, so truncation is safe
        #[allow(clippy::cast_possible_truncation)]
        msg.push(self.cookie.len() as u8);
        msg.extend_from_slice(&self.cookie);

        // Cipher suites (only CNSA 2.0 compliant)
        msg.extend_from_slice(&2u16.to_be_bytes()); // Length
        msg.extend_from_slice(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.to_be_bytes());

        // Compression methods (null only)
        msg.push(1); // Length
        msg.push(0); // Null compression

        // Extensions (minimal)
        // We'd need to add supported_groups (P-384) and signature_algorithms here
        msg.extend_from_slice(&0u16.to_be_bytes()); // No extensions for now

        msg
    }

    /// Processes a `HelloVerifyRequest`.
    fn process_hello_verify_request(&mut self, data: &[u8]) -> DtlsResult<()> {
        if data.len() < 3 {
            return Err(DtlsError::HandshakeFailed {
                reason: "HelloVerifyRequest too short".to_string(),
            });
        }

        // Skip server version (2 bytes)
        let cookie_len = data[2] as usize;
        if data.len() < 3 + cookie_len {
            return Err(DtlsError::HandshakeFailed {
                reason: "HelloVerifyRequest cookie truncated".to_string(),
            });
        }

        self.cookie = data[3..3 + cookie_len].to_vec();
        debug!(cookie_len = cookie_len, "Received cookie");
        Ok(())
    }

    /// Processes a `ServerHello` message.
    fn process_server_hello(&mut self, data: &[u8]) -> DtlsResult<()> {
        if data.len() < 38 {
            return Err(DtlsError::HandshakeFailed {
                reason: "ServerHello too short".to_string(),
            });
        }

        // Skip version (2 bytes)
        // Extract server random (32 bytes)
        self.server_random.copy_from_slice(&data[2..34]);

        // Skip session ID
        let session_id_len = data[34] as usize;
        let offset = 35 + session_id_len;

        if data.len() < offset + 2 {
            return Err(DtlsError::HandshakeFailed {
                reason: "ServerHello truncated".to_string(),
            });
        }

        // Check cipher suite
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        if cipher_suite != TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
            return Err(DtlsError::UnsupportedCipherSuite(cipher_suite));
        }

        debug!(
            "ServerHello processed, cipher suite: 0x{:04X}",
            cipher_suite
        );
        Ok(())
    }

    /// Processes a `ClientHello` message (server side).
    fn process_client_hello(&mut self, data: &[u8]) -> DtlsResult<()> {
        if data.len() < 34 {
            return Err(DtlsError::HandshakeFailed {
                reason: "ClientHello too short".to_string(),
            });
        }

        // Extract client random (after version)
        self.client_random.copy_from_slice(&data[2..34]);

        debug!("ClientHello processed");
        Ok(())
    }

    /// Verifies client hello cookie.
    fn verify_client_hello_cookie(&self, data: &[u8]) -> DtlsResult<()> {
        if data.len() < 35 {
            return Err(DtlsError::HandshakeFailed {
                reason: "ClientHello too short for cookie".to_string(),
            });
        }

        let session_id_len = data[34] as usize;
        let offset = 35 + session_id_len;

        if data.len() < offset + 1 {
            return Err(DtlsError::HandshakeFailed {
                reason: "ClientHello truncated".to_string(),
            });
        }

        let cookie_len = data[offset] as usize;
        if data.len() < offset + 1 + cookie_len {
            return Err(DtlsError::HandshakeFailed {
                reason: "ClientHello cookie truncated".to_string(),
            });
        }

        let received_cookie = &data[offset + 1..offset + 1 + cookie_len];
        if received_cookie != self.cookie {
            return Err(DtlsError::HandshakeFailed {
                reason: "cookie mismatch".to_string(),
            });
        }

        debug!("Cookie verified");
        Ok(())
    }

    /// Builds a `HelloVerifyRequest` message.
    fn build_hello_verify_request(&mut self) -> DtlsResult<Vec<u8>> {
        // Generate cookie
        let mut cookie = [0u8; 32];
        uc_crypto::random::fill_random(&mut cookie).map_err(|e| DtlsError::HandshakeFailed {
            reason: format!("failed to generate cookie: {e}"),
        })?;
        self.cookie = cookie.to_vec();

        let mut msg = Vec::new();
        msg.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());
        msg.push(cookie.len() as u8);
        msg.extend_from_slice(&cookie);

        Ok(msg)
    }

    /// Builds a `ServerHello` message.
    fn build_server_hello(&self) -> Vec<u8> {
        let mut msg = Vec::new();

        // Server version
        msg.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());

        // Server random
        msg.extend_from_slice(&self.server_random);

        // Session ID (empty)
        msg.push(0);

        // Cipher suite
        msg.extend_from_slice(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.to_be_bytes());

        // Compression method (null)
        msg.push(0);

        // No extensions
        msg.extend_from_slice(&0u16.to_be_bytes());

        msg
    }

    /// Builds a Certificate message.
    fn build_certificate(&self) -> Vec<u8> {
        let mut msg = Vec::new();

        // Calculate total certificates length
        let total_len: usize = self.local_cert_chain.iter().map(|c| 3 + c.len()).sum();

        // Certificates length (3 bytes) - total_len fits in 24 bits for valid certs
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (total_len as u32).to_be_bytes();
        msg.extend_from_slice(&len_bytes[1..4]);

        // Each certificate
        for cert in &self.local_cert_chain {
            // cert.len() fits in 24 bits for valid certificates
            #[allow(clippy::cast_possible_truncation)]
            let cert_len = (cert.len() as u32).to_be_bytes();
            msg.extend_from_slice(&cert_len[1..4]);
            msg.extend_from_slice(cert);
        }

        msg
    }

    /// Builds a `ServerKeyExchange` message.
    fn build_server_key_exchange(&mut self) -> DtlsResult<Vec<u8>> {
        // Generate ECDHE key pair
        let ecdhe = P384EphemeralKeyPair::generate().map_err(|e| DtlsError::HandshakeFailed {
            reason: format!("failed to generate ECDHE key: {e}"),
        })?;

        let public_key = ecdhe.public_key_bytes().to_vec();
        self.local_ecdhe_public = Some(public_key.clone());
        self.local_ecdhe = Some(ecdhe);

        let mut msg = Vec::new();

        // EC curve type: named_curve (3)
        msg.push(3);

        // Named curve: secp384r1 (24)
        msg.extend_from_slice(&24u16.to_be_bytes());

        // Public key length and data - P-384 public key is 97 bytes, fits in u8
        #[allow(clippy::cast_possible_truncation)]
        msg.push(public_key.len() as u8);
        msg.extend_from_slice(&public_key);

        // Sign the exchange parameters per RFC 6347
        // signed_params = client_random + server_random + ServerECDHParams
        let mut signed_data = Vec::with_capacity(64 + msg.len());
        signed_data.extend_from_slice(&self.client_random);
        signed_data.extend_from_slice(&self.server_random);
        signed_data.extend_from_slice(&msg);

        // Sign with ECDSA P-384
        let keypair =
            uc_crypto::ecdsa::P384KeyPair::from_pkcs8(&self.local_private_key).map_err(|e| {
                DtlsError::HandshakeFailed {
                    reason: format!("invalid private key: {e}"),
                }
            })?;

        let signature = keypair
            .sign(&signed_data)
            .map_err(|e| DtlsError::HandshakeFailed {
                reason: format!("signing failed: {e}"),
            })?;

        // Signature algorithm: ecdsa_secp384r1_sha384 (0x0503)
        msg.extend_from_slice(&[0x05, 0x03]);
        // Signature length (2 bytes) - ECDSA P-384 signature fits in u16
        #[allow(clippy::cast_possible_truncation)]
        msg.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        // Signature
        msg.extend_from_slice(&signature);

        Ok(msg)
    }

    /// Processes a `ServerKeyExchange` message.
    fn process_server_key_exchange(&mut self, data: &[u8]) -> DtlsResult<()> {
        if data.len() < 4 {
            return Err(DtlsError::HandshakeFailed {
                reason: "ServerKeyExchange too short".to_string(),
            });
        }

        // Curve type (1 byte) should be named_curve (3)
        if data[0] != 3 {
            return Err(DtlsError::HandshakeFailed {
                reason: format!("unsupported curve type: {}", data[0]),
            });
        }

        // Named curve
        let curve = u16::from_be_bytes([data[1], data[2]]);
        if curve != 24 {
            // secp384r1
            return Err(DtlsError::HandshakeFailed {
                reason: format!("unsupported curve: {curve}"),
            });
        }

        // Public key length
        let pk_len = data[3] as usize;
        if data.len() < 4 + pk_len {
            return Err(DtlsError::HandshakeFailed {
                reason: "ServerKeyExchange public key truncated".to_string(),
            });
        }

        self.peer_ecdhe_public = Some(data[4..4 + pk_len].to_vec());

        // Store ECDH params for signature verification
        self.ecdh_params = Some(data[..4 + pk_len].to_vec());

        // Check for signature (if present)
        if data.len() > 4 + pk_len {
            let sig_offset = 4 + pk_len;
            // Signature algorithm (2 bytes) + signature length (2 bytes) + signature
            if data.len() >= sig_offset + 4 {
                let sig_len =
                    u16::from_be_bytes([data[sig_offset + 2], data[sig_offset + 3]]) as usize;
                if data.len() >= sig_offset + 4 + sig_len {
                    let signature = &data[sig_offset + 4..sig_offset + 4 + sig_len];

                    // Verify signature if we have peer's public key
                    if let Some(peer_pubkey) = &self.peer_public_key {
                        ServerKeyExchangeVerifier::verify(
                            &self.client_random,
                            &self.server_random,
                            &data[..4 + pk_len],
                            signature,
                            peer_pubkey,
                        )?;
                        debug!("ServerKeyExchange signature verified");
                    }
                }
            }
        }

        debug!(pk_len = pk_len, "Processed ServerKeyExchange");
        Ok(())
    }

    /// Processes a Certificate message and validates the certificate chain.
    ///
    /// Per RFC 6347 §4.2.4, validates:
    /// - Certificate structure
    /// - Signature chain
    /// - Fingerprint (for DTLS-SRTP)
    fn process_certificate(&mut self, data: &[u8]) -> DtlsResult<()> {
        if data.len() < 3 {
            return Err(DtlsError::CertificateError {
                reason: "Certificate message too short".to_string(),
            });
        }

        // Total certificates length (3 bytes)
        let total_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
        if data.len() < 3 + total_len {
            return Err(DtlsError::CertificateError {
                reason: "Certificate message truncated".to_string(),
            });
        }

        // Parse certificate chain
        let mut offset = 3;
        let mut certs = Vec::new();

        while offset < 3 + total_len {
            if offset + 3 > data.len() {
                return Err(DtlsError::CertificateError {
                    reason: "Certificate entry truncated".to_string(),
                });
            }

            let cert_len =
                u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
            offset += 3;

            if offset + cert_len > data.len() {
                return Err(DtlsError::CertificateError {
                    reason: "Certificate data truncated".to_string(),
                });
            }

            certs.push(data[offset..offset + cert_len].to_vec());
            offset += cert_len;
        }

        if certs.is_empty() {
            return Err(DtlsError::CertificateError {
                reason: "No certificates in chain".to_string(),
            });
        }

        // Build validator
        let mut validator = CertificateValidator::new();
        if self.allow_self_signed {
            validator = validator.allow_self_signed();
        }
        if let Some(fp) = self.expected_fingerprint {
            validator = validator.with_fingerprint(fp);
        }

        // Validate certificate chain
        let result = validator.validate(&certs);
        match result {
            CertificateValidationResult::Valid => {
                debug!("Certificate chain validated");
            }
            CertificateValidationResult::SelfSigned => {
                debug!("Self-signed certificate accepted");
            }
            CertificateValidationResult::Invalid(reason) => {
                return Err(DtlsError::CertificateError { reason });
            }
        }

        // Extract public key from leaf certificate
        let pubkey = validator.extract_public_key(&certs[0])?;
        self.peer_public_key = Some(pubkey);
        self.peer_cert_chain = certs;

        Ok(())
    }

    /// Verifies a received Finished message.
    ///
    /// Per RFC 6347 §4.2.6, the Finished message contains `verify_data` computed as:
    /// ```text
    /// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]
    /// ```
    fn verify_finished(&self, data: &[u8], is_client_finished: bool) -> DtlsResult<()> {
        let master_secret = self.master_secret.ok_or_else(|| DtlsError::HandshakeFailed {
            reason: "no master secret for Finished verification".to_string(),
        })?;

        // Compute hash of all handshake messages (excluding this Finished)
        let handshake_hash = uc_crypto::hash::sha384(&self.handshake_hash);

        // Verify the Finished message
        FinishedVerifier::verify(data, &master_secret, &handshake_hash, is_client_finished)?;

        debug!(
            role = if is_client_finished {
                "client"
            } else {
                "server"
            },
            "Finished message verified"
        );
        Ok(())
    }

    /// Builds a `ClientKeyExchange` message.
    fn build_client_key_exchange(&mut self) -> DtlsResult<Vec<u8>> {
        // Generate ECDHE key pair
        let ecdhe = P384EphemeralKeyPair::generate().map_err(|e| DtlsError::HandshakeFailed {
            reason: format!("failed to generate ECDHE key: {e}"),
        })?;

        let public_key = ecdhe.public_key_bytes().to_vec();
        self.local_ecdhe_public = Some(public_key.clone());
        self.local_ecdhe = Some(ecdhe);

        let mut msg = Vec::new();
        // P-384 public key is 97 bytes, fits in u8
        #[allow(clippy::cast_possible_truncation)]
        msg.push(public_key.len() as u8);
        msg.extend_from_slice(&public_key);

        Ok(msg)
    }

    /// Processes a `ClientKeyExchange` message.
    fn process_client_key_exchange(&mut self, data: &[u8]) -> DtlsResult<()> {
        if data.is_empty() {
            return Err(DtlsError::HandshakeFailed {
                reason: "ClientKeyExchange empty".to_string(),
            });
        }

        let pk_len = data[0] as usize;
        if data.len() < 1 + pk_len {
            return Err(DtlsError::HandshakeFailed {
                reason: "ClientKeyExchange public key truncated".to_string(),
            });
        }

        self.peer_ecdhe_public = Some(data[1..=pk_len].to_vec());

        debug!(pk_len = pk_len, "Processed ClientKeyExchange");
        Ok(())
    }

    /// Derives the master secret and traffic keys.
    fn derive_keys(&mut self) -> DtlsResult<()> {
        // Take the ECDHE key pair (consumes it for the agreement)
        let ecdhe = self
            .local_ecdhe
            .take()
            .ok_or_else(|| DtlsError::KeyDerivationFailed {
                reason: "no local ECDHE key".to_string(),
            })?;

        let peer_public =
            self.peer_ecdhe_public
                .as_ref()
                .ok_or_else(|| DtlsError::KeyDerivationFailed {
                    reason: "no peer ECDHE public key".to_string(),
                })?;

        // Compute shared secret (consumes the ephemeral key)
        let shared_secret =
            ecdhe
                .agree(peer_public)
                .map_err(|e| DtlsError::KeyDerivationFailed {
                    reason: format!("ECDHE key agreement failed: {e}"),
                })?;

        let shared_bytes = shared_secret.as_bytes().to_vec();
        self.premaster_secret = Some(shared_bytes.clone());

        // Derive master secret using TLS 1.2 PRF with SHA-384
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);

        let master_secret = prf_sha384(&shared_bytes, b"master secret", &seed, 48);
        let mut ms = [0u8; 48];
        ms.copy_from_slice(&master_secret);
        self.master_secret = Some(ms);

        debug!("Master secret derived");
        Ok(())
    }

    /// Activates the cipher suite.
    fn activate_cipher(&mut self) -> DtlsResult<()> {
        let master_secret = self.master_secret.ok_or_else(|| DtlsError::KeyDerivationFailed {
            reason: "no master secret".to_string(),
        })?;

        // Key expansion
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.server_random);
        seed.extend_from_slice(&self.client_random);

        // For AES-256-GCM: 32 byte key + 4 byte IV for each direction
        let key_material = prf_sha384(&master_secret, b"key expansion", &seed, 72);

        let client_key_bytes: [u8; 32] =
            key_material[0..32]
                .try_into()
                .map_err(|_| DtlsError::KeyDerivationFailed {
                    reason: "key slice error".to_string(),
                })?;
        let server_key_bytes: [u8; 32] =
            key_material[32..64]
                .try_into()
                .map_err(|_| DtlsError::KeyDerivationFailed {
                    reason: "key slice error".to_string(),
                })?;
        let client_iv: [u8; 4] =
            key_material[64..68]
                .try_into()
                .map_err(|_| DtlsError::KeyDerivationFailed {
                    reason: "IV slice error".to_string(),
                })?;
        let server_iv: [u8; 4] =
            key_material[68..72]
                .try_into()
                .map_err(|_| DtlsError::KeyDerivationFailed {
                    reason: "IV slice error".to_string(),
                })?;

        let client_key =
            Aes256GcmKey::new(client_key_bytes).map_err(|e| DtlsError::KeyDerivationFailed {
                reason: format!("invalid client key: {e}"),
            })?;
        let server_key =
            Aes256GcmKey::new(server_key_bytes).map_err(|e| DtlsError::KeyDerivationFailed {
                reason: format!("invalid server key: {e}"),
            })?;

        // Activate cipher with correct key direction based on role
        if self.is_client {
            self.record_layer
                .activate_cipher(client_key, server_key, client_iv, server_iv);
        } else {
            self.record_layer
                .activate_cipher(server_key, client_key, server_iv, client_iv);
        }

        debug!("Cipher activated");
        Ok(())
    }

    /// Builds a Finished message.
    fn build_finished(&self) -> DtlsResult<Vec<u8>> {
        let master_secret = self.master_secret.ok_or_else(|| DtlsError::KeyDerivationFailed {
            reason: "no master secret".to_string(),
        })?;

        let label = if self.is_client {
            b"client finished"
        } else {
            b"server finished"
        };

        // Hash of all handshake messages
        let handshake_hash = uc_crypto::hash::sha384(&self.handshake_hash);

        let verify_data = prf_sha384(&master_secret, label, &handshake_hash, 12);

        Ok(verify_data)
    }

    /// Sends a handshake message.
    async fn send_handshake_message(
        &mut self,
        socket: &Arc<UdpSocket>,
        msg_type: HandshakeType,
        payload: &[u8],
    ) -> DtlsResult<()> {
        // Build handshake header - payload length fits in 24 bits for valid handshake messages
        #[allow(clippy::cast_possible_truncation)]
        let header = HandshakeHeader {
            msg_type,
            length: payload.len() as u32,
            message_seq: self.message_seq,
            fragment_offset: 0,
            fragment_length: payload.len() as u32,
        };
        self.message_seq += 1;

        // Combine header and payload
        let mut fragment = Vec::with_capacity(HandshakeHeader::SIZE + payload.len());
        fragment.extend_from_slice(&header.serialize());
        fragment.extend_from_slice(payload);

        // Add to handshake hash
        self.handshake_hash.extend_from_slice(&fragment);

        // Encrypt and frame
        let record = self
            .record_layer
            .encrypt_record(ContentType::Handshake, &fragment)?;

        // Send
        socket
            .send(&record)
            .await
            .map_err(|e| DtlsError::SendFailed {
                reason: e.to_string(),
            })?;

        debug!(msg_type = ?msg_type, len = payload.len(), "Sent handshake message");
        Ok(())
    }

    /// Sends a `ChangeCipherSpec` message.
    async fn send_change_cipher_spec(&mut self, socket: &Arc<UdpSocket>) -> DtlsResult<()> {
        let record = self
            .record_layer
            .encrypt_record(ContentType::ChangeCipherSpec, &[1])?;
        socket
            .send(&record)
            .await
            .map_err(|e| DtlsError::SendFailed {
                reason: e.to_string(),
            })?;
        debug!("Sent ChangeCipherSpec");
        Ok(())
    }

    /// Receives a handshake message.
    async fn recv_handshake_message(
        &mut self,
        socket: &Arc<UdpSocket>,
        recv_timeout: Duration,
    ) -> DtlsResult<(HandshakeType, Vec<u8>)> {
        loop {
            let (content_type, fragment) = self.recv_record(socket, recv_timeout).await?;

            if content_type == ContentType::Handshake {
                if fragment.len() < HandshakeHeader::SIZE {
                    return Err(DtlsError::HandshakeFailed {
                        reason: "handshake message too short".to_string(),
                    });
                }

                let header = HandshakeHeader::parse(&fragment)?;
                let payload = fragment[HandshakeHeader::SIZE..].to_vec();

                // Add to handshake hash (except Finished which we verify)
                if header.msg_type != HandshakeType::Finished {
                    self.handshake_hash.extend_from_slice(&fragment);
                }

                return Ok((header.msg_type, payload));
            } else if content_type == ContentType::Alert
                && fragment.len() >= 2 {
                    return Err(DtlsError::AlertReceived {
                        level: fragment[0],
                        description: fragment[1],
                    });
                }
            // Ignore other message types
        }
    }

    /// Receives a record.
    async fn recv_record(
        &mut self,
        socket: &Arc<UdpSocket>,
        recv_timeout: Duration,
    ) -> DtlsResult<(ContentType, Vec<u8>)> {
        let mut buf = vec![0u8; 16384 + RECORD_HEADER_LEN + 16];

        let n = timeout(recv_timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| DtlsError::Timeout)?
            .map_err(|e| DtlsError::ReceiveFailed {
                reason: e.to_string(),
            })?;

        buf.truncate(n);

        let (content_type, fragment) = self.record_layer.decrypt_record(&buf)?;
        Ok((content_type, fragment))
    }

    /// Returns the record layer for data transfer.
    #[must_use]
    pub fn into_record_layer(self) -> RecordLayer {
        self.record_layer
    }

    /// Exports SRTP keying material per RFC 5764.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn export_srtp_keying_material(&self) -> DtlsResult<Vec<u8>> {
        let master_secret = self.master_secret.ok_or_else(|| DtlsError::SrtpKeyExportFailed {
            reason: "no master secret".to_string(),
        })?;

        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);

        // SRTP keying material: 2 * (32 byte key + 12 byte salt) = 88 bytes
        let keying_material = prf_sha384(&master_secret, b"EXTRACTOR-dtls_srtp", &seed, 88);

        Ok(keying_material)
    }
}

/// TLS 1.2 PRF using HMAC-SHA-384.
fn prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    // P_SHA384(secret, seed) = HMAC_SHA384(secret, A(1) + seed) +
    //                          HMAC_SHA384(secret, A(2) + seed) + ...
    // where A(0) = seed, A(i) = HMAC_SHA384(secret, A(i-1))

    let mut result = Vec::with_capacity(length);

    // Combine label and seed
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    // A(1) = HMAC_SHA384(secret, label + seed)
    let mut a = hkdf::hmac_sha384(secret, &combined_seed);

    while result.len() < length {
        // HMAC_SHA384(secret, A(i) + label + seed)
        let mut input = Vec::with_capacity(a.len() + combined_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&combined_seed);

        let output = hkdf::hmac_sha384(secret, &input);
        result.extend_from_slice(&output);

        // A(i+1) = HMAC_SHA384(secret, A(i))
        a = hkdf::hmac_sha384(secret, &a);
    }

    result.truncate(length);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_header_parse_serialize() {
        let header = HandshakeHeader {
            msg_type: HandshakeType::ClientHello,
            length: 100,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 100,
        };

        let serialized = header.serialize();
        let parsed = HandshakeHeader::parse(&serialized).unwrap();

        assert_eq!(parsed.msg_type, header.msg_type);
        assert_eq!(parsed.length, header.length);
        assert_eq!(parsed.message_seq, header.message_seq);
        assert_eq!(parsed.fragment_offset, header.fragment_offset);
        assert_eq!(parsed.fragment_length, header.fragment_length);
    }

    #[test]
    fn test_handshake_type_conversion() {
        assert_eq!(
            HandshakeType::try_from(1).unwrap(),
            HandshakeType::ClientHello
        );
        assert_eq!(
            HandshakeType::try_from(2).unwrap(),
            HandshakeType::ServerHello
        );
        assert_eq!(
            HandshakeType::try_from(20).unwrap(),
            HandshakeType::Finished
        );
        assert!(HandshakeType::try_from(99).is_err());
    }

    #[test]
    fn test_cipher_suite_constant() {
        // IANA value for TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        assert_eq!(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 0xC02C);
    }

    #[test]
    fn test_prf_sha384() {
        // Basic test that PRF produces deterministic output
        let secret = b"secret";
        let label = b"test label";
        let seed = b"seed data";

        let result1 = prf_sha384(secret, label, seed, 32);
        let result2 = prf_sha384(secret, label, seed, 32);

        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }
}
