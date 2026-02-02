//! Unified error types for the SBC.
//!
//! ## NIST 800-53 Rev5: SI-11 (Error Handling)
//!
//! Error messages are designed to:
//! - Provide sufficient information for debugging
//! - Not leak sensitive security information to external parties
//! - Support audit logging requirements

use thiserror::Error;

/// Result type alias using [`SbcError`].
pub type SbcResult<T> = Result<T, SbcError>;

/// Top-level error type for the SBC.
///
/// This enum categorizes errors by subsystem for easier handling and logging.
#[derive(Debug, Error)]
pub enum SbcError {
    /// Transport layer errors (UDP, TCP, TLS, WebSocket).
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    /// SIP protocol errors.
    #[error("sip error: {0}")]
    Sip(#[from] SipError),

    /// Media processing errors.
    #[error("media error: {0}")]
    Media(#[from] MediaError),

    /// Cryptographic operation errors.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Configuration errors.
    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    /// Authentication/authorization errors.
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),

    /// STIR/SHAKEN verification errors.
    #[error("stir/shaken error: {0}")]
    StirShaken(#[from] StirShakenError),

    /// ICE/NAT traversal errors.
    #[error("ice error: {0}")]
    Ice(#[from] IceError),
}

/// Transport layer errors.
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
#[derive(Debug, Error)]
pub enum TransportError {
    /// Socket bind failure.
    #[error("failed to bind socket: {0}")]
    BindFailed(String),

    /// Connection establishment failure.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// TLS handshake failure.
    #[error("tls handshake failed: {0}")]
    TlsHandshakeFailed(String),

    /// Send operation failure.
    #[error("send failed: {0}")]
    SendFailed(String),

    /// Receive operation failure.
    #[error("receive failed: {0}")]
    ReceiveFailed(String),

    /// Connection timeout.
    #[error("connection timeout after {0}ms")]
    Timeout(u64),

    /// Address resolution failure.
    #[error("address resolution failed: {0}")]
    AddressResolution(String),
}

/// SIP protocol errors.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
#[derive(Debug, Error)]
pub enum SipError {
    /// Message parsing failure.
    #[error("failed to parse sip message: {0}")]
    ParseError(String),

    /// Invalid SIP method.
    #[error("invalid sip method: {0}")]
    InvalidMethod(String),

    /// Invalid SIP URI.
    #[error("invalid sip uri: {0}")]
    InvalidUri(String),

    /// Required header missing.
    #[error("missing required header: {0}")]
    MissingHeader(String),

    /// Transaction state error.
    #[error("transaction state error: {0}")]
    TransactionState(String),

    /// Dialog state error.
    #[error("dialog state error: {0}")]
    DialogState(String),

    /// Registration failure.
    #[error("registration failed: {0}")]
    RegistrationFailed(String),
}

/// Media processing errors.
#[derive(Debug, Error)]
pub enum MediaError {
    /// Codec not supported.
    #[error("unsupported codec: {0}")]
    UnsupportedCodec(String),

    /// Transcoding failure.
    #[error("transcoding failed: {0}")]
    TranscodingFailed(String),

    /// RTP packet processing error.
    #[error("rtp processing error: {0}")]
    RtpError(String),

    /// SRTP protection/unprotection failure.
    #[error("srtp error: {0}")]
    SrtpError(String),

    /// Media session not found.
    #[error("media session not found: {0}")]
    SessionNotFound(String),
}

/// Cryptographic operation errors.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// Error messages intentionally do not expose internal cryptographic details
/// that could aid attackers.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failure.
    #[error("key generation failed")]
    KeyGenerationFailed,

    /// Encryption failure.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failure (may indicate tampering).
    #[error("decryption failed")]
    DecryptionFailed,

    /// Signature generation failure.
    #[error("signature generation failed")]
    SignatureFailed,

    /// Signature verification failure.
    #[error("signature verification failed")]
    VerificationFailed,

    /// Invalid key material.
    #[error("invalid key material")]
    InvalidKeyMaterial,

    /// Key derivation failure.
    #[error("key derivation failed")]
    KeyDerivationFailed,

    /// CNSA 2.0 compliance violation attempt.
    #[error("cnsa 2.0 violation: algorithm not permitted")]
    CnsaViolation,
}

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Configuration file not found.
    #[error("config file not found: {0}")]
    FileNotFound(String),

    /// Configuration parse error.
    #[error("config parse error: {0}")]
    ParseError(String),

    /// Configuration validation error.
    #[error("config validation error: {0}")]
    ValidationError(String),

    /// Missing required configuration.
    #[error("missing required config: {0}")]
    MissingRequired(String),
}

/// Authentication and authorization errors.
///
/// ## NIST 800-53 Rev5: IA-5 (Authenticator Management)
#[derive(Debug, Error)]
pub enum AuthError {
    /// Invalid credentials.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Authentication timeout.
    #[error("authentication timeout")]
    Timeout,

    /// Account locked.
    #[error("account locked")]
    AccountLocked,

    /// Insufficient permissions.
    #[error("insufficient permissions for: {0}")]
    InsufficientPermissions(String),

    /// Token expired.
    #[error("token expired")]
    TokenExpired,

    /// Token invalid.
    #[error("invalid token")]
    InvalidToken,
}

/// STIR/SHAKEN verification errors.
///
/// ## NIST 800-53 Rev5: IA-9 (Service Identification and Authentication)
#[derive(Debug, Error)]
pub enum StirShakenError {
    /// PASSporT parsing failure.
    #[error("passport parse error: {0}")]
    PassportParseError(String),

    /// Signature verification failure.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Certificate fetch failure.
    #[error("certificate fetch failed: {0}")]
    CertificateFetchFailed(String),

    /// Certificate validation failure.
    #[error("certificate validation failed: {0}")]
    CertificateValidationFailed(String),

    /// PASSporT expired (iat too old).
    #[error("passport expired")]
    PassportExpired,

    /// Originating number mismatch.
    #[error("originating number mismatch")]
    OriginMismatch,
}

/// ICE/NAT traversal errors.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
#[derive(Debug, Error)]
pub enum IceError {
    /// Candidate gathering failure.
    #[error("candidate gathering failed: {0}")]
    GatheringFailed(String),

    /// Connectivity check failure.
    #[error("connectivity check failed: {0}")]
    ConnectivityCheckFailed(String),

    /// No valid candidate pairs.
    #[error("no valid candidate pairs found")]
    NoCandidatePairs,

    /// ICE restart required.
    #[error("ice restart required")]
    RestartRequired,

    /// STUN server unreachable.
    #[error("stun server unreachable: {0}")]
    StunUnreachable(String),

    /// TURN authentication failure.
    #[error("turn authentication failed")]
    TurnAuthFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SbcError::Crypto(CryptoError::CnsaViolation);
        assert!(err
            .to_string()
            .contains("cnsa 2.0 violation: algorithm not permitted"));
    }

    #[test]
    fn test_error_conversion() {
        let transport_err = TransportError::Timeout(5000);
        let sbc_err: SbcError = transport_err.into();
        assert!(matches!(sbc_err, SbcError::Transport(_)));
    }
}
