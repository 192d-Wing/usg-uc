//! RFC 3264 Offer/Answer Model for SDP.
//!
//! This module implements the rules for creating offers, generating answers,
//! and modifying media sessions per RFC 3264.
//!
//! ## RFC 3264 Compliance
//!
//! - **§4**: Protocol Operation (offer/answer exchange)
//! - **§5**: Generating the Initial Offer
//! - **§6**: Generating the Answer
//! - **§8**: Modifying the Session
//! - **§8.4**: Media Modification Rules
//!
//! ## Media Modification Rules (§8.4)
//!
//! When modifying a session, the following rules apply:
//!
//! 1. The number of media descriptions MUST NOT change
//! 2. The order of media descriptions MUST be preserved
//! 3. To disable a stream, set port to 0
//! 4. To add a stream, use a new SDP exchange
//! 5. Direction attributes can change within constraints

use crate::attribute::{Attribute, AttributeName, Direction};
use crate::error::{SdpError, SdpResult};
use crate::media::{MediaDescription, MediaType, TransportProtocol};
use crate::session::SessionDescription;

/// Result of comparing an offer and answer.
#[derive(Debug, Clone)]
pub struct NegotiationResult {
    /// Whether negotiation succeeded.
    pub success: bool,
    /// Per-media negotiation results.
    pub media_results: Vec<MediaNegotiationResult>,
    /// Negotiation errors, if any.
    pub errors: Vec<String>,
}

/// Result of negotiating a single media description.
#[derive(Debug, Clone)]
pub struct MediaNegotiationResult {
    /// Media index (0-based).
    pub index: usize,
    /// Media type.
    pub media_type: MediaType,
    /// Whether this media stream is active.
    pub active: bool,
    /// Negotiated direction.
    pub direction: Direction,
    /// Negotiated formats (payload types).
    pub formats: Vec<String>,
    /// Whether the answerer rejected this stream.
    pub rejected: bool,
}

/// Media modification action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaModificationAction {
    /// Keep the media stream unchanged.
    Keep,
    /// Disable the media stream (set port to 0).
    Disable,
    /// Change the direction.
    ChangeDirection(Direction),
    /// Hold the stream (sendonly or inactive).
    Hold,
    /// Resume the stream (sendrecv).
    Resume,
}

/// RFC 3264 §8.4 Media modification validator.
///
/// Validates that media modifications comply with RFC 3264 rules.
#[derive(Debug, Default)]
pub struct MediaModificationValidator {
    /// Whether to allow adding media streams (requires new exchange).
    allow_add: bool,
    /// Whether to allow removing media streams (must use port=0 instead).
    allow_remove: bool,
}

impl MediaModificationValidator {
    /// Creates a new validator with default (strict) settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allows adding media streams.
    pub fn allow_add(mut self) -> Self {
        self.allow_add = true;
        self
    }

    /// Validates a modification from original SDP to modified SDP.
    ///
    /// ## RFC 3264 §8.4 Rules
    ///
    /// 1. The number of m= lines MUST NOT decrease (can only add, not remove)
    /// 2. Media descriptions MUST remain in the same order
    /// 3. To disable a stream, port MUST be set to 0
    /// 4. Media type and transport MUST NOT change
    pub fn validate(
        &self,
        original: &SessionDescription,
        modified: &SessionDescription,
    ) -> SdpResult<Vec<MediaModification>> {
        let mut modifications = Vec::new();

        // Rule 1: Cannot have fewer media sections (unless allow_remove is set)
        if modified.media.len() < original.media.len() && !self.allow_remove {
            return Err(SdpError::InvalidModification {
                reason: format!(
                    "RFC 3264 §8.4: Cannot remove media descriptions. Original has {}, modified has {}",
                    original.media.len(),
                    modified.media.len()
                ),
            });
        }

        // Validate each original media section
        for (index, orig_media) in original.media.iter().enumerate() {
            if index >= modified.media.len() {
                // Media was removed (only valid with allow_remove)
                modifications.push(MediaModification {
                    index,
                    modification_type: MediaModificationType::Removed,
                    old_direction: Some(orig_media.direction()),
                    new_direction: None,
                    old_port: orig_media.port,
                    new_port: 0,
                });
                continue;
            }

            let mod_media = &modified.media[index];

            // Rule 4: Media type must not change
            if orig_media.media_type != mod_media.media_type {
                return Err(SdpError::InvalidModification {
                    reason: format!(
                        "RFC 3264 §8.4: Media type cannot change at index {}. Was {}, now {}",
                        index, orig_media.media_type, mod_media.media_type
                    ),
                });
            }

            // Determine modification type
            let modification_type = if mod_media.port == 0 && orig_media.port != 0 {
                MediaModificationType::Disabled
            } else if mod_media.port != 0 && orig_media.port == 0 {
                MediaModificationType::Enabled
            } else if orig_media.direction() != mod_media.direction() {
                MediaModificationType::DirectionChanged
            } else if orig_media.formats != mod_media.formats {
                MediaModificationType::FormatsChanged
            } else {
                MediaModificationType::Unchanged
            };

            modifications.push(MediaModification {
                index,
                modification_type,
                old_direction: Some(orig_media.direction()),
                new_direction: Some(mod_media.direction()),
                old_port: orig_media.port,
                new_port: mod_media.port,
            });
        }

        // Check for added media sections
        if modified.media.len() > original.media.len() {
            if !self.allow_add {
                return Err(SdpError::InvalidModification {
                    reason: format!(
                        "RFC 3264 §8.4: Adding media requires a new offer/answer exchange. \
                         Original has {}, modified has {}",
                        original.media.len(),
                        modified.media.len()
                    ),
                });
            }

            for index in original.media.len()..modified.media.len() {
                let mod_media = &modified.media[index];
                modifications.push(MediaModification {
                    index,
                    modification_type: MediaModificationType::Added,
                    old_direction: None,
                    new_direction: Some(mod_media.direction()),
                    old_port: 0,
                    new_port: mod_media.port,
                });
            }
        }

        Ok(modifications)
    }
}

/// Description of a media modification.
#[derive(Debug, Clone)]
pub struct MediaModification {
    /// Index of the media description.
    pub index: usize,
    /// Type of modification.
    pub modification_type: MediaModificationType,
    /// Original direction (if existed).
    pub old_direction: Option<Direction>,
    /// New direction (if exists).
    pub new_direction: Option<Direction>,
    /// Original port.
    pub old_port: u16,
    /// New port.
    pub new_port: u16,
}

/// Type of media modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaModificationType {
    /// No change.
    Unchanged,
    /// Stream was disabled (port set to 0).
    Disabled,
    /// Stream was re-enabled (port changed from 0).
    Enabled,
    /// Direction changed.
    DirectionChanged,
    /// Formats/codecs changed.
    FormatsChanged,
    /// New media stream added.
    Added,
    /// Media stream removed (not RFC compliant).
    Removed,
}

/// Generates an answer SDP from an offer.
///
/// ## RFC 3264 §6 Answer Generation
///
/// The answer MUST:
/// 1. Have the same number of m= lines as the offer
/// 2. Match media types at each index
/// 3. Select formats from those offered
/// 4. Set appropriate direction based on offer
pub fn generate_answer(
    offer: &SessionDescription,
    local_capabilities: &LocalCapabilities,
) -> SdpResult<SessionDescription> {
    let mut answer = SessionDescription::new(offer.origin.clone());

    // Copy session-level attributes that should be echoed
    if let Some((ufrag, pwd)) = offer.ice_credentials() {
        // Answerer generates its own credentials
        answer.add_attribute(Attribute::new(
            AttributeName::IceUfrag,
            local_capabilities.ice_ufrag.clone(),
        ));
        answer.add_attribute(Attribute::new(
            AttributeName::IcePwd,
            local_capabilities.ice_pwd.clone(),
        ));
        // Note: We still need to know their credentials (ufrag, pwd)
        let _ = ufrag;
        let _ = pwd;
    }

    // Process each media description
    for (index, offer_media) in offer.media.iter().enumerate() {
        let answer_media = generate_media_answer(offer_media, local_capabilities, index)?;
        answer.media.push(answer_media);
    }

    answer.origin.increment_version();

    Ok(answer)
}

/// Generates an answer for a single media description.
fn generate_media_answer(
    offer_media: &MediaDescription,
    capabilities: &LocalCapabilities,
    _index: usize,
) -> SdpResult<MediaDescription> {
    // Check if we support this media type
    let supported = capabilities
        .supported_media
        .iter()
        .find(|m| m.media_type == offer_media.media_type);

    let mut answer_media = MediaDescription::new(
        offer_media.media_type,
        if supported.is_some() {
            capabilities.default_port
        } else {
            0 // Reject by setting port to 0
        },
        offer_media.protocol,
    );

    if let Some(local) = supported {
        // Find common formats
        let common_formats: Vec<String> = offer_media
            .formats
            .iter()
            .filter(|f| local.formats.contains(f))
            .cloned()
            .collect();

        if common_formats.is_empty() {
            // No common formats - reject
            answer_media.port = 0;
        } else {
            answer_media.formats = common_formats;
        }

        // Set direction based on offer direction
        let answer_direction = compute_answer_direction(offer_media.direction(), local.direction);
        answer_media.add_attribute(answer_direction.to_attribute());

        // Copy rtcp-mux if offered and supported
        if offer_media.has_rtcp_mux() && local.supports_rtcp_mux {
            answer_media.add_attribute(Attribute::flag(AttributeName::RtcpMux));
        }
    }

    Ok(answer_media)
}

/// Computes the answer direction based on offer direction and local capability.
///
/// ## RFC 3264 §6.1 Direction Negotiation
///
/// | Offer Direction | Local Capability | Answer Direction |
/// |-----------------|------------------|------------------|
/// | sendrecv        | sendrecv         | sendrecv         |
/// | sendrecv        | sendonly         | recvonly         |
/// | sendrecv        | recvonly         | sendonly         |
/// | sendrecv        | inactive         | inactive         |
/// | sendonly        | *                | recvonly or inactive |
/// | recvonly        | *                | sendonly or inactive |
/// | inactive        | *                | inactive         |
pub fn compute_answer_direction(offer: Direction, local: Direction) -> Direction {
    match (offer, local) {
        // Both want bidirectional
        (Direction::Sendrecv, Direction::Sendrecv) => Direction::Sendrecv,

        // Offer is sendrecv, local has preference
        (Direction::Sendrecv, Direction::Sendonly) => Direction::Recvonly,
        (Direction::Sendrecv, Direction::Recvonly) => Direction::Sendonly,
        (Direction::Sendrecv, Direction::Inactive) => Direction::Inactive,

        // Offer is sendonly, we can only receive
        (Direction::Sendonly, Direction::Sendrecv) => Direction::Recvonly,
        (Direction::Sendonly, Direction::Recvonly) => Direction::Recvonly,
        (Direction::Sendonly, Direction::Sendonly) => Direction::Inactive, // Can't both send
        (Direction::Sendonly, Direction::Inactive) => Direction::Inactive,

        // Offer is recvonly, we can only send
        (Direction::Recvonly, Direction::Sendrecv) => Direction::Sendonly,
        (Direction::Recvonly, Direction::Sendonly) => Direction::Sendonly,
        (Direction::Recvonly, Direction::Recvonly) => Direction::Inactive, // Can't both receive
        (Direction::Recvonly, Direction::Inactive) => Direction::Inactive,

        // Offer is inactive
        (Direction::Inactive, _) => Direction::Inactive,
    }
}

/// Local media capabilities for answer generation.
#[derive(Debug, Clone)]
pub struct LocalCapabilities {
    /// Supported media configurations.
    pub supported_media: Vec<LocalMediaCapability>,
    /// Default port for media.
    pub default_port: u16,
    /// ICE username fragment.
    pub ice_ufrag: String,
    /// ICE password.
    pub ice_pwd: String,
}

impl Default for LocalCapabilities {
    fn default() -> Self {
        Self {
            supported_media: Vec::new(),
            default_port: 9,
            ice_ufrag: String::new(),
            ice_pwd: String::new(),
        }
    }
}

impl LocalCapabilities {
    /// Creates new local capabilities.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a supported media capability.
    pub fn add_media(&mut self, capability: LocalMediaCapability) {
        self.supported_media.push(capability);
    }

    /// Sets ICE credentials.
    pub fn with_ice_credentials(mut self, ufrag: impl Into<String>, pwd: impl Into<String>) -> Self {
        self.ice_ufrag = ufrag.into();
        self.ice_pwd = pwd.into();
        self
    }
}

/// Local capability for a specific media type.
#[derive(Debug, Clone)]
pub struct LocalMediaCapability {
    /// Media type.
    pub media_type: MediaType,
    /// Supported formats/payload types.
    pub formats: Vec<String>,
    /// Preferred direction.
    pub direction: Direction,
    /// Whether RTCP-mux is supported.
    pub supports_rtcp_mux: bool,
    /// Supported transport protocols.
    pub protocols: Vec<TransportProtocol>,
}

impl LocalMediaCapability {
    /// Creates a new media capability.
    pub fn new(media_type: MediaType) -> Self {
        Self {
            media_type,
            formats: Vec::new(),
            direction: Direction::Sendrecv,
            supports_rtcp_mux: true,
            protocols: vec![TransportProtocol::RtpSavp, TransportProtocol::UdpTlsRtpSavpf],
        }
    }

    /// Adds a supported format.
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.formats.push(format.into());
        self
    }

    /// Sets the preferred direction.
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }
}

/// Creates a modified SDP with a stream held.
///
/// ## RFC 3264 §8.4.3 Placing a Call on Hold
///
/// To put a stream on hold, the direction is changed to:
/// - sendonly: if we want to keep sending but stop receiving
/// - inactive: if we want to stop both
pub fn hold_media_stream(
    sdp: &mut SessionDescription,
    media_index: usize,
    hold_type: HoldType,
) -> SdpResult<()> {
    let media = sdp.media.get_mut(media_index).ok_or_else(|| SdpError::InvalidModification {
        reason: format!("media index {} out of bounds", media_index),
    })?;

    // Remove existing direction attribute
    media.attributes.retain(|a| !a.is_direction());

    // Add new direction
    let direction = match hold_type {
        HoldType::SendOnly => Direction::Sendonly,
        HoldType::Inactive => Direction::Inactive,
    };
    media.add_attribute(direction.to_attribute());

    // Increment session version
    sdp.origin.increment_version();

    Ok(())
}

/// Creates a modified SDP with a stream resumed.
///
/// ## RFC 3264 §8.4.3 Resuming from Hold
///
/// To resume from hold, change direction back to sendrecv or recvonly.
pub fn resume_media_stream(
    sdp: &mut SessionDescription,
    media_index: usize,
    direction: Direction,
) -> SdpResult<()> {
    let media = sdp.media.get_mut(media_index).ok_or_else(|| SdpError::InvalidModification {
        reason: format!("media index {} out of bounds", media_index),
    })?;

    // Remove existing direction attribute
    media.attributes.retain(|a| !a.is_direction());

    // Add new direction
    media.add_attribute(direction.to_attribute());

    // Increment session version
    sdp.origin.increment_version();

    Ok(())
}

/// Type of hold operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldType {
    /// Send only (keep sending audio/video but don't receive).
    SendOnly,
    /// Inactive (stop both sending and receiving).
    Inactive,
}

/// Disables a media stream by setting port to 0.
///
/// ## RFC 3264 §8.4 Disabling a Stream
///
/// A stream is disabled by setting its port to 0. The m= line MUST
/// remain in the SDP to preserve ordering.
pub fn disable_media_stream(sdp: &mut SessionDescription, media_index: usize) -> SdpResult<()> {
    let media = sdp.media.get_mut(media_index).ok_or_else(|| SdpError::InvalidModification {
        reason: format!("media index {} out of bounds", media_index),
    })?;

    media.port = 0;

    // Increment session version
    sdp.origin.increment_version();

    Ok(())
}

/// Re-enables a previously disabled media stream.
///
/// ## RFC 3264 §8.4 Re-enabling a Stream
///
/// A disabled stream (port=0) can be re-enabled by setting a new port.
pub fn enable_media_stream(
    sdp: &mut SessionDescription,
    media_index: usize,
    port: u16,
) -> SdpResult<()> {
    if port == 0 {
        return Err(SdpError::InvalidModification {
            reason: "port must be non-zero to enable stream".to_string(),
        });
    }

    let media = sdp.media.get_mut(media_index).ok_or_else(|| SdpError::InvalidModification {
        reason: format!("media index {} out of bounds", media_index),
    })?;

    media.port = port;

    // Increment session version
    sdp.origin.increment_version();

    Ok(())
}

/// Validates an answer against an offer.
///
/// ## RFC 3264 §6 Answer Validation
///
/// Checks that the answer:
/// 1. Has the same number of m= lines as the offer
/// 2. Media types match at each index
/// 3. Formats are a subset of offered formats
/// 4. Direction is valid for the offer direction
pub fn validate_answer(offer: &SessionDescription, answer: &SessionDescription) -> SdpResult<NegotiationResult> {
    let mut result = NegotiationResult {
        success: true,
        media_results: Vec::new(),
        errors: Vec::new(),
    };

    // Rule 1: Same number of m= lines
    if offer.media.len() != answer.media.len() {
        result.success = false;
        result.errors.push(format!(
            "RFC 3264 §6: Answer must have same number of m= lines. Offer has {}, answer has {}",
            offer.media.len(),
            answer.media.len()
        ));
        return Ok(result);
    }

    for (index, (offer_media, answer_media)) in offer.media.iter().zip(answer.media.iter()).enumerate() {
        let media_result = MediaNegotiationResult {
            index,
            media_type: offer_media.media_type,
            active: answer_media.port != 0,
            direction: answer_media.direction(),
            formats: answer_media.formats.clone(),
            rejected: answer_media.port == 0,
        };

        // Rule 2: Media types must match
        if offer_media.media_type != answer_media.media_type {
            result.success = false;
            result.errors.push(format!(
                "RFC 3264 §6: Media type mismatch at index {}. Offer: {}, Answer: {}",
                index, offer_media.media_type, answer_media.media_type
            ));
        }

        // Rule 3: Answer formats must be subset of offer formats (if not rejected)
        if answer_media.port != 0 {
            for fmt in &answer_media.formats {
                if !offer_media.formats.contains(fmt) {
                    result.success = false;
                    result.errors.push(format!(
                        "RFC 3264 §6: Answer format '{}' not in offer at index {}",
                        fmt, index
                    ));
                }
            }
        }

        // Rule 4: Direction must be valid
        if answer_media.port != 0 {
            let valid_direction = validate_answer_direction(offer_media.direction(), answer_media.direction());
            if !valid_direction {
                result.success = false;
                result.errors.push(format!(
                    "RFC 3264 §6: Invalid direction at index {}. Offer: {}, Answer: {}",
                    index,
                    offer_media.direction(),
                    answer_media.direction()
                ));
            }
        }

        result.media_results.push(media_result);
    }

    Ok(result)
}

/// Validates that an answer direction is valid for an offer direction.
fn validate_answer_direction(offer: Direction, answer: Direction) -> bool {
    match offer {
        Direction::Sendrecv => true, // Any answer direction is valid
        Direction::Sendonly => matches!(answer, Direction::Recvonly | Direction::Inactive),
        Direction::Recvonly => matches!(answer, Direction::Sendonly | Direction::Inactive),
        Direction::Inactive => answer == Direction::Inactive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Origin;

    fn create_test_offer() -> SessionDescription {
        let origin = Origin::new("123456");
        let mut sdp = SessionDescription::new(origin);

        let mut audio = MediaDescription::new(MediaType::Audio, 5000, TransportProtocol::RtpSavp);
        audio.formats = vec!["0".to_string(), "8".to_string(), "96".to_string()];
        audio.add_attribute(Attribute::flag(AttributeName::Sendrecv));
        sdp.media.push(audio);

        let mut video = MediaDescription::new(MediaType::Video, 5002, TransportProtocol::RtpSavp);
        video.formats = vec!["97".to_string()];
        video.add_attribute(Attribute::flag(AttributeName::Sendrecv));
        sdp.media.push(video);

        sdp
    }

    #[test]
    fn test_compute_answer_direction() {
        // Both want sendrecv
        assert_eq!(
            compute_answer_direction(Direction::Sendrecv, Direction::Sendrecv),
            Direction::Sendrecv
        );

        // Offer sendrecv, local sendonly -> answer recvonly
        assert_eq!(
            compute_answer_direction(Direction::Sendrecv, Direction::Sendonly),
            Direction::Recvonly
        );

        // Offer sendonly, local sendrecv -> answer recvonly
        assert_eq!(
            compute_answer_direction(Direction::Sendonly, Direction::Sendrecv),
            Direction::Recvonly
        );

        // Offer recvonly, local sendrecv -> answer sendonly
        assert_eq!(
            compute_answer_direction(Direction::Recvonly, Direction::Sendrecv),
            Direction::Sendonly
        );

        // Offer inactive -> always inactive
        assert_eq!(
            compute_answer_direction(Direction::Inactive, Direction::Sendrecv),
            Direction::Inactive
        );
    }

    #[test]
    fn test_validate_answer_direction() {
        // Sendrecv offer accepts any direction
        assert!(validate_answer_direction(Direction::Sendrecv, Direction::Sendrecv));
        assert!(validate_answer_direction(Direction::Sendrecv, Direction::Sendonly));
        assert!(validate_answer_direction(Direction::Sendrecv, Direction::Recvonly));
        assert!(validate_answer_direction(Direction::Sendrecv, Direction::Inactive));

        // Sendonly offer only accepts recvonly or inactive
        assert!(!validate_answer_direction(Direction::Sendonly, Direction::Sendrecv));
        assert!(!validate_answer_direction(Direction::Sendonly, Direction::Sendonly));
        assert!(validate_answer_direction(Direction::Sendonly, Direction::Recvonly));
        assert!(validate_answer_direction(Direction::Sendonly, Direction::Inactive));

        // Inactive offer only accepts inactive
        assert!(validate_answer_direction(Direction::Inactive, Direction::Inactive));
        assert!(!validate_answer_direction(Direction::Inactive, Direction::Sendrecv));
    }

    #[test]
    fn test_media_modification_validator() {
        let original = create_test_offer();
        let mut modified = original.clone();

        // Valid modification: change direction
        modified.media[0]
            .attributes
            .retain(|a| !a.is_direction());
        modified.media[0].add_attribute(Attribute::flag(AttributeName::Sendonly));

        let validator = MediaModificationValidator::new();
        let modifications = validator.validate(&original, &modified).unwrap();

        assert_eq!(modifications.len(), 2);
        assert_eq!(modifications[0].modification_type, MediaModificationType::DirectionChanged);
        assert_eq!(modifications[1].modification_type, MediaModificationType::Unchanged);
    }

    #[test]
    fn test_media_modification_validator_cannot_remove() {
        let original = create_test_offer();
        let mut modified = original.clone();
        modified.media.pop(); // Remove video

        let validator = MediaModificationValidator::new();
        let result = validator.validate(&original, &modified);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot remove"));
    }

    #[test]
    fn test_media_modification_validator_cannot_add() {
        let original = create_test_offer();
        let mut modified = original.clone();

        // Add new media
        let new_media = MediaDescription::new(MediaType::Application, 5004, TransportProtocol::Udp);
        modified.media.push(new_media);

        let validator = MediaModificationValidator::new();
        let result = validator.validate(&original, &modified);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Adding media"));
    }

    #[test]
    fn test_media_modification_validator_allows_add() {
        let original = create_test_offer();
        let mut modified = original.clone();

        // Add new media
        let new_media = MediaDescription::new(MediaType::Application, 5004, TransportProtocol::Udp);
        modified.media.push(new_media);

        let validator = MediaModificationValidator::new().allow_add();
        let modifications = validator.validate(&original, &modified).unwrap();

        assert_eq!(modifications.len(), 3);
        assert_eq!(modifications[2].modification_type, MediaModificationType::Added);
    }

    #[test]
    fn test_media_modification_cannot_change_type() {
        let original = create_test_offer();
        let mut modified = original.clone();

        // Change audio to video (invalid)
        modified.media[0].media_type = MediaType::Video;

        let validator = MediaModificationValidator::new();
        let result = validator.validate(&original, &modified);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Media type cannot change"));
    }

    #[test]
    fn test_disable_media_stream() {
        let mut sdp = create_test_offer();
        assert_eq!(sdp.media[0].port, 5000);

        disable_media_stream(&mut sdp, 0).unwrap();

        assert_eq!(sdp.media[0].port, 0);
        assert_eq!(sdp.origin.session_version, "2"); // Incremented
    }

    #[test]
    fn test_enable_media_stream() {
        let mut sdp = create_test_offer();
        sdp.media[0].port = 0; // Disabled

        enable_media_stream(&mut sdp, 0, 6000).unwrap();

        assert_eq!(sdp.media[0].port, 6000);
    }

    #[test]
    fn test_enable_with_zero_port_fails() {
        let mut sdp = create_test_offer();
        sdp.media[0].port = 0;

        let result = enable_media_stream(&mut sdp, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_hold_media_stream() {
        let mut sdp = create_test_offer();

        hold_media_stream(&mut sdp, 0, HoldType::SendOnly).unwrap();

        assert_eq!(sdp.media[0].direction(), Direction::Sendonly);
    }

    #[test]
    fn test_resume_media_stream() {
        let mut sdp = create_test_offer();

        // Hold first
        hold_media_stream(&mut sdp, 0, HoldType::Inactive).unwrap();
        assert_eq!(sdp.media[0].direction(), Direction::Inactive);

        // Resume
        resume_media_stream(&mut sdp, 0, Direction::Sendrecv).unwrap();
        assert_eq!(sdp.media[0].direction(), Direction::Sendrecv);
    }

    #[test]
    fn test_generate_answer() {
        let offer = create_test_offer();

        let mut capabilities = LocalCapabilities::new()
            .with_ice_credentials("localufrag", "localpassword");
        capabilities.add_media(
            LocalMediaCapability::new(MediaType::Audio)
                .with_format("0")
                .with_format("8"),
        );
        capabilities.add_media(LocalMediaCapability::new(MediaType::Video).with_format("97"));

        let answer = generate_answer(&offer, &capabilities).unwrap();

        assert_eq!(answer.media.len(), 2);
        // Audio should have common formats
        assert!(answer.media[0].formats.contains(&"0".to_string()));
        assert!(answer.media[0].formats.contains(&"8".to_string()));
        assert!(!answer.media[0].formats.contains(&"96".to_string())); // Not supported locally
    }

    #[test]
    fn test_generate_answer_rejects_unsupported() {
        let offer = create_test_offer();

        // Only support audio
        let mut capabilities = LocalCapabilities::new()
            .with_ice_credentials("ufrag", "pwd");
        capabilities.add_media(LocalMediaCapability::new(MediaType::Audio).with_format("0"));

        let answer = generate_answer(&offer, &capabilities).unwrap();

        assert_eq!(answer.media.len(), 2);
        assert!(answer.media[0].port > 0); // Audio accepted
        assert_eq!(answer.media[1].port, 0); // Video rejected
    }

    #[test]
    fn test_validate_answer() {
        let offer = create_test_offer();

        let origin = Origin::new("789");
        let mut answer = SessionDescription::new(origin);

        let mut audio = MediaDescription::new(MediaType::Audio, 6000, TransportProtocol::RtpSavp);
        audio.formats = vec!["0".to_string()]; // Subset of offer
        audio.add_attribute(Attribute::flag(AttributeName::Sendrecv));
        answer.media.push(audio);

        let mut video = MediaDescription::new(MediaType::Video, 0, TransportProtocol::RtpSavp);
        video.formats = vec![];
        answer.media.push(video);

        let result = validate_answer(&offer, &answer).unwrap();

        assert!(result.success);
        assert_eq!(result.media_results.len(), 2);
        assert!(result.media_results[0].active);
        assert!(result.media_results[1].rejected);
    }

    #[test]
    fn test_validate_answer_wrong_media_count() {
        let offer = create_test_offer();

        let origin = Origin::new("789");
        let mut answer = SessionDescription::new(origin);
        let audio = MediaDescription::new(MediaType::Audio, 6000, TransportProtocol::RtpSavp);
        answer.media.push(audio);
        // Missing video

        let result = validate_answer(&offer, &answer).unwrap();

        assert!(!result.success);
        assert!(result.errors[0].contains("same number"));
    }

    #[test]
    fn test_validate_answer_invalid_format() {
        let offer = create_test_offer();

        let origin = Origin::new("789");
        let mut answer = SessionDescription::new(origin);

        let mut audio = MediaDescription::new(MediaType::Audio, 6000, TransportProtocol::RtpSavp);
        audio.formats = vec!["99".to_string()]; // Not in offer!
        answer.media.push(audio);

        let video = MediaDescription::new(MediaType::Video, 0, TransportProtocol::RtpSavp);
        answer.media.push(video);

        let result = validate_answer(&offer, &answer).unwrap();

        assert!(!result.success);
        assert!(result.errors.iter().any(|e| e.contains("format")));
    }
}
