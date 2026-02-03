//! RFC 3550 §7 RTP Translators and Mixers.
//!
//! This module implements RTP translator and mixer functionality per RFC 3550 Section 7.
//!
//! ## RFC 3550 §7 Compliance
//!
//! ### Translators
//!
//! A translator forwards RTP packets with their SSRC unchanged. It is used to:
//! - Bridge between different transport protocols (e.g., unicast to multicast)
//! - Provide protocol conversion (e.g., IPv4 to IPv6)
//! - Perform transcoding (changing payload format)
//!
//! Per §7.1: "For translators not performing transcoding, the SSRC, sequence
//! number, and timestamp fields can all be directly copied from the original
//! RTP header."
//!
//! ### Mixers
//!
//! A mixer combines RTP packets from multiple sources into a single stream
//! with a new SSRC. Per §7.1: "The mixer places its own SSRC identifier in
//! the SSRC field and inserts the list of contributing sources as CSRC
//! identifiers."
//!
//! ## CSRC Handling (RFC 3550 §7.1)
//!
//! The CSRC list identifies the contributing sources when packets are mixed.
//! A maximum of 15 CSRC entries can be included (4-bit CC field).
//!
//! ## RTCP Handling for Translators/Mixers (RFC 3550 §7.2, §7.3)
//!
//! - Translators forward RTCP packets between domains
//! - Mixers generate their own RTCP SR/RR packets
//! - Reception reports are aggregated from all sources

use crate::error::{RtpError, RtpResult};
use crate::packet::{RtpHeader, RtpPacket};
use crate::rtcp::{ReceptionReport, RtcpHeader, RtcpPacket, RtcpType, SenderInfo};
use crate::sequence::SequenceTracker;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;

/// Maximum number of CSRC entries per RFC 3550.
pub const MAX_CSRC_COUNT: usize = 15;

/// State for a single source in a translator/mixer.
#[derive(Debug, Clone)]
pub struct SourceState {
    /// Original source SSRC.
    ssrc: u32,
    /// Sequence number tracker for this source.
    sequence_tracker: SequenceTracker,
    /// Last RTP timestamp received.
    last_timestamp: u32,
    /// Packets received from this source.
    packets_received: u64,
    /// Octets received from this source.
    octets_received: u64,
    /// Whether this source is currently active.
    active: bool,
}

impl SourceState {
    /// Creates a new source state.
    fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            sequence_tracker: SequenceTracker::new(),
            last_timestamp: 0,
            packets_received: 0,
            octets_received: 0,
            active: true,
        }
    }

    /// Returns the source SSRC.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Returns packets received count.
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received
    }

    /// Returns octets received count.
    #[must_use]
    pub fn octets_received(&self) -> u64 {
        self.octets_received
    }

    /// Returns the packet loss fraction.
    #[must_use]
    pub fn loss_fraction(&self) -> f64 {
        self.sequence_tracker.loss_fraction()
    }

    /// Returns the extended highest sequence number.
    #[must_use]
    pub fn extended_highest_seq(&self) -> u64 {
        self.sequence_tracker.extended_seq()
    }

    /// Returns whether this source is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// RTP Translator per RFC 3550 §7.1.
///
/// A translator forwards RTP packets without changing their SSRC.
/// It maintains state for each source to track sequence numbers
/// and detect packet loss.
#[derive(Debug)]
pub struct RtpTranslator {
    /// Source states indexed by SSRC.
    sources: HashMap<u32, SourceState>,
    /// SSRC mapping for translation (original -> translated).
    ssrc_mapping: Option<HashMap<u32, u32>>,
    /// Whether to perform SSRC translation.
    translate_ssrc: bool,
    /// Maximum sources to track.
    max_sources: usize,
}

impl Default for RtpTranslator {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpTranslator {
    /// Creates a new translator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            ssrc_mapping: None,
            translate_ssrc: false,
            max_sources: 256,
        }
    }

    /// Enables SSRC translation with the given mapping.
    #[must_use]
    pub fn with_ssrc_mapping(mut self, mapping: HashMap<u32, u32>) -> Self {
        self.ssrc_mapping = Some(mapping);
        self.translate_ssrc = true;
        self
    }

    /// Sets the maximum number of sources to track.
    #[must_use]
    pub fn with_max_sources(mut self, max: usize) -> Self {
        self.max_sources = max;
        self
    }

    /// Forwards an RTP packet through the translator.
    ///
    /// Per RFC 3550 §7.1: "The SSRC identifier in the RTP header and the
    /// corresponding identifier in any RTCP packets MUST NOT be altered."
    ///
    /// However, if SSRC translation is enabled, the SSRC will be mapped.
    ///
    /// Returns the forwarded packet or an error if the packet should be dropped.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn forward_packet(&mut self, packet: &RtpPacket) -> RtpResult<RtpPacket> {
        let ssrc = packet.header.ssrc;

        // Get or create source state
        if !self.sources.contains_key(&ssrc) {
            if self.sources.len() >= self.max_sources {
                // Exceeded max sources - drop oldest inactive or reject
            }
            self.sources.insert(ssrc, SourceState::new(ssrc));
        }

        let state = self
            .sources
            .get_mut(&ssrc)
            .ok_or_else(|| RtpError::InvalidRtcp {
                reason: "source state not found".to_string(),
            })?;

        // Update sequence tracking
        let is_valid = state.sequence_tracker.update(packet.header.sequence_number);
        if !is_valid {
            // Duplicate packet
            return Err(RtpError::SequenceDiscontinuity {
                expected: state.sequence_tracker.last_seq().unwrap_or(0),
                actual: packet.header.sequence_number,
            });
        }

        // Update statistics
        state.packets_received += 1;
        state.octets_received += packet.payload.len() as u64;
        state.last_timestamp = packet.header.timestamp;
        state.active = true;

        // Create forwarded packet
        let mut forwarded_header = packet.header.clone();

        // Apply SSRC translation if enabled
        if self.translate_ssrc
            && let Some(ref mapping) = self.ssrc_mapping
            && let Some(&new_ssrc) = mapping.get(&ssrc)
        {
            forwarded_header.ssrc = new_ssrc;
        }

        Ok(RtpPacket::new(forwarded_header, packet.payload.clone()))
    }

    /// Returns the state for a specific source.
    #[must_use]
    pub fn get_source(&self, ssrc: u32) -> Option<&SourceState> {
        self.sources.get(&ssrc)
    }

    /// Returns all tracked sources.
    #[must_use]
    pub fn sources(&self) -> &HashMap<u32, SourceState> {
        &self.sources
    }

    /// Returns the number of tracked sources.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Removes inactive sources.
    pub fn prune_inactive(&mut self) {
        self.sources.retain(|_, state| state.active);
    }

    /// Marks all sources as inactive (call periodically).
    pub fn mark_all_inactive(&mut self) {
        for state in self.sources.values_mut() {
            state.active = false;
        }
    }

    /// Generates reception reports for all sources.
    ///
    /// Per RFC 3550 §7.2, translators should forward RTCP, but may also
    /// generate their own reception reports.
    #[must_use]
    pub fn generate_reception_reports(&self) -> Vec<ReceptionReport> {
        self.sources
            .values()
            .map(|state| ReceptionReport {
                ssrc: state.ssrc,
                fraction_lost: (state.loss_fraction() * 256.0) as u8,
                cumulative_lost: state.sequence_tracker.packets_lost() as i32,
                extended_highest_seq: state.extended_highest_seq() as u32,
                jitter: 0, // Would need JitterCalculator per source
                last_sr: 0,
                delay_since_last_sr: 0,
            })
            .collect()
    }
}

/// RTP Mixer per RFC 3550 §7.1.
///
/// A mixer combines RTP packets from multiple sources into a single
/// stream with its own SSRC. The original SSRCs become CSRC entries.
#[derive(Debug)]
pub struct RtpMixer {
    /// The mixer's own SSRC.
    mixer_ssrc: u32,
    /// Current sequence number for output packets.
    output_sequence: u16,
    /// Current timestamp for output packets.
    output_timestamp: u32,
    /// Source states indexed by SSRC.
    sources: HashMap<u32, SourceState>,
    /// Current CSRC list (limited to 15).
    current_csrc: Vec<u32>,
    /// Packets sent by this mixer.
    packets_sent: u64,
    /// Octets sent by this mixer.
    octets_sent: u64,
    /// Maximum sources to track.
    max_sources: usize,
}

impl RtpMixer {
    /// Creates a new mixer with the given SSRC.
    ///
    /// The initial sequence number and timestamp are derived from the SSRC
    /// to provide some randomization per RFC 3550 recommendation.
    #[must_use]
    pub fn new(mixer_ssrc: u32) -> Self {
        // Use SSRC-derived values for initial sequence/timestamp
        // This provides some randomization without requiring rand crate
        let initial_seq = (mixer_ssrc >> 16) as u16;
        let initial_ts = mixer_ssrc.wrapping_mul(0x5BD1_E995);

        Self {
            mixer_ssrc,
            output_sequence: initial_seq,
            output_timestamp: initial_ts,
            sources: HashMap::new(),
            current_csrc: Vec::with_capacity(MAX_CSRC_COUNT),
            packets_sent: 0,
            octets_sent: 0,
            max_sources: 256,
        }
    }

    /// Creates a new mixer with explicit initial values.
    #[must_use]
    pub fn with_initial_values(mixer_ssrc: u32, initial_seq: u16, initial_ts: u32) -> Self {
        Self {
            mixer_ssrc,
            output_sequence: initial_seq,
            output_timestamp: initial_ts,
            sources: HashMap::new(),
            current_csrc: Vec::with_capacity(MAX_CSRC_COUNT),
            packets_sent: 0,
            octets_sent: 0,
            max_sources: 256,
        }
    }

    /// Returns the mixer's SSRC.
    #[must_use]
    pub fn mixer_ssrc(&self) -> u32 {
        self.mixer_ssrc
    }

    /// Sets the maximum number of sources to track.
    #[must_use]
    pub fn with_max_sources(mut self, max: usize) -> Self {
        self.max_sources = max;
        self
    }

    /// Adds a contributing source to the current CSRC list.
    ///
    /// Per RFC 3550 §5.1, at most 15 CSRC entries can be included.
    ///
    /// Returns true if the source was added, false if the list is full.
    pub fn add_contributing_source(&mut self, ssrc: u32) -> bool {
        if self.current_csrc.len() >= MAX_CSRC_COUNT {
            return false;
        }

        if !self.current_csrc.contains(&ssrc) {
            self.current_csrc.push(ssrc);
        }

        true
    }

    /// Removes a contributing source from the CSRC list.
    pub fn remove_contributing_source(&mut self, ssrc: u32) {
        self.current_csrc.retain(|&s| s != ssrc);
    }

    /// Clears the current CSRC list.
    pub fn clear_contributing_sources(&mut self) {
        self.current_csrc.clear();
    }

    /// Returns the current CSRC list.
    #[must_use]
    pub fn contributing_sources(&self) -> &[u32] {
        &self.current_csrc
    }

    /// Processes an input packet from a source.
    ///
    /// This updates the source state but does not produce output.
    /// Use `create_mixed_packet` to generate output.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn process_input(&mut self, packet: &RtpPacket) -> RtpResult<()> {
        let ssrc = packet.header.ssrc;

        // Get or create source state
        let state = self
            .sources
            .entry(ssrc)
            .or_insert_with(|| SourceState::new(ssrc));

        // Update sequence tracking
        state.sequence_tracker.update(packet.header.sequence_number);

        // Update statistics
        state.packets_received += 1;
        state.octets_received += packet.payload.len() as u64;
        state.last_timestamp = packet.header.timestamp;
        state.active = true;

        // Add to CSRC list if not already there
        self.add_contributing_source(ssrc);

        Ok(())
    }

    /// Creates a mixed output packet.
    ///
    /// Per RFC 3550 §7.1: "The mixer places its own SSRC identifier in the
    /// SSRC field and inserts the list of contributing sources as CSRC
    /// identifiers."
    ///
    /// # Arguments
    ///
    /// * `payload_type` - The payload type for the output packet.
    /// * `timestamp_increment` - How much to increment the timestamp.
    /// * `payload` - The mixed payload data.
    /// * `marker` - Whether to set the marker bit.
    #[must_use]
    pub fn create_mixed_packet(
        &mut self,
        payload_type: u8,
        timestamp_increment: u32,
        payload: impl Into<Bytes>,
        marker: bool,
    ) -> RtpPacket {
        let payload = payload.into();

        // Update statistics
        self.packets_sent += 1;
        self.octets_sent += payload.len() as u64;

        // Create header with mixer's SSRC
        let mut header = RtpHeader::new(
            payload_type,
            self.output_sequence,
            self.output_timestamp,
            self.mixer_ssrc,
        );
        header.marker = marker;

        // Add all CSRC entries
        for &csrc in &self.current_csrc {
            header = header.with_csrc(csrc);
        }

        // Increment sequence and timestamp for next packet
        self.output_sequence = self.output_sequence.wrapping_add(1);
        self.output_timestamp = self.output_timestamp.wrapping_add(timestamp_increment);

        RtpPacket::new(header, payload)
    }

    /// Returns the state for a specific source.
    #[must_use]
    pub fn get_source(&self, ssrc: u32) -> Option<&SourceState> {
        self.sources.get(&ssrc)
    }

    /// Returns all tracked sources.
    #[must_use]
    pub fn sources(&self) -> &HashMap<u32, SourceState> {
        &self.sources
    }

    /// Returns the number of contributing sources.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Returns packets sent by this mixer.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    /// Returns octets sent by this mixer.
    #[must_use]
    pub fn octets_sent(&self) -> u64 {
        self.octets_sent
    }

    /// Generates a Sender Report for this mixer.
    ///
    /// Per RFC 3550 §7.3: "Mixers that assemble a stream from
    /// individual contributors MUST send RTCP SR packets."
    #[must_use]
    pub fn generate_sender_report(&self, ntp_timestamp: u64) -> SenderInfo {
        let ntp_high = (ntp_timestamp >> 32) as u32;
        let ntp_low = ntp_timestamp as u32;

        SenderInfo {
            ssrc: self.mixer_ssrc,
            ntp_timestamp_msw: ntp_high,
            ntp_timestamp_lsw: ntp_low,
            rtp_timestamp: self.output_timestamp,
            sender_packet_count: self.packets_sent as u32,
            sender_octet_count: self.octets_sent as u32,
        }
    }

    /// Generates reception reports for all contributing sources.
    #[must_use]
    pub fn generate_reception_reports(&self) -> Vec<ReceptionReport> {
        self.sources
            .values()
            .map(|state| ReceptionReport {
                ssrc: state.ssrc,
                fraction_lost: (state.loss_fraction() * 256.0) as u8,
                cumulative_lost: state.sequence_tracker.packets_lost() as i32,
                extended_highest_seq: state.extended_highest_seq() as u32,
                jitter: 0,
                last_sr: 0,
                delay_since_last_sr: 0,
            })
            .collect()
    }

    /// Removes inactive sources.
    pub fn prune_inactive(&mut self) {
        let inactive: Vec<u32> = self
            .sources
            .iter()
            .filter(|(_, state)| !state.active)
            .map(|(&ssrc, _)| ssrc)
            .collect();

        for ssrc in inactive {
            self.sources.remove(&ssrc);
            self.remove_contributing_source(ssrc);
        }
    }

    /// Marks all sources as inactive.
    pub fn mark_all_inactive(&mut self) {
        for state in self.sources.values_mut() {
            state.active = false;
        }
    }
}

/// Result of validating a CSRC list.
#[derive(Debug, Clone)]
pub struct CsrcValidation {
    /// Whether the CSRC list is valid.
    pub valid: bool,
    /// Number of CSRC entries.
    pub count: usize,
    /// Error message if invalid.
    pub error: Option<String>,
}

/// Validates a CSRC list per RFC 3550.
///
/// The CSRC list must have at most 15 entries and no duplicates.
#[must_use]
pub fn validate_csrc_list(csrc_list: &[u32]) -> CsrcValidation {
    if csrc_list.len() > MAX_CSRC_COUNT {
        return CsrcValidation {
            valid: false,
            count: csrc_list.len(),
            error: Some(format!(
                "CSRC list too long: {} entries, max is {}",
                csrc_list.len(),
                MAX_CSRC_COUNT
            )),
        };
    }

    // Check for duplicates
    let mut seen = std::collections::HashSet::new();
    for &csrc in csrc_list {
        if !seen.insert(csrc) {
            return CsrcValidation {
                valid: false,
                count: csrc_list.len(),
                error: Some(format!("duplicate CSRC: {csrc:#010x}")),
            };
        }
    }

    CsrcValidation {
        valid: true,
        count: csrc_list.len(),
        error: None,
    }
}

/// Detects SSRC collision per RFC 3550 §8.2.
///
/// An SSRC collision occurs when two different sources use the same SSRC.
/// This can be detected by receiving packets with the same SSRC but
/// different source addresses.
#[derive(Debug)]
pub struct SsrcCollisionDetector {
    /// Known SSRC to source address mapping.
    known_sources: HashMap<u32, String>,
}

impl Default for SsrcCollisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SsrcCollisionDetector {
    /// Creates a new collision detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            known_sources: HashMap::new(),
        }
    }

    /// Checks for SSRC collision.
    ///
    /// Returns `Ok(())` if no collision, or an error with the colliding SSRC.
    ///
    /// Per RFC 3550 §8.2: "If an SSRC collision is detected, each participant
    /// chooses a new SSRC value."
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn check(&mut self, ssrc: u32, source_addr: &str) -> RtpResult<()> {
        if let Some(known_addr) = self.known_sources.get(&ssrc) {
            if known_addr != source_addr {
                return Err(RtpError::SsrcCollision { ssrc });
            }
        } else {
            self.known_sources.insert(ssrc, source_addr.to_string());
        }

        Ok(())
    }

    /// Removes a known source.
    pub fn remove(&mut self, ssrc: u32) {
        self.known_sources.remove(&ssrc);
    }

    /// Clears all known sources.
    pub fn clear(&mut self) {
        self.known_sources.clear();
    }
}

/// Builder for creating translator RTCP packets.
#[derive(Debug)]
pub struct TranslatorRtcpBuilder {
    /// SSRC of the translator.
    translator_ssrc: u32,
    /// Reception reports to include.
    reports: Vec<ReceptionReport>,
}

impl TranslatorRtcpBuilder {
    /// Creates a new RTCP builder for a translator.
    #[must_use]
    pub fn new(translator_ssrc: u32) -> Self {
        Self {
            translator_ssrc,
            reports: Vec::new(),
        }
    }

    /// Adds a reception report.
    #[must_use]
    pub fn with_report(mut self, report: ReceptionReport) -> Self {
        self.reports.push(report);
        self
    }

    /// Adds multiple reception reports.
    #[must_use]
    pub fn with_reports(mut self, reports: impl IntoIterator<Item = ReceptionReport>) -> Self {
        self.reports.extend(reports);
        self
    }

    /// Builds a Receiver Report RTCP packet.
    ///
    /// Per RFC 3550 §7.2: "Translators that do not modify the data must
    /// forward SR and RR packets."
    #[must_use]
    pub fn build_receiver_report(&self) -> RtcpPacket {
        let count = self.reports.len().min(31) as u8;
        let mut header = RtcpHeader::new(RtcpType::ReceiverReport, count);

        // Calculate payload size: 4 bytes for SSRC + 24 bytes per report
        let payload_len = 4 + (count as usize) * 24;
        header.length = ((payload_len + 4) / 4 - 1) as u16;

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(self.translator_ssrc);

        for report in self.reports.iter().take(31) {
            payload.put_u32(report.ssrc);
            payload.put_u8(report.fraction_lost);

            // 24-bit cumulative lost
            let lost = report.cumulative_lost & 0x00FF_FFFF;
            payload.put_u8((lost >> 16) as u8);
            payload.put_u8((lost >> 8) as u8);
            payload.put_u8(lost as u8);

            payload.put_u32(report.extended_highest_seq);
            payload.put_u32(report.jitter);
            payload.put_u32(report.last_sr);
            payload.put_u32(report.delay_since_last_sr);
        }

        RtcpPacket::new(header, payload.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translator_forward() {
        let mut translator = RtpTranslator::new();

        let header = RtpHeader::new(0, 100, 1600, 0x12345678);
        let packet = RtpPacket::new(header, vec![0u8; 160]);

        let forwarded = translator.forward_packet(&packet).unwrap();

        assert_eq!(forwarded.header.ssrc, 0x12345678);
        assert_eq!(forwarded.header.sequence_number, 100);
        assert_eq!(forwarded.payload.len(), 160);
        assert_eq!(translator.source_count(), 1);
    }

    #[test]
    fn test_translator_ssrc_mapping() {
        let mut mapping = HashMap::new();
        mapping.insert(0x12345678, 0xABCDEF01);

        let mut translator = RtpTranslator::new().with_ssrc_mapping(mapping);

        let header = RtpHeader::new(0, 100, 1600, 0x12345678);
        let packet = RtpPacket::new(header, vec![0u8; 160]);

        let forwarded = translator.forward_packet(&packet).unwrap();

        assert_eq!(forwarded.header.ssrc, 0xABCDEF01);
    }

    #[test]
    fn test_mixer_create_packet() {
        let mut mixer = RtpMixer::new(0x11111111);

        // Add some contributing sources
        mixer.add_contributing_source(0x22222222);
        mixer.add_contributing_source(0x33333333);

        let packet = mixer.create_mixed_packet(0, 160, vec![0u8; 160], false);

        assert_eq!(packet.header.ssrc, 0x11111111);
        assert_eq!(packet.header.csrc.len(), 2);
        assert!(packet.header.csrc.contains(&0x22222222));
        assert!(packet.header.csrc.contains(&0x33333333));
    }

    #[test]
    fn test_mixer_process_input() {
        let mut mixer = RtpMixer::new(0x11111111);

        // Process packets from two sources
        let header1 = RtpHeader::new(0, 100, 1600, 0x22222222);
        let packet1 = RtpPacket::new(header1, vec![0u8; 80]);

        let header2 = RtpHeader::new(0, 200, 3200, 0x33333333);
        let packet2 = RtpPacket::new(header2, vec![0u8; 80]);

        mixer.process_input(&packet1).unwrap();
        mixer.process_input(&packet2).unwrap();

        assert_eq!(mixer.source_count(), 2);
        assert_eq!(mixer.contributing_sources().len(), 2);
    }

    #[test]
    fn test_csrc_max_count() {
        let mut mixer = RtpMixer::new(0x11111111);

        // Add MAX_CSRC_COUNT sources
        for i in 0..MAX_CSRC_COUNT {
            assert!(mixer.add_contributing_source(i as u32));
        }

        // 16th should fail
        assert!(!mixer.add_contributing_source(0xFFFFFFFF));
        assert_eq!(mixer.contributing_sources().len(), MAX_CSRC_COUNT);
    }

    #[test]
    fn test_validate_csrc_list() {
        // Valid list
        let valid = validate_csrc_list(&[1, 2, 3, 4, 5]);
        assert!(valid.valid);
        assert_eq!(valid.count, 5);

        // Too many entries
        let too_many: Vec<u32> = (0..20).collect();
        let invalid = validate_csrc_list(&too_many);
        assert!(!invalid.valid);
        assert!(invalid.error.is_some());

        // Duplicate entries
        let duplicates = validate_csrc_list(&[1, 2, 3, 2, 4]);
        assert!(!duplicates.valid);
        assert!(duplicates.error.unwrap().contains("duplicate"));
    }

    #[test]
    fn test_ssrc_collision_detector() {
        let mut detector = SsrcCollisionDetector::new();

        // First packet from source
        detector.check(0x12345678, "192.168.1.1:5000").unwrap();

        // Same SSRC from same source - OK
        detector.check(0x12345678, "192.168.1.1:5000").unwrap();

        // Same SSRC from different source - collision!
        let result = detector.check(0x12345678, "192.168.1.2:5000");
        assert!(matches!(result, Err(RtpError::SsrcCollision { .. })));
    }

    #[test]
    fn test_translator_reception_reports() {
        let mut translator = RtpTranslator::new();

        // Process some packets
        for seq in 100..110 {
            let header = RtpHeader::new(0, seq, (seq as u32) * 160, 0x12345678);
            let packet = RtpPacket::new(header, vec![0u8; 160]);
            translator.forward_packet(&packet).unwrap();
        }

        let reports = translator.generate_reception_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].ssrc, 0x12345678);
    }

    #[test]
    fn test_mixer_sender_report() {
        let mut mixer = RtpMixer::new(0x11111111);

        // Send some packets
        for _ in 0..10 {
            let _ = mixer.create_mixed_packet(0, 160, vec![0u8; 160], false);
        }

        let sr = mixer.generate_sender_report(0x12345678_9ABCDEF0);

        assert_eq!(sr.ssrc, 0x11111111);
        assert_eq!(sr.sender_packet_count, 10);
        assert_eq!(sr.sender_octet_count, 1600);
    }

    #[test]
    fn test_rtcp_builder() {
        let builder = TranslatorRtcpBuilder::new(0x11111111).with_report(ReceptionReport {
            ssrc: 0x22222222,
            fraction_lost: 25,
            cumulative_lost: 10,
            extended_highest_seq: 1000,
            jitter: 100,
            last_sr: 0,
            delay_since_last_sr: 0,
        });

        let packet = builder.build_receiver_report();

        assert_eq!(packet.header.packet_type, RtcpType::ReceiverReport);
        assert_eq!(packet.header.count, 1);
    }

    #[test]
    fn test_source_state() {
        let state = SourceState::new(0x12345678);

        assert_eq!(state.ssrc(), 0x12345678);
        assert_eq!(state.packets_received(), 0);
        assert!(state.is_active());
    }
}
