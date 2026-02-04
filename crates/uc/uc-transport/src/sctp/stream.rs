//! SCTP stream management (RFC 9260 Section 5).
//!
//! This module implements per-stream state tracking including:
//! - Stream Sequence Number (SSN) management for ordered delivery
//! - Reorder buffers for out-of-order data
//! - Support for both ordered and unordered delivery modes

use bytes::Bytes;
use std::collections::{BTreeMap, HashMap, VecDeque};

use super::chunk::DataChunk;

// =============================================================================
// Stream
// =============================================================================

/// Per-stream state for SCTP associations.
///
/// Each stream maintains its own sequence numbers and reorder buffer
/// for ordered delivery. Unordered messages bypass the reorder buffer.
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct Stream {
    /// Stream identifier.
    stream_id: u16,
    /// Next outbound Stream Sequence Number.
    next_ssn_out: u16,
    /// Expected inbound Stream Sequence Number for ordered delivery.
    expected_ssn_in: u16,
    /// Whether this stream uses ordered delivery by default.
    default_ordered: bool,
    /// Reorder buffer for out-of-order ordered messages.
    /// Key is SSN, value is the data chunk.
    reorder_buffer: BTreeMap<u16, DataChunk>,
    /// Messages ready for delivery (in order).
    delivery_queue: VecDeque<Bytes>,
    /// Fragment buffer for ongoing reassembly.
    /// Key is SSN (for ordered) or TSN (for unordered), value is accumulated fragments.
    fragment_buffer: FragmentBuffer,
}

/// Buffer for accumulating message fragments.
#[derive(Debug, Default)]
struct FragmentBuffer {
    /// Fragments being assembled, keyed by SSN for ordered or arbitrary key for unordered.
    /// Value is (accumulated_data, is_unordered, expected_next_tsn).
    ongoing: HashMap<u16, FragmentState>,
}

#[derive(Debug)]
struct FragmentState {
    /// Accumulated data from fragments so far.
    data: Vec<u8>,
    /// TSN of the last fragment received.
    last_tsn: u32,
    /// Whether this is an unordered message.
    #[allow(dead_code)]
    is_unordered: bool,
}

impl FragmentBuffer {
    /// Starts a new fragment assembly or returns existing one.
    fn start_or_get(&mut self, ssn: u16, first_chunk: &DataChunk) -> &mut FragmentState {
        self.ongoing.entry(ssn).or_insert_with(|| FragmentState {
            data: Vec::new(),
            last_tsn: first_chunk.tsn,
            is_unordered: first_chunk.unordered,
        })
    }

    /// Adds data to an ongoing assembly.
    fn add_fragment(&mut self, ssn: u16, chunk: &DataChunk) -> Option<Bytes> {
        let state = self.ongoing.get_mut(&ssn)?;

        // Verify TSN ordering (should be sequential)
        // Note: In a full implementation, we'd track and validate TSN order
        state.data.extend_from_slice(&chunk.data);
        state.last_tsn = chunk.tsn;

        // If this is the ending fragment, complete the assembly
        if chunk.ending {
            let complete_data = std::mem::take(&mut state.data);
            self.ongoing.remove(&ssn);
            return Some(Bytes::from(complete_data));
        }

        None
    }

    /// Checks if there's an ongoing assembly for the given SSN.
    fn has_ongoing(&self, ssn: u16) -> bool {
        self.ongoing.contains_key(&ssn)
    }

    /// Clears all ongoing assemblies.
    fn clear(&mut self) {
        self.ongoing.clear();
    }
}

impl Stream {
    /// Creates a new stream with the given ID.
    pub fn new(stream_id: u16, default_ordered: bool) -> Self {
        Self {
            stream_id,
            next_ssn_out: 0,
            expected_ssn_in: 0,
            default_ordered,
            reorder_buffer: BTreeMap::new(),
            delivery_queue: VecDeque::new(),
            fragment_buffer: FragmentBuffer::default(),
        }
    }

    /// Returns true if this stream uses ordered delivery by default.
    pub fn is_ordered(&self) -> bool {
        self.default_ordered
    }

    /// Returns the stream ID.
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// Returns and increments the next outbound SSN.
    pub fn next_ssn(&mut self) -> u16 {
        let ssn = self.next_ssn_out;
        self.next_ssn_out = self.next_ssn_out.wrapping_add(1);
        ssn
    }

    /// Returns the current expected inbound SSN.
    pub fn expected_ssn(&self) -> u16 {
        self.expected_ssn_in
    }

    /// Processes an incoming DATA chunk for this stream.
    ///
    /// For ordered delivery, out-of-order chunks are buffered until
    /// all preceding chunks arrive. For unordered delivery, chunks
    /// are immediately available.
    ///
    /// Handles fragmentation: if B (beginning) flag is set, starts a new assembly.
    /// If E (ending) flag is set, completes the assembly and delivers the message.
    /// Single-fragment messages have both B and E flags set.
    ///
    /// Returns true if one or more messages became available for delivery.
    #[allow(clippy::missing_panics_doc)] // Unwrap is safe after start_or_get
    pub fn receive_data(&mut self, chunk: DataChunk) -> bool {
        // Handle fragmentation (RFC 9260 Section 6.9)
        // B=1, E=1: Single unfragmented message
        // B=1, E=0: First fragment
        // B=0, E=0: Middle fragment
        // B=0, E=1: Last fragment

        let ssn = chunk.ssn;
        let is_beginning = chunk.beginning;
        let is_ending = chunk.ending;

        // Handle unordered messages
        if chunk.unordered {
            return self.receive_unordered_data(chunk);
        }

        // For ordered delivery, we need to handle fragments within SSN context
        // Complete message (single fragment)
        if is_beginning && is_ending {
            return self.receive_ordered_complete(chunk);
        }

        // Fragment handling
        if is_beginning {
            // Start of fragmented message - safe to unwrap as start_or_get just inserted it
            self.fragment_buffer.start_or_get(ssn, &chunk);
            if let Some(state) = self.fragment_buffer.ongoing.get_mut(&ssn) {
                state.data.extend_from_slice(&chunk.data);
            }
        } else if self.fragment_buffer.has_ongoing(ssn) {
            // Continuation or end of fragmented message
            if let Some(complete_data) = self.fragment_buffer.add_fragment(ssn, &chunk) {
                // Message complete - deliver it
                return self.deliver_ordered_message(ssn, complete_data);
            }
        }
        // Middle or end fragment without a beginning, or waiting for more fragments
        false
    }

    /// Receives a complete ordered message (single fragment).
    fn receive_ordered_complete(&mut self, chunk: DataChunk) -> bool {
        let ssn = chunk.ssn;

        if ssn == self.expected_ssn_in {
            // This is the next expected chunk
            self.delivery_queue.push_back(chunk.data);
            self.expected_ssn_in = self.expected_ssn_in.wrapping_add(1);

            // Check if any buffered chunks can now be delivered
            self.flush_reorder_buffer();
            true
        } else if Self::ssn_gt(ssn, self.expected_ssn_in) {
            // Future chunk - buffer it
            self.reorder_buffer.insert(ssn, chunk);
            false
        } else {
            // Old/duplicate chunk - ignore
            false
        }
    }

    /// Delivers a complete ordered message after fragment assembly.
    fn deliver_ordered_message(&mut self, ssn: u16, data: Bytes) -> bool {
        if ssn == self.expected_ssn_in {
            self.delivery_queue.push_back(data);
            self.expected_ssn_in = self.expected_ssn_in.wrapping_add(1);
            self.flush_reorder_buffer();
            true
        } else if Self::ssn_gt(ssn, self.expected_ssn_in) {
            // Create a synthetic chunk for reordering
            let chunk = DataChunk {
                tsn: 0,
                stream_id: self.stream_id,
                ssn,
                ppid: 0,
                data,
                immediate: false,
                unordered: false,
                beginning: true,
                ending: true,
            };
            self.reorder_buffer.insert(ssn, chunk);
            false
        } else {
            // Old SSN - ignore
            false
        }
    }

    /// Receives unordered data (fragments or complete).
    fn receive_unordered_data(&mut self, chunk: DataChunk) -> bool {
        // For unordered, use TSN as the key (cast to u16 for simplicity)
        // Note: This is a simplification; a full implementation would track by TSN
        let key = (chunk.tsn & 0xFFFF) as u16;

        if chunk.beginning && chunk.ending {
            // Complete unordered message
            self.delivery_queue.push_back(chunk.data);
            return true;
        }

        if chunk.beginning {
            // Start of unordered fragmented message
            self.fragment_buffer.start_or_get(key, &chunk);
            if let Some(state) = self.fragment_buffer.ongoing.get_mut(&key) {
                state.data.extend_from_slice(&chunk.data);
            }
        } else if let Some(complete_data) = self
            .fragment_buffer
            .has_ongoing(key)
            .then(|| self.fragment_buffer.add_fragment(key, &chunk))
            .flatten()
        {
            self.delivery_queue.push_back(complete_data);
            return true;
        }
        // Fragment without beginning, or waiting for more fragments
        false
    }

    /// Flushes any consecutive chunks from the reorder buffer.
    fn flush_reorder_buffer(&mut self) {
        while let Some(chunk) = self.reorder_buffer.remove(&self.expected_ssn_in) {
            self.delivery_queue.push_back(chunk.data);
            self.expected_ssn_in = self.expected_ssn_in.wrapping_add(1);
        }
    }

    /// Takes the next message available for delivery, if any.
    pub fn take_message(&mut self) -> Option<Bytes> {
        self.delivery_queue.pop_front()
    }

    /// Returns true if there are messages available for delivery.
    pub fn has_messages(&self) -> bool {
        !self.delivery_queue.is_empty()
    }

    /// Returns the number of messages in the reorder buffer.
    pub fn reorder_buffer_size(&self) -> usize {
        self.reorder_buffer.len()
    }

    /// Returns the number of messages ready for delivery.
    pub fn delivery_queue_size(&self) -> usize {
        self.delivery_queue.len()
    }

    /// Compares two SSNs using serial number arithmetic (RFC 9260 Section 1.6).
    ///
    /// Returns true if `a > b` in the serial number space.
    fn ssn_gt(a: u16, b: u16) -> bool {
        // Serial number arithmetic for 16-bit values
        let diff = a.wrapping_sub(b);
        diff > 0 && diff < 32768
    }

    /// Resets the stream to initial state.
    pub fn reset(&mut self) {
        self.next_ssn_out = 0;
        self.expected_ssn_in = 0;
        self.reorder_buffer.clear();
        self.delivery_queue.clear();
        self.fragment_buffer.clear();
    }

    /// Advances the expected incoming SSN for this stream (RFC 3758).
    ///
    /// This is used when processing FORWARD-TSN chunks to skip abandoned
    /// ordered data. Any buffered data with SSN <= new_ssn is discarded.
    pub fn advance_expected_ssn(&mut self, new_ssn: u16) {
        // Only advance if the new SSN is ahead
        if Self::ssn_gt(new_ssn, self.expected_ssn_in)
            || new_ssn == self.expected_ssn_in.wrapping_add(1)
        {
            // Remove any reordered messages that would be skipped
            let old_expected = self.expected_ssn_in;
            self.expected_ssn_in = new_ssn.wrapping_add(1);

            // Remove buffered messages with SSN that was skipped
            // Keep only messages with SSN > new_ssn (i.e., ssn >= new_ssn+1)
            self.reorder_buffer.retain(|&ssn, _| Self::ssn_gt(ssn, new_ssn));

            // Also clear any ongoing fragment assemblies for skipped SSNs
            self.fragment_buffer
                .ongoing
                .retain(|&ssn, _| Self::ssn_gt(ssn, new_ssn));

            tracing::debug!(
                stream_id = self.stream_id,
                old_expected = old_expected,
                new_expected = self.expected_ssn_in,
                "Advanced expected SSN via FORWARD-TSN"
            );
        }
    }
}

// =============================================================================
// StreamManager
// =============================================================================

/// Manages all streams for an SCTP association.
///
/// Per RFC 4168, stream 0 is reserved for SIP signaling.
#[derive(Debug)]
pub struct StreamManager {
    /// Maximum number of outbound streams.
    max_outbound_streams: u16,
    /// Maximum number of inbound streams.
    max_inbound_streams: u16,
    /// Per-stream state.
    streams: HashMap<u16, Stream>,
    /// Default ordered delivery mode for new streams.
    default_ordered: bool,
}

impl StreamManager {
    /// Stream 0 is reserved for SIP signaling (RFC 4168).
    pub const SIP_SIGNALING_STREAM: u16 = 0;

    /// Creates a new stream manager.
    pub fn new(max_outbound_streams: u16, max_inbound_streams: u16, default_ordered: bool) -> Self {
        let mut manager = Self {
            max_outbound_streams,
            max_inbound_streams,
            streams: HashMap::new(),
            default_ordered,
        };

        // Pre-create stream 0 for SIP signaling
        manager.get_or_create_stream(Self::SIP_SIGNALING_STREAM);
        manager
    }

    /// Returns the maximum number of outbound streams.
    pub fn max_outbound_streams(&self) -> u16 {
        self.max_outbound_streams
    }

    /// Returns the maximum number of inbound streams.
    pub fn max_inbound_streams(&self) -> u16 {
        self.max_inbound_streams
    }

    /// Gets an existing stream or creates a new one if it doesn't exist.
    pub fn get_or_create_stream(&mut self, stream_id: u16) -> &mut Stream {
        self.streams
            .entry(stream_id)
            .or_insert_with(|| Stream::new(stream_id, self.default_ordered))
    }

    /// Gets an existing stream.
    pub fn get_stream(&self, stream_id: u16) -> Option<&Stream> {
        self.streams.get(&stream_id)
    }

    /// Gets a mutable reference to an existing stream.
    pub fn get_stream_mut(&mut self, stream_id: u16) -> Option<&mut Stream> {
        self.streams.get_mut(&stream_id)
    }

    /// Validates that a stream ID is within allowed bounds.
    pub fn is_valid_outbound_stream(&self, stream_id: u16) -> bool {
        stream_id < self.max_outbound_streams
    }

    /// Validates that an inbound stream ID is within allowed bounds.
    pub fn is_valid_inbound_stream(&self, stream_id: u16) -> bool {
        stream_id < self.max_inbound_streams
    }

    /// Allocates the next SSN for sending on a stream.
    ///
    /// Creates the stream if it doesn't exist.
    pub fn allocate_ssn(&mut self, stream_id: u16) -> u16 {
        self.get_or_create_stream(stream_id).next_ssn()
    }

    /// Processes an incoming DATA chunk.
    ///
    /// Returns `Ok(true)` if data became available for delivery,
    /// `Err` if the stream ID is invalid.
    pub fn receive_data(&mut self, chunk: DataChunk) -> Result<bool, StreamError> {
        let stream_id = chunk.stream_id;

        if !self.is_valid_inbound_stream(stream_id) {
            return Err(StreamError::InvalidStreamId { stream_id });
        }

        let stream = self.get_or_create_stream(stream_id);
        Ok(stream.receive_data(chunk))
    }

    /// Takes the next available message from any stream.
    ///
    /// Returns the stream ID and message data, or None if no messages available.
    pub fn take_message(&mut self) -> Option<(u16, Bytes)> {
        // Round-robin through streams to avoid starvation
        // For simplicity, just iterate in order for now
        for (stream_id, stream) in &mut self.streams {
            if let Some(data) = stream.take_message() {
                return Some((*stream_id, data));
            }
        }
        None
    }

    /// Takes the next available message from a specific stream.
    pub fn take_message_from_stream(&mut self, stream_id: u16) -> Option<Bytes> {
        self.streams.get_mut(&stream_id)?.take_message()
    }

    /// Returns true if any stream has messages available.
    pub fn has_messages(&self) -> bool {
        self.streams.values().any(Stream::has_messages)
    }

    /// Returns the total number of messages buffered across all streams.
    pub fn total_buffered_messages(&self) -> usize {
        self.streams.values().map(Stream::reorder_buffer_size).sum()
    }

    /// Returns the number of active streams.
    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Resets all streams to initial state.
    pub fn reset(&mut self) {
        for stream in self.streams.values_mut() {
            stream.reset();
        }
    }

    /// Iterates over all stream IDs.
    pub fn stream_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.streams.keys().copied()
    }

    /// Advances the expected SSN for a peer's stream (RFC 3758).
    ///
    /// This is used when processing FORWARD-TSN chunks to skip abandoned
    /// ordered data from the peer.
    pub fn advance_peer_ssn(&mut self, stream_id: u16, new_ssn: u16) {
        // Get or create the stream (if receiving data from a new stream)
        let stream = self.get_or_create_stream(stream_id);
        stream.advance_expected_ssn(new_ssn);
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Stream-related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// Invalid stream identifier.
    InvalidStreamId {
        /// The invalid stream ID.
        stream_id: u16,
    },
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStreamId { stream_id } => {
                write!(f, "invalid stream identifier: {stream_id}")
            }
        }
    }
}

impl std::error::Error for StreamError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data_chunk(stream_id: u16, ssn: u16, data: &[u8], unordered: bool) -> DataChunk {
        DataChunk {
            tsn: 0, // Not used for stream tests
            stream_id,
            ssn,
            ppid: 0,
            data: Bytes::copy_from_slice(data),
            immediate: false,
            unordered,
            beginning: true,
            ending: true,
        }
    }

    #[test]
    fn test_stream_ordered_in_order() {
        let mut stream = Stream::new(0, true);

        // Receive chunks in order
        assert!(stream.receive_data(make_data_chunk(0, 0, b"first", false)));
        assert!(stream.receive_data(make_data_chunk(0, 1, b"second", false)));
        assert!(stream.receive_data(make_data_chunk(0, 2, b"third", false)));

        // All should be immediately available
        assert_eq!(stream.take_message(), Some(Bytes::from("first")));
        assert_eq!(stream.take_message(), Some(Bytes::from("second")));
        assert_eq!(stream.take_message(), Some(Bytes::from("third")));
        assert_eq!(stream.take_message(), None);
    }

    #[test]
    fn test_stream_ordered_out_of_order() {
        let mut stream = Stream::new(0, true);

        // Receive chunk 2 first (out of order)
        assert!(!stream.receive_data(make_data_chunk(0, 2, b"third", false)));
        assert_eq!(stream.reorder_buffer_size(), 1);

        // Receive chunk 1 (still missing 0)
        assert!(!stream.receive_data(make_data_chunk(0, 1, b"second", false)));
        assert_eq!(stream.reorder_buffer_size(), 2);

        // No messages available yet
        assert!(!stream.has_messages());

        // Receive chunk 0 - should flush all
        assert!(stream.receive_data(make_data_chunk(0, 0, b"first", false)));
        assert_eq!(stream.reorder_buffer_size(), 0);
        assert_eq!(stream.delivery_queue_size(), 3);

        // All available in order
        assert_eq!(stream.take_message(), Some(Bytes::from("first")));
        assert_eq!(stream.take_message(), Some(Bytes::from("second")));
        assert_eq!(stream.take_message(), Some(Bytes::from("third")));
    }

    #[test]
    fn test_stream_unordered() {
        let mut stream = Stream::new(0, true);

        // Unordered chunks bypass reorder buffer
        assert!(stream.receive_data(make_data_chunk(0, 5, b"unordered1", true)));
        assert!(stream.receive_data(make_data_chunk(0, 3, b"unordered2", true)));

        assert_eq!(stream.reorder_buffer_size(), 0);
        assert_eq!(stream.take_message(), Some(Bytes::from("unordered1")));
        assert_eq!(stream.take_message(), Some(Bytes::from("unordered2")));
    }

    #[test]
    fn test_stream_ssn_allocation() {
        let mut stream = Stream::new(0, true);

        assert_eq!(stream.next_ssn(), 0);
        assert_eq!(stream.next_ssn(), 1);
        assert_eq!(stream.next_ssn(), 2);
    }

    #[test]
    fn test_stream_ssn_wrap() {
        let mut stream = Stream::new(0, true);
        stream.next_ssn_out = u16::MAX;

        assert_eq!(stream.next_ssn(), u16::MAX);
        assert_eq!(stream.next_ssn(), 0); // Wrapped
    }

    #[test]
    fn test_stream_duplicate_ssn() {
        let mut stream = Stream::new(0, true);

        // Receive SSN 0
        assert!(stream.receive_data(make_data_chunk(0, 0, b"first", false)));

        // Duplicate SSN 0 should be ignored
        assert!(!stream.receive_data(make_data_chunk(0, 0, b"duplicate", false)));

        // Only one message available
        assert_eq!(stream.take_message(), Some(Bytes::from("first")));
        assert_eq!(stream.take_message(), None);
    }

    #[test]
    fn test_stream_reset() {
        let mut stream = Stream::new(0, true);

        stream.receive_data(make_data_chunk(0, 0, b"data", false));
        stream.receive_data(make_data_chunk(0, 2, b"buffered", false));

        stream.reset();

        assert_eq!(stream.expected_ssn(), 0);
        assert_eq!(stream.reorder_buffer_size(), 0);
        assert_eq!(stream.delivery_queue_size(), 0);
    }

    #[test]
    fn test_stream_manager_creation() {
        let manager = StreamManager::new(10, 10, true);

        assert_eq!(manager.max_outbound_streams(), 10);
        assert_eq!(manager.max_inbound_streams(), 10);
        assert_eq!(manager.active_stream_count(), 1); // Stream 0 pre-created
    }

    #[test]
    fn test_stream_manager_receive_data() {
        let mut manager = StreamManager::new(10, 10, true);

        // Receive on stream 0 (pre-created)
        let result = manager.receive_data(make_data_chunk(0, 0, b"stream0", false));
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Receive on stream 5 (created on demand)
        let result = manager.receive_data(make_data_chunk(5, 0, b"stream5", false));
        assert!(result.is_ok());
        assert!(result.unwrap());

        assert_eq!(manager.active_stream_count(), 2);
    }

    #[test]
    fn test_stream_manager_invalid_stream() {
        let mut manager = StreamManager::new(5, 5, true);

        // Stream 10 is beyond max_inbound_streams
        let result = manager.receive_data(make_data_chunk(10, 0, b"invalid", false));
        assert!(matches!(
            result,
            Err(StreamError::InvalidStreamId { stream_id: 10 })
        ));
    }

    #[test]
    fn test_stream_manager_take_message() {
        let mut manager = StreamManager::new(10, 10, true);

        manager
            .receive_data(make_data_chunk(0, 0, b"msg1", false))
            .unwrap();
        manager
            .receive_data(make_data_chunk(3, 0, b"msg2", false))
            .unwrap();

        assert!(manager.has_messages());

        let msg = manager.take_message();
        assert!(msg.is_some());

        let msg = manager.take_message();
        assert!(msg.is_some());

        let msg = manager.take_message();
        assert!(msg.is_none());
    }

    #[test]
    fn test_stream_manager_allocate_ssn() {
        let mut manager = StreamManager::new(10, 10, true);

        assert_eq!(manager.allocate_ssn(0), 0);
        assert_eq!(manager.allocate_ssn(0), 1);
        assert_eq!(manager.allocate_ssn(5), 0);
        assert_eq!(manager.allocate_ssn(5), 1);
    }

    #[test]
    fn test_ssn_serial_arithmetic() {
        // Normal case
        assert!(Stream::ssn_gt(5, 3));
        assert!(!Stream::ssn_gt(3, 5));
        assert!(!Stream::ssn_gt(5, 5));

        // Wrap-around case
        assert!(Stream::ssn_gt(0, u16::MAX)); // 0 > 65535 in serial arithmetic
        assert!(Stream::ssn_gt(100, u16::MAX - 100));
    }
}
