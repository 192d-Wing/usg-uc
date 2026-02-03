//! CDR writer.

use crate::error::{CdrError, CdrResult};
use crate::format::{CdrFormat, CdrFormatter, CsvFormatter, JsonFormatter};
use crate::record::CallRecord;
use crate::{DEFAULT_BUFFER_SIZE, DEFAULT_FLUSH_INTERVAL_SECS};
use std::time::Instant;

/// CDR writer configuration.
#[derive(Debug, Clone)]
pub struct CdrWriterConfig {
    /// Output format.
    pub format: CdrFormat,
    /// Buffer size.
    pub buffer_size: usize,
    /// Flush interval in seconds.
    pub flush_interval_secs: u64,
    /// Output path (file or directory).
    pub output_path: Option<String>,
    /// Whether to include header.
    pub include_header: bool,
}

impl Default for CdrWriterConfig {
    fn default() -> Self {
        Self {
            format: CdrFormat::Json,
            buffer_size: DEFAULT_BUFFER_SIZE,
            flush_interval_secs: DEFAULT_FLUSH_INTERVAL_SECS,
            output_path: None,
            include_header: true,
        }
    }
}

impl CdrWriterConfig {
    /// Sets the format.
    #[must_use]
    pub fn with_format(mut self, format: CdrFormat) -> Self {
        self.format = format;
        self
    }

    /// Sets the buffer size.
    #[must_use]
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Sets the flush interval.
    #[must_use]
    pub fn with_flush_interval(mut self, secs: u64) -> Self {
        self.flush_interval_secs = secs;
        self
    }

    /// Sets the output path.
    #[must_use]
    pub fn with_output_path(mut self, path: impl Into<String>) -> Self {
        self.output_path = Some(path.into());
        self
    }
}

/// CDR writer statistics.
#[derive(Debug, Clone, Default)]
pub struct CdrWriterStats {
    /// Total records written.
    pub records_written: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Number of flushes.
    pub flushes: u64,
    /// Write errors.
    pub errors: u64,
}

/// CDR writer.
#[derive(Debug)]
pub struct CdrWriter {
    /// Configuration.
    config: CdrWriterConfig,
    /// JSON formatter.
    json_formatter: JsonFormatter,
    /// CSV formatter.
    csv_formatter: CsvFormatter,
    /// Buffer.
    buffer: Vec<CallRecord>,
    /// Last flush time.
    last_flush: Instant,
    /// Statistics.
    stats: CdrWriterStats,
    /// Formatted output (for testing/inspection).
    output: Vec<String>,
}

impl CdrWriter {
    /// Creates a new CDR writer.
    pub fn new(config: CdrWriterConfig) -> Self {
        Self {
            config,
            json_formatter: JsonFormatter::new(),
            csv_formatter: CsvFormatter::new(),
            buffer: Vec::new(),
            last_flush: Instant::now(),
            stats: CdrWriterStats::default(),
            output: Vec::new(),
        }
    }

    /// Creates a CDR writer with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CdrWriterConfig::default())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &CdrWriterConfig {
        &self.config
    }

    /// Returns the statistics.
    pub fn stats(&self) -> &CdrWriterStats {
        &self.stats
    }

    /// Returns the buffer size.
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns whether the buffer is full.
    pub fn is_buffer_full(&self) -> bool {
        self.buffer.len() >= self.config.buffer_size
    }

    /// Returns whether a flush is due.
    pub fn is_flush_due(&self) -> bool {
        self.last_flush.elapsed().as_secs() >= self.config.flush_interval_secs
    }

    /// Writes a record.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn write(&mut self, record: CallRecord) -> CdrResult<()> {
        if self.is_buffer_full() {
            return Err(CdrError::BufferFull {
                size: self.buffer.len(),
            });
        }

        self.buffer.push(record);

        // Auto-flush if buffer is full or interval has passed
        if self.is_buffer_full() || self.is_flush_due() {
            self.flush()?;
        }

        Ok(())
    }

    /// Flushes the buffer.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn flush(&mut self) -> CdrResult<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let formatted = self.format_buffer();

        // In a real implementation, this would write to file/network
        // For now, we store in memory for testing
        for line in &formatted {
            self.output.push(line.clone());
            self.stats.bytes_written += line.len() as u64;
        }

        self.stats.records_written += self.buffer.len() as u64;
        self.stats.flushes += 1;
        self.buffer.clear();
        self.last_flush = Instant::now();

        Ok(())
    }

    /// Formats the buffer contents.
    fn format_buffer(&self) -> Vec<String> {
        let mut output = Vec::new();

        // Add header if needed (for CSV)
        if self.config.include_header
            && self.stats.records_written == 0
            && let Some(header) = self.get_formatter().header()
        {
            output.push(header);
        }

        // Format each record
        for record in &self.buffer {
            output.push(self.get_formatter().format(record));
        }

        output
    }

    /// Returns the appropriate formatter.
    fn get_formatter(&self) -> &dyn CdrFormatter {
        match self.config.format {
            CdrFormat::Json => &self.json_formatter,
            CdrFormat::Csv => &self.csv_formatter,
            CdrFormat::Custom => &self.json_formatter, // Fallback to JSON
        }
    }

    /// Returns the output (for testing).
    pub fn output(&self) -> &[String] {
        &self.output
    }

    /// Clears the output buffer.
    pub fn clear_output(&mut self) {
        self.output.clear();
    }

    /// Sets the JSON formatter.
    #[must_use]
    pub fn with_json_formatter(mut self, formatter: JsonFormatter) -> Self {
        self.json_formatter = formatter;
        self
    }

    /// Sets the CSV formatter.
    #[must_use]
    pub fn with_csv_formatter(mut self, formatter: CsvFormatter) -> Self {
        self.csv_formatter = formatter;
        self
    }
}

impl Default for CdrWriter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{CallDirection, CallStatus, DisconnectCause};

    fn test_record(id: &str) -> CallRecord {
        let mut record = CallRecord::new(id, "+15551234567", "+15559876543")
            .with_direction(CallDirection::Outbound)
            .with_source_ip("192.168.1.100")
            .with_dest_ip("10.0.0.1")
            .with_start_time(1704067200000);

        record.status = CallStatus::Completed;
        record.disconnect_cause = DisconnectCause::NormalClearing;
        record.duration_secs = Some(60);

        record
    }

    #[test]
    fn test_writer_config_default() {
        let config = CdrWriterConfig::default();
        assert_eq!(config.format, CdrFormat::Json);
        assert_eq!(config.buffer_size, DEFAULT_BUFFER_SIZE);
    }

    #[test]
    fn test_writer_config_builder() {
        let config = CdrWriterConfig::default()
            .with_format(CdrFormat::Csv)
            .with_buffer_size(500)
            .with_flush_interval(60)
            .with_output_path("/var/log/cdr.csv");

        assert_eq!(config.format, CdrFormat::Csv);
        assert_eq!(config.buffer_size, 500);
        assert_eq!(config.output_path, Some("/var/log/cdr.csv".to_string()));
    }

    #[test]
    fn test_writer_creation() {
        let writer = CdrWriter::with_defaults();
        assert_eq!(writer.buffer_len(), 0);
        assert!(!writer.is_buffer_full());
    }

    #[test]
    fn test_writer_write() {
        let mut writer = CdrWriter::with_defaults();

        writer.write(test_record("call-1")).unwrap();

        assert_eq!(writer.buffer_len(), 1);
    }

    #[test]
    fn test_writer_flush() {
        let mut writer = CdrWriter::with_defaults();

        writer.write(test_record("call-1")).unwrap();
        writer.flush().unwrap();

        assert_eq!(writer.buffer_len(), 0);
        assert_eq!(writer.stats().records_written, 1);
        assert_eq!(writer.stats().flushes, 1);
    }

    #[test]
    fn test_writer_buffer_full() {
        let config = CdrWriterConfig::default().with_buffer_size(2);
        let mut writer = CdrWriter::new(config);

        writer.write(test_record("call-1")).unwrap();
        // This write should trigger auto-flush
        writer.write(test_record("call-2")).unwrap();

        // Should have flushed
        assert!(writer.stats().flushes >= 1);
    }

    #[test]
    fn test_writer_buffer_overflow() {
        let config = CdrWriterConfig::default()
            .with_buffer_size(2)
            .with_flush_interval(3600); // Long interval to prevent auto-flush

        let mut writer = CdrWriter::new(config);

        writer.write(test_record("call-1")).unwrap();

        // Manually fill buffer to max without flush
        writer.buffer.push(test_record("call-2"));

        // This should fail
        let result = writer.write(test_record("call-3"));
        assert!(result.is_err());
    }

    #[test]
    fn test_writer_json_output() {
        let config = CdrWriterConfig::default().with_format(CdrFormat::Json);
        let mut writer = CdrWriter::new(config);

        writer.write(test_record("call-1")).unwrap();
        writer.flush().unwrap();

        assert!(!writer.output().is_empty());
        assert!(writer.output()[0].contains("\"call_id\":\"call-1\""));
    }

    #[test]
    fn test_writer_csv_output() {
        let config = CdrWriterConfig::default().with_format(CdrFormat::Csv);
        let mut writer = CdrWriter::new(config);

        writer.write(test_record("call-1")).unwrap();
        writer.flush().unwrap();

        assert!(writer.output().len() >= 2); // Header + record
        assert!(writer.output()[0].contains("call_id")); // Header
        assert!(writer.output()[1].contains("call-1")); // Data
    }

    #[test]
    fn test_writer_stats() {
        let mut writer = CdrWriter::with_defaults();

        writer.write(test_record("call-1")).unwrap();
        writer.write(test_record("call-2")).unwrap();
        writer.flush().unwrap();

        assert_eq!(writer.stats().records_written, 2);
        assert!(writer.stats().bytes_written > 0);
    }

    #[test]
    fn test_writer_custom_formatter() {
        let config = CdrWriterConfig::default().with_format(CdrFormat::Json);
        let mut writer =
            CdrWriter::new(config).with_json_formatter(JsonFormatter::new().with_pretty(true));

        writer.write(test_record("call-1")).unwrap();
        writer.flush().unwrap();

        // Pretty JSON should have newlines
        assert!(writer.output()[0].contains('\n'));
    }

    #[test]
    fn test_writer_clear_output() {
        let mut writer = CdrWriter::with_defaults();

        writer.write(test_record("call-1")).unwrap();
        writer.flush().unwrap();

        assert!(!writer.output().is_empty());

        writer.clear_output();
        assert!(writer.output().is_empty());
    }
}
