//! CDR formatting.

use crate::record::CallRecord;

/// CDR output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CdrFormat {
    /// JSON format.
    #[default]
    Json,
    /// CSV format.
    Csv,
    /// Custom format.
    Custom,
}

/// Trait for CDR formatters.
pub trait CdrFormatter {
    /// Formats a call record.
    fn format(&self, record: &CallRecord) -> String;

    /// Returns the file extension for this format.
    fn extension(&self) -> &'static str;

    /// Returns the content type for this format.
    fn content_type(&self) -> &'static str;

    /// Returns the header (if any).
    fn header(&self) -> Option<String> {
        None
    }
}

/// JSON formatter.
#[derive(Debug, Clone, Default)]
pub struct JsonFormatter {
    /// Whether to pretty print.
    pub pretty: bool,
}

impl JsonFormatter {
    /// Creates a new JSON formatter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables pretty printing.
    #[must_use]
    pub fn with_pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }

    /// Escapes a string for JSON.
    fn escape_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                _ => result.push(c),
            }
        }
        result
    }
}

impl JsonFormatter {
    /// Adds required fields to the JSON parts.
    fn add_required_fields(parts: &mut Vec<String>, record: &CallRecord) {
        parts.push(format!(
            "\"call_id\":\"{}\"",
            Self::escape_string(&record.call_id)
        ));
        parts.push(format!("\"direction\":\"{}\"", record.direction));
        parts.push(format!(
            "\"caller\":\"{}\"",
            Self::escape_string(&record.caller)
        ));
        parts.push(format!(
            "\"callee\":\"{}\"",
            Self::escape_string(&record.callee)
        ));
        parts.push(format!(
            "\"source_ip\":\"{}\"",
            Self::escape_string(&record.source_ip)
        ));
        parts.push(format!(
            "\"dest_ip\":\"{}\"",
            Self::escape_string(&record.dest_ip)
        ));
        parts.push(format!("\"status\":\"{}\"", record.status));
        parts.push(format!(
            "\"disconnect_cause\":\"{}\"",
            record.disconnect_cause
        ));
        parts.push(format!("\"start_time_ms\":{}", record.start_time_ms));
    }

    /// Adds optional string fields to the JSON parts.
    fn add_optional_fields(parts: &mut Vec<String>, record: &CallRecord) {
        if let Some(ref corr_id) = record.correlation_id {
            parts.push(format!(
                "\"correlation_id\":\"{}\"",
                Self::escape_string(corr_id)
            ));
        }
        if let Some(ref orig) = record.original_callee {
            parts.push(format!(
                "\"original_callee\":\"{}\"",
                Self::escape_string(orig)
            ));
        }
        if let Some(ref trunk) = record.trunk_id {
            parts.push(format!("\"trunk_id\":\"{}\"", Self::escape_string(trunk)));
        }
        if let Some(ref codec) = record.codec {
            parts.push(format!("\"codec\":\"{}\"", Self::escape_string(codec)));
        }
        if let Some(ref media) = record.media_type {
            parts.push(format!("\"media_type\":\"{}\"", Self::escape_string(media)));
        }
    }

    /// Adds optional numeric fields to the JSON parts.
    fn add_timing_fields(parts: &mut Vec<String>, record: &CallRecord) {
        if let Some(connect_ms) = record.connect_time_ms {
            parts.push(format!("\"connect_time_ms\":{connect_ms}"));
        }
        if let Some(end_ms) = record.end_time_ms {
            parts.push(format!("\"end_time_ms\":{end_ms}"));
        }
        if let Some(setup_ms) = record.setup_duration_ms {
            parts.push(format!("\"setup_duration_ms\":{setup_ms}"));
        }
        if let Some(duration) = record.duration_secs {
            parts.push(format!("\"duration_secs\":{duration}"));
        }
    }

    /// Formats custom fields as a nested JSON object.
    fn format_custom_fields(&self, record: &CallRecord) -> Option<String> {
        if record.custom_fields.is_empty() {
            return None;
        }

        let custom_sep = if self.pretty { ",\n    " } else { "," };
        let custom_start = if self.pretty { "{\n    " } else { "{" };
        let custom_end = if self.pretty { "\n  }" } else { "}" };

        let custom_parts: Vec<String> = record
            .custom_fields
            .iter()
            .map(|(k, v)| {
                format!(
                    "\"{}\":\"{}\"",
                    Self::escape_string(k),
                    Self::escape_string(v)
                )
            })
            .collect();

        Some(format!(
            "\"custom_fields\":{}{}{}",
            custom_start,
            custom_parts.join(custom_sep),
            custom_end
        ))
    }
}

impl CdrFormatter for JsonFormatter {
    fn format(&self, record: &CallRecord) -> String {
        let sep = if self.pretty { ",\n  " } else { "," };
        let start = if self.pretty { "{\n  " } else { "{" };
        let end = if self.pretty { "\n}" } else { "}" };

        let mut parts = Vec::new();
        Self::add_required_fields(&mut parts, record);
        Self::add_optional_fields(&mut parts, record);
        Self::add_timing_fields(&mut parts, record);

        if let Some(custom) = self.format_custom_fields(record) {
            parts.push(custom);
        }

        format!("{}{}{}", start, parts.join(sep), end)
    }

    fn extension(&self) -> &'static str {
        "json"
    }

    fn content_type(&self) -> &'static str {
        "application/json"
    }
}

/// CSV formatter.
#[derive(Debug, Clone)]
pub struct CsvFormatter {
    /// Delimiter.
    pub delimiter: char,
    /// Quote character.
    pub quote: char,
    /// Fields to include.
    pub fields: Vec<String>,
}

impl Default for CsvFormatter {
    fn default() -> Self {
        Self {
            delimiter: ',',
            quote: '"',
            fields: vec![
                "call_id".to_string(),
                "direction".to_string(),
                "caller".to_string(),
                "callee".to_string(),
                "source_ip".to_string(),
                "dest_ip".to_string(),
                "status".to_string(),
                "disconnect_cause".to_string(),
                "start_time_ms".to_string(),
                "connect_time_ms".to_string(),
                "end_time_ms".to_string(),
                "duration_secs".to_string(),
            ],
        }
    }
}

impl CsvFormatter {
    /// Creates a new CSV formatter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the delimiter.
    #[must_use]
    pub fn with_delimiter(mut self, delimiter: char) -> Self {
        self.delimiter = delimiter;
        self
    }

    /// Sets the fields to include.
    #[must_use]
    pub fn with_fields(mut self, fields: Vec<String>) -> Self {
        self.fields = fields;
        self
    }

    /// Escapes a value for CSV.
    fn escape_value(&self, value: &str) -> String {
        if value.contains(self.delimiter) || value.contains(self.quote) || value.contains('\n') {
            let escaped = value.replace(self.quote, &format!("{}{}", self.quote, self.quote));
            format!("{}{}{}", self.quote, escaped, self.quote)
        } else {
            value.to_string()
        }
    }

    /// Gets a field value from the record.
    fn get_field(&self, record: &CallRecord, field: &str) -> String {
        let _ = self; // Silence unused_self - method may use self in future for caching
        match field {
            "call_id" => record.call_id.clone(),
            "correlation_id" => record.correlation_id.clone().unwrap_or_default(),
            "direction" => record.direction.to_string(),
            "caller" => record.caller.clone(),
            "callee" => record.callee.clone(),
            "original_callee" => record.original_callee.clone().unwrap_or_default(),
            "source_ip" => record.source_ip.clone(),
            "dest_ip" => record.dest_ip.clone(),
            "trunk_id" => record.trunk_id.clone().unwrap_or_default(),
            "status" => record.status.to_string(),
            "disconnect_cause" => record.disconnect_cause.to_string(),
            "start_time_ms" => record.start_time_ms.to_string(),
            "connect_time_ms" => record
                .connect_time_ms
                .map(|v| v.to_string())
                .unwrap_or_default(),
            "end_time_ms" => record
                .end_time_ms
                .map(|v| v.to_string())
                .unwrap_or_default(),
            "setup_duration_ms" => record
                .setup_duration_ms
                .map(|v| v.to_string())
                .unwrap_or_default(),
            "duration_secs" => record
                .duration_secs
                .map(|v| v.to_string())
                .unwrap_or_default(),
            "codec" => record.codec.clone().unwrap_or_default(),
            "media_type" => record.media_type.clone().unwrap_or_default(),
            _ => record.custom_fields.get(field).cloned().unwrap_or_default(),
        }
    }
}

impl CdrFormatter for CsvFormatter {
    fn format(&self, record: &CallRecord) -> String {
        let values: Vec<String> = self
            .fields
            .iter()
            .map(|f| self.escape_value(&self.get_field(record, f)))
            .collect();

        values.join(&self.delimiter.to_string())
    }

    fn extension(&self) -> &'static str {
        "csv"
    }

    fn content_type(&self) -> &'static str {
        "text/csv"
    }

    fn header(&self) -> Option<String> {
        Some(self.fields.join(&self.delimiter.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{CallDirection, CallStatus, DisconnectCause};

    fn test_record() -> CallRecord {
        let mut record = CallRecord::new("call-123", "+15551234567", "+15559876543")
            .with_direction(CallDirection::Outbound)
            .with_source_ip("192.168.1.100")
            .with_dest_ip("10.0.0.1")
            .with_trunk("trunk-1")
            .with_start_time(1704067200000);

        record.status = CallStatus::Completed;
        record.disconnect_cause = DisconnectCause::NormalClearing;
        record.connect_time_ms = Some(1704067201000);
        record.end_time_ms = Some(1704067261000);
        record.duration_secs = Some(60);

        record
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter::new();
        let record = test_record();
        let json = formatter.format(&record);

        assert!(json.contains("\"call_id\":\"call-123\""));
        assert!(json.contains("\"caller\":\"+15551234567\""));
        assert!(json.contains("\"status\":\"completed\""));
    }

    #[test]
    fn test_json_formatter_pretty() {
        let formatter = JsonFormatter::new().with_pretty(true);
        let record = test_record();
        let json = formatter.format(&record);

        assert!(json.contains('\n'));
    }

    #[test]
    fn test_json_escape() {
        let record = CallRecord::new("call-123", "alice\"bob", "test\nuser");
        let formatter = JsonFormatter::new();
        let json = formatter.format(&record);

        assert!(json.contains("alice\\\"bob"));
        assert!(json.contains("test\\nuser"));
    }

    #[test]
    fn test_json_extension() {
        let formatter = JsonFormatter::new();
        assert_eq!(formatter.extension(), "json");
        assert_eq!(formatter.content_type(), "application/json");
    }

    #[test]
    fn test_csv_formatter() {
        let formatter = CsvFormatter::new();
        let record = test_record();
        let csv = formatter.format(&record);

        assert!(csv.contains("call-123"));
        assert!(csv.contains("+15551234567"));
        assert!(csv.contains("completed"));
    }

    #[test]
    fn test_csv_header() {
        let formatter = CsvFormatter::new();
        let header = formatter.header();

        assert!(header.is_some());
        let header = header.unwrap();
        assert!(header.contains("call_id"));
        assert!(header.contains("caller"));
    }

    #[test]
    fn test_csv_escape() {
        let record = CallRecord::new("call,123", "alice", "bob");
        let formatter = CsvFormatter::new();
        let csv = formatter.format(&record);

        // Should be quoted because it contains a comma
        assert!(csv.contains("\"call,123\""));
    }

    #[test]
    fn test_csv_custom_delimiter() {
        let formatter = CsvFormatter::new().with_delimiter(';');
        let record = test_record();
        let csv = formatter.format(&record);

        assert!(csv.contains(';'));
        assert!(!csv.contains(','));
    }

    #[test]
    fn test_csv_custom_fields() {
        let formatter = CsvFormatter::new().with_fields(vec![
            "call_id".to_string(),
            "caller".to_string(),
            "callee".to_string(),
        ]);
        let record = test_record();
        let csv = formatter.format(&record);

        // Should only have 2 commas (3 fields)
        assert_eq!(csv.matches(',').count(), 2);
    }

    #[test]
    fn test_csv_extension() {
        let formatter = CsvFormatter::new();
        assert_eq!(formatter.extension(), "csv");
        assert_eq!(formatter.content_type(), "text/csv");
    }

    #[test]
    fn test_cdr_format_default() {
        assert_eq!(CdrFormat::default(), CdrFormat::Json);
    }
}
