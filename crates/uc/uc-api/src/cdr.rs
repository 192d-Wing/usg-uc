//! CDR (Call Detail Record) API types.
//!
//! This module provides request/response types for CDR export endpoints.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging (CDR as audit records)
//! - **AU-3**: Content of Audit Records
//! - **AU-9**: Protection of Audit Information

use std::collections::HashMap;

/// CDR query parameters for filtering.
#[derive(Debug, Clone, Default)]
pub struct CdrQueryParams {
    /// Start time (Unix timestamp in milliseconds).
    pub start_time_ms: Option<u64>,
    /// End time (Unix timestamp in milliseconds).
    pub end_time_ms: Option<u64>,
    /// Filter by caller number.
    pub caller: Option<String>,
    /// Filter by callee number.
    pub callee: Option<String>,
    /// Filter by call status.
    pub status: Option<String>,
    /// Filter by trunk ID.
    pub trunk_id: Option<String>,
    /// Filter by direction (inbound/outbound).
    pub direction: Option<String>,
    /// Filter by disconnect cause.
    pub disconnect_cause: Option<String>,
    /// Minimum duration in seconds.
    pub min_duration_secs: Option<u64>,
    /// Maximum duration in seconds.
    pub max_duration_secs: Option<u64>,
    /// Filter by source IP.
    pub source_ip: Option<String>,
    /// Filter by destination IP.
    pub dest_ip: Option<String>,
}

impl CdrQueryParams {
    /// Creates new CDR query parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the time range filter.
    #[must_use]
    pub fn with_time_range(mut self, start_ms: u64, end_ms: u64) -> Self {
        self.start_time_ms = Some(start_ms);
        self.end_time_ms = Some(end_ms);
        self
    }

    /// Sets the caller filter.
    #[must_use]
    pub fn with_caller(mut self, caller: impl Into<String>) -> Self {
        self.caller = Some(caller.into());
        self
    }

    /// Sets the callee filter.
    #[must_use]
    pub fn with_callee(mut self, callee: impl Into<String>) -> Self {
        self.callee = Some(callee.into());
        self
    }

    /// Sets the status filter.
    #[must_use]
    pub fn with_status(mut self, status: impl Into<String>) -> Self {
        self.status = Some(status.into());
        self
    }

    /// Sets the trunk filter.
    #[must_use]
    pub fn with_trunk(mut self, trunk_id: impl Into<String>) -> Self {
        self.trunk_id = Some(trunk_id.into());
        self
    }

    /// Sets the direction filter.
    #[must_use]
    pub fn with_direction(mut self, direction: impl Into<String>) -> Self {
        self.direction = Some(direction.into());
        self
    }

    /// Sets the duration range filter.
    #[must_use]
    pub fn with_duration_range(mut self, min_secs: u64, max_secs: u64) -> Self {
        self.min_duration_secs = Some(min_secs);
        self.max_duration_secs = Some(max_secs);
        self
    }

    /// Returns whether any filters are set.
    pub fn has_filters(&self) -> bool {
        self.start_time_ms.is_some()
            || self.end_time_ms.is_some()
            || self.caller.is_some()
            || self.callee.is_some()
            || self.status.is_some()
            || self.trunk_id.is_some()
            || self.direction.is_some()
            || self.disconnect_cause.is_some()
            || self.min_duration_secs.is_some()
            || self.max_duration_secs.is_some()
            || self.source_ip.is_some()
            || self.dest_ip.is_some()
    }

    /// Parses from query parameters map.
    pub fn from_query(query: &HashMap<String, String>) -> Self {
        Self {
            start_time_ms: query.get("start_time").and_then(|s| s.parse().ok()),
            end_time_ms: query.get("end_time").and_then(|s| s.parse().ok()),
            caller: query.get("caller").cloned(),
            callee: query.get("callee").cloned(),
            status: query.get("status").cloned(),
            trunk_id: query.get("trunk_id").cloned(),
            direction: query.get("direction").cloned(),
            disconnect_cause: query.get("disconnect_cause").cloned(),
            min_duration_secs: query.get("min_duration").and_then(|s| s.parse().ok()),
            max_duration_secs: query.get("max_duration").and_then(|s| s.parse().ok()),
            source_ip: query.get("source_ip").cloned(),
            dest_ip: query.get("dest_ip").cloned(),
        }
    }
}

/// CDR export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CdrExportFormat {
    /// JSON format (default).
    #[default]
    Json,
    /// CSV format.
    Csv,
}

impl CdrExportFormat {
    /// Parses from string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }

    /// Returns the content type for HTTP responses.
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Csv => "text/csv",
        }
    }

    /// Returns the file extension.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }
}

/// CDR export request parameters.
#[derive(Debug, Clone)]
pub struct CdrExportRequest {
    /// Query filters.
    pub filters: CdrQueryParams,
    /// Export format.
    pub format: CdrExportFormat,
    /// Include header (for CSV).
    pub include_header: bool,
    /// Fields to include (empty means all).
    pub fields: Vec<String>,
    /// Maximum records to export.
    pub limit: Option<usize>,
}

impl Default for CdrExportRequest {
    fn default() -> Self {
        Self {
            filters: CdrQueryParams::default(),
            format: CdrExportFormat::Json,
            include_header: true,
            fields: Vec::new(),
            limit: None,
        }
    }
}

impl CdrExportRequest {
    /// Creates a new export request.
    pub fn new(format: CdrExportFormat) -> Self {
        Self {
            format,
            ..Default::default()
        }
    }

    /// Sets the filters.
    #[must_use]
    pub fn with_filters(mut self, filters: CdrQueryParams) -> Self {
        self.filters = filters;
        self
    }

    /// Sets whether to include header.
    #[must_use]
    pub fn with_header(mut self, include: bool) -> Self {
        self.include_header = include;
        self
    }

    /// Sets the fields to include.
    #[must_use]
    pub fn with_fields(mut self, fields: Vec<String>) -> Self {
        self.fields = fields;
        self
    }

    /// Sets the maximum records.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Parses from query parameters map.
    pub fn from_query(query: &HashMap<String, String>) -> Self {
        let format = query
            .get("format")
            .and_then(|s| CdrExportFormat::from_str(s))
            .unwrap_or_default();

        let include_header = query.get("header").is_none_or(|s| s != "false" && s != "0");

        let fields = query
            .get("fields")
            .map(|s| s.split(',').map(|f| f.trim().to_string()).collect())
            .unwrap_or_default();

        let limit = query.get("limit").and_then(|s| s.parse().ok());

        Self {
            filters: CdrQueryParams::from_query(query),
            format,
            include_header,
            fields,
            limit,
        }
    }
}

/// CDR statistics response.
#[derive(Debug, Clone, Default)]
pub struct CdrStats {
    /// Total number of CDRs.
    pub total_records: u64,
    /// Total completed calls.
    pub completed_calls: u64,
    /// Total failed calls.
    pub failed_calls: u64,
    /// Total call duration in seconds.
    pub total_duration_secs: u64,
    /// Average call duration in seconds.
    pub avg_duration_secs: f64,
    /// Total inbound calls.
    pub inbound_calls: u64,
    /// Total outbound calls.
    pub outbound_calls: u64,
    /// Calls by status.
    pub calls_by_status: HashMap<String, u64>,
    /// Calls by disconnect cause.
    pub calls_by_cause: HashMap<String, u64>,
    /// Calls by trunk.
    pub calls_by_trunk: HashMap<String, u64>,
    /// Time range start (Unix ms).
    pub start_time_ms: Option<u64>,
    /// Time range end (Unix ms).
    pub end_time_ms: Option<u64>,
}

impl CdrStats {
    /// Creates new CDR stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the answer seizure ratio (ASR).
    #[allow(clippy::cast_precision_loss)]
    pub fn answer_seizure_ratio(&self) -> f64 {
        if self.total_records == 0 {
            return 0.0;
        }
        (self.completed_calls as f64 / self.total_records as f64) * 100.0
    }

    /// Returns the failure rate.
    #[allow(clippy::cast_precision_loss)]
    pub fn failure_rate(&self) -> f64 {
        if self.total_records == 0 {
            return 0.0;
        }
        (self.failed_calls as f64 / self.total_records as f64) * 100.0
    }
}

/// CDR search result.
#[derive(Debug, Clone)]
pub struct CdrSearchResult {
    /// Call ID.
    pub call_id: String,
    /// Caller number.
    pub caller: String,
    /// Callee number.
    pub callee: String,
    /// Call status.
    pub status: String,
    /// Start time (Unix ms).
    pub start_time_ms: u64,
    /// Duration in seconds.
    pub duration_secs: Option<u64>,
    /// Trunk ID.
    pub trunk_id: Option<String>,
}

/// CDR purge request.
#[derive(Debug, Clone)]
pub struct CdrPurgeRequest {
    /// Purge records older than this timestamp (Unix ms).
    pub before_time_ms: u64,
    /// Only purge records with specific status.
    pub status: Option<String>,
    /// Dry run (don't actually delete).
    pub dry_run: bool,
}

impl CdrPurgeRequest {
    /// Creates a new purge request.
    pub fn new(before_time_ms: u64) -> Self {
        Self {
            before_time_ms,
            status: None,
            dry_run: false,
        }
    }

    /// Sets the status filter.
    #[must_use]
    pub fn with_status(mut self, status: impl Into<String>) -> Self {
        self.status = Some(status.into());
        self
    }

    /// Sets dry run mode.
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
}

/// CDR purge response.
#[derive(Debug, Clone)]
pub struct CdrPurgeResponse {
    /// Number of records deleted (or would be deleted in dry run).
    pub records_deleted: u64,
    /// Was this a dry run?
    pub dry_run: bool,
    /// Cutoff timestamp used.
    pub before_time_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdr_query_params_default() {
        let params = CdrQueryParams::new();
        assert!(!params.has_filters());
    }

    #[test]
    fn test_cdr_query_params_with_filters() {
        let params = CdrQueryParams::new()
            .with_caller("+15551234567")
            .with_status("completed")
            .with_time_range(1000, 2000);

        assert!(params.has_filters());
        assert_eq!(params.caller, Some("+15551234567".to_string()));
        assert_eq!(params.status, Some("completed".to_string()));
        assert_eq!(params.start_time_ms, Some(1000));
        assert_eq!(params.end_time_ms, Some(2000));
    }

    #[test]
    fn test_cdr_query_params_from_query() {
        let mut query = HashMap::new();
        query.insert("caller".to_string(), "+15551234567".to_string());
        query.insert("start_time".to_string(), "1704067200000".to_string());
        query.insert("status".to_string(), "completed".to_string());

        let params = CdrQueryParams::from_query(&query);
        assert_eq!(params.caller, Some("+15551234567".to_string()));
        assert_eq!(params.start_time_ms, Some(1704067200000));
        assert_eq!(params.status, Some("completed".to_string()));
    }

    #[test]
    fn test_cdr_export_format() {
        assert_eq!(
            CdrExportFormat::from_str("json"),
            Some(CdrExportFormat::Json)
        );
        assert_eq!(CdrExportFormat::from_str("CSV"), Some(CdrExportFormat::Csv));
        assert_eq!(CdrExportFormat::from_str("invalid"), None);

        assert_eq!(CdrExportFormat::Json.content_type(), "application/json");
        assert_eq!(CdrExportFormat::Csv.content_type(), "text/csv");
        assert_eq!(CdrExportFormat::Json.extension(), "json");
        assert_eq!(CdrExportFormat::Csv.extension(), "csv");
    }

    #[test]
    fn test_cdr_export_request() {
        let request = CdrExportRequest::new(CdrExportFormat::Csv)
            .with_header(true)
            .with_fields(vec!["call_id".to_string(), "caller".to_string()])
            .with_limit(1000);

        assert_eq!(request.format, CdrExportFormat::Csv);
        assert!(request.include_header);
        assert_eq!(request.fields.len(), 2);
        assert_eq!(request.limit, Some(1000));
    }

    #[test]
    fn test_cdr_export_request_from_query() {
        let mut query = HashMap::new();
        query.insert("format".to_string(), "csv".to_string());
        query.insert("header".to_string(), "true".to_string());
        query.insert("fields".to_string(), "call_id,caller,callee".to_string());
        query.insert("limit".to_string(), "500".to_string());
        query.insert("caller".to_string(), "+15551234567".to_string());

        let request = CdrExportRequest::from_query(&query);
        assert_eq!(request.format, CdrExportFormat::Csv);
        assert!(request.include_header);
        assert_eq!(request.fields.len(), 3);
        assert_eq!(request.limit, Some(500));
        assert_eq!(request.filters.caller, Some("+15551234567".to_string()));
    }

    #[test]
    fn test_cdr_stats() {
        let mut stats = CdrStats::new();
        stats.total_records = 100;
        stats.completed_calls = 80;
        stats.failed_calls = 20;
        stats.total_duration_secs = 4800;
        stats.avg_duration_secs = 60.0;

        assert!((stats.answer_seizure_ratio() - 80.0).abs() < 0.01);
        assert!((stats.failure_rate() - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_cdr_stats_zero_records() {
        let stats = CdrStats::new();
        assert!((stats.answer_seizure_ratio() - 0.0).abs() < 0.01);
        assert!((stats.failure_rate() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_cdr_purge_request() {
        let request = CdrPurgeRequest::new(1704067200000)
            .with_status("completed")
            .with_dry_run(true);

        assert_eq!(request.before_time_ms, 1704067200000);
        assert_eq!(request.status, Some("completed".to_string()));
        assert!(request.dry_run);
    }
}
