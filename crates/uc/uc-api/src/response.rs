//! API response types.

use crate::error::StatusCode;
use std::collections::HashMap;

/// API response.
#[derive(Debug, Clone)]
pub struct ApiResponse<T> {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Response body.
    pub body: Option<T>,
}

impl<T> ApiResponse<T> {
    /// Creates a new response.
    pub fn new(status: StatusCode, body: T) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Some(body),
        }
    }

    /// Creates an OK response.
    pub fn ok(body: T) -> Self {
        Self::new(StatusCode::OK, body)
    }

    /// Creates a Created response.
    pub fn created(body: T) -> Self {
        Self::new(StatusCode::CREATED, body)
    }

    /// Adds a header.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Returns whether the response is successful.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }
}

impl ApiResponse<()> {
    /// Creates a No Content response.
    pub fn no_content() -> Self {
        Self {
            status: StatusCode::NO_CONTENT,
            headers: HashMap::new(),
            body: None,
        }
    }
}

/// List response with pagination metadata.
#[derive(Debug, Clone)]
pub struct ListResponse<T> {
    /// Items in this page.
    pub items: Vec<T>,
    /// Total count.
    pub total: usize,
    /// Current page.
    pub page: usize,
    /// Page size.
    pub page_size: usize,
    /// Total pages.
    pub total_pages: usize,
    /// Has more pages.
    pub has_more: bool,
}

impl<T> ListResponse<T> {
    /// Creates a new list response.
    pub fn new(items: Vec<T>, total: usize, page: usize, page_size: usize) -> Self {
        let total_pages = if page_size > 0 {
            (total + page_size - 1) / page_size
        } else {
            0
        };

        Self {
            items,
            total,
            page,
            page_size,
            total_pages,
            has_more: page < total_pages,
        }
    }

    /// Creates an empty list response.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
            page: 1,
            page_size: 0,
            total_pages: 0,
            has_more: false,
        }
    }

    /// Returns the number of items in this page.
    pub fn count(&self) -> usize {
        self.items.len()
    }

    /// Returns whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Single resource response.
#[derive(Debug, Clone)]
pub struct ResourceResponse<T> {
    /// The resource.
    pub data: T,
    /// Resource metadata.
    pub metadata: ResourceMetadata,
}

impl<T> ResourceResponse<T> {
    /// Creates a new resource response.
    pub fn new(data: T) -> Self {
        Self {
            data,
            metadata: ResourceMetadata::default(),
        }
    }

    /// Sets the metadata.
    pub fn with_metadata(mut self, metadata: ResourceMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Resource metadata.
#[derive(Debug, Clone, Default)]
pub struct ResourceMetadata {
    /// Resource ID.
    pub id: Option<String>,
    /// Created timestamp (Unix ms).
    pub created_at: Option<u64>,
    /// Updated timestamp (Unix ms).
    pub updated_at: Option<u64>,
    /// Resource version/ETag.
    pub version: Option<String>,
    /// Additional links.
    pub links: HashMap<String, String>,
}

impl ResourceMetadata {
    /// Creates new metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the ID.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the created timestamp.
    pub fn with_created_at(mut self, timestamp: u64) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Sets the updated timestamp.
    pub fn with_updated_at(mut self, timestamp: u64) -> Self {
        self.updated_at = Some(timestamp);
        self
    }

    /// Sets the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Adds a link.
    pub fn with_link(mut self, rel: impl Into<String>, href: impl Into<String>) -> Self {
        self.links.insert(rel.into(), href.into());
        self
    }
}

/// Error response.
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
    /// Field errors (for validation).
    pub field_errors: Vec<FieldError>,
    /// Request ID.
    pub request_id: Option<String>,
}

impl ErrorResponse {
    /// Creates a new error response.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            field_errors: Vec::new(),
            request_id: None,
        }
    }

    /// Adds a field error.
    pub fn with_field_error(mut self, field: impl Into<String>, message: impl Into<String>) -> Self {
        self.field_errors.push(FieldError {
            field: field.into(),
            message: message.into(),
        });
        self
    }

    /// Sets the request ID.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }
}

/// Field-level error.
#[derive(Debug, Clone)]
pub struct FieldError {
    /// Field name.
    pub field: String,
    /// Error message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_ok() {
        let response: ApiResponse<String> = ApiResponse::ok("Hello".to_string());
        assert!(response.is_success());
        assert_eq!(response.status, StatusCode::OK);
    }

    #[test]
    fn test_api_response_created() {
        let response: ApiResponse<String> = ApiResponse::created("Created".to_string());
        assert_eq!(response.status, StatusCode::CREATED);
    }

    #[test]
    fn test_api_response_no_content() {
        let response = ApiResponse::no_content();
        assert!(response.body.is_none());
    }

    #[test]
    fn test_api_response_with_header() {
        let response: ApiResponse<String> = ApiResponse::ok("test".to_string())
            .with_header("X-Custom", "value");
        assert_eq!(response.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_list_response() {
        let items = vec![1, 2, 3, 4, 5];
        let response = ListResponse::new(items, 100, 1, 5);

        assert_eq!(response.count(), 5);
        assert_eq!(response.total, 100);
        assert_eq!(response.total_pages, 20);
        assert!(response.has_more);
    }

    #[test]
    fn test_list_response_last_page() {
        let items = vec![1, 2, 3];
        let response = ListResponse::new(items, 23, 5, 5);

        assert_eq!(response.total_pages, 5);
        assert!(!response.has_more);
    }

    #[test]
    fn test_list_response_empty() {
        let response: ListResponse<i32> = ListResponse::empty();
        assert!(response.is_empty());
        assert_eq!(response.total, 0);
    }

    #[test]
    fn test_resource_response() {
        let metadata = ResourceMetadata::new()
            .with_id("123")
            .with_created_at(1704067200000)
            .with_version("v1");

        let response = ResourceResponse::new("test data".to_string()).with_metadata(metadata);

        assert_eq!(response.metadata.id, Some("123".to_string()));
    }

    #[test]
    fn test_resource_metadata_links() {
        let metadata = ResourceMetadata::new()
            .with_link("self", "/api/v1/users/123")
            .with_link("collection", "/api/v1/users");

        assert_eq!(metadata.links.len(), 2);
    }

    #[test]
    fn test_error_response() {
        let error = ErrorResponse::new("VALIDATION_ERROR", "Invalid input")
            .with_field_error("email", "Invalid format")
            .with_field_error("name", "Required")
            .with_request_id("req-123");

        assert_eq!(error.field_errors.len(), 2);
        assert_eq!(error.request_id, Some("req-123".to_string()));
    }
}
