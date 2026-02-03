//! API request types.

use crate::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};
use std::collections::HashMap;

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET method.
    Get,
    /// POST method.
    Post,
    /// PUT method.
    Put,
    /// PATCH method.
    Patch,
    /// DELETE method.
    Delete,
    /// OPTIONS method.
    Options,
    /// HEAD method.
    Head,
}

impl HttpMethod {
    /// Returns the method as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
        }
    }

    /// Parses from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            "OPTIONS" => Some(Self::Options),
            "HEAD" => Some(Self::Head),
            _ => None,
        }
    }

    /// Returns whether this method typically has a body.
    pub fn has_body(&self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch)
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Pagination parameters.
#[derive(Debug, Clone)]
pub struct PaginationParams {
    /// Page number (1-indexed).
    pub page: usize,
    /// Page size.
    pub page_size: usize,
    /// Sort field.
    pub sort_by: Option<String>,
    /// Sort direction.
    pub sort_order: SortOrder,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
            sort_by: None,
            sort_order: SortOrder::Ascending,
        }
    }
}

impl PaginationParams {
    /// Creates new pagination params.
    pub fn new(page: usize, page_size: usize) -> Self {
        Self {
            page: page.max(1),
            page_size: page_size.min(MAX_PAGE_SIZE).max(1),
            ..Default::default()
        }
    }

    /// Sets the sort field.
    pub fn with_sort(mut self, field: impl Into<String>, order: SortOrder) -> Self {
        self.sort_by = Some(field.into());
        self.sort_order = order;
        self
    }

    /// Returns the offset for database queries.
    pub fn offset(&self) -> usize {
        (self.page.saturating_sub(1)) * self.page_size
    }

    /// Returns the limit for database queries.
    pub fn limit(&self) -> usize {
        self.page_size
    }
}

/// Sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum SortOrder {
    /// Ascending order.
    #[default]
    Ascending,
    /// Descending order.
    Descending,
}


impl SortOrder {
    /// Returns as SQL string.
    pub fn as_sql(&self) -> &'static str {
        match self {
            Self::Ascending => "ASC",
            Self::Descending => "DESC",
        }
    }
}

/// API request.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    /// HTTP method.
    pub method: HttpMethod,
    /// Request path.
    pub path: String,
    /// Query parameters.
    pub query: HashMap<String, String>,
    /// Headers.
    pub headers: HashMap<String, String>,
    /// Body (as string).
    pub body: Option<String>,
    /// Request ID.
    pub request_id: Option<String>,
    /// Client IP.
    pub client_ip: Option<String>,
}

impl ApiRequest {
    /// Creates a new request.
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: None,
            request_id: None,
            client_ip: None,
        }
    }

    /// Creates a GET request.
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, path)
    }

    /// Creates a POST request.
    pub fn post(path: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, path)
    }

    /// Creates a PUT request.
    pub fn put(path: impl Into<String>) -> Self {
        Self::new(HttpMethod::Put, path)
    }

    /// Creates a DELETE request.
    pub fn delete(path: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, path)
    }

    /// Adds a query parameter.
    pub fn with_query(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.insert(key.into(), value.into());
        self
    }

    /// Adds a header.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Sets the body.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Sets the request ID.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Sets the client IP.
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Gets a query parameter.
    pub fn query_param(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(std::string::String::as_str)
    }

    /// Gets a header.
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(std::string::String::as_str)
    }

    /// Gets the Authorization header.
    pub fn authorization(&self) -> Option<&str> {
        self.header("Authorization")
    }

    /// Gets the Content-Type header.
    pub fn content_type(&self) -> Option<&str> {
        self.header("Content-Type")
    }

    /// Extracts pagination params from query.
    pub fn pagination(&self) -> PaginationParams {
        let page = self
            .query_param("page")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let page_size = self
            .query_param("page_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_PAGE_SIZE);

        let mut params = PaginationParams::new(page, page_size);

        if let Some(sort) = self.query_param("sort") {
            let order = self
                .query_param("order")
                .map(|o| {
                    if o.to_lowercase() == "desc" {
                        SortOrder::Descending
                    } else {
                        SortOrder::Ascending
                    }
                })
                .unwrap_or_default();
            params = params.with_sort(sort, order);
        }

        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert!(HttpMethod::Post.has_body());
        assert!(!HttpMethod::Get.has_body());
    }

    #[test]
    fn test_http_method_from_str() {
        assert_eq!(HttpMethod::from_str("GET"), Some(HttpMethod::Get));
        assert_eq!(HttpMethod::from_str("post"), Some(HttpMethod::Post));
        assert_eq!(HttpMethod::from_str("invalid"), None);
    }

    #[test]
    fn test_pagination_params() {
        let params = PaginationParams::new(2, 25);
        assert_eq!(params.offset(), 25);
        assert_eq!(params.limit(), 25);
    }

    #[test]
    fn test_pagination_params_bounds() {
        let params = PaginationParams::new(0, 10000);
        assert_eq!(params.page, 1);
        assert_eq!(params.page_size, MAX_PAGE_SIZE);
    }

    #[test]
    fn test_pagination_with_sort() {
        let params = PaginationParams::default().with_sort("name", SortOrder::Descending);
        assert_eq!(params.sort_by, Some("name".to_string()));
        assert_eq!(params.sort_order, SortOrder::Descending);
    }

    #[test]
    fn test_sort_order() {
        assert_eq!(SortOrder::Ascending.as_sql(), "ASC");
        assert_eq!(SortOrder::Descending.as_sql(), "DESC");
    }

    #[test]
    fn test_api_request_creation() {
        let req = ApiRequest::get("/api/v1/users")
            .with_query("page", "1")
            .with_header("Authorization", "Bearer token");

        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, "/api/v1/users");
        assert_eq!(req.query_param("page"), Some("1"));
        assert_eq!(req.authorization(), Some("Bearer token"));
    }

    #[test]
    fn test_api_request_post() {
        let req = ApiRequest::post("/api/v1/users")
            .with_body("{\"name\":\"test\"}")
            .with_header("Content-Type", "application/json");

        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.body.is_some());
        assert_eq!(req.content_type(), Some("application/json"));
    }

    #[test]
    fn test_api_request_pagination() {
        let req = ApiRequest::get("/api/v1/users")
            .with_query("page", "3")
            .with_query("page_size", "25")
            .with_query("sort", "name")
            .with_query("order", "desc");

        let pagination = req.pagination();
        assert_eq!(pagination.page, 3);
        assert_eq!(pagination.page_size, 25);
        assert_eq!(pagination.sort_by, Some("name".to_string()));
        assert_eq!(pagination.sort_order, SortOrder::Descending);
    }
}
