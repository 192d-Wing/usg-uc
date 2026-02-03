//! API error types.

use std::fmt;

/// API result type.
pub type ApiResult<T> = Result<T, ApiError>;

/// HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    /// OK.
    pub const OK: Self = Self(200);
    /// Created.
    pub const CREATED: Self = Self(201);
    /// No Content.
    pub const NO_CONTENT: Self = Self(204);
    /// Bad Request.
    pub const BAD_REQUEST: Self = Self(400);
    /// Unauthorized.
    pub const UNAUTHORIZED: Self = Self(401);
    /// Forbidden.
    pub const FORBIDDEN: Self = Self(403);
    /// Not Found.
    pub const NOT_FOUND: Self = Self(404);
    /// Method Not Allowed.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// Conflict.
    pub const CONFLICT: Self = Self(409);
    /// Unprocessable Entity.
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);
    /// Too Many Requests.
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    /// Internal Server Error.
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// Service Unavailable.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    /// Returns whether this is a success status.
    pub fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// Returns whether this is a client error.
    pub fn is_client_error(&self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    /// Returns whether this is a server error.
    pub fn is_server_error(&self) -> bool {
        self.0 >= 500 && self.0 < 600
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// API errors.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status code.
    pub status: StatusCode,
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
    /// Additional details.
    pub details: Option<String>,
}

impl ApiError {
    /// Creates a new API error.
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    /// Sets the details.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Creates a bad request error.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    /// Creates an unauthorized error.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message)
    }

    /// Creates a forbidden error.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "FORBIDDEN", message)
    }

    /// Creates a not found error.
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("{} not found", resource.into()),
        )
    }

    /// Creates a conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "CONFLICT", message)
    }

    /// Creates an internal server error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }

    /// Creates a validation error.
    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            format!("{}: {}", field.into(), message.into()),
        )
    }

    /// Creates a rate limit error.
    pub fn rate_limited() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "Rate limit exceeded",
        )
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code() {
        assert!(StatusCode::OK.is_success());
        assert!(!StatusCode::OK.is_client_error());
        assert!(StatusCode::BAD_REQUEST.is_client_error());
        assert!(StatusCode::INTERNAL_SERVER_ERROR.is_server_error());
    }

    #[test]
    fn test_api_error_creation() {
        let error = ApiError::new(StatusCode::BAD_REQUEST, "TEST", "Test error");
        assert_eq!(error.status.0, 400);
        assert_eq!(error.code, "TEST");
    }

    #[test]
    fn test_api_error_with_details() {
        let error = ApiError::bad_request("Invalid input").with_details("Field 'name' is required");
        assert!(error.details.is_some());
    }

    #[test]
    fn test_api_error_helpers() {
        assert_eq!(
            ApiError::unauthorized("test").status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(ApiError::forbidden("test").status, StatusCode::FORBIDDEN);
        assert_eq!(ApiError::not_found("User").status, StatusCode::NOT_FOUND);
        assert_eq!(ApiError::conflict("test").status, StatusCode::CONFLICT);
        assert_eq!(
            ApiError::internal("test").status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_api_error_validation() {
        let error = ApiError::validation("email", "Invalid format");
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("email"));
    }

    #[test]
    fn test_api_error_display() {
        let error = ApiError::bad_request("Invalid input");
        let display = error.to_string();
        assert!(display.contains("400"));
        assert!(display.contains("BAD_REQUEST"));
    }
}
