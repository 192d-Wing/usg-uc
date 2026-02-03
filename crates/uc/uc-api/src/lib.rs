//! REST API for SBC management and configuration.
//!
//! This crate provides the HTTP API for runtime configuration,
//! monitoring, and management of the SBC.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AC-3**: Access Enforcement
//! - **CM-6**: Configuration Settings
//! - **AU-2**: Event Logging
//!
//! ## Features
//!
//! - RESTful API endpoints
//! - Request/response types
//! - API versioning
//! - Authentication helpers

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::use_self)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

pub mod error;
pub mod request;
pub mod response;
pub mod routes;

pub use error::{ApiError, ApiResult};
pub use request::{ApiRequest, PaginationParams};
pub use response::{ApiResponse, ListResponse};
pub use routes::{Route, Router};

/// Default API version.
pub const DEFAULT_API_VERSION: &str = "v1";

/// Default page size.
pub const DEFAULT_PAGE_SIZE: usize = 50;

/// Maximum page size.
pub const MAX_PAGE_SIZE: usize = 1000;

#[cfg(test)]
mod tests {
    use super::*;

    const _: () = {
        assert!(DEFAULT_PAGE_SIZE > 0);
        assert!(MAX_PAGE_SIZE >= DEFAULT_PAGE_SIZE);
    };

    #[test]
    fn test_constants() {
        assert!(!DEFAULT_API_VERSION.is_empty());
    }
}
