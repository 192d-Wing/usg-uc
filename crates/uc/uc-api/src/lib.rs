//! REST API for SBC management and configuration.
//!
//! This crate provides route and permission metadata plus request/response
//! types for the SBC management API. It is a library only: it runs no HTTP
//! server and emits no audit events.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AC-3**: Access Enforcement — library-only. Routes are default-deny and
//!   [`Route::authorize`] / [`Router::authorize`] enforce declared
//!   permissions, but enforcement depends on the serving caller invoking
//!   them (POA&M-244: sbc-daemon does not yet call `authorize`).
//! - **CM-6**: Configuration Settings — metadata only (`config:read` /
//!   `config:admin` permissions on the `/config` routes).
//!
//! No AU-2 event logging is performed by this crate.
//!
//! ## Features
//!
//! - RESTful API endpoints
//! - Request/response types
//! - API versioning
//! - Authentication helpers

#![forbid(unsafe_code)]
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

pub mod cdr;
pub mod error;
pub mod request;
pub mod response;
pub mod routes;

pub use cdr::{CdrExportFormat, CdrExportRequest, CdrQueryParams, CdrStats};
pub use error::{ApiError, ApiResult};
pub use request::{ApiRequest, PaginationParams};
pub use response::{ApiResponse, ListResponse};
pub use routes::{Route, Router, SbcRoutes};

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
        assert_ne!(DEFAULT_API_VERSION, "");
    }
}
