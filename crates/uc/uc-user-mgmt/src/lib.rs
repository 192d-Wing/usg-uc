//! # User Management for USG SBC
//!
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_async)]
#![allow(dead_code)]
//!
//! This crate provides user management and authentication for the USG Session
//! Border Controller, supporting multiple storage backends and DoD PKI
//! certificate validation.
//!
//! ## Storage Backends
//!
//! - **SQLite** (default): Local embedded database via `rusqlite`
//! - **PostgreSQL**: Network database via `sqlx` (feature: `postgres`)
//! - **LDAP**: Directory service integration via `ldap3` (feature: `ldap`)
//!
//! ## Authentication
//!
//! - **SIP Digest**: SHA-256 based HA1 computation and verification
//! - **DoD PKI / mTLS**: X.509 certificate identity extraction (CN, EDIPI, SAN)
//!
//! ## Features
//!
//! | Feature    | Default | Description              |
//! |------------|---------|--------------------------|
//! | `sqlite`   | yes     | SQLite storage backend   |
//! | `postgres` | no      | PostgreSQL backend       |
//! | `ldap`     | no      | LDAP directory backend   |

pub mod digest;
pub mod error;
pub mod model;
pub mod pki;
pub mod store;

#[cfg(feature = "sqlite")]
pub mod sqlite;
