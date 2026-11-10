//! Call Detail Records: schema v1, formatting, integrity and durable sinks.
//!
//! The crate is SBC-agnostic: producers fill a [`CallRecord`] and hand it to
//! a [`CdrEmitter`], which never blocks the caller. A dedicated writer
//! thread applies the PII policy, assigns the per-node sequence, seals the
//! SHA-384 hash chain and writes a rotated local file (JSONL or CSV), any
//! secondary sinks (RFC 5424 syslog over a TLS stream) and an in-memory ring
//! for management queries. [`verify_file`] checks a JSONL file offline.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2 / AU-12**: Event Logging, Audit Record Generation
//! - **AU-3 / AU-3(1)**: Content of Audit Records
//! - **AU-4 / AU-5**: Storage capacity (rotation, retention); failure response
//!   (drop counting, health, fail closed at startup)
//! - **AU-9 (partial) / AU-9(2)**: tamper-evident SHA-384 hash chain and per-file
//!   digest (unkeyed, no AU-10 non-repudiation; see `chain`), optional off-host copy
//! - **AU-11 / SI-12**: Retention and PII handling (mask, HMAC-SHA-384)
//! - **SC-5**: Bounded queue, ring, field lengths
//!
//! CNSA 2.0: SHA-384 and HMAC-SHA-384 through `uc-crypto` only.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

pub mod chain;
pub mod error;
pub mod format;
pub mod pii;
pub mod record;
pub mod ring;
pub mod sink;
pub mod writer;

pub use chain::{VerifyReport, verify_file, verify_files, verify_reader, verify_sidecar};
pub use error::{CdrError, CdrResult};
pub use format::CdrFormat;
pub use pii::{HmacKey, PiiPolicy};
pub use record::{
    Attestation, CallRecord, Direction, Disposition, FileHeader, MAX_MEDIA_KINDS,
    MIN_READ_SCHEMA_VERSION, MediaKindTag, RecordingTag, ReleaseCause, ReleaseSide, SCHEMA_VERSION,
    Transport, TrunkAttempt, TrunkOutcome, Verstat, is_readable_schema, note_media_kind,
};
pub use ring::{CdrFilter, CdrPage, CdrRing};
pub use sink::{
    CdrObserver, CdrSink, FileSink, FileSinkConfig, SyslogConnector, SyslogSink, SyslogSinkConfig,
};
pub use writer::{CdrEmitter, CdrEmitterConfig, CdrHealth, CdrReload, CdrStats};
