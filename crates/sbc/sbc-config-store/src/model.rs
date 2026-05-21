//! Typed models for SBC config entities.
//!
//! The legacy `MemStore` represents DIDs as untyped `serde_json::Value`. The
//! dashboard already imposes a shape (see `crates/sbc/sbc-dashboard/src/
//! pages/Directory.tsx`): `{ did, user?, partition?, description? }`. Make
//! that shape canonical on the server side too, with an `extra` bag so
//! future fields don't require a schema migration in lockstep with the UI.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A directory number — a phone number (DID) routed to a user.
///
/// The `did` is the canonical identifier. `user` is the SIP username that
/// inbound calls to this DID get routed to. `partition` and `description`
/// are operator-facing organizational fields with no effect on routing.
///
/// `extra` carries any forward-compatible fields the dashboard may send
/// that the Rust schema hasn't been taught about yet. They're stored as
/// JSONB so queries can index them later without a column add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryNumber {
    pub did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty", flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl DirectoryNumber {
    /// Build a `DirectoryNumber` from an untyped JSON value (used by the
    /// migration helper and by the existing API handlers, which accept
    /// `serde_json::Value` bodies). Unknown fields are preserved in
    /// `extra`. Missing `did` is an error.
    ///
    /// # Errors
    /// Returns a serialization error if `value` isn't a JSON object or if
    /// `did` is missing/non-string.
    pub fn from_json(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// Serialize back to JSON for handler responses (so existing dashboard
    /// code doesn't have to change shape).
    ///
    /// # Errors
    /// Returns a serialization error if the model contains values that
    /// don't round-trip cleanly (shouldn't happen for these fields).
    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}
