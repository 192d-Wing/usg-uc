//! Integration tests for the Windows SIP Soft Client.
//!
//! This crate contains integration tests that verify the interaction
//! between multiple client components end-to-end.
//!
//! ## Test Categories
//!
//! - **Certificate Tests**: Certificate store, selection, and DTLS configuration
//! - **Registration Tests**: SIP REGISTER flow with mock server
//! - **Call Flow Tests**: Outbound/inbound call establishment
//! - **Two-Client Tests**: End-to-end calls between two client instances
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **CA-8**: Penetration Testing
//! - **SA-11**: Developer Testing and Evaluation
//! - **IA-5**: Authenticator Management (certificate tests)

#![forbid(unsafe_code)]
#![allow(clippy::missing_docs_in_private_items)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

#[cfg(test)]
mod certificate_tests;

#[cfg(test)]
mod registration_tests;

#[cfg(test)]
mod call_flow_tests;

#[cfg(test)]
mod test_utils;

#[cfg(all(test, feature = "two_client"))]
mod two_client_tests;
