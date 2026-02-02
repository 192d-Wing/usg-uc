//! Integration tests for the USG Unified Communications SBC.
//!
//! This crate contains integration tests that verify the interaction
//! between multiple SBC components.

#![forbid(unsafe_code)]
#![allow(clippy::missing_docs_in_private_items)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

#[cfg(test)]
mod config_tests;

#[cfg(test)]
mod health_tests;

#[cfg(test)]
mod metrics_tests;

#[cfg(test)]
mod policy_tests;
