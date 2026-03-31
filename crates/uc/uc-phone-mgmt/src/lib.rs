//! Phone device management and auto-provisioning for USG SBC.
//!
//! Supports Polycom VVX, Poly Edge, Cisco MPP (6800/7800/8800),
//! and Cisco 9800 series phones.

#![forbid(unsafe_code)]
#![deny(warnings)]

pub mod cisco_9800;
pub mod cisco_mpp;
pub mod error;
pub mod firmware;
pub mod model;
pub mod poly_edge;
pub mod polycom_vvx;
pub mod provisioning;
pub mod store;
