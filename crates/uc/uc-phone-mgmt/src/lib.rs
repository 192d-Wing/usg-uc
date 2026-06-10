//! Phone device management and auto-provisioning for USG SBC.
//!
//! Supports Polycom VVX, Poly Edge, Cisco MPP (6800/7800/8800),
//! Cisco 9800 series, and Teo / Tone Commander 7810/4104/4101 phones.

#![forbid(unsafe_code)]

pub mod cisco_9800;
pub mod cisco_mpp;
pub mod error;
pub mod firmware;
pub mod model;
pub mod poly_edge;
pub mod polycom_vvx;
pub mod provisioning;
pub mod store;
pub mod teo;
