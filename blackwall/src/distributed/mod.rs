//! Distributed coordination module for multi-instance Blackwall deployments.
//!
//! Enables multiple Blackwall nodes to share threat intelligence via a
//! simple peer-to-peer protocol over TCP. Nodes exchange blocked IPs,
//! JA4 fingerprints, and behavioral observations.

pub mod peer;
pub mod proto;

#[allow(unused_imports)]
pub use peer::{broadcast_block, PeerManager};
