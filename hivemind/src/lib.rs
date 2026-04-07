//! HiveMind P2P Threat Intelligence Mesh.
//!
//! Library crate exposing the core P2P modules for the HiveMind daemon.
//! Each module handles a specific aspect of the P2P networking stack:
//!
//! - `transport` — libp2p Swarm with Noise+QUIC, composite NetworkBehaviour
//! - `dht`       — Kademlia DHT for structured peer routing and IoC storage
//! - `gossip`    — GossipSub for epidemic IoC broadcast
//! - `bootstrap` — Initial peer discovery (hardcoded nodes + mDNS)
//! - `config`    — TOML-based configuration

pub mod bootstrap;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod dht;
pub mod gossip;
pub mod identity;
pub mod metrics_bridge;
pub mod ml;
pub mod reputation;
pub mod sybil_guard;
pub mod transport;
pub mod zkp;
