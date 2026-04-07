//! HiveMind Enterprise Threat Feed API.
//!
//! Provides REST, STIX/TAXII 2.1, and SIEM integration endpoints
//! for consuming verified threat intelligence from the HiveMind mesh.
//!
//! # Modules
//!
//! - `store`        — In-memory verified IoC storage with time-windowed queries
//! - `stix`         — STIX 2.1 types and IoC→STIX indicator conversion
//! - `feed`         — Query parameter parsing, filtering, and pagination
//! - `integrations` — SIEM format exporters (Splunk HEC, QRadar LEEF, CEF)
//! - `licensing`    — API key management and tier-based access control
//! - `server`       — HTTP server with request routing

pub mod feed;
pub mod integrations;
pub mod licensing;
pub mod server;
pub mod stix;
pub mod store;
