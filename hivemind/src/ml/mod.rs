//! Federated Learning subsystem for HiveMind.
//!
//! Implements distributed ML model training for Network Intrusion Detection
//! without sharing raw telemetry. Only FHE-encrypted gradients leave the node.
//!
//! # Biological Analogy
//! - B-cells = Local eBPF sensors (train on local attacks)
//! - T-cells = Aggregators (combine gradients into global model)
//! - Antibodies = Updated JA4/IoC blocklist, distributed to all nodes
//! - Immune memory = Federated model weights (stored locally)

pub mod aggregator;
pub mod defense;
pub mod gradient_share;
pub mod local_model;
