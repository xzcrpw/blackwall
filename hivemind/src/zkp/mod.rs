//! Zero-Knowledge Proof subsystem for HiveMind.
//!
//! # Proof Versions
//! - **v0 (stub)**: SHA256 commitment — no real ZKP.
//! - **v1 (commit-and-sign)**: SHA256 commitment + Ed25519 signature — privacy + non-repudiation.
//! - **v2 (Groth16)**: Real zk-SNARK proof using bellman/bls12_381 — true zero-knowledge.
//!
//! v2 is feature-gated behind `zkp-groth16`. Enable to activate real Groth16 circuits.
//!
//! # Usage
//! The `prover::prove_threat()` and `verifier::verify_threat()` functions
//! auto-select the highest available proof version.

pub mod prover;
pub mod verifier;

#[cfg(feature = "zkp-groth16")]
pub mod circuit;
