//! Cryptographic primitives for HiveMind.
//!
//! Contains gradient encryption:
//! - `fhe` — AES-256-GCM wrapper (`GradientCryptoCtx`) used in V1.0
//! - `fhe_real` — Real TFHE-based homomorphic encryption (feature-gated `fhe-real`)
//!
//! The `FheContext` alias in `fhe` will transparently upgrade to TFHE
//! when the `fhe-real` feature is enabled.

pub mod fhe;

#[cfg(feature = "fhe-real")]
pub mod fhe_real;
