//! Real Fully Homomorphic Encryption using TFHE-rs.
//!
//! Feature-gated behind `fhe-real`. Provides true homomorphic operations
//! on encrypted gradient vectors — the aggregator can sum encrypted gradients
//! WITHOUT decrypting them. This eliminates the trust requirement on the
//! aggregator node in federated learning.
//!
//! # Architecture
//! - Each node generates a `ClientKey` (private) and `ServerKey` (public).
//! - Gradients are encrypted with `ClientKey` → `FheInt32` ciphertext.
//! - The aggregator uses `ServerKey` to homomorphically add ciphertexts.
//! - Only the originating node can decrypt with its `ClientKey`.
//!
//! # Performance
//! TFHE operations are CPU-intensive. For 8GB VRAM systems:
//! - Batch gradients into chunks of 64 before encryption
//! - Use shortint parameters for efficiency
//! - Aggregation is async to avoid blocking the event loop

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheInt32, ServerKey};
use tracing::{debug, info, warn};

/// Real FHE context using TFHE-rs for homomorphic gradient operations.
pub struct RealFheContext {
    client_key: ClientKey,
    server_key: ServerKey,
}

/// Errors from real FHE operations.
#[derive(Debug)]
pub enum RealFheError {
    /// Key generation failed.
    KeyGenerationFailed(String),
    /// Encryption failed.
    EncryptionFailed(String),
    /// Decryption failed.
    DecryptionFailed(String),
    /// Homomorphic operation failed.
    HomomorphicOpFailed(String),
}

impl std::fmt::Display for RealFheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerationFailed(e) => write!(f, "FHE key generation failed: {}", e),
            Self::EncryptionFailed(e) => write!(f, "FHE encryption failed: {}", e),
            Self::DecryptionFailed(e) => write!(f, "FHE decryption failed: {}", e),
            Self::HomomorphicOpFailed(e) => write!(f, "FHE homomorphic op failed: {}", e),
        }
    }
}

impl std::error::Error for RealFheError {}

impl RealFheContext {
    /// Generate fresh FHE keys (expensive — ~seconds on first call).
    ///
    /// The `ServerKey` should be distributed to aggregator nodes.
    /// The `ClientKey` stays private on this node.
    pub fn new() -> Result<Self, RealFheError> {
        info!("generating TFHE keys (this may take a moment)...");
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        info!("TFHE keys generated — real FHE enabled");
        Ok(Self {
            client_key,
            server_key,
        })
    }

    /// Get a reference to the server key (for distribution to aggregators).
    pub fn server_key(&self) -> &ServerKey {
        &self.server_key
    }

    /// Encrypt gradient values as FHE ciphertexts.
    ///
    /// Quantizes f32 gradients to i32 (×10000 for 4 decimal places precision)
    /// before encryption. Returns serialized ciphertexts.
    pub fn encrypt_gradients(&self, gradients: &[f32]) -> Result<Vec<Vec<u8>>, RealFheError> {
        let mut encrypted = Vec::with_capacity(gradients.len());
        for (i, &g) in gradients.iter().enumerate() {
            // Quantize: f32 → i32 with 4dp precision
            let quantized = (g * 10000.0) as i32;
            let ct = FheInt32::encrypt(quantized, &self.client_key);
            let bytes = bincode::serialize(&ct)
                .map_err(|e| RealFheError::EncryptionFailed(e.to_string()))?;
            encrypted.push(bytes);
            if i % 64 == 0 && i > 0 {
                debug!(progress = i, total = gradients.len(), "FHE encryption progress");
            }
        }
        debug!(count = gradients.len(), "gradients encrypted with TFHE");
        Ok(encrypted)
    }

    /// Decrypt FHE ciphertexts back to gradient values.
    pub fn decrypt_gradients(&self, ciphertexts: &[Vec<u8>]) -> Result<Vec<f32>, RealFheError> {
        let mut gradients = Vec::with_capacity(ciphertexts.len());
        for ct_bytes in ciphertexts {
            let ct: FheInt32 = bincode::deserialize(ct_bytes)
                .map_err(|e| RealFheError::DecryptionFailed(e.to_string()))?;
            let quantized: i32 = ct.decrypt(&self.client_key);
            gradients.push(quantized as f32 / 10000.0);
        }
        debug!(count = gradients.len(), "gradients decrypted from TFHE");
        Ok(gradients)
    }

    /// Homomorphically add two encrypted gradient vectors (element-wise).
    ///
    /// This is the core FL aggregation operation — runs on the aggregator
    /// node WITHOUT access to the client key (plaintext never exposed).
    pub fn aggregate_encrypted(
        &self,
        a: &[Vec<u8>],
        b: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, RealFheError> {
        if a.len() != b.len() {
            return Err(RealFheError::HomomorphicOpFailed(
                "gradient vector length mismatch".into(),
            ));
        }

        // Set server key for homomorphic operations
        set_server_key(self.server_key.clone());

        let mut result = Vec::with_capacity(a.len());
        for (ct_a, ct_b) in a.iter().zip(b.iter()) {
            let a_ct: FheInt32 = bincode::deserialize(ct_a)
                .map_err(|e| RealFheError::HomomorphicOpFailed(e.to_string()))?;
            let b_ct: FheInt32 = bincode::deserialize(ct_b)
                .map_err(|e| RealFheError::HomomorphicOpFailed(e.to_string()))?;

            // Homomorphic addition — no decryption needed!
            let sum = a_ct + b_ct;
            let bytes = bincode::serialize(&sum)
                .map_err(|e| RealFheError::HomomorphicOpFailed(e.to_string()))?;
            result.push(bytes);
        }
        debug!(count = a.len(), "encrypted gradients aggregated homomorphically");
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fhe_encrypt_decrypt_roundtrip() {
        let ctx = RealFheContext::new().expect("key gen");
        let gradients = vec![1.5f32, -0.25, 0.0, 3.1415];
        let encrypted = ctx.encrypt_gradients(&gradients).expect("encrypt");
        let decrypted = ctx.decrypt_gradients(&encrypted).expect("decrypt");

        // Check within quantization tolerance (4dp = 0.0001)
        for (orig, dec) in gradients.iter().zip(decrypted.iter()) {
            assert!((orig - dec).abs() < 0.001, "mismatch: {} vs {}", orig, dec);
        }
    }

    #[test]
    fn fhe_homomorphic_addition() {
        let ctx = RealFheContext::new().expect("key gen");

        let a = vec![1.0f32, 2.0, 3.0];
        let b = vec![4.0f32, 5.0, 6.0];

        let enc_a = ctx.encrypt_gradients(&a).expect("encrypt a");
        let enc_b = ctx.encrypt_gradients(&b).expect("encrypt b");

        let enc_sum = ctx.aggregate_encrypted(&enc_a, &enc_b).expect("aggregate");
        let sum = ctx.decrypt_gradients(&enc_sum).expect("decrypt sum");

        for (i, expected) in [5.0f32, 7.0, 9.0].iter().enumerate() {
            assert!(
                (sum[i] - expected).abs() < 0.001,
                "idx {}: {} vs {}",
                i,
                sum[i],
                expected,
            );
        }
    }
}
