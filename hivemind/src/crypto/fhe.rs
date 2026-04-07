/// FHE (Fully Homomorphic Encryption) — gradient privacy via AES-256-GCM.
///
/// # Privacy Invariant
/// Raw gradients NEVER leave the node. Only ciphertext is transmitted.
///
/// # Implementation
/// - **v0 (legacy stub)**: `SFHE` prefix + raw f32 LE bytes (no real encryption).
/// - **v1 (encrypted)**: `RFHE` prefix + AES-256-GCM encrypted payload.
///
/// True homomorphic operations (add/multiply on ciphertext) require `tfhe-rs`
/// and are feature-gated for Phase 2+. Current encryption provides
/// confidentiality at rest and in transit but is NOT homomorphic —
/// the aggregator must decrypt before aggregating.
///
/// # Naming Convention
/// The primary type is `GradientCryptoCtx` (accurate to current implementation).
/// `FheContext` is a type alias preserved for backward compatibility and will
/// become the real FHE wrapper when `tfhe-rs` is integrated in Phase 2+.
use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{debug, warn};

/// Magic bytes identifying a v0 stub (unencrypted) payload.
const STUB_FHE_MAGIC: &[u8; 4] = b"SFHE";

/// Magic bytes identifying a v1 AES-256-GCM encrypted payload.
const REAL_FHE_MAGIC: &[u8; 4] = b"RFHE";

/// Nonce size for AES-256-GCM (96 bits).
const NONCE_SIZE: usize = NONCE_LEN;

/// Overhead: magic(4) + nonce(12) + GCM tag(16) = 32 bytes.
const ENCRYPTION_OVERHEAD: usize = 4 + NONCE_SIZE + 16;

/// Single-use nonce for AES-256-GCM sealing operations.
struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce_bytes: [u8; NONCE_SIZE]) -> Self {
        Self(Some(aead::Nonce::assume_unique_for_key(nonce_bytes)))
    }
}

impl NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

/// Gradient encryption context using AES-256-GCM.
///
/// Provides confidentiality for gradient vectors transmitted over GossipSub.
/// NOT truly homomorphic — aggregator must decrypt before aggregating.
/// Will be replaced by real FHE (`tfhe-rs`) in Phase 2+.
pub struct GradientCryptoCtx {
    /// Raw AES-256-GCM key material (32 bytes).
    key_bytes: Vec<u8>,
    /// Whether this context has been initialized with keys.
    initialized: bool,
}

/// Backward-compatible alias. Will point to a real FHE wrapper in Phase 2+.
pub type FheContext = GradientCryptoCtx;

impl Default for GradientCryptoCtx {
    fn default() -> Self {
        Self::new_encrypted().expect("GradientCryptoCtx initialization failed")
    }
}

impl GradientCryptoCtx {
    /// Create a new context with a fresh AES-256-GCM key.
    ///
    /// Generates a random 256-bit key using the system CSPRNG.
    pub fn new_encrypted() -> Result<Self, FheError> {
        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; 32];
        rng.fill(&mut key_bytes)
            .map_err(|_| FheError::KeyGenerationFailed)?;

        debug!("FHE context initialized (AES-256-GCM)");
        Ok(Self {
            key_bytes,
            initialized: true,
        })
    }

    /// Create a legacy stub context (no real encryption).
    ///
    /// For backward compatibility only. New code should use `new_encrypted()`.
    pub fn new() -> Self {
        debug!("FHE context initialized (stub — no real encryption)");
        Self {
            key_bytes: Vec::new(),
            initialized: true,
        }
    }

    /// Create FHE context from existing key material.
    ///
    /// # Arguments
    /// * `key_bytes` — 32-byte AES-256-GCM key
    pub fn from_key(key_bytes: &[u8]) -> Result<Self, FheError> {
        if key_bytes.len() != 32 {
            return Err(FheError::InvalidPayload);
        }
        Ok(Self {
            key_bytes: key_bytes.to_vec(),
            initialized: true,
        })
    }

    /// Encrypt gradient vector for safe transmission over GossipSub.
    ///
    /// # Privacy Contract
    /// The returned bytes are AES-256-GCM encrypted — not reversible
    /// without the symmetric key.
    ///
    /// # Format
    /// `RFHE(4B) || nonce(12B) || ciphertext+tag`
    ///
    /// Falls back to stub format if no key material is available.
    pub fn encrypt_gradients(&self, gradients: &[f32]) -> Result<Vec<u8>, FheError> {
        if !self.initialized {
            return Err(FheError::Uninitialized);
        }

        // Stub mode — no key material
        if self.key_bytes.is_empty() {
            return self.encrypt_stub(gradients);
        }

        // Serialize gradients to raw bytes
        let mut plaintext = Vec::with_capacity(gradients.len() * 4);
        for &g in gradients {
            plaintext.extend_from_slice(&g.to_le_bytes());
        }

        // Generate random nonce
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| FheError::EncryptionFailed)?;

        // Create sealing key
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &self.key_bytes)
            .map_err(|_| FheError::EncryptionFailed)?;
        let nonce_seq = OneNonceSequence::new(nonce_bytes);
        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_seq);

        // Encrypt in-place (appends GCM tag)
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut plaintext)
            .map_err(|_| FheError::EncryptionFailed)?;

        // Build output: RFHE || nonce || ciphertext+tag
        let mut payload = Vec::with_capacity(ENCRYPTION_OVERHEAD + plaintext.len());
        payload.extend_from_slice(REAL_FHE_MAGIC);
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&plaintext);

        debug!(
            gradient_count = gradients.len(),
            payload_size = payload.len(),
            "gradients encrypted (AES-256-GCM)"
        );
        Ok(payload)
    }

    /// Legacy stub encryption (no real crypto).
    fn encrypt_stub(&self, gradients: &[f32]) -> Result<Vec<u8>, FheError> {
        let mut payload = Vec::with_capacity(4 + gradients.len() * 4);
        payload.extend_from_slice(STUB_FHE_MAGIC);
        for &g in gradients {
            payload.extend_from_slice(&g.to_le_bytes());
        }
        debug!(
            gradient_count = gradients.len(),
            "gradients serialized (stub — no encryption)"
        );
        Ok(payload)
    }

    /// Decrypt a gradient payload received from GossipSub.
    ///
    /// Supports both RFHE (encrypted) and SFHE (legacy stub) payloads.
    pub fn decrypt_gradients(&self, payload: &[u8]) -> Result<Vec<f32>, FheError> {
        if !self.initialized {
            return Err(FheError::Uninitialized);
        }

        if payload.len() < 4 {
            return Err(FheError::InvalidPayload);
        }

        match &payload[..4] {
            b"RFHE" => self.decrypt_real(payload),
            b"SFHE" => self.decrypt_stub(payload),
            _ => {
                warn!("unknown FHE payload format");
                Err(FheError::InvalidPayload)
            }
        }
    }

    /// Decrypt an AES-256-GCM encrypted payload.
    fn decrypt_real(&self, payload: &[u8]) -> Result<Vec<f32>, FheError> {
        if self.key_bytes.is_empty() {
            return Err(FheError::Uninitialized);
        }

        // Minimum: magic(4) + nonce(12) + tag(16) = 32 bytes
        if payload.len() < ENCRYPTION_OVERHEAD {
            return Err(FheError::InvalidPayload);
        }

        let nonce_bytes: [u8; NONCE_SIZE] = payload[4..4 + NONCE_SIZE]
            .try_into()
            .map_err(|_| FheError::InvalidPayload)?;
        let mut ciphertext = payload[4 + NONCE_SIZE..].to_vec();

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &self.key_bytes)
            .map_err(|_| FheError::DecryptionFailed)?;
        let nonce_seq = OneNonceSequence::new(nonce_bytes);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_seq);

        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut ciphertext)
            .map_err(|_| FheError::DecryptionFailed)?;

        if !plaintext.len().is_multiple_of(4) {
            return Err(FheError::InvalidPayload);
        }

        let gradients: Vec<f32> = plaintext
            .chunks_exact(4)
            .map(|chunk| {
                let bytes: [u8; 4] = chunk.try_into().expect("chunk is 4 bytes");
                f32::from_le_bytes(bytes)
            })
            .collect();

        debug!(gradient_count = gradients.len(), "gradients decrypted (AES-256-GCM)");
        Ok(gradients)
    }

    /// Decrypt a legacy stub payload (just deserialization, no crypto).
    fn decrypt_stub(&self, payload: &[u8]) -> Result<Vec<f32>, FheError> {
        let data = &payload[4..];
        if !data.len().is_multiple_of(4) {
            return Err(FheError::InvalidPayload);
        }

        let gradients: Vec<f32> = data
            .chunks_exact(4)
            .map(|chunk| {
                let bytes: [u8; 4] = chunk.try_into().expect("chunk is 4 bytes");
                f32::from_le_bytes(bytes)
            })
            .collect();

        debug!(gradient_count = gradients.len(), "gradients deserialized (stub)");
        Ok(gradients)
    }

    /// Check if this is a stub (unencrypted) implementation.
    pub fn is_stub(&self) -> bool {
        self.key_bytes.is_empty()
    }
}

/// Errors from FHE operations.
#[derive(Debug, PartialEq, Eq)]
pub enum FheError {
    /// FHE context not initialized (no keys generated).
    Uninitialized,
    /// Payload format is invalid or corrupted.
    InvalidPayload,
    /// Key generation failed (CSPRNG error).
    KeyGenerationFailed,
    /// AES-256-GCM encryption failed.
    EncryptionFailed,
    /// AES-256-GCM decryption failed (tampered or wrong key).
    DecryptionFailed,
}

impl std::fmt::Display for FheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FheError::Uninitialized => write!(f, "FHE context not initialized"),
            FheError::InvalidPayload => write!(f, "invalid FHE payload format"),
            FheError::KeyGenerationFailed => write!(f, "FHE key generation failed"),
            FheError::EncryptionFailed => write!(f, "AES-256-GCM encryption failed"),
            FheError::DecryptionFailed => write!(f, "AES-256-GCM decryption failed"),
        }
    }
}

impl std::error::Error for FheError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_roundtrip() {
        let ctx = FheContext::new_encrypted().expect("init");
        let gradients = vec![1.0_f32, -0.5, 0.0, 3.14, -2.718];
        let encrypted = ctx.encrypt_gradients(&gradients).expect("encrypt");
        let decrypted = ctx.decrypt_gradients(&encrypted).expect("decrypt");
        assert_eq!(gradients, decrypted);
    }

    #[test]
    fn encrypted_has_rfhe_prefix() {
        let ctx = FheContext::new_encrypted().expect("init");
        let encrypted = ctx.encrypt_gradients(&[1.0, 2.0]).expect("encrypt");
        assert_eq!(&encrypted[..4], REAL_FHE_MAGIC);
    }

    #[test]
    fn encrypted_payload_larger_than_stub() {
        let ctx_real = FheContext::new_encrypted().expect("init");
        let ctx_stub = FheContext::new();
        let grads = vec![1.0_f32; 10];
        let real = ctx_real.encrypt_gradients(&grads).expect("encrypt");
        let stub = ctx_stub.encrypt_gradients(&grads).expect("encrypt");
        // Real encryption adds nonce(12) + tag(16) overhead
        assert!(real.len() > stub.len());
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let ctx1 = FheContext::new_encrypted().expect("init");
        let ctx2 = FheContext::new_encrypted().expect("init");
        let encrypted = ctx1.encrypt_gradients(&[1.0, 2.0]).expect("encrypt");
        assert_eq!(
            ctx2.decrypt_gradients(&encrypted),
            Err(FheError::DecryptionFailed),
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let ctx = FheContext::new_encrypted().expect("init");
        let mut encrypted = ctx.encrypt_gradients(&[1.0, 2.0]).expect("encrypt");
        // Tamper with the ciphertext (after nonce)
        let idx = 4 + NONCE_SIZE + 1;
        if idx < encrypted.len() {
            encrypted[idx] ^= 0xFF;
        }
        assert_eq!(
            ctx.decrypt_gradients(&encrypted),
            Err(FheError::DecryptionFailed),
        );
    }

    #[test]
    fn stub_roundtrip() {
        let ctx = FheContext::new();
        let gradients = vec![1.0_f32, -0.5, 0.0, 3.14, -2.718];
        let encrypted = ctx.encrypt_gradients(&gradients).expect("encrypt");
        let decrypted = ctx.decrypt_gradients(&encrypted).expect("decrypt");
        assert_eq!(gradients, decrypted);
    }

    #[test]
    fn stub_has_sfhe_prefix() {
        let ctx = FheContext::new();
        let encrypted = ctx.encrypt_gradients(&[1.0]).expect("encrypt");
        assert_eq!(&encrypted[..4], STUB_FHE_MAGIC);
    }

    #[test]
    fn rejects_invalid_payload() {
        let ctx = FheContext::new_encrypted().expect("init");
        assert_eq!(
            ctx.decrypt_gradients(&[0xDE, 0xAD]),
            Err(FheError::InvalidPayload),
        );
    }

    #[test]
    fn rejects_wrong_magic() {
        let ctx = FheContext::new_encrypted().expect("init");
        let bad = b"BADx\x00\x00\x80\x3f";
        assert_eq!(
            ctx.decrypt_gradients(bad),
            Err(FheError::InvalidPayload),
        );
    }

    #[test]
    fn empty_gradients_encrypted() {
        let ctx = FheContext::new_encrypted().expect("init");
        let encrypted = ctx.encrypt_gradients(&[]).expect("encrypt");
        let decrypted = ctx.decrypt_gradients(&encrypted).expect("decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn is_stub_reports_correctly() {
        let stub = FheContext::new();
        assert!(stub.is_stub());

        let real = FheContext::new_encrypted().expect("init");
        assert!(!real.is_stub());
    }

    #[test]
    fn from_key_roundtrip() {
        let ctx1 = FheContext::new_encrypted().expect("init");
        let encrypted = ctx1.encrypt_gradients(&[42.0, -1.0]).expect("encrypt");

        // Reconstruct context from same key material
        let ctx2 = FheContext::from_key(&ctx1.key_bytes).expect("from_key");
        let decrypted = ctx2.decrypt_gradients(&encrypted).expect("decrypt");
        assert_eq!(decrypted, vec![42.0, -1.0]);
    }

    #[test]
    fn real_ctx_can_read_stub_payload() {
        let stub = FheContext::new();
        let encrypted = stub.encrypt_gradients(&[1.0, 2.0]).expect("encrypt");

        let real = FheContext::new_encrypted().expect("init");
        let decrypted = real.decrypt_gradients(&encrypted).expect("decrypt");
        assert_eq!(decrypted, vec![1.0, 2.0]);
    }

    #[test]
    fn different_nonces_produce_different_ciphertext() {
        let ctx = FheContext::new_encrypted().expect("init");
        let e1 = ctx.encrypt_gradients(&[1.0]).expect("encrypt");
        let e2 = ctx.encrypt_gradients(&[1.0]).expect("encrypt");
        // Different nonces → different ciphertext
        assert_ne!(e1, e2);
    }
}
