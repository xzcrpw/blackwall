/// ZKP Verifier — lightweight verification of Proof of Threat.
///
/// # Proof Versions
/// - **v0 (stub)**: Checks SHA256 commitment integrity (`STUB || SHA256(stmt)`).
/// - **v1 (signed)**: Verifies Ed25519 signature over `(stmt || commitment || timestamp)`.
///
/// # Performance Target
/// Must complete in < 5ms on ARM64. Both v0/v1 verification is O(1).
use common::hivemind::ThreatProof;
use ring::digest;
use ring::signature;
use tracing::{debug, warn};

/// Magic bytes identifying a v0 stub proof.
const STUB_MAGIC: &[u8; 4] = b"STUB";

/// Expected v0 stub proof length: 4 bytes magic + 32 bytes SHA256.
const STUB_PROOF_LEN: usize = 36;

/// Expected v1 signed proof length: 32B commitment + 64B Ed25519 signature.
const V1_PROOF_LEN: usize = 96;

/// Verification result with reason for failure.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// Proof is valid and cryptographically verified (v1+).
    Valid,
    /// Proof is a valid v0 stub (not signed, but correctly formatted).
    ValidStub,
    /// Proof data is empty.
    EmptyProof,
    /// Proof format is unrecognized.
    UnknownFormat,
    /// Stub commitment does not match the statement.
    CommitmentMismatch,
    /// Proof version is unsupported.
    UnsupportedVersion,
    /// Ed25519 signature verification failed.
    SignatureInvalid,
    /// No public key provided for v1 proof.
    MissingPublicKey,
}

/// Verify a ThreatProof.
///
/// * `peer_public_key` — Ed25519 public key (32 bytes) for v1 proofs.
///   Pass `None` if only v0 stubs are expected.
///
/// Returns `VerifyResult::Valid` for verified v1 proofs,
/// `VerifyResult::ValidStub` for correctly formatted v0 proofs,
/// or an error variant describing the failure.
pub fn verify_threat(
    proof: &ThreatProof,
    peer_public_key: Option<&[u8]>,
) -> VerifyResult {
    match proof.version {
        0 => verify_v0(proof),
        1 => verify_v1(proof, peer_public_key),
        _ => {
            warn!(version = proof.version, "Unsupported proof version");
            VerifyResult::UnsupportedVersion
        }
    }
}

/// Verify a v0 stub proof.
fn verify_v0(proof: &ThreatProof) -> VerifyResult {
    if proof.proof_data.is_empty() {
        debug!("Empty proof data — treating as unproven");
        return VerifyResult::EmptyProof;
    }

    if proof.proof_data.len() == STUB_PROOF_LEN
        && proof.proof_data.starts_with(STUB_MAGIC)
    {
        return verify_stub(proof);
    }

    warn!(
        proof_len = proof.proof_data.len(),
        "Unknown v0 proof format"
    );
    VerifyResult::UnknownFormat
}

/// Verify a v1 signed proof by checking Ed25519 signature.
fn verify_v1(proof: &ThreatProof, peer_public_key: Option<&[u8]>) -> VerifyResult {
    let Some(pk_bytes) = peer_public_key else {
        warn!("v1 proof requires peer public key for verification");
        return VerifyResult::MissingPublicKey;
    };

    if proof.proof_data.len() != V1_PROOF_LEN {
        warn!(
            proof_len = proof.proof_data.len(),
            expected = V1_PROOF_LEN,
            "v1 proof has wrong length"
        );
        return VerifyResult::UnknownFormat;
    }

    let commitment = &proof.proof_data[..32];
    let sig_bytes = &proof.proof_data[32..96];

    // Reconstruct the signing input: canonical_stmt || commitment || timestamp
    let canonical = canonical_statement(&proof.statement);
    let mut sign_input = Vec::with_capacity(canonical.len() + 32 + 8);
    sign_input.extend_from_slice(&canonical);
    sign_input.extend_from_slice(commitment);
    sign_input.extend_from_slice(&proof.created_at.to_le_bytes());

    // Verify Ed25519 signature
    let pub_key = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        pk_bytes,
    );
    match pub_key.verify(&sign_input, sig_bytes) {
        Ok(()) => {
            debug!("v1 signed proof verified — signature valid");
            VerifyResult::Valid
        }
        Err(_) => {
            warn!("v1 proof signature verification failed");
            VerifyResult::SignatureInvalid
        }
    }
}

/// Verify a stub proof by recomputing the statement commitment.
fn verify_stub(proof: &ThreatProof) -> VerifyResult {
    let canonical = canonical_statement(&proof.statement);
    let expected = digest::digest(&digest::SHA256, &canonical);

    if &proof.proof_data[4..] == expected.as_ref() {
        debug!("Stub proof verified — commitment matches");
        VerifyResult::ValidStub
    } else {
        warn!("Stub proof commitment mismatch — possible tampering");
        VerifyResult::CommitmentMismatch
    }
}

/// Serialize a ProofStatement into canonical bytes (must match prover).
fn canonical_statement(stmt: &common::hivemind::ProofStatement) -> Vec<u8> {
    let mut buf = Vec::with_capacity(67);
    match &stmt.ja4_hash {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(h);
        }
        None => {
            buf.push(0);
        }
    }
    buf.push(stmt.entropy_exceeded as u8);
    buf.push(stmt.classified_malicious as u8);
    buf.push(stmt.ioc_type);
    buf
}

/// Quick check if a proof has any data at all.
pub fn has_proof(proof: &ThreatProof) -> bool {
    !proof.proof_data.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::prover;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key")
    }

    #[test]
    fn verify_valid_v0_stub() {
        let proof = prover::prove_threat(
            Some(b"t13d1516h2_8daaf6152771_e5627efa2ab1"),
            true,
            true,
            0,
            None,
        );
        assert_eq!(verify_threat(&proof, None), VerifyResult::ValidStub);
    }

    #[test]
    fn verify_empty_proof() {
        let proof = ThreatProof {
            version: 0,
            statement: common::hivemind::ProofStatement {
                ja4_hash: None,
                entropy_exceeded: false,
                classified_malicious: false,
                ioc_type: 0,
            },
            proof_data: Vec::new(),
            created_at: 0,
        };
        assert_eq!(verify_threat(&proof, None), VerifyResult::EmptyProof);
    }

    #[test]
    fn verify_tampered_v0_commitment() {
        let mut proof = prover::prove_threat(Some(b"test"), true, true, 0, None);
        if let Some(last) = proof.proof_data.last_mut() {
            *last ^= 0xFF;
        }
        assert_eq!(verify_threat(&proof, None), VerifyResult::CommitmentMismatch);
    }

    #[test]
    fn verify_unknown_format() {
        let proof = ThreatProof {
            version: 0,
            statement: common::hivemind::ProofStatement {
                ja4_hash: None,
                entropy_exceeded: false,
                classified_malicious: false,
                ioc_type: 0,
            },
            proof_data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03],
            created_at: 0,
        };
        assert_eq!(verify_threat(&proof, None), VerifyResult::UnknownFormat);
    }

    #[test]
    fn verify_unsupported_version() {
        let mut proof = prover::prove_threat(Some(b"test"), true, true, 0, None);
        proof.version = 99;
        assert_eq!(verify_threat(&proof, None), VerifyResult::UnsupportedVersion);
    }

    #[test]
    fn has_proof_check() {
        let with_proof = prover::prove_threat(Some(b"test"), true, true, 0, None);
        assert!(has_proof(&with_proof));

        let without = ThreatProof {
            version: 0,
            statement: common::hivemind::ProofStatement {
                ja4_hash: None,
                entropy_exceeded: false,
                classified_malicious: false,
                ioc_type: 0,
            },
            proof_data: Vec::new(),
            created_at: 0,
        };
        assert!(!has_proof(&without));
    }

    #[test]
    fn verify_v1_signed_proof() {
        let key = test_keypair();
        let proof = prover::prove_threat(
            Some(b"test_fp"),
            true,
            true,
            0,
            Some(&key),
        );
        let pk = key.public_key().as_ref();
        assert_eq!(verify_threat(&proof, Some(pk)), VerifyResult::Valid);
    }

    #[test]
    fn verify_v1_wrong_key_fails() {
        let key1 = test_keypair();
        let key2 = test_keypair();
        let proof = prover::prove_threat(
            Some(b"test_fp"),
            true,
            true,
            0,
            Some(&key1),
        );
        let wrong_pk = key2.public_key().as_ref();
        assert_eq!(
            verify_threat(&proof, Some(wrong_pk)),
            VerifyResult::SignatureInvalid,
        );
    }

    #[test]
    fn verify_v1_no_key_returns_missing() {
        let key = test_keypair();
        let proof = prover::prove_threat(
            Some(b"fp"),
            true,
            true,
            0,
            Some(&key),
        );
        assert_eq!(verify_threat(&proof, None), VerifyResult::MissingPublicKey);
    }

    #[test]
    fn verify_v1_tampered_proof_fails() {
        let key = test_keypair();
        let mut proof = prover::prove_threat(
            Some(b"fp"),
            true,
            true,
            0,
            Some(&key),
        );
        // Tamper with the commitment
        proof.proof_data[0] ^= 0xFF;
        let pk = key.public_key().as_ref();
        assert_eq!(
            verify_threat(&proof, Some(pk)),
            VerifyResult::SignatureInvalid,
        );
    }
}
