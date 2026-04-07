/// ZKP Prover — generates Proof of Threat for IoC reports.
///
/// Proves:
///   ∃ packet P such that:
///     JA4(P) = fingerprint_hash
///     Entropy(P) > THRESHOLD
///     Classifier(P) = MALICIOUS
///   WITHOUT REVEALING: source_ip, victim_ip, raw_payload
///
/// # Proof Versions
/// - **v0 (legacy)**: `STUB || SHA256(statement)` — no signing, backward compat
/// - **v1 (signed)**: `witness_commitment(32B) || Ed25519_signature(64B)` — real crypto
/// - **v2 (Groth16)**: Real zk-SNARK — feature-gated behind `zkp-groth16`
use common::hivemind::{ProofStatement, ThreatProof};
use ring::digest;
use ring::rand::SecureRandom;
use ring::signature::Ed25519KeyPair;
use tracing::info;

/// Magic bytes identifying a v0 stub proof.
const STUB_MAGIC: &[u8; 4] = b"STUB";

/// V1 proof size: 32 bytes witness_commitment + 64 bytes Ed25519 signature.
const V1_PROOF_LEN: usize = 96;

/// Generate a Proof of Threat for an IoC observation.
///
/// # Arguments
/// * `ja4_fingerprint` — The JA4 hash observed (if applicable)
/// * `entropy_exceeded` — Whether entropy was above the anomaly threshold
/// * `classified_malicious` — Whether the AI classifier labeled this malicious
/// * `ioc_type` — The IoC type being proven
/// * `signing_key` — Ed25519 key for v1 signed proofs (None = v0 stub)
///
/// # Returns
/// A `ThreatProof` — v1 signed (if key provided) or v0 stub (legacy).
pub fn prove_threat(
    ja4_fingerprint: Option<&[u8]>,
    entropy_exceeded: bool,
    classified_malicious: bool,
    ioc_type: u8,
    signing_key: Option<&Ed25519KeyPair>,
) -> ThreatProof {
    // Compute JA4 hash commitment (SHA256 of the fingerprint, or zeros)
    let ja4_hash = ja4_fingerprint.map(|fp| {
        let d = digest::digest(&digest::SHA256, fp);
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_ref());
        h
    });

    let statement = ProofStatement {
        ja4_hash,
        entropy_exceeded,
        classified_malicious,
        ioc_type,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (version, proof_data) = match signing_key {
        Some(key) => {
            let pd = build_signed_proof(key, &statement, now);
            info!(
                entropy_exceeded,
                classified_malicious,
                "generated signed ThreatProof (v1)"
            );
            (1u8, pd)
        }
        None => {
            let pd = build_stub_proof(&statement);
            info!(
                entropy_exceeded,
                classified_malicious,
                "generated stub ThreatProof (v0)"
            );
            (0u8, pd)
        }
    };

    ThreatProof {
        version,
        statement,
        proof_data,
        created_at: now,
    }
}

/// Build a v1 signed proof with Ed25519.
///
/// Format (96 bytes):
///   [0..32]  witness_commitment = SHA256(canonical_statement || nonce)
///   [32..96] Ed25519 signature over (canonical_statement || witness_commitment || timestamp)
///
/// The witness commitment binds the proof to specific observed data.
/// The signature provides non-repudiation (tied to peer identity).
fn build_signed_proof(
    key: &Ed25519KeyPair,
    statement: &ProofStatement,
    timestamp: u64,
) -> Vec<u8> {
    let canonical = canonical_statement(statement);

    // Generate random nonce for witness commitment uniqueness
    let rng = ring::rand::SystemRandom::new();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce).expect("RNG failure");

    // Witness commitment: SHA256(canonical || nonce)
    let mut commit_input = Vec::with_capacity(canonical.len() + 32);
    commit_input.extend_from_slice(&canonical);
    commit_input.extend_from_slice(&nonce);
    let commitment = digest::digest(&digest::SHA256, &commit_input);
    let commitment_bytes: [u8; 32] = commitment.as_ref().try_into().expect("SHA256 is 32B");

    // Signing input: canonical_statement || witness_commitment || timestamp_le
    let mut sign_input = Vec::with_capacity(canonical.len() + 32 + 8);
    sign_input.extend_from_slice(&canonical);
    sign_input.extend_from_slice(&commitment_bytes);
    sign_input.extend_from_slice(&timestamp.to_le_bytes());

    let sig = key.sign(&sign_input);

    // Proof = witness_commitment (32B) || signature (64B) = 96B
    let mut proof = Vec::with_capacity(V1_PROOF_LEN);
    proof.extend_from_slice(&commitment_bytes);
    proof.extend_from_slice(sig.as_ref());
    proof
}

/// Build a deterministic stub proof blob.
///
/// Format: STUB || SHA256(statement_canonical)
/// The verifier checks the magic prefix and validates the commitment.
fn build_stub_proof(statement: &ProofStatement) -> Vec<u8> {
    let canonical = canonical_statement(statement);
    let commitment = digest::digest(&digest::SHA256, &canonical);

    let mut proof = Vec::with_capacity(4 + 32);
    proof.extend_from_slice(STUB_MAGIC);
    proof.extend_from_slice(commitment.as_ref());
    proof
}

/// Serialize a ProofStatement into a canonical byte representation
/// for commitment hashing. Deterministic ordering.
fn canonical_statement(stmt: &ProofStatement) -> Vec<u8> {
    let mut buf = Vec::with_capacity(67);
    // ja4_hash: 1 byte presence flag + 32 bytes if present
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

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{self, KeyPair};

    fn test_keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key")
    }

    #[test]
    fn v0_stub_proof_has_correct_format() {
        let proof = prove_threat(
            Some(b"t13d1516h2_8daaf6152771_e5627efa2ab1"),
            true,
            true,
            0,
            None,
        );

        assert_eq!(proof.version, 0);
        assert!(proof.statement.entropy_exceeded);
        assert!(proof.statement.classified_malicious);
        assert!(proof.statement.ja4_hash.is_some());

        // Stub proof = 4 bytes magic + 32 bytes SHA256
        assert_eq!(proof.proof_data.len(), 36);
        assert_eq!(&proof.proof_data[..4], STUB_MAGIC);
    }

    #[test]
    fn v0_stub_proof_deterministic() {
        let p1 = prove_threat(Some(b"test_fp"), true, false, 1, None);
        let p2 = prove_threat(Some(b"test_fp"), true, false, 1, None);

        // Statement commitment should be deterministic
        assert_eq!(p1.proof_data[4..], p2.proof_data[4..]);
    }

    #[test]
    fn no_ja4_proof() {
        let proof = prove_threat(None, false, true, 2, None);
        assert!(proof.statement.ja4_hash.is_none());
        assert_eq!(proof.proof_data.len(), 36);
    }

    #[test]
    fn v1_signed_proof_has_correct_format() {
        let key = test_keypair();
        let proof = prove_threat(
            Some(b"test_fingerprint"),
            true,
            true,
            0,
            Some(&key),
        );

        assert_eq!(proof.version, 1);
        assert_eq!(proof.proof_data.len(), V1_PROOF_LEN); // 96 bytes
    }

    #[test]
    fn v1_signed_proof_verifiable() {
        let key = test_keypair();
        let proof = prove_threat(
            Some(b"test_fp"),
            true,
            false,
            1,
            Some(&key),
        );

        // Extract components
        let commitment = &proof.proof_data[..32];
        let sig_bytes = &proof.proof_data[32..96];

        // Reconstruct signing input
        let canonical = canonical_statement(&proof.statement);
        let mut sign_input = Vec::new();
        sign_input.extend_from_slice(&canonical);
        sign_input.extend_from_slice(commitment);
        sign_input.extend_from_slice(&proof.created_at.to_le_bytes());

        // Verify signature with ring
        let pub_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            key.public_key().as_ref(),
        );
        pub_key.verify(&sign_input, sig_bytes).expect("sig should verify");
    }

    #[test]
    fn v1_proofs_have_unique_commitments() {
        let key = test_keypair();
        let p1 = prove_threat(Some(b"fp"), true, true, 0, Some(&key));
        let p2 = prove_threat(Some(b"fp"), true, true, 0, Some(&key));

        // Different nonces → different commitments
        assert_ne!(p1.proof_data[..32], p2.proof_data[..32]);
    }
}
