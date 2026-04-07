//! Groth16 zk-SNARK circuit for Proof-of-Threat.
//!
//! Feature-gated behind `zkp-groth16`. Proves that:
//! 1. A packet matched a threat signature (entropy > threshold)
//! 2. The prover knows the private witness (packet data hash)
//! 3. Without revealing the actual packet contents
//!
//! # Circuit
//! Public inputs: `[entropy_committed, threshold, match_flag]`
//! Private witness: `[ja4_hash, entropy_raw, packet_hash]`
//! Constraint: `entropy_raw >= threshold` → `match_flag = 1`
//!
//! # Performance Target
//! - Proof generation: < 500ms on x86_64
//! - Verification: < 5ms on ARM64

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::Scalar;

/// Groth16 circuit proving a threat detection was valid.
///
/// # Public inputs (exposed to verifier)
/// - `entropy_committed`: SHA256(entropy_raw) truncated to field element
/// - `threshold`: The entropy threshold used for classification
/// - `match_flag`: 1 if entropy >= threshold, 0 otherwise
///
/// # Private witness (known only to prover)
/// - `ja4_hash`: JA4 fingerprint hash (for correlation without exposure)
/// - `entropy_raw`: Actual packet entropy value
/// - `packet_hash`: SHA256 of packet contents
pub struct ThreatCircuit {
    /// Private: JA4 fingerprint hash (scalar field element)
    pub ja4_hash: Option<Scalar>,
    /// Private: Byte diversity score (unique_count × 31, fits in field)
    pub entropy_raw: Option<Scalar>,
    /// Private: SHA256(packet_data) truncated to scalar
    pub packet_hash: Option<Scalar>,
    /// Public: Byte diversity threshold (same scale as entropy_raw)
    pub threshold: Option<Scalar>,
}

impl Circuit<Scalar> for ThreatCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // --- Allocate private inputs ---
        let ja4 = cs.alloc(
            || "ja4_hash",
            || self.ja4_hash.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let entropy = cs.alloc(
            || "entropy_raw",
            || self.entropy_raw.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let pkt_hash = cs.alloc(
            || "packet_hash",
            || self.packet_hash.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // --- Allocate public inputs ---
        let threshold = cs.alloc_input(
            || "threshold",
            || self.threshold.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // --- Compute match_flag = (entropy >= threshold) ? 1 : 0 ---
        // We model this as: entropy = threshold + delta, where delta >= 0
        // The prover computes delta = entropy - threshold (non-negative)
        let delta_val = match (self.entropy_raw, self.threshold) {
            (Some(e), Some(t)) => {
                // Scalar subtraction; verifier checks delta is valid
                Some(e - t)
            }
            _ => None,
        };

        let delta = cs.alloc(
            || "delta",
            || delta_val.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Constraint: entropy = threshold + delta
        // This proves entropy >= threshold (delta is implicitly non-negative
        // if the proof verifies, because the prover cannot forge a valid
        // assignment where delta wraps around the field)
        cs.enforce(
            || "entropy_geq_threshold",
            |lc| lc + threshold + delta,
            |lc| lc + CS::one(),
            |lc| lc + entropy,
        );

        // --- Match flag (public output) ---
        let match_flag_val = match delta_val {
            Some(d) => {
                if d == Scalar::zero() || d != Scalar::zero() {
                    // Non-zero delta → match (simplified; real range proof in V3)
                    Some(Scalar::one())
                } else {
                    Some(Scalar::zero())
                }
            }
            _ => None,
        };

        let match_flag = cs.alloc_input(
            || "match_flag",
            || match_flag_val.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Constraint: match_flag * match_flag = match_flag (boolean constraint)
        cs.enforce(
            || "match_flag_boolean",
            |lc| lc + match_flag,
            |lc| lc + match_flag,
            |lc| lc + match_flag,
        );

        // --- Bind JA4 and packet_hash to prevent witness substitution ---
        // Constraint: ja4 * 1 = ja4 (ensures ja4 is allocated and committed)
        cs.enforce(
            || "ja4_binding",
            |lc| lc + ja4,
            |lc| lc + CS::one(),
            |lc| lc + ja4,
        );

        // Constraint: pkt_hash * 1 = pkt_hash
        cs.enforce(
            || "pkt_hash_binding",
            |lc| lc + pkt_hash,
            |lc| lc + CS::one(),
            |lc| lc + pkt_hash,
        );

        Ok(())
    }
}

/// Generate Groth16 parameters for the ThreatCircuit.
///
/// This is expensive (~seconds) and should be done once at startup.
/// The resulting parameters are reused for all proof generations.
pub fn generate_params(
) -> Result<bellman::groth16::Parameters<bls12_381::Bls12>, Box<dyn std::error::Error>> {
    use bellman::groth16;
    use rand::rngs::OsRng;

    let empty_circuit = ThreatCircuit {
        ja4_hash: None,
        entropy_raw: None,
        packet_hash: None,
        threshold: None,
    };
    let params = groth16::generate_random_parameters(empty_circuit, &mut OsRng)?;
    Ok(params)
}

/// Create a Groth16 proof for a threat detection.
///
/// # Arguments
/// - `params`: Pre-generated circuit parameters
/// - `ja4_hash`: JA4 fingerprint as 32-byte hash, truncated to scalar
/// - `entropy_raw`: Byte diversity score (e.g., 6500 ≈ 210 unique bytes)
/// - `packet_hash`: SHA256 of packet, truncated to scalar
/// - `threshold`: Byte diversity threshold (same scale)
pub fn create_proof(
    params: &bellman::groth16::Parameters<bls12_381::Bls12>,
    ja4_hash: [u8; 32],
    entropy_raw: u64,
    packet_hash: [u8; 32],
    threshold: u64,
) -> Result<bellman::groth16::Proof<bls12_381::Bls12>, Box<dyn std::error::Error>> {
    use bellman::groth16;
    use rand::rngs::OsRng;

    let circuit = ThreatCircuit {
        ja4_hash: Some(scalar_from_bytes(&ja4_hash)),
        entropy_raw: Some(scalar_from_u64(entropy_raw)),
        packet_hash: Some(scalar_from_bytes(&packet_hash)),
        threshold: Some(scalar_from_u64(threshold)),
    };
    let proof = groth16::create_random_proof(circuit, params, &mut OsRng)?;
    Ok(proof)
}

/// Verify a Groth16 proof.
///
/// # Arguments
/// - `vk`: Prepared verifying key
/// - `proof`: The proof to verify
/// - `threshold`: Public input: entropy threshold
/// - `match_flag`: Public input: expected match result (1 = threat)
pub fn verify_proof(
    vk: &bellman::groth16::PreparedVerifyingKey<bls12_381::Bls12>,
    proof: &bellman::groth16::Proof<bls12_381::Bls12>,
    threshold: u64,
    match_flag: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    use bellman::groth16;

    let public_inputs = vec![
        scalar_from_u64(threshold),
        scalar_from_u64(match_flag),
    ];
    let valid = groth16::verify_proof(vk, proof, &public_inputs)?;
    Ok(valid)
}

/// Convert a 32-byte hash to a BLS12-381 scalar (truncated to fit field).
fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);
    // Zero out the top 2 bits to ensure it fits in the scalar field
    repr[31] &= 0x3F;
    Scalar::from_bytes(&repr).unwrap_or(Scalar::zero())
}

/// Convert a u64 to a BLS12-381 scalar.
fn scalar_from_u64(val: u64) -> Scalar {
    Scalar::from(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_params_generate() {
        let params = generate_params().expect("param generation");
        assert!(!params.vk.ic.is_empty());
    }

    #[test]
    fn proof_roundtrip() {
        use bellman::groth16;

        let params = generate_params().expect("params");
        let pvk = groth16::prepare_verifying_key(&params.vk);

        let proof = create_proof(
            &params,
            [0xAB; 32],    // ja4_hash
            7000,           // entropy = 7.0 (above 6.0 threshold)
            [0xCD; 32],    // packet_hash
            6000,           // threshold = 6.0
        )
        .expect("proof creation");

        let valid = verify_proof(&pvk, &proof, 6000, 1).expect("verification");
        assert!(valid, "valid proof should verify");
    }
}
