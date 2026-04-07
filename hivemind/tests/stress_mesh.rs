//! Stress benchmark: concurrent IoC consensus, ZKP proof+verify,
//! FHE encrypt+decrypt, reputation cascades.
//!
//! Run: `cargo test -p hivemind --test stress_mesh -- --nocapture`

use std::time::Instant;

use common::hivemind::IoC;
use hivemind::consensus::{ConsensusEngine, ConsensusResult};
use hivemind::crypto::fhe::FheContext;
use hivemind::reputation::ReputationStore;
use hivemind::zkp::{prover, verifier};

/// Deterministic 32-byte key for peer `id`.
fn peer_key(id: u16) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = (id >> 8) as u8;
    key[1] = (id & 0xFF) as u8;
    key[31] = 0xAA;
    key
}

fn make_ioc(idx: u16) -> IoC {
    IoC {
        ioc_type: 0, // MaliciousIp
        severity: 7,
        ip: 0x0A630000 | idx as u32, // 10.99.x.x
        ja4: Some(format!("t13d1517h2_stress_{:04x}", idx)),
        entropy_score: Some(7500),
        description: format!("stress-ioc-{idx}"),
        first_seen: 1_700_000_000 + idx as u64,
        confirmations: 0,
        zkp_proof: Vec::new(),
    }
}

#[test]
fn stress_100_peer_reputation_registration() {
    let mut reputation = ReputationStore::new();

    let start = Instant::now();
    for id in 0..120u16 {
        reputation.register_peer(&peer_key(id));
    }
    let elapsed = start.elapsed();

    println!("\n=== 120-PEER REPUTATION REGISTRATION ===");
    println!("  Registered:  {}", reputation.peer_count());
    println!("  Duration:    {elapsed:?}");
    println!(
        "  Per-peer:    {:.2}µs",
        elapsed.as_micros() as f64 / 120.0
    );
    assert_eq!(reputation.peer_count(), 120);
}

#[test]
fn stress_concurrent_ioc_consensus() {
    let mut engine = ConsensusEngine::new();

    let start = Instant::now();
    let mut accepted = 0u32;

    // Submit 200 IoCs, each from 3+ different peers to reach quorum
    for ioc_idx in 0..200u16 {
        let ioc = make_ioc(ioc_idx);
        for voter in 0..4u16 {
            let peer = peer_key(voter);
            let result = engine.submit_ioc(&ioc, &peer);
            if matches!(result, ConsensusResult::Accepted(_)) {
                accepted += 1;
            }
        }
    }
    let elapsed = start.elapsed();

    println!("\n=== IoC CONSENSUS STRESS (200 IoCs × 4 peers) ===");
    println!("  IoCs submitted: 200");
    println!("  Accepted:       {accepted}");
    println!("  Duration:       {elapsed:?}");
    println!(
        "  Per-IoC:        {:.2}µs",
        elapsed.as_micros() as f64 / 200.0
    );
    assert_eq!(accepted, 200, "all IoCs should reach consensus with 4 voters");
}

#[test]
fn stress_zkp_proof_verify_throughput() {
    let start = Instant::now();
    let iterations = 500u32;
    let mut proofs_valid = 0u32;

    for i in 0..iterations {
        let ja4 = format!("t13d1517h2_8daaf6152771_{:04x}", i);
        let proof = prover::prove_threat(
            Some(ja4.as_bytes()),
            true,     // entropy_exceeded
            true,     // classified_malicious
            0,        // ioc_type: MaliciousIp
            None,     // no signing key (v0 stub)
        );
        if matches!(
            verifier::verify_threat(&proof, None),
            verifier::VerifyResult::ValidStub
        ) {
            proofs_valid += 1;
        }
    }
    let elapsed = start.elapsed();

    println!("\n=== ZKP v0 STUB THROUGHPUT ===");
    println!("  Iterations:  {iterations}");
    println!("  Valid:        {proofs_valid}");
    println!("  Duration:    {elapsed:?}");
    println!(
        "  Per-cycle:   {:.2}µs",
        elapsed.as_micros() as f64 / iterations as f64
    );
    assert_eq!(proofs_valid, iterations);
}

#[test]
fn stress_zkp_signed_proof_verify() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use ring::rand::SystemRandom;

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
    let pub_key = key_pair.public_key().as_ref();

    let start = Instant::now();
    let iterations = 200u32;
    let mut proofs_valid = 0u32;

    for i in 0..iterations {
        let ja4 = format!("t13d1517h2_signed_{:04x}", i);
        let proof = prover::prove_threat(
            Some(ja4.as_bytes()),
            true,
            true,
            0,
            Some(&key_pair),
        );
        if matches!(
            verifier::verify_threat(&proof, Some(pub_key)),
            verifier::VerifyResult::Valid
        ) {
            proofs_valid += 1;
        }
    }
    let elapsed = start.elapsed();

    println!("\n=== ZKP v1 SIGNED THROUGHPUT ===");
    println!("  Iterations:  {iterations}");
    println!("  Valid:        {proofs_valid}");
    println!("  Duration:    {elapsed:?}");
    println!(
        "  Per-cycle:   {:.2}µs",
        elapsed.as_micros() as f64 / iterations as f64
    );
    assert_eq!(proofs_valid, iterations);
}

#[test]
fn stress_fhe_encrypt_decrypt_throughput() {
    let ctx = FheContext::new_encrypted().expect("fhe init");

    let start = Instant::now();
    let iterations = 1000u32;
    let mut valid = 0u32;

    for i in 0..iterations {
        // Simulate gradient vectors (10 floats each)
        let gradients: Vec<f32> = (0..10)
            .map(|j| (i as f32 * 0.01) + (j as f32 * 0.001))
            .collect();

        let encrypted = ctx.encrypt_gradients(&gradients).expect("encrypt");
        let decrypted = ctx.decrypt_gradients(&encrypted).expect("decrypt");
        if decrypted.len() == gradients.len() {
            valid += 1;
        }
    }
    let elapsed = start.elapsed();

    println!("\n=== FHE (AES-256-GCM) GRADIENT THROUGHPUT ===");
    println!("  Iterations:  {iterations}");
    println!("  Payload:     10 floats = 40 bytes each");
    println!("  Valid:        {valid}");
    println!("  Duration:    {elapsed:?}");
    println!(
        "  Per-cycle:   {:.2}µs",
        elapsed.as_micros() as f64 / iterations as f64
    );
    assert_eq!(valid, iterations);
}

#[test]
fn stress_reputation_slashing_cascade() {
    let mut store = ReputationStore::new();

    // Register 100 peers
    for id in 0..100u16 {
        store.register_peer(&peer_key(id));
    }

    let start = Instant::now();
    let mut expelled = 0u32;

    // Slash half the peers repeatedly with false reports
    for id in 0..50u16 {
        let key = peer_key(id);
        for _ in 0..10 {
            store.record_false_report(&key);
        }
        if !store.is_trusted(&key) {
            expelled += 1;
        }
    }
    // Reward the other half
    for id in 50..100u16 {
        let key = peer_key(id);
        for _ in 0..5 {
            store.record_accurate_report(&key);
        }
    }
    let elapsed = start.elapsed();

    println!("\n=== REPUTATION CASCADE ===");
    println!("  Total peers:  100");
    println!("  Slashed:      50 (10× false reports each)");
    println!("  Rewarded:     50 (5× accurate reports each)");
    println!("  Expelled:     {expelled}");
    println!("  Duration:     {elapsed:?}");
    assert!(expelled >= 30, "heavily-slashed peers should lose trust");
}

#[test]
fn stress_full_pipeline_ioc_to_proof() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use ring::rand::SystemRandom;

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
    let pub_key = key_pair.public_key().as_ref();

    let mut engine = ConsensusEngine::new();
    let mut reputation = ReputationStore::new();

    // Register 20 peers
    for id in 0..20u16 {
        reputation.register_peer(&peer_key(id));
    }

    let start = Instant::now();
    let mut end_to_end_valid = 0u32;

    // Full pipeline: IoC → consensus → ZKP proof → verify
    for ioc_idx in 0..100u16 {
        let ioc = make_ioc(ioc_idx);

        // Submit from 3 peers — 3rd should trigger acceptance (threshold=3)
        for voter in 0..3u16 {
            let result = engine.submit_ioc(&ioc, &peer_key(voter));
            if matches!(result, ConsensusResult::Accepted(_)) {
                // Generate signed ZKP proof for the accepted IoC
                let proof = prover::prove_threat(
                    ioc.ja4.as_ref().map(|s| s.as_bytes()),
                    ioc.entropy_score.map_or(false, |e| e > 7000),
                    true,
                    ioc.ioc_type,
                    Some(&key_pair),
                );

                // Verify the proof
                if matches!(
                    verifier::verify_threat(&proof, Some(pub_key)),
                    verifier::VerifyResult::Valid
                ) {
                    end_to_end_valid += 1;
                    for v in 0..3u16 {
                        reputation.record_accurate_report(&peer_key(v));
                    }
                }
            }
        }
    }
    let elapsed = start.elapsed();

    println!("\n=== FULL PIPELINE: IoC → CONSENSUS → ZKP ===");
    println!("  IoCs processed:  100");
    println!("  E2E valid:       {end_to_end_valid}");
    println!("  Duration:        {elapsed:?}");
    println!(
        "  Per-pipeline:    {:.2}µs",
        elapsed.as_micros() as f64 / 100.0
    );
    assert_eq!(end_to_end_valid, 100);
}
