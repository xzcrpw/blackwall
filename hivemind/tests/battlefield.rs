//! Battlefield Simulation — Full-scale E2E integration tests for HiveMind Threat Mesh.
//!
//! Simulates a hostile network environment with 10 virtual HiveMind nodes
//! under Sybil attack, coordinated botnet detection, federated learning
//! with Byzantine actors, and ZKP-backed consensus verification.
//!
//! These tests exercise the real code paths at module integration boundaries,
//! NOT the libp2p transport layer (which requires a live network stack).

use common::hivemind as hm;
use hm::{IoC, IoCType, ThreatSeverity};
use hivemind::consensus::{ConsensusEngine, ConsensusResult};
use hivemind::ml::aggregator::{AggregatorError, FedAvgAggregator};
use hivemind::ml::defense::{GradientDefense, GradientVerdict};
use hivemind::ml::local_model::LocalModel;
use hivemind::reputation::ReputationStore;
use hivemind::sybil_guard::{SybilError, SybilGuard};
use hivemind::zkp::{prover, verifier};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a deterministic peer pubkey from an ID byte.
fn peer_key(id: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = id;
    // Spread entropy so PoW nonce search starts differently per peer
    key[31] = id.wrapping_mul(37);
    key
}

/// Create a JA4 IoC for consensus testing.
fn make_ja4_ioc(ip: u32) -> IoC {
    IoC {
        ioc_type: IoCType::Ja4Fingerprint as u8,
        severity: ThreatSeverity::High as u8,
        ip,
        ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
        entropy_score: Some(7800),
        description: "Suspicious JA4 fingerprint — possible C2 beacon".into(),
        first_seen: now_secs(),
        confirmations: 0,
        zkp_proof: Vec::new(),
    }
}

/// Create a malicious-IP IoC.
fn make_malicious_ip_ioc(ip: u32) -> IoC {
    IoC {
        ioc_type: IoCType::MaliciousIp as u8,
        severity: ThreatSeverity::Critical as u8,
        ip,
        ja4: None,
        entropy_score: None,
        description: "Known C2 server".into(),
        first_seen: now_secs(),
        confirmations: 0,
        zkp_proof: Vec::new(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ===========================================================================
// Scenario 1 — The Swarm: Spawn 10 virtual HiveMind nodes
// ===========================================================================

#[test]
fn scenario_1_swarm_spawn_10_nodes() {
    let mut guard = SybilGuard::new();
    let mut reputation = ReputationStore::new();
    let start = Instant::now();

    // Register 10 nodes via valid Proof-of-Work
    for id in 1..=10u8 {
        let pk = peer_key(id);
        let challenge = SybilGuard::generate_pow(&pk, hm::POW_DIFFICULTY_BITS);

        // PoW must verify successfully
        let result = guard.verify_registration(&challenge);
        assert!(
            result.is_ok(),
            "Node {id} PoW verification failed: {result:?}"
        );

        // Register peer as seed peer (bootstrap nodes get elevated stake)
        reputation.register_seed_peer(&pk);
        assert!(
            reputation.is_trusted(&pk),
            "Seed peer node {id} should be trusted (SEED_PEER_STAKE >= MIN_TRUSTED)"
        );
    }

    let elapsed = start.elapsed();
    eprintln!(
        "[SWARM] 10 nodes registered via PoW in {:.2?} — all trusted (seed peers)",
        elapsed
    );

    // All 10 peers should be tracked
    assert_eq!(reputation.peer_count(), 10);
}

// ===========================================================================
// Scenario 2 — Sybil Attack: 5 malicious nodes with invalid PoW
// ===========================================================================

#[test]
fn scenario_2_sybil_attack_rejected() {
    let mut guard = SybilGuard::new();

    // First register 2 legitimate nodes so the SybilGuard has state
    for id in 1..=2u8 {
        let pk = peer_key(id);
        let challenge = SybilGuard::generate_pow(&pk, hm::POW_DIFFICULTY_BITS);
        guard
            .verify_registration(&challenge)
            .expect("Legitimate node should pass PoW");
    }

    // --- Attack vector 1: Wrong nonce (hash won't meet difficulty) ---
    let pk = peer_key(200);
    let mut forged = SybilGuard::generate_pow(&pk, hm::POW_DIFFICULTY_BITS);
    forged.nonce = forged.nonce.wrapping_add(1); // corrupt the solution
    let result = guard.verify_registration(&forged);
    assert_eq!(
        result,
        Err(SybilError::InvalidProof),
        "Corrupted nonce should yield InvalidProof"
    );

    // --- Attack vector 2: Insufficient difficulty ---
    let low_diff = hm::PowChallenge {
        peer_pubkey: peer_key(201),
        nonce: 0,
        timestamp: now_secs(),
        difficulty: hm::POW_DIFFICULTY_BITS - 5, // too easy
    };
    let result = guard.verify_registration(&low_diff);
    assert_eq!(
        result,
        Err(SybilError::InsufficientDifficulty),
        "Low difficulty should be rejected"
    );

    // --- Attack vector 3: Stale timestamp ---
    let pk = peer_key(202);
    let mut stale = SybilGuard::generate_pow(&pk, hm::POW_DIFFICULTY_BITS);
    stale.timestamp = 1_000_000; // year ~2001, way beyond TTL
    let result = guard.verify_registration(&stale);
    assert_eq!(
        result,
        Err(SybilError::StaleChallenge),
        "Stale timestamp should be rejected"
    );

    // --- Attack vector 4: Future timestamp ---
    let future = hm::PowChallenge {
        peer_pubkey: peer_key(203),
        nonce: 0,
        timestamp: now_secs() + 3600, // 1 hour in the future
        difficulty: hm::POW_DIFFICULTY_BITS,
    };
    let result = guard.verify_registration(&future);
    assert_eq!(
        result,
        Err(SybilError::StaleChallenge),
        "Future timestamp should be rejected"
    );

    // --- Attack vector 5: Replay with someone else's pubkey ---
    let victim_pk = peer_key(1);
    let attacker_pk = peer_key(204);
    let mut replay = SybilGuard::generate_pow(&victim_pk, hm::POW_DIFFICULTY_BITS);
    replay.peer_pubkey = attacker_pk; // swap pubkey — hash won't match
    let result = guard.verify_registration(&replay);
    assert_eq!(
        result,
        Err(SybilError::InvalidProof),
        "Replay with swapped pubkey should fail"
    );

    eprintln!("[SYBIL] All 5 attack vectors rejected correctly");
}

// ===========================================================================
// Scenario 3 — The Botnet Blitz: 3 nodes detect same JA4 → consensus
// ===========================================================================

#[test]
fn scenario_3_botnet_blitz_consensus() {
    let mut consensus = ConsensusEngine::new();
    let mut reputation = ReputationStore::new();

    // Register 10 honest peers
    for id in 1..=10u8 {
        reputation.register_peer(&peer_key(id));
    }

    let botnet_ioc = make_ja4_ioc(0xC0A80001); // 192.168.0.1

    // Peer 1 submits — pending (1/3)
    let r1 = consensus.submit_ioc(&botnet_ioc, &peer_key(1));
    assert_eq!(r1, ConsensusResult::Pending(1));

    // Peer 2 submits — pending (2/3)
    let r2 = consensus.submit_ioc(&botnet_ioc, &peer_key(2));
    assert_eq!(r2, ConsensusResult::Pending(2));

    // Peer 1 tries again — duplicate
    let dup = consensus.submit_ioc(&botnet_ioc, &peer_key(1));
    assert_eq!(dup, ConsensusResult::DuplicatePeer);

    // Peer 3 submits — threshold reached → Accepted(3)
    let r3 = consensus.submit_ioc(&botnet_ioc, &peer_key(3));
    assert_eq!(
        r3,
        ConsensusResult::Accepted(hm::CROSS_VALIDATION_THRESHOLD),
        "Third confirmation should trigger acceptance"
    );

    // Drain accepted IoCs
    let accepted = consensus.drain_accepted();
    assert_eq!(accepted.len(), 1, "Exactly one IoC should be accepted");
    assert_eq!(
        accepted[0].confirmations as usize,
        hm::CROSS_VALIDATION_THRESHOLD
    );
    assert_eq!(accepted[0].ioc_type, IoCType::Ja4Fingerprint as u8);

    // Reward the 3 confirming peers
    for id in 1..=3u8 {
        reputation.record_accurate_report(&peer_key(id));
    }

    // Verify stake increased for reporters
    for id in 1..=3u8 {
        let stake = reputation.get_stake(&peer_key(id));
        assert_eq!(
            stake,
            hm::INITIAL_STAKE + hm::ACCURACY_REWARD,
            "Reporter {id} should have earned accuracy reward"
        );
    }

    // Non-reporters unchanged
    let stake4 = reputation.get_stake(&peer_key(4));
    assert_eq!(stake4, hm::INITIAL_STAKE);

    // Simulate a false reporter and verify slashing
    reputation.record_false_report(&peer_key(10));
    let stake10 = reputation.get_stake(&peer_key(10));
    let expected_slash = hm::INITIAL_STAKE
        - (hm::INITIAL_STAKE * hm::SLASHING_PENALTY_PERCENT / 100);
    assert_eq!(stake10, expected_slash, "False reporter should be slashed");

    // Simulate propagation to remaining 7 nodes (in-memory) and measure latency
    let start = Instant::now();
    for id in 4..=10u8 {
        let r = consensus.submit_ioc(&accepted[0], &peer_key(id));
        // After drain, re-submitting creates a fresh pending entry.
        // Threshold is 3, so peers 4,5 → Pending; peer 6 → Accepted again;
        // then peers 7,8 → Pending; peer 9 → Accepted; peer 10 → Pending.
        match r {
            ConsensusResult::Pending(_) | ConsensusResult::Accepted(_) => {}
            other => panic!(
                "Unexpected result for peer {id}: {other:?}"
            ),
        }
    }
    let propagation = start.elapsed();
    eprintln!("[BOTNET] Consensus reached in 3 confirmations, propagation sim: {propagation:.2?}");
    assert!(
        propagation.as_millis() < 200,
        "Propagation simulation should complete in < 200ms"
    );

    eprintln!("[BOTNET] Consensus + reputation + propagation verified");
}

// ===========================================================================
// Scenario 4 — Federated Learning Stress: 5 rounds with Byzantine actors
// ===========================================================================

#[test]
fn scenario_4_federated_learning_stress() {
    let mut aggregator = FedAvgAggregator::new();
    let mut defense = GradientDefense::new();

    let param_count = {
        let model = LocalModel::new(0.01);
        model.param_count()
    };
    let dim = hm::FL_FEATURE_DIM;

    // Create 7 honest models and train them briefly on synthetic data
    let mut honest_models: Vec<LocalModel> = (0..7)
        .map(|_| LocalModel::new(0.01))
        .collect();

    // Simulated feature vector (mix of benign/malicious patterns)
    let mut features = vec![0.0_f32; dim];
    for (i, f) in features.iter_mut().enumerate() {
        *f = ((i as f32) * 0.314159).sin().abs();
    }

    // Run 5 FL rounds
    for round in 0..5u64 {
        assert_eq!(aggregator.current_round(), round);
        let mut honest_count = 0;
        let mut malicious_rejected = 0;

        // Honest peers: train model and submit gradients
        for (idx, model) in honest_models.iter_mut().enumerate() {
            let target = if idx % 2 == 0 { 1.0 } else { 0.0 };
            let _output = model.forward(&features);
            let grads = model.backward(target);

            // Defense check before aggregation
            let verdict = defense.check(&grads);
            if verdict == GradientVerdict::Safe {
                let result = aggregator.submit_gradients(
                    &peer_key((idx + 1) as u8),
                    round,
                    grads,
                );
                assert!(result.is_ok(), "Honest peer {idx} submit failed: {result:?}");
                honest_count += 1;
            }
        }

        // Byzantine peer 1: free-rider (zero gradients)
        let zeros = vec![0.0_f32; param_count];
        let v1 = defense.check(&zeros);
        assert_eq!(
            v1,
            GradientVerdict::FreeRider,
            "Round {round}: zero gradients should be flagged as free-rider"
        );
        malicious_rejected += 1;

        // Byzantine peer 2: extreme norm (gradient explosion)
        let extreme: Vec<f32> = (0..param_count).map(|i| (i as f32) * 100.0).collect();
        let v2 = defense.check(&extreme);
        assert_eq!(
            v2,
            GradientVerdict::NormExceeded,
            "Round {round}: extreme gradients should exceed norm bound"
        );
        malicious_rejected += 1;

        // Byzantine peer 3: NaN injection
        let mut nan_grads = vec![1.0_f32; param_count];
        nan_grads[param_count / 2] = f32::NAN;
        let submit_nan = aggregator.submit_gradients(&peer_key(100), round, nan_grads);
        assert_eq!(
            submit_nan,
            Err(AggregatorError::InvalidValues),
            "Round {round}: NaN gradients should be rejected by aggregator"
        );
        malicious_rejected += 1;

        // Byzantine peer 4: wrong round
        let valid_grads = vec![0.5_f32; param_count];
        let submit_wrong = aggregator.submit_gradients(
            &peer_key(101),
            round + 99,
            valid_grads,
        );
        assert_eq!(
            submit_wrong,
            Err(AggregatorError::WrongRound),
            "Round {round}: wrong round should be rejected"
        );

        assert!(
            honest_count >= hm::FL_MIN_PEERS_PER_ROUND,
            "Round {round}: need at least {} honest peers, got {honest_count}",
            hm::FL_MIN_PEERS_PER_ROUND
        );

        // Aggregate with trimmed mean
        let aggregated = aggregator
            .aggregate()
            .expect("Aggregation should succeed with enough honest peers");

        // Verify aggregated gradient sanity
        assert_eq!(aggregated.len(), param_count);
        for (i, &val) in aggregated.iter().enumerate() {
            assert!(
                val.is_finite(),
                "Round {round}, dim {i}: aggregated value must be finite"
            );
        }

        // Apply aggregated gradients to each honest model
        for model in &mut honest_models {
            model.apply_gradients(&aggregated);
        }

        eprintln!(
            "[FL] Round {round}: {honest_count} honest peers, \
             {malicious_rejected} malicious rejected, \
             aggregated {param_count} params"
        );

        aggregator.advance_round();
    }

    assert_eq!(aggregator.current_round(), 5);
    eprintln!("[FL] 5 rounds completed — Byzantine resistance verified");
}

// ===========================================================================
// Scenario 5 — ZKP Proof Chain: prove → verify cycle
// ===========================================================================

#[test]
fn scenario_5_zkp_proof_chain() {
    let start = Instant::now();

    // Test 1: Prove a JA4 fingerprint-based threat
    let ja4_fp = b"t13d1516h2_8daaf6152771_e5627efa2ab1";
    let proof_ja4 = prover::prove_threat(
        Some(ja4_fp),
        true,  // entropy exceeded
        true,  // classified malicious
        IoCType::Ja4Fingerprint as u8,
        None,
    );
    let result = verifier::verify_threat(&proof_ja4, None);
    assert_eq!(
        result,
        verifier::VerifyResult::ValidStub,
        "JA4 proof should verify as valid stub"
    );

    // Test 2: Prove an entropy anomaly without JA4
    let proof_entropy = prover::prove_threat(
        None,
        true,
        true,
        IoCType::EntropyAnomaly as u8,
        None,
    );
    let result = verifier::verify_threat(&proof_entropy, None);
    assert_eq!(
        result,
        verifier::VerifyResult::ValidStub,
        "Entropy proof should verify as valid stub"
    );

    // Test 3: Prove a malicious IP detection
    let proof_ip = prover::prove_threat(
        None,
        false,
        true,
        IoCType::MaliciousIp as u8,
        None,
    );
    let result = verifier::verify_threat(&proof_ip, None);
    assert_eq!(
        result,
        verifier::VerifyResult::ValidStub,
    );

    // Test 4: Empty proof data
    let empty_proof = hm::ThreatProof {
        version: 0,
        statement: hm::ProofStatement {
            ja4_hash: None,
            entropy_exceeded: false,
            classified_malicious: false,
            ioc_type: 0,
        },
        proof_data: Vec::new(),
        created_at: now_secs(),
    };
    let result = verifier::verify_threat(&empty_proof, None);
    assert_eq!(result, verifier::VerifyResult::EmptyProof);

    // Test 5: Tampered proof data
    let mut tampered = prover::prove_threat(
        Some(ja4_fp),
        true,
        true,
        IoCType::Ja4Fingerprint as u8,
        None,
    );
    // Flip a byte in the proof
    if let Some(byte) = tampered.proof_data.last_mut() {
        *byte ^= 0xFF;
    }
    let result = verifier::verify_threat(&tampered, None);
    assert_eq!(
        result,
        verifier::VerifyResult::CommitmentMismatch,
        "Tampered proof should fail commitment check"
    );

    // Test 6: Unsupported version
    let future_proof = hm::ThreatProof {
        version: 99,
        statement: hm::ProofStatement {
            ja4_hash: None,
            entropy_exceeded: false,
            classified_malicious: false,
            ioc_type: 0,
        },
        proof_data: vec![0u8; 100],
        created_at: now_secs(),
    };
    let result = verifier::verify_threat(&future_proof, None);
    assert_eq!(result, verifier::VerifyResult::UnsupportedVersion);

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 50,
        "6 ZKP prove/verify cycles should complete in < 50ms, took {elapsed:.2?}"
    );
    eprintln!(
        "[ZKP] 6 prove/verify cycles completed in {elapsed:.2?} — all correct"
    );
}

// ===========================================================================
// Scenario 6 — Full Pipeline: PoW → Consensus → Reputation → ZKP → FL
// ===========================================================================

#[test]
fn scenario_6_full_pipeline_integration() {
    let mut guard = SybilGuard::new();
    let mut reputation = ReputationStore::new();
    let mut consensus = ConsensusEngine::new();
    let mut aggregator = FedAvgAggregator::new();
    let mut defense = GradientDefense::new();

    let pipeline_start = Instant::now();

    // --- Phase A: Bootstrap 5 nodes via PoW ---
    let node_count = 5u8;
    for id in 1..=node_count {
        let pk = peer_key(id);
        let challenge = SybilGuard::generate_pow(&pk, hm::POW_DIFFICULTY_BITS);
        guard
            .verify_registration(&challenge)
            .unwrap_or_else(|e| panic!("Node {id} PoW failed: {e:?}"));
        reputation.register_seed_peer(&pk);
    }
    eprintln!("[PIPELINE] Phase A: {node_count} nodes bootstrapped");

    // --- Phase B: 3 nodes detect a DNS tunnel IoC → consensus ---
    let dns_ioc = IoC {
        ioc_type: IoCType::DnsTunnel as u8,
        severity: ThreatSeverity::Critical as u8,
        ip: 0x0A000001, // 10.0.0.1
        ja4: None,
        entropy_score: Some(9200),
        description: "DNS tunneling detected — high entropy in TXT queries".into(),
        first_seen: now_secs(),
        confirmations: 0,
        zkp_proof: Vec::new(),
    };

    for id in 1..=3u8 {
        let r = consensus.submit_ioc(&dns_ioc, &peer_key(id));
        if id < 3 {
            assert!(matches!(r, ConsensusResult::Pending(_)));
        } else {
            assert_eq!(r, ConsensusResult::Accepted(3));
        }
    }

    let accepted = consensus.drain_accepted();
    assert_eq!(accepted.len(), 1);

    // Reward reporters
    for id in 1..=3u8 {
        reputation.record_accurate_report(&peer_key(id));
    }

    // --- Phase C: Generate ZKP for the accepted IoC ---
    let proof = prover::prove_threat(
        None,
        true,
        true,
        accepted[0].ioc_type,
        None,
    );
    let verify = verifier::verify_threat(&proof, None);
    assert_eq!(verify, verifier::VerifyResult::ValidStub);

    // --- Phase D: One FL round after detection ---
    let dim = hm::FL_FEATURE_DIM;
    let mut features = vec![0.0_f32; dim];
    for (i, f) in features.iter_mut().enumerate() {
        *f = ((i as f32) * 0.271828).cos().abs();
    }

    for id in 1..=node_count {
        let mut model = LocalModel::new(0.01);
        let _out = model.forward(&features);
        let grads = model.backward(1.0); // all train on "malicious"

        let verdict = defense.check(&grads);
        assert_eq!(verdict, GradientVerdict::Safe);

        aggregator
            .submit_gradients(&peer_key(id), 0, grads)
            .unwrap_or_else(|e| panic!("Node {id} gradient submit failed: {e}"));
    }

    let global_update = aggregator.aggregate().expect("Aggregation must succeed");
    assert!(
        global_update.iter().all(|v| v.is_finite()),
        "Aggregated model must contain only finite values"
    );

    // --- Phase E: Verify reputation state ---
    for id in 1..=3u8 {
        assert!(reputation.is_trusted(&peer_key(id)));
        let s = reputation.get_stake(&peer_key(id));
        assert!(
            s > hm::INITIAL_STAKE,
            "Reporter {id} should have earned rewards"
        );
    }

    let pipeline_elapsed = pipeline_start.elapsed();
    eprintln!(
        "[PIPELINE] Full pipeline (PoW→Consensus→ZKP→FL→Reputation) in {pipeline_elapsed:.2?}"
    );
}

// ===========================================================================
// Scenario 7 — Multi-IoC Consensus Storm
// ===========================================================================

#[test]
fn scenario_7_multi_ioc_consensus_storm() {
    let mut consensus = ConsensusEngine::new();
    let ioc_count = 50;
    let start = Instant::now();

    // Submit 50 distinct IoCs, each from 3 different peers → all accepted
    for i in 0..ioc_count {
        let ioc = make_malicious_ip_ioc(0x0A000000 + i as u32);
        for peer_id in 1..=3u8 {
            consensus.submit_ioc(&ioc, &peer_key(peer_id + (i as u8 * 3)));
        }
    }

    let accepted = consensus.drain_accepted();
    assert_eq!(
        accepted.len(),
        ioc_count,
        "All {ioc_count} IoCs should reach consensus"
    );

    let elapsed = start.elapsed();
    eprintln!(
        "[STORM] {ioc_count} IoCs × 3 confirmations = {} submissions in {elapsed:.2?}",
        ioc_count * 3
    );
    assert!(
        elapsed.as_millis() < 100,
        "150 consensus submissions should complete in < 100ms"
    );
}

// ===========================================================================
// Scenario 8 — Reputation Slashing Cascade
// ===========================================================================

#[test]
fn scenario_8_reputation_slashing_cascade() {
    let mut reputation = ReputationStore::new();

    // Register a peer and slash them repeatedly
    let pk = peer_key(42);
    reputation.register_peer(&pk);

    let initial = reputation.get_stake(&pk);
    assert_eq!(initial, hm::INITIAL_STAKE);

    // Slash multiple times — stake should decrease each time
    let mut prev_stake = initial;
    let slash_rounds = 5;
    for round in 0..slash_rounds {
        reputation.record_false_report(&pk);
        let new_stake = reputation.get_stake(&pk);
        assert!(
            new_stake < prev_stake,
            "Round {round}: stake should decrease after slashing"
        );
        prev_stake = new_stake;
    }

    // After multiple slashings, stake should be below trusted threshold
    let final_stake = reputation.get_stake(&pk);
    eprintln!(
        "[SLASH] Stake after {slash_rounds} slashes: {final_stake} (threshold: {})",
        hm::MIN_TRUSTED_REPUTATION
    );

    // At 25% slashing per round on initial stake of 100:
    // 100 → 75 → 56 → 42 → 31 → 23 — below 50 threshold after round 3
    assert!(
        !reputation.is_trusted(&pk),
        "Peer should be untrusted after cascade slashing"
    );
}
