/// Sybil resistance via Proof-of-Work for new peer registration.
///
/// Before a peer can join the HiveMind mesh and participate in consensus,
/// it must solve a PoW challenge: find a nonce such that
/// SHA256(peer_pubkey || nonce || timestamp) has at least N leading zero bits.
///
/// This raises the cost of Sybil attacks (spawning many fake peers).
use common::hivemind;
use ring::digest;
use std::collections::VecDeque;
use tracing::{debug, info, warn};

/// Validates PoW challenges and enforces rate limiting.
pub struct SybilGuard {
    /// Rolling window of registration timestamps for rate limiting.
    registration_times: VecDeque<u64>,
}

impl Default for SybilGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SybilGuard {
    /// Create a new SybilGuard instance.
    pub fn new() -> Self {
        Self {
            registration_times: VecDeque::new(),
        }
    }

    /// Verify a Proof-of-Work challenge from a prospective peer.
    ///
    /// Returns `Ok(())` if the PoW is valid and rate limits allow registration.
    /// Returns `Err(reason)` if the PoW is invalid or rate limit is exceeded.
    pub fn verify_registration(
        &mut self,
        challenge: &hivemind::PowChallenge,
    ) -> Result<(), SybilError> {
        // Check PoW freshness — reject stale challenges
        let now = now_secs();
        if now.saturating_sub(challenge.timestamp) > hivemind::POW_CHALLENGE_TTL_SECS {
            warn!("Rejected stale PoW challenge");
            return Err(SybilError::StaleChallenge);
        }

        // Future timestamps with margin
        if challenge.timestamp > now + 30 {
            warn!("Rejected PoW challenge with future timestamp");
            return Err(SybilError::StaleChallenge);
        }

        // Verify difficulty matches minimum
        if challenge.difficulty < hivemind::POW_DIFFICULTY_BITS {
            warn!(
                actual = challenge.difficulty,
                required = hivemind::POW_DIFFICULTY_BITS,
                "PoW difficulty too low"
            );
            return Err(SybilError::InsufficientDifficulty);
        }

        // Verify the hash meets difficulty
        let hash = compute_pow_hash(
            &challenge.peer_pubkey,
            challenge.nonce,
            challenge.timestamp,
        );
        if !check_leading_zeros(&hash, challenge.difficulty) {
            warn!("PoW hash does not meet difficulty target");
            return Err(SybilError::InvalidProof);
        }

        // Rate limiting: max N registrations per minute
        self.prune_old_registrations(now);
        if self.registration_times.len() >= hivemind::MAX_PEER_REGISTRATIONS_PER_MINUTE {
            warn!("Peer registration rate limit exceeded");
            return Err(SybilError::RateLimited);
        }

        self.registration_times.push_back(now);
        info!("PoW verified — peer registration accepted");
        Ok(())
    }

    /// Generate a PoW solution for local node registration.
    ///
    /// Iterates nonces until finding one that satisfies the difficulty target.
    /// This is intentionally expensive for the registrant.
    pub fn generate_pow(peer_pubkey: &[u8; 32], difficulty: u32) -> hivemind::PowChallenge {
        let timestamp = now_secs();
        let mut nonce: u64 = 0;

        loop {
            let hash = compute_pow_hash(peer_pubkey, nonce, timestamp);
            if check_leading_zeros(&hash, difficulty) {
                debug!(nonce, "PoW solution found");
                return hivemind::PowChallenge {
                    peer_pubkey: *peer_pubkey,
                    nonce,
                    timestamp,
                    difficulty,
                };
            }
            nonce += 1;
        }
    }

    /// Remove registrations older than 60 seconds for rate limit window.
    fn prune_old_registrations(&mut self, now: u64) {
        let cutoff = now.saturating_sub(60);
        while let Some(&ts) = self.registration_times.front() {
            if ts < cutoff {
                self.registration_times.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Errors from Sybil guard verification.
#[derive(Debug, PartialEq, Eq)]
pub enum SybilError {
    /// The PoW challenge timestamp is too old.
    StaleChallenge,
    /// The PoW difficulty is below the minimum requirement.
    InsufficientDifficulty,
    /// The PoW hash does not satisfy the difficulty target.
    InvalidProof,
    /// Too many registrations in the rate limit window.
    RateLimited,
}

impl std::fmt::Display for SybilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SybilError::StaleChallenge => write!(f, "PoW challenge is stale"),
            SybilError::InsufficientDifficulty => write!(f, "PoW difficulty too low"),
            SybilError::InvalidProof => write!(f, "PoW hash does not meet difficulty"),
            SybilError::RateLimited => write!(f, "Peer registration rate limited"),
        }
    }
}

impl std::error::Error for SybilError {}

/// Compute SHA256(peer_pubkey || nonce_le || timestamp_le).
fn compute_pow_hash(peer_pubkey: &[u8; 32], nonce: u64, timestamp: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(48);
    input.extend_from_slice(peer_pubkey);
    input.extend_from_slice(&nonce.to_le_bytes());
    input.extend_from_slice(&timestamp.to_le_bytes());

    let digest = digest::digest(&digest::SHA256, &input);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

/// Check that a hash has at least `n` leading zero bits.
fn check_leading_zeros(hash: &[u8; 32], n: u32) -> bool {
    let mut remaining = n;
    for byte in hash {
        if remaining == 0 {
            return true;
        }
        if remaining >= 8 {
            if *byte != 0 {
                return false;
            }
            remaining -= 8;
        } else {
            // Check partial byte: top `remaining` bits must be 0
            let mask = 0xFF_u8 << (8 - remaining);
            return byte & mask == 0;
        }
    }
    remaining == 0
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_check() {
        let mut hash = [0u8; 32];
        assert!(check_leading_zeros(&hash, 0));
        assert!(check_leading_zeros(&hash, 8));
        assert!(check_leading_zeros(&hash, 256));

        hash[0] = 0x01; // 7 leading zeros
        assert!(check_leading_zeros(&hash, 7));
        assert!(!check_leading_zeros(&hash, 8));

        hash[0] = 0x0F; // 4 leading zeros
        assert!(check_leading_zeros(&hash, 4));
        assert!(!check_leading_zeros(&hash, 5));
    }

    #[test]
    fn pow_generation_and_verification() {
        let pubkey = [42u8; 32];
        // Use low difficulty for test speed
        let challenge = SybilGuard::generate_pow(&pubkey, 8);
        assert_eq!(challenge.difficulty, 8);
        assert_eq!(challenge.peer_pubkey, pubkey);

        // Direct hash verification (bypass verify_registration which enforces
        // minimum difficulty = POW_DIFFICULTY_BITS)
        let hash = compute_pow_hash(&pubkey, challenge.nonce, challenge.timestamp);
        assert!(check_leading_zeros(&hash, 8));
    }

    #[test]
    fn rejects_insufficient_difficulty() {
        let pubkey = [1u8; 32];
        let challenge = hivemind::PowChallenge {
            peer_pubkey: pubkey,
            nonce: 0,
            timestamp: now_secs(),
            difficulty: 1, // Below POW_DIFFICULTY_BITS
        };

        let mut guard = SybilGuard::new();
        assert_eq!(
            guard.verify_registration(&challenge),
            Err(SybilError::InsufficientDifficulty)
        );
    }

    #[test]
    fn rejects_stale_challenge() {
        let pubkey = [2u8; 32];
        let challenge = hivemind::PowChallenge {
            peer_pubkey: pubkey,
            nonce: 0,
            timestamp: 1000, // Very old
            difficulty: hivemind::POW_DIFFICULTY_BITS,
        };

        let mut guard = SybilGuard::new();
        assert_eq!(
            guard.verify_registration(&challenge),
            Err(SybilError::StaleChallenge)
        );
    }
}
