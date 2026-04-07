/// Cross-validation of IoCs through N independent peers.
///
/// A single peer's IoC report is never trusted. The consensus module
/// tracks pending IoCs and requires at least `CROSS_VALIDATION_THRESHOLD`
/// independent peer confirmations before an IoC is accepted into the
/// local threat database.
use common::hivemind::{self, IoC};
use std::collections::HashMap;
use tracing::{debug, info};

/// Unique key for deduplicating IoC submissions.
///
/// Two IoCs are considered equivalent if they share the same type, IP,
/// and JA4 fingerprint.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct IoCKey {
    ioc_type: u8,
    ip: u32,
    ja4: Option<String>,
}

impl From<&IoC> for IoCKey {
    fn from(ioc: &IoC) -> Self {
        Self {
            ioc_type: ioc.ioc_type,
            ip: ioc.ip,
            ja4: ioc.ja4.clone(),
        }
    }
}

/// A pending IoC awaiting cross-validation from multiple peers.
#[derive(Clone, Debug)]
struct PendingIoC {
    /// The IoC being validated.
    ioc: IoC,
    /// Set of peer pubkeys that confirmed this IoC (Ed25519, 32 bytes).
    confirmations: Vec<[u8; 32]>,
    /// Unix timestamp when this pending entry was created.
    created_at: u64,
}

/// Result of submitting a peer's IoC confirmation.
#[derive(Debug, PartialEq, Eq)]
pub enum ConsensusResult {
    /// IoC accepted — threshold reached. Contains final confirmation count.
    Accepted(usize),
    /// IoC recorded but threshold not yet met. Contains current count.
    Pending(usize),
    /// Duplicate confirmation from the same peer — ignored.
    DuplicatePeer,
    /// The IoC expired before reaching consensus.
    Expired,
}

/// Manages cross-validation of IoCs across independent peers.
pub struct ConsensusEngine {
    /// Pending IoCs keyed by their dedup identity.
    pending: HashMap<IoCKey, PendingIoC>,
    /// IoCs that reached consensus (for querying accepted threats).
    accepted: Vec<IoC>,
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusEngine {
    /// Create a new consensus engine.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            accepted: Vec::new(),
        }
    }

    /// Submit a peer's IoC report for cross-validation.
    ///
    /// Returns the consensus result: whether threshold was met, pending, or duplicate.
    pub fn submit_ioc(
        &mut self,
        ioc: &IoC,
        reporter_pubkey: &[u8; 32],
    ) -> ConsensusResult {
        let key = IoCKey::from(ioc);
        let now = now_secs();

        // Check if this IoC is already pending
        if let Some(pending) = self.pending.get_mut(&key) {
            // Check expiry
            if now.saturating_sub(pending.created_at) > hivemind::CONSENSUS_TIMEOUT_SECS {
                debug!("Pending IoC expired — removing");
                self.pending.remove(&key);
                return ConsensusResult::Expired;
            }

            // Check for duplicate peer confirmation
            if pending.confirmations.iter().any(|pk| pk == reporter_pubkey) {
                debug!("Duplicate confirmation from same peer — ignoring");
                return ConsensusResult::DuplicatePeer;
            }

            pending.confirmations.push(*reporter_pubkey);
            let count = pending.confirmations.len();

            if count >= hivemind::CROSS_VALIDATION_THRESHOLD {
                // Consensus reached — move to accepted
                let mut accepted_ioc = pending.ioc.clone();
                accepted_ioc.confirmations = count as u32;
                info!(
                    count,
                    ioc_type = accepted_ioc.ioc_type,
                    "IoC reached consensus — accepted"
                );
                self.accepted.push(accepted_ioc);
                self.pending.remove(&key);
                return ConsensusResult::Accepted(count);
            }

            debug!(count, threshold = hivemind::CROSS_VALIDATION_THRESHOLD, "IoC pending");
            ConsensusResult::Pending(count)
        } else {
            // First report of this IoC
            let pending = PendingIoC {
                ioc: ioc.clone(),
                confirmations: vec![*reporter_pubkey],
                created_at: now,
            };
            self.pending.insert(key, pending);
            debug!("New IoC submitted — awaiting cross-validation");
            ConsensusResult::Pending(1)
        }
    }

    /// Drain all newly accepted IoCs. Returns and clears the accepted list.
    pub fn drain_accepted(&mut self) -> Vec<IoC> {
        std::mem::take(&mut self.accepted)
    }

    /// Evict expired pending IoCs. Returns the number removed.
    pub fn evict_expired(&mut self) -> usize {
        let now = now_secs();
        let before = self.pending.len();
        self.pending.retain(|_, pending| {
            now.saturating_sub(pending.created_at) <= hivemind::CONSENSUS_TIMEOUT_SECS
        });
        let removed = before - self.pending.len();
        if removed > 0 {
            info!(removed, "Evicted expired pending IoCs");
        }
        removed
    }

    /// Number of IoCs currently awaiting consensus.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
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

    fn make_ioc() -> IoC {
        IoC {
            ioc_type: 0,
            severity: 3,
            ip: 0xC0A80001, // 192.168.0.1
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".to_string()),
            entropy_score: Some(7500),
            description: "Test malicious IP".to_string(),
            first_seen: 1700000000,
            confirmations: 0,
            zkp_proof: Vec::new(),
        }
    }

    fn peer_key(id: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = id;
        key
    }

    #[test]
    fn single_report_stays_pending() {
        let mut engine = ConsensusEngine::new();
        let ioc = make_ioc();
        let result = engine.submit_ioc(&ioc, &peer_key(1));
        assert_eq!(result, ConsensusResult::Pending(1));
        assert_eq!(engine.pending_count(), 1);
    }

    #[test]
    fn duplicate_peer_ignored() {
        let mut engine = ConsensusEngine::new();
        let ioc = make_ioc();
        engine.submit_ioc(&ioc, &peer_key(1));
        let result = engine.submit_ioc(&ioc, &peer_key(1));
        assert_eq!(result, ConsensusResult::DuplicatePeer);
    }

    #[test]
    fn consensus_reached_at_threshold() {
        let mut engine = ConsensusEngine::new();
        let ioc = make_ioc();

        for i in 1..hivemind::CROSS_VALIDATION_THRESHOLD {
            let result = engine.submit_ioc(&ioc, &peer_key(i as u8));
            assert_eq!(result, ConsensusResult::Pending(i));
        }

        let result = engine.submit_ioc(
            &ioc,
            &peer_key(hivemind::CROSS_VALIDATION_THRESHOLD as u8),
        );
        assert_eq!(
            result,
            ConsensusResult::Accepted(hivemind::CROSS_VALIDATION_THRESHOLD)
        );
        assert_eq!(engine.pending_count(), 0);

        let accepted = engine.drain_accepted();
        assert_eq!(accepted.len(), 1);
        assert_eq!(
            accepted[0].confirmations,
            hivemind::CROSS_VALIDATION_THRESHOLD as u32
        );
    }

    #[test]
    fn different_iocs_tracked_separately() {
        let mut engine = ConsensusEngine::new();

        let mut ioc1 = make_ioc();
        ioc1.ip = 1;
        let mut ioc2 = make_ioc();
        ioc2.ip = 2;

        engine.submit_ioc(&ioc1, &peer_key(1));
        engine.submit_ioc(&ioc2, &peer_key(1));
        assert_eq!(engine.pending_count(), 2);
    }
}
