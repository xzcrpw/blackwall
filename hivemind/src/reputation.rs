/// Stake-based peer reputation system for HiveMind.
///
/// Each peer starts with an initial stake. Accurate IoC reports increase
/// reputation; false reports trigger slashing (stake confiscation).
/// Only peers above the minimum trusted threshold participate in consensus.
use common::hivemind;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Internal reputation state for a single peer.
#[derive(Clone, Debug)]
struct PeerReputation {
    /// Current stake (reduced by slashing, increased by rewards).
    stake: u64,
    /// Number of IoC reports confirmed as accurate by consensus.
    accurate_reports: u64,
    /// Number of IoC reports flagged as false by consensus.
    false_reports: u64,
    /// Unix timestamp of last activity.
    last_active: u64,
}

impl PeerReputation {
    fn new() -> Self {
        Self {
            stake: hivemind::INITIAL_STAKE,
            accurate_reports: 0,
            false_reports: 0,
            last_active: now_secs(),
        }
    }
}

/// Manages reputation scores for all known peers.
pub struct ReputationStore {
    peers: HashMap<[u8; 32], PeerReputation>,
}

impl Default for ReputationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationStore {
    /// Create a new empty reputation store.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Register a new peer with initial stake. Returns false if already exists.
    ///
    /// New peers start with `INITIAL_STAKE` (below the trusted threshold).
    /// They must earn trust through accurate reports before participating
    /// in consensus. Use `register_seed_peer()` for bootstrap nodes.
    pub fn register_peer(&mut self, pubkey: &[u8; 32]) -> bool {
        if self.peers.contains_key(pubkey) {
            debug!(pubkey = hex::encode(pubkey), "Peer already registered");
            return false;
        }
        self.peers.insert(*pubkey, PeerReputation::new());
        info!(pubkey = hex::encode(pubkey), "Peer registered with initial stake");
        true
    }

    /// Register a seed peer with elevated initial stake (trusted from start).
    ///
    /// Seed peers are explicitly configured in the HiveMind config to
    /// bootstrap the reputation network. They start above MIN_TRUSTED so
    /// their IoC reports count toward consensus immediately.
    pub fn register_seed_peer(&mut self, pubkey: &[u8; 32]) -> bool {
        if self.peers.contains_key(pubkey) {
            debug!(pubkey = hex::encode(pubkey), "Seed peer already registered");
            return false;
        }
        let mut rep = PeerReputation::new();
        rep.stake = hivemind::SEED_PEER_STAKE;
        self.peers.insert(*pubkey, rep);
        info!(
            pubkey = hex::encode(pubkey),
            stake = hivemind::SEED_PEER_STAKE,
            "Seed peer registered with elevated stake"
        );
        true
    }

    /// Record an accurate IoC report — reward the reporting peer.
    pub fn record_accurate_report(&mut self, pubkey: &[u8; 32]) {
        if let Some(rep) = self.peers.get_mut(pubkey) {
            rep.accurate_reports += 1;
            rep.stake = rep.stake.saturating_add(hivemind::ACCURACY_REWARD);
            rep.last_active = now_secs();
            debug!(
                pubkey = hex::encode(pubkey),
                new_stake = rep.stake,
                "Accurate report rewarded"
            );
        }
    }

    /// Record a false IoC report — slash the reporting peer's stake.
    ///
    /// Slashing reduces stake by `SLASHING_PENALTY_PERCENT`%.
    /// If stake drops to 0, the peer is effectively banned from consensus.
    pub fn record_false_report(&mut self, pubkey: &[u8; 32]) {
        if let Some(rep) = self.peers.get_mut(pubkey) {
            rep.false_reports += 1;
            let penalty = (rep.stake * hivemind::SLASHING_PENALTY_PERCENT / 100).max(1);
            rep.stake = rep.stake.saturating_sub(penalty);
            rep.last_active = now_secs();
            warn!(
                pubkey = hex::encode(pubkey),
                penalty,
                new_stake = rep.stake,
                false_count = rep.false_reports,
                "Peer slashed for false IoC report"
            );
        }
    }

    /// Check whether a peer's reputation is above the trusted threshold.
    pub fn is_trusted(&self, pubkey: &[u8; 32]) -> bool {
        self.peers
            .get(pubkey)
            .map(|rep| rep.stake >= hivemind::MIN_TRUSTED_REPUTATION)
            .unwrap_or(false)
    }

    /// Get the current stake for a peer. Returns 0 for unknown peers.
    pub fn get_stake(&self, pubkey: &[u8; 32]) -> u64 {
        self.peers.get(pubkey).map(|rep| rep.stake).unwrap_or(0)
    }

    /// Get the reputation record for a peer (for mesh sharing).
    pub fn get_record(&self, pubkey: &[u8; 32]) -> Option<hivemind::PeerReputationRecord> {
        self.peers.get(pubkey).map(|rep| hivemind::PeerReputationRecord {
            peer_pubkey: *pubkey,
            stake: rep.stake,
            accurate_reports: rep.accurate_reports,
            false_reports: rep.false_reports,
            last_active: rep.last_active,
        })
    }

    /// Total number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Remove peers that have been inactive for longer than the given duration.
    pub fn evict_inactive(&mut self, max_inactive_secs: u64) {
        let cutoff = now_secs().saturating_sub(max_inactive_secs);
        let before = self.peers.len();
        self.peers.retain(|_, rep| rep.last_active >= cutoff);
        let evicted = before - self.peers.len();
        if evicted > 0 {
            info!(evicted, "Evicted inactive peers from reputation store");
        }
    }
}

/// Simple hex encoder for pubkeys in log messages (avoids adding `hex` crate).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
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

    fn test_pubkey(id: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = id;
        key
    }

    #[test]
    fn register_and_trust() {
        let mut store = ReputationStore::new();
        let pk = test_pubkey(1);
        assert!(store.register_peer(&pk));
        assert!(!store.register_peer(&pk)); // duplicate
        // New peers start BELOW trusted threshold (INITIAL_STAKE < MIN_TRUSTED)
        assert!(!store.is_trusted(&pk));
        assert_eq!(store.get_stake(&pk), hivemind::INITIAL_STAKE);
    }

    #[test]
    fn seed_peer_trusted_immediately() {
        let mut store = ReputationStore::new();
        let pk = test_pubkey(10);
        assert!(store.register_seed_peer(&pk));
        assert!(!store.register_seed_peer(&pk)); // duplicate
        assert!(store.is_trusted(&pk));
        assert_eq!(store.get_stake(&pk), hivemind::SEED_PEER_STAKE);
    }

    #[test]
    fn new_peer_earns_trust() {
        let mut store = ReputationStore::new();
        let pk = test_pubkey(11);
        store.register_peer(&pk);
        assert!(!store.is_trusted(&pk));
        // Earn trust through accurate reports
        // Need (MIN_TRUSTED - INITIAL_STAKE) / ACCURACY_REWARD = (50-30)/5 = 4 reports
        for _ in 0..4 {
            store.record_accurate_report(&pk);
        }
        assert!(store.is_trusted(&pk));
    }

    #[test]
    fn reward_increases_stake() {
        let mut store = ReputationStore::new();
        let pk = test_pubkey(2);
        store.register_peer(&pk);
        store.record_accurate_report(&pk);
        assert_eq!(
            store.get_stake(&pk),
            hivemind::INITIAL_STAKE + hivemind::ACCURACY_REWARD
        );
    }

    #[test]
    fn slashing_reduces_stake() {
        let mut store = ReputationStore::new();
        let pk = test_pubkey(3);
        store.register_peer(&pk);
        let initial = store.get_stake(&pk);
        store.record_false_report(&pk);
        let after = store.get_stake(&pk);
        assert!(after < initial);
        let expected_penalty = initial * hivemind::SLASHING_PENALTY_PERCENT / 100;
        assert_eq!(after, initial - expected_penalty);
    }

    #[test]
    fn repeated_slashing_reaches_zero() {
        let mut store = ReputationStore::new();
        let pk = test_pubkey(4);
        store.register_peer(&pk);
        // Slash many times — stake should never underflow
        for _ in 0..100 {
            store.record_false_report(&pk);
        }
        assert_eq!(store.get_stake(&pk), 0);
        assert!(!store.is_trusted(&pk));
    }

    #[test]
    fn unknown_peer_not_trusted() {
        let store = ReputationStore::new();
        assert!(!store.is_trusted(&test_pubkey(99)));
        assert_eq!(store.get_stake(&test_pubkey(99)), 0);
    }
}
