/// FedAvg aggregator with Byzantine fault tolerance.
///
/// Implements the Federated Averaging algorithm with a trimmed mean
/// defense against Byzantine (poisoned) gradient contributions.
///
/// # Byzantine Resistance
/// Instead of naive averaging, gradients are sorted per-dimension and
/// the top/bottom `FL_BYZANTINE_TRIM_PERCENT`% are discarded before
/// averaging. This neutralizes gradient poisoning from malicious peers.
///
/// # Biological Analogy
/// This module is the **T-cell** of the immune system: it aggregates
/// signals (gradients) from B-cells (local sensors) into a unified
/// immune response (global model).
use common::hivemind;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Pending gradient contribution from a single peer.
#[derive(Clone, Debug)]
struct PeerGradient {
    /// Decrypted gradient vector.
    gradients: Vec<f32>,
    /// Timestamp when received (for round expiry and telemetry).
    #[allow(dead_code)]
    timestamp: u64,
}

/// Manages gradient collection and aggregation for federated learning.
pub struct FedAvgAggregator {
    /// Current aggregation round.
    current_round: u64,
    /// Gradients collected for the current round, keyed by peer pubkey.
    contributions: HashMap<[u8; 32], PeerGradient>,
    /// Expected gradient dimension (set on first contribution).
    expected_dim: Option<usize>,
}

impl Default for FedAvgAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl FedAvgAggregator {
    /// Create a new aggregator starting at round 0.
    pub fn new() -> Self {
        Self {
            current_round: 0,
            contributions: HashMap::new(),
            expected_dim: None,
        }
    }

    /// Submit a peer's gradient contribution for the current round.
    ///
    /// # Returns
    /// - `Ok(count)` — current number of contributions in this round
    /// - `Err(reason)` — if the contribution was rejected
    pub fn submit_gradients(
        &mut self,
        peer_pubkey: &[u8; 32],
        round_id: u64,
        gradients: Vec<f32>,
    ) -> Result<usize, AggregatorError> {
        // Reject contributions for wrong round
        if round_id != self.current_round {
            warn!(
                expected = self.current_round,
                received = round_id,
                "Gradient for wrong round — rejecting"
            );
            return Err(AggregatorError::WrongRound);
        }

        // Reject if gradients contain NaN or infinity
        if gradients.iter().any(|g| !g.is_finite()) {
            warn!("Gradient contains NaN/Infinity — rejecting");
            return Err(AggregatorError::InvalidValues);
        }

        // Check dimension consistency
        match self.expected_dim {
            Some(dim) if dim != gradients.len() => {
                warn!(
                    expected = dim,
                    received = gradients.len(),
                    "Gradient dimension mismatch — rejecting"
                );
                return Err(AggregatorError::DimensionMismatch);
            }
            None => {
                self.expected_dim = Some(gradients.len());
            }
            _ => {}
        }

        // Reject duplicate contributions from same peer
        if self.contributions.contains_key(peer_pubkey) {
            debug!("Duplicate gradient from same peer — ignoring");
            return Err(AggregatorError::DuplicatePeer);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.contributions.insert(*peer_pubkey, PeerGradient {
            gradients,
            timestamp: now,
        });

        let count = self.contributions.len();
        debug!(count, round = self.current_round, "Gradient contribution accepted");
        Ok(count)
    }

    /// Run Byzantine-resistant FedAvg aggregation.
    ///
    /// Requires at least `FL_MIN_PEERS_PER_ROUND` contributions.
    /// Applies trimmed mean: sorts each gradient dimension across peers,
    /// discards top/bottom `FL_BYZANTINE_TRIM_PERCENT`%, averages the rest.
    ///
    /// # Returns
    /// Aggregated gradient vector, or error if insufficient contributions.
    pub fn aggregate(&self) -> Result<Vec<f32>, AggregatorError> {
        let n = self.contributions.len();
        if n < hivemind::FL_MIN_PEERS_PER_ROUND {
            return Err(AggregatorError::InsufficientPeers);
        }

        let dim = match self.expected_dim {
            Some(d) => d,
            None => return Err(AggregatorError::InsufficientPeers),
        };

        // Compute how many values to trim from each end
        let trim_count = (n * hivemind::FL_BYZANTINE_TRIM_PERCENT / 100).max(0);
        let remaining = n - 2 * trim_count;

        if remaining == 0 {
            // Too few peers to trim — fall back to simple average
            return Ok(self.simple_average(dim));
        }

        // Collect all gradient vectors
        let all_grads: Vec<&Vec<f32>> = self.contributions.values()
            .map(|pg| &pg.gradients)
            .collect();

        // Trimmed mean per dimension
        let mut result = Vec::with_capacity(dim);
        let mut column = Vec::with_capacity(n);

        for d in 0..dim {
            column.clear();
            for grads in &all_grads {
                column.push(grads[d]);
            }
            column.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            // Trim extremes and average the middle
            let trimmed = &column[trim_count..n - trim_count];
            let sum: f32 = trimmed.iter().sum();
            result.push(sum / remaining as f32);
        }

        info!(
            round = self.current_round,
            peers = n,
            trimmed = trim_count * 2,
            "FedAvg aggregation complete (trimmed mean)"
        );

        Ok(result)
    }

    /// Simple arithmetic mean fallback (when too few peers to trim).
    fn simple_average(&self, dim: usize) -> Vec<f32> {
        let n = self.contributions.len() as f32;
        let mut result = vec![0.0_f32; dim];

        for pg in self.contributions.values() {
            for (i, &g) in pg.gradients.iter().enumerate() {
                result[i] += g;
            }
        }

        for v in &mut result {
            *v /= n;
        }

        info!(
            round = self.current_round,
            peers = self.contributions.len(),
            "FedAvg aggregation complete (simple average fallback)"
        );
        result
    }

    /// Advance to the next round, clearing all contributions.
    pub fn advance_round(&mut self) {
        self.current_round += 1;
        self.contributions.clear();
        self.expected_dim = None;
        debug!(round = self.current_round, "Advanced to next FL round");
    }

    /// Get the current round number.
    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    /// Number of contributions in the current round.
    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Check if enough peers have contributed to run aggregation.
    pub fn ready_to_aggregate(&self) -> bool {
        self.contributions.len() >= hivemind::FL_MIN_PEERS_PER_ROUND
    }
}

/// Errors from the aggregation process.
#[derive(Debug, PartialEq, Eq)]
pub enum AggregatorError {
    /// Not enough peers contributed to this round.
    InsufficientPeers,
    /// Gradient contribution is for a different round.
    WrongRound,
    /// Gradient dimension doesn't match previous contributions.
    DimensionMismatch,
    /// Duplicate submission from the same peer.
    DuplicatePeer,
    /// Gradient contains NaN or infinity.
    InvalidValues,
}

impl std::fmt::Display for AggregatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggregatorError::InsufficientPeers => {
                write!(f, "Insufficient peers for aggregation")
            }
            AggregatorError::WrongRound => write!(f, "Gradient for wrong round"),
            AggregatorError::DimensionMismatch => write!(f, "Gradient dimension mismatch"),
            AggregatorError::DuplicatePeer => write!(f, "Duplicate peer contribution"),
            AggregatorError::InvalidValues => {
                write!(f, "Gradient contains NaN/Infinity")
            }
        }
    }
}

impl std::error::Error for AggregatorError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_key(id: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = id;
        key
    }

    #[test]
    fn simple_aggregation() {
        let mut agg = FedAvgAggregator::new();

        // Three peers submit identical gradients
        for i in 1..=3 {
            agg.submit_gradients(&peer_key(i), 0, vec![1.0, 2.0, 3.0])
                .expect("submit");
        }

        let result = agg.aggregate().expect("aggregate");
        assert_eq!(result.len(), 3);
        // With identical gradients, trimmed mean = simple mean
        for &v in &result {
            assert!((v - 2.0).abs() < 0.01 || (v - 1.0).abs() < 0.01 || (v - 3.0).abs() < 0.01);
        }
    }

    #[test]
    fn trimmed_mean_filters_outliers() {
        let mut agg = FedAvgAggregator::new();

        // 5 peers: one has an extreme outlier
        agg.submit_gradients(&peer_key(1), 0, vec![1.0]).expect("submit");
        agg.submit_gradients(&peer_key(2), 0, vec![1.1]).expect("submit");
        agg.submit_gradients(&peer_key(3), 0, vec![1.0]).expect("submit");
        agg.submit_gradients(&peer_key(4), 0, vec![0.9]).expect("submit");
        agg.submit_gradients(&peer_key(5), 0, vec![1000.0]).expect("submit"); // outlier

        let result = agg.aggregate().expect("aggregate");
        // With 5 peers and 20% trim, trim 1 from each end
        // Sorted: [0.9, 1.0, 1.0, 1.1, 1000.0] → trim → [1.0, 1.0, 1.1]
        // Mean = 1.033...
        assert!(result[0] < 2.0, "Outlier should be trimmed: got {}", result[0]);
    }

    #[test]
    fn rejects_wrong_round() {
        let mut agg = FedAvgAggregator::new();
        let result = agg.submit_gradients(&peer_key(1), 5, vec![1.0]);
        assert_eq!(result, Err(AggregatorError::WrongRound));
    }

    #[test]
    fn rejects_duplicate_peer() {
        let mut agg = FedAvgAggregator::new();
        agg.submit_gradients(&peer_key(1), 0, vec![1.0]).expect("first");
        let result = agg.submit_gradients(&peer_key(1), 0, vec![2.0]);
        assert_eq!(result, Err(AggregatorError::DuplicatePeer));
    }

    #[test]
    fn rejects_dimension_mismatch() {
        let mut agg = FedAvgAggregator::new();
        agg.submit_gradients(&peer_key(1), 0, vec![1.0, 2.0]).expect("first");
        let result = agg.submit_gradients(&peer_key(2), 0, vec![1.0]);
        assert_eq!(result, Err(AggregatorError::DimensionMismatch));
    }

    #[test]
    fn rejects_nan_gradients() {
        let mut agg = FedAvgAggregator::new();
        let result = agg.submit_gradients(&peer_key(1), 0, vec![f32::NAN]);
        assert_eq!(result, Err(AggregatorError::InvalidValues));
    }

    #[test]
    fn insufficient_peers() {
        let mut agg = FedAvgAggregator::new();
        agg.submit_gradients(&peer_key(1), 0, vec![1.0]).expect("submit");
        let result = agg.aggregate();
        assert_eq!(result, Err(AggregatorError::InsufficientPeers));
    }

    #[test]
    fn advance_round_clears_state() {
        let mut agg = FedAvgAggregator::new();
        agg.submit_gradients(&peer_key(1), 0, vec![1.0]).expect("submit");
        assert_eq!(agg.contribution_count(), 1);

        agg.advance_round();
        assert_eq!(agg.current_round(), 1);
        assert_eq!(agg.contribution_count(), 0);
    }

    #[test]
    fn ready_to_aggregate_check() {
        let mut agg = FedAvgAggregator::new();
        assert!(!agg.ready_to_aggregate());

        for i in 1..=hivemind::FL_MIN_PEERS_PER_ROUND as u8 {
            agg.submit_gradients(&peer_key(i), 0, vec![1.0]).expect("submit");
        }
        assert!(agg.ready_to_aggregate());
    }
}
