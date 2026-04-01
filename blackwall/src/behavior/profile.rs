//! Per-IP behavioral profile: statistics and lifecycle phase tracking.

use std::collections::HashSet;
use std::time::Instant;

/// Lifecycle phases for a tracked IP address.
/// Transitions are monotonically increasing in suspicion (except demotion to Trusted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BehaviorPhase {
    /// First contact, insufficient data for classification.
    New,
    /// Normal traffic pattern, low suspicion.
    Normal,
    /// Elevated trust after sustained benign behavior.
    Trusted,
    /// Active reconnaissance (port scanning, service enumeration).
    Probing,
    /// Systematic scanning (sequential ports, multiple protocols).
    Scanning,
    /// Exploit attempts detected (high entropy payloads, known signatures).
    Exploiting,
    /// Established command-and-control pattern (beaconing, exfiltration).
    EstablishedC2,
}

impl BehaviorPhase {
    /// Numeric suspicion level for ordering (higher = more suspicious).
    pub fn suspicion_level(self) -> u8 {
        match self {
            Self::Trusted => 0,
            Self::Normal => 1,
            Self::New => 2,
            Self::Probing => 3,
            Self::Scanning => 4,
            Self::Exploiting => 5,
            Self::EstablishedC2 => 6,
        }
    }

    /// Whether this phase should trigger active response (block/tarpit).
    pub fn is_actionable(self) -> bool {
        matches!(self, Self::Scanning | Self::Exploiting | Self::EstablishedC2)
    }
}

/// Aggregated behavioral statistics for a single source IP.
pub struct BehaviorProfile {
    /// When this IP was first observed.
    pub first_seen: Instant,
    /// When the last packet was observed.
    pub last_seen: Instant,
    /// Total packets observed from this IP.
    pub total_packets: u64,
    /// Unique destination ports contacted.
    pub unique_dst_ports: HashSet<u16>,
    /// TCP SYN packets (connection attempts).
    pub syn_count: u64,
    /// TCP ACK packets.
    pub ack_count: u64,
    /// TCP RST packets (aborted connections).
    pub rst_count: u64,
    /// TCP FIN packets (clean closes).
    pub fin_count: u64,
    /// Running sum of entropy scores (for computing average).
    pub entropy_sum: u64,
    /// Number of entropy samples collected.
    pub entropy_samples: u64,
    /// Current lifecycle phase.
    pub phase: BehaviorPhase,
    /// Suspicion score (0.0–1.0), drives escalation thresholds.
    pub suspicion_score: f32,
    /// Timestamps of recent packets for inter-arrival analysis (circular, last N).
    pub recent_timestamps: Vec<u32>,
    /// Maximum recent timestamps to keep.
    recent_ts_capacity: usize,
    /// Index for circular buffer insertion.
    recent_ts_idx: usize,
    /// Number of times this IP has been escalated.
    pub escalation_count: u32,
}

impl BehaviorProfile {
    /// Create a new profile for a first-seen IP.
    pub fn new() -> Self {
        let now = Instant::now();
        let cap = 64;
        Self {
            first_seen: now,
            last_seen: now,
            total_packets: 0,
            unique_dst_ports: HashSet::new(),
            syn_count: 0,
            ack_count: 0,
            rst_count: 0,
            fin_count: 0,
            entropy_sum: 0,
            entropy_samples: 0,
            phase: BehaviorPhase::New,
            suspicion_score: 0.0,
            recent_timestamps: vec![0u32; cap],
            recent_ts_capacity: cap,
            recent_ts_idx: 0,
            escalation_count: 0,
        }
    }

    /// Ingest a packet event, updating all counters.
    pub fn update(&mut self, event: &common::PacketEvent) {
        self.last_seen = Instant::now();
        self.total_packets += 1;
        self.unique_dst_ports.insert(event.dst_port);

        // TCP flag counters (protocol 6 = TCP)
        if event.protocol == 6 {
            if event.flags & 0x02 != 0 {
                self.syn_count += 1;
            }
            if event.flags & 0x10 != 0 {
                self.ack_count += 1;
            }
            if event.flags & 0x04 != 0 {
                self.rst_count += 1;
            }
            if event.flags & 0x01 != 0 {
                self.fin_count += 1;
            }
        }

        // Entropy tracking
        if event.entropy_score > 0 {
            self.entropy_sum += event.entropy_score as u64;
            self.entropy_samples += 1;
        }

        // Circular buffer for inter-arrival times
        self.recent_timestamps[self.recent_ts_idx] = event.timestamp_ns;
        self.recent_ts_idx = (self.recent_ts_idx + 1) % self.recent_ts_capacity;
    }

    /// Average entropy score (integer × 1000 scale), or 0 if no samples.
    pub fn avg_entropy(&self) -> u32 {
        if self.entropy_samples == 0 {
            return 0;
        }
        (self.entropy_sum / self.entropy_samples) as u32
    }

    /// Ratio of SYN-only packets (SYN without ACK) to total packets.
    pub fn syn_only_ratio(&self) -> f32 {
        if self.total_packets == 0 {
            return 0.0;
        }
        let syn_only = self.syn_count.saturating_sub(self.ack_count);
        syn_only as f32 / self.total_packets as f32
    }

    /// Duration since first observation.
    pub fn age(&self) -> std::time::Duration {
        self.last_seen.duration_since(self.first_seen)
    }

    /// Number of unique destination ports observed.
    pub fn port_diversity(&self) -> usize {
        self.unique_dst_ports.len()
    }

    /// Whether this profile has enough data for meaningful classification.
    pub fn has_sufficient_data(&self) -> bool {
        self.total_packets >= 5
    }

    /// Detect beaconing: regular inter-arrival times (C2 pattern).
    /// Returns the coefficient of variation (stddev/mean) × 1000.
    /// Low values (<300) indicate periodic/regular intervals = beaconing.
    pub fn beaconing_score(&self) -> Option<u32> {
        if self.total_packets < 20 {
            return None;
        }
        // Collect non-zero timestamps from circular buffer
        let mut timestamps: Vec<u32> = self.recent_timestamps.iter()
            .copied()
            .filter(|&t| t > 0)
            .collect();
        if timestamps.len() < 10 {
            return None;
        }
        timestamps.sort_unstable();

        // Compute inter-arrival deltas
        let mut deltas = Vec::with_capacity(timestamps.len() - 1);
        for w in timestamps.windows(2) {
            let delta = w[1].saturating_sub(w[0]);
            if delta > 0 {
                deltas.push(delta as u64);
            }
        }
        if deltas.len() < 5 {
            return None;
        }

        // Mean
        let sum: u64 = deltas.iter().sum();
        let mean = sum / deltas.len() as u64;
        if mean == 0 {
            return None;
        }

        // Variance (integer arithmetic)
        let var_sum: u64 = deltas.iter()
            .map(|&d| {
                let diff = d.abs_diff(mean);
                diff * diff
            })
            .sum();
        let variance = var_sum / deltas.len() as u64;

        // Approximate sqrt via integer Newton's method
        let stddev = isqrt(variance);

        // Coefficient of variation × 1000
        Some((stddev * 1000 / mean) as u32)
    }

    /// Detect slow scanning: few unique ports over a long time window.
    /// Returns true if pattern matches (≤ 1 port/min sustained over 10+ minutes).
    pub fn is_slow_scanning(&self) -> bool {
        let age_secs = self.age().as_secs();
        if age_secs < 600 {
            // Need at least 10 minutes of observation
            return false;
        }
        let ports = self.port_diversity();
        if ports < 3 {
            return false;
        }
        // Rate: ports per minute
        let age_mins = age_secs / 60;
        if age_mins == 0 {
            return false;
        }
        let ports_per_min = ports as u64 * 100 / age_mins; // ×100 for precision
        // ≤ 1.5 ports/min = slow scan (150 in ×100 scale)
        ports_per_min <= 150 && ports >= 5
    }

    /// Advance to a more suspicious phase (never demote except to Trusted).
    pub fn escalate_to(&mut self, new_phase: BehaviorPhase) {
        if new_phase.suspicion_level() > self.phase.suspicion_level() {
            self.phase = new_phase;
            self.escalation_count += 1;
        }
    }

    /// Promote to Trusted after sustained benign behavior.
    pub fn promote_to_trusted(&mut self) {
        self.phase = BehaviorPhase::Trusted;
        self.suspicion_score = 0.0;
    }
}

/// Integer square root via Newton's method.
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(flags: u8, dst_port: u16, entropy: u32) -> common::PacketEvent {
        common::PacketEvent {
            src_ip: 0x0100007f, // 127.0.0.1
            dst_ip: 0x0200007f,
            src_port: 12345,
            dst_port,
            protocol: 6,
            flags,
            payload_len: 64,
            entropy_score: entropy,
            timestamp_ns: 0,
            _padding: 0,
            packet_size: 128,
        }
    }

    #[test]
    fn new_profile_defaults() {
        let p = BehaviorProfile::new();
        assert_eq!(p.phase, BehaviorPhase::New);
        assert_eq!(p.total_packets, 0);
        assert_eq!(p.suspicion_score, 0.0);
    }

    #[test]
    fn update_increments_counters() {
        let mut p = BehaviorProfile::new();
        let syn_event = make_event(0x02, 80, 3000);
        p.update(&syn_event);
        assert_eq!(p.total_packets, 1);
        assert_eq!(p.syn_count, 1);
        assert_eq!(p.ack_count, 0);
        assert_eq!(p.unique_dst_ports.len(), 1);
    }

    #[test]
    fn avg_entropy_calculation() {
        let mut p = BehaviorProfile::new();
        p.update(&make_event(0x02, 80, 6000));
        p.update(&make_event(0x02, 443, 8000));
        assert_eq!(p.avg_entropy(), 7000);
    }

    #[test]
    fn syn_only_ratio() {
        let mut p = BehaviorProfile::new();
        // 3 SYN-only
        for port in 1..=3 {
            p.update(&make_event(0x02, port, 0));
        }
        // 1 SYN+ACK
        p.update(&make_event(0x12, 80, 0));
        // syn_count=4, ack_count=1, total=4
        // syn_only = 4-1 = 3, ratio = 3/4 = 0.75
        assert!((p.syn_only_ratio() - 0.75).abs() < 0.01);
    }

    #[test]
    fn escalation_monotonic() {
        let mut p = BehaviorProfile::new();
        p.escalate_to(BehaviorPhase::Probing);
        assert_eq!(p.phase, BehaviorPhase::Probing);
        // Cannot go back to New
        p.escalate_to(BehaviorPhase::New);
        assert_eq!(p.phase, BehaviorPhase::Probing);
        // Can go forward to Scanning
        p.escalate_to(BehaviorPhase::Scanning);
        assert_eq!(p.phase, BehaviorPhase::Scanning);
        assert_eq!(p.escalation_count, 2);
    }

    #[test]
    fn trusted_promotion() {
        let mut p = BehaviorProfile::new();
        p.escalate_to(BehaviorPhase::Normal);
        p.suspicion_score = 0.3;
        p.promote_to_trusted();
        assert_eq!(p.phase, BehaviorPhase::Trusted);
        assert_eq!(p.suspicion_score, 0.0);
    }

    #[test]
    fn phase_suspicion_ordering() {
        assert!(BehaviorPhase::Trusted.suspicion_level() < BehaviorPhase::Normal.suspicion_level());
        assert!(BehaviorPhase::Normal.suspicion_level() < BehaviorPhase::Probing.suspicion_level());
        assert!(
            BehaviorPhase::Probing.suspicion_level() < BehaviorPhase::Scanning.suspicion_level()
        );
        assert!(
            BehaviorPhase::Scanning.suspicion_level()
                < BehaviorPhase::Exploiting.suspicion_level()
        );
        assert!(
            BehaviorPhase::Exploiting.suspicion_level()
                < BehaviorPhase::EstablishedC2.suspicion_level()
        );
    }

    #[test]
    fn actionable_phases() {
        assert!(!BehaviorPhase::New.is_actionable());
        assert!(!BehaviorPhase::Normal.is_actionable());
        assert!(!BehaviorPhase::Trusted.is_actionable());
        assert!(!BehaviorPhase::Probing.is_actionable());
        assert!(BehaviorPhase::Scanning.is_actionable());
        assert!(BehaviorPhase::Exploiting.is_actionable());
        assert!(BehaviorPhase::EstablishedC2.is_actionable());
    }

    #[test]
    fn beaconing_insufficient_data() {
        let p = BehaviorProfile::new();
        assert!(p.beaconing_score().is_none());
    }

    #[test]
    fn beaconing_regular_intervals() {
        let mut p = BehaviorProfile::new();
        // Simulate 30 packets with regular timestamps (every 1000ns)
        for i in 0..30 {
            let mut e = make_event(0x12, 443, 2000);
            e.timestamp_ns = (i + 1) * 1000;
            p.update(&e);
        }
        if let Some(cv) = p.beaconing_score() {
            // Regular intervals → low coefficient of variation
            assert!(cv < 300, "expected low CV for regular beaconing, got {}", cv);
        }
    }

    #[test]
    fn slow_scan_detection() {
        let mut p = BehaviorProfile::new();
        // Simulate slow scanning: spread ports over time
        // We can't easily fake elapsed time, but we can set up the port diversity
        for port in 1..=10 {
            p.update(&make_event(0x02, port, 0));
        }
        // With 10 ports and <10min age, should NOT detect
        assert!(!p.is_slow_scanning());
    }

    #[test]
    fn isqrt_values() {
        assert_eq!(super::isqrt(0), 0);
        assert_eq!(super::isqrt(1), 1);
        assert_eq!(super::isqrt(4), 2);
        assert_eq!(super::isqrt(9), 3);
        assert_eq!(super::isqrt(100), 10);
        assert_eq!(super::isqrt(1000000), 1000);
    }
}
