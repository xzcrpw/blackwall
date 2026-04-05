//! Deterministic state transitions for the behavioral engine.
//!
//! Evaluates a `BehaviorProfile` against threshold-based rules and returns
//! a `TransitionVerdict` indicating whether to escalate, hold, or promote.

use super::profile::{BehaviorPhase, BehaviorProfile};

// --- Transition thresholds ---

/// Unique destination ports to trigger Probing escalation.
const PROBING_PORT_THRESHOLD: usize = 5;
/// Unique destination ports to trigger Scanning escalation.
const SCANNING_PORT_THRESHOLD: usize = 20;
/// SYN-only ratio above this → likely SYN flood or scan.
const SYN_FLOOD_RATIO: f32 = 0.8;
/// Minimum packets for SYN flood detection.
const SYN_FLOOD_MIN_PACKETS: u64 = 50;
/// Average entropy (×1000) above this → encrypted/exploit payload.
const EXPLOIT_ENTROPY_THRESHOLD: u32 = 7500;
/// Minimum entropy samples for exploit detection.
const EXPLOIT_MIN_SAMPLES: u64 = 10;
/// RST ratio above this (with sufficient packets) → scanning/exploit.
const RST_RATIO_THRESHOLD: f32 = 0.5;
/// Minimum packets to evaluate RST ratio.
const RST_RATIO_MIN_PACKETS: u64 = 20;
/// Beaconing coefficient of variation threshold (×1000).
/// Values below this indicate highly regular intervals (C2 beaconing).
const BEACONING_CV_THRESHOLD: u32 = 300;
/// Packets needed to promote New → Normal.
const NORMAL_PACKET_THRESHOLD: u64 = 10;
/// Seconds of benign activity before promoting Normal → Trusted.
const TRUSTED_AGE_SECS: u64 = 300;
/// Minimum packets for Trusted promotion.
const TRUSTED_PACKET_THRESHOLD: u64 = 100;
/// Suspicion score increase per escalation event.
pub const SUSPICION_INCREMENT: f32 = 0.15;
/// Maximum suspicion score.
pub const SUSPICION_MAX: f32 = 1.0;
/// Suspicion decay per evaluation when no escalation.
const SUSPICION_DECAY: f32 = 0.02;

/// Result of evaluating a profile's behavioral transitions.
#[derive(Debug, Clone, PartialEq)]
pub enum TransitionVerdict {
    /// No phase change, continue monitoring.
    Hold,
    /// Escalate to a more suspicious phase.
    Escalate {
        from: BehaviorPhase,
        to: BehaviorPhase,
        reason: &'static str,
    },
    /// Promote to a less suspicious phase (Trusted).
    Promote {
        from: BehaviorPhase,
        to: BehaviorPhase,
    },
}

/// Evaluate a profile and apply deterministic transitions.
/// Returns the verdict and mutates the profile in place.
pub fn evaluate_transitions(profile: &mut BehaviorProfile) -> TransitionVerdict {
    if !profile.has_sufficient_data() {
        return TransitionVerdict::Hold;
    }

    let current = profile.phase;

    // --- Check for escalation conditions (highest severity first) ---

    // C2 beaconing: sustained high entropy with regular intervals + many packets
    if current.suspicion_level() < BehaviorPhase::EstablishedC2.suspicion_level()
        && profile.avg_entropy() > EXPLOIT_ENTROPY_THRESHOLD
        && profile.total_packets > 200
        && profile.port_diversity() <= 3
        && profile.age().as_secs() > 60
    {
        return apply_escalation(
            profile,
            BehaviorPhase::EstablishedC2,
            "sustained high entropy with low port diversity (C2 pattern)",
        );
    }

    // C2 beaconing: regular inter-arrival intervals (even without high entropy)
    if current.suspicion_level() < BehaviorPhase::EstablishedC2.suspicion_level()
        && profile.total_packets > 100
        && profile.age().as_secs() > 120
    {
        if let Some(cv) = profile.beaconing_score() {
            if cv < BEACONING_CV_THRESHOLD && profile.port_diversity() <= 3 {
                return apply_escalation(
                    profile,
                    BehaviorPhase::EstablishedC2,
                    "regular beaconing intervals detected (C2 callback pattern)",
                );
            }
        }
    }

    // Exploit: high entropy payloads
    if current.suspicion_level() < BehaviorPhase::Exploiting.suspicion_level()
        && profile.avg_entropy() > EXPLOIT_ENTROPY_THRESHOLD
        && profile.entropy_samples >= EXPLOIT_MIN_SAMPLES
    {
        return apply_escalation(
            profile,
            BehaviorPhase::Exploiting,
            "high entropy payloads (encrypted/exploit traffic)",
        );
    }

    // Scanning: many unique ports
    if current.suspicion_level() < BehaviorPhase::Scanning.suspicion_level()
        && profile.port_diversity() > SCANNING_PORT_THRESHOLD
    {
        return apply_escalation(
            profile,
            BehaviorPhase::Scanning,
            "extensive port scanning (>20 unique ports)",
        );
    }

    // SYN flood: high SYN-only ratio with sufficient volume
    if current.suspicion_level() < BehaviorPhase::Scanning.suspicion_level()
        && profile.syn_only_ratio() > SYN_FLOOD_RATIO
        && profile.total_packets >= SYN_FLOOD_MIN_PACKETS
    {
        return apply_escalation(
            profile,
            BehaviorPhase::Scanning,
            "SYN flood pattern (>80% SYN-only, >50 packets)",
        );
    }

    // Slow scan: few ports over a long time window (stealth reconnaissance)
    if current.suspicion_level() < BehaviorPhase::Scanning.suspicion_level()
        && profile.is_slow_scanning()
    {
        return apply_escalation(
            profile,
            BehaviorPhase::Scanning,
            "slow scan pattern (≤1.5 ports/min over 10+ minutes)",
        );
    }

    // RST storm: many connection resets (scanner getting rejected)
    if current.suspicion_level() < BehaviorPhase::Probing.suspicion_level()
        && profile.total_packets >= RST_RATIO_MIN_PACKETS
    {
        let rst_ratio = profile.rst_count as f32 / profile.total_packets as f32;
        if rst_ratio > RST_RATIO_THRESHOLD {
            return apply_escalation(
                profile,
                BehaviorPhase::Probing,
                "high RST ratio (>50%, scanning likely rejected)",
            );
        }
    }

    // Probing: moderate port diversity
    if current.suspicion_level() < BehaviorPhase::Probing.suspicion_level()
        && profile.port_diversity() > PROBING_PORT_THRESHOLD
    {
        return apply_escalation(
            profile,
            BehaviorPhase::Probing,
            "port diversity above probing threshold (>5 unique ports)",
        );
    }

    // --- Check for promotion conditions ---

    // New → Normal: sufficient packets without triggering any escalation
    if current == BehaviorPhase::New && profile.total_packets >= NORMAL_PACKET_THRESHOLD {
        profile.phase = BehaviorPhase::Normal;
        return TransitionVerdict::Promote {
            from: BehaviorPhase::New,
            to: BehaviorPhase::Normal,
        };
    }

    // Normal → Trusted: sustained benign behavior
    if current == BehaviorPhase::Normal
        && profile.age().as_secs() >= TRUSTED_AGE_SECS
        && profile.total_packets >= TRUSTED_PACKET_THRESHOLD
        && profile.suspicion_score < 0.1
    {
        profile.promote_to_trusted();
        return TransitionVerdict::Promote {
            from: BehaviorPhase::Normal,
            to: BehaviorPhase::Trusted,
        };
    }

    // --- No transition: decay suspicion slightly ---
    profile.suspicion_score = (profile.suspicion_score - SUSPICION_DECAY).max(0.0);

    TransitionVerdict::Hold
}

/// Apply an escalation: update phase, bump suspicion, return verdict.
fn apply_escalation(
    profile: &mut BehaviorProfile,
    target: BehaviorPhase,
    reason: &'static str,
) -> TransitionVerdict {
    let from = profile.phase;
    profile.escalate_to(target);
    profile.suspicion_score = (profile.suspicion_score + SUSPICION_INCREMENT).min(SUSPICION_MAX);
    TransitionVerdict::Escalate {
        from,
        to: target,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(flags: u8, dst_port: u16, entropy: u32) -> common::PacketEvent {
        common::PacketEvent {
            src_ip: 0x0100007f,
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
    fn insufficient_data_holds() {
        let mut p = BehaviorProfile::new();
        p.update(&make_event(0x02, 80, 3000));
        assert_eq!(evaluate_transitions(&mut p), TransitionVerdict::Hold);
    }

    #[test]
    fn new_to_normal_promotion() {
        let mut p = BehaviorProfile::new();
        // 10 benign packets to same port
        for _ in 0..10 {
            p.update(&make_event(0x12, 80, 2000)); // SYN+ACK
        }
        let v = evaluate_transitions(&mut p);
        assert_eq!(
            v,
            TransitionVerdict::Promote {
                from: BehaviorPhase::New,
                to: BehaviorPhase::Normal,
            }
        );
        assert_eq!(p.phase, BehaviorPhase::Normal);
    }

    #[test]
    fn port_scan_escalation() {
        let mut p = BehaviorProfile::new();
        // Hit 25 unique ports (> SCANNING_PORT_THRESHOLD=20)
        for port in 1..=25 {
            p.update(&make_event(0x02, port, 1000));
        }
        let v = evaluate_transitions(&mut p);
        match v {
            TransitionVerdict::Escalate { to, reason, .. } => {
                assert_eq!(to, BehaviorPhase::Scanning);
                assert!(reason.contains("port scanning"));
            }
            other => panic!("expected Scanning escalation, got {:?}", other),
        }
    }

    #[test]
    fn syn_flood_escalation() {
        let mut p = BehaviorProfile::new();
        // 60 SYN-only packets to same port
        for _ in 0..60 {
            p.update(&make_event(0x02, 80, 0));
        }
        let v = evaluate_transitions(&mut p);
        match v {
            TransitionVerdict::Escalate { to, reason, .. } => {
                assert_eq!(to, BehaviorPhase::Scanning);
                assert!(reason.contains("SYN flood"));
            }
            other => panic!("expected SYN flood escalation, got {:?}", other),
        }
    }

    #[test]
    fn high_entropy_exploit() {
        let mut p = BehaviorProfile::new();
        // 15 high-entropy packets
        for port in 1..=15 {
            p.update(&make_event(0x12, port, 7800));
        }
        let v = evaluate_transitions(&mut p);
        match v {
            TransitionVerdict::Escalate { to, reason, .. } => {
                assert_eq!(to, BehaviorPhase::Exploiting);
                assert!(reason.contains("entropy"));
            }
            other => panic!("expected Exploiting escalation, got {:?}", other),
        }
    }

    #[test]
    fn suspicion_increases_on_escalation() {
        let mut p = BehaviorProfile::new();
        assert_eq!(p.suspicion_score, 0.0);
        for port in 1..=6 {
            p.update(&make_event(0x02, port, 1000));
        }
        evaluate_transitions(&mut p);
        assert!(p.suspicion_score > 0.0);
    }

    #[test]
    fn suspicion_decays_when_benign() {
        let mut p = BehaviorProfile::new();
        p.suspicion_score = 0.5;
        p.phase = BehaviorPhase::Normal;
        // Feed benign traffic (same port, low entropy)
        for _ in 0..10 {
            p.update(&make_event(0x12, 80, 2000));
        }
        evaluate_transitions(&mut p);
        assert!(p.suspicion_score < 0.5);
    }
}
