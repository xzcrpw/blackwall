/// Feed query parameter parsing and response formatting.
///
/// Bridges the HTTP layer (server.rs) to the storage layer (store.rs)
/// by parsing URL query parameters into `QueryParams` and formatting
/// paginated feed results as JSON responses.
use common::hivemind;

use crate::store::QueryParams;

/// Parse query parameters from a URI query string.
///
/// Supported parameters:
/// - `since` — Unix timestamp filter (only IoCs verified after this time)
/// - `severity` — Minimum severity level (0-4)
/// - `type` — IoC type filter (0-4)
/// - `limit` — Page size (capped by tier max)
/// - `offset` — Pagination offset
///
/// Invalid parameter values are silently ignored (defaults used).
pub fn parse_query_params(query: Option<&str>, max_page_size: usize) -> QueryParams {
    let mut params = QueryParams::new();
    params.limit = params.limit.min(max_page_size);

    let query = match query {
        Some(q) => q,
        None => return params,
    };

    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = match parts.next() {
            Some(k) => k,
            None => continue,
        };
        let value = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        match key {
            "since" => {
                if let Ok(ts) = value.parse::<u64>() {
                    params.since = Some(ts);
                }
            }
            "severity" => {
                if let Ok(sev) = value.parse::<u8>() {
                    if sev <= 4 {
                        params.min_severity = Some(sev);
                    }
                }
            }
            "type" => {
                if let Ok(t) = value.parse::<u8>() {
                    if t <= 4 {
                        params.ioc_type = Some(t);
                    }
                }
            }
            "limit" => {
                if let Ok(l) = value.parse::<usize>() {
                    params.limit = l.min(max_page_size).max(1);
                }
            }
            "offset" => {
                if let Ok(o) = value.parse::<usize>() {
                    params.offset = o;
                }
            }
            _ => {} // Unknown params silently ignored
        }
    }

    params
}

/// Feed statistics for the /api/v1/stats endpoint.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FeedStats {
    /// Total verified IoCs in the feed.
    pub total_iocs: usize,
    /// Breakdown by severity level.
    pub by_severity: SeverityBreakdown,
    /// Breakdown by IoC type.
    pub by_type: TypeBreakdown,
}

/// Count of IoCs per severity level.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SeverityBreakdown {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

/// Count of IoCs per type.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TypeBreakdown {
    pub malicious_ip: usize,
    pub ja4_fingerprint: usize,
    pub entropy_anomaly: usize,
    pub dns_tunnel: usize,
    pub behavioral_pattern: usize,
}

/// Compute feed statistics from the store.
pub fn compute_stats(store: &crate::store::ThreatFeedStore) -> FeedStats {
    let all = store.all();
    let mut by_severity = SeverityBreakdown::default();
    let mut by_type = TypeBreakdown::default();

    for vioc in all {
        match hivemind::ThreatSeverity::from_u8(vioc.ioc.severity) {
            hivemind::ThreatSeverity::Info => by_severity.info += 1,
            hivemind::ThreatSeverity::Low => by_severity.low += 1,
            hivemind::ThreatSeverity::Medium => by_severity.medium += 1,
            hivemind::ThreatSeverity::High => by_severity.high += 1,
            hivemind::ThreatSeverity::Critical => by_severity.critical += 1,
        }

        match hivemind::IoCType::from_u8(vioc.ioc.ioc_type) {
            hivemind::IoCType::MaliciousIp => by_type.malicious_ip += 1,
            hivemind::IoCType::Ja4Fingerprint => by_type.ja4_fingerprint += 1,
            hivemind::IoCType::EntropyAnomaly => by_type.entropy_anomaly += 1,
            hivemind::IoCType::DnsTunnel => by_type.dns_tunnel += 1,
            hivemind::IoCType::BehavioralPattern => by_type.behavioral_pattern += 1,
        }
    }

    FeedStats {
        total_iocs: all.len(),
        by_severity,
        by_type,
    }
}

/// Mesh stats compatible with the TUI dashboard's MeshStats struct.
///
/// Returns IoC counts mapped to the dashboard's expected fields.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DashboardMeshStats {
    pub connected: bool,

    // P2P Mesh
    pub peer_count: u64,
    pub dht_records: u64,
    pub gossip_topics: u64,
    pub messages_per_sec: f64,

    // Threat Intel
    pub iocs_shared: u64,
    pub iocs_received: u64,
    pub avg_reputation: f64,

    // Network Firewall (XDP/eBPF)
    pub packets_total: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub anomalies_sent: u64,

    // A2A Firewall (separate from XDP)
    pub a2a_jwts_verified: u64,
    pub a2a_violations: u64,
    pub a2a_injections: u64,

    // Cryptography
    pub zkp_proofs_generated: u64,
    pub zkp_proofs_verified: u64,
    pub fhe_encrypted: bool,
}

/// Compute dashboard-compatible mesh stats from the store.
pub fn compute_mesh_stats(store: &crate::store::ThreatFeedStore, counters: &crate::server::HivemindCounters) -> DashboardMeshStats {
    use std::sync::atomic::Ordering;
    let all = store.all();
    let total = all.len() as u64;

    // eBPF/XDP counters
    let pkt_total = counters.packets_total.load(Ordering::Relaxed);
    let pkt_passed = counters.packets_passed.load(Ordering::Relaxed);
    let pkt_dropped = counters.packets_dropped.load(Ordering::Relaxed);
    let anomalies = counters.anomalies_sent.load(Ordering::Relaxed);

    // P2P counters
    let peers = counters.peer_count.load(Ordering::Relaxed);
    let iocs_p2p = counters.iocs_shared_p2p.load(Ordering::Relaxed);
    let rep_x100 = counters.avg_reputation_x100.load(Ordering::Relaxed);
    let msgs_total = counters.messages_total.load(Ordering::Relaxed);

    // A2A counters
    let a2a_jwts = counters.a2a_jwts_verified.load(Ordering::Relaxed);
    let a2a_viol = counters.a2a_violations.load(Ordering::Relaxed);
    let a2a_inj = counters.a2a_injections.load(Ordering::Relaxed);

    DashboardMeshStats {
        connected: true,
        peer_count: peers,
        dht_records: total,
        gossip_topics: if total > 0 || peers > 0 { 1 } else { 0 },
        messages_per_sec: msgs_total as f64 / 60.0,
        iocs_shared: iocs_p2p,
        iocs_received: pkt_total,
        avg_reputation: rep_x100 as f64 / 100.0,
        packets_total: pkt_total,
        packets_passed: pkt_passed,
        packets_dropped: pkt_dropped,
        anomalies_sent: anomalies,
        a2a_jwts_verified: a2a_jwts,
        a2a_violations: a2a_viol,
        a2a_injections: a2a_inj,
        zkp_proofs_generated: 0,
        zkp_proofs_verified: 0,
        fhe_encrypted: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_query() {
        let params = parse_query_params(None, 1000);
        assert_eq!(params.limit, hivemind::API_DEFAULT_PAGE_SIZE);
        assert_eq!(params.offset, 0);
        assert!(params.since.is_none());
        assert!(params.min_severity.is_none());
        assert!(params.ioc_type.is_none());
    }

    #[test]
    fn parse_all_params() {
        let params = parse_query_params(
            Some("since=1700000000&severity=3&type=1&limit=50&offset=10"),
            1000,
        );
        assert_eq!(params.since, Some(1700000000));
        assert_eq!(params.min_severity, Some(3));
        assert_eq!(params.ioc_type, Some(1));
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
    }

    #[test]
    fn limit_capped_by_tier() {
        let params = parse_query_params(Some("limit=5000"), 100);
        assert_eq!(params.limit, 100);
    }

    #[test]
    fn invalid_params_ignored() {
        let params = parse_query_params(
            Some("since=notanumber&severity=99&limit=abc&unknown=foo"),
            1000,
        );
        assert!(params.since.is_none());
        assert!(params.min_severity.is_none()); // 99 > 4, ignored
        assert_eq!(params.limit, hivemind::API_DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn compute_stats_populated() {
        use crate::store::ThreatFeedStore;
        use common::hivemind::IoC;

        let mut store = ThreatFeedStore::new();
        store.insert(
            IoC {
                ioc_type: 0,
                severity: 3,
                ip: 1,
                ja4: None,
                entropy_score: None,
                description: "test".to_string(),
                first_seen: 1000,
                confirmations: 3,
                zkp_proof: Vec::new(),
            },
            2000,
        );
        store.insert(
            IoC {
                ioc_type: 1,
                severity: 4,
                ip: 2,
                ja4: None,
                entropy_score: None,
                description: "test2".to_string(),
                first_seen: 1000,
                confirmations: 3,
                zkp_proof: Vec::new(),
            },
            3000,
        );

        let stats = compute_stats(&store);
        assert_eq!(stats.total_iocs, 2);
        assert_eq!(stats.by_severity.high, 1);
        assert_eq!(stats.by_severity.critical, 1);
        assert_eq!(stats.by_type.malicious_ip, 1);
        assert_eq!(stats.by_type.ja4_fingerprint, 1);
    }
}
