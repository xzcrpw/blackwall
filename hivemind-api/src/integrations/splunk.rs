/// Splunk HTTP Event Collector (HEC) format exporter.
///
/// Converts verified IoCs to Splunk HEC JSON format suitable for
/// direct ingestion via the Splunk HEC endpoint.
///
/// Format reference: <https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector>
use common::hivemind::{self, IoCType, ThreatSeverity};
use serde::Serialize;

use crate::store::{ip_to_string, VerifiedIoC};

/// Splunk HEC event wrapper.
#[derive(Clone, Debug, Serialize)]
pub struct SplunkEvent {
    /// Unix timestamp of the event.
    pub time: u64,
    /// Splunk source identifier.
    pub source: &'static str,
    /// Splunk sourcetype for indexing.
    pub sourcetype: &'static str,
    /// Target Splunk index.
    pub index: &'static str,
    /// Event payload.
    pub event: SplunkEventData,
}

/// Inner event data for Splunk HEC.
#[derive(Clone, Debug, Serialize)]
pub struct SplunkEventData {
    /// IoC type as human-readable string.
    pub ioc_type: &'static str,
    /// Severity as human-readable string.
    pub severity: &'static str,
    /// Numeric severity (0-4).
    pub severity_id: u8,
    /// Source IP in dotted notation (if applicable).
    pub src_ip: String,
    /// JA4 fingerprint (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    /// Byte diversity score (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_score: Option<u32>,
    /// Human-readable description.
    pub description: String,
    /// Number of independent confirmations.
    pub confirmations: u32,
    /// Unix timestamp when first observed.
    pub first_seen: u64,
    /// Unix timestamp when consensus was reached.
    pub verified_at: u64,
    /// STIX identifier for cross-referencing.
    pub stix_id: String,
}

/// Convert a verified IoC to a Splunk HEC event.
pub fn ioc_to_splunk(vioc: &VerifiedIoC) -> SplunkEvent {
    let ioc = &vioc.ioc;
    let ioc_type = IoCType::from_u8(ioc.ioc_type);
    let severity = ThreatSeverity::from_u8(ioc.severity);

    SplunkEvent {
        time: vioc.verified_at,
        source: "hivemind",
        sourcetype: hivemind::SPLUNK_SOURCETYPE,
        index: "threat_intel",
        event: SplunkEventData {
            ioc_type: ioc_type_label(ioc_type),
            severity: severity_label(severity),
            severity_id: ioc.severity,
            src_ip: ip_to_string(ioc.ip),
            ja4: ioc.ja4.clone(),
            entropy_score: ioc.entropy_score,
            description: ioc.description.clone(),
            confirmations: ioc.confirmations,
            first_seen: ioc.first_seen,
            verified_at: vioc.verified_at,
            stix_id: vioc.stix_id.clone(),
        },
    }
}

/// Convert a batch of verified IoCs to Splunk HEC events.
pub fn batch_to_splunk(iocs: &[VerifiedIoC]) -> Vec<SplunkEvent> {
    iocs.iter().map(ioc_to_splunk).collect()
}

/// Human-readable IoC type label.
fn ioc_type_label(t: IoCType) -> &'static str {
    match t {
        IoCType::MaliciousIp => "malicious_ip",
        IoCType::Ja4Fingerprint => "ja4_fingerprint",
        IoCType::EntropyAnomaly => "entropy_anomaly",
        IoCType::DnsTunnel => "dns_tunnel",
        IoCType::BehavioralPattern => "behavioral_pattern",
    }
}

/// Human-readable severity label.
fn severity_label(s: ThreatSeverity) -> &'static str {
    match s {
        ThreatSeverity::Info => "info",
        ThreatSeverity::Low => "low",
        ThreatSeverity::Medium => "medium",
        ThreatSeverity::High => "high",
        ThreatSeverity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::hivemind::IoC;

    fn sample_vioc() -> VerifiedIoC {
        VerifiedIoC {
            ioc: IoC {
                ioc_type: 0,
                severity: 3,
                ip: 0xC0A80001,
                ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".to_string()),
                entropy_score: Some(7500),
                description: "Malicious IP".to_string(),
                first_seen: 1700000000,
                confirmations: 3,
                zkp_proof: Vec::new(),
            },
            verified_at: 1700001000,
            stix_id: "indicator--aabbccdd-1122-3344-5566-778899aabbcc".to_string(),
        }
    }

    #[test]
    fn splunk_event_fields() {
        let vioc = sample_vioc();
        let event = ioc_to_splunk(&vioc);

        assert_eq!(event.time, 1700001000);
        assert_eq!(event.source, "hivemind");
        assert_eq!(event.sourcetype, hivemind::SPLUNK_SOURCETYPE);
        assert_eq!(event.event.ioc_type, "malicious_ip");
        assert_eq!(event.event.severity, "high");
        assert_eq!(event.event.src_ip, "192.168.0.1");
        assert_eq!(event.event.confirmations, 3);
    }

    #[test]
    fn splunk_severity_mapping() {
        assert_eq!(severity_label(ThreatSeverity::Info), "info");
        assert_eq!(severity_label(ThreatSeverity::Critical), "critical");
    }

    #[test]
    fn splunk_batch() {
        let iocs = vec![sample_vioc(), sample_vioc()];
        let batch = batch_to_splunk(&iocs);
        assert_eq!(batch.len(), 2);
    }
}
