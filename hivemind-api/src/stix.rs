/// STIX 2.1 types and IoC-to-STIX conversion.
///
/// Implements core STIX Structured Threat Information Expression objects
/// for the Enterprise Threat Feed API. Converts HiveMind IoCs to
/// STIX Indicator SDOs within STIX Bundles.
///
/// Reference: <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>
use common::hivemind::{self, IoCType, ThreatSeverity};
use serde::Serialize;

use crate::store::{ip_to_string, unix_to_iso8601, VerifiedIoC};

/// STIX 2.1 Bundle — top-level container for STIX objects.
#[derive(Clone, Debug, Serialize)]
pub struct StixBundle {
    /// Always "bundle".
    #[serde(rename = "type")]
    pub object_type: &'static str,
    /// Deterministic bundle ID.
    pub id: String,
    /// List of STIX objects.
    pub objects: Vec<StixIndicator>,
}

/// STIX 2.1 Indicator SDO — represents an IoC observation.
#[derive(Clone, Debug, Serialize)]
pub struct StixIndicator {
    /// Always "indicator".
    #[serde(rename = "type")]
    pub object_type: &'static str,
    /// STIX spec version.
    pub spec_version: &'static str,
    /// Deterministic STIX ID (from store).
    pub id: String,
    /// ISO 8601 creation timestamp.
    pub created: String,
    /// ISO 8601 modification timestamp.
    pub modified: String,
    /// Human-readable indicator name.
    pub name: String,
    /// STIX pattern expression.
    pub pattern: String,
    /// Pattern language (always "stix").
    pub pattern_type: &'static str,
    /// When this indicator becomes valid.
    pub valid_from: String,
    /// Confidence score (0-100).
    pub confidence: u8,
    /// Indicator type labels.
    pub indicator_types: Vec<&'static str>,
    /// Descriptive labels.
    pub labels: Vec<String>,
}

/// TAXII 2.1 Collection resource.
#[derive(Clone, Debug, Serialize)]
pub struct TaxiiCollection {
    /// Collection identifier.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Whether this collection can be read.
    pub can_read: bool,
    /// Whether this collection can be written to.
    pub can_write: bool,
    /// Supported media types.
    pub media_types: Vec<&'static str>,
}

/// TAXII 2.1 API Root discovery response.
#[derive(Clone, Debug, Serialize)]
pub struct TaxiiDiscovery {
    /// API root title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Supported TAXII versions.
    pub versions: Vec<&'static str>,
    /// Maximum content length.
    pub max_content_length: usize,
}

/// Convert a verified IoC to a STIX 2.1 Indicator.
pub fn ioc_to_indicator(vioc: &VerifiedIoC) -> StixIndicator {
    let ioc = &vioc.ioc;
    let ioc_type = IoCType::from_u8(ioc.ioc_type);
    let severity = ThreatSeverity::from_u8(ioc.severity);

    let name = build_indicator_name(ioc_type, ioc);
    let pattern = build_stix_pattern(ioc_type, ioc);
    let confidence = severity_to_confidence(severity);
    let indicator_types = ioc_type_to_stix_types(ioc_type);
    let created = unix_to_iso8601(vioc.verified_at);
    let valid_from = unix_to_iso8601(ioc.first_seen);

    StixIndicator {
        object_type: "indicator",
        spec_version: hivemind::STIX_SPEC_VERSION,
        id: vioc.stix_id.clone(),
        created: created.clone(),
        modified: created,
        name,
        pattern,
        pattern_type: "stix",
        valid_from,
        confidence,
        indicator_types,
        labels: vec![format!("severity:{}", ioc.severity)],
    }
}

/// Build a STIX bundle from a list of verified IoCs.
pub fn build_bundle(iocs: &[VerifiedIoC]) -> StixBundle {
    let objects: Vec<StixIndicator> = iocs.iter().map(ioc_to_indicator).collect();

    // Bundle ID: deterministic from object count + first ID
    let bundle_suffix = if let Some(first) = objects.first() {
        first.id.chars().skip(12).take(36).collect::<String>()
    } else {
        "00000000-0000-0000-0000-000000000000".to_string()
    };

    StixBundle {
        object_type: "bundle",
        id: format!("bundle--{bundle_suffix}"),
        objects,
    }
}

/// Build the default TAXII collection descriptor.
pub fn default_collection() -> TaxiiCollection {
    TaxiiCollection {
        id: hivemind::TAXII_COLLECTION_ID.to_string(),
        title: hivemind::TAXII_COLLECTION_TITLE.to_string(),
        description: "Consensus-verified threat indicators from the HiveMind P2P mesh. \
                      Each IoC has been cross-validated by at least 3 independent peers."
            .to_string(),
        can_read: true,
        can_write: false,
        media_types: vec![hivemind::STIX_CONTENT_TYPE],
    }
}

/// Build the TAXII API root discovery response.
pub fn discovery_response() -> TaxiiDiscovery {
    TaxiiDiscovery {
        title: "HiveMind Threat Feed".to_string(),
        description: "TAXII 2.1 API for the HiveMind decentralized threat intelligence mesh."
            .to_string(),
        versions: vec!["taxii-2.1"],
        max_content_length: hivemind::MAX_MESSAGE_SIZE,
    }
}

/// Build a human-readable indicator name from IoC fields.
fn build_indicator_name(ioc_type: IoCType, ioc: &common::hivemind::IoC) -> String {
    match ioc_type {
        IoCType::MaliciousIp => {
            format!("Malicious IP {}", ip_to_string(ioc.ip))
        }
        IoCType::Ja4Fingerprint => {
            let ja4 = ioc.ja4.as_deref().unwrap_or("unknown");
            format!("Malicious JA4 fingerprint {ja4}")
        }
        IoCType::EntropyAnomaly => {
            let score = ioc.entropy_score.unwrap_or(0);
            format!("High-entropy anomaly (score={score}) from {}", ip_to_string(ioc.ip))
        }
        IoCType::DnsTunnel => {
            format!("DNS tunneling from {}", ip_to_string(ioc.ip))
        }
        IoCType::BehavioralPattern => {
            format!("Behavioral anomaly from {}", ip_to_string(ioc.ip))
        }
    }
}

/// Build a STIX pattern expression from an IoC.
///
/// STIX patterns follow the STIX Patterning language:
/// `[<object-type>:<property> = '<value>']`
fn build_stix_pattern(ioc_type: IoCType, ioc: &common::hivemind::IoC) -> String {
    match ioc_type {
        IoCType::MaliciousIp => {
            format!("[ipv4-addr:value = '{}']", ip_to_string(ioc.ip))
        }
        IoCType::Ja4Fingerprint => {
            let ja4 = ioc.ja4.as_deref().unwrap_or("unknown");
            format!("[network-traffic:extensions.'tls-ext'.ja4 = '{ja4}']")
        }
        IoCType::EntropyAnomaly => {
            format!(
                "[network-traffic:src_ref.type = 'ipv4-addr' AND \
                 network-traffic:src_ref.value = '{}']",
                ip_to_string(ioc.ip)
            )
        }
        IoCType::DnsTunnel => {
            format!(
                "[domain-name:resolves_to_refs[*].value = '{}']",
                ip_to_string(ioc.ip)
            )
        }
        IoCType::BehavioralPattern => {
            format!(
                "[network-traffic:src_ref.type = 'ipv4-addr' AND \
                 network-traffic:src_ref.value = '{}']",
                ip_to_string(ioc.ip)
            )
        }
    }
}

/// Map threat severity to STIX confidence score (0-100).
fn severity_to_confidence(severity: ThreatSeverity) -> u8 {
    match severity {
        ThreatSeverity::Info => 20,
        ThreatSeverity::Low => 40,
        ThreatSeverity::Medium => 60,
        ThreatSeverity::High => 80,
        ThreatSeverity::Critical => 95,
    }
}

/// Map IoC type to STIX indicator type labels.
fn ioc_type_to_stix_types(ioc_type: IoCType) -> Vec<&'static str> {
    match ioc_type {
        IoCType::MaliciousIp => vec!["malicious-activity", "anomalous-activity"],
        IoCType::Ja4Fingerprint => vec!["malicious-activity"],
        IoCType::EntropyAnomaly => vec!["anomalous-activity"],
        IoCType::DnsTunnel => vec!["malicious-activity", "anomalous-activity"],
        IoCType::BehavioralPattern => vec!["anomalous-activity"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::hivemind::IoC;

    fn sample_ioc() -> IoC {
        IoC {
            ioc_type: 0, // MaliciousIp
            severity: 3, // High
            ip: 0xC0A80001,
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".to_string()),
            entropy_score: Some(7500),
            description: "Test malicious IP".to_string(),
            first_seen: 1700000000,
            confirmations: 3,
            zkp_proof: Vec::new(),
        }
    }

    fn sample_verified() -> VerifiedIoC {
        VerifiedIoC {
            stix_id: "indicator--aabbccdd-1122-3344-5566-778899aabbcc".to_string(),
            verified_at: 1700001000,
            ioc: sample_ioc(),
        }
    }

    #[test]
    fn ioc_converts_to_indicator() {
        let vioc = sample_verified();
        let indicator = ioc_to_indicator(&vioc);

        assert_eq!(indicator.object_type, "indicator");
        assert_eq!(indicator.spec_version, "2.1");
        assert_eq!(indicator.id, vioc.stix_id);
        assert_eq!(indicator.pattern_type, "stix");
        assert_eq!(indicator.confidence, 80); // High severity
        assert!(indicator.name.contains("192.168.0.1"));
        assert!(indicator.pattern.contains("192.168.0.1"));
    }

    #[test]
    fn bundle_creation() {
        let viocs = vec![sample_verified()];
        let bundle = build_bundle(&viocs);

        assert_eq!(bundle.object_type, "bundle");
        assert!(bundle.id.starts_with("bundle--"));
        assert_eq!(bundle.objects.len(), 1);
    }

    #[test]
    fn empty_bundle() {
        let bundle = build_bundle(&[]);
        assert_eq!(bundle.objects.len(), 0);
        assert!(bundle.id.starts_with("bundle--"));
    }

    #[test]
    fn stix_patterns_by_type() {
        let ioc = sample_ioc();

        // MaliciousIp
        let pattern = build_stix_pattern(IoCType::MaliciousIp, &ioc);
        assert!(pattern.starts_with("[ipv4-addr:value"));

        // Ja4Fingerprint
        let mut ja4_ioc = ioc.clone();
        ja4_ioc.ioc_type = 1;
        let pattern = build_stix_pattern(IoCType::Ja4Fingerprint, &ja4_ioc);
        assert!(pattern.contains("tls-ext"));

        // DnsTunnel
        let pattern = build_stix_pattern(IoCType::DnsTunnel, &ioc);
        assert!(pattern.contains("domain-name"));
    }

    #[test]
    fn taxii_discovery() {
        let disc = discovery_response();
        assert!(disc.versions.contains(&"taxii-2.1"));
    }

    #[test]
    fn taxii_collection() {
        let coll = default_collection();
        assert_eq!(coll.id, hivemind::TAXII_COLLECTION_ID);
        assert!(coll.can_read);
        assert!(!coll.can_write);
    }
}
