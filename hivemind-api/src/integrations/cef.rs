/// ArcSight Common Event Format (CEF) exporter.
///
/// Converts verified IoCs to CEF format for ingestion by ArcSight,
/// Sentinel, and other SIEM platforms that support CEF.
///
/// Format: `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions`
///
/// Reference: <https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf>
use common::hivemind::{self, IoCType, ThreatSeverity};

use crate::store::{ip_to_string, unix_to_iso8601, VerifiedIoC};

/// Convert a verified IoC to a CEF format string.
///
/// The returned string is a single CEF event line.
pub fn ioc_to_cef(vioc: &VerifiedIoC) -> String {
    let ioc = &vioc.ioc;
    let ioc_type = IoCType::from_u8(ioc.ioc_type);
    let severity = ThreatSeverity::from_u8(ioc.severity);

    let sig_id = cef_signature_id(ioc_type);
    let name = escape_cef_header(&cef_event_name(ioc_type, ioc));
    let sev = cef_severity(severity);

    // CEF header (pipe-delimited, 7 fields after CEF:0)
    let header = format!(
        "CEF:0|{}|{}|{}|{sig_id}|{name}|{sev}",
        escape_cef_header(hivemind::SIEM_VENDOR),
        escape_cef_header(hivemind::SIEM_PRODUCT),
        escape_cef_header(hivemind::SIEM_VERSION),
    );

    // CEF extensions (key=value space-delimited)
    let src_ip = ip_to_string(ioc.ip);
    let timestamp = unix_to_iso8601(vioc.verified_at);

    let mut ext = format!(
        "src={src_ip} rt={timestamp} cat={} msg={} cs1Label=stix_id cs1={} \
         cn1Label=confirmations cn1={}",
        escape_cef_value(cef_category(ioc_type)),
        escape_cef_value(&ioc.description),
        escape_cef_value(&vioc.stix_id),
        ioc.confirmations,
    );

    if let Some(ref ja4) = ioc.ja4 {
        ext.push_str(&format!(
            " cs2Label=ja4 cs2={}",
            escape_cef_value(ja4)
        ));
    }

    if let Some(entropy) = ioc.entropy_score {
        ext.push_str(&format!(" cn2Label=entropy_score cn2={entropy}"));
    }

    format!("{header}|{ext}")
}

/// Convert a batch of verified IoCs to newline-delimited CEF.
pub fn batch_to_cef(iocs: &[VerifiedIoC]) -> String {
    iocs.iter()
        .map(ioc_to_cef)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Map IoC type to CEF signature ID.
fn cef_signature_id(t: IoCType) -> u16 {
    match t {
        IoCType::MaliciousIp => 1001,
        IoCType::Ja4Fingerprint => 1002,
        IoCType::EntropyAnomaly => 1003,
        IoCType::DnsTunnel => 1004,
        IoCType::BehavioralPattern => 1005,
    }
}

/// Build human-readable CEF event name.
fn cef_event_name(t: IoCType, ioc: &common::hivemind::IoC) -> String {
    match t {
        IoCType::MaliciousIp => format!("Malicious IP {}", ip_to_string(ioc.ip)),
        IoCType::Ja4Fingerprint => "Malicious TLS Fingerprint".to_string(),
        IoCType::EntropyAnomaly => "High Entropy Anomaly".to_string(),
        IoCType::DnsTunnel => "DNS Tunneling Detected".to_string(),
        IoCType::BehavioralPattern => "Behavioral Anomaly".to_string(),
    }
}

/// Map threat severity to CEF severity (0-10).
fn cef_severity(s: ThreatSeverity) -> u8 {
    match s {
        ThreatSeverity::Info => 1,
        ThreatSeverity::Low => 3,
        ThreatSeverity::Medium => 5,
        ThreatSeverity::High => 8,
        ThreatSeverity::Critical => 10,
    }
}

/// Map IoC type to CEF category string.
fn cef_category(t: IoCType) -> &'static str {
    match t {
        IoCType::MaliciousIp => "Threat/MaliciousIP",
        IoCType::Ja4Fingerprint => "Threat/TLSFingerprint",
        IoCType::EntropyAnomaly => "Anomaly/Entropy",
        IoCType::DnsTunnel => "Threat/DNSTunnel",
        IoCType::BehavioralPattern => "Anomaly/Behavioral",
    }
}

/// Escape pipe characters in CEF header fields.
///
/// CEF uses `|` as the header delimiter — pipes must be escaped as `\|`.
fn escape_cef_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape special characters in CEF extension values.
///
/// Backslash, equals, and newlines must be escaped in extension values.
fn escape_cef_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::hivemind::IoC;

    fn sample_vioc() -> VerifiedIoC {
        VerifiedIoC {
            ioc: IoC {
                ioc_type: 0,
                severity: 4,
                ip: 0x0A000001,
                ja4: Some("t13d".to_string()),
                entropy_score: Some(8000),
                description: "Critical threat".to_string(),
                first_seen: 1700000000,
                confirmations: 5,
                zkp_proof: Vec::new(),
            },
            verified_at: 1700001000,
            stix_id: "indicator--test".to_string(),
        }
    }

    #[test]
    fn cef_format_structure() {
        let vioc = sample_vioc();
        let cef = ioc_to_cef(&vioc);

        // CEF header has 8 pipe-delimited fields
        let parts: Vec<&str> = cef.splitn(8, '|').collect();
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0], "CEF:0");
        assert_eq!(parts[1], "Blackwall");
        assert_eq!(parts[2], "HiveMind");
        assert_eq!(parts[3], "1.0");
        assert_eq!(parts[4], "1001"); // MaliciousIp signature ID
        assert!(parts[5].contains("10.0.0.1"));
        assert_eq!(parts[6], "10"); // Critical severity
    }

    #[test]
    fn cef_escapes_pipes() {
        assert_eq!(escape_cef_header("test|pipe"), "test\\|pipe");
        assert_eq!(escape_cef_header("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn cef_escapes_extension_values() {
        assert_eq!(escape_cef_value("key=value"), "key\\=value");
        assert_eq!(escape_cef_value("line\nnew"), "line\\nnew");
    }

    #[test]
    fn cef_severity_mapping() {
        assert_eq!(cef_severity(ThreatSeverity::Info), 1);
        assert_eq!(cef_severity(ThreatSeverity::High), 8);
        assert_eq!(cef_severity(ThreatSeverity::Critical), 10);
    }
}
