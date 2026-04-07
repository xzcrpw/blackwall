/// IBM QRadar LEEF (Log Event Extended Format) exporter.
///
/// Converts verified IoCs to LEEF 2.0 format for ingestion by
/// IBM QRadar SIEM via log source or Syslog.
///
/// LEEF format: `LEEF:2.0|Vendor|Product|Version|EventID\tkey=value\tkey=value`
///
/// Reference: <https://www.ibm.com/docs/en/dsm?topic=leef-overview>
use common::hivemind::{self, IoCType, ThreatSeverity};

use crate::store::{ip_to_string, unix_to_iso8601, VerifiedIoC};

/// Convert a verified IoC to LEEF 2.0 format string.
///
/// The returned string is a single LEEF event line suitable for
/// Syslog forwarding or file-based ingestion.
pub fn ioc_to_leef(vioc: &VerifiedIoC) -> String {
    let ioc = &vioc.ioc;
    let ioc_type = IoCType::from_u8(ioc.ioc_type);
    let severity = ThreatSeverity::from_u8(ioc.severity);

    let event_id = leef_event_id(ioc_type);
    let sev = leef_severity(severity);

    // LEEF header
    let header = format!(
        "LEEF:2.0|{}|{}|{}|{}",
        hivemind::SIEM_VENDOR,
        hivemind::SIEM_PRODUCT,
        hivemind::SIEM_VERSION,
        event_id,
    );

    // LEEF attributes (tab-delimited)
    let src_ip = ip_to_string(ioc.ip);
    let timestamp = unix_to_iso8601(vioc.verified_at);
    let desc = escape_leef_value(&ioc.description);

    let mut attrs = format!(
        "sev={sev}\tsrc={src_ip}\tdevTime={timestamp}\tcat={event_id}\t\
         msg={desc}\tconfirmations={}\tstix_id={}",
        ioc.confirmations,
        escape_leef_value(&vioc.stix_id),
    );

    if let Some(ref ja4) = ioc.ja4 {
        attrs.push_str(&format!("\tja4={}", escape_leef_value(ja4)));
    }

    if let Some(entropy) = ioc.entropy_score {
        attrs.push_str(&format!("\tentropy_score={entropy}"));
    }

    format!("{header}\t{attrs}")
}

/// Convert a batch of verified IoCs to newline-delimited LEEF.
pub fn batch_to_leef(iocs: &[VerifiedIoC]) -> String {
    iocs.iter()
        .map(ioc_to_leef)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Map IoC type to LEEF event ID.
fn leef_event_id(t: IoCType) -> &'static str {
    match t {
        IoCType::MaliciousIp => "MaliciousIP",
        IoCType::Ja4Fingerprint => "JA4Fingerprint",
        IoCType::EntropyAnomaly => "EntropyAnomaly",
        IoCType::DnsTunnel => "DNSTunnel",
        IoCType::BehavioralPattern => "BehavioralPattern",
    }
}

/// Map threat severity to LEEF numeric severity (1-10).
fn leef_severity(s: ThreatSeverity) -> u8 {
    match s {
        ThreatSeverity::Info => 1,
        ThreatSeverity::Low => 3,
        ThreatSeverity::Medium => 5,
        ThreatSeverity::High => 7,
        ThreatSeverity::Critical => 10,
    }
}

/// Escape special characters in LEEF attribute values.
///
/// LEEF uses tab as delimiter — tabs and newlines must be escaped.
fn escape_leef_value(s: &str) -> String {
    s.replace('\t', "\\t")
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
                severity: 3,
                ip: 0xC0A80001,
                ja4: Some("t13d1516h2_abc".to_string()),
                entropy_score: Some(7500),
                description: "Malicious IP detected".to_string(),
                first_seen: 1700000000,
                confirmations: 3,
                zkp_proof: Vec::new(),
            },
            verified_at: 1700001000,
            stix_id: "indicator--aabb".to_string(),
        }
    }

    #[test]
    fn leef_header_format() {
        let vioc = sample_vioc();
        let leef = ioc_to_leef(&vioc);

        assert!(leef.starts_with("LEEF:2.0|Blackwall|HiveMind|1.0|MaliciousIP"));
        assert!(leef.contains("sev=7"));
        assert!(leef.contains("src=192.168.0.1"));
        assert!(leef.contains("ja4=t13d1516h2_abc"));
        assert!(leef.contains("entropy_score=7500"));
    }

    #[test]
    fn leef_escapes_special_chars() {
        let escaped = escape_leef_value("test\ttab\nnewline");
        assert_eq!(escaped, "test\\ttab\\nnewline");
    }

    #[test]
    fn leef_severity_mapping() {
        assert_eq!(leef_severity(ThreatSeverity::Info), 1);
        assert_eq!(leef_severity(ThreatSeverity::Critical), 10);
    }
}
