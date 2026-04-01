use common::PacketEvent;
use std::collections::HashSet;

use crate::ai::client::OllamaClient;

/// System prompt for threat classification. Low temperature, structured output.
pub const CLASSIFICATION_SYSTEM_PROMPT: &str = r#"You are a network security analyst.
Analyze the following traffic summary and classify the threat.
Respond with EXACTLY one line in this format:
VERDICT:<Benign|Suspicious|Malicious> CATEGORY:<category> CONFIDENCE:<0.0-1.0>

Categories: DDoS_SYN_Flood, DDoS_UDP_Flood, Port_Scan, Brute_Force,
Exploit, C2_Communication, Data_Exfiltration, Other

Example: VERDICT:Malicious CATEGORY:Port_Scan CONFIDENCE:0.85"#;

/// Classification verdict from the AI module.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatVerdict {
    /// Normal traffic.
    Benign,
    /// Needs monitoring but not yet actionable.
    Suspicious { reason: String, confidence: f32 },
    /// Confirmed threat — take action.
    Malicious {
        category: ThreatCategory,
        confidence: f32,
    },
    /// LLM unavailable, deterministic rules didn't match.
    Unknown,
}

/// Threat categories for classification.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatCategory {
    DdosSynFlood,
    DdosUdpFlood,
    PortScan,
    BruteForce,
    Exploit,
    C2Communication,
    DataExfiltration,
    Other(String),
}

/// Classifies batched events using deterministic rules + LLM fallback.
pub struct ThreatClassifier {
    client: OllamaClient,
}

impl ThreatClassifier {
    /// Create a new classifier backed by the given Ollama client.
    pub fn new(client: OllamaClient) -> Self {
        Self { client }
    }

    /// Get a reference to the underlying Ollama client.
    pub fn client(&self) -> &OllamaClient {
        &self.client
    }

    /// Classify a batch of events from the same source IP.
    pub async fn classify(&self, events: &[PacketEvent]) -> ThreatVerdict {
        if events.is_empty() {
            return ThreatVerdict::Benign;
        }

        // 1. Quick deterministic check
        if let Some(verdict) = self.deterministic_classify(events) {
            return verdict;
        }

        // 2. If LLM unavailable, return Unknown
        if !self.client.is_available() {
            return ThreatVerdict::Unknown;
        }

        // 3. Build prompt and query LLM
        let prompt = self.build_classification_prompt(events);
        match self.client.classify_threat(&prompt).await {
            Ok(response) => self.parse_llm_response(&response),
            Err(_) => ThreatVerdict::Unknown,
        }
    }

    /// Deterministic fallback classification (no LLM needed).
    fn deterministic_classify(&self, events: &[PacketEvent]) -> Option<ThreatVerdict> {
        let count = events.len() as u32;
        if count == 0 {
            return None;
        }

        let avg_entropy = events.iter().map(|e| e.entropy_score).sum::<u32>() / count;

        // Very high entropy + many events → encrypted attack payload
        if avg_entropy > 7500 && events.len() > 50 {
            return Some(ThreatVerdict::Malicious {
                category: ThreatCategory::Exploit,
                confidence: 0.7,
            });
        }

        // SYN flood detection: many SYN without ACK
        let syn_count = events
            .iter()
            .filter(|e| e.flags & 0x02 != 0 && e.flags & 0x10 == 0)
            .count();
        if syn_count > 100 {
            return Some(ThreatVerdict::Malicious {
                category: ThreatCategory::DdosSynFlood,
                confidence: 0.9,
            });
        }

        // Port scan detection: many unique destination ports
        let unique_ports: HashSet<u16> = events.iter().map(|e| e.dst_port).collect();
        if unique_ports.len() > 20 {
            return Some(ThreatVerdict::Malicious {
                category: ThreatCategory::PortScan,
                confidence: 0.85,
            });
        }

        None
    }

    fn build_classification_prompt(&self, events: &[PacketEvent]) -> String {
        let src_ip = common::util::ip_from_u32(events[0].src_ip);
        let event_count = events.len();
        let avg_entropy = events.iter().map(|e| e.entropy_score).sum::<u32>() / event_count as u32;

        let unique_dst_ports: HashSet<u16> = events.iter().map(|e| e.dst_port).collect();

        let syn_count = events.iter().filter(|e| e.flags & 0x02 != 0).count();
        let ack_count = events.iter().filter(|e| e.flags & 0x10 != 0).count();
        let rst_count = events.iter().filter(|e| e.flags & 0x04 != 0).count();

        let tcp_count = events.iter().filter(|e| e.protocol == 6).count();
        let udp_count = events.iter().filter(|e| e.protocol == 17).count();

        format!(
            "Source IP: {}\nEvent count: {} in last 10s\n\
             Avg entropy: {:.1}/8.0\nProtocols: TCP={}, UDP={}\n\
             Unique dst ports: {}\n\
             TCP flags: SYN={}, ACK={}, RST={}",
            src_ip,
            event_count,
            avg_entropy as f64 / 1000.0,
            tcp_count,
            udp_count,
            unique_dst_ports.len(),
            syn_count,
            ack_count,
            rst_count,
        )
    }

    fn parse_llm_response(&self, response: &str) -> ThreatVerdict {
        // Parse format: "VERDICT:Malicious CATEGORY:Port_Scan CONFIDENCE:0.85"
        let line = response.lines().find(|l| l.starts_with("VERDICT:"));
        let line = match line {
            Some(l) => l,
            None => return ThreatVerdict::Unknown,
        };

        let mut verdict_str = "";
        let mut category_str = "";
        let mut confidence: f32 = 0.0;

        for part in line.split_whitespace() {
            if let Some(v) = part.strip_prefix("VERDICT:") {
                verdict_str = v;
            } else if let Some(c) = part.strip_prefix("CATEGORY:") {
                category_str = c;
            } else if let Some(conf) = part.strip_prefix("CONFIDENCE:") {
                confidence = conf.parse().unwrap_or(0.0);
            }
        }

        match verdict_str {
            "Benign" => ThreatVerdict::Benign,
            "Suspicious" => ThreatVerdict::Suspicious {
                reason: category_str.to_string(),
                confidence,
            },
            "Malicious" => {
                let category = match category_str {
                    "DDoS_SYN_Flood" => ThreatCategory::DdosSynFlood,
                    "DDoS_UDP_Flood" => ThreatCategory::DdosUdpFlood,
                    "Port_Scan" => ThreatCategory::PortScan,
                    "Brute_Force" => ThreatCategory::BruteForce,
                    "Exploit" => ThreatCategory::Exploit,
                    "C2_Communication" => ThreatCategory::C2Communication,
                    "Data_Exfiltration" => ThreatCategory::DataExfiltration,
                    other => ThreatCategory::Other(other.to_string()),
                };
                ThreatVerdict::Malicious {
                    category,
                    confidence,
                }
            }
            _ => ThreatVerdict::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::client::OllamaClient;

    fn test_classifier() -> ThreatClassifier {
        let client = OllamaClient::new(
            "http://localhost:11434".into(),
            "test".into(),
            "test".into(),
            1000,
        );
        ThreatClassifier::new(client)
    }

    #[test]
    fn parse_malicious_verdict() {
        let c = test_classifier();
        let resp = "VERDICT:Malicious CATEGORY:Port_Scan CONFIDENCE:0.85";
        match c.parse_llm_response(resp) {
            ThreatVerdict::Malicious {
                category,
                confidence,
            } => {
                assert_eq!(category, ThreatCategory::PortScan);
                assert!((confidence - 0.85).abs() < 0.01);
            }
            other => panic!("expected Malicious, got {:?}", other),
        }
    }

    #[test]
    fn parse_benign_verdict() {
        let c = test_classifier();
        let resp = "VERDICT:Benign CATEGORY:None CONFIDENCE:0.95";
        assert_eq!(c.parse_llm_response(resp), ThreatVerdict::Benign);
    }

    #[test]
    fn parse_suspicious_verdict() {
        let c = test_classifier();
        let resp = "VERDICT:Suspicious CATEGORY:Brute_Force CONFIDENCE:0.6";
        match c.parse_llm_response(resp) {
            ThreatVerdict::Suspicious { reason, confidence } => {
                assert_eq!(reason, "Brute_Force");
                assert!((confidence - 0.6).abs() < 0.01);
            }
            other => panic!("expected Suspicious, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_on_garbage() {
        let c = test_classifier();
        assert_eq!(
            c.parse_llm_response("some random LLM output"),
            ThreatVerdict::Unknown
        );
    }

    #[test]
    fn parse_unknown_on_empty() {
        let c = test_classifier();
        assert_eq!(c.parse_llm_response(""), ThreatVerdict::Unknown);
    }

    #[test]
    fn parse_multiline_finds_verdict() {
        let c = test_classifier();
        let resp =
            "Analyzing traffic...\nVERDICT:Malicious CATEGORY:DDoS_SYN_Flood CONFIDENCE:0.9\nDone.";
        match c.parse_llm_response(resp) {
            ThreatVerdict::Malicious { category, .. } => {
                assert_eq!(category, ThreatCategory::DdosSynFlood);
            }
            other => panic!("expected Malicious, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_syn_flood_detection() {
        let c = test_classifier();
        // Generate 120 SYN-only events (flags = 0x02)
        let events: Vec<PacketEvent> = (0..120)
            .map(|_| PacketEvent {
                src_ip: 0x0A000001,
                dst_ip: 0x0A000002,
                src_port: 12345,
                dst_port: 80,
                protocol: 6,
                flags: 0x02, // SYN only
                payload_len: 0,
                entropy_score: 1000,
                timestamp_ns: 0,
                _padding: 0,
                packet_size: 64,
            })
            .collect();

        match c.deterministic_classify(&events) {
            Some(ThreatVerdict::Malicious { category, .. }) => {
                assert_eq!(category, ThreatCategory::DdosSynFlood);
            }
            other => panic!("expected SYN flood, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_port_scan_detection() {
        let c = test_classifier();
        // Generate events to 25 unique destination ports
        let events: Vec<PacketEvent> = (0..25)
            .map(|i| PacketEvent {
                src_ip: 0x0A000001,
                dst_ip: 0x0A000002,
                src_port: 12345,
                dst_port: 1000 + i as u16,
                protocol: 6,
                flags: 0x02,
                payload_len: 64,
                entropy_score: 3000,
                timestamp_ns: 0,
                _padding: 0,
                packet_size: 128,
            })
            .collect();

        match c.deterministic_classify(&events) {
            Some(ThreatVerdict::Malicious { category, .. }) => {
                assert_eq!(category, ThreatCategory::PortScan);
            }
            other => panic!("expected PortScan, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_benign_traffic() {
        let c = test_classifier();
        // Few events, normal entropy, single port
        let events: Vec<PacketEvent> = (0..5)
            .map(|_| PacketEvent {
                src_ip: 0x0A000001,
                dst_ip: 0x0A000002,
                src_port: 12345,
                dst_port: 443,
                protocol: 6,
                flags: 0x12, // SYN+ACK
                payload_len: 64,
                entropy_score: 3000,
                timestamp_ns: 0,
                _padding: 0,
                packet_size: 128,
            })
            .collect();

        // Should return None (no deterministic match → falls through to LLM)
        assert!(c.deterministic_classify(&events).is_none());
    }
}
