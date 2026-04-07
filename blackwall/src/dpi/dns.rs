//! DNS query/response dissector.
//!
//! Parses DNS wire format from raw bytes.
//! Extracts query name, type, and detects tunneling indicators.

/// Extracted DNS query metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    /// Transaction ID
    pub id: u16,
    /// Whether this is a query (false) or response (true)
    pub is_response: bool,
    /// Number of questions
    pub question_count: u16,
    /// First query domain name (if present)
    pub query_name: Option<String>,
    /// First query type (A=1, AAAA=28, MX=15, TXT=16, CNAME=5)
    pub query_type: Option<u16>,
}

/// Maximum DNS name length to parse (prevents excessive processing).
const MAX_DNS_NAME_LEN: usize = 253;
/// Maximum label count to prevent infinite loops on malformed packets.
const MAX_LABELS: usize = 128;

/// Parse a DNS query/response from raw bytes (UDP payload).
pub fn parse_query(data: &[u8]) -> Option<DnsInfo> {
    // DNS header is 12 bytes minimum
    if data.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = (flags & 0x8000) != 0;
    let question_count = u16::from_be_bytes([data[4], data[5]]);

    // Sanity: must have at least 1 question
    if question_count == 0 || question_count > 256 {
        return None;
    }

    // Parse first question name starting at offset 12
    let (query_name, offset) = parse_dns_name(data, 12)?;

    // Parse query type (2 bytes after name)
    let query_type = if offset + 2 <= data.len() {
        Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
    } else {
        None
    };

    Some(DnsInfo {
        id,
        is_response,
        question_count,
        query_name: Some(query_name),
        query_type,
    })
}

/// Parse a DNS domain name from wire format. Returns (name, bytes_consumed_offset).
fn parse_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut labels = 0;

    loop {
        if pos >= data.len() || labels >= MAX_LABELS {
            return None;
        }

        let label_len = data[pos] as usize;
        if label_len == 0 {
            pos += 1;
            break;
        }

        // Compression pointer (0xC0 prefix) — not following for simplicity
        if label_len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }

        if label_len > 63 {
            return None; // Invalid label length
        }

        pos += 1;
        if pos + label_len > data.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }

        let label = std::str::from_utf8(&data[pos..pos + label_len]).ok()?;
        name.push_str(label);

        if name.len() > MAX_DNS_NAME_LEN {
            return None;
        }

        pos += label_len;
        labels += 1;
    }

    if name.is_empty() {
        return None;
    }

    Some((name, pos))
}

/// Heuristic: check if a DNS query name looks like DNS tunneling.
/// High entropy names, very long labels, and many subdomains are suspicious.
pub fn is_tunneling_suspect(name: &str) -> bool {
    // Long overall name
    if name.len() > 60 {
        return true;
    }

    let labels: Vec<&str> = name.split('.').collect();

    // Many subdomain levels
    if labels.len() > 6 {
        return true;
    }

    // Any individual label is unusually long (>30 chars suggests encoded data)
    for label in &labels {
        if label.len() > 30 {
            return true;
        }
    }

    // High ratio of digits/hex chars in labels (encoded payload)
    let total_chars: usize = labels.iter().take(labels.len().saturating_sub(2)).map(|l| l.len()).sum();
    if total_chars > 10 {
        let hex_chars: usize = labels
            .iter()
            .take(labels.len().saturating_sub(2))
            .flat_map(|l| l.chars())
            .filter(|c| c.is_ascii_hexdigit() && !c.is_ascii_alphabetic())
            .count();
        if hex_chars * 3 > total_chars {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ];
        // Encode name
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root terminator
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // Class IN
        pkt
    }

    #[test]
    fn parse_simple_a_query() {
        let pkt = build_dns_query("example.com", 1);
        let info = parse_query(&pkt).unwrap();
        assert_eq!(info.id, 0x1234);
        assert!(!info.is_response);
        assert_eq!(info.question_count, 1);
        assert_eq!(info.query_name, Some("example.com".into()));
        assert_eq!(info.query_type, Some(1)); // A record
    }

    #[test]
    fn parse_txt_query() {
        let pkt = build_dns_query("tunnel.evil.com", 16);
        let info = parse_query(&pkt).unwrap();
        assert_eq!(info.query_name, Some("tunnel.evil.com".into()));
        assert_eq!(info.query_type, Some(16)); // TXT record
    }

    #[test]
    fn reject_too_short() {
        assert!(parse_query(&[0; 6]).is_none());
    }

    #[test]
    fn tunneling_detection() {
        assert!(!is_tunneling_suspect("google.com"));
        assert!(!is_tunneling_suspect("www.example.com"));
        assert!(is_tunneling_suspect(
            "aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVk.tunnel.evil.com"
        ));
        assert!(is_tunneling_suspect(
            "a.b.c.d.e.f.g.evil.com"
        ));
    }
}
