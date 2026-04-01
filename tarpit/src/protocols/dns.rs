//! DNS canary honeypot.
//!
//! Listens on UDP port 53, responds to all queries with a configurable canary IP,
//! and logs attacker DNS queries for forensic analysis.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

/// Canary IP to return in A record responses.
const DEFAULT_CANARY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 200);

/// Maximum DNS message size we handle.
const MAX_DNS_MSG: usize = 512;

/// Run a DNS canary server on the specified bind address.
/// Responds to all A queries with the canary IP.
pub async fn run_dns_canary(bind_addr: &str, canary_ip: Ipv4Addr) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    tracing::info!(addr = %bind_addr, canary = %canary_ip, "DNS canary listening");

    let mut buf = [0u8; MAX_DNS_MSG];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        if len < 12 {
            continue; // Too short for DNS header
        }

        let query = &buf[..len];
        let qname = extract_qname(query);
        tracing::info!(
            attacker = %src,
            query = %qname,
            "DNS canary query"
        );

        if let Some(response) = build_response(query, canary_ip) {
            let _ = socket.send_to(&response, src).await;
        }
    }
}

/// Extract the query name from a DNS message (after the 12-byte header).
fn extract_qname(msg: &[u8]) -> String {
    if msg.len() < 13 {
        return String::from("<empty>");
    }

    let mut name = String::new();
    let mut pos = 12;
    let mut first = true;

    for _ in 0..128 {
        if pos >= msg.len() {
            break;
        }
        let label_len = msg[pos] as usize;
        if label_len == 0 {
            break;
        }
        if !first {
            name.push('.');
        }
        first = false;
        pos += 1;
        let end = pos + label_len;
        if end > msg.len() {
            break;
        }
        for &b in &msg[pos..end] {
            if b.is_ascii_graphic() || b == b'-' || b == b'_' {
                name.push(b as char);
            } else {
                name.push('?');
            }
        }
        pos = end;
    }

    if name.is_empty() {
        String::from("<root>")
    } else {
        name
    }
}

/// Build a DNS response with a single A record pointing to the canary IP.
fn build_response(query: &[u8], canary_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let mut resp = Vec::with_capacity(query.len() + 16);

    // Copy transaction ID from query
    resp.push(query[0]);
    resp.push(query[1]);

    // Flags: standard response, recursion available, no error
    resp.push(0x81); // QR=1, opcode=0, AA=0, TC=0, RD=1
    resp.push(0x80); // RA=1, Z=0, RCODE=0

    // QDCOUNT = 1 (echo the question)
    resp.push(0x00);
    resp.push(0x01);
    // ANCOUNT = 1 (one answer)
    resp.push(0x00);
    resp.push(0x01);
    // NSCOUNT = 0
    resp.push(0x00);
    resp.push(0x00);
    // ARCOUNT = 0
    resp.push(0x00);
    resp.push(0x00);

    // Copy the question section from query
    let question_start = 12;
    let mut pos = question_start;
    // Walk through the question name
    for _ in 0..128 {
        if pos >= query.len() {
            return None;
        }
        let label_len = query[pos] as usize;
        if label_len == 0 {
            pos += 1; // Skip the zero terminator
            break;
        }
        pos += 1 + label_len;
    }
    // Skip QTYPE (2) + QCLASS (2)
    if pos + 4 > query.len() {
        return None;
    }
    pos += 4;

    // Copy the entire question from query
    resp.extend_from_slice(&query[question_start..pos]);

    // Answer section: A record
    // Name pointer: 0xC00C points to offset 12 (the question name)
    resp.push(0xC0);
    resp.push(0x0C);
    // TYPE: A (1)
    resp.push(0x00);
    resp.push(0x01);
    // CLASS: IN (1)
    resp.push(0x00);
    resp.push(0x01);
    // TTL: 300 seconds
    resp.push(0x00);
    resp.push(0x00);
    resp.push(0x01);
    resp.push(0x2C);
    // RDLENGTH: 4 (IPv4 address)
    resp.push(0x00);
    resp.push(0x04);
    // RDATA: canary IP
    let octets = canary_ip.octets();
    resp.extend_from_slice(&octets);

    Some(resp)
}

/// Default canary IP address.
pub fn default_canary_ip() -> Ipv4Addr {
    DEFAULT_CANARY_IP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_simple_qname() {
        // DNS query for "example.com" — label format: 7example3com0
        let mut msg = vec![0u8; 12]; // header
        msg.push(7); // "example" length
        msg.extend_from_slice(b"example");
        msg.push(3); // "com" length
        msg.extend_from_slice(b"com");
        msg.push(0); // terminator
        msg.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN

        assert_eq!(extract_qname(&msg), "example.com");
    }

    #[test]
    fn extract_empty_message() {
        assert_eq!(extract_qname(&[0u8; 8]), "<empty>");
    }

    #[test]
    fn build_response_valid() {
        let mut query = vec![0xAB, 0xCD]; // Transaction ID
        query.extend_from_slice(&[0x01, 0x00]); // Flags (standard query)
        query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
        query.push(3); // "foo"
        query.extend_from_slice(b"foo");
        query.push(0); // terminator
        query.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN

        let resp = build_response(&query, Ipv4Addr::new(10, 0, 0, 200)).unwrap();
        // Check transaction ID preserved
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
        // Check ANCOUNT = 1
        assert_eq!(resp[6], 0x00);
        assert_eq!(resp[7], 0x01);
        // Check canary IP at end
        let ip_start = resp.len() - 4;
        assert_eq!(&resp[ip_start..], &[10, 0, 0, 200]);
    }

    #[test]
    fn build_response_too_short() {
        assert!(build_response(&[0u8; 6], Ipv4Addr::LOCALHOST).is_none());
    }
}
