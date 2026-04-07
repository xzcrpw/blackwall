//! Deep Packet Inspection (DPI) dissectors for protocol-level analysis.
//!
//! Operates on raw connection bytes captured from network streams.
//! Dissectors extract protocol metadata for threat classification.

#[allow(dead_code)]
pub mod dns;
#[allow(dead_code)]
pub mod http;
#[allow(dead_code)]
pub mod ssh;

/// Protocol identified by DPI analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum DetectedProtocol {
    Http(http::HttpInfo),
    Dns(dns::DnsInfo),
    Ssh(ssh::SshInfo),
    Unknown,
}

/// Attempt to identify the protocol from the first bytes of a connection.
#[allow(dead_code)]
pub fn identify_protocol(data: &[u8]) -> DetectedProtocol {
    // Try HTTP first (most common on redirected traffic)
    if let Some(info) = http::parse_request(data) {
        return DetectedProtocol::Http(info);
    }
    // Try SSH banner
    if let Some(info) = ssh::parse_banner(data) {
        return DetectedProtocol::Ssh(info);
    }
    // Try DNS (UDP payload)
    if let Some(info) = dns::parse_query(data) {
        return DetectedProtocol::Dns(info);
    }
    DetectedProtocol::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_http_get() {
        let data = b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match identify_protocol(data) {
            DetectedProtocol::Http(info) => {
                assert_eq!(info.method, "GET");
                assert_eq!(info.path, "/admin");
            }
            other => panic!("expected Http, got {:?}", other),
        }
    }

    #[test]
    fn identify_ssh_banner() {
        let data = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
        match identify_protocol(data) {
            DetectedProtocol::Ssh(info) => {
                assert!(info.version.contains("OpenSSH"));
            }
            other => panic!("expected Ssh, got {:?}", other),
        }
    }

    #[test]
    fn identify_unknown() {
        let data = b"\x00\x01\x02\x03random binary";
        assert_eq!(identify_protocol(data), DetectedProtocol::Unknown);
    }
}
