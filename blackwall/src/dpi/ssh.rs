//! SSH banner/version dissector.
//!
//! Parses SSH protocol version exchange strings.
//! Extracts software version and detects known scanning tools.

/// Extracted SSH banner metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInfo {
    /// Full version string (e.g., "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
    pub version: String,
    /// Protocol version ("2.0" or "1.99")
    pub protocol: String,
    /// Software identifier (e.g., "OpenSSH_9.6p1")
    pub software: String,
    /// Optional comment/OS info
    pub comment: Option<String>,
}

/// Known SSH scanning/attack tool identifiers.
const SUSPICIOUS_SSH_SOFTWARE: &[&str] = &[
    "libssh",         // Frequently used by bots
    "paramiko",       // Python SSH library, common in automated attacks
    "putty",          // PuTTY — sometimes spoofed
    "go",             // Go SSH libraries (automated scanners)
    "asyncssh",       // Python async SSH
    "nmap",           // Nmap SSH scanning
    "dropbear_2012",  // Very old, likely compromised device
    "dropbear_2014",
    "sshlibrary",
    "russh",
];

/// Parse an SSH banner from raw connection bytes.
pub fn parse_banner(data: &[u8]) -> Option<SshInfo> {
    let text = std::str::from_utf8(data).ok()?;
    let line = text.lines().next()?;

    // SSH banner format: SSH-protoversion-softwareversion [SP comments]
    if !line.starts_with("SSH-") {
        return None;
    }

    let banner = line.strip_prefix("SSH-")?;

    // Split into protocol-softwareversion and optional comment
    let (proto_sw, comment) = match banner.split_once(' ') {
        Some((ps, c)) => (ps, Some(c.trim().to_string())),
        None => (banner.trim_end_matches('\r'), None),
    };

    // Split protocol and software
    let (protocol, software) = proto_sw.split_once('-')?;

    Some(SshInfo {
        version: line.to_string(),
        protocol: protocol.to_string(),
        software: software.to_string(),
        comment,
    })
}

/// Check if the SSH software banner matches known scanning/attack tools.
pub fn is_suspicious_software(software: &str) -> bool {
    let lower = software.to_lowercase();
    SUSPICIOUS_SSH_SOFTWARE.iter().any(|s| lower.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openssh_banner() {
        let data = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
        let info = parse_banner(data).unwrap();
        assert_eq!(info.protocol, "2.0");
        assert_eq!(info.software, "OpenSSH_9.6p1");
        assert_eq!(info.comment, Some("Ubuntu-3ubuntu13.5".into()));
    }

    #[test]
    fn parse_no_comment() {
        let data = b"SSH-2.0-dropbear_2022.82\r\n";
        let info = parse_banner(data).unwrap();
        assert_eq!(info.protocol, "2.0");
        assert_eq!(info.software, "dropbear_2022.82");
        assert!(info.comment.is_none());
    }

    #[test]
    fn reject_non_ssh() {
        assert!(parse_banner(b"HTTP/1.1 200 OK\r\n").is_none());
        assert!(parse_banner(b"\x00\x01\x02").is_none());
    }

    #[test]
    fn suspicious_software_detection() {
        assert!(is_suspicious_software("libssh-0.9.6"));
        assert!(is_suspicious_software("Paramiko_3.4.0"));
        assert!(!is_suspicious_software("OpenSSH_9.6p1"));
        assert!(!is_suspicious_software("dropbear_2022.82"));
    }
}
