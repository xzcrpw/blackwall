//! JA4 fingerprint assembler: converts raw TLS ClientHello components
//! into a JA4-format string.
//!
//! JA4 format (simplified):
//!   `t{version}{sni_flag}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}`
//!
//! - version: TLS version code (12=TLS1.2, 13=TLS1.3)
//! - sni_flag: 'd' if SNI present, 'i' if absent
//! - cipher_count: 2-digit count of cipher suites (capped at 99)
//! - ext_count: 2-digit count of extensions (capped at 99)
//! - cipher_hash: first 12 chars of hex-encoded hash of sorted cipher suite IDs
//! - ext_hash: first 12 chars of hex-encoded hash of sorted extension IDs

use common::TlsComponentsEvent;

/// Assembled JA4 fingerprint with metadata.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Ja4Fingerprint {
    /// Full JA4 string (e.g., "t13d1510_a0b1c2d3e4f5_f5e4d3c2b1a0")
    pub fingerprint: String,
    /// Source IP (network byte order)
    pub src_ip: u32,
    /// Destination IP (network byte order)
    pub dst_ip: u32,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// SNI hostname (if present)
    pub sni: Option<String>,
}

/// Assembles JA4 fingerprints from eBPF TlsComponentsEvent.
pub struct Ja4Assembler;

impl Ja4Assembler {
    /// Compute JA4 fingerprint from raw TLS ClientHello components.
    pub fn assemble(event: &TlsComponentsEvent) -> Ja4Fingerprint {
        let version = tls_version_code(event.tls_version);
        let sni_flag = if event.has_sni != 0 { 'd' } else { 'i' };
        let cipher_count = (event.cipher_count as u16).min(99);
        let ext_count = (event.ext_count as u16).min(99);

        // Sort and hash cipher suites
        let mut ciphers: Vec<u16> = event.ciphers[..event.cipher_count as usize]
            .iter()
            .copied()
            // GREASE values: 0x{0a,1a,2a,...,fa}0a — skip them
            .filter(|&c| !is_grease(c))
            .collect();
        ciphers.sort_unstable();
        let cipher_hash = truncated_hash(&ciphers);

        // Sort and hash extensions
        let mut extensions: Vec<u16> = event.extensions[..event.ext_count as usize]
            .iter()
            .copied()
            .filter(|&e| !is_grease(e))
            .collect();
        extensions.sort_unstable();
        let ext_hash = truncated_hash(&extensions);

        // Build JA4 string
        let fingerprint = format!(
            "t{}{}{:02}{:02}_{}_{}",
            version, sni_flag, cipher_count, ext_count, cipher_hash, ext_hash
        );

        // Extract SNI
        let sni = if event.has_sni != 0 {
            let sni_bytes = &event.sni[..];
            let end = sni_bytes.iter().position(|&b| b == 0).unwrap_or(sni_bytes.len());
            if end > 0 {
                Some(String::from_utf8_lossy(&sni_bytes[..end]).into_owned())
            } else {
                None
            }
        } else {
            None
        };

        Ja4Fingerprint {
            fingerprint,
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            sni,
        }
    }
}

/// Map TLS version u16 to JA4 version code.
fn tls_version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// Check if a TLS value is a GREASE (Generate Random Extensions And Sustain Extensibility) value.
/// GREASE values follow pattern: 0x{0a,1a,2a,...,fa}0a
fn is_grease(val: u16) -> bool {
    let hi = (val >> 8) as u8;
    let lo = val as u8;
    lo == 0x0a && hi & 0x0f == 0x0a
}

/// Compute a simple hash of sorted u16 values, return first 12 hex chars.
/// Uses FNV-1a for speed (no cryptographic requirement).
fn truncated_hash(values: &[u16]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    for &v in values {
        let bytes = v.to_be_bytes();
        for &b in &bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        }
    }
    format!("{:012x}", hash)[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tls_event(
        version: u16,
        ciphers: &[u16],
        extensions: &[u16],
        has_sni: bool,
        sni: &[u8],
    ) -> TlsComponentsEvent {
        let mut event = TlsComponentsEvent {
            src_ip: 0x0100007f,
            dst_ip: 0xC0A80001u32.to_be(),
            src_port: 54321,
            dst_port: 443,
            tls_version: version,
            cipher_count: ciphers.len().min(20) as u8,
            ext_count: extensions.len().min(20) as u8,
            ciphers: [0u16; 20],
            extensions: [0u16; 20],
            sni: [0u8; 32],
            alpn_first_len: 0,
            has_sni: if has_sni { 1 } else { 0 },
            timestamp_ns: 0,
            _padding: [0; 2],
        };
        for (i, &c) in ciphers.iter().take(20).enumerate() {
            event.ciphers[i] = c;
        }
        for (i, &e) in extensions.iter().take(20).enumerate() {
            event.extensions[i] = e;
        }
        let copy_len = sni.len().min(32);
        event.sni[..copy_len].copy_from_slice(&sni[..copy_len]);
        event
    }

    #[test]
    fn ja4_tls13_with_sni() {
        let event = make_tls_event(
            0x0304,
            &[0x1301, 0x1302, 0x1303],
            &[0x0000, 0x000a, 0x000b, 0x000d],
            true,
            b"example.com",
        );
        let fp = Ja4Assembler::assemble(&event);
        assert!(fp.fingerprint.starts_with("t13d0304_"));
        assert_eq!(fp.sni, Some("example.com".to_string()));
        assert_eq!(fp.dst_port, 443);
    }

    #[test]
    fn ja4_tls12_no_sni() {
        let event = make_tls_event(
            0x0303,
            &[0xc02c, 0xc02b, 0x009e],
            &[0x000a, 0x000b],
            false,
            &[],
        );
        let fp = Ja4Assembler::assemble(&event);
        assert!(fp.fingerprint.starts_with("t12i0302_"));
        assert_eq!(fp.sni, None);
    }

    #[test]
    fn grease_values_filtered() {
        // 0x0a0a is a GREASE value
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a0a));
        assert!(is_grease(0xfa0a));
        assert!(!is_grease(0x0001));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn truncated_hash_deterministic() {
        let h1 = truncated_hash(&[0x1301, 0x1302, 0x1303]);
        let h2 = truncated_hash(&[0x1301, 0x1302, 0x1303]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 12);
    }

    #[test]
    fn truncated_hash_order_matters() {
        // Input is pre-sorted, so different order = different hash
        let h1 = truncated_hash(&[0x0001, 0x0002]);
        let h2 = truncated_hash(&[0x0002, 0x0001]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn tls_version_mapping() {
        assert_eq!(tls_version_code(0x0304), "13");
        assert_eq!(tls_version_code(0x0303), "12");
        assert_eq!(tls_version_code(0x0302), "11");
        assert_eq!(tls_version_code(0x0301), "10");
        assert_eq!(tls_version_code(0x0300), "s3");
        assert_eq!(tls_version_code(0x0200), "00");
    }
}
