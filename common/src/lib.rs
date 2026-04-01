#![cfg_attr(not(feature = "user"), no_std)]

/// Action to take on a matched rule.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RuleAction {
    /// Allow packet through
    Pass = 0,
    /// Drop packet silently
    Drop = 1,
    /// Redirect to tarpit honeypot
    RedirectTarpit = 2,
}

/// Packet event emitted from eBPF via RingBuf when anomaly detected.
/// 32 bytes, naturally aligned, zero-copy safe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketEvent {
    /// Source IPv4 address (network byte order)
    pub src_ip: u32,
    /// Destination IPv4 address (network byte order)
    pub dst_ip: u32,
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    pub protocol: u8,
    /// TCP flags bitmask (SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01)
    pub flags: u8,
    /// Number of payload bytes analyzed for entropy
    pub payload_len: u16,
    /// Shannon entropy × 1000 (integer, range 0–8000)
    pub entropy_score: u32,
    /// Lower 32 bits of bpf_ktime_get_ns()
    pub timestamp_ns: u32,
    /// Reserved padding for alignment
    pub _padding: u32,
    /// Total IP packet size in bytes
    pub packet_size: u32,
}

/// Key for IP blocklist/allowlist HashMap.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuleKey {
    pub ip: u32,
}

/// Value for IP blocklist/allowlist HashMap.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuleValue {
    /// Action: 0=Pass, 1=Drop, 2=RedirectTarpit
    pub action: u8,
    pub _pad1: u8,
    pub _pad2: u16,
    /// Expiry in seconds since boot (0 = permanent)
    pub expires_at: u32,
}

/// Key for LpmTrie CIDR matching.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CidrKey {
    /// Prefix length (0-32)
    pub prefix_len: u32,
    /// Network address (network byte order)
    pub ip: u32,
}

/// Global statistics counters.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Counters {
    pub packets_total: u64,
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub anomalies_sent: u64,
}

/// Maximum cipher suite IDs to capture from TLS ClientHello.
pub const TLS_MAX_CIPHERS: usize = 20;

/// Maximum extension IDs to capture from TLS ClientHello.
pub const TLS_MAX_EXTENSIONS: usize = 20;

/// Maximum SNI hostname bytes to capture.
pub const TLS_MAX_SNI: usize = 32;

/// TLS ClientHello raw components emitted from eBPF for JA4 assembly.
/// Contains the raw fields needed to compute JA4 fingerprint in userspace.
/// 128 bytes total, naturally aligned.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TlsComponentsEvent {
    /// Source IPv4 address (network byte order on LE host)
    pub src_ip: u32,
    /// Destination IPv4 address
    pub dst_ip: u32,
    /// Source port (host byte order)
    pub src_port: u16,
    /// Destination port (host byte order)
    pub dst_port: u16,
    /// TLS version from ClientHello (e.g., 0x0303 = TLS 1.2)
    pub tls_version: u16,
    /// Number of cipher suites in ClientHello
    pub cipher_count: u8,
    /// Number of extensions in ClientHello
    pub ext_count: u8,
    /// First N cipher suite IDs (network byte order)
    pub ciphers: [u16; TLS_MAX_CIPHERS],
    /// First N extension type IDs (network byte order)
    pub extensions: [u16; TLS_MAX_EXTENSIONS],
    /// SNI hostname (first 32 bytes, null-padded)
    pub sni: [u8; TLS_MAX_SNI],
    /// ALPN first protocol length (0 if no ALPN)
    pub alpn_first_len: u8,
    /// Whether SNI extension was present
    pub has_sni: u8,
    /// Lower 32 bits of bpf_ktime_get_ns()
    pub timestamp_ns: u32,
    /// Padding to 140 bytes
    pub _padding: [u8; 2],
}

/// Egress event emitted from TC classifier for outbound traffic analysis.
/// 32 bytes, naturally aligned, zero-copy safe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct EgressEvent {
    /// Source IPv4 address (local server)
    pub src_ip: u32,
    /// Destination IPv4 address (remote)
    pub dst_ip: u32,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP)
    pub protocol: u8,
    /// TCP flags (if TCP)
    pub flags: u8,
    /// Payload length in bytes
    pub payload_len: u16,
    /// DNS query name length (0 if not DNS)
    pub dns_query_len: u16,
    /// Entropy score of outbound payload (same scale as ingress)
    pub entropy_score: u16,
    /// Lower 32 bits of bpf_ktime_get_ns()
    pub timestamp_ns: u32,
    /// Total packet size
    pub packet_size: u32,
}

/// Detected protocol from DPI tail call analysis.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpiProtocol {
    /// Unknown protocol
    Unknown = 0,
    /// HTTP (detected by method keyword)
    Http = 1,
    /// SSH (detected by "SSH-" banner)
    Ssh = 2,
    /// DNS (detected by port 53 + valid structure)
    Dns = 3,
    /// TLS (handled separately via TlsComponentsEvent)
    Tls = 4,
}

impl DpiProtocol {
    /// Convert a raw u8 value to DpiProtocol.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => DpiProtocol::Http,
            2 => DpiProtocol::Ssh,
            3 => DpiProtocol::Dns,
            4 => DpiProtocol::Tls,
            _ => DpiProtocol::Unknown,
        }
    }
}

/// DPI event emitted from eBPF tail call programs via RingBuf.
/// 24 bytes, naturally aligned, zero-copy safe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DpiEvent {
    /// Source IPv4 address
    pub src_ip: u32,
    /// Destination IPv4 address
    pub dst_ip: u32,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Detected protocol (DpiProtocol as u8)
    pub protocol: u8,
    /// Protocol-specific flags (e.g., suspicious path for HTTP, tunneling for DNS)
    pub flags: u8,
    /// Payload length
    pub payload_len: u16,
    /// Lower 32 bits of bpf_ktime_get_ns()
    pub timestamp_ns: u32,
}

/// DPI flags for HTTP detection.
pub const DPI_HTTP_FLAG_SUSPICIOUS_PATH: u8 = 0x01;
/// DPI flags for DNS detection.
pub const DPI_DNS_FLAG_LONG_QUERY: u8 = 0x01;
pub const DPI_DNS_FLAG_TUNNELING_SUSPECT: u8 = 0x02;
/// DPI flags for SSH detection.
pub const DPI_SSH_FLAG_SUSPICIOUS_SW: u8 = 0x01;

/// RingBuf size for DPI events (64 KB, power of 2).
pub const DPI_RINGBUF_SIZE_BYTES: u32 = 64 * 1024;

/// PROG_ARRAY indices for DPI tail call programs.
pub const DPI_PROG_HTTP: u32 = 0;
pub const DPI_PROG_DNS: u32 = 1;
pub const DPI_PROG_SSH: u32 = 2;

// --- Pod safety (aya requirement for BPF map types, userspace only) ---
// SAFETY: All types are #[repr(C)], contain only fixed-width integers,
// have no padding holes (explicit padding fields), and no pointers.
// eBPF side has no Pod trait — types just need #[repr(C)] + Copy.

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for CidrKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Counters {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TlsComponentsEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EgressEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DpiEvent {}

// --- Constants ---

/// TLS record content type for Handshake.
pub const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// TLS handshake type for ClientHello.
pub const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;

/// RingBuf size for TLS events (64 KB, power of 2).
pub const TLS_RINGBUF_SIZE_BYTES: u32 = 64 * 1024;

/// RingBuf size for egress events (64 KB, power of 2).
pub const EGRESS_RINGBUF_SIZE_BYTES: u32 = 64 * 1024;

/// DNS query name length threshold for tunneling detection.
pub const DNS_TUNNEL_QUERY_LEN_THRESHOLD: u16 = 200;

/// Entropy threshold × 1000. Payloads above this → anomaly event.
/// 6.5 bits = 6500 (encrypted/compressed traffic typically 7.0+)
pub const ENTROPY_ANOMALY_THRESHOLD: u32 = 6500;

/// Maximum payload bytes to analyze for entropy (must fit in eBPF bounded loop).
pub const MAX_PAYLOAD_ANALYSIS_BYTES: usize = 128;

/// RingBuf size in bytes (must be power of 2). 256 KB.
pub const RINGBUF_SIZE_BYTES: u32 = 256 * 1024;

/// Maximum entries in IP blocklist HashMap.
pub const BLOCKLIST_MAX_ENTRIES: u32 = 65536;

/// Maximum entries in CIDR LpmTrie.
pub const CIDR_MAX_ENTRIES: u32 = 4096;

/// Tarpit default port.
pub const TARPIT_PORT: u16 = 9999;

/// Tarpit base delay milliseconds.
pub const TARPIT_BASE_DELAY_MS: u64 = 50;

/// Tarpit max delay milliseconds.
pub const TARPIT_MAX_DELAY_MS: u64 = 500;

/// Tarpit jitter range milliseconds.
pub const TARPIT_JITTER_MS: u64 = 100;

/// Tarpit min chunk size (bytes).
pub const TARPIT_MIN_CHUNK: usize = 1;

/// Tarpit max chunk size (bytes).
pub const TARPIT_MAX_CHUNK: usize = 15;

// --- Helper functions (std-only) ---

#[cfg(feature = "user")]
pub mod util {
    use core::net::Ipv4Addr;

    /// Convert u32 (network byte order stored on LE host) to displayable IPv4.
    ///
    /// eBPF reads IP header fields as raw u32 on bpfel (little-endian).
    /// The wire bytes [A,B,C,D] become a LE u32 value. `u32::from_be()`
    /// converts that to a host-order value that `Ipv4Addr::from(u32)` expects.
    pub fn ip_from_u32(ip: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be(ip))
    }

    /// Convert IPv4 to u32 matching eBPF's bpfel representation.
    ///
    /// `Ipv4Addr → u32` yields a host-order value (MSB = first octet).
    /// `.to_be()` converts to the same representation eBPF stores.
    pub fn ip_to_u32(ip: Ipv4Addr) -> u32 {
        u32::from(ip).to_be()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn packet_event_size_and_alignment() {
        assert_eq!(mem::size_of::<PacketEvent>(), 32);
        assert_eq!(mem::align_of::<PacketEvent>(), 4);
    }

    #[test]
    fn rule_key_size() {
        assert_eq!(mem::size_of::<RuleKey>(), 4);
    }

    #[test]
    fn rule_value_size() {
        assert_eq!(mem::size_of::<RuleValue>(), 8);
    }

    #[test]
    fn cidr_key_size() {
        assert_eq!(mem::size_of::<CidrKey>(), 8);
    }

    #[test]
    fn counters_size() {
        assert_eq!(mem::size_of::<Counters>(), 32);
    }

    #[test]
    fn tls_components_event_size() {
        assert_eq!(mem::size_of::<TlsComponentsEvent>(), 140);
    }

    #[test]
    fn tls_components_event_alignment() {
        assert_eq!(mem::align_of::<TlsComponentsEvent>(), 4);
    }

    #[test]
    fn egress_event_size() {
        assert_eq!(mem::size_of::<EgressEvent>(), 28);
    }

    #[test]
    fn egress_event_alignment() {
        assert_eq!(mem::align_of::<EgressEvent>(), 4);
    }

    #[test]
    fn entropy_threshold_in_range() {
        assert!(ENTROPY_ANOMALY_THRESHOLD <= 8000);
        assert!(ENTROPY_ANOMALY_THRESHOLD > 0);
    }

    #[test]
    fn ringbuf_size_is_power_of_two() {
        assert!(RINGBUF_SIZE_BYTES.is_power_of_two());
    }

    #[test]
    fn ip_conversion_roundtrip() {
        use util::*;
        let ip = core::net::Ipv4Addr::new(192, 168, 1, 1);
        let raw = ip_to_u32(ip);
        assert_eq!(ip_from_u32(raw), ip);
    }

    #[test]
    fn dpi_event_size() {
        assert_eq!(mem::size_of::<DpiEvent>(), 20);
    }

    #[test]
    fn dpi_event_alignment() {
        assert_eq!(mem::align_of::<DpiEvent>(), 4);
    }
}
