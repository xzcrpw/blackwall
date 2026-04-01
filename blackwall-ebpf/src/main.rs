#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{classifier, map, xdp};
use aya_ebpf::maps::{HashMap, LpmTrie, PerCpuArray, ProgramArray, RingBuf};
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::programs::{TcContext, XdpContext};
use common::{
    Counters, DpiEvent, DpiProtocol, EgressEvent, PacketEvent, RuleKey, RuleValue,
    TlsComponentsEvent, BLOCKLIST_MAX_ENTRIES, CIDR_MAX_ENTRIES,
    DPI_DNS_FLAG_LONG_QUERY, DPI_DNS_FLAG_TUNNELING_SUSPECT,
    DPI_HTTP_FLAG_SUSPICIOUS_PATH, DPI_PROG_DNS, DPI_PROG_HTTP, DPI_PROG_SSH,
    DPI_RINGBUF_SIZE_BYTES, DPI_SSH_FLAG_SUSPICIOUS_SW, DNS_TUNNEL_QUERY_LEN_THRESHOLD,
    EGRESS_RINGBUF_SIZE_BYTES, ENTROPY_ANOMALY_THRESHOLD, MAX_PAYLOAD_ANALYSIS_BYTES,
    RINGBUF_SIZE_BYTES, TLS_CONTENT_TYPE_HANDSHAKE, TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_MAX_CIPHERS, TLS_MAX_EXTENSIONS, TLS_MAX_SNI, TLS_RINGBUF_SIZE_BYTES,
};
use core::mem;

// --- Network Header Structs ---

#[repr(C)]
struct EthHdr {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C)]
struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    len: u16,
    check: u16,
}

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// --- eBPF Maps ---

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_SIZE_BYTES, 0);

#[map]
static BLOCKLIST: HashMap<RuleKey, RuleValue> =
    HashMap::with_max_entries(BLOCKLIST_MAX_ENTRIES, 0);

#[map]
static CIDR_RULES: LpmTrie<u32, RuleValue> =
    LpmTrie::with_max_entries(CIDR_MAX_ENTRIES, 0);

#[map]
static COUNTERS: PerCpuArray<Counters> = PerCpuArray::with_max_entries(1, 0);

#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(TLS_RINGBUF_SIZE_BYTES, 0);

#[map]
static EGRESS_EVENTS: RingBuf = RingBuf::with_byte_size(EGRESS_RINGBUF_SIZE_BYTES, 0);

#[map]
static DPI_EVENTS: RingBuf = RingBuf::with_byte_size(DPI_RINGBUF_SIZE_BYTES, 0);

/// PROG_ARRAY for DPI tail calls: index 0=HTTP, 1=DNS, 2=SSH
#[map]
static DPI_PROGS: ProgramArray = ProgramArray::with_max_entries(4, 0);

/// PerCpuArray scratch buffer for passing context to tail call programs.
/// Layout: [src_ip(4), dst_ip(4), src_port(2), dst_port(2), payload_offset(4), data_end(4)] = 20 bytes
#[repr(C)]
#[derive(Copy, Clone)]
struct DpiScratch {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    payload_offset: u32,
}

#[map]
static DPI_SCRATCH: PerCpuArray<DpiScratch> = PerCpuArray::with_max_entries(1, 0);

// --- Entry Point ---

#[xdp]
pub fn blackwall_xdp(ctx: XdpContext) -> u32 {
    match try_blackwall_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_blackwall_xdp(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // --- Parse Ethernet header ---
    let eth_hdr_end = data + mem::size_of::<EthHdr>();
    if eth_hdr_end > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let eth_hdr = data as *const EthHdr;
    let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });
    if ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- Parse IPv4 header ---
    let ip_hdr_start = eth_hdr_end;
    let ip_hdr_end = ip_hdr_start + mem::size_of::<Ipv4Hdr>();
    if ip_hdr_end > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_hdr = ip_hdr_start as *const Ipv4Hdr;
    let src_ip = unsafe { (*ip_hdr).src_addr };
    let dst_ip = unsafe { (*ip_hdr).dst_addr };
    let protocol = unsafe { (*ip_hdr).proto };
    let total_len = u16::from_be(unsafe { (*ip_hdr).tot_len }) as u32;

    // --- Increment counters ---
    if let Some(counters) = COUNTERS.get_ptr_mut(0) {
        unsafe { (*counters).packets_total += 1 };
    }

    // --- Check BLOCKLIST HashMap ---
    let key = RuleKey { ip: src_ip };
    if let Some(rule) = unsafe { BLOCKLIST.get(&key) } {
        match rule.action {
            0 => {
                // Explicit allow
                increment_passed();
                return Ok(xdp_action::XDP_PASS);
            }
            1 => {
                // Block
                increment_dropped();
                return Ok(xdp_action::XDP_DROP);
            }
            2 => {
                // Redirect to tarpit — emit event, PASS for userspace DNAT
                emit_event(ctx, src_ip, dst_ip, 0, 0, protocol, 0, 0, 0, total_len);
                increment_passed();
                return Ok(xdp_action::XDP_PASS);
            }
            _ => {}
        }
    }

    // --- Check CIDR_RULES LpmTrie ---
    let cidr_key = LpmKey::new(32, src_ip);
    if let Some(rule) = CIDR_RULES.get(&cidr_key) {
        match rule.action {
            0 => {
                increment_passed();
                return Ok(xdp_action::XDP_PASS);
            }
            1 => {
                increment_dropped();
                return Ok(xdp_action::XDP_DROP);
            }
            2 => {
                emit_event(ctx, src_ip, dst_ip, 0, 0, protocol, 0, 0, 0, total_len);
                increment_passed();
                return Ok(xdp_action::XDP_PASS);
            }
            _ => {}
        }
    }

    // --- Parse transport header ---
    let transport_start = ip_hdr_end;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut tcp_flags: u8 = 0;
    let mut payload_start = transport_start;

    if protocol == IPPROTO_TCP {
        let tcp_hdr_end = transport_start + mem::size_of::<TcpHdr>();
        if tcp_hdr_end > data_end {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
        let tcp_hdr = transport_start as *const TcpHdr;
        src_port = u16::from_be(unsafe { (*tcp_hdr).src_port });
        dst_port = u16::from_be(unsafe { (*tcp_hdr).dst_port });
        // Extract flags from doff_flags: lower byte of big-endian u16
        let doff_flags = u16::from_be(unsafe { (*tcp_hdr).doff_flags });
        tcp_flags = (doff_flags & 0x3F) as u8;
        // Data offset is in upper 4 bits (in 32-bit words)
        let data_offset = ((doff_flags >> 12) & 0xF) as usize * 4;
        payload_start = transport_start + data_offset;
    } else if protocol == IPPROTO_UDP {
        let udp_hdr_end = transport_start + mem::size_of::<UdpHdr>();
        if udp_hdr_end > data_end {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
        let udp_hdr = transport_start as *const UdpHdr;
        src_port = u16::from_be(unsafe { (*udp_hdr).src_port });
        dst_port = u16::from_be(unsafe { (*udp_hdr).dst_port });
        payload_start = udp_hdr_end;
    }

    // --- Detect suspicious TCP flag patterns ---
    // SYN scan: SYN set, ACK not set (connection attempt / port scan)
    // XMAS scan: FIN+PSH+URG set (0x29)
    // NULL scan: no flags set (0x00)
    // These emit events even without payload, enabling AI-based scan detection.
    if protocol == IPPROTO_TCP {
        let syn = tcp_flags & 0x02 != 0;
        let ack = tcp_flags & 0x10 != 0;
        let fin = tcp_flags & 0x01 != 0;
        let psh = tcp_flags & 0x08 != 0;
        let urg = tcp_flags & 0x20 != 0;
        let rst = tcp_flags & 0x04 != 0;

        // SYN-only (no ACK, no RST) = connection attempt / SYN scan / SYN flood
        let syn_only = syn && !ack && !rst;
        // XMAS = FIN+PSH+URG
        let xmas = fin && psh && urg;
        // NULL = no flags at all
        let null_scan = tcp_flags == 0;

        if syn_only || xmas || null_scan {
            emit_event(
                ctx, src_ip, dst_ip, src_port, dst_port,
                protocol, tcp_flags, 0, 0, total_len,
            );
            if let Some(counters) = COUNTERS.get_ptr_mut(0) {
                unsafe { (*counters).anomalies_sent += 1 };
            }
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }

        // --- TLS ClientHello detection (port 443) ---
        // ARCH: Parse TLS record → handshake → ClientHello → emit components
        if dst_port == 443 && payload_start + 6 <= data_end {
            try_parse_tls_client_hello(
                payload_start, data_end,
                src_ip, dst_ip, src_port, dst_port,
            );
        }
    }

    // --- DPI tail call dispatch ---
    // ARCH: PROG_ARRAY tail calls for protocol-specific deep packet inspection.
    // On success the tail-called program replaces this one (no return).
    // On failure (program not loaded at index) execution falls through to entropy.
    if payload_start + 4 <= data_end {
        if let Some(scratch) = DPI_SCRATCH.get_ptr_mut(0) {
            unsafe {
                (*scratch).src_ip = src_ip;
                (*scratch).dst_ip = dst_ip;
                (*scratch).src_port = src_port;
                (*scratch).dst_port = dst_port;
                (*scratch).payload_offset = (payload_start - data) as u32;
            }
            if protocol == IPPROTO_TCP {
                if dst_port == 80 || dst_port == 8080 {
                    let _ = unsafe { DPI_PROGS.tail_call(ctx, DPI_PROG_HTTP as u32) };
                }
                if dst_port == 22 {
                    let _ = unsafe { DPI_PROGS.tail_call(ctx, DPI_PROG_SSH as u32) };
                }
            } else if protocol == IPPROTO_UDP && dst_port == 53 {
                let _ = unsafe { DPI_PROGS.tail_call(ctx, DPI_PROG_DNS as u32) };
            }
        }
    }

    // --- Calculate payload entropy ---
    let payload_len = if payload_start < data_end {
        data_end - payload_start
    } else {
        0
    };

    if payload_len == 0 {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    // --- Entropy estimation via unique byte count ---
    // Uses a 32-byte (256-bit) bitmap on the stack to track distinct byte values.
    // Much cheaper for the BPF verifier than a 256-entry histogram with ilog2.
    // Random/encrypted data: ~200-256 unique bytes → high entropy score.
    // ASCII text/protocol: ~30-80 unique bytes → low entropy score.
    let mut seen = [0u8; 32]; // 256-bit bitmap (32 bytes, fits in stack)
    let mut bytes_analyzed: u32 = 0;
    for i in 0..MAX_PAYLOAD_ANALYSIS_BYTES {
        let byte_ptr = payload_start + i;
        if byte_ptr + 1 > data_end {
            break;
        }
        let byte_val = unsafe { *(byte_ptr as *const u8) };
        // Set bit in bitmap: seen[byte_val / 8] |= 1 << (byte_val % 8)
        let idx = (byte_val >> 3) as usize;
        let bit = 1u8 << (byte_val & 7);
        if idx < 32 {
            seen[idx] |= bit;
        }
        bytes_analyzed += 1;
    }

    if bytes_analyzed == 0 {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    // Popcount: count total set bits across 32 bytes (bounded loops only)
    let mut unique_count: u32 = 0;
    for i in 0..32u32 {
        let byte = seen[i as usize];
        for j in 0..8u32 {
            unique_count += ((byte >> j) & 1) as u32;
        }
    }

    // Scale unique_count (1–256) to entropy × 1000 range (0–8000).
    // Formula: entropy_approx = unique_count * 8000 / 256 = unique_count * 31
    // Encrypted payloads (128+ bytes): ~230-256 unique → score ~7000-8000.
    // ASCII text: ~40-60 unique → score ~1200-1800.
    let entropy = unique_count * 31;

    // --- Emit event if entropy exceeds threshold ---
    if entropy > ENTROPY_ANOMALY_THRESHOLD {
        emit_event(
            ctx,
            src_ip, dst_ip,
            src_port, dst_port,
            protocol, tcp_flags,
            bytes_analyzed as u16,
            entropy,
            total_len,
        );
        if let Some(counters) = COUNTERS.get_ptr_mut(0) {
            unsafe { (*counters).anomalies_sent += 1 };
        }
    }

    increment_passed();
    Ok(xdp_action::XDP_PASS)
}

// --- TLS ClientHello Parser ---
// ARCH: Parses TLS record → handshake → ClientHello to extract JA4 components.
// All offsets are byte-level with mandatory bounds checks for the verifier.
// Variable-length fields use bounded loops (TLS_MAX_CIPHERS, TLS_MAX_EXTENSIONS).
// Zero-copy: reserves TlsComponentsEvent from TLS_EVENTS RingBuf, fills in-place.

fn try_parse_tls_client_hello(
    payload_start: usize,
    data_end: usize,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
) {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    // Then handshake header: type(1) + length(3) = 4 bytes
    // Then ClientHello: version(2) + random(32) + session_id_len(1) = 35 bytes
    // Minimum: 5 + 4 + 35 = 44 bytes before cipher_suites
    let mut pos = payload_start;

    // --- TLS Record Layer ---
    if pos + 5 > data_end {
        return;
    }
    let content_type = unsafe { *(pos as *const u8) };
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return;
    }
    // Skip TLS record version (2 bytes), record length (2 bytes)
    // We don't validate record length — the verifier ensures per-access bounds
    pos += 5;

    // --- Handshake Header ---
    if pos + 4 > data_end {
        return;
    }
    let handshake_type = unsafe { *(pos as *const u8) };
    if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO {
        return;
    }
    // Skip handshake length (3 bytes)
    pos += 4;

    // --- ClientHello body ---
    // client_version (2 bytes)
    if pos + 2 > data_end {
        return;
    }
    let ver_hi = unsafe { *(pos as *const u8) };
    let ver_lo = unsafe { *((pos + 1) as *const u8) };
    let tls_version: u16 = (ver_hi as u16) << 8 | ver_lo as u16;
    pos += 2;

    // random (32 bytes)
    if pos + 32 > data_end {
        return;
    }
    pos += 32;

    // session_id_len (1 byte) + session_id (variable)
    if pos + 1 > data_end {
        return;
    }
    let session_id_len = unsafe { *(pos as *const u8) } as usize;
    pos += 1;
    // Session ID can be 0-32 bytes; clamp to 32 for safety
    if session_id_len > 32 {
        return;
    }
    if pos + session_id_len > data_end {
        return;
    }
    pos += session_id_len;

    // --- Cipher Suites ---
    // cipher_suites_len (2 bytes) = total bytes of cipher suite data
    if pos + 2 > data_end {
        return;
    }
    let cs_len_hi = unsafe { *(pos as *const u8) } as usize;
    let cs_len_lo = unsafe { *((pos + 1) as *const u8) } as usize;
    let cipher_suites_len = (cs_len_hi << 8) | cs_len_lo;
    pos += 2;

    // Each cipher suite is 2 bytes. Count = cipher_suites_len / 2
    if cipher_suites_len > 512 || pos + cipher_suites_len > data_end {
        return;
    }

    // Reserve RingBuf entry for zero-copy fill
    let mut entry = match TLS_EVENTS.reserve::<TlsComponentsEvent>(0) {
        Some(e) => e,
        None => return,
    };
    let event = entry.as_mut_ptr();

    // Fill header fields
    unsafe {
        (*event).src_ip = src_ip;
        (*event).dst_ip = dst_ip;
        (*event).src_port = src_port;
        (*event).dst_port = dst_port;
        (*event).tls_version = tls_version;
        (*event).cipher_count = 0;
        (*event).ext_count = 0;
        (*event).has_sni = 0;
        (*event).alpn_first_len = 0;
        (*event).timestamp_ns = 0;
        (*event)._padding = [0; 2];
        // Zero arrays
        let mut zi = 0u32;
        while zi < TLS_MAX_CIPHERS as u32 {
            (*event).ciphers[zi as usize] = 0;
            zi += 1;
        }
        zi = 0;
        while zi < TLS_MAX_EXTENSIONS as u32 {
            (*event).extensions[zi as usize] = 0;
            zi += 1;
        }
        zi = 0;
        while zi < TLS_MAX_SNI as u32 {
            (*event).sni[zi as usize] = 0;
            zi += 1;
        }
    }

    // Read cipher suites (bounded by TLS_MAX_CIPHERS)
    let cs_end = pos + cipher_suites_len;
    let mut cipher_idx: u8 = 0;
    let mut i: usize = 0;
    // PERF: bounded loop — verifier needs a hard constant upper bound
    while i < 256 {
        if pos + 2 > cs_end {
            break;
        }
        if pos + 2 > data_end {
            break;
        }
        let c_hi = unsafe { *(pos as *const u8) } as u16;
        let c_lo = unsafe { *((pos + 1) as *const u8) } as u16;
        let cipher = (c_hi << 8) | c_lo;
        pos += 2;

        if (cipher_idx as usize) < TLS_MAX_CIPHERS {
            unsafe { (*event).ciphers[cipher_idx as usize] = cipher };
            cipher_idx += 1;
        }
        i += 1;
    }
    unsafe { (*event).cipher_count = cipher_idx };
    // Ensure pos is at cipher suites end
    pos = cs_end;

    // --- Compression Methods ---
    // comp_methods_len (1 byte) + methods (variable)
    if pos + 1 > data_end {
        unsafe { (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32 };
        entry.submit(0);
        return;
    }
    let comp_len = unsafe { *(pos as *const u8) } as usize;
    pos += 1;
    if comp_len > 16 || pos + comp_len > data_end {
        unsafe { (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32 };
        entry.submit(0);
        return;
    }
    pos += comp_len;

    // --- Extensions ---
    // extensions_len (2 bytes)
    if pos + 2 > data_end {
        unsafe { (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32 };
        entry.submit(0);
        return;
    }
    let ext_len_hi = unsafe { *(pos as *const u8) } as usize;
    let ext_len_lo = unsafe { *((pos + 1) as *const u8) } as usize;
    let extensions_total_len = (ext_len_hi << 8) | ext_len_lo;
    pos += 2;

    if extensions_total_len > 1200 || pos + extensions_total_len > data_end {
        unsafe { (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32 };
        entry.submit(0);
        return;
    }

    let ext_end = pos + extensions_total_len;
    let mut ext_idx: u8 = 0;

    // Parse individual extensions (bounded loop)
    let mut ext_iter: usize = 0;
    while ext_iter < 128 {
        // Each extension: type(2) + length(2) + data(length)
        if pos + 4 > ext_end {
            break;
        }
        if pos + 4 > data_end {
            break;
        }
        let etype_hi = unsafe { *(pos as *const u8) } as u16;
        let etype_lo = unsafe { *((pos + 1) as *const u8) } as u16;
        let ext_type = (etype_hi << 8) | etype_lo;
        let elen_hi = unsafe { *((pos + 2) as *const u8) } as u16;
        let elen_lo = unsafe { *((pos + 3) as *const u8) } as u16;
        let ext_data_len = ((elen_hi << 8) | elen_lo) as usize;
        pos += 4;

        if ext_data_len > 1200 || pos + ext_data_len > data_end {
            break;
        }

        // Record extension type
        if (ext_idx as usize) < TLS_MAX_EXTENSIONS {
            unsafe { (*event).extensions[ext_idx as usize] = ext_type };
            ext_idx += 1;
        }

        // SNI extension (type 0x0000)
        if ext_type == 0x0000 && ext_data_len >= 5 {
            // SNI list: list_len(2) + name_type(1) + name_len(2) + name(name_len)
            if pos + 5 <= data_end {
                let name_len_hi = unsafe { *((pos + 3) as *const u8) } as usize;
                let name_len_lo = unsafe { *((pos + 4) as *const u8) } as usize;
                let name_len = (name_len_hi << 8) | name_len_lo;
                let name_start = pos + 5;
                if name_start + name_len <= data_end && name_len <= 256 {
                    let copy_len = if name_len < TLS_MAX_SNI { name_len } else { TLS_MAX_SNI };
                    let mut si: usize = 0;
                    while si < TLS_MAX_SNI {
                        if si >= copy_len {
                            break;
                        }
                        if name_start + si + 1 > data_end {
                            break;
                        }
                        unsafe {
                            (*event).sni[si] = *((name_start + si) as *const u8);
                        }
                        si += 1;
                    }
                    unsafe { (*event).has_sni = 1 };
                }
            }
        }

        // ALPN extension (type 0x0010)
        if ext_type == 0x0010 && ext_data_len >= 4 {
            // ALPN: alpn_list_len(2) + proto_len(1) + proto(proto_len)
            if pos + 3 <= data_end {
                let alpn_proto_len = unsafe { *((pos + 2) as *const u8) };
                unsafe { (*event).alpn_first_len = alpn_proto_len };
            }
        }

        pos += ext_data_len;
        ext_iter += 1;
    }

    unsafe {
        (*event).ext_count = ext_idx;
        (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32;
    }

    entry.submit(0);
}

// --- Helper Functions ---

/// Emit a PacketEvent to the EVENTS RingBuf (zero-copy).
fn emit_event(
    _ctx: &XdpContext,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    payload_len: u16,
    entropy_score: u32,
    packet_size: u32,
) {
    if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).src_ip = src_ip;
            (*event).dst_ip = dst_ip;
            (*event).src_port = src_port;
            (*event).dst_port = dst_port;
            (*event).protocol = protocol;
            (*event).flags = flags;
            (*event).payload_len = payload_len;
            (*event).entropy_score = entropy_score;
            (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32;
            (*event)._padding = 0;
            (*event).packet_size = packet_size;
        }
        entry.submit(0);
    }
}

fn increment_passed() {
    if let Some(counters) = COUNTERS.get_ptr_mut(0) {
        unsafe { (*counters).packets_passed += 1 };
    }
}

fn increment_dropped() {
    if let Some(counters) = COUNTERS.get_ptr_mut(0) {
        unsafe { (*counters).packets_dropped += 1 };
    }
}

/// Emit a DpiEvent to the DPI_EVENTS RingBuf (zero-copy).
fn emit_dpi_event(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    payload_len: u16,
) {
    if let Some(mut entry) = DPI_EVENTS.reserve::<DpiEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).src_ip = src_ip;
            (*event).dst_ip = dst_ip;
            (*event).src_port = src_port;
            (*event).dst_port = dst_port;
            (*event).protocol = protocol;
            (*event).flags = flags;
            (*event).payload_len = payload_len;
            (*event).timestamp_ns =
                (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32;
        }
        entry.submit(0);
    }
}

// --- DPI Tail Call Programs ---
// ARCH: Each program is loaded into DPI_PROGS ProgramArray by userspace.
// They receive same XdpContext as the caller and read pre-parsed metadata
// from DPI_SCRATCH PerCpuArray to avoid re-parsing headers.

#[xdp]
pub fn dpi_http(ctx: XdpContext) -> u32 {
    match try_dpi_http(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_dpi_http(ctx: &XdpContext) -> Result<u32, i64> {
    let scratch_ptr = match DPI_SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let data = ctx.data();
    let data_end = ctx.data_end();
    let (src_ip, dst_ip, src_port, dst_port, payload_start);
    unsafe {
        src_ip = (*scratch_ptr).src_ip;
        dst_ip = (*scratch_ptr).dst_ip;
        src_port = (*scratch_ptr).src_port;
        dst_port = (*scratch_ptr).dst_port;
        payload_start = data + (*scratch_ptr).payload_offset as usize;
    }

    if payload_start + 4 > data_end {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    // Check for HTTP method signatures
    let b0 = unsafe { *(payload_start as *const u8) };
    let b1 = unsafe { *((payload_start + 1) as *const u8) };
    let b2 = unsafe { *((payload_start + 2) as *const u8) };
    let b3 = unsafe { *((payload_start + 3) as *const u8) };

    let is_http = (b0 == b'G' && b1 == b'E' && b2 == b'T' && b3 == b' ')
        || (b0 == b'P' && b1 == b'O' && b2 == b'S' && b3 == b'T')
        || (b0 == b'H' && b1 == b'E' && b2 == b'A' && b3 == b'D')
        || (b0 == b'P' && b1 == b'U' && b2 == b'T' && b3 == b' ')
        || (b0 == b'D' && b1 == b'E' && b2 == b'L' && b3 == b'E')
        || (b0 == b'H' && b1 == b'T' && b2 == b'T' && b3 == b'P');

    if !is_http {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    let mut flags: u8 = 0;

    // Scan URI for suspicious paths (bounded to 128 bytes)
    let avail = if data_end > payload_start { data_end - payload_start } else { 0 };
    let scan_max = if avail > 128 { 128 } else { avail };
    let mut i: usize = 0;
    while i + 4 < scan_max {
        let p = payload_start + i;
        if p + 4 > data_end {
            break;
        }
        let c0 = unsafe { *(p as *const u8) };
        let c1 = unsafe { *((p + 1) as *const u8) };
        let c2 = unsafe { *((p + 2) as *const u8) };
        let c3 = unsafe { *((p + 3) as *const u8) };
        // /wp- (WordPress probing)
        if c0 == b'/' && c1 == b'w' && c2 == b'p' && c3 == b'-' {
            flags |= DPI_HTTP_FLAG_SUSPICIOUS_PATH;
            break;
        }
        // /adm (admin path)
        if c0 == b'/' && c1 == b'a' && c2 == b'd' && c3 == b'm' {
            flags |= DPI_HTTP_FLAG_SUSPICIOUS_PATH;
            break;
        }
        // /cmd or /cgi (command injection / CGI probing)
        if c0 == b'/' && c1 == b'c' && (c2 == b'm' || c2 == b'g') {
            flags |= DPI_HTTP_FLAG_SUSPICIOUS_PATH;
            break;
        }
        i += 1;
    }

    let plen = if data_end > payload_start {
        (data_end - payload_start) as u16
    } else {
        0
    };
    emit_dpi_event(
        src_ip, dst_ip, src_port, dst_port,
        DpiProtocol::Http as u8, flags, plen,
    );
    increment_passed();
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn dpi_dns(ctx: XdpContext) -> u32 {
    match try_dpi_dns(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_dpi_dns(ctx: &XdpContext) -> Result<u32, i64> {
    let scratch_ptr = match DPI_SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let data = ctx.data();
    let data_end = ctx.data_end();
    let (src_ip, dst_ip, src_port, dst_port, payload_start);
    unsafe {
        src_ip = (*scratch_ptr).src_ip;
        dst_ip = (*scratch_ptr).dst_ip;
        src_port = (*scratch_ptr).src_port;
        dst_port = (*scratch_ptr).dst_port;
        payload_start = data + (*scratch_ptr).payload_offset as usize;
    }

    // DNS header is 12 bytes minimum
    if payload_start + 12 > data_end {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    let mut flags: u8 = 0;

    // Parse DNS query name length (after 12-byte header)
    let qname_start = payload_start + 12;
    let mut qpos = qname_start;
    let mut qlen: u16 = 0;
    let mut label_count: usize = 0;
    let mut qi: usize = 0;
    while qi < 253 {
        if qpos + 1 > data_end {
            break;
        }
        let label_len = unsafe { *(qpos as *const u8) };
        if label_len == 0 {
            qlen += 1;
            break;
        }
        qlen += 1 + label_len as u16;
        qpos += 1 + label_len as usize;
        label_count += 1;
        qi += 1;
    }

    // Long query name → potential DNS tunneling
    if qlen > DNS_TUNNEL_QUERY_LEN_THRESHOLD as u16 {
        flags |= DPI_DNS_FLAG_LONG_QUERY;
    }
    // High label count (>5 labels) is suspicious for tunneling
    if label_count > 5 {
        flags |= DPI_DNS_FLAG_TUNNELING_SUSPECT;
    }

    let plen = if data_end > payload_start {
        (data_end - payload_start) as u16
    } else {
        0
    };
    emit_dpi_event(
        src_ip, dst_ip, src_port, dst_port,
        DpiProtocol::Dns as u8, flags, plen,
    );
    increment_passed();
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn dpi_ssh(ctx: XdpContext) -> u32 {
    match try_dpi_ssh(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_dpi_ssh(ctx: &XdpContext) -> Result<u32, i64> {
    let scratch_ptr = match DPI_SCRATCH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let data = ctx.data();
    let data_end = ctx.data_end();
    let (src_ip, dst_ip, src_port, dst_port, payload_start);
    unsafe {
        src_ip = (*scratch_ptr).src_ip;
        dst_ip = (*scratch_ptr).dst_ip;
        src_port = (*scratch_ptr).src_port;
        dst_port = (*scratch_ptr).dst_port;
        payload_start = data + (*scratch_ptr).payload_offset as usize;
    }

    // SSH banner: "SSH-"
    if payload_start + 4 > data_end {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    let b0 = unsafe { *(payload_start as *const u8) };
    let b1 = unsafe { *((payload_start + 1) as *const u8) };
    let b2 = unsafe { *((payload_start + 2) as *const u8) };
    let b3 = unsafe { *((payload_start + 3) as *const u8) };

    if b0 != b'S' || b1 != b'S' || b2 != b'H' || b3 != b'-' {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    let mut flags: u8 = 0;

    // Scan version string for suspicious SSH implementations
    let avail = if data_end > payload_start { data_end - payload_start } else { 0 };
    let scan_max = if avail > 64 { 64 } else { avail };
    let mut i: usize = 4; // Start after "SSH-"
    while i + 4 < scan_max {
        let p = payload_start + i;
        if p + 4 > data_end {
            break;
        }
        let c0 = unsafe { *(p as *const u8) };
        let c1 = unsafe { *((p + 1) as *const u8) };
        let c2 = unsafe { *((p + 2) as *const u8) };
        let c3 = unsafe { *((p + 3) as *const u8) };
        // "libs" from "libssh" (common in automated attacks)
        if c0 == b'l' && c1 == b'i' && c2 == b'b' && c3 == b's' {
            flags |= DPI_SSH_FLAG_SUSPICIOUS_SW;
            break;
        }
        // "para" from "paramiko" (Python SSH library)
        if c0 == b'p' && c1 == b'a' && c2 == b'r' && c3 == b'a' {
            flags |= DPI_SSH_FLAG_SUSPICIOUS_SW;
            break;
        }
        // "drop" from "dropbear" (embedded SSH, often IoT botnets)
        if c0 == b'd' && c1 == b'r' && c2 == b'o' && c3 == b'p' {
            flags |= DPI_SSH_FLAG_SUSPICIOUS_SW;
            break;
        }
        i += 1;
    }

    let plen = if data_end > payload_start {
        (data_end - payload_start) as u16
    } else {
        0
    };
    emit_dpi_event(
        src_ip, dst_ip, src_port, dst_port,
        DpiProtocol::Ssh as u8, flags, plen,
    );
    increment_passed();
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// --- TC Egress Classifier ---
// ARCH: Monitors outbound traffic for C2 beaconing, DNS tunneling, data exfiltration.
// Attached to TC egress hook — sees all packets leaving the server.

const TC_ACT_OK: i32 = 0;
// DNS port for query length extraction
const DNS_PORT: u16 = 53;

#[classifier]
pub fn blackwall_egress(ctx: TcContext) -> i32 {
    match try_blackwall_egress(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, // Never drop egress on error
    }
}

fn try_blackwall_egress(ctx: &TcContext) -> Result<i32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // --- Parse Ethernet header ---
    let eth_hdr_end = data + mem::size_of::<EthHdr>();
    if eth_hdr_end > data_end {
        return Ok(TC_ACT_OK);
    }
    let eth_hdr = data as *const EthHdr;
    let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });
    if ether_type != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }

    // --- Parse IPv4 header ---
    let ip_hdr_start = eth_hdr_end;
    let ip_hdr_end = ip_hdr_start + mem::size_of::<Ipv4Hdr>();
    if ip_hdr_end > data_end {
        return Ok(TC_ACT_OK);
    }
    let ip_hdr = ip_hdr_start as *const Ipv4Hdr;
    let src_ip = unsafe { (*ip_hdr).src_addr };
    let dst_ip = unsafe { (*ip_hdr).dst_addr };
    let protocol = unsafe { (*ip_hdr).proto };
    let total_len = u16::from_be(unsafe { (*ip_hdr).tot_len }) as u32;

    // --- Parse transport header ---
    let transport_start = ip_hdr_end;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut tcp_flags: u8 = 0;
    let mut payload_start = transport_start;

    if protocol == IPPROTO_TCP {
        let tcp_hdr_end = transport_start + mem::size_of::<TcpHdr>();
        if tcp_hdr_end > data_end {
            return Ok(TC_ACT_OK);
        }
        let tcp_hdr = transport_start as *const TcpHdr;
        src_port = u16::from_be(unsafe { (*tcp_hdr).src_port });
        dst_port = u16::from_be(unsafe { (*tcp_hdr).dst_port });
        let doff_flags = u16::from_be(unsafe { (*tcp_hdr).doff_flags });
        tcp_flags = (doff_flags & 0x3F) as u8;
        let data_offset = ((doff_flags >> 12) & 0xF) as usize * 4;
        payload_start = transport_start + data_offset;
    } else if protocol == IPPROTO_UDP {
        let udp_hdr_end = transport_start + mem::size_of::<UdpHdr>();
        if udp_hdr_end > data_end {
            return Ok(TC_ACT_OK);
        }
        let udp_hdr = transport_start as *const UdpHdr;
        src_port = u16::from_be(unsafe { (*udp_hdr).src_port });
        dst_port = u16::from_be(unsafe { (*udp_hdr).dst_port });
        payload_start = udp_hdr_end;
    } else {
        return Ok(TC_ACT_OK);
    }

    // --- Calculate payload length ---
    let payload_len = if payload_start < data_end {
        (data_end - payload_start) as u16
    } else {
        0u16
    };

    // --- DNS query length extraction (dst port 53) ---
    let mut dns_query_len: u16 = 0;
    if dst_port == DNS_PORT && payload_start + 12 <= data_end {
        // DNS header is 12 bytes. After that, the query name starts.
        // Query name: sequence of length-prefixed labels ending with 0x00.
        // We measure total bytes of the query name section.
        let qname_start = payload_start + 12;
        let mut qpos = qname_start;
        let mut qlen: u16 = 0;
        // Bounded loop: DNS names max 253 chars
        let mut qi: usize = 0;
        while qi < 253 {
            if qpos + 1 > data_end {
                break;
            }
            let label_len = unsafe { *(qpos as *const u8) };
            if label_len == 0 {
                qlen += 1; // Count the terminating zero
                break;
            }
            qlen += 1 + label_len as u16; // length byte + label data
            qpos += 1 + label_len as usize;
            qi += 1;
        }
        dns_query_len = qlen;
    }

    // --- Outbound entropy estimation (same bitmap approach as ingress) ---
    let mut entropy_score: u16 = 0;
    if payload_len > 0 {
        let mut seen = [0u8; 32];
        let mut bytes_analyzed: u32 = 0;
        let max_bytes = if (payload_len as usize) < MAX_PAYLOAD_ANALYSIS_BYTES {
            payload_len as usize
        } else {
            MAX_PAYLOAD_ANALYSIS_BYTES
        };
        let mut i: usize = 0;
        while i < MAX_PAYLOAD_ANALYSIS_BYTES {
            if i >= max_bytes {
                break;
            }
            let byte_ptr = payload_start + i;
            if byte_ptr + 1 > data_end {
                break;
            }
            let byte_val = unsafe { *(byte_ptr as *const u8) };
            let idx = (byte_val >> 3) as usize;
            let bit = 1u8 << (byte_val & 7);
            if idx < 32 {
                seen[idx] |= bit;
            }
            bytes_analyzed += 1;
            i += 1;
        }

        if bytes_analyzed > 0 {
            let mut unique_count: u32 = 0;
            let mut bi: u32 = 0;
            while bi < 32 {
                let byte = seen[bi as usize];
                let mut bj: u32 = 0;
                while bj < 8 {
                    unique_count += ((byte >> bj) & 1) as u32;
                    bj += 1;
                }
                bi += 1;
            }
            // Scale to 0-8000 range, but truncate to u16 (max 8000 fits)
            entropy_score = (unique_count * 31) as u16;
        }
    }

    // --- Emit EgressEvent ---
    // Emit for: DNS queries, high-entropy outbound, or all TCP with payload
    let should_emit = dns_query_len > 0
        || entropy_score > ENTROPY_ANOMALY_THRESHOLD as u16
        || (protocol == IPPROTO_TCP && payload_len > 0);

    if should_emit {
        if let Some(mut entry) = EGRESS_EVENTS.reserve::<EgressEvent>(0) {
            let event = entry.as_mut_ptr();
            unsafe {
                (*event).src_ip = src_ip;
                (*event).dst_ip = dst_ip;
                (*event).src_port = src_port;
                (*event).dst_port = dst_port;
                (*event).protocol = protocol;
                (*event).flags = tcp_flags;
                (*event).payload_len = payload_len;
                (*event).dns_query_len = dns_query_len;
                (*event).entropy_score = entropy_score;
                (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32;
                (*event).packet_size = total_len;
            }
            entry.submit(0);
        }
    }

    Ok(TC_ACT_OK)
}
