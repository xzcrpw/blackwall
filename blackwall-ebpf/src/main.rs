#![no_std]
#![no_main]


use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{classifier, map, xdp};
use aya_ebpf::maps::{HashMap, LruHashMap, LpmTrie, PerCpuArray, ProgramArray, RingBuf};
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::programs::{TcContext, XdpContext};
use common::{
    Counters, DpiEvent, DpiProtocol, EgressEvent, PacketEvent, RuleKey, RuleValue,
    TlsComponentsEvent, ConnTrackKey, ConnTrackValue, NatKey, NatValue, TarpitTarget,
    RateLimitValue,
    BLOCKLIST_MAX_ENTRIES, CIDR_MAX_ENTRIES, CONN_TRACK_MAX_ENTRIES, NAT_TABLE_MAX_ENTRIES,
    RATE_LIMIT_MAX_ENTRIES, RATE_LIMIT_PPS, RATE_LIMIT_BURST,
    CT_STATE_NEW, CT_STATE_SYN_SENT, CT_STATE_SYN_RECV, CT_STATE_ESTABLISHED,
    CT_STATE_FIN_WAIT, CT_STATE_CLOSED,
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

// --- eBPF Native DNAT Maps ---

/// Tarpit DNAT configuration — single element populated by userspace.
/// Contains: port, local_ip, enabled flag.
#[map]
static TARPIT_TARGET: PerCpuArray<TarpitTarget> = PerCpuArray::with_max_entries(1, 0);

/// NAT tracking table — maps attacker (src_ip, src_port) to original dst_port.
/// Used by TC egress to reverse-NAT tarpit responses.
/// LRU eviction handles stale entries automatically.
#[map]
static NAT_TABLE: LruHashMap<NatKey, NatValue> =
    LruHashMap::with_max_entries(NAT_TABLE_MAX_ENTRIES, 0);

/// Stateful connection tracking — 5-tuple keyed LRU map for TCP flow state.
/// Enables: SYN flood detection, flow reassembly awareness, protocol anomalies.
#[map]
static CONN_TRACK: LruHashMap<ConnTrackKey, ConnTrackValue> =
    LruHashMap::with_max_entries(CONN_TRACK_MAX_ENTRIES, 0);

/// Per-IP rate limit token bucket — LRU map keyed by src_ip.
/// Limits packets-per-second from any single IP to prevent DDoS flooding
/// the RingBuf → userspace pipeline. Checked AFTER blocklist (blocked IPs
/// are already dropped) but BEFORE anomaly detection and RingBuf emission.
#[map]
static RATE_LIMIT: LruHashMap<u32, RateLimitValue> =
    LruHashMap::with_max_entries(RATE_LIMIT_MAX_ENTRIES, 0);

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
        // Check expiry: if expires_at is set and rule has expired, treat as no-match
        let expired = if rule.expires_at != 0 {
            let now_secs = unsafe { aya_ebpf::helpers::bpf_ktime_get_boot_ns() / 1_000_000_000 };
            now_secs > rule.expires_at as u64
        } else {
            false
        };
        if !expired {
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
                    // Redirect to tarpit — eBPF native DNAT
                    // (perform_dnat handles counting internally)
                    let dnat_result = perform_dnat(ctx);
                    return Ok(dnat_result);
                }
                _ => {}
            }
        }
    }

    // --- Check CIDR_RULES LpmTrie ---
    let cidr_key = LpmKey::new(32, src_ip);
    if let Some(rule) = CIDR_RULES.get(&cidr_key) {
        // Check expiry for CIDR rules too
        let expired = if rule.expires_at != 0 {
            let now_secs = unsafe { aya_ebpf::helpers::bpf_ktime_get_boot_ns() / 1_000_000_000 };
            now_secs > rule.expires_at as u64
        } else {
            false
        };
        if !expired {
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
                    // Redirect to tarpit — eBPF native DNAT (CIDR match)
                    // (perform_dnat handles counting internally)
                    let dnat_result = perform_dnat(ctx);
                    return Ok(dnat_result);
                }
                _ => {}
            }
        }
    }

    // --- Per-IP Rate Limiting (Token Bucket) ---
    // ARCH: Prevents DDoS from flooding RingBuf → userspace pipeline.
    // Each IP gets RATE_LIMIT_BURST tokens, refilled at RATE_LIMIT_PPS/sec.
    // When tokens exhausted → XDP_DROP. LRU eviction handles table pressure.
    let now_secs = unsafe { (aya_ebpf::helpers::bpf_ktime_get_boot_ns() / 1_000_000_000) as u32 };
    if let Some(rl) = RATE_LIMIT.get_ptr_mut(&src_ip) {
        let elapsed = now_secs.saturating_sub(unsafe { (*rl).last_refill });
        if elapsed > 0 {
            // Refill tokens: elapsed_secs * PPS, capped at BURST
            let refill = elapsed.saturating_mul(RATE_LIMIT_PPS);
            let new_tokens = unsafe { (*rl).tokens }.saturating_add(refill);
            unsafe {
                (*rl).tokens = if new_tokens > RATE_LIMIT_BURST {
                    RATE_LIMIT_BURST
                } else {
                    new_tokens
                };
                (*rl).last_refill = now_secs;
            }
        }
        let tokens = unsafe { (*rl).tokens };
        if tokens == 0 {
            increment_dropped();
            return Ok(xdp_action::XDP_DROP);
        }
        unsafe { (*rl).tokens = tokens - 1 };
    } else {
        // First packet from this IP — initialize bucket
        let rl_val = RateLimitValue {
            tokens: RATE_LIMIT_BURST - 1, // -1 for this packet
            last_refill: now_secs,
        };
        if RATE_LIMIT.insert(&src_ip, &rl_val, 0).is_err() {
            // LRU map full and insert failed — drop to prevent flood bypass
            increment_dropped();
            return Ok(xdp_action::XDP_DROP);
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

    // --- Stateful Connection Tracking ---
    // ARCH: Update per-flow state in CONN_TRACK LRU map.
    // Tracks TCP handshake state, packet counts, and cumulative flags.
    // Enables SYN flood detection and protocol anomaly identification.
    if protocol == IPPROTO_TCP || protocol == IPPROTO_UDP {
        let ct_key = ConnTrackKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        };
        let now = unsafe { (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32 };
        if let Some(ct_val) = CONN_TRACK.get_ptr_mut(&ct_key) {
            // Existing flow — update counters and state
            unsafe {
                (*ct_val).packet_count += 1;
                (*ct_val).byte_count += total_len;
                (*ct_val).last_seen = now;
                (*ct_val).flags_seen |= tcp_flags;
                // TCP state machine transitions
                if protocol == IPPROTO_TCP {
                    let syn = tcp_flags & 0x02 != 0;
                    let ack = tcp_flags & 0x10 != 0;
                    let fin = tcp_flags & 0x01 != 0;
                    let rst = tcp_flags & 0x04 != 0;
                    if rst {
                        (*ct_val).state = CT_STATE_CLOSED;
                    } else if fin {
                        (*ct_val).state = CT_STATE_FIN_WAIT;
                    } else if syn && ack && (*ct_val).state == CT_STATE_SYN_SENT {
                        (*ct_val).state = CT_STATE_SYN_RECV;
                    } else if ack && (*ct_val).state == CT_STATE_SYN_RECV {
                        (*ct_val).state = CT_STATE_ESTABLISHED;
                    }
                }
            }
        } else {
            // New flow — insert initial state
            let initial_state = if protocol == IPPROTO_TCP && (tcp_flags & 0x02 != 0) {
                CT_STATE_SYN_SENT
            } else if protocol == IPPROTO_TCP {
                CT_STATE_ESTABLISHED // mid-flow pickup
            } else {
                CT_STATE_NEW
            };
            let ct_val = ConnTrackValue {
                state: initial_state,
                flags_seen: tcp_flags,
                _pad: 0,
                packet_count: 1,
                byte_count: total_len,
                last_seen: now,
            };
            let _ = CONN_TRACK.insert(&ct_key, &ct_val, 0);
        }
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

    // --- Calculate payload entropy ---
    // ARCH: Entropy must be computed BEFORE DPI tail calls. bpf_tail_call
    // invalidates all packet pointer registers on fall-through, making it
    // impossible to re-derive valid pkt pointers from a saved scalar offset.
    // By computing entropy first, we use the original (verified) pkt pointers.
    let payload_len = if payload_start < data_end {
        data_end - payload_start
    } else {
        0
    };

    if payload_len > 0 {
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

        if bytes_analyzed > 0 {
            // Popcount: count total set bits across 32 bytes (bounded loops only)
            let mut unique_count: u32 = 0;
            for i in 0..32u32 {
                let byte = seen[i as usize];
                for j in 0..8u32 {
                    unique_count += ((byte >> j) & 1) as u32;
                }
            }

            // Byte diversity score: unique_count × 31 (range 0–7936).
            // NOT Shannon entropy — bitmap popcount heuristic, no FP math.
            // Encrypted payloads (128+ bytes): ~230-256 unique → score ~7000-7936.
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
        }
    }

    // --- DPI tail call dispatch ---
    // ARCH: PROG_ARRAY tail calls for protocol-specific deep packet inspection.
    // On success the tail-called program replaces this one (no return).
    // On failure (program not loaded at index) execution falls through to XDP_PASS.
    // Tail calls MUST be the last action — bpf_tail_call invalidates all pkt pointers.
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

    increment_passed();
    Ok(xdp_action::XDP_PASS)
}

// --- TLS ClientHello Parser ---
// ARCH: Parses TLS record → handshake → ClientHello to extract JA4 components.
// All offsets are byte-level with mandatory bounds checks for the verifier.
// Variable-length fields use bounded loops (TLS_MAX_CIPHERS, TLS_MAX_EXTENSIONS).
// ARCH: Simplified TLS ClientHello detector. Only reads fixed-offset fields
// (content type, handshake type, TLS version) to avoid BPF verifier issues
// with variable-length field parsing. Detailed cipher suite, extension, and
// SNI parsing is deferred to userspace — the BPF verifier on kernel 6.6
// cannot track packet pointers through accumulated variable-offset arithmetic
// (session_id_len + cipher_suites_len + comp_len causes var_off to exceed
// MAX_PACKET_OFF, making all subsequent bounds checks ineffective).

fn try_parse_tls_client_hello(
    payload_start: usize,
    data_end: usize,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
) {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    // Handshake header: type(1) + length(3) = 4 bytes
    // ClientHello body: version(2) = minimum 2 bytes
    // Total minimum: 5 + 4 + 2 = 11 bytes needed for detection
    if payload_start + 11 > data_end {
        return;
    }

    // --- TLS Record Layer ---
    let content_type = unsafe { *(payload_start as *const u8) };
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return;
    }

    // --- Handshake Header (at payload_start + 5) ---
    let handshake_type = unsafe { *((payload_start + 5) as *const u8) };
    if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO {
        return;
    }

    // --- ClientHello version (at payload_start + 9) ---
    let ver_hi = unsafe { *((payload_start + 9) as *const u8) } as u16;
    let ver_lo = unsafe { *((payload_start + 10) as *const u8) } as u16;
    let tls_version: u16 = (ver_hi << 8) | ver_lo;

    // Reserve RingBuf entry for zero-copy fill
    let mut entry = match TLS_EVENTS.reserve::<TlsComponentsEvent>(0) {
        Some(e) => e,
        None => return,
    };
    let event = entry.as_mut_ptr();

    // Fill event with detected ClientHello info
    // Cipher suites, extensions, and SNI are left zeroed — parsed in userspace
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
        (*event).timestamp_ns = (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32;
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
        // ARCH: Bound payload_offset before adding to pkt pointer so the
        // verifier knows umax <= 1500, preventing var_off overflow past
        // MAX_PACKET_OFF (65535).
        let offset = (*scratch_ptr).payload_offset as usize;
        if offset > 1500 {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
        payload_start = data + offset;
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
        // ARCH: Bound payload_offset before adding to pkt pointer so the
        // verifier knows umax <= 1500, preventing var_off overflow past
        // MAX_PACKET_OFF (65535).
        let offset = (*scratch_ptr).payload_offset as usize;
        if offset > 1500 {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
        payload_start = data + offset;
    }

    // DNS header is 12 bytes minimum
    if payload_start + 12 > data_end {
        increment_passed();
        return Ok(xdp_action::XDP_PASS);
    }

    let mut flags: u8 = 0;

    // ARCH: Simplified DNS tunneling heuristic — we use total payload length
    // instead of walking DNS labels, because the label-by-label loop
    // (`qpos += 1 + label_len` × 253 iterations) accumulates var_off on the
    // pkt pointer past MAX_PACKET_OFF, causing verifier rejection.
    // Detailed DNS label parsing is deferred to userspace.
    let plen_total = if data_end > payload_start {
        data_end - payload_start
    } else {
        0
    };
    // DNS queries longer than the threshold (including 12-byte header)
    // are suspicious for tunneling
    if plen_total > DNS_TUNNEL_QUERY_LEN_THRESHOLD as usize + 12 {
        flags |= DPI_DNS_FLAG_LONG_QUERY;
    }
    // Very large DNS payloads (> 200 bytes) often indicate tunneling
    if plen_total > 200 {
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
        // ARCH: Bound payload_offset before adding to pkt pointer so the
        // verifier knows umax <= 1500, preventing var_off overflow past
        // MAX_PACKET_OFF (65535).
        let offset = (*scratch_ptr).payload_offset as usize;
        if offset > 1500 {
            increment_passed();
            return Ok(xdp_action::XDP_PASS);
        }
        payload_start = data + offset;
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

// --- eBPF Native DNAT Engine ---
// ARCH: perform_dnat rewrites dst_port → tarpit_port on the incoming packet.
// TCP/UDP checksum is incrementally updated (RFC 1624, integer-only).
// The original dst_port is stored in NAT_TABLE so TC egress can reverse it.
// No IP address change needed — tarpit binds to 0.0.0.0:tarpit_port,
// so kernel routes the modified packet to the local tarpit socket.

/// Incremental one's-complement checksum update for a 16-bit field change (RFC 1624).
/// All integer arithmetic — no floating point.
#[inline(always)]
fn csum_replace2(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let sum: u32 = (!old_csum as u32) + (!old_val as u32) + (new_val as u32);
    let folded = (sum >> 16) + (sum & 0xFFFF);
    let folded = folded + (folded >> 16);
    !(folded as u16)
}

/// Perform native DNAT: rewrite dst_port to tarpit port, update checksum,
/// store original port in NAT_TABLE, emit event, return XDP_PASS.
/// Parses transport header internally — called from BLOCKLIST/CIDR action=2.
// PERF: #[inline(always)] required — BPF-to-BPF call codegen shifts pkt_end
// pointer (r6 <<= 32) which the verifier rejects as prohibited arithmetic.
#[inline(always)]
fn perform_dnat(
    ctx: &XdpContext,
) -> u32 {
    // Re-parse packet headers inside DNAT path (avoids >5 arg limit)
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth_hdr_size = mem::size_of::<EthHdr>();
    let ip_hdr_size = mem::size_of::<Ipv4Hdr>();

    if data + eth_hdr_size + ip_hdr_size > data_end {
        return xdp_action::XDP_PASS;
    }
    let ip_hdr = (data + eth_hdr_size) as *const Ipv4Hdr;
    let src_ip = unsafe { (*ip_hdr).src_addr };
    let dst_ip = unsafe { (*ip_hdr).dst_addr };
    let protocol = unsafe { (*ip_hdr).proto };
    let total_len = u16::from_be(unsafe { (*ip_hdr).tot_len }) as u32;

    // Read tarpit config from PerCpuArray
    let tarpit = match TARPIT_TARGET.get(0) {
        Some(t) => t,
        None => return xdp_action::XDP_PASS,
    };
    if tarpit.enabled == 0 || tarpit.port == 0 {
        return xdp_action::XDP_PASS;
    }

    let tarpit_port = tarpit.port;
    let transport_start = data + eth_hdr_size + ip_hdr_size;

    if protocol == IPPROTO_TCP {
        let tcp_end = transport_start + mem::size_of::<TcpHdr>();
        if tcp_end > data_end {
            return xdp_action::XDP_PASS;
        }
        let tcp_hdr = transport_start as *mut TcpHdr;
        let src_port = u16::from_be(unsafe { (*tcp_hdr).src_port });
        let dst_port = u16::from_be(unsafe { (*tcp_hdr).dst_port });

        // Skip if already DNATed (avoid double-rewrite)
        if dst_port == tarpit_port {
            return xdp_action::XDP_PASS;
        }

        // Store original dst_port in NAT table for TC reverse-NAT
        let nat_key = NatKey {
            src_ip,
            src_port: src_port as u32,
        };
        let now = unsafe { (aya_ebpf::helpers::bpf_ktime_get_ns() & 0xFFFF_FFFF) as u32 };
        let nat_val = NatValue {
            orig_dst_port: dst_port,
            _pad: 0,
            timestamp: now,
        };
        let _ = NAT_TABLE.insert(&nat_key, &nat_val, 0);

        // Rewrite dst_port to tarpit port
        let old_port_be = unsafe { (*tcp_hdr).dst_port };
        let new_port_be = u16::to_be(tarpit_port);
        unsafe { (*tcp_hdr).dst_port = new_port_be };

        // Incremental TCP checksum update (only port changed)
        let old_check = unsafe { (*tcp_hdr).check };
        let new_check = csum_replace2(
            u16::from_be(old_check),
            u16::from_be(old_port_be),
            tarpit_port,
        );
        unsafe { (*tcp_hdr).check = u16::to_be(new_check) };

        // Emit event for userspace logging/AI
        emit_event(
            ctx, src_ip, dst_ip, src_port, dst_port,
            protocol, 0, 0, 0, total_len,
        );
        increment_passed();
        return xdp_action::XDP_PASS;
    }

    // Non-TCP (UDP, ICMP, etc.) — tarpit is TCP-only, just pass through.
    // This preserves WireGuard, DNS, and other UDP services for DNAT'd IPs.
    increment_passed();
    xdp_action::XDP_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// --- TC Egress Classifier ---
// ARCH: Monitors outbound traffic for C2 beaconing, DNS tunneling, data exfiltration.
// Attached to TC egress hook — sees all packets leaving the server.

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
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
    #[allow(unused_assignments)]
    let mut src_port: u16 = 0;
    #[allow(unused_assignments)]
    let mut dst_port: u16 = 0;
    let mut tcp_flags: u8 = 0;
    #[allow(unused_assignments)]
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

    // --- TC Reverse-NAT for Tarpit Responses ---
    // ARCH: When the tarpit responds to a DNAT-ed connection, the src_port
    // is the tarpit port. We look up the NAT table by (dst_ip=attacker_ip,
    // dst_port=attacker_port) to find the original dst_port the attacker
    // was trying to reach, then rewrite src_port to that original port.
    // This makes the tarpit appear as the real service to the attacker.
    if let Some(tarpit) = TARPIT_TARGET.get(0) {
        if tarpit.enabled != 0 && tarpit.port != 0 && src_port == tarpit.port {
            // This is a tarpit response — reverse the NAT
            let nat_key = NatKey {
                src_ip: dst_ip,             // attacker IP
                src_port: dst_port as u32,  // attacker source port
            };
            if let Some(nat_val) = unsafe { NAT_TABLE.get(&nat_key) } {
                let orig_port = nat_val.orig_dst_port;
                if protocol == IPPROTO_TCP {
                    let tcp_hdr_end = transport_start + mem::size_of::<TcpHdr>();
                    if tcp_hdr_end <= data_end {
                        let tcp_hdr = transport_start as *mut TcpHdr;
                        let old_port_be = unsafe { (*tcp_hdr).src_port };
                        let new_port_be = u16::to_be(orig_port);
                        unsafe { (*tcp_hdr).src_port = new_port_be };
                        let old_check = unsafe { (*tcp_hdr).check };
                        let new_check = csum_replace2(
                            u16::from_be(old_check),
                            u16::from_be(old_port_be),
                            orig_port,
                        );
                        unsafe { (*tcp_hdr).check = u16::to_be(new_check) };
                        // Update src_port for downstream analytics
                        src_port = orig_port;
                    }
                } else if protocol == IPPROTO_UDP {
                    let udp_hdr_end = transport_start + mem::size_of::<UdpHdr>();
                    if udp_hdr_end <= data_end {
                        let udp_hdr = transport_start as *mut UdpHdr;
                        let old_port_be = unsafe { (*udp_hdr).src_port };
                        let new_port_be = u16::to_be(orig_port);
                        unsafe { (*udp_hdr).src_port = new_port_be };
                        let old_check = unsafe { (*udp_hdr).check };
                        if old_check != 0 {
                            let new_check = csum_replace2(
                                u16::from_be(old_check),
                                u16::from_be(old_port_be),
                                orig_port,
                            );
                            unsafe { (*udp_hdr).check = u16::to_be(new_check) };
                        }
                        src_port = orig_port;
                    }
                }
            } else {
                // NAT_TABLE entry evicted (LRU pressure) — we no longer know
                // the original dst_port the attacker was targeting. Passing
                // this packet through would expose the tarpit port in the
                // TCP source, instantly revealing the honeypot. Drop instead;
                // the attacker sees a stalled connection (acceptable for a
                // tarpit session that was going to time out anyway).
                return Ok(TC_ACT_SHOT);
            }
        }
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
