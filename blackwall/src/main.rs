mod ai;
#[allow(dead_code)]
mod antifingerprint;
mod behavior;
mod config;
mod distributed;
mod dpi;
mod events;
mod feeds;
#[cfg(feature = "iptables-legacy")]
mod firewall;
#[cfg(not(feature = "iptables-legacy"))]
mod firewall {
    //! No-op stub when iptables-legacy feature is disabled (V2.0 eBPF DNAT).
    use anyhow::Result;
    use std::net::Ipv4Addr;

    #[allow(deprecated, dead_code)]
    pub struct FirewallManager;

    #[allow(deprecated, dead_code)]
    impl FirewallManager {
        pub fn new(_tarpit_port: u16) -> Self { Self }
        pub fn redirect_to_tarpit(&mut self, _ip: Ipv4Addr) -> Result<()> { Ok(()) }
        pub fn flush_pending(&mut self) -> Result<()> { Ok(()) }
        pub fn cleanup_all(&mut self) -> Result<()> { Ok(()) }
    }
}
mod ja4;
mod metrics;
mod pcap;
mod rules;

use anyhow::{Context, Result};
use aya::maps::{HashMap, LpmTrie, PerCpuArray, ProgramArray, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use common::{Counters, DpiEvent, DpiProtocol, EgressEvent, NatKey, NatValue,
    PacketEvent, RuleKey, RuleValue, TarpitTarget,
    TlsComponentsEvent, DNS_TUNNEL_QUERY_LEN_THRESHOLD, DPI_PROG_DNS, DPI_PROG_HTTP,
    DPI_PROG_SSH, ENTROPY_ANOMALY_THRESHOLD};
use crossbeam_queue::SegQueue;
use std::collections::HashMap as StdHashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use ai::batch::EventBatcher;
use ai::classifier::{ThreatClassifier, ThreatVerdict};
use ai::client::OllamaClient;
use behavior::{BehaviorPhase, BehaviorProfile, TransitionVerdict, evaluate_transitions};
use feeds::FeedSource;
use ja4::assembler::Ja4Assembler;
use ja4::db::Ja4Database;

/// Default block duration for malicious IPs (10 minutes).
const MALICIOUS_BLOCK_SECS: u32 = 600;
/// Default tarpit redirect duration for suspicious IPs (5 minutes).
const SUSPICIOUS_REDIRECT_SECS: u32 = 300;
/// How many events to batch per source IP before classification.
const BATCH_SIZE: usize = 20;
/// Time window (seconds) before flushing an incomplete batch.
const BATCH_WINDOW_SECS: u64 = 10;
/// Interval between Ollama health checks (seconds).
const HEALTH_CHECK_INTERVAL_SECS: u64 = 60;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("blackwall=info")),
        )
        .init();

    tracing::info!("Blackwall daemon starting");

    // --- Load configuration ---
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = config::load_config(&PathBuf::from(&config_path)).unwrap_or_else(|e| {
        tracing::warn!("config load failed ({}), using defaults", e);
        toml::from_str("").expect("default config")
    });

    let iface = cfg.network.interface.clone();
    tracing::info!(interface = %iface, "attaching XDP program");

    // --- Load eBPF ---
    let ebpf_path = std::env::var("BLACKWALL_EBPF_PATH")
        .unwrap_or_else(|_| "blackwall-ebpf/target/bpfel-unknown-none/release/blackwall-ebpf".into());
    let mut ebpf = Ebpf::load_file(&ebpf_path)
        .with_context(|| format!("failed to load eBPF from {}", ebpf_path))?;

    // --- Attach XDP ---
    let program: &mut Xdp = ebpf
        .program_mut("blackwall_xdp")
        .context("XDP program not found")?
        .try_into()?;
    program.load()?;
    let xdp_flags = match cfg.network.xdp_mode.as_str() {
        "native" => XdpFlags::default(),
        "offload" => XdpFlags::HW_MODE,
        _ => XdpFlags::SKB_MODE, // "generic" or unknown — safest for WSL2/virtual NICs
    };
    program.attach(&iface, xdp_flags)?;
    tracing::info!(xdp_mode = %cfg.network.xdp_mode, "XDP program attached");

    // --- Attach TC egress (optional — requires clsact qdisc) ---
    let tc_attached = {
        let mut attached = false;
        if let Some(prog) = ebpf.program_mut("blackwall_egress") {
            let tc_result: Result<&mut SchedClassifier, _> = prog.try_into();
            if let Ok(tc) = tc_result {
                match tc.load() {
                    Ok(()) => match tc.attach(&iface, TcAttachType::Egress) {
                        Ok(_) => {
                            tracing::info!("TC egress classifier attached");
                            attached = true;
                        }
                        Err(e) => tracing::warn!("TC egress attach failed: {} — disabled", e),
                    },
                    Err(e) => tracing::warn!("TC egress load failed: {} — disabled", e),
                }
            } else {
                tracing::warn!("TC egress program type mismatch — disabled");
            }
        } else {
            tracing::warn!("TC egress program not found — disabled");
        }
        attached
    };

    // --- Open maps ---
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;
    let blocklist: HashMap<_, RuleKey, RuleValue> = HashMap::try_from(
        ebpf.take_map("BLOCKLIST")
            .context("BLOCKLIST map not found")?,
    )?;
    let cidr_rules: LpmTrie<_, u32, RuleValue> = LpmTrie::try_from(
        ebpf.take_map("CIDR_RULES")
            .context("CIDR_RULES map not found")?,
    )?;
    let counters: PerCpuArray<_, Counters> = PerCpuArray::try_from(
        ebpf.take_map("COUNTERS")
            .context("COUNTERS map not found")?,
    )?;

    // --- Open TLS_EVENTS map (optional — may not exist in older eBPF builds) ---
    let tls_ring_buf = ebpf
        .take_map("TLS_EVENTS")
        .and_then(|m| RingBuf::try_from(m).ok());
    let tls_enabled = tls_ring_buf.is_some();
    if tls_enabled {
        tracing::info!("TLS_EVENTS map found — JA4 fingerprinting enabled");
    } else {
        tracing::warn!("TLS_EVENTS map not found — JA4 fingerprinting disabled");
    }

    // --- Open EGRESS_EVENTS map (conditional on TC attachment) ---
    let egress_ring_buf = if tc_attached {
        ebpf.take_map("EGRESS_EVENTS")
            .and_then(|m| RingBuf::try_from(m).ok())
    } else {
        None
    };
    if egress_ring_buf.is_some() {
        tracing::info!("EGRESS_EVENTS map found — egress monitoring enabled");
    }

    // --- Open DPI_EVENTS map (optional — requires DPI tail call programs) ---
    let dpi_ring_buf = ebpf
        .take_map("DPI_EVENTS")
        .and_then(|m| RingBuf::try_from(m).ok());
    if dpi_ring_buf.is_some() {
        tracing::info!("DPI_EVENTS map found — DPI inspection enabled");
    }

    // --- Load DPI tail call programs into DPI_PROGS ProgramArray (optional) ---
    let _dpi_progs = {
        let map_opt = ebpf
            .take_map("DPI_PROGS")
            .and_then(|m| ProgramArray::try_from(m).ok());
        match map_opt {
            Some(mut progs) => {
                for (name, idx) in [
                    ("dpi_http", DPI_PROG_HTTP),
                    ("dpi_dns", DPI_PROG_DNS),
                    ("dpi_ssh", DPI_PROG_SSH),
                ] {
                    if let Some(prog) = ebpf.program_mut(name) {
                        let xdp_result: Result<&mut Xdp, _> = prog.try_into();
                        if let Ok(xdp) = xdp_result {
                            if let Err(e) = xdp.load() {
                                tracing::warn!(program = name, "DPI tail call load failed: {}", e);
                                continue;
                            }
                            match xdp.fd() {
                                Ok(fd) => {
                                    if let Err(e) = progs.set(idx, fd, 0) {
                                        tracing::warn!(program = name, "DPI PROG_ARRAY set failed: {}", e);
                                    } else {
                                        tracing::info!(program = name, index = idx, "DPI tail call loaded");
                                    }
                                }
                                Err(e) => tracing::warn!(program = name, "DPI fd error: {}", e),
                            }
                        }
                    } else {
                        tracing::warn!(program = name, "DPI program not found in ELF");
                    }
                }
                Some(progs)
            }
            None => {
                tracing::warn!("DPI_PROGS map not available — DPI tail calls disabled");
                None
            }
        }
    };

    // --- Populate TARPIT_TARGET eBPF map for native DNAT ---
    // ARCH: The tarpit port and local IP are pushed into a PerCpuArray
    // so XDP can rewrite packets in-kernel without iptables fork/exec.
    {
        let tarpit_target_map = ebpf.take_map("TARPIT_TARGET");
        if let Some(map_data) = tarpit_target_map {
            match PerCpuArray::<_, TarpitTarget>::try_from(map_data) {
                Ok(mut tarpit_map) => {
                    // Resolve local interface IP
                    let local_ip_raw = resolve_iface_ip(&iface);
                    let tarpit_cfg = TarpitTarget {
                        port: cfg.tarpit.port,
                        _pad: 0,
                        local_ip: local_ip_raw,
                        enabled: if cfg.tarpit.enabled { 1 } else { 0 },
                        _reserved: 0,
                    };
                    // PerCpuArray: set same value for all CPUs
                    let num_cpus = aya::util::nr_cpus()
                        .unwrap_or(1);
                    let values = aya::maps::PerCpuValues::try_from(
                        vec![tarpit_cfg; num_cpus],
                    ).expect("PerCpuValues from vec");
                    if let Err(e) = tarpit_map.set(0, values, 0) {
                        tracing::warn!("TARPIT_TARGET map set failed: {} — eBPF DNAT disabled", e);
                    } else {
                        tracing::info!(
                            port = cfg.tarpit.port,
                            local_ip = %Ipv4Addr::from(u32::from_be(local_ip_raw)),
                            "eBPF native DNAT enabled (replaces iptables)"
                        );
                    }
                }
                Err(e) => tracing::warn!("TARPIT_TARGET map open failed: {} — eBPF DNAT disabled", e),
            }
        } else {
            tracing::warn!("TARPIT_TARGET map not found — eBPF DNAT disabled, falling back to iptables");
        }
    }

    // --- Open NAT_TABLE map (read-only from userspace for monitoring) ---
    let _nat_table_map = ebpf.take_map("NAT_TABLE")
        .and_then(|m| HashMap::<_, NatKey, NatValue>::try_from(m).ok());
    if _nat_table_map.is_some() {
        tracing::info!("NAT_TABLE map opened — connection NAT tracking active");
    }

    // --- Shared event queues ---
    let event_queue: Arc<SegQueue<PacketEvent>> = Arc::new(SegQueue::new());
    let tls_queue: Arc<SegQueue<TlsComponentsEvent>> = Arc::new(SegQueue::new());
    let egress_queue: Arc<SegQueue<EgressEvent>> = Arc::new(SegQueue::new());
    let dpi_queue: Arc<SegQueue<DpiEvent>> = Arc::new(SegQueue::new());

    // --- Rule manager ---
    let mut rule_manager = rules::RuleManager::new(blocklist, cidr_rules);

    // Load static rules from config
    for ip_str in &cfg.rules.blocklist {
        if let Some((ip_part, prefix_str)) = ip_str.split_once('/') {
            if let (Ok(ip), Ok(prefix)) = (ip_part.parse::<Ipv4Addr>(), prefix_str.parse::<u32>()) {
                let raw = common::util::ip_to_u32(ip);
                if let Err(e) = rule_manager.add_cidr_rule(raw, prefix, common::RuleAction::Drop) {
                    tracing::warn!(rule = %ip_str, "failed to add CIDR block rule: {}", e);
                }
            } else {
                tracing::warn!(rule = %ip_str, "invalid blocklist CIDR");
            }
        } else {
            match ip_str.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    let raw = common::util::ip_to_u32(ip);
                    if let Err(e) = rule_manager.block_ip(raw, 0) {
                        tracing::warn!(%ip, "failed to add static block rule: {}", e);
                    }
                }
                Err(_) => tracing::warn!(rule = %ip_str, "invalid blocklist IP"),
            }
        }
    }
    for ip_str in &cfg.rules.allowlist {
        if let Some((ip_part, prefix_str)) = ip_str.split_once('/') {
            if let (Ok(ip), Ok(prefix)) = (ip_part.parse::<Ipv4Addr>(), prefix_str.parse::<u32>()) {
                let raw = common::util::ip_to_u32(ip);
                if let Err(e) = rule_manager.add_cidr_rule(raw, prefix, common::RuleAction::Pass) {
                    tracing::warn!(rule = %ip_str, "failed to add CIDR allow rule: {}", e);
                }
            } else {
                tracing::warn!(rule = %ip_str, "invalid allowlist CIDR");
            }
        } else {
            match ip_str.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    let raw = common::util::ip_to_u32(ip);
                    if let Err(e) = rule_manager.allow_ip(raw) {
                        tracing::warn!(%ip, "failed to add static allow rule: {}", e);
                    }
                }
                Err(_) => tracing::warn!(rule = %ip_str, "invalid allowlist IP"),
            }
        }
    }

    // --- Firewall manager (iptables DNAT — legacy fallback) ---
    #[allow(deprecated)]
    let mut firewall_mgr = firewall::FirewallManager::new(cfg.tarpit.port);

    // --- PCAP forensic capture (optional) ---
    let pcap_writer = if cfg.pcap.enabled {
        match pcap::PcapWriter::new(std::path::PathBuf::from(&cfg.pcap.output_dir)) {
            Ok(w) => {
                tracing::info!(dir = %cfg.pcap.output_dir, "PCAP capture enabled");
                Some(w)
            }
            Err(e) => {
                tracing::warn!("PCAP init failed: {} — capture disabled", e);
                None
            }
        }
    } else {
        None
    };

    // --- AI classification pipeline ---
    let ai_client = OllamaClient::new(
        cfg.ai.ollama_url.clone(),
        cfg.ai.model.clone(),
        cfg.ai.fallback_model.clone(),
        cfg.ai.timeout_ms,
    );
    let classifier = ThreatClassifier::new(ai_client);
    let mut batcher = EventBatcher::new(BATCH_SIZE, BATCH_WINDOW_SECS);
    let ai_enabled = cfg.ai.enabled;

    // Initial health check
    if ai_enabled {
        let healthy = classifier.client().health_check().await;
        tracing::info!(available = healthy, "Ollama health check");
    }

    // --- Build threat feed sources from config ---
    let feed_sources: Vec<FeedSource> = cfg.feeds.sources.iter().map(|s| FeedSource {
        name: s.name.clone(),
        url: s.url.clone(),
        block_duration_secs: s.block_duration_secs.unwrap_or(cfg.feeds.block_duration_secs),
    }).collect();
    let feeds_enabled = cfg.feeds.enabled;
    let feed_refresh_secs = cfg.feeds.refresh_interval_secs;

    // --- Distributed peer listener (optional) ---
    let peer_manager = if cfg.distributed.enabled {
        if cfg.distributed.peer_psk.is_empty() {
            anyhow::bail!(
                "distributed.peer_psk must be set when distributed mode is enabled \
                 (all peers must share the same pre-shared key)"
            );
        }
        let node_id = if cfg.distributed.node_id.is_empty() {
            "blackwall-node".to_string()
        } else {
            cfg.distributed.node_id.clone()
        };
        let mgr = std::sync::Arc::new(tokio::sync::Mutex::new(
            distributed::PeerManager::new(node_id, cfg.distributed.peer_psk.as_bytes()),
        ));
        for peer_addr in &cfg.distributed.peers {
            if let Ok(addr) = peer_addr.parse() {
                mgr.lock().await.add_peer(addr);
            }
        }
        Some(mgr)
    } else {
        None
    };

    // --- Run concurrent tasks ---
    let eq = event_queue.clone();
    let tq = tls_queue.clone();
    let egq = egress_queue.clone();
    let dq = dpi_queue.clone();
    let peer_mgr_clone = peer_manager.clone();
    let peer_bind_port = cfg.distributed.bind_port;
    let distributed_enabled = cfg.distributed.enabled;
    tokio::select! {
        r = events::consume_events(ring_buf, eq) => {
            tracing::error!("RingBuf consumer exited: {:?}", r);
        }
        r = consume_tls_task(tls_ring_buf, tq) => {
            tracing::error!("TLS consumer exited: {:?}", r);
        }
        r = consume_egress_task(egress_ring_buf, egq) => {
            tracing::error!("Egress consumer exited: {:?}", r);
        }
        r = consume_dpi_task(dpi_ring_buf, dq) => {
            tracing::error!("DPI consumer exited: {:?}", r);
        }
        r = process_events(
            event_queue.clone(),
            tls_queue.clone(),
            egress_queue.clone(),
            dpi_queue.clone(),
            &mut batcher,
            &classifier,
            &mut rule_manager,
            &mut firewall_mgr,
            ai_enabled,
            &feed_sources,
            feeds_enabled,
            feed_refresh_secs,
            &pcap_writer,
        ) => {
            tracing::error!("Event processor exited: {:?}", r);
        }
        r = metrics::metrics_tick(counters, 10) => {
            tracing::error!("Metrics ticker exited: {:?}", r);
        }
        r = health_check_loop(&classifier, ai_enabled) => {
            tracing::error!("Health check loop exited: {:?}", r);
        }
        r = async {
            if distributed_enabled {
                let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], peer_bind_port));
                distributed::peer::listen_for_peers(bind_addr, peer_mgr_clone.unwrap()).await
            } else {
                // Park forever if distributed mode is disabled
                std::future::pending::<anyhow::Result<()>>().await
            }
        } => {
            tracing::error!("Peer listener exited: {:?}", r);
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }

    // --- Graceful shutdown ---
    firewall_mgr.cleanup_all()?;
    tracing::info!("Blackwall daemon stopped");
    Ok(())
}

/// TLS RingBuf consumer task (conditional — only runs if TLS_EVENTS map exists).
async fn consume_tls_task(
    tls_ring_buf: Option<RingBuf<aya::maps::MapData>>,
    tls_tx: Arc<SegQueue<TlsComponentsEvent>>,
) -> Result<()> {
    match tls_ring_buf {
        Some(rb) => events::consume_tls_events(rb, tls_tx).await,
        None => {
            // No TLS map — park forever
            std::future::pending::<()>().await;
            Ok(())
        }
    }
}

/// Egress RingBuf consumer task (conditional — only runs if EGRESS_EVENTS map exists).
async fn consume_egress_task(
    egress_ring_buf: Option<RingBuf<aya::maps::MapData>>,
    egress_tx: Arc<SegQueue<EgressEvent>>,
) -> Result<()> {
    match egress_ring_buf {
        Some(rb) => events::consume_egress_events(rb, egress_tx).await,
        None => {
            std::future::pending::<()>().await;
            Ok(())
        }
    }
}

/// DPI RingBuf consumer task (conditional — only runs if DPI_EVENTS map exists).
async fn consume_dpi_task(
    dpi_ring_buf: Option<RingBuf<aya::maps::MapData>>,
    dpi_tx: Arc<SegQueue<DpiEvent>>,
) -> Result<()> {
    match dpi_ring_buf {
        Some(rb) => events::consume_dpi_events(rb, dpi_tx).await,
        None => {
            std::future::pending::<()>().await;
            Ok(())
        }
    }
}

/// Shared state for the event processing loop.
struct EventContext<'a> {
    batcher: &'a mut EventBatcher,
    classifier: &'a ThreatClassifier,
    rule_manager: &'a mut rules::RuleManager,
    firewall_mgr: &'a mut firewall::FirewallManager,
    ai_enabled: bool,
    pcap_writer: &'a Option<pcap::PcapWriter>,
    profiles: StdHashMap<u32, BehaviorProfile>,
    ja4_db: Ja4Database,
}

impl<'a> EventContext<'a> {
    /// Drain packet events: behavioral profiling → batch → AI classification.
    async fn drain_packet_events(&mut self, queue: &SegQueue<PacketEvent>) -> bool {
        let mut drained = false;
        while let Some(event) = queue.pop() {
            drained = true;

            // PERF: Skip re-classification for IPs already blocked/redirected.
            // This prevents a feedback loop where DNAT'd packets emit events
            // that get re-classified and re-apply the DNAT rule, resetting expiry.
            if self.rule_manager.is_blocked_or_redirected(event.src_ip) {
                tracing::trace!(
                    ip = %common::util::ip_from_u32(event.src_ip),
                    "skipping event from blocked/redirected IP"
                );
                continue;
            }

            let profile = self.profiles
                .entry(event.src_ip)
                .or_insert_with(BehaviorProfile::new);
            profile.update(&event);

            let transition = evaluate_transitions(profile);
            match &transition {
                TransitionVerdict::Escalate { from, to, reason } => {
                    let ip_addr = common::util::ip_from_u32(event.src_ip);
                    tracing::warn!(
                        %ip_addr,
                        from = ?from,
                        to = ?to,
                        suspicion = profile.suspicion_score,
                        reason,
                        "behavioral escalation"
                    );
                    if to.is_actionable() {
                        handle_behavioral_action(
                            *to,
                            event.src_ip,
                            self.rule_manager,
                            self.firewall_mgr,
                        );
                        if let Some(ref pcap) = self.pcap_writer {
                            pcap.flag_ip(common::util::ip_from_u32(event.src_ip));
                        }
                    }
                }
                TransitionVerdict::Promote { from, to } => {
                    let ip_addr = common::util::ip_from_u32(event.src_ip);
                    tracing::debug!(%ip_addr, from = ?from, to = ?to, "behavioral promotion");
                }
                TransitionVerdict::Hold => {}
            }

            if let Some(batch) = self.batcher.push(event) {
                let src_ip = batch[0].src_ip;
                if self.ai_enabled {
                    let verdict = self.classifier.classify(&batch).await;
                    handle_verdict(verdict, src_ip, self.rule_manager, self.firewall_mgr);
                    // Discard any remaining partial batch for this IP after blocking
                    if self.rule_manager.is_blocked_or_redirected(src_ip) {
                        self.batcher.discard_ip(src_ip);
                    }
                }
            }
        }
        drained
    }

    /// Drain TLS events: JA4 fingerprint assembly and malicious client detection.
    fn drain_tls_events(&mut self, tls_queue: &SegQueue<TlsComponentsEvent>) -> bool {
        let mut drained = false;
        while let Some(tls_event) = tls_queue.pop() {
            drained = true;
            let ip_addr = common::util::ip_from_u32(tls_event.src_ip);
            let fingerprint = Ja4Assembler::assemble(&tls_event);
            let ja4_match = self.ja4_db.lookup(&fingerprint.fingerprint);

            match &ja4_match {
                ja4::db::Ja4Match::Malicious { name, confidence } => {
                    tracing::warn!(
                        %ip_addr,
                        ja4 = %fingerprint.fingerprint,
                        tool = %name,
                        confidence,
                        "JA4 malicious tool detected"
                    );
                    if let Err(e) = self.rule_manager.block_ip(tls_event.src_ip, MALICIOUS_BLOCK_SECS) {
                        tracing::error!(%ip_addr, "failed to block JA4 match: {}", e);
                    }
                }
                ja4::db::Ja4Match::Benign { name } => {
                    tracing::debug!(
                        %ip_addr,
                        ja4 = %fingerprint.fingerprint,
                        tool = %name,
                        "JA4 benign client identified"
                    );
                }
                ja4::db::Ja4Match::Unknown => {
                    tracing::trace!(
                        %ip_addr,
                        ja4 = %fingerprint.fingerprint,
                        "JA4 fingerprint (unknown)"
                    );
                }
            }
        }
        drained
    }

    /// Drain egress events: DNS tunneling and data exfiltration detection.
    fn drain_egress_events(&self, egress_queue: &SegQueue<EgressEvent>) -> bool {
        let mut drained = false;
        while let Some(egress) = egress_queue.pop() {
            drained = true;
            let dst_addr = common::util::ip_from_u32(egress.dst_ip);

            if egress.dns_query_len > DNS_TUNNEL_QUERY_LEN_THRESHOLD {
                tracing::warn!(
                    %dst_addr,
                    dns_query_len = egress.dns_query_len,
                    entropy = egress.entropy_score,
                    "DNS tunneling suspected — query length exceeds {} bytes",
                    DNS_TUNNEL_QUERY_LEN_THRESHOLD,
                );
            }

            if egress.entropy_score > ENTROPY_ANOMALY_THRESHOLD as u16 {
                tracing::warn!(
                    %dst_addr,
                    port = egress.dst_port,
                    entropy = egress.entropy_score,
                    payload_len = egress.payload_len,
                    "high-entropy outbound traffic — possible exfiltration"
                );
            }
        }
        drained
    }

    /// Drain DPI events: protocol-level deep inspection results.
    fn drain_dpi_events(&mut self, dpi_queue: &SegQueue<DpiEvent>) -> bool {
        let mut drained = false;
        while let Some(dpi_event) = dpi_queue.pop() {
            drained = true;
            let src_addr = common::util::ip_from_u32(dpi_event.src_ip);
            let proto_name = match DpiProtocol::from_u8(dpi_event.protocol) {
                DpiProtocol::Http => "HTTP",
                DpiProtocol::Dns => "DNS",
                DpiProtocol::Ssh => "SSH",
                DpiProtocol::Tls => "TLS",
                DpiProtocol::Unknown => "unknown",
            };

            if dpi_event.flags != 0 {
                tracing::warn!(
                    %src_addr,
                    protocol = proto_name,
                    flags = dpi_event.flags,
                    payload_len = dpi_event.payload_len,
                    "DPI suspicious activity detected"
                );
                let profile = self.profiles
                    .entry(dpi_event.src_ip)
                    .or_insert_with(BehaviorProfile::new);
                profile.suspicion_score = (profile.suspicion_score + 0.15).min(1.0);
            } else {
                tracing::trace!(
                    %src_addr,
                    protocol = proto_name,
                    payload_len = dpi_event.payload_len,
                    "DPI protocol identified"
                );
            }
        }
        drained
    }

    /// Flush expired batches and pending DNAT redirects.
    async fn flush_batches(&mut self) {
        let expired = self.batcher.flush_expired();
        for (ip, batch) in expired {
            // Skip re-classification for IPs already blocked/redirected.
            if self.rule_manager.is_blocked_or_redirected(ip) {
                tracing::debug!(
                    ip = %common::util::ip_from_u32(ip),
                    batch_size = batch.len(),
                    "flush_batches: skipping stale batch for already-blocked IP"
                );
                continue;
            }
            if self.ai_enabled {
                let verdict = self.classifier.classify(&batch).await;
                handle_verdict(verdict, ip, self.rule_manager, self.firewall_mgr);
            }
        }
        if let Err(e) = self.firewall_mgr.flush_pending() {
            tracing::warn!("pending DNAT flush failed: {}", e);
        }
    }

    /// Expire stale rules and prune idle behavior profiles.
    fn expire_stale(&mut self) {
        match self.rule_manager.expire_stale_rules() {
            Ok(ref expired) if !expired.is_empty() => {
                tracing::info!(count = expired.len(), "expired stale rules");
                // Purge behavioral profiles for expired IPs to prevent
                // immediate re-classification on next packet.
                for ip in expired {
                    self.profiles.remove(ip);
                }
            }
            Err(e) => tracing::warn!("rule expiry error: {}", e),
            _ => {}
        }
        let before = self.profiles.len();
        self.profiles.retain(|_, p| p.age().as_secs() < 600);
        let pruned = before - self.profiles.len();
        if pruned > 0 {
            tracing::debug!(count = pruned, "pruned stale behavior profiles");
        }
    }
}

/// Main event processing loop: drain queue → update profiles → batch → classify → act.
#[allow(clippy::too_many_arguments)]
async fn process_events(
    queue: Arc<SegQueue<PacketEvent>>,
    tls_queue: Arc<SegQueue<TlsComponentsEvent>>,
    egress_queue: Arc<SegQueue<EgressEvent>>,
    dpi_queue: Arc<SegQueue<DpiEvent>>,
    batcher: &mut EventBatcher,
    classifier: &ThreatClassifier,
    rule_manager: &mut rules::RuleManager,
    firewall_mgr: &mut firewall::FirewallManager,
    ai_enabled: bool,
    feed_sources: &[FeedSource],
    feeds_enabled: bool,
    feed_refresh_secs: u64,
    pcap_writer: &Option<pcap::PcapWriter>,
) -> Result<()> {
    let mut ctx = EventContext {
        batcher,
        classifier,
        rule_manager,
        firewall_mgr,
        ai_enabled,
        pcap_writer,
        profiles: StdHashMap::new(),
        ja4_db: Ja4Database::with_defaults(),
    };

    let mut flush_interval =
        tokio::time::interval(std::time::Duration::from_secs(BATCH_WINDOW_SECS));
    let mut expiry_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut feed_interval =
        tokio::time::interval(std::time::Duration::from_secs(feed_refresh_secs));
    let mut feed_first_tick = true;
    let mut hivemind_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        let mut drained = false;
        drained |= ctx.drain_packet_events(&queue).await;
        drained |= ctx.drain_tls_events(&tls_queue);
        drained |= ctx.drain_egress_events(&egress_queue);
        drained |= ctx.drain_dpi_events(&dpi_queue);

        tokio::select! {
            _ = flush_interval.tick() => {
                ctx.flush_batches().await;
            }
            _ = expiry_interval.tick() => {
                ctx.expire_stale();
            }
            _ = feed_interval.tick(), if feeds_enabled => {
                if feed_first_tick {
                    feed_first_tick = false;
                    tracing::info!(
                        sources = feed_sources.len(),
                        "initial threat feed fetch"
                    );
                }
                let entries = feeds::fetch_all_feeds(feed_sources).await;
                // Clear stale CIDR rules before re-adding from fresh feeds
                if let Err(e) = ctx.rule_manager.clear_cidr_rules() {
                    tracing::warn!("failed to clear CIDR rules before refresh: {}", e);
                }
                let mut added = 0usize;
                for (entry, duration) in &entries {
                    match entry {
                        feeds::FeedEntry::Single(ip) => {
                            let raw = common::util::ip_to_u32(*ip);
                            if ctx.rule_manager.block_ip(raw, *duration).is_ok() {
                                added += 1;
                            }
                        }
                        feeds::FeedEntry::Cidr(ip, prefix) => {
                            let raw = common::util::ip_to_u32(*ip);
                            if ctx.rule_manager.add_cidr_rule(
                                raw,
                                *prefix as u32,
                                common::RuleAction::Drop,
                            ).is_ok() {
                                added += 1;
                            }
                        }
                    }
                }
                if !entries.is_empty() {
                    tracing::info!(
                        total = entries.len(),
                        added,
                        "threat feed refresh complete"
                    );
                }
            }
            _ = hivemind_interval.tick() => {
                ingest_hivemind_iocs(ctx.rule_manager);
            }
            _ = tokio::task::yield_now(), if !drained => {}
        }
    }
}

/// Publish an IoC to the local HiveMind daemon via TCP injection endpoint.
///
/// Non-blocking: spawned as a background task so the main event loop is never
/// stalled by hivemind connectivity issues.
fn publish_ioc_to_hivemind(ip: u32, severity: u8, ioc_type: &str, description: &str) {
    let ioc = common::hivemind::IoC {
        ioc_type: match ioc_type {
            "behavioral" => 4,
            "entropy" => 2,
            _ => 0, // IP-based
        },
        severity,
        ip,
        ja4: None,
        entropy_score: None,
        description: description.to_string(),
        first_seen: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        confirmations: 0,
        zkp_proof: Vec::new(),
    };

    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let addr = format!("127.0.0.1:{}", common::hivemind::IOC_INJECT_PORT);
        let mut stream = match tokio::net::TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "hivemind IoC publish: connect failed (hivemind may be down)");
                return;
            }
        };
        let json = match serde_json::to_vec(&ioc) {
            Ok(j) => j,
            Err(e) => {
                tracing::debug!(error = %e, "hivemind IoC publish: serialize failed");
                return;
            }
        };
        let len = (json.len() as u32).to_be_bytes();
        if let Err(e) = stream.write_all(&len).await {
            tracing::debug!(error = %e, "hivemind IoC publish: write length failed");
            return;
        }
        if let Err(e) = stream.write_all(&json).await {
            tracing::debug!(error = %e, "hivemind IoC publish: write payload failed");
            return;
        }
        let ip_addr = common::util::ip_from_u32(ioc.ip);
        tracing::info!(%ip_addr, severity = ioc.severity, "published IoC to HiveMind mesh");
    });
}

/// Act on a classification verdict.
fn handle_verdict(
    verdict: ThreatVerdict,
    src_ip: u32,
    rule_manager: &mut rules::RuleManager,
    _firewall_mgr: &mut firewall::FirewallManager,
) {
    let ip_addr = common::util::ip_from_u32(src_ip);

    match verdict {
        ThreatVerdict::Malicious {
            ref category,
            confidence,
        } => {
            // Defense-in-depth: skip if already blocked
            if rule_manager.is_blocked_or_redirected(src_ip) {
                tracing::debug!(
                    %ip_addr,
                    ?category,
                    "handle_verdict: skipping re-block for already-blocked IP"
                );
                return;
            }
            tracing::warn!(
                %ip_addr,
                ?category,
                confidence,
                "MALICIOUS — blocking IP via eBPF"
            );
            // Block in eBPF map (action=DROP — packet never reaches userspace)
            if let Err(e) = rule_manager.block_ip(src_ip, MALICIOUS_BLOCK_SECS) {
                tracing::error!(%ip_addr, "failed to block: {}", e);
            }
            publish_ioc_to_hivemind(
                src_ip, 90, "ip",
                &format!("AI verdict: malicious ({:?}, confidence={})", category, confidence),
            );
        }
        ThreatVerdict::Suspicious {
            ref reason,
            confidence,
        } => {
            // Defense-in-depth: skip if already blocked/redirected
            if rule_manager.is_blocked_or_redirected(src_ip) {
                tracing::debug!(
                    %ip_addr,
                    reason,
                    "handle_verdict: skipping re-redirect for already-blocked IP"
                );
                return;
            }
            tracing::info!(
                %ip_addr,
                reason,
                confidence,
                "SUSPICIOUS — redirecting to tarpit via eBPF DNAT"
            );
            // Redirect to tarpit via eBPF DNAT (action=RedirectTarpit)
            if let Err(e) = rule_manager.redirect_to_tarpit(src_ip, SUSPICIOUS_REDIRECT_SECS) {
                tracing::error!(%ip_addr, "failed to set tarpit redirect: {}", e);
            }
            publish_ioc_to_hivemind(
                src_ip, 50, "ip",
                &format!("AI verdict: suspicious ({}, confidence={})", reason, confidence),
            );
        }
        ThreatVerdict::Benign => {
            tracing::debug!(%ip_addr, "BENIGN — no action");
        }
        ThreatVerdict::Unknown => {
            tracing::debug!(%ip_addr, "UNKNOWN — LLM unavailable, no action");
        }
    }
}

/// Act on a behavioral engine escalation to an actionable phase.
fn handle_behavioral_action(
    phase: BehaviorPhase,
    src_ip: u32,
    rule_manager: &mut rules::RuleManager,
    _firewall_mgr: &mut firewall::FirewallManager,
) {
    let ip_addr = common::util::ip_from_u32(src_ip);

    // Defense-in-depth: skip if already blocked/redirected
    if rule_manager.is_blocked_or_redirected(src_ip) {
        tracing::debug!(
            %ip_addr,
            ?phase,
            "handle_behavioral_action: skipping — IP already blocked/redirected"
        );
        return;
    }

    match phase {
        BehaviorPhase::EstablishedC2 => {
            // Hard block C2 communication via eBPF DROP
            tracing::warn!(%ip_addr, "behavioral C2 detected — blocking via eBPF");
            if let Err(e) = rule_manager.block_ip(src_ip, MALICIOUS_BLOCK_SECS) {
                tracing::error!(%ip_addr, "failed to block C2: {}", e);
            }
            publish_ioc_to_hivemind(
                src_ip, 95, "behavioral",
                "behavioral engine: C2 communication detected",
            );
        }
        BehaviorPhase::Exploiting => {
            // Block exploit attempts via eBPF DROP
            tracing::warn!(%ip_addr, "behavioral exploit detected — blocking via eBPF");
            if let Err(e) = rule_manager.block_ip(src_ip, MALICIOUS_BLOCK_SECS) {
                tracing::error!(%ip_addr, "failed to block exploit: {}", e);
            }
            publish_ioc_to_hivemind(
                src_ip, 95, "behavioral",
                "behavioral engine: exploit attempt detected",
            );
        }
        BehaviorPhase::Scanning => {
            // Redirect scanners to tarpit via eBPF DNAT (gather intel)
            tracing::info!(%ip_addr, "behavioral scan detected — redirecting to tarpit");
            if let Err(e) = rule_manager.redirect_to_tarpit(src_ip, SUSPICIOUS_REDIRECT_SECS) {
                tracing::error!(%ip_addr, "failed to tarpit scanner: {}", e);
            }
            publish_ioc_to_hivemind(
                src_ip, 60, "behavioral",
                "behavioral engine: port scanning detected",
            );
        }
        _ => {} // Non-actionable phases handled by Hold
    }
}

/// Periodically check Ollama availability.
async fn health_check_loop(classifier: &ThreatClassifier, enabled: bool) -> Result<()> {
    if !enabled {
        // AI disabled — park forever
        std::future::pending::<()>().await;
    }
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS));
    loop {
        interval.tick().await;
        let ok = classifier.client().health_check().await;
        tracing::debug!(available = ok, "Ollama health check");
    }
}

/// Resolve local IPv4 address of an interface by parsing /proc/net/if_inet6
/// or /sys/class/net. Fallback: 0.0.0.0 (means DNAT effectively disabled).
fn resolve_iface_ip(iface: &str) -> u32 {
    // Read from /proc/net/fib_trie or ip addr show
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output();
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Format: "2: eth2    inet 192.168.0.127/24 ..."
            for word in stdout.split_whitespace() {
                if let Some(ip_str) = word.split('/').next() {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        return common::util::ip_to_u32(ip);
                    }
                }
            }
            tracing::warn!(iface = %iface, "could not resolve interface IP — DNAT may not work");
            0
        }
        Err(e) => {
            tracing::warn!(iface = %iface, "ip addr command failed: {} — DNAT may not work", e);
            0
        }
    }
}

/// Default block duration for IoCs accepted via HiveMind P2P consensus (1 hour).
/// Used as fallback when the enriched JSON format lacks a duration field.
const HIVEMIND_BLOCK_DURATION_SECS: u32 = 3600;

/// Enriched IoC entry written by hivemind, read by blackwall.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct HivemindIocEntry {
    ip: u32,
    #[serde(default)]
    severity: u8,
    #[serde(default)]
    confirmations: u8,
    #[serde(default)]
    duration_secs: u32,
}

/// Ingest accepted IoC IPs from HiveMind's shared file and add them to the BLOCKLIST.
///
/// Uses atomic rename to avoid race conditions: renames the shared file to a
/// temporary path, reads from the temp copy, then removes it. HiveMind can
/// safely create + append to the original path even during ingestion.
///
/// On crash recovery: if a leftover `.processing` file exists from a previous
/// crashed cycle, it is ingested first before attempting a new rename.
///
/// Supports both enriched JSON Lines format (with severity/confidence/TTL)
/// and legacy raw u32 format for backward compatibility.
fn ingest_hivemind_iocs(rule_manager: &mut rules::RuleManager) {
    let path = std::path::Path::new("/run/blackwall/hivemind_accepted_iocs");
    let tmp_path = path.with_extension("processing");

    // Recovery: process leftover .processing file from a previous crash
    if tmp_path.exists() {
        if verify_ioc_file_permissions(&tmp_path) {
            ingest_ioc_file(&tmp_path, rule_manager);
        }
        let _ = std::fs::remove_file(&tmp_path);
    }

    // Atomic rename — if the file doesn't exist or another process raced us,
    // rename fails and we skip. No TOCTOU: we never check exists() first.
    if std::fs::rename(path, &tmp_path).is_err() {
        return;
    }

    if !verify_ioc_file_permissions(&tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return;
    }

    ingest_ioc_file(&tmp_path, rule_manager);
    let _ = std::fs::remove_file(&tmp_path);
}

/// Verify ownership and permissions of an IoC file before processing.
///
/// Rejects files that are:
/// - Not owned by root (uid 0)
/// - World-writable (mode & 0o002 != 0)
/// - Group-writable (mode & 0o020 != 0)
///
/// This prevents unprivileged processes from injecting block rules.
fn verify_ioc_file_permissions(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            let uid = meta.uid();
            let mode = meta.mode();
            if uid != 0 {
                tracing::warn!(
                    path = %path.display(), uid,
                    "IoC file not owned by root — refusing to ingest (possible injection)"
                );
                return false;
            }
            if mode & 0o022 != 0 {
                tracing::warn!(
                    path = %path.display(), mode = format!("{:o}", mode),
                    "IoC file is group/world-writable — refusing to ingest"
                );
                return false;
            }
            true
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(), error = %e,
                "cannot stat IoC file — refusing to ingest"
            );
            false
        }
    }
}

/// Read and process a single IoC file, adding entries to the rule manager.
fn ingest_ioc_file(file_path: &std::path::Path, rule_manager: &mut rules::RuleManager) {
    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(path = %file_path.display(), error = %e, "failed to read IoC file");
            return;
        }
    };
    if content.is_empty() {
        return;
    }
    let mut added = 0u32;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try enriched JSON format first, fall back to legacy raw u32
        let (ip, duration) = if trimmed.starts_with('{') {
            match serde_json::from_str::<HivemindIocEntry>(trimmed) {
                Ok(entry) => {
                    let dur = if entry.duration_secs > 0 {
                        entry.duration_secs
                    } else {
                        HIVEMIND_BLOCK_DURATION_SECS
                    };
                    (entry.ip, dur)
                }
                Err(e) => {
                    tracing::warn!(line = trimmed, error = %e, "malformed IoC JSON");
                    continue;
                }
            }
        } else if let Ok(ip) = trimmed.parse::<u32>() {
            // Legacy format: raw u32 IP with default duration
            (ip, HIVEMIND_BLOCK_DURATION_SECS)
        } else {
            continue;
        };

        // IoC IPs are stored in host-endian format (u32::from(Ipv4Addr)).
        // The BLOCKLIST map uses bpfel format (matching ip_to_u32 / XDP src_ip).
        // Convert with .to_be() to match what XDP reads from packet headers.
        let bpfel_ip = ip.to_be();
        if rule_manager.block_ip(bpfel_ip, duration).is_ok() {
            let ip_addr = common::util::ip_from_u32(bpfel_ip);
            tracing::info!(%ip_addr, duration, "blocked IP from HiveMind consensus");
            added += 1;
        }
    }
    if added > 0 {
        tracing::info!(count = added, "ingested HiveMind consensus IoCs");
    }
}
