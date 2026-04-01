mod ai;
#[allow(dead_code)]
mod antifingerprint;
mod behavior;
mod config;
#[allow(dead_code)]
mod distributed;
mod dpi;
mod events;
mod feeds;
mod firewall;
mod ja4;
mod metrics;
mod pcap;
mod rules;

use anyhow::{Context, Result};
use aya::maps::{HashMap, LpmTrie, PerCpuArray, ProgramArray, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::Ebpf;
use common::{Counters, DpiEvent, DpiProtocol, EgressEvent, PacketEvent, RuleKey, RuleValue,
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

    // --- Shared event queues ---
    let event_queue: Arc<SegQueue<PacketEvent>> = Arc::new(SegQueue::new());
    let tls_queue: Arc<SegQueue<TlsComponentsEvent>> = Arc::new(SegQueue::new());
    let egress_queue: Arc<SegQueue<EgressEvent>> = Arc::new(SegQueue::new());
    let dpi_queue: Arc<SegQueue<DpiEvent>> = Arc::new(SegQueue::new());

    // --- Rule manager ---
    let mut rule_manager = rules::RuleManager::new(blocklist, cidr_rules);

    // Load static rules from config
    for ip_str in &cfg.rules.blocklist {
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
    for ip_str in &cfg.rules.allowlist {
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

    // --- Firewall manager (iptables DNAT) ---
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

    // --- Run concurrent tasks ---
    let eq = event_queue.clone();
    let tq = tls_queue.clone();
    let egq = egress_queue.clone();
    let dq = dpi_queue.clone();
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
    let mut flush_interval =
        tokio::time::interval(std::time::Duration::from_secs(BATCH_WINDOW_SECS));
    let mut expiry_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut feed_interval =
        tokio::time::interval(std::time::Duration::from_secs(feed_refresh_secs));
    // Fetch feeds immediately on startup, then every refresh_interval
    let mut feed_first_tick = true;
    let mut profiles: StdHashMap<u32, BehaviorProfile> = StdHashMap::new();
    let ja4_db = Ja4Database::with_defaults();

    loop {
        // Drain all queued events
        let mut drained = false;
        while let Some(event) = queue.pop() {
            drained = true;

            // --- Behavioral engine: update per-IP profile ---
            let profile = profiles
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
                    // Actionable phases trigger immediate response
                    if to.is_actionable() {
                        handle_behavioral_action(
                            *to,
                            event.src_ip,
                            rule_manager,
                            firewall_mgr,
                        );
                        // Flag for PCAP capture on actionable escalation
                        if let Some(ref pcap) = pcap_writer {
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

            // --- Existing batch → AI pipeline ---
            if let Some(batch) = batcher.push(event) {
                let src_ip = batch[0].src_ip;
                if ai_enabled {
                    let verdict = classifier.classify(&batch).await;
                    handle_verdict(verdict, src_ip, rule_manager, firewall_mgr);
                }
            }
        }

        // --- Drain TLS events → JA4 fingerprint assembly ---
        while let Some(tls_event) = tls_queue.pop() {
            drained = true;
            let ip_addr = common::util::ip_from_u32(tls_event.src_ip);
            let fingerprint = Ja4Assembler::assemble(&tls_event);
            let ja4_match = ja4_db.lookup(&fingerprint.fingerprint);

            match &ja4_match {
                ja4::db::Ja4Match::Malicious { name, confidence } => {
                    tracing::warn!(
                        %ip_addr,
                        ja4 = %fingerprint.fingerprint,
                        tool = %name,
                        confidence,
                        "JA4 malicious tool detected"
                    );
                    // Block known malicious TLS clients
                    if let Err(e) = rule_manager.block_ip(tls_event.src_ip, MALICIOUS_BLOCK_SECS) {
                        tracing::error!(%ip_addr, "failed to block JA4 match: {}", e);
                    }
                    if let Err(e) = firewall_mgr.redirect_to_tarpit(ip_addr) {
                        tracing::error!(%ip_addr, "failed to redirect JA4 match: {}", e);
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

        // --- Drain egress events → outbound traffic analysis ---
        while let Some(egress) = egress_queue.pop() {
            drained = true;
            let dst_addr = common::util::ip_from_u32(egress.dst_ip);

            // Log DNS queries with long names (potential tunneling)
            if egress.dns_query_len > DNS_TUNNEL_QUERY_LEN_THRESHOLD {
                tracing::warn!(
                    %dst_addr,
                    dns_query_len = egress.dns_query_len,
                    entropy = egress.entropy_score,
                    "DNS tunneling suspected — query length exceeds {} bytes",
                    DNS_TUNNEL_QUERY_LEN_THRESHOLD,
                );
            }

            // Log high-entropy outbound traffic (potential data exfiltration)
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

        // --- Drain DPI events → protocol-level deep inspection results ---
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
                // Feed DPI detections into behavioral engine
                let profile = profiles
                    .entry(dpi_event.src_ip)
                    .or_insert_with(BehaviorProfile::new);
                profile.suspicion_score = (profile.suspicion_score + 15.0).min(100.0);
            } else {
                tracing::trace!(
                    %src_addr,
                    protocol = proto_name,
                    payload_len = dpi_event.payload_len,
                    "DPI protocol identified"
                );
            }
        }

        // Periodically flush time-expired batches and expire stale rules
        tokio::select! {
            _ = flush_interval.tick() => {
                let expired = batcher.flush_expired();
                for (ip, batch) in expired {
                    if ai_enabled {
                        let verdict = classifier.classify(&batch).await;
                        handle_verdict(verdict, ip, rule_manager, firewall_mgr);
                    }
                }
            }
            _ = expiry_interval.tick() => {
                match rule_manager.expire_stale_rules() {
                    Ok(n) if n > 0 => tracing::info!(count = n, "expired stale rules"),
                    Err(e) => tracing::warn!("rule expiry error: {}", e),
                    _ => {}
                }
                // Prune stale profiles (no packets for 10 minutes)
                let before = profiles.len();
                profiles.retain(|_, p| p.age().as_secs() < 600);
                let pruned = before - profiles.len();
                if pruned > 0 {
                    tracing::debug!(count = pruned, "pruned stale behavior profiles");
                }
            }
            _ = feed_interval.tick(), if feeds_enabled => {
                if feed_first_tick {
                    feed_first_tick = false;
                    tracing::info!(
                        sources = feed_sources.len(),
                        "initial threat feed fetch"
                    );
                }
                let ips = feeds::fetch_all_feeds(feed_sources).await;
                let mut added = 0usize;
                for (ip, duration) in &ips {
                    let raw = common::util::ip_to_u32(*ip);
                    if rule_manager.block_ip(raw, *duration).is_ok() {
                        added += 1;
                    }
                }
                if !ips.is_empty() {
                    tracing::info!(
                        total = ips.len(),
                        added,
                        "threat feed refresh complete"
                    );
                }
            }
            _ = tokio::task::yield_now(), if !drained => {}
        }
    }
}

/// Act on a classification verdict.
fn handle_verdict(
    verdict: ThreatVerdict,
    src_ip: u32,
    rule_manager: &mut rules::RuleManager,
    firewall_mgr: &mut firewall::FirewallManager,
) {
    let ip_addr = common::util::ip_from_u32(src_ip);

    match verdict {
        ThreatVerdict::Malicious {
            ref category,
            confidence,
        } => {
            tracing::warn!(
                %ip_addr,
                ?category,
                confidence,
                "MALICIOUS — blocking IP and adding iptables redirect"
            );
            // Block in eBPF map
            if let Err(e) = rule_manager.block_ip(src_ip, MALICIOUS_BLOCK_SECS) {
                tracing::error!(%ip_addr, "failed to block: {}", e);
            }
            // Redirect to tarpit via iptables
            if let Err(e) = firewall_mgr.redirect_to_tarpit(ip_addr) {
                tracing::error!(%ip_addr, "failed to redirect to tarpit: {}", e);
            }
        }
        ThreatVerdict::Suspicious {
            ref reason,
            confidence,
        } => {
            tracing::info!(
                %ip_addr,
                reason,
                confidence,
                "SUSPICIOUS — redirecting to tarpit"
            );
            // Redirect to tarpit but don't hard-block in eBPF
            if let Err(e) = rule_manager.redirect_to_tarpit(src_ip, SUSPICIOUS_REDIRECT_SECS) {
                tracing::error!(%ip_addr, "failed to set tarpit redirect: {}", e);
            }
            if let Err(e) = firewall_mgr.redirect_to_tarpit(ip_addr) {
                tracing::error!(%ip_addr, "failed to redirect to tarpit: {}", e);
            }
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
    firewall_mgr: &mut firewall::FirewallManager,
) {
    let ip_addr = common::util::ip_from_u32(src_ip);
    match phase {
        BehaviorPhase::EstablishedC2 => {
            // Hard block C2 communication
            tracing::warn!(%ip_addr, "behavioral C2 detected — blocking");
            if let Err(e) = rule_manager.block_ip(src_ip, MALICIOUS_BLOCK_SECS) {
                tracing::error!(%ip_addr, "failed to block C2: {}", e);
            }
            if let Err(e) = firewall_mgr.redirect_to_tarpit(ip_addr) {
                tracing::error!(%ip_addr, "failed to redirect C2 to tarpit: {}", e);
            }
        }
        BehaviorPhase::Exploiting => {
            // Block exploit attempts
            tracing::warn!(%ip_addr, "behavioral exploit detected — blocking");
            if let Err(e) = rule_manager.block_ip(src_ip, MALICIOUS_BLOCK_SECS) {
                tracing::error!(%ip_addr, "failed to block exploit: {}", e);
            }
            if let Err(e) = firewall_mgr.redirect_to_tarpit(ip_addr) {
                tracing::error!(%ip_addr, "failed to redirect exploit to tarpit: {}", e);
            }
        }
        BehaviorPhase::Scanning => {
            // Redirect scanners to tarpit (don't hard block — gather intel)
            tracing::info!(%ip_addr, "behavioral scan detected — redirecting to tarpit");
            if let Err(e) = rule_manager.redirect_to_tarpit(src_ip, SUSPICIOUS_REDIRECT_SECS) {
                tracing::error!(%ip_addr, "failed to tarpit scanner: {}", e);
            }
            if let Err(e) = firewall_mgr.redirect_to_tarpit(ip_addr) {
                tracing::error!(%ip_addr, "failed to redirect scanner to tarpit: {}", e);
            }
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
