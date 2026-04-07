/// HiveMind — P2P Threat Intelligence Mesh daemon.
///
/// Entry point for the HiveMind node. Builds the libp2p swarm,
/// subscribes to GossipSub topics, connects to bootstrap nodes,
/// and runs the event loop with consensus + reputation tracking.
use anyhow::Context;
use libp2p::{futures::StreamExt, swarm::SwarmEvent};
use std::path::PathBuf;
use tracing::{info, warn};

use hivemind::bootstrap;
use hivemind::config::{self, HiveMindConfig, NodeMode};
use hivemind::consensus::{ConsensusEngine, ConsensusResult};
use hivemind::crypto::fhe::FheContext;
use hivemind::dht;
use hivemind::gossip;
use hivemind::identity;
use hivemind::metrics_bridge::{self, SharedP2pMetrics, P2pMetrics};
use hivemind::ml::aggregator::FedAvgAggregator;
use hivemind::ml::defense::{GradientDefense, GradientVerdict};
use hivemind::ml::gradient_share;
use hivemind::ml::local_model::LocalModel;
use hivemind::reputation::ReputationStore;
use hivemind::sybil_guard::SybilGuard;
use hivemind::transport;
use hivemind::zkp;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt::init();

    let config = load_or_default_config()?;

    // --- Persistent identity ---
    let key_path = identity::resolve_key_path(config.identity_key_path.as_deref())
        .context("Cannot resolve identity key path")?;
    let keypair = identity::load_or_generate(&key_path)
        .context("Cannot load/generate identity keypair")?;

    let mut swarm = transport::build_swarm(&config, keypair)
        .context("Failed to build HiveMind swarm")?;

    let local_peer_id = *swarm.local_peer_id();
    info!(%local_peer_id, "HiveMind node starting");

    // Start listening
    transport::start_listening(&mut swarm, &config)?;

    // Subscribe to GossipSub topics
    gossip::subscribe_all(&mut swarm)?;

    // Configure topic scoring (anti-poisoning)
    gossip::configure_topic_scoring(&mut swarm);

    // Connect to bootstrap nodes
    let seed_peer_ids = bootstrap::connect_bootstrap_nodes(&mut swarm, &config, &local_peer_id)?;

    // --- P2P metrics bridge (pushes live stats to hivemind-api) ---
    let p2p_metrics: SharedP2pMetrics = std::sync::Arc::new(P2pMetrics::default());

    // Metrics push interval (5 seconds) — pushes P2P stats to hivemind-api
    let mut metrics_interval = tokio::time::interval(
        std::time::Duration::from_secs(5),
    );
    metrics_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!(mode = ?config.mode, "HiveMind event loop starting");

    match config.mode {
        NodeMode::Bootstrap => run_bootstrap_loop(&mut swarm, &p2p_metrics, metrics_interval).await,
        NodeMode::Full => run_full_loop(&mut swarm, &local_peer_id, &seed_peer_ids, &p2p_metrics, metrics_interval).await,
    }
}

/// Lightweight bootstrap event loop — only Kademlia routing + GossipSub
/// message forwarding + metrics push. No reputation, consensus, FL, or ZKP.
///
/// ARCH: Bootstrap nodes will also serve as Circuit Relay v2 destinations
/// once NAT traversal is implemented (AutoNAT + Relay).
async fn run_bootstrap_loop(
    swarm: &mut libp2p::Swarm<transport::HiveMindBehaviour>,
    p2p_metrics: &SharedP2pMetrics,
    mut metrics_interval: tokio::time::Interval,
) -> anyhow::Result<()> {
    info!("Running in BOOTSTRAP mode — relay only (no DPI/AI/FL)");

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_bootstrap_event(swarm, event, p2p_metrics);
            }
            _ = metrics_interval.tick() => {
                metrics_bridge::push_p2p_metrics(p2p_metrics).await;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT — shutting down bootstrap node");
                break;
            }
        }
    }

    info!("HiveMind bootstrap node shut down gracefully");
    Ok(())
}

/// Full event loop — all modules active.
async fn run_full_loop(
    swarm: &mut libp2p::Swarm<transport::HiveMindBehaviour>,
    local_peer_id: &libp2p::PeerId,
    seed_peer_ids: &[libp2p::PeerId],
    p2p_metrics: &SharedP2pMetrics,
    mut metrics_interval: tokio::time::Interval,
) -> anyhow::Result<()> {
    // --- Phase 1: Anti-Poisoning modules ---
    let mut reputation = ReputationStore::new();
    let mut consensus = ConsensusEngine::new();
    let sybil_guard = SybilGuard::new();

    // Register bootstrap nodes as seed peers with elevated stake so their
    // IoC reports are trusted immediately. Without this, INITIAL_STAKE < MIN_TRUSTED
    // means no peer can ever reach consensus.
    for peer_id in seed_peer_ids {
        let pubkey = peer_id_to_pubkey(peer_id);
        reputation.register_seed_peer(&pubkey);
    }
    // Also register self as seed peer — our own IoC submissions should count
    let local_pubkey_seed = peer_id_to_pubkey(local_peer_id);
    reputation.register_seed_peer(&local_pubkey_seed);

    info!(
        seed_peers = seed_peer_ids.len() + 1,
        "Phase 1 security modules initialized (reputation, consensus, sybil_guard)"
    );

    // --- Phase 2: Federated Learning modules ---
    let mut local_model = LocalModel::new(0.01);
    let fhe_ctx = FheContext::new();
    let mut aggregator = FedAvgAggregator::new();
    let mut gradient_defense = GradientDefense::new();

    // Extract local node pubkey for gradient messages
    let local_pubkey = peer_id_to_pubkey(local_peer_id);

    info!(
        model_params = local_model.param_count(),
        fhe_stub = fhe_ctx.is_stub(),
        "Phase 2 federated learning modules initialized"
    );

    // Periodic eviction interval (5 minutes)
    let mut eviction_interval = tokio::time::interval(
        std::time::Duration::from_secs(common::hivemind::CONSENSUS_TIMEOUT_SECS),
    );
    eviction_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Federated learning round interval (60 seconds)
    let mut fl_round_interval = tokio::time::interval(
        std::time::Duration::from_secs(common::hivemind::FL_ROUND_INTERVAL_SECS),
    );
    fl_round_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("Full-mode event loop starting");

    // --- Proof ingestion socket (enterprise module → hivemind) ---
    let proof_addr = format!("127.0.0.1:{}", common::hivemind::PROOF_INGEST_PORT);
    let proof_listener = tokio::net::TcpListener::bind(&proof_addr)
        .await
        .context("failed to bind proof ingestion listener")?;
    info!(addr = %proof_addr, "proof ingestion listener ready");

    // --- IoC injection socket (for testing/integration) ---
    let ioc_addr = format!("127.0.0.1:{}", common::hivemind::IOC_INJECT_PORT);
    let ioc_listener = tokio::net::TcpListener::bind(&ioc_addr)
        .await
        .context("failed to bind IoC injection listener")?;
    info!(addr = %ioc_addr, "IoC injection listener ready");

    // Main event loop
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    swarm,
                    event,
                    local_peer_id,
                    &mut reputation,
                    &mut consensus,
                    &fhe_ctx,
                    &mut aggregator,
                    &mut gradient_defense,
                    &mut local_model,
                    p2p_metrics,
                );
            }
            result = proof_listener.accept() => {
                if let Ok((stream, addr)) = result {
                    tracing::debug!(%addr, "proof ingestion connection");
                    ingest_proof_envelope(swarm, stream).await;
                }
            }
            result = ioc_listener.accept() => {
                if let Ok((stream, addr)) = result {
                    tracing::debug!(%addr, "IoC injection connection");
                    ingest_and_publish_ioc(
                        swarm,
                        stream,
                        &local_pubkey,
                        &mut reputation,
                        &mut consensus,
                    ).await;
                }
            }
            _ = eviction_interval.tick() => {
                consensus.evict_expired();
            }
            _ = fl_round_interval.tick() => {
                // Federated Learning round: compute and broadcast gradients
                handle_fl_round(
                    swarm,
                    &mut local_model,
                    &fhe_ctx,
                    &mut aggregator,
                    &local_pubkey,
                );
            }
            _ = metrics_interval.tick() => {
                metrics_bridge::push_p2p_metrics(p2p_metrics).await;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT — shutting down HiveMind");
                break;
            }
        }
    }

    // Log accepted IoCs before shutting down
    let final_accepted = consensus.drain_accepted();
    if !final_accepted.is_empty() {
        info!(
            count = final_accepted.len(),
            "Draining accepted IoCs at shutdown"
        );
    }
    // Suppress unused variable warnings until sybil_guard is wired
    // into the peer registration handshake protocol (Phase 2).
    let _ = &sybil_guard;

    info!("HiveMind shut down gracefully");
    Ok(())
}

/// Read a length-prefixed proof envelope from a TCP connection and
/// publish it to GossipSub.
///
/// Wire format: `[4-byte big-endian length][JSON payload]`.
async fn ingest_proof_envelope(
    swarm: &mut libp2p::Swarm<transport::HiveMindBehaviour>,
    mut stream: tokio::net::TcpStream,
) {
    use tokio::io::AsyncReadExt;

    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf).await {
        warn!(error = %e, "proof ingestion: failed to read length prefix");
        return;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > common::hivemind::MAX_MESSAGE_SIZE {
        warn!(len, "proof ingestion: invalid message length");
        return;
    }

    // Read payload
    let mut buf = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut buf).await {
        warn!(error = %e, len, "proof ingestion: failed to read payload");
        return;
    }

    // Publish to GossipSub
    match gossip::publish_proof_envelope(swarm, &buf) {
        Ok(msg_id) => {
            info!(?msg_id, bytes = len, "published ingested proof to mesh");
        }
        Err(e) => {
            warn!(error = %e, "failed to publish ingested proof to GossipSub");
        }
    }
}

/// Read a length-prefixed IoC JSON from a TCP connection, publish it
/// to GossipSub IOC topic, and submit to local consensus.
///
/// Wire format: `[4-byte big-endian length][JSON IoC payload]`.
async fn ingest_and_publish_ioc(
    swarm: &mut libp2p::Swarm<transport::HiveMindBehaviour>,
    mut stream: tokio::net::TcpStream,
    local_pubkey: &[u8; 32],
    reputation: &mut ReputationStore,
    consensus: &mut ConsensusEngine,
) {
    use common::hivemind::IoC;
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf).await {
        warn!(error = %e, "IoC inject: failed to read length prefix");
        return;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > common::hivemind::MAX_MESSAGE_SIZE {
        warn!(len, "IoC inject: invalid message length");
        return;
    }

    let mut buf = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut buf).await {
        warn!(error = %e, len, "IoC inject: failed to read payload");
        return;
    }

    let ioc: IoC = match serde_json::from_slice(&buf) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "IoC inject: invalid JSON");
            return;
        }
    };

    // 1. Publish to GossipSub so other peers receive it
    match gossip::publish_ioc(swarm, &ioc) {
        Ok(msg_id) => {
            info!(?msg_id, ip = ioc.ip, "published injected IoC to mesh");
        }
        Err(e) => {
            warn!(error = %e, "failed to publish injected IoC to GossipSub");
        }
    }

    // 2. Submit to local consensus with our own pubkey
    match consensus.submit_ioc(&ioc, local_pubkey) {
        ConsensusResult::Accepted(count) => {
            info!(count, ip = ioc.ip, "injected IoC reached consensus");
            reputation.record_accurate_report(local_pubkey);
            if ioc.ip != 0 {
                if let Err(e) = append_accepted_ioc(ioc.ip, ioc.severity, count as u8) {
                    warn!("failed to persist accepted IoC: {}", e);
                }
            }
        }
        ConsensusResult::Pending(count) => {
            info!(count, ip = ioc.ip, "injected IoC pending cross-validation");
        }
        ConsensusResult::DuplicatePeer => {
            warn!(ip = ioc.ip, "injected IoC: duplicate peer submission");
        }
        ConsensusResult::Expired => {
            info!(ip = ioc.ip, "injected IoC: pending entry expired");
        }
    }
}

/// Load config from `hivemind.toml` in the current directory, or use defaults.
fn load_or_default_config() -> anyhow::Result<HiveMindConfig> {
    let config_path = PathBuf::from("hivemind.toml");
    if config_path.exists() {
        let cfg = config::load_config(&config_path)
            .context("Failed to load hivemind.toml")?;
        info!(?config_path, "Configuration loaded");
        Ok(cfg)
    } else {
        info!("No hivemind.toml found — using default configuration");
        Ok(HiveMindConfig {
            mode: Default::default(),
            identity_key_path: None,
            network: Default::default(),
            bootstrap: Default::default(),
        })
    }
}

/// Lightweight event handler for bootstrap mode.
///
/// Only processes Kademlia routing, GossipSub forwarding (no content
/// inspection), mDNS discovery, Identify, and connection lifecycle.
/// GossipSub messages are automatically forwarded by the protocol — we
/// just need to update metrics and log connection events.
fn handle_bootstrap_event(
    swarm: &mut libp2p::Swarm<transport::HiveMindBehaviour>,
    event: SwarmEvent<transport::HiveMindBehaviourEvent>,
    p2p_metrics: &SharedP2pMetrics,
) {
    match event {
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Kademlia(kad_event)) => {
            dht::handle_kad_event(kad_event);
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Message { message_id, propagation_source, .. },
        )) => {
            // Bootstrap nodes only forward — no content inspection
            p2p_metrics.messages_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::debug!(?message_id, %propagation_source, "Relayed GossipSub message");
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Subscribed { peer_id, topic },
        )) => {
            info!(%peer_id, %topic, "Peer subscribed to topic");
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Unsubscribed { peer_id, topic },
        )) => {
            info!(%peer_id, %topic, "Peer unsubscribed from topic");
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(_)) => {}
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Mdns(
            libp2p::mdns::Event::Discovered(peers),
        )) => {
            let local = *swarm.local_peer_id();
            bootstrap::handle_mdns_discovered(swarm, peers, &local);
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Mdns(
            libp2p::mdns::Event::Expired(peers),
        )) => {
            bootstrap::handle_mdns_expired(swarm, peers);
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Identify(
            libp2p::identify::Event::Received { peer_id, info, .. },
        )) => {
            for addr in info.listen_addrs {
                if bootstrap::is_routable_addr(&addr) {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
            }
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Identify(_)) => {}
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "New listen address");
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            info!(%peer_id, ?endpoint, "Connection established");
            p2p_metrics.peer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            info!(%peer_id, cause = ?cause, "Connection closed");
            let prev = p2p_metrics.peer_count.load(std::sync::atomic::Ordering::Relaxed);
            if prev > 0 {
                p2p_metrics.peer_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        SwarmEvent::IncomingConnectionError { local_addr, error, .. } => {
            warn!(%local_addr, %error, "Incoming connection error");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            warn!(peer = ?peer_id, %error, "Outgoing connection error");
        }
        _ => {}
    }
}

/// Dispatch swarm events to the appropriate handler module.
#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    swarm: &mut libp2p::Swarm<transport::HiveMindBehaviour>,
    event: SwarmEvent<transport::HiveMindBehaviourEvent>,
    local_peer_id: &libp2p::PeerId,
    reputation: &mut ReputationStore,
    consensus: &mut ConsensusEngine,
    fhe_ctx: &FheContext,
    aggregator: &mut FedAvgAggregator,
    gradient_defense: &mut GradientDefense,
    local_model: &mut LocalModel,
    p2p_metrics: &SharedP2pMetrics,
) {
    match event {
        // --- Kademlia events ---
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Kademlia(kad_event)) => {
            dht::handle_kad_event(kad_event);
        }

        // --- GossipSub events ---
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Message {
                propagation_source,
                message,
                message_id,
                ..
            },
        )) => {
            info!(?message_id, %propagation_source, "GossipSub message received");
            p2p_metrics.messages_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Phase 2: Route gradient messages to FL handler
            if message.topic.as_str() == common::hivemind::topics::GRADIENT_TOPIC {
                if let Some(update) = gradient_share::handle_gradient_message(
                    propagation_source,
                    &message.data,
                ) {
                    handle_gradient_update(
                        update,
                        &propagation_source,
                        fhe_ctx,
                        aggregator,
                        gradient_defense,
                        local_model,
                        reputation,
                    );
                }
                return;
            }

            if let Some(ioc) = gossip::handle_gossip_message(
                propagation_source,
                message.clone(),
            ) {
                // Phase 1: Extract reporter pubkey from original publisher,
                // NOT propagation_source (which is the forwarding peer).
                // GossipSub MessageAuthenticity::Signed embeds the author.
                let author = message.source.unwrap_or(propagation_source);
                let reporter_pubkey = peer_id_to_pubkey(&author);

                // Register peer if new (idempotent)
                reputation.register_peer(&reporter_pubkey);

                // Verify ZKP proof if present
                if !ioc.zkp_proof.is_empty() {
                    // Deserialize and verify the proof attached to the IoC
                    if let Ok(proof) = serde_json::from_slice::<
                        common::hivemind::ThreatProof,
                    >(&ioc.zkp_proof) {
                        let result = zkp::verifier::verify_threat(&proof, None);
                        match result {
                            zkp::verifier::VerifyResult::Valid
                            | zkp::verifier::VerifyResult::ValidStub => {
                                info!(%propagation_source, "ZKP proof verified");
                            }
                            other => {
                                warn!(
                                    %propagation_source,
                                    result = ?other,
                                    "ZKP proof verification failed — untrusted IoC"
                                );
                            }
                        }
                    }
                }

                // Submit to consensus — only trusted peers count
                if reputation.is_trusted(&reporter_pubkey) {
                    match consensus.submit_ioc(&ioc, &reporter_pubkey) {
                        ConsensusResult::Accepted(count) => {
                            info!(
                                count,
                                ioc_type = ioc.ioc_type,
                                "IoC reached consensus — adding to threat database"
                            );
                            reputation.record_accurate_report(&reporter_pubkey);
                            // Persist accepted IoC IP for blackwall daemon ingestion
                            if ioc.ip != 0 {
                                if let Err(e) = append_accepted_ioc(
                                    ioc.ip,
                                    ioc.severity,
                                    count as u8,
                                ) {
                                    warn!("failed to persist accepted IoC: {}", e);
                                }
                            }
                        }
                        ConsensusResult::Pending(count) => {
                            info!(
                                count,
                                threshold = common::hivemind::CROSS_VALIDATION_THRESHOLD,
                                "IoC pending cross-validation"
                            );
                        }
                        ConsensusResult::DuplicatePeer => {
                            warn!(
                                %propagation_source,
                                "Duplicate IoC confirmation — ignoring"
                            );
                        }
                        ConsensusResult::Expired => {
                            info!("Pending IoC expired before consensus");
                        }
                    }
                } else {
                    warn!(
                        %propagation_source,
                        stake = reputation.get_stake(&reporter_pubkey),
                        "IoC from untrusted peer — ignoring"
                    );
                }
            }
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Subscribed { peer_id, topic },
        )) => {
            info!(%peer_id, %topic, "Peer subscribed to topic");
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(
            libp2p::gossipsub::Event::Unsubscribed { peer_id, topic },
        )) => {
            info!(%peer_id, %topic, "Peer unsubscribed from topic");
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Gossipsub(_)) => {}

        // --- mDNS events ---
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Mdns(
            libp2p::mdns::Event::Discovered(peers),
        )) => {
            bootstrap::handle_mdns_discovered(
                swarm,
                peers,
                local_peer_id,
            );
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Mdns(
            libp2p::mdns::Event::Expired(peers),
        )) => {
            bootstrap::handle_mdns_expired(swarm, peers);
        }

        // --- Identify events ---
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Identify(
            libp2p::identify::Event::Received { peer_id, info, .. },
        )) => {
            info!(
                %peer_id,
                protocol = %info.protocol_version,
                agent = %info.agent_version,
                "Identify: received peer info"
            );
            // Add identified addresses to Kademlia
            for addr in info.listen_addrs {
                if bootstrap::is_routable_addr(&addr) {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
            }
        }
        SwarmEvent::Behaviour(transport::HiveMindBehaviourEvent::Identify(_)) => {}

        // --- Connection lifecycle ---
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "New listen address");
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            info!(%peer_id, ?endpoint, "Connection established");
            p2p_metrics.peer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        SwarmEvent::ConnectionClosed {
            peer_id, cause, ..
        } => {
            info!(
                %peer_id,
                cause = ?cause,
                "Connection closed"
            );
            // Saturating decrement
            let prev = p2p_metrics.peer_count.load(std::sync::atomic::Ordering::Relaxed);
            if prev > 0 {
                p2p_metrics.peer_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        SwarmEvent::IncomingConnectionError {
            local_addr, error, ..
        } => {
            warn!(%local_addr, %error, "Incoming connection error");
        }
        SwarmEvent::OutgoingConnectionError {
            peer_id, error, ..
        } => {
            warn!(peer = ?peer_id, %error, "Outgoing connection error");
        }
        _ => {}
    }
}

/// Extract a 32-byte public key representation from a PeerId.
///
/// PeerId is a multihash of the public key. We use the raw bytes
/// truncated/padded to 32 bytes as a deterministic peer identifier
/// for the reputation system.
fn peer_id_to_pubkey(peer_id: &libp2p::PeerId) -> [u8; 32] {
    let bytes = peer_id.to_bytes();
    let mut pubkey = [0u8; 32];
    let len = bytes.len().min(32);
    pubkey[..len].copy_from_slice(&bytes[..len]);
    pubkey
}

/// Handle an incoming gradient update from a peer.
///
/// Decrypts the FHE payload, runs defense checks, and submits to
/// the aggregator if safe. When enough contributions arrive, triggers
/// federated aggregation and model update.
fn handle_gradient_update(
    update: common::hivemind::GradientUpdate,
    propagation_source: &libp2p::PeerId,
    fhe_ctx: &FheContext,
    aggregator: &mut FedAvgAggregator,
    gradient_defense: &mut GradientDefense,
    local_model: &mut LocalModel,
    reputation: &mut ReputationStore,
) {
    // Decrypt gradients from FHE ciphertext
    let gradients = match fhe_ctx.decrypt_gradients(&update.encrypted_gradients) {
        Ok(g) => g,
        Err(e) => {
            warn!(
                %propagation_source,
                error = %e,
                "Failed to decrypt gradient payload"
            );
            return;
        }
    };

    // Run defense checks on decrypted gradients
    match gradient_defense.check(&gradients) {
        GradientVerdict::Safe => {}
        verdict => {
            warn!(
                %propagation_source,
                ?verdict,
                "Gradient rejected by defense module"
            );
            // Slash reputation for bad gradient contributions
            let pubkey = peer_id_to_pubkey(propagation_source);
            reputation.record_false_report(&pubkey);
            return;
        }
    }

    // Submit to aggregator
    match aggregator.submit_gradients(
        &update.peer_pubkey,
        update.round_id,
        gradients,
    ) {
        Ok(count) => {
            info!(
                count,
                round = update.round_id,
                "Gradient contribution accepted"
            );

            // If enough peers contributed, aggregate and update model
            if aggregator.ready_to_aggregate() {
                match aggregator.aggregate() {
                    Ok(agg_gradients) => {
                        local_model.apply_gradients(&agg_gradients);
                        info!(
                            round = aggregator.current_round(),
                            participants = count,
                            "Federated model updated via FedAvg"
                        );
                        aggregator.advance_round();
                    }
                    Err(e) => {
                        warn!(error = %e, "Aggregation failed");
                    }
                }
            }
        }
        Err(e) => {
            warn!(
                %propagation_source,
                error = %e,
                "Gradient contribution rejected"
            );
        }
    }
}

/// Periodic federated learning round handler.
///
/// Computes local gradients on a synthetic training sample, encrypts
/// them via FHE, and broadcasts to the gradient topic.
fn handle_fl_round(
    swarm: &mut libp2p::Swarm<transport::HiveMindBehaviour>,
    local_model: &mut LocalModel,
    fhe_ctx: &FheContext,
    aggregator: &mut FedAvgAggregator,
    local_pubkey: &[u8; 32],
) {
    let round_id = aggregator.current_round();

    // ARCH: In production, training data comes from local eBPF telemetry.
    // For now, use a synthetic "benign traffic" sample as a training signal.
    let synthetic_input = vec![0.5_f32; common::hivemind::FL_FEATURE_DIM];
    let synthetic_target = 0.0; // benign

    // Forward and backward pass
    local_model.forward(&synthetic_input);
    let gradients = local_model.backward(synthetic_target);

    // Encrypt gradients before transmission
    let encrypted = match fhe_ctx.encrypt_gradients(&gradients) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to encrypt gradients — skipping FL round");
            return;
        }
    };

    // Publish to the gradient topic
    match gradient_share::publish_gradients(swarm, local_pubkey, round_id, encrypted) {
        Ok(msg_id) => {
            info!(
                ?msg_id,
                round_id,
                "Local gradients broadcasted for FL round"
            );
        }
        Err(e) => {
            // Expected to fail when no peers are connected — not an error
            warn!(error = %e, "Could not publish gradients (no peers?)");
        }
    }
}

/// Append an accepted IoC IP to the shared file for blackwall daemon ingestion.
///
/// Format: one JSON object per line with ip, severity, confidence, and
/// block duration. The blackwall daemon polls this file, reads all lines,
/// adds them to the BLOCKLIST with the prescribed TTL, and removes the file.
/// Directory is created on first write if it doesn't exist.
fn append_accepted_ioc(ip: u32, severity: u8, confirmations: u8) -> std::io::Result<()> {
    use std::io::Write;
    let dir = PathBuf::from("/run/blackwall");
    if !dir.exists() {
        info!(dir = %dir.display(), "creating /run/blackwall directory");
        std::fs::create_dir_all(&dir)?;
    }
    let path = dir.join("hivemind_accepted_iocs");

    // Block duration scales with severity: high severity → longer block
    let duration_secs: u32 = match severity {
        0..=2 => 1800,   // low: 30 min
        3..=5 => 3600,   // medium: 1 hour
        6..=8 => 7200,   // high: 2 hours
        _ => 14400,       // critical: 4 hours
    };

    info!(
        ip,
        severity,
        confirmations,
        duration_secs,
        path = %path.display(),
        "persisting accepted IoC to file"
    );

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(
        file,
        r#"{{"ip":{},"severity":{},"confirmations":{},"duration_secs":{}}}"#,
        ip, severity, confirmations, duration_secs,
    )?;
    info!("IoC persisted successfully");
    Ok(())
}
