/// HiveMind transport layer — libp2p swarm with Noise + QUIC.
///
/// Provides the core networking stack: identity management, encrypted
/// transport, and the composite NetworkBehaviour that combines Kademlia,
/// GossipSub, mDNS, and Identify protocols.
///
/// ## NAT Traversal Roadmap
///
/// ARCH: Future versions will add two more behaviours to the composite:
///
/// 1. **AutoNAT** (`libp2p::autonat`) — allows nodes behind NAT to
///    discover their reachability by asking bootstrap nodes to probe them.
///    `SwarmBuilder::with_behaviour` already supports adding it.
///
/// 2. **Circuit Relay v2** (`libp2p::relay`) — bootstrap nodes
///    (`mode = "bootstrap"`) become relay servers. NATed full nodes act
///    as relay clients, receiving inbound connections through the relay.
///    This means the `HiveMindBehaviour` struct will gain:
///      - `relay_server: relay::Behaviour` (on bootstrap nodes)
///      - `relay_client: relay::client::Behaviour` (on full nodes)
///      - `dcutr: dcutr::Behaviour` (Direct Connection Upgrade through Relay)
///
/// The persistent identity (identity.rs) is a prerequisite for relay —
/// relay reservations are tied to PeerId and break on identity change.
use anyhow::Context;
use libp2p::{
    gossipsub, identify, identity, kad, mdns,
    swarm::NetworkBehaviour,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::time::Duration;
use tracing::info;

use crate::config::HiveMindConfig;

/// Composite behaviour combining all HiveMind P2P protocols.
#[derive(NetworkBehaviour)]
pub struct HiveMindBehaviour {
    /// Kademlia DHT for structured peer routing and IoC storage.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// GossipSub for epidemic broadcast of threat indicators.
    pub gossipsub: gossipsub::Behaviour,
    /// mDNS for automatic local peer discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// Identify protocol for exchanging peer metadata.
    pub identify: identify::Behaviour,
}

/// Build and return a configured libp2p Swarm with HiveMindBehaviour.
///
/// The swarm uses QUIC transport with Noise encryption (handled by QUIC
/// internally). Ed25519 keypair is loaded from disk (or generated on
/// first run) to provide a stable PeerId across restarts.
pub fn build_swarm(
    config: &HiveMindConfig,
    keypair: identity::Keypair,
) -> anyhow::Result<Swarm<HiveMindBehaviour>> {
    let local_peer_id = PeerId::from(keypair.public());

    info!(%local_peer_id, "HiveMind node identity loaded");

    let heartbeat = Duration::from_secs(config.network.heartbeat_secs);
    let idle_timeout = Duration::from_secs(config.network.idle_timeout_secs);
    let max_transmit = config.network.max_message_size;

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            let peer_id = PeerId::from(key.public());

            // --- Kademlia DHT ---
            let store = kad::store::MemoryStore::new(peer_id);
            let mut kad_config = kad::Config::new(libp2p::StreamProtocol::new("/hivemind/kad/1.0.0"));
            kad_config.set_query_timeout(Duration::from_secs(
                common::hivemind::KADEMLIA_QUERY_TIMEOUT_SECS,
            ));
            let kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);

            // --- GossipSub ---
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(heartbeat)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(max_transmit)
                .message_id_fn(|msg: &gossipsub::Message| {
                    // PERF: deduplicate by content hash to prevent re-processing
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    msg.data.hash(&mut hasher);
                    msg.topic.hash(&mut hasher);
                    gossipsub::MessageId::from(hasher.finish().to_be_bytes().to_vec())
                })
                .build()
                .map_err(|e| {
                    // gossipsub::ConfigBuilderError doesn't impl std::error::Error
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
            })?;

            // --- mDNS ---
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                peer_id,
            )?;

            // --- Identify ---
            let identify = identify::Behaviour::new(identify::Config::new(
                "/hivemind/0.1.0".to_string(),
                key.public(),
            ));

            Ok(HiveMindBehaviour {
                kademlia,
                gossipsub,
                mdns,
                identify,
            })
        })
        .map_err(|e| anyhow::anyhow!("Failed to build swarm behaviour: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(idle_timeout))
        .build();

    Ok(swarm)
}

/// Start listening on the configured multiaddress.
pub fn start_listening(
    swarm: &mut Swarm<HiveMindBehaviour>,
    config: &HiveMindConfig,
) -> anyhow::Result<()> {
    let listen_addr: Multiaddr = config
        .network
        .listen_addr
        .parse()
        .context("Invalid listen multiaddress")?;

    swarm
        .listen_on(listen_addr.clone())
        .context("Failed to start listening")?;

    info!(%listen_addr, "HiveMind listening");
    Ok(())
}
