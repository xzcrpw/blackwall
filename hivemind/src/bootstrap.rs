/// Bootstrap protocol for HiveMind peer discovery.
///
/// Supports three discovery mechanisms:
/// 1. Hardcoded bootstrap nodes (compiled into the binary)
/// 2. User-configured bootstrap nodes (from hivemind.toml)
/// 3. mDNS (for local/LAN peer discovery)
///
/// ARCH: Bootstrap nodes will become Circuit Relay v2 servers
/// for NAT traversal once AutoNAT is integrated.
use anyhow::Context;
use libp2p::{Multiaddr, PeerId, Swarm};
use libp2p::multiaddr::Protocol;
use tracing::{info, warn};

use crate::config::HiveMindConfig;
use crate::transport::HiveMindBehaviour;

/// Check if a multiaddress points to a routable (non-loopback, non-unspecified) IP.
///
/// Rejects 127.0.0.0/8, ::1, 0.0.0.0, :: to prevent self-referencing connections
/// that cause "Unexpected peer ID" errors in Kademlia.
pub fn is_routable_addr(addr: &Multiaddr) -> bool {
    let mut has_ip = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                has_ip = true;
                if ip.is_loopback() || ip.is_unspecified() {
                    return false;
                }
            }
            Protocol::Ip6(ip) => {
                has_ip = true;
                if ip.is_loopback() || ip.is_unspecified() {
                    return false;
                }
            }
            _ => {}
        }
    }
    has_ip
}

/// Built-in bootstrap nodes baked into the binary.
///
/// These are lightweight relay-only VPS instances that never go down.
/// They run `mode = "bootstrap"` and serve only as DHT entry points.
/// Users can disable them by setting `bootstrap.use_default_nodes = false`.
///
/// IMPORTANT: Update these when deploying new bootstrap infrastructure.
/// Format: "/ip4/<ip>/udp/4001/quic-v1/p2p/<peer-id>"
pub const DEFAULT_BOOTSTRAP_NODES: &[&str] = &[
    // EU-West (OVH France) — primary bootstrap
    "/ip4/135.125.234.128/udp/4001/quic-v1/p2p/12D3KooWGb9Nkhao6qKdfQPD3yxyktbDAyDunngMGcyxM7VLg74b",
    // EU-West (OVH France) — secondary bootstrap
    "/ip4/57.128.255.94/udp/4001/quic-v1/p2p/12D3KooWDW6kR7SX5RZyaUUokEdeWKMVyAyF8KNedxvhagDPUrW7",
    // NA-East (OVH Canada) — tertiary bootstrap
    "/ip4/158.69.194.27/udp/4001/quic-v1/p2p/12D3KooWDeZf7zKtFU2DEzbuUpNPQ5d3Cjvw5rbRXKA7eF4vk4JF",
];

/// Connect to bootstrap nodes (default + user-configured) and initiate
/// Kademlia bootstrap for full DHT peer discovery.
///
/// Bootstrap nodes are specified as multiaddresses in the config file.
/// Each address must include a `/p2p/<peer-id>` component.
pub fn connect_bootstrap_nodes(
    swarm: &mut Swarm<HiveMindBehaviour>,
    config: &HiveMindConfig,
    local_peer_id: &PeerId,
) -> anyhow::Result<Vec<PeerId>> {
    let mut seed_peers = Vec::new();

    // --- 1. Built-in (hardcoded) bootstrap nodes ---
    if config.bootstrap.use_default_nodes {
        for addr_str in DEFAULT_BOOTSTRAP_NODES {
            match try_add_bootstrap(swarm, addr_str, local_peer_id) {
                Ok(Some(pid)) => seed_peers.push(pid),
                Ok(None) => {} // self-referencing, skipped
                Err(e) => {
                    warn!(
                        addr = addr_str,
                        error = %e,
                        "Failed to parse default bootstrap node — skipping"
                    );
                }
            }
        }
    }

    // --- 2. User-configured bootstrap nodes ---
    for node_addr_str in &config.bootstrap.nodes {
        match try_add_bootstrap(swarm, node_addr_str, local_peer_id) {
            Ok(Some(pid)) => seed_peers.push(pid),
            Ok(None) => {}
            Err(e) => {
                warn!(
                    addr = node_addr_str,
                    error = %e,
                    "Failed to parse bootstrap node address — skipping"
                );
            }
        }
    }

    if !seed_peers.is_empty() {
        // Initiate Kademlia bootstrap to discover more peers
        swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map_err(|e| anyhow::anyhow!("Kademlia bootstrap failed: {e:?}"))?;
        info!(count = seed_peers.len(), "Bootstrap initiated with known peers");
    } else {
        info!("No bootstrap nodes configured — relying on mDNS discovery");
    }

    Ok(seed_peers)
}

/// Try to add a single bootstrap node. Returns Ok(Some(PeerId)) if added,
/// Ok(None) if skipped (self-referencing), Err on parse failure.
fn try_add_bootstrap(
    swarm: &mut Swarm<HiveMindBehaviour>,
    addr_str: &str,
    local_peer_id: &PeerId,
) -> anyhow::Result<Option<PeerId>> {
    let (peer_id, addr) = parse_bootstrap_addr(addr_str)?;

    // SECURITY: Reject self-referencing bootstrap entries
    if peer_id == *local_peer_id {
        warn!("Skipping bootstrap node that references self");
        return Ok(None);
    }

    // SECURITY: Reject loopback/unspecified addresses
    if !is_routable_addr(&addr) {
        warn!(%addr, "Skipping bootstrap node with non-routable address");
        return Ok(None);
    }

    swarm
        .behaviour_mut()
        .kademlia
        .add_address(&peer_id, addr.clone());
    swarm
        .behaviour_mut()
        .gossipsub
        .add_explicit_peer(&peer_id);

    info!(%peer_id, %addr, "Added bootstrap node");
    Ok(Some(peer_id))
}

/// Parse a multiaddress string that includes a `/p2p/<peer-id>` suffix.
///
/// Example: `/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmPeer...`
fn parse_bootstrap_addr(addr_str: &str) -> anyhow::Result<(PeerId, Multiaddr)> {
    let addr: Multiaddr = addr_str
        .parse()
        .context("Invalid multiaddress format")?;

    // Extract PeerId from the /p2p/ component
    let peer_id = addr
        .iter()
        .find_map(|proto| {
            if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                Some(peer_id)
            } else {
                None
            }
        })
        .context("Bootstrap address must include /p2p/<peer-id> component")?;

    // Strip the /p2p/ component from the address for Kademlia
    let transport_addr: Multiaddr = addr
        .iter()
        .filter(|proto| !matches!(proto, libp2p::multiaddr::Protocol::P2p(_)))
        .collect();

    Ok((peer_id, transport_addr))
}

/// Handle mDNS discovery events — add discovered peers to both
/// Kademlia and GossipSub.
pub fn handle_mdns_discovered(
    swarm: &mut Swarm<HiveMindBehaviour>,
    peers: Vec<(PeerId, Multiaddr)>,
    local_peer_id: &PeerId,
) {
    for (peer_id, addr) in peers {
        // SECURITY: Reject self-referencing entries
        if peer_id == *local_peer_id {
            continue;
        }

        // SECURITY: Reject loopback/unspecified addresses
        if !is_routable_addr(&addr) {
            warn!(%peer_id, %addr, "mDNS: skipping non-routable address");
            continue;
        }

        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, addr.clone());
        swarm
            .behaviour_mut()
            .gossipsub
            .add_explicit_peer(&peer_id);

        info!(%peer_id, %addr, "mDNS: discovered local peer");
    }
}

/// Handle mDNS expiry events — remove expired peers from GossipSub.
pub fn handle_mdns_expired(
    swarm: &mut Swarm<HiveMindBehaviour>,
    peers: Vec<(PeerId, Multiaddr)>,
) {
    for (peer_id, _addr) in peers {
        swarm
            .behaviour_mut()
            .gossipsub
            .remove_explicit_peer(&peer_id);

        info!(%peer_id, "mDNS: peer expired");
    }
}
