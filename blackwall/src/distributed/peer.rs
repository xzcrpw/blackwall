//! Peer management: discovery, connection, and message exchange.
//!
//! Manages connections to other Blackwall nodes for distributed
//! threat intelligence sharing.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::proto::{self, BlockedIpPayload, HelloPayload, MessageType};

/// Default port for peer communication.
pub const DEFAULT_PEER_PORT: u16 = 9471;
/// Heartbeat interval.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// Peer connection timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum peers to maintain.
const MAX_PEERS: usize = 16;
/// Maximum message payload size (64 KB).
const MAX_PAYLOAD_SIZE: usize = 65536;

/// Known peer state.
#[derive(Debug)]
struct PeerState {
    addr: SocketAddr,
    node_id: Option<String>,
    last_seen: Instant,
    blocked_count: u32,
}

/// Manages distributed peer connections and threat intel sharing.
pub struct PeerManager {
    /// Our node identifier
    node_id: String,
    /// Known peers with their state
    peers: HashMap<SocketAddr, PeerState>,
    /// IPs received from peers (ip → source_peer)
    shared_blocks: HashMap<Ipv4Addr, SocketAddr>,
}

impl PeerManager {
    /// Create a new peer manager with the given node ID.
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            peers: HashMap::new(),
            shared_blocks: HashMap::new(),
        }
    }

    /// Add a peer address to the known peers list.
    pub fn add_peer(&mut self, addr: SocketAddr) {
        if self.peers.len() >= MAX_PEERS {
            tracing::warn!("max peers reached, ignoring {}", addr);
            return;
        }
        self.peers.entry(addr).or_insert_with(|| PeerState {
            addr,
            node_id: None,
            last_seen: Instant::now(),
            blocked_count: 0,
        });
    }

    /// Get count of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get count of shared block entries received from peers.
    #[allow(dead_code)]
    pub fn shared_block_count(&self) -> usize {
        self.shared_blocks.len()
    }

    /// Process a received blocked IP notification from a peer.
    pub fn receive_blocked_ip(
        &mut self,
        from: SocketAddr,
        payload: &BlockedIpPayload,
    ) -> Option<(Ipv4Addr, u32)> {
        // Only accept if confidence is reasonable
        if payload.confidence < 50 {
            tracing::debug!(
                peer = %from,
                ip = %payload.ip,
                confidence = payload.confidence,
                "ignoring low-confidence peer block"
            );
            return None;
        }

        self.shared_blocks.insert(payload.ip, from);

        tracing::info!(
            peer = %from,
            ip = %payload.ip,
            reason = %payload.reason,
            confidence = payload.confidence,
            "received blocked IP from peer"
        );

        Some((payload.ip, payload.duration_secs))
    }

    /// Create a hello payload for this node.
    pub fn make_hello(&self, blocked_count: u32) -> HelloPayload {
        HelloPayload {
            node_id: self.node_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            blocked_count,
        }
    }

    /// Handle an incoming hello from a peer.
    pub fn handle_hello(&mut self, from: SocketAddr, hello: &HelloPayload) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.node_id = Some(hello.node_id.clone());
            peer.last_seen = Instant::now();
            peer.blocked_count = hello.blocked_count;
        }
        tracing::info!(
            peer = %from,
            node_id = %hello.node_id,
            blocked = hello.blocked_count,
            "peer hello received"
        );
    }

    /// Prune peers that haven't been seen in a while.
    pub fn prune_stale_peers(&mut self, max_age: Duration) {
        let before = self.peers.len();
        self.peers.retain(|_, p| p.last_seen.elapsed() < max_age);
        let pruned = before - self.peers.len();
        if pruned > 0 {
            tracing::info!(count = pruned, "pruned stale peers");
        }
    }

    /// Get addresses of all known peers.
    pub fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.peers.keys().copied().collect()
    }
}

/// Broadcast a blocked IP to all known peers.
///
/// Sends in parallel via individual TCP connections. Failures to individual
/// peers are logged and ignored — the block still applies locally.
pub async fn broadcast_block(
    manager: &std::sync::Arc<tokio::sync::Mutex<PeerManager>>,
    payload: &BlockedIpPayload,
) {
    let addrs = {
        let mgr = manager.lock().await;
        mgr.peer_addrs()
    };

    if addrs.is_empty() {
        return;
    }

    tracing::info!(
        ip = %payload.ip,
        peers = addrs.len(),
        "broadcasting block to peers"
    );

    let mut tasks = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let p = payload.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = send_blocked_ip(addr, &p).await {
                tracing::warn!(peer = %addr, error = %e, "failed to broadcast block");
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}

/// Send a blocked IP notification to a single peer.
pub async fn send_blocked_ip(
    addr: SocketAddr,
    payload: &BlockedIpPayload,
) -> Result<()> {
    let json = serde_json::to_vec(payload).context("serialize BlockedIpPayload")?;
    let msg = proto::encode_message(MessageType::BlockedIp, &json);

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("peer connect timeout")?
        .context("peer connect failed")?;

    stream.write_all(&msg).await.context("peer write failed")?;
    stream.flush().await?;

    Ok(())
}

/// Listen for incoming peer connections and process messages.
pub async fn listen_for_peers(
    bind_addr: SocketAddr,
    manager: std::sync::Arc<tokio::sync::Mutex<PeerManager>>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("failed to bind peer listener")?;

    tracing::info!(addr = %bind_addr, "peer listener started");

    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        let mgr = manager.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_peer_connection(&mut stream, peer_addr, &mgr).await {
                tracing::debug!(peer = %peer_addr, "peer connection error: {}", e);
            }
        });
    }
}

/// Handle a single incoming peer connection.
async fn handle_peer_connection(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    manager: &std::sync::Arc<tokio::sync::Mutex<PeerManager>>,
) -> Result<()> {
    let mut header_buf = [0u8; 9];
    stream.read_exact(&mut header_buf).await?;

    let (msg_type, payload_len) = proto::decode_header(&header_buf)
        .context("invalid message header")?;

    if payload_len > MAX_PAYLOAD_SIZE {
        anyhow::bail!("payload too large: {}", payload_len);
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let mut mgr = manager.lock().await;

    match msg_type {
        MessageType::Hello => {
            let hello: HelloPayload = serde_json::from_slice(&payload)?;
            mgr.handle_hello(peer_addr, &hello);
        }
        MessageType::BlockedIp => {
            let blocked: BlockedIpPayload = serde_json::from_slice(&payload)?;
            mgr.receive_blocked_ip(peer_addr, &blocked);
        }
        MessageType::Heartbeat => {
            if let Some(peer) = mgr.peers.get_mut(&peer_addr) {
                peer.last_seen = Instant::now();
            }
        }
        _ => {
            tracing::debug!(peer = %peer_addr, msg_type = ?msg_type, "unhandled message type");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_manager_add_and_count() {
        let mut mgr = PeerManager::new("test-node".into());
        assert_eq!(mgr.peer_count(), 0);

        mgr.add_peer("10.0.0.1:9471".parse().unwrap());
        assert_eq!(mgr.peer_count(), 1);

        // Duplicate
        mgr.add_peer("10.0.0.1:9471".parse().unwrap());
        assert_eq!(mgr.peer_count(), 1);
    }

    #[test]
    fn receive_blocked_ip_with_confidence() {
        let mut mgr = PeerManager::new("test-node".into());
        let peer: SocketAddr = "10.0.0.2:9471".parse().unwrap();
        mgr.add_peer(peer);

        // High confidence — accepted
        let high = BlockedIpPayload {
            ip: Ipv4Addr::new(192, 168, 1, 100),
            reason: "port scan".into(),
            duration_secs: 600,
            confidence: 85,
        };
        assert!(mgr.receive_blocked_ip(peer, &high).is_some());

        // Low confidence — rejected
        let low = BlockedIpPayload {
            ip: Ipv4Addr::new(192, 168, 1, 200),
            reason: "maybe scan".into(),
            duration_secs: 60,
            confidence: 30,
        };
        assert!(mgr.receive_blocked_ip(peer, &low).is_none());
    }

    #[test]
    fn make_hello() {
        let mgr = PeerManager::new("node-42".into());
        let hello = mgr.make_hello(100);
        assert_eq!(hello.node_id, "node-42");
        assert_eq!(hello.blocked_count, 100);
    }

    #[test]
    fn prune_stale_peers() {
        let mut mgr = PeerManager::new("test".into());
        mgr.add_peer("10.0.0.1:9471".parse().unwrap());
        mgr.add_peer("10.0.0.2:9471".parse().unwrap());
        assert_eq!(mgr.peer_count(), 2);

        // Stale after 0 seconds = prune all
        mgr.prune_stale_peers(Duration::from_secs(0));
        assert_eq!(mgr.peer_count(), 0);
    }
}
