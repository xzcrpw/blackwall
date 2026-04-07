//! Peer management: discovery, connection, and message exchange.
//!
//! Manages connections to other Blackwall nodes for distributed
//! threat intelligence sharing.
#![allow(dead_code)]

use anyhow::{Context, Result};
use ring::hmac;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::proto::{self, BlockedIpPayload, HelloPayload, MessageType, HEADER_SIZE};

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
struct PeerState {
    addr: SocketAddr,
    node_id: Option<String>,
    last_seen: Instant,
    blocked_count: u32,
    /// Persistent outbound connection for broadcasts (reused across sends).
    outbound: Option<TcpStream>,
}

/// Manages distributed peer connections and threat intel sharing.
pub struct PeerManager {
    /// Our node identifier
    node_id: String,
    /// Known peers with their state
    peers: HashMap<SocketAddr, PeerState>,
    /// IPs received from peers (ip → source_peer)
    shared_blocks: HashMap<Ipv4Addr, SocketAddr>,
    /// HMAC-SHA256 key derived from peer PSK for message authentication.
    hmac_key: hmac::Key,
}

impl PeerManager {
    /// Create a new peer manager with the given node ID and pre-shared key.
    pub fn new(node_id: String, peer_psk: &[u8]) -> Self {
        Self {
            node_id,
            peers: HashMap::new(),
            shared_blocks: HashMap::new(),
            hmac_key: hmac::Key::new(hmac::HMAC_SHA256, peer_psk),
        }
    }

    /// Get reference to the HMAC key for message signing/verification.
    pub fn hmac_key(&self) -> &hmac::Key {
        &self.hmac_key
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
            outbound: None,
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

    /// Take outbound streams from all peers for concurrent use.
    /// Returns (addr, Option<TcpStream>) pairs. Caller MUST return streams
    /// via `return_outbound()` after use.
    fn take_outbound_streams(&mut self) -> Vec<(SocketAddr, Option<TcpStream>)> {
        self.peers
            .iter_mut()
            .map(|(addr, state)| (*addr, state.outbound.take()))
            .collect()
    }

    /// Return an outbound stream (or None if it broke) to a peer.
    fn return_outbound(&mut self, addr: &SocketAddr, stream: Option<TcpStream>) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.outbound = stream;
        }
    }
}

/// Broadcast a blocked IP to all known peers.
///
/// Reuses persistent outbound TCP connections where possible. Creates new
/// connections only when no existing stream is available or the previous
/// one has broken. Sends in parallel; individual peer failures are logged
/// and do not block other peers.
pub async fn broadcast_block(
    manager: &std::sync::Arc<tokio::sync::Mutex<PeerManager>>,
    payload: &BlockedIpPayload,
) {
    let peers = {
        let mut mgr = manager.lock().await;
        mgr.take_outbound_streams()
    };

    if peers.is_empty() {
        return;
    }

    tracing::info!(
        ip = %payload.ip,
        peers = peers.len(),
        "broadcasting block to peers"
    );

    let json = match serde_json::to_vec(payload) {
        Ok(j) => j,
        Err(e) => {
            // Return streams untouched on serialization failure
            let mut mgr = manager.lock().await;
            for (addr, stream) in peers {
                mgr.return_outbound(&addr, stream);
            }
            tracing::warn!(error = %e, "failed to serialize BlockedIpPayload");
            return;
        }
    };
    let msg = {
        let mgr = manager.lock().await;
        proto::encode_message(MessageType::BlockedIp, &json, mgr.hmac_key())
    };

    let mut tasks = Vec::with_capacity(peers.len());
    for (addr, existing) in peers {
        let msg_clone = msg.clone();
        tasks.push(tokio::spawn(async move {
            let stream = send_or_reconnect(addr, existing, &msg_clone).await;
            (addr, stream)
        }));
    }

    // Return streams (live or None) back to the manager
    let mut mgr = manager.lock().await;
    for task in tasks {
        if let Ok((addr, stream)) = task.await {
            mgr.return_outbound(&addr, stream);
        }
    }
}

/// Try to send on an existing connection; reconnect if broken.
/// Returns the stream if it's still alive, or None if the peer is unreachable.
async fn send_or_reconnect(
    addr: SocketAddr,
    existing: Option<TcpStream>,
    msg: &[u8],
) -> Option<TcpStream> {
    // Try existing connection first
    if let Some(mut stream) = existing {
        if stream.write_all(msg).await.is_ok() && stream.flush().await.is_ok() {
            return Some(stream);
        }
        // Connection broken — fall through to reconnect
        tracing::debug!(peer = %addr, "outbound stream broken, reconnecting");
    }

    // Create new connection
    let mut stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(peer = %addr, error = %e, "peer connect failed");
            return None;
        }
        Err(_) => {
            tracing::warn!(peer = %addr, "peer connect timeout");
            return None;
        }
    };

    if stream.write_all(msg).await.is_ok() && stream.flush().await.is_ok() {
        Some(stream)
    } else {
        tracing::warn!(peer = %addr, "failed to write to new peer connection");
        None
    }
}

/// Send a blocked IP notification to a single peer (one-off, no pool).
pub async fn send_blocked_ip(
    addr: SocketAddr,
    payload: &BlockedIpPayload,
    key: &hmac::Key,
) -> Result<()> {
    let json = serde_json::to_vec(payload).context("serialize BlockedIpPayload")?;
    let msg = proto::encode_message(MessageType::BlockedIp, &json, key);

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
                tracing::warn!(peer = %peer_addr, "peer connection ended: {}", e);
            }
        });
    }
}

/// Handle an incoming peer connection — loops reading messages until the
/// remote side disconnects or an I/O error occurs. Sends responses to HELLO
/// and Heartbeat messages so the controller can track liveness.
///
/// Non-fatal errors (bad JSON, unknown payloads) are logged and the loop
/// continues. Only I/O errors (connection reset, EOF) break the loop.
async fn handle_peer_connection(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    manager: &std::sync::Arc<tokio::sync::Mutex<PeerManager>>,
) -> Result<()> {
    // Disable Nagle's algorithm for low-latency responses
    let _ = stream.set_nodelay(true);

    tracing::info!(peer = %peer_addr, "peer connected, entering read loop");

    loop {
        // --- Read header: magic(4) + type(1) + payload_len(4) + hmac(32) ---
        let mut header_buf = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header_buf).await?;

        let (msg_type, payload_len) = match proto::decode_header(&header_buf) {
            Some(h) => h,
            None => {
                tracing::warn!(
                    peer = %peer_addr,
                    "invalid header (bad magic or unknown type), dropping connection"
                );
                anyhow::bail!("invalid header from {}", peer_addr);
            }
        };

        if payload_len > MAX_PAYLOAD_SIZE {
            tracing::warn!(
                peer = %peer_addr, len = payload_len,
                "payload too large, dropping connection"
            );
            anyhow::bail!("payload too large: {}", payload_len);
        }

        // --- Read payload (I/O error is fatal) ---
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload).await?;
        }

        // --- Verify HMAC-SHA256 before processing ---
        {
            let mgr = manager.lock().await;
            if !proto::verify_hmac(&header_buf, &payload, mgr.hmac_key()) {
                tracing::warn!(
                    peer = %peer_addr, msg_type = ?msg_type,
                    "HMAC verification failed — rejecting message"
                );
                anyhow::bail!("HMAC verification failed from {}", peer_addr);
            }
        }

        // --- Process message (parse errors are non-fatal → continue) ---
        match msg_type {
            MessageType::Hello => {
                let hello: HelloPayload = match serde_json::from_slice(&payload) {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!(peer = %peer_addr, error = %e, "bad Hello JSON, skipping");
                        continue;
                    }
                };
                let resp_msg = {
                    let mut mgr = manager.lock().await;
                    // Auto-register the peer so future heartbeats update last_seen
                    mgr.add_peer(peer_addr);
                    mgr.handle_hello(peer_addr, &hello);
                    let resp = mgr.make_hello(mgr.shared_block_count() as u32);
                    let resp_bytes = serde_json::to_vec(&resp)
                        .context("serialize Hello response")?;
                    proto::encode_message(MessageType::Hello, &resp_bytes, mgr.hmac_key())
                }; // mgr dropped here before I/O
                stream.write_all(&resp_msg).await?;
                stream.flush().await?;
            }
            MessageType::BlockedIp => {
                let blocked: BlockedIpPayload = match serde_json::from_slice(&payload) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(peer = %peer_addr, error = %e, "bad BlockedIp JSON, skipping");
                        continue;
                    }
                };
                let mut mgr = manager.lock().await;
                mgr.receive_blocked_ip(peer_addr, &blocked);
            }
            MessageType::Heartbeat => {
                let resp_msg = {
                    let mut mgr = manager.lock().await;
                    if let Some(peer) = mgr.peers.get_mut(&peer_addr) {
                        peer.last_seen = Instant::now();
                    }
                    let resp = mgr.make_hello(mgr.shared_block_count() as u32);
                    let resp_bytes = serde_json::to_vec(&resp)
                        .context("serialize Heartbeat response")?;
                    proto::encode_message(MessageType::Hello, &resp_bytes, mgr.hmac_key())
                }; // mgr dropped here before I/O
                stream.write_all(&resp_msg).await?;
                stream.flush().await?;
            }
            _ => {
                tracing::debug!(
                    peer = %peer_addr, msg_type = ?msg_type,
                    "unhandled message type, continuing"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk() -> &'static [u8] {
        b"test-secret-key-for-blackwall"
    }

    #[test]
    fn peer_manager_add_and_count() {
        let mut mgr = PeerManager::new("test-node".into(), test_psk());
        assert_eq!(mgr.peer_count(), 0);

        mgr.add_peer("10.0.0.1:9471".parse().unwrap());
        assert_eq!(mgr.peer_count(), 1);

        // Duplicate
        mgr.add_peer("10.0.0.1:9471".parse().unwrap());
        assert_eq!(mgr.peer_count(), 1);
    }

    #[test]
    fn receive_blocked_ip_with_confidence() {
        let mut mgr = PeerManager::new("test-node".into(), test_psk());
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
        let mgr = PeerManager::new("node-42".into(), test_psk());
        let hello = mgr.make_hello(100);
        assert_eq!(hello.node_id, "node-42");
        assert_eq!(hello.blocked_count, 100);
    }

    #[test]
    fn prune_stale_peers() {
        let mut mgr = PeerManager::new("test".into(), test_psk());
        mgr.add_peer("10.0.0.1:9471".parse().unwrap());
        mgr.add_peer("10.0.0.2:9471".parse().unwrap());
        assert_eq!(mgr.peer_count(), 2);

        // Stale after 0 seconds = prune all
        mgr.prune_stale_peers(Duration::from_secs(0));
        assert_eq!(mgr.peer_count(), 0);
    }
}
