//! Blackwall Controller — centralized monitoring for distributed Blackwall sensors.
//!
//! Connects to Blackwall sensor nodes via the peer protocol, collects
//! threat intelligence, and displays aggregated status on stdout.

use anyhow::{Context, Result};
use ring::hmac;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Controller node ID prefix.
const CONTROLLER_ID: &str = "controller";
/// Default peer port for sensor connections.
const DEFAULT_PEER_PORT: u16 = 9471;
/// Status report interval.
const REPORT_INTERVAL: Duration = Duration::from_secs(10);
/// Connection timeout for reaching sensors.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Heartbeat interval.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Wire protocol constants (must match blackwall::distributed::proto).
const HELLO_TYPE: u8 = 0x01;
const HEARTBEAT_TYPE: u8 = 0x04;
const PROTOCOL_MAGIC: [u8; 4] = [0x42, 0x57, 0x4C, 0x01];
/// HMAC-SHA256 tag size.
const HMAC_SIZE: usize = 32;
/// V2 header: magic(4) + type(1) + payload_len(4) + hmac(32) = 41.
const HEADER_SIZE: usize = 4 + 1 + 4 + HMAC_SIZE;

/// State of a connected sensor.
struct SensorState {
    addr: SocketAddr,
    node_id: String,
    last_seen: Instant,
    blocked_ips: u32,
    connected: bool,
    stream: Option<TcpStream>,
}

/// Simple distributed controller that monitors Blackwall sensors.
struct Controller {
    sensors: HashMap<SocketAddr, SensorState>,
    node_id: String,
    hmac_key: hmac::Key,
}

impl Controller {
    fn new(psk: &[u8]) -> Self {
        let hostname = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| "controller-0".into());
        Self {
            sensors: HashMap::new(),
            node_id: format!("{}-{}", CONTROLLER_ID, hostname),
            hmac_key: hmac::Key::new(hmac::HMAC_SHA256, psk),
        }
    }

    /// Connect to a sensor at the given address.
    async fn connect_sensor(&mut self, addr: SocketAddr) -> Result<()> {
        let stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(addr),
        )
        .await
        .with_context(|| format!("timeout connecting to {}", addr))?
        .with_context(|| format!("failed to connect to {}", addr))?;

        // Send HELLO with V2 wire protocol (magic + type + len + hmac + JSON payload)
        let hello = encode_hello(&self.node_id, &self.hmac_key);
        let mut stream = stream;
        stream.write_all(&hello).await
            .with_context(|| format!("failed to send hello to {}", addr))?;

        // Try to read a framed response (non-blocking with short timeout)
        let mut node_id = format!("sensor-{}", addr);
        let mut blocked_count = 0u32;
        let mut authenticated = false;
        match tokio::time::timeout(
            Duration::from_secs(2),
            read_frame(&mut stream, &self.hmac_key),
        ).await {
            Ok(Ok((msg_type, payload))) => {
                if msg_type == HELLO_TYPE {
                    if let Ok(hello_resp) = serde_json::from_slice::<HelloResponse>(&payload) {
                        node_id = hello_resp.node_id;
                        blocked_count = hello_resp.blocked_count;
                        authenticated = true;
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(%addr, error = %e, "sensor authentication failed");
            }
            Err(_) => {
                tracing::warn!(%addr, "sensor HELLO response timeout — not authenticated");
            }
        }

        if !authenticated {
            tracing::warn!(%addr, "sensor NOT connected — HMAC authentication failed");
            self.sensors.insert(addr, SensorState {
                addr,
                node_id,
                last_seen: Instant::now(),
                blocked_ips: 0,
                connected: false,
                stream: None,
            });
            return Ok(());
        }

        tracing::info!(%addr, %node_id, blocked_count, "sensor connected");
        self.sensors.insert(addr, SensorState {
            addr,
            node_id,
            last_seen: Instant::now(),
            blocked_ips: blocked_count,
            connected: true,
            stream: Some(stream),
        });

        Ok(())
    }

    /// Send heartbeat to all connected sensors and read responses.
    async fn send_heartbeats(&mut self) {
        let heartbeat_msg = encode_heartbeat(&self.hmac_key);
        for sensor in self.sensors.values_mut() {
            if !sensor.connected {
                continue;
            }
            let stream = match sensor.stream.as_mut() {
                Some(s) => s,
                None => {
                    sensor.connected = false;
                    continue;
                }
            };
            // Send heartbeat
            if stream.write_all(&heartbeat_msg).await.is_err() {
                tracing::debug!(addr = %sensor.addr, "heartbeat send failed — marking offline");
                sensor.connected = false;
                sensor.stream = None;
                continue;
            }
            // Try to read a response (non-blocking, short timeout)
            match tokio::time::timeout(Duration::from_secs(2), read_frame(stream, &self.hmac_key)).await {
                Ok(Ok((msg_type, payload))) => {
                    sensor.last_seen = Instant::now();
                    if msg_type == HELLO_TYPE {
                        if let Ok(resp) = serde_json::from_slice::<HelloResponse>(&payload) {
                            sensor.blocked_ips = resp.blocked_count;
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(addr = %sensor.addr, error = %e, "heartbeat HMAC error — disconnecting");
                    sensor.connected = false;
                    sensor.stream = None;
                }
                Err(_) => {
                    // Timeout reading response — don't update last_seen,
                    // sensor may be unreachable
                    tracing::debug!(addr = %sensor.addr, "heartbeat response timeout");
                }
            }
        }
    }

    /// Print a status report of all sensors.
    fn print_status(&self) {
        println!("\n=== Blackwall Controller Status ===");
        println!("Sensors: {}", self.sensors.len());
        println!("{:<25} {:<20} {:<12} {:<10}", "Address", "Node ID", "Blocked IPs", "Status");
        println!("{}", "-".repeat(70));
        for sensor in self.sensors.values() {
            let age = sensor.last_seen.elapsed().as_secs();
            let status = if sensor.connected && age < 60 {
                "online"
            } else {
                "stale"
            };
            println!(
                "{:<25} {:<20} {:<12} {:<10}",
                sensor.addr,
                &sensor.node_id[..sensor.node_id.len().min(19)],
                sensor.blocked_ips,
                status,
            );
        }
        println!();
    }
}

/// Encode a HELLO message with V2 wire protocol:
/// magic(4) + type(1) + payload_len(4) + hmac(32) + JSON payload.
fn encode_hello(node_id: &str, key: &hmac::Key) -> Vec<u8> {
    let payload = format!(
        r#"{{"node_id":"{}","version":"1.0.0","blocked_count":0}}"#,
        node_id
    );
    let payload_bytes = payload.as_bytes();
    encode_message(HELLO_TYPE, payload_bytes, key)
}

/// Encode a heartbeat message (empty payload) with HMAC.
fn encode_heartbeat(key: &hmac::Key) -> Vec<u8> {
    encode_message(HEARTBEAT_TYPE, &[], key)
}

/// Encode a V2 wire message: magic(4) + type(1) + payload_len(4) + hmac(32) + payload.
/// HMAC covers: magic + type + payload_len + payload.
fn encode_message(msg_type: u8, payload: &[u8], key: &hmac::Key) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&PROTOCOL_MAGIC);
    buf.push(msg_type);
    buf.extend_from_slice(&len.to_le_bytes());
    // Compute HMAC over header fields + payload
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(&PROTOCOL_MAGIC);
    ctx.update(&[msg_type]);
    ctx.update(&len.to_le_bytes());
    ctx.update(payload);
    let tag = ctx.sign();
    buf.extend_from_slice(tag.as_ref());
    buf.extend_from_slice(payload);
    buf
}

/// Read a single V2 framed message from a stream. Returns (type_byte, payload).
/// Verifies HMAC-SHA256 and rejects unauthenticated messages.
async fn read_frame(stream: &mut TcpStream, key: &hmac::Key) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header).await.context("read header")?;
    if header[..4] != PROTOCOL_MAGIC {
        anyhow::bail!("bad magic");
    }
    let msg_type = header[4];
    let payload_len = u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if payload_len > 65536 {
        anyhow::bail!("payload too large");
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await.context("read payload")?;
    }
    // Verify HMAC: tag is at header[9..41], signed data = magic+type+len+payload
    let hmac_tag = &header[9..9 + HMAC_SIZE];
    let mut verify_data = Vec::with_capacity(9 + payload.len());
    verify_data.extend_from_slice(&header[..9]);
    verify_data.extend_from_slice(&payload);
    hmac::verify(key, &verify_data, hmac_tag)
        .map_err(|_| anyhow::anyhow!("HMAC verification failed — wrong PSK or tampered response"))?;
    Ok((msg_type, payload))
}

/// Deserialized HELLO response from sensor.
#[derive(serde::Deserialize)]
struct HelloResponse {
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    blocked_count: u32,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("blackwall_controller=info")),
        )
        .init();

    tracing::info!("Blackwall Controller starting");

    // PSK for HMAC-SHA256 peer authentication (must match sensor config)
    let psk = std::env::var("BLACKWALL_PSK")
        .unwrap_or_default();
    if psk.is_empty() {
        anyhow::bail!(
            "BLACKWALL_PSK environment variable is required. \
             Set it to the same peer_psk value configured on your sensors."
        );
    }

    // Parse sensor addresses from args: blackwall-controller <addr1> <addr2> ...
    let sensor_addrs: Vec<SocketAddr> = std::env::args()
        .skip(1)
        .filter_map(|arg| {
            // Accept "host:port" or just "host" (use default port)
            if arg.contains(':') {
                arg.parse().ok()
            } else {
                format!("{}:{}", arg, DEFAULT_PEER_PORT).parse().ok()
            }
        })
        .collect();

    if sensor_addrs.is_empty() {
        tracing::info!("usage: BLACKWALL_PSK=<key> blackwall-controller <addr:port> [...]");
        tracing::info!("example: BLACKWALL_PSK=mysecret blackwall-controller 192.168.1.10:9471");
        return Ok(());
    }

    let mut controller = Controller::new(psk.as_bytes());
    tracing::info!(node_id = %controller.node_id, sensors = sensor_addrs.len(), "connecting to sensors");

    // Initial connection to all sensors
    for addr in &sensor_addrs {
        if let Err(e) = controller.connect_sensor(*addr).await {
            tracing::warn!(%addr, "failed to connect to sensor: {}", e);
        }
    }

    controller.print_status();

    // Main loop: periodic status reports + reconnection
    let mut report_interval = tokio::time::interval(REPORT_INTERVAL);
    let mut heartbeat_interval = tokio::time::interval(HEARTBEAT_INTERVAL);

    loop {
        tokio::select! {
            _ = report_interval.tick() => {
                controller.print_status();
            }
            _ = heartbeat_interval.tick() => {
                // Send heartbeats to connected sensors and read responses
                controller.send_heartbeats().await;
                // Reconnect disconnected sensors
                for addr in &sensor_addrs {
                    let is_disconnected = controller.sensors
                        .get(addr)
                        .map(|s| !s.connected)
                        .unwrap_or(true);
                    if is_disconnected {
                        if let Err(e) = controller.connect_sensor(*addr).await {
                            tracing::debug!(%addr, "reconnect failed: {}", e);
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    Ok(())
}
