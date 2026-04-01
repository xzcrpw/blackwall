//! Blackwall Controller — centralized monitoring for distributed Blackwall sensors.
//!
//! Connects to Blackwall sensor nodes via the peer protocol, collects
//! threat intelligence, and displays aggregated status on stdout.

use anyhow::{Context, Result};
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
const _HEARTBEAT_TYPE: u8 = 0x02;

/// State of a connected sensor.
struct SensorState {
    addr: SocketAddr,
    node_id: String,
    last_seen: Instant,
    blocked_ips: u32,
    connected: bool,
}

/// Simple distributed controller that monitors Blackwall sensors.
struct Controller {
    sensors: HashMap<SocketAddr, SensorState>,
    node_id: String,
}

impl Controller {
    fn new() -> Self {
        let hostname = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| "controller-0".into());
        Self {
            sensors: HashMap::new(),
            node_id: format!("{}-{}", CONTROLLER_ID, hostname),
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

        // Send HELLO
        let hello = encode_hello(&self.node_id);
        let mut stream = stream;
        stream.write_all(&hello).await
            .with_context(|| format!("failed to send hello to {}", addr))?;

        // Read HELLO response
        let mut header = [0u8; 5];
        if let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_secs(3),
            stream.read_exact(&mut header),
        ).await {
            let msg_type = header[0];
            let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
            if msg_type == HELLO_TYPE && payload_len < 4096 {
                let mut payload = vec![0u8; payload_len];
                if stream.read_exact(&mut payload).await.is_ok() {
                    let node_id = String::from_utf8_lossy(&payload).to_string();
                    tracing::info!(%addr, node_id = %node_id, "sensor connected");
                    self.sensors.insert(addr, SensorState {
                        addr,
                        node_id,
                        last_seen: Instant::now(),
                        blocked_ips: 0,
                        connected: true,
                    });
                    return Ok(());
                }
            }
        }

        // Partial success — mark as connected but no ID
        self.sensors.insert(addr, SensorState {
            addr,
            node_id: format!("unknown-{}", addr),
            last_seen: Instant::now(),
            blocked_ips: 0,
            connected: true,
        });

        Ok(())
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

/// Encode a HELLO message (type=0x01 + 4-byte len + node_id bytes).
fn encode_hello(node_id: &str) -> Vec<u8> {
    let id_bytes = node_id.as_bytes();
    let len = id_bytes.len() as u32;
    let mut msg = Vec::with_capacity(5 + id_bytes.len());
    msg.push(HELLO_TYPE);
    msg.extend_from_slice(&len.to_le_bytes());
    msg.extend_from_slice(id_bytes);
    msg
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
        tracing::info!("usage: blackwall-controller <sensor_addr:port> [sensor_addr:port ...]");
        tracing::info!("example: blackwall-controller 192.168.1.10:9471 192.168.1.11:9471");
        return Ok(());
    }

    let mut controller = Controller::new();
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
                // Mark stale sensors
                for sensor in controller.sensors.values_mut() {
                    if sensor.last_seen.elapsed() > Duration::from_secs(90) {
                        sensor.connected = false;
                    }
                }
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
