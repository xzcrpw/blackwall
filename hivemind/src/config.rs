/// HiveMind configuration.
use serde::Deserialize;
use std::path::Path;

/// Node operating mode.
///
/// - `Full` — default: runs all modules (reputation, consensus, FL, metrics bridge).
/// - `Bootstrap` — lightweight relay: only Kademlia + GossipSub forwarding.
///   Designed for $5/mo VPS that hold tens of thousands of connections.
///   No DPI, XDP, AI, ZKP, or federated learning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    #[default]
    Full,
    Bootstrap,
}

/// Top-level configuration for the HiveMind daemon.
#[derive(Debug, Clone, Deserialize)]
pub struct HiveMindConfig {
    /// Node operating mode (full | bootstrap).
    #[serde(default)]
    pub mode: NodeMode,
    /// Explicit path to the identity key file.
    /// If omitted, defaults to ~/.blackwall/identity.key (or /etc/blackwall/identity.key as root).
    #[serde(default)]
    pub identity_key_path: Option<String>,
    /// Network configuration.
    #[serde(default)]
    pub network: NetworkConfig,
    /// Bootstrap configuration.
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
}

/// Network-level settings.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    /// Listen address for QUIC transport (e.g., "/ip4/0.0.0.0/udp/4001/quic-v1").
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Maximum GossipSub message size in bytes.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    /// GossipSub heartbeat interval in seconds.
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
    /// Idle connection timeout in seconds.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

/// Bootstrap node configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapConfig {
    /// List of additional user-specified bootstrap multiaddresses.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Use built-in (hardcoded) bootstrap nodes. Default: true.
    /// Set to false only for isolated/private meshes.
    #[serde(default = "default_use_default_nodes")]
    pub use_default_nodes: bool,
    /// Enable mDNS for local peer discovery.
    #[serde(default = "default_mdns_enabled")]
    pub mdns_enabled: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            max_message_size: default_max_message_size(),
            heartbeat_secs: default_heartbeat_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            use_default_nodes: default_use_default_nodes(),
            mdns_enabled: default_mdns_enabled(),
        }
    }
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/udp/4001/quic-v1".to_string()
}

fn default_max_message_size() -> usize {
    common::hivemind::MAX_MESSAGE_SIZE
}

fn default_heartbeat_secs() -> u64 {
    common::hivemind::GOSSIPSUB_HEARTBEAT_SECS
}

fn default_idle_timeout_secs() -> u64 {
    60
}

fn default_mdns_enabled() -> bool {
    true
}

fn default_use_default_nodes() -> bool {
    true
}

/// Load HiveMind configuration from a TOML file.
pub fn load_config(path: &Path) -> anyhow::Result<HiveMindConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: HiveMindConfig = toml::from_str(&content)?;
    Ok(config)
}
