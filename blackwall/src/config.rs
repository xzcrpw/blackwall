use serde::Deserialize;
use std::path::Path;

/// Top-level daemon configuration, loaded from TOML.
#[derive(Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub thresholds: ThresholdConfig,
    #[serde(default)]
    pub tarpit: TarpitConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub feeds: FeedsConfig,
    #[serde(default)]
    pub pcap: PcapConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub distributed: DistributedConfig,
}

/// Network / XDP attachment settings.
#[derive(Deserialize)]
pub struct NetworkConfig {
    /// Network interface to attach XDP program to.
    #[serde(default = "default_interface")]
    pub interface: String,
    /// XDP attach mode: "generic", "native", or "offload".
    #[serde(default = "default_xdp_mode")]
    pub xdp_mode: String,
}

/// Anomaly detection thresholds.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ThresholdConfig {
    /// Byte diversity score above which a packet is considered anomalous.
    #[serde(default = "default_entropy_anomaly")]
    pub entropy_anomaly: u32,
}

/// Tarpit honeypot configuration.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct TarpitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_tarpit_port")]
    pub port: u16,
    #[serde(default = "default_base_delay")]
    pub base_delay_ms: u64,
    #[serde(default = "default_max_delay")]
    pub max_delay_ms: u64,
    #[serde(default = "default_jitter")]
    pub jitter_ms: u64,
    /// Per-protocol deception service port overrides.
    #[serde(default)]
    pub services: DeceptionServicesConfig,
}

/// Per-protocol port configuration for the deception mesh.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct DeceptionServicesConfig {
    /// SSH honeypot port (default: 22).
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// HTTP honeypot port (default: 80).
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    /// MySQL honeypot port (default: 3306).
    #[serde(default = "default_mysql_port")]
    pub mysql_port: u16,
    /// DNS canary port (default: 53).
    #[serde(default = "default_dns_port")]
    pub dns_port: u16,
}

/// AI / LLM classification settings.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct AiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ollama_url")]
    pub ollama_url: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_fallback_model")]
    pub fallback_model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Static rules loaded at startup.
#[derive(Deserialize, Default)]
pub struct RulesConfig {
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// Threat feed configuration.
#[derive(Deserialize)]
pub struct FeedsConfig {
    /// Whether threat feed fetching is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Refresh interval in seconds (default: 1 hour).
    #[serde(default = "default_feed_refresh_secs")]
    pub refresh_interval_secs: u64,
    /// Block duration for feed-sourced IPs in seconds (default: 1 hour).
    #[serde(default = "default_feed_block_secs")]
    pub block_duration_secs: u32,
    /// Feed source URLs.
    #[serde(default = "default_feed_sources")]
    pub sources: Vec<FeedSourceConfig>,
}

/// A single threat feed source entry.
#[derive(Deserialize, Clone)]
pub struct FeedSourceConfig {
    pub name: String,
    pub url: String,
    /// Override block duration for this feed (uses parent default if absent).
    pub block_duration_secs: Option<u32>,
}

/// PCAP forensic capture configuration.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PcapConfig {
    /// Whether PCAP capture is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Output directory for pcap files.
    #[serde(default = "default_pcap_dir")]
    pub output_dir: String,
    /// Maximum pcap file size in MB before rotation.
    #[serde(default = "default_pcap_max_size")]
    pub max_size_mb: u64,
    /// Maximum number of rotated pcap files to keep.
    #[serde(default = "default_pcap_max_files")]
    pub max_files: usize,
    /// Compress rotated pcap files with gzip.
    #[serde(default)]
    pub compress_rotated: bool,
}

/// Distributed coordination configuration.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct DistributedConfig {
    /// Whether distributed mode is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Mode: "sensor" (reports to controller) or "standalone" (default).
    #[serde(default = "default_distributed_mode")]
    pub mode: String,
    /// Peer addresses to connect to.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Port to listen for peer connections.
    #[serde(default = "default_peer_port")]
    pub bind_port: u16,
    /// Node identifier (auto-generated if empty).
    #[serde(default)]
    pub node_id: String,
    /// Pre-shared key for HMAC-SHA256 peer authentication.
    /// All peers in the mesh must share the same PSK.
    /// If empty, distributed mode refuses to start.
    #[serde(default)]
    pub peer_psk: String,
}

// --- Defaults ---

fn default_interface() -> String {
    "eth0".into()
}
fn default_xdp_mode() -> String {
    "generic".into()
}
fn default_entropy_anomaly() -> u32 {
    common::ENTROPY_ANOMALY_THRESHOLD
}
fn default_true() -> bool {
    true
}
fn default_tarpit_port() -> u16 {
    common::TARPIT_PORT
}
fn default_base_delay() -> u64 {
    common::TARPIT_BASE_DELAY_MS
}
fn default_max_delay() -> u64 {
    common::TARPIT_MAX_DELAY_MS
}
fn default_jitter() -> u64 {
    common::TARPIT_JITTER_MS
}
fn default_ollama_url() -> String {
    "http://localhost:11434".into()
}
fn default_model() -> String {
    "qwen3:1.7b".into()
}
fn default_fallback_model() -> String {
    "qwen3:0.6b".into()
}
fn default_max_tokens() -> u32 {
    512
}
fn default_timeout_ms() -> u64 {
    5000
}
fn default_feed_refresh_secs() -> u64 {
    3600
}
fn default_feed_block_secs() -> u32 {
    3600
}
fn default_feed_sources() -> Vec<FeedSourceConfig> {
    vec![
        FeedSourceConfig {
            name: "firehol-level1".into(),
            url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset".into(),
            block_duration_secs: None,
        },
        FeedSourceConfig {
            name: "feodo-tracker".into(),
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".into(),
            block_duration_secs: None,
        },
    ]
}
fn default_pcap_dir() -> String {
    "/var/lib/blackwall/pcap".into()
}
fn default_pcap_max_size() -> u64 {
    100
}
fn default_pcap_max_files() -> usize {
    10
}
fn default_ssh_port() -> u16 {
    22
}
fn default_http_port() -> u16 {
    80
}
fn default_mysql_port() -> u16 {
    3306
}
fn default_dns_port() -> u16 {
    53
}
fn default_distributed_mode() -> String {
    "standalone".into()
}
fn default_peer_port() -> u16 {
    9471
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interface: default_interface(),
            xdp_mode: default_xdp_mode(),
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            entropy_anomaly: default_entropy_anomaly(),
        }
    }
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_tarpit_port(),
            base_delay_ms: default_base_delay(),
            max_delay_ms: default_max_delay(),
            jitter_ms: default_jitter(),
            services: DeceptionServicesConfig::default(),
        }
    }
}

impl Default for DeceptionServicesConfig {
    fn default() -> Self {
        Self {
            ssh_port: default_ssh_port(),
            http_port: default_http_port(),
            mysql_port: default_mysql_port(),
            dns_port: default_dns_port(),
        }
    }
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ollama_url: default_ollama_url(),
            model: default_model(),
            fallback_model: default_fallback_model(),
            max_tokens: default_max_tokens(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_interval_secs: default_feed_refresh_secs(),
            block_duration_secs: default_feed_block_secs(),
            sources: default_feed_sources(),
        }
    }
}

impl Default for PcapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output_dir: default_pcap_dir(),
            max_size_mb: default_pcap_max_size(),
            max_files: default_pcap_max_files(),
            compress_rotated: false,
        }
    }
}

impl Default for DistributedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_distributed_mode(),
            peers: Vec::new(),
            bind_port: default_peer_port(),
            node_id: String::new(),
            peer_psk: String::new(),
        }
    }
}

/// Load configuration from a TOML file.
pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
