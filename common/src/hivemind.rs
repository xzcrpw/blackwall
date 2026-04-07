//! HiveMind Threat Mesh — shared types for P2P threat intelligence.
//!
//! These types are used by both the hivemind daemon and potentially
//! by eBPF programs that feed threat data into the mesh.

/// Maximum length of a JA4 fingerprint string (e.g., "t13d1516h2_8daaf6152771_e5627efa2ab1").
pub const JA4_FINGERPRINT_LEN: usize = 36;

/// Maximum length of a threat description.
pub const THREAT_DESC_LEN: usize = 128;

/// Maximum bootstrap nodes in configuration.
pub const MAX_BOOTSTRAP_NODES: usize = 16;

/// Default GossipSub fan-out.
pub const GOSSIPSUB_FANOUT: usize = 10;

/// Default GossipSub heartbeat interval in seconds.
pub const GOSSIPSUB_HEARTBEAT_SECS: u64 = 1;

/// Default Kademlia query timeout in seconds.
pub const KADEMLIA_QUERY_TIMEOUT_SECS: u64 = 60;

/// Maximum GossipSub message size (64 KB).
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// GossipSub message deduplication TTL in seconds.
pub const MESSAGE_DEDUP_TTL_SECS: u64 = 120;

/// Kademlia k-bucket size.
pub const K_BUCKET_SIZE: usize = 20;

/// Severity level of a threat indicator.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThreatSeverity {
    /// Informational — low confidence or low impact.
    Info = 0,
    /// Low — minor scanning or recon activity.
    Low = 1,
    /// Medium — active probing or known-bad pattern.
    Medium = 2,
    /// High — confirmed malicious with high confidence.
    High = 3,
    /// Critical — active exploitation or C2 communication.
    Critical = 4,
}

impl ThreatSeverity {
    /// Convert raw u8 to ThreatSeverity.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => ThreatSeverity::Info,
            1 => ThreatSeverity::Low,
            2 => ThreatSeverity::Medium,
            3 => ThreatSeverity::High,
            4 => ThreatSeverity::Critical,
            _ => ThreatSeverity::Info,
        }
    }
}

/// Type of Indicator of Compromise.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoCType {
    /// IPv4 address associated with malicious activity.
    MaliciousIp = 0,
    /// JA4 TLS fingerprint of known malware/tool.
    Ja4Fingerprint = 1,
    /// High-entropy payload pattern (encrypted C2, exfil).
    EntropyAnomaly = 2,
    /// DNS tunneling indicator.
    DnsTunnel = 3,
    /// Behavioral pattern (port scan, brute force).
    BehavioralPattern = 4,
}

impl IoCType {
    /// Convert raw u8 to IoCType.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => IoCType::MaliciousIp,
            1 => IoCType::Ja4Fingerprint,
            2 => IoCType::EntropyAnomaly,
            3 => IoCType::DnsTunnel,
            4 => IoCType::BehavioralPattern,
            _ => IoCType::MaliciousIp,
        }
    }
}

/// Indicator of Compromise — the core unit of threat intelligence shared
/// across the HiveMind mesh. Designed for GossipSub transmission.
///
/// This is a userspace-only type (not eBPF), so we use std types freely.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IoC {
    /// Type of indicator.
    pub ioc_type: u8,
    /// Severity level.
    pub severity: u8,
    /// IPv4 address (if applicable, 0 otherwise).
    pub ip: u32,
    /// JA4 fingerprint string (if applicable).
    pub ja4: Option<String>,
    /// Byte diversity score (unique_count × 31, if applicable).
    pub entropy_score: Option<u32>,
    /// Human-readable description.
    pub description: String,
    /// Unix timestamp when this IoC was first observed.
    pub first_seen: u64,
    /// Number of independent peers that confirmed this IoC.
    pub confirmations: u32,
    /// ZKP proof blob (empty until Phase 1 implementation).
    pub zkp_proof: Vec<u8>,
}

/// A threat report broadcast via GossipSub. Contains one or more IoCs
/// from a single reporting node.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ThreatReport {
    /// Unique report ID (UUID v4 bytes).
    pub report_id: [u8; 16],
    /// Reporter's Ed25519 public key (32 bytes).
    pub reporter_pubkey: [u8; 32],
    /// Unix timestamp of the report.
    pub timestamp: u64,
    /// List of IoCs in this report.
    pub indicators: Vec<IoC>,
    /// Ed25519 signature over the serialized indicators.
    pub signature: Vec<u8>,
}

/// GossipSub topic identifiers for HiveMind.
pub mod topics {
    /// IoC broadcast topic — new threat indicators.
    pub const IOC_TOPIC: &str = "hivemind/ioc/v1";
    /// JA4 fingerprint sharing topic.
    pub const JA4_TOPIC: &str = "hivemind/ja4/v1";
    /// Federated learning gradient exchange topic.
    pub const GRADIENT_TOPIC: &str = "hivemind/federated/gradients/v1";
    /// Peer heartbeat / presence topic.
    pub const HEARTBEAT_TOPIC: &str = "hivemind/heartbeat/v1";
    /// A2A violation proof sharing topic.
    pub const A2A_VIOLATIONS_TOPIC: &str = "hivemind/a2a-violations/v1";
}

/// Port for local proof ingestion IPC (enterprise module → hivemind).
///
/// Hivemind listens on `127.0.0.1:PROOF_INGEST_PORT` for length-prefixed
/// proof envelopes from the enterprise daemon (optional) on the same machine.
pub const PROOF_INGEST_PORT: u16 = 9821;

/// Port for local IoC injection (testing/integration).
///
/// Hivemind listens on `127.0.0.1:IOC_INJECT_PORT` for length-prefixed
/// IoC JSON payloads. The injected IoC is published to GossipSub and
/// submitted to local consensus with the node's own pubkey.
pub const IOC_INJECT_PORT: u16 = 9822;

// --- Phase 1: Anti-Poisoning Constants ---

/// Initial reputation stake for new peers.
///
/// Set BELOW MIN_TRUSTED_REPUTATION so new peers must earn trust through
/// accurate reports before participating in consensus. Prevents Sybil
/// attacks where fresh peers immediately inject false IoCs.
pub const INITIAL_STAKE: u64 = 30;

/// Minimum reputation score to be considered trusted.
pub const MIN_TRUSTED_REPUTATION: u64 = 50;

/// Initial reputation stake for explicitly configured seed peers.
/// Seed peers start trusted to bootstrap the consensus network.
pub const SEED_PEER_STAKE: u64 = 100;

/// Slashing penalty for submitting a false IoC (% of stake).
pub const SLASHING_PENALTY_PERCENT: u64 = 25;

/// Reward for accurate IoC report (stake units).
pub const ACCURACY_REWARD: u64 = 5;

/// Minimum independent peer confirmations to accept an IoC.
pub const CROSS_VALIDATION_THRESHOLD: usize = 3;

/// Time window (seconds) for pending IoC cross-validation before expiry.
pub const CONSENSUS_TIMEOUT_SECS: u64 = 300;

/// Proof-of-Work difficulty for new peer registration (leading zero bits).
pub const POW_DIFFICULTY_BITS: u32 = 20;

/// Maximum new peer registrations per minute (rate limit).
pub const MAX_PEER_REGISTRATIONS_PER_MINUTE: usize = 10;

/// PoW challenge freshness window (seconds).
pub const POW_CHALLENGE_TTL_SECS: u64 = 120;

// --- Phase 1: ZKP Stub Types ---

/// A zero-knowledge proof that a threat was observed without revealing
/// raw packet data. Stub type for Phase 0-1 interface stability.
///
/// In future phases, this will contain a bellman/arkworks SNARK proof.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ThreatProof {
    /// Version of the proof format (for forward compatibility).
    pub version: u8,
    /// The statement being proven (what claims are made).
    pub statement: ProofStatement,
    /// Opaque proof bytes. Empty = stub, non-empty = real SNARK proof.
    pub proof_data: Vec<u8>,
    /// Unix timestamp when proof was generated.
    pub created_at: u64,
}

/// What a ZKP proof claims to demonstrate, without revealing private inputs.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofStatement {
    /// JA4 fingerprint hash that was matched (public output).
    pub ja4_hash: Option<[u8; 32]>,
    /// Whether entropy exceeded the anomaly threshold (public output).
    pub entropy_exceeded: bool,
    /// Whether the behavioral classifier labeled this as malicious.
    pub classified_malicious: bool,
    /// IoC type this proof covers.
    pub ioc_type: u8,
}

/// Proof-of-Work challenge for Sybil resistance.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PowChallenge {
    /// The peer's public key (32 bytes Ed25519).
    pub peer_pubkey: [u8; 32],
    /// Nonce found by the peer that satisfies difficulty.
    pub nonce: u64,
    /// Timestamp when the PoW was computed.
    pub timestamp: u64,
    /// Difficulty in leading zero bits.
    pub difficulty: u32,
}

/// Peer reputation record shared across the mesh.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerReputationRecord {
    /// Ed25519 public key of the peer (32 bytes).
    pub peer_pubkey: [u8; 32],
    /// Current stake (starts at INITIAL_STAKE).
    pub stake: u64,
    /// Cumulative accuracy score (accurate reports).
    pub accurate_reports: u64,
    /// Count of false positives flagged by consensus.
    pub false_reports: u64,
    /// Unix timestamp of last activity.
    pub last_active: u64,
}

// --- Phase 2: Federated Learning Constants ---

/// Interval between federated learning aggregation rounds (seconds).
pub const FL_ROUND_INTERVAL_SECS: u64 = 60;

/// Minimum peers required to run an aggregation round.
pub const FL_MIN_PEERS_PER_ROUND: usize = 3;

/// Maximum serialized gradient payload size (bytes). 16 KB.
pub const FL_MAX_GRADIENT_SIZE: usize = 16384;

/// Percentage of extreme values to trim in Byzantine-resistant FedAvg.
/// Trims top and bottom 20% of gradient contributions per dimension.
pub const FL_BYZANTINE_TRIM_PERCENT: usize = 20;

/// Feature vector dimension for the local NIDS model.
pub const FL_FEATURE_DIM: usize = 32;

/// Hidden layer size for the local NIDS model.
pub const FL_HIDDEN_DIM: usize = 16;

/// Z-score threshold × 1000 for gradient anomaly detection.
/// Value of 3000 means z-score > 3.0 triggers alarm.
pub const GRADIENT_ANOMALY_ZSCORE_THRESHOLD: u64 = 3000;

/// Maximum gradient norm (squared, integer) before rejection.
/// Prevents gradient explosion attacks.
pub const FL_MAX_GRADIENT_NORM_SQ: u64 = 1_000_000;

// --- Phase 2: Federated Learning Types ---

/// Encrypted gradient update broadcast via GossipSub.
///
/// Privacy invariant: raw gradients NEVER leave the node.
/// Only FHE-encrypted ciphertext is transmitted.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GradientUpdate {
    /// Reporter's Ed25519 public key (32 bytes).
    pub peer_pubkey: [u8; 32],
    /// Aggregation round identifier.
    pub round_id: u64,
    /// FHE-encrypted gradient payload. Raw gradients NEVER transmitted.
    pub encrypted_gradients: Vec<u8>,
    /// Unix timestamp of gradient computation.
    pub timestamp: u64,
}

/// Result of a federated aggregation round.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AggregatedModel {
    /// Aggregation round identifier.
    pub round_id: u64,
    /// Aggregated model weights (after FedAvg).
    pub weights: Vec<f32>,
    /// Number of peers that contributed to this round.
    pub participant_count: usize,
    /// Unix timestamp of aggregation completion.
    pub timestamp: u64,
}

// --- Phase 3: Enterprise Threat Feed Constants ---

/// Default HTTP port for the Enterprise Threat Feed API.
///
/// Uses 8090 (not 8443) because all traffic is plaintext HTTP on loopback.
/// Port 8443 conventionally implies HTTPS and would be misleading.
pub const API_DEFAULT_PORT: u16 = 8090;

/// Default API listen address.
pub const API_DEFAULT_ADDR: &str = "127.0.0.1";

/// Maximum IoCs returned per API request.
pub const API_MAX_PAGE_SIZE: usize = 1000;

/// Default IoCs per page in API responses.
pub const API_DEFAULT_PAGE_SIZE: usize = 100;

/// API key length in bytes (hex-encoded = 64 chars).
pub const API_KEY_LENGTH: usize = 32;

/// TAXII 2.1 content type header value.
pub const TAXII_CONTENT_TYPE: &str = "application/taxii+json;version=2.1";

/// STIX 2.1 content type header value.
pub const STIX_CONTENT_TYPE: &str = "application/stix+json;version=2.1";

/// TAXII collection ID for the primary threat feed.
pub const TAXII_COLLECTION_ID: &str = "hivemind-threat-feed-v1";

/// TAXII collection title.
pub const TAXII_COLLECTION_TITLE: &str = "HiveMind Verified Threat Feed";

/// STIX spec version.
pub const STIX_SPEC_VERSION: &str = "2.1";

/// Product vendor name for SIEM formats.
pub const SIEM_VENDOR: &str = "Blackwall";

/// Product name for SIEM formats.
pub const SIEM_PRODUCT: &str = "HiveMind";

/// Product version for SIEM formats.
pub const SIEM_VERSION: &str = "1.0";

/// Splunk sourcetype for HiveMind events.
pub const SPLUNK_SOURCETYPE: &str = "hivemind:threat_feed";

// --- Phase 3: Enterprise API Tier Types ---

/// API access tier determining rate limits and format availability.
#[cfg(feature = "user")]
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApiTier {
    /// Free tier: JSON feed, limited page size.
    Free,
    /// Enterprise tier: all formats, full page size, STIX/TAXII.
    Enterprise,
    /// National security tier: full access + macro-analytics.
    NationalSecurity,
}

#[cfg(feature = "user")]
impl ApiTier {
    /// Maximum page size allowed for this tier.
    pub fn max_page_size(self) -> usize {
        match self {
            ApiTier::Free => 50,
            ApiTier::Enterprise => API_MAX_PAGE_SIZE,
            ApiTier::NationalSecurity => API_MAX_PAGE_SIZE,
        }
    }

    /// Whether this tier can access SIEM integration formats.
    pub fn can_access_siem(self) -> bool {
        matches!(self, ApiTier::Enterprise | ApiTier::NationalSecurity)
    }

    /// Whether this tier can access STIX/TAXII endpoints.
    pub fn can_access_taxii(self) -> bool {
        matches!(self, ApiTier::Enterprise | ApiTier::NationalSecurity)
    }
}
