//! Stats collector — polls hivemind-api for mesh statistics.

use serde::Deserialize;
use tracing::warn;

/// Collected mesh statistics for dashboard rendering.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MeshStats {
    /// Whether we're connected to the API.
    #[serde(default)]
    pub connected: bool,

    // P2P Mesh
    #[serde(default)]
    pub peer_count: u64,
    #[serde(default)]
    pub dht_records: u64,
    #[serde(default)]
    pub gossip_topics: u64,
    #[serde(default)]
    pub messages_per_sec: f64,

    // Threat Intel
    #[serde(default)]
    pub iocs_shared: u64,
    #[serde(default)]
    pub iocs_received: u64,
    #[serde(default)]
    pub avg_reputation: f64,

    // Network Firewall (XDP/eBPF)
    #[serde(default)]
    pub packets_total: u64,
    #[serde(default)]
    pub packets_passed: u64,
    #[serde(default)]
    pub packets_dropped: u64,
    #[serde(default)]
    pub anomalies_sent: u64,

    // A2A Firewall (separate counters)
    #[serde(default)]
    pub a2a_jwts_verified: u64,
    #[serde(default)]
    pub a2a_violations: u64,
    #[serde(default)]
    pub a2a_injections: u64,

    // Cryptography
    #[serde(default)]
    pub zkp_proofs_generated: u64,
    #[serde(default)]
    pub zkp_proofs_verified: u64,
    #[serde(default)]
    pub fhe_encrypted: bool,
}

/// HTTP collector that polls the hivemind-api stats endpoint.
pub struct Collector {
    url: String,
}

impl Collector {
    /// Create a new collector targeting the given base URL.
    pub fn new(base_url: &str) -> Self {
        Self {
            url: format!("{}/stats", base_url.trim_end_matches('/')),
        }
    }

    /// Fetch latest stats from the API.
    ///
    /// Returns default stats with `connected = false` on any error.
    pub async fn fetch(&self) -> MeshStats {
        match self.fetch_inner().await {
            Ok(mut stats) => {
                stats.connected = true;
                stats
            }
            Err(e) => {
                warn!(url = %self.url, error = %e, "failed to fetch mesh stats");
                MeshStats {
                    connected: false,
                    ..Default::default()
                }
            }
        }
    }

    async fn fetch_inner(&self) -> Result<MeshStats, Box<dyn std::error::Error>> {
        // Use a simple TCP connection + manual HTTP/1.1 request
        // to avoid pulling in heavy HTTP client deps.
        let url: hyper::Uri = self.url.parse()?;
        let host = url.host().unwrap_or("127.0.0.1");
        let port = url.port_u16().unwrap_or(9100);
        let path = url.path();

        let stream = tokio::net::TcpStream::connect(format!("{host}:{port}")).await?;
        let io = hyper_util::rt::TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!(error = %e, "HTTP connection error");
            }
        });

        let req = hyper::Request::builder()
            .uri(path)
            .header("Host", host)
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;

        let resp = sender.send_request(req).await?;

        use http_body_util::BodyExt;
        let body = resp.into_body().collect().await?.to_bytes();
        let stats: MeshStats = serde_json::from_slice(&body)?;
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stats_disconnected() {
        let stats = MeshStats::default();
        assert!(!stats.connected);
        assert_eq!(stats.peer_count, 0);
    }

    #[test]
    fn deserialize_partial_json() {
        let json = r#"{"peer_count": 42, "fhe_encrypted": true}"#;
        let stats: MeshStats = serde_json::from_str(json).expect("parse");
        assert_eq!(stats.peer_count, 42);
        assert!(stats.fhe_encrypted);
        assert_eq!(stats.a2a_jwts_verified, 0); // default
    }

    #[test]
    fn collector_url_construction() {
        let c1 = Collector::new("http://localhost:9100");
        assert_eq!(c1.url, "http://localhost:9100/stats");

        let c2 = Collector::new("http://localhost:9100/");
        assert_eq!(c2.url, "http://localhost:9100/stats");
    }
}
