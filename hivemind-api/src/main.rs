/// HiveMind Enterprise Threat Feed API — entry point.
///
/// Starts the HTTP server with configured address, initializes the
/// in-memory IoC store and license manager, and serves threat feed
/// endpoints.
///
/// # Usage
///
/// ```sh
/// hivemind-api
/// ```
///
/// # Configuration
///
/// Currently reads from defaults. Production configuration will
/// come from a TOML file via the `common` crate config layer.
use std::net::SocketAddr;

use common::hivemind;
use tracing::info;
use tracing_subscriber::EnvFilter;

use hivemind_api::licensing::LicenseManager;
use hivemind_api::server::{self, HivemindCounters};
use hivemind_api::store::ThreatFeedStore;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .compact()
        .init();

    info!(
        version = hivemind::SIEM_VERSION,
        "Starting HiveMind Enterprise Threat Feed API"
    );

    // Initialize shared state
    let store = ThreatFeedStore::shared();
    let licensing = LicenseManager::shared();
    let counters = std::sync::Arc::new(HivemindCounters::default());

    // Load bootstrap API keys from environment (if any)
    // SECURITY: Keys from env vars, never hardcoded
    if let Ok(key) = std::env::var("HIVEMIND_API_KEY_ENTERPRISE") {
        licensing
            .write()
            .expect("licensing lock not poisoned")
            .register_key(&key, hivemind::ApiTier::Enterprise);
    }
    if let Ok(key) = std::env::var("HIVEMIND_API_KEY_NS") {
        licensing
            .write()
            .expect("licensing lock not poisoned")
            .register_key(&key, hivemind::ApiTier::NationalSecurity);
    }

    let addr = SocketAddr::from((
        hivemind::API_DEFAULT_ADDR
            .parse::<std::net::Ipv4Addr>()
            .expect("valid default bind address"),
        hivemind::API_DEFAULT_PORT,
    ));

    server::run(addr, store, licensing, counters).await
}
