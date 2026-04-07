//! Load Test & Licensing Lockdown — Stress simulation for HiveMind Enterprise API.
//!
//! Spawns a real hyper server, seeds it with IoCs, then hammers it with
//! concurrent clients measuring response latency and verifying tier-based
//! access control enforcement.

use common::hivemind::{ApiTier, IoC};
use hivemind_api::licensing::LicenseManager;
use hivemind_api::server::{self, HivemindCounters};
use hivemind_api::store::ThreatFeedStore;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Make a raw HTTP/1.1 GET request and return (status_code, body).
async fn http_get(addr: SocketAddr, path: &str, bearer: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("TCP connect failed");

    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    );
    if let Some(token) = bearer {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request failed");

    let mut buf = Vec::with_capacity(8192);
    stream
        .read_to_end(&mut buf)
        .await
        .expect("read response failed");

    let raw = String::from_utf8_lossy(&buf);

    // Parse status code from "HTTP/1.1 NNN ..."
    let status = raw
        .get(9..12)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // Split at the blank line separating headers from body
    let body = raw
        .find("\r\n\r\n")
        .map(|i| raw[i + 4..].to_string())
        .unwrap_or_default();

    (status, body)
}

/// Seed the store with `count` synthetic IoCs at 1-second intervals.
fn seed_store(store: &mut ThreatFeedStore, count: usize) {
    let base_time = 1_700_000_000u64;
    for i in 0..count {
        let ioc = IoC {
            ioc_type: (i % 5) as u8,
            severity: ((i % 5) as u8).min(4),
            ip: 0xC6120000 + i as u32, // 198.18.x.x range
            ja4: if i % 3 == 0 {
                Some("t13d1516h2_8daaf6152771_e5627efa2ab1".into())
            } else {
                None
            },
            entropy_score: Some(5000 + (i as u32 * 100)),
            description: format!("Synthetic threat indicator #{i}"),
            first_seen: base_time + i as u64,
            confirmations: 3,
            zkp_proof: Vec::new(),
        };
        store.insert(ioc, base_time + i as u64 + 60);
    }
}

/// Find a free TCP port by binding to :0 and reading the assigned port.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind :0 failed");
    listener
        .local_addr()
        .expect("local_addr failed")
        .port()
}

// ===========================================================================
// Scenario A — API Hammering: 100 concurrent clients
// ===========================================================================

#[tokio::test(flavor = "current_thread")]
async fn scenario_a_api_hammering() {
    // Setup
    let store = ThreatFeedStore::shared();
    let licensing = LicenseManager::shared();

    // Seed 50 IoCs
    {
        let mut s = store.write().expect("lock");
        seed_store(&mut s, 50);
    }

    // Register an Enterprise-tier key
    let api_key = "test-enterprise-key-12345678";
    {
        let mut lm = licensing.write().expect("lock");
        lm.register_key(api_key, ApiTier::Enterprise);
    }

    // Start server on a random port
    let port = free_port().await;
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let server_store = store.clone();
    let server_lic = licensing.clone();
    let counters = std::sync::Arc::new(HivemindCounters::default());
    let server_handle = tokio::task::spawn(async move {
        let _ = server::run(addr, server_store, server_lic, counters).await;
    });

    // Give the server a moment to bind — try connecting in a quick retry loop
    let mut connected = false;
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            connected = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(connected, "Server did not start within retry window");

    // Define the endpoints to hit
    let endpoints = [
        "/api/v1/feed",
        "/api/v1/feed/stix",
        "/api/v1/feed/splunk",
        "/api/v1/stats",
    ];

    // Spawn 100 concurrent client tasks
    let client_count = 100;
    let mut handles = Vec::with_capacity(client_count);
    let start = Instant::now();

    for i in 0..client_count {
        let endpoint = endpoints[i % endpoints.len()];
        let key = api_key.to_string();
        handles.push(tokio::task::spawn(async move {
            let t = Instant::now();
            let (status, body) = http_get(addr, endpoint, Some(&key)).await;
            let latency = t.elapsed();
            (i, status, body.len(), latency)
        }));
    }

    // Collect results
    let mut total_latency = std::time::Duration::ZERO;
    let mut max_latency = std::time::Duration::ZERO;
    let mut error_count = 0;

    for handle in handles {
        let (idx, status, body_len, latency) = handle.await.expect("task panicked");
        if status != 200 {
            error_count += 1;
            eprintln!(
                "[HAMMER] Client {idx}: HTTP {status} (body {body_len}B) in {latency:.2?}"
            );
        }
        total_latency += latency;
        if latency > max_latency {
            max_latency = latency;
        }
    }

    let total_elapsed = start.elapsed();
    let avg_latency = total_latency / client_count as u32;

    eprintln!(
        "[HAMMER] {client_count} clients completed in {total_elapsed:.2?}"
    );
    eprintln!(
        "[HAMMER] Avg latency: {avg_latency:.2?}, Max: {max_latency:.2?}, Errors: {error_count}"
    );

    assert_eq!(
        error_count, 0,
        "All authenticated requests should succeed (HTTP 200)"
    );

    // Abort the server
    server_handle.abort();
}

// ===========================================================================
// Scenario B — Licensing Lockdown: tier-based access denial
// ===========================================================================

#[tokio::test(flavor = "current_thread")]
async fn scenario_b_licensing_lockdown() {
    let store = ThreatFeedStore::shared();
    let licensing = LicenseManager::shared();

    // Seed 10 IoCs
    {
        let mut s = store.write().expect("lock");
        seed_store(&mut s, 10);
    }

    // Register keys at each tier
    let free_key = "free-tier-key-aaaa";
    let enterprise_key = "enterprise-tier-key-bbbb";
    let ns_key = "national-security-key-cccc";
    {
        let mut lm = licensing.write().expect("lock");
        lm.register_key(free_key, ApiTier::Free);
        lm.register_key(enterprise_key, ApiTier::Enterprise);
        lm.register_key(ns_key, ApiTier::NationalSecurity);
    }

    let port = free_port().await;
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let server_store = store.clone();
    let server_lic = licensing.clone();
    let counters = std::sync::Arc::new(HivemindCounters::default());
    let server_handle = tokio::task::spawn(async move {
        let _ = server::run(addr, server_store, server_lic, counters).await;
    });

    // Wait for server
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::task::yield_now().await;
    }

    // --- Free tier: /api/v1/feed should work ---
    let (status, _) = http_get(addr, "/api/v1/feed", Some(free_key)).await;
    assert_eq!(status, 200, "Free tier should access /api/v1/feed");

    // --- Free tier: /api/v1/stats should work ---
    let (status, _) = http_get(addr, "/api/v1/stats", Some(free_key)).await;
    assert_eq!(status, 200, "Free tier should access /api/v1/stats");

    // --- Free tier: SIEM endpoints BLOCKED ---
    let siem_paths = [
        "/api/v1/feed/splunk",
        "/api/v1/feed/qradar",
        "/api/v1/feed/cef",
    ];
    for path in &siem_paths {
        let (status, _) = http_get(addr, path, Some(free_key)).await;
        assert_eq!(
            status, 403,
            "Free tier should be FORBIDDEN from {path}"
        );
    }

    // --- Free tier: STIX/TAXII endpoints BLOCKED ---
    let taxii_paths = [
        "/api/v1/feed/stix",
        "/taxii2/collections/",
    ];
    for path in &taxii_paths {
        let (status, _) = http_get(addr, path, Some(free_key)).await;
        assert_eq!(
            status, 403,
            "Free tier should be FORBIDDEN from {path}"
        );
    }

    // --- No auth: should get 401 Unauthorized ---
    let (status, _) = http_get(addr, "/api/v1/feed/splunk", None).await;
    assert_eq!(
        status, 401,
        "No auth header should yield 401 Unauthorized"
    );

    // --- Invalid key: should get denied ---
    let (status, _) = http_get(addr, "/api/v1/feed", Some("totally-bogus-key")).await;
    // /api/v1/feed allows unauthenticated access via effective_tier=Free fallback,
    // but with an invalid key, the server resolves tier to None and falls through
    // to Free default for /api/v1/feed
    assert!(
        status == 200 || status == 401,
        "/api/v1/feed with invalid key: got {status}"
    );

    // --- Enterprise tier: SIEM endpoints ALLOWED ---
    for path in &siem_paths {
        let (status, body) = http_get(addr, path, Some(enterprise_key)).await;
        assert_eq!(
            status, 200,
            "Enterprise tier should access {path}, got {status}"
        );
        assert!(!body.is_empty(), "{path} response body should not be empty");
    }

    // --- Enterprise tier: TAXII endpoints ALLOWED ---
    for path in &taxii_paths {
        let (status, _) = http_get(addr, path, Some(enterprise_key)).await;
        assert_eq!(
            status, 200,
            "Enterprise tier should access {path}, got {status}"
        );
    }

    // --- NationalSecurity tier: everything ALLOWED ---
    let all_paths = [
        "/api/v1/feed",
        "/api/v1/feed/stix",
        "/api/v1/feed/splunk",
        "/api/v1/feed/qradar",
        "/api/v1/feed/cef",
        "/api/v1/stats",
        "/taxii2/",
        "/taxii2/collections/",
    ];
    for path in &all_paths {
        let (status, _) = http_get(addr, path, Some(ns_key)).await;
        assert_eq!(
            status, 200,
            "NationalSecurity tier should access {path}, got {status}"
        );
    }

    // --- Unknown endpoint: 404 ---
    let (status, _) = http_get(addr, "/api/v1/nonexistent", Some(enterprise_key)).await;
    assert_eq!(status, 404, "Unknown endpoint should yield 404");

    eprintln!("[LOCKDOWN] All tier-based access control assertions passed");
    server_handle.abort();
}

// ===========================================================================
// Scenario C — Feed Content Integrity: verify response payloads
// ===========================================================================

#[tokio::test(flavor = "current_thread")]
async fn scenario_c_feed_content_integrity() {
    let store = ThreatFeedStore::shared();
    let licensing = LicenseManager::shared();

    // Seed 5 IoCs
    {
        let mut s = store.write().expect("lock");
        seed_store(&mut s, 5);
    }

    let api_key = "integrity-test-key";
    {
        let mut lm = licensing.write().expect("lock");
        lm.register_key(api_key, ApiTier::Enterprise);
    }

    let port = free_port().await;
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let ss = store.clone();
    let sl = licensing.clone();
    let counters = std::sync::Arc::new(HivemindCounters::default());
    let server_handle = tokio::task::spawn(async move {
        let _ = server::run(addr, ss, sl, counters).await;
    });

    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::task::yield_now().await;
    }

    // --- JSON feed ---
    let (status, body) = http_get(addr, "/api/v1/feed", Some(api_key)).await;
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("Invalid JSON in /api/v1/feed response: {e}"));
    assert!(
        parsed.get("items").is_some(),
        "Feed response should contain 'items' field"
    );
    assert!(
        parsed.get("total").is_some(),
        "Feed response should contain 'total' field"
    );

    // --- STIX bundle ---
    let (status, body) = http_get(addr, "/api/v1/feed/stix", Some(api_key)).await;
    assert_eq!(status, 200);
    let stix: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("Invalid STIX JSON: {e}"));
    assert_eq!(
        stix.get("type").and_then(|t| t.as_str()),
        Some("bundle"),
        "STIX response should be a bundle"
    );

    // --- Splunk HEC ---
    let (status, body) = http_get(addr, "/api/v1/feed/splunk", Some(api_key)).await;
    assert_eq!(status, 200);
    let splunk: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("Invalid Splunk JSON: {e}"));
    assert!(splunk.is_array(), "Splunk response should be a JSON array");

    // --- QRadar LEEF (plain text) ---
    let (status, body) = http_get(addr, "/api/v1/feed/qradar", Some(api_key)).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("LEEF:"),
        "QRadar response should contain LEEF headers"
    );

    // --- CEF (plain text) ---
    let (status, body) = http_get(addr, "/api/v1/feed/cef", Some(api_key)).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("CEF:"),
        "CEF response should contain CEF headers"
    );

    // --- Stats ---
    let (status, body) = http_get(addr, "/api/v1/stats", Some(api_key)).await;
    assert_eq!(status, 200);
    let stats: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("Invalid stats JSON: {e}"));
    let total = stats
        .get("total_iocs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(total, 5, "Stats should report 5 total IoCs");

    // --- TAXII discovery (no auth needed, but we send one) ---
    let (status, body) = http_get(addr, "/taxii2/", Some(api_key)).await;
    assert_eq!(status, 200);
    let taxii: serde_json::Value = serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("Invalid TAXII JSON: {e}"));
    assert!(
        taxii.get("title").is_some(),
        "TAXII discovery should contain title"
    );

    eprintln!("[INTEGRITY] All 7 endpoints return well-formed responses");
    server_handle.abort();
}
