/// HTTP server with request routing and response formatting.
///
/// Implements a hyper 1.x HTTP server with manual path-based routing.
/// All endpoints require API key authentication via `Authorization: Bearer <key>`
/// header, except for the TAXII discovery endpoint.
///
/// # Endpoints
///
/// | Path | Description | Tier |
/// |------|-------------|------|
/// | `GET /taxii2/` | TAXII 2.1 API root discovery | Any |
/// | `GET /taxii2/collections/` | List TAXII collections | Enterprise+ |
/// | `GET /taxii2/collections/{id}/objects/` | STIX objects | Enterprise+ |
/// | `GET /api/v1/feed` | JSON feed of verified IoCs | Any |
/// | `GET /api/v1/feed/stix` | STIX 2.1 bundle | Enterprise+ |
/// | `GET /api/v1/feed/splunk` | Splunk HEC format | Enterprise+ |
/// | `GET /api/v1/feed/qradar` | QRadar LEEF format | Enterprise+ |
/// | `GET /api/v1/feed/cef` | CEF format | Enterprise+ |
/// | `GET /api/v1/stats` | Feed statistics | Any |
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use common::hivemind::{self, ApiTier};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::feed;
use crate::integrations::{cef, qradar, splunk};
use crate::licensing::{self, SharedLicenseManager};
use crate::stix;
use crate::store::SharedStore;

/// Live counters pushed by blackwall, hivemind, and enterprise daemons (optional)
/// via `POST /push`. Each daemon pushes only its own fields.
#[derive(Default)]
pub struct HivemindCounters {
    // eBPF/XDP counters (pushed by blackwall daemon)
    pub packets_total: AtomicU64,
    pub packets_passed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub anomalies_sent: AtomicU64,

    // P2P mesh counters (pushed by hivemind daemon)
    pub peer_count: AtomicU64,
    pub iocs_shared_p2p: AtomicU64,
    pub avg_reputation_x100: AtomicU64,
    pub messages_total: AtomicU64,

    // A2A counters (pushed by enterprise module when active)
    pub a2a_jwts_verified: AtomicU64,
    pub a2a_violations: AtomicU64,
    pub a2a_injections: AtomicU64,
}

pub type SharedCounters = Arc<HivemindCounters>;

/// Delta payload for `POST /push`.
///
/// All fields are optional so each daemon can push only its own counters
/// without zeroing out counters owned by other daemons.
#[derive(serde::Deserialize)]
struct CounterDelta {
    // eBPF counters (from blackwall)
    packets_total: Option<u64>,
    packets_passed: Option<u64>,
    packets_dropped: Option<u64>,
    anomalies_sent: Option<u64>,

    // P2P counters (from hivemind)
    peer_count: Option<u64>,
    iocs_shared_p2p: Option<u64>,
    avg_reputation_x100: Option<u64>,
    messages_total: Option<u64>,

    // A2A counters (from enterprise module)
    a2a_jwts_verified: Option<u64>,
    a2a_violations: Option<u64>,
    a2a_injections: Option<u64>,
}

/// Start the HTTP server and listen for connections.
///
/// This function runs forever (until the process is terminated).
/// Each incoming connection spawns a new task for HTTP/1.1 handling.
pub async fn run(
    addr: SocketAddr,
    store: SharedStore,
    licensing: SharedLicenseManager,
    counters: SharedCounters,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "Enterprise Threat Feed API listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let store = store.clone();
        let licensing = licensing.clone();
        let counters = counters.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let store = store.clone();
                let licensing = licensing.clone();
                let counters = counters.clone();
                async move { handle_request(req, store, licensing, counters, peer).await }
            });

            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                error!(peer = %peer, error = %e, "HTTP connection error");
            }
        });
    }
}

/// Route an HTTP request to the appropriate handler.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    store: SharedStore,
    licensing: SharedLicenseManager,
    counters: SharedCounters,
    peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());

    // Extract API key
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    let token = licensing::extract_bearer_token(auth_header);
    let had_token = token.is_some();

    // Validate API key
    let tier = match token {
        Some(key) => {
            let mgr = licensing
                .read()
                .expect("licensing lock not poisoned");
            mgr.validate(key)
        }
        None => None,
    };

    info!(
        %peer,
        %method,
        path = %path,
        authenticated = tier.is_some(),
        "Request received"
    );

    // Route based on method + path
    let response = match (&method, path.as_str()) {
        // TAXII 2.1 endpoints
        (&Method::GET, "/taxii2/") => handle_taxii_discovery(),

        (&Method::GET, "/taxii2/collections/") => {
            require_taxii(tier, had_token, handle_taxii_collections)
        }

        (&Method::GET, p) if is_taxii_objects_path(p) => {
            require_taxii(tier, had_token, || {
                let store = store
                    .read()
                    .expect("store lock not poisoned");
                let max_page = tier.map_or(50, |t| t.max_page_size());
                let params = feed::parse_query_params(query.as_deref(), max_page);
                let result = store.query(&params);
                let bundle = stix::build_bundle(&result.items);
                json_response(StatusCode::OK, hivemind::STIX_CONTENT_TYPE, &bundle)
            })
        }

        // Custom REST endpoints
        (&Method::GET, "/api/v1/feed") => {
            let effective_tier = tier.unwrap_or(ApiTier::Free);
            let store = store
                .read()
                .expect("store lock not poisoned");
            let params = feed::parse_query_params(
                query.as_deref(),
                effective_tier.max_page_size(),
            );
            let result = store.query(&params);
            json_response(StatusCode::OK, "application/json", &result)
        }

        (&Method::GET, "/api/v1/feed/stix") => {
            require_taxii(tier, had_token, || {
                let store = store
                    .read()
                    .expect("store lock not poisoned");
                let max_page = tier.map_or(50, |t| t.max_page_size());
                let params = feed::parse_query_params(query.as_deref(), max_page);
                let result = store.query(&params);
                let bundle = stix::build_bundle(&result.items);
                json_response(StatusCode::OK, hivemind::STIX_CONTENT_TYPE, &bundle)
            })
        }

        (&Method::GET, "/api/v1/feed/splunk") => {
            require_siem(tier, had_token, || {
                let store = store
                    .read()
                    .expect("store lock not poisoned");
                let max_page = tier.map_or(50, |t| t.max_page_size());
                let params = feed::parse_query_params(query.as_deref(), max_page);
                let result = store.query(&params);
                let events = splunk::batch_to_splunk(&result.items);
                json_response(StatusCode::OK, "application/json", &events)
            })
        }

        (&Method::GET, "/api/v1/feed/qradar") => {
            require_siem(tier, had_token, || {
                let store = store
                    .read()
                    .expect("store lock not poisoned");
                let max_page = tier.map_or(50, |t| t.max_page_size());
                let params = feed::parse_query_params(query.as_deref(), max_page);
                let result = store.query(&params);
                text_response(
                    StatusCode::OK,
                    "text/plain",
                    &qradar::batch_to_leef(&result.items),
                )
            })
        }

        (&Method::GET, "/api/v1/feed/cef") => {
            require_siem(tier, had_token, || {
                let store = store
                    .read()
                    .expect("store lock not poisoned");
                let max_page = tier.map_or(50, |t| t.max_page_size());
                let params = feed::parse_query_params(query.as_deref(), max_page);
                let result = store.query(&params);
                text_response(
                    StatusCode::OK,
                    "text/plain",
                    &cef::batch_to_cef(&result.items),
                )
            })
        }

        (&Method::GET, "/api/v1/stats") => {
            let store = store
                .read()
                .expect("store lock not poisoned");
            let stats = feed::compute_stats(&store);
            json_response(StatusCode::OK, "application/json", &stats)
        }

        // Dashboard mesh stats endpoint (no auth required)
        (&Method::GET, "/stats") => {
            let store = store
                .read()
                .expect("store lock not poisoned");
            let mesh = feed::compute_mesh_stats(&store, &counters);
            json_response(StatusCode::OK, "application/json", &mesh)
        }

        // Internal metrics push from blackwall daemon (localhost only)
        (&Method::POST, "/push") => {
            // SECURITY: only accept from loopback
            if !peer.ip().is_loopback() {
                warn!(%peer, "rejected /push from non-loopback");
                return Ok(error_response(StatusCode::FORBIDDEN, "Forbidden"));
            }
            let body_bytes = match req.collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => return Ok(error_response(StatusCode::BAD_REQUEST, "bad body")),
            };
            match serde_json::from_slice::<CounterDelta>(&body_bytes) {
                Ok(delta) => {
                    // eBPF counters (from blackwall)
                    if let Some(v) = delta.packets_total {
                        counters.packets_total.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.packets_passed {
                        counters.packets_passed.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.packets_dropped {
                        counters.packets_dropped.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.anomalies_sent {
                        counters.anomalies_sent.store(v, Ordering::Relaxed);
                    }
                    // P2P counters (from hivemind)
                    if let Some(v) = delta.peer_count {
                        counters.peer_count.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.iocs_shared_p2p {
                        counters.iocs_shared_p2p.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.avg_reputation_x100 {
                        counters.avg_reputation_x100.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.messages_total {
                        counters.messages_total.store(v, Ordering::Relaxed);
                    }
                    // A2A counters (from enterprise module)
                    if let Some(v) = delta.a2a_jwts_verified {
                        counters.a2a_jwts_verified.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.a2a_violations {
                        counters.a2a_violations.store(v, Ordering::Relaxed);
                    }
                    if let Some(v) = delta.a2a_injections {
                        counters.a2a_injections.store(v, Ordering::Relaxed);
                    }
                    json_response(StatusCode::OK, "application/json", &serde_json::json!({"ok": true}))
                }
                Err(e) => {
                    warn!(%e, "failed to parse /push payload");
                    error_response(StatusCode::BAD_REQUEST, "invalid JSON")
                }
            }
        }
        _ => {
            warn!(%method, path = %path, "Unknown endpoint");
            error_response(StatusCode::NOT_FOUND, "Not found")
        }
    };

    Ok(response)
}

// --- TAXII endpoint handlers ---

/// Handle TAXII 2.1 API root discovery (no auth required).
fn handle_taxii_discovery() -> Response<Full<Bytes>> {
    let discovery = stix::discovery_response();
    json_response(StatusCode::OK, hivemind::TAXII_CONTENT_TYPE, &discovery)
}

/// Handle TAXII 2.1 collection listing.
fn handle_taxii_collections() -> Response<Full<Bytes>> {
    let collections = vec![stix::default_collection()];
    let wrapper = serde_json::json!({ "collections": collections });
    json_response(StatusCode::OK, hivemind::TAXII_CONTENT_TYPE, &wrapper)
}

// --- Access control helpers ---

/// Require Enterprise+ tier for TAXII endpoints.
fn require_taxii<F>(tier: Option<ApiTier>, had_token: bool, f: F) -> Response<Full<Bytes>>
where
    F: FnOnce() -> Response<Full<Bytes>>,
{
    match tier {
        Some(t) if t.can_access_taxii() => f(),
        Some(_) => error_response(
            StatusCode::FORBIDDEN,
            "TAXII endpoints require Enterprise or NationalSecurity tier",
        ),
        None if had_token => error_response(
            StatusCode::UNAUTHORIZED,
            "Invalid API key",
        ),
        None => error_response(
            StatusCode::UNAUTHORIZED,
            "Authorization header with Bearer token required",
        ),
    }
}

/// Require Enterprise+ tier for SIEM integration endpoints.
fn require_siem<F>(tier: Option<ApiTier>, had_token: bool, f: F) -> Response<Full<Bytes>>
where
    F: FnOnce() -> Response<Full<Bytes>>,
{
    match tier {
        Some(t) if t.can_access_siem() => f(),
        Some(_) => error_response(
            StatusCode::FORBIDDEN,
            "SIEM integration endpoints require Enterprise or NationalSecurity tier",
        ),
        None if had_token => error_response(
            StatusCode::UNAUTHORIZED,
            "Invalid API key",
        ),
        None => error_response(
            StatusCode::UNAUTHORIZED,
            "Authorization header with Bearer token required",
        ),
    }
}

// --- Path matching ---

/// Check if a path matches the TAXII collection objects pattern.
///
/// Pattern: `/taxii2/collections/<id>/objects/`
fn is_taxii_objects_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/taxii2/collections/") else {
        return false;
    };
    rest.ends_with("/objects/") && rest.len() > "/objects/".len()
}

// --- Response builders ---

/// Build a JSON response with the given status and content type.
fn json_response<T: serde::Serialize>(
    status: StatusCode,
    content_type: &str,
    body: &T,
) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(body).unwrap_or_else(|e| {
        format!("{{\"error\":\"serialization failed: {e}\"}}")
    });
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("x-hivemind-version", hivemind::SIEM_VERSION)
        .body(Full::new(Bytes::from(json)))
        .expect("building response with valid parameters")
}

/// Build a plain-text response.
fn text_response(
    status: StatusCode,
    content_type: &str,
    body: &str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("x-hivemind-version", hivemind::SIEM_VERSION)
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("building response with valid parameters")
}

/// Build a JSON error response.
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": message,
        "status": status.as_u16(),
    });
    json_response(status, "application/json", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxii_objects_path_matching() {
        assert!(is_taxii_objects_path(
            "/taxii2/collections/hivemind-threat-feed-v1/objects/"
        ));
        assert!(!is_taxii_objects_path("/taxii2/collections/"));
        assert!(!is_taxii_objects_path("/taxii2/collections/objects/"));
        assert!(!is_taxii_objects_path("/api/v1/feed"));
    }

    #[test]
    fn error_response_format() {
        let resp = error_response(StatusCode::UNAUTHORIZED, "test error");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let ct = resp.headers().get("content-type").expect("has content-type");
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn json_response_has_version_header() {
        let resp = json_response(StatusCode::OK, "application/json", &"hello");
        let ver = resp
            .headers()
            .get("x-hivemind-version")
            .expect("has version");
        assert_eq!(ver, hivemind::SIEM_VERSION);
    }
}
