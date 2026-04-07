//! Metrics bridge — pushes P2P mesh stats to hivemind-api.
//!
//! Periodically POSTs peer_count, iocs_shared, avg_reputation, and
//! messages_total to the hivemind-api `/push` endpoint so the TUI
//! dashboard can display live P2P mesh status.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::debug;

const HIVEMIND_API_PUSH: &str = "http://127.0.0.1:8090/push";

/// Shared P2P metrics tracked by the event loop and pushed periodically.
#[derive(Default)]
pub struct P2pMetrics {
    pub peer_count: AtomicU64,
    pub iocs_shared: AtomicU64,
    pub avg_reputation_x100: AtomicU64,
    pub messages_total: AtomicU64,
}

pub type SharedP2pMetrics = Arc<P2pMetrics>;

/// Push current P2P metrics to hivemind-api.
///
/// Fire-and-forget: logs on failure, never panics.
pub async fn push_p2p_metrics(metrics: &P2pMetrics) {
    let peers = metrics.peer_count.load(Ordering::Relaxed);
    let iocs = metrics.iocs_shared.load(Ordering::Relaxed);
    let rep = metrics.avg_reputation_x100.load(Ordering::Relaxed);
    let msgs = metrics.messages_total.load(Ordering::Relaxed);

    let body = format!(
        r#"{{"peer_count":{peers},"iocs_shared_p2p":{iocs},"avg_reputation_x100":{rep},"messages_total":{msgs}}}"#
    );

    let result = async {
        let stream = tokio::net::TcpStream::connect("127.0.0.1:8090").await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "hivemind-api push connection dropped");
            }
        });
        let req = Request::builder()
            .method("POST")
            .uri(HIVEMIND_API_PUSH)
            .header("content-type", "application/json")
            .header("host", "127.0.0.1")
            .body(Full::new(Bytes::from(body)))?;
        sender.send_request(req).await?;
        anyhow::Ok(())
    }
    .await;

    if let Err(e) = result {
        debug!(error = %e, "failed to push P2P metrics to hivemind-api");
    }
}
