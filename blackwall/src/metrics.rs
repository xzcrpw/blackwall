use anyhow::Result;
use aya::maps::{MapData, PerCpuArray};
use common::Counters;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::time::Duration;

const HIVEMIND_PUSH_URL: &str = "http://127.0.0.1:8090/push";

/// Periodically read eBPF COUNTERS (sum across CPUs), log via tracing,
/// and push the latest values to hivemind-api for the live dashboard.
pub async fn metrics_tick(
    counters: PerCpuArray<MapData, Counters>,
    interval_secs: u64,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        let values = match counters.get(&0, 0) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("failed to read counters: {}", e);
                continue;
            }
        };

        let total = values.iter().fold(
            Counters {
                packets_total: 0,
                packets_passed: 0,
                packets_dropped: 0,
                anomalies_sent: 0,
            },
            |acc, c| Counters {
                packets_total: acc.packets_total + c.packets_total,
                packets_passed: acc.packets_passed + c.packets_passed,
                packets_dropped: acc.packets_dropped + c.packets_dropped,
                anomalies_sent: acc.anomalies_sent + c.anomalies_sent,
            },
        );

        tracing::info!(
            total = total.packets_total,
            passed = total.packets_passed,
            dropped = total.packets_dropped,
            anomalies = total.anomalies_sent,
            "counters"
        );

        // Push live metrics to hivemind-api dashboard
        push_to_hivemind(
            total.packets_total,
            total.packets_passed,
            total.packets_dropped,
            total.anomalies_sent,
        )
        .await;
    }
}

/// Fire-and-forget push of current eBPF counter totals to hivemind-api.
async fn push_to_hivemind(
    packets_total: u64,
    packets_passed: u64,
    packets_dropped: u64,
    anomalies_sent: u64,
) {
    let body = format!(
        r#"{{"packets_total":{packets_total},"packets_passed":{packets_passed},"packets_dropped":{packets_dropped},"anomalies_sent":{anomalies_sent}}}"#
    );
    let result = async {
        let stream = tokio::net::TcpStream::connect("127.0.0.1:8090").await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "hivemind-api push connection dropped");
            }
        });
        let req = Request::builder()
            .method("POST")
            .uri(HIVEMIND_PUSH_URL)
            .header("content-type", "application/json")
            .header("host", "127.0.0.1")
            .body(Full::new(Bytes::from(body)))?;
        sender.send_request(req).await?;
        anyhow::Ok(())
    }
    .await;
    if let Err(e) = result {
        tracing::debug!(error = %e, "failed to push metrics to hivemind-api (daemon may not be running)");
    }
}
