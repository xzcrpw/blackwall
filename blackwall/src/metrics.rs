use anyhow::Result;
use aya::maps::{MapData, PerCpuArray};
use common::Counters;
use std::time::Duration;

/// Periodically read eBPF COUNTERS (sum across CPUs) and log via tracing.
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
    }
}
