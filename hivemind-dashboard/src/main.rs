//! HiveMind TUI Dashboard — live mesh monitoring via ANSI terminal.
//!
//! Zero external TUI deps — pure ANSI escape codes + tokio.
//! Polls the hivemind-api HTTP endpoint for stats and renders
//! a live-updating dashboard in the terminal.

use std::io::{self, Write};
use std::time::Duration;
use tokio::signal;
use tracing_subscriber::EnvFilter;

mod app;
mod collector;

use app::Dashboard;
use collector::Collector;

/// Default refresh interval in milliseconds.
const DEFAULT_REFRESH_MS: u64 = 1000;

/// Default API endpoint (hivemind-api default port).
const DEFAULT_API_URL: &str = "http://127.0.0.1:8090";

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let api_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());

    let refresh = Duration::from_millis(
        std::env::args()
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_REFRESH_MS),
    );

    let collector = Collector::new(&api_url);
    let mut dashboard = Dashboard::new();

    // Enter alternate screen + hide cursor
    print!("\x1B[?1049h\x1B[?25l");
    io::stdout().flush()?;

    let result = run_loop(&collector, &mut dashboard, refresh).await;

    // Restore terminal: show cursor + leave alternate screen
    print!("\x1B[?25h\x1B[?1049l");
    io::stdout().flush()?;

    result
}

async fn run_loop(
    collector: &Collector,
    dashboard: &mut Dashboard,
    refresh: Duration,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                break;
            }
            _ = tokio::time::sleep(refresh) => {
                let stats = collector.fetch().await;
                dashboard.update(stats);
                dashboard.render(&mut io::stdout())?;
            }
        }
    }
    Ok(())
}
