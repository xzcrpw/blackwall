mod antifingerprint;
mod canary;
mod jitter;
mod llm;
mod motd;
mod protocols;
mod sanitize;
mod session;

use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Maximum concurrent honeypot sessions.
const MAX_CONCURRENT_SESSIONS: usize = 100;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("tarpit=info")),
        )
        .init();

    tracing::info!("Tarpit honeypot starting");

    // Configuration (env vars or defaults)
    let bind_addr = std::env::var("TARPIT_BIND")
        .unwrap_or_else(|_| format!("127.0.0.1:{}", common::TARPIT_PORT));
    let ollama_url =
        std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".into());
    let model = std::env::var("TARPIT_MODEL").unwrap_or_else(|_| "llama3.2:3b".into());
    let fallback = std::env::var("TARPIT_FALLBACK_MODEL").unwrap_or_else(|_| "qwen3:1.7b".into());

    let ollama = Arc::new(llm::OllamaClient::new(ollama_url, model, fallback, 30_000));
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));

    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!(addr = %bind_addr, "listening for connections");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, addr) = accept?;
                let permit = semaphore.clone().acquire_owned().await?;
                let ollama = ollama.clone();

                tokio::spawn(async move {
                    tracing::info!(attacker = %addr, "new session");
                    if let Err(e) = handle_connection(stream, addr, &ollama).await {
                        tracing::debug!(attacker = %addr, "session error: {}", e);
                    }
                    drop(permit);
                });
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Route a connection to the appropriate protocol handler based on initial bytes.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    ollama: &llm::OllamaClient,
) -> anyhow::Result<()> {
    // Anti-fingerprinting: randomize TCP stack before any data exchange
    antifingerprint::randomize_tcp_options(&stream);
    // Anti-fingerprinting: random initial delay to prevent timing analysis
    antifingerprint::random_initial_delay().await;

    // Try to detect protocol from first bytes
    match protocols::detect_and_peek(&mut stream).await {
        Ok((protocols::IncomingProtocol::Http, _)) => {
            tracing::info!(attacker = %addr, protocol = "http", "routing to HTTP honeypot");
            protocols::handle_http_session(stream, addr).await
        }
        Ok((protocols::IncomingProtocol::Mysql, _)) => {
            tracing::info!(attacker = %addr, protocol = "mysql", "routing to MySQL honeypot");
            protocols::handle_mysql_session(stream, addr).await
        }
        Ok(_) => {
            // SSH or Unknown — default to bash simulation
            session::handle_session(stream, addr, ollama).await
        }
        Err(_) => {
            // Peek failed — default to bash simulation
            session::handle_session(stream, addr, ollama).await
        }
    }
}
