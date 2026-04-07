use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{antifingerprint, jitter, llm, motd, sanitize};

const MAX_HISTORY: usize = 20;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Minimum interval between LLM queries per session (rate limit).
const MIN_QUERY_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum commands per session before forceful disconnect.
const MAX_COMMANDS_PER_SESSION: u32 = 500;

/// Per-attacker session state.
pub struct Session {
    addr: SocketAddr,
    pub command_count: u32,
    started_at: Instant,
    last_query: Instant,
    cwd: String,
    username: String,
    hostname: String,
    history: Vec<String>,
}

impl Session {
    /// Create a new session for an incoming connection.
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            addr,
            command_count: 0,
            started_at: now,
            // Allow the first command immediately by backdating last_query
            last_query: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
            cwd: "/root".into(),
            username: "root".into(),
            hostname: "web-prod-03".into(),
            history: Vec::new(),
        }
    }

    /// Source address for logging.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Check and enforce rate limit. Returns true if the query is allowed.
    pub fn rate_limit_check(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_query) < MIN_QUERY_INTERVAL {
            return false;
        }
        self.last_query = now;
        true
    }

    /// Generate the fake bash prompt string.
    pub fn prompt(&self) -> String {
        format!("{}@{}:{}# ", self.username, self.hostname, self.cwd)
    }

    /// Record a command in history (bounded).
    pub fn push_command(&mut self, cmd: &str) {
        if self.history.len() >= MAX_HISTORY {
            self.history.remove(0);
        }
        self.history.push(cmd.to_string());
    }

    /// Access command history (for LLM context).
    pub fn history(&self) -> &[String] {
        &self.history
    }
}

/// Handle a single attacker session from connect to disconnect.
pub async fn handle_session(
    mut stream: TcpStream,
    addr: SocketAddr,
    ollama: &llm::OllamaClient,
) -> anyhow::Result<()> {
    let mut session = Session::new(addr);

    // 1. Send MOTD
    let motd = motd::generate_motd();
    stream.write_all(motd.as_bytes()).await?;

    // 2. Send initial prompt
    stream.write_all(session.prompt().as_bytes()).await?;

    // 3. Command loop
    let mut buf = [0u8; 1024];
    loop {
        let n = match tokio::time::timeout(IDLE_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tracing::debug!(attacker = %session.addr(), "read error: {}", e);
                break;
            }
            Err(_) => {
                tracing::debug!(attacker = %session.addr(), "idle timeout");
                break;
            }
        };

        if n == 0 {
            break; // Connection closed
        }

        let input = sanitize::clean_input(&buf[..n]);
        if input.is_empty() {
            stream.write_all(session.prompt().as_bytes()).await?;
            continue;
        }

        // Log attacker input for forensics
        tracing::info!(
            attacker_ip = %session.addr().ip(),
            command = %input,
            cmd_num = session.command_count,
            "attacker_command"
        );

        // Enforce per-session command limit
        if session.command_count >= MAX_COMMANDS_PER_SESSION {
            tracing::info!(attacker_ip = %session.addr().ip(), "max command limit reached, disconnecting");
            break;
        }

        // Rate-limit LLM queries
        let normalized = sanitize::normalize_to_ascii(&input);
        let response = if antifingerprint::detect_prompt_injection(&normalized) {
            // Prompt injection detected — return decoy response, never forward to LLM
            tracing::warn!(
                attacker_ip = %session.addr().ip(),
                command = %input,
                "prompt injection attempt detected"
            );
            antifingerprint::injection_decoy_response(&input)
        } else if session.rate_limit_check() {
            // Defense-in-depth: scrub injection phrases before LLM even if
            // detect_prompt_injection didn't fire (novel bypass variants)
            let scrubbed = sanitize::sanitize_for_llm(&input);
            match ollama.query(&session, &scrubbed).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(attacker_ip = %session.addr().ip(), error = %e, "LLM query failed");
                    format!(
                        "bash: {}: command not found\n",
                        input.split_whitespace().next().unwrap_or("")
                    )
                }
            }
        } else {
            tracing::debug!(attacker_ip = %session.addr().ip(), "rate limited");
            // Rate limited — return a plausible slow response
            tokio::time::sleep(Duration::from_millis(200)).await;
            format!(
                "bash: {}: command not found\n",
                input.split_whitespace().next().unwrap_or("")
            )
        };

        // Stream response with tarpit jitter
        jitter::stream_with_tarpit(&mut stream, &response).await?;

        // Ensure response ends with newline
        if !response.ends_with('\n') {
            stream.write_all(b"\n").await?;
        }

        // Update session state
        session.push_command(&input);
        session.command_count += 1;

        // Send next prompt
        stream.write_all(session.prompt().as_bytes()).await?;
    }

    tracing::info!(
        attacker_ip = %session.addr().ip(),
        commands = session.command_count,
        duration_secs = session.started_at.elapsed().as_secs(),
        "session ended"
    );
    Ok(())
}
