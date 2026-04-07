use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Instant;

/// Max iptables fork/exec calls per second to prevent resource exhaustion
/// under DDoS. Excess IPs are queued and applied via `iptables-restore` batch.
const MAX_INDIVIDUAL_OPS_PER_SEC: u32 = 10;

/// Manages iptables DNAT rules to redirect attacker traffic to the tarpit.
///
/// # Deprecation
/// **V2.0**: eBPF native DNAT via TARPIT_TARGET map replaces iptables.
/// This manager is retained as a legacy fallback for systems where XDP
/// header rewriting is not available (e.g., HW offload without TC support).
/// New deployments should use eBPF DNAT exclusively.
///
/// # Performance
/// Individual `redirect_to_tarpit` calls use fork/exec (fine at low rate).
/// Under DDoS, callers should use `redirect_batch` or call `flush_pending`
/// periodically — these use `iptables-restore --noflush` (single fork for N rules).
#[deprecated(note = "V2.0: eBPF native DNAT replaces iptables. Retained as legacy fallback.")]
pub struct FirewallManager {
    active_redirects: HashSet<Ipv4Addr>,
    /// IPs awaiting batch insertion (rate-limit overflow).
    pending_redirects: Vec<Ipv4Addr>,
    tarpit_port: u16,
    /// Rate limiter: ops performed in the current second.
    ops_this_window: u32,
    /// Start of the current rate-limit window.
    window_start: Instant,
}

impl FirewallManager {
    /// Create a new FirewallManager targeting the given tarpit port.
    pub fn new(tarpit_port: u16) -> Self {
        Self {
            active_redirects: HashSet::new(),
            pending_redirects: Vec::new(),
            tarpit_port,
            ops_this_window: 0,
            window_start: Instant::now(),
        }
    }

    /// Reset the rate-limit window if a second has elapsed.
    fn maybe_reset_window(&mut self) {
        if self.window_start.elapsed().as_secs() >= 1 {
            self.ops_this_window = 0;
            self.window_start = Instant::now();
        }
    }

    /// Add a DNAT rule to redirect all TCP traffic from `ip` to the tarpit.
    ///
    /// If the per-second rate limit is exceeded, the IP is queued for batch
    /// insertion via `flush_pending()`.
    pub fn redirect_to_tarpit(&mut self, ip: Ipv4Addr) -> Result<()> {
        if self.active_redirects.contains(&ip) {
            return Ok(());
        }

        self.maybe_reset_window();

        if self.ops_this_window >= MAX_INDIVIDUAL_OPS_PER_SEC {
            // Rate limit hit — queue for batch insertion
            if !self.pending_redirects.contains(&ip) {
                self.pending_redirects.push(ip);
                tracing::debug!(%ip, pending = self.pending_redirects.len(),
                    "DNAT queued (rate limit)");
            }
            return Ok(());
        }

        self.apply_single_redirect(ip)?;
        self.ops_this_window += 1;
        Ok(())
    }

    /// Apply a single iptables DNAT rule via fork/exec.
    fn apply_single_redirect(&mut self, ip: Ipv4Addr) -> Result<()> {
        let dest = format!("127.0.0.1:{}", self.tarpit_port);
        let status = Command::new("iptables")
            .args([
                "-t", "nat", "-A", "PREROUTING",
                "-s", &ip.to_string(),
                "-p", "tcp",
                "-j", "DNAT",
                "--to-destination", &dest,
            ])
            .status()
            .context("failed to execute iptables")?;

        if !status.success() {
            anyhow::bail!("iptables returned non-zero status for redirect of {}", ip);
        }

        self.active_redirects.insert(ip);
        tracing::info!(%ip, "iptables DNAT redirect added");
        Ok(())
    }

    /// Batch-insert multiple DNAT rules in a single `iptables-restore` call.
    ///
    /// Uses `--noflush` to append rules without clearing existing tables.
    /// Single fork/exec for N rules — O(1) process creation vs O(N).
    pub fn redirect_batch(&mut self, ips: &[Ipv4Addr]) -> Result<()> {
        let new_ips: Vec<Ipv4Addr> = ips
            .iter()
            .copied()
            .filter(|ip| !self.active_redirects.contains(ip))
            .collect();

        if new_ips.is_empty() {
            return Ok(());
        }

        let dest = format!("127.0.0.1:{}", self.tarpit_port);
        let mut rules = String::from("*nat\n");
        for ip in &new_ips {
            // PERF: single iptables-restore call for all IPs
            rules.push_str(&format!(
                "-A PREROUTING -s {} -p tcp -j DNAT --to-destination {}\n",
                ip, dest
            ));
        }
        rules.push_str("COMMIT\n");

        let mut child = Command::new("iptables-restore")
            .arg("--noflush")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn iptables-restore")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(rules.as_bytes())
                .context("failed to write to iptables-restore stdin")?;
        }

        let output = child
            .wait_with_output()
            .context("iptables-restore failed")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("iptables-restore failed: {}", stderr);
        }

        for ip in &new_ips {
            self.active_redirects.insert(*ip);
        }

        tracing::info!(count = new_ips.len(), "iptables DNAT batch redirect added");
        Ok(())
    }

    /// Flush all pending (rate-limited) redirects via a single batch call.
    ///
    /// Should be called periodically from the event loop (e.g. every 1s).
    pub fn flush_pending(&mut self) -> Result<()> {
        if self.pending_redirects.is_empty() {
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending_redirects);
        tracing::info!(count = pending.len(), "flushing pending DNAT redirects");
        self.redirect_batch(&pending)
    }

    /// Remove the DNAT rule for a specific IP.
    pub fn remove_redirect(&mut self, ip: Ipv4Addr) -> Result<()> {
        if !self.active_redirects.contains(&ip) {
            return Ok(());
        }

        let dest = format!("127.0.0.1:{}", self.tarpit_port);
        let status = Command::new("iptables")
            .args([
                "-t", "nat", "-D", "PREROUTING",
                "-s", &ip.to_string(),
                "-p", "tcp",
                "-j", "DNAT",
                "--to-destination", &dest,
            ])
            .status()
            .context("failed to execute iptables")?;

        if !status.success() {
            tracing::warn!(%ip, "iptables rule removal returned non-zero");
        }

        self.active_redirects.remove(&ip);
        Ok(())
    }

    /// Remove all active redirect rules. Called on graceful shutdown.
    pub fn cleanup_all(&mut self) -> Result<()> {
        let ips: Vec<Ipv4Addr> = self.active_redirects.iter().copied().collect();
        for ip in ips {
            if let Err(e) = self.remove_redirect(ip) {
                tracing::warn!(%ip, "cleanup failed: {}", e);
            }
        }
        Ok(())
    }

    /// Number of currently active DNAT redirects.
    pub fn active_count(&self) -> usize {
        self.active_redirects.len()
    }

    /// Number of pending (rate-limited) redirects awaiting flush.
    pub fn pending_count(&self) -> usize {
        self.pending_redirects.len()
    }
}

impl Drop for FirewallManager {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup_all() {
            tracing::error!("firewall cleanup on drop failed: {}", e);
        }
    }
}
