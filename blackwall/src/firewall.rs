use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

/// Manages iptables DNAT rules to redirect attacker traffic to the tarpit.
pub struct FirewallManager {
    active_redirects: Vec<Ipv4Addr>,
    tarpit_port: u16,
}

impl FirewallManager {
    /// Create a new FirewallManager targeting the given tarpit port.
    pub fn new(tarpit_port: u16) -> Self {
        Self {
            active_redirects: Vec::new(),
            tarpit_port,
        }
    }

    /// Add a DNAT rule to redirect all TCP traffic from `ip` to the tarpit.
    pub fn redirect_to_tarpit(&mut self, ip: Ipv4Addr) -> Result<()> {
        if self.active_redirects.contains(&ip) {
            return Ok(());
        }

        let dest = format!("127.0.0.1:{}", self.tarpit_port);
        let status = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-s",
                &ip.to_string(),
                "-p",
                "tcp",
                "-j",
                "DNAT",
                "--to-destination",
                &dest,
            ])
            .status()
            .context("failed to execute iptables")?;

        if !status.success() {
            anyhow::bail!("iptables returned non-zero status for redirect of {}", ip);
        }

        self.active_redirects.push(ip);
        tracing::info!(%ip, "iptables DNAT redirect added");
        Ok(())
    }

    /// Remove the DNAT rule for a specific IP.
    pub fn remove_redirect(&mut self, ip: Ipv4Addr) -> Result<()> {
        let dest = format!("127.0.0.1:{}", self.tarpit_port);
        let status = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-s",
                &ip.to_string(),
                "-p",
                "tcp",
                "-j",
                "DNAT",
                "--to-destination",
                &dest,
            ])
            .status()
            .context("failed to execute iptables")?;

        if !status.success() {
            tracing::warn!(%ip, "iptables rule removal returned non-zero");
        }

        self.active_redirects.retain(|&a| a != ip);
        Ok(())
    }

    /// Remove all active redirect rules. Called on graceful shutdown.
    pub fn cleanup_all(&mut self) -> Result<()> {
        let ips: Vec<Ipv4Addr> = self.active_redirects.clone();
        for ip in ips {
            if let Err(e) = self.remove_redirect(ip) {
                tracing::warn!(%ip, "cleanup failed: {}", e);
            }
        }
        Ok(())
    }
}

impl Drop for FirewallManager {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup_all() {
            tracing::error!("firewall cleanup on drop failed: {}", e);
        }
    }
}
