//! ANSI terminal dashboard renderer.
//!
//! Renders a live-updating dashboard using only ANSI escape codes.
//! No external TUI crates — pure `\x1B[` sequences.

use std::io::{self, Write};

use crate::collector::MeshStats;

/// ANSI color codes.
const GREEN: &str = "\x1B[32m";
const YELLOW: &str = "\x1B[33m";
const RED: &str = "\x1B[31m";
const CYAN: &str = "\x1B[36m";
const BOLD: &str = "\x1B[1m";
const DIM: &str = "\x1B[2m";
const RESET: &str = "\x1B[0m";

/// Unicode box-drawing characters.
const TL: char = '┌';
const TR: char = '┐';
const BL: char = '└';
const BR: char = '┘';
const HZ: char = '─';
const VT: char = '│';

/// Terminal dashboard state.
pub struct Dashboard {
    stats: MeshStats,
    frame: u64,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            stats: MeshStats::default(),
            frame: 0,
        }
    }

    /// Update dashboard with fresh stats.
    pub fn update(&mut self, stats: MeshStats) {
        self.stats = stats;
        self.frame += 1;
    }

    /// Render the full dashboard to the given writer.
    pub fn render<W: Write>(&self, w: &mut W) -> io::Result<()> {
        // Move cursor to top-left, clear screen
        write!(w, "\x1B[H\x1B[2J")?;

        self.render_header(w)?;
        writeln!(w)?;
        self.render_mesh_panel(w)?;
        writeln!(w)?;
        self.render_threat_panel(w)?;
        writeln!(w)?;
        self.render_network_fw_panel(w)?;
        writeln!(w)?;
        self.render_a2a_panel(w)?;
        writeln!(w)?;
        self.render_crypto_panel(w)?;
        writeln!(w)?;
        self.render_footer(w)?;

        w.flush()
    }

    fn render_header<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let status = if self.stats.connected {
            format!("{GREEN}● CONNECTED{RESET}")
        } else {
            format!("{RED}○ DISCONNECTED{RESET}")
        };

        writeln!(
            w,
            "  {BOLD}{CYAN}╔══════════════════════════════════════════════════╗{RESET}"
        )?;
        writeln!(
            w,
            "  {BOLD}{CYAN}║{RESET}  {BOLD}BLACKWALL HIVEMIND{RESET}  {DIM}v2.0{RESET}  \
             {status}  {DIM}frame #{}{RESET}  {BOLD}{CYAN}║{RESET}",
            self.frame,
        )?;
        writeln!(
            w,
            "  {BOLD}{CYAN}╚══════════════════════════════════════════════════╝{RESET}"
        )
    }

    fn render_mesh_panel<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.draw_box_top(w, " P2P Mesh ", 48)?;
        self.draw_kv(w, "Peers", &self.stats.peer_count.to_string(), 48)?;
        self.draw_kv(
            w,
            "DHT Records",
            &self.stats.dht_records.to_string(),
            48,
        )?;
        self.draw_kv(
            w,
            "GossipSub Topics",
            &self.stats.gossip_topics.to_string(),
            48,
        )?;
        self.draw_kv(
            w,
            "Messages/s",
            &format!("{:.1}", self.stats.messages_per_sec),
            48,
        )?;
        self.draw_box_bottom(w, 48)
    }

    fn render_threat_panel<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.draw_box_top(w, " Threat Intel ", 48)?;
        self.draw_kv(
            w,
            "IoCs Shared",
            &self.stats.iocs_shared.to_string(),
            48,
        )?;
        self.draw_kv(
            w,
            "IoCs Received",
            &self.stats.iocs_received.to_string(),
            48,
        )?;

        let reputation_color = if self.stats.avg_reputation > 80.0 {
            GREEN
        } else if self.stats.avg_reputation > 50.0 {
            YELLOW
        } else {
            RED
        };
        self.draw_kv_colored(
            w,
            "Avg Reputation",
            &format!("{:.1}", self.stats.avg_reputation),
            reputation_color,
            48,
        )?;
        self.draw_box_bottom(w, 48)
    }

    fn render_a2a_panel<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.draw_box_top(w, " A2A Firewall ", 48)?;
        self.draw_kv(
            w,
            "JWTs Verified",
            &self.stats.a2a_jwts_verified.to_string(),
            48,
        )?;
        self.draw_kv(
            w,
            "Violations Blocked",
            &self.stats.a2a_violations.to_string(),
            48,
        )?;
        self.draw_kv(
            w,
            "Injections Detected",
            &self.stats.a2a_injections.to_string(),
            48,
        )?;
        self.draw_box_bottom(w, 48)
    }

    fn render_network_fw_panel<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.draw_box_top(w, " Network Firewall ", 48)?;
        self.draw_kv(
            w,
            "Packets Total",
            &self.stats.packets_total.to_string(),
            48,
        )?;
        self.draw_kv(
            w,
            "Packets Passed",
            &self.stats.packets_passed.to_string(),
            48,
        )?;

        let dropped_color = if self.stats.packets_dropped > 0 {
            RED
        } else {
            GREEN
        };
        self.draw_kv_colored(
            w,
            "Packets Dropped",
            &self.stats.packets_dropped.to_string(),
            dropped_color,
            48,
        )?;

        let anomaly_color = if self.stats.anomalies_sent > 0 {
            YELLOW
        } else {
            GREEN
        };
        self.draw_kv_colored(
            w,
            "Anomalies",
            &self.stats.anomalies_sent.to_string(),
            anomaly_color,
            48,
        )?;
        self.draw_box_bottom(w, 48)
    }

    fn render_crypto_panel<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.draw_box_top(w, " Cryptography ", 48)?;
        self.draw_kv(
            w,
            "ZKP Proofs Generated",
            &self.stats.zkp_proofs_generated.to_string(),
            48,
        )?;
        self.draw_kv(
            w,
            "ZKP Proofs Verified",
            &self.stats.zkp_proofs_verified.to_string(),
            48,
        )?;

        let fhe_status = if self.stats.fhe_encrypted {
            format!("{GREEN}AES-256-GCM{RESET}")
        } else {
            format!("{YELLOW}STUB{RESET}")
        };
        self.draw_kv(w, "FHE Mode", &fhe_status, 48)?;
        self.draw_box_bottom(w, 48)
    }

    fn render_footer<W: Write>(&self, w: &mut W) -> io::Result<()> {
        writeln!(
            w,
            "  {DIM}Press Ctrl+C to exit  |  Refresh: 1s  |  \
             API: hivemind-api{RESET}"
        )
    }

    // ── Box drawing helpers ─────────────────────────────────────

    fn draw_box_top<W: Write>(
        &self,
        w: &mut W,
        title: &str,
        width: usize,
    ) -> io::Result<()> {
        let inner = width - 2 - title.len();
        write!(w, "  {TL}{HZ}")?;
        write!(w, "{BOLD}{title}{RESET}")?;
        for _ in 0..inner {
            write!(w, "{HZ}")?;
        }
        writeln!(w, "{TR}")
    }

    fn draw_box_bottom<W: Write>(&self, w: &mut W, width: usize) -> io::Result<()> {
        write!(w, "  {BL}")?;
        for _ in 0..width - 2 {
            write!(w, "{HZ}")?;
        }
        writeln!(w, "{BR}")
    }

    fn draw_kv<W: Write>(
        &self,
        w: &mut W,
        key: &str,
        value: &str,
        width: usize,
    ) -> io::Result<()> {
        let padding = width - 6 - key.len() - value.len();
        let pad = if padding > 0 { padding } else { 1 };
        write!(w, "  {VT}  {key}")?;
        for _ in 0..pad {
            write!(w, " ")?;
        }
        writeln!(w, "{BOLD}{value}{RESET}  {VT}")
    }

    fn draw_kv_colored<W: Write>(
        &self,
        w: &mut W,
        key: &str,
        value: &str,
        color: &str,
        width: usize,
    ) -> io::Result<()> {
        let padding = width - 6 - key.len() - value.len();
        let pad = if padding > 0 { padding } else { 1 };
        write!(w, "  {VT}  {key}")?;
        for _ in 0..pad {
            write!(w, " ")?;
        }
        writeln!(w, "{color}{BOLD}{value}{RESET}  {VT}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_default_dashboard() {
        let dash = Dashboard::new();
        let mut buf = Vec::new();
        dash.render(&mut buf).expect("render");
        let output = String::from_utf8(buf).expect("utf8");
        assert!(output.contains("BLACKWALL HIVEMIND"));
        assert!(output.contains("P2P Mesh"));
        assert!(output.contains("Threat Intel"));
        assert!(output.contains("Network Firewall"));
        assert!(output.contains("A2A Firewall"));
        assert!(output.contains("Cryptography"));
    }

    #[test]
    fn update_increments_frame() {
        let mut dash = Dashboard::new();
        assert_eq!(dash.frame, 0);
        dash.update(MeshStats::default());
        assert_eq!(dash.frame, 1);
        dash.update(MeshStats::default());
        assert_eq!(dash.frame, 2);
    }

    #[test]
    fn connected_shows_green() {
        let mut dash = Dashboard::new();
        dash.update(MeshStats {
            connected: true,
            ..Default::default()
        });
        let mut buf = Vec::new();
        dash.render(&mut buf).expect("render");
        let output = String::from_utf8(buf).expect("utf8");
        assert!(output.contains("CONNECTED"));
    }
}
