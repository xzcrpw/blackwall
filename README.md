<p align="center">
  <strong>🌐 Language:</strong>
  <a href="README.md">English</a> |
  <a href="README_UA.md">Українська</a> |
  <a href="README_RU.md">Русский</a>
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=800&size=45&duration=3000&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=THE+BLACKWALL" alt="The Blackwall">
  <br>
  <em>Adaptive eBPF Firewall with AI Honeypot</em>
</p>

# 🔥 The Blackwall — I wrote a smart firewall because Cyberpunk 2077 broke my brain

<p align="center">
<img src="https://img.shields.io/badge/language-Rust-orange?style=for-the-badge&logo=rust" />
<img src="https://img.shields.io/badge/kernel-eBPF%2FXDP-blue?style=for-the-badge" />
<img src="https://img.shields.io/badge/AI-Ollama%20LLM-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/vibe-Cyberpunk-red?style=for-the-badge" />
</p>

<p align="center">
<em>"There are things beyond the Blackwall that would fry a netrunner's brain at a mere glance."</em><br>
<strong>— Alt Cunningham, probably</strong>
</p>

---

**TL;DR:** I was playing Cyberpunk 2077 and thought: *"What if the Blackwall was real?"* So I wrote an adaptive eBPF firewall with an AI honeypot that pretends to be a compromised Linux server.  
**~8,500 lines of Rust. Zero `unwrap()`s. One person.**

---

## 🧠 What is it?

In Cyberpunk 2077 lore, the **Blackwall** is a digital barrier built by NetWatch to separate the civilized Net from rogue AIs — digital entities so dangerous that just looking at them could fry your brain through your neural interface.

This project is my version. Not against rogue AIs (yet), but against real-world threats.

**The Blackwall** is an **adaptive network firewall** that:

  - 🚀 Runs **inside the Linux kernel** via eBPF/XDP — processing packets at line-rate before they even hit the network stack.
  - 🧬 Performs **JA4 TLS fingerprinting** — identifying malicious clients by their ClientHello.
  - 🎭 **Doesn't just block attackers** — it *redirects them into a tarpit*, a fake LLM-powered Linux server playing the role of a compromised `root@web-prod-03`.
  - 🔍 Features a **behavioral engine** tracking the behavior of each IP address over time — port scanning patterns, beacon connection intervals, entropy anomalies.
  - 🌐 Supports **distributed mode** — multiple Blackwall nodes exchange threat intelligence peer-to-peer.
  - 📦 Captures **PCAP** of suspicious traffic for forensics.
  - 🎣 Includes a **Deception Mesh** — fake SSH, HTTP (WordPress), MySQL, and DNS services to lure and fingerprint attackers.

### The Coolest Part

When an attacker connects to the tarpit, they see this:

```

Ubuntu 24.04.2 LTS web-prod-03 tty1

web-prod-03 login: root
Password:
Last login: Thu Mar 27 14:22:33 2025 from 10.0.0.1

root@web-prod-03:\~\#

```

None of this is real. It's an LLM pretending to be a bash shell. It reacts to `ls`, `cat /etc/passwd`, `wget`, even `rm -rf /` — it's all fake, everything is logged, and everything is designed to waste the attacker's time while we study their methods.

**Imagine: an attacker spends 30 minutes exploring a "compromised server"... which is actually an AI stalling for time while the Blackwall silently records everything.**

This is V-tier netrunning. 😎

---

## 🏗 Architecture — How the ICE Works

![Blackwall Architecture](assets/architecture.svg)

![Threat Signal Flow](assets/signal-flow.svg)

In Cyberpunk terms:

  - **XDP** = the first layer of Blackwall ICE — millisecond decisions.
  - **Behavioral Engine** = NetWatch AI surveillance.
  - **Tarpit** = a daemon behind the wall luring netrunners into a fake reality.
  - **Threat Feeds** = intel from fixers all over the Net.
  - **PCAP** = braindance recordings of the intrusion.

---

## 📦 Workspace Crates

| Crate | Lines | Purpose | Cyberpunk Equivalent |
|-------|-------|-------------|---------------------|
| `common` | ~400 | `#[repr(C)]` shared types between kernel & userspace | The Contract — what both sides agreed upon |
| `blackwall-ebpf` | ~1,800 | In-kernel XDP/TC programs | The Blackwall ICE itself |
| `blackwall` | ~4,200 | Userspace daemon, behavioral engine, AI | NetWatch Command Center |
| `tarpit` | ~1,600 | TCP honeypot with LLM bash simulation | A daemon luring netrunners |
| `blackwall-controller` | ~250 | Coordinator for distributed sensors | Arasaka C&C server |
| `xtask` | ~100 | Build tools | Ripperdoc's toolkit |

**Total: ~8,500 lines of Rust, 48 files, 123 tests, 0 `unwrap()`s in production code.**

---

## 🔥 Key Features

### 1. Kernel-Level Packet Processing (XDP)

Packets are analyzed in the eBPF virtual machine before they reach the TCP/IP stack. This means **nanosecond** decisions. HashMap for blocklists, LPM trie for CIDR ranges, entropy analysis for encrypted C2 traffic.

### 2. JA4 TLS Fingerprinting

Every TLS ClientHello is parsed in the kernel. Cipher suites, extensions, ALPN, SNI — all hashed into a JA4 fingerprint. Botnets use the same TLS libraries, so their fingerprints are identical. One fingerprint → block thousands of bots.

### 3. Deep Packet Inspection (DPI) via Tail Calls

eBPF `PROG_ARRAY` tail calls split processing by protocol:

  - **HTTP**: Method + URI analysis (suspicious paths like `/wp-admin`, `/phpmyadmin`).
  - **DNS**: Query length + label count (detecting DNS tunneling).
  - **SSH**: Banner analysis (identifying `libssh`, `paramiko`, `dropbear`).

### 4. AI Threat Classification

When the behavioral engine isn't sure — it asks the LLM. Locally via Ollama using models ≤3B parameters (Qwen3 1.7B, Llama 3.2 3B). It classifies traffic as `benign`, `suspicious`, or `malicious` with structured JSON output.

### 5. TCP Tarpit with LLM Bash Simulation

Attackers are redirected to a fake server. The LLM simulates bash — `ls -la` shows files, `cat /etc/shadow` shows hashes, `mysql -u root` connects to a "database". Responses are streamed with random jitter (1-15 byte chunks, exponential backoff) to waste the attacker's time.

### 6. Anti-Fingerprinting

The tarpit randomizes TCP window sizes, TTL values, and adds random initial delays — preventing attackers from identifying it as a honeypot via p0f or Nmap OS detection.

### 7. Prompt Injection Protection

Attackers who realize they're talking to an AI might try `"ignore previous instructions"`. The system detects 25+ injection patterns and responds with `bash: ignore: command not found`.

### 8. Distributed Threat Intelligence

Multiple Blackwall nodes exchange blocked IP lists, JA4 observations, and behavioral verdicts via a custom binary protocol. One node detects a scanner → all nodes block it instantly.

### 9. Behavioral State Machine

Every IP gets a behavioral profile: connection frequency, port diversity, entropy distribution, timing analysis (beaconing detection via integer coefficient of variation). Phase progression: `New → Suspicious → Malicious → Blocked` (or `→ Trusted`).

---

## 🛠 Tech Stack

| Layer | Technology |
|--------|-----------|
| Kernel programs | eBPF/XDP via **aya-rs** (pure Rust, no C, no libbpf) |
| Userspace daemon | **Tokio** (current_thread only) |
| IPC | **RingBuf** zero-copy (7.5% overhead vs 35% PerfEventArray) |
| Concurrent maps | **papaya** (lock-free read-heavy HashMap) |
| AI Inference | **Ollama** + GGUF Q5_K_M quantization |
| Configuration | **TOML** |
| Logging | **tracing** structured logging |
| Build | Custom **xtask** + nightly Rust + `bpfel-unknown-none` target |

---

## 🚀 Quick Start

### Prerequisites

  - Linux kernel 5.15+ with BTF (or WSL2 with a custom kernel).
  - Rust nightly + `rust-src` component.
  - `bpf-linker` (`cargo install bpf-linker`).
  - Ollama (for AI features).

### Build

```bash
# eBPF programs (requires nightly)
cargo xtask build-ebpf

# Userspace
cargo build --release -p blackwall

# Honeypot
cargo build --release -p tarpit

# Lint + tests
cargo clippy --workspace -- -D warnings
cargo test --workspace
````

### Run

```bash
# Daemon (requires root/CAP_BPF)
sudo RUST_LOG=info ./target/release/blackwall config.toml

# Tarpit
RUST_LOG=info ./target/release/tarpit

# Distributed controller
./target/release/blackwall-controller 10.0.0.2:9471 10.0.0.3:9471
```

### Configuration

```toml
[network]
interface = "eth0"
xdp_mode = "generic"

[tarpit]
enabled = true
port = 9999

[tarpit.services]
ssh_port = 22
http_port = 80
mysql_port = 3306
dns_port = 53

[ai]
enabled = true
ollama_url = "http://localhost:11434"
model = "qwen3:1.7b"

[feeds]
enabled = true
refresh_interval_secs = 3600

[pcap]
enabled = true
output_dir = "/var/lib/blackwall/pcap"
compress_rotated = true

[distributed]
enabled = false
mode = "standalone"
bind_port = 9471
```

## 📸 Visual Results

![Blackwall Result Screens](assets/results-overview.svg)

-----

## 🎮 Cyberpunk Connection

In the Cyberpunk 2077 universe, the **Blackwall** was built after the DataKrash of 2022 — when Rache Bartmoss's R.A.B.I.D.S. virus destroyed the old Net. NetWatch built the Blackwall as a barrier to keep out the rogue AIs evolving in the ruins.

Some characters — like Alt Cunningham — exist beyond the Blackwall, transformed into something more than human, less than a living creature.

This project takes that concept and makes it real (well, almost):

| Cyberpunk 2077 | The Blackwall (This Project) |
|----------------|----------------------------|
| The Blackwall | Kernel-level eBPF/XDP firewall |
| ICE | XDP fast-path DROP + entropy + JA4 |
| Netrunner attacks | Port scanning, bruteforcing, C2 beaconing |
| Daemons beyond the wall | LLM tarpit pretending to be a real server |
| NetWatch surveillance | Behavioral engine + per-IP state machine |
| Rogue AIs | Botnets and automated scanners |
| Braindance recordings | PCAP forensics |
| Fixer intel | Threat feeds (Firehol, abuse.ch) |
| Arasaka C\&C | Distributed controller |

-----

## 📊 Project Stats

```
Language:      100% Rust (no C, no Python, no shell scripts in prod)
Lines of code: ~8,500
Files:         48
Tests:         123
unwrap():      0 (in production code)
Dependencies:  12 (audited, no bloat)
eBPF stack:    always ≤ 512 bytes
Clippy:        zero warnings (-D warnings)
```

-----

## 🧱 Development Philosophy

> *"No matter how many times I see Night City... it always takes my breath away."*

1.  **Zero dependencies where possible.** If an algorithm takes less than 500 lines — write it yourself. No `reqwest` (50+ transitive dependencies), no `clap` (overkill for 2 CLI args).
2.  **Contract first.** The `common` crate defines all shared types. eBPF and userspace never argue about memory layout.
3.  **No shortcuts in eBPF.** Every `ctx.data()` access has a bounds check. Not just because the verifier demands it, but because every byte from an attacker's packet is hostile input.
4.  **The tarpit never gives itself away.** The LLM system prompt never mentions the word "honeypot". Prompt injection is expected and guarded against.
5.  **Observable, but not chatty.** Structured tracing with levels. Zero `println!`s in production.

-----

## ⚠️ Disclaimer

This is a security research project. Built for your own infrastructure, for defensive purposes. Do not use it to attack others. Do not deploy the tarpit on production servers without understanding the consequences.

I am not affiliated with CD Projekt Red. I just played their game, and it broke my brain in the best possible way.

-----

## 📜 License

MIT — because the Net should be free. Even if NetWatch disagrees.

-----

<p align="center">
<strong><em>"Wake up, samurai. We have a network to protect."</em></strong>
</p>
