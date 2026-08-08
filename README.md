

██████╗ ███████╗██╗   ██╗
██╔══██╗██╔════╝██║   ██║
██║  ██║█████╗  ██║   ██║
██║  ██║██╔══╝  ██║   ██║
██████╔╝██║     ╚██████║
╚═════╝ ╚═╝      ╚═════╝

██╗  ██╗██████╗ ███████╗███████╗███╗   ██╗███████╗███████╗
██║  ██║██╔══██╗██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
███████║██████╔╝█████╗  █████╗  ██╔██╗ ██║█████╗  ███████╗
██╔══██║██╔══██╗██╔══╝  ██╔══╝  ██║╚██╗██║██╔══╝  ╚════██║
██║  ██║██║  ██║███████╗███████╗██║ ╚████║███████╗███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝

> **法律与伦理边界声明**
>
> 本项目是一个 **教学研究与合法授权环境下的防御模拟系统**。
>
> - **仅限授权实验环境运行**：L3 "主动反制" 和 L4 "网络隔离" 模块在真实网络中可能违反
>   《网络安全法》《刑法》等相关法律法规。
> - **禁止未经授权使用**：禁止在未获得明确书面授权的任何网络环境中运行本系统的反制模块。
> - **mock_mode 默认开启**：在不接入真实 LLM API 时，所有反制行为均为模拟，不产生实际网络流量。
> - **作者与贡献者免责**：使用者因违反上述声明产生的任何法律后果，由使用者自行承担。

# DFU — Distributed AI Defense

> Teaching prototype / Demo prototype — simulates distributed defense behavior inside a single process. Not a production-ready system.

---

## Key Features

| Feature | Description |
|---------|-------------|
| 🛡️ **Autonomous Detection** | Packet capture + real-time traffic analysis via OutboundMonitor. Detects C2 beacons, data exfiltration, port scans, brute force attacks. |
| 🧠 **LLM-Powered Analysis** | Multi-model threat analysis with fallback. Distinguishes real attacks from false positives. |
| ⚡ **Dynamic Countermeasures** | 5-level FSM escalation (L0→L4): Monitor → Soft block → Hard block → Offensive → Network isolation. |
| 🔄 **自适应进化** | 攻击模式聚类 → 自动生成防御规则。随着时间的推移，系统会变得更加智能。 |
| 🔌 **插件架构** | 开放的接口支持自定义检测传感器和应对措施执行器。 |
| 🖥️ **Real-Time Dashboard** | Live attack map, defense timeline, stats panel. Front-end demo (offline demo; no backend SSE). |
| 🫁 **Alarm Nose (L4 Alert Loop)** | 4-level automatic alert escalation (L1 log → L2 confirm → L3 block → L4 isolate) with countdown timers, human acknowledgement/cancel, and optional enforced isolation. |
| 🍯 **Honeypot Integration** | Ingest attack events reported by external honeypots and feed them into the DFU detect → decide → respond pipeline. |
| 🎬 **Demo Mode** | Pre-built attack scenarios (C2 beacon, data exfiltration, mixed APT) replayable over SSE to showcase the full defense chain. |
| 🧬 **Organ Telemetry** | Real-time metrics for 13 defense organs (prefrontal, left/right brain, left/right hand, repair hand, self-heal, report mouth, alarm nose, memory, whitelist, skill box, medic). |

---

## Quick Start

### 🖥️ Desktop App (Recommended)

Runs as a standalone Windows desktop app: starts a FastAPI service bound to `127.0.0.1` only, loads the management panel in a native desktop window (pywebview / WebView2), and exits gracefully when the window closes.

```bash
# Option 1: run the packaged exe (no Python needed)
# Unzip dist/dfu_prototype_desktop.zip, then double-click dfu_prototype_desktop.exe
# The desktop window opens and loads the management panel at http://127.0.0.1:8000/monster

# Option 2: run from source
pip install -r requirements.txt pywebview
python desktop_launcher.py                # default port 8000, auto-increments if busy
python desktop_launcher.py --port 9000    # specify port
```

- The service binds to `127.0.0.1` only and is not exposed to the LAN; closing the desktop window stops the service and exits.
- Requires the WebView2 runtime (preinstalled on Windows 10/11; install
  [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) if missing).
- Packaging: `python -m PyInstaller temp/dfu_prototype_desktop.spec --noconfirm --distpath dist --workpath temp/pyinstaller_build_desktop`

### 🌐 Browser Mode (Development / Debug)

```bash
# Install dependencies
pip install -r requirements.txt

# Start the web server (binds to 127.0.0.1 and auto-opens the browser)
python web_server.py

# To disable auto-open
python web_server.py --no-browser
# Then open manually
open http://127.0.0.1:8000/monster
```

---

##架构

```
┌─────────────────────────────────────────────────────────┐
│ 网络仪表板 │
│ FastAPI + SSE + Live HTML │
└──────────────────────┬──────────────────────────────────┘
│
┌──────────────────────▼──────────────────────────────────┐
│                    Event Bus (In-Process Memory Bus)                   │
└──┬─────────┬─────────┬──────────┬──────────┬───────────┘
   │         │         │          │          │
┌──▼──┐  ┌──▼──┐  ┌──▼──┐   ┌───▼───┐  ┌──▼───┐
│Packet│  │Outbd│  │Event│   │ LLM   │  │FSM   │
│Capture│  │Monit│  │Aggreg│   │Analysis│  │Engine│
└──────┘  └─────┘  └─────┘   └───────┘  └──────┘
```

> **编排说明**：当前为**单机多进程 / 本地编排**架构（FastAPI 主进程 + 异步 worker），事件总线为进程内内存总线；未接入 RabbitMQ 等外部消息中间件，`cluster/rabbitmq_bus.py` 仅为历史遗留占位（已被废弃 worker 引用），不参与运行时数据通路。

### Key Modules

- **Alarm Nose (报警鼻, `organs/alarm_nose.py`)** — a 4-level automatic alert organ that grades threat alerts / FSM states / organ health signals into L1 (log, natural decay) → L2 (notify + human confirm + countdown) → L3 (close ports + urgent notify + countdown) → L4 (firewall full-block, soft-isolation signal + countdown, enforced on timeout). L4 reuses the FSM soft-isolation mechanism (no physical NIC changes); AlarmNose only publishes trigger signals and never modifies FSM state directly.
- **Honeypot (`/api/honeypot/event`)** — accepts attack events reported by external honeypots (web scan, SSH/FTP brute force, port scans, etc.), maps honeypot categories to DFU threat categories, and publishes them into the DFU pipeline as `threat_alert` messages for detection → decision → response.
- **Demo Mode (`/api/demo/*`)** — `c2_beacon`, `data_exfil` and `mixed_attack` presets inject pre-built attack event sequences through the EventChainRecorder; the full attack → defense process is streamed in real time over SSE.
- **Organ Data (`/api/dfu/organs/data`)** — returns live metrics for 13 defense organs: prefrontal (situational awareness), left-hand (traffic monitor), left-brain (detection), right-brain (analysis), right-hand (action), repair-hand (medic), self-heal (MedicAgent), report-mouth (reporting), alarm-nose (alerts), memory (knowledge router + hot/cold store), whitelist (IP whitelist), skill-box (defense skills).

---

## Benchmark Results (Demo Dataset)

| Scenario | Events | Detection Rate | FSM Action | Latency |
|----------|--------|---------------|------------|---------|
| C2 Beacon | 6 | 100% | L2 Hard Block | 0.11s |
| Data Exfiltration | 10 | 100% | L3 Offensive | 0.13s |
| Port Scan | 20 | 100% | L4 Isolate | 0.13s |
| Brute Force | 15 | 100% | L4 Isolate | 0.12s |
| Mixed APT | 51 | 100% | L4 (3 IPs) | 0.31s |

*Full benchmark report: [benchmarks/benchmark_report.md](benchmarks/benchmark_report.md)*

---

## Configuration

All configuration is handled through environment variables:

```bash
# Change API token
export DFU_AUTH_API_TOKEN="your-secure-token-here"

# Bootstrap key for first access to GET /api/token (optional; random if unset)
export DFU_BOOTSTRAP_TOKEN="your-bootstrap-key-here"

# Set LLM API key (optional, mock mode by default)
export DFU_LLM_API_KEY="your-api-key"

# Adjust detection sensitivity
export DFU_EXFIL_THRESHOLD=20971520  # 20MB

# Start
python web_server.py
```

---

## API Reference

All endpoints are served by FastAPI (`web_server.py`). Endpoints marked **Auth** require an API token — obtain it from `GET /api/token` (with the `X-Bootstrap-Token` header or `?bootstrap=<key>` for first-access protection) and send it as the `Authorization: Bearer <token>` header.

### Web UI (HTML)

|Endpoint|Method|Auth|Description|
|----------|--------|------|-------------|
| `/` | GET | — | Landing page |
| `/monster` | GET | — | MonsterDFU single-file SPA management panel |
| `/live` | GET | — | Live demo attack big-screen (front-end demo / offline demo; local mock scenarios, no backend SSE) |
| `/compare` | GET | — | Comparison demo page (no DFU vs with DFU) |

### Health & Probes

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | — | Health check — component liveness status |
| `/healthz` | GET | — | Liveness probe: is the process running |
| `/readyz` | GET | — | Readiness probe: is the system initialized and ready |

### DFU Core

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/dfu/status` | GET | — | DFU runtime status: `running` / `uptime` / `start_time` / `components` |
| `/api/dfu/start` | POST | — | Start the DFU core (idempotent) |
| `/api/dfu/stop` | POST | — | Stop the DFU core (idempotent) |
| `/api/dfu/organs/data` | GET | — | One-shot live data for all 13 defense organs; `running=false` when the system is not started |
| `/api/status` | GET | — | System status incl. token usage |
| `/api/stats` | GET | — | 当前防御统计数据 |
| `/api/attack` | POST | ✅ |运行攻击场景；请求体 `{"scenario": "c2_beacon"|"data_exfil"|"port_scan"|"brute_force"|"mixed_apt"|"all"}` |
| `/api/token-usage` | GET | — |LLM令牌消耗统计 |
| `/api/reset-token-usage` | POST | — |重置LLM令牌统计 |

###Chat

|Endpoint|Method|Auth|Description|
|----------|--------|------|-------------|
| `/api/chat` | POST | — | Chat proxy: forwards MonsterDFU frontend chat requests to an OpenAI-compatible endpoint; body `{"messages":[...], "api_key": str, "model": str, "base_url": str, "stream": bool?}` |

### Events & Monitoring

|Endpoint|Method|Auth|Description|
|----------|--------|------|-------------|
| `/api/events/stream` | GET | — | SSE real-time event stream (heartbeat every 15s) |
| `/api/events` | GET | — | Poll event history; `?since=<unix_ts>` returns events after that timestamp |
| `/api/metrics` | GET | — | JSON snapshot of all monitoring metrics |
| `/api/metrics/stream` | GET | — | SSE stream pushing metrics every 2 seconds |
| `/metrics` | GET | — | Prometheus-format `/metrics` endpoint |
| `/api/resources` | GET | — | CPU / memory usage sampling |

### Forensics & Security

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/forensic/timeline` | GET | — | Attack-chain forensic timeline (time / source IP / attack type / response action) |
| `/api/vuln/ports` | GET | — | 通过端口扫描获取本地开放端口 |
| `/api/outbound/connections` | GET | — | 本地活跃出站连接 |
| `/api/audit/events` | GET | — | 近期安全审计事件 |

###L4隔离与熔毁

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/l4/status` | GET | ✅ | L4 status overview: active L4 IPs + three-gate state |
| `/api/l4/confirm` | POST | ✅ | Confirm L4 network isolation for `{"source_ip": str}`; closes gate 3 and auto-degrades L4 back to L3 |
| `/api/l4/reject` | POST | ✅ | Reject L4 isolation (cancel confirmation, keep L4 state) |
| `/api/meltdown/on` | POST | ✅ | Enable system meltdown (system-wide defensive freeze) |
| `/api/meltdown/off` | POST | ✅ | Disable system meltdown |

### Alarm Nose (L4 Alerts)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/alarm-nose/status` | GET | ✅ | Alarm Nose real-time status: current level / countdown / 4-level alert history |
| `/api/alarm-nose/ack` | POST | ✅ | Acknowledge the current alert (stop countdown, clear alert, back to L1 log state) |
| `/api/alarm-nose/cancel` | POST | ✅ | Cancel the current alert (stop countdown, cancel auto-escalation, back to L1 log state) |
| `/api/alarm-nose/confirm-l4` | POST | ✅ | Manually confirm L4: immediately trigger the soft-isolation signal (reuses the FSM mechanism, no physical NIC cut) |

### Honeypot

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/honeypot/event` | POST | ✅ | Accept an attack event reported by a honeypot and inject it into the DFU pipeline; body `{"category", "severity", "src_ip", "src_port", "dst_port", "payload_preview"}` |

### Demo Mode

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/demo/scenarios` | GET | — | List available demo scenarios (`c2_beacon`, `data_exfil`, `mixed_attack`) |
| `/api/demo/trigger` | POST | ✅ | Trigger a demo attack sequence; body `{"scenario": "c2_beacon"|"data_exfil"|"mixed_attack"}` (default `c2_beacon`) |

###认证

|Endpoint|Method|Auth|Description|
|----------|--------|------|-------------|
| `/api/token` | GET | Bootstrap | Return the current web token; requires `X-Bootstrap-Token` header or `?bootstrap=<key>` (matches `DFU_BOOTSTRAP_TOKEN`, random if unset). The frontend fetches it here and carries it on subsequent `/api/*` requests |

---

## Project Structure

```
dfu-defense/
├── main.py                    # Entry point
├── cli.py                     # CLI tool (dfu start/demo/bench/status)
├── config/
│ ├── default_config.yaml # 默认配置
├── utils/
│ ├── logging_config.py # 标准化日志记录
│ └── error_handler.py # 错误处理工具函数
├── organs/
│ ├── capturer.py # 数据包捕获 (libpcap/scapy)
│ ├── observer_outbound.py # 出站流量监控器
│ ├── alarm_nose.py # 四级自动报警机制 (L1→L4)
│ ├── auditor_log.py # 安全审计日志
│ ├── fsm.py # 对策状态机
│ └── evolver.py # 自适应防御进化器
├── benchmarks/
│ ├── attack_dataset.py # 攻击场景数据集
│ ├── run_benchmark.py # 基准测试运行器
│ └── benchmark_report.md # 最新基准测试报告
├── static/
│ ├── index.html # 管理控制台
│ ├── monster.html # 小怪兽单文件 SPA 管理面板（/monster）
│ ├── live.html # 实时演示仪表板（/live）
│ └── compare.html # 对比演示页（/compare，无 DFU vs 有 DFU）
├── docker-compose.yml # 生产环境部署
├── Dockerfile # 多阶段构建
└── README.md # 此文件```
