██████╗ ███████╗██╗   ██╗
██╔══██╗██╔════╝██║   ██║
██║  ██║█████╗  ██║   ██║
██║  ██║██╔══╝  ██║   ██║
██████╔╝██║     ╚██████╔╝
╚═════╝ ╚═╝      ╚═════╝

██╗  ██╗██████╗ ███████╗███████╗███╗   ██╗███████╗███████╗
██║  ██║██╔══██╗██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
███████║██████╔╝█████╗  █████╗  ██╔██╗ ██║█████╗  ███████╗
██╔══██║██╔══██╗██╔══╝  ██╔══╝  ██║╚██╗██║██╔══╝  ╚════██║
██║  ██║██║  ██║███████╗███████╗██║ ╚████║███████╗███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝

# DFU — Distributed AI Defense

> 教学原型 / Demo Prototype — 单进程内模拟分布式防御行为，非生产就绪系统

---

## Key Features

| Feature | Description |
|---------|-------------|
| 🛡️ **Autonomous Detection** | Packet capture + real-time traffic analysis via OutboundMonitor. Detects C2 beacons, data exfiltration, port scans, brute force attacks. |
| 🧠 **LLM-Powered Analysis** | Multi-model threat analysis with fallback. Distinguishes real attacks from false positives. |
| ⚡ **Dynamic Countermeasures** | 5-level FSM escalation (L0→L4): Monitor → Soft block → Hard block → Offensive → Network isolation. |
| 🔄 **Self-Evolving** | Attack pattern clustering → automatic defense rule generation. Gets smarter over time. |
| 🔌 **Plugin Architecture** | Open interfaces for custom detection sensors and countermeasure actors. |
| 🖥️ **Real-Time Dashboard** | Live attack map, defense timeline, stats panel. SSE-powered. |

---

## Quick Start

### 🖥️ 桌面版（推荐）

独立 Windows 桌面软件形态：内部启动 FastAPI 服务（仅绑定 `127.0.0.1` 本机回环），
用原生桌面窗口（pywebview / WebView2）加载管理面板，不再调用系统浏览器，关闭窗口即优雅退出。

```bash
# 方式一：双击 exe（无需安装 Python）
# 解压 dist/dfu_prototype_desktop.zip 后，双击其中的 dfu_prototype_desktop.exe
# 桌面窗口会直接弹出并加载管理面板 http://127.0.0.1:8000/monster

# 方式二：源码运行
pip install -r requirements.txt pywebview
python desktop_launcher.py                # 默认端口 8000，被占用时自动顺延
python desktop_launcher.py --port 9000    # 指定端口
```

- 服务仅绑定 `127.0.0.1`，不暴露局域网；关闭桌面窗口即停止服务并退出进程。
- 依赖 WebView2 运行时（Windows 10/11 一般已内置；缺失时请安装
  [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)）。
- 打包方法：`python -m PyInstaller temp/dfu_prototype_desktop.spec --noconfirm --distpath dist --workpath temp/pyinstaller_build_desktop`

### 🌐 浏览器模式（开发/调试）

```bash
# Install dependencies
pip install -r requirements.txt

# Start the web server（默认仅监听 127.0.0.1，并自动打开浏览器）
python web_server.py

# 不自动打开浏览器时
python web_server.py --no-browser
# 然后手动打开
open http://127.0.0.1:8000/monster
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Web Dashboard                       │
│              FastAPI + SSE + Live HTML                    │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                    Event Bus (RabbitMQ)                   │
└──┬─────────┬─────────┬──────────┬──────────┬───────────┘
   │         │         │          │          │
┌──▼──┐  ┌──▼──┐  ┌──▼──┐   ┌───▼───┐  ┌──▼───┐
│Packet│  │Outbd│  │Event│   │ LLM   │  │FSM   │
│Capture│  │Monit│  │Aggreg│   │Analysis│  │Engine│
└──────┘  └─────┘  └─────┘   └───────┘  └──────┘
```

---

## Benchmark Results（演示数据集 / Demo Dataset）

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

# Set LLM API key (optional, mock mode by default)
export DFU_LLM_API_KEY="your-api-key"

# Adjust detection sensitivity
export DFU_EXFIL_THRESHOLD=20971520  # 20MB

# Start
python web_server.py
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/events/stream` | SSE | Real-time event stream |
| `/api/events?since=ts` | GET | Poll events |
| `/api/stats` | GET | Current defense stats |
| `/api/demo/scenarios` | GET | Available demo scenarios |
| `/api/demo/trigger` | POST | Trigger attack scenario |
| `/live` | GET | Live demo dashboard |

---

## Project Structure

```
dfu-defense/
├── web_server.py              # FastAPI web server (browser mode)
├── desktop_launcher.py        # Desktop launcher (recommended, pywebview)
├── main.py                    # Entry point / system bootstrap
├── cli.py                     # CLI tool (dfu start/demo/bench/status)
├── config.py                  # Environment-driven configuration
├── persistence.py             # Persistence helpers
├── capturer_entry.py          # Packet capture entry helper
├── core/                      # Dual-brain core engine
│   ├── brain_left.py          # Left brain: rule/signature reasoning
│   ├── brain_right.py         # Right brain: LLM/pattern reasoning
│   ├── countermeasure_fsm.py  # 5-level FSM (L0→L4)
│   ├── event_aggregator.py    # Event correlation
│   ├── llm_client.py          # Multi-model LLM client with fallback
│   └── ...                    # validator / signature_engine / medic etc.
├── organs/                    # Detection & action organs
│   ├── capturer.py            # Packet capture (libpcap/scapy)
│   ├── observer_outbound.py   # Outbound traffic monitor
│   ├── observer_realtime.py   # Realtime monitor
│   ├── firewall_executor.py   # Countermeasure actor
│   └── ...                    # alarm / auditor / notifier / tracker etc.
├── communication/             # Message bus & middleware
├── knowledge/                 # Hot/cold stores, evolver, vector store
├── cluster/                   # Distributed unit registry & dispatcher
├── production/                # Compliance / perf / security audit tools
├── upgrade/                   # Model store & rollout controller
├── config/
│   └── default_config.yaml    # Default configuration
├── utils/                     # Logging & error handling utilities
├── benchmarks/                # Attack dataset & benchmark runner
├── rules/                     # Signature rules (default.rules + ET Open)
├── static/                    # Web dashboard (HTML/JS)
├── tests/                     # Test suite
├── deploy/                    # systemd unit & env template
├── tools/                     # Attack simulation & stress test scripts
├── docker-compose.yml         # Production deployment
├── Dockerfile                 # Multi-stage build
└── README.md                  # This file
```
