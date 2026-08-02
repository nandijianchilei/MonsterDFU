"""
DFU Web 管理界面 — FastAPI 后端

启动方式：
    python web_server.py              # 默认 http://localhost:8000
    python web_server.py --port 9000  # 自定义端口
"""

import argparse
import asyncio
import json
import os
import sys
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import secrets

# 控制台中文乱码修复：强制 stdout/stderr 使用 UTF-8（桌面版 / 控制台均生效）
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 确保项目根目录在 sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
# PyInstaller 打包后，静态资源/规则文件位于 _MEIPASS 解压目录
_MEIPASS = getattr(sys, "_MEIPASS", None)
if _MEIPASS:
    PROJECT_ROOT = _MEIPASS
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config, get_config
from core.brain_left import LeftBrain
from core.brain_right import RightBrain
from core.countermeasure_fsm import CountermeasureFSM, FSMLevel
from core.llm_client import LLMClient
from core.medic_agent import MedicAgent
from core.monitor import get_metrics_collector
from core.validator import ValidatorAgent
from knowledge.hot_store import HotKnowledgeStore
from knowledge.cold_store import ColdKnowledgeStore
from knowledge.router import KnowledgeRouter
from organs.alarm_nose import AlarmNose
from organs.actor_ip_isolation import IPIsolationAgent
from organs.auditor_log import LogAuditorAgent, LogAnomalySimulator
from organs.capturer import PacketCapture
from organs.firewall_executor import FirewallExecutor
from organs.notifier import Notifier
from organs.observer_outbound import OutboundMonitor
from organs.observer_traffic import TrafficMonitorAgent
from organs.scanner_vuln import VulnScannerAgent, VulnSimulator
from organs.scheduler_resource import ResourceSchedulerAgent
from organs.tracker_forensic import ForensicTrackerAgent
from persistence import get_persistence, PersistenceStore
from tests.simulate_attack import AttackSimulator
from utils.logger import init_global_logger, get_logger

try:
    from fastapi import FastAPI, Request, HTTPException, Depends
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, Response
    from fastapi.staticfiles import StaticFiles
    import uvicorn
except ImportError:
    print("缺少依赖：pip install fastapi uvicorn sse-starlette")
    sys.exit(1)

try:
    import httpx  # 用于 /api/chat 对话代理转发
except ImportError:
    print("缺少依赖：pip install httpx")
    sys.exit(1)

# 服务器启动时间戳（用于健康检查）
_server_start_time = time.time()

# ==================== Token 认证 ====================

# 从环境变量 DFU_WEB_TOKEN 读取；未设置则生成随机 token 并打印到控制台/日志
_API_TOKEN = os.environ.get("DFU_WEB_TOKEN", "")
if not _API_TOKEN:
    _API_TOKEN = secrets.token_hex(16)
    print(f"[Auth] 未设置 DFU_WEB_TOKEN，已生成随机 Token: {_API_TOKEN}")
else:
    print("[Auth] 已从环境变量 DFU_WEB_TOKEN 加载 Token")
_AUTH_ENABLED = True
security = HTTPBearer(auto_error=False)

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Bearer Token 认证中间件。Token 来自 DFU_WEB_TOKEN（未设置则随机生成）。"""
    if credentials is None:
        raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
    if credentials.credentials != _API_TOKEN:
        raise HTTPException(status_code=403, detail="Token 无效")
    return True

# ==================== 系统管理器 ====================

class DFUWebManager:
    """封装 DFU 系统生命周期，为 Web API 提供后端能力。"""

    def __init__(self):
        self.config = get_config()
        self.bus: MessageBus = get_message_bus()
        self.logger = get_logger("WebServer")
        self._running = False

        # 监控指标采集器
        self.metrics = get_metrics_collector()

        # 知识库（冷热分层 + 路由器）
        self.hot_store = HotKnowledgeStore(
            max_capacity=500, unit_id="web",
            db_path=os.path.join(PROJECT_ROOT, "knowledge", "hot_store_web.db"),
        )
        self.cold_store = ColdKnowledgeStore(
            store_path=os.path.join(PROJECT_ROOT, "knowledge", "cold_store.jsonl"),
            unit_id="web"
        )
        self.knowledge_router = KnowledgeRouter(
            hot_store=self.hot_store,
            cold_store=self.cold_store,
            unit_id="web"
        )

        # LLM
        self.llm_client = LLMClient(self.config.llm)

        # 核心 Agent
        self.traffic_monitor = TrafficMonitorAgent(self.config)
        self.left_brain = LeftBrain(
            self.config,
            llm_client=self.llm_client,
            knowledge_router=self.knowledge_router,
        )
        self.right_brain = RightBrain(
            self.config,
            llm_client=self.llm_client,
            knowledge_router=self.knowledge_router,
        )
        self.validator = ValidatorAgent(self.config)
        self.ip_isolation = IPIsolationAgent(self.config)

        # 阶段2 Agent
        self.vuln_scanner = VulnScannerAgent(self.config, demo_mode=False)
        self.log_auditor = LogAuditorAgent(self.config, demo_mode=False)
        self.resource_scheduler = ResourceSchedulerAgent(self.config, demo_mode=False)
        self.forensic_tracker = ForensicTrackerAgent(self.config)
        self.outbound_monitor = OutboundMonitor(self.config, demo_mode=False)
        self.medic_agent = MedicAgent(self.config)
        self.vuln_simulator = VulnSimulator(self.config)
        self.log_simulator = LogAnomalySimulator(self.config)

        # ── 报警鼻 4 级警报系统（Phase 2 落地）──
        # FSM 共享实例：报警鼻只读取等级；L4 软隔离信号由现有 FSM 机制执行（不物理断网）
        self.fsm = CountermeasureFSM()
        self.alarm_nose = AlarmNose(
            config=self.config.alarm_nose,
            notifier=Notifier(),
            firewall=FirewallExecutor(self.logger, real_exec=False),  # 默认模拟，跨平台安全
            fsm=self.fsm,
            bus=self.bus,
            on_l4_execute=self._on_alarm_nose_l4,
        )

        # 攻击模拟器
        self.simulator = AttackSimulator(
            ddos_source_count=self.config.simulator.ddos_source_ip_count,
            ddos_rate=self.config.simulator.ddos_requests_per_second,
            scan_port_range=self.config.simulator.port_scan_range,
            scan_speed=self.config.simulator.port_scan_speed,
            brute_attempts=self.config.simulator.brute_force_attempts,
            brute_target_port=self.config.simulator.brute_force_target_port,
        )

        # 实时抓包模块 (PacketCapture)
        self.capturer = PacketCapture(self.bus, self.config)
        # 全流量监听：不过滤端口，所有 TCP/UDP 流量进入检测管线
        # （如需定向监控可调用 set_port_filter([...]) 指定端口）
        self.capturer.enable_detection_feed()
        self.logger.info("实时抓包模块已初始化 (PacketCapture)")

        # 熔断状态
        self._meltdown = False

        # 持久化存储
        self._persistence: PersistenceStore = get_persistence()

        # SSE 客户端队列
        self._sse_queues: List[asyncio.Queue] = []

        # 统计
        self._stats: Dict[str, int] = {
            "total_alerts": 0,
            "total_actions": 0,
            "total_decisions": 0,
            "total_events": 0,
        }

        # Medic 注册
        self._medic_alive_flags: Dict[str, bool] = {
            "TrafficMonitor": True, "LeftBrain": True, "RightBrain": True,
            "Validator": True, "IPIsolation": True, "VulnScanner": True,
            "LogAuditor": True, "ResourceScheduler": True, "ForensicTracker": True,
            "PacketCapture": True,
        }

    async def start(self) -> None:
        """启动所有 Agent（幂等：已在运行时直接返回，可安全重复调用）。"""
        if self._running:
            self.logger.info("DFU 已在运行中，忽略重复启动")
            return
        self._running = True
        self._start_time = time.time()
        try:
            # 持久化存储
            await self._persistence.connect()

            # 处置 + 校验
            await self.ip_isolation.start()
            await self.validator.start()

            # 阶段2器官
            await self.resource_scheduler.start()
            await self.forensic_tracker.start()
            await self.vuln_scanner.start()
            await self.log_auditor.start()
            await self.outbound_monitor.start()

            # 双引擎
            await self.left_brain.start()
            await self.right_brain.start()

            # 观测
            await self.traffic_monitor.start()

            # 实时抓包
            self.capturer.start()

            # 医疗
            self._register_medic()
            await self.medic_agent.start()

            # 消息总线全局监听 → SSE
            await self.bus.subscribe("*", self._on_bus_event)

            # 报警鼻后台巡检（L1 衰减 + 倒计时兜底）
            self.alarm_nose.start()

            # 启动指标采集后台任务
            asyncio.create_task(self._metrics_loop())
        except Exception as e:
            self._running = False
            self._start_time = 0.0
            self.logger.error(f"DFU 启动失败，已回滚运行状态: {e}")
            raise

        self.logger.info("Web 管理器：所有 Agent 已启动")

    async def stop(self) -> None:
        """停止所有 Agent（幂等：未运行时直接返回，可安全重复调用）。"""
        if not self._running:
            self.logger.info("DFU 未在运行，忽略停止")
            return
        self._running = False
        try:
            await self.alarm_nose.stop()
            await self.medic_agent.stop()
            await self.traffic_monitor.stop()
            await self.left_brain.stop()
            await self.right_brain.stop()
            await self.validator.stop()
            await self.ip_isolation.stop()
            await self.vuln_scanner.stop()
            await self.log_auditor.stop()
            await self.resource_scheduler.stop()
            await self.forensic_tracker.stop()
            await self.outbound_monitor.stop()
            await self.capturer.stop()
            await self._persistence.close()
        except Exception as e:
            self.logger.error(f"DFU 停止过程异常: {e}")
        self._start_time = 0.0
        self.logger.info("Web 管理器：所有 Agent 已停止")

    def _register_medic(self) -> None:
        """注册所有 Agent 到医疗系统。"""
        for agent_name in self._medic_alive_flags:
            def make_hb_cb(name):
                async def hb():
                    return self._meltdown is False and self._medic_alive_flags.get(name, False)
                return hb
            def make_snapshot_cb(name):
                def snap():
                    return {"name": name, "timestamp": datetime.now().isoformat()}
                return snap
            def make_iso_cb(name):
                async def iso(aname, isolated):
                    self.logger.warning(f"[医疗回调] {aname} {'隔离' if isolated else '恢复'}")
                return iso
            self.medic_agent.register_agent(
                agent_name=agent_name,
                heartbeat_callback=make_hb_cb(agent_name),
                snapshot_callback=make_snapshot_cb(agent_name),
                isolation_callback=make_iso_cb(agent_name),
            )

    # ── 消息总线 → SSE ──

    async def _on_bus_event(self, msg: Message) -> None:
        """将消息总线事件转化为 SSE 事件并推送到所有客户端。"""
        if not self._running:
            return
        msg_type = msg.type

        sse_event = None

        if msg_type == "threat_alert":
            payload = msg.payload
            indicator = payload.get("indicator", payload)
            sse_event = {
                "event": "alert",
                "data": json.dumps({
                    "type": "alert",
                    "alert_id": indicator.get("id", payload.get("id", "")),
                    "severity": indicator.get("severity", payload.get("severity", "medium")),
                    "attack_type": indicator.get("category", payload.get("category", "unknown")),
                    "src_ip": indicator.get("source_ip", payload.get("source_ip", "")),
                    "message": indicator.get("description", payload.get("description", "")),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }, ensure_ascii=False),
            }
            self._stats["total_alerts"] += 1
            self.metrics.record_organ("traffic")
            # 持久化
            indicator_dict = indicator if isinstance(indicator, dict) else indicator.to_dict()
            asyncio.create_task(self._persistence.insert_alert(indicator_dict))
            # 报警鼻：threat_alert 事件 → assess（L1-L4 分级评估）
            asyncio.create_task(self.alarm_nose.assess(payload))

        elif msg_type == "isolation_action":
            # 报警鼻：isolation_action 事件 → assess_fsm（只读 FSM 等级联动）
            asyncio.create_task(
                self.alarm_nose.assess_fsm(self.fsm.get_all_levels() if self.fsm else {})
            )

        elif msg_type == "defense_plan":
            sse_event = {
                "event": "decision",
                "data": json.dumps({
                    "type": "decision",
                    "source": "LeftBrain",
                    "alert_id": msg.payload.get("alert_id", ""),
                    "action": msg.payload.get("action", ""),
                    "reasoning": msg.payload.get("reason", "")[:200],
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }, ensure_ascii=False),
            }
            self._stats["total_decisions"] += 1

        elif msg_type == "attack_analysis":
            sse_event = {
                "event": "decision",
                "data": json.dumps({
                    "type": "decision",
                    "source": "RightBrain",
                    "alert_id": msg.payload.get("alert_id", ""),
                    "action": msg.payload.get("attack_type", ""),
                    "reasoning": msg.payload.get("root_cause", "")[:200],
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }, ensure_ascii=False),
            }

        elif msg_type == "action_result":
            sse_event = {
                "event": "action",
                "data": json.dumps({
                    "type": "action",
                    "agent": "IPIsolation",
                    "target_ip": msg.payload.get("target_ip", ""),
                    "result": "isolated" if msg.payload.get("success") else "failed",
                    "message": msg.payload.get("message", ""),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }, ensure_ascii=False),
            }
            self._stats["total_actions"] += 1
            self.metrics.record_organ("ip_isolation")
            # 持久化
            iso_data = {
                "alert_id": msg.payload.get("alert_id", ""),
                "action": msg.payload.get("action", "block"),
                "target_ip": msg.payload.get("target_ip", ""),
                "reason": "",
                "success": msg.payload.get("success", False),
                "message": msg.payload.get("message", ""),
                "safety_rejected": msg.payload.get("safety_rejected", False),
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }
            asyncio.create_task(self._persistence.insert_isolation_action(iso_data))

        elif msg_type in ("medic_event", "schedule_result", "forensic_report"):
            sse_event = {
                "event": "system",
                "data": json.dumps({
                    "type": "system",
                    "component": msg.source,
                    "status": "healthy",
                    "message": str(msg.payload)[:200],
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }, ensure_ascii=False),
            }
            # 按消息来源映射器官
            source_organ_map = {
                "VulnScanner": "vuln_scan",
                "LogAuditor": "log_audit",
                "ResourceScheduler": "compute",
                "ForensicTracker": "trace",
            }
            if msg.source in source_organ_map:
                self.metrics.record_organ(source_organ_map[msg.source])

        if sse_event:
            self._stats["total_events"] += 1
            await self._broadcast_sse(sse_event)

    async def _broadcast_sse(self, event: dict) -> None:
        """向所有 SSE 客户端广播事件。"""
        dead = []
        for q in self._sse_queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            try:
                self._sse_queues.remove(q)
            except ValueError:
                pass

    def add_sse_client(self) -> asyncio.Queue:
        """注册新的 SSE 客户端，返回其事件队列。"""
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._sse_queues.append(q)
        return q

    def remove_sse_client(self, q: asyncio.Queue) -> None:
        """移除 SSE 客户端。"""
        try:
            self._sse_queues.remove(q)
        except ValueError:
            pass

    # ── 监控指标 ──

    async def _metrics_loop(self) -> None:
        """后台定时采集系统指标并同步 LLM 统计。"""
        while self._running:
            try:
                self.metrics.update_system_metrics()
                self.metrics.sync_llm_stats(
                    self.llm_client.call_count,
                    self.llm_client.fail_count,
                )
                # 消费 LLMClient 中暂存的延迟毫秒数
                lat = self.llm_client._last_latency_ms
                if lat > 0:
                    self.metrics.record_llm_call(success=True, latency_ms=lat)
                    self.llm_client._last_latency_ms = 0.0
                # 报警鼻：MedicAgent 心跳回调变化 → assess_health
                try:
                    await self.alarm_nose.assess_health(self.medic_agent.get_health_status())
                except Exception as e:
                    self.logger.debug(f"报警鼻健康评估异常: {e}")
            except Exception as e:
                self.logger.debug(f"指标采集异常: {e}")
            await asyncio.sleep(2.0)

    # ── 攻击场景 ──

    async def run_attack(self, scenario: str) -> Dict[str, Any]:
        """触发攻击场景。"""
        if self._meltdown:
            return {"success": False, "error": "系统处于熔断状态，无法触发攻击"}

        try:
            if scenario == "all":
                await self._run_single("ddos")
                await asyncio.sleep(1.5)
                await self._run_single("port_scan")
                await asyncio.sleep(1.5)
                await self._run_single("brute_force")
            else:
                await self._run_single(scenario)

            return {"success": True, "scenario": scenario}
        except Exception as e:
            self.logger.error(f"攻击场景 {scenario} 失败: {e}")
            return {"success": False, "error": str(e)}

    async def _run_single(self, scenario: str) -> None:
        """执行单个攻击场景，生成流量数据并发布到消息总线。"""
        if scenario == "ddos":
            packets = self.simulator.generate_ddos()
            for packet in packets:
                await self.bus.publish(Message(
                    source="AttackSimulator", target="TrafficMonitor",
                    type="traffic_data", payload=packet,
                ))
        elif scenario == "port_scan":
            packets = self.simulator.generate_port_scan()
            for packet in packets:
                await self.bus.publish(Message(
                    source="AttackSimulator", target="TrafficMonitor",
                    type="traffic_data", payload=packet,
                ))
        elif scenario == "brute_force":
            packets = self.simulator.generate_brute_force()
            for packet in packets:
                await self.bus.publish(Message(
                    source="AttackSimulator", target="TrafficMonitor",
                    type="traffic_data", payload=packet,
                ))
        await asyncio.sleep(3.0)  # 等待 Agent 处理完成

    # ── 报警鼻 L4 软隔离信号桥接 ──

    async def _on_alarm_nose_l4(self, signal: dict) -> None:
        """
        报警鼻 L4 触发信号 → 复用 countermeasure_fsm 现有 L4 软隔离机制（软隔离，不物理断网）。
        报警鼻只发信号；此处由既有 FSM 三闸门流程实际执行网络隔离。
        """
        source_ip = signal.get("source_ip", "")
        if source_ip and self.fsm is not None:
            try:
                current = self.fsm.get_level(source_ip)
                if current == FSMLevel.L3_OFFENSIVE:
                    action = self.fsm.check_network_kill_conditions(source_ip)
                    if action:
                        self.logger.warning(
                            f"[AlarmNose→FSM] L4 软隔离已由 FSM 执行: {source_ip} "
                            f"{action.old_level}→{action.new_level} | {action.reason}"
                        )
                else:
                    self.logger.warning(
                        f"[AlarmNose→FSM] L4 信号已接收（{source_ip} 当前 FSM 等级 {current}，"
                        f"软隔离由 FSM 按三闸门流程执行）"
                    )
            except Exception as e:
                self.logger.warning(f"[AlarmNose→FSM] L4 软隔离桥接异常: {e}")

        await self._broadcast_sse({
            "event": "alarm",
            "data": json.dumps({
                "type": "alarm_l4",
                "source": "AlarmNose",
                "severity": "severe",
                "src_ip": source_ip,
                "message": f"报警鼻 L4 触发，已发布软隔离信号（复用 FSM，不物理断网）: {signal.get('trigger', '')}",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }, ensure_ascii=False),
        })

    # ── 熔断 ──

    async def meltdown_on(self) -> Dict[str, Any]:
        """手动触发熔断。"""
        self._meltdown = True
        self._medic_alive_flags = {k: False for k in self._medic_alive_flags}
        self.logger.warning("[Web] 手动触发熔断")
        await self._broadcast_sse({
            "event": "system",
            "data": json.dumps({
                "type": "system", "component": "Meltdown",
                "status": "warning",
                "message": "系统熔断已激活，所有处置暂停",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }, ensure_ascii=False),
        })
        return {"success": True, "meltdown": True}

    async def meltdown_off(self) -> Dict[str, Any]:
        """手动解除熔断。"""
        self._meltdown = False
        self._medic_alive_flags = {k: True for k in self._medic_alive_flags}
        self.logger.info("[Web] 手动解除熔断")
        await self._broadcast_sse({
            "event": "system",
            "data": json.dumps({
                "type": "system", "component": "Meltdown",
                "status": "healthy",
                "message": "系统熔断已解除，恢复正常运行",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }, ensure_ascii=False),
        })
        return {"success": True, "meltdown": False}

    # ── 状态查询 ──

    def get_status(self) -> Dict[str, Any]:
        """获取系统状态摘要。"""
        left_stats = self.left_brain.get_stats()
        right_stats = self.right_brain.get_stats()
        validator_stats = self.validator.get_stats()
        blacklist = self.ip_isolation.get_blacklist()
        health = self.medic_agent.get_health_status()

        agent_status = {}
        for name, record in health.items():
            agent_status[name] = record.status.value if hasattr(record, 'status') else "unknown"

        return {
            "running": self._running,
            "meltdown": self._meltdown,
            "llm_mode": "mock" if self.llm_client.mock_mode else "real",
            "llm_model": self.llm_client.config.model,
            "agents": agent_status,
            "left_brain": {
                "total_alerts": left_stats["total_alerts"],
                "llm_count": left_stats.get("llm_count", 0),
                "fallback_count": left_stats.get("fallback_count", 0),
            },
            "right_brain": {
                "total_alerts": right_stats["total_alerts"],
                "avg_confidence": round(right_stats["avg_confidence"], 2),
                "llm_count": right_stats.get("llm_count", 0),
                "fallback_count": right_stats.get("fallback_count", 0),
            },
            "validator": {
                "passed": validator_stats["total_passed"],
                "rejected": validator_stats["total_rejected"],
            },
            "blacklist_count": len(blacklist),
            "blacklist_ips": list(blacklist),
            "persistence": {
                "connected": self._persistence.is_connected,
            },
        }

    def get_stats(self) -> Dict[str, Any]:
        """返回统计摘要。"""
        left_stats = self.left_brain.get_stats()
        validator_stats = self.validator.get_stats()

        total = max(self._stats["total_alerts"], 1)
        hit_rate = round(self._stats["total_actions"] / total * 100, 1)

        return {
            **self._stats,
            "hit_rate": hit_rate,
            "passed": validator_stats["total_passed"],
            "rejected": validator_stats["total_rejected"],
            "left_severity": left_stats["alerts_by_severity"],
            "left_compute": round(left_stats.get("total_compute_units", 0), 1),
            "compliance": "16/16",
        }

    # ── DFU 启停状态（供前端按钮轮询） ──

    def get_dfu_status(self) -> Dict[str, Any]:
        """返回 DFU 运行状态、uptime 与各器官 components up/down。"""
        if self._running and self._start_time > 0:
            uptime = time.time() - self._start_time
            start_time_str = datetime.fromtimestamp(self._start_time).strftime("%Y-%m-%d %H:%M:%S")
        else:
            uptime = 0.0
            start_time_str = None

        components: Dict[str, str] = {}
        try:
            health = self.medic_agent.get_health_status()
        except Exception:
            health = {}
        for name, record in health.items():
            raw = record.status.value if hasattr(record, "status") else "unknown"
            if raw in ("healthy", "ok"):
                components[name] = "up"
            elif raw in ("degraded", "recovering", "busy"):
                components[name] = "degraded"
            else:
                components[name] = "down"

        return {
            "running": self._running,
            "uptime": round(uptime, 1),
            "start_time": start_time_str,
            "components": components,
        }

    # ── 12 器官实时数据 ──

    async def get_organs_data(self) -> Dict[str, Any]:
        """一次性返回 12 个器官的实时数据（由真实 Agent 状态组装）。

        数据结构：{ "<organ-id>": {"metrics": [...], "tableRows": [...], "list": [...]} }
        """
        data: Dict[str, Any] = {}

        # 读取各 Agent 真实状态（每项单独容错，防止单点异常拖垮整包）
        left_stats = self._safe(lambda: self.left_brain.get_stats(), {})
        right_stats = self._safe(lambda: self.right_brain.get_stats(), {})
        validator_stats = self._safe(lambda: self.validator.get_stats(), {})
        ip_stats = self._safe(lambda: self.ip_isolation.get_stats(), {})
        blacklist = self._safe(lambda: list(self.ip_isolation.get_blacklist()), [])
        health = self._safe(lambda: self.medic_agent.get_health_status(), {})
        medic_log = self._safe(lambda: self.medic_agent.get_medic_log(), [])
        breaker = self._safe(lambda: self.medic_agent.get_circuit_breaker_status(), {"is_open": False, "reason": ""})
        cap_stats = self._safe(lambda: dict(self.capturer.stats), {})
        observer = self.traffic_monitor
        req_counter = self._safe(lambda: dict(observer._request_counter), {})
        port_set = self._safe(lambda: {k: set(v) for k, v in observer._port_set.items()}, {})
        vuln_alerted = self._safe(lambda: sorted(self.vuln_scanner._alerted), [])
        schedule_history = self._safe(lambda: self.resource_scheduler.get_schedule_history(), [])
        resource_state = self._safe(lambda: self.resource_scheduler.get_resource_state(), None)
        kb_stats = await self._safe_async(self.knowledge_router.get_stats, {})
        hot_stats = await self._safe_async(self.hot_store.get_stats, {})
        cold_stats = await self._safe_async(self.cold_store.get_stats, {})
        hot_keys = await self._safe_async(self.hot_store.keys, [])
        metrics = self._safe(lambda: self.metrics.get_metrics(), {})

        # 事件历史（供汇报嘴/报警鼻）
        history = _event_history[-30:]

        left_sev = left_stats.get("alerts_by_severity", {})
        right_cat = right_stats.get("analyses_by_category", {})
        total_packets = cap_stats.get("total_packets", 0)
        published = cap_stats.get("published_events", 0)
        filtered = cap_stats.get("filtered_dropped", 0)
        pcap = cap_stats.get("pcap_packets", 0)

        # ---- 1. prefrontal 前额叶 · 实时态势 ----
        obs_targets = []
        for ip, ports in list(port_set.items())[:6]:
            obs_targets.append([ip, f"{len(ports)} port(s)", "Monitoring", "-"])
        for ip in blacklist[:2]:
            obs_targets.append([ip, "-", "Blocked", "Active"])
        data["prefrontal"] = {
            "metrics": [
                total_packets,
                len(req_counter),
                len(blacklist),
            ],
            "tableRows": obs_targets[:8],
            "list": [
                {"t": "Firewall", "s": f"{len(blacklist)} rules (blacklist)"},
                {"t": "Defense Mode", "s": "Auto" if self._running else "Standby"},
                {"t": "Capture Feed", "s": f"published {published} / dropped {filtered}"},
            ],
        }

        # ---- 2. left-hand 左手 · 巡逻感知 ----
        patrol_rows = []
        for item in vuln_alerted[-6:]:
            cve, _, target = item.partition(":")
            patrol_rows.append([cve or item, target or "-", "Alerted", "High"])
        for ip, ports in list(port_set.items())[:4]:
            patrol_rows.append([f"{len(ports)} port(s) probed", ip, "Scan", "Info"])
        data["left-hand"] = {
            "metrics": [
                len(port_set),
                len(vuln_alerted),
                round(pcap / 60.0, 1),
            ],
            "tableRows": patrol_rows[:8],
            "list": [
                {"t": "Patrol Policy", "s": "Probe monitored ports & CVE scan"},
                {"t": "Vuln Watchlist", "s": f"{len(vuln_alerted)} CVE alert(s)"},
                {"t": "Deep Scan", "s": "High-risk ports only"},
            ],
        }

        # ---- 3. left-brain 左脑 · 防御决策 ----
        data["left-brain"] = {
            "metrics": [
                left_stats.get("total_alerts", 0),
                left_stats.get("llm_count", 0),
                round(left_stats.get("total_compute_units", 0), 1),
            ],
            "tableRows": [
                ["Low", "low", left_sev.get("low", 0)],
                ["Medium", "medium", left_sev.get("medium", 0)],
                ["High", "high", left_sev.get("high", 0)],
                ["Severe", "severe", left_sev.get("severe", 0)],
            ],
            "list": [
                {"t": "Model", "s": "LLM + Rules"},
                {"t": "Schema Blocks", "s": f"{left_stats.get('schema_blocks', 0)} blocked / {left_stats.get('schema_passes', 0)} passed"},
                {"t": "Fallback", "s": f"{left_stats.get('fallback_count', 0)} fallback(s)"},
            ],
        }

        # ---- 4. right-brain 右脑 · 干扰决策 ----
        data["right-brain"] = {
            "metrics": [
                right_stats.get("total_alerts", 0),
                round(right_stats.get("avg_confidence", 0), 2),
                right_stats.get("llm_count", 0),
            ],
            "tableRows": [
                ["DDoS", "ddos", right_cat.get("ddos", 0)],
                ["Port Scan", "port_scan", right_cat.get("port_scan", 0)],
                ["Brute Force", "brute_force", right_cat.get("brute_force", 0)],
                ["Vuln", "vuln", right_cat.get("vuln", 0)],
                ["Audit", "audit", right_cat.get("audit", 0)],
            ],
            "list": [
                {"t": "Model", "s": "LLM + Rules"},
                {"t": "Schema Blocks", "s": f"{right_stats.get('schema_blocks', 0)} blocked / {right_stats.get('schema_passes', 0)} passed"},
                {"t": "Fallback", "s": f"{right_stats.get('fallback_count', 0)} fallback(s)"},
            ],
        }

        # ---- 5. right-hand 右手 · 主动执行 ----
        block_rows = []
        for ip in blacklist[:6]:
            block_rows.append([f"#{block_rows.__len__() + 1}", "BLOCK", ip, "Active"])
        data["right-hand"] = {
            "metrics": [
                len(block_rows),
                ip_stats.get("total_blocks", 0) + ip_stats.get("total_releases", 0),
                round(self._safe(lambda: ip_stats.get("total_blocks", 0) / max(ip_stats.get("total_blocks", 0) + ip_stats.get("total_releases", 0) + ip_stats.get("total_errors", 0), 1) * 100, 0), 1),
            ],
            "tableRows": block_rows[:8] if block_rows else [["-", "-", "-", "Idle"]],
            "list": [
                {"t": "Total Blocks", "s": str(ip_stats.get("total_blocks", 0))},
                {"t": "Total Releases", "s": str(ip_stats.get("total_releases", 0))},
                {"t": "Safety Rejected", "s": str(ip_stats.get("total_rejected_by_safety", 0))},
            ],
        }

        # ---- 6. repair-hand 备用修复手 · 弹性执行 ----
        sched_rows = []
        for log in schedule_history[-6:]:
            sched_rows.append([
                str(log.get("timestamp", "-"))[11:19] if isinstance(log.get("timestamp"), str) else "-",
                log.get("task", log.get("type", "-")),
                str(log.get("status", log.get("result", "-"))),
            ])
        role = "Combat" if self._running and any(r.status.value not in ("healthy",) for r in health.values()) else "Patrol"
        resource = resource_state
        res_line = "n/a"
        if resource is not None:
            res_line = f"{resource.used_cpu_cores}/{resource.total_cpu_cores} CPU · {resource.used_memory_gb}/{resource.total_memory_gb} GB"
        data["repair-hand"] = {
            "metrics": [
                role,
                len(schedule_history),
                len(schedule_history),
            ],
            "tableRows": sched_rows[:6],
            "list": [
                {"t": "Role", "s": role + " (combat on failover)"},
                {"t": "Resource Pool", "s": res_line},
                {"t": "Quota Per Agent", "s": str(resource.quota_per_agent) if resource is not None else "-"},
            ],
        }

        # ---- 7. self-heal 自愈单元 · 本体监护 ----
        unhealthy = [name for name, r in health.items() if r.status.value not in ("healthy",)]
        report_rows = []
        for log in medic_log[:8]:
            report_rows.append([
                str(log.get("timestamp", "-"))[:19],
                str(log.get("event_type", log.get("description", "-")))[:40],
                str(log.get("status", log.get("result", "-")))[:40],
            ])
        data["self-heal"] = {
            "metrics": [
                "Healthy" if not unhealthy else "Degraded",
                f"{len(health)} checks",
                len(unhealthy),
            ],
            "tableRows": report_rows[:8],
            "list": [
                {"t": "Heartbeat", "s": "1s cycle · " + ("OK" if not unhealthy else "ALERT")},
                {"t": "Circuit Breaker", "s": ("OPEN" if breaker.get("is_open") else "Closed") + (f" · {breaker.get('reason')}" if breaker.get("reason") else "")},
                {"t": "Unhealthy Organs", "s": ", ".join(unhealthy) if unhealthy else "None"},
            ],
        }

        # ---- 8. report-mouth 汇报嘴 · 事件日志 ----
        timeline_rows = []
        for ev in history:
            ts = ev.get("timestamp")
            ts_s = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if isinstance(ts, (int, float)) else str(ts)
            timeline_rows.append([
                ts_s,
                str(ev.get("category", ev.get("type", "-"))),
                str(ev.get("severity", "-")),
                str(ev.get("source_ip", "-")),
                str(ev.get("description", ""))[:30],
            ])
        data["report-mouth"] = {
            "metrics": [
                len(history),
                left_stats.get("total_alerts", 0) + right_stats.get("total_alerts", 0),
                self._stats.get("total_actions", 0),
            ],
            "tableRows": timeline_rows[:8],
            "list": [
                {"t": "Persistence", "s": "Connected" if self._persistence.is_connected else "Disconnected"},
                {"t": "Export", "s": "CSV timeline available"},
            ],
        }

        # ---- 9. alarm-nose 报警鼻 · 4级自动警报闭环 ----
        nose = self._safe(lambda: self.alarm_nose.get_status(), {})
        nose_level = nose.get("level", "L0-normal")
        nose_rows = []
        for h in nose.get("history", [])[-8:]:
            nose_rows.append([
                str(h.get("timestamp", "-"))[11:19],
                str(h.get("level", "-")),
                str(h.get("detail", ""))[:36],
            ])
        nose_l4_ips = nose.get("fsm_l4_ips") or []
        countdown_s = nose.get("countdown_remaining_secs") or 0
        data["alarm-nose"] = {
            "metrics": [
                nose_level,
                nose.get("alert_count", 0),
                f"{round(countdown_s)}s" if countdown_s and nose.get("ack_required") else "—",
            ],
            "tableRows": nose_rows[:8] if nose_rows else [["-", "-", "待触发"]],
            "list": [
                {"t": "Fuse Config", "s": f"L2={int(self.config.alarm_nose.l2_countdown_secs)}s / L3={int(self.config.alarm_nose.l3_countdown_secs)}s / L4={int(self.config.alarm_nose.l4_execute_countdown_secs)}s"},
                {"t": "Meltdown", "s": "Active" if self._meltdown else "Off"},
                {"t": "FSM Soft-Isolation", "s": f"{len(nose_l4_ips)} IP(s) L4-isolate"},
            ],
        }

        # ---- 10. memory 记忆库脑干 · 攻防知识库 ----
        kb_rows = []
        for key in hot_keys[:8]:
            kb_rows.append([str(key), "Hot", str(hot_stats.get("size", "-"))])
        data["memory"] = {
            "metrics": [
                kb_stats.get("total_queries", 0),
                hot_stats.get("size", 0),
                cold_stats.get("size", 0),
            ],
            "tableRows": kb_rows[:8],
            "list": [
                {"t": "KB Hit Rate", "s": f"{round(kb_stats.get('hit_rate', 0) * 100, 1)}%" if isinstance(kb_stats.get("hit_rate"), float) else str(kb_stats.get("hit_rate", "-"))},
                {"t": "Hot Store", "s": f"{hot_stats.get('size', 0)}/{hot_stats.get('max_capacity', '-')} · hit {round(hot_stats.get('hit_rate', 0) * 100, 1)}%" if isinstance(hot_stats.get("hit_rate"), float) else str(hot_stats.get("size", 0))},
                {"t": "Cold Store", "s": f"{cold_stats.get('size', 0)} archived · {cold_stats.get('total_archives', 0)} archives"},
            ],
        }

        # ---- 11. whitelist 白名单前置单元 · 信任前置 ----
        wl_rows = []
        for ip in blacklist[:6]:
            wl_rows.append(["07-31", ip, "IP"])
        data["whitelist"] = {
            "metrics": [
                len(blacklist),
                0,
                ip_stats.get("total_blocks", 0) + ip_stats.get("total_monitors", 0),
            ],
            "tableRows": wl_rows[:6] if wl_rows else [["-", "-", "-"]],
            "list": [
                {"t": "Policy", "s": "Matched WL entries pass through"},
                {"t": "Monitored", "s": f"{ip_stats.get('total_monitors', 0)} monitor(s)"},
            ],
        }

        # ---- 12. skill-box Skill工具箱 · 工具接入 ----
        tool_rows = []
        org_throughput = metrics.get("org_throughput", {}) or {}
        for organ_id, count in list(org_throughput.items())[:8]:
            tool_rows.append([str(organ_id), "On", str(count)])
        data["skill-box"] = {
            "metrics": [
                len(org_throughput),
                len(org_throughput),
                sum(v for v in org_throughput.values() if isinstance(v, (int, float))),
            ],
            "tableRows": tool_rows[:8],
            "list": [
                {"t": "LLM Calls", "s": f"{self.llm_client.call_count} calls / {self.llm_client.fail_count} fails"},
                {"t": "Last Latency", "s": f"{self.llm_client._last_latency_ms:.0f} ms" if self.llm_client._last_latency_ms > 0 else "-"},
                {"t": "Mode", "s": "mock" if self.llm_client.mock_mode else "real"},
            ],
        }

        return data

    @staticmethod
    def _safe(fn, default):
        try:
            return fn()
        except Exception:
            return default

    @staticmethod
    async def _safe_async(coro_factory, default):
        try:
            return await coro_factory()
        except Exception:
            return default


# ==================== FastAPI 应用 ====================

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    global manager
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    init_global_logger(log_dir)
    # 仅创建管理器实例，不自动启动 DFU；由前端"启动 DFU"按钮通过 API 触发
    manager = DFUWebManager()
    yield
    if manager and manager._running:
        await manager.stop()


app = FastAPI(title="DFU 管理界面", version="1.0", lifespan=lifespan)
manager: Optional[DFUWebManager] = None
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")

# Live Demo SSE 全局事件队列与历史
_event_queues: list[asyncio.Queue] = []
_event_history: list[dict] = []

# ── CORS 中间件 ──
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 安全认证中间件 ──
from fastapi import HTTPException, Request
import secrets

def _get_api_token() -> str:
    """返回当前 Web Token（与顶部 _API_TOKEN 一致：DFU_WEB_TOKEN 或随机生成）。"""
    return _API_TOKEN


_AUTH_WHITELIST = [
    # 健康检查（无需鉴权）
    "/healthz",
    "/readyz",
    "/health",
    # 普通页面（无需鉴权）
    "/live",
    "/compare",
    "/monster",
    "/login",
    "/static",
    # Token 分发端点（前端启动时获取 token）
    "/api/token",
]


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """API Token 认证中间件"""
    path = request.url.path

    if any(path.startswith(w) for w in _AUTH_WHITELIST):
        return await call_next(request)

    if path.startswith("/api/"):
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not token:
            token = request.headers.get("X-DFU-Token", "").strip()
        if not token or not secrets.compare_digest(token, _get_api_token()):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "message": "请在请求头中提供有效的 API Token"}
            )

    return await call_next(request)


# ── 静态页面 ──

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("<h1>index.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/live", response_class=HTMLResponse)
async def live_demo():
    """Live Demo 攻击演示大屏"""
    live_path = os.path.join(STATIC_DIR, "live.html")
    if not os.path.exists(live_path):
        return HTMLResponse("<h1>live.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    live_html = Path(live_path).read_text(encoding="utf-8")
    return HTMLResponse(content=live_html)


@app.get("/compare", response_class=HTMLResponse)
async def compare_demo():
    """对比演示页: 无DFU防护 vs 有DFU防护"""
    compare_path = os.path.join(STATIC_DIR, "compare.html")
    if not os.path.exists(compare_path):
        return HTMLResponse("<h1>compare.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    compare_html = Path(compare_path).read_text(encoding="utf-8")
    return HTMLResponse(content=compare_html)


@app.get("/monster", response_class=HTMLResponse)
async def monster_demo():
    """MonsterDFU 小怪兽前端 UI（单文件 SPA）"""
    monster_path = os.path.join(STATIC_DIR, "monster.html")
    if not os.path.exists(monster_path):
        return HTMLResponse("<h1>monster.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    monster_html = Path(monster_path).read_text(encoding="utf-8")
    return HTMLResponse(content=monster_html)


# ── DFU 启停 API（供前端启动按钮 / 器官页调用，已加入白名单） ──

@app.get("/api/dfu/status")
async def dfu_status():
    """DFU 运行状态：running / uptime / start_time / components。"""
    return manager.get_dfu_status() if manager else {"running": False, "uptime": 0.0, "start_time": None, "components": {}}


@app.post("/api/dfu/start")
async def dfu_start():
    """启动 DFU 核心系统（幂等：已运行则直接返回成功）。"""
    if manager is None:
        return JSONResponse(status_code=503, content={"success": False, "message": "DFU 管理器尚未初始化"})
    try:
        await manager.start()
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": f"DFU 启动失败: {e}"})
    return {"success": True, "message": "DFU 已启动"}


@app.post("/api/dfu/stop")
async def dfu_stop():
    """停止 DFU 核心系统（幂等：未运行则直接返回成功）。"""
    if manager is None:
        return JSONResponse(status_code=503, content={"success": False, "message": "DFU 管理器尚未初始化"})
    try:
        await manager.stop()
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": f"DFU 停止失败: {e}"})
    return {"success": True, "message": "DFU 已停止"}


@app.get("/api/dfu/organs/data")
async def dfu_organs_data():
    """一次性返回 12 个器官实时数据；系统未运行时返回 running=false。"""
    if manager is None or not manager._running:
        return {"running": False}
    try:
        data = await manager.get_organs_data()
        return {"running": True, "organs": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"获取器官数据失败: {e}"})


# ── REST API ──

@app.post("/api/chat")
async def api_chat(request: Request):
    """对话代理：将 MonsterDFU 前端聊天请求转发到 OpenAI 兼容接口。
    请求体: {messages: [...], api_key: str, model: str, base_url: str, stream?: bool}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "请求体必须是合法 JSON"}, status_code=400)

    messages = body.get("messages")
    api_key = (body.get("api_key") or "").strip()
    model = (body.get("model") or "").strip() or "gpt-3.5-turbo"
    base_url = (body.get("base_url") or "").strip() or "https://api.openai.com/v1"
    stream = bool(body.get("stream", False))
    temperature = float(body.get("temperature", 0.7))
    max_tokens = int(body.get("max_tokens", 2048))

    if not messages or not isinstance(messages, list) or not messages:
        return JSONResponse({"error": "messages 参数缺失或格式错误"}, status_code=400)
    if not api_key:
        return JSONResponse({"error": "API key 为空，请在设置页配置 API Key 后再对话"}, status_code=400)

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
            if stream:
                req = client.build_request("POST", url, headers=headers, json=payload)
                resp = await client.send(req, stream=True)
                if resp.status_code >= 400:
                    detail = (await resp.aread()).decode("utf-8", "ignore")[:500]
                    return JSONResponse(
                        {"error": f"上游接口返回 {resp.status_code}", "detail": detail},
                        status_code=502,
                    )

                async def event_stream():
                    try:
                        async for line in resp.aiter_lines():
                            yield line + "\n"
                    finally:
                        await resp.aclose()

                return StreamingResponse(
                    event_stream(),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )

            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                try:
                    detail = resp.json()
                except Exception:
                    detail = resp.text[:500]
                return JSONResponse(
                    {"error": f"上游接口返回 {resp.status_code}", "detail": detail},
                    status_code=502,
                )
            return JSONResponse(resp.json())
    except httpx.TimeoutException:
        return JSONResponse(
            {"error": "请求上游接口超时，请检查 base_url 与网络连接"}, status_code=504
        )
    except Exception as exc:
        return JSONResponse({"error": f"请求上游接口失败: {exc}"}, status_code=502)


@app.get("/api/status")
async def api_status():
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    status = manager.get_status()
    # 补充 Token 消耗统计
    try:
        from core.llm_client import LLMClient
        status["token_usage"] = manager.llm_client.get_token_usage()
    except Exception:
        status["token_usage"] = None
    return status


@app.get("/api/token-usage")
async def api_token_usage():
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return manager.llm_client.get_token_usage()


@app.post("/api/reset-token-usage")
async def api_reset_token_usage():
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    manager.llm_client.reset_token_usage()
    return {"success": True, "message": "Token 统计已重置"}


@app.get("/api/stats")
async def api_stats():
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return manager.get_stats()


@app.post("/api/attack")
async def api_attack(request: Request, _auth=Depends(verify_token)):
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    body = await request.json()
    scenario = body.get("scenario", "all")
    result = await manager.run_attack(scenario)
    return result


@app.post("/api/honeypot/event")
async def api_honeypot_event(request: Request, _auth=Depends(verify_token)):
    """接收蜜罐上报的攻击事件，注入 DFU 检测→决策→处置管道。"""
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    if manager._meltdown:
        return JSONResponse({"error": "系统熔断中"}, status_code=503)

    body = await request.json()
    raw_category = body.get("category", "unknown")
    severity = body.get("severity", "medium")
    src_ip = body.get("src_ip", "0.0.0.0")
    src_port = body.get("src_port", 0)
    payload_preview = body.get("payload_preview", "")

    # 蜜罐分类 → DFU ThreatCategory 映射
    _HP_TO_DFU = {
        "web_scan": "port_scan", "web_attack": "port_scan",
        "ssh_brute": "brute_force", "ftp_brute": "brute_force",
        "smtp_scan": "port_scan", "rdp_scan": "port_scan",
        "db_scan": "port_scan", "ssl_scan": "port_scan",
        "tls_scan": "port_scan", "port_knock": "unknown",
        "unknown_probe": "unknown",
    }
    dfu_category = _HP_TO_DFU.get(raw_category, "unknown")

    alert = Message(
        source="Honeypot",
        target="TrafficMonitor",
        type="threat_alert",
        payload={
            "id": f"hp-{int(time.time())}-{src_ip.replace('.', '_')}",
            "category": dfu_category,
            "severity": severity,
            "source_ip": src_ip,
            "source_port": src_port,
            "target_ip": src_ip,
            "target_port": body.get("dst_port", 2222),
            "description": f"蜜罐捕获 {raw_category}: {payload_preview[:80]}",
            "raw_payload": payload_preview,
        },
    )
    await manager.bus.publish(alert)
    return {"success": True, "alert_id": alert.payload["id"]}


@app.post("/api/meltdown/on")
async def api_meltdown_on(_auth=Depends(verify_token)):
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return await manager.meltdown_on()


@app.post("/api/meltdown/off")
async def api_meltdown_off(_auth=Depends(verify_token)):
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return await manager.meltdown_off()


# ── L4 网络隔离确认 API（Phase 1.5）──

@app.post("/api/l4/confirm")
async def l4_confirm(request: Request):
    """
    Web 面板确认 L4 网络隔离（需 Token 认证）。
    调用 CountermeasureFSM.set_web_panel_confirmed(ip, True)
    三元组：确认后闸门3关闭，L4 自动降级回 L3。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    body = await request.json()
    source_ip = body.get("source_ip", "")
    if not source_ip:
        raise HTTPException(status_code=400, detail="缺少 source_ip 参数")

    manager = _get_manager()
    fsm = manager.fsm if hasattr(manager, 'fsm') else None
    if fsm is None:
        raise HTTPException(status_code=503, detail="FSM 未就绪")

    fsm.set_web_panel_confirmed(source_ip, True)
    return {
        "status": "ok",
        "action": "l4_confirmed",
        "source_ip": source_ip,
        "message": f"L4 隔离已确认，{source_ip} 将自动降级回 L3"
    }


@app.post("/api/l4/reject")
async def l4_reject(request: Request):
    """
    Web 面板拒绝 L4 网络隔离（取消确认，保持 L4 状态）。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    body = await request.json()
    source_ip = body.get("source_ip", "")
    if not source_ip:
        raise HTTPException(status_code=400, detail="缺少 source_ip 参数")

    manager = _get_manager()
    fsm = manager.fsm if hasattr(manager, 'fsm') else None
    if fsm is None:
        raise HTTPException(status_code=503, detail="FSM 未就绪")

    # 拒绝确认 → 保持 L4，不清除确认态（仍可后续确认）
    return {
        "status": "ok",
        "action": "l4_rejected",
        "source_ip": source_ip,
        "message": f"L4 隔离保持，请继续监控 {source_ip}"
    }


@app.get("/api/l4/status")
async def l4_status(request: Request):
    """
    获取 L4 状态概览：活跃 L4 IP 列表 + 三闸门状态。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    manager = _get_manager()
    fsm = manager.fsm if hasattr(manager, 'fsm') else None
    if fsm is None:
        return {"l4_active": [], "l4_count": 0, "fsm_available": False}

    all_levels = fsm.get_all_levels()
    l4_ips = {ip: level for ip, level in all_levels.items() if level == "L4-isolate"}

    l4_details = []
    for ip in l4_ips:
        state = fsm._states.get(ip)
        if state:
            now = time.time()
            passed, reason = state.check_l4_triple_gate(now)
            l4_details.append({
                "ip": ip,
                "level": state.level,
                "vuln_errors": state.vuln_error_count,
                "l3_unstoppable": (now - state.l3_unstoppable_since) if state.l3_unstoppable_since else 0,
                "web_confirmed": state.web_panel_confirmed,
                "triple_gate_passed": passed,
                "gate_reason": reason,
            })

    return {
        "l4_active": l4_details,
        "l4_count": len(l4_details),
        "fsm_summary": fsm.summary(),
        "fsm_available": True,
    }


# ── 报警鼻 4 级警报 API（Phase 2）──

@app.get("/api/alarm-nose/status")
async def alarm_nose_status(request: Request):
    """报警鼻实时状态：等级 / 倒计时 / 4 级告警历史（需 Token 认证）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    manager = _get_manager()
    if manager is None or manager.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    return manager.alarm_nose.get_status()


@app.post("/api/alarm-nose/ack")
async def alarm_nose_ack(request: Request):
    """人工确认当前警报（停止倒计时，解除警报，回到 L1 记录态）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    manager = _get_manager()
    if manager is None or manager.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    result = await manager.alarm_nose.manual_ack()
    return {"status": "ok", **result}


@app.post("/api/alarm-nose/cancel")
async def alarm_nose_cancel(request: Request):
    """人工取消当前警报（停止倒计时，取消自动升级，回到 L1 记录态）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    manager = _get_manager()
    if manager is None or manager.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    result = await manager.alarm_nose.manual_cancel()
    return {"status": "ok", **result}


@app.post("/api/alarm-nose/confirm-l4")
async def alarm_nose_confirm_l4(request: Request):
    """人工确认执行 L4：立即触发软隔离信号（复用 FSM 机制，不物理断网）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    manager = _get_manager()
    if manager is None or manager.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    result = await manager.alarm_nose.confirm_l4()
    if not result.get("success"):
        return JSONResponse(status_code=400, content={"status": "error", **result})
    return {"status": "ok", **result}


# ── Token 分发端点（前端启动时获取 token 注入请求头）──

@app.get("/api/token")
async def api_token():
    """返回当前 Web Token。前端通过此端点获取 token 并在后续 /api/* 请求头携带。"""
    return {"token": _get_api_token(), "header": "X-DFU-Token"}


# ── 健康检查端点 ──

@app.get("/healthz")
async def healthz():
    """存活探针：进程是否运行。"""
    return {"status": "ok"}

@app.get("/readyz")
async def readyz():
    """就绪探针：系统是否完成初始化并可以接受请求。"""
    if manager and manager._running:
        return {"status": "ready"}
    return JSONResponse({"status": "not_ready"}, status_code=503)


@app.get("/health")
async def health_check():
    """健康检查端点——各组件存活状态"""
    from utils.logging_config import get_logger as _get_logger
    health = {
        "status": "ok",
        "version": "0.1.0",
        "uptime": time.time() - _server_start_time,
        "timestamp": time.time(),
        "components": {
            "web_server": {"status": "up"},
            "fsm": {"status": "unknown"},
            "event_bus": {"status": "unknown"},
        }
    }

    try:
        fsm = _get_fsm()
        if fsm:
            health["components"]["fsm"] = {
                "status": "up",
                "level": fsm.get_global_level(),
                "managed_ips": len(fsm.isolated_ips) if hasattr(fsm, 'isolated_ips') else 0,
            }
            health["components"]["event_bus"] = {"status": "up"}
    except Exception as e:
        health["components"]["fsm"] = {"status": "degraded", "error": str(e)}
        health["status"] = "degraded"

    return health


# ── 辅助函数 ──

def _get_manager() -> Optional[DFUWebManager]:
    """获取全局 DFUWebManager 实例。"""
    global manager
    return manager


async def _check_auth(request: Request) -> bool:
    """检查请求是否携带有效的 API Token。支持 Authorization: Bearer 和 X-DFU-Token 两种方式。"""
    if not _AUTH_ENABLED:
        return True
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        token = request.headers.get("X-DFU-Token", "").strip()
    return bool(token) and secrets.compare_digest(token, _API_TOKEN)


def _get_fsm():
    """获取全局 FSM（CountermeasureFSM）实例。"""
    m = _get_manager()
    if m is None:
        return None
    return getattr(m, 'fsm', None)


# ── 演示模式（DFU最后一公里）──

@app.post("/api/demo/trigger")
async def demo_trigger(request: Request):
    """
    触发演示攻击序列。
    预设3个场景: c2_beacon, data_exfil, mixed_attack
    通过 EventChainRecorder 注入预设攻击事件，
    SSE 实时推送攻击→防御全过程。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")

    body = await request.json()
    scenario = body.get("scenario", "c2_beacon")

    manager = _get_manager()
    bus = get_message_bus()

    # 预设攻击场景事件序列
    events = _get_demo_events(scenario)

    # 异步注入（不阻塞响应）
    asyncio.create_task(_inject_demo_events(bus, events))

    return {
        "status": "ok",
        "scenario": scenario,
        "events_count": len(events),
        "message": f"演示模式已触发: {scenario}",
    }


@app.get("/api/demo/scenarios")
async def demo_scenarios():
    """返回可用的演示场景列表。"""
    return {
        "scenarios": [
            {"id": "c2_beacon", "name": "C2 信标检测", "description": "模拟 C2 服务器定期回连，触发信标检测→L0→L1→L2 升级"},
            {"id": "data_exfil", "name": "数据外泄", "description": "模拟内网服务器向公网传输大文件，触发外泄告警→L0→L1→L2 升级"},
            {"id": "mixed_attack", "name": "混合攻击 (C2+外泄+DDoS)", "description": "多源混合攻击，触发全链路 L0→L3 防御升级"},
        ]
    }


def _get_demo_events(scenario: str) -> list:
    """构造演示用攻击事件序列。"""
    now = time.time()
    events = []

    if scenario == "c2_beacon":
        # 6 次信标回连，间隔递增
        for i in range(6):
            events.append({
                "type": "outbound_traffic",
                "payload": {
                    "dst_ip": "203.0.113.42",
                    "dst_port": 4444,
                    "size": 128,
                    "timestamp": now + i * 3,
                }
            })
        # 再加上告警事件，让 FSM 看到
        for i in range(8):
            events.append({
                "type": "threat_alert",
                "payload": {
                    "source_organ": "outbound_monitor",
                    "indicator": {"source_ip": "203.0.113.42", "category": "beacon", "severity": "high"},
                    "category": "beacon",
                    "severity": "high",
                }
            })

    elif scenario == "data_exfil":
        # 外泄事件
        for i in range(5):
            size = 12 * 1024 * 1024 if i % 2 == 0 else 3 * 1024 * 1024
            events.append({
                "type": "outbound_traffic",
                "payload": {
                    "dst_ip": "198.51.100.88",
                    "dst_port": 443,
                    "size": size,
                    "timestamp": now + i * 0.5,
                }
            })
        for i in range(8):
            events.append({
                "type": "threat_alert",
                "payload": {
                    "source_organ": "outbound_monitor",
                    "indicator": {"source_ip": "198.51.100.88", "category": "exfiltration", "severity": "high"},
                    "category": "exfiltration",
                    "severity": "high",
                }
            })

    elif scenario == "mixed_attack":
        # 多源攻击
        ips = ["10.0.0.1", "10.0.0.2", "192.168.1.100"]
        for i, ip in enumerate(ips):
            for j in range(5):
                events.append({
                    "type": "threat_alert",
                    "payload": {
                        "source_organ": "monitor",
                        "indicator": {"source_ip": ip, "category": "ddos", "severity": "high"},
                        "category": "ddos",
                        "severity": "high",
                    }
                })
            events.append({
                "type": "outbound_traffic",
                "payload": {
                    "dst_ip": ip, "dst_port": 4444, "size": 128,
                    "timestamp": now + i * 2 + j * 0.3,
                }
            })

    return events


async def _inject_demo_events(bus, events):
    """异步注入演示事件到消息总线。"""
    for evt in events:
        msg = Message(
            source="DemoMode",
            target=evt.get("target", "EventAggregator"),
            type=evt["type"],
            payload=evt["payload"],
        )
        await bus.publish(msg)
        await _broadcast_event("attack_event", {
            "source_ip": evt["payload"].get("dst_ip", evt["payload"].get("source_ip", "unknown")),
            "category": evt["payload"].get("category", evt["type"]),
            "severity": evt["payload"].get("severity", "medium"),
            "description": f"{evt['type']} from {evt['payload'].get('dst_ip', 'unknown')}",
        })
        await asyncio.sleep(0.3)


async def _broadcast_event(event_type: str, payload: dict):
    """广播事件给所有 SSE 订阅者"""
    event = {"type": event_type, "timestamp": time.time(), **payload}
    dead = []
    for q in _event_queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        _event_queues.remove(q)
    # 追加到事件历史
    _event_history.append(event)
    # 只保留最近 200 条
    if len(_event_history) > 200:
        _event_history[:] = _event_history[-200:]


@app.get("/api/events")
async def get_events(since: float = 0, limit: int = 50):
    """轮询获取事件历史。since=时间戳，仅返回该时间之后的事件"""
    result = [e for e in _event_history if e.get("timestamp", 0) > since]
    return {"events": result[-limit:], "server_time": time.time()}


# ── 器官能力 API（前端展示对接）──

@app.get("/api/forensic/timeline")
async def api_forensic_timeline(limit: int = 50):
    """取证时间线：返回攻击链时间线列表（时间/源IP/攻击类型/处置动作）。"""
    if manager is None or not manager._running:
        return {"running": False, "timeline": []}
    try:
        timeline = manager.forensic_tracker.get_timeline()
        return {
            "running": True,
            "total": len(timeline),
            "timeline": timeline[:limit],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"取证时间线获取失败: {e}"})


@app.get("/api/vuln/ports")
async def api_vuln_ports():
    """端口扫描结果：返回本地开放端口列表。"""
    if manager is None or not manager._running:
        return {"running": False, "ports": []}
    try:
        ports = manager.vuln_scanner.get_open_ports()
        return {
            "running": True,
            "scan_time": manager.vuln_scanner._last_scan_time,
            "total": len(ports),
            "ports": ports,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"端口扫描结果获取失败: {e}"})


@app.get("/api/outbound/connections")
async def api_outbound_connections():
    """出站连接：返回本机对外主动连接列表。"""
    if manager is None or not manager._running:
        return {"running": False, "connections": []}
    try:
        data = manager.outbound_monitor.get_outbound_connections()
        return {"running": True, **data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"出站连接获取失败: {e}"})


@app.get("/api/audit/events")
async def api_audit_events(limit: int = 50):
    """日志审计：返回最近安全事件。"""
    if manager is None or not manager._running:
        return {"running": False, "events": []}
    try:
        events = manager.log_auditor.get_event_log_cache()
        return {
            "running": True,
            "total": len(events),
            "events": events[:limit],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"审计事件获取失败: {e}"})


@app.get("/api/resources")
async def api_resources():
    """资源监控：返回 CPU/内存实时使用率采样。"""
    if manager is None or not manager._running:
        return {"running": False, "resource": {}}
    try:
        stats = manager.resource_scheduler.get_real_resource_stats()
        return {"running": True, "resource": stats}
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"资源监控获取失败: {e}"})


# ── SSE 事件流 ──

@app.get("/api/events/stream")
async def api_events_stream():
    if not manager:
        return StreamingResponse(
            _empty_generator(),
            media_type="text/event-stream",
        )

    queue = manager.add_sse_client()

    async def event_generator():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {event['event']}\ndata: {event['data']}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            manager.remove_sse_client(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


async def _empty_generator():
    yield ": no manager\n\n"


# ── 监控指标 API ──

@app.get("/api/metrics")
async def api_metrics():
    """返回当前全部监控指标的 JSON 快照。"""
    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return manager.metrics.get_metrics()


@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus 标准 /metrics 端点。"""
    from prometheus_client import generate_latest, CollectorRegistry, Gauge, Counter, Histogram

    if not manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)

    data = manager.metrics.get_metrics()
    registry = CollectorRegistry()

    # 系统资源
    Gauge("dfu_cpu_percent", "CPU 使用率(%)", registry=registry).set(data.get("cpu_percent", -1))
    Gauge("dfu_memory_percent", "内存使用率(%)", registry=registry).set(data.get("memory_percent", -1))

    # LLM 调用
    Gauge("dfu_llm_calls_total", "LLM 总调用次数", registry=registry).set(data.get("llm_calls", 0))
    Gauge("dfu_llm_success_total", "LLM 成功调用次数", registry=registry).set(data.get("llm_success", 0))
    Gauge("dfu_llm_failed_total", "LLM 失败调用次数", registry=registry).set(data.get("llm_failed", 0))
    Gauge("dfu_llm_avg_latency_ms", "LLM 平均延迟(ms)", registry=registry).set(data.get("llm_avg_latency_ms", 0))

    # 知识库
    Gauge("dfu_kb_hits_total", "知识库命中次数", registry=registry).set(data.get("kb_hits", 0))
    Gauge("dfu_kb_misses_total", "知识库未命中次数", registry=registry).set(data.get("kb_misses", 0))
    Gauge("dfu_kb_hit_rate", "知识库命中率(%)", registry=registry).set(data.get("kb_hit_rate", 0))

    # 感知模块吞吐量
    throughput = data.get("org_throughput", {})
    for organ_name, count in throughput.items():
        Gauge(f"dfu_organ_{organ_name}_total", f"器官 {organ_name} 处理次数", registry=registry).set(count)

    return Response(generate_latest(registry), media_type="text/plain; version=0.0.4")


@app.get("/api/metrics/stream")
async def api_metrics_stream():
    """SSE 流，每 2 秒推送一次最新监控指标。"""
    if not manager:
        return StreamingResponse(
            _empty_generator(),
            media_type="text/event-stream",
        )

    async def metrics_generator():
        while manager and manager._running:
            try:
                data = manager.metrics.get_metrics()
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            except Exception:
                yield ": error\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(
        metrics_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── 全局异常处理器 ──
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """全局未捕获异常处理"""
    from utils.logging_config import get_logger as _log
    _log("web_server").error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": str(exc) if config.get("logging", "level") == "DEBUG" else "An unexpected error occurred"
        }
    )


# ==================== 启动入口 ====================

def main():
    parser = argparse.ArgumentParser(description="DFU Web 管理界面")
    default_port = get_config().web_port
    parser.add_argument("--port", type=int, default=default_port, help=f"监听端口（默认 {default_port}）")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args()

    url = f"http://localhost:{args.port}"

    if not args.no_browser:
        # 延迟打开浏览器，给 uvicorn 启动时间
        def _open_browser():
            time.sleep(1.5)
            webbrowser.open(url)
        import threading
        threading.Thread(target=_open_browser, daemon=True).start()

    print(f"\n  DFU Web 管理界面")
    print(f"  地址: {url}")
    print(f"  按 Ctrl+C 停止\n")

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=args.port,
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
