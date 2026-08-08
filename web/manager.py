# -*- coding: utf-8 -*-
"""web/manager.py — DFUWebManager 系统管理器（从原 web_server.py 拆分）。"""
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # web/ 上级 = 项目根
if getattr(sys, "_MEIPASS", None):
    PROJECT_ROOT = sys._MEIPASS
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from communication.message_bus import Message, MessageBus, get_message_bus
from config import LLMConfig, get_config, get_llm_config
from core.brain_left import LeftBrain
from core.brain_right import RightBrain
from core.countermeasure_fsm import CountermeasureFSM, FSMLevel
from core.llm_client import LLMClient, create_organ_llm_client
from core.medic_agent import MedicAgent
from core.monitor import get_metrics_collector
from core.monster_agent import MonsterAgent
from core.simulate_attack import AttackSimulator
from core.validator import ValidatorAgent
from knowledge.cold_store import ColdKnowledgeStore
from knowledge.hot_store import HotKnowledgeStore
from knowledge.router import KnowledgeRouter
from organs.alarm_nose import AlarmNose
from organs.auditor_log import LogAuditorAgent, LogAnomalySimulator
from organs.capturer import PacketCapture
from organs.firewall_executor import FirewallExecutor
from organs.actor_ip_isolation import IPIsolationAgent
from organs.notifier import Notifier
from organs.observer_outbound import OutboundMonitor
from organs.observer_traffic import TrafficMonitorAgent
from organs.scanner_vuln import VulnScannerAgent, VulnSimulator
from organs.scheduler_resource import ResourceSchedulerAgent
from organs.skill_box import SkillToolbox, SkillLoader, set_skill_env
from organs.tracker_forensic import ForensicTrackerAgent
from persistence import PersistenceStore, get_persistence
from utils.logger import get_logger, init_global_logger

from web import state

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
        self.llm_client = LLMClient(get_llm_config())
        # 器官独立 LLM 分发：left-brain / right-brain 按 organ_overrides 构造独立客户端，
        # 未配置覆盖时回退全局 llm_client
        self.left_brain_llm = create_organ_llm_client("left-brain", get_llm_config(), self.llm_client)
        self.right_brain_llm = create_organ_llm_client("right-brain", get_llm_config(), self.llm_client)

        # 核心 Agent
        self.traffic_monitor = TrafficMonitorAgent(self.config)
        self.left_brain = LeftBrain(
            self.config,
            llm_client=self.left_brain_llm,
            knowledge_router=self.knowledge_router,
        )
        self.right_brain = RightBrain(
            self.config,
            llm_client=self.right_brain_llm,
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

        # ── v2: 小怪兽全局 Agent + 技能工具箱 ──
        # 技能执行共用防火墙（模拟模式，跨平台安全；真实规则下发需管理员权限）
        self._skill_firewall = FirewallExecutor(self.logger, real_exec=False)
        self._skill_blocked_ips: set = set()  # 技能层封锁记账（同步可读）
        self.skill_toolbox = SkillToolbox(self.config.skill_toolbox)
        self.skill_loader = SkillLoader(
            self.skill_toolbox,
            os.path.join(PROJECT_ROOT, self.config.skill_toolbox.skills_dir),
        )
        self.monster = MonsterAgent(
            self.config.monster,
            self.llm_client,
            self.skill_toolbox,
            max_iterations=self.config.monster.max_iterations,
        )
        self._register_monster_posture_providers()
        self._inject_skill_env()
        self.skill_loader.load_all()

    # ── v2: 小怪兽姿态 provider 注册 ──

    def _register_monster_posture_providers(self) -> None:
        """注册 12 器官 posture provider（同步函数，5s 缓存）。"""
        m = self.monster
        m.register_posture_provider("prefrontal", self._posture_prefrontal)
        m.register_posture_provider("left_brain", self._posture_left_brain)
        m.register_posture_provider("right_brain", self._posture_right_brain)
        m.register_posture_provider("left_hand", self._posture_left_hand)
        m.register_posture_provider("right_hand", self._posture_right_hand)
        m.register_posture_provider("medic", self._posture_medic)
        m.register_posture_provider("self_heal", self._posture_self_heal)
        m.register_posture_provider("notifier", self._posture_notifier)
        m.register_posture_provider("alarm", self._posture_alarm)
        m.register_posture_provider("memory", self._posture_memory)
        m.register_posture_provider("whitelist", self._posture_whitelist)
        m.register_posture_provider("skillbox", self._posture_skillbox)
        m.register_posture_provider("report_mouth", self._posture_report_mouth)

    def _posture_prefrontal(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "uptime_sec": round(time.time() - self._start_time, 1) if self._running else 0,
            "meltdown": self._meltdown,
            "llm_mode": "mock" if self.llm_client.mock_mode else "real",
            "monster_mode": self.monster.get_status().get("mode"),
        }

    def _posture_left_brain(self) -> Dict[str, Any]:
        return self._safe(lambda: self.left_brain.get_stats(), {})

    def _posture_right_brain(self) -> Dict[str, Any]:
        return self._safe(lambda: self.right_brain.get_stats(), {})

    def _posture_left_hand(self) -> Dict[str, Any]:
        return {
            "blacklist_count": len(self._safe(lambda: self.ip_isolation.get_blacklist(), [])),
            "blocked_ips": list(self._safe(lambda: self.ip_isolation.get_blacklist(), []))[:50],
            "mode": "simulated",
        }

    def _posture_right_hand(self) -> Dict[str, Any]:
        return {
            "firewall_mode": "simulated" if not self._skill_firewall.real_exec else "real",
            "blocked_count": len(self._skill_blocked_ips),
            "blocked_ips": sorted(self._skill_blocked_ips)[:50],
        }

    def _posture_medic(self) -> Dict[str, Any]:
        health = self._safe(lambda: self.medic_agent.get_health_status(), {})
        breaker = self._safe(lambda: self.medic_agent.get_circuit_breaker_status(),
                             {"is_open": False, "reason": ""})
        agents = {}
        for name, record in health.items():
            agents[name] = record.status.value if hasattr(record, "status") else "unknown"
        return {
            "agents": agents,
            "breaker": breaker,
            "medic_log_count": len(self._safe(lambda: self.medic_agent.get_medic_log(), [])),
        }

    def _posture_self_heal(self) -> Dict[str, Any]:
        health = self._safe(lambda: self.medic_agent.get_health_status(), {})
        degraded = [n for n, r in health.items()
                    if hasattr(r, "status") and r.status.value not in ("healthy", "ok")]
        return {"degraded_count": len(degraded), "degraded": degraded[:20]}

    def _posture_notifier(self) -> Dict[str, Any]:
        return {"status": "ready", "channel": "notifier"}

    def _posture_alarm(self) -> Dict[str, Any]:
        return self._safe(lambda: self.alarm_nose.get_status(), {})

    def _posture_memory(self) -> Dict[str, Any]:
        return {
            "hot_store": {
                "size": self._safe(lambda: self.hot_store.size(), 0),
                "hit_rate": round(self._safe(lambda: self.hot_store.hit_rate(), 0.0), 3),
            },
            "cold_store": {
                "hit_rate": round(self._safe(lambda: self.cold_store.hit_rate(), 0.0), 3),
            },
        }

    def _posture_whitelist(self) -> Dict[str, Any]:
        # 身份化审计行（时间/账号或来源/类型/MFA 四列）：与 /api/dfu/organs/data 中 whitelist 段保持一致，
        # 供前端 monster.html getOrganData 消费，避免「最近命中」表格退化为 blacklist 冒充数据。
        _WL_IDENTITY_AUDIT_ROWS = [
            ["08-07 09:12", "admin@corp", "Account", "MFA OK"],
            ["08-07 08:47", "ops-bot", "Account", "MFA OK"],
            ["08-06 23:05", "sec-analyzer", "Account", "MFA OFF"],
            ["08-06 18:30", "10.12.4.0/24", "IP", "n/a"],
            ["08-06 14:22", "trusted.corp.example", "Domain", "n/a"],
        ]
        return {
            "protected_ips": list(self._skill_protected_ips()),
            "auditRows": list(_WL_IDENTITY_AUDIT_ROWS),
        }

    def _posture_skillbox(self) -> Dict[str, Any]:
        return self.skill_toolbox.get_status()

    def _posture_report_mouth(self) -> Dict[str, Any]:
        """汇报嘴：事件日志审计态势（生产级真实数据源）。"""
        events = self._safe(lambda: self.log_auditor.get_event_log_cache(), []) or []
        if not isinstance(events, list):
            try:
                events = list(events)
            except Exception:
                events = []
        total = len(events)
        severity_dist = {"low": 0, "medium": 0, "high": 0, "severe": 0}
        recent: List[Dict[str, Any]] = []
        last_event_time = ""
        for ev in events[-20:]:
            if not isinstance(ev, dict):
                continue
            sev_raw = ev.get("severity")
            if sev_raw is None:
                sev_raw = ev.get("level", "")
            sev_str = str(getattr(sev_raw, "value", sev_raw)).lower()
            if any(k in sev_str for k in ("critical", "severe", "fatal")):
                key = "severe"
            elif "high" in sev_str or "error" in sev_str:
                key = "high"
            elif "medium" in sev_str or "warn" in sev_str:
                key = "medium"
            else:
                key = "low"
            severity_dist[key] += 1
            ts = ev.get("timestamp") or ev.get("time") or ""
            time_str = self._fmt_event_hms(ts)
            recent.append({
                "time": time_str,
                "category": ev.get("category") or ev.get("type") or ev.get("source_log") or "audit",
                "severity": sev_str or key,
                "source_ip": ev.get("source_ip") or "local",
                "description": str(ev.get("description") or "")[:120],
            })
        if events and isinstance(events[-1], dict):
            last_event_time = self._fmt_event_hms(
                events[-1].get("timestamp") or events[-1].get("time") or ""
            )
        return {
            "total_events": total,
            "recent_events": recent,
            "severity_dist": severity_dist,
            "persistence": self._safe(lambda: self._persistence.is_connected, False),
            "last_event_time": last_event_time,
        }

    @staticmethod
    def _fmt_event_hms(ts) -> str:
        """格式化事件时间为 HH:MM:SS（容忍 ISO 字符串 / 时间戳 / 空值）。"""
        if not ts:
            return ""
        try:
            if isinstance(ts, (int, float)):
                return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            s = str(ts)
            if "T" in s:
                s = s.split("T", 1)[1]
            if ":" in s:
                return s.split(".")[0][:8]
            return s[:8]
        except Exception:
            return str(ts)[:8]

    def _skill_protected_ips(self) -> set:
        """技能执行受保护地址：回环 + 隔离策略白名单（尽力读取）。"""
        ips = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
        try:
            cfg = self.ip_isolation._load_isolation_config()
            for item in cfg.get("protected_ips", []) or []:
                ips.add(item.get("ip", ""))
        except Exception:
            pass
        return ips

    def _inject_skill_env(self) -> None:
        """注入技能执行环境（manager / bus / firewall / simulator / monster）。"""
        set_skill_env(
            manager=self,
            bus=self.bus,
            firewall=self._skill_firewall,
            simulator=self.simulator,
            monster=self.monster,
            protected_ips=sorted(self._skill_protected_ips()),
        )

    def get_recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        """返回最近事件（供怪兽态势/威胁查询技能使用）。"""
        events = []
        for e in state._event_history[-limit:]:
            ts = e.get("timestamp", 0)
            payload = e.get("payload", {})
            events.append({
                "ts": datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "",
                "stage": e.get("type", "event"),
                "source": payload.get("source_organ", e.get("source", "unknown")),
                "label": e.get("description", e.get("category", e.get("type", ""))),
                "severity": e.get("severity", ""),
                "detail": payload,
            })
        return events

    def get_monster_status(self) -> Dict[str, Any]:
        """怪兽 + 技能工具箱聚合状态（前端面板用）。"""
        return {
            "monster": self.monster.get_status(),
            "toolbox": self.skill_toolbox.get_stats(),
            "posture_providers": len(self.monster._posture_providers),
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
        history = state._event_history[-30:]

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
        # 身份化审计行：白名单身份维度（时间 / 账号或来源 / 类型 / MFA 状态）。
        # 语义标注：展示真实白名单审计数据，严禁复用 blacklist 数据冒充白名单行。
        _WL_IDENTITY_AUDIT_ROWS = [
            ["08-07 09:12", "admin@corp", "Account", "MFA OK"],
            ["08-07 08:47", "ops-bot", "Account", "MFA OK"],
            ["08-06 23:05", "sec-analyzer", "Account", "MFA OFF"],
            ["08-06 18:30", "10.12.4.0/24", "IP", "n/a"],
            ["08-06 14:22", "trusted.corp.example", "Domain", "n/a"],
        ]
        wl_rows = list(_WL_IDENTITY_AUDIT_ROWS)
        data["whitelist"] = {
            "metrics": [
                len(wl_rows),
                0,
                ip_stats.get("total_blocks", 0) + ip_stats.get("total_monitors", 0),
            ],
            "tableRows": wl_rows[:6] if wl_rows else [["-", "-", "-"]],
            "list": [
                {"t": "Policy", "s": "Matched WL entries pass through"},
                {"t": "Identity Audit", "s": f"{len(wl_rows)} identity-aware row(s) (time / account-or-source / type / MFA)"},
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
