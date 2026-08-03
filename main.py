#!/usr/bin/env python3
"""
多智能体分层分布式AI防御系统 - 原型入口文件
启动所有Agent，运行模拟攻击场景，打印完整的事件链日志。

运行方式：
    python main.py                          # 默认 stage2 全模式
    python main.py --stage 1                # 仅运行阶段1核心Agent
    python main.py --stage 2                # 运行阶段2全部Agent（含器官+医疗）
    python main.py --stage 2 --scenario ddos    # 阶段2 + 单一场景
    python main.py --stage 2 --fault-sim    # 阶段2 + 故障模拟
"""

import argparse
import asyncio
import json
import os
import random
import sys
from datetime import datetime
from typing import Dict, List, Optional

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config, get_config
from organs.capturer import PacketCapture
from core.brain_left import LeftBrain
from core.brain_right import RightBrain
from core.event_aggregator import EventAggregator
from core.rule_frontend import RuleEngineFrontend
from core.llm_client import LLMClient
from core.medic_agent import MedicAgent
from core.validator import ValidatorAgent
from organs.actor_ip_isolation import IPIsolationAgent
from organs.auditor_log import LogAuditorAgent, LogAnomalySimulator
from organs.observer_traffic import TrafficMonitorAgent
from organs.observer_realtime import RealtimeTrafficAgent
from organs.scanner_vuln import VulnScannerAgent, VulnSimulator
from organs.scheduler_resource import ResourceSchedulerAgent
from organs.tracker_forensic import ForensicTrackerAgent
from organs.observer_outbound import OutboundMonitor
from tests.simulate_attack import AttackSimulator
from utils.logger import init_global_logger, get_logger

# 阶段3：集群化与冷热知识库
from cluster.registry import ClusterRegistry
from cluster.dispatcher import LoadDispatcher, DispatchStrategy
from cluster.dfu_unit import DFUUnit

# 阶段4：灰度升级与生产就绪
from upgrade.model_store import ModelWeightStore
from upgrade.package_builder import UpgradePackageBuilder
from upgrade.rollout_controller import RolloutController
from production.perf_monitor import PerformanceMonitor
from production.security_auditor import SecurityAuditor
from production.stress_tester import StressTester
from production.compliance_checklist import ComplianceChecker


# ==================== 事件链记录器 ====================

class EventChainRecorder:
    """
    事件链记录器：订阅消息总线，自动记录完整事件链。

    阶段2扩展：新增 vuln_alert、audit_alert、schedule_result、forensic_report、
    medic_event 事件类型的记录支持。
    """

    TYPE_STAGE_MAP = {
        "traffic_data":     ("attack",   "攻击流量数据包"),
        "threat_alert":     ("observe",  "观测Agent检测到威胁告警"),
        "merged_threat_alert": ("observe", "事件聚合器输出合并威胁告警"),
        "unhandled_threat": ("observe", "规则引擎未命中的原始告警"),
        "rule_handled": ("left", "规则引擎前置分流快速命中"),
        "defense_plan":     ("left",     "分析引擎输出防御方案"),
        "attack_analysis":  ("right",    "响应引擎输出攻击分析"),
        "isolation_action": ("validate", "校验Agent下发的隔离指令"),
        "action_result":    ("execute",  "处置Agent执行结果"),
        # 阶段2新增事件类型
        "schedule_result":  ("resource", "算力调度Agent执行调度"),
        "forensic_report":  ("forensic", "溯源追踪Agent输出溯源报告"),
        "medic_event":      ("medic",    "医疗Agent自愈系统事件"),
        # 阶段3新增事件类型
        "knowledge_hit":    ("knowledge","知识库命中"),
        "knowledge_promote":("knowledge","冷库升温到热库"),
        "sync_event":       ("sync",     "跨单元知识同步"),
        "dispatch_event":   ("dispatch", "负载分发事件"),
        "cluster_status":   ("cluster",  "集群状态事件"),
        # Phase 1.5 新增事件类型
        "outbound_beacon":  ("outbound", "出站监测发现信标通信"),
        "outbound_exfil":   ("outbound", "出站监测检测到数据外泄"),
        "outbound_domain":  ("outbound", "出站监测命中可疑域名"),
        "outbound_l4_isolate": ("outbound", "L4网络隔离已触发"),
    }

    def __init__(self, bus: MessageBus):
        self.events: list = []
        self.bus = bus
        self._lock = asyncio.Lock()
        self._running = False

    async def start(self) -> None:
        """启动全局监听。"""
        self._running = True
        await self.bus.subscribe("*", self._on_message)

    async def stop(self) -> None:
        self._running = False

    async def _on_message(self, msg: Message) -> None:
        """全局消息处理器。"""
        if not self._running:
            return
        msg_type = msg.type
        if msg_type == "traffic_data":
            return
        info = self.TYPE_STAGE_MAP.get(msg_type)
        if info is None:
            return
        stage, label = info

        detail = self._format_detail(msg)
        async with self._lock:
            self.events.append({
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "stage": stage,
                "label": label,
                "detail": detail,
                "source": msg.source,
            })

    def _format_detail(self, msg: Message) -> str:
        """格式化消息详情为可读字符串。"""
        payload = msg.payload
        lines = []
        msg_type = msg.type

        if msg_type == "threat_alert":
            source_organ = payload.get("source_organ", "")
            if source_organ:
                lines.append(f"来源器官: {source_organ}")
            # 兼容新旧格式：旧格式 indicator 在顶层字段，新格式在 payload.indicator
            indicator = payload.get("indicator", {})
            if not indicator:
                # 旧格式兼容
                indicator = payload
            lines.append(f"告警ID: {indicator.get('id') or payload.get('id')}")
            lines.append(f"类别: {indicator.get('category') or payload.get('category')}")
            lines.append(f"级别: {indicator.get('severity') or payload.get('severity')}")
            lines.append(f"源IP: {indicator.get('source_ip') or payload.get('source_ip')}")
            lines.append(f"描述: {indicator.get('description') or payload.get('description', '')}")

        elif msg_type == "unhandled_threat":
            indicator = payload.get("indicator", payload)
            lines.append(f"源IP: {indicator.get('source_ip') or payload.get('source_ip')}")
            lines.append(f"类别: {indicator.get('category') or payload.get('category')}")
            lines.append(f"级别: {indicator.get('severity') or payload.get('severity')}")
            lines.append("规则: 未命中 → 交聚合器")

        elif msg_type == "rule_handled":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"动作: {payload.get('action')}")
            lines.append(f"级别: {payload.get('severity')}")
            lines.append(f"规则: {payload.get('rule_id')}")
            lines.append(f"置信度: {payload.get('confidence', 0):.2f}")

        elif msg_type == "merged_threat_alert":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"聚合告警数: {payload.get('event_count')}")
            lines.append(f"源IP: {payload.get('source_ip')}")
            lines.append(f"类别: {payload.get('category')}")

        elif msg_type == "defense_plan":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"确认级别: {payload.get('severity_confirm')}")
            lines.append(f"处置动作: {payload.get('action')}")
            lines.append(f"目标IP: {payload.get('target_ip')}")
            lines.append(f"算力开销: {payload.get('compute_cost', 0)}")

        elif msg_type == "attack_analysis":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"攻击类型: {payload.get('attack_type')}")
            conf = payload.get('confidence', 0)
            lines.append(f"置信度: {conf:.2f}" if isinstance(conf, float) else f"置信度: {conf}")
            lines.append(f"溯源: {payload.get('root_cause', '')[:80]}")
            actions = payload.get('recommended_actions', [])
            lines.append(f"推荐策略: {', '.join(actions)}")

        elif msg_type == "isolation_action":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"动作: {payload.get('action')}")
            lines.append(f"目标IP: {payload.get('target_ip')}")
            lines.append(f"优先级: {payload.get('priority')}")
            lines.append(f"原因: {payload.get('reason', '')[:80]}")

        elif msg_type == "action_result":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"目标IP: {payload.get('target_ip')}")
            lines.append(f"动作: {payload.get('action')}")
            lines.append(f"结果: {'成功' if payload.get('success') else '失败'}")
            lines.append(f"说明: {payload.get('message')}")
            lines.append(f"黑名单大小: {payload.get('blacklist_size')}")

        elif msg_type == "schedule_result":
            log_entry = payload.get("log_entry", {})
            rs = payload.get("resource_state", {})
            lines.append(f"调度ID: {log_entry.get('schedule_id')}")
            lines.append(f"目标: {log_entry.get('target_organ')}")
            lines.append(f"动作: {log_entry.get('action')}")
            lines.append(f"CPU: {rs.get('cpu_usage_pct', 0):.1f}%")
            lines.append(f"内存: {rs.get('memory_usage_pct', 0):.1f}%")

        elif msg_type == "forensic_report":
            chain = payload.get("hop_chain", [])
            hops = " → ".join(h.get("ip", "") for h in chain)
            lines.append(f"报告ID: {payload.get('report_id')}")
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"跳板链: {hops}")
            lines.append(f"可信度: {payload.get('confidence', 0):.0%}")
            lines.append(f"根因: {payload.get('root_cause', '')[:100]}")

        elif msg_type == "medic_event":
            lines.append(f"类型: {payload.get('type')}")
            lines.append(f"描述: {payload.get('description')}")

        elif msg_type == "vuln_report":
            lines.append(f"CVE: {payload.get('cve_id')}")
            lines.append(f"服务: {payload.get('service')}")
            lines.append(f"CVSS: {payload.get('cvss_score')}")
            lines.append(f"描述: {payload.get('description', '')[:80]}")

        elif msg_type == "log_anomaly":
            lines.append(f"类型: {payload.get('type')}")
            lines.append(f"用户: {payload.get('username')}")
            lines.append(f"源IP: {payload.get('source_ip')}")
            lines.append(f"详情: {payload.get('detail', '')[:80]}")

        # 阶段3事件格式
        elif msg_type == "knowledge_hit":
            lines.append(f"特征: {payload.get('feature', '')}")
            lines.append(f"来源: {payload.get('source', '')}")
            lines.append(f"耗时: {payload.get('latency_ms', 0):.2f}ms")

        elif msg_type == "knowledge_promote":
            lines.append(f"特征: {payload.get('feature', '')}")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "sync_event":
            lines.append(f"发起方: {payload.get('from_unit', '')}")
            lines.append(f"接收方: {payload.get('to_unit', '')}")
            lines.append(f"同步条目: {payload.get('entry_count', 0)}")
            lines.append(f"延迟: {payload.get('latency_ms', 0):.2f}ms")

        elif msg_type == "dispatch_event":
            lines.append(f"任务ID: {payload.get('task_id', '')}")
            lines.append(f"目标单元: {payload.get('target_unit', '')}")
            lines.append(f"策略: {payload.get('strategy', '')}")

        elif msg_type == "cluster_status":
            lines.append(f"集群规模: {payload.get('total_units', 0)} 单元")
            lines.append(f"活跃: {payload.get('active_units', 0)}")
            lines.append(f"描述: {payload.get('description', '')}")

        # Phase 1.5 出站事件格式
        elif msg_type == "outbound_beacon":
            lines.append(f"源IP: {payload.get('source_ip', '')}")
            lines.append(f"目标IP: {payload.get('dest_ip', '')}")
            lines.append(f"端口: {payload.get('dest_port', '')}")
            lines.append(f"周期: {payload.get('interval_sec', 0)}s")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "outbound_exfil":
            lines.append(f"源IP: {payload.get('source_ip', '')}")
            lines.append(f"目标域名: {payload.get('dest_domain', '')}")
            lines.append(f"外泄字节: {payload.get('bytes_sent', 0)}")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "outbound_domain":
            lines.append(f"源IP: {payload.get('source_ip', '')}")
            lines.append(f"域名: {payload.get('domain', '')}")
            lines.append(f"匹配特征: {payload.get('match_type', '')}")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "outbound_l4_isolate":
            lines.append(f"目标IP: {payload.get('target_ip', '')}")
            lines.append(f"原等级: {payload.get('old_level', '')}")
            lines.append(f"新等级: {payload.get('new_level', '')}")
            lines.append(f"原因: {payload.get('reason', '')}")
            lines.append(f"动作: {payload.get('action', '')}")

        return "\n".join(lines) if lines else str(payload)[:200]

    def add_manual_event(self, stage: str, msg: str) -> None:
        """手动添加事件。"""
        self.events.append({
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "stage": stage,
            "label": msg,
            "detail": "",
            "source": "System",
        })

    def add_medic_event(self, event_type: str, description: str, detail: dict = None) -> None:
        """添加医疗Agent事件（通过消息总线发布）。"""
        self.events.append({
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "stage": "medic",
            "label": event_type,
            "detail": description,
            "source": "MedicAgent",
        })

    def print_chain(self) -> None:
        """打印完整事件链。"""
        print("\n" + "=" * 80)
        print("  事件链完整记录")
        print("=" * 80)

        stage_icons = {
            "attack":   "⚡",
            "observe":  "👁 ",
            "left":     "🧠",
            "right":    "🧠",
            "validate": "🔍",
            "execute":  "🛡 ",
            "resource": "⚙ ",
            "forensic": "🔬",
            "medic":    "🏥",
            "knowledge":"📚",
            "sync":     "🔄",
            "dispatch": "📤",
            "cluster":  "🌐",
            "outbound": "🚫",
        }

        for i, event in enumerate(self.events, 1):
            stage = event["stage"]
            icon = stage_icons.get(stage, "  ")
            print(f"\n[{i:02d}] {event['time']} {icon} {event['label']}")
            print(f"     来源: {event['source']}")
            if event["detail"]:
                for line in event["detail"].split("\n"):
                    if line.strip():
                        print(f"       {line.strip()}")

        print("\n" + "=" * 80)
        print(f"  事件链总计: {len(self.events)} 个事件")
        print("=" * 80)


# ==================== 主运行器 ====================

class DFUPrototypeRunner:
    """原型运行器：编排所有 Agent 的启动、攻击模拟和事件链记录。"""

    def __init__(self, config: Config, recorder: EventChainRecorder, stage: int = 1,
                 llm_client: Optional[LLMClient] = None):
        self.config = config
        self.recorder = recorder
        self.bus = get_message_bus()
        self.logger = get_logger("Main")
        self.stage = stage
        self._is_realtime = (stage == "realtime")
        self.llm_client = llm_client

        # ===== 阶段1核心Agent（始终初始化）=====
        self.traffic_monitor = TrafficMonitorAgent(config)
        self.left_brain = LeftBrain(config, llm_client=llm_client)
        self.right_brain = RightBrain(config, llm_client=llm_client)
        self.validator = ValidatorAgent(config)
        self.ip_isolation = IPIsolationAgent(config)
        self.event_aggregator = EventAggregator(config.event_aggregator)
        self.logger.info("事件聚合器已初始化")
        self.rule_frontend = RuleEngineFrontend(config)
        self.logger.info("规则引擎前置分流已初始化")

        # ===== Phase 1.5 新增模块 =====
        self.outbound_monitor = OutboundMonitor(config)
        self.logger.info("出站流量监测模块已初始化 (OutboundMonitor)")
        self.fsm = self.ip_isolation.fsm  # Phase 1.5: 复用 FSM 引用用于 L4 三闸门检查
        self.logger.info("Phase 1.5 FSM L4 网络隔离就绪 (三闸门锁)")

        # ===== 实时抓包模块 (PacketCapture) =====
        self.capturer = PacketCapture(self.bus, self.config)
        self.capturer.set_port_filter([4444, 8443, 31337, 10443, 18443, 443, 80])
        self.capturer.enable_detection_feed()
        self.logger.info("实时抓包模块已初始化 (PacketCapture)")

        # ===== 阶段2新增Agent =====
        self.vuln_scanner: Optional[VulnScannerAgent] = None
        self.log_auditor: Optional[LogAuditorAgent] = None
        self.resource_scheduler: Optional[ResourceSchedulerAgent] = None
        self.forensic_tracker: Optional[ForensicTrackerAgent] = None
        self.medic_agent: Optional[MedicAgent] = None
        self.vuln_simulator: Optional[VulnSimulator] = None
        self.log_simulator: Optional[LogAnomalySimulator] = None

        if not self._is_realtime and stage >= 2:
            self.vuln_scanner = VulnScannerAgent(config)
            self.log_auditor = LogAuditorAgent(config)
            self.resource_scheduler = ResourceSchedulerAgent(config)
            self.forensic_tracker = ForensicTrackerAgent(config)
            self.medic_agent = MedicAgent(config)
            self.vuln_simulator = VulnSimulator(config)
            self.log_simulator = LogAnomalySimulator(config)

        # ===== 阶段3：集群化与冷热知识库 =====
        self.registry: Optional[ClusterRegistry] = None
        self.dispatcher: Optional[LoadDispatcher] = None
        self.units: List[DFUUnit] = []

        if not self._is_realtime and stage >= 3:
            unit_count = config.stage3.default_unit_count
            self.registry = ClusterRegistry(
                heartbeat_timeout=config.stage3.cluster_heartbeat_timeout
            )
            self.dispatcher = LoadDispatcher(
                self.registry,
                strategy=DispatchStrategy.LEAST_CONNECTIONS,
            )
            self.logger.info(f"阶段3集群初始化: 创建 {unit_count} 个 DFUUnit 实例")

            for _ in range(unit_count):
                unit = DFUUnit(config, self.registry, knowledge_dir=config.log_dir)
                self.units.append(unit)
            self.logger.info(f"阶段3知识库目录: {config.log_dir}")

        # ===== 阶段4：灰度升级与生产就绪 =====
        self.model_store: Optional[ModelWeightStore] = None
        self.package_builder: Optional[UpgradePackageBuilder] = None
        self.rollout_controller: Optional[RolloutController] = None
        self.perf_monitor: Optional[PerformanceMonitor] = None
        self.security_auditor: Optional[SecurityAuditor] = None
        self.stress_tester: Optional[StressTester] = None
        self.compliance_checker: Optional[ComplianceChecker] = None

        if not self._is_realtime and stage >= 4:
            sc = config.stage4
            output_dir = sc.production_output_dir
            os.makedirs(output_dir, exist_ok=True)

            self.model_store = ModelWeightStore(
                store_dir=sc.model_store_dir,
                dry_run=sc.dry_run,
            )
            self.package_builder = UpgradePackageBuilder(
                store_dir=sc.upgrade_package_dir,
                dry_run=sc.dry_run,
            )
            self.rollout_controller = RolloutController(
                canary_ratio=sc.canary_ratio,
                incremental_ratio=sc.incremental_ratio,
                canary_observe_rounds=sc.canary_observe_rounds,
                incremental_observe_rounds=sc.incremental_observe_rounds,
                heartbeat_interval=self.config.medic.heartbeat_interval,
                dry_run=sc.dry_run,
                output_dir=output_dir,
            )
            self.perf_monitor = PerformanceMonitor(
                cpu_threshold_pct=sc.perf_cpu_threshold_pct,
                memory_threshold_pct=sc.perf_memory_threshold_pct,
                latency_threshold_ms=sc.perf_latency_threshold_ms,
                fp_rate_threshold=sc.perf_fp_rate_threshold,
                fn_rate_threshold=sc.perf_fn_rate_threshold,
                success_rate_threshold=sc.perf_success_rate_threshold,
            )
            self.security_auditor = SecurityAuditor(dry_run=sc.dry_run)
            self.stress_tester = StressTester(
                duration_per_level=sc.stress_test_duration_per_level,
                dry_run=sc.dry_run,
                output_dir=output_dir,
            )
            self.compliance_checker = ComplianceChecker(
                security_auditor=self.security_auditor,
                medic_agent=self.medic_agent,
                rollout_controller=self.rollout_controller,
                stress_tester=self.stress_tester,
                dry_run=sc.dry_run,
            )
            self.logger.info("阶段4组件初始化: 灰度升级引擎 + 生产就绪组件")
            self.logger.info(f"  输出目录: {output_dir}")

        # 真实流量接入模块
        self.realtime_traffic: Optional[RealtimeTrafficAgent] = None
        if stage == "realtime":
            self.realtime_traffic = RealtimeTrafficAgent(config)
            self.logger.info("真实流量接入模块已初始化 (pcap分析 + 在线监听)")

        # 攻击模拟器
        self.simulator = AttackSimulator(
            ddos_source_count=config.simulator.ddos_source_ip_count,
            ddos_rate=config.simulator.ddos_requests_per_second,
            scan_port_range=config.simulator.port_scan_range,
            scan_speed=config.simulator.port_scan_speed,
            brute_attempts=config.simulator.brute_force_attempts,
            brute_target_port=config.simulator.brute_force_target_port,
        )

    async def start_all_agents(self) -> None:
        """启动所有 Agent（严格按数据流顺序注册）。"""
        # 处置Agent先注册
        await self.ip_isolation.start()
        await self.validator.start()

        # 规则引擎前置分流：在聚合器和双脑之前启动，拦截原始告警
        await self.rule_frontend.start()
        self.logger.info("规则引擎前置分流已启动")

        # 事件聚合器：在双脑之前启动，订阅 unhandled_threat
        await self.event_aggregator.start()

        # 阶段2器官Agent
        if not self._is_realtime and self.stage >= 2:
            await self.resource_scheduler.start()
            await self.forensic_tracker.start()
            await self.vuln_scanner.start()
            await self.log_auditor.start()

        # 双引擎注册
        await self.left_brain.start()
        await self.right_brain.start()

        # 观测Agent最后注册：realtime 模式用 RealtimeTrafficAgent，其他用 TrafficMonitorAgent
        if self.stage == "realtime" and self.realtime_traffic:
            await self.realtime_traffic.start()
        else:
            await self.traffic_monitor.start()

        # Phase 1.5: 出站流量监测（在所有观测Agent之后）
        await self.outbound_monitor.start()
        self.logger.info("出站流量监测Agent已启动")

        # 实时抓包模块（在观测Agent之后，全局记录器之前）
        self.capturer.start()
        self.logger.info("实时抓包模块已启动 (PacketCapture)")

        # 全局事件记录器
        await self.recorder.start()

        # 医疗Agent（独立协程）
        if not self._is_realtime and self.stage >= 2 and self.medic_agent:
            self._register_all_to_medic()
            await self.medic_agent.start()

        agent_names = [
            "TrafficMonitor" if self.stage != "realtime" else "RealtimeTraffic",
            "RuleEngineFrontend", "EventAggregator",
            "LeftBrain", "RightBrain", "Validator", "IPIsolation",
            "OutboundMonitor", "PacketCapture",
        ]
        if not self._is_realtime and self.stage >= 2:
            agent_names.extend([
                "VulnScanner", "LogAuditor", "ResourceScheduler",
                "ForensicTracker", "MedicAgent"
            ])
        self.logger.info(f"所有 Agent 已启动 ({len(agent_names)}个): {', '.join(agent_names)}")

        # 阶段3：部署所有单元
        if not self._is_realtime and self.stage >= 3:
            for unit in self.units:
                await unit.deploy()
            self.logger.info(f"{len(self.units)} 个 DFUUnit 已注册到集群")

    def _register_all_to_medic(self) -> None:
        """将所有 Agent 注册到医疗自愈系统。"""
        medic = self.medic_agent
        if not medic:
            return

        # 基于心跳检查：对每个注册的 Agent 使用简单存活检测
        # 实际场景中应对接真实 Agent 的心跳接口
        self._medic_alive_flags: Dict[str, bool] = {
            "TrafficMonitor": True,
            "LeftBrain": True,
            "RightBrain": True,
            "Validator": True,
            "IPIsolation": True,
            "OutboundMonitor": True,
            "PacketCapture": True,
            "VulnScanner": True,
            "LogAuditor": True,
            "ResourceScheduler": True,
            "ForensicTracker": True,
        }

        for agent_name in self._medic_alive_flags:
            # 根据 Agent 内部状态构建心跳回调
            def make_hb_cb(name):
                async def hb():
                    return self._medic_alive_flags.get(name, False)
                return hb

            def make_snapshot_cb(name):
                def snap():
                    return {"name": name, "timestamp": datetime.now().isoformat()}
                return snap

            def make_iso_cb(name):
                async def iso(aname, isolated):
                    self.logger.warning(
                        f"[医疗回调] Agent {aname} {'被隔离' if isolated else '已恢复'}"
                    )
                return iso

            medic.register_agent(
                agent_name=agent_name,
                heartbeat_callback=make_hb_cb(agent_name),
                snapshot_callback=make_snapshot_cb(agent_name),
                isolation_callback=make_iso_cb(agent_name),
            )

    async def stop_all_agents(self) -> None:
        """停止所有 Agent。"""
        if not self._is_realtime and self.stage >= 2 and self.medic_agent:
            await self.medic_agent.stop()
        await self.recorder.stop()
        if self._is_realtime and self.realtime_traffic:
            await self.realtime_traffic.stop()
        else:
            await self.traffic_monitor.stop()
        await self.left_brain.stop()
        await self.right_brain.stop()
        await self.rule_frontend.stop()
        await self.event_aggregator.stop()
        await self.validator.stop()
        await self.ip_isolation.stop()
        await self.outbound_monitor.stop()
        await self.capturer.stop()
        if not self._is_realtime and self.stage >= 2:
            await self.vuln_scanner.stop()
            await self.log_auditor.stop()
            await self.resource_scheduler.stop()
            await self.forensic_tracker.stop()
        # 阶段3：关闭所有单元
        if not self._is_realtime and self.stage >= 3:
            for unit in self.units:
                await unit.shutdown()
        self.logger.info("所有 Agent 已停止")

    async def _inject_traffic(self, packets: list, scenario_name: str) -> None:
        """将模拟攻击流量逐包注入消息总线。"""
        total = len(packets)
        self.recorder.add_manual_event(
            "attack",
            f"场景 [{scenario_name}] 开始注入 {total} 个流量包"
        )
        for i, packet in enumerate(packets):
            msg = Message(
                source="AttackSimulator",
                target="TrafficMonitor",
                type="traffic_data",
                payload=packet,
            )
            await self.bus.publish(msg)
            if i % 50 == 0 and i > 0:
                await asyncio.sleep(0.01)
        self.recorder.add_manual_event(
            "attack",
            f"场景 [{scenario_name}] 流量注入完成"
        )

    # ==================== 阶段1场景 ====================

    async def run_scenario(self, scenario: str) -> None:
        """运行单个攻击场景（阶段1）。"""
        scenario_names = {
            "ddos": "DDoS洪水攻击",
            "port_scan": "端口扫描攻击",
            "brute_force": "暴力破解攻击",
        }
        name = scenario_names.get(scenario, scenario)

        print(f"\n{'─' * 60}")
        print(f"  >>> 场景: {name} <<<")
        print(f"{'─' * 60}")

        self.traffic_monitor.reset_state()

        if scenario == "ddos":
            packets = self.simulator.generate_ddos()
        elif scenario == "port_scan":
            packets = self.simulator.generate_port_scan()
        elif scenario == "brute_force":
            packets = self.simulator.generate_brute_force()
        else:
            self.logger.warning(f"未知场景: {scenario}")
            return

        await self._inject_traffic(packets, name)
        await asyncio.sleep(5.0)

        blacklist = self.ip_isolation.get_blacklist()
        action_log = self.ip_isolation.get_action_log()
        print(f"  场景 [{name}] 完成 | 黑名单: {len(blacklist)} IP | 处置动作: {len(action_log)} 次")
        if blacklist:
            for ip in blacklist:
                print(f"    - 已隔离: {ip}")

    async def run_all_scenarios(self) -> None:
        """运行全部3种攻击场景。"""
        for scenario in ["ddos", "port_scan", "brute_force"]:
            await self.run_scenario(scenario)
            await asyncio.sleep(0.5)

    # ==================== 阶段2场景 ====================

    async def run_stage2_multi_organ(self) -> None:
        """
        阶段2：多感知模块协同测试场景。
        同时注入 DDoS + 漏洞扫描结果 + 异常日志，验证多感知模块并行处理。
        """
        print("\n" + "=" * 80)
        print("  阶段2：多感知模块协同测试")
        print("  场景: DDoS攻击 + 漏洞扫描 + 日志审计 并行注入")
        print("=" * 80)

        self.traffic_monitor.reset_state()

        # 注入DDoS流量
        self.recorder.add_manual_event("attack", "[多感知模块协同] 开始注入DDoS流量")
        ddos_packets = self.simulator.generate_ddos()
        for i, packet in enumerate(ddos_packets):
            await self.bus.publish(Message(
                source="AttackSimulator", target="TrafficMonitor",
                type="traffic_data", payload=packet,
            ))
            if i % 50 == 0 and i > 0:
                await asyncio.sleep(0.01)
        self.recorder.add_manual_event("attack", "[多感知模块协同] DDoS流量注入完成")
        print("  [1/3] DDoS 流量已注入 (450个包)")

        # 注入漏洞报告
        self.recorder.add_manual_event("attack", "[多感知模块协同] 开始注入漏洞报告")
        vuln_reports = self.simulator.generate_vuln_reports(
            count=self.config.simulator.vuln_report_count
        )
        for report in vuln_reports:
            await self.bus.publish(Message(
                source="AttackSimulator", target="VulnScanner",
                type="vuln_report", payload=report,
            ))
        self.recorder.add_manual_event("attack", f"[多感知模块协同] 漏洞报告注入完成 ({len(vuln_reports)}条)")
        print(f"  [2/3] 漏洞报告已注入 ({len(vuln_reports)}条)")

        # 注入异常日志
        self.recorder.add_manual_event("attack", "[多感知模块协同] 开始注入异常日志")
        log_anomalies = self.simulator.generate_log_anomalies(
            count=self.config.simulator.log_anomaly_count
        )
        for anomaly in log_anomalies:
            # 登录失败类型需重复发送以触发阈值
            if anomaly["type"] == "login_failure":
                repeat = self.config.stage2.audit_login_fail_threshold + 1
                for _ in range(repeat):
                    await self.bus.publish(Message(
                        source="AttackSimulator", target="LogAuditor",
                        type="log_anomaly", payload=anomaly,
                    ))
                    await asyncio.sleep(0.01)
            else:
                await self.bus.publish(Message(
                    source="AttackSimulator", target="LogAuditor",
                    type="log_anomaly", payload=anomaly,
                ))
        self.recorder.add_manual_event("attack", f"[多感知模块协同] 异常日志注入完成 ({len(log_anomalies)}类)")
        print(f"  [3/3] 异常日志已注入 ({len(log_anomalies)}类)")

        # 等待所有感知模块处理完毕
        await asyncio.sleep(6.0)

        # 统计结果
        blacklist = self.ip_isolation.get_blacklist()
        action_log = self.ip_isolation.get_action_log()
        resource_state = self.resource_scheduler.get_resource_state()
        forensic_reports = self.forensic_tracker.get_reports()

        print("\n  多感知模块协同测试完成:")
        print(f"    流量告警 → 黑名单: {len(blacklist)} IP | 处置: {len(action_log)} 次")
        print(f"    漏洞扫描 → 处理 {self.config.simulator.vuln_report_count} 条CVE报告")
        print(f"    日志审计 → 处理 {len(log_anomalies)} 类异常事件")
        print(f"    算力调度 → CPU使用率: {(resource_state.used_cpu_cores/resource_state.total_cpu_cores*100):.1f}%")
        print(f"    溯源追踪 → 生成 {len(forensic_reports)} 份溯源报告")

    async def run_fault_simulation(self) -> None:
        """
        故障模拟：随机杀死一个Agent，验证医疗Agent检测、隔离、恢复全链路。
        """
        print("\n" + "=" * 80)
        print("  阶段2：医疗自愈 - 故障模拟")
        print("  模拟: 随机Agent失联 → 医疗Agent检测 → 隔离 → 恢复")
        print("=" * 80)

        if not self.medic_agent:
            print("  医疗Agent未启用（stage=1），跳过故障模拟")
            return

        # 选择要"杀死"的Agent（排除医疗Agent自身）
        target_agents = list(self._medic_alive_flags.keys())
        victim = random.choice(target_agents)

        self.recorder.add_manual_event("attack", f"[故障模拟] 即将使 {victim} 失联")
        print(f"\n  >>> 故障注入: {victim} 即将失联 <<<")

        # 发布医疗事件到消息总线
        await self.bus.publish(Message(
            source="FaultSimulator",
            target="*",
            type="medic_event",
            payload={
                "type": "fault_injected",
                "description": f"故障模拟: {victim} 被手动标记为失联",
            },
        ))

        # 标记失联
        self._medic_alive_flags[victim] = False
        self.recorder.add_manual_event("medic", f"[故障注入] {victim} 已失联 (心跳停止)")
        print(f"  [1] {victim} 心跳已停止")

        # 等待医疗Agent检测到故障（2个心跳周期）
        await asyncio.sleep(self.config.medic.heartbeat_interval * 2 + 1)

        # 检查医疗Agent是否已隔离
        health = self.medic_agent.get_health_status()
        if victim in health and health[victim].status.value == "isolated":
            self.recorder.add_manual_event("medic", f"[医疗检测] {victim} 已被隔离")
            print(f"  [2] 医疗Agent已检测到 {victim} 故障并隔离")
        else:
            status = health.get(victim)
            st = status.status.value if status else "unknown"
            self.recorder.add_manual_event("medic", f"[医疗检测] {victim} 状态: {st}")
            print(f"  [2] {victim} 当前状态: {st}")

        # 检查熔断器
        cb_status = self.medic_agent.get_circuit_breaker_status()
        if cb_status["is_open"]:
            self.recorder.add_manual_event("medic", f"[熔断] 熔断器已开启: {cb_status['reason']}")
            print(f"  [!] 熔断器已开启: {cb_status['reason']}")

        # 恢复阶段：恢复Agent心跳
        await asyncio.sleep(1)
        self.recorder.add_manual_event("attack", f"[故障恢复] {victim} 心跳恢复")
        self._medic_alive_flags[victim] = True
        print(f"  [3] {victim} 心跳已恢复")

        # 等待医疗Agent检测恢复（恢复确认周期）
        await asyncio.sleep(self.config.medic.heartbeat_interval * (self.config.medic.recovery_confirm_count + 2))

        health_after = self.medic_agent.get_health_status()
        if victim in health_after:
            final_status = health_after[victim].status.value
            self.recorder.add_manual_event("medic", f"[恢复确认] {victim} 最终状态: {final_status}")
            print(f"  [4] {victim} 最终状态: {final_status}")

        cb_status_after = self.medic_agent.get_circuit_breaker_status()
        if not cb_status_after["is_open"]:
            self.recorder.add_manual_event("medic", "[熔断] 熔断器已解除")
            print("  [5] 熔断器已解除")

        # 打印医疗事件日志
        medic_log = self.medic_agent.get_medic_log()
        print(f"\n  医疗Agent事件日志 ({len(medic_log)} 条):")
        for entry in medic_log:
            print(f"    [{entry['timestamp'][:19]}] {entry['type']}: {entry['description']}")

    # ==================== 阶段3场景 ====================

    async def run_stage3_knowledge_test(self) -> None:
        """
        测试场景1：同构攻击 → 验证热库命中率随查询次数上升。

        多次注入相同特征的DDoS攻击流量到单元0，观察热库命中率变化。
        """
        print("\n" + "=" * 80)
        print("  阶段3：场景1 - 知识库命中率测试")
        print("  目标: 重复查询相同攻击特征，验证热库命中率上升")
        print("=" * 80)

        if not self.units:
            print("  无可用单元，跳过")
            return

        unit = self.units[0]
        attack_category = "ddos"
        attack_type = "syn_flood"
        source_ips = [
            "10.0.0.55", "10.0.0.55", "10.0.0.55",  # 同IP多轮
            "10.0.0.56", "10.0.0.56",
            "10.0.0.57",
        ]

        # 预填充冷库（模拟历史低频攻击数据）
        feature_template = f"{attack_category}:{attack_type}:10.0.0"
        await unit.cold_store.archive([
            {
                "key": feature_template,
                "attack_type": attack_type,
                "category": attack_category,
                "severity": "high",
                "rule": "rate_limit 500rps",
                "description": "SYN Flood DDoS pattern - east region",
            }
        ])

        print("\n  [预填充] 已在冷库写入低频攻击特征\n")

        # 依次查询——前几次冷库命中并升温，后续热库直接命中
        rounds = [
            ("第1轮", 3, "前3次查询：特征不在热库 → 路由到冷库 → 自动升温"),
            ("第2轮", 3, "再3次查询：热库已有特征 → 直接命中"),
            ("第3轮", 2, "最后2次查询：确认热库持续命中"),
        ]

        for round_label, count, desc in rounds:
            print(f"  {round_label} — {desc}")
            for i in range(count):
                ip = source_ips[i % len(source_ips)]
                traffic = {
                    "category": attack_category,
                    "attack_type": attack_type,
                    "source_ip": ip,
                    "severity": "high",
                    "rps": 350,
                }
                result = await unit.handle_attack(traffic)
                source = result["knowledge_source"]
                latency = result["knowledge_latency_ms"]
                print(f"    查询{len(source_ips[:count])}: IP={ip} | 来源={source} | 耗时={latency:.1f}ms")

                # 发布知识库事件
                await self.bus.publish(Message(
                    source=unit.unit_id, target="EventChainRecorder",
                    type="knowledge_hit" if result["knowledge_hit"] else "knowledge_promote",
                    payload={
                        "feature": result["feature"],
                        "source": source,
                        "latency_ms": latency,
                        "unit_id": unit.unit_id,
                    },
                ))

            ks = await unit.router.get_stats()
            print(f"    [统计] 总查询: {ks['total_queries']} | 热库命中率: {ks['hot_hit_rate']:.1%} | 冷库命中率: {ks['cold_hit_rate']:.1%}\n")

        # 最终统计
        final_stats = await unit.router.get_stats()
        print(f"  >>> 测试结果：热库最终命中率 = {final_stats['hot_hit_rate']:.1%}, "
              f"热库条目数 = {final_stats['hot_size']}, 升温次数 = {final_stats['promotions']}")

    async def run_stage3_cross_unit_sync(self) -> None:
        """
        测试场景2：跨单元知识同步。

        单元A遭遇未知攻击 → 升温入库 → 同步到单元B/C → B/C 热库命中。
        """
        print("\n" + "=" * 80)
        print("  阶段3：场景2 - 跨单元知识同步")
        print("  目标: 单元A发现新攻击 → 同步到B/C → 集群共享防护")
        print("=" * 80)

        if len(self.units) < 3:
            print(f"  单元不足（需要3个，当前{len(self.units)}），跳过")
            return

        unit_a, unit_b, unit_c = self.units[0], self.units[1], self.units[2]

        # 模拟：单元A遭遇未知新型攻击（zero-day）
        new_attack_feature = "zero_day:cve_2026_8848:172.16.99"
        new_attack_traffic = {
            "category": "zero_day",
            "attack_type": "cve_2026_8848",
            "source_ip": "172.16.99.42",
            "severity": "severe",
            "rps": 2000,
        }

        print(f"\n  [步骤1] {unit_a.unit_id} 首次遭遇未知新型攻击")
        result_a1 = await unit_a.handle_attack(new_attack_traffic)
        print(f"    来源: {result_a1['knowledge_source']} | 决策: {result_a1['decision']}")

        # 单元A手动录入知识并归档冷库后升温
        kb_entry = {
            "key": new_attack_feature,
            "attack_type": "cve_2026_8848",
            "category": "zero_day",
            "severity": "severe",
            "rule": "block_all immediate",
            "description": "Zero-day RCE via CVE-2026-8848, inbound TCP/8848",
        }
        await unit_a.hot_store.update([kb_entry])
        print(f"    {unit_a.unit_id} 已将新攻击特征写入热库")

        # 单元A发起同步到单元B
        print(f"\n  [步骤2] {unit_a.unit_id} → {unit_b.unit_id} 高危增量同步")
        sync_result = await unit_a.sync_to(unit_b.unit_id, [kb_entry])
        await self.bus.publish(Message(
            source=unit_a.unit_id, target="EventChainRecorder",
            type="sync_event", payload={
                "from_unit": unit_a.unit_id,
                "to_unit": unit_b.unit_id,
                "entry_count": sync_result["synced_entries"],
                "latency_ms": sync_result["latency_ms"],
            },
        ))
        print(f"    同步条目: {sync_result['synced_entries']} | 延迟: {sync_result['latency_ms']:.1f}ms")

        # 单元B吸收同步数据
        await unit_b.hot_store.update(sync_result["entries"])
        print(f"    {unit_b.unit_id} 已吸收同步数据")

        # 单元A发起同步到单元C
        print(f"\n  [步骤3] {unit_a.unit_id} → {unit_c.unit_id} 高危增量同步")
        sync_result2 = await unit_a.sync_to(unit_c.unit_id, [kb_entry])
        await self.bus.publish(Message(
            source=unit_a.unit_id, target="EventChainRecorder",
            type="sync_event", payload={
                "from_unit": unit_a.unit_id,
                "to_unit": unit_c.unit_id,
                "entry_count": sync_result2["synced_entries"],
                "latency_ms": sync_result2["latency_ms"],
            },
        ))
        await unit_c.hot_store.update(sync_result2["entries"])
        print(f"    同步条目: {sync_result2['synced_entries']} | 延迟: {sync_result2['latency_ms']:.1f}ms")

        # 验证：单元B/C 查询同一特征应直接热库命中
        print("\n  [步骤4] 验证跨单元知识共享")
        for unit in [unit_b, unit_c]:
            result = await unit.handle_attack(new_attack_traffic)
            source = result["knowledge_source"]
            latency = result["knowledge_latency_ms"]
            print(f"    {unit.unit_id}: 来源={source} | 耗时={latency:.1f}ms | 决策={result['decision']}")
            await self.bus.publish(Message(
                source=unit.unit_id, target="EventChainRecorder",
                type="knowledge_hit", payload={
                    "feature": result["feature"],
                    "source": source,
                    "latency_ms": latency,
                    "unit_id": unit.unit_id,
                },
            ))

        # 打印同步事件日志
        print("\n  >>> 同步事件日志:")
        for unit in self.units:
            log = await unit.sync_manager.get_sync_log()
            for entry in log:
                print(f"    [{entry['timestamp']}] {entry['from_unit']} → {entry['to_unit']} "
                      f"| {entry['entry_count']}条 | {entry['latency_ms']:.1f}ms")

        # 向集群消息总线发布状态
        await self.bus.publish(Message(
            source="Stage3Runner", target="EventChainRecorder",
            type="cluster_status", payload={
                "total_units": len(self.units),
                "active_units": len(self.units),
                "description": "跨单元同步完成，集群已共享零日漏洞特征",
            },
        ))

        print("\n  >>> 各单元知识库状态:")
        for unit in self.units:
            s = await unit.status()
            print(f"    {s['unit_id']}: 热库={s['knowledge_stats']['hot_size']}条 "
                  f"命中率={s['knowledge_stats']['hot_hit_rate']:.1%} "
                  f"处理攻击={s['attacks_handled']}次")

    async def run_stage3_load_distribution(self) -> None:
        """
        测试场景3：负载分发。

        多条攻击流量通过最少连接策略分发到3个单元。
        """
        print("\n" + "=" * 80)
        print("  阶段3：场景3 - 负载分发测试")
        print("  目标: 12条攻击流量按最少连接策略分发到3个单元")
        print("=" * 80)

        if len(self.units) < 3 or not self.dispatcher:
            print("  单元不足或分发器未初始化，跳过")
            return

        # 生成12条混合攻击流量
        attack_flows = []
        categories = ["ddos", "port_scan", "brute_force", "zero_day"]
        severities = ["low", "medium", "high", "severe"]
        for i in range(12):
            attack_flows.append({
                "task_id": f"atk-{i+1:02d}",
                "category": categories[i % len(categories)],
                "attack_type": f"type_{categories[i % len(categories)]}",
                "source_ip": f"192.168.{10 + i // 4}.{10 + i % 4}",
                "severity": severities[i % len(severities)],
                "rps": (i + 1) * 50,
            })

        print(f"\n  共 {len(attack_flows)} 条攻击流量待分发，策略: {self.dispatcher.strategy.value}\n")

        for flow in attack_flows:
            task_id = flow["task_id"]
            target_id, routing_info = await self.dispatcher.dispatch(task_id, flow)

            # 找到目标单元并处理攻击
            target_unit = next((u for u in self.units if u.unit_id == target_id), None)
            if target_unit:
                result = await target_unit.handle_attack(flow)
                await self.bus.publish(Message(
                    source="LoadDispatcher", target="EventChainRecorder",
                    type="dispatch_event", payload={
                        "task_id": task_id,
                        "target_unit": target_id,
                        "strategy": routing_info["strategy"],
                    },
                ))
                hit = "命中" if result["knowledge_hit"] else "未命中"
                print(f"    [{task_id}] → {target_id} | {flow['category']}/{flow['severity']} | 知识库{hit}")

            await asyncio.sleep(0.05)

        # 释放所有连接
        for unit in self.units:
            await self.dispatcher.release(unit.unit_id)

        # 打印负载分布
        load_dist = await self.dispatcher.get_load_distribution()
        print("\n  >>> 最终负载分布:")
        for uid, count in load_dist.items():
            unit = next((u for u in self.units if u.unit_id == uid), None)
            attacks = unit.attacks_handled if unit else 0
            print(f"    {uid}: 分配 {count} 个任务 | 实际处理 {attacks} 次攻击")

        # 打印分发日志
        dispatch_log = await self.dispatcher.get_dispatch_log()
        print(f"\n  >>> 分发日志 (共 {len(dispatch_log)} 条):")
        for entry in dispatch_log:
            print(f"    {entry['task_id']} → {entry['unit_id']} [{entry['strategy']}]")

    # ==================== 阶段4场景 ====================

    async def run_stage4_upgrade_and_production(self, qps_list: Optional[List[int]] = None) -> None:
        """
        阶段4：灰度升级与生产就绪完整流程。

        1. 双引擎协商生成升级包
        2. 灰度推送（金丝雀→增量→全量）
        3. 压力测试（多档QPS）
        4. 性能监控采集
        5. 安全审计
        6. 合规检查
        7. 输出生产就绪报告

        Args:
            qps_list: 覆盖默认 QPS 级别列表，如 [10, 50, 100, 200, 500, 1000]
        """
        print("\n" + "=" * 80)
        print("  阶段4：灰度升级与生产就绪")
        print("  目标: 升级包构建 → 灰度推送 → 压力测试 → 审计/合规 → 生产报告")
        print("=" * 80)

        sc = self.config.stage4
        output_dir = sc.production_output_dir

        # ================================================================
        # 步骤1：双引擎协商生成升级包
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤1/7] 双引擎协商生成升级包")
        print(f"  {'─' * 60}")

        # 模拟双引擎协商：分析引擎提议新增规则，响应引擎评审
        left_proposal = {
            "proposer": "left_brain",
            "changes": [
                {
                    "component": "left_brain",
                    "change_type": "rule_update",
                    "description": "新增检测规则: 针对 CVE-2026-9999 零日漏洞的 SYN+ACK 指纹识别",
                    "old_value": {
                        "rules": [
                            "rate_limit_500rps",
                            "geo_ip_block_high_risk_region",
                        ]
                    },
                    "new_value": {
                        "rules": [
                            "rate_limit_500rps",
                            "geo_ip_block_high_risk_region",
                            "cve_2026_9999_synack_fingerprint",  # 新增
                            "port_8848_traffic_anomaly",           # 新增
                        ]
                    },
                },
                {
                    "component": "right_brain",
                    "change_type": "config_change",
                    "description": "调整置信度阈值: 攻击溯源置信度从 0.75 提升至 0.82",
                    "old_value": {"confidence_threshold": 0.75},
                    "new_value": {"confidence_threshold": 0.82},
                },
                {
                    "component": "observer_traffic",
                    "change_type": "config_change",
                    "description": "调整流量监控灵敏度: 异常检测阈值从 3σ 收紧至 2.5σ",
                    "old_value": {"anomaly_sigma": 3.0},
                    "new_value": {"anomaly_sigma": 2.5},
                },
            ],
        }

        # 响应引擎评审
        right_review = {
            "reviewer": "right_brain",
            "verdict": "approved",
            "comments": [
                "cve_2026_9999_synack_fingerprint 规则逻辑正确，建议加入回滚验证",
                "置信度提升至 0.82 合理，当前误报率可接受范围内",
                "2.5σ 阈值收紧后将提升约15%检测率，需关注误报率波动",
            ],
        }

        print(f"    分析引擎提案: {len(left_proposal['changes'])} 项变更")
        print(f"    响应引擎评审: {right_review['verdict']} — {right_review['comments'][0][:40]}...")

        # 构建升级包
        # build_package 接受 Dict[str, Any]，需包含 version/description/target_components/change_type
        package = self.package_builder.build_package({
            "version": "2.0.0",
            "description": "阶段4生产就绪升级: 新增零日漏洞检测规则 + 置信度阈值调整 + 流量监控灵敏度收紧",
            "target_components": ["left_brain", "right_brain", "observer_traffic"],
            "change_type": "rule_update",
            "severity": "high",
            "changes_detail": {
                "left_brain": {
                    "type": "rule_update",
                    "new_value": {
                        "rules": [
                            "rate_limit_500rps",
                            "geo_ip_block_high_risk_region",
                            "cve_2026_9999_synack_fingerprint",
                            "port_8848_traffic_anomaly",
                        ]
                    },
                    "old_value": {
                        "rules": [
                            "rate_limit_500rps",
                            "geo_ip_block_high_risk_region",
                        ]
                    },
                },
                "right_brain": {
                    "type": "config_change",
                    "new_value": {"confidence_threshold": 0.82},
                    "old_value": {"confidence_threshold": 0.75},
                },
                "observer_traffic": {
                    "type": "config_change",
                    "new_value": {"anomaly_sigma": 2.5},
                    "old_value": {"anomaly_sigma": 3.0},
                },
            },
        })
        pkg_size = len(json.dumps(package.to_dict(), ensure_ascii=False))
        print(f"    升级包 v{package.version} 已生成 | ID: {package.package_id} | "
              f"大小: {pkg_size}B | 校验和: {package.checksum[:16]}...")

        # 验证升级包
        validation = self.package_builder.validate_package(package)
        print(f"    升级包验证: {'通过' if validation.valid else '失败'}")
        if not validation.valid:
            print(f"    验证失败项: {validation.errors}")
            return

        # 升级包已在 build_package 中持久化（非 dry_run 模式）
        pkg_path = os.path.join(sc.upgrade_package_dir, f"{package.package_id}.json")
        print(f"    升级包已持久化: {pkg_path}")

        # ================================================================
        # 步骤2：灰度推送
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤2/7] 灰度推送")
        print(f"  {'─' * 60}")

        cluster_units = self.units if self.units else []
        if not cluster_units:
            print("    无集群单元，跳过灰度推送")
        else:
            print(f"    推送策略: 金丝雀 {sc.canary_ratio:.0%} → 增量 {sc.incremental_ratio:.0%} → 全量 {1 - sc.canary_ratio - sc.incremental_ratio:.0%}")
            rollout_result = await self.rollout_controller.start_rollout(package, cluster_units)
            rollout_completed = rollout_result.status == "completed"
            print(f"    推送结果: {'全部成功' if rollout_completed else rollout_result.status}")
            # 打印各阶段批次结果
            for br_key, label in [("canary_result", "金丝雀"), ("incremental_result", "增量"), ("full_result", "全量")]:
                br = getattr(rollout_result, br_key, None)
                if br:
                    status_icon = "✓" if br.status.name == "SUCCESS" else "✗"
                    print(f"      {status_icon} {label}批次: "
                          f"成功 {len(br.units_succeeded)}/{len(br.target_unit_ids)} 单元")

            if rollout_result.rollback_targets:
                print(f"    [!] 回滚触发: 回滚 {len(rollout_result.rollback_targets)} 个单元到快照版本")

            # 推送结果已在 start_rollout 中持久化
            rollout_path = os.path.join(sc.production_output_dir, f"{rollout_result.rollout_id}_report.json")
            print(f"    推送记录已持久化: {rollout_path}")

        # ================================================================
        # 步骤3：压力测试
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤3/7] 压力测试")
        print(f"  {'─' * 60}")

        target_qps = qps_list if qps_list else list(sc.stress_test_qps_levels)
        print(f"    即将进行 {len(target_qps)} 档高压力测试")
        print(f"    QPS 级别: {target_qps}")
        print(f"    每档持续时间: {sc.stress_test_duration_per_level}s")

        stress_report = await self.stress_tester.run_stress_test(target_qps)

        for level_result in stress_report.levels:
            qps = level_result.qps
            avg_lat = level_result.avg_latency_ms
            err_rate = level_result.error_rate
            kb_hit = level_result.knowledge_hit_rate
            queue_depth = level_result.queue_depth
            print(f"    [{qps:>4d} QPS] 平均延迟={avg_lat:.1f}ms | "
                  f"错误率={err_rate:.2%} | 知识库命中={kb_hit:.2%} | 队列深度={queue_depth}")

        # CSV 已在 run_stress_test 中自动生成
        csv_path = stress_report.csv_path
        print(f"    压力测试CSV已生成: {csv_path}")

        # ================================================================
        # 步骤4：性能监控
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤4/7] 性能监控")
        print(f"  {'─' * 60}")

        # 采集基线指标
        baseline_metrics = self.perf_monitor.collect_metrics()
        print("    基线指标:")
        print(f"      CPU: {baseline_metrics.cpu_usage_pct:.1f}% | "
              f"内存: {baseline_metrics.memory_usage_pct:.1f}% | "
              f"延迟: {baseline_metrics.avg_response_latency_ms:.2f}ms")

        # 按各QPS级别采集（模拟压力下的指标变化）
        for qps_level in target_qps:
            metrics = self.perf_monitor.collect_metrics_for_qps(qps=qps_level)
            violations = self.perf_monitor.check_thresholds(metrics)
            if violations:
                for v in violations:
                    print(f"    [{qps_level} QPS] ⚠ {v.metric}: {v.current_value} (阈值: {v.threshold})")

        summary = self.perf_monitor.get_summary()
        print(f"    性能汇总: 共采集 {summary['collection_count']} 个快照 | "
              f"超阈值 {summary['violation_count']} 次")

        # ================================================================
        # 步骤4.5：注入测试攻击流量
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤4.5/7] 注入测试攻击流量")
        print(f"  {'─' * 60}")

        # 注入暴力破解攻击流量，确保合规检查中"处置日志至少包含一条记录"通过
        await self.run_scenario("brute_force")

        # ================================================================
        # 步骤5：安全审计
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤5/7] 安全审计")
        print(f"  {'─' * 60}")

        # 从IP隔离日志中提取处置动作进行审计
        action_log = self.ip_isolation.get_action_log()
        audit_results = []
        for idx, log_entry in enumerate(action_log[:20]):  # 最多审计20条
            record = self.security_auditor.record_action(
                alert_id=log_entry.get("alert_id", "unknown"),
                detector_agent="TrafficMonitor",
                decision_agent="LeftBrain",
                executor_agent="IPIsolation",
                action=log_entry.get("action", "unknown"),
                target=log_entry.get("target_ip", "unknown"),
                severity=log_entry.get("severity", "medium"),
                result=log_entry.get("result", "success"),
                reason=f"审计条目 #{idx + 1}: {log_entry.get('action', 'unknown')} 针对 {log_entry.get('target_ip', 'unknown')}",
            )
            result = self.security_auditor.audit_action(record)
            audit_results.append(result)

        passed_audits = sum(1 for r in audit_results if r.passed)
        blocked_audits = sum(1 for r in audit_results if not r.passed)
        print(f"    审计动作: {len(audit_results)} 条 | 通过: {passed_audits} | 拦截: {blocked_audits}")

        if blocked_audits > 0:
            for r in audit_results:
                if not r.passed:
                    print(f"      ✗ 动作 {r.action.action_id[:16]}...: {r.issues}")

        # 生成审计报告
        audit_report = self.security_auditor.generate_audit_report()
        audit_report_path = os.path.join(sc.production_output_dir, f"{audit_report.report_id}.json")
        self.security_auditor.save_report(audit_report, audit_report_path)
        print(f"    审计报告已生成: {audit_report_path}")

        # ================================================================
        # 步骤6：合规检查
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤6/7] 合规检查")
        print(f"  {'─' * 60}")

        compliance_report = self.compliance_checker.run_all_checks()
        for check in compliance_report.checks:
            status_icon = "✓" if check.passed else "✗"
            print(f"    {status_icon} {check.item}: {'通过' if check.passed else '失败'}")
            if not check.passed and check.recommendation:
                print(f"       修复建议: {check.recommendation}")

        print(f"    合规总结: {compliance_report.passed_checks}/{compliance_report.total_checks} 通过")

        # ================================================================
        # 步骤7：生成完整生产就绪报告
        # ================================================================
        print(f"\n  {'─' * 60}")
        print("  [步骤7/7] 生成生产就绪报告")
        print(f"  {'─' * 60}")

        # 计算压力测试聚合指标
        stress_levels = stress_report.levels
        stress_avg_latency = sum(l.avg_latency_ms for l in stress_levels) / max(len(stress_levels), 1)
        stress_avg_error = sum(l.error_rate for l in stress_levels) / max(len(stress_levels), 1)
        stress_avg_kb_hit = sum(l.knowledge_hit_rate for l in stress_levels) / max(len(stress_levels), 1)

        production_report = {
            "report_meta": {
                "generated_at": datetime.now().isoformat(),
                "stage": 4,
                "stage_name": "灰度升级与生产就绪",
                "dry_run": sc.dry_run,
            },
            "upgrade_package_version": package.version,
            "rollout": {
                "total_batches": sum(1 for x in [rollout_result.canary_result, rollout_result.incremental_result, rollout_result.full_result] if x is not None),
                "status": rollout_result.status,
                "strategy": f"金丝雀{sc.canary_ratio:.0%}→增量{sc.incremental_ratio:.0%}→全量",
            } if cluster_units else None,
            "stress_test": {
                "qps_levels": target_qps,
                "avg_latency_ms": round(stress_avg_latency, 2),
                "avg_error_rate": round(stress_avg_error, 4),
                "avg_knowledge_hit_rate": round(stress_avg_kb_hit, 4),
                "max_sustained_qps": stress_report.max_sustained_qps,
            },
            "performance": {
                "collection_count": summary["collection_count"],
                "violation_count": summary["violation_count"],
            },
            "audit": {
                "total_audited": len(audit_results),
                "passed": passed_audits,
                "blocked": blocked_audits,
            },
            "compliance": {
                "total_checks": compliance_report.total_checks,
                "passed": compliance_report.passed_checks,
                "failed": compliance_report.failed_checks,
            },
        }

        report_filename = f"production_ready_report_stage4_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(output_dir, report_filename)
        if not sc.dry_run:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(production_report, f, ensure_ascii=False, indent=2)
        else:
            # dry-run 仍然模拟写入，但不实际写盘
            report_path = os.path.join(output_dir, report_filename)

        print(f"    生产就绪报告: {report_path}")

        # 向消息总线发布完成事件
        await self.bus.publish(Message(
            source="Stage4Runner",
            target="EventChainRecorder",
            type="cluster_status",
            payload={
                "total_units": len(cluster_units),
                "active_units": len(cluster_units),
                "description": f"阶段4完成: 升级包 v{package.version}, "
                               f"合规 {compliance_report.passed_checks}/{compliance_report.total_checks} 通过",
            },
        ))

        print("\n  >>> 阶段4全部流程完成 <<<\n")

    # ==================== 真实流量接入 ====================

    async def run_realtime(self, pcap_path: str = "", listen: bool = False, capture: bool = False) -> None:
        """
        真实流量接入模式。

        Args:
            pcap_path: pcap 文件路径（可选）
            listen:     是否启动在线监听
            capture:    是否启用网络抓包模式
        """
        if not self.realtime_traffic:
            print("  [错误] RealtimeTrafficAgent 未初始化")
            return

        rt = self.realtime_traffic

        # ── Capturer 网络抓包层（复用已在 start_all_agents 中启动的 self.capturer）──
        capturer_task = None
        if capture:
            # self.capturer 已在 start_all_agents 中启动嗅探循环，只需更新端口过滤
            self.capturer.set_port_filter([4444, 8443, 31337, 10443, 18443, 443, 80])
            print("  在线抓包模式: 通过 scapy 实时捕获网络数据包")
        elif pcap_path:
            # pcap 回放模式：在已启动的嗅探循环基础上追加回放任务
            self.capturer.set_port_filter([4444, 8443, 31337, 10443, 18443, 443, 80])
            capturer_task = asyncio.create_task(self.capturer.replay_pcap(pcap_path))

        print("\n" + "=" * 80)
        print("  阶段: 真实流量接入 (Realtime)")
        print("  模式: ", end="")
        if pcap_path and listen:
            print(f"pcap 离线分析 ({pcap_path}) + 在线监听 ({self.config.realtime.listen_port})")
        elif pcap_path:
            print(f"pcap 离线分析 ({pcap_path})")
        elif listen:
            print(f"在线监听 ({self.config.realtime.listen_port})")
        else:
            print("等待中（未指定 pcap 或 listen）")
        print("=" * 80)

        # 1) 先分析 pcap（如果指定）
        if pcap_path:
            try:
                await rt.analyze_pcap(pcap_path)
            except RuntimeError as e:
                print(f"\n  [错误] {e}")
                return

        # 2) 进入在线监听（如果指定）
        if listen:
            server = await rt.start_listening()

            if not pcap_path:
                print("  等待流量日志输入...\n")

            # 持续运行直到用户中断
            try:
                while self.realtime_traffic._running:
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                pass
            finally:
                server.close()
                await server.wait_closed()
                print(f"\n  已停止监听 (共处理 {rt.stats['total_packets']} 包, 告警 {rt.stats['alerts_generated']} 次)")

        # 无监听模式则等待事件链处理完毕
        if not listen and pcap_path:
            await asyncio.sleep(5.0)

        # 停止回放任务（主 capturer 由 stop_all_agents 统一停止）
        if capturer_task:
            capturer_task.cancel()
            try:
                await capturer_task
            except asyncio.CancelledError:
                pass

    # ==================== 打印摘要 ====================

    async def print_summary(self) -> None:
        """打印运行摘要。"""
        print("\n" + "=" * 80)
        print("  运行摘要")
        print("=" * 80)

        left_stats = self.left_brain.get_stats()
        right_stats = self.right_brain.get_stats()
        validator_stats = self.validator.get_stats()
        blacklist = self.ip_isolation.get_blacklist()
        action_log = self.ip_isolation.get_action_log()

        print("\n  [LLM] 推理中枢")
        llm_mode = "mock" if (self.llm_client and self.llm_client.mock_mode) else "real"
        llm_model = self.llm_client.config.model if self.llm_client else "N/A"
        print(f"    模式: {llm_mode} | 模型: {llm_model}")

        print("\n  [分析引擎 - 后勤防御中枢]")
        print(f"    处理告警: {left_stats['total_alerts']}")
        print(f"    级别分布: {left_stats['alerts_by_severity']}")
        print(f"    总算力: {left_stats['total_compute_units']:.1f}")
        if 'llm_count' in left_stats:
            print(f"    决策来源: LLM({left_stats.get('llm_count', 0)}) | Fallback({left_stats.get('fallback_count', 0)})")

        print("\n  [响应引擎 - 修复反击中枢]")
        print(f"    分析告警: {right_stats['total_alerts']}")
        print(f"    平均置信度: {right_stats['avg_confidence']:.2f}")
        print(f"    分类: {right_stats['analyses_by_category']}")
        if 'llm_count' in right_stats:
            print(f"    决策来源: LLM({right_stats.get('llm_count', 0)}) | Fallback({right_stats.get('fallback_count', 0)})")

        print("\n  [校验Agent]")
        print(f"    收到方案: {validator_stats['total_received']}")
        print(f"    通过: {validator_stats['total_passed']}")
        print(f"    驳回: {validator_stats['total_rejected']}")

        print("\n  [处置Agent - IP隔离]")
        print(f"    黑名单IP数: {len(blacklist)}")
        if blacklist:
            for ip in blacklist:
                print(f"      {ip}")
        print(f"    处置日志条数: {len(action_log)}")

        # 阶段2额外摘要
        if not self._is_realtime and self.stage >= 2:
            print("\n  [阶段2扩展感知模块]")
            if self.resource_scheduler:
                rs = self.resource_scheduler.get_resource_state()
                print(f"    算力调度 - 调度记录: {len(self.resource_scheduler.get_schedule_history())} 次")
                print(f"    资源池: CPU {rs.used_cpu_cores}/{rs.total_cpu_cores}核 | 内存 {rs.used_memory_gb}/{rs.total_memory_gb}GB")
            if self.forensic_tracker:
                reports = self.forensic_tracker.get_reports()
                print(f"    溯源追踪 - 报告数: {len(reports)}")
                for r in reports:
                    print(f"      {r.report_id}: {r.alert_id} 跳板链深度={len(r.hop_chain)} 可信度={r.confidence:.0%}")

            if self.medic_agent:
                health = self.medic_agent.get_health_status()
                print("\n  [医疗Agent - 自愈系统]")
                print(f"    监管Agent数: {len(health)}")
                for name, record in health.items():
                    status_icon = "✓" if record.status.value == "healthy" else "✗"
                    print(f"      {status_icon} {name}: {record.status.value}")
                cb = self.medic_agent.get_circuit_breaker_status()
                print(f"    熔断器: {'开启' if cb['is_open'] else '关闭'}")

        # Phase 1.5 出站监测 + L4 网络隔离摘要
        print("\n  [Phase 1.5 - 出站监测 + L4网络隔离]")
        om = self.outbound_monitor
        stats = om.stats if hasattr(om, 'stats') else {}
        print(f"    出站流量监测: "
              f"信标={stats.get('beacon_total', 0)} "
              f"外泄={stats.get('exfil_total', 0)} "
              f"可疑域名={stats.get('domain_total', 0)} "
              f"威胁告警={stats.get('alert_total', 0)}")

        fsm_stats = self.fsm._stats if hasattr(self.fsm, '_stats') else {}
        print(f"    FSM L4状态: "
              f"L4活跃IP={fsm_stats.get('active_l4', 0)} "
              f"L4总触发={fsm_stats.get('l4_activations', 0)}次 "
              f"升级={fsm_stats.get('upgrades', 0)} 降级={fsm_stats.get('downgrades', 0)}")

        # 阶段3集群摘要
        if not self._is_realtime and self.stage >= 3 and self.units:
            print("\n  [阶段3 - 集群状态摘要]")
            print(f"   集群规模: {len(self.units)} 个数据防御单元")
            for unit in self.units:
                s = await unit.status()
                kb = s["knowledge_stats"]
                print(f"     {s['unit_id']}: 状态={s['status']} | 热库={kb['hot_size']}条 "
                      f"命中率={kb['hot_hit_rate']:.1%} | 攻击处理={s['attacks_handled']}次")

            if self.dispatcher:
                load_dist = await self.dispatcher.get_load_distribution()
                print(f"    负载分布: {dict(load_dist)}")

            # 同步事件摘要
            all_syncs = []
            for unit in self.units:
                sl = await unit.sync_manager.get_sync_log()
                all_syncs.extend(sl)
            print(f"    跨单元同步事件: {len(all_syncs)} 条")
            for s in all_syncs[-6:]:
                print(f"      [{s['timestamp']}] {s['from_unit']} → {s['to_unit']} "
                      f"| {s['entry_count']}条 | {s['latency_ms']:.1f}ms")

            # 集群注册状态
            reg_stats = await self.registry.get_stats()
            print(f"    注册中心: {reg_stats['active_units']}/{reg_stats['total_registered']} 活跃")

        # 阶段4灰度升级与生产就绪摘要
        if not self._is_realtime and self.stage >= 4:
            print("\n  [阶段4 - 灰度升级与生产就绪]")
            if self.model_store:
                versions = {}
                for comp in ["left_brain", "right_brain", "observer_traffic"]:
                    vers = self.model_store.list_versions(comp)
                    versions[comp] = len(vers)
                print(f"    模型存储: 跟踪组件 {len(versions)} 个 | 各组件版本数: {versions}")
            if self.package_builder:
                print("    升级包构建器: 就绪")
            if self.rollout_controller:
                print("    灰度推送器: 就绪 (金丝雀→增量→全量)")
            if self.perf_monitor:
                s = self.perf_monitor.get_summary()
                print(f"    性能监控: 采集 {s['collection_count']} 快照 | 超阈值 {s['violation_count']} 次")
            if self.security_auditor:
                print("    安全审计器: 就绪")
            if self.compliance_checker:
                print("    合规检查器: 就绪")
            print(f"    输出目录: {self.config.stage4.production_output_dir}")

        print("\n" + "=" * 80)


# ==================== 主函数 ====================

async def async_main(
    stage: int = 2,
    scenario: str = "all",
    fault_sim: bool = False,
    qps: Optional[List[int]] = None,
    dry_run: bool = False,
    pcap_path: str = "",
    listen: bool = False,
    mock: bool = False,
    model: Optional[str] = None,
    capture: bool = False,
) -> None:
    """
    异步主函数。

    Args:
        stage:     运行阶段 (1=仅核心Agent, 2=全套Agent含器官+医疗, 3=集群化+冷热知识库, 4=灰度升级+生产就绪, 'realtime'=真实流量接入)
        scenario:  攻击场景 (all / ddos / port_scan / brute_force)
        fault_sim: 是否运行故障模拟 (仅 stage2 有效)
        qps:       覆盖默认压力测试 QPS 级别列表 (仅 stage4 有效)
        dry_run:   干跑模式，跳过实际文件写入 (仅 stage4 有效)
        pcap_path: pcap/pcapng 文件路径 (仅 realtime 有效)
        listen:    启动在线监听模式 (仅 realtime 有效)
    """
    # 初始化日志
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    init_global_logger(log_dir)

    stage_desc_map = {
        1: "阶段1 - 核心Agent",
        2: "阶段2 - 全套Agent（感知模块扩展+医疗自愈）",
        3: "阶段3 - 集群化与冷热知识库",
        4: "阶段4 - 灰度升级与生产就绪",
        "realtime": "真实流量接入 - pcap离线分析 + 在线监听",
    }
    stage_desc = stage_desc_map.get(stage, f"阶段{stage}")

    print("\n" + "=" * 80)
    print("  多智能体分层分布式AI防御系统")
    print("  DFU (Dual-Brain Distributed AI Defense Fighting Unit)")
    print(f"  {stage_desc}")
    print("=" * 80)

    # 加载配置
    config = get_config()
    os.makedirs(config.log_dir, exist_ok=True)

    # 初始化 LLM 客户端
    llm_config = config.llm
    if model:
        llm_config.model = model
    if mock:
        llm_config.mock_mode = True
    llm_client = LLMClient(llm_config)
    mode_label = "mock" if llm_client.mock_mode else "real"
    print(f"\n  [LLM] 模式: {mode_label} | 模型: {llm_client.config.model}")

    # 创建事件链记录器
    bus = get_message_bus()
    recorder = EventChainRecorder(bus)

    # 创建运行器
    runner = DFUPrototypeRunner(config, recorder, stage=stage, llm_client=llm_client)

    try:
        # 启动所有 Agent
        await runner.start_all_agents()
        agent_count_map = {1: 6, 2: 10, 3: 10, 4: 10, "realtime": 5}
        agent_count = agent_count_map.get(stage, 10)
        print(f"\n  系统初始化完成，{agent_count} 个 Agent 已上线")
        if stage == "realtime":
            print("  真实流量接入模式: RealtimeTraffic + LeftBrain + RightBrain + Validator + IPIsolation")
        elif stage >= 2:
            print("  医疗Agent自愈系统已激活，正在后台监控所有Agent健康状态")
        if stage != "realtime" and stage >= 3:
            print(f"  集群模式: {len(runner.units)} 个 DFUUnit 已部署，知识库已就绪")
        if stage != "realtime" and stage >= 4:
            print(f"  生产就绪模式: 灰度升级引擎已就绪，输出目录 {config.stage4.production_output_dir}")
        print()

        # 运行场景
        if stage == "realtime":
            await runner.run_realtime(pcap_path=pcap_path, listen=listen)
        elif stage >= 4:
            # 阶段4：灰度升级与生产就绪完整流程
            runner.config.stage4.dry_run = dry_run
            await runner.run_stage4_upgrade_and_production(qps_list=qps)
        elif stage >= 3:
            # 阶段3：依次运行三个场景
            await runner.run_stage3_knowledge_test()
            await asyncio.sleep(0.5)
            await runner.run_stage3_cross_unit_sync()
            await asyncio.sleep(0.5)
            await runner.run_stage3_load_distribution()
        elif fault_sim and stage >= 2:
            # 故障模拟模式：先运行多感知模块协同，再做故障模拟
            await runner.run_stage2_multi_organ()
            await asyncio.sleep(1.0)
            await runner.run_fault_simulation()
        elif stage >= 2:
            await runner.run_stage2_multi_organ()
        else:
            if scenario == "all":
                await runner.run_all_scenarios()
            else:
                await runner.run_scenario(scenario)

        # 额外等待确保最后的异步任务完成
        await asyncio.sleep(1.0)

        # 打印事件链
        recorder.print_chain()

        # 打印运行摘要
        await runner.print_summary()

    except KeyboardInterrupt:
        print("\n\n用户中断，正在关闭...")
    except Exception as e:
        print(f"\n\n运行出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await runner.stop_all_agents()
        print("\n  原型演示结束。\n")


def main() -> None:
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        description="多智能体分层分布式AI防御系统 - 原型"
    )
    parser.add_argument(
        "--stage",
        type=str,
        default="2",
        choices=["1", "2", "3", "4", "realtime"],
        help="运行阶段: 1=仅核心Agent, 2=全套Agent含感知模块扩展+医疗自愈, 3=集群化与冷热知识库, 4=灰度升级+生产就绪, realtime=真实流量接入（默认: 2）",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="all",
        choices=["all", "ddos", "port_scan", "brute_force"],
        help="选择攻击场景（默认: all。stage2/stage3/stage4 时自动使用对应场景）",
    )
    parser.add_argument(
        "--fault-sim",
        action="store_true",
        help="启用故障模拟（仅 stage2 有效），随机杀死Agent并验证医疗Agent自愈全链路",
    )
    parser.add_argument(
        "--qps",
        type=str,
        default=None,
        help="覆盖压力测试 QPS 级别列表（仅 stage4 有效），逗号分隔。默认: 10,50,100,200,500,1000",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="干跑模式（仅 stage4 有效），跳过实际文件写入",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default="",
        help="pcap/pcapng 文件路径（仅 realtime 有效），离线分析模式",
    )
    parser.add_argument(
        "--listen",
        action="store_true",
        help="启动在线监听模式（仅 realtime 有效），接收 JSON 格式流量日志",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=None,
        help="在线监听端口（仅 realtime 有效），覆盖默认配置",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="强制启用 LLM mock 模式（默认自动检测：有 API key 用真实LLM，没有用 mock）",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="覆盖 LLMConfig 中的模型名称（如 gpt-4、hunyuan-lite 等）",
    )
    parser.add_argument(
        "--capture",
        action="store_true",
        default=True,
        help="启用在线抓包模式（默认开启），通过 scapy 实时捕获网络数据包。需安装 Npcap",
    )
    args = parser.parse_args()

    # 解析 --stage 为 int 或保持 str
    stage = int(args.stage) if args.stage.isdigit() else args.stage

    # 解析 --qps 参数
    qps_list = None
    if args.qps:
        qps_list = [int(x.strip()) for x in args.qps.split(",")]

    asyncio.run(async_main(stage, args.scenario, args.fault_sim, qps_list, args.dry_run,
                           pcap_path=args.pcap, listen=args.listen,
                           mock=args.mock, model=args.model, capture=args.capture))


if __name__ == "__main__":
    main()
