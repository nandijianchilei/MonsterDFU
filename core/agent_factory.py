"""Agent 工厂：创建并注入所有器官/双脑/蜜罐/知识路由/集群 Agent。

从 DFUPrototypeRunner.__init__ 迁移而来。
"""
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from core.agent_registry import AgentRegistry, AgentSpec
from core.countermeasure_fsm import CountermeasureFSM

if TYPE_CHECKING:
    from core.runner import DFURunner


class AgentFactory:
    """创建并组装所有 Agent 实例，注入到 Runner 中。"""

    @staticmethod
    def create_all(runner: "DFURunner") -> None:
        """在 runner 上创建全部 Agent 并完成装配。"""
        # 延迟导入以避免循环引用
        from config import Config
        from core.brain_left import LeftBrain
        from core.brain_right import RightBrain
        from core.validator import ValidatorAgent
        from core.event_aggregator import EventAggregator
        from core.rule_frontend import RuleEngineFrontend
        from core.medic_agent import MedicAgent
        from core.honeypot import HoneypotAgent
        from core.interference import InterferenceAgent
        from organs.actor_ip_isolation import IPIsolationAgent
        from organs.observer_traffic import TrafficMonitorAgent
        from organs.observer_outbound import OutboundMonitor
        from organs.scanner_vuln import VulnScannerAgent
        from organs.auditor_log import LogAuditorAgent
        from organs.scheduler_resource import ResourceSchedulerAgent
        from organs.tracker_forensic import ForensicTrackerAgent
        from organs.capturer import PacketCapture
        from core.simulate_attack import AttackSimulator
        from organs.scanner_vuln import VulnSimulator
        from organs.auditor_log import LogAnomalySimulator
        from organs.observer_realtime import RealtimeTrafficAgent
        from cluster.dfu_unit import DFUUnit
        from cluster.registry import ClusterRegistry
        from cluster.dispatcher import LoadDispatcher, DispatchStrategy

        cfg: Config = runner.config

        # ===== 阶段1核心Agent（始终初始化）=====
        runner.traffic_monitor = TrafficMonitorAgent(cfg)
        from config import get_llm_config
        from core.llm_client import create_organ_llm_client
        runner.left_brain_llm = create_organ_llm_client("left-brain", get_llm_config(), runner.llm_client)
        runner.right_brain_llm = create_organ_llm_client("right-brain", get_llm_config(), runner.llm_client)
        runner.left_brain = LeftBrain(cfg, llm_client=runner.left_brain_llm)
        runner.right_brain = RightBrain(cfg, llm_client=runner.right_brain_llm)
        runner.validator = ValidatorAgent(cfg)
        runner.ip_isolation = IPIsolationAgent(cfg)
        runner.event_aggregator = EventAggregator(cfg.event_aggregator)
        runner.logger.info("事件聚合器已初始化")
        runner.rule_frontend = RuleEngineFrontend(cfg)
        runner.logger.info("规则引擎前置分流已初始化")

        # ===== Phase 1.5 新增模块 =====
        runner.outbound_monitor = OutboundMonitor(cfg)
        runner.logger.info("出站流量监测模块已初始化 (OutboundMonitor)")
        runner.fsm = CountermeasureFSM()
        runner.logger.info("Phase 1.5 FSM L4 网络隔离就绪 (三闸门锁)")

        # ===== 实时抓包模块 (PacketCapture) =====
        runner.capturer = PacketCapture(runner.bus, cfg)
        runner.capturer.set_port_filter([4444, 8443, 31337, 10443, 18443, 443, 80])
        runner.capturer.enable_detection_feed()
        runner.logger.info("实时抓包模块已初始化 (PacketCapture)")

        # ===== 阶段2新增Agent =====
        runner.vuln_scanner: Optional[VulnScannerAgent] = None
        runner.log_auditor: Optional[LogAuditorAgent] = None
        runner.resource_scheduler: Optional[ResourceSchedulerAgent] = None
        runner.forensic_tracker: Optional[ForensicTrackerAgent] = None
        runner.medic_agent: Optional[MedicAgent] = None
        runner.vuln_simulator: Optional[VulnSimulator] = None
        runner.log_simulator: Optional[LogAnomalySimulator] = None
        runner.honeypot: Optional[HoneypotAgent] = None
        runner.interference_agent: Optional[InterferenceAgent] = None

        if not runner._is_realtime and runner.stage >= 2:
            runner.vuln_scanner = VulnScannerAgent(cfg)
            runner.log_auditor = LogAuditorAgent(cfg)
            runner.resource_scheduler = ResourceSchedulerAgent(cfg)
            runner.forensic_tracker = ForensicTrackerAgent(cfg)
            runner.medic_agent = MedicAgent(cfg)
            runner.vuln_simulator = VulnSimulator(cfg)
            runner.log_simulator = LogAnomalySimulator(cfg)
            runner.honeypot = HoneypotAgent(cfg)
            runner.right_brain.honeypot = runner.honeypot
            runner.interference_agent = InterferenceAgent(cfg, fsm=runner.fsm)
            runner.right_brain.interference_agent = runner.interference_agent
        elif runner._is_realtime:
            runner.honeypot = HoneypotAgent(cfg)
            runner.right_brain.honeypot = runner.honeypot
            runner.interference_agent = InterferenceAgent(cfg, fsm=runner.fsm)
            runner.right_brain.interference_agent = runner.interference_agent

        # ===== 阶段3：集群化与冷热知识库 =====
        runner.cluster_registry: Optional[ClusterRegistry] = None
        runner.dispatcher: Optional[LoadDispatcher] = None
        runner.units: List[DFUUnit] = []

        if not runner._is_realtime and runner.stage >= 3:
            unit_count = cfg.stage3.default_unit_count
            runner.cluster_registry = ClusterRegistry(
                heartbeat_timeout=cfg.stage3.cluster_heartbeat_timeout
            )
            runner.dispatcher = LoadDispatcher(
                runner.cluster_registry,
                strategy=DispatchStrategy.LEAST_CONNECTIONS,
            )
            runner.logger.info(f"阶段3集群初始化: 创建 {unit_count} 个 DFUUnit 实例")

            for _ in range(unit_count):
                unit = DFUUnit(cfg, runner.cluster_registry, knowledge_dir=cfg.log_dir)
                runner.units.append(unit)
            runner.logger.info(f"阶段3知识库目录: {cfg.log_dir}")

        # ===== 阶段4：灰度升级与生产就绪 =====
        from upgrade.model_store import ModelWeightStore
        from upgrade.package_builder import UpgradePackageBuilder
        from upgrade.rollout_controller import RolloutController
        from production.perf_monitor import PerformanceMonitor
        from production.security_auditor import SecurityAuditor
        from production.stress_tester import StressTester
        from production.compliance_checklist import ComplianceChecker

        runner.model_store: Optional[ModelWeightStore] = None
        runner.package_builder: Optional[UpgradePackageBuilder] = None
        runner.rollout_controller: Optional[RolloutController] = None
        runner.perf_monitor: Optional[PerformanceMonitor] = None
        runner.security_auditor: Optional[SecurityAuditor] = None
        runner.stress_tester: Optional[StressTester] = None
        runner.compliance_checker: Optional[ComplianceChecker] = None

        if not runner._is_realtime and runner.stage >= 4:
            sc = cfg.stage4
            output_dir = sc.production_output_dir
            os.makedirs(output_dir, exist_ok=True)

            runner.model_store = ModelWeightStore(
                store_dir=sc.model_store_dir,
                dry_run=sc.dry_run,
            )
            runner.package_builder = UpgradePackageBuilder(
                store_dir=sc.upgrade_package_dir,
                dry_run=sc.dry_run,
            )
            runner.rollout_controller = RolloutController(
                canary_ratio=sc.canary_ratio,
                incremental_ratio=sc.incremental_ratio,
                canary_observe_rounds=sc.canary_observe_rounds,
                incremental_observe_rounds=sc.incremental_observe_rounds,
                heartbeat_interval=cfg.medic.heartbeat_interval,
                dry_run=sc.dry_run,
                output_dir=output_dir,
            )
            runner.perf_monitor = PerformanceMonitor(
                cpu_threshold_pct=sc.perf_cpu_threshold_pct,
                memory_threshold_pct=sc.perf_memory_threshold_pct,
                latency_threshold_ms=sc.perf_latency_threshold_ms,
                fp_rate_threshold=sc.perf_fp_rate_threshold,
                fn_rate_threshold=sc.perf_fn_rate_threshold,
                success_rate_threshold=sc.perf_success_rate_threshold,
            )
            runner.security_auditor = SecurityAuditor(dry_run=sc.dry_run)
            runner.stress_tester = StressTester(
                duration_per_level=sc.stress_test_duration_per_level,
                dry_run=sc.dry_run,
                output_dir=output_dir,
            )
            runner.compliance_checker = ComplianceChecker(
                security_auditor=runner.security_auditor,
                medic_agent=runner.medic_agent,
                rollout_controller=runner.rollout_controller,
                stress_tester=runner.stress_tester,
                dry_run=sc.dry_run,
            )
            runner.logger.info("阶段4组件初始化: 灰度升级引擎 + 生产就绪组件")
            runner.logger.info(f"  输出目录: {output_dir}")

        # 真实流量接入模块
        runner.realtime_traffic: Optional[RealtimeTrafficAgent] = None
        if runner.stage == "realtime":
            runner.realtime_traffic = RealtimeTrafficAgent(cfg)
            runner.logger.info("真实流量接入模块已初始化 (pcap分析 + 在线监听)")

        # 攻击模拟器
        runner.simulator = AttackSimulator(
            ddos_source_count=cfg.simulator.ddos_source_ip_count,
            ddos_rate=cfg.simulator.ddos_requests_per_second,
            scan_port_range=cfg.simulator.port_scan_range,
            scan_speed=cfg.simulator.port_scan_speed,
            brute_attempts=cfg.simulator.brute_force_attempts,
            brute_target_port=cfg.simulator.brute_force_target_port,
        )

        # ===== Agent 注册表装配 =====
        runner._agent_registry = AgentRegistry()
        AgentFactory._build_agent_registry(runner)

    @staticmethod
    def _build_agent_registry(runner: "DFURunner") -> None:
        """声明全部 Agent 的装配注册表（顺序即数据流启动顺序）。"""
        reg = runner._agent_registry

        reg.add(AgentSpec(name="IPIsolation", instance=runner.ip_isolation))
        reg.add(AgentSpec(name="Validator", instance=runner.validator))

        reg.add(AgentSpec(name="RuleEngineFrontend", instance=runner.rule_frontend))
        reg.add(AgentSpec(name="EventAggregator", instance=runner.event_aggregator))

        reg.add(AgentSpec(
            name="ResourceScheduler", instance=runner.resource_scheduler,
            stage_required=2, non_realtime_only=True, medic_monitored=True,
        ))
        reg.add(AgentSpec(
            name="ForensicTracker", instance=runner.forensic_tracker,
            stage_required=2, non_realtime_only=True, medic_monitored=True,
        ))
        reg.add(AgentSpec(
            name="VulnScanner", instance=runner.vuln_scanner,
            stage_required=2, non_realtime_only=True, medic_monitored=True,
        ))
        reg.add(AgentSpec(
            name="LogAuditor", instance=runner.log_auditor,
            stage_required=2, non_realtime_only=True, medic_monitored=True,
        ))
        reg.add(AgentSpec(
            name="Honeypot", instance=runner.honeypot,
            stage_required=2, medic_monitored=True,
        ))
        reg.add(AgentSpec(
            name="Interference", instance=runner.interference_agent,
            stage_required=2, medic_monitored=True,
        ))

        reg.add(AgentSpec(
            name="LeftBrain", instance=runner.left_brain, medic_monitored=True,
        ))
        reg.add(AgentSpec(
            name="RightBrain", instance=runner.right_brain, medic_monitored=True,
        ))

        reg.add(AgentSpec(
            name="RealtimeTraffic", instance=runner.realtime_traffic,
            realtime_only=True,
        ))
        reg.add(AgentSpec(
            name="TrafficMonitor", instance=runner.traffic_monitor,
            non_realtime_only=True, medic_monitored=True,
        ))

        reg.add(AgentSpec(
            name="OutboundMonitor", instance=runner.outbound_monitor,
            medic_monitored=True,
        ))

        reg.add(AgentSpec(
            name="PacketCapture", instance=runner.capturer, medic_monitored=True,
        ))

        reg.add(AgentSpec(name="EventRecorder", instance=runner.recorder))

        async def _start_medic():
            AgentFactory._register_all_to_medic(runner)
            await runner.medic_agent.start()

        reg.add(AgentSpec(
            name="MedicAgent", instance=runner.medic_agent,
            start=_start_medic, stage_required=2, non_realtime_only=True,
        ))

    @staticmethod
    def _register_all_to_medic(runner: "DFURunner") -> None:
        """将所有声明 medic_monitored 的 Agent 注册到医疗自愈系统。"""
        medic = runner.medic_agent
        if not medic:
            return

        runner._medic_alive_flags: Dict[str, bool] = {
            spec.name: True for spec in runner._agent_registry.specs(
                stage=runner.stage, is_realtime=runner._is_realtime,
            ) if spec.medic_monitored
        }

        for agent_name in runner._medic_alive_flags:
            def make_hb_cb(name):
                async def hb():
                    return runner._medic_alive_flags.get(name, False)
                return hb

            def make_snapshot_cb(name):
                def snap():
                    return {"name": name, "timestamp": datetime.now().isoformat()}
                return snap

            def make_iso_cb(name):
                async def iso(aname, isolated):
                    runner.logger.warning(
                        f"[医疗回调] Agent {aname} {'被隔离' if isolated else '已恢复'}"
                    )
                return iso

            medic.register_agent(
                agent_name=agent_name,
                heartbeat_callback=make_hb_cb(agent_name),
                snapshot_callback=make_snapshot_cb(agent_name),
                isolation_callback=make_iso_cb(agent_name),
            )
