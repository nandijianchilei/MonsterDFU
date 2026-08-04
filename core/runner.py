"""DFU 原型运行器。

从 main.py 的 DFUPrototypeRunner 迁移而来：
- Agent 装配逻辑 → core/agent_factory.py (AgentFactory.create_all)
- 场景执行逻辑 → core/scenario_runner.py (ScenarioRunnerMixin)
- 本文件只保留运行器骨架：状态持有、启动/停止、流量注入。
"""
import asyncio
from typing import List, Optional

from communication.message_bus import Message, get_message_bus
from config import Config
from core.agent_factory import AgentFactory
from core.agent_registry import AgentRegistry
from core.event_recorder import EventChainRecorder
from core.llm_client import LLMClient
from core.scenario_runner import ScenarioRunnerMixin
from utils.logger import get_logger


class DFUPrototypeRunner(ScenarioRunnerMixin):
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

        # 全部 Agent 的创建与装配委托给 AgentFactory（含注册表/医疗注册）
        AgentFactory.create_all(self)

    @property
    def registry(self) -> "AgentRegistry":
        """兼容别名：Agent 注册表（供既有测试/外部引用）。"""
        return self._agent_registry

    # ==================== 启动/停止 ====================

    async def start_all_agents(self) -> None:
        """启动所有 Agent（按注册表声明顺序装配）。"""
        started = await self._agent_registry.start_all(
            stage=self.stage, is_realtime=self._is_realtime,
        )
        self.logger.info(f"所有 Agent 已启动 ({len(started)}个): {', '.join(started)}")

        # 阶段3：部署所有单元
        if not self._is_realtime and self.stage >= 3:
            for unit in self.units:
                await unit.deploy()
            self.logger.info(f"{len(self.units)} 个 DFUUnit 已注册到集群")

    async def stop_all_agents(self) -> None:
        """停止所有 Agent（按注册表声明的倒序回收，先停医疗再停处置）。"""
        await self._agent_registry.stop_all(
            stage=self.stage, is_realtime=self._is_realtime,
        )
        # 阶段3：关闭所有单元
        if not self._is_realtime and self.stage >= 3:
            for unit in self.units:
                await unit.shutdown()
        self.logger.info("所有 Agent 已停止")

    # ==================== 流量注入 ====================

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
