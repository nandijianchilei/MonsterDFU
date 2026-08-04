"""Agent 注册表驱动装配工厂（融合增强 v1.1 第一阶段 · 地基）。

将 Agent 的创建/启动/停止从 main.py 手工硬编码（start_all_agents / stop_all_agents）
解耦为"注册表声明 + 工厂装配"。新增器官只需向注册表 add() 一行声明即可：

    runner.registry.add(AgentSpec(
        name="MyNewOrgan",
        instance=MyNewOrganAgent(config),
        stage_required=2,          # 可选：仅 stage >= 2 时装配
        non_realtime_only=True,    # 可选：仅非 realtime 模式装配
        medic_monitored=True,      # 可选：纳入医疗自愈心跳
    ))

start_all() / stop_all() 会按注册顺序（stop 为倒序）批量启停，并自动跳过
不满足 stage / 实时模式的 Agent。
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class AgentSpec:
    """单个 Agent 的装配声明。

    Attributes:
        name: 全局唯一 Agent 名（用于日志与医疗注册）。
        instance: 已实例化的 Agent 对象；或提供 factory 惰性装配。
        factory: 可选，返回 Agent 实例的可调用对象（与 instance 二选一）。
        start: 可选，自定义启动函数（async 或 sync）；默认调用 instance.start()。
        stop: 可选，自定义停止函数（async 或 sync）；默认调用 instance.stop()。
        stage_required: 可选，仅在 runner.stage >= 该值时装配。
        realtime_only: True 时仅 realtime 模式装配。
        non_realtime_only: True 时仅非 realtime 模式装配。
        medic_monitored: True 时纳入医疗自愈系统的心跳监控。
        order: 注册顺序（自动按 add 顺序递增，无需手动指定）。
    """

    name: str
    instance: Any = None
    factory: Optional[Callable[[], Any]] = None
    start: Optional[Callable[..., Any]] = None
    stop: Optional[Callable[..., Any]] = None
    stage_required: Optional[int] = None
    realtime_only: bool = False
    non_realtime_only: bool = False
    medic_monitored: bool = False
    order: int = field(default=0, init=False)

    def resolve(self) -> Any:
        """返回 Agent 实例（优先 instance，其次 factory 惰性创建）。"""
        if self.instance is not None:
            return self.instance
        if self.factory is not None:
            self.instance = self.factory()
            return self.instance
        raise ValueError(f"AgentSpec[{self.name}] 缺少 instance 或 factory")

    def match_stage(self, stage: int, is_realtime: bool) -> bool:
        """判断该 Agent 是否满足当前运行模式/阶段的条件。"""
        if self.stage_required is not None:
            if isinstance(stage, str):
                # realtime 模式视为阶段 1（stage_required 主要针对分阶段非实时模式）
                if not is_realtime:
                    return False
            elif stage < self.stage_required:
                return False
        if self.realtime_only and not is_realtime:
            return False
        if self.non_realtime_only and is_realtime:
            return False
        return True


class AgentRegistry:
    """注册表驱动的 Agent 装配工厂。

    用法：
        reg = AgentRegistry()
        reg.add(AgentSpec(name="A", instance=agent_a))
        reg.add(AgentSpec(name="B", instance=agent_b, stage_required=2))
        await reg.start_all(stage=2, is_realtime=False)   # 自动跳过不满足条件的
        await reg.stop_all()
    """

    def __init__(self) -> None:
        self._specs: Dict[str, AgentSpec] = {}
        self._order_counter: int = 0

    # ---------- 注册 ----------

    def add(self, spec: AgentSpec) -> AgentSpec:
        """注册一个 Agent 装配声明。同名重复注册会抛错（避免双 Agent 漂移）。"""
        if spec.name in self._specs:
            raise ValueError(
                f"AgentRegistry: 重复注册 Agent[{spec.name}]，"
                f"请检查装配声明（原声明 order={self._specs[spec.name].order}）"
            )
        spec.order = self._order_counter
        self._order_counter += 1
        self._specs[spec.name] = spec
        return spec

    def remove(self, name: str) -> AgentSpec:
        """注销一个 Agent 声明；不存在时抛 KeyError（防止静默丢注册项）。"""
        if name not in self._specs:
            raise KeyError(f"Agent 未注册: {name}")
        return self._specs.pop(name)

    # ---------- 查询 ----------

    def contains(self, name: str) -> bool:
        return name in self._specs

    def get(self, name: str) -> Optional[AgentSpec]:
        return self._specs.get(name)

    def names(self) -> List[str]:
        """按注册顺序返回所有 Agent 名。"""
        return [s.name for s in sorted(self._specs.values(), key=lambda s: s.order)]

    def specs(self, stage: int = 1, is_realtime: bool = False) -> List[AgentSpec]:
        """返回满足当前模式/阶段条件的装配清单（按注册顺序）。"""
        return [
            s for s in sorted(self._specs.values(), key=lambda s: s.order)
            if s.match_stage(stage, is_realtime)
        ]

    def count(self, stage: int = 1, is_realtime: bool = False) -> int:
        return len(self.specs(stage, is_realtime))

    # ---------- 启停 ----------

    async def start_all(self, stage: int = 1, is_realtime: bool = False) -> List[str]:
        """按注册顺序启动满足条件的全部 Agent。

        Returns:
            实际启动的 Agent 名列表。
        """
        started: List[str] = []
        for spec in self.specs(stage, is_realtime):
            await self._start_one(spec)
            started.append(spec.name)
        return started

    async def _start_one(self, spec: AgentSpec) -> None:
        """启动单个 Agent：优先 spec.start，其次 instance.start()。"""
        instance = spec.resolve()
        if spec.start is not None:
            result = spec.start()
            if inspect.isawaitable(result):
                await result
            return
        if instance is None:
            raise ValueError(f"AgentSpec[{spec.name}] 无法解析出实例")
        method = getattr(instance, "start", None)
        if method is None:
            return  # 无 start 的被动组件（如纯数据结构）允许跳过
        result = method()
        if inspect.isawaitable(result):
            await result

    async def stop_all(self, stage: int = 1, is_realtime: bool = False) -> List[str]:
        """按注册顺序的倒序停止满足条件的全部 Agent。"""
        stopped: List[str] = []
        for spec in reversed(self.specs(stage, is_realtime)):
            await self._stop_one(spec)
            stopped.append(spec.name)
        return stopped

    async def _stop_one(self, spec: AgentSpec) -> None:
        instance = spec.resolve()
        if spec.stop is not None:
            result = spec.stop()
            if inspect.isawaitable(result):
                await result
            return
        if instance is None:
            return
        method = getattr(instance, "stop", None)
        if method is None:
            return
        result = method()
        if inspect.isawaitable(result):
            await result
