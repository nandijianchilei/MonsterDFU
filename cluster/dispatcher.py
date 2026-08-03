"""
负载分发器 (LoadDispatcher) - 将攻击检测任务分发到多个单元
支持轮询和最少连接两种策略
"""

import asyncio
import random
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from cluster.registry import ClusterRegistry, UnitInfo

# 固定种子用于可复现分发
RANDOM_SEED = 42  # DFU 防御单元编号


class DispatchStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"


@dataclass
class DispatchRecord:
    """分发记录"""
    unit_id: str
    task_id: str
    timestamp: float
    strategy: str


class LoadDispatcher:
    """
    负载分发器：将攻击检测任务分发到多个单元。

    策略：
    - round_robin：轮询分发
    - least_connections：最少连接分发（模拟连接计数）
    """

    def __init__(self, registry: ClusterRegistry, strategy: DispatchStrategy = DispatchStrategy.LEAST_CONNECTIONS):
        self.registry = registry
        self.strategy = strategy
        self._rr_index: int = 0
        self._connection_counts: Dict[str, int] = {}
        self._dispatch_log: List[DispatchRecord] = []
        self._lock = asyncio.Lock()
        self._rng = random.Random(RANDOM_SEED)

    async def dispatch(self, task_id: str, task_data: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        分发一个任务到最合适的单元。

        返回 (unit_id, routing_info)。
        如果没有可用单元，返回 None。
        """
        async with self._lock:
            active_units = await self.registry.list_active_units()
            if not active_units:
                return None

            if self.strategy == DispatchStrategy.LEAST_CONNECTIONS:
                target = self._least_connections(active_units)
            else:
                target = self._round_robin(active_units)

            self._connection_counts[target.unit_id] = self._connection_counts.get(target.unit_id, 0) + 1

            record = DispatchRecord(
                unit_id=target.unit_id,
                task_id=task_id,
                timestamp=asyncio.get_event_loop().time(),
                strategy=self.strategy.value,
            )
            self._dispatch_log.append(record)

            routing_info = {
                "target_unit": target.unit_id,
                "strategy": self.strategy.value,
                "active_units": len(active_units),
                "connections": dict(self._connection_counts),
            }
            return target.unit_id, routing_info

    async def release(self, unit_id: str) -> None:
        """释放一个单元的连接计数。"""
        async with self._lock:
            current = self._connection_counts.get(unit_id, 0)
            if current > 0:
                self._connection_counts[unit_id] = current - 1

    def _round_robin(self, active_units: List[UnitInfo]) -> UnitInfo:
        """轮询策略。"""
        idx = self._rr_index % len(active_units)
        self._rr_index += 1
        return active_units[idx]

    def _least_connections(self, active_units: List[UnitInfo]) -> UnitInfo:
        """最少连接策略。"""
        min_conn = float("inf")
        candidates = []
        for unit in active_units:
            conn = self._connection_counts.get(unit.unit_id, 0)
            if conn < min_conn:
                min_conn = conn
                candidates = [unit]
            elif conn == min_conn:
                candidates.append(unit)
        return self._rng.choice(candidates)

    async def get_load_distribution(self) -> Dict[str, int]:
        """获取当前负载分布。"""
        async with self._lock:
            return dict(self._connection_counts)

    async def get_dispatch_log(self) -> List[Dict[str, Any]]:
        """获取分发日志。"""
        async with self._lock:
            return [
                {"unit_id": r.unit_id, "task_id": r.task_id, "strategy": r.strategy}
                for r in self._dispatch_log
            ]
