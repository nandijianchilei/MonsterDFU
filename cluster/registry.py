"""
集群注册中心 (ClusterRegistry) - 维护集群中所有数据防御单元的注册信息
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class UnitInfo:
    """单元注册信息"""
    unit_id: str
    address: str
    status: str = "active"  # active / degraded / offline
    knowledge_version: int = 1
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)


class ClusterRegistry:
    """
    集群注册中心：维护所有单元的生命周期和健康状态。

    - register / unregister / list_active_units
    - 心跳检测与自动下线
    """

    def __init__(self, heartbeat_timeout: float = 10.0):
        self._units: Dict[str, UnitInfo] = {}
        self._lock = asyncio.Lock()
        self.heartbeat_timeout = heartbeat_timeout

    async def register(self, unit_id: str, address: str = "", knowledge_version: int = 1) -> UnitInfo:
        """注册一个新单元。"""
        async with self._lock:
            if unit_id in self._units:
                # 重新注册：更新心跳和状态
                existing = self._units[unit_id]
                existing.last_heartbeat = time.time()
                existing.status = "active"
                existing.knowledge_version = knowledge_version
                return existing

            info = UnitInfo(
                unit_id=unit_id,
                address=address or f"dfu://{unit_id}",
                knowledge_version=knowledge_version,
            )
            self._units[unit_id] = info
            return info

    async def unregister(self, unit_id: str) -> bool:
        """注销一个单元。"""
        async with self._lock:
            if unit_id not in self._units:
                return False
            self._units[unit_id].status = "offline"
            return True

    async def heartbeat(self, unit_id: str) -> bool:
        """单元心跳上报。"""
        async with self._lock:
            if unit_id not in self._units:
                return False
            self._units[unit_id].last_heartbeat = time.time()
            self._units[unit_id].status = "active"
            return True

    async def list_active_units(self) -> List[UnitInfo]:
        """获取所有活跃单元列表（含心跳超时自动标记）。"""
        async with self._lock:
            now = time.time()
            active = []
            for info in self._units.values():
                if now - info.last_heartbeat > self.heartbeat_timeout:
                    info.status = "offline"
                else:
                    active.append(info)
            return active

    async def list_all_units(self) -> List[UnitInfo]:
        """获取全部单元列表。"""
        async with self._lock:
            return list(self._units.values())

    async def get_unit(self, unit_id: str) -> Optional[UnitInfo]:
        """获取指定单元信息。"""
        async with self._lock:
            return self._units.get(unit_id)

    async def get_stats(self) -> Dict:
        """获取集群注册状态摘要。"""
        async with self._lock:
            all_units = list(self._units.values())
            now = time.time()
            active_count = sum(1 for u in all_units if u.status == "active"
                             and now - u.last_heartbeat <= self.heartbeat_timeout)
            return {
                "total_registered": len(all_units),
                "active_units": active_count,
                "offline_units": len(all_units) - active_count,
                "units": {u.unit_id: {"status": u.status, "version": u.knowledge_version}
                         for u in all_units},
            }
