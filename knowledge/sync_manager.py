"""
增量同步管理器 (SyncManager) - 管理单元间知识库同步
仅同步高危威胁（severity ≥ high）的增量数据
模拟跨单元同步延迟 5-30ms
"""

import asyncio
import random
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class SyncEvent:
    """同步事件记录"""
    timestamp: str
    from_unit: str
    to_unit: str
    entry_count: int
    latency_ms: float
    severity_filter: str = "high"


class SyncManager:
    """
    增量同步管理器：管理单元间知识库的增量同步。

    - 仅同步 severity ≥ high 的增量数据
    - 模拟跨单元同步延迟 5-30ms
    - 支持 push / pull 两种同步模式
    - 记录同步事件日志
    """

    def __init__(self, unit_id: str):
        self.unit_id = unit_id
        self._sync_log: List[SyncEvent] = []
        self._lock = asyncio.Lock()

        # 各单元已同步时间戳记录
        self._peer_timestamps: Dict[str, float] = {}

    async def push(self, target_unit_id: str, delta_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        向目标单元推送增量数据。仅保留 severity ≥ high 的条目。

        返回推送结果摘要。
        """
        latency = random.uniform(0.005, 0.030)
        await asyncio.sleep(latency)

        # 过滤：仅同步高危威胁
        filtered = [e for e in delta_entries
                    if e.get("severity", "").lower() in ("high", "severe", "critical")]

        async with self._lock:
            self._peer_timestamps[target_unit_id] = time.time()

            event = SyncEvent(
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                from_unit=self.unit_id,
                to_unit=target_unit_id,
                entry_count=len(filtered),
                latency_ms=latency * 1000,
            )
            self._sync_log.append(event)

        return {
            "action": "push",
            "from_unit": self.unit_id,
            "to_unit": target_unit_id,
            "total_entries": len(delta_entries),
            "synced_entries": len(filtered),
            "skipped_entries": len(delta_entries) - len(filtered),
            "latency_ms": latency * 1000,
            "entries": filtered,
        }

    async def pull(self, source_unit_id: str, since_timestamp: Optional[float] = None) -> Dict[str, Any]:
        """
        从源单元拉取增量数据（模拟远端查询）。

        返回拉取结果摘要。实际数据由调用方通过侧信道传输，
        本方法仅记录拉取事件并返回元信息。
        """
        latency = random.uniform(0.005, 0.030)
        await asyncio.sleep(latency)

        since_ts = since_timestamp or 0.0

        async with self._lock:
            event = SyncEvent(
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                from_unit=source_unit_id,
                to_unit=self.unit_id,
                entry_count=0,  # 由实际传输确定
                latency_ms=latency * 1000,
            )
            self._sync_log.append(event)

        return {
            "action": "pull",
            "from_unit": source_unit_id,
            "to_unit": self.unit_id,
            "since_timestamp": since_ts,
            "latency_ms": latency * 1000,
        }

    async def get_sync_log(self) -> List[Dict[str, Any]]:
        """获取同步事件日志。"""
        async with self._lock:
            return [
                {
                    "timestamp": e.timestamp,
                    "from_unit": e.from_unit,
                    "to_unit": e.to_unit,
                    "entry_count": e.entry_count,
                    "latency_ms": e.latency_ms,
                }
                for e in self._sync_log
            ]

    async def get_last_sync_time(self, peer_unit_id: str) -> float:
        """获取与指定对等单元的最后同步时间。"""
        async with self._lock:
            return self._peer_timestamps.get(peer_unit_id, 0.0)
