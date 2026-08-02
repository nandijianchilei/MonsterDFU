"""
冷库 (ColdKnowledgeStore) - 模拟分布式冷库（文件持久化）
存储低频、跨区域新型威胁数据。
"""

import asyncio
import json
import os
import random
import time
from datetime import datetime
from typing import Any, Dict, List, Optional


class ColdKnowledgeStore:
    """
    冷库：基于 JSONL 文件持久化的低频知识存储。

    - 查询模拟 5-15ms 延迟
    - 支持归档（热库淘汰条目写入冷库）
    - 支持升温（高频命中条目提升回热库）
    """

    def __init__(self, store_path: str, unit_id: str = ""):
        self.store_path = store_path
        self.unit_id = unit_id
        self._lock = asyncio.Lock()

        # 统计
        self.total_queries: int = 0
        self.total_hits: int = 0
        self.total_archives: int = 0

        # 命中计数（用于升温判断）
        self._hit_counts: Dict[str, int] = {}

        # 确保上级目录存在
        os.makedirs(os.path.dirname(store_path), exist_ok=True)

        # 首次加载已有数据
        self._ensure_file()

    @property
    def hit_rate(self) -> float:
        if self.total_queries == 0:
            return 0.0
        return self.total_hits / self.total_queries

    def _ensure_file(self) -> None:
        """确保存储文件存在。"""
        if not os.path.exists(self.store_path):
            with open(self.store_path, "w", encoding="utf-8") as f:
                f.write("")

    async def query(self, feature_key: str) -> Optional[Dict[str, Any]]:
        """
        查询冷库特征，模拟 5-15ms 分布式延迟。
        命中返回规则数据，未命中返回 None。
        自动记录命中计数。
        """
        latency = random.uniform(0.005, 0.015)
        await asyncio.sleep(latency)

        async with self._lock:
            self.total_queries += 1

            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if entry.get("key") == feature_key:
                            entry.pop("key", None)
                            entry["_source"] = "cold"
                            self.total_hits += 1
                            self._hit_counts[feature_key] = self._hit_counts.get(feature_key, 0) + 1
                            return entry
            except FileNotFoundError:
                pass

        return None

    async def archive(self, entries: List[Dict[str, Any]]) -> int:
        """
        归档数据到冷库（从热库淘汰或主动写入）。
        每个条目需包含 'key' 字段。
        返回成功写入数。
        """
        async with self._lock:
            count = 0
            now_ts = time.time()
            with open(self.store_path, "a", encoding="utf-8") as f:
                for entry in entries:
                    key = entry.get("key")
                    if not key:
                        continue
                    record = {"key": key, **{k: v for k, v in entry.items() if k != "key"},
                              "_archived_at": datetime.now().isoformat(), "_archived_ts": now_ts}
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    count += 1
            self.total_archives += count
            return count

    async def promote(self, feature_key: str) -> Optional[Dict[str, Any]]:
        """
        升温操作：将冷库中某条目标记为高频命中，并从冷库中移除（交给调用方写回热库）。
        返回该条目数据，调用方应将其写入热库并从冷库物理删除。
        """
        async with self._lock:
            entry_data = None
            remaining_lines = []

            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            remaining_lines.append(line)
                            continue
                        if entry.get("key") == feature_key:
                            entry.pop("key", None)
                            entry["_source"] = "cold_promoted"
                            entry_data = entry
                        else:
                            remaining_lines.append(json.dumps(entry, ensure_ascii=False))
            except FileNotFoundError:
                pass

            if entry_data is not None:
                # 写回冷库（移除升温条目）
                with open(self.store_path, "w", encoding="utf-8") as f:
                    for rl in remaining_lines:
                        f.write(rl + "\n")
                self._hit_counts.pop(feature_key, None)

            return entry_data

    async def get_hit_counts(self, threshold: int = 3) -> List[str]:
        """
        返回命中次数超过阈值的特征键（用于判断是否需要升温）。
        """
        async with self._lock:
            return [k for k, v in self._hit_counts.items() if v >= threshold]

    async def get_stats(self) -> Dict[str, Any]:
        """获取冷库统计信息。"""
        async with self._lock:
            entry_count = 0
            try:
                with open(self.store_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            entry_count += 1
            except FileNotFoundError:
                pass
            return {
                "unit_id": self.unit_id,
                "store_path": self.store_path,
                "size": entry_count,
                "total_queries": self.total_queries,
                "total_hits": self.total_hits,
                "hit_rate": self.hit_rate,
                "total_archives": self.total_archives,
            }
