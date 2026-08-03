"""
热库 (HotKnowledgeStore) - 基于 SQLite 持久化的 LRU 缓存
存储高频攻击特征、常用防御规则，每个数据防御单元持有一份本地热库副本。

从 OrderDict 内存缓存改造为 SQLite 持久化存储：
- 进程/容器重启后数据不丢失
- LRU 淘汰基于 last_hit 时间戳排序
- 接口签名和行为与原实现完全兼容
"""

import os
import time
import asyncio
import json
from typing import Any, Dict, List, Optional

import aiosqlite


class HotKnowledgeStore:
    """
    热库：基于 SQLite 的持久化 LRU 缓存。

    - 最大容量 500 条
    - 自动 LRU 淘汰（按 last_hit 排序）
    - 命中率统计（会话级，重启清零）
    - 支持增量更新和归档
    - 每个 DFU 单元通过 unit_id 隔离数据
    """

    def __init__(self, max_capacity: int = 500, unit_id: str = "", db_path: str = ""):
        self.max_capacity = max_capacity
        self.unit_id = unit_id
        self._lock = asyncio.Lock()
        self._db_path = db_path or "dfu_hot_store.db"
        self._conn: Optional[aiosqlite.Connection] = None
        self._initialized = False
        self._cached_size: int = 0

        # 统计（会话级，重启清零 — 与旧版行为一致）
        self.total_queries: int = 0
        self.total_hits: int = 0

    # ── 延迟初始化 ──

    async def _ensure_db(self) -> None:
        """延迟初始化数据库连接和表结构（首次操作时触发）。"""
        if self._initialized:
            return
        async with self._lock:
            if self._initialized:
                return
            db_dir = os.path.dirname(self._db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            self._conn = await aiosqlite.connect(self._db_path)
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("""
                CREATE TABLE IF NOT EXISTS hot_store (
                    key         TEXT PRIMARY KEY,
                    data        TEXT NOT NULL,
                    last_hit    REAL NOT NULL,
                    hit_count   INTEGER DEFAULT 0,
                    created_at  REAL NOT NULL,
                    unit_id     TEXT DEFAULT ''
                )
            """)
            await self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hot_store_last_hit
                ON hot_store(last_hit)
            """)
            await self._conn.commit()

            # 加载当前单元的条目数
            cursor = await self._conn.execute(
                "SELECT COUNT(*) as cnt FROM hot_store WHERE unit_id = ?",
                (self.unit_id,),
            )
            row = await cursor.fetchone()
            await cursor.close()
            self._cached_size = row["cnt"] if row else 0
            self._initialized = True

    # ── 属性 ──

    @property
    def hit_rate(self) -> float:
        if self.total_queries == 0:
            return 0.0
        return self.total_hits / self.total_queries

    @property
    def size(self) -> int:
        return self._cached_size

    # ── 核心接口 ──

    async def query(self, feature_key: str) -> Optional[Dict[str, Any]]:
        """
        查询热库特征，命中返回规则数据，未命中返回 None。
        自动更新 last_hit 和命中统计。
        """
        await self._ensure_db()
        async with self._lock:
            self.total_queries += 1
            cursor = await self._conn.execute(
                "SELECT data FROM hot_store WHERE key = ? AND unit_id = ?",
                (feature_key, self.unit_id),
            )
            row = await cursor.fetchone()
            await cursor.close()

            if row is None:
                return None

            now = time.monotonic()
            await self._conn.execute(
                "UPDATE hot_store SET last_hit = ?, hit_count = hit_count + 1 WHERE key = ? AND unit_id = ?",
                (now, feature_key, self.unit_id),
            )
            await self._conn.commit()
            self.total_hits += 1
            return json.loads(row["data"])

    async def update(self, entries: List[Dict[str, Any]]) -> int:
        """
        增量更新热库。每个条目需包含 'key' 字段作为唯一标识。
        已存在的 key 会合并 data；新 key 会插入。
        超出 max_capacity 时自动 LRU 淘汰。
        返回实际新增的条目数。
        """
        await self._ensure_db()
        async with self._lock:
            count = 0
            now = time.monotonic()
            for entry_data in entries:
                key = entry_data.get("key")
                if not key:
                    continue
                data = {k: v for k, v in entry_data.items() if k != "key"}
                data_json = json.dumps(data, ensure_ascii=False)

                # 检查是否已存在
                cursor = await self._conn.execute(
                    "SELECT data FROM hot_store WHERE key = ? AND unit_id = ?",
                    (key, self.unit_id),
                )
                existing = await cursor.fetchone()
                await cursor.close()

                if existing:
                    # 合并更新
                    existing_data = json.loads(existing["data"])
                    existing_data.update(data)
                    merged_json = json.dumps(existing_data, ensure_ascii=False)
                    await self._conn.execute(
                        "UPDATE hot_store SET data = ?, last_hit = ? WHERE key = ? AND unit_id = ?",
                        (merged_json, now, key, self.unit_id),
                    )
                else:
                    # 新增
                    await self._conn.execute(
                        "INSERT INTO hot_store (key, data, last_hit, hit_count, created_at, unit_id) "
                        "VALUES (?, ?, ?, 0, ?, ?)",
                        (key, data_json, now, now, self.unit_id),
                    )
                    count += 1
                    self._cached_size += 1

            await self._conn.commit()

            # LRU 淘汰：超出容量时删除最久未命中的条目
            if self._cached_size > self.max_capacity:
                overflow = self._cached_size - self.max_capacity
                cursor = await self._conn.execute(
                    "SELECT key FROM hot_store WHERE unit_id = ? ORDER BY last_hit ASC LIMIT ?",
                    (self.unit_id, overflow),
                )
                rows = await cursor.fetchall()
                await cursor.close()
                for r in rows:
                    await self._conn.execute(
                        "DELETE FROM hot_store WHERE key = ? AND unit_id = ?",
                        (r["key"], self.unit_id),
                    )
                    self._cached_size -= 1
                await self._conn.commit()

            return count

    async def evict_lru(self) -> List[Dict[str, Any]]:
        """
        手动淘汰最久未命中的条目，返回被淘汰条目列表（供冷库归档）。
        淘汰数量 = 当前条目数 - max_capacity（仅在超出时执行）。
        """
        await self._ensure_db()
        async with self._lock:
            overflow = self._cached_size - self.max_capacity
            if overflow <= 0:
                return []

            cursor = await self._conn.execute(
                "SELECT key, data, hit_count FROM hot_store WHERE unit_id = ? "
                "ORDER BY last_hit ASC LIMIT ?",
                (self.unit_id, overflow),
            )
            rows = await cursor.fetchall()
            await cursor.close()

            evicted = []
            for r in rows:
                evicted.append({
                    "key": r["key"],
                    **json.loads(r["data"]),
                    "_hit_count": r["hit_count"],
                })
                await self._conn.execute(
                    "DELETE FROM hot_store WHERE key = ? AND unit_id = ?",
                    (r["key"], self.unit_id),
                )
                self._cached_size -= 1
            await self._conn.commit()
            return evicted

    async def get_stats(self) -> Dict[str, Any]:
        """获取热库统计信息。"""
        await self._ensure_db()
        async with self._lock:
            return {
                "unit_id": self.unit_id,
                "size": self._cached_size,
                "max_capacity": self.max_capacity,
                "total_queries": self.total_queries,
                "total_hits": self.total_hits,
                "hit_rate": self.hit_rate,
            }

    async def keys(self) -> List[str]:
        """返回当前所有 key。"""
        await self._ensure_db()
        async with self._lock:
            cursor = await self._conn.execute(
                "SELECT key FROM hot_store WHERE unit_id = ?",
                (self.unit_id,),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            return [r["key"] for r in rows]

    # ── 生命周期 ──

    async def close(self) -> None:
        """关闭数据库连接。"""
        async with self._lock:
            if self._conn:
                await self._conn.close()
                self._conn = None
                self._initialized = False
                self._cached_size = 0
