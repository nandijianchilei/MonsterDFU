"""
知识库路由器 (KnowledgeRouter) - 双脑查询入口
优先查热库 → 未命中查冷库 → 冷库命中后自动升温到热库
→ 仍未命中走向量语义搜索 fallback → 向量命中后升温到热库
双脑并行查询时确保同一特征不会被重复拉取
"""

import asyncio
import time
from typing import Any, Dict, Optional, TYPE_CHECKING

from knowledge.hot_store import HotKnowledgeStore
from knowledge.cold_store import ColdKnowledgeStore

if TYPE_CHECKING:
    from knowledge.vector_store import VectorKnowledgeStore


class KnowledgeRouter:
    """
    知识库路由器：统一查询入口，实现热→冷→向量→升温四级流。

    - 优先查热库（精确匹配，~0.01ms）
    - 热库未命中则查冷库（精确匹配，~5-15ms）
    - 冷库未命中且 vector_store 可用则查向量层（语义搜索，~5ms）
    - 冷库/向量命中后自动升温到热库
    - 并行查询去重锁防止重复拉取
    - 向量层为可选组件，不传时行为完全不变
    """

    def __init__(
        self,
        hot_store: HotKnowledgeStore,
        cold_store: ColdKnowledgeStore,
        unit_id: str = "",
        vector_store: "Optional[VectorKnowledgeStore]" = None,
    ):
        self.hot_store = hot_store
        self.cold_store = cold_store
        self.unit_id = unit_id
        self.vector_store = vector_store

        # 统计
        self.total_queries: int = 0
        self.promotions: int = 0
        self.vector_hits: int = 0
        self._inflight: Dict[str, asyncio.Lock] = {}
        self._inflight_lock = asyncio.Lock()

    async def query(self, feature_key: str) -> Optional[Dict[str, Any]]:
        """
        统一查询入口：热库 → 冷库 → 自动升温。

        返回命中数据，或 None（两级均未命中）。
        """
        t_start = time.monotonic()

        # 1. 查热库
        result = await self.hot_store.query(feature_key)
        if result is not None:
            elapsed_ms = (time.monotonic() - t_start) * 1000
            self.total_queries += 1
            return {"data": result, "source": "hot", "latency_ms": elapsed_ms}

        # 2. 并行去重：同一特征正在被其他查询拉取时等待
        inflight_lock = await self._get_inflight_lock(feature_key)
        async with inflight_lock:
            # 双重检查：可能在等待期间热库已被更新
            result = await self.hot_store.query(feature_key)
            if result is not None:
                elapsed_ms = (time.monotonic() - t_start) * 1000
                self.total_queries += 1
                return {"data": result, "source": "hot", "latency_ms": elapsed_ms}

            # 3. 查冷库
            result = await self.cold_store.query(feature_key)
            if result is not None:
                # 4a. 自动升温：写回热库
                await self.hot_store.update([{"key": feature_key, **result}])
                self.promotions += 1
                elapsed_ms = (time.monotonic() - t_start) * 1000
                self.total_queries += 1
                return {"data": result, "source": "cold_promoted", "latency_ms": elapsed_ms}

            # 4. 向量 fallback（可选）
            if self.vector_store is not None:
                vector_results = self.vector_store.search(feature_key, top_k=3)
                if vector_results:
                    best_score, best_data = vector_results[0]
                    # 相似度 ≥ 0.7 视为命中
                    if best_score >= 0.7:
                        await self.hot_store.update([{"key": feature_key, **best_data}])
                        self.promotions += 1
                        self.vector_hits += 1
                        elapsed_ms = (time.monotonic() - t_start) * 1000
                        self.total_queries += 1
                        return {
                            "data": best_data,
                            "source": "vector_promoted",
                            "similarity": best_score,
                            "latency_ms": elapsed_ms,
                        }

        elapsed_ms = (time.monotonic() - t_start) * 1000
        self.total_queries += 1
        return None

    async def _get_inflight_lock(self, feature_key: str) -> asyncio.Lock:
        """获取并行去重锁。"""
        async with self._inflight_lock:
            if feature_key not in self._inflight:
                self._inflight[feature_key] = asyncio.Lock()
            return self._inflight[feature_key]

    async def get_stats(self) -> Dict[str, Any]:
        """获取路由器统计信息。"""
        hot_stats = await self.hot_store.get_stats()
        cold_stats = await self.cold_store.get_stats()
        stats = {
            "unit_id": self.unit_id,
            "total_queries": self.total_queries,
            "promotions": self.promotions,
            "vector_hits": self.vector_hits,
            "hot_hit_rate": hot_stats["hit_rate"],
            "cold_hit_rate": cold_stats["hit_rate"],
            "hot_size": hot_stats["size"],
            "cold_size": cold_stats["size"],
        }
        if self.vector_store is not None:
            stats["vector_stats"] = self.vector_store.get_stats()
        return stats
