"""
单元实例 (DFUUnit) - 封装一个完整数据防御单元
包含该单元的所有Agent + 知识库，每个单元有独立的单元ID。
"""

import asyncio
import time
from typing import Any, Dict, List, Optional

from cluster.registry import ClusterRegistry
from communication.message_bus import get_message_bus
from config import Config
from knowledge.hot_store import HotKnowledgeStore
from knowledge.cold_store import ColdKnowledgeStore
from knowledge.router import KnowledgeRouter
from knowledge.sync_manager import SyncManager


class DFUUnit:
    """
    一个完整的数据防御单元，封装：
    - 分析引擎 / 响应引擎 / 校验Agent / 处置Agent 等核心Agent
    - 热库 / 冷库 / 知识库路由器 / 同步管理器
    - 独立的单元ID和状态管理

    注意：为保持阶段3原型简洁，Agent 在本阶段通过知识库交互体现，
    不与阶段1/2的完整Agent生命周期耦合。核心Agent由 DFUPrototypeRunner
    统一管理，DFUUnit 负责知识库与集群层面的抽象。
    """

    _next_id = 1

    @classmethod
    def _generate_unit_id(cls) -> str:
        unit_id = f"dfu-unit-{cls._next_id:02d}"
        cls._next_id += 1
        return unit_id

    def __init__(self, config: Config, registry: ClusterRegistry,
                 unit_id: Optional[str] = None, knowledge_dir: Optional[str] = None):
        self.config = config
        self.registry = registry
        self.unit_id = unit_id or self._generate_unit_id()
        self.bus = get_message_bus()
        self._status = "initialized"
        self._deploy_time: float = 0.0

        # 知识库组件
        store_dir = knowledge_dir or config.project_root
        self.hot_store = HotKnowledgeStore(
            max_capacity=500, unit_id=self.unit_id,
            db_path=f"{store_dir}\\logs\\hot_store_{self.unit_id}.db",
        )
        self.cold_store = ColdKnowledgeStore(
            store_path=f"{store_dir}\\logs\\cold_store_{self.unit_id}.jsonl",
            unit_id=self.unit_id,
        )
        self.router = KnowledgeRouter(self.hot_store, self.cold_store, unit_id=self.unit_id)
        self.sync_manager = SyncManager(self.unit_id)

        # 统计信息
        self.attacks_handled: int = 0
        self._lock = asyncio.Lock()

    async def deploy(self) -> None:
        """部署单元：注册到集群注册中心。"""
        await self.registry.register(
            self.unit_id,
            address=f"dfu://{self.unit_id}",
            knowledge_version=1,
        )
        self._status = "active"
        self._deploy_time = time.time()

    async def shutdown(self) -> None:
        """关闭单元：从集群注销。"""
        await self.registry.unregister(self.unit_id)
        self._status = "offline"

    async def status(self) -> Dict[str, Any]:
        """获取单元状态摘要。"""
        ks = await self.router.get_stats()
        return {
            "unit_id": self.unit_id,
            "status": self._status,
            "uptime_seconds": time.time() - self._deploy_time if self._deploy_time else 0,
            "attacks_handled": self.attacks_handled,
            "knowledge_stats": ks,
        }

    async def handle_attack(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理攻击流量：模拟双引擎查询知识库后做出决策。

        流程：
        1. 从流量数据提取特征
        2. 路由器查询知识库
        3. 返回处理结果（含知识库命中信息）
        """
        async with self._lock:
            self.attacks_handled += 1

        # 提取特征
        feature_key = self._extract_feature_key(traffic_data)

        # 知识库查询（热库→冷库→升温）
        kb_result = await self.router.query(feature_key)

        # 模拟处理延迟
        await asyncio.sleep(0.002)

        result = {
            "unit_id": self.unit_id,
            "feature": feature_key,
            "decision": "block" if kb_result is not None else "analyze",
            "knowledge_hit": kb_result is not None,
            "knowledge_source": kb_result["source"] if kb_result else "none",
            "knowledge_latency_ms": kb_result["latency_ms"] if kb_result else 0,
            "traffic_summary": {
                "source_ip": traffic_data.get("source_ip", "unknown"),
                "category": traffic_data.get("category", "unknown"),
                "severity": traffic_data.get("severity", "low"),
            },
        }

        return result

    def _extract_feature_key(self, traffic_data: Dict[str, Any]) -> str:
        """从流量数据提取特征键。"""
        category = traffic_data.get("category", "unknown")
        source_ip = traffic_data.get("source_ip", "")
        attack_type = traffic_data.get("attack_type", "")
        # 特征键格式：category:attack_type:ip_prefix
        ip_prefix = ".".join(source_ip.split(".")[:3]) if source_ip else ""
        return f"{category}:{attack_type}:{ip_prefix}"

    async def query_knowledge(self, feature_key: str) -> Optional[Dict[str, Any]]:
        """直接查询知识库（绕过 handle_attack）。"""
        return await self.router.query(feature_key)

    async def sync_from(self, peer_unit_id: str, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        从对等单元接收同步数据（push 接收方）。
        高危条目写入热库。
        """
        result = await self.sync_manager.pull(peer_unit_id)
        # 将条目写入热库
        if entries:
            await self.hot_store.update(entries)
        return result

    async def sync_to(self, peer_unit_id: str, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        向对等单元推送同步数据（push 发起方）。
        """
        return await self.sync_manager.push(peer_unit_id, entries)
