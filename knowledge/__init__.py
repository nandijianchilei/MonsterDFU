"""
knowledge/ - 冷热分层知识库模块

包含：
- HotKnowledgeStore：热库（LRU 内存缓存）
- ColdKnowledgeStore：冷库（文件持久化）
- VectorKnowledgeStore：向量存储（ChromaDB 语义检索）
- KnowledgeRouter：知识库路由器（热→冷→向量→升温）
- SyncManager：增量同步管理器
"""

from knowledge.hot_store import HotKnowledgeStore
from knowledge.cold_store import ColdKnowledgeStore
from knowledge.vector_store import VectorKnowledgeStore
from knowledge.router import KnowledgeRouter
from knowledge.sync_manager import SyncManager

__all__ = [
    "HotKnowledgeStore",
    "ColdKnowledgeStore",
    "VectorKnowledgeStore",
    "KnowledgeRouter",
    "SyncManager",
]
