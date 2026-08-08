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
from knowledge.vector_store import VectorKnowledgeStore, CHROMADB_AVAILABLE
from knowledge.router import KnowledgeRouter
from knowledge.sync_manager import SyncManager

# chromadb 为可选依赖（pip install .[ml]）；vector_store 模块内部已做降级，
# 此处基于其 CHROMADB_AVAILABLE 暴露可用性标志，未安装时仅无法实例化，不影响导入。
VECTOR_STORE_AVAILABLE = CHROMADB_AVAILABLE

__all__ = [
    "HotKnowledgeStore",
    "ColdKnowledgeStore",
    "VectorKnowledgeStore",
    "KnowledgeRouter",
    "SyncManager",
    "VECTOR_STORE_AVAILABLE",
]
