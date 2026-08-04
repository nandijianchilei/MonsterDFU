"""
向量知识存储 (VectorKnowledgeStore) - 语义向量层

基于 ChromaDB + sentence-transformers 实现语义向量检索，
作为精确匹配的 fallback 层，在 key 未命中时提供语义近似匹配。

设计原则：
- embed 方法：使用 all-MiniLM-L6-v2 生成 384 维向量
- add(feature_key, data)：将特征数据向量化后存入 ChromaDB
- search(feature_key, top_k)：语义检索，相似度 ≥ 0.7 视为命中
"""

import os
import json
from typing import Any, Dict, List, Tuple
from chromadb import PersistentClient
from chromadb.config import Settings


class VectorKnowledgeStore:
    """
    向量知识存储：语义向量检索层。

    作为精确匹配的 fallback，在 key 未命中时提供语义近似匹配。
    使用 ChromaDB 持久化存储 + all-MiniLM-L6-v2 生成向量。

    相似度阈值 0.7，低于此值视为未命中。
    """

    _EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
    _SIMILARITY_THRESHOLD = 0.7
    _COLLECTION_NAME = "knowledge_vectors"

    def __init__(self, persist_dir: str):
        """
        初始化向量存储。

        Args:
            persist_dir: ChromaDB 持久化目录路径
        """
        os.makedirs(persist_dir, exist_ok=True)

        self._persist_dir = persist_dir
        self._client = PersistentClient(path=persist_dir, settings=Settings(anonymized_telemetry=False))
        self._collection = self._client.get_or_create_collection(
            name=self._COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"}
        )
        self._embedder = None  # 延迟加载
        self._total_adds: int = 0
        self._total_searches: int = 0
        self._total_hits: int = 0

    def _get_embedder(self):
        """延迟加载 sentence-transformers 模型。"""
        if self._embedder is None:
            from sentence_transformers import SentenceTransformer
            self._embedder = SentenceTransformer(self._EMBED_MODEL_NAME)
        return self._embedder

    def embed(self, texts: List[str]) -> List[List[float]]:
        """
        使用 sentence-transformers 生成向量。

        Args:
            texts: 待编码的文本列表

        Returns:
            向量列表，每个向量为 384 维 float 列表
        """
        model = self._get_embedder()
        embeddings = model.encode(texts, normalize_embeddings=True)
        return embeddings.tolist()

    def add(self, feature_key: str, data: Dict[str, Any]) -> str:
        """
        将特征数据向量化后存入 ChromaDB。

        Args:
            feature_key: 特征键（用于生成向量的文本）
            data: 关联的特征数据，JSON 序列化后存储

        Returns:
            ChromaDB 生成的文档 ID
        """
        embedding = self.embed([feature_key])[0]
        metadata = {"feature_key": feature_key, "data_json": json.dumps(data, ensure_ascii=False)}

        # 生成唯一 ID：feature_key 的 hash + 时间戳后缀避免重复
        doc_id = str(hash(feature_key) & 0xFFFFFFFFFFFFFFFF)

        # 如果已存在则先删除再添加（upsert 语义）
        existing = self._collection.get(ids=[doc_id])
        if existing and existing["ids"]:
            self._collection.update(
                ids=[doc_id],
                embeddings=[embedding],
                metadatas=[metadata],
                documents=[feature_key]
            )
        else:
            self._collection.add(
                ids=[doc_id],
                embeddings=[embedding],
                metadatas=[metadata],
                documents=[feature_key]
            )

        self._total_adds += 1
        return doc_id

    def search(self, feature_key: str, top_k: int = 3) -> List[Tuple[float, Dict[str, Any]]]:
        """
        语义检索：在向量库中搜索与 feature_key 最相似的条目。

        Args:
            feature_key: 查询特征键
            top_k: 返回最相似的前 K 个结果

        Returns:
            [(similarity_score, data), ...] 按相似度降序排列，仅保留 ≥ 阈值的结果
        """
        self._total_searches += 1

        query_embedding = self.embed([feature_key])[0]

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            include=["metadatas", "distances"]
        )

        if not results["ids"] or not results["ids"][0]:
            return []

        output = []
        for i, doc_id in enumerate(results["ids"][0]):
            distance = results["distances"][0][i]
            # ChromaDB cosine 距离：0=完全相同，2=完全相反
            similarity = 1.0 - (distance / 2.0)
            if similarity >= self._SIMILARITY_THRESHOLD:
                metadata = results["metadatas"][0][i]
                data = json.loads(metadata["data_json"])
                output.append((similarity, data))
                self._total_hits += 1

        return output

    def get_stats(self) -> Dict[str, Any]:
        """获取向量存储统计信息。"""
        # 尝试获取 collection 大小
        try:
            count = self._collection.count()
        except Exception:
            count = 0
        return {
            "persist_dir": self._persist_dir,
            "total_adds": self._total_adds,
            "total_searches": self._total_searches,
            "total_hits": self._total_hits,
            "collection_size": count,
        }
