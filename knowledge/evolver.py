"""
知识库自进化引擎 (Knowledge Evolver)
- 监听 EventAggregator 输出的威胁事件
- 对高频攻击模式聚类
- 自动生成防御规则和 LLM prompt snippet
- 写入冷热知识库（与现有 KnowledgeRouter 接口对齐）
"""

import asyncio, json, time, hashlib, logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from datetime import datetime

from communication.message_bus import Message, get_message_bus
from knowledge.hot_store import HotKnowledgeStore
from knowledge.cold_store import ColdKnowledgeStore
from knowledge.router import KnowledgeRouter
from config import Config

logger = logging.getLogger("Evolver")

@dataclass
class AttackPattern:
    """攻击模式聚合"""
    pattern_id: str
    category: str           # ddos / brute_force / port_scan / beacon / exfil / domain
    signature: str          # 攻击指纹（向量化可搜索）
    source_ips: Set[str] = field(default_factory=set)
    target_ports: List[int] = field(default_factory=list)
    hit_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    severity_peak: str = "low"
    generated_rules: List[str] = field(default_factory=list)
    defense_snippet: str = ""

@dataclass
class EvolverConfig:
    min_pattern_hits: int = 5           # 最少命中次数才触发进化
    pattern_window_seconds: int = 300   # 模式识别窗口
    max_hot_patterns: int = 50          # 热模式上限
    hot_ttl_seconds: int = 3600         # 热模式存活时间

class KnowledgeEvolver:
    """
    知识库自进化引擎：
    - 订阅 merged_threat_alert（来自 EventAggregator）
    - 按 (category, severity) 聚类攻击模式
    - 达到阈值后生成防御规则 → 写入知识库
    """

    def __init__(
        self,
        config: Config,
        evolver_config: Optional[EvolverConfig] = None,
        hot_store: Optional[HotKnowledgeStore] = None,
        cold_store: Optional[ColdKnowledgeStore] = None,
        router: Optional[KnowledgeRouter] = None,
    ):
        self.config = config
        self.ec = evolver_config or EvolverConfig()
        self.bus = get_message_bus()

        # 允许外部注入或自动构建
        if router is not None:
            self.router = router
            self._hot_store = hot_store
            self._cold_store = cold_store
        else:
            self._hot_store = hot_store or HotKnowledgeStore(
                max_capacity=config.stage3.hot_store_max_capacity,
                db_path=config.project_root + "/data/hot_store.db",
            )
            self._cold_store = cold_store or ColdKnowledgeStore(
                store_path=config.project_root + "/data/cold_store.jsonl",
            )
            self.router = KnowledgeRouter(
                hot_store=self._hot_store,
                cold_store=self._cold_store,
                unit_id="evolver",
            )

        self._patterns: Dict[str, AttackPattern] = {}
        self._recent: Dict[str, List[float]] = defaultdict(list)  # pattern_hash → timestamps
        self._rule_cache: Set[str] = set()  # 已生成规则去重
        self._running = False
        self.stats = {"patterns_discovered": 0, "rules_generated": 0, "snippets_generated": 0}

    async def start(self):
        self._running = True
        await self.bus.subscribe("merged_threat_alert", self._on_threat)
        asyncio.create_task(self._decay_loop())
        asyncio.create_task(self._hot_sync_loop())
        logger.info("知识库自进化引擎已启动")

    async def stop(self):
        self._running = False

    async def _on_threat(self, msg: Message):
        """处理威胁事件，提取模式并聚类。"""
        payload = msg.payload
        indicator = payload.get("indicator", {})
        category = payload.get("category", "unknown")
        severity = payload.get("severity", "medium")
        source_ip = indicator.get("source_ip", "unknown")
        dst_ip = indicator.get("dst_ip", "")

        # 计算模式指纹
        pattern_hash = self._make_pattern_hash(category, severity, dst_ip or source_ip)

        # 窗口内命中计数
        now = time.time()
        self._recent[pattern_hash] = [t for t in self._recent[pattern_hash] if now - t < self.ec.pattern_window_seconds]
        self._recent[pattern_hash].append(now)

        hit_count = len(self._recent[pattern_hash])
        if hit_count < self.ec.min_pattern_hits:
            return

        # 创建或更新攻击模式
        if pattern_hash not in self._patterns:
            pattern = AttackPattern(
                pattern_id=pattern_hash[:16],
                category=category,
                signature=f"{category}:{severity}:{dst_ip or source_ip[:16]}",
                first_seen=now,
            )
            self._patterns[pattern_hash] = pattern
            self.stats["patterns_discovered"] += 1

        pattern = self._patterns[pattern_hash]
        pattern.hit_count = hit_count
        pattern.last_seen = now
        pattern.source_ips.add(source_ip)
        if indicator.get("dst_port"):
            pattern.target_ports.append(indicator["dst_port"])
        if self._severity_order(severity) > self._severity_order(pattern.severity_peak):
            pattern.severity_peak = severity

        # 达到生成阈值 → 产规则
        rule_threshold = self.ec.min_pattern_hits * 2
        if hit_count >= rule_threshold and len(pattern.generated_rules) == 0:
            await self._generate_defense(pattern)

    async def _generate_defense(self, pattern: AttackPattern):
        """为攻击模式生成防御规则和 prompt snippet。"""
        rule_id = f"evolved_{pattern.pattern_id}_{int(time.time())}"
        if rule_id in self._rule_cache:
            return
        self._rule_cache.add(rule_id)

        # 1. 生成 iptables / rate-limit 规则
        rule_lines = []
        for ip in pattern.source_ips:
            rule_lines.append(f"# Evolved rule {rule_id}: block {ip} ({pattern.category})")
            rule_lines.append(f"iptables -A INPUT -s {ip} -j DROP")
        rule_text = "\n".join(rule_lines)
        pattern.generated_rules.append(rule_text)
        self.stats["rules_generated"] += 1

        # 2. 生成防御经验 snippet（供 LLM 参考）
        snippet = (
            f"[DFU知识库-自进化] 攻击模式: {pattern.category} | "
            f"峰值严重度: {pattern.severity_peak} | "
            f"命中 {pattern.hit_count} 次 | "
            f"源IP: {', '.join(list(pattern.source_ips)[:5])} | "
            f"建议: 启用 {pattern.category} 专项规则 + "
            f"{'速率限制' if pattern.category in ('ddos','brute_force') else 'IP黑名单'}"
        )
        pattern.defense_snippet = snippet
        self.stats["snippets_generated"] += 1

        # 3. 写入知识库（冷库持久化 + 热库缓存）
        entry = {
            "key": f"evolved:{pattern.category}:{pattern.pattern_id}",
            "category": pattern.category,
            "severity_peak": pattern.severity_peak,
            "hit_count": pattern.hit_count,
            "source_ips": list(pattern.source_ips),
            "rules": pattern.generated_rules,
            "snippet": snippet,
            "discovered_at": datetime.now().isoformat(),
        }
        # 写入冷库（文件持久化）
        await self._cold_store.archive([entry])
        # 同时预热到热库（LRU 缓存）
        await self._hot_store.update([entry])

        logger.info(f"[Evolver] 生成防御规则: {rule_id} | 类别={pattern.category} | IP数={len(pattern.source_ips)}")

    async def _decay_loop(self):
        """定期清理过期模式。"""
        while self._running:
            await asyncio.sleep(120)
            now = time.time()
            expired = [
                ph for ph, pattern in self._patterns.items()
                if now - pattern.last_seen > self.ec.hot_ttl_seconds
            ]
            for ph in expired:
                del self._patterns[ph]
                del self._recent[ph]
            if len(self._patterns) > self.ec.max_hot_patterns:
                sorted_patterns = sorted(self._patterns.items(), key=lambda x: x[1].hit_count, reverse=True)
                self._patterns = dict(sorted_patterns[:self.ec.max_hot_patterns])

    async def _hot_sync_loop(self):
        """定期同步热模式到 hot_store。"""
        while self._running:
            await asyncio.sleep(60)
            entries = []
            for pattern in self._patterns.values():
                entries.append({
                    "key": f"active:{pattern.category}:{pattern.pattern_id}",
                    "category": pattern.category,
                    "hit_count": pattern.hit_count,
                    "severity_peak": pattern.severity_peak,
                    "last_seen": pattern.last_seen,
                })
            if entries:
                await self._hot_store.update(entries)

    def get_patterns(self) -> List[dict]:
        return [
            {
                "pattern_id": p.pattern_id,
                "category": p.category,
                "hit_count": p.hit_count,
                "severity_peak": p.severity_peak,
                "source_ips": list(p.source_ips)[:10],
                "rules_count": len(p.generated_rules),
            }
            for p in self._patterns.values()
        ]

    def get_stats(self) -> dict:
        return {**self.stats, "active_patterns": len(self._patterns)}

    @staticmethod
    def _make_pattern_hash(category: str, severity: str, target: str) -> str:
        return hashlib.md5(f"{category}:{severity}:{target}".encode()).hexdigest()

    @staticmethod
    def _severity_order(sev: str) -> int:
        return {"low": 0, "medium": 1, "high": 2, "severe": 3}.get(sev, 0)
