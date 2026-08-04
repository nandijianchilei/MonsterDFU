"""
事件聚合器 (Event Aggregator)
=======================
感知层与双脑之间的时间窗口聚合模块。

原理：
- 订阅规则引擎前置分流转发的 `unhandled_threat` 消息（规则未命中的告警）
- 按 (源IP + 类别) 键在时间窗口内聚合告警
- 窗口期满时发布 `merged_threat_alert` 供双脑处理
- 单告警立即透传(无延迟)，多告警窗口合并

问题解决：
  当前 DDoS 450 个包 → 450 条独立 threat_alert → 双脑被淹死
  聚合后 → 1 条 merged_threat_alert → 双脑一次完整分析
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from communication.message_bus import Message, MessageBus, get_message_bus
from config import EventAggregatorConfig
from utils.logger import get_logger


@dataclass
class AggregationWindow:
    """单个聚合窗口：维护一个 (IP, 类别) 键下的所有告警。"""

    key: str          # f"{source_ip}:{category}"
    source_ip: str
    category: str
    config: EventAggregatorConfig
    created_at: float = field(default_factory=lambda: __import__("time").monotonic())

    # 聚合数据
    _alerts: List[Dict[str, Any]] = field(default_factory=list)
    _severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "low": 0, "medium": 0, "high": 0, "severe": 0,
    })
    _total_packets: int = 0
    _peak_rate: float = 0.0
    _first_seen: Optional[str] = None
    _last_seen: Optional[str] = None
    _target_ips: Set[str] = field(default_factory=set)
    _target_ports: Set[int] = field(default_factory=set)

    # 当前聚合级别（按告警数量加权）
    _severity_order = {"low": 0, "medium": 1, "high": 2, "severe": 3}

    @property
    def event_count(self) -> int:
        return len(self._alerts)

    @property
    def peak_severity(self) -> str:
        """返回窗口内最高严重级别。"""
        best = "low"
        best_order = 0
        for sev, count in self._severity_counts.items():
            if count > 0 and self._severity_order[sev] > best_order:
                best = sev
                best_order = self._severity_order[sev]
        return best

    def add(self, alert: Dict[str, Any]) -> None:
        """将一条告警加入窗口。"""
        self._alerts.append(alert)
        severity = alert.get("severity", "low")
        self._severity_counts[severity] = self._severity_counts.get(severity, 0) + 1

        raw = alert.get("raw_data", {})
        self._total_packets += raw.get("request_count", raw.get("attempts", 1))
        rate = raw.get("requests_per_second", raw.get("rate", 0))
        if rate > self._peak_rate:
            self._peak_rate = rate

        now = datetime.now().isoformat()
        if self._first_seen is None:
            self._first_seen = now
        self._last_seen = now

        target_ip = alert.get("target_ip")
        if target_ip:
            self._target_ips.add(target_ip)
        target_port = alert.get("target_port")
        if target_port:
            self._target_ports.add(target_port)

        # 限制原始详情条数
        detail_limit = self.config.max_indicators_detail
        if len(self._alerts) > detail_limit:
            keep_half = detail_limit // 2
            self._alerts = (
                self._alerts[:keep_half] + self._alerts[-keep_half:]
            )

    def build_merged_alert(self) -> Optional[Dict[str, Any]]:
        """构建聚合后的告警。若无告警返回 None。"""
        if not self._alerts:
            return None

        return {
            "alert_id": self._key_to_alert_id(),
            "aggregated": True,
            "event_count": len(self._alerts),
            "window_ms": self.config.window_ms,
            "source_ip": self.source_ip,
            "category": self.category,
            "severity": self.peak_severity,
            "target_ips": sorted(self._target_ips),
            "target_ports": sorted(self._target_ports),
            "indicators": self._alerts,
            "summary": {
                "first_seen": self._first_seen,
                "last_seen": self._last_seen,
                "total_packets": self._total_packets,
                "peak_rate": self._peak_rate,
                "severity_breakdown": self._severity_counts,
            },
        }

    def _key_to_alert_id(self) -> str:
        """生成聚合告警 ID。"""
        import hashlib
        import time as _time
        payload = f"{self.key}:{self._total_packets}:{int(_time.time())}"
        return f"merged_{hashlib.md5(payload.encode()).hexdigest()[:12]}"


class EventAggregator:
    """
    事件聚合器：感知层与双脑之间的时间窗口聚合中间件。

    生命周期：
      start() → 订阅 threat_alert 主题
      stop()  → 取消订阅，flush 所有未到期窗口

    聚合策略：
      - 同(源IP, 类别)告警进入同一窗口
      - 窗口期满(默认2s)发布 merged_threat_alert
      - 单告警立即透传(不等待窗口期满)
      - 最多等待 idle_timeout_ms(5s) 防止永久搁置
    """

    def __init__(self, config: EventAggregatorConfig):
        """
        Args:
            config: 聚合器配置
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.logger: logging.Logger = get_logger("EventAggregator")

        # key → AggregationWindow 映射
        self._windows: Dict[str, AggregationWindow] = {}
        # key → asyncio.Task(flush 定时器)
        self._timers: Dict[str, asyncio.Task] = {}
        # key → 窗口创建时间戳
        self._window_started: Dict[str, float] = {}

        self._running = False

        # 统计
        self._stats = {
            "total_received": 0,
            "total_merged": 0,
            "total_flushed": 0,
        }

    # ==================== 生命周期 ====================

    async def start(self) -> None:
        """启动聚合器，订阅规则引擎前置分流转发的未处理告警。"""
        self._running = True
        await self.bus.subscribe("unhandled_threat", self._on_threat_alert)
        self.logger.info(
            f"事件聚合器已启动 | 窗口={self.config.window_ms}ms | "
            f"最大等待={self.config.idle_timeout_ms}ms"
        )

    async def stop(self) -> None:
        """停止聚合器，flush 所有未到期窗口。"""
        self._running = False
        # 取消所有未完成定时器
        for task in self._timers.values():
            task.cancel()
        self._timers.clear()

        # 立即 flush 所有窗口
        pending = list(self._windows.keys())
        for key in pending:
            await self._flush(key, reason="aggregator stop")
        self._windows.clear()
        self._window_started.clear()

        self.logger.info(
            f"事件聚合器已停止 | 收:{self._stats['total_received']} | "
            f"合:{self._stats['total_merged']} | 发:{self._stats['total_flushed']}"
        )

    # ==================== 消息处理 ====================

    async def _on_threat_alert(self, msg: Message) -> None:
        """接收 threat_alert 消息，入窗口聚合。"""
        if not self._running:
            return

        payload = msg.payload
        if not isinstance(payload, dict):
            return

        self._stats["total_received"] += 1
        key = self._make_key(payload)

        if key not in self._windows:
            self._windows[key] = AggregationWindow(
                key=key,
                source_ip=payload.get("source_ip", "unknown"),
                category=payload.get("category", "unknown"),
                config=self.config,
            )
            self._window_started[key] = __import__("time").monotonic()

        window = self._windows[key]
        window.add(payload)

        if window.event_count == 1:
            await self._flush(key, reason="single alert")
        elif window.event_count == 2:
            self._schedule_flush(key)

        if len(self._windows) > self.config.max_concurrent_windows:
            oldest_key = min(self._windows, key=lambda k: self._window_started.get(k, 0))
            self.logger.warning(f"窗口溢出，强制 flush: {oldest_key}")
            await self._flush(oldest_key, reason="overflow")

        # 防无限等待：idle_timeout 超时强制 flush
        now = __import__("time").monotonic()
        for k in list(self._window_started.keys()):
            if k in self._windows and (now - self._window_started[k]) > (
                self.config.idle_timeout_ms / 1000
            ):
                await self._flush(k, reason="idle timeout")

    def _schedule_flush(self, key: str) -> None:
        """安排窗口到期 flush。"""
        if key in self._timers:
            return  # 已有定时器

        async def _delayed_flush():
            delay = self.config.window_ms / 1000
            await asyncio.sleep(delay)
            if key in self._windows:
                await self._flush(key, reason="window expiry")

        self._timers[key] = asyncio.create_task(_delayed_flush())

    async def _flush(self, key: str, reason: str = "") -> None:
        """将窗口内容构建为 merged_threat_alert 并发布。"""
        window = self._windows.pop(key, None)
        if window is None:
            return

        self._timers.pop(key, None)
        self._window_started.pop(key, None)

        merged = window.build_merged_alert()
        if merged is None:
            return

        self._stats["total_merged"] += 1
        self._stats["total_flushed"] += 1

        msg = Message(
            source="EventAggregator",
            target="*",
            type="merged_threat_alert",
            payload=merged,
        )
        await self.bus.publish(msg)
        self.logger.debug(
            f"窗口 flush ({reason}): {key} | {window.event_count}条→1 聚合 "
            f"| severity={merged['severity']} | packets={merged['summary']['total_packets']}"
        )

    # ==================== 辅助方法 ====================

    @staticmethod
    def _make_key(payload: dict) -> str:
        """生成聚合键: f"{source_ip}:{category}"。"""
        source_ip = payload.get("source_ip", "unknown")
        category = payload.get("category", "unknown")
        return f"{source_ip}:{category}"

    @property
    def windows_count(self) -> int:
        return len(self._windows)

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    @property
    def active_keys(self) -> List[str]:
        return list(self._windows.keys())
