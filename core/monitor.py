"""
监控指标采集器 — MetricsCollector 单例

采集系统资源、LLM 调用、知识库命中率、签名引擎命中率、感知模块吞吐量，
线程安全，支持 JSON 导出和 SSE 推送。

用法:
    from core.monitor import get_metrics_collector
    mc = get_metrics_collector()
    mc.record_llm_call(success=True, latency_ms=850)
    mc.update_system_metrics()
    data = mc.get_metrics()
"""

import logging
import threading
from typing import Dict

from utils.logger import get_logger


class MetricsCollector:
    """
    指标采集器单例。
    所有指标更新由 threading.Lock 保护。
    """

    _instance: "MetricsCollector" = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "MetricsCollector":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        self.logger: logging.Logger = get_logger("MetricsCollector")
        self._data_lock: threading.Lock = threading.Lock()

        # 系统资源
        self._cpu_percent: float = -1.0
        self._memory_percent: float = -1.0
        self._psutil_available: bool = False
        try:
            import psutil
            self._psutil = psutil
            self._psutil_available = True
            self.logger.info("[Monitor] psutil 可用，将采集 CPU/内存指标")
        except ImportError:
            self.logger.warning("[Monitor] psutil 未安装，CPU/内存指标返回 -1")
            self._psutil_available = False

        # LLM 调用
        self._llm_calls: int = 0
        self._llm_success: int = 0
        self._llm_failed: int = 0
        self._llm_latency_samples: list = []  # 最近 100 条延迟 (ms)

        # 知识库命中
        self._kb_hits: int = 0
        self._kb_misses: int = 0

        # 签名引擎命中
        self._sig_hits: int = 0

        # 各感知模块吞吐量
        self._org_throughput: Dict[str, int] = {
            "traffic": 0,
            "vuln_scan": 0,
            "log_audit": 0,
            "compute": 0,
            "trace": 0,
            "ip_isolation": 0,
        }

    # ── 系统指标 ──

    def update_system_metrics(self) -> None:
        """采集 CPU 与内存使用率（应从后台定时器周期性调用）。"""
        if not self._psutil_available:
            return
        try:
            self._cpu_percent = self._psutil.cpu_percent(interval=0.1)
            self._memory_percent = self._psutil.virtual_memory().percent
        except Exception as e:
            self.logger.debug(f"采集系统指标失败: {e}")

    # ── LLM 调用 ──

    def record_llm_call(self, success: bool, latency_ms: float = 0.0) -> None:
        """记录一次 LLM 调用。"""
        with self._data_lock:
            self._llm_calls += 1
            if success:
                self._llm_success += 1
            else:
                self._llm_failed += 1
            if latency_ms > 0:
                self._llm_latency_samples.append(latency_ms)
                if len(self._llm_latency_samples) > 100:
                    self._llm_latency_samples = self._llm_latency_samples[-100:]

    def sync_llm_stats(self, call_count: int, fail_count: int) -> None:
        """从外部 LLMClient 同步累计统计。"""
        with self._data_lock:
            self._llm_calls = call_count
            self._llm_failed = fail_count
            self._llm_success = call_count - fail_count

    # ── 知识库 ──

    def record_kb_hit(self) -> None:
        with self._data_lock:
            self._kb_hits += 1

    def record_kb_miss(self) -> None:
        with self._data_lock:
            self._kb_misses += 1

    # ── 签名引擎 ──

    def record_sig_hit(self) -> None:
        """记录一次签名引擎命中。"""
        with self._data_lock:
            self._sig_hits += 1

    # ── 感知模块吞吐 ──

    def record_organ(self, organ_name: str) -> None:
        """记录某感知模块的一次处理。"""
        with self._data_lock:
            if organ_name in self._org_throughput:
                self._org_throughput[organ_name] += 1

    # ── 导出 ──

    def get_metrics(self) -> dict:
        """返回当前全部指标的 JSON 友好字典。"""
        with self._data_lock:
            total_kb = self._kb_hits + self._kb_misses
            hit_rate = (
                round(self._kb_hits / total_kb * 100, 1)
                if total_kb > 0
                else 0.0
            )
            latencies = self._llm_latency_samples
            avg_lat = (
                round(sum(latencies) / len(latencies), 1)
                if latencies
                else 0.0
            )

            return {
                "cpu_percent": round(self._cpu_percent, 1),
                "memory_percent": round(self._memory_percent, 1),
                "llm_calls": self._llm_calls,
                "llm_success": self._llm_success,
                "llm_failed": self._llm_failed,
                "llm_avg_latency_ms": avg_lat,
                "kb_hits": self._kb_hits,
                "kb_misses": self._kb_misses,
                "kb_hit_rate": hit_rate,
                "sig_hits": self._sig_hits,
                "org_throughput": dict(self._org_throughput),
            }

    def get_latency_samples(self) -> list:
        """返回最近延迟样本（供前端画曲线图）。"""
        with self._data_lock:
            return list(self._llm_latency_samples)


def get_metrics_collector() -> MetricsCollector:
    """获取 MetricsCollector 单例。"""
    return MetricsCollector()
