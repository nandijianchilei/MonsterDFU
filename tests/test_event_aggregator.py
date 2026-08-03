"""
事件聚合器 (event_aggregator) 单元测试
覆盖：AggregationWindow 聚合窗口（峰值 severity、目标聚合、摘要、详情条数限制）、
EventAggregator 生命周期（单告警透传、窗口过期 flush、stop flush、idle 超时、
窗口溢出、统计）。

说明：实现中单告警立即透传（event_count == 1 即 flush），因此合并窗口行为
通过 AggregationWindow 直接验证，聚合器层验证调度/生命周期分支。
"""

import asyncio
import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from communication.message_bus import Message, get_message_bus
from config import EventAggregatorConfig
from core.event_aggregator import AggregationWindow, EventAggregator


def _alert(source_ip="1.1.1.1", category="port_scan", severity="medium", **extra):
    alert = {
        "source_ip": source_ip,
        "category": category,
        "severity": severity,
        "target_ip": "192.168.1.10",
        "target_port": 80,
        "raw_data": {"request_count": 10, "requests_per_second": 5.0},
    }
    alert.update(extra)
    return alert


class TestAggregationWindow(unittest.TestCase):
    """聚合窗口纯逻辑"""

    def setUp(self):
        self.config = EventAggregatorConfig(window_ms=2000, max_indicators_detail=20)

    def test_event_count(self):
        w = AggregationWindow("1.1.1.1:port_scan", "1.1.1.1", "port_scan", self.config)
        self.assertEqual(w.event_count, 0)
        w.add(_alert())
        w.add(_alert())
        self.assertEqual(w.event_count, 2)

    def test_peak_severity(self):
        w = AggregationWindow("1.1.1.1:port_scan", "1.1.1.1", "port_scan", self.config)
        w.add(_alert(severity="low"))
        self.assertEqual(w.peak_severity, "low")
        w.add(_alert(severity="severe"))
        self.assertEqual(w.peak_severity, "severe")
        # 低级别不覆盖
        w.add(_alert(severity="low"))
        self.assertEqual(w.peak_severity, "severe")

    def test_build_merged_alert_empty(self):
        w = AggregationWindow("1.1.1.1:port_scan", "1.1.1.1", "port_scan", self.config)
        self.assertIsNone(w.build_merged_alert())

    def test_build_merged_alert_fields(self):
        w = AggregationWindow("1.1.1.1:port_scan", "1.1.1.1", "port_scan", self.config)
        w.add(_alert(target_ip="10.0.0.2", target_port=443, severity="medium"))
        w.add(_alert(target_ip="10.0.0.3", target_port=80, severity="high"))
        merged = w.build_merged_alert()
        self.assertTrue(merged["aggregated"])
        self.assertEqual(merged["event_count"], 2)
        self.assertEqual(merged["source_ip"], "1.1.1.1")
        self.assertEqual(merged["category"], "port_scan")
        self.assertEqual(merged["severity"], "high")
        self.assertEqual(merged["target_ips"], ["10.0.0.2", "10.0.0.3"])
        self.assertEqual(merged["target_ports"], [80, 443])
        self.assertEqual(merged["window_ms"], 2000)
        self.assertTrue(merged["alert_id"].startswith("merged_"))
        self.assertEqual(merged["summary"]["total_packets"], 20)
        self.assertEqual(merged["summary"]["peak_rate"], 5.0)
        self.assertEqual(merged["summary"]["severity_breakdown"]["high"], 1)

    def test_total_packets_defaults_to_one(self):
        w = AggregationWindow("1.1.1.1:port_scan", "1.1.1.1", "port_scan", self.config)
        w.add(_alert(raw_data={}))
        merged = w.build_merged_alert()
        self.assertEqual(merged["summary"]["total_packets"], 1)

    def test_detail_limit_keeps_head_and_tail(self):
        cfg = EventAggregatorConfig(max_indicators_detail=4)
        w = AggregationWindow("1.1.1.1:port_scan", "1.1.1.1", "port_scan", cfg)
        for i in range(6):
            w.add(_alert(severity="low", seq=i))
        self.assertEqual(w.event_count, 4)  # 2 头 + 2 尾
        merged = w.build_merged_alert()
        seqs = [a["seq"] for a in merged["indicators"]]
        self.assertEqual(seqs, [0, 1, 4, 5])

    def test_timestamps_set(self):
        w = AggregationWindow("1.1.1.1:port_scan", "1.1.1.1", "port_scan", self.config)
        w.add(_alert())
        merged = w.build_merged_alert()
        self.assertIsNotNone(merged["summary"]["first_seen"])
        self.assertIsNotNone(merged["summary"]["last_seen"])


class TestEventAggregator(unittest.TestCase):
    """聚合器生命周期与调度"""

    def _run(self, coro):
        return asyncio.run(coro)

    async def _drain(self):
        """让总线后台 handler 任务完成（publish 不等待 handler）"""
        await asyncio.sleep(0.02)

    def _make_aggregator(self, **cfg_overrides):
        cfg = EventAggregatorConfig(**cfg_overrides)
        agg = EventAggregator(cfg)
        return agg

    def test_make_key(self):
        self.assertEqual(
            EventAggregator._make_key({"source_ip": "1.1.1.1", "category": "bruteforce"}),
            "1.1.1.1:bruteforce",
        )
        self.assertEqual(
            EventAggregator._make_key({"category": "x"}),
            "unknown:x",
        )

    def test_single_alert_flushed_immediately(self):
        async def scenario():
            bus = get_message_bus()
            merged = []
            await bus.subscribe("merged_threat_alert", lambda m: merged.append(m))
            agg = self._make_aggregator()
            await agg.start()
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload=_alert(source_ip="10.9.9.9"))
            )
            await self._drain()
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[-1].payload["source_ip"], "10.9.9.9")
            self.assertEqual(merged[-1].payload["event_count"], 1)
            self.assertEqual(agg.get_stats()["total_flushed"], 1)
            self.assertEqual(agg.get_stats()["total_received"], 1)

        self._run(scenario())

    def test_two_alerts_both_passthrough(self):
        """按当前实现：连续告警各自单条透传（窗口在单告警时即 flush）"""
        async def scenario():
            bus = get_message_bus()
            merged = []
            await bus.subscribe("merged_threat_alert", lambda m: merged.append(m))
            agg = self._make_aggregator()
            await agg.start()
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload=_alert(source_ip="10.9.9.8"))
            )
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload=_alert(source_ip="10.9.9.8"))
            )
            await self._drain()
            self.assertEqual(len(merged), 2)
            self.assertEqual(agg.get_stats()["total_flushed"], 2)

        self._run(scenario())

    def test_window_expiry_flush(self):
        """event_count==2 分支：窗口期满后 flush（通过白盒注入窗口）"""
        async def scenario():
            bus = get_message_bus()
            merged = []
            await bus.subscribe("merged_threat_alert", lambda m: merged.append(m))
            agg = self._make_aggregator(window_ms=50, idle_timeout_ms=2000)
            await agg.start()
            key = "10.7.7.7:port_scan"
            window = AggregationWindow(key, "10.7.7.7", "port_scan", agg.config)
            window.add(_alert(source_ip="10.7.7.7"))
            window.add(_alert(source_ip="10.7.7.7"))
            agg._windows[key] = window
            agg._window_started[key] = time.monotonic()
            agg._schedule_flush(key)
            await asyncio.sleep(0.15)
            self.assertEqual(merged[-1].payload["event_count"], 2)
            self.assertEqual(agg.get_stats()["total_flushed"], 1)

        self._run(scenario())

    def test_stop_flushes_pending(self):
        async def scenario():
            bus = get_message_bus()
            merged = []
            await bus.subscribe("merged_threat_alert", lambda m: merged.append(m))
            agg = self._make_aggregator(window_ms=5000, idle_timeout_ms=5000)
            await agg.start()
            key = "10.6.6.6:port_scan"
            window = AggregationWindow(key, "10.6.6.6", "port_scan", agg.config)
            window.add(_alert(source_ip="10.6.6.6"))
            agg._windows[key] = window
            agg._window_started[key] = time.monotonic()
            await agg.stop()
            await self._drain()
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[-1].payload["event_count"], 1)
            self.assertEqual(agg.windows_count, 0)

        self._run(scenario())

    def test_idle_timeout_flush(self):
        async def scenario():
            bus = get_message_bus()
            merged = []
            await bus.subscribe("merged_threat_alert", lambda m: merged.append(m))
            agg = self._make_aggregator(window_ms=5000, idle_timeout_ms=100)
            await agg.start()
            key = "10.5.5.5:port_scan"
            window = AggregationWindow(key, "10.5.5.5", "port_scan", agg.config)
            window.add(_alert(source_ip="10.5.5.5"))
            agg._windows[key] = window
            agg._window_started[key] = time.monotonic() - 10  # 早就超时
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload=_alert(source_ip="10.5.5.5"))
            )
            # idle 检查会 flush 旧窗口（10.5.5.5）
            self.assertNotIn(key, agg._windows)
            self.assertEqual(agg.get_stats()["total_flushed"], 1)

        self._run(scenario())

    def test_overflow_flush_oldest(self):
        async def scenario():
            bus = get_message_bus()
            merged = []
            await bus.subscribe("merged_threat_alert", lambda m: merged.append(m))
            agg = self._make_aggregator(window_ms=5000, idle_timeout_ms=5000, max_concurrent_windows=2)
            await agg.start()
            # 先塞 3 个窗口（10.1.1.1 最老）
            for i, ip in enumerate(("10.1.1.1", "10.2.2.2", "10.3.3.3")):
                key = f"{ip}:port_scan"
                window = AggregationWindow(key, ip, "port_scan", agg.config)
                window.add(_alert(source_ip=ip))
                agg._windows[key] = window
                agg._window_started[key] = time.monotonic() - (3 - i)
            # 10.3.3.3 窗口已存在，再收一条 → event_count==2 不立即 flush
            # → len(windows)=3 > max=2 → 溢出 flush 最老的 10.1.1.1
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload=_alert(source_ip="10.3.3.3"))
            )
            self.assertNotIn("10.1.1.1:port_scan", agg._windows)
            self.assertIn("10.2.2.2:port_scan", agg._windows)
            self.assertIn("10.3.3.3:port_scan", agg._windows)

        self._run(scenario())

    def test_non_dict_payload_ignored(self):
        async def scenario():
            agg = self._make_aggregator()
            await agg.start()
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload="not-a-dict")
            )
            self.assertEqual(agg.get_stats()["total_received"], 0)

        self._run(scenario())

    def test_stopped_aggregator_ignores(self):
        async def scenario():
            agg = self._make_aggregator()
            await agg.stop()
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload=_alert(source_ip="10.0.0.1"))
            )
            self.assertEqual(agg.get_stats()["total_received"], 0)

        self._run(scenario())

    def test_windows_count_and_active_keys(self):
        async def scenario():
            agg = self._make_aggregator()
            await agg.start()
            key = "10.4.4.4:port_scan"
            window = AggregationWindow(key, "10.4.4.4", "port_scan", agg.config)
            window.add(_alert(source_ip="10.4.4.4"))
            agg._windows[key] = window
            agg._window_started[key] = time.monotonic()
            self.assertEqual(agg.windows_count, 1)
            self.assertEqual(agg.active_keys, [key])
            await agg.stop()

        self._run(scenario())

    def test_stats(self):
        async def scenario():
            agg = self._make_aggregator()
            await agg.start()
            stats = agg.get_stats()
            self.assertEqual(stats["total_received"], 0)
            self.assertEqual(stats["total_merged"], 0)
            self.assertEqual(stats["total_flushed"], 0)
            await agg._on_threat_alert(
                Message(source="pre", target="*", type="unhandled_threat", payload=_alert(source_ip="10.8.8.8"))
            )
            stats = agg.get_stats()
            self.assertEqual(stats["total_received"], 1)
            self.assertEqual(stats["total_merged"], 1)
            self.assertEqual(stats["total_flushed"], 1)

        self._run(scenario())


if __name__ == "__main__":
    unittest.main()
