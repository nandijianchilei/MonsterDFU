"""
欺骗层蜜罐模块测试（融合增强 v1.1 阶段2）。

覆盖：
1. HoneypotService 虚拟端口 banner 响应（已知/未知端口）
2. 诱捕记录生成与统计
3. 源 IP 诱捕情报摘要（双脑决策支持）
4. HoneypotAgent 订阅 threat_alert → 蜜罐重定向 → 发布 honeypot_trap
5. 非侦察类告警不触发诱捕
6. build_redirect_plan 决策建议
7. export_json 导出
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from communication.message_bus import Message
from config import Config
from core.honeypot import (
    HoneypotAgent,
    HoneypotService,
    TRAP_TRIGGER_CATEGORIES,
)
from main import DFUPrototypeRunner as Runner, EventChainRecorder


def make_config() -> Config:
    cfg = Config()
    cfg.project_root = os.getcwd()
    return cfg


def make_alert_msg(
    bus_source: str = "TrafficMonitor",
    category: str = "port_scan",
    source_ip: str = "10.0.0.66",
    target_ip: str = "192.168.1.10",
    target_port: int = None,
    alert_id: str = "ALERT-001",
    severity: str = "medium",
) -> Message:
    payload = {
        "id": alert_id,
        "category": category,
        "severity": severity,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "target_port": target_port,
        "description": "测试告警",
        "raw_data": {"scanned_port_count": 3},
    }
    return Message(
        source=bus_source,
        target="*",
        type="threat_alert",
        payload=payload,
    )


class TestHoneypotService(unittest.TestCase):
    def setUp(self):
        self.service = HoneypotService(max_records=100)

    def test_known_port_banner(self):
        """已知端口返回对应服务指纹。"""
        result = self.service.simulate_handshake(22)
        self.assertEqual(result["service"], "SSH")
        self.assertIn("OpenSSH", result["banner"])

    def test_unknown_port_banner(self):
        """未知端口返回通用占位响应。"""
        result = self.service.simulate_handshake(65534)
        self.assertEqual(result["service"], "unknown-65534")
        self.assertEqual(result["banner"], "banner-65534")

    def test_record_trap(self):
        """诱捕记录生成，含 banner 与交互条目。"""
        record = self.service.record_trap(
            source_ip="10.0.0.66",
            target_ip="192.168.1.10",
            port=80,
            alert_id="ALERT-001",
        )
        self.assertEqual(record.service, "HTTP")
        self.assertIn("nginx", record.banner_response)
        self.assertEqual(len(record.interaction_entries), 1)
        self.assertEqual(record.interaction_entries[0]["type"], "probe")
        self.assertEqual(record.alert_id, "ALERT-001")

    def test_record_trap_custom_entries(self):
        """支持自定义交互条目（登录尝试/载荷注入）。"""
        record = self.service.record_trap(
            source_ip="10.0.0.66",
            target_ip="192.168.1.10",
            port=21,
            alert_id="ALERT-002",
            interaction_entries=[
                {"type": "probe", "content": "TCP 探测", "timestamp": "2026-01-01T00:00:00"},
                {"type": "login_attempt", "content": "USER admin", "timestamp": "2026-01-01T00:00:01"},
            ],
        )
        self.assertEqual(len(record.interaction_entries), 2)
        self.assertEqual(record.interaction_entries[1]["type"], "login_attempt")

    def test_stats(self):
        """统计包含总量/去重源/端口分布。"""
        self.service.record_trap("1.1.1.1", "10.0.0.1", 22)
        self.service.record_trap("1.1.1.1", "10.0.0.1", 80)
        self.service.record_trap("2.2.2.2", "10.0.0.1", 22)
        stats = self.service.get_stats()
        self.assertEqual(stats["total_traps"], 3)
        self.assertEqual(stats["unique_sources"], 2)
        self.assertEqual(stats["traps_by_port"][22], 2)
        self.assertEqual(stats["traps_by_service"]["SSH"], 2)

    def test_trap_context(self):
        """源 IP 诱捕情报摘要（双脑决策支持）。"""
        self.service.record_trap("1.1.1.1", "10.0.0.1", 22)
        self.service.record_trap("1.1.1.1", "10.0.0.1", 80)
        ctx = self.service.get_trap_context("1.1.1.1")
        self.assertTrue(ctx["trapped"])
        self.assertEqual(ctx["ports_probed"], [22, 80])
        self.assertIn("SSH", ctx["services_seen"])
        self.assertEqual(ctx["interaction_count"], 2)

        empty = self.service.get_trap_context("9.9.9.9")
        self.assertFalse(empty["trapped"])
        self.assertEqual(empty["ports_probed"], [])

    def test_max_records(self):
        """记录数超过上限时裁剪最旧记录。"""
        svc = HoneypotService(max_records=3)
        for i in range(5):
            svc.record_trap(f"10.0.0.{i}", "10.0.0.1", 22)
        self.assertEqual(len(svc.get_records()), 3)
        self.assertEqual(svc.get_records()[0].source_ip, "10.0.0.2")

    def test_clear(self):
        """清空记录。"""
        self.service.record_trap("1.1.1.1", "10.0.0.1", 22)
        self.service.clear()
        self.assertEqual(self.service.get_stats()["total_traps"], 0)


class TestHoneypotAgent(unittest.TestCase):
    def setUp(self):
        self.config = make_config()
        self.agent = HoneypotAgent(self.config)

    def test_trigger_categories(self):
        """侦察类类别应包含 port_scan / vuln / brute_force。"""
        self.assertIn("port_scan", TRAP_TRIGGER_CATEGORIES)
        self.assertIn("vuln", TRAP_TRIGGER_CATEGORIES)
        self.assertIn("brute_force", TRAP_TRIGGER_CATEGORIES)

    def _run(self, coro):
        return asyncio.run(coro)

    def test_handle_port_scan_alert(self):
        """port_scan 告警触发蜜罐重定向并返回 honeypot_trap 事件。"""
        self.agent._running = True
        resp = self._run(self.agent._handle_alert(make_alert_msg(alert_id="ALERT-SCAN")))
        self.assertIsNotNone(resp)
        self.assertEqual(resp.type, "honeypot_trap")
        self.assertEqual(resp.source, "HoneypotAgent")
        payload = resp.payload
        self.assertEqual(payload["alert_id"], "ALERT-SCAN")
        self.assertEqual(payload["source_ip"], "10.0.0.66")
        self.assertGreaterEqual(len(payload["records"]), 1)
        # 无指定目标端口时诱捕常见服务指纹端口
        ports = [r["port"] for r in payload["records"]]
        self.assertIn(22, ports)
        # 诱捕情报已写入服务
        self.assertTrue(self.agent.get_trap_context("10.0.0.66")["trapped"])

    def test_handle_alert_with_target_port(self):
        """告警指定目标端口时，仅诱捕该端口。"""
        self.agent._running = True
        resp = self._run(self.agent._handle_alert(
            make_alert_msg(category="vuln", target_port=6379, alert_id="ALERT-VULN")
        ))
        ports = [r["port"] for r in resp.payload["records"]]
        self.assertEqual(ports, [6379])

    def test_non_trigger_category(self):
        """非侦察类告警（ddos）不触发蜜罐。"""
        self.agent._running = True
        resp = self._run(self.agent._handle_alert(make_alert_msg(category="ddos")))
        self.assertIsNone(resp)
        self.assertFalse(self.agent.get_trap_context("10.0.0.66")["trapped"])

    def test_not_running(self):
        """未启动时忽略告警。"""
        self.agent._running = False
        resp = self._run(self.agent._handle_alert(make_alert_msg()))
        self.assertIsNone(resp)

    def test_build_redirect_plan(self):
        """生成蜜罐重定向处置建议。"""
        self.agent._running = True
        self._run(self.agent._handle_alert(make_alert_msg(alert_id="ALERT-PLAN")))
        plan = self.agent.build_redirect_plan("10.0.0.66", severity="high")
        self.assertEqual(plan["action"], "redirect_honeypot")
        self.assertEqual(plan["target_ip"], "10.0.0.66")
        self.assertIn("诱捕", plan["reason"])
        self.assertIn(plan["severity"], ("low", "medium", "high", "severe"))
        self.assertTrue(plan["risk"].startswith("低"))

    def test_bus_integration(self):
        """总线闭环：发布 threat_alert → 蜜罐订阅处理 → 产出 honeypot_trap。"""
        from communication.message_bus import get_message_bus

        bus = get_message_bus()
        received = []

        async def collect(msg):
            received.append(msg)

        async def scenario():
            await bus.subscribe("honeypot_trap", collect)
            await self.agent.start()
            # 发布侦察类告警（type=threat_alert, target=* 广播）
            await bus.publish(make_alert_msg(alert_id="ALERT-BUS"))
            # 给异步 handler 一个调度机会
            await asyncio.sleep(0.05)
            await self.agent.stop()

        asyncio.run(scenario())
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].type, "honeypot_trap")
        self.assertEqual(received[0].payload["alert_id"], "ALERT-BUS")

    def test_export_json(self):
        """导出诱捕记录为 JSON。"""
        self.agent._running = True
        self._run(self.agent._handle_alert(make_alert_msg(alert_id="ALERT-EXP")))
        out = os.path.join(tempfile.gettempdir(), "honeypot_export_test.json")
        try:
            path = self.agent.export_json(out)
            self.assertTrue(os.path.exists(path))
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["total_traps"], len(self.agent.get_records()))
            self.assertIn("stats", data)
            self.assertIn("records", data)
        finally:
            if os.path.exists(out):
                os.remove(out)


class TestHoneypotAssembly(unittest.TestCase):
    """蜜罐在 Runner 装配注册表中的声明验证。"""

    def test_stage2_assembly(self):
        cfg = Config()
        r = Runner(cfg, EventChainRecorder(None), stage=2)
        names = r.registry.names()
        self.assertIn("Honeypot", names)
        self.assertIsNotNone(r.honeypot)
        self.assertIs(r.right_brain.honeypot, r.honeypot)

    def test_stage2_order_before_brain(self):
        """蜜罐声明应先于双脑，保证决策支持可用。"""
        cfg = Config()
        r = Runner(cfg, EventChainRecorder(None), stage=2)
        spec = r.registry.specs(stage=2, is_realtime=False)
        names = [s.name for s in spec]
        self.assertLess(names.index("Honeypot"), names.index("RightBrain"))

    def test_stage1_skips_honeypot(self):
        """stage1 不装配蜜罐，右脑也不注入。"""
        cfg = Config()
        r = Runner(cfg, EventChainRecorder(None), stage=1)
        names = [s.name for s in r.registry.specs(stage=1, is_realtime=False)]
        self.assertNotIn("Honeypot", names)
        self.assertIsNone(r.honeypot)
        self.assertIsNone(r.right_brain.honeypot)


if __name__ == "__main__":
    unittest.main()
