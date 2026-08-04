"""
攻击路径干扰层模块测试（融合增强 v1.1 第三阶段 · 默认关闭）。

覆盖：
1. InterferenceConfig 默认关闭、仅授权环境可执行
2. InterferenceService 五级门控（disabled/authorization/severity/category/level）
3. blindfold（终端输出污染）与 puppeteer（API 诱饵）执行与审计
4. kill-switch 联动强制停用
5. InterferenceAgent 总线闭环（默认不触发 / 授权环境触发 / 熔断停用）
6. build_interference_plan 决策建议
7. CountermeasureFSM kill-switch 门控（熔断不升级）
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

from communication.message_bus import Message, get_message_bus
from config import Config, InterferenceConfig
from core.countermeasure_fsm import CountermeasureFSM
from core.interference import (
    DECOY_MARKER,
    INTERFERENCE_EVENT_TYPE,
    KILL_SWITCH_EVENT_TYPE,
    METHOD_BLINDFOLD,
    METHOD_PUPPETEER,
    InterferenceAgent,
    InterferenceService,
)


def make_config(enabled: bool = False, **kwargs) -> Config:
    cfg = Config()
    cfg.project_root = os.getcwd()
    cfg.interference = InterferenceConfig(enabled=enabled, **kwargs)
    return cfg


def make_alert_msg(
    category: str = "exploit",
    source_ip: str = "10.0.0.77",
    severity: str = "high",
    alert_id: str = "ALERT-IF-001",
    authorized: bool = True,
    api_path: str = "",
) -> Message:
    payload = {
        "id": alert_id,
        "category": category,
        "severity": severity,
        "source_ip": source_ip,
        "target_ip": "192.168.1.20",
        "target_port": 8443,
        "api_path": api_path,
        "description": "干扰层测试告警",
        "raw_data": {},
        "authorized": authorized,
    }
    return Message(
        source="TrafficMonitor",
        target="*",
        type="threat_alert",
        payload=payload,
    )


class DummyFSM:
    """duck-typing FSM：只提供 get_level。"""

    def __init__(self, level: str = "L2"):
        self._level = level

    def get_level(self, source_ip: str):
        return self._level


class TestInterferenceConfig(unittest.TestCase):
    def test_default_disabled(self):
        """默认关闭：enabled=False、authorized_only=True、min_severity=high。"""
        cfg = InterferenceConfig()
        self.assertFalse(cfg.enabled)
        self.assertTrue(cfg.authorized_only)
        self.assertEqual(cfg.min_severity, "high")
        self.assertIn("exploit", cfg.trigger_categories)
        self.assertGreaterEqual(cfg.audit_capacity, 100)

    def test_env_override(self):
        """DFU_INTERFERENCE=on 环境变量覆盖 enabled。"""
        os.environ["DFU_INTERFERENCE"] = "on"
        try:
            from config import build_config

            cfg = build_config()
            self.assertTrue(cfg.interference.enabled)
        finally:
            os.environ.pop("DFU_INTERFERENCE", None)


class TestInterferenceService(unittest.TestCase):
    def setUp(self):
        self.service = InterferenceService(
            InterferenceConfig(enabled=True, authorized_only=True)
        )

    def test_disabled_gate(self):
        """默认关闭：enabled=False 时 blindfold 被拦。"""
        svc = InterferenceService(InterferenceConfig(enabled=False))
        result = svc.blindfold("10.0.0.1", category="exploit", severity="high",
                               payload={"authorized": True}, fsm_level="L2")
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "interference_disabled")

    def test_authorization_gate(self):
        """authorized_only 时缺少授权标志被拦。"""
        result = self.service.blindfold("10.0.0.1", category="exploit",
                                        severity="high", payload={}, fsm_level="L2")
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "not_authorized")

    def test_severity_gate(self):
        """严重级别低于 min_severity 被拦。"""
        result = self.service.blindfold("10.0.0.1", category="exploit",
                                        severity="medium", payload={"authorized": True},
                                        fsm_level="L2")
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "severity_below_threshold")

    def test_category_gate(self):
        """类别不在白名单被拦。"""
        result = self.service.blindfold("10.0.0.1", category="normal_traffic",
                                        severity="high", payload={"authorized": True},
                                        fsm_level="L2")
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "category_not_in_whitelist")

    def test_fsm_level_gate(self):
        """FSM 等级低于 L2 被拦。"""
        result = self.service.blindfold("10.0.0.1", category="exploit",
                                        severity="high", payload={"authorized": True},
                                        fsm_level="L1")
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "fsm_level_below_l2")

    def test_blindfold_applied(self):
        """门控全开时 blindfold 执行并返回误导响应。"""
        result = self.service.blindfold("10.0.0.1", category="exploit",
                                        severity="high", payload={"authorized": True},
                                        fsm_level="L2")
        self.assertTrue(result["applied"])
        self.assertEqual(result["method"], METHOD_BLINDFOLD)
        self.assertIn(DECOY_MARKER, result["decoy_response"])
        self.assertTrue(result["audit_id"])

    def test_puppeteer_applied(self):
        """门控全开时 puppeteer 执行并返回诱饵 API 响应。"""
        result = self.service.puppeteer("10.0.0.1", api_path="/api/internal/status",
                                        category="exploit", severity="high",
                                        payload={"authorized": True}, fsm_level="L2")
        self.assertTrue(result["applied"])
        self.assertEqual(result["method"], METHOD_PUPPETEER)
        self.assertEqual(result["decoy_response"]["_marker"], DECOY_MARKER)
        self.assertTrue(result["audit_id"])

    def test_kill_switch_force_stop(self):
        """kill-switch 开启后强制停用（即使 config.enabled=True）。"""
        self.service.set_kill_switch(True)
        self.assertFalse(self.service.enabled)
        result = self.service.blindfold("10.0.0.1", category="exploit",
                                        severity="high", payload={"authorized": True},
                                        fsm_level="L2")
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "interference_disabled")

    def test_stats_counters(self):
        """统计计数与审计记录。"""
        self.service.blindfold("10.0.0.1", category="exploit", severity="high",
                               payload={"authorized": True}, fsm_level="L2")
        self.service.blindfold("10.0.0.2", category="exploit", severity="medium",
                               payload={"authorized": True}, fsm_level="L2")
        stats = self.service.get_stats()
        self.assertEqual(stats["blindfold_applied"], 1)
        self.assertEqual(stats["blocked_by_severity"], 1)
        self.assertEqual(len(self.service.get_audit_log()), 2)
        self.assertEqual(len(self.service.get_audit_by_source("10.0.0.1")), 1)

    def test_export_json(self):
        """导出干扰审计 JSON。"""
        self.service.blindfold("10.0.0.1", category="exploit", severity="high",
                               payload={"authorized": True}, fsm_level="L2")
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "interference_audit.json")
            self.service.export_json(out)
            self.assertTrue(os.path.exists(out))
            with open(out, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data["audit"]), 1)
            self.assertEqual(data["audit"][0]["method"], METHOD_BLINDFOLD)


class TestInterferenceAgent(unittest.TestCase):
    def setUp(self):
        self.bus = get_message_bus()
        self.received = []

    async def _collect(self, msg):
        self.received.append(msg)

    def _agent(self, enabled: bool = True, level: str = "L2"):
        cfg = make_config(enabled=enabled, authorized_only=True)
        fsm = DummyFSM(level)
        return InterferenceAgent(cfg, fsm=fsm)

    def test_default_disabled_no_event(self):
        """默认关闭：发布 threat_alert 不产出 interference_applied。"""
        agent = self._agent(enabled=False)
        received = []

        async def scenario():
            await self.bus.subscribe(INTERFERENCE_EVENT_TYPE, lambda m: received.append(m))
            await agent.start()
            await self.bus.publish(make_alert_msg())
            await asyncio.sleep(0.05)
            await agent.stop()

        asyncio.run(scenario())
        self.assertEqual(len(received), 0)

    def test_authorized_trigger_blindfold(self):
        """授权环境开启：发布威胁告警产出 interference_applied（blindfold）。"""
        agent = self._agent(enabled=True)
        received = []

        async def scenario():
            await self.bus.subscribe(INTERFERENCE_EVENT_TYPE, lambda m: received.append(m))
            await agent.start()
            await self.bus.publish(make_alert_msg())
            await asyncio.sleep(0.05)
            await agent.stop()

        asyncio.run(scenario())
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].type, INTERFERENCE_EVENT_TYPE)
        self.assertEqual(received[0].payload["method"], METHOD_BLINDFOLD)
        self.assertEqual(received[0].payload["source_ip"], "10.0.0.77")

    def test_authorized_trigger_puppeteer(self):
        """带 api_path 的告警触发 puppeteer（API 拦截改写）。"""
        agent = self._agent(enabled=True)
        received = []

        async def scenario():
            await self.bus.subscribe(INTERFERENCE_EVENT_TYPE, lambda m: received.append(m))
            await agent.start()
            await self.bus.publish(make_alert_msg(api_path="/api/internal/users"))
            await asyncio.sleep(0.05)
            await agent.stop()

        asyncio.run(scenario())
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].payload["method"], METHOD_PUPPETEER)

    def test_kill_switch_event_stops(self):
        """kill_switch 事件开启后干扰层强制停用。"""
        agent = self._agent(enabled=True)
        received = []

        async def scenario():
            await self.bus.subscribe(INTERFERENCE_EVENT_TYPE, lambda m: received.append(m))
            await agent.start()
            await self.bus.publish(Message(
                source="web_server", target="*", type=KILL_SWITCH_EVENT_TYPE,
                payload={"type": KILL_SWITCH_EVENT_TYPE, "on": True},
            ))
            await asyncio.sleep(0.02)
            await self.bus.publish(make_alert_msg())
            await asyncio.sleep(0.05)
            await agent.stop()

        asyncio.run(scenario())
        self.assertEqual(len(received), 0)
        self.assertTrue(agent.service.get_stats()["kill_switch"])

    def test_build_interference_plan_disabled(self):
        """默认关闭时计划返回 none。"""
        agent = self._agent(enabled=False)
        plan = agent.build_interference_plan("10.0.0.77", severity="high")
        self.assertEqual(plan["action"], "none")

    def test_build_interference_plan_enabled(self):
        """开启时返回干扰策略（L2 → blindfold）。"""
        agent = self._agent(enabled=True, level="L2")
        plan = agent.build_interference_plan("10.0.0.77", severity="high")
        self.assertEqual(plan["action"], "interference_blindfold")
        self.assertEqual(plan["fsm_level"], "L2")

    def test_build_interference_plan_puppeteer_for_l3(self):
        """L3 及以上建议 puppeteer。"""
        agent = self._agent(enabled=True, level="L3")
        plan = agent.build_interference_plan("10.0.0.77", severity="severe")
        self.assertEqual(plan["action"], "interference_puppeteer")


class TestFSMKillSwitch(unittest.TestCase):
    def test_disabled_fsm_no_upgrade(self):
        """FSM set_enabled(False) 后 evaluate 不升级，保持当前等级。"""
        fsm = CountermeasureFSM()
        fsm.set_enabled(False)
        action = fsm.evaluate("10.0.0.99", severity="severe", category="exploit")
        self.assertTrue(action.keep_level)
        self.assertEqual(action.old_level, action.new_level)
        self.assertIn("kill-switch", action.reason)

    def test_enabled_fsm_normal(self):
        """FSM 正常时累计告警仍按规则升级。"""
        fsm = CountermeasureFSM()
        upgraded = False
        for _ in range(8):
            action = fsm.evaluate("10.0.0.99", severity="severe", category="exploit")
            if not action.keep_level:
                upgraded = True
                break
        self.assertTrue(upgraded)


if __name__ == "__main__":
    unittest.main()
