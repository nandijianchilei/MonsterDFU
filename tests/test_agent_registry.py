"""
Agent 注册表装配工厂 (agent_registry) 单元测试
覆盖：注册顺序、start_all/stop_all 顺序、阶段/实时条件过滤、重复注册、remove。
"""

import asyncio
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.agent_registry import AgentRegistry, AgentSpec


class FakeAgent:
    def __init__(self, name):
        self.name = name
        self.started = False

    async def start(self):
        self.started = True

    async def stop(self):
        self.started = False


class TestAgentRegistry(unittest.TestCase):
    def _make_registry(self):
        reg = AgentRegistry()
        self.a = FakeAgent("A")
        self.b = FakeAgent("B")
        self.c = FakeAgent("C")
        reg.add(AgentSpec(name="A", instance=self.a))
        reg.add(AgentSpec(name="B", instance=self.b, stage_required=2, non_realtime_only=True))
        reg.add(AgentSpec(name="C", instance=self.c, realtime_only=True))
        return reg

    def test_registration_order(self):
        reg = self._make_registry()
        self.assertEqual(reg.names(), ["A", "B", "C"])

    def test_duplicate_registration_raises(self):
        reg = self._make_registry()
        with self.assertRaises(ValueError):
            reg.add(AgentSpec(name="A", instance=self.a))

    def test_stage1_only_plain_agents(self):
        reg = self._make_registry()
        specs = reg.specs(stage=1, is_realtime=False)
        self.assertEqual([s.name for s in specs], ["A"])

    def test_stage2_includes_non_realtime(self):
        reg = self._make_registry()
        specs = reg.specs(stage=2, is_realtime=False)
        self.assertEqual([s.name for s in specs], ["A", "B"])

    def test_realtime_includes_realtime_only(self):
        reg = self._make_registry()
        specs = reg.specs(stage="realtime", is_realtime=True)
        self.assertEqual([s.name for s in specs], ["A", "C"])

    def test_start_all_order_and_state(self):
        reg = self._make_registry()
        asyncio.run(reg.start_all(stage=2, is_realtime=False))
        self.assertTrue(self.a.started)
        self.assertTrue(self.b.started)
        self.assertFalse(self.c.started)

    def test_stop_all_reverse_order(self):
        reg = self._make_registry()
        asyncio.run(reg.start_all(stage=2, is_realtime=False))
        stopped = asyncio.run(reg.stop_all(stage=2, is_realtime=False))
        self.assertEqual(stopped, ["B", "A"])
        self.assertFalse(self.a.started)
        self.assertFalse(self.b.started)

    def test_remove_agent(self):
        reg = self._make_registry()
        reg.remove("B")
        self.assertEqual(reg.names(), ["A", "C"])

    def test_remove_missing_raises(self):
        reg = self._make_registry()
        with self.assertRaises(KeyError):
            reg.remove("NotExist")

    def test_get_spec(self):
        reg = self._make_registry()
        spec = reg.get("C")
        self.assertEqual(spec.name, "C")
        self.assertTrue(spec.realtime_only)
        self.assertIsNone(reg.get("NotExist"))


if __name__ == "__main__":
    unittest.main()
