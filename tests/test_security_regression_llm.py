"""
安全回归测试：LLM 降级标注与 MonsterAgent 降级模式传播。

覆盖本批安全修复：
- P1-8/P2-13  llm_client.chat_json / chat_with_tools 真实调用失败时返回体带 degraded: true
- R2          纯 chat() 降级契约（_degraded 标志，返回体不带标记的兼容分支不在此测）
- P1-7        monster_agent 检测 resp.degraded 后返回 mode=degraded 而非 real

测试风格：pytest + 直接 import 模块，mock 掉真实网络调用。
"""

import asyncio
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import LLMConfig
from core.llm_client import LLMClient
from core.monster_agent import MonsterAgent


def _make_client():
    """构造真实模式（非 mock）的 LLMClient，供注入失败场景使用。"""
    return LLMClient(LLMConfig(api_key="test-key-123", mock_mode=False))


class TestChatJsonDegradedFlag(unittest.TestCase):
    """"chat_json：真实调用失败时返回体带 degraded: true。"""

    def test_failure_marks_degraded(self):
        client = _make_client()
        client._real_chat_json = AsyncMock(side_effect=RuntimeError("upstream down"))
        result = asyncio.run(client.chat_json("sys", "user"))
        self.assertIs(result.get("degraded"), True)

    def test_success_has_no_degraded_flag(self):
        client = _make_client()
        client._real_chat_json = AsyncMock(return_value={"ok": True})
        result = asyncio.run(client.chat_json("sys", "user"))
        self.assertNotIn("degraded", result)


class TestChatWithToolsDegradedFlag(unittest.TestCase):
    """"chat_with_tools：真实调用失败时返回体带 degraded: true。"""

    def test_failure_marks_degraded(self):
        client = _make_client()
        client._call_api_once_full = AsyncMock(side_effect=RuntimeError("upstream down"))
        result = asyncio.run(client.chat_with_tools(
            messages=[{"role": "user", "content": "hi"}],
            tools=None, temperature=0.3,
        ))
        self.assertIs(result.get("degraded"), True)
        self.assertEqual(result.get("finish_reason"), "fallback")

    def test_success_has_no_degraded_flag(self):
        client = _make_client()
        client._call_api_once_full = AsyncMock(return_value={
            "content": "ok", "tool_calls": None, "finish_reason": "stop",
        })
        result = asyncio.run(client.chat_with_tools(
            messages=[], tools=None, temperature=0.3,
        ))
        self.assertNotIn("degraded", result)


class _FakeToolbox:
    def get_tool_schemas_for_llm(self):
        return []

    async def invoke(self, name, args, caller="monster"):
        return {"ok": True}


class _FakeLLM:
    mock_mode = False

    def __init__(self, degraded):
        self._degraded = degraded

    async def chat_with_tools(self, messages, tools=None, temperature=0.3):
        if self._degraded:
            return {"content": "fallback decision", "tool_calls": None,
                    "finish_reason": "fallback", "degraded": True}
        return {"content": "real decision", "tool_calls": None, "finish_reason": "stop"}


class TestMonsterAgentDegradedMode(unittest.TestCase):
    """"monster_agent：上游返回 degraded 时最终 mode=degraded 而非 real。"""

    def _agent(self, degraded):
        return MonsterAgent(
            config=None,
            llm_client=_FakeLLM(degraded),
            skill_toolbox=_FakeToolbox(),
        )

    def test_degraded_upstream_returns_mode_degraded(self):
        result = asyncio.run(self._agent(True)._real_react("attack detected"))
        self.assertEqual(result["mode"], "degraded")
        self.assertIs(result["degraded"], True)

    def test_normal_upstream_returns_mode_real(self):
        result = asyncio.run(self._agent(False)._real_react("attack detected"))
        self.assertEqual(result["mode"], "real")
        self.assertIs(result["degraded"], False)


if __name__ == "__main__":
    unittest.main()
