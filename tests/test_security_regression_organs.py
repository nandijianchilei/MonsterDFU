"""
安全回归测试：iptables 返回契约（CompletedProcess）与器官独立 LLM 配置分发。

覆盖本批安全修复：
- P1-4  firewall_executor._run_iptables 返回 subprocess.CompletedProcess，
        调用方可直接访问 returncode / stdout / stderr，不再抛 AttributeError
- P1-8  config.build_organ_llm_config / llm_client.create_organ_llm_client：
        配置 organ_overrides 的器官返回独立实例，未配置/use_global 回退全局

测试风格：pytest + 直接 import 模块，mock 掉真实子进程与配置读取。
"""

import asyncio
import os
import subprocess
import sys
import unittest
from unittest.mock import AsyncMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import config as config_mod
from config import LLMConfig
from core import llm_client as llm_client_mod
from core.llm_client import LLMClient, create_organ_llm_client
# _run_iptables 为 IptablesBackend 类方法（无实例状态依赖）
from organs.firewall_executor import IptablesBackend


class _FakeProc:
    """模拟 asyncio.create_subprocess_exec 返回的子进程对象。"""

    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


class TestRunIptablesContract(unittest.TestCase):
    """"_run_iptables 必须返回 CompletedProcess，字段可正常访问。"""

    def _fw(self):
        # 绕过 __init__（_run_iptables 不依赖实例状态）
        return object.__new__(IptablesBackend)

    def _patch_subprocess(self, proc):
        # Windows 的 os 无 geteuid，用 create=True 注入假实现
        return (
            patch.object(os, "geteuid", create=True, return_value=0),
            patch("asyncio.create_subprocess_exec", new_callable=AsyncMock,
                  return_value=proc),
        )

    def test_success_returns_completed_process(self):
        fw = self._fw()
        p_geteuid, p_exec = self._patch_subprocess(
            _FakeProc(0, b"Chain INPUT (policy ACCEPT)", b""))
        with p_geteuid, p_exec:
            proc = asyncio.run(fw._run_iptables(["-L"]))

        self.assertIsInstance(proc, subprocess.CompletedProcess)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "Chain INPUT (policy ACCEPT)")
        self.assertEqual(proc.stderr, "")
        self.assertIsNotNone(proc.args)

    def test_error_returns_completed_process(self):
        fw = self._fw()
        p_geteuid, p_exec = self._patch_subprocess(
            _FakeProc(1, b"", b"Permission denied"))
        with p_geteuid, p_exec:
            proc = asyncio.run(fw._run_iptables(["-I", "INPUT"]))

        self.assertIsInstance(proc, subprocess.CompletedProcess)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "Permission denied")

    def test_args_recorded_in_completed_process(self):
        fw = self._fw()
        p_geteuid, p_exec = self._patch_subprocess(_FakeProc(0))
        with p_geteuid, p_exec:
            proc = asyncio.run(fw._run_iptables(["--list", "INPUT"]))
        self.assertIsNotNone(proc.args)
        self.assertIn("--list", proc.args)


class TestOrganConfigDistribution(unittest.TestCase):
    """"器官独立 LLM 配置：有覆盖出独立实例，无覆盖/use_global 回退。"""

    def _base(self):
        return LLMConfig(
            provider="volcano",
            api_base="https://ark.cn-beijing.volces.com/api/v3",
            api_key="base-key",
            model="base-model",
        )

    def test_override_returns_independent_config(self):
        with patch.object(config_mod, "get_organ_llm_override", return_value={
            "provider": "openai",
            "api_base": "https://api.openai.com/v1",
            "api_key": "organ-key",
            "model": "gpt-4o",
        }):
            cfg = config_mod.build_organ_llm_config("left_brain", self._base())

        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.provider, "openai")
        self.assertEqual(cfg.api_base, "https://api.openai.com/v1")
        self.assertEqual(cfg.api_key, "organ-key")
        self.assertEqual(cfg.model, "gpt-4o")

    def test_no_override_returns_none(self):
        with patch.object(config_mod, "get_organ_llm_override", return_value=None):
            cfg = config_mod.build_organ_llm_config("left_brain", self._base())
        self.assertIsNone(cfg)

    def test_empty_override_returns_none(self):
        with patch.object(config_mod, "get_organ_llm_override", return_value={}):
            cfg = config_mod.build_organ_llm_config("left_brain", self._base())
        self.assertIsNone(cfg)

    def test_use_global_returns_none(self):
        with patch.object(config_mod, "get_organ_llm_override", return_value={
            "use_global": True, "model": "gpt-4o",
        }):
            cfg = config_mod.build_organ_llm_config("left_brain", self._base())
        self.assertIsNone(cfg)

    def test_camel_case_fields_supported(self):
        with patch.object(config_mod, "get_organ_llm_override", return_value={
            "baseUrl": "https://example.com/v1",
            "apiKey": "camel-key",
            "model": "camel-model",
        }):
            cfg = config_mod.build_organ_llm_config("left_brain", self._base())
        self.assertEqual(cfg.api_base, "https://example.com/v1")
        self.assertEqual(cfg.api_key, "camel-key")
        self.assertEqual(cfg.model, "camel-model")

    def test_override_does_not_mutate_base(self):
        base = self._base()
        with patch.object(config_mod, "get_organ_llm_override", return_value={
            "provider": "openai", "api_key": "organ-key",
        }):
            cfg = config_mod.build_organ_llm_config("left_brain", base)
        cfg.api_key = "changed"
        self.assertEqual(base.api_key, "base-key")

    def test_create_client_override_returns_new_instance(self):
        base = self._base()
        fallback = LLMClient(base)

        def fake_build(key, base_llm):
            return LLMConfig(provider="openai",
                             api_base="https://api.openai.com/v1",
                             api_key="organ-key", model="gpt-4o")

        with patch.object(llm_client_mod, "build_organ_llm_config", side_effect=fake_build):
            client = create_organ_llm_client("left_brain", base, fallback)

        self.assertIsNotNone(client)
        self.assertIsNot(client, fallback)
        self.assertEqual(client.config.provider, "openai")
        self.assertEqual(client.config.api_key, "organ-key")
        self.assertEqual(client.config.model, "gpt-4o")

    def test_create_client_no_override_returns_fallback(self):
        base = self._base()
        fallback = LLMClient(base)
        with patch.object(llm_client_mod, "build_organ_llm_config", return_value=None):
            client = create_organ_llm_client("left_brain", base, fallback)
        self.assertIs(client, fallback)


if __name__ == "__main__":
    unittest.main()
