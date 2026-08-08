"""
安全回归测试：Bootstrap 鉴权 / SSRF 校验 / Bearer Token 解析 / 白名单精确匹配。

覆盖 web_server.py 本批安全修复：
- P0-1  /api/token 首访保护（X-Bootstrap-Token）
- P0-2  Bearer 单轨解析（_extract_bearer_token，禁止裸 token / 错误 scheme）
- P1-5  SSRF 防护（_resolve_host_safe / _ssrf_check_url：私有/回环/链路本地/元数据/字面量）
- P1-6  白名单精确匹配（/api/token-usage 不被 /api/token 前缀连带放行）

测试风格：pytest + 直接 import 模块，不启动真实网络服务。
"""

import asyncio
import os
import sys
import unittest
from types import SimpleNamespace

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import web_server as ws


class TestBootstrapTokenAuth(unittest.TestCase):
    """/api/token 首访保护：无 / 错误 Bootstrap Key -> 401，正确 -> 200 Bearer。"""

    def _req(self, headers=None):
        return SimpleNamespace(headers=headers or {})

    def _call(self, request, bootstrap=None):
        return asyncio.run(ws.api_token(request, bootstrap))

    def test_missing_bootstrap_header_401(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self._call(self._req({}))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_wrong_bootstrap_header_401(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self._call(self._req({"X-Bootstrap-Token": "wrong-key"}))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_wrong_bootstrap_query_401(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self._call(self._req({}), bootstrap="wrong-key")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_correct_bootstrap_header_returns_bearer(self):
        result = self._call(self._req({"X-Bootstrap-Token": ws._BOOTSTRAP_TOKEN}))
        self.assertTrue(result.get("token"))
        self.assertEqual(result.get("header"), "Authorization")
        self.assertEqual(result.get("scheme"), "Bearer")

    def test_correct_bootstrap_query_returns_bearer(self):
        result = self._call(self._req({}), bootstrap=ws._BOOTSTRAP_TOKEN)
        self.assertTrue(result.get("token"))
        self.assertEqual(result.get("scheme"), "Bearer")


class TestExtractBearerToken(unittest.TestCase):
    """"统一 Bearer 解析：仅接受 'Bearer ' scheme，禁止裸 token / 错误 scheme。"""

    def _req(self, auth=None):
        headers = {}
        if auth is not None:
            headers["Authorization"] = auth
        return SimpleNamespace(headers=headers)

    def test_accept_bearer(self):
        self.assertEqual(ws._extract_bearer_token(self._req("Bearer abc123")), "abc123")

    def test_accept_bearer_case_insensitive(self):
        self.assertEqual(ws._extract_bearer_token(self._req("bearer abc123")), "abc123")

    def test_reject_bare_token(self):
        self.assertEqual(ws._extract_bearer_token(self._req("abc123")), "")

    def test_reject_wrong_scheme(self):
        self.assertEqual(ws._extract_bearer_token(self._req("Basic abc123")), "")

    def test_reject_missing_header(self):
        self.assertEqual(ws._extract_bearer_token(self._req()), "")

    def test_reject_scheme_without_token(self):
        self.assertEqual(ws._extract_bearer_token(self._req("Bearer")), "")


class TestSSRFProtection(unittest.TestCase):
    """"SSRF 防护：拒绝私有/回环/链路本地/云元数据/字面量地址，允许公网。"""

    def _err(self, url):
        return ws._ssrf_check_url(url)

    def test_reject_loopback(self):
        self.assertIsNotNone(self._err("http://127.0.0.1/"))
        self.assertIsNotNone(self._err("http://localhost/"))
        self.assertIsNotNone(self._err("http://[::1]/"))

    def test_reject_private(self):
        self.assertIsNotNone(self._err("http://10.0.0.1/"))
        self.assertIsNotNone(self._err("http://192.168.1.1/"))
        self.assertIsNotNone(self._err("http://172.16.0.1/"))

    def test_reject_cloud_metadata(self):
        self.assertIsNotNone(self._err("http://169.254.169.254/latest/meta-data/"))

    def test_reject_link_local(self):
        self.assertIsNotNone(self._err("http://169.254.1.1/"))

    def test_reject_integer_literal(self):
        # 2130706433 == 127.0.0.1（能解析则按回环拒绝；不能解析则按无法解析拒绝）
        self.assertIsNotNone(self._err("http://2130706433/"))

    def test_reject_hex_literal(self):
        # 0x7f000001 == 127.0.0.1
        self.assertIsNotNone(self._err("http://0x7f000001/"))

    def test_allow_public_address(self):
        self.assertIsNone(self._err("http://8.8.8.8/"))

    def test_reject_url_without_host(self):
        self.assertIsNotNone(self._err("http:///"))
        self.assertIsNotNone(self._err("not-a-url"))

    def test_redirect_recheck_contract_in_source(self):
        """重定向逐跳 SSRF 复检契约（最多 5 跳）：不跟随重定向 + 逐跳复检。

        api_chat 已随 web_server 拆分迁移至 web/organ_handlers.py，
        契约源码检查同步指向该模块。
        """
        with open(os.path.join(PROJECT_ROOT, "web", "organ_handlers.py"), encoding="utf-8") as f:
            content = f.read()
        self.assertIn("follow_redirects=False", content)
        self.assertIn("301, 302, 303, 307, 308", content)
        # 重定向循环内必须调用 _ssrf_check_url 复检新 URL
        self.assertIn("_ssrf_check_url(url)", content)


class TestWhitelistExactMatch(unittest.TestCase):
    """"白名单精确匹配：/api/token-usage 不再被 /api/token 前缀连带放行。"""

    def _call_middleware(self, path, headers=None):
        req = SimpleNamespace(url=SimpleNamespace(path=path), headers=headers or {})

        async def call_next(request):
            return "PASSED"

        return asyncio.run(ws.auth_middleware(req, call_next))

    def test_token_endpoint_in_whitelist(self):
        self.assertIn("/api/token", ws._AUTH_WHITELIST)

    def test_token_usage_not_in_whitelist(self):
        self.assertNotIn("/api/token-usage", ws._AUTH_WHITELIST)

    def test_token_usage_without_token_401(self):
        resp = self._call_middleware("/api/token-usage")
        self.assertEqual(resp.status_code, 401)

    def test_token_endpoint_passes_through(self):
        self.assertEqual(self._call_middleware("/api/token"), "PASSED")

    def test_api_requires_valid_bearer(self):
        resp = self._call_middleware("/api/status")
        self.assertEqual(resp.status_code, 401)

    def test_api_with_valid_bearer_passes(self):
        resp = self._call_middleware("/api/status", {"Authorization": f"Bearer {ws._API_TOKEN}"})
        self.assertEqual(resp, "PASSED")


if __name__ == "__main__":
    unittest.main()
