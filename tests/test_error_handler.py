"""
错误处理模块单元测试
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestErrorHandler(unittest.TestCase):
    """测试全局错误处理工具"""

    def test_catch_all_decorator_sync(self):
        """catch_all 装饰器能捕获同步函数异常"""
        from utils.error_handler import catch_all

        @catch_all
        def failing_func():
            raise ValueError("test error")

        result = failing_func()
        self.assertIsNone(result)

    def test_catch_all_decorator_async(self):
        """catch_all 装饰器能捕获异步函数异常"""
        import asyncio
        from utils.error_handler import catch_all

        @catch_all
        async def failing_func():
            raise ValueError("test async error")

        result = asyncio.run(failing_func())
        self.assertIsNone(result)

    def test_safe_call_sync_fallback(self):
        """safe_call 通过 asyncio.run 能返回 fallback 值"""
        import asyncio
        from utils.error_handler import safe_call

        async def test():
            def failing():
                raise RuntimeError("fail")
            return await safe_call(failing, fallback_return="fallback")

        result = asyncio.run(test())
        self.assertEqual(result, "fallback")

    def test_safe_call_sync_success(self):
        """safe_call 通过 asyncio.run 能返回实际值"""
        import asyncio
        from utils.error_handler import safe_call

        async def test():
            def working():
                return "success"
            return await safe_call(working, fallback_return="fallback")

        result = asyncio.run(test())
        self.assertEqual(result, "success")

    def test_graceful_shutdown_register(self):
        """优雅关闭管理器注册回调"""
        import asyncio
        from utils.error_handler import graceful_shutdown

        calls = []
        graceful_shutdown.register("test", lambda: calls.append("called"))

        asyncio.run(graceful_shutdown.shutdown())
        self.assertIn("called", calls)


if __name__ == "__main__":
    unittest.main()
