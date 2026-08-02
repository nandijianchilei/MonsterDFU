"""
配置系统单元测试
"""

import os
import sys
import tempfile
import unittest

# 添加项目根目录到 sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestDfuConfigSystem(unittest.TestCase):
    """测试新配置加载系统 (dfuconfig/)"""
    
    def setUp(self):
        # 清除环境变量污染
        for key in list(os.environ.keys()):
            if key.startswith("DFU_"):
                del os.environ[key]
    
    def test_default_config_loads(self):
        """默认配置能正常加载"""
        from dfuconfig import config
        self.assertIsNotNone(config.get("server", "port"))
        self.assertEqual(config.get("server", "port"), 8000)
        self.assertEqual(config.get("auth", "api_token"), "dfu-default-token-change-me")
    
    def test_env_override(self):
        """环境变量能覆盖配置（__ 为层级分隔符）"""
        os.environ["DFU_SERVER__PORT"] = "9090"
        os.environ["DFU_AUTH__API_TOKEN"] = "test-token-123"

        from dfuconfig import config
        config.reload()

        self.assertEqual(config.get("server", "port"), 9090)
        self.assertEqual(config.get("auth", "api_token"), "test-token-123")

    def test_env_boolean_parsing(self):
        """环境变量布尔值解析"""
        os.environ["DFU_LLM__MOCK_MODE"] = "false"
        from dfuconfig import config
        config.reload()
        self.assertIs(config.get("llm", "mock_mode"), False)

        os.environ["DFU_LLM__MOCK_MODE"] = "true"
        config.reload()
        self.assertIs(config.get("llm", "mock_mode"), True)

    def test_env_int_parsing(self):
        """环境变量整型解析（复合键名保持单下划线）"""
        os.environ["DFU_DETECTION__OUTBOUND_MONITOR__POLL_INTERVAL_MS"] = "5000"
        from dfuconfig import config
        config.reload()
        self.assertEqual(config.get("detection.outbound_monitor.poll_interval_ms"), 5000)
    
    def test_config_contains(self):
        """__contains__ 操作"""
        from dfuconfig import config
        self.assertIn("server", config)
        self.assertNotIn("nonexistent_section", config)
    
    def test_get_with_default(self):
        """带默认值的 get"""
        from dfuconfig import config
        val = config.get("nonexistent.path", default="fallback")
        self.assertEqual(val, "fallback")


if __name__ == "__main__":
    unittest.main()
