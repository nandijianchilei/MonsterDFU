"""
日志系统单元测试
"""

import os
import sys
import logging
import unittest
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestLoggingConfig(unittest.TestCase):
    """测试标准化日志系统"""
    
    def test_get_logger_returns_logger(self):
        """get_logger 返回 Logger 实例"""
        from utils.logging_config import get_logger
        logger = get_logger("test_module")
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, "test_module")
    
    def test_get_logger_caches(self):
        """同一名称返回同一 logger"""
        from utils.logging_config import get_logger
        logger1 = get_logger("cache_test")
        logger2 = get_logger("cache_test")
        self.assertIs(logger1, logger2)
    
    def test_logger_has_handlers(self):
        """logger 创建后应有 handlers"""
        from utils.logging_config import get_logger
        logger = get_logger("handler_test")
        self.assertTrue(len(logger.handlers) >= 1)
    
    def test_logger_output(self):
        """logger 能正常输出且不抛出异常"""
        from utils.logging_config import get_logger
        logger = get_logger("output_test")
        try:
            logger.info("test info message")
            logger.warning("test warning")
            logger.error("test error")
        except Exception as e:
            self.fail(f"Logger raised exception: {e}")


if __name__ == "__main__":
    unittest.main()
