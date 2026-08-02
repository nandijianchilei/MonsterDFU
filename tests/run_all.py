#!/usr/bin/env python3
"""
DFU 测试套件入口 —— 运行所有单元测试

用法：
    python tests/run_all.py          # 全部测试
    python tests/run_all.py -v       # 详细输出
    python tests/run_all.py Config   # 仅运行配置测试
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def run_tests(pattern: str = "test_*.py", verbosity: int = 1):
    """发现并运行测试"""
    loader = unittest.TestLoader()
    suite = loader.discover(TEST_DIR, pattern=pattern)
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    verbosity = 2 if "-v" in sys.argv else 1
    
    # 如果指定了模块名，只运行该模块
    specific_tests = [a for a in sys.argv[1:] if not a.startswith("-")]
    if specific_tests:
        pattern = f"test_{specific_tests[0].lower()}.py"
        success = run_tests(pattern=pattern, verbosity=verbosity)
    else:
        success = run_tests(verbosity=verbosity)
    
    sys.exit(0 if success else 1)
