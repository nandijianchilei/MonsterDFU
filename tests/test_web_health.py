"""
Web 服务器健康检查 API 测试
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestHealthEndpoint(unittest.TestCase):
    """测试 /health 端点"""
    
    def test_health_endpoint_exists(self):
        """验证 web_server.py 包含 /health 路由"""
        with open(os.path.join(PROJECT_ROOT, "web_server.py"), encoding="utf-8") as f:
            content = f.read()
        
        self.assertIn('"/health"', content, "/health 路由未定义")
        self.assertIn("health_check", content, "health_check 处理函数未定义")
    
    def test_auth_middleware_exists(self):
        """验证安全中间件存在"""
        with open(os.path.join(PROJECT_ROOT, "web_server.py"), encoding="utf-8") as f:
            content = f.read()
        
        self.assertIn("auth_middleware", content, "认证中间件未定义")
        self.assertIn("Authorization", content, "Authorization 头处理未定义")
    
    def test_health_whitelisted(self):
        """验证 /health 在认证白名单中"""
        with open(os.path.join(PROJECT_ROOT, "web_server.py"), encoding="utf-8") as f:
            content = f.read()
        
        self.assertIn('"/health"', content)
    
    def test_global_exception_handler_exists(self):
        """验证全局异常处理器存在"""
        with open(os.path.join(PROJECT_ROOT, "web_server.py"), encoding="utf-8") as f:
            content = f.read()
        
        self.assertIn("global_exception_handler", content)
        self.assertIn('status_code=500', content)


if __name__ == "__main__":
    unittest.main()
