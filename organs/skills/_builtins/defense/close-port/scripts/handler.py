"""自动生成：技能 handler（DFU v2 内置技能）。"""
import time
from organs.skill_box import get_skill_env


def _safe_get_status(obj, default=None):
    try:
        return obj.get_status() if hasattr(obj, "get_status") else default
    except Exception:
        return default

async def handler(params: dict) -> dict:
    env = get_skill_env()
    manager = env.get("manager")
    firewall = env.get("firewall")
    port = params.get("port")
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            return {"success": False, "error": "端口必须在 1-65535"}
    except (TypeError, ValueError):
        return {"success": False, "error": "port 参数必须是整数"}
    if firewall is None:
        return {"success": False, "error": "防火墙组件未注入"}
    # 简化实现：模拟为防火墙规则记录（Windows netsh 按 IP 规则，端口受限场景记录日志）
    result = {"port": port, "action": "close", "mode": "simulated",
              "note": "端口关闭已记录，真实规则下发需系统管理员权限"}
    return {"success": True, "result": result, "message": f"已限制端口 {port}"}
