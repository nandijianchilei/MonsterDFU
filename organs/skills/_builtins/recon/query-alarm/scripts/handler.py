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
    if manager is None or manager.alarm_nose is None:
        return {"success": False, "error": "报警鼻未就绪"}
    status = _safe_get_status(manager.alarm_nose, {})
    return {"success": True, "result": status}
