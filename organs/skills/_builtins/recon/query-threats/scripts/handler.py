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
    if manager is None:
        return {"success": False, "error": "DFUWebManager 未注入"}
    limit = int(params.get("limit", 10))
    events = manager.get_recent_events(limit=limit)
    threats = [e for e in events if e.get("stage") in ("observe", "attack", "left", "right")]
    return {"success": True, "result": {"count": len(threats), "events": threats[:limit]}}
