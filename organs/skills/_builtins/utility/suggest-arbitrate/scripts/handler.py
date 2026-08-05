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
    monster = env.get("monster")
    if monster is None:
        return {"success": False, "error": "MonsterAgent 未注入"}
    left_advice = params.get("left_advice")
    right_advice = params.get("right_advice")
    verdict = monster.arbitrate(left_advice, right_advice)
    return {"success": True, "result": verdict if verdict else
            {"message": "无冲突建议输入，请提供 left_advice/right_advice"}}
