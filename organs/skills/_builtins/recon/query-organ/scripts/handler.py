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
    organ_id = params.get("organ_id", "")
    if monster is None:
        return {"success": False, "error": "MonsterAgent 未注入"}
    if not organ_id:
        return {"success": False, "error": "缺少 organ_id 参数"}
    posture = monster.gather_global_posture()
    if organ_id not in posture:
        return {"success": False, "error": f"器官 {organ_id} 不存在，可用: {list(posture.keys())}"}
    return {"success": True, "result": {organ_id: posture[organ_id]}}
