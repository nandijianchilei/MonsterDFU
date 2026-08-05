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
    bus = env.get("bus")
    target = str(params.get("target", "127.0.0.1")).strip()
    if target not in ("127.0.0.1", "::1"):
        return {"success": False, "error": "攻击模拟目标仅限本地回环 127.0.0.1/::1"}
    if manager is None or manager.simulator is None or bus is None:
        return {"success": False, "error": "模拟器未就绪"}
    packets = manager.simulator.generate_ddos()
    for p in packets[:200]:
        from communication.message_bus import Message
        await bus.publish(Message(source="SkillSimulator", target="TrafficMonitor",
                                  type="traffic_data", payload=p))
    return {"success": True, "result": {"packets": len(packets[:200]), "target": target,
            "chain": "报警鼻L2→L3升级 / L4闸门 / EventRecorder"},
            "message": f"已注入 {len(packets[:200])} 个 DDoS 模拟包（验证链路）"}
