"""自动生成：技能 handler（DFU v2 内置技能）。"""
import time
from organs.skill_box import get_skill_env


def _safe_get_status(obj, default=None):
    try:
        return obj.get_status() if hasattr(obj, "get_status") else default
    except Exception:
        return default

# 可调动器官白名单（写死在代码里，防怪兽乱派活）
DISPATCHABLE_ORGANS = {
    "brain_left":    {"label": "左脑",      "task_desc": "防御分析/威胁研判"},
    "scanner_vuln":  {"label": "漏洞扫描",   "task_desc": "端口/漏洞扫描"},
    "ip_isolation":  {"label": "左手(隔离)", "task_desc": "IP 隔离执行"},
    "firewall":      {"label": "右手(封禁)", "task_desc": "防火墙规则下发"},
    "medic":         {"label": "修复手",     "task_desc": "健康检查/修复"},
    "whitelist":     {"label": "白名单",     "task_desc": "名单增删查"},
    "notifier":      {"label": "汇报嘴",     "task_desc": "发送通知/汇报"},
}


async def handler(params: dict) -> dict:
    """通过 MessageBus 派活给指定器官。"""
    env = get_skill_env()
    organ_id = params.get("organ_id", "")
    task = params.get("task", "")
    task_params = params.get("params", {}) or {}

    if organ_id not in DISPATCHABLE_ORGANS:
        return {"success": False,
                "error": f"器官 {organ_id} 不可被调动。可调动: {', '.join(DISPATCHABLE_ORGANS)}"}
    if not task:
        return {"success": False, "error": "缺少 task 参数"}

    bus = env.get("bus")
    if bus is None:
        return {"success": False, "error": "MessageBus 未注入"}
    from communication.message_bus import Message
    await bus.publish(Message(
        source="skill_toolbox",
        target=organ_id,
        type=f"dispatch_{task}",
        payload={
            **task_params,
            "request_id": f"dispatch_{int(time.time()*1000)}",
            "dispatcher": "monster",
        },
    ))
    label = DISPATCHABLE_ORGANS[organ_id]["label"]
    return {"success": True, "organ": organ_id, "task": task,
            "message": f"已调动{label}执行{task}，结果将通过事件总线回流"}
