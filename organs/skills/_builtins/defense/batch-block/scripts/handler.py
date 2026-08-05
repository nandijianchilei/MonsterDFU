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
    ips = params.get("ips", []) or []
    if not isinstance(ips, list) or not ips:
        return {"success": False, "error": "ips 参数必须是 IP 列表"}
    if len(ips) > 100:
        return {"success": False, "error": f"批量操作单次上限 100 项，当前 {len(ips)} 项"}
    if firewall is None or manager is None:
        return {"success": False, "error": "执行组件未注入"}
    protected = set(env.get("protected_ips", []) or [])
    skipped, blocked = [], []
    for ip in ips:
        ip = str(ip).strip()
        if not ip:
            continue
        if ip in protected:
            skipped.append({"ip": ip, "reason": "protected"})
            continue
        try:
            await firewall.block_ip(ip, reason="monster batch block")
            blocked.append(ip)
        except Exception as e:
            skipped.append({"ip": ip, "reason": str(e)})
    try:
        manager._skill_blocked_ips.update(blocked)
    except Exception:
        pass
    return {"success": True, "result": {"blocked": blocked, "skipped": skipped,
            "count": len(blocked)}, "message": f"已封锁 {len(blocked)} 个 IP"}
