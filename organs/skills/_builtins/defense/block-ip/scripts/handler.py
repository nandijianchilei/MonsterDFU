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
    ip = str(params.get("ip", "")).strip()
    reason = str(params.get("reason", "monster dispatch"))[:200]
    if not ip:
        return {"success": False, "error": "缺少 ip 参数"}
    if manager is None or firewall is None:
        return {"success": False, "error": "执行组件未注入"}
    # 白名单前置检查（安全约束 #6）
    protected = set(env.get("protected_ips", []) or [])
    if ip in protected:
        return {"success": False, "error": f"目标 {ip} 在受保护名单内，拒绝封锁"}
    blacklist = manager.ip_isolation.get_blacklist() if manager.ip_isolation else []
    if ip in blacklist:
        return {"success": False, "error": f"{ip} 已在黑名单中"}
    result = await firewall.block_ip(ip, reason=reason)
    try:
        manager._skill_blocked_ips.add(ip)
    except Exception:
        pass
    return {"success": True, "result": {"ip": ip, "blocked": True,
            "detail": str(result)}, "message": f"已封锁 {ip}"}
