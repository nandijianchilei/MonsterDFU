# -*- coding: utf-8 -*-
"""web/health.py — 健康检查端点（从原 web_server.py 拆分）。"""
import time
from typing import Optional

from fastapi.responses import JSONResponse

from core.countermeasure_fsm import FSMLevel

from web import state


def _get_fsm():
    m = state.get_manager()
    if m is None:
        return None
    return m.fsm if hasattr(m, "fsm") else None


async def healthz():
    """存活探针：进程是否运行。"""
    return {"status": "ok"}

async def readyz():
    """就绪探针：系统是否完成初始化并可以接受请求。"""
    if state.manager and state.manager._running:
        return {"status": "ready"}
    return JSONResponse({"status": "not_ready"}, status_code=503)


async def health_check():
    """健康检查端点——各组件存活状态"""
    health = {
        "status": "ok",
        "version": "0.1.0",
        "uptime": time.time() - state._server_start_time,
        "timestamp": time.time(),
        "components": {
            "web_server": {"status": "up"},
            "fsm": {"status": "unknown"},
            "event_bus": {"status": "unknown"},
        }
    }

    try:
        fsm = _get_fsm()
        if fsm:
            levels = fsm.get_all_levels()
            _LEVEL_ORDER = [
                FSMLevel.L0_MONITOR, FSMLevel.L1_SOFT, FSMLevel.L2_HARD,
                FSMLevel.L3_OFFENSIVE, FSMLevel.L4_ISOLATE,
            ]
            max_idx = 0
            for lv in levels.values():
                if lv in _LEVEL_ORDER:
                    idx = _LEVEL_ORDER.index(lv)
                    if idx > max_idx:
                        max_idx = idx
            health["components"]["fsm"] = {
                "status": "up",
                "level": _LEVEL_ORDER[max_idx],
                "managed_ips": len(levels),
            }
            health["components"]["event_bus"] = {"status": "up"}
    except Exception as e:
        health["components"]["fsm"] = {"status": "degraded", "error": str(e)}
        health["status"] = "degraded"

    return health


# ── 辅助函数 ──
