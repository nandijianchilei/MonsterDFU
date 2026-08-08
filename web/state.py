# -*- coding: utf-8 -*-
"""web/state.py — web 包共享运行时状态（从原 web_server.py 拆分）。"""
import time
from typing import Any, Dict, List, Optional

# 服务器启动时间戳（健康检查用）
_server_start_time = time.time()

# DFUWebManager 单例（由 web_server lifespan 创建）
manager: Optional["DFUWebManager"] = None


def get_manager():
    return manager


def set_manager(m):
    global manager
    manager = m


# Live Demo SSE 全局事件队列与历史
_event_queues: list = []
_event_history: list = []

# kill-switch / HITL 全局状态
_KILL_SWITCH_ON = False
_HITL_PENDING: Dict[str, Dict[str, Any]] = {}
_HITL_COUNTER = 0
