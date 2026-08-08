# -*- coding: utf-8 -*-
"""web/pages.py — 静态页面路由（从原 web_server.py 拆分）。"""
import os
import sys
from pathlib import Path

from fastapi.responses import HTMLResponse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # web/ 上级 = 项目根
if getattr(sys, "_MEIPASS", None):
    PROJECT_ROOT = sys._MEIPASS
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")


async def index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("<h1>index.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


async def live_demo():
    """Live Demo 攻击演示大屏"""
    live_path = os.path.join(STATIC_DIR, "live.html")
    if not os.path.exists(live_path):
        return HTMLResponse("<h1>live.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    live_html = Path(live_path).read_text(encoding="utf-8")
    return HTMLResponse(content=live_html)


async def compare_demo():
    """对比演示页: 无DFU防护 vs 有DFU防护"""
    compare_path = os.path.join(STATIC_DIR, "compare.html")
    if not os.path.exists(compare_path):
        return HTMLResponse("<h1>compare.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    compare_html = Path(compare_path).read_text(encoding="utf-8")
    return HTMLResponse(content=compare_html)


async def monster_demo():
    """MonsterDFU 小怪兽前端 UI（单文件 SPA）"""
    monster_path = os.path.join(STATIC_DIR, "monster.html")
    if not os.path.exists(monster_path):
        return HTMLResponse("<h1>monster.html 未找到，请确认 static/ 目录存在</h1>", status_code=404)
    monster_html = Path(monster_path).read_text(encoding="utf-8")
    return HTMLResponse(content=monster_html)
