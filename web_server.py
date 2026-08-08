"""
DFU Web 管理界面 — FastAPI 后端（模块化拆分版）

启动方式：
    python web_server.py              # 默认 http://localhost:8000
    python web_server.py --port 9000  # 自定义端口

模块结构（web/ 包）：
    web/auth.py            认证与 Token 分发（Bearer 单轨 / Bootstrap 首访保护 / SSRF 防护）
    web/manager.py         DFUWebManager 系统管理器
    web/pages.py           静态页面路由
    web/health.py          健康检查端点 /healthz /readyz /health
    web/metrics.py         Prometheus /metrics 与 SSE 指标流
    web/llm_config_api.py  LLM 配置 API（统一走 config.get_llm_config）
    web/organ_handlers.py  器官/怪兽/HITL/kill-switch/L4/攻击/对话/演示 API
    web/state.py           共享运行时状态

鉴权：统一 Bearer 单轨（Authorization: Bearer <token>）；/api/token 白名单仅限
      Bootstrap Key 首访换取。SSRF 防护：/api/chat 转发上游前逐跳复检
      （follow_redirects=False，301/302/303/307/308 最多 5 跳，_ssrf_check_url 复检）。
"""

import argparse
import os
import sys
import time
import webbrowser
from contextlib import asynccontextmanager

# 控制台中文乱码修复：强制 stdout/stderr 使用 UTF-8（桌面版 / 控制台均生效）
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 确保项目根目录在 sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
# PyInstaller 打包后，静态资源/规则文件位于 _MEIPASS 解压目录
_MEIPASS = getattr(sys, "_MEIPASS", None)
if _MEIPASS:
    PROJECT_ROOT = _MEIPASS
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import get_config
from dfuconfig import config

try:
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn
except ImportError:
    print("缺少依赖：pip install fastapi uvicorn sse-starlette")
    sys.exit(1)

# web 子模块（行为与原单文件 web_server.py 一致）
from web import state
from web.auth import (
    _API_TOKEN,  # noqa: F401  # re-export（tests 直接引用 web_server 符号）
    _AUTH_WHITELIST,  # noqa: F401
    _BOOTSTRAP_TOKEN,  # noqa: F401
    _check_auth,  # noqa: F401
    _extract_bearer_token,  # noqa: F401
    _is_token_expired,  # noqa: F401
    _ssrf_check_url,  # noqa: F401
    _validate_token,  # noqa: F401
    api_token,
    auth_middleware,
    verify_token,  # noqa: F401
)
from web.health import health_check, healthz, readyz
from web.llm_config_api import (
    api_get_llm_config,
    api_get_organ_llm_config,
    api_put_llm_config,
    api_put_organ_llm_config,
    api_test_llm,
)
from web.manager import DFUWebManager
from web.metrics import api_metrics, api_metrics_stream, prometheus_metrics
from web.organ_handlers import (
    alarm_nose_ack,
    alarm_nose_cancel,
    alarm_nose_confirm_l4,
    alarm_nose_status,
    api_attack,
    api_audit_events,
    api_chat,
    api_events_stream,
    api_forensic_timeline,
    api_hitl_approve,
    api_hitl_deny,
    api_hitl_pending,
    api_honeypot_event,
    api_kill_switch_get,
    api_kill_switch_set,
    api_meltdown_off,
    api_meltdown_on,
    api_outbound_connections,
    api_reset_token_usage,
    api_resources,
    api_stats,
    api_status,
    api_token_usage,
    api_vuln_ports,
    demo_scenarios,
    demo_trigger,
    dfu_organs_data,
    dfu_start,
    dfu_status,
    dfu_stop,
    get_events,
    l4_confirm,
    l4_reject,
    l4_status,
    monster_calls,
    monster_chat,
    monster_confirm,
    monster_posture,
    monster_skills,
    monster_skills_import,
    monster_skills_reload,
    monster_skills_toggle,
    monster_status,
)
from web.pages import compare_demo, index, live_demo, monster_demo
from utils.logger import init_global_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    init_global_logger(log_dir)
    # 仅创建管理器实例，不自动启动 DFU；由前端"启动 DFU"按钮通过 API 触发
    state.set_manager(DFUWebManager())
    yield
    mgr = state.get_manager()
    if mgr and mgr._running:
        await mgr.stop()


app = FastAPI(title="DFU 管理界面", version="1.0", lifespan=lifespan)

# ── CORS 中间件 ──
_CORS_ORIGINS = [o.strip() for o in os.environ.get("DFU_CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 安全认证中间件（Bearer 单轨 + 过期校验，白名单精确匹配）──
app.middleware("http")(auth_middleware)

# ── 静态页面 ──
app.get("/", response_class=HTMLResponse)(index)
app.get("/live", response_class=HTMLResponse)(live_demo)
app.get("/compare", response_class=HTMLResponse)(compare_demo)
app.get("/monster", response_class=HTMLResponse)(monster_demo)

# ── DFU 启停 API（供前端启动按钮 / 器官页调用，已加入白名单） ──
app.get("/api/dfu/status")(dfu_status)
app.post("/api/dfu/start")(dfu_start)
app.post("/api/dfu/stop")(dfu_stop)
app.get("/api/dfu/organs/data")(dfu_organs_data)

# ── 对话 / 状态 / Token 统计 ──
app.post("/api/chat")(api_chat)
app.get("/api/status")(api_status)
app.get("/api/token-usage")(api_token_usage)
app.post("/api/reset-token-usage")(api_reset_token_usage)
app.get("/api/stats")(api_stats)

# ── 攻击 / 蜜罐 / 熔断 / kill-switch ──
app.post("/api/attack")(api_attack)
app.post("/api/honeypot/event")(api_honeypot_event)
app.post("/api/meltdown/on")(api_meltdown_on)
app.post("/api/meltdown/off")(api_meltdown_off)
app.get("/api/kill-switch")(api_kill_switch_get)
app.post("/api/kill-switch")(api_kill_switch_set)

# ── HITL / L4 / 报警鼻 ──
app.get("/api/hitl/pending")(api_hitl_pending)
app.post("/api/hitl/approve")(api_hitl_approve)
app.post("/api/hitl/deny")(api_hitl_deny)
app.post("/api/l4/confirm")(l4_confirm)
app.post("/api/l4/reject")(l4_reject)
app.get("/api/l4/status")(l4_status)
app.get("/api/alarm-nose/status")(alarm_nose_status)
app.post("/api/alarm-nose/ack")(alarm_nose_ack)
app.post("/api/alarm-nose/cancel")(alarm_nose_cancel)
app.post("/api/alarm-nose/confirm-l4")(alarm_nose_confirm_l4)

# ── Token 分发（白名单，首访保护） / LLM 配置 ──
app.get("/api/token")(api_token)
app.get("/api/config/llm")(api_get_llm_config)
app.put("/api/config/llm")(api_put_llm_config)
app.get("/api/config/llm/organs")(api_get_organ_llm_config)
app.put("/api/config/llm/organs")(api_put_organ_llm_config)
app.post("/api/llm/test")(api_test_llm)

# ── 健康检查（白名单） ──
app.get("/healthz")(healthz)
app.get("/readyz")(readyz)
app.get("/health")(health_check)

# ── 怪兽 ──
app.post("/api/monster/chat")(monster_chat)
app.post("/api/monster/confirm")(monster_confirm)
app.get("/api/monster/posture")(monster_posture)
app.get("/api/monster/skills")(monster_skills)
app.post("/api/monster/skills/toggle")(monster_skills_toggle)
app.get("/api/monster/calls")(monster_calls)
app.get("/api/monster/status")(monster_status)
app.post("/api/monster/skills/reload")(monster_skills_reload)
app.post("/api/monster/skills/import")(monster_skills_import)

# ── 演示模式 / 事件 / 取证 / 监控数据 ──
app.post("/api/demo/trigger")(demo_trigger)
app.get("/api/demo/scenarios")(demo_scenarios)
app.get("/api/events")(get_events)
app.get("/api/forensic/timeline")(api_forensic_timeline)
app.get("/api/vuln/ports")(api_vuln_ports)
app.get("/api/outbound/connections")(api_outbound_connections)
app.get("/api/audit/events")(api_audit_events)
app.get("/api/resources")(api_resources)
app.get("/api/events/stream")(api_events_stream)

# ── 指标（Prometheus） ──
app.get("/api/metrics")(api_metrics)
app.get("/metrics")(prometheus_metrics)
app.get("/api/metrics/stream")(api_metrics_stream)


# ── 全局异常处理器 ──
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """全局未捕获异常处理"""
    from utils.logging_config import get_logger as _log
    _log("web_server").error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": str(exc) if (config.get("logging", "level") == "DEBUG") else "An unexpected error occurred"
        }
    )


# ==================== 启动入口 ====================

def main():
    parser = argparse.ArgumentParser(description="DFU Web 管理界面")
    default_port = get_config().web_port
    parser.add_argument("--port", type=int, default=default_port, help=f"监听端口（默认 {default_port}）")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args()

    url = f"http://localhost:{args.port}"

    if not args.no_browser:
        # 延迟打开浏览器，给 uvicorn 启动时间
        def _open_browser():
            time.sleep(1.5)
            webbrowser.open(url)
        import threading
        threading.Thread(target=_open_browser, daemon=True).start()

    print("\n  DFU Web 管理界面")
    print(f"  地址: {url}")
    print("  按 Ctrl+C 停止\n")

    uvicorn.run(
        app,
        host=os.environ.get("DFU_WEB_HOST", "127.0.0.1"),
        port=args.port,
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
