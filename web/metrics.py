# -*- coding: utf-8 -*-
"""web/metrics.py — 监控指标 API（从原 web_server.py 拆分）。"""
import asyncio
import json

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from web import state
from web.auth import _check_auth


async def _empty_generator():
    yield ": no manager\n\n"


async def api_metrics():
    """返回当前全部监控指标的 JSON 快照。"""
    if not state.manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return state.manager.metrics.get_metrics()


async def prometheus_metrics(request: Request):
    """Prometheus 标准 /metrics 端点。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")
    from prometheus_client import generate_latest, CollectorRegistry, Gauge

    if not state.manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)

    data = state.manager.metrics.get_metrics()
    registry = CollectorRegistry()

    # 系统资源
    Gauge("dfu_cpu_percent", "CPU 使用率(%)", registry=registry).set(data.get("cpu_percent", -1))
    Gauge("dfu_memory_percent", "内存使用率(%)", registry=registry).set(data.get("memory_percent", -1))

    # LLM 调用
    Gauge("dfu_llm_calls_total", "LLM 总调用次数", registry=registry).set(data.get("llm_calls", 0))
    Gauge("dfu_llm_success_total", "LLM 成功调用次数", registry=registry).set(data.get("llm_success", 0))
    Gauge("dfu_llm_failed_total", "LLM 失败调用次数", registry=registry).set(data.get("llm_failed", 0))
    Gauge("dfu_llm_avg_latency_ms", "LLM 平均延迟(ms)", registry=registry).set(data.get("llm_avg_latency_ms", 0))

    # 知识库
    Gauge("dfu_kb_hits_total", "知识库命中次数", registry=registry).set(data.get("kb_hits", 0))
    Gauge("dfu_kb_misses_total", "知识库未命中次数", registry=registry).set(data.get("kb_misses", 0))
    Gauge("dfu_kb_hit_rate", "知识库命中率(%)", registry=registry).set(data.get("kb_hit_rate", 0))

    # 感知模块吞吐量
    throughput = data.get("org_throughput", {})
    for organ_name, count in throughput.items():
        Gauge(f"dfu_organ_{organ_name}_total", f"器官 {organ_name} 处理次数", registry=registry).set(count)

    return Response(generate_latest(registry), media_type="text/plain; version=0.0.4")


async def api_metrics_stream():
    """SSE 流，每 2 秒推送一次最新监控指标。"""
    if not state.manager:
        return StreamingResponse(
            _empty_generator(),
            media_type="text/event-stream",
        )

    async def metrics_generator():
        while state.manager and state.manager._running:
            try:
                data = state.manager.metrics.get_metrics()
                yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            except Exception:
                yield ": error\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(
        metrics_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
