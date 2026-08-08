# -*- coding: utf-8 -*-
"""web/organ_handlers.py — 器官/怪兽/HITL/kill-switch/L4/攻击 API（从原 web_server.py 拆分）。"""
import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import httpx
from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from communication.message_bus import Message, get_message_bus

from web import state
from web.auth import _check_auth, _ssrf_check_url, verify_token
from web.metrics import _empty_generator


def kill_switch_enabled() -> bool:
    """全局熔断是否开启（供输出护栏 / L4 三闸门协同调用）。"""
    return state._KILL_SWITCH_ON


def _submit_hitl(action: Dict[str, Any]) -> str:
    """将护栏降级的高危处置提交到 HITL 待确认队列，返回请求 ID。"""
    state._HITL_COUNTER += 1
    req_id = f"hitl_{state._HITL_COUNTER}"
    state._HITL_PENDING[req_id] = {**action, "id": req_id, "status": "pending"}
    return req_id


async def api_attack(request: Request, _auth=Depends(verify_token)):
    if not state.manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    body = await request.json()
    scenario = body.get("scenario", "all")
    result = await state.manager.run_attack(scenario)
    return result


async def api_honeypot_event(request: Request, _auth=Depends(verify_token)):
    """接收蜜罐上报的攻击事件，注入 DFU 检测→决策→处置管道。"""
    if not state.manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    if state.manager._meltdown:
        return JSONResponse({"error": "系统熔断中"}, status_code=503)

    body = await request.json()
    raw_category = body.get("category", "unknown")
    severity = body.get("severity", "medium")
    src_ip = body.get("src_ip", "0.0.0.0")
    src_port = body.get("src_port", 0)
    payload_preview = body.get("payload_preview", "")

    # 蜜罐分类 → DFU ThreatCategory 映射
    _HP_TO_DFU = {
        "web_scan": "port_scan", "web_attack": "port_scan",
        "ssh_brute": "brute_force", "ftp_brute": "brute_force",
        "smtp_scan": "port_scan", "rdp_scan": "port_scan",
        "db_scan": "port_scan", "ssl_scan": "port_scan",
        "tls_scan": "port_scan", "port_knock": "unknown",
        "unknown_probe": "unknown",
    }
    dfu_category = _HP_TO_DFU.get(raw_category, "unknown")

    alert = Message(
        source="Honeypot",
        target="TrafficMonitor",
        type="threat_alert",
        payload={
            "id": f"hp-{int(time.time())}-{src_ip.replace('.', '_')}",
            "category": dfu_category,
            "severity": severity,
            "source_ip": src_ip,
            "source_port": src_port,
            "target_ip": src_ip,
            "target_port": body.get("dst_port", 2222),
            "description": f"蜜罐捕获 {raw_category}: {payload_preview[:80]}",
            "raw_payload": payload_preview,
        },
    )
    await state.manager.bus.publish(alert)
    return {"success": True, "alert_id": alert.payload["id"]}


async def api_meltdown_on(_auth=Depends(verify_token)):
    if not state.manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return await state.manager.meltdown_on()


async def api_meltdown_off(_auth=Depends(verify_token)):
    if not state.manager:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return await state.manager.meltdown_off()


async def api_kill_switch_get(_auth=Depends(verify_token)):
    """查询 kill-switch 状态。"""
    return {"kill_switch": state._KILL_SWITCH_ON}


async def api_kill_switch_set(request: Request, _auth=Depends(verify_token)):
    """开关 kill-switch：开启后熔断所有自动处置，仅保留告警与 HITL 通道。"""
    body = await request.json()
    on = bool(body.get("on", False))
    state._KILL_SWITCH_ON = on
    state_desc = "开启" if on else "关闭"

    # 联动 FSM：熔断开启时禁止任何自动升级（evaluate 保持当前等级，仅告警）
    mgr = state.get_manager()
    fsm = mgr.fsm if hasattr(mgr, "fsm") else None
    if fsm is not None:
        fsm.set_enabled(not on)

    # 发布 kill_switch 总线事件：干扰层（InterferenceAgent）订阅后强制停用
    await get_message_bus().publish(Message(
        source="web_server",
        target="*",
        type="kill_switch",
        payload={"type": "kill_switch", "on": on},
    ))

    print(f"[KillSwitch] {state_desc}全局熔断")
    return {
        "status": "ok",
        "kill_switch": state._KILL_SWITCH_ON,
        "message": f"全局熔断已{state_desc}，自动处置已{'熔断' if on else '恢复'}",
    }


async def api_hitl_pending(_auth=Depends(verify_token)):
    """列出待人工确认的高危处置动作。"""
    return {"pending": list(state._HITL_PENDING.values())}


async def api_hitl_approve(request: Request, _auth=Depends(verify_token)):
    """人工批准某个被护栏降级的高危处置，恢复并放行执行。"""
    body = await request.json()
    req_id = str(body.get("id", ""))
    if not req_id or req_id not in state._HITL_PENDING:
        raise HTTPException(status_code=404, detail="待确认项不存在或已处理")
    item = state._HITL_PENDING.pop(req_id)
    item["approved"] = True
    # 放行动作：恢复降级前的 original_action（若存在）
    item["executed_action"] = item.get("original_action", item.get("action"))
    print(f"[HITL] 人工批准处置: {item.get('executed_action')} (id={req_id})")
    return {"status": "ok", "approved": True, "item": item}


async def api_hitl_deny(request: Request, _auth=Depends(verify_token)):
    """人工拒绝某个待确认处置，丢弃该动作。"""
    body = await request.json()
    req_id = str(body.get("id", ""))
    if not req_id or req_id not in state._HITL_PENDING:
        raise HTTPException(status_code=404, detail="待确认项不存在或已处理")
    item = state._HITL_PENDING.pop(req_id)
    item["approved"] = False
    print(f"[HITL] 人工拒绝处置: {item.get('original_action', item.get('action'))} (id={req_id})")
    return {"status": "ok", "approved": False, "item": item}


# ── L4 网络隔离确认 API（Phase 1.5）──


async def l4_confirm(request: Request):
    """
    Web 面板确认 L4 网络隔离（需 Token 认证）。
    调用 CountermeasureFSM.set_web_panel_confirmed(ip, True)
    三元组：确认后闸门3关闭，L4 自动降级回 L3。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    body = await request.json()
    source_ip = body.get("source_ip", "")
    if not source_ip:
        raise HTTPException(status_code=400, detail="缺少 source_ip 参数")

    mgr = state.get_manager()
    fsm = mgr.fsm if hasattr(mgr, 'fsm') else None
    if fsm is None:
        raise HTTPException(status_code=503, detail="FSM 未就绪")

    fsm.set_web_panel_confirmed(source_ip, True)
    return {
        "status": "ok",
        "action": "l4_confirmed",
        "source_ip": source_ip,
        "message": f"L4 隔离已确认，{source_ip} 将自动降级回 L3"
    }


async def l4_reject(request: Request):
    """
    Web 面板拒绝 L4 网络隔离（取消确认，保持 L4 状态）。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    body = await request.json()
    source_ip = body.get("source_ip", "")
    if not source_ip:
        raise HTTPException(status_code=400, detail="缺少 source_ip 参数")

    mgr = state.get_manager()
    fsm = mgr.fsm if hasattr(mgr, 'fsm') else None
    if fsm is None:
        raise HTTPException(status_code=503, detail="FSM 未就绪")

    # 拒绝确认 → 保持 L4，不清除确认态（仍可后续确认）
    return {
        "status": "ok",
        "action": "l4_rejected",
        "source_ip": source_ip,
        "message": f"L4 隔离保持，请继续监控 {source_ip}"
    }


async def l4_status(request: Request):
    """
    获取 L4 状态概览：活跃 L4 IP 列表 + 三闸门状态。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    mgr = state.get_manager()
    fsm = mgr.fsm if hasattr(mgr, 'fsm') else None
    if fsm is None:
        return {"l4_active": [], "l4_count": 0, "fsm_available": False}

    all_levels = fsm.get_all_levels()
    l4_ips = {ip: level for ip, level in all_levels.items() if level == "L4-isolate"}

    l4_details = []
    for ip in l4_ips:
        fsm_state = fsm._states.get(ip)
        if fsm_state:
            now = time.time()
            passed, reason = fsm_state.check_l4_triple_gate(now)
            l4_details.append({
                "ip": ip,
                "level": fsm_state.level,
                "vuln_errors": fsm_state.vuln_error_count,
                "l3_unstoppable": (now - fsm_state.l3_unstoppable_since) if fsm_state.l3_unstoppable_since else 0,
                "web_confirmed": fsm_state.web_panel_confirmed,
                "triple_gate_passed": passed,
                "gate_reason": reason,
            })

    return {
        "l4_active": l4_details,
        "l4_count": len(l4_details),
        "fsm_summary": fsm.summary(),
        "fsm_available": True,
    }


# ── 报警鼻 4 级警报 API（Phase 2）──


async def alarm_nose_status(request: Request):
    """报警鼻实时状态：等级 / 倒计时 / 4 级告警历史（需 Token 认证）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    mgr = state.get_manager()
    if mgr is None or mgr.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    return mgr.alarm_nose.get_status()


async def alarm_nose_ack(request: Request):
    """人工确认当前警报（停止倒计时，解除警报，回到 L1 记录态）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    mgr = state.get_manager()
    if mgr is None or mgr.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    result = await mgr.alarm_nose.manual_ack()
    return {"status": "ok", **result}


async def alarm_nose_cancel(request: Request):
    """人工取消当前警报（停止倒计时，取消自动升级，回到 L1 记录态）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    mgr = state.get_manager()
    if mgr is None or mgr.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    result = await mgr.alarm_nose.manual_cancel()
    return {"status": "ok", **result}


async def alarm_nose_confirm_l4(request: Request):
    """人工确认执行 L4：立即触发软隔离信号（复用 FSM 机制，不物理断网）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权：需要有效的 API Token")

    mgr = state.get_manager()
    if mgr is None or mgr.alarm_nose is None:
        raise HTTPException(status_code=503, detail="报警鼻未初始化")
    result = await mgr.alarm_nose.confirm_l4()
    if not result.get("success"):
        return JSONResponse(status_code=400, content={"status": "error", **result})
    return {"status": "ok", **result}


# ── Token 分发端点（前端启动时获取 token 注入请求头）──


async def monster_chat(request: Request):
    """小怪兽对话接口（mock 确定性决策 / 真实 ReAct 循环）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")
    m = state.get_manager()
    if m is None or m.monster is None:
        raise HTTPException(status_code=503, detail="MonsterAgent 未初始化")
    body = await request.json()
    message = (body.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message 不能为空")
    result = await m.monster.chat(message, caller="user")
    return {"status": "ok", "result": result}


async def monster_confirm(request: Request):
    """高危技能确认/取消。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")
    m = state.get_manager()
    if m is None or m.skill_toolbox is None:
        raise HTTPException(status_code=503, detail="SkillToolbox 未初始化")
    body = await request.json()
    token = (body.get("confirm_token") or "").strip()
    approved = bool(body.get("approved", True))
    if not token:
        raise HTTPException(status_code=400, detail="confirm_token 不能为空")
    result = await m.skill_toolbox.confirm(token, approved=approved, caller="user")
    return {"status": "ok", "result": result}


async def monster_posture(force: bool = False):
    """获取小怪兽全局态势（12 器官）。"""
    m = state.get_manager()
    if m is None or m.monster is None:
        raise HTTPException(status_code=503, detail="MonsterAgent 未初始化")
    posture = m.monster.gather_global_posture(force_refresh=force)
    return {"status": "ok", "posture": posture}


async def monster_skills(category: str = ""):
    """技能清单（含启用状态、风险等级、调用统计）。"""
    m = state.get_manager()
    if m is None or m.skill_toolbox is None:
        raise HTTPException(status_code=503, detail="SkillToolbox 未初始化")
    tools = m.skill_toolbox.list_tools(category=category or None)
    return {
        "status": "ok",
        "skills": [
            {
                "id": t.tool_id,
                "name_zh": t.name_zh,
                "category": t.category,
                "risk_level": t.risk_level,
                "enabled": t.enabled,
                "description": t.description,
                "call_count": t.call_count,
                "last_called": t.last_called,
            }
            for t in tools
        ],
    }


async def monster_skills_toggle(request: Request):
    """启用/禁用指定技能。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")
    m = state.get_manager()
    if m is None or m.skill_toolbox is None:
        raise HTTPException(status_code=503, detail="SkillToolbox 未初始化")
    body = await request.json()
    tool_id = (body.get("tool_id") or "").strip()
    enabled = bool(body.get("enabled", True))
    if not tool_id:
        raise HTTPException(status_code=400, detail="tool_id 不能为空")
    ok = m.skill_toolbox.enable(tool_id) if enabled else m.skill_toolbox.disable(tool_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"技能 {tool_id} 不存在")
    return {"status": "ok", "tool_id": tool_id, "enabled": enabled}


async def monster_calls(limit: int = 30):
    """技能调用审计日志。"""
    m = state.get_manager()
    if m is None or m.skill_toolbox is None:
        raise HTTPException(status_code=503, detail="SkillToolbox 未初始化")
    logs = m.skill_toolbox.get_call_log(limit=limit)
    return {
        "status": "ok",
        "calls": [
            {
                "ts": datetime.fromtimestamp(c.get("timestamp", 0)).strftime("%H:%M:%S"),
                "tool": c.get("tool_id", ""),
                "caller": c.get("caller", ""),
                "success": c.get("success", False),
                "error": c.get("error", ""),
                "latency_ms": c.get("latency_ms", 0),
                "result_summary": (c.get("result_summary") or "")[:120],
            }
            for c in logs
        ],
    }


async def monster_status():
    """怪兽 + 工具箱聚合状态。"""
    m = state.get_manager()
    if m is None:
        raise HTTPException(status_code=503, detail="DFU 未初始化")
    return {"status": "ok", "data": m.get_monster_status()}


async def monster_skills_reload(request: Request):
    """热重载技能目录（保留内置技能）。"""
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")
    m = state.get_manager()
    if m is None or m.skill_loader is None:
        raise HTTPException(status_code=503, detail="SkillLoader 未初始化")
    result = m.skill_loader.reload()
    return {"status": "ok", "result": result}


async def monster_skills_import(request: Request):
    """导入外部技能：复制 SKILL.md 文件/目录到技能目录并热重载。"""
    import shutil
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")
    m = state.get_manager()
    if m is None or m.skill_loader is None:
        raise HTTPException(status_code=503, detail="SkillLoader 未初始化")

    body = await request.json()
    src_path = body.get("path", "").strip()
    if not src_path:
        raise HTTPException(status_code=400, detail="缺少 path 参数")

    src = Path(src_path)
    if not src.exists():
        raise HTTPException(status_code=400, detail=f"路径不存在: {src_path}")

    # 路径白名单：仅允许导入项目目录（dfu_prototype）内的技能文件，防止任意文件读取/跨目录复制
    _PROJECT_ROOT = Path(__file__).resolve().parent.parent
    src_resolved = src.resolve()
    if not src_resolved.is_relative_to(_PROJECT_ROOT):
        raise HTTPException(status_code=400, detail=f"仅支持导入项目目录内的技能路径: {_PROJECT_ROOT}")
    src = src_resolved

    # 目标: organs/skills/_builtins/ 下同名目录
    dest_dir = m.skill_loader.skills_dir / src.name if src.is_dir() else m.skill_loader.skills_dir / src.stem

    try:
        if src.is_dir():
            if dest_dir.exists():
                raise HTTPException(status_code=409, detail=f"技能目录已存在: {dest_dir}")
            shutil.copytree(str(src), str(dest_dir))
            imported = f"目录 '{src.name}'"
        else:
            if not src.name.upper().startswith("SKILL"):
                raise HTTPException(status_code=400, detail="仅支持 SKILL.md 或 SKILL 开头的 Markdown 文件")
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest_dir / "SKILL.md"))
            imported = f"文件 '{src.name}'"
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"复制失败: {e}")

    # 热重载
    reload_result = m.skill_loader.reload()
    return {"status": "ok", "imported": imported, "dest": str(dest_dir), "reload": reload_result}


# ── 演示模式（DFU最后一公里）──

# ── DFU 启停 / 状态 / 对话 API（从原 web_server.py 拆分） ──

async def dfu_status():
    """DFU 运行状态：running / uptime / start_time / components。"""
    mgr = state.get_manager()
    return mgr.get_dfu_status() if mgr else {"running": False, "uptime": 0.0, "start_time": None, "components": {}}


async def dfu_start():
    """启动 DFU 核心系统（幂等：已运行则直接返回成功）。"""
    mgr = state.get_manager()
    if mgr is None:
        return JSONResponse(status_code=503, content={"success": False, "message": "DFU 管理器尚未初始化"})
    try:
        await mgr.start()
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": f"DFU 启动失败: {e}"})
    return {"success": True, "message": "DFU 已启动"}


async def dfu_stop():
    """停止 DFU 核心系统（幂等：未运行则直接返回成功）。"""
    mgr = state.get_manager()
    if mgr is None:
        return JSONResponse(status_code=503, content={"success": False, "message": "DFU 管理器尚未初始化"})
    try:
        await mgr.stop()
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": f"DFU 停止失败: {e}"})
    return {"success": True, "message": "DFU 已停止"}


async def dfu_organs_data():
    """一次性返回 12 个器官实时数据；系统未运行时返回 running=false。"""
    mgr = state.get_manager()
    if mgr is None or not mgr._running:
        return {"running": False}
    try:
        data = await mgr.get_organs_data()
        return {"running": True, "organs": data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"获取器官数据失败: {e}"})


async def api_chat(request: Request):
    """对话代理：将 MonsterDFU 前端聊天请求转发到 OpenAI 兼容接口。
    请求体: {messages: [...], api_key: str, model: str, base_url: str, stream?: bool}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "请求体必须是合法 JSON"}, status_code=400)

    messages = body.get("messages")
    api_key = (body.get("api_key") or "").strip()
    model = (body.get("model") or "").strip() or "gpt-3.5-turbo"
    base_url = (body.get("base_url") or "").strip() or "https://api.openai.com/v1"
    stream = bool(body.get("stream", False))
    temperature = float(body.get("temperature", 0.7))
    max_tokens = int(body.get("max_tokens", 2048))

    if not messages or not isinstance(messages, list) or not messages:
        return JSONResponse({"error": "messages 参数缺失或格式错误"}, status_code=400)
    if not api_key:
        return JSONResponse({"error": "API key 为空，请在设置页配置 API Key 后再对话"}, status_code=400)

    # SSRF 防护：先 DNS 解析/字面量归一化，拒绝私有/回环/链路本地/元数据地址，重定向后复检
    ssrf_err = _ssrf_check_url(base_url)
    if ssrf_err:
        return JSONResponse({"error": ssrf_err}, status_code=400)

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=10.0), follow_redirects=False) as client:
            if stream:
                req = client.build_request("POST", url, headers=headers, json=payload)
                resp = await client.send(req, stream=True)
                # 重定向逐跳 SSRF 复检（最多 5 跳）
                redirect_count = 0
                while resp.status_code in (301, 302, 303, 307, 308) and redirect_count < 5:
                    location = resp.headers.get("location")
                    await resp.aclose()
                    if not location:
                        break
                    url = str(httpx.URL(url).join(location))
                    ssrf_err = _ssrf_check_url(url)
                    if ssrf_err:
                        return JSONResponse({"error": ssrf_err}, status_code=400)
                    req = client.build_request("POST", url, headers=headers, json=payload)
                    resp = await client.send(req, stream=True)
                    redirect_count += 1
                if resp.status_code >= 400:
                    detail = (await resp.aread()).decode("utf-8", "ignore")[:500]
                    return JSONResponse(
                        {"error": f"上游接口返回 {resp.status_code}", "detail": detail},
                        status_code=502,
                    )

                async def event_stream():
                    try:
                        async for line in resp.aiter_lines():
                            yield line + "\n"
                    finally:
                        await resp.aclose()

                return StreamingResponse(
                    event_stream(),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )

            resp = await client.post(url, headers=headers, json=payload)
            # 重定向逐跳 SSRF 复检（最多 5 跳）
            redirect_count = 0
            while resp.status_code in (301, 302, 303, 307, 308) and redirect_count < 5:
                location = resp.headers.get("location")
                await resp.aclose()
                if not location:
                    break
                url = str(httpx.URL(url).join(location))
                ssrf_err = _ssrf_check_url(url)
                if ssrf_err:
                    return JSONResponse({"error": ssrf_err}, status_code=400)
                resp = await client.post(url, headers=headers, json=payload)
                redirect_count += 1
            if resp.status_code >= 400:
                try:
                    detail = resp.json()
                except Exception:
                    detail = resp.text[:500]
                return JSONResponse(
                    {"error": f"上游接口返回 {resp.status_code}", "detail": detail},
                    status_code=502,
                )
            return JSONResponse(resp.json())
    except httpx.TimeoutException:
        return JSONResponse(
            {"error": "请求上游接口超时，请检查 base_url 与网络连接"}, status_code=504
        )
    except Exception as exc:
        return JSONResponse({"error": f"请求上游接口失败: {exc}"}, status_code=502)


async def api_status():
    mgr = state.get_manager()
    if not mgr:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    status = mgr.get_status()
    # 补充 Token 消耗统计
    try:
        status["token_usage"] = mgr.llm_client.get_token_usage()
    except Exception:
        status["token_usage"] = None
    return status


async def api_token_usage():
    mgr = state.get_manager()
    if not mgr:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return mgr.llm_client.get_token_usage()


async def api_reset_token_usage():
    mgr = state.get_manager()
    if not mgr:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    mgr.llm_client.reset_token_usage()
    return {"success": True, "message": "Token 统计已重置"}


async def api_stats():
    mgr = state.get_manager()
    if not mgr:
        return JSONResponse({"error": "系统未初始化"}, status_code=503)
    return mgr.get_stats()


async def demo_trigger(request: Request):
    """
    触发演示攻击序列。
    预设3个场景: c2_beacon, data_exfil, mixed_attack
    通过 EventChainRecorder 注入预设攻击事件，
    SSE 实时推送攻击→防御全过程。
    """
    token_ok = await _check_auth(request)
    if not token_ok:
        raise HTTPException(status_code=401, detail="未授权")

    body = await request.json()
    scenario = body.get("scenario", "c2_beacon")

    bus = get_message_bus()

    # 预设攻击场景事件序列
    events = _get_demo_events(scenario)

    # 异步注入（不阻塞响应）
    asyncio.create_task(_inject_demo_events(bus, events))

    return {
        "status": "ok",
        "scenario": scenario,
        "events_count": len(events),
        "message": f"演示模式已触发: {scenario}",
    }


async def demo_scenarios():
    """返回可用的演示场景列表。"""
    return {
        "scenarios": [
            {"id": "c2_beacon", "name": "C2 信标检测", "description": "模拟 C2 服务器定期回连，触发信标检测→L0→L1→L2 升级"},
            {"id": "data_exfil", "name": "数据外泄", "description": "模拟内网服务器向公网传输大文件，触发外泄告警→L0→L1→L2 升级"},
            {"id": "mixed_attack", "name": "混合攻击 (C2+外泄+DDoS)", "description": "多源混合攻击，触发全链路 L0→L3 防御升级"},
        ]
    }


def _get_demo_events(scenario: str) -> list:
    """构造演示用攻击事件序列。"""
    now = time.time()
    events = []

    if scenario == "c2_beacon":
        # 6 次信标回连，间隔递增
        for i in range(6):
            events.append({
                "type": "outbound_traffic",
                "payload": {
                    "dst_ip": "203.0.113.42",
                    "dst_port": 4444,
                    "size": 128,
                    "timestamp": now + i * 3,
                }
            })
        # 再加上告警事件，让 FSM 看到
        for i in range(8):
            events.append({
                "type": "threat_alert",
                "payload": {
                    "source_organ": "outbound_monitor",
                    "indicator": {"source_ip": "203.0.113.42", "category": "beacon", "severity": "high"},
                    "category": "beacon",
                    "severity": "high",
                }
            })

    elif scenario == "data_exfil":
        # 外泄事件
        for i in range(5):
            size = 12 * 1024 * 1024 if i % 2 == 0 else 3 * 1024 * 1024
            events.append({
                "type": "outbound_traffic",
                "payload": {
                    "dst_ip": "198.51.100.88",
                    "dst_port": 443,
                    "size": size,
                    "timestamp": now + i * 0.5,
                }
            })
        for i in range(8):
            events.append({
                "type": "threat_alert",
                "payload": {
                    "source_organ": "outbound_monitor",
                    "indicator": {"source_ip": "198.51.100.88", "category": "exfiltration", "severity": "high"},
                    "category": "exfiltration",
                    "severity": "high",
                }
            })

    elif scenario == "mixed_attack":
        # 多源攻击
        ips = ["10.0.0.1", "10.0.0.2", "192.168.1.100"]
        for i, ip in enumerate(ips):
            for j in range(5):
                events.append({
                    "type": "threat_alert",
                    "payload": {
                        "source_organ": "monitor",
                        "indicator": {"source_ip": ip, "category": "ddos", "severity": "high"},
                        "category": "ddos",
                        "severity": "high",
                    }
                })
            events.append({
                "type": "outbound_traffic",
                "payload": {
                    "dst_ip": ip, "dst_port": 4444, "size": 128,
                    "timestamp": now + i * 2 + j * 0.3,
                }
            })

    return events


async def _inject_demo_events(bus, events):
    """异步注入演示事件到消息总线。"""
    for evt in events:
        msg = Message(
            source="DemoMode",
            target=evt.get("target", "EventAggregator"),
            type=evt["type"],
            payload=evt["payload"],
        )
        await bus.publish(msg)
        await _broadcast_event("attack_event", {
            "source_ip": evt["payload"].get("dst_ip", evt["payload"].get("source_ip", "unknown")),
            "category": evt["payload"].get("category", evt["type"]),
            "severity": evt["payload"].get("severity", "medium"),
            "description": f"{evt['type']} from {evt['payload'].get('dst_ip', 'unknown')}",
        })
        await asyncio.sleep(0.3)


async def _broadcast_event(event_type: str, payload: dict):
    """广播事件给所有 SSE 订阅者"""
    event = {"type": event_type, "timestamp": time.time(), **payload}
    dead = []
    for q in state._event_queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        state._event_queues.remove(q)
    # 追加到事件历史
    state._event_history.append(event)
    # 只保留最近 200 条
    if len(state._event_history) > 200:
        state._event_history[:] = state._event_history[-200:]


async def get_events(since: float = 0, limit: int = 50):
    """轮询获取事件历史。since=时间戳，仅返回该时间之后的事件"""
    result = [e for e in state._event_history if e.get("timestamp", 0) > since]
    return {"events": result[-limit:], "server_time": time.time()}


async def api_forensic_timeline(limit: int = 50):
    """取证时间线：返回攻击链时间线列表（时间/源IP/攻击类型/处置动作）。"""
    mgr = state.get_manager()
    if mgr is None or not mgr._running:
        return {"running": False, "timeline": []}
    try:
        timeline = mgr.forensic_tracker.get_timeline()
        return {
            "running": True,
            "total": len(timeline),
            "timeline": timeline[:limit],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"取证时间线获取失败: {e}"})


async def api_vuln_ports():
    """端口扫描结果：返回本地开放端口列表。"""
    mgr = state.get_manager()
    if mgr is None or not mgr._running:
        return {"running": False, "ports": []}
    try:
        ports = mgr.vuln_scanner.get_open_ports()
        return {
            "running": True,
            "scan_time": mgr.vuln_scanner._last_scan_time,
            "total": len(ports),
            "ports": ports,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"端口扫描结果获取失败: {e}"})


async def api_outbound_connections():
    """出站连接：返回本机对外主动连接列表。"""
    mgr = state.get_manager()
    if mgr is None or not mgr._running:
        return {"running": False, "connections": []}
    try:
        data = mgr.outbound_monitor.get_outbound_connections()
        return {"running": True, **data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"出站连接获取失败: {e}"})


async def api_audit_events(limit: int = 50):
    """日志审计：返回最近安全事件。"""
    mgr = state.get_manager()
    if mgr is None or not mgr._running:
        return {"running": False, "events": []}
    try:
        events = mgr.log_auditor.get_event_log_cache()
        return {
            "running": True,
            "total": len(events),
            "events": events[:limit],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"审计事件获取失败: {e}"})


async def api_resources():
    """资源监控：返回 CPU/内存实时使用率采样。"""
    mgr = state.get_manager()
    if mgr is None or not mgr._running:
        return {"running": False, "resource": {}}
    try:
        stats = mgr.resource_scheduler.get_real_resource_stats()
        return {"running": True, "resource": stats}
    except Exception as e:
        return JSONResponse(status_code=500, content={"running": False, "message": f"资源监控获取失败: {e}"})


async def api_events_stream():
    mgr = state.get_manager()
    if not mgr:
        return StreamingResponse(
            _empty_generator(),
            media_type="text/event-stream",
        )

    queue = mgr.add_sse_client()

    async def event_generator():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {event['event']}\ndata: {event['data']}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            mgr.remove_sse_client(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


