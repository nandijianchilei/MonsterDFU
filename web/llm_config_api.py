# -*- coding: utf-8 -*-
"""web/llm_config_api.py — LLM 配置 API（从原 web_server.py 拆分）。"""
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request

from config import (
    LLMConfig,
    get_config,
    get_llm_config,
    load_llm_user_config,
    save_llm_user_config,
)
from core.llm_client import LLMClient, create_organ_llm_client

from web import state
from web.auth import verify_token


LLM_PROVIDER_PRESETS = {
    "volcano": {
        "name": "火山引擎",
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "models": ["deepseek-v4-pro-260425", "deepseek-v3-241226", "deepseek-r1-250120", "doubao-pro-32k"],
        "model_hint": "填火山引擎推理接入点 ID（ep- 开头）或模型名",
    },
    "openai": {
        "name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "model_hint": "模型名称，如 gpt-4o",
    },
    "deepseek": {
        "name": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "model_hint": "模型名称，如 deepseek-chat",
    },
    "ollama": {
        "name": "本地 Ollama",
        "base_url": "http://localhost:11434/v1",
        "models": ["llama3.2", "qwen2.5", "mistral"],
        "model_hint": "本地已拉取的模型名",
    },
    "custom": {
        "name": "自定义",
        "base_url": "",
        "models": [],
        "model_hint": "任意 OpenAI 兼容服务",
    },
    "mock": {
        "name": "Mock 模式（不调用 API）",
        "base_url": "",
        "models": [],
        "model_hint": "无需 Key，本地模拟输出",
    },
}

_LLM_EDITABLE_FIELDS = (
    "provider", "api_base", "api_key", "model", "backup_model",
    "temperature", "max_tokens", "timeout", "max_retries", "mock_mode",
)


def _mask_api_key(key: str) -> str:
    """脱敏展示 API Key：保留前 4 后 4，中间打星。"""
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"


def _serialize_llm_config(cfg: LLMConfig) -> Dict[str, Any]:
    """将 LLMConfig 转为前端可读 dict（Key 脱敏）。"""
    return {
        "provider": cfg.provider,
        "api_base": cfg.api_base,
        "api_key": _mask_api_key(cfg.api_key),
        "has_api_key": bool(cfg.api_key),
        "model": cfg.model,
        "backup_model": cfg.backup_model,
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
        "timeout": cfg.timeout,
        "max_retries": cfg.max_retries,
        "mock_mode": cfg.mock_mode,
        "effective_mode": "mock" if (cfg.mock_mode or not cfg.api_key) else "real",
    }


async def api_get_llm_config(_auth=Depends(verify_token)):
    """获取当前生效的 LLM 配置（含脱敏 Key）+ 内置 Provider 预设。"""
    m = state.get_manager()
    cfg = m.llm_client.config if m else get_llm_config()
    return {
        "status": "ok",
        "config": _serialize_llm_config(cfg),
        "presets": LLM_PROVIDER_PRESETS,
        "source": "llm_user.json" if load_llm_user_config() else "yaml/env 默认",
    }


async def api_put_llm_config(request: Request, _auth=Depends(verify_token)):
    """保存 LLM 配置：写入 llm_user.json 并热更新运行中的 LLMClient。

    请求体支持部分更新；api_key 传空字符串表示保留已有 Key（避免每次保存清空）。
    """
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")

    # 合并：先读已有用户配置，再覆盖本次传入字段
    merged = dict(load_llm_user_config())
    for k in _LLM_EDITABLE_FIELDS:
        if k in body:
            merged[k] = body[k]

    # api_key 为空串 → 保留已有 Key（优先用户配置，其次当前生效配置）
    if "api_key" in merged and not merged.get("api_key"):
        existing = load_llm_user_config().get("api_key", "") or get_config().llm.api_key
        merged["api_key"] = existing

    if not save_llm_user_config(merged):
        raise HTTPException(status_code=500, detail="配置写入失败，请检查 config 目录权限")

    # 热更新运行中的 LLMClient（无需重启）
    m = state.get_manager()
    if m:
        new_cfg = get_llm_config()
        m.llm_client.reconfigure(new_cfg)

    return {
        "status": "ok",
        "config": _serialize_llm_config(get_llm_config()),
        "msg": "LLM 配置已保存并热更新生效",
    }


async def api_get_organ_llm_config(_auth=Depends(verify_token)):
    """读取各器官独立 LLM 覆盖配置（存于 llm_user.json 的 organ_overrides 字段）。"""
    user_cfg = load_llm_user_config()
    return {"status": "ok", "organ_overrides": user_cfg.get("organ_overrides", {}) or {}}


async def api_put_organ_llm_config(request: Request, _auth=Depends(verify_token)):
    """保存各器官独立 LLM 覆盖配置。

    请求体: {"organ_overrides": {organ_id: {use_global, vendor, api_key, base_url, model}}}
    """
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")
    overrides = body.get("organ_overrides")
    if not isinstance(overrides, dict):
        raise HTTPException(status_code=400, detail="organ_overrides 必须是对象")

    merged = dict(load_llm_user_config())
    # 空 dict 视为清空全部器官覆盖
    merged["organ_overrides"] = overrides

    if not save_llm_user_config(merged):
        raise HTTPException(status_code=500, detail="配置写入失败，请检查 config 目录权限")

    # 热重配置器官独立 LLM 客户端：保存后无需重启即可让 left/right brain 使用新配置
    mgr = state.get_manager()
    if mgr is not None and hasattr(mgr, "left_brain") and hasattr(mgr, "right_brain"):
        base_cfg = get_llm_config()
        mgr.left_brain_llm = create_organ_llm_client("left-brain", base_cfg, mgr.llm_client)
        mgr.right_brain_llm = create_organ_llm_client("right-brain", base_cfg, mgr.llm_client)
        if hasattr(mgr.left_brain, "llm_client"):
            mgr.left_brain.llm_client = mgr.left_brain_llm
        if hasattr(mgr.right_brain, "llm_client"):
            mgr.right_brain.llm_client = mgr.right_brain_llm

    return {"status": "ok", "organ_overrides": overrides, "msg": "各器官 LLM 覆盖配置已保存"}


async def api_test_llm(request: Request, _auth=Depends(verify_token)):
    """用给定参数发一条真实请求测试 LLM 连通性（不保存配置）。"""
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")
    api_base = str(body.get("api_base", "")).strip()
    api_key = str(body.get("api_key", "")).strip()
    model = str(body.get("model", "")).strip()
    if not api_base or not api_key or not model:
        raise HTTPException(status_code=400, detail="api_base / api_key / model 均为必填")
    result = await LLMClient.test_connection(api_base, api_key, model)
    return {"status": "ok" if result["ok"] else "error", **result}


# ── 健康检查端点 ──
