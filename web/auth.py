# -*- coding: utf-8 -*-
"""web/auth.py — 认证与 Token 分发（从原 web_server.py 拆分）。

包含：Token 初始化 / 过期轮换 / Bearer 校验 / SSRF 防护 /
      verify_token 依赖 / auth_middleware / /api/token 端点。
"""
import ipaddress
import os
import secrets
import socket
import sys
import time
import urllib.parse
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from web import state


def _stdout_reconfigure():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


_stdout_reconfigure()

_API_TOKEN = os.environ.get("DFU_WEB_TOKEN", "") or os.environ.get("DFU_AUTH_API_TOKEN", "")
if not _API_TOKEN:
    _API_TOKEN = secrets.token_hex(16)
    print(f"[Auth] 未设置 DFU_WEB_TOKEN/DFU_AUTH_API_TOKEN，已生成随机 Token: {_API_TOKEN}")
else:
    print("[Auth] 已从环境变量 DFU_WEB_TOKEN/DFU_AUTH_API_TOKEN 加载 Token")

# Bootstrap Key（/api/token 首访保护）：
# - 首次获取 Token 时必须携带本 Key（请求头 X-Bootstrap-Token 或 URL 参数 ?bootstrap=）
# - 来源：环境变量 DFU_BOOTSTRAP_TOKEN；未设置则随机生成并打印到控制台/日志
# - 用途：防止攻击者无凭据调用 /api/token 直接换取有效 Token（首访保护）
_BOOTSTRAP_TOKEN = os.environ.get("DFU_BOOTSTRAP_TOKEN", "")
if not _BOOTSTRAP_TOKEN:
    _BOOTSTRAP_TOKEN = secrets.token_hex(16)
    print(f"[Auth] 未设置 DFU_BOOTSTRAP_TOKEN，已生成随机 Bootstrap Key: {_BOOTSTRAP_TOKEN}")
    print("[Auth] 前端获取 Token 请携带 X-Bootstrap-Token 请求头或 ?bootstrap=<key> 参数")
else:
    print("[Auth] 已从环境变量 DFU_BOOTSTRAP_TOKEN 加载 Bootstrap Key")

# Token 有效期（秒），默认 24h；0 或负值表示永不过期（仅显式配置）
_TOKEN_TTL_SECONDS = int(os.environ.get("DFU_WEB_TOKEN_TTL", "86400"))
_token_issued_at = time.time()

security = HTTPBearer(auto_error=False)


def _is_token_expired() -> bool:
    """Token 是否已过期（TTL<=0 表示永不过期）。"""
    if _TOKEN_TTL_SECONDS <= 0:
        return False
    return (time.time() - _token_issued_at) > _TOKEN_TTL_SECONDS


def _refresh_api_token() -> str:
    """轮换 API Token（供 /api/token 在过期时刷新使用）。"""
    global _API_TOKEN, _token_issued_at
    _API_TOKEN = secrets.token_hex(16)
    _token_issued_at = time.time()
    return _API_TOKEN


def _token_remaining_seconds() -> int:
    """当前 Token 剩余有效期（秒）。"""
    if _TOKEN_TTL_SECONDS <= 0:
        return -1
    remain = _TOKEN_TTL_SECONDS - int(time.time() - _token_issued_at)
    return max(remain, 0)


def _validate_token(token: str) -> bool:
    """统一 Token 校验：单轨 Bearer + 过期检查（常量时间比较）。"""
    if not token:
        return False
    if _is_token_expired():
        return False
    return secrets.compare_digest(token, _API_TOKEN)


def _extract_bearer_token(request: Request) -> str:
    """统一 Bearer 解析：仅接受 'Bearer ' scheme 前缀，禁止无 scheme 裸 token。"""
    auth = request.headers.get("Authorization", "")
    if not auth:
        return ""
    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def _resolve_host_safe(host: str) -> Optional[str]:
    """将 hostname / 十进制 / 十六进制字面量归一化为点分十进制 IP；失败返回 None。"""
    if not host:
        return None
    h = host.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(h)
    except OSError:
        return None


def _ssrf_check_url(url: str) -> Optional[str]:
    """SSRF 防护：解析 host 为 IP，拒绝私有/回环/链路本地/元数据地址；返回错误描述或 None。"""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return "无效 URL"
    host = parsed.hostname
    if not host:
        return "URL 缺少主机名"
    ip_str = _resolve_host_safe(host)
    if not ip_str:
        return f"无法解析主机名: {host}"
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"无法解析为合法 IP: {host}"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return f"拒绝访问私有/保留地址: {host} -> {ip_str}"
    if str(ip) == "169.254.169.254" or str(ip).lower() in ("fd00::1", "fe80::1"):
        return f"拒绝访问云元数据/链路本地地址: {host} -> {ip_str}"
    return None


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Bearer Token 认证依赖（FastAPI Depends 用）。

    Token 来自 DFU_WEB_TOKEN（未设置则随机生成），统一单轨校验，
    过期后返回 401 提示前端刷新。
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
    if not _validate_token(credentials.credentials):
        if _is_token_expired():
            raise HTTPException(status_code=401, detail="Token 已过期，请通过 GET /api/token 刷新")
        raise HTTPException(status_code=403, detail="Token 无效")
    return True

# ==================== 系统管理器 ====================


def _get_api_token() -> str:
    """返回当前 Web Token（与顶部 _API_TOKEN 一致：DFU_WEB_TOKEN 或随机生成）。"""
    return _API_TOKEN


_AUTH_WHITELIST = [
    # 健康检查（无需鉴权）
    "/healthz",
    "/readyz",
    "/health",
    # 普通页面（无需鉴权）
    "/live",
    "/compare",
    "/monster",
    "/login",
    "/static",
    # Token 分发端点（前端启动时获取 token）
    "/api/token",
    "/api/events/stream",
]


async def auth_middleware(request: Request, call_next):
    """API Token 认证中间件（统一 Bearer 单轨 + 过期校验）"""
    path = request.url.path

    if path in _AUTH_WHITELIST or path.startswith("/static"):
        return await call_next(request)

    if path.startswith("/api/"):
        token = _extract_bearer_token(request)
        if not _validate_token(token):
            if _is_token_expired():
                return JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized", "message": "Token 已过期，请通过 GET /api/token 刷新"}
                )
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "message": "请在请求头中提供有效的 API Token（Authorization: Bearer <token>）"}
            )

    return await call_next(request)


# ── 静态页面 ──


async def api_token(request: Request, bootstrap: str = None):
    """Token 分发端点：返回当前有效 Token，过期则自动轮换刷新。

    首访保护：必须携带 Bootstrap Key（请求头 `X-Bootstrap-Token` 或
    URL 参数 `?bootstrap=<key>`，与 DFU_BOOTSTRAP_TOKEN 一致），否则 401。
    前端在启动时调用本端点获取 token，后续所有 /api/* 请求统一
    使用 `Authorization: Bearer <token>` 携带（已废弃 X-DFU-Token 双轨）。
    """
    # 首访保护：必须携带 Bootstrap Key（请求头 X-Bootstrap-Token 或 ?bootstrap=<key>），否则 401
    supplied = request.headers.get("X-Bootstrap-Token", "").strip() or (bootstrap or "").strip()
    if not supplied or not secrets.compare_digest(supplied, _BOOTSTRAP_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="缺少或错误的 Bootstrap Key，请携带 X-Bootstrap-Token 请求头或 ?bootstrap=<key> 参数"
        )
    if _is_token_expired():
        _refresh_api_token()
        print("[Auth] Token 已过期，自动轮换刷新")
    return {
        "token": _API_TOKEN,
        "header": "Authorization",
        "scheme": "Bearer",
        "expires_in": _token_remaining_seconds(),
    }


# ── LLM 配置 API（UI 设置页接入，参考 Cherry Studio 预设注册表模式）──

# 内置 Provider 预设：前端设置页下拉选择后自动填充 base_url


async def _check_auth(request: Request) -> bool:
    """检查请求是否携带有效的 API Token（统一 Bearer 单轨 + 过期校验）。"""
    token = _extract_bearer_token(request)
    return _validate_token(token)
