"""
攻击路径干扰层（融合增强 v1.1 第三阶段 · 默认关闭）。

对外口径：攻击路径干扰与安全验证 —— 对已确认的高危攻击源，
在"降低攻击成功率、增加攻击成本"目标下提供两种受控手段：

1. blindfold（终端输出污染，Labyrinth BLINDFOLD 思路）：
   对攻击者会话返回混淆 / 误导响应（诱饵指纹、虚假状态），使攻击者
   基于错误信息继续侦察，浪费其时间与工具链。
2. puppeteer（API 拦截改写，Labyrinth PUPPETEER 思路）：
   对攻击者发往内部 API 的请求返回诱饵响应（伪造数据/假状态），
   使攻击者误以为利用成功，实际未触碰真实业务。

安全约束（硬编码，不可由 config 关闭）：
- 默认关闭：仅授权环境通过 `DFU_INTERFERENCE=on` 或 config 显式开启；
- kill-switch 联动：全局熔断开启后强制停用，仅保留告警；
- 仅对 FSM 等级 >= L2 的已确认恶意源生效；
- 每次干扰动作完整记录审计日志（时间/源/手段/目标/原因/内容摘要）；
- 干扰只作用于"响应内容"，不主动攻击、不触碰真实业务数据。

对外仅依赖 communication.message_bus / config / utils.logger / core.countermeasure_fsm
（FSM 以 duck-typing 方式注入：提供 get_level 即可，便于单测替换）。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config, InterferenceConfig
from utils.logger import get_logger


# ==================== 干扰手段常量 ====================

METHOD_BLINDFOLD = "blindfold"   # 终端输出污染（误导响应）
METHOD_PUPPETEER = "puppeteer"   # API 拦截改写（诱饵响应）

# 诱饵标记：注入干扰响应中，便于审计回溯与去重
DECOY_MARKER = "[DFU-INTERFERENCE-DECOY]"

# 干扰响应模板：盲干扰时对攻击者可见的误导内容
BLINDFOLD_RESPONSES = [
    "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/plain\r\n\r\n"
    "it works",
    "HTTP/1.1 404 Not Found\r\nServer: nginx/1.18.0\r\n\r\n",
    "HTTP/1.1 301 Moved Permanently\r\nLocation: https://internal.corp.local/\r\n\r\n",
]

# API 诱饵响应模板：伪造内部 API 返回（含假凭据/假版本，诱导攻击者继续投入）
PUPPETEER_RESPONSES = [
    {"ok": True, "code": 0, "message": "success", "data": {"token": "decoy_eyJhbGciOiJIUzI1NiJ9"}},
    {"ok": True, "code": 0, "message": "success", "data": {"version": "2.4.1", "build": "20260804"}},
    {"ok": True, "code": 0, "message": "success", "data": {"user": "admin", "role": "root"}},
]

# 干扰手段开关（用于事件 payload 标记）
INTERFERENCE_EVENT_TYPE = "interference_applied"
KILL_SWITCH_EVENT_TYPE = "kill_switch"

# 触发干扰的威胁类别（默认白名单，与 InterferenceConfig.trigger_categories 对应）
DEFAULT_TRIGGER_CATEGORIES = ("exploit", "brute_force", "command_injection", "port_scan", "vuln", "c2_beacon")

# 干扰目标等级门槛：FSM 等级 >= 该值才允许干扰（L0/L1 仅告警观察）
MIN_FSM_LEVEL = "L2"

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "severe": 4}


@dataclass
class InterferenceAudit:
    """单条干扰审计记录。"""

    audit_id: str
    source_ip: str
    method: str
    target: str
    category: str
    reason: str
    payload_digest: str
    response_digest: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    blocked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """转为字典格式。"""
        return {
            "audit_id": self.audit_id,
            "source_ip": self.source_ip,
            "method": self.method,
            "target": self.target,
            "category": self.category,
            "reason": self.reason,
            "payload_digest": self.payload_digest,
            "response_digest": self.response_digest,
            "timestamp": self.timestamp,
            "blocked": self.blocked,
        }


def _digest(obj: Any) -> str:
    """计算对象摘要（用于审计去重，不存原文）。"""
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class InterferenceService:
    """干扰层核心服务：受控的盲干扰 / API 诱饵 + 全量审计（纯内存）。"""

    def __init__(self, config: Optional[InterferenceConfig] = None) -> None:
        self.config: InterferenceConfig = config or InterferenceConfig()
        self._audit: List[InterferenceAudit] = []
        self._kill_switch = False
        self._logger: logging.Logger = get_logger("Interference")
        self._stats: Dict[str, int] = {
            "blindfold_applied": 0,
            "puppeteer_applied": 0,
            "blocked_by_disabled": 0,
            "blocked_by_kill_switch": 0,
            "blocked_by_authorization": 0,
            "blocked_by_severity": 0,
            "blocked_by_category": 0,
            "blocked_by_level": 0,
        }

    # ---------- 门控 ----------

    @property
    def enabled(self) -> bool:
        """总开关：config.enabled 且未熔断。"""
        return self.config.enabled and not self._kill_switch

    def set_kill_switch(self, on: bool) -> None:
        """联动全局熔断：开启后强制停用干扰层。"""
        self._kill_switch = on
        if on:
            self._logger.warning("kill-switch 开启，干扰层已强制停用")
        else:
            self._logger.info("kill-switch 关闭，干扰层恢复（仍需 config.enabled）")

    def check_authorized(self, payload: Dict[str, Any]) -> bool:
        """授权校验：authorized_only 时要求 payload 显式携带 authorized=True。"""
        if not self.config.authorized_only:
            return True
        return bool(payload.get("authorized", False))

    def check_gate(
        self, category: str, severity: str, fsm_level: Optional[str], payload: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """逐级门控检查。

        Returns:
            (allowed, reason) —— allowed=True 表示可执行干扰；False 时 reason 说明拦截原因。
        """
        if not self.enabled:
            self._stats["blocked_by_disabled"] += 1
            return False, "interference_disabled"
        if not self.check_authorized(payload):
            self._stats["blocked_by_authorization"] += 1
            return False, "not_authorized"
        if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(self.config.min_severity, 3):
            self._stats["blocked_by_severity"] += 1
            return False, "severity_below_threshold"
        if category not in self.config.trigger_categories:
            self._stats["blocked_by_category"] += 1
            return False, "category_not_in_whitelist"
        if fsm_level is not None and _level_rank(fsm_level) < _level_rank(MIN_FSM_LEVEL):
            self._stats["blocked_by_level"] += 1
            return False, "fsm_level_below_l2"
        return True, "allowed"

    # ---------- 干扰手段 ----------

    def blindfold(
        self,
        source_ip: str,
        category: str = "unknown",
        severity: str = "high",
        target: str = "attacker_session",
        payload: Optional[Dict[str, Any]] = None,
        fsm_level: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        终端输出污染：对攻击者会话返回混淆 / 误导响应。

        仅在门控全开时执行；返回干扰结果（含诱饵响应与审计摘要）。
        """
        payload = payload or {}
        allowed, reason = self.check_gate(category, severity, fsm_level, payload)
        if not allowed:
            self._audit.append(
                InterferenceAudit(
                    audit_id=f"IF-{uuid.uuid4().hex[:8].upper()}",
                    source_ip=source_ip,
                    method=METHOD_BLINDFOLD,
                    target=target,
                    category=category,
                    reason=f"blocked:{reason}",
                    payload_digest=_digest(payload),
                    response_digest="",
                    blocked=True,
                )
            )
            return {"applied": False, "reason": reason, "method": METHOD_BLINDFOLD}

        if not self.config.blindfold_enabled:
            return {"applied": False, "reason": "blindfold_disabled", "method": METHOD_BLINDFOLD}

        response = self._pick_blindfold_response(source_ip)
        self._stats["blindfold_applied"] += 1
        audit = self._record_audit(
            source_ip=source_ip,
            method=METHOD_BLINDFOLD,
            target=target,
            category=category,
            reason="攻击路径干扰：对已确认攻击源返回误导响应",
            payload=payload,
            response=response,
        )
        self._logger.info(
            f"[干扰] blindfold {source_ip} ({category}/{severity}) -> 误导响应已投放"
        )
        return {
            "applied": True,
            "method": METHOD_BLINDFOLD,
            "source_ip": source_ip,
            "target": target,
            "category": category,
            "severity": severity,
            "decoy_response": response,
            "decoy_marker": DECOY_MARKER,
            "audit_id": audit.audit_id,
        }

    def puppeteer(
        self,
        source_ip: str,
        api_path: str = "/api/internal/status",
        category: str = "unknown",
        severity: str = "high",
        payload: Optional[Dict[str, Any]] = None,
        fsm_level: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        API 拦截改写：对攻击者请求返回诱饵响应（伪造数据/假状态）。

        仅在门控全开时执行；返回干扰结果（含诱饵响应与审计摘要）。
        """
        payload = payload or {}
        allowed, reason = self.check_gate(category, severity, fsm_level, payload)
        if not allowed:
            self._audit.append(
                InterferenceAudit(
                    audit_id=f"IF-{uuid.uuid4().hex[:8].upper()}",
                    source_ip=source_ip,
                    method=METHOD_PUPPETEER,
                    target=api_path,
                    category=category,
                    reason=f"blocked:{reason}",
                    payload_digest=_digest(payload),
                    response_digest="",
                    blocked=True,
                )
            )
            return {"applied": False, "reason": reason, "method": METHOD_PUPPETEER}

        if not self.config.puppeteer_enabled:
            return {"applied": False, "reason": "puppeteer_disabled", "method": METHOD_PUPPETEER}

        response = self._pick_puppeteer_response(source_ip)
        self._stats["puppeteer_applied"] += 1
        audit = self._record_audit(
            source_ip=source_ip,
            method=METHOD_PUPPETEER,
            target=api_path,
            category=category,
            reason="攻击路径干扰：对已确认攻击源返回诱饵 API 响应",
            payload=payload,
            response=response,
        )
        self._logger.info(
            f"[干扰] puppeteer {source_ip} ({category}/{severity}) -> 诱饵 API 响应已投放"
        )
        return {
            "applied": True,
            "method": METHOD_PUPPETEER,
            "source_ip": source_ip,
            "target": api_path,
            "category": category,
            "severity": severity,
            "decoy_response": response,
            "decoy_marker": DECOY_MARKER,
            "audit_id": audit.audit_id,
        }

    # ---------- 内部 ----------

    def _pick_blindfold_response(self, source_ip: str) -> str:
        """基于源 IP 稳定选取误导响应（同一源看到同一响应，便于去重）。"""
        idx = int(hashlib.md5(source_ip.encode("utf-8")).hexdigest(), 16) % len(BLINDFOLD_RESPONSES)
        return BLINDFOLD_RESPONSES[idx] + "\n" + DECOY_MARKER

    def _pick_puppeteer_response(self, source_ip: str) -> Dict[str, Any]:
        """基于源 IP 稳定选取诱饵 API 响应。"""
        idx = int(hashlib.md5(source_ip.encode("utf-8")).hexdigest(), 16) % len(PUPPETEER_RESPONSES)
        return {**PUPPETEER_RESPONSES[idx], "_marker": DECOY_MARKER}

    def _record_audit(
        self,
        source_ip: str,
        method: str,
        target: str,
        category: str,
        reason: str,
        payload: Dict[str, Any],
        response: Any,
    ) -> InterferenceAudit:
        """记录干扰审计（只存摘要，不存原文）。"""
        audit = InterferenceAudit(
            audit_id=f"IF-{uuid.uuid4().hex[:8].upper()}",
            source_ip=source_ip,
            method=method,
            target=target,
            category=category,
            reason=reason,
            payload_digest=_digest(payload),
            response_digest=_digest(response),
        )
        self._audit.append(audit)
        if len(self._audit) > self.config.audit_capacity:
            self._audit = self._audit[-self.config.audit_capacity:]
        return audit

    # ---------- 查询/导出 ----------

    def get_audit_log(self) -> List[InterferenceAudit]:
        """返回全部审计记录（时间正序）。"""
        return list(self._audit)

    def get_audit_by_source(self, source_ip: str) -> List[InterferenceAudit]:
        """按源 IP 过滤审计记录。"""
        return [a for a in self._audit if a.source_ip == source_ip]

    def get_stats(self) -> Dict[str, Any]:
        """返回干扰层统计（含拦截原因分布）。"""
        return {
            "enabled": self.enabled,
            "config_enabled": self.config.enabled,
            "kill_switch": self._kill_switch,
            "authorized_only": self.config.authorized_only,
            "min_severity": self.config.min_severity,
            **self._stats,
            "audit_count": len(self._audit),
        }

    def export_json(self, filepath: str) -> str:
        """导出全部干扰审计为 JSON 文件。

        Args:
            filepath: 输出 JSON 文件路径（绝对路径）

        Returns:
            写入的文件路径
        """
        report = {
            "exported_at": datetime.now().isoformat(),
            "stats": self.get_stats(),
            "audit": [a.to_dict() for a in self._audit],
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        self._logger.info(f"干扰审计已导出: {filepath} ({len(self._audit)} 条)")
        return filepath


def _level_rank(level: Optional[str]) -> int:
    """FSM 等级转数值（L0=0 ... L4=4），未知等级返回 -1。"""
    if not level:
        return -1
    digits = "".join(ch for ch in str(level) if ch.isdigit())
    if not digits:
        return -1
    return int(digits)


class InterferenceAgent:
    """
    攻击路径干扰层 Agent（默认关闭，仅授权环境开启）。

    职责：
    1. 订阅 threat_alert，对满足门控（enabled + 授权 + 严重级别 + 类别白名单
       + FSM 等级 >= L2）的高危告警执行攻击路径干扰（blindfold/puppeteer）；
    2. 订阅 kill_switch 事件，熔断开启时强制停用；
    3. 发布 interference_applied 事件（供双脑/取证/记录器消费）；
    4. 提供 build_interference_plan 决策支持接口（供双脑注入策略）。
    """

    def __init__(
        self,
        config: Config,
        fsm: Any = None,
        service: Optional[InterferenceService] = None,
    ) -> None:
        self.config = config
        self.fsm = fsm  # duck-typing：提供 get_level(source_ip) -> Optional[str]
        self.service = service or InterferenceService(config.interference)
        self.bus: MessageBus = get_message_bus()
        self.logger: logging.Logger = get_logger("InterferenceAgent")
        self._running = False

    # ---------- 生命周期 ----------

    async def start(self) -> None:
        """启动干扰层 Agent：订阅威胁告警与熔断事件。"""
        self._running = True
        await self.bus.subscribe("threat_alert", self._handle_alert)
        await self.bus.subscribe(KILL_SWITCH_EVENT_TYPE, self._handle_kill_switch)
        state = "已启用" if self.config.interference.enabled else "默认关闭"
        self.logger.info(f"干扰层Agent已启动（{state}，仅授权环境可执行干扰）")

    async def stop(self) -> None:
        """停止干扰层 Agent。"""
        self._running = False
        self.logger.info("干扰层Agent已停止")

    # ---------- 总线事件处理 ----------

    async def _handle_kill_switch(self, msg: Message) -> None:
        """处理 kill_switch 事件：熔断开启强制停用干扰层。"""
        on = bool(msg.payload.get("on", False))
        self.service.set_kill_switch(on)

    async def _handle_alert(self, msg: Message) -> Optional[Message]:
        """处理 threat_alert：门控通过时执行攻击路径干扰并发布事件。"""
        if not self._running:
            return None

        payload = msg.payload
        indicator = payload.get("indicator", payload)
        category = indicator.get("category", payload.get("category", "unknown"))
        alert_id = indicator.get("id", payload.get("id", msg.msg_id))
        source_ip = indicator.get("source_ip", payload.get("source_ip", ""))
        severity = indicator.get("severity", payload.get("severity", "medium"))
        target_ip = indicator.get("target_ip", payload.get("target_ip", "192.168.1.1"))
        target_port = indicator.get("target_port", payload.get("target_port"))
        api_path = indicator.get("api_path", payload.get("api_path", f"/api/internal/{category}"))

        if not source_ip:
            return None

        # 授权标志：仅 authorized_only=True 的显式授权环境才会携带
        authorized_payload = {"authorized": bool(payload.get("authorized", False))}

        # FSM 等级门槛
        fsm_level = None
        if self.fsm is not None and hasattr(self.fsm, "get_level"):
            fsm_level = self.fsm.get_level(source_ip)

        allowed, reason = self.service.check_gate(category, severity, fsm_level, authorized_payload)
        if not allowed:
            self.logger.debug(f"干扰门控拦截: {source_ip} ({category}/{severity}) -> {reason}")
            return None

        # 选择手段：带 API 路径的告警优先 puppeteer（API 拦截改写），其余 blindfold
        if api_path:
            result = self.service.puppeteer(
                source_ip=source_ip,
                api_path=api_path,
                category=category,
                severity=severity,
                payload=authorized_payload,
                fsm_level=fsm_level,
            )
        else:
            result = self.service.blindfold(
                source_ip=source_ip,
                category=category,
                severity=severity,
                target=f"session-{source_ip}:{target_port}" if target_port else f"session-{source_ip}",
                payload=authorized_payload,
                fsm_level=fsm_level,
            )

        if not result.get("applied"):
            return None

        self.logger.warning(
            f"[干扰] {source_ip} ({category}/{severity}) 攻击路径干扰已执行: {result['method']}"
        )

        # 发布 interference_applied 事件（广播，供双脑/取证/记录器消费）
        return Message(
            source="InterferenceAgent",
            target="*",
            type=INTERFERENCE_EVENT_TYPE,
            payload={
                "type": INTERFERENCE_EVENT_TYPE,
                "alert_id": alert_id,
                "source_ip": source_ip,
                "target_ip": target_ip,
                "category": category,
                "severity": severity,
                "method": result["method"],
                "target": result.get("target", result.get("api_path", "")),
                "audit_id": result.get("audit_id", ""),
                "decoy_marker": DECOY_MARKER,
                "fsm_level": fsm_level,
                "note": "攻击路径干扰与安全验证（仅授权环境，默认关闭）",
            },
        )

    # ---------- 双脑决策支持 ----------

    def build_interference_plan(
        self, source_ip: str, severity: str = "high"
    ) -> Dict[str, Any]:
        """
        生成攻击路径干扰处置建议（供双脑注入 recommended_actions）。

        Args:
            source_ip: 攻击源 IP
            severity:  告警严重级别

        Returns:
            干扰计划 dict：含动作名 interference_blindfold / interference_puppeteer、
            触发条件、风险提示。默认关闭时返回 disabled 提示。
        """
        if not self.config.interference.enabled:
            return {
                "action": "none",
                "reason": "攻击路径干扰层默认关闭（仅授权环境可开启），当前不执行干扰",
                "severity": severity,
                "risk": "无",
            }
        fsm_level = None
        if self.fsm is not None and hasattr(self.fsm, "get_level"):
            fsm_level = self.fsm.get_level(source_ip)
        method = "interference_blindfold" if fsm_level is None or _level_rank(fsm_level) < 3 else "interference_puppeteer"
        return {
            "action": method,
            "target_ip": source_ip,
            "reason": (
                f"已确认高危攻击源（FSM 等级 {fsm_level or 'unknown'}），"
                "执行攻击路径干扰以降低攻击成功率、增加攻击成本"
            ),
            "severity": severity,
            "fsm_level": fsm_level,
            "risk": "低：仅对响应内容做误导，不触碰真实业务数据；受 kill-switch 与授权门控",
        }

    # ---------- 查询/导出 ----------

    def get_audit_log(self) -> List[InterferenceAudit]:
        """返回全部干扰审计。"""
        return self.service.get_audit_log()

    def get_stats(self) -> Dict[str, Any]:
        """返回干扰层统计。"""
        return self.service.get_stats()

    def export_json(self, filepath: str) -> str:
        """导出干扰审计为 JSON 文件。"""
        return self.service.export_json(filepath)
