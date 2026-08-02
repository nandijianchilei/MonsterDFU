"""
规则引擎前置分流 (RuleEngineFrontend)
================================
观测层与聚合/双脑之间的签名规则快速通道。

原理：
- 订阅观测层发布的 `threat_alert`（原始告警）
- 每收到一条告警，调用 SignatureEngine 做 <1ms 规则匹配
- 规则命中 → 直接生成 rule_handled（含 defense_plan + attack_analysis），跳过双脑
- 规则未命中 → 发布 unhandled_threat → 走正常聚合+双脑 LLM 路径

收益：
- 80% 常规告警 <1ms 处理，LLM 调用量降 80%
"""

import asyncio
import ipaddress
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from communication.message_bus import Message, MessageBus, get_message_bus
from communication.skill_middleware import AlertSeverity, ThreatCategory, ThreatIndicator
from config import Config
from core.signature_engine import SignatureEngine
from utils.logger import get_logger


# =============================================================================
# 动作闸门 PolicyGate（提示注入第三层防护：动作白名单闸门）
# -----------------------------------------------------------------------------
# 双脑决策（LLM 或规则）产生的任何动作在执行前必须过闸门：
#   1. 白名单命中      → deny（受信任来源不执行拦截动作）
#   2. protected_ips   → deny（保护网段不可拦截）
#   3. 源 IP 真实性    → 校验失败 deny（is_ip_real_and_external 必须通过）
#   4. confidence < 0.8 → human_review（转人工复核，不自动执行）
# =============================================================================

# 保护网段（与 llm_schema_validator / actor_ip_isolation 对齐）
POLICY_GATE_PROTECTED_NETS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# 动作白名单默认值（这些 IP 是受信任来源，不执行拦截动作）
DEFAULT_POLICY_GATE_WHITELIST: List[str] = [
    "104.16.0.0/13",   # Cloudflare
    "103.21.244.0/22",  # Cloudflare
]

# 需要过闸门的动作（其余动作如 monitor / rate_limit 放行但记录）
GATED_ACTIONS = {"block", "isolate_ip"}


def is_ip_real_and_external(ip: Optional[str]) -> bool:
    """
    校验源 IP 真实且为公网可路由地址。

    失败条件：非法格式 / 回环 / 私网 / 链路本地 / 组播 / 保留 / 未指定 / 广播。
    这是提示注入与伪造源 IP 的第一道防线——伪造的 src_ip 不允许触发任何拦截动作。
    """
    if not ip:
        return False
    ip = str(ip).strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    if addr.is_global is False:
        return False
    return True


class PolicyGate:
    """
    动作闸门：所有防御动作执行前必须通过。

    用法：
        gate = PolicyGate(config)
        result = gate.policy_gate(action, target_ip, confidence)
        # result["decision"] in ("allow", "deny", "human_review")
    """

    def __init__(self, config: Optional[Config] = None,
                 whitelist: Optional[List[str]] = None,
                 protected_ips: Optional[List[str]] = None):
        self.config = config
        self._whitelist = [ipaddress.ip_network(n, strict=False) for n in (whitelist or DEFAULT_POLICY_GATE_WHITELIST)]
        self._protected = [ipaddress.ip_network(n, strict=False) for n in (protected_ips or POLICY_GATE_PROTECTED_NETS)]
        self.min_confidence = 0.8
        self._stats = {
            "total_checked": 0,
            "allow": 0,
            "deny_whitelist": 0,
            "deny_protected": 0,
            "deny_unreal_ip": 0,
            "human_review": 0,
        }

    # ── 网段命中 ──

    def _ip_in_networks(self, ip: Optional[str], networks: List[ipaddress.IPv4Network]) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(str(ip).strip())
            return any(addr in net for net in networks)
        except ValueError:
            return False

    def in_whitelist(self, ip: Optional[str]) -> bool:
        """是否命中动作白名单（受信任来源）。"""
        return self._ip_in_networks(ip, self._whitelist)

    def in_protected(self, ip: Optional[str]) -> bool:
        """是否命中保护网段。"""
        return self._ip_in_networks(ip, self._protected)

    # ── 闸门主入口 ──

    def policy_gate(self, action: str, target_ip: Optional[str],
                    confidence: float = 0.0) -> Dict[str, Any]:
        """
        对单个动作执行闸门判定。

        Returns:
            {
              "decision": "allow" | "deny" | "human_review",
              "reason": 判定原因,
              "action": 原始动作,
              "target_ip": 目标IP,
              "confidence": 置信度,
            }
        """
        self._stats["total_checked"] += 1
        reason = "allow"

        # 非拦截类动作（monitor / rate_limit）放行
        if action not in GATED_ACTIONS:
            self._stats["allow"] += 1
            return {"decision": "allow", "reason": "non_gated_action", "action": action,
                    "target_ip": target_ip, "confidence": confidence}

        # 1. 白名单命中 → deny
        if self.in_whitelist(target_ip):
            self._stats["deny_whitelist"] += 1
            return {"decision": "deny", "reason": f"whitelist_hit:{target_ip}", "action": action,
                    "target_ip": target_ip, "confidence": confidence}

        # 2. 保护网段命中 → deny
        if self.in_protected(target_ip):
            self._stats["deny_protected"] += 1
            return {"decision": "deny", "reason": f"protected_ip:{target_ip}", "action": action,
                    "target_ip": target_ip, "confidence": confidence}

        # 3. 源 IP 真实性校验失败 → deny
        if not is_ip_real_and_external(target_ip):
            self._stats["deny_unreal_ip"] += 1
            return {"decision": "deny", "reason": f"unreal_source_ip:{target_ip}", "action": action,
                    "target_ip": target_ip, "confidence": confidence}

        # 4. 置信度过低 → human_review
        if confidence < self.min_confidence:
            self._stats["human_review"] += 1
            return {"decision": "human_review",
                    "reason": f"low_confidence:{confidence:.2f}<{self.min_confidence}",
                    "action": action, "target_ip": target_ip, "confidence": confidence}

        self._stats["allow"] += 1
        return {"decision": "allow", "reason": "allow", "action": action,
                "target_ip": target_ip, "confidence": confidence}

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)


class RuleEngineFrontend:
    """
    规则引擎前置分流器：规则快速通道 vs 未知告警进入双脑。
    """

    def __init__(self, config: Config):
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.logger = get_logger("RuleEngineFrontend")
        self._running = False

        # 共享签名引擎（与双脑共用实例，避免重复加载规则）
        self.sig_engine = SignatureEngine(config)

        # 统计
        self._stats = {
            "total_received": 0,
            "rule_hit": 0,
            "rule_miss": 0,
            "by_category": {},
        }

    # ==================== 生命周期 ====================

    async def start(self) -> None:
        """启动规则引擎前置分流，订阅原始威胁告警。"""
        self._running = True
        await self.bus.subscribe("threat_alert", self._handle_alert)
        self.logger.info("规则引擎前置分流已启动｜规则快速通道模式")

    async def stop(self) -> None:
        """停止规则引擎前置分流。"""
        self._running = False
        self.logger.info(
            f"规则引擎前置分流已停止｜收: {self._stats['total_received']} "
            f"命中: {self._stats['rule_hit']} 未命中: {self._stats['rule_miss']}"
        )

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息。"""
        return dict(self._stats)

    # ==================== 核心处理 ====================

    async def _handle_alert(self, msg: Message) -> None:
        """
        处理原始威胁告警：规则匹配 → 分流。
        """
        if not self._running:
            return

        payload = msg.payload
        if not isinstance(payload, dict):
            return

        # 解析告警（兼容新旧格式）
        indicator = payload.get("indicator", payload)
        alert_id = indicator.get("id", payload.get("id", "UNKNOWN"))
        self._stats["total_received"] += 1

        # 构建为 ThreatIndicator 用于签名匹配
        threat = ThreatIndicator(
            id=alert_id,
            category=ThreatCategory(indicator.get("category", payload.get("category", "unknown"))),
            severity=AlertSeverity(indicator.get("severity", payload.get("severity", "low"))),
            source_ip=indicator.get("source_ip", payload.get("source_ip", "")),
            target_ip=indicator.get("target_ip", payload.get("target_ip")),
            target_port=indicator.get("target_port", payload.get("target_port")),
            description=indicator.get("description", payload.get("description", "")),
            raw_data=indicator.get("raw_data", payload.get("raw_data", {})),
            detection_time=indicator.get("detection_time", payload.get("detection_time", "")),
        )

        # ---- 签名引擎匹配（<1ms） ----
        sig_alert = {
            "type": threat.category.value,
            "source_ip": threat.source_ip,
            "dst_port": threat.target_port,
            "packets": threat.raw_data.get("packets", 0),
            "ports": threat.raw_data.get("ports", 0),
            "payload": str(threat.raw_data.get("payload", "")),
        }
        sig_result = self.sig_engine.match(sig_alert)

        if sig_result is not None and sig_result["confidence"] >= 0.5:
            # ── 规则命中：直接发 rule_handled，跳过聚合+双脑 ──
            self._stats["rule_hit"] += 1
            cat = threat.category.value
            self._stats["by_category"][cat] = self._stats["by_category"].get(cat, 0) + 1

            await self._publish_rule_handled(threat, sig_result)
        else:
            # ── 规则未命中：发 unhandled_threat 给 EventAggregator ──
            self._stats["rule_miss"] += 1
            await self._publish_unhandled(threat, payload)

    async def _publish_rule_handled(
        self, threat: ThreatIndicator, sig_result: Dict[str, Any]
    ) -> None:
        """
        规则命中 → 发布 rule_handled（包含双脑等价输出）。
        Validator 直接消费此消息进行校验。
        """
        msg = Message(
            source="RuleEngineFrontend",
            target="Validator",
            type="rule_handled",
            payload={
                "alert_id": threat.id,
                "source_ip": threat.source_ip,
                "target_ip": threat.target_ip,
                "target_port": threat.target_port,
                "category": threat.category.value,
                "severity": sig_result["severity"],
                "action": sig_result["action"],
                "confidence": sig_result["confidence"],
                "rule_id": sig_result["rule_id"],
                "rule_category": sig_result["category"],
                "reason": (
                    f"[RULE-FRONTEND] 规则 {sig_result['rule_id']} 命中 "
                    f"({sig_result['category']})，置信度 {sig_result['confidence']:.2f}"
                ),
                "attack_type": sig_result.get("category", "unknown"),
                "root_cause": f"签名快速通道 sid={sig_result['rule_id']}",
                "recommended_actions": [sig_result["action"]],
                "timestamp": datetime.now().isoformat(),
                # 双脑等价格式字段（Validator 兼容）
                "severity_confirm": sig_result["severity"],
                "compute_cost": 0.05,
                # 溯源格式
                "trace_data": {
                    "summary": f"[RULE-FRONTEND] 签名规则快速命中",
                    "method": f"SignatureEngine sid={sig_result['rule_id']}",
                },
            },
        )
        await self.bus.publish(msg)
        self.logger.info(
            f"[RULE-HIT] {threat.id} | {threat.category.value}/{sig_result['severity']} "
            f"→ {sig_result['action']} | sid={sig_result['rule_id']}"
        )

    async def _publish_unhandled(self, threat: ThreatIndicator, raw_payload: Dict) -> None:
        """
        规则未命中 → 发布 unhandled_threat（EventAggregator 消费）。
        保持与原始 threat_alert 格式兼容，追加 rule_miss 标记。
        """
        raw_payload["rule_miss"] = True
        raw_payload["rule_checked"] = True
        msg = Message(
            source="RuleEngineFrontend",
            target="EventAggregator",
            type="unhandled_threat",
            payload=raw_payload,
        )
        await self.bus.publish(msg)
