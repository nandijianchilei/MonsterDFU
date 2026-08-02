"""
校验Agent：二次复核过滤
接收双引擎融合后的方案，检查方案是否存在冲突、误判。
对高风险操作必须确认无冲突后才下发，低冲突直接放行。
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, Optional, Set

from communication.message_bus import Message, MessageBus, get_message_bus
from communication.skill_middleware import (
    AlertSeverity,
    AttackAnalysis,
    DefensePlan,
    IsolationAction,
    MergedPlan,
    SkillMiddleware,
)
from config import Config
from utils.logger import get_logger


@dataclass
class ValidationResult:
    """校验结果。"""
    alert_id: str
    passed: bool               # 是否通过校验
    reason: str                # 校验结论/驳回原因
    merged_plan: MergedPlan    # 融合方案（通过时有值）
    conflict_details: Optional[Dict] = None  # 冲突详情（驳回时有值）


class ValidatorAgent:
    """
    校验Agent：二次复核过滤。

    职责：
    1. 等待同一告警的分析引擎方案和响应引擎分析都到达
    2. 融合为统一方案
    3. 检查方案是否存在冲突、误判
    4. 高风险操作强制确认无冲突后才下发
    5. 低冲突直接放行
    """

    def __init__(self, config: Config):
        """
        Args:
            config: 全局配置对象
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.middleware = SkillMiddleware()
        self.logger: logging.Logger = get_logger("Validator")

        # 缓存：alert_id → {"left": plan, "right": analysis}
        self._pending: Dict[str, dict] = {}

        # 已处理的告警（防重）
        self._processed: Set[str] = set()

        # 统计
        self._stats = {
            "total_received": 0,
            "total_passed": 0,
            "total_rejected": 0,
            "rejection_reasons": [],
        }

        self._running = False

    async def start(self) -> None:
        """启动校验Agent，订阅双引擎方案及规则前置快速命中。"""
        self._running = True
        await self.bus.subscribe("defense_plan", self._handle_left_plan)
        await self.bus.subscribe("attack_analysis", self._handle_right_analysis)
        await self.bus.subscribe("rule_handled", self._handle_rule_handled)
        self.logger.info("校验Agent已启动，等待双引擎方案...")

    async def stop(self) -> None:
        """停止校验Agent。"""
        self._running = False
        self.logger.info(
            f"校验Agent已停止 | 通过:{self._stats['total_passed']} | "
            f"驳回:{self._stats['total_rejected']}"
        )

    async def _handle_left_plan(self, msg: Message) -> Optional[Message]:
        """
        接收分析引擎防御方案。

        Args:
            msg: 分析引擎防御方案消息
        """
        if not self._running:
            return None

        payload = msg.payload
        alert_id = payload["alert_id"]

        if alert_id in self._processed:
            return None

        self._stats["total_received"] += 1

        plan = DefensePlan(
            alert_id=alert_id,
            severity_confirm=AlertSeverity(payload["severity_confirm"]),
            action=payload["action"],
            target_ip=payload["target_ip"],
            reason=payload["reason"],
            log_evidence=payload.get("log_evidence", {}),
            compute_cost=payload.get("compute_cost", 0.0),
        )

        if alert_id not in self._pending:
            self._pending[alert_id] = {"left": None, "right": None}
        self._pending[alert_id]["left"] = plan

        self.logger.debug(f"收到分析引擎方案: {alert_id} | 动作: {plan.action}")

        # 检查是否双引擎方案都到了
        return await self._try_merge(alert_id)

    async def _handle_right_analysis(self, msg: Message) -> Optional[Message]:
        """
        接收响应引擎攻击分析。

        Args:
            msg: 响应引擎分析消息
        """
        if not self._running:
            return None

        payload = msg.payload
        alert_id = payload["alert_id"]

        if alert_id in self._processed:
            return None

        self._stats["total_received"] += 1

        analysis = AttackAnalysis(
            alert_id=alert_id,
            attack_type=payload["attack_type"],
            root_cause=payload["root_cause"],
            confidence=payload["confidence"],
            recommended_actions=payload["recommended_actions"],
            estimated_impact=payload.get("estimated_impact", ""),
        )

        if alert_id not in self._pending:
            self._pending[alert_id] = {"left": None, "right": None}
        self._pending[alert_id]["right"] = analysis

        self.logger.debug(f"收到响应引擎分析: {alert_id} | 置信度: {analysis.confidence:.2f}")

        return await self._try_merge(alert_id)

    async def _handle_rule_handled(self, msg: Message) -> Optional[Message]:
        """
        接收规则引擎前置分流的快速命中结果（已含双脑等价输出）。
        规则命中意味着双脑侧已被跳过，直接从校验 -> 处置。

        Args:
            msg: rule_handled 消息
        """
        if not self._running:
            return None

        payload = msg.payload
        alert_id = payload["alert_id"]

        if alert_id in self._processed:
            return None

        self._stats["total_received"] += 1

        # 规则命中已自带合并方案，构造 mock 双脑方案走标准校验路径
        left_plan = DefensePlan(
            alert_id=alert_id,
            severity_confirm=AlertSeverity(payload["severity"]),
            action=payload["action"],
            target_ip=payload["source_ip"],
            reason=payload["reason"],
            log_evidence=payload.get("trace_data", {}),
            compute_cost=0.1,
        )
        right_analysis = AttackAnalysis(
            alert_id=alert_id,
            attack_type=payload.get("attack_type", "unknown"),
            root_cause=f"[SIGNATURE] {payload.get('rule_id', 'N/A')}: {payload.get('reason', '')}",
            confidence=payload.get("confidence", 0.8),
            recommended_actions=[payload["action"]],
            estimated_impact="[RULE-HANDLED] 签名引擎快速通道",
        )

        # 走标准 _merge_plans + _validate 路径
        merged = self._merge_plans(left_plan, right_analysis)
        validation = await self._validate(merged)

        if validation.passed:
            self._stats["total_passed"] += 1
            self.logger.info(
                f"[RULE-HANDLED] 校验通过: {alert_id} | "
                f"动作: {merged.merged_action} | 级别: {left_plan.severity_confirm.value}"
            )
            # 下发执行指令
            isolation_action = self.middleware.plan_to_isolation_action(merged)
            action_msg = Message(
                source="Validator",
                target="IPIsolation",
                type="isolation_action",
                payload={
                    "alert_id": isolation_action.alert_id,
                    "target_ip": isolation_action.target_ip,
                    "action": isolation_action.action,
                    "priority": isolation_action.priority,
                    "reason": isolation_action.reason,
                },
            )
            return action_msg
        else:
            self._stats["total_rejected"] += 1
            self.logger.warning(
                f"[RULE-HANDLED] 校验驳回: {alert_id} | 理由: {validation.reason}"
            )
            return None

    async def _try_merge(self, alert_id: str) -> Optional[Message]:
        """
        尝试融合双引擎方案，两者都到达后进行校验。

        Args:
            alert_id: 告警ID

        Returns:
            若通过校验，返回隔离指令消息；否则返回驳回消息
        """
        pending = self._pending.get(alert_id)
        if not pending or pending["left"] is None or pending["right"] is None:
            return None  # 尚未全部到达

        left_plan = pending["left"]
        right_analysis = pending["right"]

        # 清理缓存
        del self._pending[alert_id]
        self._processed.add(alert_id)

        # 1. 融合方案
        merged = self._merge_plans(left_plan, right_analysis)

        # 2. 校验
        validation = await self._validate(merged)

        if validation.passed:
            self._stats["total_passed"] += 1
            self.logger.info(
                f"校验通过: {alert_id} | 动作: {merged.merged_action} | "
                f"级别: {left_plan.severity_confirm.value}"
            )

            # 3. 下发执行指令
            isolation_action = self.middleware.plan_to_isolation_action(merged)

            action_msg = Message(
                source="Validator",
                target="IPIsolation",
                type="isolation_action",
                payload={
                    "alert_id": isolation_action.alert_id,
                    "target_ip": isolation_action.target_ip,
                    "action": isolation_action.action,
                    "priority": isolation_action.priority,
                    "reason": isolation_action.reason,
                },
            )

            return action_msg

        else:
            self._stats["total_rejected"] += 1
            self._stats["rejection_reasons"].append({
                "alert_id": alert_id,
                "reason": validation.reason,
                "details": validation.conflict_details,
            })
            self.logger.warning(
                f"校验驳回: {alert_id} | 理由: {validation.reason}"
            )
            return None  # 驳回不下发

    def _merge_plans(
        self,
        left_plan: DefensePlan,
        right_analysis: AttackAnalysis,
    ) -> MergedPlan:
        """
        融合左响应引擎方案。

        融合规则：
        - 以分析引擎的处置动作为主
        - 响应引擎的置信度影响最终动作的强制程度
        - 响应引擎的溯源信息补充到理由中

        Args:
            left_plan:      分析引擎方案
            right_analysis: 响应引擎分析

        Returns:
            MergedPlan 实例
        """
        # 默认使用分析引擎的处置动作
        merged_action = left_plan.action

        # 若响应引擎置信度极高且建议更激进，可升格
        if right_analysis.confidence > 0.9:
            if left_plan.action == "monitor" and "isolate_ip" in right_analysis.recommended_actions:
                merged_action = "isolate_ip"
                self.logger.info(f"{left_plan.alert_id}: 响应引擎高置信度触发动作升格: monitor → isolate_ip")

        return MergedPlan(
            alert_id=left_plan.alert_id,
            left_plan=left_plan,
            right_analysis=right_analysis,
            merged_action=merged_action,
        )

    async def _validate(self, merged: MergedPlan) -> ValidationResult:
        """
        二次复核校验。

        检查项：
        1. 左响应引擎方案是否冲突
        2. 是否可能误判（响应引擎置信度过低）
        3. 高风险操作检查
        4. IP 白名单检查

        Args:
            merged: 融合后的方案

        Returns:
            ValidationResult 实例
        """
        left = merged.left_plan
        right = merged.right_analysis
        conflicts = {}

        # 检查1：响应引擎置信度过低 → 可能误判
        if right.confidence < 0.5:
            conflicts["low_confidence"] = {
                "rule": "置信度过低",
                "detail": f"响应引擎置信度仅 {right.confidence:.2f}，低于 0.5 阈值",
            }

        # 检查2：分析引擎动作与响应引擎建议策略一致性
        left_action = left.action
        right_actions = right.recommended_actions
        if left_action == "isolate_ip" and "IP隔离" not in right_actions:
            if right.confidence < 0.6:
                conflicts["action_mismatch"] = {
                    "rule": "双引擎动作不一致",
                    "detail": f"分析引擎建议 {left_action}，响应引擎建议 {', '.join(right_actions)}，"
                              f"且响应引擎置信度({right.confidence:.2f})偏低",
                }

        # 检查3：高风险操作（隔离）→ 必须确认无冲突
        if merged.merged_action == "isolate_ip":
            if conflicts:
                # 存在冲突，驳回高风险操作
                reason = "高风险操作(isolate_ip)与校验规则冲突，驳回执行"
                return ValidationResult(
                    alert_id=merged.alert_id,
                    passed=False,
                    reason=reason,
                    merged_plan=merged,
                    conflict_details=conflicts,
                )
            # 无冲突，执行额外的 IP 合理性检查
            ip = left.target_ip
            octets = ip.split(".")
            if octets[0] == "0" or octets[0] == "255":
                conflicts["invalid_ip"] = {
                    "rule": "无效IP",
                    "detail": f"IP {ip} 为保留地址，不应隔离",
                }

        # 检查4：模拟场景特殊处理 - 暴力破解中等数量不隔离
        if right.attack_type and "暴力破解" in right.attack_type:
            raw = left.log_evidence.get("raw_data", {})
            attempts = raw.get("attempts", 0)
            if attempts < 100 and merged.merged_action == "isolate_ip":
                conflicts["excessive_response"] = {
                    "rule": "过度响应",
                    "detail": f"暴力破解仅 {attempts} 次尝试即触发隔离，建议降级为限速",
                }

        # 判定：有冲突则驳回
        if conflicts:
            reason = "校验发现冲突: " + "; ".join(conflicts.keys())
            return ValidationResult(
                alert_id=merged.alert_id,
                passed=False,
                reason=reason,
                merged_plan=merged,
                conflict_details=conflicts,
            )

        # 无冲突 → 放行
        return ValidationResult(
            alert_id=merged.alert_id,
            passed=True,
            reason="校验通过，无冲突",
            merged_plan=merged,
        )

    def get_stats(self) -> dict:
        """获取统计信息。"""
        return self._stats.copy()
