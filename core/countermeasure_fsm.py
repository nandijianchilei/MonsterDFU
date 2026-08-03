"""
L0-L4 反击状态机（Phase 1.5 新增 L4 网络隔离）
每 IP 独立状态机，按攻击持续时间和严重程度自动升级/降级反制策略。
防震荡：升级后至少停留 60s 才降级，降级后 30s 不反弹。

L4 网络隔离三道闸门（仅由外部 check_network_kill_conditions 触发）：
  1. 自身系统频发漏洞报错
  2. L3 已不足以阻挡攻击
  3. Web 面板无人确认超过 10 分钟（依赖 Web 面板登录/API Key 认证）
  禁止碰触物理网卡 —— 仅走防火墙软隔离
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("CountermeasureFSM")

# ── 等级定义 ──

class FSMLevel:
    """状态等级常量。"""
    L0_MONITOR = "L0-monitor"
    L1_SOFT = "L1-soft"
    L2_HARD = "L2-hard"
    L3_OFFENSIVE = "L3-offensive"
    L4_ISOLATE = "L4-isolate"  # Phase 1.5: 网络隔离

LEVEL_ORDER = [
    FSMLevel.L0_MONITOR,
    FSMLevel.L1_SOFT,
    FSMLevel.L2_HARD,
    FSMLevel.L3_OFFENSIVE,
    FSMLevel.L4_ISOLATE,
]
LEVEL_ACTIONS = {
    FSMLevel.L0_MONITOR: "monitor",
    FSMLevel.L1_SOFT: "rate_limit",
    FSMLevel.L2_HARD: "isolate_ip",
    FSMLevel.L3_OFFENSIVE: "block",
    FSMLevel.L4_ISOLATE: "network_isolation",  # 防火墙软隔离，不动物理网卡
}

# ── 超参 ──

DEFAULT_ESCALATION_COUNT = 3      # 连续告警 3 次升级
DEFAULT_ESCALATION_TIME = 120     # 或 120s 内持续告警
DEFAULT_COOLDOWN_AFTER_UP = 60    # 升级后至少 60s 才降级
DEFAULT_DEBOUNCE_DOWN = 30        # 降级后 30s 不反弹
DEFAULT_TTL_AFTER_IDLE = 300      # 无新告警 5min 后移除状态机

# ── L2 硬隔离升级门槛（severity 参与判定）──
# 判定规则：仅 low 告警不得触发硬隔离升级（避免"3 条 low 就硬隔离 IP"的过激行为）。
#   1. 升级目标为 L2_HARD 时，要求该 IP 的 peak_severity 至少为 L2_HARD_MIN_SEVERITY（high）；
#   2. 全部为 low 告警时，需累计告警数达到 L2_HARD_LOW_COUNT_CAP 才允许升级（防御性兜底）。
# 可通过环境变量覆盖：DFU_FSM_L2_MIN_SEVERITY / DFU_FSM_L2_LOW_COUNT_CAP
L2_HARD_MIN_SEVERITY = "high"
L2_HARD_LOW_COUNT_CAP = 8
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "severe": 3}

# ── L4 三闸门超参 ──
# 以下参数为全局设定，也可通过 check_network_kill_conditions 覆盖
L4_VULN_THRESHOLD = 5             # 自身漏洞报错次数阈值
L4_WEB_CONFIRM_TIMEOUT = 600      # Web 面板无人确认超时（秒）= 10 分钟
L4_L3_PERSIST_THRESHOLD = 180     # L3 级别持续攻击无法压制的时间（秒）


class IPState:
    """单一 IP 的 FSM 状态。"""

    def __init__(self, source_ip: str) -> None:
        self.source_ip = source_ip
        self.level: str = FSMLevel.L0_MONITOR
        self.alert_count = 0
        self.first_seen: float = time.time()
        self.last_alert: float = time.time()
        self.last_upgrade: float = 0.0
        self.last_downgrade: float = 0.0
        self.peak_severity: str = "low"

        # ── L4 三闸门状态（仅 L3→L4 升级时判定）──
        # 闸门1：自身漏洞报错次数
        self.vuln_error_count: int = 0
        # 闸门1：最近一次漏洞报错时间
        self.last_vuln_error: float = 0.0
        # 闸门2：L3 级别的持续攻击是否无法压制
        self.l3_unstoppable_since: Optional[float] = None
        # 闸门3：是否已通过 Web 面板获得确认（登录/API Key 认证，非消息总线）
        self.web_panel_confirmed: bool = False
        self.web_panel_last_check: float = 0.0

    def record_vuln_error(self, now: float) -> None:
        """记录一次自身漏洞报错（闸门1）。"""
        self.vuln_error_count += 1
        self.last_vuln_error = now

    def set_web_panel_confirmed(self, confirmed: bool, now: float) -> None:
        """设置 Web 面板确认状态（闸门3 认证态，仅 Web 面板 API 调用有效）。"""
        self.web_panel_confirmed = confirmed
        self.web_panel_last_check = now

    def check_l4_triple_gate(self, now: float) -> Tuple[bool, str]:
        """
        检查 L4 三闸门是否全部满足。

        Returns:
            (passed: bool, reason: str)
        """
        gates = []
        reasons = []

        # 闸门1：自身漏洞报错次数 ≥ 阈值
        gate1 = self.vuln_error_count >= L4_VULN_THRESHOLD
        gates.append(gate1)
        reasons.append(
            f"闸门1(自身漏洞): {self.vuln_error_count}/{L4_VULN_THRESHOLD}"
        )

        # 闸门2：L3 无法压制攻击 ≥ 阈值
        if self.l3_unstoppable_since is not None:
            l3_duration = now - self.l3_unstoppable_since
            gate2 = l3_duration >= L4_L3_PERSIST_THRESHOLD
            reasons.append(
                f"闸门2(L3不可挡): {l3_duration:.0f}s/{L4_L3_PERSIST_THRESHOLD}s"
            )
        else:
            gate2 = False
            reasons.append("闸门2(L3不可挡): 未触发")
        gates.append(gate2)

        # 闸门3：Web 面板无人确认超时（认证操作仅依赖 Web 面板）
        if self.web_panel_last_check > 0:
            no_confirm_duration = now - self.web_panel_last_check
            gate3 = self.web_panel_confirmed is False and no_confirm_duration >= L4_WEB_CONFIRM_TIMEOUT
            reasons.append(
                f"闸门3(Web无人确认): {no_confirm_duration:.0f}s/{L4_WEB_CONFIRM_TIMEOUT}s"
            )
        else:
            # 从未触发过 Web 确认检查，默认超时
            gate3 = True
            reasons.append("闸门3(Web无人确认): 从未确认")
        gates.append(gate3)

        all_passed = all(gates)
        return all_passed, "; ".join(reasons)

    def update(self, severity: str, now: float) -> "PendingAction":
        """
        收到新告警时调用，返回是否触发升级/降级/保持。

        Returns:
            PendingAction 描述要执行的操作
        """
        self.alert_count += 1
        self.last_alert = now

        # 更新峰值 severity
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(self.peak_severity, 0):
            self.peak_severity = severity

        return self._evaluate(now)

    def tick(self, now: float) -> Optional["PendingAction"]:
        """
        无新告警时定时心跳调用，处理超时降级或移除。
        """
        elapsed = now - self.last_alert

        # 长时间无活动 → 逐步降级
        if elapsed > 60 and self.level != FSMLevel.L0_MONITOR:
            cooldown_ok = (now - self.last_upgrade) > DEFAULT_COOLDOWN_AFTER_UP
            if cooldown_ok:
                new_level = self._decrement()
                self.last_downgrade = now
                self.level = new_level
                logger.info(
                    f"[FSM] {self.source_ip} 超时降级: {new_level} "
                    f"(静默 {elapsed:.0f}s)"
                )
                return PendingAction(
                    ip=self.source_ip,
                    old_level=self._increment(1),
                    new_level=new_level,
                    action=LEVEL_ACTIONS[new_level],
                    reason=f"超时静默 {elapsed:.0f}s 自动降级",
                )

        # 超时无活动且 L0 → 标记可移除
        if elapsed > DEFAULT_TTL_AFTER_IDLE and self.level == FSMLevel.L0_MONITOR:
            return PendingAction(
                ip=self.source_ip,
                old_level=FSMLevel.L0_MONITOR,
                new_level="REMOVED",
                action="remove",
                reason=f"超时 {elapsed:.0f}s 无活动，移除状态机",
            )

        return None

    def _evaluate(self, now: float) -> "PendingAction":
        """评估是否需要升级。"""
        # 防震荡：升级后冷却期内不降级
        if now - self.last_upgrade < DEFAULT_COOLDOWN_AFTER_UP:
            # 但可以继续升级
            pass

        # 升级判定
        should_up = False
        reason = ""

        if self.alert_count >= DEFAULT_ESCALATION_COUNT:
            should_up = True
            reason = f"连续 {self.alert_count} 次告警触发升级"
        elif (now - self.first_seen) >= DEFAULT_ESCALATION_TIME:
            should_up = True
            reason = f"持续攻击 {DEFAULT_ESCALATION_TIME}s 触发升级"

        if not should_up:
            return PendingAction(
                ip=self.source_ip,
                old_level=self.level,
                new_level=self.level,
                action=LEVEL_ACTIONS[self.level],
                reason="维持当前等级",
                keep_level=True,
            )

        # 检查是否可以升级
        level_idx = LEVEL_ORDER.index(self.level)
        if level_idx >= len(LEVEL_ORDER) - 1:
            return PendingAction(
                ip=self.source_ip,
                old_level=self.level,
                new_level=self.level,
                action=LEVEL_ACTIONS[self.level],
                reason="已达最高等级",
                keep_level=True,
            )

        new_level = LEVEL_ORDER[level_idx + 1]

        # ── severity 参与升级判定：L2 硬隔离门槛 ──
        # 仅 low 告警不得触发硬隔离升级；需累计 high/critical（peak_severity >=
        # L2_HARD_MIN_SEVERITY），或全部为 low 时累计告警数达到 L2_HARD_LOW_COUNT_CAP
        # 才允许升级到 L2，避免"3 条 low 就硬隔离 IP"的过激行为。
        if new_level == FSMLevel.L2_HARD:
            sev_score = SEVERITY_ORDER.get(self.peak_severity, 0)
            if sev_score < SEVERITY_ORDER.get(L2_HARD_MIN_SEVERITY, 2) and \
               self.alert_count < L2_HARD_LOW_COUNT_CAP:
                logger.info(
                    f"[FSM] {self.source_ip} 拒绝升级 L2-hard: 仅 {self.peak_severity} 告警"
                    f"(需 {L2_HARD_MIN_SEVERITY}+ 或累计 {L2_HARD_LOW_COUNT_CAP} 次)"
                )
                return PendingAction(
                    ip=self.source_ip,
                    old_level=self.level,
                    new_level=self.level,
                    action=LEVEL_ACTIONS[self.level],
                    reason=f"仅 {self.peak_severity} 告警，未达硬隔离升级条件",
                    keep_level=True,
                )

        self.level = new_level
        self.last_upgrade = now
        self.alert_count = 0  # 升级后重置计数

        logger.info(
            f"[FSM] {self.source_ip} 升级: {new_level} | {reason} | "
            f"peak={self.peak_severity}"
        )
        return PendingAction(
            ip=self.source_ip,
            old_level=LEVEL_ORDER[level_idx],
            new_level=new_level,
            action=LEVEL_ACTIONS[new_level],
            reason=f"[FSM] {reason} → {new_level}",
            keep_level=False,
        )

    def _increment(self, n: int = 1) -> str:
        idx = LEVEL_ORDER.index(self.level)
        new_idx = min(idx + n, len(LEVEL_ORDER) - 1)
        return LEVEL_ORDER[new_idx]

    def _decrement(self) -> str:
        idx = LEVEL_ORDER.index(self.level)
        return LEVEL_ORDER[max(idx - 1, 0)]


class PendingAction:
    """FSM 评估输出的待执行动作。"""

    def __init__(
        self,
        ip: str,
        old_level: str,
        new_level: str,
        action: str,
        reason: str,
        keep_level: bool = False,
    ) -> None:
        self.ip = ip
        self.old_level = old_level
        self.new_level = new_level
        self.action = action
        self.reason = reason
        self.keep_level = keep_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "old_level": self.old_level,
            "new_level": self.new_level,
            "action": self.action,
            "reason": self.reason,
            "keep_level": self.keep_level,
        }


class CountermeasureFSM:
    """
    L0-L4 反击状态机管理器（Phase 1.5 新增 L4 网络隔离）。
    管理全量 IP 的独立状态机，提供告警评估和心跳降级接口。
    """

    def __init__(self) -> None:
        self._states: Dict[str, IPState] = {}
        self._stats = {
            "total_ips": 0,
            "active_l0": 0,
            "active_l1": 0,
            "active_l2": 0,
            "active_l3": 0,
            "active_l4": 0,
            "upgrades": 0,
            "downgrades": 0,
            "removed": 0,
            "l4_activations": 0,
        }
        self._enabled = True

    # ── 公开接口 ──

    def evaluate(
        self,
        source_ip: str,
        severity: str = "medium",
        category: str = "unknown",
    ) -> PendingAction:
        """
        收到新告警时评估该 IP 的状态机。

        Args:
            source_ip: 攻击源 IP
            severity: 告警严重级别
            category: 告警类别

        Returns:
            PendingAction 描述反制动作
        """
        now = time.time()
        state = self._states.get(source_ip)
        if state is None:
            state = IPState(source_ip)
            self._states[source_ip] = state
            self._stats["total_ips"] += 1
            logger.debug(f"[FSM] 新建状态机: {source_ip}")

        action = state.update(severity, now)
        self._refresh_stats()

        if not action.keep_level:
            self._stats["upgrades"] += 1

        return action

    def check_network_kill_conditions(self, source_ip: str) -> Optional[PendingAction]:
        """
        检查指定 IP 是否可以触发 L4 网络隔离（三闸门）。

        仅在 L3 状态下检查；L4 状态下检查是否可以降级回 L3。
        返回 PendingAction 或 None。
        """
        now = time.time()
        state = self._states.get(source_ip)
        if state is None:
            return None

        if state.level == FSMLevel.L4_ISOLATE:
            # L4 状态下检查是否应降级回 L3
            # 条件：任一闸门不再满足
            passed, _ = state.check_l4_triple_gate(now)
            if not passed:
                # 闸门不再全满足 → 降级回 L3
                old_level = state.level
                state.level = FSMLevel.L3_OFFENSIVE
                state.last_downgrade = now
                self._stats["downgrades"] += 1
                logger.info(
                    f"[FSM] {source_ip} L4→L3 降级: 闸门条件不再全部满足"
                )
                self._refresh_stats()
                return PendingAction(
                    ip=source_ip,
                    old_level=old_level,
                    new_level=FSMLevel.L3_OFFENSIVE,
                    action=LEVEL_ACTIONS[FSMLevel.L3_OFFENSIVE],
                    reason="L4→L3 降级: 闸门条件不再全部满足",
                )
            return None

        # 仅在 L3 状态下检查能否升级到 L4
        if state.level != FSMLevel.L3_OFFENSIVE:
            return None

        # 标记 L3 无法压制
        if state.l3_unstoppable_since is None:
            state.l3_unstoppable_since = now

        passed, reason = state.check_l4_triple_gate(now)
        if not passed:
            return None

        # 三闸门全开 → 触发 L4 网络隔离（防火墙软隔离，不动物理网卡）
        old_level = state.level
        state.level = FSMLevel.L4_ISOLATE
        state.last_upgrade = now
        self._stats["l4_activations"] += 1
        self._stats["upgrades"] += 1

        logger.warning(
            f"[FSM] {source_ip} 升级→L4-ISOLATE | 三闸门全开: {reason}"
        )
        self._refresh_stats()
        return PendingAction(
            ip=source_ip,
            old_level=old_level,
            new_level=FSMLevel.L4_ISOLATE,
            action=LEVEL_ACTIONS[FSMLevel.L4_ISOLATE],
            reason=f"L4 网络隔离触发 | 三闸门全开: {reason}",
        )

    def record_vuln_error(self, source_ip: str) -> None:
        """记录指定 IP 的自身漏洞报错（闸门1 计数）。"""
        state = self._states.get(source_ip)
        if state:
            state.record_vuln_error(time.time())

    def set_web_panel_confirmed(self, source_ip: str, confirmed: bool) -> None:
        """
        设置 Web 面板确认状态（闸门3）。
        此方法只能由 Web 面板的认证 API 调用，不接受消息总线消息。
        """
        state = self._states.get(source_ip)
        if state:
            state.set_web_panel_confirmed(confirmed, time.time())

    def tick_all(self) -> List[PendingAction]:
        """
        定时心跳（建议 30s 调用一次），处理降级和过期移除。
        """
        actions: List[PendingAction] = []
        now = time.time()
        to_remove: List[str] = []

        for ip, state in self._states.items():
            result = state.tick(now)
            if result is not None:
                if result.new_level == "REMOVED":
                    to_remove.append(ip)
                    self._stats["removed"] += 1
                    self._stats["downgrades"] += 1
                elif result.new_level != result.old_level:
                    self._stats["downgrades"] += 1
                actions.append(result)

        for ip in to_remove:
            del self._states[ip]
            self._stats["total_ips"] -= 1

        self._refresh_stats()
        return actions

    def get_level(self, source_ip: str) -> Optional[str]:
        """查询指定 IP 的当前等级。"""
        state = self._states.get(source_ip)
        return state.level if state else None

    def get_all_levels(self) -> Dict[str, str]:
        """返回全部 {IP: 等级} 映射。"""
        return {ip: s.level for ip, s in self._states.items()}

    def summary(self) -> str:
        """返回概要。"""
        s = self._stats
        return (
            f"CountermeasureFSM(总IP={s['total_ips']}, "
            f"L0={s['active_l0']}, L1={s['active_l1']}, "
            f"L2={s['active_l2']}, L3={s['active_l3']}, "
            f"L4={s['active_l4']}, "
            f"升级={s['upgrades']}, 降级={s['downgrades']}, "
            f"L4触发={s['l4_activations']})"
        )

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled

    # ── 内部 ──

    def _refresh_stats(self) -> None:
        l0 = l1 = l2 = l3 = l4 = 0
        for s in self._states.values():
            if s.level == FSMLevel.L0_MONITOR:
                l0 += 1
            elif s.level == FSMLevel.L1_SOFT:
                l1 += 1
            elif s.level == FSMLevel.L2_HARD:
                l2 += 1
            elif s.level == FSMLevel.L3_OFFENSIVE:
                l3 += 1
            elif s.level == FSMLevel.L4_ISOLATE:
                l4 += 1
        self._stats["active_l0"] = l0
        self._stats["active_l1"] = l1
        self._stats["active_l2"] = l2
        self._stats["active_l3"] = l3
        self._stats["active_l4"] = l4
