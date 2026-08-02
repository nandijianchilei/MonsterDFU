"""
报警鼻（Alarm Nose）— 4 级自动警报闭环器官。

职责：
    对威胁告警 / FSM 状态 / 器官健康三类信号做分级评估，形成
    L1(记录·自然衰减) → L2(通知+人工确认+倒计时) → L3(关端口+紧急通知+倒计时)
    → L4(防火墙全封锁·软隔离信号+倒计时，超时强制执行) 的自动升级闭环。

边界（严格遵守）：
    - L4 最终动作复用 core/countermeasure_fsm.py 的 L4 软隔离机制（不动物理网卡）。
      AlarmNose 只发布触发信号（消息总线 + 可注入回调），不直接修改 FSM 状态。
    - L3 关闭被攻击端口复用 organs/firewall_executor.py 的现有封禁能力。
    - 本器官只读取 FSM 等级与 MedicAgent 健康状态，不反向修改它们。
"""

import asyncio
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger("AlarmNose")


class AlarmNose:
    """
    4 级自动警报器官。

    使用示例：
        nose = AlarmNose(config.alarm_nose, notifier=notifier, firewall=firewall, fsm=fsm)
        await nose.assess(alert_payload)          # threat_alert 事件
        await nose.assess_fsm(fsm.get_all_levels())  # isolation_action 事件
        await nose.assess_health(medic.get_health_status())  # 心跳回调
    """

    # 警报等级常量（与 FSM L0-L4 对齐，L0 表示正常/监控）
    L0 = "L0-normal"
    L1 = "L1-log"
    L2 = "L2-confirm"
    L3 = "L3-emergency"
    L4 = "L4-isolate"
    LEVEL_ORDER = [L0, L1, L2, L3, L4]

    # 告警 payload 白名单字段（与 false_positive_filter 保持一致）
    _ALERT_FIELDS = ("src_ip", "source_ip", "dst_port", "target_port", "packet_count",
                     "signature_hits", "category", "severity", "id", "description")

    def __init__(
        self,
        config,
        notifier: Optional[Any] = None,
        firewall: Optional[Any] = None,
        fsm: Optional[Any] = None,
        bus: Optional[Any] = None,
        on_l4_execute: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger=None,
    ) -> None:
        self.cfg = config
        self._notifier = notifier
        self._firewall = firewall          # FirewallExecutor（可为 None → 仅记录模拟）
        self._fsm = fsm                    # CountermeasureFSM（只读）
        self._bus = bus                    # MessageBus（用于发布 L4 触发信号）
        self._on_l4_execute = on_l4_execute  # 外部注入的 L4 软隔离执行回调（复用 FSM 机制）
        self.logger = logger or globals()["logger"]

        # 当前警报状态
        self._level: str = self.L0
        self._trigger: str = ""
        self._alert_count: int = 0
        self._window_start: float = 0.0
        self._last_alert_ts: float = 0.0
        self._ack_required: bool = False
        self._countdown_deadline: Optional[float] = None
        self._countdown_task: Optional[asyncio.Task] = None
        self._last_action_summary: str = ""

        # FSM / 健康只读快照
        self._fsm_levels: Dict[str, str] = {}
        self._health: Dict[str, str] = {}

        # 4 级告警历史（供前端表格）
        self._history: List[Dict[str, Any]] = []

        # 后台任务
        self._loop_task: Optional[asyncio.Task] = None
        self._running: bool = False

    # ── 生命周期 ──

    def start(self) -> None:
        """启动后台衰减/倒计时巡检任务（幂等）。"""
        if self._running:
            return
        self._running = True
        self._loop_task = asyncio.create_task(self._loop())
        self.logger.info("[AlarmNose] 报警鼻后台巡检已启动")

    async def stop(self) -> None:
        """停止后台任务并清理倒计时。"""
        self._running = False
        if self._loop_task is not None:
            self._loop_task.cancel()
            self._loop_task = None
        if self._countdown_task is not None:
            self._countdown_task.cancel()
            self._countdown_task = None
        self._countdown_deadline = None
        self.logger.info("[AlarmNose] 报警鼻已停止")

    async def _loop(self) -> None:
        """后台巡检：L1 自然衰减 + 倒计时兜底（每 1 秒）。"""
        while self._running:
            try:
                await self._decay()
                # 倒计时兜底：若任务异常丢失仍按 deadline 强制执行
                if self._level in (self.L2, self.L3, self.L4) and self._countdown_deadline is not None:
                    if time.time() >= self._countdown_deadline:
                        await self._on_countdown_expire(force=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.warning(f"[AlarmNose] 巡检异常: {e}")
            await asyncio.sleep(1.0)

    # ── 事件桥接入口 ──

    async def assess(self, alert: Dict[str, Any]) -> str:
        """
        评估威胁告警（threat_alert 事件 → assess）。

        alert 支持两种形态：
          - 扁平：{"src_ip": "...", "dst_port": 8080, "packet_count": N, ...}
          - 嵌套：{"indicator": {"source_ip": "...", "category": "..."}, "severity": "..."}
        仅提取白名单字段，其余（含原始 payload 文本）一律丢弃。
        """
        # 提取白名单字段
        flat: Dict[str, Any] = {}
        if isinstance(alert.get("indicator"), dict):
            flat = self._pick(alert["indicator"])
        flat.update(self._pick(alert))

        src_ip = flat.get("src_ip") or flat.get("source_ip") or "unknown"
        severity = str(flat.get("severity", "medium")).lower()
        category = str(flat.get("category", "unknown"))

        now = time.time()
        self._alert_count += 1
        self._last_alert_ts = now
        if self._window_start <= 0:
            self._window_start = now

        # 惰性衰减：若曾升级后回到低等级，重置窗口
        if self._level in (self.L0, self.L1):
            self._window_start = now

        # L1：记录（自然衰减）
        if self._level == self.L0:
            self._level = self.L1
            self._trigger = f"告警 {category}/{severity} 来自 {src_ip}"
            self.logger.info(f"[AlarmNose] L1 记录告警: {self._trigger} (累计 {self._alert_count})")

        # L2 判定：窗口内告警数达标 或 高严重级告警
        if self._level == self.L1:
            window_alerts = self._alert_count
            high_count_ok = window_alerts >= self.cfg.l2_high_count
            severe_ok = severity in ("high", "severe")
            if high_count_ok or severe_ok:
                self.logger.warning(
                    f"[AlarmNose] L1→L2 升级 | 窗口告警 {window_alerts}/{self.cfg.l2_high_count} "
                    f"或 severity={severity}"
                )
                await self._escalate(
                    self.L2,
                    trigger=f"窗口内 {window_alerts} 条告警（{category}/{severity}）来自 {src_ip}",
                )
                return self._level

        # L3 快速通道：severe 级直接上 L3
        if self._level == self.L2 and severity == "severe":
            self.logger.warning(f"[AlarmNose] L2→L3 快速升级 | severe 告警来自 {src_ip}")
            await self._escalate(
                self.L3,
                trigger=f"severe 级告警来自 {src_ip}（{category}）",
            )
            return self._level

        return self._level

    async def assess_fsm(self, fsm_levels: Dict[str, str]) -> str:
        """
        评估 FSM 等级快照（isolation_action 事件 → assess_fsm）。

        只读取、不修改：若 FSM 中某 IP 已进入 L4-isolate，报警鼻同步进入 L4 警报态。
        """
        self._fsm_levels = dict(fsm_levels or {})
        l4_ips = [ip for ip, lv in self._fsm_levels.items() if str(lv).endswith("L4-isolate") or str(lv) == "L4-isolate"]

        if l4_ips and self._level != self.L4:
            self.logger.warning(f"[AlarmNose] FSM L4 软隔离已激活，报警鼻同步 L4: {l4_ips}")
            await self._escalate(
                self.L4,
                trigger=f"FSM 软隔离已激活: {', '.join(l4_ips[:5])}",
                fsm_sync=True,
            )
        return self._level

    async def assess_health(self, health: Dict[str, Any]) -> str:
        """
        评估器官健康状态（MedicAgent 心跳回调变化 → assess_health）。

        只读取健康状态；不健康比例达到 organ_failure_l3_ratio 升 L3，
        达到 organ_failure_l4_ratio 升 L4。
        """
        snapshot: Dict[str, str] = {}
        for name, record in (health or {}).items():
            if hasattr(record, "status"):
                snapshot[name] = record.status.value if hasattr(record.status, "value") else str(record.status)
            elif isinstance(record, dict):
                snapshot[name] = str(record.get("status", "unknown"))
            else:
                snapshot[name] = str(record)
        self._health = snapshot

        total = len(snapshot)
        if total == 0:
            return self._level
        unhealthy = [n for n, s in snapshot.items() if s not in ("healthy", "ok")]
        ratio = len(unhealthy) / total

        self.logger.debug(f"[AlarmNose] 健康巡检: 不健康 {len(unhealthy)}/{total} ({ratio:.2f})")

        if ratio >= self.cfg.organ_failure_l4_ratio and self._level not in (self.L3, self.L4):
            await self._escalate(
                self.L4,
                trigger=f"器官不健康比例 {ratio:.0%} ≥ L4 阈值 {self.cfg.organ_failure_l4_ratio:.0%} "
                        f"({', '.join(unhealthy[:5])})",
            )
        elif ratio >= self.cfg.organ_failure_l3_ratio and self._level == self.L1:
            await self._escalate(
                self.L3,
                trigger=f"器官不健康比例 {ratio:.0%} ≥ L3 阈值 {self.cfg.organ_failure_l3_ratio:.0%} "
                        f"({', '.join(unhealthy[:5])})",
            )
        return self._level

    # ── 升级与倒计时 ──

    async def _escalate(self, level: str, trigger: str, fsm_sync: bool = False) -> None:
        """统一升级入口：设置等级、通知、启动倒计时。"""
        self._level = level
        self._trigger = trigger
        self._ack_required = level in (self.L2, self.L3, self.L4)

        if level == self.L2:
            await self._notify("L2", trigger, alert_count=self._alert_count,
                               countdown_secs=self.cfg.l2_countdown_secs)
            self._start_countdown(self.cfg.l2_countdown_secs, self.L3,
                                  f"L2 未确认超时自动升级 L3: {trigger}")
        elif level == self.L3:
            summary = await self._execute_l3()
            self._last_action_summary = summary
            await self._notify("L3", trigger, countdown_secs=self.cfg.l3_countdown_secs,
                               action_summary=summary)
            self._start_countdown(self.cfg.l3_countdown_secs, self.L4,
                                  f"L3 未确认超时自动升级 L4: {trigger}")
        elif level == self.L4:
            await self._execute_l4(trigger)
            await self._notify("L4", trigger, countdown_secs=self.cfg.l4_execute_countdown_secs)
            self._start_countdown(self.cfg.l4_execute_countdown_secs, self.L4,
                                  f"L4 超时强制执行软隔离: {trigger}")

        self._record_history(level, trigger, fsm_sync=fsm_sync)

    def _start_countdown(self, secs: float, next_level: str, reason: str) -> None:
        """启动倒计时任务；到达 deadline 后由任务或巡检兜底触发升级。"""
        self._countdown_deadline = time.time() + max(float(secs), 1.0)
        self._countdown_next_level = next_level
        self._countdown_reason = reason
        if self._countdown_task is not None and not self._countdown_task.done():
            self._countdown_task.cancel()
        self._countdown_task = asyncio.create_task(self._countdown_worker(self._countdown_deadline))

    async def _countdown_worker(self, deadline: float) -> None:
        """倒计时等待任务。"""
        try:
            remain = deadline - time.time()
            if remain > 0:
                await asyncio.sleep(remain)
            await self._on_countdown_expire(force=False)
        except asyncio.CancelledError:
            pass

    async def _on_countdown_expire(self, force: bool = False) -> None:
        """
        倒计时到期统一处理。

        L2 超时 → L3；L3 超时 → L4；L4 超时 → 强制执行软隔离（复用 FSM 机制，不物理断网）。
        """
        if self._level == self.L0:
            return
        # 非强制触发且未到 deadline 时直接返回（防重复）
        if not force and self._countdown_deadline is not None and time.time() < self._countdown_deadline:
            return

        current = self._level
        self._countdown_task = None
        self._countdown_deadline = None
        self.logger.warning(f"[AlarmNose] 倒计时到期: {current} → 升级处理")

        if current == self.L2:
            await self._escalate(self.L3, trigger=self._trigger or "L2 倒计时超时自动升级")
        elif current == self.L3:
            await self._escalate(self.L4, trigger=self._trigger or "L3 倒计时超时自动升级")
        elif current == self.L4:
            # L4 超时强制执行软隔离信号
            await self._execute_l4(self._trigger or "L4 倒计时超时强制执行", forced=True)
            await self._notify("L4_EXECUTED", self._trigger or "L4 强制执行")
            self._record_history(self.L4, (self._trigger or "L4 强制执行") + " [已执行]")

    # ── 动作执行 ──

    async def _execute_l3(self) -> str:
        """
        L3 动作：关闭被攻击端口（复用 firewall_executor 封禁能力）。
        未注入防火墙执行器时仅记录模拟结果，保证演示/测试环境安全。
        """
        src_ip = self._last_src_ip()
        if self._firewall is None:
            summary = f"模拟关闭被攻击端口（{src_ip or 'unknown'}），未注入防火墙执行器"
            self.logger.warning(f"[AlarmNose] L3 动作: {summary}")
            return summary
        try:
            result = await self._firewall.block_ip(
                src_ip or "unknown",
                reason="alarm_nose_l3_close_attacked_port",
            )
            summary = f"已关闭来自 {src_ip or 'unknown'} 的攻击通路: {result.message}"
            self.logger.warning(f"[AlarmNose] L3 动作: {summary}")
            return summary
        except Exception as e:
            summary = f"L3 封禁失败: {e}"
            self.logger.error(f"[AlarmNose] {summary}")
            return summary

    async def _execute_l4(self, trigger: str, forced: bool = False) -> None:
        """
        L4 动作：防火墙全封锁（软隔离）。

        报警鼻只发布触发信号（消息总线 + 注入回调），实际软隔离动作由现有
        countermeasure_fsm 机制执行 —— 软隔离，不动物理网卡，不做物理断网。
        """
        signal = {
            "level": "L4",
            "trigger": trigger,
            "forced": forced,
            "source_ip": self._last_src_ip(),
            "action": "soft_isolation_signal",
            "source_organ": "alarm_nose",
            "timestamp": datetime.now().isoformat(),
        }
        # 1) 注入回调（web_server 桥接到 FSM 软隔离机制）
        if self._on_l4_execute is not None:
            try:
                await self._on_l4_execute(signal)
            except Exception as e:
                self.logger.error(f"[AlarmNose] L4 回调执行失败: {e}")
        # 2) 消息总线发布触发信号
        if self._bus is not None:
            try:
                from communication.message_bus import Message
                await self._bus.publish(Message(
                    source="AlarmNose",
                    target="*",
                    type="alarm_nose.l4_execute",
                    payload=signal,
                ))
            except Exception as e:
                self.logger.warning(f"[AlarmNose] L4 信号发布失败: {e}")

        self.logger.warning(
            f"[AlarmNose] L4 触发信号已发布（软隔离，不物理断网）: "
            f"{trigger} forced={forced}"
        )

    # ── 人工确认 / 解除 ──

    async def manual_ack(self, level: Optional[str] = None) -> Dict[str, Any]:
        """
        人工确认当前警报：停止倒计时，确认已处置，等级回到 L1（记录态）。
        """
        if self._level == self.L0:
            return {"success": False, "message": "当前无活动警报"}
        confirmed_level = self._level
        self._stop_countdown()
        self._record_history(confirmed_level, (self._trigger or "人工确认") + " [已确认]")
        self.logger.info(f"[AlarmNose] 人工确认 {confirmed_level}，解除倒计时")
        self._level = self.L1
        self._ack_required = False
        self._trigger = f"已确认处置（原 {confirmed_level}）"
        return {"success": True, "confirmed_level": confirmed_level, "level": self._level}

    async def manual_cancel(self, level: Optional[str] = None) -> Dict[str, Any]:
        """
        人工取消当前警报：停止倒计时，取消升级，回到 L1（记录态）。
        """
        if self._level == self.L0:
            return {"success": False, "message": "当前无活动警报"}
        cancelled_level = self._level
        self._stop_countdown()
        self._record_history(cancelled_level, (self._trigger or "人工取消") + " [已取消]")
        self.logger.info(f"[AlarmNose] 人工取消 {cancelled_level}，停止自动升级")
        self._level = self.L1
        self._ack_required = False
        self._trigger = f"已人工取消（原 {cancelled_level}）"
        return {"success": True, "cancelled_level": cancelled_level, "level": self._level}

    async def confirm_l4(self) -> Dict[str, Any]:
        """人工确认执行 L4：立即强制执行软隔离信号（复用 FSM 机制）。"""
        if self._level != self.L4:
            return {"success": False, "message": "当前不在 L4 状态，无需确认执行"}
        self._stop_countdown()
        await self._execute_l4(self._trigger or "人工确认执行 L4", forced=True)
        await self._notify("L4_EXECUTED", self._trigger or "人工确认执行 L4")
        self._record_history(self.L4, (self._trigger or "人工确认执行 L4") + " [已确认执行]")
        return {"success": True, "message": "L4 软隔离已确认执行"}

    def _stop_countdown(self) -> None:
        if self._countdown_task is not None and not self._countdown_task.done():
            self._countdown_task.cancel()
        self._countdown_task = None
        self._countdown_deadline = None

    # ── 通知 ──

    async def _notify(self, level: str, trigger: str, alert_count: int = 0,
                      countdown_secs: float = 0.0, action_summary: str = "") -> None:
        if self._notifier is None:
            self.logger.info(f"[AlarmNose] 通知({level}): {trigger}")
            return
        try:
            await self._notifier.send_alarm_alert(
                level=level,
                trigger=trigger,
                alert_count=alert_count,
                countdown_secs=countdown_secs,
                action_summary=action_summary,
            )
        except Exception as e:
            self.logger.warning(f"[AlarmNose] 通知发送失败: {e}")

    # ── L1 自然衰减 ──

    async def _decay(self) -> None:
        """L1 记录态自然衰减：超过 l1_decay_secs 无新告警则回到 L0。"""
        if self._level == self.L1 and self._last_alert_ts > 0:
            idle = time.time() - self._last_alert_ts
            if idle >= self.cfg.l1_decay_secs:
                self.logger.info(f"[AlarmNose] L1 自然衰减 → L0（静默 {idle:.0f}s）")
                self._level = self.L0
                self._trigger = ""
                self._alert_count = 0
                self._window_start = 0.0
                self._ack_required = False

    # ── 状态查询 ──

    def get_status(self) -> Dict[str, Any]:
        """返回报警鼻实时状态（等级/倒计时/历史/只读快照）。"""
        remaining = 0.0
        if self._countdown_deadline is not None:
            remaining = max(0.0, self._countdown_deadline - time.time())
        return {
            "level": self._level,
            "level_label": self._level_label(self._level),
            "trigger": self._trigger,
            "alert_count": self._alert_count,
            "ack_required": self._ack_required,
            "countdown_remaining_secs": round(remaining, 1),
            "countdown_total_secs": self._countdown_total_secs(),
            "last_action_summary": self._last_action_summary,
            "fsm_levels": dict(self._fsm_levels),
            "fsm_l4_ips": [ip for ip, lv in self._fsm_levels.items() if lv == "L4-isolate"],
            "health": dict(self._health),
            "history": list(self._history[-30:]),
        }

    @staticmethod
    def _level_label(level: str) -> str:
        return {
            AlarmNose.L0: "正常监控",
            AlarmNose.L1: "L1 记录·自然衰减",
            AlarmNose.L2: "L2 需人工确认",
            AlarmNose.L3: "L3 紧急处置",
            AlarmNose.L4: "L4 最高威胁·软隔离",
        }.get(level, level)

    def _countdown_total_secs(self) -> float:
        if self._level == self.L2:
            return self.cfg.l2_countdown_secs
        if self._level == self.L3:
            return self.cfg.l3_countdown_secs
        if self._level == self.L4:
            return self.cfg.l4_execute_countdown_secs
        return 0.0

    # ── 内部辅助 ──

    def _pick(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """仅提取白名单字段。"""
        return {k: v for k, v in data.items() if k in self._ALERT_FIELDS}

    def _last_src_ip(self) -> str:
        # 从触发原因中尽力还原源 IP（仅为动作摘要用）
        import re
        m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", self._trigger)
        return m.group(0) if m else "unknown"

    def _record_history(self, level: str, detail: str, fsm_sync: bool = False) -> None:
        self._history.append({
            "level": level,
            "detail": detail,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "fsm_sync": fsm_sync,
        })
        if len(self._history) > 200:
            self._history[:] = self._history[-200:]
