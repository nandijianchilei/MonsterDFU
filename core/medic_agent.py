"""
医疗Agent自愈系统：独立协程运行的自我愈合模块。

核心功能：
1. 心跳检测：定期轮询所有注册Agent的健康状态，超时未响应标记为故障
2. 故障隔离：标记故障Agent为 isolated 状态，暂停向其发消息
3. 权重回滚：维护每个Agent的配置快照，故障时自动回滚到上一稳定版本
4. 熔断机制：当故障Agent数量超过阈值时，自动触发熔断
   ——所有处置类Agent切换到安全模式（仅记录不执行）
5. 恢复检测：故障Agent恢复心跳后自动解除隔离
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from config import Config
from utils.logger import get_logger


class AgentHealthStatus(Enum):
    """Agent 健康状态枚举。"""
    HEALTHY = "healthy"       # 正常
    DEGRADED = "degraded"     # 降级（响应慢但未超时）
    UNRESPONSIVE = "unresponsive"  # 无响应
    ISOLATED = "isolated"     # 已隔离
    RECOVERING = "recovering" # 恢复中


@dataclass
class AgentHealthRecord:
    """单个 Agent 的健康记录。"""
    agent_name: str
    status: AgentHealthStatus = AgentHealthStatus.HEALTHY
    last_heartbeat: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    isolated_at: Optional[float] = None
    config_snapshot: Optional[dict] = None  # 配置快照，用于回滚
    error_log: List[str] = field(default_factory=list)


@dataclass
class CircuitBreakerState:
    """熔断器状态。"""
    is_open: bool = False           # 熔断是否开启
    opened_at: Optional[float] = None  # 熔断开启时间
    reason: str = ""


class MedicAgent:
    """
    医疗自愈 Agent。

    作为独立协程运行，不与标准消息总线通信（使用内部轮询机制），
    但会向消息总线发布医疗事件日志供事件链记录。

    架构设计：
    - _health_map: 维护所有注册 Agent 的健康状态
    - _breakers:   熔断器状态机
    - 心跳通过每个 Agent 注册的回调函数完成
    """

    def __init__(self, config: Config):
        """
        Args:
            config: 全局配置对象
        """
        self.config = config
        self.logger: logging.Logger = get_logger("MedicAgent")

        # 健康记录: agent_name → AgentHealthRecord
        self._health_map: Dict[str, AgentHealthRecord] = {}

        # 熔断器状态
        self._breaker: CircuitBreakerState = CircuitBreakerState()

        # 处置类Agent名单（触发熔断时需切换到安全模式）
        self._action_agents: List[str] = [
            "IPIsolation",
            "ResourceScheduler",
        ]

        # 已注册Agent的配置快照回调: agent_name → callable
        self._snapshot_callbacks: Dict[str, callable] = {}

        # 心跳检查回调: agent_name → callable
        self._heartbeat_callbacks: Dict[str, callable] = {}

        # 隔离/恢复回调
        self._isolation_callbacks: Dict[str, callable] = {}

        # 配置回滚回调: agent_name → callable(agent_name, config_snapshot) -> dict
        self._rollback_callbacks: Dict[str, callable] = {}

        # 医疗事件日志
        self._medic_log: List[dict] = []

        self._running = False
        self._task: Optional[asyncio.Task] = None

    # ==================== 注册接口 ====================

    def register_agent(
        self,
        agent_name: str,
        heartbeat_callback: callable = None,
        snapshot_callback: callable = None,
        isolation_callback: callable = None,
        rollback_callback: callable = None,
    ) -> None:
        """
        注册 Agent 到医疗系统。

        Args:
            agent_name:          Agent 名称
            heartbeat_callback:  心跳检测回调，应返回 True/False
            snapshot_callback:   配置快照回调，应返回当前配置 dict
            isolation_callback:  隔离状态变更回调，接收 (agent_name, is_isolated: bool)
            rollback_callback:   配置回滚回调，接收 (agent_name, config_snapshot)，
                                 应将快照写回配置并生效；恢复时被调用
        """
        record = AgentHealthRecord(
            agent_name=agent_name,
            last_heartbeat=time.time(),
        )
        self._health_map[agent_name] = record

        if heartbeat_callback:
            self._heartbeat_callbacks[agent_name] = heartbeat_callback
        if snapshot_callback:
            self._snapshot_callbacks[agent_name] = snapshot_callback
        if isolation_callback:
            self._isolation_callbacks[agent_name] = isolation_callback
        if rollback_callback:
            self._rollback_callbacks[agent_name] = rollback_callback

        self.logger.info(f"医疗系统注册 Agent: {agent_name}")

    # ==================== 生命周期 ====================

    async def start(self) -> asyncio.Task:
        """
        启动医疗 Agent 协程。

        Returns:
            asyncio.Task 对象
        """
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        self._log_event("medic_started", "医疗Agent自愈系统启动", detail={
            "registered_agents": list(self._health_map.keys()),
            "heartbeat_interval": self.config.medic.heartbeat_interval,
            "circuit_breaker_ratio": self.config.medic.circuit_breaker_ratio,
        })
        self.logger.info(f"医疗Agent已启动，监管 {len(self._health_map)} 个Agent")
        return self._task

    async def stop(self) -> None:
        """停止医疗 Agent。"""
        self._running = False
        if self._task:
            self._task.cancel()
        self._log_event("medic_stopped", "医疗Agent自愈系统停止")
        self.logger.info("医疗Agent已停止")

    # ==================== 核心循环 ====================

    async def _run_loop(self) -> None:
        """医疗Agent主循环：心跳检测 + 熔断判断 + 恢复检测。"""
        while self._running:
            try:
                await self._heartbeat_check()
                self._evaluate_circuit_breaker()

                # 如果熔断已开启，检查是否超时需强制解除
                if self._breaker.is_open:
                    self._check_circuit_breaker_timeout()

                await asyncio.sleep(self.config.medic.heartbeat_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"医疗Agent循环异常: {e}")

    # ==================== 心跳检测 ====================

    async def _heartbeat_check(self) -> None:
        """对每个注册的 Agent 执行心跳检测。"""
        now = time.time()
        timeout = self.config.medic.heartbeat_timeout

        for agent_name, record in list(self._health_map.items()):
            # 已被隔离的 Agent 跳过心跳检测，走恢复流程
            if record.status == AgentHealthStatus.ISOLATED:
                continue

            # 执行心跳回调
            alive = True
            if agent_name in self._heartbeat_callbacks:
                try:
                    callback = self._heartbeat_callbacks[agent_name]
                    if asyncio.iscoroutinefunction(callback):
                        alive = await callback()
                    else:
                        alive = callback()
                except Exception as e:
                    self.logger.warning(f"Agent {agent_name} 心跳回调异常: {e}")
                    alive = False

            # 心跳响应正常
            if alive:
                record.last_heartbeat = now
                record.consecutive_failures = 0
                record.consecutive_successes += 1

                # 恢复确认：连续 N 次心跳正常 → 解除降级
                if record.status == AgentHealthStatus.RECOVERING and \
                   record.consecutive_successes >= self.config.medic.recovery_confirm_count:
                    self._recover_agent(agent_name, record)

            # 心跳失败（无响应或超时）
            else:
                record.consecutive_failures += 1
                record.consecutive_successes = 0
                elapsed = now - record.last_heartbeat

                if elapsed > timeout and record.consecutive_failures >= 2:
                    if record.status == AgentHealthStatus.HEALTHY:
                        record.status = AgentHealthStatus.UNRESPONSIVE
                        record.error_log.append(
                            f"{datetime.now().isoformat()}: 心跳超时 {elapsed:.1f}s"
                        )
                        self._log_event("agent_unresponsive", f"Agent {agent_name} 心跳超时",
                                        detail={"elapsed_seconds": round(elapsed, 1)})
                        # 尝试隔离
                        await self._isolate_agent(agent_name, record)
                elif elapsed > timeout * 0.5 and record.status == AgentHealthStatus.HEALTHY:
                    record.status = AgentHealthStatus.DEGRADED
                    self._log_event("agent_degraded", f"Agent {agent_name} 响应降级",
                                    detail={"elapsed_seconds": round(elapsed, 1)})

    # ==================== 故障隔离 ====================

    async def _isolate_agent(self, agent_name: str, record: AgentHealthRecord) -> None:
        """
        隔离故障 Agent。

        Steps:
        1. 保存当前配置快照（用于回滚）
        2. 标记为 ISOLATED
        3. 触发隔离回调

        Args:
            agent_name: Agent 名称
            record:     健康记录
        """
        # 保存配置快照
        if agent_name in self._snapshot_callbacks:
            try:
                callback = self._snapshot_callbacks[agent_name]
                if asyncio.iscoroutinefunction(callback):
                    record.config_snapshot = await callback()
                else:
                    record.config_snapshot = callback()
            except Exception as e:
                self.logger.error(f"保存 {agent_name} 配置快照失败: {e}")

        # 标记隔离
        record.status = AgentHealthStatus.ISOLATED
        record.isolated_at = time.time()

        # 触发隔离回调
        if agent_name in self._isolation_callbacks:
            try:
                callback = self._isolation_callbacks[agent_name]
                if asyncio.iscoroutinefunction(callback):
                    await callback(agent_name, True)
                else:
                    callback(agent_name, True)
            except Exception as e:
                self.logger.error(f"隔离回调异常 {agent_name}: {e}")

        self._log_event("agent_isolated", f"Agent {agent_name} 已被隔离",
                        detail={"failed_count": record.consecutive_failures})
        self.logger.warning(f"Agent {agent_name} 已被隔离 (连续失败 {record.consecutive_failures} 次)")

    # ==================== 恢复检测 ====================

    def _recover_agent(self, agent_name: str, record: AgentHealthRecord) -> None:
        """
        恢复 Agent：从 ISOLATED 切回 HEALTHY 并执行配置回滚。

        Args:
            agent_name: Agent 名称
            record:     健康记录
        """
        old_status = record.status

        # 配置回滚（如果保存了快照且注册了回滚回调）：
        # 真正将 config_snapshot 写回配置并生效，使自愈回滚闭环。
        if record.config_snapshot is not None and agent_name in self._rollback_callbacks:
            try:
                rollback_cb = self._rollback_callbacks[agent_name]
                result = rollback_cb(agent_name, record.config_snapshot)
                if asyncio.iscoroutine(result):
                    # 在运行中的事件循环里调度异步回滚
                    asyncio.get_running_loop().create_task(result)
                self.logger.info(
                    f"Agent {agent_name} 配置回滚已应用（快照 {len(record.config_snapshot)} 项）"
                )
                record.config_snapshot = None  # 回滚完成，清空快照避免重复回滚
            except Exception as e:
                self.logger.error(f"配置回滚失败 {agent_name}: {e}")

        # 解隔离 → 恢复
        if agent_name in self._isolation_callbacks:
            try:
                callback = self._isolation_callbacks[agent_name]
                callback(agent_name, False)
            except Exception as e:
                self.logger.error(f"恢复回调异常 {agent_name}: {e}")

        record.status = AgentHealthStatus.HEALTHY
        record.isolated_at = None
        record.consecutive_failures = 0

        self._log_event("agent_recovered", f"Agent {agent_name} 从 {old_status.value} 恢复为 HEALTHY",
                        detail={"consecutive_successes": record.consecutive_successes})
        self.logger.info(f"Agent {agent_name} 已恢复正常 (连续心跳成功 {record.consecutive_successes} 次)")

    # ==================== 熔断机制 ====================

    def _evaluate_circuit_breaker(self) -> None:
        """
        评估是否需要触发或解除熔断。

        触发条件：isolated_agent_count / total_count >= circuit_breaker_ratio
        """
        total = len(self._health_map)
        if total == 0:
            return

        isolated_count = sum(
            1 for r in self._health_map.values()
            if r.status in (AgentHealthStatus.ISOLATED, AgentHealthStatus.UNRESPONSIVE)
        )
        ratio = isolated_count / total

        # 触发熔断
        if not self._breaker.is_open and ratio >= self.config.medic.circuit_breaker_ratio:
            self._breaker.is_open = True
            self._breaker.opened_at = time.time()
            self._breaker.reason = (
                f"故障Agent比例 {isolated_count}/{total}={ratio:.0%} >= 阈值 "
                f"{self.config.medic.circuit_breaker_ratio:.0%}，触发熔断"
            )
            self._log_event("circuit_breaker_open", self._breaker.reason,
                            detail={"isolated_count": isolated_count, "total": total, "ratio": round(ratio, 2)})
            self.logger.warning(f"[熔断] {self._breaker.reason}")

        # 解除熔断：全部 Agent 恢复健康
        elif self._breaker.is_open and isolated_count == 0:
            self._breaker.is_open = False
            self._breaker.opened_at = None
            self._log_event("circuit_breaker_closed", "所有Agent已恢复，解除熔断")
            self.logger.info("[熔断解除] 所有Agent已恢复正常")

    def _check_circuit_breaker_timeout(self) -> None:
        """检查熔断是否超时，超时强制解除。"""
        if not self._breaker.is_open or self._breaker.opened_at is None:
            return

        elapsed = time.time() - self._breaker.opened_at
        if elapsed >= self.config.medic.max_circuit_breaker_duration:
            self._breaker.is_open = False
            self._breaker.opened_at = None
            self._log_event("circuit_breaker_timeout",
                            f"熔断超时 ({elapsed:.0f}s) 强制解除")
            self.logger.warning(f"[熔断超时] 熔断已持续 {elapsed:.0f}s，强制解除")

    def is_circuit_breaker_open(self) -> bool:
        """外部查询：当前是否处于熔断状态。"""
        return self._breaker.is_open

    def is_action_allowed(self, agent_name: str) -> bool:
        """
        外部查询：指定处置Agent是否可执行实际操作。

        熔断期间，所有处置类Agent只能记录不能实际执行。

        Args:
            agent_name: Agent 名称

        Returns:
            True 表示可执行，False 表示仅记录
        """
        if self._breaker.is_open and agent_name in self._action_agents:
            return False
        return True

    # ==================== 事件日志 ====================

    def _log_event(self, event_type: str, description: str, detail: dict = None) -> None:
        """记录医疗事件日志。"""
        entry = {
            "event_id": f"MEDIC-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "description": description,
            "detail": detail or {},
        }
        self._medic_log.append(entry)

    def get_medic_log(self) -> List[dict]:
        """获取医疗事件日志。"""
        return self._medic_log

    def get_health_status(self) -> Dict[str, AgentHealthRecord]:
        """获取所有注册Agent的健康状态。"""
        return dict(self._health_map)

    def get_circuit_breaker_status(self) -> dict:
        """获取熔断器状态。"""
        return {
            "is_open": self._breaker.is_open,
            "opened_at": (
                datetime.fromtimestamp(self._breaker.opened_at).isoformat()
                if self._breaker.opened_at else None
            ),
            "reason": self._breaker.reason,
        }
