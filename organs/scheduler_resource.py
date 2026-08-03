"""
算力调度Agent：接收分析引擎的算力调度指令，管理模拟资源池，
执行CPU/内存分配调整并输出调度日志。

v2 做实：
- 加 CPU + 内存使用率监控：用 psutil.cpu_percent + virtual_memory
- 每 30 秒采样一次
- 资源使用 >80% 时通过 message_bus 发布告警
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config
from utils.logger import get_logger

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# 资源告警阈值（百分比）
CPU_ALERT_THRESHOLD = 80.0
MEM_ALERT_THRESHOLD = 80.0
# 监控采样间隔（秒）
MONITOR_INTERVAL = 30


@dataclass
class ResourceState:
    """模拟资源池状态快照。"""
    total_cpu_cores: int = 16
    used_cpu_cores: int = 4
    total_memory_gb: float = 32.0
    used_memory_gb: float = 8.0
    quota_per_agent: int = 100  # 每个Agent的算力配额
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())


class ResourceSchedulerAgent:
    """
    算力调度感知模块 Agent。

    职责：
    1. 订阅分析引擎下发的算力调度指令（resource_schedule）
    2. 维护模拟资源池状态
    3. 执行 CPU/内存分配调整
    4. 输出调度日志，发布调度结果事件
    """

    def __init__(self, config: Config, demo_mode: bool = True):
        """
        Args:
            config: 全局配置对象
            demo_mode: True 时仅保留模拟资源调度逻辑；
                       False 时额外启动 psutil CPU/内存监控后台任务。
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.logger: logging.Logger = get_logger("ResourceScheduler")
        self.demo_mode = demo_mode

        # 模拟资源池
        self.resource: ResourceState = ResourceState(
            quota_per_agent=self.config.stage2.default_compute_quota,
        )

        # 调度历史
        self._schedule_log: List[dict] = []

        # 真实资源监控数据
        self._real_cpu_percent: float = 0.0
        self._real_mem_percent: float = 0.0
        self._real_mem_used_gb: float = 0.0
        self._real_mem_total_gb: float = 0.0
        self._last_monitor_time: Optional[str] = None

        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """启动算力调度Agent，订阅调度指令。非 demo 模式启动资源监控。"""
        self._running = True
        await self.bus.subscribe("resource_schedule", self._handle_schedule)
        self.logger.info(
            f"算力调度Agent已启动 | CPU: {self.resource.total_cpu_cores}核 "
            f"| 内存: {self.resource.total_memory_gb}GB | 等待调度指令..."
        )

        if not self.demo_mode:
            self._monitor_task = asyncio.create_task(self._monitor_loop())
            self.logger.info("后台资源监控循环已启动 (psutil)")

    async def stop(self) -> None:
        """停止算力调度Agent。"""
        self._running = False
        self.logger.info("算力调度Agent已停止")

    def get_resource_state(self) -> ResourceState:
        """获取当前资源池状态。"""
        return self.resource

    async def _handle_schedule(self, message: Message) -> Optional[Message]:
        """
        处理算力调度指令，调整资源分配。

        Args:
            message: 包含调度指令的事件消息

        Returns:
            调度结果消息（将自动发布到总线）
        """
        if not self._running:
            return None

        payload = message.payload
        action = payload.get("action", "adjust")
        target_organ = payload.get("target_organ", "unknown")
        cpu_delta = payload.get("cpu_delta", 0)
        memory_delta_gb = payload.get("memory_delta_gb", 0.0)
        reason = payload.get("reason", "双引擎决策引发调度")
        alert_id = payload.get("alert_id", "")

        # 记录调度前状态
        before_state = {
            "cpu": self.resource.used_cpu_cores,
            "memory": self.resource.used_memory_gb,
        }

        # 执行资源调整
        if action == "adjust":
            self.resource.used_cpu_cores = max(0, min(
                self.resource.total_cpu_cores,
                self.resource.used_cpu_cores + cpu_delta
            ))
            self.resource.used_memory_gb = max(0, min(
                self.resource.total_memory_gb,
                self.resource.used_memory_gb + memory_delta_gb
            ))
        elif action == "release":
            # 释放资源
            self.resource.used_cpu_cores = max(0, self.resource.used_cpu_cores + cpu_delta)
            self.resource.used_memory_gb = max(0, self.resource.used_memory_gb + memory_delta_gb)

        # 更新配额
        self.resource.quota_per_agent = max(10, self.resource.quota_per_agent + payload.get("quota_delta", 0))
        self.resource.last_updated = datetime.now().isoformat()

        after_state = {
            "cpu": self.resource.used_cpu_cores,
            "memory": self.resource.used_memory_gb,
        }

        # 记录调度日志
        log_entry = {
            "schedule_id": f"SCH-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": self.resource.last_updated,
            "action": action,
            "target_organ": target_organ,
            "alert_id": alert_id,
            "reason": reason,
            "before": before_state,
            "after": after_state,
            "quota": self.resource.quota_per_agent,
        }
        self._schedule_log.append(log_entry)

        cpu_usage_pct = (self.resource.used_cpu_cores / self.resource.total_cpu_cores) * 100
        mem_usage_pct = (self.resource.used_memory_gb / self.resource.total_memory_gb) * 100

        self.logger.info(
            f"算力调度执行: {action} | {target_organ} | "
            f"CPU {before_state['cpu']}→{after_state['cpu']}核 ({cpu_usage_pct:.1f}%) | "
            f"内存 {before_state['memory']:.1f}→{after_state['memory']:.1f}GB ({mem_usage_pct:.1f}%)"
        )

        return Message(
            source="ResourceScheduler",
            target="LeftBrain",
            type="schedule_result",
            payload={
                "type": "schedule_result",
                "log_entry": log_entry,
                "resource_state": {
                    "cpu_cores_used": self.resource.used_cpu_cores,
                    "cpu_cores_total": self.resource.total_cpu_cores,
                    "memory_gb_used": self.resource.used_memory_gb,
                    "memory_gb_total": self.resource.total_memory_gb,
                    "cpu_usage_pct": round(cpu_usage_pct, 1),
                    "memory_usage_pct": round(mem_usage_pct, 1),
                    "quota_per_agent": self.resource.quota_per_agent,
                },
            },
        )

    # ── 真实资源监控（psutil）──

    async def _monitor_loop(self) -> None:
        """后台循环：每 30 秒采样 CPU + 内存使用率，超阈值告警。"""
        if not HAS_PSUTIL:
            self.logger.warning("psutil 不可用，资源监控跳过")
            return

        # 第一次调用 cpu_percent 需要预热（返回 0.0）
        psutil.cpu_percent(interval=1)

        while self._running:
            try:
                await self._sample_resources()
            except Exception as e:
                self.logger.error(f"资源采样异常: {e}")
            await asyncio.sleep(MONITOR_INTERVAL)

    async def _sample_resources(self) -> None:
        """采样 CPU 和内存使用率，超过阈值时通过 message_bus 发布告警。"""
        if not HAS_PSUTIL:
            return

        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()

        self._real_cpu_percent = cpu
        self._real_mem_percent = mem.percent
        self._real_mem_used_gb = mem.used / (1024 ** 3)
        self._real_mem_total_gb = mem.total / (1024 ** 3)
        self._last_monitor_time = datetime.now().isoformat()

        alerts = []

        if cpu > CPU_ALERT_THRESHOLD:
            alerts.append({
                "type": "cpu_high",
                "severity": "high" if cpu > 95 else "medium",
                "value": round(cpu, 1),
                "threshold": CPU_ALERT_THRESHOLD,
                "description": f"CPU 使用率 {cpu:.1f}% 超过阈值 {CPU_ALERT_THRESHOLD}%",
            })

        if mem.percent > MEM_ALERT_THRESHOLD:
            alerts.append({
                "type": "memory_high",
                "severity": "high" if mem.percent > 95 else "medium",
                "value": round(mem.percent, 1),
                "threshold": MEM_ALERT_THRESHOLD,
                "description": (
                    f"内存使用率 {mem.percent:.1f}% "
                    f"({mem.used / (1024**3):.1f}/{mem.total / (1024**3):.1f} GB) "
                    f"超过阈值 {MEM_ALERT_THRESHOLD}%"
                ),
            })

        for alert in alerts:
            await self.bus.publish(Message(
                source="ResourceScheduler",
                target="EventAggregator",
                type="threat_alert",
                payload={
                    "source_organ": "resource_scheduler",
                    "indicator": {
                        "id": f"RES-{uuid.uuid4().hex[:8].upper()}",
                        "category": alert["type"],
                        "severity": alert["severity"],
                        "source_ip": "localhost",
                        "dst_ip": "localhost",
                        "description": alert["description"],
                        "timestamp": self._last_monitor_time,
                    },
                    "category": alert["type"],
                    "severity": alert["severity"],
                    "original": alert,
                },
            ))
            self.logger.warning(f"资源告警: {alert['description']}")

    def get_real_resource_stats(self) -> Dict[str, Any]:
        """获取最近一次真实资源采样数据。"""
        return {
            "cpu_percent": self._real_cpu_percent,
            "mem_percent": self._real_mem_percent,
            "mem_used_gb": round(self._real_mem_used_gb, 2),
            "mem_total_gb": round(self._real_mem_total_gb, 2),
            "last_monitor_time": self._last_monitor_time,
        }

    def get_schedule_history(self) -> List[dict]:
        """获取调度历史记录。"""
        return self._schedule_log
