"""
Skill 中间件模块
定义统一威胁描述格式（简化版 STIX），将感知模块 Agent 的异构输出转换为标准格式，
将双引擎指令转换为器官可执行的本地动作格式。
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ==================== 简化版 STIX（统一威胁描述格式）====================


class ThreatCategory(Enum):
    """威胁类别枚举。"""
    DDOS = "ddos"               # 分布式拒绝服务
    PORT_SCAN = "port_scan"     # 端口扫描
    BRUTE_FORCE = "brute_force" # 暴力破解
    VULN = "vuln"               # 漏洞
    AUDIT = "audit"             # 日志审计异常
    UNKNOWN = "unknown"         # 未知


class AlertSeverity(Enum):
    """告警严重级别枚举。"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SEVERE = "severe"


@dataclass
class ThreatIndicator:
    """
    统一威胁指标（简化版 STIX Indicator）。

    Fields:
        id:              威胁唯一标识
        category:        威胁类别
        severity:        严重级别
        source_ip:       攻击源 IP
        target_ip:       目标 IP
        target_port:     目标端口（可为 None）
        description:     威胁描述
        raw_data:        原始观测数据
        detection_time:  检测时间
    """
    id: str
    category: ThreatCategory
    severity: AlertSeverity
    source_ip: str
    target_ip: str
    target_port: Optional[int]
    description: str
    raw_data: Dict[str, Any]
    detection_time: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """转为字典格式。"""
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "description": self.description,
            "raw_data": self.raw_data,
            "detection_time": self.detection_time,
        }


# ==================== 双引擎方案格式 ====================


@dataclass
class DefensePlan:
    """
    分析引擎防御方案。

    Fields:
        alert_id:          关联的告警 ID
        severity_confirm:  确认的严重级别
        action:            推荐处置动作（如 'isolate_ip', 'rate_limit', 'monitor'）
        target_ip:         处置目标IP
        reason:            处置理由
        log_evidence:      日志存证（分析引擎存证的数据摘要）
        compute_cost:      预估算力开销
    """
    alert_id: str
    severity_confirm: AlertSeverity
    action: str
    target_ip: str
    reason: str
    log_evidence: Dict[str, Any]
    compute_cost: float


@dataclass
class AttackAnalysis:
    """
    响应引擎攻击分析/反击方案。

    Fields:
        alert_id:               关联的告警 ID
        attack_type:            推断的攻击类型
        root_cause:             溯源分析结果
        confidence:             置信度 (0.0 - 1.0)
        recommended_actions:    推荐的反击/拦截策略列表
        estimated_impact:       预估影响范围
    """
    alert_id: str
    attack_type: str
    root_cause: str
    confidence: float
    recommended_actions: List[str]
    estimated_impact: str


@dataclass
class MergedPlan:
    """
    双引擎融合方案。

    Fields:
        alert_id:       关联的告警 ID
        left_plan:      分析引擎方案
        right_analysis: 响应引擎分析
        merged_action:  融合后的最终动作
    """
    alert_id: str
    left_plan: DefensePlan
    right_analysis: AttackAnalysis
    merged_action: str


# ==================== 处置动作格式（器官本地动作） ====================


@dataclass
class IsolationAction:
    """
    IP 隔离本地动作格式。

    Fields:
        alert_id:        关联的告警 ID
        target_ip:       要隔离的IP
        action:          动作类型（'isolate', 'release'）
        priority:        优先级
        reason:          隔离原因
        timestamp:       执行时间
    """
    alert_id: str
    target_ip: str
    action: str
    priority: str
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ==================== Skill 中间件 ====================


class SkillMiddleware:
    """
    Skill 中间件：负责报文格式转换和标准化。

    核心职责：
    1. 将观测 Agent 的异构输出 → 统一 ThreatIndicator
    2. 将双引擎融合方案 → 感知模块可执行的 IsolationAction
    3. 确保所有 Agent 使用统一的报文格式
    """

    def __init__(self):
        self._id_counter = 0

    def _next_alert_id(self) -> str:
        """生成告警ID。"""
        self._id_counter += 1
        return f"ALERT-{self._id_counter:04d}"

    # ----- 观测 Agent 输出 → ThreatIndicator -----

    def normalize_ddos_alert(
        self,
        source_ip: str,
        request_count: int,
        target_ip: str = "192.168.1.1",
        target_port: int = 80,
        raw_data: Optional[Dict] = None,
    ) -> ThreatIndicator:
        """
        将 DDoS 检测输出标准化为 ThreatIndicator。

        Args:
            source_ip:      攻击源 IP
            request_count:  请求次数
            target_ip:      目标 IP
            target_port:    目标端口
            raw_data:       原始数据

        Returns:
            标准化的 ThreatIndicator
        """
        # 根据请求数分级
        if request_count >= 500:
            severity = AlertSeverity.SEVERE
        elif request_count >= 200:
            severity = AlertSeverity.HIGH
        elif request_count >= 100:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        return ThreatIndicator(
            id=self._next_alert_id(),
            category=ThreatCategory.DDOS,
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=target_port,
            description=f"DDoS洪水攻击：源IP {source_ip} 在时间窗口内发送 {request_count} 次请求",
            raw_data=raw_data or {"request_count": request_count},
        )

    def normalize_port_scan_alert(
        self,
        source_ip: str,
        scanned_ports: List[int],
        target_ip: str = "192.168.1.1",
        raw_data: Optional[Dict] = None,
    ) -> ThreatIndicator:
        """
        将端口扫描检测输出标准化为 ThreatIndicator。

        Args:
            source_ip:      扫描源 IP
            scanned_ports:  被扫描的端口列表
            target_ip:      目标 IP
            raw_data:       原始数据

        Returns:
            标准化的 ThreatIndicator
        """
        port_count = len(scanned_ports)
        if port_count >= 100:
            severity = AlertSeverity.SEVERE
        elif port_count >= 50:
            severity = AlertSeverity.HIGH
        elif port_count >= 20:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        return ThreatIndicator(
            id=self._next_alert_id(),
            category=ThreatCategory.PORT_SCAN,
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=None,
            description=f"端口扫描：源IP {source_ip} 扫描了 {port_count} 个不同端口",
            raw_data=raw_data or {"scanned_port_count": port_count},
        )

    def normalize_brute_force_alert(
        self,
        source_ip: str,
        attempts: int,
        target_ip: str = "192.168.1.1",
        target_port: int = 22,
        raw_data: Optional[Dict] = None,
    ) -> ThreatIndicator:
        """
        将暴力破解检测输出标准化为 ThreatIndicator。

        Args:
            source_ip:      攻击源 IP
            attempts:       尝试次数
            target_ip:      目标 IP
            target_port:    目标端口
            raw_data:       原始数据

        Returns:
            标准化的 ThreatIndicator
        """
        if attempts >= 500:
            severity = AlertSeverity.SEVERE
        elif attempts >= 200:
            severity = AlertSeverity.HIGH
        elif attempts >= 100:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        return ThreatIndicator(
            id=self._next_alert_id(),
            category=ThreatCategory.BRUTE_FORCE,
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=target_port,
            description=f"暴力破解：源IP {source_ip} 对端口 {target_port} 发起 {attempts} 次认证尝试",
            raw_data=raw_data or {"attempts": attempts, "target_port": target_port},
        )

    # ----- 双引擎方案 → 感知模块动作 -----

    def plan_to_isolation_action(
        self,
        merged_plan: MergedPlan,
        priority: str = "high",
    ) -> IsolationAction:
        """
        将融合方案转换为 IP 隔离的本地动作格式。

        Args:
            merged_plan: 融合后的方案
            priority:    执行优先级

        Returns:
            IsolationAction 实例
        """
        reason = (
            f"[{merged_plan.right_analysis.attack_type}] "
            f"{merged_plan.left_plan.reason} | "
            f"溯源: {merged_plan.right_analysis.root_cause}"
        )

        return IsolationAction(
            alert_id=merged_plan.alert_id,
            target_ip=merged_plan.left_plan.target_ip,
            action=merged_plan.merged_action,
            priority=priority,
            reason=reason,
        )
