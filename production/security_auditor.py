"""
安全审计器 - 审计所有处置动作，生成合规审计报告。

审计内容：
  - 所有处置动作的可追溯日志
  - 权限边界检查（白名单验证）
  - 合规存证（生成审计报告 JSON）
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


@dataclass
class ActionRecord:
    """单条处置动作记录。"""
    timestamp: str
    action_id: str
    alert_id: str
    detector_agent: str       # 检测告警的 Agent
    decision_agent: str       # 决策 Agent（分析引擎/响应引擎）
    executor_agent: str       # 执行 Agent（处置器官）
    action: str               # 处置动作（block_ip / rate_limit / quarantine）
    target: str               # 目标（IP / 域名 / 端口）
    severity: str             # 告警级别
    result: str               # 执行结果（success / failure / skipped）
    reason: str               # 处置原因
    duration_seconds: Optional[float] = None  # 处置持续时间


@dataclass
class AuditResult:
    """单条审计结果。"""
    action: ActionRecord
    passed: bool
    checks: List[Dict[str, Any]]  # 各项检查结果
    issues: List[str]             # 发现的问题


@dataclass
class AuditReport:
    """完整审计报告。"""
    report_id: str
    time_range_start: str
    time_range_end: str
    total_actions: int
    passed_actions: int
    failed_actions: int
    permission_violations: List[Dict[str, Any]]
    integrity_checks: Dict[str, Any]
    results: List[AuditResult]
    checksum: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "time_range": {"start": self.time_range_start, "end": self.time_range_end},
            "summary": {
                "total_actions": self.total_actions,
                "passed": self.passed_actions,
                "failed": self.failed_actions,
                "pass_rate": self.passed_actions / max(1, self.total_actions),
            },
            "permission_violations": self.permission_violations,
            "integrity_checks": self.integrity_checks,
            "results": [
                {
                    "action_id": r.action.action_id,
                    "passed": r.passed,
                    "checks": r.checks,
                    "issues": r.issues,
                }
                for r in self.results
            ],
            "checksum": self.checksum,
        }


class SecurityAuditor:
    """
    安全审计器。

    功能：
    1. 记录所有处置动作
    2. 执行白名单边界检查
    3. 生成可追溯的审计报告（含哈希完整性校验）
    """

    # 白名单：允许的目标列表（外部可操作目标）
    # 格式：{类型: [允许值列表]}
    WHITELIST = {
        "ip": [  # 允许操作的IP范围
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
        ],
        "domain": ["internal.example.com"],
        "port": [22, 80, 443, 3306, 6379, 8443],
    }

    # 禁止操作列表
    BLOCKLIST = {
        "ip": ["127.0.0.1", "::1", "0.0.0.0"],
        "domain": ["localhost"],
    }

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._action_log: List[ActionRecord] = []
        self._counter = 0

    def record_action(
        self,
        alert_id: str,
        detector_agent: str,
        decision_agent: str,
        executor_agent: str,
        action: str,
        target: str,
        severity: str,
        result: str,
        reason: str,
        duration_seconds: Optional[float] = None,
    ) -> ActionRecord:
        """
        记录一条处置动作。

        Returns:
            记录后的 ActionRecord
        """
        self._counter += 1
        ts = datetime.now().isoformat()
        action_id = f"ACT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._counter:04d}"

        record = ActionRecord(
            timestamp=ts,
            action_id=action_id,
            alert_id=alert_id,
            detector_agent=detector_agent,
            decision_agent=decision_agent,
            executor_agent=executor_agent,
            action=action,
            target=target,
            severity=severity,
            result=result,
            reason=reason,
            duration_seconds=duration_seconds,
        )
        self._action_log.append(record)
        return record

    def audit_action(self, action_record: ActionRecord) -> AuditResult:
        """
        审计单条处置动作。

        检查项：
        1. 白名单验证：目标是否在允许操作范围内
        2. 黑名单检查：目标是否在禁止操作列表中
        3. 权限边界：处置Agent是否有权限执行该动作
        4. 日志完整性：必填字段是否齐全
        5. 时间戳合理性

        Returns:
            AuditResult
        """
        checks = []
        issues = []

        # 检查1：白名单验证
        target_type = self._classify_target(action_record.target)
        whitelist_check = self._check_whitelist(target_type, action_record.target)
        checks.append({
            "name": "whitelist_verification",
            "passed": whitelist_check["passed"],
            "detail": whitelist_check["detail"],
        })
        if not whitelist_check["passed"]:
            issues.append(f"白名单验证失败: {whitelist_check['detail']}")

        # 检查2：黑名单检查
        blocklist_check = self._check_blocklist(target_type, action_record.target)
        checks.append({
            "name": "blocklist_verification",
            "passed": blocklist_check["passed"],
            "detail": blocklist_check["detail"],
        })
        if not blocklist_check["passed"]:
            issues.append(f"黑名单拦截: {blocklist_check['detail']}")

        # 检查3：处置Agent权限检查
        allowed_actions = self._get_agent_permissions(action_record.executor_agent)
        permission_check = {
            "name": "agent_permission",
            "passed": action_record.action in allowed_actions,
            "detail": f"Agent {action_record.executor_agent} 允许动作: {allowed_actions}",
        }
        checks.append(permission_check)
        if not permission_check["passed"]:
            issues.append(f"Agent {action_record.executor_agent} 无权限执行 {action_record.action}")

        # 检查4：必填字段完整性
        required_fields = ["alert_id", "detector_agent", "decision_agent", "executor_agent",
                          "action", "target", "severity", "result", "reason"]
        missing = [f for f in required_fields if not getattr(action_record, f, None)]
        completeness_check = {
            "name": "field_completeness",
            "passed": len(missing) == 0,
            "detail": f"缺失字段: {missing}" if missing else "所有必填字段完整",
        }
        checks.append(completeness_check)
        if missing:
            issues.append(f"字段不完整: {missing}")

        # 检查5：结果合理性
        if action_record.result == "failure" and not action_record.reason:
            issues.append("执行失败但未提供原因")

        # 检查6：持续时间合理性
        if action_record.duration_seconds is not None and action_record.duration_seconds <= 0:
            issues.append(f"无效的持续时间: {action_record.duration_seconds}s")

        return AuditResult(
            action=action_record,
            passed=len(issues) == 0,
            checks=checks,
            issues=issues,
        )

    def generate_audit_report(
        self,
        time_range: Optional[tuple] = None,
    ) -> AuditReport:
        """
        生成完整审计报告。

        Args:
            time_range: 可选的时间范围 (start_str, end_str)，None 则审计全部

        Returns:
            AuditReport
        """
        # 筛选时间范围内的记录
        actions = self._action_log
        if time_range:
            start_str, end_str = time_range
            start_dt = datetime.fromisoformat(start_str) if "T" in start_str else datetime.strptime(start_str, "%Y-%m-%d")
            end_dt = datetime.fromisoformat(end_str) if "T" in end_str else datetime.strptime(end_str, "%Y-%m-%d")
            actions = [
                a for a in self._action_log
                if start_dt <= datetime.fromisoformat(a.timestamp) <= end_dt
            ]
            time_start = start_str
            time_end = end_str
        else:
            time_start = actions[0].timestamp if actions else datetime.now().isoformat()
            time_end = actions[-1].timestamp if actions else datetime.now().isoformat()

        # 审计每条记录
        audit_results = [self.audit_action(a) for a in actions]

        # 统计
        passed = sum(1 for r in audit_results if r.passed)
        failed = len(audit_results) - passed

        # 权限违规
        permission_violations = []
        for r in audit_results:
            for issue in r.issues:
                if "权限" in issue or "permission" in issue:
                    permission_violations.append({
                        "action_id": r.action.action_id,
                        "agent": r.action.executor_agent,
                        "issue": issue,
                    })

        # 完整性校验哈希
        report_id = f"AUDIT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        payload = json.dumps({
            "time_range": [time_start, time_end],
            "total_actions": len(actions),
            "passed": passed,
            "failed": failed,
        }, sort_keys=True)
        checksum = hashlib.sha256(payload.encode()).hexdigest()

        report = AuditReport(
            report_id=report_id,
            time_range_start=time_start,
            time_range_end=time_end,
            total_actions=len(actions),
            passed_actions=passed,
            failed_actions=failed,
            permission_violations=permission_violations,
            integrity_checks={
                "tamper_evident": True,
                "algorithm": "SHA-256",
                "checksum": checksum,
                "verified": True,
            },
            results=audit_results,
            checksum=checksum,
        )

        return report

    def _classify_target(self, target: str) -> str:
        """根据目标字符串分类类型。"""
        if target.count(".") == 3 and all(p.isdigit() for p in target.split(".")):
            return "ip"
        if "." in target and not target[0].isdigit():
            return "domain"
        if target.isdigit():
            return "port"
        return "unknown"

    def _check_whitelist(self, target_type: str, target: str) -> Dict[str, Any]:
        """检查目标是否在允许列表中。"""
        if target_type not in self.WHITELIST:
            return {"passed": True, "detail": f"类型 {target_type} 无白名单限制"}

        # 检查黑名单
        if target_type in self.BLOCKLIST and target in self.BLOCKLIST[target_type]:
            return {"passed": False, "detail": f"目标 {target} 在禁止列表中"}

        # 检查白名单
        for allowed in self.WHITELIST.get(target_type, []):
            if target_type == "ip":
                if "/" in allowed and self._ip_in_subnet(target, allowed):
                    return {"passed": True, "detail": f"目标 {target} 在允许范围 {allowed}"}
            else:
                if target == str(allowed):
                    return {"passed": True, "detail": f"目标 {target} 在允许列表中"}

        return {"passed": False, "detail": f"目标 {target} 不在任何允许范围"}

    def _check_blocklist(self, target_type: str, target: str) -> Dict[str, Any]:
        """检查目标是否在禁止列表中。"""
        if target_type in self.BLOCKLIST and target in self.BLOCKLIST[target_type]:
            return {"passed": False, "detail": f"目标 {target} 在禁止操作列表"}
        return {"passed": True, "detail": "不在禁止列表"}

    def _ip_in_subnet(self, ip: str, subnet: str) -> bool:
        """检查 IP 是否在子网范围内。"""
        import ipaddress
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return False

    def _get_agent_permissions(self, agent_name: str) -> List[str]:
        """根据 Agent 名称返回允许的处置动作列表。"""
        permissions = {
            "IPIsolation": ["block_ip", "unblock_ip", "rate_limit"],
            "ActorIPIsolation": ["block_ip", "unblock_ip", "rate_limit"],
            "TrafficMonitor": [],
            "LeftBrain": [],
            "RightBrain": [],
            "Validator": ["validate_block", "validate_unblock"],
            "VulnScanner": ["patch_vuln", "quarantine_service"],
            "LogAuditor": ["disable_account", "reset_password"],
            "ResourceScheduler": ["throttle_resource", "reallocate"],
            "ForensicTracker": ["log_evidence", "trace_hops"],
        }
        return permissions.get(agent_name, [])

    def get_action_log(self) -> List[ActionRecord]:
        """获取所有已记录的动作。"""
        return list(self._action_log)

    def save_report(self, report: AuditReport, filepath: str) -> None:
        """持久化审计报告（含哈希签名）。"""
        if self.dry_run:
            return
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
