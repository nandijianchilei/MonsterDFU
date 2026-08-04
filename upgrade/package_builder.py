"""
升级包生成器 - 双引擎协商后生成灰度升级包。

升级包以 JSON 格式封装：版本号、目标组件列表、变更类型、变更内容、
回滚快照和验证检查清单。
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List


@dataclass
class UpgradePackage:
    """升级包数据结构。"""
    package_id: str
    version: str                          # 语义化版本号 (semver)
    description: str                      # 升级描述
    target_components: List[str]          # 目标组件列表
    change_type: str                      # model_weight / rule_update / config_change
    changes: Dict[str, Any]               # 变更内容明细（组件→变更项）
    rollback_snapshots: Dict[str, Any]    # 回滚快照（组件→变更前旧值）
    validation_checklist: List[Dict[str, Any]]  # 验证检查清单
    left_brain_decision: Dict[str, Any]   # 分析引擎协商结果
    right_brain_analysis: Dict[str, Any]  # 响应引擎协商结果
    created_at: str
    checksum: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "version": self.version,
            "description": self.description,
            "target_components": self.target_components,
            "change_type": self.change_type,
            "changes": self.changes,
            "rollback_snapshots": self.rollback_snapshots,
            "validation_checklist": self.validation_checklist,
            "left_brain_decision": self.left_brain_decision,
            "right_brain_analysis": self.right_brain_analysis,
            "created_at": self.created_at,
            "checksum": self.checksum,
        }


@dataclass
class ValidationResult:
    """升级包验证结果。"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class UpgradePackageBuilder:
    """
    升级包生成器。

    实现双引擎协商机制：
    - 分析引擎：评估变更对防御体系的影响，决定是否批准
    - 响应引擎：分析攻击趋势，推荐变更参数
    """

    SUPPORTED_COMPONENTS = [
        "left_brain",
        "right_brain",
        "observer_traffic",
        "actor_ip_isolation",
        "scanner_vuln",
        "auditor_log",
        "scheduler_resource",
        "tracker_forensic",
    ]

    SUPPORTED_CHANGE_TYPES = ["model_weight", "rule_update", "config_change"]

    def __init__(self, store_dir: str, dry_run: bool = False):
        self.store_dir = store_dir
        self.dry_run = dry_run
        self._package_counter = 0
        if not dry_run:
            os.makedirs(store_dir, exist_ok=True)

    def _run_left_brain_assessment(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析引擎协商：评估变更对防御体系的影响。

        模拟分析引擎的后勤防御中枢做出审批决策。
        """
        target_components = list(changes.get("target_components", []))
        change_type = changes.get("change_type", "config_change")
        severity = changes.get("severity", "medium")

        # 分析引擎根据严重级别和组件重要性计算风险分数
        risk_scores = {
            "left_brain": 9, "right_brain": 9,
            "observer_traffic": 7, "actor_ip_isolation": 8,
            "scanner_vuln": 5, "auditor_log": 4,
            "scheduler_resource": 3, "tracker_forensic": 4,
        }

        total_risk = sum(risk_scores.get(c, 5) for c in target_components)
        risk_level = "low" if total_risk <= 10 else ("medium" if total_risk <= 25 else "high")

        # 分析引擎的防御评估
        approved = risk_level != "high" or change_type != "model_weight"

        left_output = {
            "assessment_id": f"LB-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "approved": approved,
            "risk_level": risk_level,
            "total_risk_score": total_risk,
            "compute_cost_estimate": len(target_components) * 15,
            "defense_impact": {
                "detection_pipeline": "observer_traffic" in target_components,
                "response_pipeline": "actor_ip_isolation" in target_components,
                "brain_core": any(c in target_components for c in ["left_brain", "right_brain"]),
            },
            "conditions": [] if approved else ["高风险变更需人工审批", "建议先在离线环境验证"],
            "recommended_rollout": "canary_first" if approved else "rejected",
        }

        return left_output

    def _run_right_brain_analysis(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """
        响应引擎协商：分析攻击趋势，推荐变更参数。

        模拟响应引擎的修复反击中枢提供攻击分析视角。
        """
        change_type = changes.get("change_type", "config_change")
        severity = changes.get("severity", "medium")

        right_output = {
            "analysis_id": f"RB-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "attack_trend": "increasing" if severity == "severe" else "stable",
            "confidence": 0.78 if change_type == "model_weight" else 0.92,
            "recommended_actions": [
                "更新检测规则以覆盖新型攻击变种",
                "调整阈值减少误报率",
            ],
            "threat_landscape": {
                "active_threats": ["DDoS", "port_scan", "brute_force"],
                "emerging_threats": ["zero_day_exploit"] if severity == "severe" else [],
            },
            "rollback_trigger_conditions": [
                "金丝雀批次误报率 > 15%",
                "金丝雀批次处理延迟 > 500ms",
                "新版本拦截成功率 < 90%",
            ],
        }

        return right_output

    def _generate_validation_checklist(self, package: "UpgradePackage") -> List[Dict[str, Any]]:
        """生成验证检查清单。"""
        checklist = [
            {
                "id": "CHK-001",
                "item": "版本号格式校验",
                "target": "semver格式正确",
                "method": "正则匹配 ^\\d+\\.\\d+\\.\\d+$",
            },
            {
                "id": "CHK-002",
                "item": "回滚快照完整性",
                "target": "所有变更组件均有快照",
                "method": "检查 rollback_snapshots 键等于 target_components",
            },
            {
                "id": "CHK-003",
                "item": "组件白名单检查",
                "target": "目标组件均在支持列表中",
                "method": "检查 target_components ⊆ SUPPORTED_COMPONENTS",
            },
            {
                "id": "CHK-004",
                "item": "变更类型合法",
                "target": "change_type 在支持列表中",
                "method": "枚举校验",
            },
            {
                "id": "CHK-005",
                "item": "双引擎协商记录完整",
                "target": "left_brain_decision 和 right_brain_analysis 均非空",
                "method": "字段存在性检查",
            },
            {
                "id": "CHK-006",
                "item": "回滚触发条件已定义",
                "target": "right_brain_analysis.rollback_trigger_conditions 非空",
                "method": "列表非空检查",
            },
            {
                "id": "CHK-007",
                "item": "校验和完整性",
                "target": "checksum 字段已计算",
                "method": "SHA256 校验",
            },
        ]
        return checklist

    def build_package(self, changes: Dict[str, Any]) -> UpgradePackage:
        """
        双引擎协商后生成升级包。

        Args:
            changes: 变更描述字典，需包含：
                - version: 语义化版本号
                - description: 升级描述
                - target_components: 目标组件列表
                - change_type: 变更类型
                - severity: 严重级别（可选）
                - changes_detail: 各组件变更明细（可选）

        Returns:
            UpgradePackage 实例
        """
        # 提取参数
        version = changes.get("version", "1.1.0")
        description = changes.get("description", "自动生成的升级包")
        target_components = changes.get("target_components", self.SUPPORTED_COMPONENTS[:4])
        change_type = changes.get("change_type", "config_change")
        severity = changes.get("severity", "medium")

        # 生成唯一包ID
        self._package_counter += 1
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        package_id = f"PKG-{ts}-{self._package_counter:04d}"

        # 双引擎协商
        left_result = self._run_left_brain_assessment(changes)
        right_result = self._run_right_brain_analysis(changes)

        # 如果分析引擎驳回，仍然生成包但标记
        if not left_result["approved"]:
            description += " [分析引擎驳回 - 需人工审批]"

        # 构建变更内容和回滚快照
        changes_detail = changes.get("changes_detail", {})
        rollback_snapshots = {}
        for comp in target_components:
            # 模拟变更内容
            changes_detail.setdefault(comp, {
                "type": change_type,
                "new_value": {"threshold": 0.75, "sensitivity": "high"},
                "reason": f"根据响应引擎攻击趋势分析更新 {comp}",
            })
            # 回滚快照 = 变更前值
            rollback_snapshots[comp] = {
                "type": change_type,
                "old_value": {"threshold": 0.60, "sensitivity": "medium"},
                "version_before": "1.0.0",
            }

        # 构建升级包
        package = UpgradePackage(
            package_id=package_id,
            version=version,
            description=description,
            target_components=target_components,
            change_type=change_type,
            changes=changes_detail,
            rollback_snapshots=rollback_snapshots,
            validation_checklist=[],
            left_brain_decision=left_result,
            right_brain_analysis=right_result,
            created_at=datetime.now().isoformat(),
        )

        # 生成验证清单
        package.validation_checklist = self._generate_validation_checklist(package)

        # 计算校验和
        payload = json.dumps({
            "package_id": package.package_id,
            "version": package.version,
            "target_components": package.target_components,
            "change_type": package.change_type,
            "changes": package.changes,
        }, sort_keys=True)
        package.checksum = hashlib.sha256(payload.encode()).hexdigest()

        # 持久化
        if not self.dry_run:
            pkg_path = os.path.join(self.store_dir, f"{package_id}.json")
            with open(pkg_path, "w", encoding="utf-8") as f:
                json.dump(package.to_dict(), f, indent=2, ensure_ascii=False)

        return package

    def validate_package(self, package: UpgradePackage) -> ValidationResult:
        """
        验证升级包的完整性和合法性。

        Returns:
            ValidationResult（含错误和警告列表）
        """
        errors = []
        warnings = []

        # CHK-001: 版本号格式
        import re
        if not re.match(r"^\d+\.\d+\.\d+$", package.version):
            errors.append(f"版本号格式无效: {package.version}，应为 semver")

        # CHK-002: 回滚快照完整性
        missing_snapshots = set(package.target_components) - set(package.rollback_snapshots.keys())
        if missing_snapshots:
            errors.append(f"回滚快照缺失组件: {missing_snapshots}")

        # CHK-003: 组件白名单
        invalid_comps = set(package.target_components) - set(self.SUPPORTED_COMPONENTS)
        if invalid_comps:
            errors.append(f"不支持的组件: {invalid_comps}")

        # CHK-004: 变更类型合法
        if package.change_type not in self.SUPPORTED_CHANGE_TYPES:
            errors.append(f"不支持的变更类型: {package.change_type}")

        # CHK-005: 双引擎协商
        if not package.left_brain_decision:
            warnings.append("缺少分析引擎协商记录")
        if not package.right_brain_analysis:
            warnings.append("缺少响应引擎分析记录")

        # CHK-006: 回滚触发条件
        rb_conditions = package.right_brain_analysis.get("rollback_trigger_conditions", [])
        if not rb_conditions:
            warnings.append("未定义回滚触发条件")

        # CHK-007: 校验和
        if not package.checksum:
            errors.append("缺少校验和")
        else:
            # 重新计算校验和
            payload = json.dumps({
                "package_id": package.package_id,
                "version": package.version,
                "target_components": package.target_components,
                "change_type": package.change_type,
                "changes": package.changes,
            }, sort_keys=True)
            expected = hashlib.sha256(payload.encode()).hexdigest()
            if expected != package.checksum:
                errors.append("校验和不匹配，数据可能损坏")

        # 额外检查：target_components 非空
        if not package.target_components:
            errors.append("目标组件列表为空")

        # 额外检查：version 递增（与已有包比较）
        if not self.dry_run:
            existing = [f for f in os.listdir(self.store_dir) if f.endswith(".json")]
            for ef in existing:
                fpath = os.path.join(self.store_dir, ef)
                with open(fpath, "r", encoding="utf-8") as f:
                    ep = json.load(f)
                if ep.get("version") == package.version and ep.get("package_id") != package.package_id:
                    warnings.append(f"版本 {package.version} 已存在（包 {ep.get('package_id')}）")

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )
