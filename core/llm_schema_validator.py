"""
LLM Schema 校验器
在双脑发布防御方案前拦截格式/语义/安全违规，防止 LLM 幻觉威胁系统。

4 层校验：
1. JSON 语法校验
2. 结构字段校验（必需字段、有效枚举值）
3. 逻辑约束校验（severity/action 一致性）
4. 高危硬拦截校验（保护网段不可 block）
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("LLMSchemaValidator")

# ── 边界定义 ──

VALID_SEVERITIES = {"low", "medium", "high", "severe"}
VALID_ACTIONS = {"monitor", "rate_limit", "isolate_ip", "block"}
VALID_CATEGORIES = {"ddos", "port_scan", "brute_force", "vuln", "audit", "unknown"}

# 保护网段（不可执行 block/isolate_ip）
PROTECTED_NETS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# ── Schema 定义 ──

# 双脑决策输出允许的固定字段白名单（提示注入防护：自由指令字段一律拦截）
# 允许字段含任务点名的 recommend / target_ip / confidence，以及现有必需字段；
# 下划线前缀字段（_threat 等内部标记）允许通过，供降级路径使用。
LEFT_BRAIN_ALLOWED_ALERT_FIELDS = {
    "id", "severity", "action", "reason", "resource_advice",
    "recommend", "target_ip", "confidence",
}
RIGHT_BRAIN_ALLOWED_THREAT_FIELDS = {
    "alert_id", "attack_type", "trace", "vulnerabilities",
    "countermeasures", "confidence", "recommend", "target_ip", "source_ip",
}

LEFT_BRAIN_SCHEMA = {
    "required_root_keys": {"alerts", "summary", "reasoning"},
    "required_alert_keys": {"id", "severity", "action", "reason", "resource_advice"},
    "valid_severities": VALID_SEVERITIES,
    "valid_actions": VALID_ACTIONS,
    "allowed_alert_fields": LEFT_BRAIN_ALLOWED_ALERT_FIELDS,
}

RIGHT_BRAIN_SCHEMA = {
    "required_root_keys": {"threats", "trace", "countermeasures", "confidence", "reasoning"},
    "required_threat_keys": {"alert_id", "attack_type", "trace", "vulnerabilities", "countermeasures", "confidence"},
    "valid_categories": VALID_CATEGORIES,
    "allowed_threat_fields": RIGHT_BRAIN_ALLOWED_THREAT_FIELDS,
}


class LLMSchemaValidator:
    """LLM 输出结构/语义/安全校验器。"""

    def __init__(self) -> None:
        self._stats = {
            "total": 0,
            "passed": 0,
            "syntax_error": 0,
            "schema_violation": 0,
            "safety_block": 0,
        }

    # ── 公开校验接口 ──

    def validate_left(self, raw: str, target_ip: Optional[str] = None) -> Tuple[bool, Optional[Dict], List[str]]:
        """
        校验分析引擎（LeftBrain）输出。

        Returns:
            (valid, parsed_json, errors)
        """
        self._stats["total"] += 1
        errors: List[str] = []

        parsed = self._parse_json(raw, errors)
        if parsed is None:
            self._stats["syntax_error"] += 1
            return False, None, errors

        self._validate_schema(parsed, LEFT_BRAIN_SCHEMA, errors)
        self._validate_left_logic(parsed, errors)
        if target_ip:
            self._validate_safety(target_ip, parsed, errors)

        valid = len(errors) == 0
        if not valid:
            self._stats["schema_violation"] += 1 if not any("保护网段" in e for e in errors) else 0
            if any("保护网段" in e for e in errors):
                self._stats["safety_block"] += 1
        else:
            self._stats["passed"] += 1

        return valid, parsed, errors

    def validate_right(self, raw: str, target_ip: Optional[str] = None) -> Tuple[bool, Optional[Dict], List[str]]:
        """
        校验响应引擎（RightBrain）输出。

        Returns:
            (valid, parsed_json, errors)
        """
        self._stats["total"] += 1
        errors: List[str] = []

        parsed = self._parse_json(raw, errors)
        if parsed is None:
            self._stats["syntax_error"] += 1
            return False, None, errors

        self._validate_schema(parsed, RIGHT_BRAIN_SCHEMA, errors)
        self._validate_right_logic(parsed, errors)
        if target_ip:
            self._validate_safety(target_ip, parsed, errors)

        valid = len(errors) == 0
        if not valid:
            self._stats["schema_violation"] += 1 if not any("保护网段" in e for e in errors) else 0
            if any("保护网段" in e for e in errors):
                self._stats["safety_block"] += 1
        else:
            self._stats["passed"] += 1

        return valid, parsed, errors

    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    # ── 内部校验方法 ──

    def _parse_json(self, raw: str, errors: List[str]) -> Optional[Dict]:
        """第 1 层：JSON 语法校验。"""
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if not isinstance(parsed, dict):
                errors.append("根节点不是 JSON 对象")
                return None
            return parsed
        except json.JSONDecodeError as e:
            errors.append(f"JSON 语法错误: {e}")
            return None

    def _validate_schema(self, parsed: Dict, schema: Dict, errors: List[str]) -> None:
        """第 2 层：结构字段校验。"""
        # 根键校验
        required = schema.get("required_root_keys", set())
        missing = required - parsed.keys()
        if missing:
            errors.append(f"缺少必需根字段: {', '.join(sorted(missing))}")

        # Left：校验 alerts 数组
        if "alerts" in parsed:
            self._validate_alerts(parsed["alerts"], schema, errors)

        # Right：校验 threats 数组
        if "threats" in parsed:
            self._validate_threats(parsed["threats"], schema, errors)

    def _validate_alerts(self, alerts: Any, schema: Dict, errors: List[str]) -> None:
        if not isinstance(alerts, list):
            errors.append("alerts 字段必须是数组")
            return
        required = schema.get("required_alert_keys", set())
        valid_sev = schema.get("valid_severities", set())
        valid_act = schema.get("valid_actions", set())
        allowed = schema.get("allowed_alert_fields")
        for i, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                errors.append(f"alerts[{i}] 不是对象")
                continue
            missing = required - alert.keys()
            if missing:
                errors.append(f"alerts[{i}] 缺少字段: {', '.join(sorted(missing))}")
            if alert.get("severity") not in valid_sev:
                errors.append(f"alerts[{i}] severity='{alert.get('severity')}' 无效")
            if alert.get("action") not in valid_act:
                errors.append(f"alerts[{i}] action='{alert.get('action')}' 无效")
            if allowed is not None:
                extra = [k for k in alert.keys()
                         if k not in allowed and not k.startswith("_")]
                if extra:
                    errors.append(
                        f"alerts[{i}] 含白名单外字段(疑似注入指令): {', '.join(sorted(extra))}"
                    )

    def _validate_threats(self, threats: Any, schema: Dict, errors: List[str]) -> None:
        if not isinstance(threats, list):
            errors.append("threats 字段必须是数组")
            return
        required = schema.get("required_threat_keys", set())
        valid_cat = schema.get("valid_categories", set())
        allowed = schema.get("allowed_threat_fields")
        for i, t in enumerate(threats):
            if not isinstance(t, dict):
                errors.append(f"threats[{i}] 不是对象")
                continue
            missing = required - t.keys()
            if missing:
                errors.append(f"threats[{i}] 缺少字段: {', '.join(sorted(missing))}")
            if "attack_type" in t and t["attack_type"] not in valid_cat and "unknown" not in t["attack_type"]:
                pass  # 攻击类型是自由文本描述，不做枚举校验
            conf = t.get("confidence", 1.0)
            if not isinstance(conf, (int, float)) or conf < 0 or conf > 1:
                errors.append(f"threats[{i}] confidence={conf} 不在 [0,1] 范围")
            if allowed is not None:
                extra = [k for k in t.keys()
                         if k not in allowed and not k.startswith("_")]
                if extra:
                    errors.append(
                        f"threats[{i}] 含白名单外字段(疑似注入指令): {', '.join(sorted(extra))}"
                    )

    def _validate_left_logic(self, parsed: Dict, errors: List[str]) -> None:
        """第 3 层：LeftBrain 逻辑约束校验。"""
        alerts = parsed.get("alerts", [])
        summary = parsed.get("summary", {})
        # severity 与 action 一致性：severe 必须 block 或 isolate_ip
        for alert in alerts:
            sev = alert.get("severity", "")
            act = alert.get("action", "")
            if sev == "severe" and act not in ("block", "isolate_ip"):
                errors.append(
                    f"逻辑违规: severe 级别告警 {alert.get('id', '')} "
                    f"action='{act}' 应为 block/isolate_ip"
                )
            if sev == "low" and act in ("block", "isolate_ip"):
                errors.append(
                    f"逻辑违规: low 级别告警 {alert.get('id', '')} "
                    f"action='{act}' 过度处置"
                )
        # summary 计数一致性
        if isinstance(summary, dict):
            summary_total = summary.get("total", -1)
            if summary_total != -1 and summary_total != len(alerts):
                errors.append(
                    f"summary.total={summary_total} 与 alerts 数量 {len(alerts)} 不一致"
                )

    def _validate_right_logic(self, parsed: Dict, errors: List[str]) -> None:
        """第 3 层：RightBrain 逻辑约束校验。"""
        threats = parsed.get("threats", [])
        # 全局 confidence 与 threats 数组平均值大致对齐
        global_conf = parsed.get("confidence", 0.0)
        if threats and global_conf > 0:
            avg = sum(t.get("confidence", 0.0) for t in threats) / len(threats)
            if abs(global_conf - avg) > 0.3:
                errors.append(
                    f"逻辑违规: 全局 confidence={global_conf:.2f} "
                    f"与 threats 平均 {avg:.2f} 偏差超过 0.3"
                )

    def _is_protected(self, ip: str) -> bool:
        """检查 IP 是否在保护网段内。"""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1])
        if first == 127:
            return True
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        return False

    def _validate_safety(self, target_ip: str, parsed: Dict, errors: List[str]) -> None:
        """第 4 层：高危硬拦截校验。保护网段不可 block/isolate_ip。"""
        if not self._is_protected(target_ip):
            return
        alerts = parsed.get("alerts", []) if "alerts" in parsed else []
        threats = parsed.get("threats", []) if "threats" in parsed else []
        for alert in alerts:
            act = alert.get("action", "")
            if act in ("block", "isolate_ip"):
                errors.append(
                    f"高危拦截: 保护网段 IP {target_ip} 不可 {act} "
                    f"(告警 {alert.get('id', '')})"
                )
        for t in threats:
            cms = t.get("countermeasures", [])
            for cm in cms:
                if any(kw in cm.lower() for kw in ("block", "isolate", "ban", "封禁")):
                    errors.append(
                        f"高危拦截: 保护网段 IP {target_ip} 的反制策略 '{cm}' 违规"
                    )

    def __repr__(self) -> str:
        s = self._stats
        return (
            f"LLMSchemaValidator(total={s['total']}, pass={s['passed']}, "
            f"syntax={s['syntax_error']}, schema={s['schema_violation']}, "
            f"safety={s['safety_block']})"
        )
