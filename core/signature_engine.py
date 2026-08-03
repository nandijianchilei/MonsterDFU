"""
规则引擎 — 基于 Suricata 规则格式的快速特征匹配模块。

设计目标：
- 匹配速度 预期 <1ms，LLM 约 2-5s（未做正式基准测试）
- 接口与 ThreatIndicator 兼容
- 支持预置规则 + 外部规则文件加载
"""

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ==================== 规则解析相关数据结构 ====================

@dataclass
class SignatureRule:
    """解析后的规则条目。"""

    sid: int
    msg: str
    classtype: str
    priority: int
    protocol: str
    raw: str

    # 匹配条件（从规则选项中提取）
    attack_type: str = ""               # 从 msg 推断的攻击类型
    threshold_count: int = 0            # 阈值-数量
    threshold_seconds: int = 0          # 阈值-时间窗口（秒）
    threshold_track: str = ""           # by_src / by_dst
    content_patterns: List[str] = field(default_factory=list)  # content 匹配串

    @property
    def category(self) -> str:
        """映射 classtype 到 ThreatCategory。"""
        mapping = {
            "attempted-dos": "ddos",
            "attempted-recon": "recon",
            "attempted-admin": "brute_force",
            "web-application-attack": "web_attack",
            "trojan-activity": "malware_c2",
            "attempted-user": "brute_force",
            "misc-attack": "web_attack",
            "misc-activity": "web_attack",
            "network-scan": "port_scan",
        }
        return mapping.get(self.classtype, self.classtype)

    @property
    def severity(self) -> str:
        """priority -> severity 映射。"""
        mapping = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        return mapping.get(self.priority, "medium")

    @property
    def action(self) -> str:
        """推荐处置动作。"""
        category_actions = {
            "ddos": "block_ip",
            "recon": "rate_limit",
            "brute_force": "block_ip",
            "web_attack": "block_ip",
            "c2_beacon": "isolate_host",
            "malware_c2": "isolate_host",
            "dns_tunnel": "block_domain",
            "data_exfiltration": "block_ip",
        }
        return category_actions.get(self.category, "monitor")


# ==================== 规则解析器 ====================

class RuleParser:
    """Suricata 简化规则格式解析器。"""

    # 匹配规则行：alert <protocol> ... (options)
    _RULE_RE = re.compile(
        r"alert\s+(?P<protocol>\w+)\s+"
        r"(?P<src_ip>[^\s]+)\s+(?P<src_port>[^\s]+)\s+"
        r"->\s+(?P<dst_ip>[^\s]+)\s+(?P<dst_port>[^\s]+)\s+"
        r"\((?P<options>.+)\)\s*;?\s*$"
    )

    _SID_RE = re.compile(r"sid\s*:\s*(\d+)")
    _MSG_RE = re.compile(r"msg\s*:\s*\"([^\"]+)\"")
    _CLASSTYPE_RE = re.compile(r"classtype\s*:\s*([^;]+)")
    _PRIORITY_RE = re.compile(r"priority\s*:\s*(\d+)")
    _THRESHOLD_RE = re.compile(
        r"threshold\s*:\s*type\s+(\w+)\s*,\s*track\s+(\w+)\s*,\s*count\s+(\d+)\s*,\s*seconds\s+(\d+)"
    )
    _CONTENT_RE = re.compile(r"content\s*:\s*\"([^\"]+)\"", re.IGNORECASE)

    # 从 msg 推断 attack type
    _TYPE_HINTS = {
        "ddos": "ddos",
        "dos": "ddos",
        "port scan": "port_scan",
        "scan": "port_scan",
        "brute": "brute_force",
        "bruteforce": "brute_force",
        "sql injection": "sql_injection",
        "sql inject": "sql_injection",
        "sql": "sql_injection",
        "c2": "c2_beacon",
        "beacon": "c2_beacon",
        "malware": "malware_c2",
        "trojan": "malware_c2",
        "ransomware": "malware_c2",
        "backdoor": "malware_c2",
        "dns tunnel": "dns_tunnel",
        "dns tunneling": "dns_tunnel",
        "exfiltration": "data_exfiltration",
        "exfil": "data_exfiltration",
        "data exfil": "data_exfiltration",
        "web attack": "web_attack",
        "directory traversal": "web_attack",
        "path traversal": "web_attack",
        "xss": "web_attack",
        "cross site": "web_attack",
        "phishing": "web_attack",
    }

    @classmethod
    def parse_line(cls, line: str) -> Optional[SignatureRule]:
        """解析单行规则，失败返回 None。"""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        m = cls._RULE_RE.match(line)
        if not m:
            return None

        options = m.group("options")

        sid_match = cls._SID_RE.search(options)
        msg_match = cls._MSG_RE.search(options)
        ct_match = cls._CLASSTYPE_RE.search(options)
        pri_match = cls._PRIORITY_RE.search(options)
        th_match = cls._THRESHOLD_RE.search(options)
        content_matches = cls._CONTENT_RE.findall(options)

        if not sid_match:
            return None

        msg = msg_match.group(1) if msg_match else ""
        priority = int(pri_match.group(1)) if pri_match else 3
        attack_type = cls._infer_type(msg)

        rule = SignatureRule(
            sid=int(sid_match.group(1)),
            msg=msg,
            classtype=ct_match.group(1).strip().rstrip(";") if ct_match else "unknown",
            priority=priority,
            protocol=m.group("protocol"),
            raw=line,
            attack_type=attack_type,
        )

        if th_match:
            rule.threshold_count = int(th_match.group(3))
            rule.threshold_seconds = int(th_match.group(4))
            rule.threshold_track = th_match.group(2)

        if content_matches:
            rule.content_patterns = [c.lower() for c in content_matches]

        return rule

    @classmethod
    def _infer_type(cls, msg: str) -> str:
        """从规则 msg 推断攻击类型。"""
        lower = msg.lower()
        for key, atype in cls._TYPE_HINTS.items():
            if key in lower:
                return atype
        return "unknown"

    @classmethod
    def parse_file(cls, filepath: str) -> List[SignatureRule]:
        """解析整个规则文件，返回规则列表。"""
        rules: List[SignatureRule] = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                rule = cls.parse_line(line)
                if rule:
                    rules.append(rule)
        return rules


# ==================== 规则引擎 ====================

class SignatureEngine:
    """
    特征规则引擎 — 对告警进行快速规则匹配。

    用法:
        engine = SignatureEngine()           # 加载默认规则
        result = engine.match(alert)         # 返回命中结果或 None
        engine.load_rules_from_file(path)    # 追加外部规则
        stats = engine.get_stats()           # 获取命中统计
    """

    DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "default.rules"

    def __init__(self, rules_path: Optional[str] = None):
        self._rules: Dict[int, SignatureRule] = {}
        self._stats: Dict[str, int] = {
            "total_matches": 0,
            "total_checks": 0,
            "last_match_time": 0.0,
        }
        self._per_rule_hits: Dict[int, int] = {}

        # 加载默认规则
        default_path = str(rules_path or self.DEFAULT_RULES_PATH)
        if Path(default_path).exists():
            loaded = self.load_rules_from_file(default_path)
            if loaded == 0:
                self._load_builtin_rules()
        else:
            self._load_builtin_rules()

    # ---------- 规则加载 ----------

    def _load_builtin_rules(self):
        """加载硬编码的内置规则（确保无外部文件也能工作）。"""
        builtin_lines = [
            'alert tcp any any -> any any (msg:"ET DOS Possible DDOS Attack"; flow:to_server; threshold:type threshold, track by_src, count 100, seconds 10; classtype:attempted-dos; sid:2000001; priority:1;)',
            'alert tcp any any -> any any (msg:"ET SCAN Port Scan Detected"; flow:to_server; threshold:type threshold, track by_src, count 30, seconds 5; classtype:attempted-recon; sid:2000002; priority:2;)',
            'alert tcp any any -> any any (msg:"ET BRUTE Brute Force Login Attempt"; flow:to_server; threshold:type threshold, track by_src, count 20, seconds 5; classtype:attempted-admin; sid:2000003; priority:1;)',
            'alert tcp any any -> any any (msg:"ET WEB SQL Injection Attempt"; flow:to_server; content:"SELECT"; nocase; classtype:web-application-attack; sid:2000004; priority:1;)',
            'alert tcp any any -> any any (msg:"ET MALWARE C2 Beacon Activity"; flow:to_server; threshold:type both, track by_src, count 5, seconds 60; classtype:trojan-activity; sid:2000005; priority:1;)',
        ]
        for line in builtin_lines:
            rule = RuleParser.parse_line(line)
            if rule:
                self._rules[rule.sid] = rule
                self._per_rule_hits[rule.sid] = 0

    def load_rules_from_file(self, filepath: str) -> int:
        """从外部文件加载规则（追加模式），返回成功加载数量。"""
        rules = RuleParser.parse_file(filepath)
        count = 0
        for rule in rules:
            self._rules[rule.sid] = rule  # 同 sid 覆盖
            if rule.sid not in self._per_rule_hits:
                self._per_rule_hits[rule.sid] = 0
            count += 1
        return count

    # ---------- 核心匹配 ----------

    def match(self, alert: dict) -> Optional[dict]:
        """
        对告警进行规则匹配。

        Args:
            alert: 告警字典，需包含以下字段（部分可选）：
                - type: 攻击类型字符串（如 ddos / port_scan / brute_force / sql_injection / c2_beacon）
                - source_ip: 来源 IP
                - dst_port: 目标端口（可选）
                - packets: 报文数（可选，用于阈值匹配）
                - ports: 扫描端口数（可选）
                - payload: 载荷内容（可选，用于 content 匹配）

        Returns:
            命中返回 {rule_id, category, severity, action, confidence}，未命中返回 None。
        """
        self._stats["total_checks"] += 1

        alert_type = str(alert.get("type", "")).lower()
        alert_packets = alert.get("packets", 0)
        alert_ports = alert.get("ports", 0)
        alert_payload = str(alert.get("payload", "")).lower()
        alert_src = alert.get("source_ip", "")

        best_confidence = 0.0
        best_rule: Optional[SignatureRule] = None

        for rule in self._rules.values():
            confidence = self._evaluate_rule(rule, alert_type, alert_packets, alert_ports, alert_payload)
            if confidence > 0 and confidence > best_confidence:
                best_confidence = confidence
                best_rule = rule

        if best_rule is None:
            return None

        # 更新统计
        self._stats["total_matches"] += 1
        self._stats["last_match_time"] = time.time()
        self._per_rule_hits[best_rule.sid] = self._per_rule_hits.get(best_rule.sid, 0) + 1

        # 阈值规则额外验证
        if best_rule.threshold_count > 0:
            threshold_met = alert_packets >= best_rule.threshold_count or alert_ports >= best_rule.threshold_count
            if not threshold_met:
                best_confidence = max(best_confidence - 0.3, 0.1)

        return {
            "rule_id": best_rule.sid,
            "category": best_rule.category,
            "severity": best_rule.severity,
            "action": best_rule.action,
            "confidence": round(min(best_confidence, 1.0), 2),
        }

    def _evaluate_rule(
        self,
        rule: SignatureRule,
        alert_type: str,
        alert_packets: int,
        alert_ports: int,
        alert_payload: str,
    ) -> float:
        """评估单条规则与告警的匹配度，返回 0.0~1.0 的置信度。"""
        score = 0.0

        # 1. 攻击类型匹配（权重 0.5）
        if rule.attack_type and alert_type:
            if rule.attack_type == alert_type:
                score += 0.5
            elif self._is_related_type(rule.attack_type, alert_type):
                score += 0.3
            else:
                return 0.0  # 类型完全不相关，跳过
        else:
            score += 0.2  # 类型信息不足时给基础分

        # 2. 阈值匹配（权重 0.3）
        if rule.threshold_count > 0:
            effective_value = max(alert_packets, alert_ports)
            if effective_value >= rule.threshold_count:
                ratio = min(effective_value / rule.threshold_count, 3.0) / 3.0
                score += 0.3 * ratio
            else:
                score -= 0.1
        else:
            score += 0.15  # 无阈值要求时给一半

        # 3. content 匹配（权重 0.2）
        if rule.content_patterns:
            content_hit = any(p in alert_payload for p in rule.content_patterns)
            if content_hit:
                score += 0.2
            else:
                score -= 0.05
        else:
            score += 0.1

        return max(score, 0.0)

    # ---------- 统计 ----------

    def get_stats(self) -> dict:
        """返回命中统计。"""
        return {
            "total_checks": self._stats["total_checks"],
            "total_matches": self._stats["total_matches"],
            "hit_rate": (
                round(self._stats["total_matches"] / self._stats["total_checks"], 4)
                if self._stats["total_checks"] > 0
                else 0.0
            ),
            "last_match_time": self._stats["last_match_time"],
            "rules_loaded": len(self._rules),
            "per_rule_hits": dict(self._per_rule_hits),
        }

    # ---------- 辅助方法 ----------

    @staticmethod
    def _is_related_type(rule_type: str, alert_type: str) -> bool:
        """判断两个攻击类型是否相关。"""
        related_groups = [
            {"ddos", "port_scan", "recon"},
            {"brute_force", "credential_stuffing"},
            {"sql_injection", "xss", "web_attack"},
            {"c2_beacon", "malware_c2", "malware", "trojan"},
            {"dns_tunnel", "c2_beacon", "malware_c2"},
            {"data_exfiltration", "c2_beacon", "malware_c2"},
        ]
        for group in related_groups:
            if rule_type in group and alert_type in group:
                return True
        return False


# ==================== 便捷工厂函数 ====================

def create_engine(rules_dir: Optional[str] = None) -> SignatureEngine:
    """
    创建 SignatureEngine 实例，自动加载规则。

    加载策略（按优先级）：
    1. 若 rules_dir 指定，加载其下 default.rules
    2. 自动扫描 rules/et_open/ 目录下所有 .rules 文件并加载
    3. 内置规则兜底（确保无外部文件也能运行）

    Args:
        rules_dir: 规则目录路径，默认自动探测项目根目录下的 rules/

    Returns:
        已加载规则的 SignatureEngine 实例
    """
    if rules_dir is None:
        # 自动探测项目 rules 目录
        rules_dir = str(Path(__file__).resolve().parent.parent / "rules")

    engine = SignatureEngine(rules_path=str(Path(rules_dir) / "default.rules"))

    # 自动加载 ET Open 规则集（支持 et_open/ 和 et_open/rules/ 两种布局）
    et_open_candidates = [
        Path(rules_dir) / "et_open" / "rules",   # 嵌套: et_open/rules/*.rules
        Path(rules_dir) / "et_open",               # 扁平: et_open/*.rules
    ]
    total_loaded = 0
    for et_dir in et_open_candidates:
        if et_dir.is_dir():
            rule_files = sorted(et_dir.glob("*.rules"))
            for rf in rule_files:
                try:
                    loaded = engine.load_rules_from_file(str(rf))
                    total_loaded += loaded
                except Exception:
                    pass  # 跳过无法解析的文件
    if total_loaded > 0:
        import logging
        logging.getLogger(__name__).info(
            f"已从 ET Open 加载 {total_loaded} 条规则"
        )

    return engine
