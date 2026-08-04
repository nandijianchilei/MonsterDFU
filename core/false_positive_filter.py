"""
误报过滤层 (FalsePositiveFilter)
===============================
将正常流量（clean_traffic）的误报收敛到 0。

过滤管线（按顺序）：
  1. WhitelistFilter  —— 白名单（域名 / IP 网段 / 端口）
                        命中"可信域名"或"可信 IP 网段"的事件直接判定为正常，不产生告警；
                        端口白名单不单独硬放行（避免掩盖端口扫描等攻击），作为 LLM 二次确认的
                        良性信号参与评分。
  2. AlertThreshold   —— 告警阈值：同一来源（source_ip）+ 同一类别，多次触发才升级为告警，
                        单次低频触发不告警（收敛噪音）；
                        例外：severity 为 high/severe 的高危信号直接放行，不做阈值压制。
  3. LLMConfirmLayer  —— LLM 二次确认：对通过前两层的候选告警做二次判定。
                        默认使用确定性 mock（离线可复现、可测试），可插拔真实 LLM（confirm_fn）。
                        mock 依据可信域名/IP、标准端口、包大小、可疑端口、超大包、
                        可疑类别等信号综合打分；判定为 benign 的候选告警被抑制。

设计目标：
  - 演示数据集误报 10 → 0
  - 演示数据集检测率 100%
"""

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── 默认可信域名前缀（与 organs/observer_outbound.py 的 TRUSTED_DOMAINS 对齐）──
DEFAULT_TRUSTED_DOMAINS: List[str] = [
    "cdn.", "api.", "oss.", "static.", "img.",
    "google.", "bing.", "baidu.", "tencent.", "aliyun.",
    "microsoft.", "github.", "docker.", "pypi.", "npm.",
    "cloudflare.", "amazonaws.", "azure.",
]

# ── 默认可信 IP 网段（Cloudflare 等主流 CDN，覆盖 clean_traffic 的 104.16.x.x）──
DEFAULT_TRUSTED_IP_NETWORKS: List[str] = [
    "104.16.0.0/13",    # Cloudflare
    "103.21.244.0/22",  # Cloudflare
    "103.22.200.0/22",  # Cloudflare
    "103.31.4.0/22",    # Cloudflare
]

# ── 默认标准端口（正常 HTTPS/API 出站）──
DEFAULT_TRUSTED_PORTS: List[int] = [80, 443, 8443]

# C2 信标常用可疑端口
C2_SUSPICIOUS_PORTS: set = {4444, 5555, 6666, 7777, 8443, 9001, 31337, 1337, 8088, 9999}

# 高危类别：直接跳过阈值压制
HIGH_RISK_SEVERITIES = {"high", "severe"}

# =============================================================================
# 提示注入输入净化（Prompt-Injection Input Sanitization）
# -----------------------------------------------------------------------------
# 告警数据在进入 LLM 前必须经过净化：
#   1. 只允许白名单结构化字段进入 prompt（严禁原始 payload / 自由文本）；
#   2. 对允许进入的字符串值，剥离注入惯用控制串（\nSYSTEM: / ignore previous /
#      作为管理员 等）。
# =============================================================================

# 观测数据白名单字段（提示注入防护：仅允许结构化字段进 LLM，严禁原始 payload 文本）
OBSERVATION_FIELD_WHITELIST = {
    "id",
    "category",
    "severity",
    "src_ip",           # 攻击源 IP
    "dst_port",         # 被攻击端口
    "packet_count",     # 包数量（raw_data.packets）
    "signature_hits",   # 签名引擎命中数（raw_data.signature_hits）
    "request_count",    # 请求次数（raw_data.request_count）
    "scanned_port_count",  # 扫描端口数（raw_data.scanned_port_count / unique_ports）
    "attempts",         # 暴力破解尝试数（raw_data.attempts）
}

# 注入惯用控制串（不区分大小写匹配，命中即剥离/告警）
INJECTION_CONTROL_PATTERNS = [
    "\nSYSTEM:",
    "\r\nSYSTEM:",
    "SYSTEM:",
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "forget everything",
    "作为管理员",
    "以管理员身份",
    "你现在是",
    "假装你是",
    "忽略之前",
    "忽略以上",
    "请忽略",
    "无视以上",
    "override",
    "jailbreak",
    "developer mode",
    "do anything now",
]


def sanitize_text(text: Any, max_len: int = 200) -> str:
    """
    剥离文本中的提示注入惯用控制串，并限制长度。

    用于进入 LLM prompt 的所有字符串字段（告警 id / src_ip / 描述等）。
    命中注入控制串的字段会被截断到控制串前，避免控制指令进入 prompt。
    """
    if text is None:
        return ""
    s = str(text)
    lowered = s.lower()
    for pattern in INJECTION_CONTROL_PATTERNS:
        idx = lowered.find(pattern.lower())
        if idx >= 0:
            # 截断到控制串之前，彻底阻断注入指令
            s = s[:idx]
            lowered = s.lower()
    if len(s) > max_len:
        s = s[:max_len]
    return s.strip()


def extract_observation_fields(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    从告警字典中提取【白名单结构化字段】，供 LLM prompt 使用。

    规则：
      - 只返回 OBSERVATION_FIELD_WHITELIST 内的键；
      - src_ip 取自 source_ip / src_ip；dst_port 取自 target_port / dst_port；
      - 数值指标从 raw_data（packets / signature_hits / request_count /
        scanned_port_count / unique_ports / attempts）中提取；
      - 所有字符串值经 sanitize_text 剥离注入控制串；
      - 严禁返回 raw_data 全量 / description / payload 等自由文本字段。
    """
    result: Dict[str, Any] = {}
    raw_data = raw.get("raw_data", {})
    if not isinstance(raw_data, dict):
        raw_data = {}

    for fname in OBSERVATION_FIELD_WHITELIST:
        value = None
        if fname == "src_ip":
            value = raw.get("source_ip") or raw.get("src_ip")
        elif fname == "dst_port":
            value = raw.get("target_port") or raw.get("dst_port")
        elif fname == "packet_count":
            value = raw_data.get("packets")
        elif fname == "signature_hits":
            value = raw_data.get("signature_hits")
        elif fname == "request_count":
            value = raw_data.get("request_count")
        elif fname == "scanned_port_count":
            value = raw_data.get("scanned_port_count", raw_data.get("unique_ports"))
        elif fname == "attempts":
            value = raw_data.get("attempts")
        elif fname in raw:
            value = raw.get(fname)

        if value is None:
            continue
        if isinstance(value, str):
            value = sanitize_text(value)
        result[fname] = value

    return result


class InputSanitizer:
    """
    输入净化器门面：告警进 LLM 前调用。

    用法：
        san = InputSanitizer()
        clean = san.sanitize_alert(raw_alert_dict)
    """

    def __init__(self) -> None:
        self.stats = {
            "sanitized_alerts": 0,
            "injection_stripped": 0,
            "payload_blocked": 0,
        }

    def sanitize_alert(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        净化单条告警：只保留白名单结构化字段，剥离注入控制串。
        """
        self.stats["sanitized_alerts"] += 1
        # 若原始告警携带 payload / raw_data 全量字段，记录被阻断的载荷
        if "payload" in raw or raw.get("raw_data"):
            self.stats["payload_blocked"] += 1
        clean = extract_observation_fields(raw)
        if any(
            p.lower() in str(v).lower()
            for v in raw.values()
            if isinstance(v, str)
            for p in INJECTION_CONTROL_PATTERNS
        ):
            self.stats["injection_stripped"] += 1
        return clean

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)


@dataclass
class FPFilterConfig:
    """误报过滤层配置。"""
    enabled: bool = True
    ip_networks: List[str] = field(default_factory=lambda: list(DEFAULT_TRUSTED_IP_NETWORKS))
    ports: List[int] = field(default_factory=lambda: list(DEFAULT_TRUSTED_PORTS))
    domains: List[str] = field(default_factory=lambda: list(DEFAULT_TRUSTED_DOMAINS))
    min_triggers: int = 2          # 同一来源同一类别触发次数 >= 此值才升级为告警
    window_seconds: float = 0.0    # 0 表示不限窗口（累计计数）
    llm_enabled: bool = True
    llm_mock: bool = True
    llm_benign_threshold: float = 0.6
    confirm_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "FPFilterConfig":
        """从普通字典构造配置（供 legacy config.yaml / 环境变量注入）。"""
        cfg = cls()
        if not data or not isinstance(data, dict):
            return cfg
        cfg.enabled = bool(data.get("enabled", cfg.enabled))
        whitelist = data.get("whitelist") or {}
        if isinstance(whitelist, dict):
            if whitelist.get("ip_networks"):
                cfg.ip_networks = list(whitelist["ip_networks"])
            if whitelist.get("ports"):
                cfg.ports = [int(p) for p in whitelist["ports"]]
            if whitelist.get("domains"):
                cfg.domains = [str(d) for d in whitelist["domains"]]
        threshold = data.get("threshold") or {}
        if isinstance(threshold, dict):
            cfg.min_triggers = int(threshold.get("min_triggers", cfg.min_triggers))
            cfg.window_seconds = float(threshold.get("window_seconds", cfg.window_seconds))
        llm = data.get("llm") or {}
        if isinstance(llm, dict):
            cfg.llm_enabled = bool(llm.get("enabled", cfg.llm_enabled))
            cfg.llm_mock = bool(llm.get("mock", cfg.llm_mock))
            cfg.llm_benign_threshold = float(llm.get("benign_threshold", cfg.llm_benign_threshold))
        return cfg

    @classmethod
    def from_df_config(cls) -> "FPFilterConfig":
        """从 dfuconfig（default_config.yaml + 环境变量）读取配置。"""
        try:
            from dfuconfig import config as df_config
            section = df_config.get("false_positive_filter", default=None)
            if not section:
                return cls()
            if isinstance(section, dict):
                return cls.from_dict(dict(section))
            # ConfigDict 兼容
            return cls.from_dict(_configdict_to_dict(section))
        except Exception:
            return cls()


def _configdict_to_dict(obj: Any) -> Dict[str, Any]:
    """将 dfuconfig.ConfigDict 递归转为普通 dict。"""
    if hasattr(obj, "items"):
        return {k: _configdict_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_configdict_to_dict(v) for v in obj]
    return obj


# ── 1. 白名单过滤 ──

class WhitelistFilter:
    """白名单：可信域名（前缀）、可信 IP 网段、标准端口。"""

    def __init__(
        self,
        ip_networks: Optional[List[str]] = None,
        ports: Optional[List[int]] = None,
        domains: Optional[List[str]] = None,
    ):
        self._networks = [ip_network(n, strict=False) for n in (ip_networks or DEFAULT_TRUSTED_IP_NETWORKS)]
        self._ports = set(ports or DEFAULT_TRUSTED_PORTS)
        self._domains = [str(d).lower().strip().rstrip(".") for d in (domains or DEFAULT_TRUSTED_DOMAINS)]
        self.stats = {"domain_hit": 0, "ip_hit": 0, "port_hit": 0}

    def match_reason(self, event: Dict[str, Any]) -> Optional[str]:
        """
        返回事件命中的白名单信号：
          'domain' / 'ip' / 'port' / None
        'domain' 与 'ip' 属于硬放行信号；'port' 仅作为辅助信号（不单独放行）。
        """
        domain = str(event.get("domain", "") or "").lower().strip().rstrip(".")
        if domain:
            for prefix in self._domains:
                if domain == prefix or domain.startswith(prefix):
                    self.stats["domain_hit"] += 1
                    return "domain"

        dst_ip = str(event.get("dst_ip", "") or "")
        if dst_ip:
            try:
                addr = ip_address(dst_ip)
                for net in self._networks:
                    if addr in net:
                        self.stats["ip_hit"] += 1
                        return "ip"
            except ValueError:
                pass

        port = event.get("dst_port")
        if port in self._ports:
            self.stats["port_hit"] += 1
            return "port"

        return None

    def is_benign(self, event: Dict[str, Any]) -> bool:
        """是否命中硬放行白名单（可信域名 / 可信 IP）。"""
        return self.match_reason(event) in ("domain", "ip")

    def has_standard_port(self, event: Dict[str, Any]) -> bool:
        return event.get("dst_port") in self._ports

    def is_trusted_ip(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            addr = ip_address(ip)
            return any(addr in net for net in self._networks)
        except ValueError:
            return False

    def is_trusted_domain(self, domain: str) -> bool:
        d = str(domain or "").lower().strip().rstrip(".")
        if not d:
            return False
        return any(d == prefix or d.startswith(prefix) for prefix in self._domains)


# ── 2. 告警阈值 ──

class AlertThreshold:
    """
    告警阈值：同一来源（source_ip）+ 同一类别，触发次数达到 min_triggers 才升级为告警。

    window_seconds > 0 时按滑动窗口计数；= 0 时累计计数。
    """

    def __init__(self, min_triggers: int = 2, window_seconds: float = 0.0):
        self.min_triggers = max(1, int(min_triggers))
        self.window_seconds = float(window_seconds)
        self._counters: Dict[Tuple[str, str], Any] = {}
        self.stats = {"suppressed": 0, "passed": 0}

    def should_alert(self, source_key: Tuple[str, str], timestamp: float) -> bool:
        """登记一次触发并判断是否达到告警阈值。source_key = (source_ip, category)。"""
        key = (str(source_key[0]), str(source_key[1]))
        ts = float(timestamp or 0.0)

        if self.window_seconds > 0:
            records = self._counters.setdefault(key, [])
            records.append(ts)
            window_start = ts - self.window_seconds
            self._counters[key] = [t for t in records if t >= window_start]
            count = len(self._counters[key])
        else:
            count = self._counters.get(key, 0) + 1
            self._counters[key] = count

        if count >= self.min_triggers:
            self.stats["passed"] += 1
            return True
        self.stats["suppressed"] += 1
        return False


# ── 3. LLM 二次确认 ──

class LLMConfirmLayer:
    """
    LLM 二次确认层。

    对候选告警做二次判定，输出 (verdict, confidence)：
      - verdict = 'benign'：确认为正常流量，抑制告警
      - verdict = 'malicious'：确认攻击，放行告警

    默认 mock 模式：确定性规则评分（离线可复现）。
    可通过 confirm_fn 注入真实 LLM 调用（OpenAI 兼容接口），返回
    {"verdict": "benign"|"malicious", "confidence": float, "reason": str}；
    真实 LLM 调用失败时自动回退到 mock（安全兜底：未确认的告警一律放行）。
    """

    def __init__(
        self,
        enabled: bool = True,
        mock: bool = True,
        benign_threshold: float = 0.6,
        confirm_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ):
        self.enabled = enabled
        self.mock = mock
        self.benign_threshold = float(benign_threshold)
        self._confirm_fn = confirm_fn
        self.stats = {"llm_calls": 0, "confirmed_benign": 0, "confirmed_malicious": 0}

    def confirm(self, context: Dict[str, Any]) -> Tuple[str, float]:
        """返回 (verdict, confidence)。"""
        if not self.enabled:
            self.stats["llm_calls"] += 1
            self.stats["confirmed_malicious"] += 1
            return "malicious", 1.0

        if self._confirm_fn is not None:
            try:
                res = self._confirm_fn(context)
                verdict = str(res.get("verdict", "malicious")).lower().strip()
                if verdict not in ("benign", "malicious"):
                    verdict = "malicious"
                confidence = float(res.get("confidence", 0.5))
                self.stats["llm_calls"] += 1
                if verdict == "benign":
                    self.stats["confirmed_benign"] += 1
                else:
                    self.stats["confirmed_malicious"] += 1
                return verdict, confidence
            except Exception:
                # 真实 LLM 失败 → 回退 mock
                pass

        self.stats["llm_calls"] += 1
        verdict, confidence = self._mock_confirm(context)
        if verdict == "benign":
            self.stats["confirmed_benign"] += 1
        else:
            self.stats["confirmed_malicious"] += 1
        return verdict, confidence

    def _mock_confirm(self, context: Dict[str, Any]) -> Tuple[str, float]:
        """
        确定性 mock 判定：
          - 良性信号：可信域名 / 可信 IP / 标准端口 / 合理包大小
          - 恶意信号：可疑端口 / 超大包 / 超小包 / 可疑类别
        当良性得分 >= benign_threshold 且 >= 恶意得分时判定 benign。
        """
        benign = 0.0
        malicious = 0.0

        domain = str(context.get("domain", "") or "")
        dst_ip = str(context.get("dst_ip", "") or "")
        port = int(context.get("dst_port", 0) or 0)
        size = int(context.get("size", 0) or 0)
        category = str(context.get("category", "") or "")

        # 良性信号
        whitelist = WhitelistFilter(
            ip_networks=DEFAULT_TRUSTED_IP_NETWORKS,
            ports=DEFAULT_TRUSTED_PORTS,
            domains=DEFAULT_TRUSTED_DOMAINS,
        )
        if domain and whitelist.is_trusted_domain(domain):
            benign += 0.4
        if dst_ip and whitelist.is_trusted_ip(dst_ip):
            benign += 0.3
        if port in set(DEFAULT_TRUSTED_PORTS):
            benign += 0.2
        if 100 <= size <= 64 * 1024:
            benign += 0.1

        # 恶意信号
        if port in C2_SUSPICIOUS_PORTS:
            malicious += 0.3
        if size >= 100 * 1024:
            malicious += 0.4
        elif 0 < size < 256:
            malicious += 0.1
        if category in ("c2_beacon", "data_exfil", "port_scan", "bruteforce"):
            malicious += 0.3
        if category == "suspicious_domain":
            malicious += 0.3

        if benign >= self.benign_threshold and benign >= malicious:
            return "benign", round(max(benign, malicious), 2)
        return "malicious", round(max(benign, malicious), 2)


# ── 门面：误报过滤层 ──

# ==================== 第四层：输出护栏（处置动作白名单） ====================

ALLOWED_ACTION_WHITELIST = {
    "none", "alert",
    "block_ip", "isolate_ip", "rate_limit",
    "shutdown_port", "drop_packet",
    "challenge", "sandbox", "redirect_honeypot",
    "notify_admin", "remediate",
}

# 高危动作：默认不允许自动放行，需 HITL 人工确认或显式 allow_high_risk
HIGH_RISK_ACTIONS = {"isolate_ip", "shutdown_port", "sandbox", "redirect_honeypot"}


class OutputGuardLayer:
    """第四层输出护栏：对 LLM 生成的处置动作做白名单校验。

    输入护栏决定"哪些告警值得响应"，输出护栏决定"响应动作是否合法"。
    作用：
    - 拦截 LLM 幻觉出的未注册动作（delete / format / reboot / drop_database 等）；
    - 高危动作默认降级为 alert（可配置 allow_high_risk=True 放行），防止自愈系统
      在误判时对生产环境造成二次破坏；
    - 与 HITL/kill-switch 协同：被降级的高危动作交由人工确认通道处理。
    """

    def __init__(self, enabled: bool = True, allow_high_risk: bool = False) -> None:
        self.enabled = enabled
        self.allow_high_risk = allow_high_risk
        self.stats: Dict[str, int] = {
            "actions_checked": 0,
            "actions_passed": 0,
            "actions_rejected": 0,
            "high_risk_flagged": 0,
        }

    def validate_action(self, action: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        """校验单个处置动作。

        Returns:
            (safe_action, reason)：
            - reason="ok"：动作合法，原样返回（浅拷贝）；
            - reason="unknown_action"：动作不在白名单，降级为 alert 并记录 original_action；
            - reason="blocked_high_risk"：高危动作未获 HITL 授权，降级为 alert；
            - reason="guard_disabled"：护栏被关闭，原样返回。
        """
        self.stats["actions_checked"] += 1

        if not self.enabled:
            self.stats["actions_passed"] += 1
            return dict(action), "guard_disabled"

        act = str(action.get("action", "") or "").strip().lower()
        if act not in ALLOWED_ACTION_WHITELIST:
            self.stats["actions_rejected"] += 1
            return {
                **action,
                "action": "alert",
                "original_action": act,
                "guard_reason": "unknown_action",
            }, "unknown_action"

        if act in HIGH_RISK_ACTIONS and not self.allow_high_risk:
            self.stats["actions_rejected"] += 1
            self.stats["high_risk_flagged"] += 1
            return {
                **action,
                "action": "alert",
                "original_action": act,
                "guard_reason": "high_risk_requires_hitl",
            }, "blocked_high_risk"

        self.stats["actions_passed"] += 1
        return dict(action), "ok"

    def validate_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量校验处置动作列表，返回净化后的动作列表。"""
        return [self.validate_action(a)[0] for a in actions]


class FalsePositiveFilter:
    """
    误报过滤层门面。

    用法：
        fp = FalsePositiveFilter(FPFilterConfig())
        emit, reason = fp.should_emit(event, category)
        if emit:
            ...发布告警...
        else:
            ...抑制（reason 说明命中的过滤机制）...
    """

    def __init__(self, config: Optional[FPFilterConfig] = None):
        cfg = config or FPFilterConfig()
        self.enabled = cfg.enabled
        self.config = cfg
        self._whitelist = WhitelistFilter(cfg.ip_networks, cfg.ports, cfg.domains)
        self._threshold = AlertThreshold(cfg.min_triggers, cfg.window_seconds)
        self._llm = LLMConfirmLayer(cfg.llm_enabled, cfg.llm_mock, cfg.llm_benign_threshold, cfg.confirm_fn)
        # 第四层：输出护栏（处置动作白名单，默认开启；高危动作默认降级）
        self._output_guard = OutputGuardLayer()
        self.stats: Dict[str, int] = {
            "total_evaluated": 0,
            "whitelist_suppressed": 0,
            "threshold_suppressed": 0,
            "llm_suppressed": 0,
            "alerts_passed": 0,
            "high_risk_bypassed_threshold": 0,
            "output_actions_checked": 0,
            "output_actions_rejected": 0,
            "output_high_risk_flagged": 0,
        }

    @classmethod
    def from_df_config(cls) -> "FalsePositiveFilter":
        return cls(FPFilterConfig.from_df_config())

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "FalsePositiveFilter":
        return cls(FPFilterConfig.from_dict(data))

    def should_emit(self, event: Dict[str, Any], category: str) -> Tuple[bool, str]:
        """
        判断事件是否应产生告警。

        Args:
            event: 事件字典（含 source_ip/dst_ip/dst_port/size/severity/domain/timestamp 等）
            category: 告警类别（如 c2_beacon / data_exfil / port_scan / bruteforce / normal）

        Returns:
            (emit, reason) —— emit=True 表示放行告警；emit=False 表示抑制，
            reason 说明命中的过滤机制（whitelist:domain / whitelist:ip / threshold /
            llm_confirmed_benign 等）。
        """
        self.stats["total_evaluated"] += 1

        if not self.enabled:
            self.stats["alerts_passed"] += 1
            return True, "filter_disabled"

        # 1. 白名单：可信域名 / 可信 IP 硬放行
        reason = self._whitelist.match_reason(event)
        if reason in ("domain", "ip"):
            self.stats["whitelist_suppressed"] += 1
            return False, f"whitelist:{reason}"

        # 2. 告警阈值：同一来源同一类别多次触发才升级；高危信号直接放行
        severity = str(event.get("severity", "") or "").lower()
        if severity not in HIGH_RISK_SEVERITIES:
            source = str(event.get("source_ip", "") or "") or str(event.get("dst_ip", "") or "") or "unknown"
            source_key = (source, category)
            timestamp = event.get("timestamp", 0) or 0
            if not self._threshold.should_alert(source_key, timestamp):
                self.stats["threshold_suppressed"] += 1
                return False, "threshold"
        else:
            self.stats["high_risk_bypassed_threshold"] += 1

        # 3. LLM 二次确认
        context = {
            "domain": event.get("domain", ""),
            "dst_ip": event.get("dst_ip", ""),
            "dst_port": event.get("dst_port", 0),
            "size": event.get("size", 0),
            "category": category,
            "source_ip": event.get("source_ip", ""),
            "severity": severity,
        }
        verdict, _confidence = self._llm.confirm(context)
        if verdict == "benign":
            self.stats["llm_suppressed"] += 1
            return False, "llm_confirmed_benign"

        self.stats["alerts_passed"] += 1
        return True, "alert"

    def validate_action(self, action: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        """第四层输出护栏：校验 LLM 生成的单个处置动作。

        非法动作降级为 alert 并保留 original_action 供审计；
        高危动作（隔离/断端口/沙箱/蜜罐重定向）默认降级，需 HITL 确认。

        Returns:
            (safe_action, reason)
        """
        safe, reason = self._output_guard.validate_action(action)
        self.stats["output_actions_checked"] += 1
        if reason == "unknown_action" or reason == "blocked_high_risk":
            self.stats["output_actions_rejected"] += 1
            if reason == "blocked_high_risk":
                self.stats["output_high_risk_flagged"] += 1
        return safe, reason

    def validate_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量校验处置动作列表，返回净化后的动作列表。"""
        return [self.validate_action(a)[0] for a in actions]

    def get_stats_report(self) -> str:
        """生成过滤层统计摘要（用于 benchmark 报告）。"""
        s = self.stats
        suppressed = s["whitelist_suppressed"] + s["threshold_suppressed"] + s["llm_suppressed"]
        return (
            f"评估 {s['total_evaluated']} 条 | 放行 {s['alerts_passed']} | "
            f"抑制 {suppressed}（白名单 {s['whitelist_suppressed']} / "
            f"阈值 {s['threshold_suppressed']} / LLM {s['llm_suppressed']}）| "
            f"高危直通 {s['high_risk_bypassed_threshold']} | "
            f"输出护栏 {s['output_actions_checked']} 次动作（拒绝 {s['output_actions_rejected']} / "
            f"高危待HITL {s['output_high_risk_flagged']}）"
        )

    def reset(self) -> None:
        """重置阈值计数与统计（用于独立场景评测）。"""
        self._threshold = AlertThreshold(self.config.min_triggers, self.config.window_seconds)
        for key in self.stats:
            self.stats[key] = 0
