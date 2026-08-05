"""
多智能体分层分布式AI防御系统 - 配置文件
集中管理所有可调参数：检测阈值、告警分级标准、Agent超时等。

配置加载优先级（由高到低）：
  1. 环境变量（DFU_ 前缀，如 DFU_LLM__API_KEY）
  2. config.yaml（项目根目录）
  3. dataclass 默认值

兼容旧环境变量名：RABBITMQ_URL, ETCD_URL, PROMETHEUS_URL

路径解析规则：
  - config.yaml 中 project.root 为空时，自动取 DFU_PROJECT_ROOT 环境变量，
    若仍未设置则取 os.getcwd()
  - config.yaml 中相对路径（rules_dir、et_open_dir、stage4 各路径等）
    由代码内部拼接 project.root 得到绝对路径
"""

import os
from dataclasses import dataclass, field
from typing import Any, Dict

# ── dotenv 加载（可选依赖，未安装时降级为仅读系统环境变量）──
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


# ── 项目根目录探测 ──

def _detect_project_root() -> str:
    """探测项目根目录：环境变量 DFU_PROJECT_ROOT > config.py 所在目录。"""
    env_root = os.environ.get("DFU_PROJECT_ROOT", "")
    if env_root:
        return env_root
    return os.path.dirname(os.path.abspath(__file__))


def _resolve_path(project_root: str, path: str) -> str:
    """将路径解析为绝对路径。

    - 若 path 已是绝对路径，直接返回；
    - 否则以 project_root 为基准拼接后返回。
    - 若 project_root 为空，自动取 DFU_PROJECT_ROOT 环境变量或 os.getcwd()。
    """
    if os.path.isabs(path):
        return path
    root = project_root or os.environ.get("DFU_PROJECT_ROOT", "") or os.getcwd()
    return os.path.join(root, path)


_PROJECT_ROOT = _detect_project_root()


# ── YAML 加载 ──

def _load_yaml(path: str) -> Dict[str, Any]:
    """从 YAML 文件加载配置，返回空字典若失败。"""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data
    except Exception:
        return {}


def _env_override(yaml_data: Dict[str, Any]) -> Dict[str, Any]:
    """环境变量覆盖 YAML 值。

    支持的命名格式：
      - DFU_<SECTION>__<KEY>  如 DFU_LLM__API_KEY
      - DFU_PROJECT_ROOT       项目根目录
      - RABBITMQ_URL           兼容旧名 → rabbitmq.url
      - ETCD_URL               兼容旧名 → etcd.url
      - PROMETHEUS_URL         兼容旧名 → prometheus.url
    """
    data = yaml_data

    # 兼容旧环境变量名（优先级低于 DFU_ 前缀）
    legacy_map = {
        "RABBITMQ_URL": ("rabbitmq", "url"),
        "ETCD_URL": ("etcd", "url"),
        "PROMETHEUS_URL": ("prometheus", "url"),
    }
    for env_key, (section, field_name) in legacy_map.items():
        val = os.environ.get(env_key, "")
        if val:
            if section not in data:
                data[section] = {}
            data[section][field_name] = val

    # DFU_ 前缀环境变量覆盖
    for key, value in os.environ.items():
        if not key.startswith("DFU_"):
            continue
        config_key = key[4:]  # 去掉 DFU_
        if config_key == "PROJECT_ROOT":
            if "project" not in data:
                data["project"] = {}
            data["project"]["root"] = value
            continue
        # 处理 DFU_SECTION__KEY 格式
        if "__" in config_key:
            parts = config_key.lower().split("__")
            if len(parts) == 2:
                section, field = parts
                if section not in data:
                    data[section] = {}
                data[section][field] = value

    return data


# ── 构建 Config ──

def _get_cfg(data: Dict[str, Any], section: str, key: str, default: Any) -> Any:
    """从字典获取嵌套值，回退到默认值。"""
    section_data = data.get(section, {})
    if isinstance(section_data, dict):
        return section_data.get(key, default)
    return default


def build_config() -> "Config":
    """构建完整 Config 实例：.env → YAML → 环境变量覆盖 → dataclass 默认值。"""
    # 加载项目根目录 .env（未安装 python-dotenv 时跳过）
    if load_dotenv is not None:
        load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))
    yaml_path = os.path.join(_PROJECT_ROOT, "config", "default_config.yaml")
    if not os.path.exists(yaml_path):
        print(f"[config] 警告：配置文件 {yaml_path} 不存在，将使用 dataclass 默认值")
    yaml_data = _load_yaml(yaml_path)
    yaml_data = _env_override(yaml_data)

    # 项目路径：若 yaml 中 project.root 为空字符串，fallback 到 DFU_PROJECT_ROOT 或 cwd
    project_root = _get_cfg(yaml_data, "project", "root", _PROJECT_ROOT)
    if not project_root:
        project_root = os.environ.get("DFU_PROJECT_ROOT", "") or os.getcwd()
    log_dir = _get_cfg(yaml_data, "project", "log_dir", "logs")

    # 规则目录：相对路径需拼接 project_root
    rules_dir = _resolve_path(project_root, _get_cfg(yaml_data, "rules", "rules_dir", "rules"))
    et_open_dir = _resolve_path(project_root, _get_cfg(yaml_data, "rules", "et_open_dir", "rules/et_open"))

    # 误报过滤层（白名单 + 告警阈值 + LLM 二次确认；空 dict 使用 core 默认值）
    false_positive_filter = yaml_data.get("false_positive_filter", {}) or {}
    # IP 隔离配置（real_exec / max_blocks 等；空 dict 使用 actor_ip_isolation 默认值）
    isolation = yaml_data.get("isolation", {}) or {}
    # 报警鼻 4 级警报配置（空 dict 使用 AlarmNoseConfig 默认值）
    alarm_nose = yaml_data.get("alarm_nose", {}) or {}
    # 攻击路径干扰层配置（空 dict 使用 InterferenceConfig 默认值；默认关闭）
    interference = yaml_data.get("interference", {}) or {}
    # 授权环境显式开启：DFU_INTERFERENCE=on / 1 / true 覆盖 enabled
    if os.environ.get("DFU_INTERFERENCE", "").strip().lower() in ("on", "1", "true"):
        interference = {**interference, "enabled": True}
    # 数据/审计目录
    data_dir = _get_cfg(yaml_data, "project", "data_dir", "logs")

    # LLM
    llm = LLMConfig(
        api_base=_get_cfg(yaml_data, "llm", "api_base", LLMConfig.api_base),
        api_key=_get_cfg(yaml_data, "llm", "api_key", LLMConfig.api_key),
        model=_get_cfg(yaml_data, "llm", "model", LLMConfig.model),
        backup_model=_get_cfg(yaml_data, "llm", "backup_model", LLMConfig.backup_model),
        temperature=float(_get_cfg(yaml_data, "llm", "temperature", LLMConfig.temperature)),
        max_tokens=int(_get_cfg(yaml_data, "llm", "max_tokens", LLMConfig.max_tokens)),
        timeout=int(_get_cfg(yaml_data, "llm", "timeout", LLMConfig.timeout)),
        max_retries=int(_get_cfg(yaml_data, "llm", "max_retries", LLMConfig.max_retries)),
        mock_mode=bool(_get_cfg(yaml_data, "llm", "mock_mode", LLMConfig.mock_mode)),
    )
    # 启动时输出 LLM 配置状态（与 core/llm_client 的 mock 判定保持一致）
    llm_mode = "mock" if (llm.mock_mode or not llm.api_key) else "real"
    print(f"LLM 配置状态: {llm_mode}，模型: {llm.model or '(未设置)'}")

    # Stage4：相对路径需拼接 project_root
    stage4 = Stage4Config(
        model_store_dir=_resolve_path(project_root, _get_cfg(yaml_data, "stage4", "model_store_dir", "output/model_store")),
        upgrade_package_dir=_resolve_path(project_root, _get_cfg(yaml_data, "stage4", "upgrade_package_dir", "output/upgrade_packages")),
        production_output_dir=_resolve_path(project_root, _get_cfg(yaml_data, "stage4", "production_output_dir", "output")),
        audit_report_path=_resolve_path(project_root, _get_cfg(yaml_data, "stage4", "audit_report_path", "output/audit_report.json")),
        compliance_report_path=_resolve_path(project_root, _get_cfg(yaml_data, "stage4", "compliance_report_path", "output/compliance_report.json")),
        production_report_path=_resolve_path(project_root, _get_cfg(yaml_data, "stage4", "production_report_path", "output/production_report.json")),
    )

    # RabbitMQ
    rabbitmq_url = _get_cfg(yaml_data, "rabbitmq", "url", "amqp://dfu:K7mP2xW9qR5tN8bL4jH1@localhost:5672/")

    # etcd
    etcd_url = _get_cfg(yaml_data, "etcd", "url", "http://localhost:2379")

    # Prometheus
    prometheus_url = _get_cfg(yaml_data, "prometheus", "url", "http://localhost:9090")

    # Web Server
    web_host = _get_cfg(yaml_data, "web_server", "host", "0.0.0.0")
    web_port = int(_get_cfg(yaml_data, "web_server", "port", 8000))

    return Config(
        project_root=project_root,
        log_dir=log_dir,
        rules_dir=rules_dir,
        et_open_dir=et_open_dir,
        llm=llm,
        stage4=stage4,
        false_positive_filter=false_positive_filter,
        isolation=isolation,
        alarm_nose=AlarmNoseConfig(
            l2_window_secs=float(alarm_nose.get("l2_window_secs", AlarmNoseConfig.l2_window_secs)),
            l2_high_count=int(alarm_nose.get("l2_high_count", AlarmNoseConfig.l2_high_count)),
            l2_countdown_secs=float(alarm_nose.get("l2_countdown_secs", AlarmNoseConfig.l2_countdown_secs)),
            l3_countdown_secs=float(alarm_nose.get("l3_countdown_secs", AlarmNoseConfig.l3_countdown_secs)),
            l4_execute_countdown_secs=float(alarm_nose.get("l4_execute_countdown_secs", AlarmNoseConfig.l4_execute_countdown_secs)),
            l1_decay_secs=float(alarm_nose.get("l1_decay_secs", AlarmNoseConfig.l1_decay_secs)),
            organ_failure_l3_ratio=float(alarm_nose.get("organ_failure_l3_ratio", AlarmNoseConfig.organ_failure_l3_ratio)),
            organ_failure_l4_ratio=float(alarm_nose.get("organ_failure_l4_ratio", AlarmNoseConfig.organ_failure_l4_ratio)),
        ),
        interference=InterferenceConfig(
            enabled=bool(interference.get("enabled", InterferenceConfig.enabled)),
            authorized_only=bool(interference.get("authorized_only", InterferenceConfig.authorized_only)),
            blindfold_enabled=bool(interference.get("blindfold_enabled", InterferenceConfig.blindfold_enabled)),
            puppeteer_enabled=bool(interference.get("puppeteer_enabled", InterferenceConfig.puppeteer_enabled)),
            min_severity=str(interference.get("min_severity", InterferenceConfig.min_severity)),
            trigger_categories=tuple(interference.get("trigger_categories", InterferenceConfig.trigger_categories)),
            audit_capacity=int(interference.get("audit_capacity", InterferenceConfig.audit_capacity)),
        ),
        data_dir=data_dir,
        _rabbitmq_url=rabbitmq_url,
        _etcd_url=etcd_url,
        _prometheus_url=prometheus_url,
        _web_host=web_host,
        _web_port=web_port,
    )


# =============================================================================
# 配置数据类（默认值仅供无 config.yaml / 无环境变量时兜底）
# =============================================================================


@dataclass
class TrafficThresholds:
    """流量检测阈值配置"""
    # 高频同IP请求：同一IP在时间窗口内请求次数超过此值视为异常（次/窗口）
    high_freq_request_count: int = 100
    # 高频检测时间窗口（秒）
    high_freq_time_window: float = 5.0

    # 端口扫描：同一IP在时间窗口内访问不同端口数超过此值视为扫描（个/窗口）
    port_scan_port_count: int = 20
    port_scan_time_window: float = 10.0

    # 暴力破解：认证尝试次数超过此值视为攻击（次/窗口）
    brute_force_attempts_threshold: int = 50
    brute_force_time_window: float = 10.0


@dataclass
class AlertLevelConfig:
    """告警分级标准配置"""
    # DDoS 告警分级阈值
    ddos_severe_threshold: int = 500       # 单窗口请求数 >= 此值 → 严重
    ddos_high_threshold: int = 200         # 单窗口请求数 >= 此值 → 高
    ddos_medium_threshold: int = 100       # 单窗口请求数 >= 此值 → 中（低于则为低）

    # 端口扫描告警分级阈值
    scan_severe_threshold: int = 100       # 不同端口数 >= 此值 → 严重
    scan_high_threshold: int = 50          # 不同端口数 >= 此值 → 高
    scan_medium_threshold: int = 20        # 不同端口数 >= 此值 → 中

    # 大流量脉冲告警分级阈值
    burst_severe_threshold: int = 100 * 1024 * 1024   # 100MB → 严重
    burst_high_threshold: int = 50 * 1024 * 1024      # 50MB → 高
    burst_medium_threshold: int = 10 * 1024 * 1024    # 10MB → 中


@dataclass
class AgentConfig:
    """Agent 配置"""
    # 消息总线轮询间隔（秒）
    message_bus_poll_interval: float = 0.1
    # Agent 处理超时（秒）
    agent_timeout: float = 30.0
    # 分析引擎日志存证路径（容器内用 /app/logs，本地用项目路径）
    left_brain_log_path: str = "logs/left_brain_log.jsonl"
    # 校验Agent冲突检查级别阈值：>=此值强制检查
    validator_conflict_check_threshold: str = "high"  # low / medium / high / severe


@dataclass
class SimulatorConfig:
    """模拟攻击配置"""
    # DDoS 模拟：攻击源IP数量
    ddos_source_ip_count: int = 3
    # DDoS 模拟：每个源IP每秒请求数
    ddos_requests_per_second: int = 150
    # 端口扫描模拟：扫描端口范围
    port_scan_range: tuple = (1, 65535)
    # 端口扫描模拟：扫描速度（端口/秒）
    port_scan_speed: int = 50
    # 暴力破解模拟：尝试次数
    brute_force_attempts: int = 200
    # 暴力破解模拟：目标服务端口
    brute_force_target_port: int = 22
    # 漏洞报告模拟：每次生成数量
    vuln_report_count: int = 3
    # 异常日志模拟：每次生成数量
    log_anomaly_count: int = 4


@dataclass
class MedicConfig:
    """医疗Agent自愈系统配置"""
    # 心跳检测间隔（秒）
    heartbeat_interval: float = 2.0
    # Agent 心跳超时阈值（秒），超时未响应标记故障
    heartbeat_timeout: float = 6.0
    # 熔断阈值：故障Agent数量/总注册Agent数比例 >= 此值触发熔断
    circuit_breaker_ratio: float = 0.5
    # 恢复检测间隔（秒）
    recovery_check_interval: float = 3.0
    # 最大熔断持续时间（秒），超时强制解除
    max_circuit_breaker_duration: float = 60.0
    # 故障恢复需要连续心跳成功次数
    recovery_confirm_count: int = 3


@dataclass
class Stage2Config:
    """阶段2：新增器官配置"""
    # 漏洞扫描：CVSS评分阈值（>=此值告警）
    vuln_cvss_threshold: float = 5.0
    # 日志审计：异常登录失败阈值（次/窗口）
    audit_login_fail_threshold: int = 5
    # 资源调度：默认算力配额
    default_compute_quota: int = 100
    # 取证追踪：最大跳板链深度
    max_trace_depth: int = 5


@dataclass
class Stage3Config:
    """阶段3：集群化与冷热知识库配置"""
    # 热库最大容量
    hot_store_max_capacity: int = 500
    # 冷库查询延迟范围（毫秒）
    cold_query_latency_min_ms: float = 5.0
    cold_query_latency_max_ms: float = 15.0
    # 同步延迟范围（毫秒）
    sync_latency_min_ms: float = 5.0
    sync_latency_max_ms: float = 30.0
    # 同步过滤：仅此级别及以上才同步
    sync_severity_threshold: str = "high"  # low / medium / high / severe
    # 集群心跳超时（秒）
    cluster_heartbeat_timeout: float = 10.0
    # 集群单元数量
    default_unit_count: int = 3
    # 冷库升温命中阈值
    promotion_hit_threshold: int = 3


@dataclass
class EventAggregatorConfig:
    """事件聚合器配置"""
    # 聚合窗口时长（毫秒）
    window_ms: int = 2000
    # 聚合后保留原始详情条数（条）
    max_indicators_detail: int = 20
    # 最大等待时间（毫秒），防无限等待
    idle_timeout_ms: int = 5000
    # 最大并发窗口数
    max_concurrent_windows: int = 100


@dataclass
class RealtimeConfig:
    """真实流量接入配置"""
    # pcap 分块读取的包数量
    pcap_chunk_size: int = 10000
    # 在线监听端口
    listen_port: int = 9999
    # 监听地址
    listen_host: str = "0.0.0.0"
    # 高频请求阈值（次/秒）
    high_freq_threshold: int = 100
    # 端口扫描阈值（不同端口数）
    port_scan_threshold: int = 10
    # 大流量阈值 MB/s
    large_flow_threshold_mbps: float = 10.0
    # SYN Flood 阈值（SYN包/秒）
    syn_flood_threshold: int = 500
    # 检测时间窗口（秒）
    time_window_seconds: int = 1


@dataclass
class Stage4Config:
    """阶段4：灰度升级与生产就绪配置"""
    # 灰度推送：金丝雀批次比例
    canary_ratio: float = 0.10
    # 灰度推送：增量批次比例
    incremental_ratio: float = 0.30
    # 金丝雀观察轮次（心跳周期）
    canary_observe_rounds: int = 3
    # 增量观察轮次（心跳周期）
    incremental_observe_rounds: int = 2
    # 模型权重存储目录
    model_store_dir: str = "output/model_store"
    # 升级包存储目录
    upgrade_package_dir: str = "output/upgrade_packages"
    # 生产输出目录
    production_output_dir: str = "output"
    # 压力测试 QPS 级别列表
    stress_test_qps_levels: tuple = (10, 50, 100, 200, 500, 1000)
    # 压力测试每级持续时间（秒）
    stress_test_duration_per_level: float = 3.0
    # 性能监控阈值
    perf_cpu_threshold_pct: float = 80.0
    perf_memory_threshold_pct: float = 85.0
    perf_latency_threshold_ms: float = 500.0
    perf_fp_rate_threshold: float = 0.10
    perf_fn_rate_threshold: float = 0.05
    perf_success_rate_threshold: float = 0.95
    # 审计报告路径
    audit_report_path: str = "output/audit_report.json"
    # 合规检查报告路径
    compliance_report_path: str = "output/compliance_report.json"
    # 生产就绪报告路径
    production_report_path: str = "output/production_report.json"
    # 干跑模式（跳过实际文件写入）
    dry_run: bool = False


@dataclass
class InterferenceConfig:
    """攻击路径干扰层配置（融合增强 v1.1 第三阶段，默认关闭）。

    对外口径：攻击路径干扰与安全验证（降低攻击成功率、增加攻击成本），
    不表述为"控制/反制攻击者"。默认关闭，仅授权环境可通过
    `DFU_INTERFERENCE=on` 环境变量或 config 开启；kill-switch 开启时强制停用。
    """

    # 干扰层总开关：默认关闭（安全默认）。仅授权环境显式开启。
    enabled: bool = False
    # 仅授权环境：True 时要求 payload 携带 authorized 标志或环境变量确认
    authorized_only: bool = True
    # 终端输出污染（BLINDFOLD 思路）：对攻击者会话返回混淆/误导响应
    blindfold_enabled: bool = True
    # API 拦截改写（PUPPETEER 思路）：对攻击者请求返回诱饵响应
    puppeteer_enabled: bool = True
    # 最小触发严重级别（low/medium/high/severe），低于该级别不干扰
    min_severity: str = "high"
    # 触发干扰的威胁类别白名单
    trigger_categories: tuple = ("exploit", "brute_force", "command_injection", "port_scan", "vuln", "c2_beacon")
    # 审计日志容量上限
    audit_capacity: int = 1000


@dataclass
class LLMConfig:
    """LLM 调用配置"""
    # 火山引擎 API 地址（OpenAI 兼容格式）
    api_base: str = "https://ark.cn-beijing.volces.com/api/v3"
    # 火山引擎 API Key
    api_key: str = ""
    # 主模型：DeepSeek 3.2 推理端点 ID
    model: str = ""
    # 备用模型：豆包1.8多模态端点 ID
    backup_model: str = ""
    # 推理温度（0-2），越低越确定
    temperature: float = 0.3
    # 最大输出 token 数（真实推理需要更多 token）
    max_tokens: int = 2000
    # 超时秒数（火山引擎可能有稍高延迟）
    timeout: int = 60
    # 最大重试次数
    max_retries: int = 2
    # mock 模式开关（False 走真实 API）
    mock_mode: bool = False


@dataclass
class OutboundMonitorConfig:
    """出站流量监测配置"""
    # 信标检测：心跳间隔偏差容忍度（倍）
    beacon_interval_tolerance: float = 1.5
    # 信标检测：最小采样次数
    beacon_min_samples: int = 3
    # 外泄检测：单次外泄流量阈值（字节）
    exfil_single_threshold_bytes: int = 100 * 1024  # 100KB
    # 外泄检测：窗口内累计外泄阈值（字节）
    exfil_window_threshold_bytes: int = 1024 * 1024  # 1MB
    # 外泄检测：时间窗口（秒）
    exfil_window_seconds: float = 60.0
    # 未知域名检测：域名可疑度评分阈值（0-1）
    domain_suspicious_threshold: float = 0.6
    # 检测采样间隔（秒）
    check_interval: float = 10.0


@dataclass
class AlarmNoseConfig:
    """报警鼻（4级自动警报闭环）配置"""
    # L2 判定窗口：窗口内告警数量 >= l2_high_count 触发 L2 警报（秒）
    l2_window_secs: float = 30.0
    # L2 触发阈值：窗口内高威胁告警数量
    l2_high_count: int = 3
    # L2 人工确认倒计时：超时未确认自动升级 L3（秒）
    l2_countdown_secs: float = 60.0
    # L3 人工确认倒计时：超时未确认自动升级 L4（秒）
    l3_countdown_secs: float = 120.0
    # L4 执行倒计时：L4 警报发出后强制执行软隔离的等待时长（秒）
    l4_execute_countdown_secs: float = 30.0
    # L1 自然衰减：无新告警超过该时长，L1 等级自动回归正常（秒）
    l1_decay_secs: float = 300.0
    # 器官健康恶化比例阈值：异常器官占比 >= 此值升 L3
    organ_failure_l3_ratio: float = 0.3
    # 器官健康恶化比例阈值：异常器官占比 >= 此值升 L4
    organ_failure_l4_ratio: float = 0.6


@dataclass
class EvolverConfig:
    """知识库自进化配置"""
    min_pattern_hits: int = 5
    pattern_window_seconds: int = 300
    max_hot_patterns: int = 50
    hot_ttl_seconds: int = 3600


@dataclass
class MonsterAgentConfig:
    """小怪兽全局 Agent 配置（v2）"""
    # 态势缓存 TTL（秒）
    posture_ttl_sec: float = 5.0
    # ReAct 最大迭代轮数
    max_iterations: int = 8
    # 对话历史保留条数（双向，含 user/assistant）
    history_max: int = 40
    # 系统提示词中的态势摘要截断长度
    posture_summary_max_chars: int = 4000


@dataclass
class SkillToolboxConfig:
    """技能工具箱配置（v2）"""
    # 技能目录（相对项目根）
    skills_dir: str = "organs/skills"
    # 每技能限频（次/分钟，0=不限）
    ratelimit_per_min: int = 5
    # 高危确认令牌有效期（秒）
    confirm_token_ttl_sec: float = 60.0
    # 审计日志容量上限
    call_log_max: int = 500


@dataclass
class Config:
    """总配置"""
    thresholds: TrafficThresholds = field(default_factory=TrafficThresholds)
    alert_levels: AlertLevelConfig = field(default_factory=AlertLevelConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    simulator: SimulatorConfig = field(default_factory=SimulatorConfig)
    medic: MedicConfig = field(default_factory=MedicConfig)
    stage2: Stage2Config = field(default_factory=Stage2Config)
    stage3: Stage3Config = field(default_factory=Stage3Config)
    stage4: Stage4Config = field(default_factory=Stage4Config)
    realtime: RealtimeConfig = field(default_factory=RealtimeConfig)
    event_aggregator: EventAggregatorConfig = field(default_factory=EventAggregatorConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    outbound_monitor: OutboundMonitorConfig = field(default_factory=OutboundMonitorConfig)
    alarm_nose: AlarmNoseConfig = field(default_factory=AlarmNoseConfig)
    evolver: EvolverConfig = field(default_factory=EvolverConfig)
    # 攻击路径干扰层（v1.1 第三阶段；默认关闭，仅授权环境开启）
    interference: InterferenceConfig = field(default_factory=InterferenceConfig)
    # 小怪兽全局 Agent（v2）
    monster: MonsterAgentConfig = field(default_factory=MonsterAgentConfig)
    # 技能工具箱（v2）
    skill_toolbox: SkillToolboxConfig = field(default_factory=SkillToolboxConfig)

    # 项目根目录（容器内默认 /app，本地可通过环境变量 DFU_PROJECT_ROOT 覆盖）
    project_root: str = ""
    # 日志目录
    log_dir: str = "logs"
    # 规则引擎目录（由代码根据 project_root 解析为绝对路径）
    rules_dir: str = ""
    et_open_dir: str = ""

    # 误报过滤层配置（白名单/阈值/LLM 二次确认；空 dict 使用 core 默认值）
    false_positive_filter: Dict[str, Any] = field(default_factory=dict)
    # IP 隔离配置（real_exec / max_blocks / block_cooldown_sec / protected_ips；空 dict 使用 actor_ip_isolation 默认值）
    isolation: Dict[str, Any] = field(default_factory=dict)
    # 数据/审计目录
    data_dir: str = "logs"

    # ── 新增外部服务配置（不参与 dataclass __init__ 类型推断的"普通字段"）──
    _rabbitmq_url: str = "amqp://dfu:K7mP2xW9qR5tN8bL4jH1@localhost:5672/"
    _etcd_url: str = "http://localhost:2379"
    _prometheus_url: str = "http://localhost:9090"
    _web_host: str = "0.0.0.0"
    _web_port: int = 8000

    @property
    def rabbitmq_url(self) -> str:
        """RabbitMQ 连接 URL。"""
        return self._rabbitmq_url

    @property
    def etcd_url(self) -> str:
        """etcd 连接 URL。"""
        return self._etcd_url

    @property
    def prometheus_url(self) -> str:
        """Prometheus 连接 URL。"""
        return self._prometheus_url

    @property
    def web_host(self) -> str:
        """Web 管理后端监听地址。"""
        return self._web_host

    @property
    def web_port(self) -> int:
        """Web 管理后端监听端口。"""
        return self._web_port


# ── 便捷单例 ──

_config_instance: Config = None


def get_config() -> Config:
    """获取全局配置单例（YAML + 环境变量自动加载）。"""
    global _config_instance
    if _config_instance is None:
        _config_instance = build_config()
    return _config_instance


def reset_config() -> Config:
    """重置全局配置单例（用于测试）。"""
    global _config_instance
    _config_instance = build_config()
    return _config_instance
