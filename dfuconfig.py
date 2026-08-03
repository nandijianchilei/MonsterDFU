"""
DFU 配置加载模块 (dfuconfig)
============================
提供 `config` 单例：加载 config/default_config.yaml 为 ConfigDict（支持点号/字典访问），
并支持环境变量覆盖，规则：
  - DFU_<SECTION>_<KEY>      单下划线：首段为 section，其余为 key（如 DFU_SERVER_PORT=8080）
  - DFU_<SECTION>__<KEY>     双下划线：显式层级分隔（如 DFU_DETECTION__OUTBOUND_MONITOR__POLL_INTERVAL_MS）
环境变量值自动做类型推断：true/false -> bool，数字串 -> int/float，其余保留字符串。

使用方式：
    from dfuconfig import config
    config.get("server", "port")            # -> 8000
    config.get("llm", "mock_mode")          # -> True
    config.get("detection.outbound_monitor.poll_interval_ms")  # 点路径
    config.get("nonexistent.path", default="fallback")          # -> "fallback"
    config.server.port                      # 点号属性访问
    config["server"]["port"]                # 字典访问
    config.reload()                         # 重新加载 YAML + 环境变量
"""

import os
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - 无 PyYAML 时回退内置默认配置
    yaml = None

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "default_config.yaml"

# 内置兜底配置：YAML 缺失/损坏时保证基础功能可用（与 default_config.yaml 对齐）
_FALLBACK_CONFIG = {
    "server": {"host": "0.0.0.0", "port": 8000, "workers": 4, "ssl_cert": "", "ssl_key": ""},
    "auth": {"enabled": True, "api_token": "dfu-default-token-change-me"},
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "file": "logs/dfu.log",
        "max_size_mb": 100,
        "backup_count": 5,
        "json_output": False,
    },
    "detection": {
        "outbound_monitor": {
            "enabled": True,
            "poll_interval_ms": 2000,
            "beacon": {"min_connections": 3, "min_interval_sec": 1.0},
            "exfiltration": {"threshold_bytes": 10485760},
            "domain": {"blocklist": []},
        }
    },
    "countermeasure": {
        "fsm": {
            "default_policy": "monitor",
            "auto_escalate": True,
            "levels": {"L0": "monitor", "L1": "soft_block", "L2": "hard_block", "L3": "offensive", "L4": "isolate"},
            "l4": {"vuln_threshold": 5, "web_confirm_timeout_sec": 600, "l3_persist_threshold_sec": 180},
            "offensive": {"enabled": True},
        }
    },
    "llm": {
        "provider": "volcano",
        "api_key": "",
        "model": "deepseek-v3-241226",
        "temperature": 0.1,
        "max_tokens": 1024,
        "timeout_sec": 30,
        "mock_mode": True,
    },
    "storage": {"persistent": {"enabled": True, "db_path": "data/dfu.db"}, "memory": {"max_events": 5000}},
    "management": {"allow_origins": ["*"], "rate_limit_per_min": 60},
}


def _wrap(value):
    """递归将 dict 包装为 ConfigDict，list 元素同样递归处理。"""
    if isinstance(value, dict):
        return ConfigDict(value)
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    return value


class ConfigDict(dict):
    """支持点号/字典访问与分层 get 的配置字典。

    访问方式：
      - cfg["section"]["key"]          字典访问
      - cfg["section.key"]             点路径字典访问
      - cfg.section.key                属性访问（缺失抛 AttributeError）
      - cfg.get("section", "key")      分层 get（第二参为子键）
      - cfg.get("section.key")         点路径 get
      - cfg.get("key", default)        普通 dict.get 语义（叶子值 + 默认值）
    """

    def __init__(self, data=None):
        super().__init__()
        if data:
            for k, v in data.items():
                dict.__setitem__(self, k, _wrap(v))

    def __getitem__(self, key):
        if isinstance(key, str) and "." in key:
            node = dict.__getitem__(self, key.split(".")[0])
            for part in key.split(".")[1:]:
                node = node[part]
            return node
        return dict.__getitem__(self, key)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return dict.__getitem__(self, name)
        except KeyError:
            raise AttributeError(f"config has no key: {name!r}") from None

    def get(self, path, key=None, default=None):
        """分层取值。

        两种调用形态：
          - get("section", "key", default=None)：section 可为点路径，key 为段内子键；
          - get("section.key", default=None)：完整点路径；当 path 解析到叶子值时，
            第二个位置参数按 dict.get(key, default) 语义作为默认值。
        """
        node = self
        for part in str(path).split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        if key is not None:
            if isinstance(node, dict):
                # path 解析到的是配置段 → key 为段内子键
                if key in node:
                    return node[key]
                return default if default is not None else None
            # path 解析到叶子值 → key 参数实为默认值（兼容 dict.get(key, default)）
            return node
        return node

    def to_dict(self):
        """递归转为普通 dict（供 from_df_config 等消费方使用）。"""
        return {k: (v.to_dict() if isinstance(v, ConfigDict) else v) for k, v in self.items()}

    def reload(self):
        """重新加载配置（YAML + 环境变量）。"""
        reload()


def _coerce_env_value(raw: str):
    """环境变量值类型推断：bool / int / float / str。"""
    s = str(raw).strip()
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _collect_env_overrides():
    """收集 DFU_ 前缀环境变量，返回 {层级元组: 原始值}。"""
    overrides = {}
    for name, value in os.environ.items():
        if not name.startswith("DFU_"):
            continue
        raw = name[len("DFU_"):]
        if "__" in raw:
            parts = tuple(p.lower() for p in raw.split("__"))
        else:
            # 兼容单下划线：首段为 section，其余为 key
            pieces = raw.split("_")
            parts = (pieces[0].lower(), "_".join(pieces[1:]).lower())
        overrides[parts] = value
    return overrides


def _apply_env_overrides(data):
    """将环境变量覆盖写入 data（普通 dict）。缺失层级直接跳过。"""
    for parts, raw_value in _collect_env_overrides().items():
        node = data
        ok = True
        for part in parts[:-1]:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                ok = False
                break
        if ok and isinstance(node, dict) and parts[-1] in node:
            node[parts[-1]] = _coerce_env_value(raw_value)


def _load_yaml_config():
    """加载 YAML 配置；文件缺失/损坏/不可解析时回退内置默认配置。"""
    if yaml is None or not _DEFAULT_CONFIG_PATH.exists():
        return dict(_FALLBACK_CONFIG)
    try:
        with open(_DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
        if isinstance(loaded, dict):
            return loaded
        return dict(_FALLBACK_CONFIG)
    except Exception:
        return dict(_FALLBACK_CONFIG)


def reload():
    """重新加载配置：读取 YAML 并应用环境变量覆盖。"""
    data = _load_yaml_config()
    _apply_env_overrides(data)
    config.clear()
    for k, v in data.items():
        dict.__setitem__(config, k, _wrap(v))


# 全局单例：模块导入时立即初始化
config = ConfigDict()
reload()
