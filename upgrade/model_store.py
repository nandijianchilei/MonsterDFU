"""
模型权重存储 - 模拟模型权重版本管理。

每个组件的权重以 JSON 文件持久化，支持多版本切换。
组件列表: left_brain / right_brain / observer_traffic / actor_ip_isolation /
          scanner_vuln / auditor_log / scheduler_resource / tracker_forensic
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


class ModelWeightStore:
    """模型权重多版本存储管理器。"""

    # 支持的组件列表
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

    def __init__(self, store_dir: str, dry_run: bool = False):
        """
        Args:
            store_dir: 权重存储根目录
            dry_run: 干跑模式，跳过实际文件写入
        """
        self.store_dir = store_dir
        self.dry_run = dry_run
        self._loaded_versions: Dict[str, str] = {}  # component → current_version

        if not dry_run:
            os.makedirs(store_dir, exist_ok=True)

    def _component_dir(self, component: str) -> str:
        return os.path.join(self.store_dir, component)

    def _version_path(self, component: str, version: str) -> str:
        return os.path.join(self._component_dir(component), f"{version}.json")

    def _index_path(self, component: str) -> str:
        return os.path.join(self._component_dir(component), "_index.json")

    def _generate_weights(self, component: str, version: str, seed: int = 0) -> Dict[str, Any]:
        """生成模拟模型权重。不同种子产生不同权重值。"""
        base_weights = {
            "left_brain": {
                "severity_weights": {"low": 0.3, "medium": 0.5, "high": 0.7, "severe": 0.9},
                "compute_bias": 0.5 + seed * 0.01,
                "decision_threshold": 0.6 + seed * 0.005,
            },
            "right_brain": {
                "confidence_weights": {"ddos": 0.85, "port_scan": 0.80, "brute_force": 0.75, "zero_day": 0.65},
                "analysis_depth": min(3 + seed, 10),
                "match_threshold": 0.70 + seed * 0.01,
            },
            "observer_traffic": {
                "window_size": 5.0 + seed * 0.1,
                "detection_sensitivity": 0.75 + seed * 0.02,
                "threshold_multiplier": 1.0 + seed * 0.05,
            },
            "actor_ip_isolation": {
                "block_duration": 3600 + seed * 600,
                "cooldown_period": 1800 + seed * 300,
                "max_blacklist_size": 1000 + seed * 100,
            },
            "scanner_vuln": {
                "cvss_threshold": 5.0 + seed * 0.5,
                "scan_depth": min(3 + seed // 2, 8),
                "confidence_weight": 0.60 + seed * 0.03,
            },
            "auditor_log": {
                "login_fail_threshold": 5 + seed,
                "audit_window": 60.0 + seed * 5.0,
                "anomaly_sensitivity": 0.70 + seed * 0.03,
            },
            "scheduler_resource": {
                "cpu_quota": 100 + seed * 20,
                "memory_quota_gb": 16 + seed * 4,
                "priority_weights": {"critical": 10, "high": 6, "medium": 3, "low": 1},
            },
            "tracker_forensic": {
                "max_trace_depth": 5 + seed,
                "confidence_decay": 0.85 - seed * 0.01,
                "timeout_per_hop": 2.0 - seed * 0.05,
            },
        }

        weights = base_weights.get(component, {"default": True, "seed": seed})
        # 用种子微调数值
        if isinstance(weights, dict) and seed > 0:
            import copy
            weights = copy.deepcopy(weights)
            for k in list(weights.keys()):
                if isinstance(weights[k], (int, float)):
                    # 在 ±5% 范围内微调
                    delta = (seed * 0.03 - 0.03)
                    if isinstance(weights[k], int):
                        weights[k] = max(1, int(weights[k] * (1 + delta)))
                    else:
                        weights[k] = round(weights[k] * (1 + delta), 4)
        return weights

    def save_version(self, component: str, version: str, weights: Optional[Dict] = None) -> str:
        """
        保存一个新版本的模型权重。

        Args:
            component: 组件名称
            version: 语义化版本号 (semver)
            weights: 权重字典，None 则自动生成

        Returns:
            保存的版本号
        """
        if component not in self.SUPPORTED_COMPONENTS:
            raise ValueError(f"不支持的组件: {component}，支持: {self.SUPPORTED_COMPONENTS}")

        if weights is None:
            seed = int(version.replace(".", "").ljust(3, "0")[:3]) if version.replace(".", "").isdigit() else 1
            weights = self._generate_weights(component, version, seed)

        # 添加版本元信息
        record = {
            "component": component,
            "version": version,
            "created_at": datetime.now().isoformat(),
            "weights": weights,
        }

        if not self.dry_run:
            comp_dir = self._component_dir(component)
            os.makedirs(comp_dir, exist_ok=True)

            # 写入权重文件
            vpath = self._version_path(component, version)
            with open(vpath, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2, ensure_ascii=False)

            # 更新索引
            self._update_index(component, version)

        self._loaded_versions[component] = version
        return version

    def load_version(self, component: str, version: str) -> Optional[Dict[str, Any]]:
        """
        加载指定版本的模型权重。

        Returns:
            完整记录字典，或 None（版本不存在）
        """
        if component not in self.SUPPORTED_COMPONENTS:
            return None

        vpath = self._version_path(component, version)
        if not os.path.exists(vpath):
            # 版本不存在时自动生成
            seed = int(version.replace(".", "").ljust(3, "0")[:3]) if version.replace(".", "").isdigit() else 0
            weights = self._generate_weights(component, version, seed)
            return {
                "component": component,
                "version": version,
                "created_at": datetime.now().isoformat(),
                "weights": weights,
            }

        with open(vpath, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_versions(self, component: str) -> List[str]:
        """列出某组件的所有版本号。"""
        if not self.dry_run:
            idx = self._index_path(component)
            if os.path.exists(idx):
                with open(idx, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data.get("versions", [])
        return list(self._loaded_versions.values())

    def get_current_version(self, component: str) -> Optional[str]:
        """获取组件当前激活的版本。"""
        return self._loaded_versions.get(component)

    def _update_index(self, component: str, version: str) -> None:
        """更新组件版本索引。"""
        idx_path = self._index_path(component)
        index = {"component": component, "versions": [], "updated_at": ""}

        if os.path.exists(idx_path):
            with open(idx_path, "r", encoding="utf-8") as f:
                index = json.load(f)

        versions = index.get("versions", [])
        if version not in versions:
            versions.append(version)
        index["versions"] = sorted(versions)
        index["updated_at"] = datetime.now().isoformat()

        with open(idx_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, ensure_ascii=False)

    def get_all_versions(self) -> Dict[str, List[str]]:
        """获取所有组件的版本列表。"""
        result = {}
        for comp in self.SUPPORTED_COMPONENTS:
            result[comp] = self.list_versions(comp)
        return result

    def seed_initial_versions(self) -> Dict[str, str]:
        """
        为所有支持的组件生成初始版本 1.0.0。
        供干跑模式使用。

        Returns:
            组件名 → 版本号映射
        """
        versions = {}
        for comp in self.SUPPORTED_COMPONENTS:
            v = self.save_version(comp, "1.0.0")
            versions[comp] = v
        return versions
