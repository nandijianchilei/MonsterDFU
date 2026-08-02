"""
混合攻击数据集 (AttackDataset)

提供可重复使用的预设攻击测试序列，用于基准评测和回归测试。
每个场景包含 15-30 条告警事件，附描述和期望检测结果。

依赖：仅标准库 + time
"""

import random
import time as time_module
from typing import Any, Dict, List, Optional


class AttackDataset:
    """
    混合攻击测试数据集。

    提供标准化的攻击场景序列，支持以下用途：
    - 检测算法基准评测（benchmark）
    - 回归测试（regression test）
    - 演示模式数据源（demo）

    使用方式：
        ds = AttackDataset()
        scenario = ds.get_scenario("c2_beacon")
        for event in scenario["events"]:
            print(event)
    """

    SCENARIOS: Dict[str, Dict[str, Any]] = {
        "c2_beacon": {
            "description": (
                "C2 信标回连 — 6 次等间隔小包回连到可疑端口（4444/8443/31337），"
                "模拟远控木马心跳。间隔 3-5s，包大小 64-256 字节。"
            ),
            "expected_detection": {
                "alerts": ["beacon"],
                "min_alert_count": 1,
                "severity": "high",
                "note": "间隔规律的小包回连应被信标检测命中",
            },
        },
        "data_exfil": {
            "description": (
                "数据外泄 — 2 次单包大流量（12MB、18MB）+ 8 次窗口累计外泄"
                "（6MB/3MB 交替），模拟敏感数据窃取。"
            ),
            "expected_detection": {
                "alerts": ["exfiltration"],
                "min_alert_count": 2,
                "severity": "severe",
                "note": "单包超大 + 窗口累计均需触发外泄告警",
            },
        },
        "port_scan": {
            "description": (
                "端口扫描 — 同一源 IP（10.0.1.100）在 2 秒内探测 20 个不同端口"
                "（22/23/25/53/80/.../8080），模拟横向移动侦察。"
            ),
            "expected_detection": {
                "alerts": ["port_scan"],
                "min_alert_count": 1,
                "severity": "medium",
                "note": "短时间内大量不同端口访问应被扫描检测命中",
            },
        },
        "bruteforce": {
            "description": (
                "暴力破解 — 15 次快速 SSH 登录失败（10.0.1.200 → 192.168.1.10:22），"
                "间隔 0.5-2s，模拟口令爆破。"
            ),
            "expected_detection": {
                "alerts": ["bruteforce"],
                "min_alert_count": 1,
                "severity": "high",
                "note": "短时间内密集认证失败应被暴力破解检测命中",
            },
        },
        "mixed_attack": {
            "description": (
                "混合攻击 — C2 信标 + 数据外泄 + 端口扫描 + 暴力破解乱序混合，"
                "模拟 APT 攻击链，时间跨度约 120 秒。"
            ),
            "expected_detection": {
                "alerts": ["beacon", "exfiltration", "port_scan", "bruteforce"],
                "min_alert_count": 4,
                "severity": "severe",
                "note": "四种攻击类型应全部被检测到",
            },
        },
        "clean_traffic": {
            "description": (
                "正常流量 — 10 条 HTTPS/API 调用（github/cdn/google/...），"
                "用于测试误报率。不应产生任何告警。"
            ),
            "expected_detection": {
                "alerts": [],
                "min_alert_count": 0,
                "severity": "none",
                "note": "正常域名 + 标准端口 + 合理包大小 → 零告警",
            },
        },
    }

    RNG = random.Random(42)  # 固定种子保证可复现

    def get_scenario(self, name: str) -> Dict[str, Any]:
        """
        获取指定场景的攻击事件列表。

        Args:
            name: 场景名称，可选值：
                  c2_beacon, data_exfil, port_scan, bruteforce,
                  mixed_attack, clean_traffic

        Returns:
            {
                "name": str,
                "description": str,
                "expected_detection": dict,
                "events": List[Dict],  # 每条事件含 type/severity/source_ip/...
            }

        Raises:
            ValueError: 场景名称不存在
        """
        if name not in self.SCENARIOS:
            valid = ", ".join(sorted(self.SCENARIOS.keys()))
            raise ValueError(f"未知场景: '{name}'，有效值: {valid}")

        builder_name = f"_build_{name}"
        builder = getattr(self, builder_name, None)
        if builder is None:
            raise ValueError(f"场景 '{name}' 的构建方法 {builder_name} 未实现")

        events = builder()
        return {
            "name": name,
            "description": self.SCENARIOS[name]["description"],
            "expected_detection": dict(self.SCENARIOS[name]["expected_detection"]),
            "events": events,
        }

    def list_scenarios(self) -> List[Dict[str, Any]]:
        """列出所有可用场景的元数据（不构建事件）。"""
        return [
            {
                "name": name,
                "description": meta["description"],
                "expected_detection": dict(meta["expected_detection"]),
            }
            for name, meta in self.SCENARIOS.items()
        ]

    def get_all_events(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        获取全部场景的事件列表（用于全量 benchmark）。

        Returns:
            {scenario_name: [events]}
        """
        return {name: self.get_scenario(name)["events"] for name in self.SCENARIOS}

    # ── 工具方法 ──

    @staticmethod
    def _make_event(
        event_type: str,
        severity: str,
        source_ip: str,
        dst_ip: str,
        dst_port: int,
        size: int,
        timestamp: float,
        category: str,
        **extra: Any,
    ) -> Dict[str, Any]:
        """构造标准告警事件字典。"""
        event: Dict[str, Any] = {
            "type": event_type,
            "severity": severity,
            "source_ip": source_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "size": size,
            "timestamp": timestamp,
            "category": category,
        }
        event.update(extra)
        return event

    @staticmethod
    def _ts(base: float, offset: float) -> float:
        """生成时间戳：基准时间 + 偏移秒数。"""
        return base + offset

    # ── c2_beacon ──

    def _build_c2_beacon(self) -> List[Dict[str, Any]]:
        """
        6 次 C2 信标回连：
        - 目标 IP: 198.51.100.10
        - 端口: 4444/4444/8443/31337/8443/4444
        - 大小: 128/64/256/128/64/128 字节
        - 间隔: 3.2/4.1/3.8/4.5/3.5 秒
        """
        base = time_module.time()
        intervals = [3.2, 4.1, 3.8, 4.5, 3.5]
        ports = [4444, 4444, 8443, 31337, 8443, 4444]
        sizes = [128, 64, 256, 128, 64, 128]

        events = []
        ts = base
        for i in range(6):
            events.append(self._make_event(
                event_type="outbound",
                severity="info",
                source_ip="10.0.1.50",
                dst_ip="198.51.100.10",
                dst_port=ports[i],
                size=sizes[i],
                timestamp=ts,
                category="c2_beacon",
            ))
            if i < 5:
                ts += intervals[i]
        return events

    # ── data_exfil ──

    def _build_data_exfil(self) -> List[Dict[str, Any]]:
        """
        数据外泄：2 次单包大流量 + 8 次窗口累计（6MB/3MB 交替）。
        目标 IP: 203.0.113.200:443
        """
        base = time_module.time()
        events = []

        # 2 次单包大流量
        ts = base
        events.append(self._make_event(
            event_type="outbound", severity="severe",
            source_ip="10.0.1.50", dst_ip="203.0.113.200",
            dst_port=443, size=12 * 1024 * 1024, timestamp=ts,
            category="data_exfil",
        ))
        ts += 2.5
        events.append(self._make_event(
            event_type="outbound", severity="severe",
            source_ip="10.0.1.50", dst_ip="203.0.113.200",
            dst_port=443, size=18 * 1024 * 1024, timestamp=ts,
            category="data_exfil",
        ))

        # 8 次窗口累计（6MB/3MB 交替，间隔 1.8s）
        ts += 3.0
        alt_sizes = [6 * 1024 * 1024, 3 * 1024 * 1024] * 4
        for i, sz in enumerate(alt_sizes):
            events.append(self._make_event(
                event_type="outbound", severity="high",
                source_ip="10.0.1.50", dst_ip="203.0.113.200",
                dst_port=443, size=sz,
                timestamp=ts + i * 1.8,
                category="data_exfil",
            ))
        return events

    # ── port_scan ──

    def _build_port_scan(self) -> List[Dict[str, Any]]:
        """
        端口扫描：20 次不同端口，同一源 IP（10.0.1.100），2 秒内分两批。
        """
        base = time_module.time()
        scan_ports = [
            22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
            445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 8080,
        ]
        events = []
        for i, port in enumerate(scan_ports):
            ts = base + (i // 10) * 1.0 + (i % 10) * 0.05
            events.append(self._make_event(
                event_type="outbound", severity="info",
                source_ip="10.0.1.100", dst_ip="192.168.1.1",
                dst_port=port, size=60, timestamp=ts,
                category="port_scan",
            ))
        return events

    # ── bruteforce ──

    def _build_bruteforce(self) -> List[Dict[str, Any]]:
        """
        暴力破解：15 次 SSH 登录失败（10.0.1.200 → 192.168.1.10:22），
        间隔 0.5-2s（固定种子 RNG 保证可复现）。
        """
        base = time_module.time()
        events = []
        ts = base
        for i in range(15):
            events.append(self._make_event(
                event_type="auth_failure", severity="medium",
                source_ip="10.0.1.200", dst_ip="192.168.1.10",
                dst_port=22, size=120, timestamp=ts,
                category="bruteforce",
            ))
            ts += 0.5 + self.RNG.random() * 1.5  # 0.5 ~ 2.0 秒
        return events

    # ── mixed_attack ──

    def _build_mixed_attack(self) -> List[Dict[str, Any]]:
        """
        混合攻击：合并四种攻击场景的事件，按时间戳排序后缩放至约 120 秒跨度。
        """
        builders = [
            self._build_c2_beacon,
            self._build_data_exfil,
            self._build_port_scan,
            self._build_bruteforce,
        ]
        all_events: List[Dict[str, Any]] = []
        for builder in builders:
            all_events.extend(builder())

        # 按时间戳排序
        all_events.sort(key=lambda e: e["timestamp"])

        # 缩放时间轴至约 120 秒
        if all_events:
            first_ts = all_events[0]["timestamp"]
            last_ts = all_events[-1]["timestamp"]
            span = last_ts - first_ts
            if span > 0:
                scale = 120.0 / span
                base = time_module.time()
                for e in all_events:
                    e["timestamp"] = base + (e["timestamp"] - first_ts) * scale

        return all_events

    # ── clean_traffic ──

    def _build_clean_traffic(self) -> List[Dict[str, Any]]:
        """
        正常流量：10 条 HTTPS/API 调用，使用白名单域名和标准端口。
        不应触发任何告警。
        """
        base = time_module.time()
        normal_ports = [443, 443, 80, 443, 8443, 443, 443, 80, 443, 443]
        sizes = [800, 1200, 400, 2000, 600, 1500, 900, 300, 1800, 700]
        domains = [
            "api.github.com",
            "cdn.jsdelivr.net",
            "google.com",
            "api.openai.com",
            "docker.io",
            "pypi.org",
            "npmjs.com",
            "cloudflare.com",
            "amazonaws.com",
            "microsoft.com",
        ]
        events = []
        for i in range(10):
            events.append(self._make_event(
                event_type="outbound",
                severity="info",
                source_ip="10.0.1.50",
                dst_ip=f"104.16.{i}.1",
                dst_port=normal_ports[i],
                size=sizes[i],
                timestamp=base + i * 2.0,
                category="normal",
                domain=domains[i],
            ))
        return events
