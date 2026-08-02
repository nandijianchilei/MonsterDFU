"""
Phase 1.5 - 出站流量监测 Agent (OutboundMonitor)

职责：
  1. 真实出站连接扫描：基于 psutil.net_connections() 捕获本机对外主动连接的
     目标 IP + 端口 + 进程名，疑似 C2（已知恶意端口）或非标准端口大流量外联时
     通过 message_bus 发布告警，注入 event_aggregator 链路。
  2. 信标/心跳检测：识别目标 IP 的定期回连模式（C2 信标特征）
  3. 数据外泄检测：监控出站包大小，单包/窗口超阈告警
  4. 未知域名检测：对解析到外网的域名做可疑评分

模式：demo_mode=True 时只保留原有模拟逻辑（向后兼容）；
      demo_mode=False 时启用 psutil 真实扫描。
输出：通过 EventAggregator 管道发布 threat_alert（source_organ="outbound_monitor"）
"""

import asyncio
import hashlib
import logging
import os
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config, OutboundMonitorConfig
from core.false_positive_filter import FPFilterConfig, FalsePositiveFilter
from utils.logger import get_logger

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# 常见可信域名（白名单前缀匹配）
TRUSTED_DOMAINS: Set[str] = {
    "cdn.", "api.", "oss.", "static.", "img.",
    "google.", "bing.", "baidu.", "tencent.", "aliyun.",
    "microsoft.", "github.", "docker.", "pypi.", "npm.",
    "cloudflare.", "amazonaws.", "azure.",
}

# C2 信标端口常客
C2_SUSPICIOUS_PORTS: Set[int] = {4444, 5555, 6666, 7777, 8443, 9001, 31337, 1337, 8088, 9999}


class OutboundMonitor:
    """
    出站流量监测 Agent。

    订阅 outbound_traffic 消息，进行三类检测：
    - beacon_detection: 信标模式（定期回连）
    - exfil_detection: 数据外泄（大包/累计）
    - domain_detection: 可疑域名
    """

    def __init__(self, config: Config, demo_mode: bool = True):
        """
        Args:
            config: 全局配置对象
            demo_mode: True 时仅保留原有模拟消息订阅逻辑；
                       False 时启用 psutil 真实出站连接扫描。
        """
        self.config = config
        self.omc: OutboundMonitorConfig = config.outbound_monitor
        self.bus: MessageBus = get_message_bus()
        self.logger: logging.Logger = get_logger("OutboundMonitor")
        self.demo_mode = demo_mode

        # 信标检测：dst_ip → [(timestamp, packet_size), ...]
        self._beacon_records: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=20)
        )

        # 外泄检测：dst_ip → [(timestamp, bytes), ...]
        self._exfil_records: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=200)
        )

        # 域名记录：domain → set of timestamps
        self._domain_records: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=50)
        )

        # 已告警去重（用 hash 避免重复告警）
        self._alerted_hashes: Set[str] = set()

        # 真实扫描去重：已告警过的连接 (pid, remote_ip, remote_port)
        self._conn_alerted: Set[Tuple[int, str, int]] = set()

        # 最近一次真实扫描的连接列表（供前端展示）
        self._last_connections: List[Dict[str, Any]] = []
        self._last_scan_time: Optional[str] = None

        # 误报过滤层（白名单 + 告警阈值 + LLM 二次确认），配置为空时使用 core 默认值
        fp_dict = getattr(config, "false_positive_filter", None) or {}
        self.fp_filter = FalsePositiveFilter(FPFilterConfig.from_dict(fp_dict))

        # 统计追踪
        self.stats: Dict[str, int] = {
            "beacon_total": 0,
            "exfil_total": 0,
            "domain_total": 0,
            "alert_total": 0,
            "fp_suppressed": 0,
            "real_scan_count": 0,
            "real_conn_checked": 0,
        }

        self._running = False
        self._scan_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._running = True
        await self.bus.subscribe("outbound_traffic", self._handle_outbound)
        self.logger.info("出站流量监测Agent已启动，监听出站流量...")

        # 定期清理过期告警去重缓存
        asyncio.create_task(self._cleanup_loop())

        # 非 demo 模式：启动真实 psutil 出站连接扫描循环
        if not self.demo_mode:
            if HAS_PSUTIL:
                self._scan_task = asyncio.create_task(self._scan_loop())
                self.logger.info("出站连接扫描循环已启动（psutil 真实模式）")
            else:
                self.logger.warning("demo_mode=False 但 psutil 不可用，退化为 demo 模式")

    async def stop(self) -> None:
        self._running = False
        self.logger.info("出站流量监测Agent已停止")

    # ── 消息处理 ──

    async def _handle_outbound(self, msg: Message) -> None:
        """处理出站流量消息。"""
        payload = msg.payload
        dst_ip = payload.get("dst_ip", "")
        dst_port = payload.get("dst_port", 0)
        packet_size = payload.get("size", 0)
        domain = payload.get("domain", "")
        timestamp = payload.get("timestamp", datetime.now().timestamp())
        now = timestamp

        alerts: List[Dict[str, Any]] = []

        # 信标检测（基于目标 IP + 端口）
        if dst_ip:
            alerts.extend(self._check_beacon(dst_ip, dst_port, packet_size, now))

        # 外泄检测
        if dst_ip and packet_size > 0:
            alerts.extend(self._check_exfil(dst_ip, dst_port, packet_size, now))

        # 域名检测
        if domain:
            alerts.extend(self._check_domain(domain, dst_ip, now))

        # 发出告警（先经过误报过滤层：白名单 → 阈值 → LLM 二次确认）
        for alert in alerts:
            evt = self._alert_to_event(alert)
            emit, _reason = self.fp_filter.should_emit(evt, alert["type"])
            if not emit:
                self.stats["fp_suppressed"] += 1
                continue
            await self._emit_alert(alert)

    @staticmethod
    def _alert_to_event(alert: Dict[str, Any]) -> Dict[str, Any]:
        """将检测结果转换为误报过滤层统一事件结构。"""
        return {
            "type": alert["type"],
            "severity": alert["severity"],
            "source_ip": alert.get("source_ip", ""),
            "dst_ip": alert.get("dst_ip", ""),
            "dst_port": alert.get("dst_port", 0),
            "domain": alert.get("domain", ""),
            "size": alert.get("packet_size", 0),
        }

    # ── 检测逻辑 ──

    def _check_beacon(self, dst_ip: str, dst_port: int, packet_size: int, now: float) -> List[Dict]:
        """
        信标检测：跟踪到目标 IP 的出站时间序列，判断是否等间隔回连。

        特征：
        - 连续连接间隔偏差 < 容忍度
        - 小包（< 512 字节）更可疑
        - 使用 C2 常见端口加分
        """
        record = self._beacon_records[dst_ip]
        record.append((now, packet_size))

        if len(record) < self.omc.beacon_min_samples:
            return []

        # 提取时间戳序列
        timestamps = [t for t, _ in record]
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if len(intervals) < 2:
            return []

        # 计算平均间隔和偏差
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1.0:
            return []  # 低于1秒间隔不算信标（太密集可能是正常流量）

        deviations = [abs(iv - mean_interval) / mean_interval for iv in intervals]
        avg_deviation = sum(deviations) / len(deviations)

        # 间隔偏差容忍度检查
        if avg_deviation > self.omc.beacon_interval_tolerance:
            return []

        # 计算可疑分数
        score = 0.0
        # 小包加分（C2 信标通常包小）
        avg_size = sum(s for _, s in record) / len(record)
        if avg_size < 512:
            score += 0.3
        # 端口加分
        if dst_port in C2_SUSPICIOUS_PORTS:
            score += 0.3
        # 间隔规律性加分
        if avg_deviation < 0.3:
            score += 0.3
        # 持续时长加分
        duration = timestamps[-1] - timestamps[0]
        if duration > 60:
            score += 0.2

        if score < 0.5:
            return []

        severity = "high" if score > 0.7 else "medium"

        return [{
            "type": "beacon",
            "severity": severity,
            "source_ip": "internal",
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "description": (
                f"出站信标特征: {dst_ip}:{dst_port} "
                f"平均间隔 {mean_interval:.1f}s, 偏差 {avg_deviation:.2f}, "
                f"分数 {score:.2f}, 包数 {len(record)}"
            ),
            "score": score,
            "interval": round(mean_interval, 1),
            "deviation": round(avg_deviation, 2),
            "packet_count": len(record),
        }]

    def _check_exfil(self, dst_ip: str, dst_port: int, packet_size: int, now: float) -> List[Dict]:
        """
        数据外泄检测：单包超阈值 或 窗口内累计超阈值。
        """
        alerts = []

        # 单包检测
        if packet_size >= self.omc.exfil_single_threshold_bytes:
            alerts.append({
                "type": "exfiltration",
                "severity": "severe",
                "source_ip": "internal",
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "description": (
                    f"单包外泄: {dst_ip} 发送 {packet_size} 字节 "
                    f"(阈值 {self.omc.exfil_single_threshold_bytes})"
                ),
                "packet_size": packet_size,
                "exfil_type": "single_packet",
            })

        # 窗口累计检测
        record = self._exfil_records[dst_ip]
        record.append((now, packet_size))

        # 清理窗口外的旧记录
        window_start = now - self.omc.exfil_window_seconds
        while record and record[0][0] < window_start:
            record.popleft()

        total_bytes = sum(s for _, s in record)
        if total_bytes >= self.omc.exfil_window_threshold_bytes:
            alerts.append({
                "type": "exfiltration",
                "severity": "high",
                "source_ip": "internal",
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "description": (
                    f"窗口累计外泄: {dst_ip} "
                    f"近 {self.omc.exfil_window_seconds}s 共 {total_bytes} 字节 "
                    f"(阈值 {self.omc.exfil_window_threshold_bytes})"
                ),
                "total_bytes": total_bytes,
                "window_seconds": self.omc.exfil_window_seconds,
                "packet_count": len(record),
                "exfil_type": "window_accumulate",
            })

        return alerts

    def _check_domain(self, domain: str, dst_ip: str, now: float) -> List[Dict]:
        """
        域名可疑度检测。
        - 白名单前缀直接放过
        - 评分维度：熵值、长度、是否为 IP 直连、TLD 可疑度
        """
        domain_lower = domain.lower().strip()

        # 白名单放过
        for prefix in TRUSTED_DOMAINS:
            if domain_lower.startswith(prefix):
                return []

        # IP 直连（纯数字+点 → 无域名）
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_lower):
            # IP 直连本身不算域名异常，交给其它检测
            return []

        score = 0.0
        reasons = []

        # 1. 域名熵值（随机字符域名）
        def _entropy(s: str) -> float:
            if not s:
                return 0.0
            from math import log2
            prob = [s.count(c) / len(s) for c in set(s)]
            return -sum(p * log2(p) for p in prob)

        main_part = domain_lower.split(".")[0] if "." in domain_lower else domain_lower
        ent = _entropy(main_part)
        if ent > 4.0:
            score += 0.3
            reasons.append(f"熵值{ent:.2f}")

        # 2. 域名长度（长域名可疑）
        if len(main_part) > 20:
            score += 0.15
            reasons.append("长域名")
        elif len(main_part) > 12:
            score += 0.05

        # 3. 顶级域名可疑
        suspicious_tlds = {".xyz", ".top", ".club", ".work", ".gq", ".ml", ".cf", ".tk", ".link", ".click", ".download"}
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                score += 0.2
                reasons.append(f"TLD{tld}")
                break

        # 4. 数字组合过多
        digit_count = sum(c.isdigit() for c in main_part)
        if len(main_part) > 0 and digit_count / len(main_part) > 0.4:
            score += 0.15
            reasons.append("高数字占比")

        # 5. 连续辅音/特殊字符
        if "--" in main_part or ".." in domain_lower:
            score += 0.1
            reasons.append("含异常字符")

        if score < self.omc.domain_suspicious_threshold:
            return []

        severity = "high" if score > 0.8 else "medium"

        return [{
            "type": "suspicious_domain",
            "severity": severity,
            "source_ip": "internal",
            "dst_ip": dst_ip or domain_lower,
            "domain": domain_lower,
            "description": (
                f"可疑域名: {domain_lower} "
                f"分数 {score:.2f} ({', '.join(reasons)})"
            ),
            "score": round(score, 2),
            "reasons": reasons,
        }]

    # ── 告警发布 ──

    async def _emit_alert(self, alert: Dict[str, Any]) -> None:
        """发布格式化的 threat_alert 到消息总线，同时记录统计和专用事件。"""
        # 去重哈希
        dedup_key = hashlib.md5(
            f"{alert['type']}:{alert.get('dst_ip', '')}:{alert.get('domain', '')}:{alert['severity']}"
            .encode()
        ).hexdigest()
        if dedup_key in self._alerted_hashes:
            return
        self._alerted_hashes.add(dedup_key)

        # 统计计数
        alert_type = alert["type"]
        if alert_type == "beacon":
            self.stats["beacon_total"] += 1
        elif alert_type == "exfiltration":
            self.stats["exfil_total"] += 1
        elif alert_type == "suspicious_domain":
            self.stats["domain_total"] += 1
        self.stats["alert_total"] += 1

        alert_id = str(uuid.uuid4())[:8]
        indicator = {
            "id": alert_id,
            "category": alert["type"],
            "severity": alert["severity"],
            "source_ip": alert["source_ip"],
            "dst_ip": alert["dst_ip"],
            "description": alert["description"],
            "timestamp": datetime.now().isoformat(),
        }
        # 添加额外字段
        if "score" in alert:
            indicator["score"] = alert["score"]
        if "domain" in alert:
            indicator["domain"] = alert["domain"]

        # 1. 标准威胁告警 → 进入 EventAggregator 管道
        msg = Message(
            source="OutboundMonitor",
            target="EventAggregator",
            type="threat_alert",
            payload={
                "source_organ": "outbound_monitor",
                "indicator": indicator,
                "category": alert["type"],
                "severity": alert["severity"],
                "original": alert,
            },
        )
        await self.bus.publish(msg)

        # 2. 专用事件类型 → 驱动 EventChainRecorder 记录
        event_type_map = {
            "beacon": "outbound_beacon",
            "exfiltration": "outbound_exfil",
            "suspicious_domain": "outbound_domain",
        }
        chain_type = event_type_map.get(alert_type)
        if chain_type:
            chain_payload = {
                "source_ip": alert.get("source_ip", ""),
                "dest_ip": alert.get("dst_ip", ""),
                "dest_port": alert.get("dst_port", 0),
                "description": alert["description"][:80],
                "severity": alert["severity"],
            }
            if alert_type == "beacon":
                chain_payload["interval_sec"] = alert.get("interval", 0)
            elif alert_type == "exfiltration":
                chain_payload["bytes_sent"] = alert.get("packet_size", 0)
            elif alert_type == "suspicious_domain":
                chain_payload["domain"] = alert.get("domain", "")
                chain_payload["match_type"] = ",".join(alert.get("reasons", []))

            await self.bus.publish(Message(
                source="OutboundMonitor",
                target="EventChainRecorder",
                type=chain_type,
                payload=chain_payload,
            ))

        self.logger.info(
            f"[告警] {alert_id} | {alert['type']} | {alert['severity']} | "
            f"{alert.get('dst_ip', '') or alert.get('domain', '')} | {alert['description'][:60]}"
        )

    # ── 真实出站连接扫描（psutil）──

    async def _scan_loop(self) -> None:
        """后台循环：按 check_interval 间隔扫描 psutil 出站连接。"""
        while self._running:
            try:
                await self._scan_outbound_connections()
            except Exception as e:
                self.logger.error(f"出站连接扫描异常: {e}")
            await asyncio.sleep(self.omc.check_interval)

    async def _scan_outbound_connections(self) -> None:
        """基于 psutil.net_connections() 捕获本机对外主动连接，
        对命中 C2 端口的连接通过 message_bus 发布告警。"""
        if not HAS_PSUTIL:
            return

        self.stats["real_scan_count"] += 1
        local_ips = self._get_local_ips()

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
            self.logger.debug("psutil.net_connections() 权限不足，跳过本轮扫描")
            return

        # 本轮连接缓存（每次扫描重置）
        scan_conns: List[Dict[str, Any]] = []

        for conn in conns:
            # 仅关注 ESTABLISHED 的出站连接
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_ip = conn.laddr.ip if conn.laddr else ""

            # 过滤本地回环和本机 IP（入站类连接）
            if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                continue
            if remote_ip in local_ips:
                continue

            # 获取进程名
            proc_name = "unknown"
            pid = conn.pid or 0
            if pid:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = f"pid_{pid}"

            self.stats["real_conn_checked"] += 1

            # 缓存连接记录（供 /api/outbound/connections 展示）
            scan_conns.append({
                "local_ip": local_ip,
                "local_port": conn.laddr.port if conn.laddr else 0,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "process": proc_name,
                "pid": pid,
                "status": conn.status,
                "suspicious": remote_port in C2_SUSPICIOUS_PORTS,
                "checked_at": datetime.now().isoformat(),
            })

            # C2 端口命中检测
            if remote_port in C2_SUSPICIOUS_PORTS:
                dedup_key = (pid, remote_ip, remote_port)
                if dedup_key in self._conn_alerted:
                    continue
                self._conn_alerted.add(dedup_key)

                await self._emit_alert({
                    "type": "beacon",
                    "severity": "high",
                    "source_ip": local_ip or "internal",
                    "dst_ip": remote_ip,
                    "dst_port": remote_port,
                    "description": (
                        f"真实出站连接命中C2端口: {proc_name}(PID={pid}) → "
                        f"{remote_ip}:{remote_port}"
                    ),
                    "score": 0.85,
                    "interval": 0,
                    "deviation": 0,
                    "packet_count": 1,
                })

        # 保存本轮连接缓存
        self._last_connections = scan_conns
        self._last_scan_time = datetime.now().isoformat()

    def get_outbound_connections(self) -> Dict[str, Any]:
        """获取最近一次真实扫描的出站连接列表。"""
        return {
            "scan_time": self._last_scan_time,
            "total": len(self._last_connections),
            "suspicious_count": sum(1 for c in self._last_connections if c.get("suspicious")),
            "connections": self._last_connections,
        }

    @staticmethod
    def _get_local_ips() -> Set[str]:
        """获取本机所有非回环 IP 地址集合。"""
        ips: Set[str] = set()
        try:
            import socket
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ip and not ip.startswith("127.") and ip != "::1":
                    ips.add(ip)
        except Exception:
            pass
        # 回退：用 psutil 网卡地址
        if HAS_PSUTIL:
            try:
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == 2:  # AF_INET
                            ips.add(addr.address)
            except Exception:
                pass
        return ips

    # ── 清理 ──

    async def _cleanup_loop(self) -> None:
        """定期清理告警去重缓存（避免内存泄漏）。"""
        while self._running:
            await asyncio.sleep(300)
            self._alerted_hashes.clear()
            if len(self._conn_alerted) > 500:
                self._conn_alerted.clear()
