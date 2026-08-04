"""
观测Agent：流量监测模块
模拟监听网络流量，检测异常：高频同IP请求、异常端口扫描、大流量脉冲。
输出标准格式的威胁告警。
"""

import logging
from typing import Dict, List, Optional, Set

from communication.message_bus import Message, MessageBus, get_message_bus
from communication.skill_middleware import SkillMiddleware, ThreatIndicator
from config import Config
from utils.logger import get_logger


class TrafficMonitorAgent:
    """
    流量监测观测 Agent。

    职责：
    1. 订阅模拟攻击流量消息
    2. 维护短期滑动窗口统计
    3. 检测三类异常：高频请求、端口扫描、大流量脉冲
    4. 输出标准 ThreatIndicator 告警
    """

    def __init__(self, config: Config):
        """
        Args:
            config: 全局配置对象
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.middleware = SkillMiddleware()
        self.logger: logging.Logger = get_logger("TrafficMonitor")

        # 滑动窗口统计
        self._request_counter: Dict[str, List[float]] = {}     # IP → [timestamp, ...]
        self._port_set: Dict[str, Set[int]] = {}                # IP → set(port)
        self._traffic_volume: Dict[str, List[tuple]] = {}       # IP → [(timestamp, bytes), ...]

        # 已告警去重
        self._alerted: Set[str] = set()

        self._running = False

    async def start(self) -> None:
        """启动观测Agent，订阅攻击流量消息。"""
        self._running = True
        await self.bus.subscribe("traffic_data", self._handle_traffic)
        self.logger.info("流量监测Agent已启动，正在监听流量...")

    async def stop(self) -> None:
        """停止观测Agent。"""
        self._running = False
        self.logger.info("流量监测Agent已停止")

    async def _handle_traffic(self, msg: Message) -> Optional[Message]:
        """
        处理模拟攻击流量消息。

        Args:
            msg: 流量数据消息，payload 包含：
                 - type: 'ddos' | 'port_scan' | 'brute_force'
                 - source_ip, target_ip, target_port, size（可选）
                 - timestamp

        Returns:
            若检测到异常则返回告警消息
        """
        if not self._running:
            return None

        payload = msg.payload
        traffic_type = payload.get("type", "unknown")
        source_ip = payload.get("source_ip", "unknown")
        target_ip = payload.get("target_ip", "192.168.1.1")
        target_port = payload.get("target_port", 80)
        size = payload.get("size", 0)
        ts = payload.get("timestamp", 0)

        threat = None

        # 真实流量：统一走三类检测（各自内部维护窗口统计），并记录流量体积
        if traffic_type == "realtime":
            threat = self._check_high_freq(source_ip, target_ip, target_port, ts, payload)
            if not threat:
                threat = self._check_port_scan(source_ip, target_ip, target_port, ts, payload)
            if not threat:
                threat = self._check_traffic_burst(source_ip, target_ip, target_port, ts, size, payload)
            # 流量体积统计（供前端展示）
            if source_ip not in self._traffic_volume:
                self._traffic_volume[source_ip] = []
            self._traffic_volume[source_ip].append((ts, size))
        elif traffic_type == "ddos":
            threat = self._check_high_freq(source_ip, target_ip, target_port, ts, payload)
        elif traffic_type == "port_scan":
            threat = self._check_port_scan(source_ip, target_ip, target_port, ts, payload)
        elif traffic_type == "brute_force":
            threat = self._check_traffic_burst(source_ip, target_ip, target_port, ts, size, payload)

        if threat:
            self.logger.warning(f"检测到威胁: [{threat.category.value}] {threat.description}")
            return self._build_alert_message(threat)
        return None

    def _check_high_freq(
        self,
        source_ip: str,
        target_ip: str,
        target_port: int,
        ts: float,
        raw_data: Dict,
    ) -> Optional[ThreatIndicator]:
        """
        检测高频同IP请求（DDoS特征）。

        滑动窗口算法：保留最近 T 秒内的请求时间戳，统计窗口中请求数。
        """
        threshold = self.config.thresholds.high_freq_request_count
        window = self.config.thresholds.high_freq_time_window

        if source_ip not in self._request_counter:
            self._request_counter[source_ip] = []

        timestamps = self._request_counter[source_ip]
        timestamps.append(ts)
        # 清理过期数据
        cutoff = ts - window
        self._request_counter[source_ip] = [t for t in timestamps if t >= cutoff]

        count = len(self._request_counter[source_ip])

        if count >= threshold:
            dedup_key = f"ddos_{source_ip}_{int(ts // 5)}"  # 每5秒最多一条去重
            if dedup_key in self._alerted:
                return None
            self._alerted.add(dedup_key)
            self.logger.debug(f"高频请求检测: {source_ip} 在 {window}s 内发送 {count} 次请求")
            return self.middleware.normalize_ddos_alert(
                source_ip=source_ip,
                request_count=count,
                target_ip=target_ip,
                target_port=target_port,
                raw_data={**raw_data, "window_seconds": window},
            )
        return None

    def _check_port_scan(
        self,
        source_ip: str,
        target_ip: str,
        target_port: int,
        ts: float,
        raw_data: Dict,
    ) -> Optional[ThreatIndicator]:
        """
        检测异常端口扫描：同一IP短时间内访问大量不同端口。
        """
        threshold = self.config.thresholds.port_scan_port_count

        if source_ip not in self._port_set:
            self._port_set[source_ip] = set()

        self._port_set[source_ip].add(target_port)
        port_count = len(self._port_set[source_ip])

        if port_count >= threshold:
            dedup_key = f"scan_{source_ip}_{int(ts // 10)}"
            if dedup_key in self._alerted:
                return None
            self._alerted.add(dedup_key)
            self.logger.debug(f"端口扫描检测: {source_ip} 已访问 {port_count} 个不同端口")
            return self.middleware.normalize_port_scan_alert(
                source_ip=source_ip,
                scanned_ports=list(self._port_set[source_ip]),
                target_ip=target_ip,
                raw_data={**raw_data, "unique_ports": port_count},
            )
        return None

    def _check_traffic_burst(
        self,
        source_ip: str,
        target_ip: str,
        target_port: int,
        ts: float,
        size: int,
        raw_data: Dict,
    ) -> Optional[ThreatIndicator]:
        """
        检测暴力破解特征：通过认证尝试次数判断。
        """
        threshold = self.config.thresholds.brute_force_attempts_threshold
        attempts = raw_data.get("attempts", 0)

        if attempts >= threshold:
            dedup_key = f"brute_{source_ip}_{int(ts // 60)}"  # 1分钟去重窗口
            if dedup_key in self._alerted:
                return None
            self._alerted.add(dedup_key)
            self.logger.debug(f"暴力破解检测: {source_ip} 发起 {attempts} 次认证尝试")
            return self.middleware.normalize_brute_force_alert(
                source_ip=source_ip,
                attempts=attempts,
                target_ip=target_ip,
                target_port=target_port,
                raw_data=raw_data,
            )
        return None

    def _build_alert_message(self, threat: ThreatIndicator) -> Message:
        """
        构建标准威胁告警消息，同时发送给双引擎。

        Args:
            threat: 标准化威胁指标

        Returns:
            告警 Message（target='*' 广播给双引擎）
        """
        return Message(
            source="TrafficMonitor",
            target="*",  # 广播
            type="threat_alert",
            payload=threat.to_dict(),
        )

    def reset_state(self) -> None:
        """重置内部统计状态（用于测试）。"""
        self._request_counter.clear()
        self._port_set.clear()
        self._traffic_volume.clear()
        self._alerted.clear()
