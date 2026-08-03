"""
真实流量接入Agent (RealtimeTrafficAgent)
支持 pcap 离线分析和本地端口在线监听两种模式。

模式1：pcap 离线分析
  - 读取 pcap/pcapng 文件，使用 scapy 解析
  - 提取流量特征并检测异常
  - 检测结果转换为标准 ThreatAlert 格式，通过消息总线发布

模式2：本地端口在线监听
  - 使用 asyncio 在指定端口监听
  - 接收 JSON 格式的流量日志（兼容 Suricata/Snort EVE JSON 格式）
  - 实时解析并检测，检测到异常立即告警
"""

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from communication.message_bus import Message, MessageBus, get_message_bus
from communication.skill_middleware import AlertSeverity, SkillMiddleware, ThreatCategory, ThreatIndicator
from config import Config
from utils.logger import get_logger


# ==================== 依赖检查 ====================

_SCAPY_AVAILABLE = False
try:
    import scapy.all  # noqa: F401
    from scapy.all import IP, TCP, UDP, PcapReader
    _SCAPY_AVAILABLE = True
except ImportError:
    pass


# ==================== pcap 数据包解析器 ====================

class PcapPacketParser:
    """pcap 数据包解析器，从原始字节或 scapy 包中提取流量特征。"""

    @staticmethod
    def from_scapy(pkt) -> Optional[Dict[str, Any]]:
        """
        从 scapy 包提取标准化流量特征。

        Returns:
            包含 src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp 的字典，
            非 IP 包返回 None。
        """
        try:
            if not pkt.haslayer(IP):
                return None
            ip = pkt[IP]
            result = {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "protocol": "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER"),
                "size": len(pkt),
                "timestamp": float(pkt.time),
            }
            if pkt.haslayer(TCP):
                result["src_port"] = pkt[TCP].sport
                result["dst_port"] = pkt[TCP].dport
                result["tcp_flags"] = int(pkt[TCP].flags)
                result["is_syn"] = bool(pkt[TCP].flags & 0x02) and not bool(pkt[TCP].flags & 0x10)  # SYN without ACK
            elif pkt.haslayer(UDP):
                result["src_port"] = pkt[UDP].sport
                result["dst_port"] = pkt[UDP].dport
                result["tcp_flags"] = 0
                result["is_syn"] = False
            else:
                result["src_port"] = 0
                result["dst_port"] = 0
                result["tcp_flags"] = 0
                result["is_syn"] = False
            return result
        except Exception:
            return None

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        从 JSON 字典提取标准化流量特征。
        支持 Suricata/Snort EVE JSON 格式和简化格式。
        """
        # EVE JSON 格式
        if "src_ip" in data:
            return {
                "src_ip": data.get("src_ip", "0.0.0.0"),
                "dst_ip": data.get("dst_ip", data.get("dest_ip", "0.0.0.0")),
                "src_port": data.get("src_port", 0),
                "dst_port": data.get("dst_port", data.get("dest_port", 0)),
                "protocol": data.get("proto", data.get("protocol", "TCP")).upper(),
                "size": data.get("bytes", data.get("size", 0)),
                "timestamp": data.get("timestamp", time.time()),
                "is_syn": "SYN" in str(data.get("flags", "")).upper(),
            }
        # 简化格式
        if "source_ip" in data:
            return {
                "src_ip": data["source_ip"],
                "dst_ip": data.get("target_ip", data.get("dest_ip", "0.0.0.0")),
                "src_port": data.get("source_port", data.get("src_port", 0)),
                "dst_port": data.get("target_port", data.get("dst_port", data.get("dest_port", 0))),
                "protocol": data.get("protocol", "TCP").upper(),
                "size": data.get("size", 0),
                "timestamp": data.get("timestamp", time.time()),
                "is_syn": False,
            }
        return None


# ==================== RealtimeTrafficAgent ====================

class RealtimeTrafficAgent:
    """
    真实流量接入 Agent。

    支持两种运行模式：
    1. pcap 离线分析：读取 pcap/pcapng 文件，逐包检测异常
    2. 本地端口在线监听：接收 JSON 行格式流量日志
    """

    def __init__(self, config: Config):
        """
        Args:
            config: 全局配置对象
        """
        self.config = config
        self.rt_config = config.realtime

        # 自动选择消息总线：分布式模式用 RabbitMQ，本地模式用内存总线
        rabbitmq_url = os.environ.get("RABBITMQ_URL", "")
        if rabbitmq_url:
            from communication.rabbitmq_bus import RabbitMQBus
            self.bus: Any = RabbitMQBus()
        else:
            self.bus: MessageBus = get_message_bus()

        self.middleware = SkillMiddleware()
        self.logger: logging.Logger = get_logger("RealtimeTraffic")

        # 滑动窗口统计
        self._request_counter: Dict[str, List[Tuple[float, float]]] = {}     # (src_ip, dst_ip) → [(ts, size), ...]
        self._port_set: Dict[str, Set[int]] = {}                              # src_ip → set(dst_port)
        self._syn_counter: Dict[str, List[float]] = {}                        # (src_ip, dst_ip, dst_port) → [ts, ...]
        self._alerted: Set[str] = set()

        self._running = False
        self._server: Optional[asyncio.AbstractServer] = None
        self._total_packets = 0
        self._total_alerts = 0

    # ==================== 公共入口 ====================

    async def start(self) -> None:
        """启动 Agent（订阅消息总线）。"""
        self._running = True
        # 如果使用 RabbitMQBus，需要先建立连接
        if hasattr(self.bus, "connect"):
            await self.bus.connect("realtime", binding_keys=["threat_alert"])
        self.logger.info("真实流量接入Agent已启动")

    async def stop(self) -> None:
        """停止 Agent。"""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.logger.info("真实流量接入Agent已停止")

    async def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        离线分析 pcap/pcapng 文件。

        Args:
            pcap_path: pcap 文件绝对路径

        Returns:
            分析摘要：total_packets, alerts_generated, anomalies_found
        """
        if not _SCAPY_AVAILABLE:
            raise RuntimeError(
                "pcap 分析需要 scapy 库。请安装：pip install scapy"
            )

        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"pcap 文件不存在: {pcap_path}")

        file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
        self.logger.info(f"开始分析 pcap: {pcap_path} ({file_size_mb:.1f} MB)")
        print(f"\n  pcap 分析: {pcap_path} ({file_size_mb:.1f} MB)")
        print(f"  分块大小: {self.rt_config.pcap_chunk_size} 包/块")

        self._total_packets = 0
        self._total_alerts = 0
        chunk_count = 0

        try:
            with PcapReader(pcap_path) as reader:
                chunk_packets = 0
                for pkt in reader:
                    if not self._running:
                        break

                    parsed = PcapPacketParser.from_scapy(pkt)
                    if parsed:
                        chunk_packets += 1
                        self._total_packets += 1
                        await self._process_packet(parsed)

                    # 分块处理，定期释放 GIL
                    if chunk_packets >= self.rt_config.pcap_chunk_size:
                        chunk_count += 1
                        if chunk_count % 10 == 0:
                            print(f"    已处理 {self._total_packets} 包 | 告警 {self._total_alerts} 次")
                        chunk_packets = 0
                        await asyncio.sleep(0)  # 让出事件循环

                # 处理末块
                if chunk_packets > 0:
                    chunk_count += 1
        except Exception as e:
            self.logger.error(f"pcap 解析错误: {e}")
            raise

        summary = {
            "total_packets": self._total_packets,
            "alerts_generated": self._total_alerts,
            "chunks_processed": chunk_count,
        }
        print(f"\n  pcap 分析完成: 共 {self._total_packets} 包 | 告警 {self._total_alerts} 次")
        return summary

    async def start_listening(self) -> asyncio.AbstractServer:
        """
        启动本地端口在线监听。

        Returns:
            asyncio TCP 服务器实例
        """
        host = self.rt_config.listen_host
        port = self.rt_config.listen_port

        self._server = await asyncio.start_server(
            self._handle_client,
            host=host,
            port=port,
        )

        self.logger.info(f"在线监听已启动: {host}:{port}")
        print(f"\n  在线监听模式: {host}:{port}")
        print("  接收 JSON 行格式的流量日志")
        print("  按 Ctrl+C 停止")

        return self._server

    # ==================== 客户端处理 ====================

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        处理客户端连接。逐行读取 JSON 格式的流量日志。
        """
        addr = writer.get_extra_info("peername")
        self.logger.info(f"新连接: {addr}")

        try:
            while self._running:
                line = await reader.readline()
                if not line:
                    break

                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue

                try:
                    data = json.loads(line_str)
                except json.JSONDecodeError:
                    self.logger.warning(f"无效 JSON: {line_str[:100]}")
                    continue

                # 支持批量数组
                if isinstance(data, list):
                    for item in data:
                        parsed = PcapPacketParser.from_dict(item)
                        if parsed:
                            self._total_packets += 1
                            await self._process_packet(parsed)
                else:
                    parsed = PcapPacketParser.from_dict(data)
                    if parsed:
                        self._total_packets += 1
                        await self._process_packet(parsed)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"客户端处理错误 ({addr}): {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            self.logger.info(f"连接关闭: {addr}")

    # ==================== 数据包处理 ====================

    async def _process_packet(self, info: Dict[str, Any]) -> None:
        """
        处理单个标准化流量数据包，执行四项异常检测。

        Args:
            info: 标准化流量特征字典（src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp, is_syn）
        """
        src_ip = info["src_ip"]
        dst_ip = info["dst_ip"]
        dst_port = info["dst_port"]
        size = info.get("size", 0)
        ts = info.get("timestamp", time.time())
        is_syn = info.get("is_syn", False)
        protocol = info.get("protocol", "TCP")

        # 1. 高频同IP请求检测
        threat = await self._check_high_freq(src_ip, dst_ip, dst_port, ts, size, info)
        if threat:
            await self._publish_alert(threat)

        # 2. 端口扫描检测
        threat = await self._check_port_scan(src_ip, dst_ip, dst_port, ts, info)
        if threat:
            await self._publish_alert(threat)

        # 3. 大流量脉冲检测
        threat = await self._check_traffic_burst(src_ip, dst_ip, ts, size, info)
        if threat:
            await self._publish_alert(threat)

        # 4. SYN Flood 检测
        if is_syn and protocol == "TCP":
            threat = await self._check_syn_flood(src_ip, dst_ip, dst_port, ts, info)
            if threat:
                await self._publish_alert(threat)

    # ==================== 异常检测方法 ====================

    async def _check_high_freq(
        self, src_ip: str, dst_ip: str, dst_port: int, ts: float, size: int, raw: Dict,
    ) -> Optional[ThreatIndicator]:
        """检测高频同IP请求。"""
        threshold = self.rt_config.high_freq_threshold
        window = self.rt_config.time_window_seconds

        key = f"{src_ip}->{dst_ip}:{dst_port}"
        if key not in self._request_counter:
            self._request_counter[key] = []

        entries = self._request_counter[key]
        entries.append((ts, size))
        cutoff = ts - window
        self._request_counter[key] = [(t, s) for t, s in entries if t >= cutoff]
        count = len(self._request_counter[key])

        if count >= threshold:
            dedup_key = f"hf_{key}_{int(ts // (window * 2))}"
            if dedup_key in self._alerted:
                return None
            self._alerted.add(dedup_key)
            self.logger.debug(f"高频请求: {src_ip} 在 {window}s 内向 {dst_ip}:{dst_port} 发送 {count} 次")
            return self.middleware.normalize_ddos_alert(
                source_ip=src_ip,
                request_count=count,
                target_ip=dst_ip,
                target_port=dst_port,
                raw_data={**raw, "detection": "high_freq", "window_seconds": window},
            )
        return None

    async def _check_port_scan(
        self, src_ip: str, dst_ip: str, dst_port: int, ts: float, raw: Dict,
    ) -> Optional[ThreatIndicator]:
        """检测端口扫描行为。"""
        threshold = self.rt_config.port_scan_threshold

        if src_ip not in self._port_set:
            self._port_set[src_ip] = set()

        self._port_set[src_ip].add(dst_port)
        port_count = len(self._port_set[src_ip])

        if port_count >= threshold:
            dedup_key = f"ps_{src_ip}_{int(ts // 15)}"
            if dedup_key in self._alerted:
                return None
            self._alerted.add(dedup_key)
            self.logger.debug(f"端口扫描: {src_ip} 已访问 {port_count} 个不同端口")
            return self.middleware.normalize_port_scan_alert(
                source_ip=src_ip,
                scanned_ports=list(self._port_set[src_ip]),
                target_ip=dst_ip,
                raw_data={**raw, "detection": "port_scan", "unique_ports": port_count},
            )
        return None

    async def _check_traffic_burst(
        self, src_ip: str, dst_ip: str, ts: float, size: int, raw: Dict,
    ) -> Optional[ThreatIndicator]:
        """检测大流量脉冲（单流 > threshold MB/s）。"""
        threshold_mbps = self.rt_config.large_flow_threshold_mbps
        threshold_bytes_per_sec = threshold_mbps * 1024 * 1024
        window = self.rt_config.time_window_seconds

        # 使用专用的流量统计：_traffic_volume: (src_ip, dst_ip) → [(ts, size), ...]
        if not hasattr(self, "_traffic_volume"):
            self._traffic_volume: Dict[str, List[Tuple[float, float]]] = {}

        key = f"{src_ip}->{dst_ip}"
        if key not in self._traffic_volume:
            self._traffic_volume[key] = []

        entries = self._traffic_volume[key]
        entries.append((ts, size))
        cutoff = ts - window
        self._traffic_volume[key] = [(t, s) for t, s in entries if t >= cutoff]

        total_bytes = sum(s for t, s in self._traffic_volume[key])
        byte_rate = total_bytes / max(window, 0.1)  # bytes/s

        if byte_rate >= threshold_bytes_per_sec:
            mbps = byte_rate / (1024 * 1024)
            dedup_key = f"burst_{key}_{int(ts // (window * 2))}"
            if dedup_key in self._alerted:
                return None
            self._alerted.add(dedup_key)
            self.logger.debug(f"大流量脉冲: {src_ip} → {dst_ip}，{mbps:.1f} MB/s")
            return ThreatIndicator(
                id=self.middleware._next_alert_id(),
                category=ThreatCategory.DDOS,
                severity=AlertSeverity.HIGH if mbps >= threshold_mbps * 2 else AlertSeverity.MEDIUM,
                source_ip=src_ip,
                target_ip=dst_ip,
                target_port=None,
                description=f"大流量脉冲：{src_ip} → {dst_ip}，{mbps:.1f} MB/s（阈值 {threshold_mbps} MB/s）",
                raw_data={**raw, "detection": "traffic_burst", "mbps": round(mbps, 2)},
            )
        return None

    async def _check_syn_flood(
        self, src_ip: str, dst_ip: str, dst_port: int, ts: float, raw: Dict,
    ) -> Optional[ThreatIndicator]:
        """检测 SYN Flood（同目标同端口大量 SYN 包）。"""
        threshold = self.rt_config.syn_flood_threshold
        window = self.rt_config.time_window_seconds

        key = f"{src_ip}->{dst_ip}:{dst_port}"
        if key not in self._syn_counter:
            self._syn_counter[key] = []

        entries = self._syn_counter[key]
        entries.append(ts)
        cutoff = ts - window
        self._syn_counter[key] = [t for t in entries if t >= cutoff]
        syn_count = len(self._syn_counter[key])

        if syn_count >= threshold:
            dedup_key = f"syn_{key}_{int(ts // (window * 3))}"
            if dedup_key in self._alerted:
                return None
            self._alerted.add(dedup_key)
            self.logger.debug(f"SYN Flood: {src_ip} → {dst_ip}:{dst_port}，{syn_count} SYN/s")
            return ThreatIndicator(
                id=self.middleware._next_alert_id(),
                category=ThreatCategory.BRUTE_FORCE,
                severity=AlertSeverity.HIGH if syn_count >= threshold * 2 else AlertSeverity.MEDIUM,
                source_ip=src_ip,
                target_ip=dst_ip,
                target_port=dst_port,
                description=f"SYN Flood：{src_ip} → {dst_ip}:{dst_port}，{syn_count} SYN包/秒",
                raw_data={**raw, "detection": "syn_flood", "syn_count": syn_count},
            )
        return None

    async def _publish_alert(self, threat: ThreatIndicator) -> None:
        """发布标准威胁告警消息到消息总线。"""
        self._total_alerts += 1
        msg = Message(
            source="RealtimeTraffic",
            target="*",
            type="threat_alert",
            payload=threat.to_dict(),
        )
        await self.bus.publish(msg)

    def reset_state(self) -> None:
        """重置内部统计状态。"""
        self._request_counter.clear()
        self._port_set.clear()
        self._syn_counter.clear()
        self._alerted.clear()
        self._total_packets = 0
        self._total_alerts = 0

    @property
    def stats(self) -> Dict[str, Any]:
        """返回当前统计摘要。"""
        return {
            "total_packets": self._total_packets,
            "alerts_generated": self._total_alerts,
            "tracked_ips": len(self._request_counter),
            "port_scan_sources": len(self._port_set),
        }
