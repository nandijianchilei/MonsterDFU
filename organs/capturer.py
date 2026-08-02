"""
Phase 1.5 - 网络抓包层 (PacketCapture)

基于 scapy 实现网络数据包捕获模块，支持实时抓包和 PCAP 回放两种模式。
通过消息总线发布 outbound_traffic 事件，供 OutboundMonitor 消费。

输出：向消息总线发布 outbound_traffic 事件，格式与 OutboundMonitor 兼容：
      {dst_ip, dst_port, size, timestamp, protocol}
"""

import asyncio
import logging
import time as time_module
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config
from utils.logger import get_logger


class PacketCapture:
    """
    网络数据包捕获模块，支持在线实时抓包和 PCAP 回放两种模式。

    构造参数：
        event_bus: MessageBus 实例（通过 get_message_bus() 获取）
        config:    Config 实例

    使用方式：
        pc = PacketCapture(get_message_bus(), get_config())
        pc.set_port_filter([4444, 8443, 31337])   # 可选过滤
        pc.start()                                   # 启动抓包
        ...
        await pc.stop()                              # 停止抓包

        # PCAP 回放（离线调试/benchmark）
        result = await pc.replay_pcap("traffic.pcap")
    """

    def __init__(self, event_bus: MessageBus, config: Config):
        self.bus = event_bus
        self.config = config
        self.logger: logging.Logger = get_logger("PacketCapture")

        # 过滤规则
        self._target_ports: Set[int] = set()
        self._target_ip_ranges: List[str] = []  # CIDR 格式，如 ["10.0.0.0/8"]

        # 运行状态
        self._running = False
        self._sniff_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # 检测管线馈送：设为 True 时，抓包数据会额外发布 traffic_data 消息送入检测管线
        self._detection_feed = False
        self._local_ip = ""

        # pcap 持久化（盲测）：设置路径后，抓到的原始包在 stop() 时写入 pcap 文件
        self._pcap_persist_path: str = ""
        self._captured_packets: List[Any] = []

        # 统计追踪
        self.stats: Dict[str, int] = {
            "total_packets": 0,
            "published_events": 0,
            "filtered_dropped": 0,
            "pcap_packets": 0,
        }

    # ── 过滤配置 ──

    def set_port_filter(self, ports: List[int]) -> None:
        """设置目标端口过滤：只抓这些端口的包。传入空列表清除过滤。"""
        self._target_ports = set(ports)
        self.logger.info(f"端口过滤已设置: {sorted(self._target_ports)}")

    def set_ip_filter(self, cidr_list: List[str]) -> None:
        """设置目标 IP 范围过滤：只抓这些 CIDR 范围内的包。传入空列表清除过滤。"""
        self._target_ip_ranges = cidr_list
        self.logger.info(f"IP 过滤已设置: {self._target_ip_ranges}")

    def clear_filters(self) -> None:
        """清除所有过滤规则（放行所有流量）。"""
        self._target_ports.clear()
        self._target_ip_ranges.clear()
        self.logger.info("所有过滤规则已清除")

    def enable_detection_feed(self, local_ip: str = "") -> None:
        """
        启用检测管线馈送：在发布 outbound_traffic 的基础上，
        额外发布 traffic_data 消息，供 TrafficMonitor 消费并送入检测管线。

        Args:
            local_ip: 本机 IP 地址，用于区分流量方向（可选）
        """
        self._detection_feed = True
        self._local_ip = local_ip
        self.logger.info("检测管线馈送已启用")

    # ── 抓包控制 ──

    def start(self) -> None:
        """启动抓包循环。在后台异步任务中运行 scapy sniff。"""
        self._running = True
        self._loop = asyncio.get_running_loop()
        self._sniff_task = asyncio.create_task(self._capture_loop())
        self.logger.info("PacketCapture 已启动，正在监听网络流量...")

    async def stop(self) -> None:
        """停止抓包，打印统计摘要；若启用了 pcap 持久化则写入 pcap 文件。"""
        self._running = False
        if self._sniff_task:
            self._sniff_task.cancel()
            try:
                await self._sniff_task
            except asyncio.CancelledError:
                pass
            self._sniff_task = None

        # pcap 持久化：将缓存的原始包写入文件
        if self._pcap_persist_path and self._captured_packets:
            try:
                from scapy.utils import wrpcap
                wrpcap(self._pcap_persist_path, self._captured_packets)
                self.logger.info(
                    f"已持久化 {len(self._captured_packets)} 个包到 "
                    f"{self._pcap_persist_path}（真实流量盲测数据）"
                )
            except Exception as e:
                self.logger.error(f"pcap 持久化失败: {e}")

        self.logger.info(
            f"PacketCapture 已停止。统计: 总包 {self.stats['total_packets']}, "
            f"发布 {self.stats['published_events']}, "
            f"过滤丢弃 {self.stats['filtered_dropped']}"
        )

    async def _capture_loop(self) -> None:
        """抓包主循环：在 executor 线程中运行阻塞式 sniff。"""
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, self._run_sniff)
        except Exception as e:
            self.logger.error(f"抓包线程异常: {e}")

    def _run_sniff(self) -> None:
        """
        同步 sniff 调用（在 executor 线程中运行）。
        scapy.sniff 是阻塞调用，通过 stop_filter 检查退出条件。
        """
        try:
            from scapy.all import sniff
            sniff(
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except ImportError:
            self.logger.error(
                "scapy 未安装，请执行: pip install scapy"
            )
        except OSError as e:
            error_msg = str(e)
            if "Npcap" in error_msg or "WinPcap" in error_msg:
                self.logger.error(
                    "Npcap 未安装或未运行。请从 https://npcap.com 下载安装 Npcap，"
                    "安装时勾选 'WinPcap API-compatible Mode'。"
                )
            else:
                self.logger.error(f"抓包设备错误: {error_msg}")
        except Exception as e:
            self.logger.error(f"sniff 运行时异常: {e}")

    # ── 包处理 ──

    def _packet_handler(self, packet) -> None:
        """
        数据包回调（在 sniff 线程中调用）。

        解析 IP/TCP/UDP 层，提取 dst_ip、dst_port、size、timestamp，
        构造 outbound_traffic 事件发布到消息总线。
        """
        if not self._running:
            return

        self.stats["total_packets"] += 1

        try:
            ip_layer = packet.getlayer("IP")
            if ip_layer is None:
                return

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(packet)

            # 解析传输层端口
            dst_port = 0
            protocol = "IP"
            tcp_layer = packet.getlayer("TCP")
            udp_layer = packet.getlayer("UDP")
            if tcp_layer:
                dst_port = tcp_layer.dport
                protocol = "TCP"
            elif udp_layer:
                dst_port = udp_layer.dport
                protocol = "UDP"

            # 过滤检查
            if not self._pass_filter(dst_ip, dst_port):
                self.stats["filtered_dropped"] += 1
                return

            # 时间戳
            timestamp = getattr(packet, "time", time_module.time())

            # ── pcap 持久化（盲测）：缓存原始包，stop() 时写入 ──
            if self._pcap_persist_path:
                self._captured_packets.append(packet)
                self.stats["pcap_packets"] += 1

            # ── 发布 outbound_traffic 事件（给 OutboundMonitor）──
            event = {
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "size": size,
                "timestamp": timestamp,
                "protocol": protocol,
            }

            msg = Message(
                source="PacketCapture",
                target="OutboundMonitor",
                type="outbound_traffic",
                payload=event,
            )

            # 从同步线程安全地发布到异步消息总线
            if self._loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self.bus.publish(msg), self._loop
                )
            self.stats["published_events"] += 1

            # ── 检测管线馈送：发布 traffic_data 消息（给 TrafficMonitor）──
            if self._detection_feed:
                # 区分方向：若 dst_ip 是本地地址则视为入站（src 为攻击源），否则为出站
                if self._local_ip and dst_ip == self._local_ip:
                    traffic_src = src_ip
                    traffic_dst = dst_ip
                else:
                    traffic_src = src_ip
                    traffic_dst = dst_ip

                traffic_event = {
                    "type": "realtime",
                    "source_ip": traffic_src,
                    "target_ip": traffic_dst,
                    "target_port": dst_port,
                    "size": size,
                    "timestamp": timestamp,
                    "protocol": protocol,
                }

                traffic_msg = Message(
                    source="PacketCapture",
                    target="TrafficMonitor",
                    type="traffic_data",
                    payload=traffic_event,
                )
                if self._loop is not None:
                    asyncio.run_coroutine_threadsafe(
                        self.bus.publish(traffic_msg), self._loop
                    )

        except Exception as e:
            self.logger.debug(f"包解析异常: {e}")

    def _pass_filter(self, dst_ip: str, dst_port: int) -> bool:
        """
        检查数据包是否通过过滤规则。

        规则逻辑：
        - 未设置任何过滤 → 全部放行
        - 端口过滤已设置 → 仅放行匹配端口的包
        - IP 过滤已设置 → 仅放行匹配 CIDR 范围的包
        - 两者同时设置 → 同时满足才放行
        """
        if self._target_ports and dst_port not in self._target_ports:
            return False

        if self._target_ip_ranges:
            from ipaddress import ip_address, ip_network
            try:
                addr = ip_address(dst_ip)
                if not any(addr in ip_network(cidr, strict=False) for cidr in self._target_ip_ranges):
                    return False
            except ValueError:
                return False

        return True

    # ── PCAP 回放 ──

    async def replay_pcap(self, pcap_path: str, speed_factor: float = 1.0) -> Dict[str, Any]:
        """
        读取 .pcap 文件，按原始时间戳节奏回放，用于离线调试和 benchmark。

        Args:
            pcap_path:    .pcap 文件路径
            speed_factor: 回放速度倍率（1.0=实时，2.0=两倍速，0.5=半速）

        Returns:
            {
                "status": "completed" | "error",
                "total_packets": int,
                "replayed": int,
                "skipped": int,
                "events_published": int,
                "elapsed_seconds": float,
                "reason": str,  # 仅 error 时存在
            }
        """
        try:
            from scapy.utils import rdpcap
        except ImportError:
            self.logger.error("scapy 未安装，无法回放 PCAP")
            return {"status": "error", "reason": "scapy not installed"}

        self.logger.info(f"开始回放 PCAP: {pcap_path} (速度倍率: {speed_factor}x)")

        try:
            packets = rdpcap(pcap_path)
        except FileNotFoundError:
            self.logger.error(f"PCAP 文件不存在: {pcap_path}")
            return {"status": "error", "reason": f"file not found: {pcap_path}"}
        except Exception as e:
            self.logger.error(f"读取 PCAP 文件失败: {e}")
            return {"status": "error", "reason": str(e)}

        total = len(packets)
        replayed = 0
        start_wall = time_module.time()
        prev_time: Optional[float] = None

        for i, packet in enumerate(packets):
            if not self._running:
                self.logger.info("回放被手动停止")
                break

            # 按时间戳节奏等待
            pkt_time = getattr(packet, "time", None)
            if pkt_time is not None and prev_time is not None:
                delta = (pkt_time - prev_time) / speed_factor
                if delta > 0:
                    await asyncio.sleep(min(delta, 5.0))  # 上限 5 秒防卡死
            prev_time = pkt_time

            # 处理包（会触发 _packet_handler 并发布事件）
            self._packet_handler(packet)
            replayed += 1

            if (i + 1) % 1000 == 0:
                elapsed = time_module.time() - start_wall
                self.logger.info(f"回放进度: {i+1}/{total} ({elapsed:.1f}s)")

        elapsed = time_module.time() - start_wall
        result = {
            "status": "completed",
            "total_packets": total,
            "replayed": replayed,
            "skipped": total - replayed,
            "events_published": self.stats["published_events"],
            "elapsed_seconds": round(elapsed, 2),
        }
        self.logger.info(
            f"PCAP 回放完成: {replayed}/{total} 包, "
            f"耗时 {elapsed:.1f}s, 发布 {result['events_published']} 事件"
        )
        return result
