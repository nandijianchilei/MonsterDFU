"""
实时流量 Worker — 从 pcap 文件或在线端口获取真实流量，检测 DDoS/扫描/SYN Flood。

环境变量:
  RABBITMQ_URL   RabbitMQ 连接
  PCAP_FILE      pcap 文件路径（离线模式）
  LISTEN_PORT    在线监听端口（默认 9999）
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from organs.observer_realtime import RealtimeTrafficAgent
from config import get_config
from utils.logger import get_logger

logger = get_logger("RealtimeWorker")


class RealtimeWorker:
    def __init__(self):
        self.config = get_config()
        self.agent = RealtimeTrafficAgent(self.config)
        self.pcap_file = os.environ.get("PCAP_FILE", "")

    async def start(self):
        await self.agent.start()
        if self.pcap_file and os.path.isfile(self.pcap_file):
            logger.info(f"[Realtime] pcap 离线模式: {self.pcap_file}")
            await self.agent.analyze_pcap(self.pcap_file)
        else:
            port = self.config.realtime.listen_port
            logger.info(f"[Realtime] 在线监听模式: 0.0.0.0:{port}")
            await self.agent.start_listening()


async def main():
    worker = RealtimeWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
