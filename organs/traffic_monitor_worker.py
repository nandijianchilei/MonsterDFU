"""
流量监测 Worker — 从 RabbitMQ 消费原始流量，检测 DDoS/扫描/爆破。

环境变量: RABBITMQ_URL
"""

import asyncio
import os
import sys
import random
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from config import Config, AlertLevelConfig, get_config
from utils.logger import get_logger

logger = get_logger("TrafficMonitorWorker")


class TrafficMonitorWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.config = get_config()
        self.thresholds: AlertLevelConfig = self.config.alert_levels
        self.alert_count = 0

    async def start(self):
        await self.bus.connect("organ_traffic")
        # 订阅攻击模拟流量
        await self.bus.subscribe("raw_traffic", self.on_traffic)
        # 自生成告警流（模拟真实流量）
        asyncio.create_task(self._traffic_generator())
        logger.info("[TrafficWorker] 已就绪，监听 raw_traffic...")

    async def on_traffic(self, msg: Message):
        """处理原始流量数据，生成威胁告警。"""
        data = msg.payload
        src_ip = data.get("source_ip", "0.0.0.0")
        traffic_type = data.get("type", "unknown")
        packet_count = data.get("packets", 0)
        port_count = data.get("ports", 0)

        severity = self._classify(traffic_type, packet_count, port_count)
        self.alert_count += 1

        alert = Message(
            source="TrafficMonitor",
            target="*",
            msg_type="threat_alert",
            payload={
                "id": f"ALERT-{self.alert_count:04d}",
                "category": traffic_type,
                "severity": severity,
                "source_ip": src_ip,
                "packets": packet_count,
                "ports": port_count,
                "description": f"检测到 {traffic_type} 攻击，来自 {src_ip}",
                "timestamp": datetime.now().isoformat(),
            },
        )
        await self.bus.publish(alert)
        logger.info(
            f"[流量] 告警 #{self.alert_count}: {traffic_type} ({severity})"
        )

    def _classify(self, traffic_type, packets, ports):
        if packets >= self.thresholds.ddos_severe_threshold:
            return "severe"
        if packets >= self.thresholds.ddos_high_threshold:
            return "high"
        if packets >= self.thresholds.ddos_medium_threshold:
            return "medium"
        return "low"

    async def _traffic_generator(self):
        """定期生成模拟流量用于压测。"""
        types = ["ddos", "port_scan", "brute_force"]
        ips = [f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(5)]
        while True:
            await asyncio.sleep(random.randint(8, 20))
            t = random.choice(types)
            msg = Message(
                source="AttackSimulator",
                target="organ_traffic",
                msg_type="raw_traffic",
                payload={
                    "source_ip": random.choice(ips),
                    "type": t,
                    "packets": random.randint(50, 600),
                    "ports": random.randint(5, 120),
                },
            )
            await self.bus.publish(msg)


async def main():
    worker = TrafficMonitorWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
