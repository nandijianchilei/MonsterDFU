"""
溯源追踪 Worker — 关联攻击链，构建攻击者画像。

环境变量: RABBITMQ_URL
"""

import asyncio
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from utils.logger import get_logger

logger = get_logger("TraceWorker")


class TraceWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.trace_count = 0
        self.attack_graph: dict = {}  # src_ip -> chain

    async def start(self):
        await self.bus.connect("organ_trace")
        await self.bus.subscribe("threat_alert", self.on_alert)
        await self.bus.subscribe("action_result", self.on_action)
        logger.info("[TraceWorker] 已就绪，构建攻击链...")

    async def on_alert(self, msg: Message):
        src_ip = msg.payload.get("source_ip", "")
        attack_type = msg.payload.get("category", "unknown")
        entry = self.attack_graph.setdefault(src_ip, [])
        entry.append({"type": attack_type, "time": datetime.now().isoformat()})

        report = Message(
            source="ForensicTracker",
            target="*",
            msg_type="forensic_report",
            payload={
                "source_ip": src_ip,
                "chain_length": len(entry),
                "recent_attack": attack_type,
                "timestamp": datetime.now().isoformat(),
            },
        )
        await self.bus.publish(report)

    async def on_action(self, msg: Message):
        src_ip = msg.payload.get("source_ip", "")
        action = msg.payload.get("action", "")
        self.trace_count += 1
        logger.info(f"[溯源] #{self.trace_count}: {src_ip} -> {action}")


async def main():
    worker = TraceWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
