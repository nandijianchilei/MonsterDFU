"""
日志审计 Worker — 消费审计日志流，检测异常行为。

环境变量: RABBITMQ_URL
"""

import asyncio
import os
import sys
import random
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from utils.logger import get_logger

logger = get_logger("LogAuditorWorker")

ANOMALY_PATTERNS = [
    "多次登录失败",
    "非工作时间访问",
    "敏感文件读取",
    "权限提升尝试",
    "异常数据外传",
]


class LogAuditorWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.audit_count = 0

    async def start(self):
        await self.bus.connect("organ_log")
        await self.bus.subscribe("audit_log", self.on_log)
        logger.info("[LogAuditorWorker] 已就绪，等待审计日志...")

    async def on_log(self, msg: Message):
        log_entry = msg.payload
        self.audit_count += 1

        # 随机检测异常
        anomaly = None
        if random.random() < 0.3:
            anomaly = random.choice(ANOMALY_PATTERNS)

        report = Message(
            source="LogAuditor",
            target="*",
            msg_type="audit_report",
            payload={
                "audit_id": f"AUDIT-{self.audit_count:04d}",
                "log_source": log_entry.get("source", "unknown"),
                "anomaly_detected": anomaly,
                "severity": "medium" if anomaly else "low",
                "timestamp": datetime.now().isoformat(),
            },
        )
        await self.bus.publish(report)
        if anomaly:
            logger.info(f"[日志审计] #{self.audit_count}: 异常 '{anomaly}'")


async def main():
    worker = LogAuditorWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
