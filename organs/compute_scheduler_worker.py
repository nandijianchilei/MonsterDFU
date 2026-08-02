"""
算力调度 Worker — 管理算力分配，调度密集计算任务。

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

logger = get_logger("ComputeSchedulerWorker")


class ComputeSchedulerWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.task_count = 0
        self.active_tasks = 0
        self.max_concurrent = 4

    async def start(self):
        await self.bus.connect("organ_compute")
        await self.bus.subscribe("compute_task", self.on_task)
        logger.info("[ComputeSchedulerWorker] 已就绪，等待计算任务...")

    async def on_task(self, msg: Message):
        self.task_count += 1
        task_id = msg.payload.get("task_id", f"TASK-{self.task_count}")
        logger.info(f"[算力调度] 接收任务: {task_id}")

        # 模拟计算
        await asyncio.sleep(random.uniform(0.5, 2.0))

        report = Message(
            source="ResourceScheduler",
            target="*",
            msg_type="compute_result",
            payload={
                "task_id": task_id,
                "status": "completed",
                "duration_ms": random.randint(100, 2000),
                "node": f"node-{random.randint(1, 3)}",
                "timestamp": datetime.now().isoformat(),
            },
        )
        await self.bus.publish(report)

    def get_load(self) -> float:
        return self.active_tasks / max(1, self.max_concurrent)


async def main():
    worker = ComputeSchedulerWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
