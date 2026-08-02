"""
校验 Worker — 订阅双脑输出，融合校验后发布最终处置方案。

环境变量: RABBITMQ_URL
"""

import asyncio
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from utils.logger import get_logger

logger = get_logger("VerifyWorker")


class VerifyWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.pending_alerts: dict = {}  # alert_id -> {left, right}

    async def start(self):
        await self.bus.connect("verify", binding_keys=["defense_plan", "attack_analysis"])
        await self.bus.subscribe("defense_plan", self.on_left)
        await self.bus.subscribe("attack_analysis", self.on_right)
        logger.info("[VerifyWorker] 已就绪，等待双脑输出...")

    async def on_left(self, msg: Message):
        alert_id = msg.payload.get("alert_id", msg.msg_id)
        entry = self.pending_alerts.setdefault(alert_id, {})
        entry["left"] = msg.payload
        entry["left_time"] = datetime.now()
        await self._try_fuse(alert_id)

    async def on_right(self, msg: Message):
        alert_id = msg.payload.get("alert_id", msg.msg_id)
        entry = self.pending_alerts.setdefault(alert_id, {})
        entry["right"] = msg.payload
        entry["right_time"] = datetime.now()
        await self._try_fuse(alert_id)

    async def _try_fuse(self, alert_id: str):
        entry = self.pending_alerts.get(alert_id)
        if not entry or "left" not in entry or "right" not in entry:
            return

        left = entry["left"]
        right = entry["right"]

        # 融合决策
        action = left.get("action", "monitor")
        left_conf = left.get("confidence", 0.5)
        right_conf = right.get("confidence", 0.5)
        fused_confidence = round((left_conf + right_conf) / 2, 2)

        # 冲突检测
        conflict = False
        if left.get("action") == "isolate" and right.get("threat_actor") == "未识别":
            conflict = True

        final_action = action
        if conflict and fused_confidence < 0.7:
            final_action = "monitor"
            logger.warning(f"[校验] 冲突检测: alert={alert_id}, 降级为 monitor")

        resp = Message(
            source="Validator",
            target="ip_isolation",
            msg_type="action_result",
            payload={
                "alert_id": alert_id,
                "action": final_action,
                "confidence": fused_confidence,
                "conflict": conflict,
                "source_ip": left.get("source_ip", ""),
                "reasoning": left.get("reasoning", ""),
                "threat_actor": right.get("threat_actor", ""),
                "attack_chain": right.get("attack_chain", ""),
                "timestamp": datetime.now().isoformat(),
            },
        )
        await self.bus.publish(resp)
        logger.info(
            f"[校验] 最终处置: {final_action} (置信度 {fused_confidence})"
        )

        # 清理
        del self.pending_alerts[alert_id]


async def main():
    worker = VerifyWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
