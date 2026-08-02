"""
响应引擎 Worker — 从 RabbitMQ 消费告警，做溯源分析和关联推理。

瓶颈修复:
- 并发控制: asyncio.Semaphore(5) 每 Worker 最多 5 个并发 LLM 调用
- 超时保护: asyncio.wait_for(timeout=20) 防止慢调用阻塞

环境变量: RABBITMQ_URL
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from config import Config, get_config
from core.llm_client import LLMClient
from utils.logger import get_logger

logger = get_logger("RightBrainWorker")


class RightBrainWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.config = get_config()
        self.llm = LLMClient(self.config.llm)
        self.analysis_count = 0
        self._semaphore = asyncio.Semaphore(5)

    async def start(self):
        await self.bus.connect("right_brain", binding_keys=["threat_alert"])
        await self.bus.subscribe("threat_alert", self.on_alert)
        logger.info("[RightBrainWorker] 已就绪，等待威胁告警...")

    async def on_alert(self, msg: Message):
        async with self._semaphore:
            payload = msg.payload
            indicator = payload.get("indicator", payload)
            alert_type = indicator.get("category", payload.get("category", "unknown"))
            severity = indicator.get("severity", payload.get("severity", "medium"))
            src_ip = indicator.get("source_ip", payload.get("source_ip", ""))

            logger.info(f"[响应引擎] 收到告警: {alert_type} 来自 {src_ip}")

            try:
                analysis = await self._analyze(alert_type, severity, src_ip, indicator)
            except Exception as e:
                logger.warning(f"[响应引擎] LLM 失败，降级: {e}")
                analysis = self._fallback_analysis(alert_type, severity, src_ip)

            self.analysis_count += 1
            resp = Message(
                source="RightBrain",
                target="verify",
                msg_type="attack_analysis",
                payload={
                    "alert_id": indicator.get("id", msg.msg_id),
                    "attack_chain": analysis.get("attack_chain", "unknown"),
                    "threat_actor": analysis.get("threat_actor", "unknown"),
                    "confidence": analysis.get("confidence", 0.5),
                    "source_ip": src_ip,
                    "analysis_source": analysis.get("source", "rule"),
                },
            )
            await self.bus.publish(resp)
            logger.info(f"[响应引擎] 分析已发布: {analysis.get('threat_actor')}")

    async def _analyze(self, alert_type, severity, src_ip, indicator):
        prompt = (
            f"告警类型: {alert_type}, 严重程度: {severity}, 源IP: {src_ip}。"
            f"请做溯源分析，返回JSON: {attack_chain, threat_actor, confidence}"
        )
        try:
            result = await asyncio.wait_for(
                self.llm.chat_json(
                    "你是安全防御响应引擎，负责威胁溯源和关联分析。返回JSON格式。",
                    prompt,
                ),
                timeout=20.0,
            )
            result["source"] = "LLM"
            return result
        except asyncio.TimeoutError:
            raise RuntimeError(f"LLM 调用超时 (>20s)")
        except Exception:
            raise

    def _fallback_analysis(self, alert_type, severity, src_ip):
        base = {
            "attack_chain": f"单一节点攻击 ({alert_type})",
            "threat_actor": "未识别",
            "confidence": 0.5,
            "source": "RULE-FALLBACK",
        }
        if severity in ("severe", "high"):
            base["attack_chain"] = f"疑似APT攻击链 ({alert_type})"
            base["threat_actor"] = "高级持续性威胁"
            base["confidence"] = 0.7
        return base


async def main():
    worker = RightBrainWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
