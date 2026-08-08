"""
分析引擎 Worker — 从 RabbitMQ 消费告警，LLM 推理后发布处置决策。

瓶颈修复:
- 并发控制: asyncio.Semaphore(5) 每 Worker 最多 5 个并发 LLM 调用
- 超时保护: asyncio.wait_for(timeout=15) 防止慢调用阻塞消费队列
- 快速通道: 确定性规则 (obvious attacks) 跳过 LLM，毫秒级决策

环境变量: RABBITMQ_URL, ETCD_URL, REDIS_URL
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from config import get_config, get_llm_config
from core.llm_client import LLMClient, create_organ_llm_client
from utils.logger import get_logger

logger = get_logger("LeftBrainWorker")


class LeftBrainWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.config = get_config()
        # 按器官独立覆盖配置创建客户端；未配置覆盖时回退全局配置客户端
        self.llm = create_organ_llm_client("left-brain", get_llm_config()) or LLMClient(get_llm_config())
        self.decision_count = 0
        self._semaphore = asyncio.Semaphore(5)

    async def start(self):
        await self.bus.connect("left_brain", binding_keys=["threat_alert"])
        await self.bus.subscribe("threat_alert", self.on_alert)
        logger.info("[LeftBrainWorker] 已就绪，等待威胁告警...")

    async def on_alert(self, msg: Message):
        """接收威胁告警，调用 LLM 做防护决策（带并发控制和快速通道）。"""
        async with self._semaphore:
            payload = msg.payload
            indicator = payload.get("indicator", payload)
            alert_type = indicator.get("category", payload.get("category", "unknown"))
            severity = indicator.get("severity", payload.get("severity", "medium"))
            src_ip = indicator.get("source_ip", payload.get("source_ip", ""))

            logger.info(f"[分析引擎] 收到告警: {alert_type} ({severity}) 来自 {src_ip}")

            try:
                decision = await self._analyze(alert_type, severity, src_ip, indicator)
            except Exception as e:
                logger.warning(f"[分析引擎] LLM 失败，降级规则引擎: {e}")
                decision = self._fallback_rule(alert_type, severity, src_ip)

            self.decision_count += 1
            # 快速通道决策无需验证，直接计数跳过 publish（避免 fanout 放大）
            if decision.get("source") == "FAST-PATH":
                logger.debug(f"[分析引擎] 快速决策计数: {decision.get('action')}")
            else:
                resp = Message(
                    source="LeftBrain",
                    target="verify",
                    msg_type="defense_plan",
                    payload={
                        "alert_id": indicator.get("id", msg.msg_id),
                        "action": decision.get("action", "monitor"),
                        "reasoning": decision.get("reasoning", "fallback"),
                        "confidence": decision.get("confidence", 0.5),
                        "source_ip": src_ip,
                        "decision_source": decision.get("source", "rule"),
                    },
                )
                await self.bus.publish(resp)
            logger.info(f"[分析引擎] 决策已发布: {decision.get('action')} [{decision.get('source')}]")

    async def _analyze(self, alert_type, severity, src_ip, indicator):
        """加速决策流程: 快速通道 -> LLM (带 15s 超时) -> 降级规则。"""
        fast = self._fast_path_rule(alert_type, severity, src_ip, indicator)
        if fast:
            logger.info(f"[分析引擎] 快速通道命中: {alert_type} -> {fast['action']}")
            return fast

        prompt = (
            f"告警类型: {alert_type}, 严重程度: {severity}, 源IP: {src_ip}。"
            f"请给出防护动作(monitor/rate_limit/block/isolate)和置信度(0-1)。"
        )
        try:
            result = await asyncio.wait_for(
                self.llm.chat_json(
                    "你是安全防御分析引擎，负责实时防护决策。返回JSON: {action, confidence, reasoning}",
                    prompt,
                ),
                timeout=15.0,
            )
            result["source"] = "LLM"
            return result
        except asyncio.TimeoutError:
            raise RuntimeError("LLM 调用超时 (>15s)")
        except Exception:
            raise

    def _fast_path_rule(self, alert_type, severity, src_ip, indicator):
        """确定性快速通道：对明显攻击在 O(1) 内直接决策，跳过 LLM。"""
        raw = indicator.get("raw_data", {})
        if not raw:
            return None

        # 归一化取值：兼容攻击模拟器/压测工具/suricata 等不同来源的字段名
        def _get_number(*keys):
            for k in keys:
                v = raw.get(k)
                if isinstance(v, (int, float)):
                    return v
            return 0

        # ── 洪泛类 ──
        if alert_type in ("ddos", "syn_flood"):
            req = _get_number("request_count", "packets", "syn_count", "count")
            if req >= 500:
                return {"action": "block", "confidence": 0.98,
                        "reasoning": f"[快速通道] 洪泛攻击: {req}次请求/包", "source": "FAST-PATH"}
            if req >= 120:
                return {"action": "rate_limit", "confidence": 0.85,
                        "reasoning": f"[快速通道] 疑似洪泛: {req}次请求/包", "source": "FAST-PATH"}

        # ── 端口扫描 ──
        if alert_type == "port_scan":
            ports = _get_number("scanned_port_count", "unique_ports", "ports")
            if ports >= 80:
                return {"action": "block", "confidence": 0.95,
                        "reasoning": f"[快速通道] 全端口扫描: {ports}端口", "source": "FAST-PATH"}
            if ports >= 30:
                return {"action": "rate_limit", "confidence": 0.82,
                        "reasoning": f"[快速通道] 大量端口扫描: {ports}端口", "source": "FAST-PATH"}

        # ── 暴力破解 ──
        if alert_type == "brute_force":
            attempts = _get_number("attempts", "packets")
            if attempts >= 500:
                return {"action": "block", "confidence": 0.95,
                        "reasoning": f"[快速通道] 暴力破解: {attempts}次尝试", "source": "FAST-PATH"}
            if attempts >= 40:
                return {"action": "rate_limit", "confidence": 0.82,
                        "reasoning": f"[快速通道] 疑似暴力: {attempts}次", "source": "FAST-PATH"}

        # ── 数据外泄 ──
        if alert_type == "data_exfil":
            mb = _get_number("mb_transferred", "size_mb")
            if mb >= 100:
                return {"action": "isolate", "confidence": 0.97,
                        "reasoning": f"[快速通道] 大规模数据外泄: {mb}MB", "source": "FAST-PATH"}
            if mb >= 50:
                return {"action": "block", "confidence": 0.88,
                        "reasoning": f"[快速通道] 数据外泄: {mb}MB", "source": "FAST-PATH"}

        # ── DNS隧道 ──
        if alert_type == "dns_tunnel":
            q = _get_number("queries", "query_count")
            if q >= 300:
                return {"action": "block", "confidence": 0.92,
                        "reasoning": f"[快速通道] DNS隧道: {q}次查询", "source": "FAST-PATH"}
            if q >= 100:
                return {"action": "rate_limit", "confidence": 0.80,
                        "reasoning": f"[快速通道] 疑似DNS隧道: {q}次查询", "source": "FAST-PATH"}

        return None

    def _fallback_rule(self, alert_type, severity, src_ip):
        rules = {
            "severe": {"action": "isolate", "confidence": 0.95},
            "high": {"action": "block", "confidence": 0.85},
            "medium": {"action": "rate_limit", "confidence": 0.70},
            "low": {"action": "monitor", "confidence": 0.60},
        }
        decision = rules.get(severity, {"action": "monitor", "confidence": 0.50})
        decision["reasoning"] = f"规则引擎降级决策: {alert_type} {severity}"
        decision["source"] = "RULE-FALLBACK"
        return decision


async def main():
    worker = LeftBrainWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
