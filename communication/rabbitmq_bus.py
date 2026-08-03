"""
RabbitMQ 消息总线 — 分布式模式下的消息通信后端。

基于 aio-pika，保持与 MessageBus 相同的事件语义：
- publish(msg) → 发布到 AMQP fanout exchange
- subscribe(topic, handler) → 绑定队列消费
- request(msg, timeout) → RPC 请求-响应

配置来源（优先级由高到低）：
    1. 构造函数 url 参数
    2. 环境变量 RABBITMQ_URL
    3. config.yaml 中的 rabbitmq.url
    4. 硬编码默认值（仅兜底）
"""

import asyncio
import json
import os
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger("RabbitMQBus")

MessageHandler = Callable[["Message"], Optional["Message"]]


class Message:
    """与本地 MessageBus 兼容的消息格式。"""

    def __init__(
        self,
        source: str,
        target: str = "*",
        msg_type: str = "alert",
        payload: Any = None,
        timestamp: Optional[str] = None,
        msg_id: Optional[str] = None,
        reply_to: Optional[str] = None,
    ):
        self.source = source
        self.target = target
        self.type = msg_type
        self.payload = payload or {}
        self.timestamp = timestamp or datetime.now().isoformat()
        self.msg_id = msg_id or str(uuid.uuid4())
        self.reply_to = reply_to

    def to_dict(self) -> dict:
        return {
            "msg_id": self.msg_id,
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "reply_to": self.reply_to,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)

    @classmethod
    def from_dict(cls, data: dict) -> "Message":
        return cls(
            source=data.get("source", "unknown"),
            target=data.get("target", "*"),
            msg_type=data.get("type", "alert"),
            payload=data.get("payload", {}),
            timestamp=data.get("timestamp"),
            msg_id=data.get("msg_id"),
            reply_to=data.get("reply_to"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Message":
        return cls.from_dict(json.loads(json_str))


class RabbitMQBus:
    """
    基于 RabbitMQ 的分布式消息总线。

    使用 topic exchange 按 msg_type 路由消息（替代 fanout），
    每个 worker 通过 binding keys 订阅感兴趣的消息类型，
    消除 fanout 10× 放大。

    消息类型 → 路由键:
      threat_alert  → 分析引擎、响应引擎、器官
      defense_plan  → verify、attack_simulator、器官
      heartbeat     → 所有器官
    """

    EXCHANGE_NAME = "dfu.events"
    DLX_EXCHANGE = "dfu.dlx"
    DLQ_NAME = "dfu.dead"
    RPC_EXCHANGE = "dfu.rpc"
    MAX_RETRIES = 3

    def __init__(self, url: Optional[str] = None):
        if url:
            self._url = url
        elif os.environ.get("RABBITMQ_URL"):
            self._url = os.environ["RABBITMQ_URL"]
        else:
            try:
                from config import get_config
                self._url = get_config().rabbitmq_url
            except Exception:
                self._url = "amqp://dfu:K7mP2xW9qR5tN8bL4jH1@localhost:5672/"
        self._connection = None
        self._channel = None
        self._exchange = None
        self._direct_exchange = None
        self._queue = None
        self._consumer_tag = None
        self._handlers: Dict[str, List[MessageHandler]] = {}
        self._running = False
        self._pending_rpc: Dict[str, asyncio.Future] = {}
        self._history: List[Message] = []
        self._history_max = 500

    # ── 连接 ──

    async def connect(
        self,
        service_name: str = "worker",
        binding_keys: list = None,
    ) -> None:
        """建立 RabbitMQ 连接，声明 topic exchange、DLX 和队列。

        Args:
            service_name: 服务名，用于队列命名
            binding_keys: 绑定路由键列表，如 ['threat_alert', 'defense_plan']。
                          默认 ['#'] 接收所有消息。空列表不会绑定任何 key。
        """
        import aio_pika

        if binding_keys is None:
            binding_keys = ["#"]

        retries = 0
        while True:
            try:
                self._connection = await aio_pika.connect_robust(self._url)
                self._channel = await self._connection.channel()

                # 声明 DLX（死信交换机）
                self._dlx_exchange = await self._channel.declare_exchange(
                    self.DLX_EXCHANGE,
                    aio_pika.ExchangeType.TOPIC,
                    durable=True,
                )
                # 声明死信队列
                self._dlq = await self._channel.declare_queue(
                    self.DLQ_NAME, durable=True,
                )
                await self._dlq.bind(self._dlx_exchange, routing_key="#")

                self._exchange = await self._channel.declare_exchange(
                    self.EXCHANGE_NAME,
                    aio_pika.ExchangeType.TOPIC,
                    durable=True,
                )
                # 声明独占队列，绑定 DLX
                queue_name = f"dfu.{service_name}.{uuid.uuid4().hex[:6]}"
                self._queue = await self._channel.declare_queue(
                    queue_name,
                    auto_delete=True,
                    arguments={
                        "x-dead-letter-exchange": self.DLX_EXCHANGE,
                    },
                )
                for key in binding_keys:
                    await self._queue.bind(self._exchange, routing_key=key)
                self._consumer_tag = await self._queue.consume(self._on_message)
                self._running = True
                logger.info(
                    f"[RabbitMQBus] 已连接: {self._url} -> queue={queue_name} keys={binding_keys}"
                )
                break
            except Exception as e:
                retries += 1
                wait = min(retries * 2, 30)
                logger.warning(
                    f"[RabbitMQBus] 连接失败 (重试 {retries}, {wait}s): {e}"
                )
                await asyncio.sleep(wait)

    async def disconnect(self) -> None:
        """断开连接。"""
        self._running = False
        try:
            if self._consumer_tag:
                await self._queue.cancel(self._consumer_tag)
            if self._channel:
                await self._channel.close()
            if self._connection:
                await self._connection.close()
        except Exception:
            pass

    # ── 发布/订阅 ──

    async def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """注册消息处理器。topic 匹配 msg.type / msg.target / '*'。"""
        if topic not in self._handlers:
            self._handlers[topic] = []
        self._handlers[topic].append(handler)
        logger.debug(f"[RabbitMQBus] 订阅 '{topic}' -> {handler.__name__}")

    async def publish(self, msg: Message, delivery_mode: int = 1) -> None:
        """发布消息到 topic exchange。
        
        路由键 = msg.type（如 threat_alert / defense_plan / heartbeat）。
        delivery_mode=1 非持久化，减轻 Broker 压力。
        """
        import aio_pika
        body = msg.to_json().encode("utf-8")
        routing_key = msg.type or ""
        await self._exchange.publish(
            aio_pika.Message(body=body, delivery_mode=delivery_mode),
            routing_key=routing_key,
        )

    async def request(self, msg: Message, timeout: float = 30.0) -> Optional[Message]:
        """RPC 请求-响应（简化版：通过消息总线级联实现）。"""
        future = asyncio.get_event_loop().create_future()
        self._pending_rpc[msg.msg_id] = future
        await self.publish(msg)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_rpc.pop(msg.msg_id, None)
            return None

    # ── 消费循环 ──

    async def _on_message(self, message) -> None:
        """RabbitMQ 消息到达回调。支持 DLX + N 次重试。"""

        async with message.process():
            try:
                # 读取重试计数（存储在 x-death 头中）
                retry_count = 0
                if message.headers and "x-death" in message.headers:
                    death_list = message.headers["x-death"]
                    if death_list:
                        retry_count = death_list[0].get("count", 0)

                body = message.body.decode("utf-8")
                msg = Message.from_json(body)

                # 响应关联
                if msg.reply_to and msg.reply_to in self._pending_rpc:
                    future = self._pending_rpc.pop(msg.reply_to)
                    if not future.done():
                        future.set_result(msg)

                # 路由到处理器
                matched = []
                for topic, handlers in self._handlers.items():
                    if topic in (msg.type, msg.target, "*"):
                        matched.extend(handlers)

                for handler in matched:
                    try:
                        result = handler(msg)
                        if asyncio.iscoroutine(result):
                            result = await result
                        if isinstance(result, Message):
                            await self.publish(result)
                    except Exception as e:
                        logger.error(f"[Handler] {handler.__name__} 异常: {e}")
                        # 未耗尽重试次数 → nack+requeue（由 DLX 机制处理）
                        if retry_count < self.MAX_RETRIES:
                            await message.reject(requeue=False)
                            return
                        # 已耗尽 → 已在 DLX 路径上，由 RabbitMQ 自动路由到 DLQ

                # 历史
                self._history.append(msg)
                if len(self._history) > self._history_max:
                    self._history = self._history[-self._history_max:]

            except Exception as e:
                logger.error(f"[RabbitMQBus] 消息处理异常: {e}")
                # 解析/路由异常也走 DLX 重试
                if message.headers and "x-death" in (message.headers or {}):
                    death_list = message.headers.get("x-death", [])
                    retry_count = death_list[0].get("count", 0) if death_list else 0
                else:
                    retry_count = 0
                if retry_count < self.MAX_RETRIES:
                    await message.reject(requeue=False)
                # 超过重试次数后由 RabbitMQ 自动投递到 DLQ

    def get_history(self, limit: int = 50) -> List[dict]:
        return [m.to_dict() for m in self._history[-limit:]]

    @property
    def is_connected(self) -> bool:
        return self._running
