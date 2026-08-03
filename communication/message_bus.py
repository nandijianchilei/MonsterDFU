"""
消息总线模块
实现简化的异步消息总线，支持 Agent 之间发布/订阅模式。
消息格式统一为 JSON，包含字段：source, target, type, payload, timestamp
支持请求-响应模式（Request-Reply）。
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("MessageBus")


@dataclass
class Message:
    """
    统一消息格式，所有 Agent 间通信均使用此格式。

    Fields:
        source:    消息来源 Agent 名称
        target:    消息目标 Agent 名称（广播时为 '*'）
        type:      消息类型（如 'alert', 'decision', 'action', 'response'）
        payload:   消息负载（任意 JSON 可序列化对象）
        timestamp: 消息生成时间戳（ISO 8601 格式字符串）
        msg_id:    消息唯一标识
        reply_to:  若为响应消息，填写原消息的 msg_id
    """
    source: str
    target: str
    type: str
    payload: Any
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    msg_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    reply_to: Optional[str] = None

    def to_dict(self) -> dict:
        """序列化为字典。"""
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
        """序列化为 JSON 字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)

    @classmethod
    def from_dict(cls, data: dict) -> "Message":
        """从字典反序列化。"""
        return cls(
            source=data["source"],
            target=data["target"],
            type=data["type"],
            payload=data["payload"],
            timestamp=data.get("timestamp"),
            msg_id=data.get("msg_id", str(uuid.uuid4())),
            reply_to=data.get("reply_to"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Message":
        """从 JSON 字符串反序列化。"""
        return cls.from_dict(json.loads(json_str))


# 消息处理器类型：接收 Message，返回可选的响应 Message
MessageHandler = Callable[[Message], Optional[Message]]


class MessageBus:
    """
    异步消息总线，支持发布/订阅模式和请求/响应模式。

    架构说明：
    - 每个 Agent 通过 subscribe() 注册感兴趣的消息类型或目标名称
    - publish() 将消息推送给所有匹配的订阅者
    - request() 发送消息并等待第一个匹配的响应（通过 reply_to 关联）
    """

    def __init__(self):
        # topic -> list of handlers
        self._subscribers: Dict[str, List[MessageHandler]] = {}
        # pending requests: msg_id -> Future
        self._pending_requests: Dict[str, asyncio.Future] = {}
        # 消息历史（用于调试）
        self._history: List[Message] = []
        self._history_max_len: int = 1000
        self._lock = asyncio.Lock()

    async def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """
        订阅某个主题。topic 可以是消息的 type 字段，也可以是 target 字段。

        Args:
            topic:   订阅主题（消息 type 或 target）
            handler: 消息处理函数，接收 Message，可返回响应 Message
        """
        async with self._lock:
            if topic not in self._subscribers:
                self._subscribers[topic] = []
            self._subscribers[topic].append(handler)

    async def unsubscribe(self, topic: str, handler: MessageHandler) -> None:
        """取消订阅。"""
        async with self._lock:
            if topic in self._subscribers:
                try:
                    self._subscribers[topic].remove(handler)
                except ValueError:
                    pass

    async def publish(self, msg: Message) -> List[asyncio.Task]:
        """
        发布消息，异步通知所有匹配的订阅者。

        Args:
            msg: 要发布的消息

        Returns:
            所有订阅者处理任务的列表
        """
        async with self._lock:
            self._add_to_history(msg)
            # 匹配规则：订阅 topic == msg.type 或 topic == msg.target 或 topic == '*'
            matched_handlers = []
            for topic, handlers in self._subscribers.items():
                if topic in (msg.type, msg.target, "*"):
                    matched_handlers.extend(handlers)

        # 异步执行所有处理器
        tasks = []
        for handler in matched_handlers:
            task = asyncio.create_task(self._safe_handle(handler, msg))
            tasks.append(task)

        # 检查是否有匹配的响应（request-reply 模式）
        if msg.reply_to and msg.reply_to in self._pending_requests:
            future = self._pending_requests.pop(msg.reply_to)
            if not future.done():
                future.set_result(msg)

        return tasks

    async def _safe_handle(self, handler: MessageHandler, msg: Message) -> None:
        """安全调用处理器，捕获异常。若处理器返回 Message 则自动 publish 到总线上。"""
        try:
            result = handler(msg)
            if asyncio.iscoroutine(result):
                result = await result
            # 若处理器返回了 Message，自动发布到总线（实现 Agent 间级联通信）
            if result is not None and isinstance(result, Message):
                await self.publish(result)
        except Exception as e:
            logger.exception("[MessageBus] 处理器异常: %s", e)

    async def request(
        self,
        msg: Message,
        timeout: float = 30.0,
    ) -> Optional[Message]:
        """
        请求-响应模式：发送消息并等待响应。

        Args:
            msg:     请求消息（会自动设置 msg_id 用于关联响应）
            timeout: 超时时间（秒）

        Returns:
            响应消息，超时返回 None
        """
        future = asyncio.get_event_loop().create_future()
        self._pending_requests[msg.msg_id] = future

        # 发布请求消息
        await self.publish(msg)

        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            return response
        except asyncio.TimeoutError:
            # 清理
            self._pending_requests.pop(msg.msg_id, None)
            return None

    def _add_to_history(self, msg: Message) -> None:
        """将消息加入历史记录。"""
        self._history.append(msg)
        if len(self._history) > self._history_max_len:
            self._history = self._history[-self._history_max_len:]

    def get_history(self, limit: int = 50) -> List[dict]:
        """获取最近的历史消息（字典格式）。"""
        msgs = self._history[-limit:]
        return [m.to_dict() for m in msgs]


# 全局消息总线实例（单例）
_global_bus: Optional[MessageBus] = None


def get_message_bus() -> MessageBus:
    """获取全局消息总线实例。"""
    global _global_bus
    if _global_bus is None:
        _global_bus = MessageBus()
    return _global_bus
