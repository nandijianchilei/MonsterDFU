"""
内存消息总线 (message_bus) 单元测试
覆盖：Message 序列化/反序列化、发布/订阅/回调、取消订阅、异常处理器隔离、
handler 返回消息自动级联发布、请求-响应模式、历史记录、全局单例。
"""

import asyncio
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from communication.message_bus import Message, MessageBus, get_message_bus


class TestMessage(unittest.TestCase):
    """消息数据结构与序列化"""

    def test_default_fields(self):
        msg = Message(source="a", target="b", type="alert", payload={"x": 1})
        self.assertEqual(msg.source, "a")
        self.assertEqual(msg.target, "b")
        self.assertEqual(msg.type, "alert")
        self.assertIsNotNone(msg.msg_id)
        self.assertIsNotNone(msg.timestamp)
        self.assertIsNone(msg.reply_to)

    def test_to_dict_roundtrip(self):
        msg = Message(
            source="a", target="b", type="alert",
            payload={"k": "v"}, reply_to="req-1",
        )
        d = msg.to_dict()
        restored = Message.from_dict(d)
        self.assertEqual(restored.source, msg.source)
        self.assertEqual(restored.target, msg.target)
        self.assertEqual(restored.type, msg.type)
        self.assertEqual(restored.payload, msg.payload)
        self.assertEqual(restored.msg_id, msg.msg_id)
        self.assertEqual(restored.reply_to, "req-1")

    def test_json_roundtrip(self):
        msg = Message(source="a", target="*", type="decision", payload=[1, 2, 3])
        restored = Message.from_json(msg.to_json())
        self.assertEqual(restored.source, "a")
        self.assertEqual(restored.payload, [1, 2, 3])
        self.assertEqual(restored.msg_id, msg.msg_id)

    def test_from_dict_missing_optional(self):
        msg = Message.from_dict({"source": "a", "target": "b", "type": "t", "payload": None})
        self.assertIsNotNone(msg.msg_id)

    def test_unique_msg_ids(self):
        m1 = Message(source="a", target="b", type="t", payload={})
        m2 = Message(source="a", target="b", type="t", payload={})
        self.assertNotEqual(m1.msg_id, m2.msg_id)


class TestMessageBusSubscribePublish(unittest.TestCase):
    """发布/订阅/回调"""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_publish_by_type(self):
        async def scenario():
            bus = MessageBus()
            received = []

            async def handler(msg):
                received.append(msg)

            await bus.subscribe("alert", handler)
            tasks = await bus.publish(Message(source="a", target="*", type="alert", payload={}))
            await asyncio.gather(*tasks)
            self.assertEqual(len(received), 1)
            self.assertEqual(received[0].type, "alert")

        self._run(scenario())

    def test_publish_by_target(self):
        async def scenario():
            bus = MessageBus()
            received = []

            async def handler(msg):
                received.append(msg)

            await bus.subscribe("left-brain", handler)
            tasks = await bus.publish(Message(source="right-brain", target="left-brain", type="any", payload={}))
            await asyncio.gather(*tasks)
            self.assertEqual(len(received), 1)

        self._run(scenario())

    def test_publish_wildcard(self):
        async def scenario():
            bus = MessageBus()
            received = []

            async def handler(msg):
                received.append(msg)

            await bus.subscribe("*", handler)
            tasks = await bus.publish(Message(source="a", target="b", type="whatever", payload={}))
            await asyncio.gather(*tasks)
            self.assertEqual(len(received), 1)

        self._run(scenario())

    def test_non_matching_topic_not_delivered(self):
        async def scenario():
            bus = MessageBus()
            received = []

            async def handler(msg):
                received.append(msg)

            await bus.subscribe("other", handler)
            tasks = await bus.publish(Message(source="a", target="b", type="alert", payload={}))
            await asyncio.gather(*tasks)
            self.assertEqual(len(received), 0)

        self._run(scenario())

    def test_unsubscribe(self):
        async def scenario():
            bus = MessageBus()
            received = []

            async def handler(msg):
                received.append(msg)

            await bus.subscribe("alert", handler)
            await bus.unsubscribe("alert", handler)
            tasks = await bus.publish(Message(source="a", target="b", type="alert", payload={}))
            await asyncio.gather(*tasks)
            self.assertEqual(len(received), 0)

        self._run(scenario())

    def test_unsubscribe_missing_handler_no_error(self):
        async def scenario():
            bus = MessageBus()
            await bus.unsubscribe("never-subscribed", lambda m: None)

        self._run(scenario())

    def test_handler_exception_isolated(self):
        async def scenario():
            bus = MessageBus()
            received = []

            async def bad_handler(msg):
                raise RuntimeError("boom")

            async def good_handler(msg):
                received.append(msg)

            await bus.subscribe("alert", bad_handler)
            await bus.subscribe("alert", good_handler)
            tasks = await bus.publish(Message(source="a", target="b", type="alert", payload={}))
            await asyncio.gather(*tasks)  # 异常被吞掉，不影响其他处理器与发布
            self.assertEqual(len(received), 1)
            self.assertEqual(len(bus.get_history()), 1)

        self._run(scenario())

    def test_sync_handler_supported(self):
        async def scenario():
            bus = MessageBus()
            received = []

            def handler(msg):
                received.append(msg)

            await bus.subscribe("alert", handler)
            tasks = await bus.publish(Message(source="a", target="b", type="alert", payload={}))
            await asyncio.gather(*tasks)
            self.assertEqual(len(received), 1)

        self._run(scenario())

    def test_handler_return_message_cascades(self):
        """handler 返回 Message 时自动发布到总线（级联）"""
        async def scenario():
            bus = MessageBus()
            received = []

            async def responder(msg):
                if msg.type == "request":
                    return Message(source="worker", target="*", type="response", payload={"ok": True})
                received.append(msg)

            await bus.subscribe("request", responder)
            await bus.subscribe("response", responder)
            tasks = await bus.publish(Message(source="client", target="*", type="request", payload={}))
            await asyncio.gather(*tasks)
            self.assertEqual(len(received), 1)
            self.assertEqual(received[0].type, "response")

        self._run(scenario())

    def test_history_recorded(self):
        async def scenario():
            bus = MessageBus()
            await bus.publish(Message(source="a", target="b", type="alert", payload={"n": 1}))
            await bus.publish(Message(source="a", target="b", type="alert", payload={"n": 2}))
            history = bus.get_history()
            self.assertEqual(len(history), 2)
            self.assertEqual(history[-1]["payload"], {"n": 2})

        self._run(scenario())

    def test_history_limit(self):
        async def scenario():
            bus = MessageBus()
            for i in range(1100):
                await bus.publish(Message(source="a", target="b", type="t", payload=i))
            self.assertEqual(len(bus.get_history(limit=2000)), 1000)

        self._run(scenario())


class TestMessageBusRequestReply(unittest.TestCase):
    """请求-响应模式"""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_request_reply(self):
        async def scenario():
            bus = MessageBus()

            async def responder(msg):
                if msg.type == "query":
                    return Message(
                        source="worker", target="client", type="response",
                        payload={"result": 42}, reply_to=msg.msg_id,
                    )

            await bus.subscribe("query", responder)
            req = Message(source="client", target="*", type="query", payload={"q": "meaning"})
            resp = await bus.request(req, timeout=1.0)
            self.assertIsNotNone(resp)
            self.assertEqual(resp.type, "response")
            self.assertEqual(resp.payload, {"result": 42})
            self.assertEqual(resp.reply_to, req.msg_id)

        self._run(scenario())

    def test_request_timeout(self):
        async def scenario():
            bus = MessageBus()  # 无订阅者
            resp = await bus.request(
                Message(source="client", target="*", type="query", payload={}),
                timeout=0.05,
            )
            self.assertIsNone(resp)

        self._run(scenario())


class TestGlobalBus(unittest.TestCase):
    """全局总线单例"""

    def test_singleton(self):
        bus1 = get_message_bus()
        bus2 = get_message_bus()
        self.assertIs(bus1, bus2)
        self.assertIsInstance(bus1, MessageBus)


if __name__ == "__main__":
    unittest.main()
