"""
独立抓包服务入口 —— 供 Docker capturer 容器使用。

启动一个仅包含 PacketCapture 模块的轻量进程，
将实时抓包数据馈入 dfu 检测管线（通过 RabbitMQ 消息总线）。
网络模式需设为 host（scapy 需要原生套接字权限）。
"""

import asyncio
import logging
import sys

from communication.message_bus import get_message_bus
from config import get_config
from organs.capturer import PacketCapture

logger = logging.getLogger("capturer_entry")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)


async def main() -> None:
    bus = get_message_bus()
    config = get_config()

    capturer = PacketCapture(bus, config)
    capturer.set_port_filter([4444, 8443, 31337, 10443, 18443, 443, 80])
    capturer.enable_detection_feed()

    logger.info("Capturer 服务启动中...")
    capturer.start()
    logger.info("Capturer 服务已启动，进入常驻运行状态")

    try:
        while True:
            await asyncio.sleep(5)
            stats = capturer.stats
            logger.info(
                "[心跳] 已发布 %d 事件 | 解析 %d 包 | 过滤放弃 %d",
                stats.get("published_events", 0),
                stats.get("packets_parsed", 0),
                stats.get("filtered_dropped", 0),
            )
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("正在停止 Capturer...")
        await capturer.stop()
        logger.info("Capturer 已停止")


if __name__ == "__main__":
    asyncio.run(main())
