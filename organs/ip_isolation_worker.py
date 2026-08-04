"""
IP 隔离 Worker — 执行 IP 黑名单/防火墙规则下发。

环境变量: RABBITMQ_URL
支持真实防火墙执行（iptables / Windows Firewall）或模拟。

读取 config.yaml 中 isolation.real_exec 来决定模拟/真实模式。
"""

import asyncio
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from organs.firewall_executor import FirewallExecutor
from organs.notifier import get_notifier
from utils.logger import get_logger

logger = get_logger("IPIsolationWorker")


class IPIsolationWorker:
    """
    IP 隔离 Worker。
    监听 action_result 消息，执行防火墙操作并记录隔离状态。
    """

    def __init__(self):
        self.bus = RabbitMQBus()
        self.blocked_ips: set = set()
        self.isolation_count = 0

        # 从 config.yaml 直接读取隔离配置（Config dataclass 未包含 isolation 字段）
        import yaml
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yaml")
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f) or {}
            iso_cfg = yaml_data.get("isolation", {})
            real_exec = iso_cfg.get("real_exec", False)
        except Exception:
            real_exec = False

        self._fw = FirewallExecutor(logger=logger, real_exec=real_exec)
        self._notifier = get_notifier()

    async def start(self):
        await self.bus.connect("organ_ip")
        await self.bus.subscribe("action_result", self.on_action)
        logger.info("[IPIsolationWorker] 已就绪，等待处置指令...")

    async def on_action(self, msg: Message):
        """
        处理动作结果消息，执行防火墙操作并记录隔离状态。

        Args:
            msg: action_result 消息
        """
        payload = msg.payload
        action = payload.get("action", "monitor")
        target_ip = payload.get("target_ip", payload.get("source_ip", ""))
        alert_id = payload.get("alert_id", "")
        message = payload.get("message", "")

        if action in ("block", "isolate", "isolate_ip", "ban"):
            # 执行真实/模拟防火墙操作
            result = await self._fw.block_ip(target_ip, reason=message)
            success = result.success

            if success:
                self.blocked_ips.add(target_ip)
            self.isolation_count += 1

            status = "已封禁" if success else "封禁失败"
            logger.info(
                f"[IP隔离] #{self.isolation_count}: {target_ip} {status} "
                f"(告警 {alert_id}) | {result.message[:80]}"
            )

            # 发布隔离日志
            report = Message(
                source="IPIsolation",
                target="*",
                msg_type="isolation_log",
                payload={
                    "ip": target_ip,
                    "action": action,
                    "alert_id": alert_id,
                    "success": success,
                    "result_message": result.message,
                    "blocked_count": len(self.blocked_ips),
                    "timestamp": datetime.now().isoformat(),
                },
            )
            await self.bus.publish(report)

            # 异步发送告警通知（不阻塞处置主流程）
            asyncio.create_task(
                self._notifier.send_block_alert(
                    alert_id=alert_id,
                    ip=target_ip,
                    action=action,
                    message=result.message,
                    blocked_count=len(self.blocked_ips),
                )
            )

        elif action == "release":
            result = await self._fw.release_ip(target_ip)
            if result.success:
                self.blocked_ips.discard(target_ip)
            logger.info(f"[IP隔离] 已释放: {target_ip} (告警 {alert_id}) | {result.message[:80]}")

            # 异步发送释放通知
            asyncio.create_task(
                self._notifier.send_release_alert(
                    alert_id=alert_id,
                    ip=target_ip,
                    message=result.message,
                    blocked_count=len(self.blocked_ips),
                )
            )

        else:
            logger.debug(f"[IP隔离] 跳过 {target_ip}: 动作为 {action} | {message[:60]}")

    def get_state(self) -> dict:
        """获取当前 Worker 状态。"""
        return {
            "blocked_count": len(self.blocked_ips),
            "isolation_count": self.isolation_count,
            "blocked_ips": sorted(self.blocked_ips),
        }


async def main():
    worker = IPIsolationWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
