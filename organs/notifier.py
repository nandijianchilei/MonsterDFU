"""
告警通知模块 — 支持企业微信/钉钉/飞书 Webhook 推送。

从 config.yaml 的 notify 节读取配置。
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Optional

import aiohttp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

logger = get_logger("Notifier")

# ── 消息模板 ──

BLOCK_TEMPLATE = """## 🚫 DFU 已封禁攻击 IP
> 告警ID: {alert_id}
> 攻击IP: **{ip}**
> 处置动作: {action}
> 时间: {timestamp}
> 已封禁数量: {blocked_count}
> 结果: {message}"""

RELEASE_TEMPLATE = """## ✅ DFU 已释放 IP
> 告警ID: {alert_id}
> 释放IP: **{ip}**
> 时间: {timestamp}
> 当前封禁数: {blocked_count}
> 结果: {message}"""

# ── 报警鼻 4 级警报模板 ──

ALARM_L2_TEMPLATE = """## 🔶 DFU 报警鼻 L2 级警报（需人工确认）
> 等级: **L2 - 需人工确认**
> 触发原因: {trigger}
> 告警数: {alert_count}
> 倒计时: {countdown_secs}s 内未确认将自动升级至 **L3**
> 时间: {timestamp}
> 请尽快在控制台确认或取消本次警报"""

ALARM_L3_TEMPLATE = """## 🟠 DFU 报警鼻 L3 级警报（紧急处置中）
> 等级: **L3 - 紧急**
> 触发原因: {trigger}
> 已执行: 关闭被攻击端口 / {action_summary}
> 倒计时: {countdown_secs}s 内未确认将自动升级至 **L4**
> 时间: {timestamp}
> 请立即在控制台确认或取消本次警报"""

ALARM_L4_TEMPLATE = """## 🔴 DFU 报警鼻 L4 级警报（最高威胁）
> 等级: **L4 - 最高威胁**
> 触发原因: {trigger}
> 已执行: 防火墙全封锁（软隔离）
> 执行倒计时: {countdown_secs}s 后强制执行软隔离
> 时间: {timestamp}
> 请在控制台确认执行或取消本次警报"""

ALARM_L4_EXECUTED_TEMPLATE = """## ⛔ DFU 报警鼻 L4 级已强制执行
> 等级: **L4 - 已强制执行软隔离**
> 触发原因: {trigger}
> 已执行: 防火墙全封锁（软隔离，复用 FSM 机制）
> 时间: {timestamp}
> 系统已进入最高防护状态，请立即人工介入"""


class Notifier:
    """
    异步 Webhook 通知发送器。

    支持企业微信机器人、钉钉机器人、飞书机器人等兼容 markdown 格式的 webhook。
    """

    def __init__(self):
        self._webhook_urls: list[str] = []
        self._enabled: bool = False
        self._session: Optional[aiohttp.ClientSession] = None
        self._load_config()

    def _load_config(self):
        """从 config.yaml 读取通知配置。"""
        try:
            import yaml
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "config.yaml",
            )
            with open(config_path, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f) or {}
            notify_cfg = yaml_data.get("notify", {})

            self._enabled = notify_cfg.get("enabled", False)
            self._webhook_urls = notify_cfg.get("webhook_urls", [])

            if self._enabled and self._webhook_urls:
                logger.info(f"[Notifier] 已启用，{len(self._webhook_urls)} 个 webhook 目标")
            elif self._enabled:
                logger.warning("[Notifier] 已启用但未配置 webhook_urls")
            else:
                logger.info("[Notifier] 通知功能未启用")
        except Exception:
            self._enabled = False
            self._webhook_urls = []
            logger.info("[Notifier] 通知功能未启用（无配置）")

    @property
    def enabled(self) -> bool:
        return self._enabled and bool(self._webhook_urls)

    async def _ensure_session(self):
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
            )

    async def send_block_alert(
        self,
        alert_id: str,
        ip: str,
        action: str,
        message: str,
        blocked_count: int,
    ):
        """发送封禁告警通知。"""
        if not self.enabled:
            return

        text = BLOCK_TEMPLATE.format(
            alert_id=alert_id,
            ip=ip,
            action=action,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            blocked_count=blocked_count,
            message=message[:200],
        )
        await self._send_all(text)

    async def send_release_alert(
        self,
        alert_id: str,
        ip: str,
        message: str,
        blocked_count: int,
    ):
        """发送释放告警通知。"""
        if not self.enabled:
            return

        text = RELEASE_TEMPLATE.format(
            alert_id=alert_id,
            ip=ip,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            blocked_count=blocked_count,
            message=message[:200],
        )
        await self._send_all(text)

    async def send_alarm_alert(
        self,
        level: str,
        trigger: str,
        alert_count: int = 0,
        countdown_secs: float = 0.0,
        action_summary: str = "",
    ):
        """发送报警鼻 4 级警报通知。

        Args:
            level: 警报级别，取值 L2 / L3 / L4 / L4_EXECUTED
            trigger: 触发原因描述
            alert_count: 触发告警数量（L2 使用）
            countdown_secs: 倒计时秒数（L2/L3/L4 使用）
            action_summary: 已执行动作摘要（L3 使用）
        """
        if not self.enabled:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        template_map = {
            "L2": ALARM_L2_TEMPLATE,
            "L3": ALARM_L3_TEMPLATE,
            "L4": ALARM_L4_TEMPLATE,
            "L4_EXECUTED": ALARM_L4_EXECUTED_TEMPLATE,
        }
        template = template_map.get(level, ALARM_L2_TEMPLATE)

        if level == "L2":
            text = template.format(
                trigger=trigger[:200],
                alert_count=alert_count,
                countdown_secs=int(countdown_secs),
                timestamp=timestamp,
            )
        elif level == "L3":
            text = template.format(
                trigger=trigger[:200],
                action_summary=action_summary[:200],
                countdown_secs=int(countdown_secs),
                timestamp=timestamp,
            )
        elif level == "L4":
            text = template.format(
                trigger=trigger[:200],
                countdown_secs=int(countdown_secs),
                timestamp=timestamp,
            )
        else:  # L4_EXECUTED
            text = template.format(
                trigger=trigger[:200],
                timestamp=timestamp,
            )
        await self._send_all(text)

    async def _send_all(self, text: str):
        """向所有 webhook 发送消息。"""
        await self._ensure_session()
        payload = {
            "msgtype": "markdown",
            "markdown": {"content": text},
        }
        tasks = [
            self._send_one(url, payload)
            for url in self._webhook_urls
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_one(self, url: str, payload: dict):
        """向单个 webhook 发送 POST 请求。"""
        try:
            async with self._session.post(url, json=payload) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    logger.error(
                        f"[Notifier] webhook 发送失败 {url[:60]}: "
                        f"HTTP {resp.status} | {body[:200]}"
                    )
                else:
                    logger.debug(f"[Notifier] webhook 发送成功 {url[:60]}")
        except Exception as e:
            logger.error(f"[Notifier] webhook 异常 {url[:60]}: {e}")

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None


# ── 全局单例 ──

_notifier: Optional[Notifier] = None


def get_notifier() -> Notifier:
    global _notifier
    if _notifier is None:
        _notifier = Notifier()
    return _notifier
