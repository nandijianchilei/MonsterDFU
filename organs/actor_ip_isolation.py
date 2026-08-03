"""
处置Agent：IP隔离模块
接收双脑下发的隔离指令，执行 IP 封禁/释放操作。

支持三种模式（由 config.yaml → isolation.real_exec 控制）：
- real_exec=true: 真实调用 iptables（Linux）/ Windows Firewall
- real_exec=false: 模拟执行（内存黑名单，默认）

支持动作：block / isolate / isolate_ip / ban / release / rate_limit / monitor
"""

import asyncio
import ipaddress
import json
import logging
import random
import time
from pathlib import Path
from typing import Optional

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config
from utils.logger import get_logger
from organs.firewall_executor import (
    FirewallExecutor,
    FirewallResult,
)


class IPIsolationAgent:
    """
    IP 隔离处置 Agent。

    职责：
    1. 订阅双脑下发的隔离指令
    2. 执行 IP 封禁/释放（真实或模拟）
    3. 返回执行结果
    """

    def __init__(self, config: Config):
        """
        Args:
            config: 全局配置对象
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.logger: logging.Logger = get_logger("IPIsolation")

        # 读取隔离配置（含安全护栏参数）
        iso_cfg = self._load_isolation_config()
        self._real_exec = iso_cfg["real_exec"]
        self._max_blocks = iso_cfg["max_blocks"]
        self._block_cooldown_sec = iso_cfg["block_cooldown_sec"]
        self._protected_networks: list[ipaddress.IPv4Network] = iso_cfg["protected_networks"]

        # 初始化防火墙执行器
        self._fw = FirewallExecutor(
            logger=self.logger,
            real_exec=self._real_exec,
        )

        # 兼容旧代码的内存黑名单（模拟模式下使用）
        self._blacklist: set = set()
        self._action_log: list = []

        # 封禁冷却追踪: {ip: last_block_timestamp}
        self._block_cooldowns: dict[str, float] = {}

        # 统计
        self._stats = {
            "total_blocks": 0,
            "total_releases": 0,
            "total_monitors": 0,
            "total_errors": 0,
            "total_rejected_by_safety": 0,
        }

        # 审计日志路径
        self._audit_log_path: Path = (
            Path(config.data_dir) / "audit" / "isolation_audit.jsonl"
            if hasattr(config, "data_dir")
            else Path("logs") / "audit" / "isolation_audit.jsonl"
        )
        self._audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        self._running = False

    def _load_isolation_config(self) -> dict:
        """加载隔离配置，返回包含所有安全护栏参数的字典。"""
        defaults = {
            "real_exec": False,
            "max_blocks": 100,
            "block_cooldown_sec": 30,
            "protected_networks": [
                ipaddress.IPv4Network("127.0.0.1/32"),
                ipaddress.IPv4Network("10.0.0.0/8"),
                ipaddress.IPv4Network("172.16.0.0/12"),
                ipaddress.IPv4Network("192.168.0.0/16"),
            ],
        }
        try:
            iso_cfg = getattr(self.config, "isolation", None)
            if iso_cfg is None:
                return defaults

            if isinstance(iso_cfg, dict):
                cfg = dict(iso_cfg)
            else:
                cfg = {k: getattr(iso_cfg, k, None) for k in defaults}

            result = {
                "real_exec": cfg.get("real_exec", defaults["real_exec"]),
                "max_blocks": cfg.get("max_blocks", defaults["max_blocks"]),
                "block_cooldown_sec": cfg.get(
                    "block_cooldown_sec", defaults["block_cooldown_sec"]
                ),
            }
            # 解析保护网络列表
            raw_protected = cfg.get("protected_ips", None)
            if raw_protected and isinstance(raw_protected, list):
                networks = []
                for entry in raw_protected:
                    try:
                        # 自动补全 /32 如果没指定掩码
                        net = entry if "/" in entry else f"{entry}/32"
                        networks.append(ipaddress.IPv4Network(net, strict=False))
                    except ValueError:
                        self.logger.warning(f"无效的保护IP/CIDR: {entry}，已跳过")
                result["protected_networks"] = networks if networks else defaults["protected_networks"]
            else:
                result["protected_networks"] = defaults["protected_networks"]

            return result
        except Exception:
            return defaults

    # ── 安全护栏 ──

    def _is_protected_ip(self, ip_str: str) -> tuple[bool, str]:
        """检查 IP 是否在保护网络范围内。返回 (是否受保护, 匹配的网络描述)。"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            for network in self._protected_networks:
                if ip in network:
                    return True, str(network)
        except (ValueError, ipaddress.AddressValueError):
            return True, "invalid_ip_format"
        return False, ""

    def _check_block_cooldown(self, ip: str) -> bool:
        """检查 IP 封禁冷却时间。返回 True 表示可以封禁。"""
        now = time.time()
        last = self._block_cooldowns.get(ip, 0)
        if now - last < self._block_cooldown_sec:
            return False
        self._block_cooldowns[ip] = now
        return True

    async def _is_block_limit_reached(self, block_action: str) -> bool:
        """检查封禁数量是否达到上限。block_action 区分真实/模拟。"""
        if block_action not in ("isolate", "isolate_ip", "block", "ban"):
            return False
        blocked = await self._fw.list_blocked()
        if len(blocked) >= self._max_blocks:
            return True
        return False

    async def _check_safety(
        self, target_ip: str, action: str, reason: str
    ) -> Optional[str]:
        """
        综合安全检查。返回 None 表示通过，返回字符串表示拒绝原因。
        """
        block_actions = {"isolate", "isolate_ip", "block", "ban"}

        # 1. 保护IP检查（仅封禁类操作）
        if action in block_actions:
            is_protected, net_desc = self._is_protected_ip(target_ip)
            if is_protected:
                reason_msg = (
                    f"IP {target_ip} 位于保护网络 {net_desc}，拒绝封禁"
                    if net_desc != "invalid_ip_format"
                    else f"IP {target_ip} 格式无效，拒绝封禁"
                )
                self.logger.warning(f"[安全护栏] {reason_msg}")
                self._stats["total_rejected_by_safety"] += 1
                return reason_msg

            # 2. 封禁上限检查
            if await self._is_block_limit_reached(action):
                msg = (
                    f"封禁数量已达上限 {self._max_blocks}，拒绝新封禁指令: {target_ip}"
                )
                self.logger.warning(f"[安全护栏] {msg}")
                self._stats["total_rejected_by_safety"] += 1
                return msg

            # 3. 冷却时间检查
            if not self._check_block_cooldown(target_ip):
                remaining = self._block_cooldown_sec - (
                    time.time() - self._block_cooldowns.get(target_ip, 0)
                )
                msg = (
                    f"IP {target_ip} 处于封禁冷却期（剩余 {remaining:.0f}s），跳过重复封禁"
                )
                self.logger.info(f"[安全护栏] {msg}")
                return msg

        return None

    def _write_audit_log(
        self,
        action: str,
        target_ip: str,
        reason: str,
        success: bool,
        message: str,
        alert_id: str,
    ) -> None:
        """写入结构化审计日志（JSON Lines）。"""
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "action": action,
            "target_ip": target_ip,
            "reason": reason,
            "success": success,
            "message": message,
            "alert_id": alert_id,
            "mode": "real" if self._real_exec else "simulated",
            "blocked_count": len(self._blacklist),
            "stats": self._stats.copy(),
        }
        try:
            with open(self._audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.error(f"审计日志写入失败: {e}")

    # ── 启动/停止 ──

    async def start(self) -> None:
        """启动处置Agent，订阅隔离指令。"""
        self._running = True
        await self.bus.subscribe("isolation_action", self._handle_isolation)
        mode = "真实执行" if self._real_exec else "模拟"
        self.logger.info(f"IP隔离Agent已启动 [{mode}模式]，等待隔离指令...")

    async def stop(self) -> None:
        """停止处置Agent。"""
        self._running = False
        self.logger.info(
            f"IP隔离Agent已停止 | "
            f"封禁:{self._stats['total_blocks']} | "
            f"释放:{self._stats['total_releases']} | "
            f"监控:{self._stats['total_monitors']} | "
            f"错误:{self._stats['total_errors']} | "
            f"安全拦截:{self._stats['total_rejected_by_safety']}"
        )

    async def _handle_isolation(self, msg: Message) -> Optional[Message]:
        """
        处理IP隔离指令（含安全护栏）。
        """
        if not self._running:
            return None

        payload = msg.payload
        action = payload.get("action", "isolate")
        target_ip = payload.get("target_ip", "unknown")
        alert_id = payload.get("alert_id", "unknown")
        reason = payload.get("reason", "")

        # 动作标准化
        ACTION_NORMALIZE = {
            "block_ip": "block",
            "isolate_host": "isolate_ip",
            "isolate_ip": "isolate_ip",
            "block_domain": "block",
            "alert": "monitor",
        }
        action = ACTION_NORMALIZE.get(action, action)

        self.logger.info(f"收到隔离指令: 对 {target_ip} 执行 {action} (告警 {alert_id})")

        # ── 安全护栏 ──
        safety_block = await self._check_safety(target_ip, action, reason)
        if safety_block is not None:
            result = FirewallResult(
                success=False,
                message=f"[安全护栏阻断] {safety_block}",
            )
            self._write_audit_log(action, target_ip, reason, False, safety_block, alert_id)
            return Message(
                source="IPIsolation",
                target=msg.source,
                type="action_result",
                payload={
                    "alert_id": alert_id,
                    "target_ip": target_ip,
                    "action": action,
                    "success": False,
                    "message": safety_block,
                    "blocked_count": len(await self._fw.list_blocked()),
                    "safety_rejected": True,
                },
                reply_to=msg.msg_id,
            )

        # 执行隔离操作
        result = await self._execute_isolation(target_ip, action, reason)

        # 更新统计
        if not result.success:
            self._stats["total_errors"] += 1

        # 审计日志
        self._write_audit_log(
            action, target_ip, reason,
            result.success, result.message, alert_id,
        )

        # 返回执行结果
        response = Message(
            source="IPIsolation",
            target=msg.source,
            type="action_result",
            payload={
                "alert_id": alert_id,
                "target_ip": target_ip,
                "action": action,
                "success": result.success,
                "message": result.message,
                "blocked_count": len(await self._fw.list_blocked()),
            },
            reply_to=msg.msg_id,
        )
        return response

    async def _execute_isolation(
        self,
        target_ip: str,
        action: str,
        reason: str,
    ) -> FirewallResult:
        """
        执行 IP 隔离操作（委托给 FirewallExecutor）。

        Args:
            target_ip: 目标IP
            action:    动作类型
            reason:    执行原因

        Returns:
            FirewallResult
        """
        # 跳过无效IP
        invalid_ips = {"N/A", "unknown", "127.0.0.1", "0.0.0.0", ""}
        if target_ip in invalid_ips or (target_ip and not any(c.isdigit() for c in target_ip[:3])):
            self.logger.debug(f"跳过无效IP: {target_ip}")
            return FirewallResult(
                success=True,
                message=f"IP '{target_ip}' 为无效地址，跳过隔离操作",
            )

        # 模拟网络延迟（模拟模式下）
        if not self._real_exec:
            await asyncio.sleep(random.uniform(0.05, 0.2))

        # 路由动作
        block_actions = {"isolate", "isolate_ip", "block", "ban"}

        if action in block_actions:
            result = await self._fw.block_ip(target_ip, reason)
            if result.success:
                self._stats["total_blocks"] += 1
                self._blacklist.add(target_ip)
            return result

        elif action == "release":
            result = await self._fw.release_ip(target_ip)
            if result.success:
                self._stats["total_releases"] += 1
                self._blacklist.discard(target_ip)
            return result

        elif action in ("rate_limit", "monitor"):
            self._stats["total_monitors"] += 1
            self.logger.info(f"[{action}] {target_ip} | 理由: {reason[:60]}")
            return FirewallResult(
                success=True,
                message=f"已记录 {action} 指令: {target_ip}（仅监控，无实际拦截）",
            )

        else:
            self.logger.error(f"未知动作类型: {action}")
            return FirewallResult(
                success=False,
                message=f"未知动作类型: {action}",
            )

    def _log_action(
        self,
        action: str,
        target_ip: str,
        reason: str,
        success: bool,
    ) -> None:
        """记录操作日志。"""
        self._action_log.append({
            "action": action,
            "target_ip": target_ip,
            "reason": reason,
            "result": "success" if success else "failed",
        })

    async def get_blocked_ips(self) -> list[str]:
        """获取当前被封禁的 IP 列表。"""
        return await self._fw.list_blocked()

    def get_blacklist(self) -> list:
        """获取内存黑名单（兼容旧接口）。"""
        return sorted(self._blacklist)

    def get_action_log(self) -> list:
        """获取操作日志。"""
        return self._action_log.copy()

    def get_stats(self) -> dict:
        """获取统计信息。"""
        return dict(self._stats)

    async def cleanup(self) -> FirewallResult:
        """清理所有防火墙规则。"""
        result = await self._fw.cleanup()
        self._blacklist.clear()
        return result

    def reset_state(self) -> None:
        """重置内部状态（用于测试）。"""
        self._blacklist.clear()
        self._action_log.clear()
        self._stats = {
            "total_blocks": 0,
            "total_releases": 0,
            "total_monitors": 0,
            "total_errors": 0,
        }
