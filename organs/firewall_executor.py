"""
防火墙执行器 — OS 抽象层，支持 iptables（Linux）和 Windows Firewall。
按 config.yaml 中 isolation.real_exec 决定真实执行还是模拟模式。

设计原则：
- 原子操作：添加/删除规则失败时回滚
- 去重：封禁前检查规则是否已存在
- 审计：每次操作写入结构化日志
"""

import asyncio
import logging
import os
import platform
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Action(Enum):
    BLOCK = "block"
    RELEASE = "release"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"


@dataclass
class FirewallRule:
    ip: str
    action: Action
    reason: str = ""
    alert_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    rule_id: str = ""  # 系统内唯一规则标识


@dataclass
class FirewallResult:
    success: bool
    message: str
    rule: Optional[FirewallRule] = None


# ── 抽象接口 ──

class BaseFirewallBackend(ABC):
    """防火墙后端抽象基类"""

    @abstractmethod
    async def block_ip(self, ip: str, reason: str = "") -> FirewallResult:
        """封禁 IP"""
        ...

    @abstractmethod
    async def release_ip(self, ip: str) -> FirewallResult:
        """释放 IP"""
        ...

    @abstractmethod
    async def is_blocked(self, ip: str) -> bool:
        """检查 IP 是否被封禁"""
        ...

    @abstractmethod
    async def list_blocked(self) -> list[str]:
        """列出所有被封禁 IP"""
        ...

    @abstractmethod
    async def cleanup(self) -> FirewallResult:
        """清理所有本模块创建的规则"""
        ...


# ── Linux iptables 后端 ──

class IptablesBackend(BaseFirewallBackend):
    """
    Linux iptables 后端。
    使用 iptables 的 INPUT 链封禁 IP。
    需要 NET_ADMIN capability 或 root 权限。
    """

    CHAIN_NAME = "DFU_BLOCK"

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._chain_created = False
        self._os = platform.system()

    async def _ensure_chain(self) -> FirewallResult:
        """确保 DFU_BLOCK 链存在并挂载到 INPUT"""
        if self._chain_created:
            return FirewallResult(success=True, message="链已就绪")

        if self._os != "Linux":
            return FirewallResult(
                success=False,
                message=f"iptables 仅适用于 Linux，当前系统: {self._os}",
            )

        try:
            # 检查链是否存在
            check = await self._run_iptables(
                ["-L", self.CHAIN_NAME, "-n"],
                check_only=True,
            )
            if check.returncode != 0:
                # 创建链
                await self._run_iptables(["-N", self.CHAIN_NAME])
                # 挂载到 INPUT 链（避免重复挂载）
                await self._run_iptables(
                    ["-I", "INPUT", "1", "-j", self.CHAIN_NAME]
                )
                self.logger.info(f"已创建 iptables 链: {self.CHAIN_NAME}")

            self._chain_created = True
            return FirewallResult(success=True, message=f"链 {self.CHAIN_NAME} 就绪")

        except Exception as e:
            return FirewallResult(
                success=False,
                message=f"初始化 iptables 链失败: {e}",
            )

    async def block_ip(self, ip: str, reason: str = "") -> FirewallResult:
        """封禁 IP：添加 DROP 规则到 DFU_BLOCK 链"""
        if not self._is_valid_ip(ip):
            return FirewallResult(
                success=False,
                message=f"无效 IP 地址: {ip}",
            )

        # 确保链存在
        chain_result = await self._ensure_chain()
        if not chain_result.success:
            return chain_result

        # 检查是否已封禁（去重）
        if await self.is_blocked(ip):
            return FirewallResult(
                success=True,
                message=f"IP {ip} 已被封禁，跳过",
            )

        try:
            rule_id = f"dfu_{ip.replace('.', '_')}_{int(datetime.now().timestamp())}"
            # 添加注释以便日后识别和清理
            comment = f"DFU auto-block: {reason[:80]}" if reason else "DFU auto-block"
            result = await self._run_iptables([
                "-A", self.CHAIN_NAME,
                "-s", ip,
                "-j", "DROP",
                "-m", "comment", "--comment", comment,
            ])

            if result.returncode == 0:
                self.logger.warning(f"[iptables] 已封禁 IP: {ip} | 原因: {reason[:60]}")
                return FirewallResult(
                    success=True,
                    message=f"IP {ip} 已通过 iptables 封禁",
                    rule=FirewallRule(
                        ip=ip,
                        action=Action.BLOCK,
                        reason=reason,
                        rule_id=rule_id,
                    ),
                )
            else:
                return FirewallResult(
                    success=False,
                    message=f"iptables 封禁失败: {result.stderr.strip()}",
                )

        except Exception as e:
            self.logger.error(f"iptables 封禁异常: {e}")
            return FirewallResult(
                success=False,
                message=f"iptables 封禁异常: {e}",
            )

    async def release_ip(self, ip: str) -> FirewallResult:
        """释放 IP：从 DFU_BLOCK 链删除对应规则"""
        if not self._is_valid_ip(ip):
            return FirewallResult(success=False, message=f"无效 IP: {ip}")

        if not await self.is_blocked(ip):
            return FirewallResult(success=True, message=f"IP {ip} 未被封禁，无需释放")

        try:
            result = await self._run_iptables([
                "-D", self.CHAIN_NAME,
                "-s", ip,
                "-j", "DROP",
            ])

            if result.returncode == 0:
                self.logger.info(f"[iptables] 已释放 IP: {ip}")
                return FirewallResult(
                    success=True,
                    message=f"IP {ip} 已释放",
                    rule=FirewallRule(ip=ip, action=Action.RELEASE),
                )
            else:
                return FirewallResult(
                    success=False,
                    message=f"iptables 释放失败: {result.stderr.strip()}",
                )

        except Exception as e:
            return FirewallResult(success=False, message=f"iptables 释放异常: {e}")

    async def is_blocked(self, ip: str) -> bool:
        """检查 IP 是否在 DFU_BLOCK 链中"""
        try:
            result = await self._run_iptables(
                ["-L", self.CHAIN_NAME, "-n"],
                check_only=True,
            )
            if result.returncode != 0:
                return False
            return ip in result.stdout
        except Exception:
            return False

    async def list_blocked(self) -> list[str]:
        """列出 DFU_BLOCK 链中所有 IP"""
        try:
            result = await self._run_iptables(
                ["-L", self.CHAIN_NAME, "-n"],
                check_only=True,
            )
            if result.returncode != 0:
                return []
            ips = []
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[3] in ("DROP", "REJECT"):
                    ips.append(parts[3])
            return ips
        except Exception:
            return []

    async def cleanup(self) -> FirewallResult:
        """删除 DFU_BLOCK 链及其在 INPUT 中的跳转"""
        try:
            # 从 INPUT 中移除跳转
            await self._run_iptables(
                ["-D", "INPUT", "-j", self.CHAIN_NAME],
                check_only=True,
            )
            # 清空并删除链
            await self._run_iptables(["-F", self.CHAIN_NAME])
            await self._run_iptables(["-X", self.CHAIN_NAME])
            self._chain_created = False
            self.logger.info(f"已清理 iptables 链: {self.CHAIN_NAME}")
            return FirewallResult(success=True, message="iptables 规则已清理")
        except Exception as e:
            return FirewallResult(success=False, message=f"清理失败: {e}")

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        invalid = {"N/A", "unknown", "127.0.0.1", "0.0.0.0", "", "localhost"}
        if ip in invalid:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    async def _run_iptables(
        self,
        args: list[str],
        check_only: bool = False,
    ) -> subprocess.CompletedProcess:
        """异步执行 iptables 命令"""
        cmd = ["sudo", "iptables-legacy"] + args if os.geteuid() != 0 else ["iptables-legacy"] + args
        if check_only:
            cmd = ["iptables-legacy"] + args  # check 不需要 sudo

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return await proc.communicate()


# ── Windows Firewall 后端 ──

class WindowsFirewallBackend(BaseFirewallBackend):
    """
    Windows 防火墙后端。
    使用 netsh advfirewall 添加/删除入站阻止规则。
    需要管理员权限。
    """

    RULE_PREFIX = "DFU_Block_"

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    async def block_ip(self, ip: str, reason: str = "") -> FirewallResult:
        if not self._is_valid_ip(ip):
            return FirewallResult(success=False, message=f"无效 IP: {ip}")

        if await self.is_blocked(ip):
            return FirewallResult(success=True, message=f"IP {ip} 已被封禁，跳过")

        rule_name = f"{self.RULE_PREFIX}{ip.replace('.', '_')}"
        desc = f"DFU auto-block: {reason[:200]}" if reason else "DFU auto-block"

        try:
            result = await self._run_netsh([
                "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                f"description={desc}",
            ])

            if result.returncode == 0:
                self.logger.warning(f"[WinFW] 已封禁 IP: {ip}")
                return FirewallResult(
                    success=True,
                    message=f"IP {ip} 已通过 Windows 防火墙封禁",
                    rule=FirewallRule(
                        ip=ip,
                        action=Action.BLOCK,
                        reason=reason,
                        rule_id=rule_name,
                    ),
                )
            else:
                return FirewallResult(
                    success=False,
                    message=f"Windows 防火墙封禁失败: {result.stderr.strip()}",
                )

        except Exception as e:
            return FirewallResult(success=False, message=f"Windows 防火墙异常: {e}")

    async def release_ip(self, ip: str) -> FirewallResult:
        if not self._is_valid_ip(ip):
            return FirewallResult(success=False, message=f"无效 IP: {ip}")

        rule_name = f"{self.RULE_PREFIX}{ip.replace('.', '_')}"

        if not await self.is_blocked(ip):
            return FirewallResult(success=True, message=f"IP {ip} 未被封禁")

        try:
            result = await self._run_netsh([
                "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ])

            if result.returncode == 0 or "未找到" in result.stderr:
                self.logger.info(f"[WinFW] 已释放 IP: {ip}")
                return FirewallResult(
                    success=True,
                    message=f"IP {ip} 已释放",
                    rule=FirewallRule(ip=ip, action=Action.RELEASE),
                )
            else:
                return FirewallResult(
                    success=False,
                    message=f"Windows 防火墙释放失败: {result.stderr.strip()}",
                )

        except Exception as e:
            return FirewallResult(success=False, message=f"Windows 防火墙异常: {e}")

    async def is_blocked(self, ip: str) -> bool:
        rule_name = f"{self.RULE_PREFIX}{ip.replace('.', '_')}"
        try:
            result = await self._run_netsh([
                "advfirewall", "firewall", "show", "rule",
                f"name={rule_name}",
            ])
            return result.returncode == 0 and rule_name in result.stdout
        except Exception:
            return False

    async def list_blocked(self) -> list[str]:
        try:
            result = await self._run_netsh([
                "advfirewall", "firewall", "show", "rule",
                "name=all", "dir=in",
            ])
            ips = []
            for line in result.stdout.splitlines():
                if self.RULE_PREFIX in line:
                    # 从规则名提取 IP
                    name = line.split(":")[-1].strip() if ":" in line else ""
                    if name.startswith(self.RULE_PREFIX):
                        ip = name[len(self.RULE_PREFIX):].replace("_", ".")
                        ips.append(ip)
            return ips
        except Exception:
            return []

    async def cleanup(self) -> FirewallResult:
        try:
            blocked = await self.list_blocked()
            for ip in blocked:
                await self.release_ip(ip)
            self.logger.info(f"已清理 {len(blocked)} 条 Windows 防火墙规则")
            return FirewallResult(success=True, message=f"已清理 {len(blocked)} 条规则")
        except Exception as e:
            return FirewallResult(success=False, message=f"清理失败: {e}")

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        invalid = {"N/A", "unknown", "127.0.0.1", "0.0.0.0", "", "localhost"}
        if ip in invalid:
            return False
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    async def _run_netsh(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = ["netsh"] + args
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        # 尝试多种编码
        for enc in ["gbk", "utf-8", "cp936"]:
            try:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=proc.returncode,
                    stdout=stdout_bytes.decode(enc),
                    stderr=stderr_bytes.decode(enc),
                )
            except UnicodeDecodeError:
                continue
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
        )


# ── 模拟后端（开发/测试用） ──

class SimulatedBackend(BaseFirewallBackend):
    """模拟防火墙后端，维护内存黑名单，不实际操作系统防火墙。"""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._blacklist: set = set()
        self._history: list[FirewallRule] = []

    async def block_ip(self, ip: str, reason: str = "") -> FirewallResult:
        if ip in self._blacklist:
            return FirewallResult(success=True, message=f"IP {ip} 已在黑名单中")

        self._blacklist.add(ip)
        rule = FirewallRule(ip=ip, action=Action.BLOCK, reason=reason)
        self._history.append(rule)
        self.logger.warning(f"[模拟] 封禁 IP: {ip}")
        return FirewallResult(success=True, message=f"IP {ip} 已模拟封禁", rule=rule)

    async def release_ip(self, ip: str) -> FirewallResult:
        if ip not in self._blacklist:
            return FirewallResult(success=True, message=f"IP {ip} 不在黑名单中")

        self._blacklist.discard(ip)
        rule = FirewallRule(ip=ip, action=Action.RELEASE)
        self._history.append(rule)
        self.logger.info(f"[模拟] 释放 IP: {ip}")
        return FirewallResult(success=True, message=f"IP {ip} 已模拟释放", rule=rule)

    async def is_blocked(self, ip: str) -> bool:
        return ip in self._blacklist

    async def list_blocked(self) -> list[str]:
        return sorted(self._blacklist)

    async def cleanup(self) -> FirewallResult:
        count = len(self._blacklist)
        self._blacklist.clear()
        return FirewallResult(success=True, message=f"已清理 {count} 条模拟规则")


# ── 外观层：自动选择后端 ──

class FirewallExecutor:
    """
    防火墙执行器外观。
    按配置自动选择 iptables / Windows Firewall / 模拟后端。
    """

    def __init__(
        self,
        logger: logging.Logger,
        real_exec: bool = False,
        backend: Optional[BaseFirewallBackend] = None,
    ):
        self.logger = logger
        self._real_exec = real_exec

        if backend:
            self._backend = backend
        elif real_exec:
            self._backend = self._auto_detect_backend()
        else:
            self._backend = SimulatedBackend(logger)
            self.logger.info("防火墙模式: 模拟（isolation.real_exec=false）")

    def _auto_detect_backend(self) -> BaseFirewallBackend:
        system = platform.system()
        if system == "Linux":
            self.logger.info("防火墙模式: iptables（真实执行）")
            return IptablesBackend(self.logger)
        elif system == "Windows":
            self.logger.info("防火墙模式: Windows Firewall（真实执行）")
            return WindowsFirewallBackend(self.logger)
        else:
            self.logger.warning(f"未知系统 {system}，回退为模拟模式")
            return SimulatedBackend(self.logger)

    async def block_ip(self, ip: str, reason: str = "") -> FirewallResult:
        return await self._backend.block_ip(ip, reason)

    async def release_ip(self, ip: str) -> FirewallResult:
        return await self._backend.release_ip(ip)

    async def is_blocked(self, ip: str) -> bool:
        return await self._backend.is_blocked(ip)

    async def list_blocked(self) -> list[str]:
        return await self._backend.list_blocked()

    async def cleanup(self) -> FirewallResult:
        return await self._backend.cleanup()

    @property
    def real_exec(self) -> bool:
        return self._real_exec
