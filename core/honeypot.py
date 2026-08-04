"""
自建轻量蜜罐（欺骗层 · 融合增强 v1.1 阶段2）。

纯 Python 实现，零外部框架依赖（不引入 HoneyTrap-AI / AlterHive / Labyrinth 等重型系统），
以"虚拟端口诱捕 + 交互日志记录 + 总线重定向"形成欺骗层最小闭环：

- 虚拟端口诱捕：内置常见服务指纹表（FTP/SSH/Telnet/HTTP/MySQL/Redis/RDP...），
  对攻击者的探测请求模拟 banner 握手与命令交互，不真实监听端口（模拟环境）。
- 交互日志记录：每条诱捕记录保存源/目标 IP、端口、服务指纹、banner 响应、
  交互条目序列（探测/登录尝试/命令注入），供取证与双脑分析。
- 总线集成：订阅 threat_alert（port_scan / vuln / brute_force 等侦察类告警），
  将扫描源"重定向"至蜜罐并发布 honeypot_trap 事件；提供 build_redirect_plan /
  get_trap_context 供双脑决策支持。

对外仅依赖 communication.message_bus / config / utils.logger，与现有器官 Agent 一致。
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config
from utils.logger import get_logger


# ==================== 服务指纹库 ====================

SERVICE_FINGERPRINTS: Dict[int, Dict[str, str]] = {
    21: {
        "name": "FTP",
        "banner": "220 (vsFTPd 3.0.5)",
        "prompt": "331 Please specify the password.",
    },
    22: {
        "name": "SSH",
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "prompt": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    },
    23: {
        "name": "Telnet",
        "banner": "Welcome to Ubuntu 22.04 LTS\r\nlocalhost login: ",
        "prompt": "localhost login: ",
    },
    80: {
        "name": "HTTP",
        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html",
        "prompt": "HTTP/1.1 200 OK",
    },
    443: {
        "name": "HTTPS",
        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
        "prompt": "HTTP/1.1 200 OK",
    },
    3306: {
        "name": "MySQL",
        "banner": "8.0.35-0ubuntu0.22.04.1",
        "prompt": "8.0.35-0ubuntu0.22.04.1",
    },
    3389: {
        "name": "RDP",
        "banner": "RDP 协议握手协商响应",
        "prompt": "RDP 协议握手协商响应",
    },
    6379: {
        "name": "Redis",
        "banner": "-ERR wrong number of arguments for 'auth' command",
        "prompt": "redis> ",
    },
    8080: {
        "name": "HTTP-Proxy",
        "banner": "HTTP/1.1 200 Connection established",
        "prompt": "HTTP/1.1 200 Connection established",
    },
}

# 侦察类威胁类别：命中即触发蜜罐重定向
TRAP_TRIGGER_CATEGORIES = ("port_scan", "vuln", "brute_force", "probe")

# 交互日志条目类型
INTERACTION_PROBE = "probe"          # 端口探测/握手
INTERACTION_LOGIN = "login_attempt"  # 登录尝试
INTERACTION_PAYLOAD = "payload"      # 命令/载荷注入


@dataclass
class HoneypotRecord:
    """单条蜜罐诱捕记录。"""

    record_id: str
    source_ip: str
    target_ip: str
    port: int
    service: str
    banner_response: str
    interaction_entries: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    alert_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转为字典格式。"""
        return {
            "record_id": self.record_id,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "port": self.port,
            "service": self.service,
            "banner_response": self.banner_response,
            "interaction_entries": self.interaction_entries,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
        }


class HoneypotService:
    """蜜罐核心服务：虚拟端口诱捕与交互日志记录（纯内存）。"""

    def __init__(self, max_records: int = 1000) -> None:
        self.max_records = max_records
        self._records: List[HoneypotRecord] = []
        self._logger: logging.Logger = get_logger("Honeypot")

    # ---------- 诱捕交互 ----------

    def simulate_handshake(self, port: int) -> Dict[str, str]:
        """
        模拟对指定端口的 TCP 握手 / banner 响应。

        Args:
            port: 目标蜜罐端口

        Returns:
            {"service": 服务名, "banner": banner 响应, "prompt": 后续交互提示符}
            未知端口返回通用占位响应。
        """
        fp = SERVICE_FINGERPRINTS.get(port)
        if fp is None:
            return {
                "service": f"unknown-{port}",
                "banner": f"banner-{port}",
                "prompt": f"banner-{port}",
            }
        return {
            "service": fp["name"],
            "banner": fp["banner"],
            "prompt": fp["prompt"],
        }

    def record_trap(
        self,
        source_ip: str,
        target_ip: str,
        port: int,
        alert_id: str = "",
        interaction_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> HoneypotRecord:
        """
        记录一次蜜罐诱捕事件（探测 → banner 响应 → 交互条目）。

        Args:
            source_ip: 攻击源 IP
            target_ip: 目标（蜜罐）IP
            port:      被探测的蜜罐端口
            alert_id:  关联的威胁告警 ID（可为空）
            interaction_entries: 可选交互条目列表；缺省自动补一条 probe 记录

        Returns:
            新生成的 HoneypotRecord
        """
        handshake = self.simulate_handshake(port)
        entries = list(interaction_entries) if interaction_entries else [
            {
                "type": INTERACTION_PROBE,
                "content": f"TCP 探测 {source_ip} -> {target_ip}:{port}",
                "timestamp": datetime.now().isoformat(),
            }
        ]
        record = HoneypotRecord(
            record_id=f"HP-{uuid.uuid4().hex[:8].upper()}",
            source_ip=source_ip,
            target_ip=target_ip,
            port=port,
            service=handshake["service"],
            banner_response=handshake["banner"],
            interaction_entries=entries,
            alert_id=alert_id,
        )
        self._records.append(record)
        if len(self._records) > self.max_records:
            self._records = self._records[-self.max_records:]
        self._logger.debug(
            f"蜜罐诱捕: {source_ip} -> {target_ip}:{port} ({record.service})"
        )
        return record

    # ---------- 查询/统计 ----------

    def get_records(self) -> List[HoneypotRecord]:
        """返回全部诱捕记录（时间正序）。"""
        return list(self._records)

    def get_records_by_source(self, source_ip: str) -> List[HoneypotRecord]:
        """按源 IP 过滤诱捕记录。"""
        return [r for r in self._records if r.source_ip == source_ip]

    def get_stats(self) -> Dict[str, Any]:
        """统计蜜罐诱捕情况。"""
        total = len(self._records)
        by_port: Dict[int, int] = {}
        by_service: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for r in self._records:
            by_port[r.port] = by_port.get(r.port, 0) + 1
            by_service[r.service] = by_service.get(r.service, 0) + 1
            by_source[r.source_ip] = by_source.get(r.source_ip, 0) + 1
        return {
            "total_traps": total,
            "unique_sources": len(by_source),
            "traps_by_port": by_port,
            "traps_by_service": by_service,
            "traps_by_source": by_source,
        }

    def get_trap_context(self, source_ip: str) -> Dict[str, Any]:
        """
        生成某源 IP 的诱捕情报摘要（供双脑决策支持）。

        包含：该源探测过的端口/服务、banner 响应、交互条目、最近探测时间。
        """
        records = self.get_records_by_source(source_ip)
        if not records:
            return {
                "source_ip": source_ip,
                "trapped": False,
                "ports_probed": [],
                "services_seen": [],
                "interaction_count": 0,
                "last_seen": None,
            }
        ports = sorted({r.port for r in records})
        services = sorted({r.service for r in records})
        total_interactions = sum(len(r.interaction_entries) for r in records)
        return {
            "source_ip": source_ip,
            "trapped": True,
            "ports_probed": ports,
            "services_seen": services,
            "interaction_count": total_interactions,
            "last_seen": max(r.timestamp for r in records),
        }

    def clear(self) -> None:
        """清空全部诱捕记录（测试用）。"""
        self._records.clear()


class HoneypotAgent:
    """
    欺骗层蜜罐 Agent。

    职责：
    1. 订阅 threat_alert，对侦察类告警（port_scan / vuln / brute_force）触发蜜罐重定向
    2. 记录诱捕交互并发布 honeypot_trap 事件（供双脑/取证/记录器消费）
    3. 提供 build_redirect_plan / get_trap_context 决策支持接口（供双脑注入策略）
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.logger: logging.Logger = get_logger("HoneypotAgent")
        self.service = HoneypotService()
        self._running = False

    # ---------- 生命周期 ----------

    async def start(self) -> None:
        """启动蜜罐 Agent，订阅威胁告警。"""
        self._running = True
        await self.bus.subscribe("threat_alert", self._handle_alert)
        self.logger.info("蜜罐Agent已启动，等待侦察类威胁告警...")

    async def stop(self) -> None:
        """停止蜜罐 Agent。"""
        self._running = False
        self.logger.info("蜜罐Agent已停止")

    # ---------- 总线事件处理 ----------

    async def _handle_alert(self, msg: Message) -> Optional[Message]:
        """处理 threat_alert：命中侦察类类别时执行蜜罐重定向并发布诱捕事件。"""
        if not self._running:
            return None

        payload = msg.payload
        indicator = payload.get("indicator", payload)
        category = indicator.get("category", payload.get("category", "unknown"))
        alert_id = indicator.get("id", payload.get("id", msg.msg_id))
        source_ip = indicator.get("source_ip", payload.get("source_ip", ""))
        target_ip = indicator.get("target_ip", payload.get("target_ip", "192.168.1.1"))
        target_port = indicator.get("target_port", payload.get("target_port"))

        if category not in TRAP_TRIGGER_CATEGORIES:
            return None
        if not source_ip:
            return None

        # 确定诱捕端口：优先告警目标端口，其次常见服务指纹端口
        trap_ports = [target_port] if isinstance(target_port, int) else list(SERVICE_FINGERPRINTS.keys())

        records = []
        for port in trap_ports[:5]:  # 单次最多诱捕 5 个端口，防告警洪泛
            record = self.service.record_trap(
                source_ip=source_ip,
                target_ip=target_ip,
                port=port,
                alert_id=alert_id,
            )
            records.append(record)

        self.logger.info(
            f"蜜罐重定向: {source_ip} ({category}) -> 诱捕 {len(records)} 个端口: "
            f"{', '.join(str(r.port) for r in records)}"
        )

        # 发布 honeypot_trap 事件（广播，供双脑/取证/记录器消费）
        return Message(
            source="HoneypotAgent",
            target="*",
            type="honeypot_trap",
            payload={
                "type": "honeypot_trap",
                "alert_id": alert_id,
                "source_ip": source_ip,
                "target_ip": target_ip,
                "category": category,
                "records": [r.to_dict() for r in records],
                "trap_context": self.service.get_trap_context(source_ip),
            },
        )

    # ---------- 双脑决策支持 ----------

    def build_redirect_plan(
        self, source_ip: str, severity: str = "medium"
    ) -> Dict[str, Any]:
        """
        生成蜜罐重定向处置建议（供双脑注入 recommended_actions）。

        Args:
            source_ip: 攻击源 IP
            severity:  告警严重级别（low/medium/high/severe）

        Returns:
            重定向计划 dict：含动作名 redirect_honeypot、诱捕端口、风险提示。
        """
        context = self.service.get_trap_context(source_ip)
        return {
            "action": "redirect_honeypot",
            "target_ip": source_ip,
            "reason": (
                f"侦察行为已确认，将该源流量重定向至蜜罐诱捕以获取攻击手法情报"
                f"（已诱捕 {context['interaction_count']} 次交互）"
                if context["trapped"] else
                "疑似侦察行为，重定向至蜜罐进行诱捕验证"
            ),
            "trap_ports": context["ports_probed"] or list(SERVICE_FINGERPRINTS.keys())[:4],
            "severity": severity,
            "risk": "低：蜜罐为虚拟服务，不接触真实业务端口",
        }

    def get_trap_context(self, source_ip: str) -> Dict[str, Any]:
        """查询某源 IP 的诱捕情报（双脑决策支持）。"""
        return self.service.get_trap_context(source_ip)

    # ---------- 查询/导出 ----------

    def get_records(self) -> List[HoneypotRecord]:
        """返回全部诱捕记录。"""
        return self.service.get_records()

    def get_stats(self) -> Dict[str, Any]:
        """返回蜜罐统计。"""
        return self.service.get_stats()

    def export_json(self, filepath: str) -> str:
        """导出全部诱捕记录为 JSON 文件。

        Args:
            filepath: 输出 JSON 文件路径（绝对路径）

        Returns:
            写入的文件路径
        """
        report = {
            "exported_at": datetime.now().isoformat(),
            "total_traps": len(self.service.get_records()),
            "stats": self.service.get_stats(),
            "records": [r.to_dict() for r in self.service.get_records()],
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        self.logger.info(f"蜜罐记录已导出: {filepath} ({report['total_traps']} 条)")
        return filepath
