"""
溯源追踪Agent：接收响应引擎的溯源指令，模拟攻击路径还原（IP跳板链分析、时间线重建）。
输出溯源报告。

v2 做实：
- 基于 message_bus 订阅 threat_alert 事件，自动记录攻击链时间线（有序列表）
- 每次收到告警事件记录时间戳、源 IP、攻击类型、处置动作
- get_timeline() 返回完整时间线
- export_json(filepath) 导出 JSON 格式时间线报告
"""

import asyncio
import json
import logging
import os
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from communication.message_bus import Message, MessageBus, get_message_bus
from config import Config
from utils.logger import get_logger


@dataclass
class ForensicReport:
    """溯源追踪报告。"""
    report_id: str
    alert_id: str
    target_ip: str
    hop_chain: List[Dict[str, str]]  # 跳板链 [{ip, country, asn, timestamp}, ...]
    timeline: List[Dict[str, str]]   # 攻击时间线 [{timestamp, event}, ...]
    root_cause: str                  # 根因分析
    confidence: float                # 溯源可信度 (0.0 ~ 1.0)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


class ForensicTrackerAgent:
    """
    溯源追踪感知模块 Agent。

    职责：
    1. 订阅响应引擎下发的溯源指令（forensic_trace）
    2. 模拟攻击路径还原：IP跳板链分析、时间线重建
    3. 基于 message_bus 订阅 threat_alert 事件，自动记录攻击链时间线
    4. 提供 get_timeline() / export_json() 查询与导出
    """

    # 模拟国家/ASN 数据库
    IP_GEO_DB = [
        {"country": "CN", "asn": "AS4134", "region": "广东, 中国"},
        {"country": "US", "asn": "AS15169", "region": "California, United States"},
        {"country": "RU", "asn": "AS8359", "region": "Moscow, Russia"},
        {"country": "NL", "asn": "AS16276", "region": "Amsterdam, Netherlands"},
        {"country": "KR", "asn": "AS4766", "region": "Seoul, South Korea"},
        {"country": "SG", "asn": "AS55430", "region": "Singapore"},
        {"country": "DE", "asn": "AS24940", "region": "Frankfurt, Germany"},
        {"country": "JP", "asn": "AS2516", "region": "Tokyo, Japan"},
        {"country": "BR", "asn": "AS26599", "region": "Sao Paulo, Brazil"},
        {"country": "VN", "asn": "AS7552", "region": "Ho Chi Minh City, Vietnam"},
        {"country": "IR", "asn": "AS16322", "region": "Tehran, Iran"},
        {"country": "NG", "asn": "AS29465", "region": "Lagos, Nigeria"},
    ]

    def __init__(self, config: Config):
        """
        Args:
            config: 全局配置对象
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.logger: logging.Logger = get_logger("ForensicTracker")

        # 报告存档（模拟跳板链报告）
        self._reports: List[ForensicReport] = []

        # 真实攻击链时间线（有序列表，按时间戳倒序）
        self._timeline: List[Dict[str, Any]] = []

        # 已跟踪的告警去重
        self._tracked_ids: set = set()

        self._running = False

    async def start(self) -> None:
        """启动溯源追踪Agent，订阅溯源指令和 threat_alert 事件。"""
        self._running = True
        await self.bus.subscribe("forensic_trace", self._handle_trace)
        # 订阅全局威胁告警，自动记录时间线
        await self.bus.subscribe("threat_alert", self._handle_alert)
        self.logger.info("溯源追踪Agent已启动，等待溯源指令和威胁告警...")

    async def stop(self) -> None:
        """停止溯源追踪Agent。"""
        self._running = False
        self.logger.info("溯源追踪Agent已停止")

    async def _handle_trace(self, message: Message) -> Optional[Message]:
        """
        处理溯源指令，执行攻击路径还原。

        Args:
            message: 包含溯源指令的事件消息

        Returns:
            包含溯源报告的 Message（将自动发布到总线）
        """
        if not self._running:
            return None

        payload = message.payload
        alert_id = payload.get("alert_id", "UNKNOWN")
        target_ip = payload.get("target_ip", "192.168.1.1")
        source_ip = payload.get("source_ip", "unknown")
        attack_type = payload.get("attack_type", "unknown")

        # 生成模拟跳板链
        depth = min(
            random.randint(1, self.config.stage2.max_trace_depth),
            self.config.stage2.max_trace_depth
        )
        hop_chain = self._generate_hop_chain(source_ip, depth)

        # 生成模拟攻击时间线
        timeline = self._generate_timeline(attack_type, depth)

        # 识别根因
        if depth >= 3:
            root_cause = (
                f"检测到多层跳板代理（{depth}层），疑似APT组织利用僵尸网络中转。"
                f"真实攻击源可能位于 {hop_chain[-1]['country']} ({hop_chain[-1]['asn']})，"
                f"建议提交威胁情报平台进一步关联分析。"
            )
            confidence = round(random.uniform(0.60, 0.75), 2)
        elif depth == 2:
            root_cause = (
                f"攻击链包含{depth}个跳板节点，疑似使用VPN/代理服务中转。"
                f"出口节点位于 {hop_chain[0]['country']}，需进一步确认是否傀儡机。"
            )
            confidence = round(random.uniform(0.75, 0.88), 2)
        else:
            root_cause = (
                f"攻击源IP {source_ip} 为单跳直连，可能为真实攻击IP"
                f"（位于 {hop_chain[0]['country']}），或使用住宅代理隐藏。"
            )
            confidence = round(random.uniform(0.82, 0.95), 2)

        # 构建报告
        report = ForensicReport(
            report_id=f"FR-{uuid.uuid4().hex[:8].upper()}",
            alert_id=alert_id,
            target_ip=target_ip,
            hop_chain=hop_chain,
            timeline=timeline,
            root_cause=root_cause,
            confidence=confidence,
        )
        self._reports.append(report)

        self.logger.info(
            f"溯源完成: {alert_id} | 跳板链深度={depth} | "
            f"路径: {' → '.join(h['ip'] for h in hop_chain)} | 可信度={confidence:.0%}"
        )

        return Message(
            source="ForensicTracker",
            target="RightBrain",
            type="forensic_report",
            payload={
                "type": "forensic_report",
                "report_id": report.report_id,
                "alert_id": report.alert_id,
                "target_ip": report.target_ip,
                "hop_chain": report.hop_chain,
                "timeline": report.timeline,
                "root_cause": report.root_cause,
                "confidence": report.confidence,
                "generated_at": report.generated_at,
            },
        )

    def _generate_hop_chain(self, source_ip: str, depth: int) -> List[Dict[str, str]]:
        """
        生成模拟跳板链。

        Args:
            source_ip: 初始攻击源 IP
            depth:     跳板深度

        Returns:
            跳板链列表，从攻击源到目标
        """
        chain = []
        current_time = datetime.now()

        # 第一跳（可能为真实攻击源）
        geo = random.choice(self.IP_GEO_DB)
        chain.append({
            "hop": "1",
            "ip": source_ip,
            "country": geo["country"],
            "asn": geo["asn"],
            "region": geo["region"],
            "timestamp": (current_time - timedelta(seconds=random.randint(1, 30))).isoformat(),
            "note": "疑似真实攻击源" if random.random() > 0.4 else "可能为第一层跳板",
        })

        # 中间跳板
        for i in range(1, depth):
            hop_ip = f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            geo = random.choice(self.IP_GEO_DB)
            chain.append({
                "hop": str(i + 1),
                "ip": hop_ip,
                "country": geo["country"],
                "asn": geo["asn"],
                "region": geo["region"],
                "timestamp": (current_time + timedelta(seconds=random.randint(1, 10) * i)).isoformat(),
                "note": "跳板/代理节点" if i < depth else "疑似出口节点",
            })

        return chain

    def _generate_timeline(self, attack_type: str, depth: int) -> List[Dict[str, str]]:
        """
        生成模拟攻击时间线。

        Args:
            attack_type: 攻击类型
            depth:       跳板深度（用于估算时间跨度）

        Returns:
            攻击时间线事件列表
        """
        events = [
            {"timestamp": (datetime.now() - timedelta(minutes=30)).isoformat(),
             "event": f"攻击者通过第{1}跳节点发起初始侦察探测"},
            {"timestamp": (datetime.now() - timedelta(minutes=25)).isoformat(),
             "event": "执行端口扫描和服务识别"},
            {"timestamp": (datetime.now() - timedelta(minutes=20)).isoformat(),
             "event": f"识别到可利用服务，开始 {attack_type} 攻击准备"},
            {"timestamp": (datetime.now() - timedelta(minutes=10)).isoformat(),
             "event": f"通过跳板链发起 {attack_type} 攻击载荷"},
            {"timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
             "event": "攻击流量到达目标，触发防御系统检测"},
            {"timestamp": datetime.now().isoformat(),
             "event": "DFU防御系统检测到攻击并进行双引擎分析"},
        ]

        if depth >= 3:
            events.insert(3, {
                "timestamp": (datetime.now() - timedelta(minutes=15)).isoformat(),
                "event": "攻击者通过多层跳板进行流量混淆和IP隐藏",
            })

        return events

    def get_reports(self) -> List[ForensicReport]:
        """获取所有溯源报告。"""
        return self._reports

    # ── 真实时间线：自动订阅告警 ──

    async def _handle_alert(self, message: Message) -> None:
        """处理 threat_alert 事件，自动记录到攻击链时间线。"""
        if not self._running:
            return

        payload = message.payload
        indicator = payload.get("indicator", payload)
        alert_id = indicator.get("id", payload.get("id", str(uuid.uuid4())[:8]))

        if alert_id in self._tracked_ids:
            return
        self._tracked_ids.add(alert_id)

        entry = {
            "timestamp": datetime.now().isoformat(),
            "alert_id": alert_id,
            "source_organ": payload.get("source_organ", message.source),
            "attack_type": indicator.get("category", payload.get("category", "unknown")),
            "severity": indicator.get("severity", payload.get("severity", "medium")),
            "source_ip": indicator.get("source_ip", payload.get("source_ip", "")),
            "dst_ip": indicator.get("dst_ip", payload.get("dst_ip", "")),
            "description": (indicator.get("description", "") or "")[:200],
            "action": self._derive_action(
                indicator.get("severity", payload.get("severity", "medium")),
                indicator.get("category", payload.get("category", "unknown")),
            ),
        }
        self._timeline.append(entry)
        self.logger.debug(
            f"时间线记录: {alert_id} | {entry['attack_type']} | {entry['severity']}"
        )

    @staticmethod
    def _derive_action(severity: str, attack_type: str) -> str:
        """根据告警等级与攻击类型推导处置动作。"""
        sev = str(severity).lower()
        cat = str(attack_type).lower()

        if sev == "critical" or sev == "high":
            return "隔离源IP并阻断"
        if "exfil" in cat or "beacon" in cat:
            return "阻断连接并溯源"
        if sev == "medium":
            return "记录并加强监控"
        if cat in ("port_scan", "vuln"):
            return "拦截扫描源并关闭端口"
        return "归档观察"

    def get_timeline(self) -> List[Dict[str, Any]]:
        """获取完整攻击链时间线（按时间倒序，最新的在前）。"""
        return sorted(
            self._timeline,
            key=lambda e: e.get("timestamp", ""),
            reverse=True,
        )

    def export_json(self, filepath: str) -> str:
        """导出攻击链时间线为 JSON 文件。

        Args:
            filepath: 输出 JSON 文件路径（绝对路径）

        Returns:
            写入的文件路径
        """
        timeline = self.get_timeline()
        report = {
            "exported_at": datetime.now().isoformat(),
            "total_events": len(timeline),
            "timeline": timeline,
            "forensic_reports": [
                {
                    "report_id": r.report_id,
                    "alert_id": r.alert_id,
                    "target_ip": r.target_ip,
                    "hop_chain": r.hop_chain,
                    "root_cause": r.root_cause,
                    "confidence": r.confidence,
                    "generated_at": r.generated_at,
                }
                for r in self._reports
            ],
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        self.logger.info(f"时间线已导出: {filepath} ({len(timeline)} 条事件)")
        return filepath
