"""
漏洞扫描Agent：模拟对目标系统进行漏洞扫描，检测开放端口、服务版本、已知CVE匹配。
输出标准格式漏洞告警。

v2 做实：
- 加基础 TCP 端口扫描：用 socket.connect_ex 扫描本地监听端口 1-1024 及
  常见高危端口（135/139/445/3389/5985/6379/27017/3306/5432/8080/9200）
- 记录开放端口列表并通过 message_bus 发布
- 原 VulnSimulator 保留为 demo 模式
"""

import asyncio
import logging
import random
import socket
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from communication.message_bus import Message, MessageBus, get_message_bus
from communication.skill_middleware import (
    SkillMiddleware,
    ThreatIndicator,
    ThreatCategory,
    AlertSeverity,
)
from config import Config
from utils.logger import get_logger

# 常见高危/敏感端口（含知名服务默认端口）
HIGH_RISK_PORTS: List[int] = [
    135, 139, 445,          # Windows SMB/RPC
    3389,                    # RDP
    5985, 5986,             # WinRM
    6379,                    # Redis
    27017,                   # MongoDB
    3306,                    # MySQL
    5432,                    # PostgreSQL
    8080, 8443,             # HTTP 代理/管理
    9200, 9300,             # Elasticsearch
    11211,                   # Memcached
    5000,                    # Docker Registry
    2375, 2376,             # Docker API
    9000,                    # Portainer / MinIO
    15672,                   # RabbitMQ 管理
]


class VulnScannerAgent:
    """
    漏洞扫描感知模块 Agent。

    职责：
    1. 订阅漏洞报告消息（vuln_report）
    2. 解析 CVE 编号、受影响服务、CVSS 评分
    3. CVSS 评分超过阈值时生成标准漏洞告警
    4. 发布 vuln_alert 事件供双引擎处理
    5. v2：基于 socket.connect_ex 进行真实 TCP 端口扫描
    """

    # 端口→服务名映射
    PORT_SERVICE_MAP: Dict[int, str] = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        135: "MSRPC", 139: "NetBIOS", 3389: "RDP",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        27017: "MongoDB", 8080: "HTTP-Alt", 9200: "Elasticsearch",
        5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        11211: "Memcached", 5000: "Docker-Registry",
        2375: "Docker-API", 2376: "Docker-API-TLS",
        9000: "Portainer/MinIO", 15672: "RabbitMQ-Mgmt",
    }

    def __init__(self, config: Config, demo_mode: bool = True):
        """
        Args:
            config: 全局配置对象
            demo_mode: True 时仅保留模拟 CVE 匹配逻辑；
                       False 时额外启动 TCP 端口扫描后台任务。
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.middleware = SkillMiddleware()
        self.logger: logging.Logger = get_logger("VulnScanner")
        self.demo_mode = demo_mode

        # 已告警去重（按 CVE + target_ip）
        self._alerted: set = set()

        # 真实扫描结果
        self._open_ports: List[Dict[str, Any]] = []
        self._last_scan_time: Optional[str] = None

        self._running = False
        self._scan_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """启动漏洞扫描Agent，订阅漏洞报告消息。非 demo 模式启动后台端口扫描。"""
        self._running = True
        await self.bus.subscribe("vuln_report", self._handle_vuln_report)
        self.logger.info("漏洞扫描Agent已启动，正在监听漏洞报告...")

        if not self.demo_mode:
            self._scan_task = asyncio.create_task(self._port_scan_loop())
            self.logger.info("后台 TCP 端口扫描循环已启动")

    async def stop(self) -> None:
        """停止漏洞扫描Agent。"""
        self._running = False
        self.logger.info("漏洞扫描Agent已停止")

    async def _handle_vuln_report(self, message: Message) -> Optional[Message]:
        """
        处理漏洞报告消息，解析并生成标准告警。

        Args:
            message: 包含漏洞数据的事件消息

        Returns:
            包含标准化 ThreatIndicator 的 Message（将自动发布到总线）
        """
        if not self._running:
            return None

        payload = message.payload
        cve_id = payload.get("cve_id", "CVE-UNKNOWN")
        service = payload.get("service", "unknown")
        cvss_score = payload.get("cvss_score", 0.0)
        target_ip = payload.get("target_ip", "192.168.1.1")
        description = payload.get("description", "")

        # 去重检测
        dedup_key = f"{cve_id}:{target_ip}"
        if dedup_key in self._alerted:
            self.logger.debug(f"漏洞 {cve_id} 已告警过，跳过")
            return None
        self._alerted.add(dedup_key)

        # 根据 CVSS 评分分级
        if cvss_score >= 9.0:
            severity = AlertSeverity.SEVERE
        elif cvss_score >= 7.0:
            severity = AlertSeverity.HIGH
        elif cvss_score >= self.config.stage2.vuln_cvss_threshold:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        indicator = ThreatIndicator(
            id=f"VULN-{uuid.uuid4().hex[:8].upper()}",
            category=ThreatCategory.VULN,
            severity=severity,
            source_ip="N/A",
            target_ip=target_ip,
            target_port=payload.get("port"),
            description=f"[{cve_id}] CVSS {cvss_score:.1f} - {service}: {description}",
            raw_data={
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "service": service,
                "port": payload.get("port"),
                "description": description,
                "affected_version": payload.get("affected_version", ""),
                "scanner_type": "vuln_scanner",
            },
            detection_time=datetime.now().isoformat(),
        )

        self.logger.info(
            f"检测到漏洞 {cve_id} | CVSS {cvss_score:.1f} | {service} | 严重级别: {severity.value}"
        )

        alert_payload = indicator.to_dict()
        alert_payload["source_organ"] = "vuln_scanner"
        return Message(
            source="VulnScanner",
            target="*",
            type="threat_alert",
            payload=alert_payload,
        )

    # ── 真实 TCP 端口扫描 ──

    async def _port_scan_loop(self) -> None:
        """后台循环：每 300 秒扫描一次本地端口。"""
        while self._running:
            try:
                await self._scan_ports()
            except Exception as e:
                self.logger.error(f"端口扫描异常: {e}")
            await asyncio.sleep(300)

    async def _scan_ports(self) -> None:
        """基于 socket.connect_ex 扫描本地 TCP 端口。

        扫描范围：1-1024 已知服务端口 + HIGH_RISK_PORTS 高危端口（去重）。
        记录开放端口并通过 message_bus 发布。同步扫描放入线程池，避免阻塞事件循环。
        """
        try:
            # 同步 socket 扫描放入线程池，防止阻塞 asyncio 事件循环
            open_ports = await asyncio.to_thread(self._scan_ports_sync)
        except Exception as e:
            self.logger.error(f"端口扫描失败: {e}")
            return

        self._open_ports = open_ports
        self._last_scan_time = datetime.now().isoformat()

        high_risk_open = [p for p in open_ports if p["high_risk"]]
        self.logger.info(
            f"端口扫描完成: {len(open_ports)} 个开放, "
            f"其中 {len(high_risk_open)} 个高危"
        )

        # 对高危开放端口发布告警
        for entry in high_risk_open:
            await self._publish_port_alert(entry)

        # 发布扫描汇总事件
        await self.bus.publish(Message(
            source="VulnScanner",
            target="EventAggregator",
            type="port_scan_result",
            payload={
                "source_organ": "vuln_scanner",
                "scan_time": self._last_scan_time,
                "total_scanned": len(open_ports),
                "open_ports": open_ports,
                "high_risk_count": len(high_risk_open),
            },
        ))

    def _scan_ports_sync(self) -> List[Dict[str, Any]]:
        """同步执行 TCP 端口扫描（在线程池中运行）。

        Returns:
            开放端口列表：[{port, service, high_risk}]
        """
        target = "127.0.0.1"
        # 合并端口列表（去重、排序）
        all_ports = sorted(set(
            list(range(1, 1025)) + HIGH_RISK_PORTS
        ))

        open_ports: List[Dict[str, Any]] = []
        for port in all_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:  # 端口开放
                    service = self.PORT_SERVICE_MAP.get(port, "unknown")
                    is_high_risk = port in HIGH_RISK_PORTS
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "high_risk": is_high_risk,
                    })
            except Exception:
                continue
        return open_ports

    async def _publish_port_alert(self, port_entry: Dict[str, Any]) -> None:
        """为高危开放端口发布 threat_alert。"""
        indicator = ThreatIndicator(
            id=f"PORT-{uuid.uuid4().hex[:8].upper()}",
            category=ThreatCategory.VULN,
            severity=AlertSeverity.MEDIUM,
            source_ip="127.0.0.1",
            target_ip="127.0.0.1",
            target_port=port_entry["port"],
            description=(
                f"高危端口开放: {port_entry['port']}/{port_entry['service']} "
                f"在 localhost 监听，可能存在攻击面暴露"
            ),
            raw_data={
                "scan_type": "tcp_connect",
                "port": port_entry["port"],
                "service": port_entry["service"],
                "scanner_type": "vuln_scanner",
            },
            detection_time=datetime.now().isoformat(),
        )
        alert_payload = indicator.to_dict()
        alert_payload["source_organ"] = "vuln_scanner"
        await self.bus.publish(Message(
            source="VulnScanner",
            target="*",
            type="threat_alert",
            payload=alert_payload,
        ))

    def get_open_ports(self) -> List[Dict[str, Any]]:
        """获取最近一次扫描的开放端口列表。"""
        return self._open_ports


class VulnSimulator:
    """
    漏洞数据模拟器。
    生成模拟的 CVE 漏洞报告，注入到消息总线中。
    """

    # 预定义 CVE 数据库
    CVE_TEMPLATES = [
        {
            "cve_id": "CVE-2024-6387",
            "service": "OpenSSH",
            "port": 22,
            "cvss_base": 8.1,
            "description": "RegreSSHion - OpenSSH 信号处理器竞争条件导致远程代码执行",
            "affected_version": "8.5p1 ~ 9.8p1",
        },
        {
            "cve_id": "CVE-2024-3094",
            "service": "XZ Utils",
            "port": None,
            "cvss_base": 10.0,
            "description": "xz-utils 后门植入，SSHD 认证绕过",
            "affected_version": "5.6.0 ~ 5.6.1",
        },
        {
            "cve_id": "CVE-2023-44487",
            "service": "HTTP/2",
            "port": 443,
            "cvss_base": 7.5,
            "description": "HTTP/2 快速重置攻击导致拒绝服务（Rapid Reset）",
            "affected_version": "多版本",
        },
        {
            "cve_id": "CVE-2023-38545",
            "service": "libcurl",
            "port": 443,
            "cvss_base": 8.8,
            "description": "SOCKS5 代理堆溢出导致远程代码执行",
            "affected_version": "7.69.0 ~ 8.3.0",
        },
        {
            "cve_id": "CVE-2024-21683",
            "service": "Confluence",
            "port": 8090,
            "cvss_base": 7.0,
            "description": "Atlassian Confluence Data Center 远程代码执行",
            "affected_version": "< 8.6.3",
        },
        {
            "cve_id": "CVE-2024-27198",
            "service": "JetBrains TeamCity",
            "port": 8111,
            "cvss_base": 9.8,
            "description": "TeamCity 身份验证绕过导致远程代码执行",
            "affected_version": "< 2023.11.4",
        },
        {
            "cve_id": "CVE-2023-46805",
            "service": "Ivanti Connect Secure",
            "port": 443,
            "cvss_base": 8.2,
            "description": "Ivanti ICS 身份验证绕过漏洞",
            "affected_version": "9.x / 22.x",
        },
        {
            "cve_id": "CVE-2024-21887",
            "service": "ConnectWise ScreenConnect",
            "port": 8041,
            "cvss_base": 9.1,
            "description": "ScreenConnect 路径遍历导致远程代码执行",
            "affected_version": "< 23.9.8",
        },
    ]

    def __init__(self, config: Config):
        self.config = config
        self.bus = get_message_bus()
        self.logger = get_logger("VulnSimulator")

    async def inject_reports(self, target_ip: str = "192.168.1.1") -> List[dict]:
        """
        向消息总线注入模拟漏洞报告。

        Args:
            target_ip: 目标主机 IP

        Returns:
            注入的漏洞报告列表
        """
        count = self.config.simulator.vuln_report_count
        sampled = random.sample(self.CVE_TEMPLATES, min(count, len(self.CVE_TEMPLATES)))
        reports = []

        for template in sampled:
            # 引入随机偏差模拟真实扫描波动
            jitter = random.uniform(-0.5, 0.5)
            cvss_score = round(min(max(template["cvss_base"] + jitter, 0.0), 10.0), 1)
            report = {
                **template,
                "cvss_score": cvss_score,
                "target_ip": target_ip,
            }
            reports.append(report)

            await self.bus.publish(
                Message(
                    source="VulnSimulator",
                    target="VulnScanner",
                    type="vuln_report",
                    payload=report,
                )
            )
            self.logger.info(f"注入漏洞报告: {template['cve_id']} (CVSS {cvss_score:.1f})")

        self.logger.info(f"共注入 {len(reports)} 条漏洞报告")
        return reports
