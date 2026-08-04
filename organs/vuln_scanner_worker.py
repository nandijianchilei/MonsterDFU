"""
漏洞扫描 Worker — 接收扫描任务，返回漏洞报告。

环境变量: RABBITMQ_URL
"""

import asyncio
import os
import sys
import random
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from utils.logger import get_logger

logger = get_logger("VulnScannerWorker")

VULN_DB = [
    {"id": "CVE-2024-1234", "name": "SQL Injection", "severity": "high"},
    {"id": "CVE-2024-5678", "name": "XSS", "severity": "medium"},
    {"id": "CVE-2024-9012", "name": "RCE", "severity": "critical"},
    {"id": "CVE-2024-3456", "name": "CSRF", "severity": "low"},
    {"id": "CVE-2024-7890", "name": "Path Traversal", "severity": "medium"},
]


class VulnScannerWorker:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.scan_count = 0

    async def start(self):
        await self.bus.connect("organ_vuln")
        await self.bus.subscribe("scan_request", self.on_scan)
        logger.info("[VulnScannerWorker] 已就绪，等待扫描请求...")

    async def on_scan(self, msg: Message):
        target = msg.payload.get("target", "unknown")
        self.scan_count += 1

        # 模拟扫描结果
        findings = random.sample(VULN_DB, k=random.randint(0, 3))
        report = Message(
            source="VulnScanner",
            target="*",
            msg_type="vuln_report",
            payload={
                "scan_id": f"SCAN-{self.scan_count:04d}",
                "target": target,
                "findings": findings,
                "total_vulns": len(findings),
                "timestamp": datetime.now().isoformat(),
            },
        )
        await self.bus.publish(report)
        logger.info(f"[漏洞扫描] #{self.scan_count}: {target} -> {len(findings)} 漏洞")


async def main():
    worker = VulnScannerWorker()
    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
