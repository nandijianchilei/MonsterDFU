"""
攻击模拟器 — 持续注入多种攻击流量到 RabbitMQ 供压力测试。

环境变量: RABBITMQ_URL
用法: 单独容器运行 `docker-compose --profile attack up attack-sim`
"""

import asyncio
import os
import random
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.rabbitmq_bus import RabbitMQBus, Message
from utils.logger import get_logger

logger = get_logger("AttackSimulator")

ATTACK_TEMPLATES = [
    # DDoS
    {"type": "ddos", "packets": 550, "ports": 1, "severity": "severe"},
    {"type": "ddos", "packets": 250, "ports": 1, "severity": "high"},
    {"type": "ddos", "packets": 120, "ports": 1, "severity": "medium"},
    # Port Scan
    {"type": "port_scan", "packets": 10, "ports": 80, "severity": "high"},
    {"type": "port_scan", "packets": 5, "ports": 35, "severity": "medium"},
    # Brute Force
    {"type": "brute_force", "packets": 80, "ports": 1, "severity": "high"},
    {"type": "brute_force", "packets": 40, "ports": 1, "severity": "medium"},
    # SQL Injection
    {"type": "sql_injection", "packets": 15, "ports": 1, "severity": "high",
     "payload": "SELECT * FROM users WHERE 1=1 --"},
    {"type": "sql_injection", "packets": 5, "ports": 1, "severity": "medium",
     "payload": "UNION SELECT password FROM admin"},
    # Malware C2 Beacon
    {"type": "malware_c2", "packets": 8, "ports": 443, "severity": "severe",
     "payload": "beacon_heartbeat"},
    {"type": "malware_c2", "packets": 3, "ports": 8080, "severity": "high",
     "payload": "c2_checkin"},
    # Web Attack (Directory Traversal / File Inclusion)
    {"type": "web_attack", "packets": 12, "ports": 1, "severity": "high",
     "payload": "../../etc/passwd"},
    {"type": "web_attack", "packets": 6, "ports": 1, "severity": "medium",
     "payload": "/proc/self/environ"},
    # DNS Tunnel
    {"type": "dns_tunnel", "packets": 50, "ports": 53, "severity": "high",
     "payload": "base64encodeddata.malicious.example.com"},
    {"type": "dns_tunnel", "packets": 25, "ports": 53, "severity": "medium",
     "payload": "tunnel.exfil.example.com"},
    # Data Exfiltration
    {"type": "data_exfiltration", "packets": 100, "ports": 1, "severity": "severe",
     "payload": "large_outbound_transfer"},
    {"type": "data_exfiltration", "packets": 40, "ports": 1, "severity": "high",
     "payload": "sensitive_file_upload"},
]


class AttackSimulator:
    def __init__(self):
        self.bus = RabbitMQBus()
        self.count = 0
        self.ips = [
            f"218.92.{random.randint(1, 254)}.{random.randint(1, 254)}"
            for _ in range(20)
        ]

    async def start(self):
        await self.bus.connect("attack_simulator", binding_keys=["defense_plan"])
        logger.info("[AttackSimulator] 开始注入攻击流量...")
        await self._attack_loop()

    async def _attack_loop(self):
        while True:
            template = random.choice(ATTACK_TEMPLATES)
            src_ip = random.choice(self.ips)
            self.count += 1

            msg = Message(
                source="AttackSimulator",
                target="*",
                msg_type="raw_traffic",
                payload={
                    "source_ip": src_ip,
                    "type": template["type"],
                    "packets": template["packets"],
                    "ports": template["ports"],
                    "payload": template.get("payload", ""),
                    "timestamp": datetime.now().isoformat(),
                },
            )
            await self.bus.publish(msg)
            logger.info(
                f"[攻击] #{self.count}: {template['type']} ({template['severity']})"
                f" 来自 {src_ip}"
            )
            await asyncio.sleep(random.uniform(3, 10))


async def main():
    sim = AttackSimulator()
    try:
        await sim.start()
    except KeyboardInterrupt:
        logger.info("[AttackSimulator] 已停止")


if __name__ == "__main__":
    asyncio.run(main())
