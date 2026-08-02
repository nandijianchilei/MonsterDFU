"""
模拟攻击流量生成器
生成模拟攻击数据：DDoS洪水、端口扫描、暴力破解、漏洞报告、异常日志。
"""

import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TrafficPacket:
    """模拟流量数据包。"""
    type: str               # 攻击类型：ddos / port_scan / brute_force
    source_ip: str          # 源 IP
    target_ip: str          # 目标 IP
    target_port: int        # 目标端口
    size: int               # 流量大小（字节）
    attempts: int           # 尝试次数（仅暴力破解有意义）
    timestamp: float        # 时间戳


@dataclass
class VulnReport:
    """模拟漏洞报告。"""
    cve_id: str
    service: str
    port: Optional[int]
    cvss_score: float
    description: str
    affected_version: str


@dataclass
class LogAnomaly:
    """模拟异常日志事件。"""
    type: str               # login_failure / privilege_escalation / sensitive_access
    username: str
    source_ip: str
    target_ip: str
    service: str
    detail: str
    port: Optional[int] = None


class AttackSimulator:
    """
    模拟攻击数据生成器。

    支持五种攻击/异常数据类型：
    1. DDoS 洪水：模拟多个僵尸节点高频发送 HTTP 请求
    2. 端口扫描：模拟 nmap/masscan 风格的全端口或选择性扫描
    3. 暴力破解：模拟 hydra/medusa 风格的 SSH 暴力破解
    4. 漏洞报告：模拟 CVE 漏洞扫描结果
    5. 异常日志：模拟登录失败、权限变更、敏感文件访问
    """

    # 预设的攻击源 IP 池
    DDOS_IP_POOL = [
        "45.33.32.156",
        "104.237.155.121",
        "198.58.118.167",
        "23.239.11.43",
        "172.104.21.87",
        "139.162.53.21",
    ]

    SCAN_IP_POOL = [
        "91.234.42.18",
        "185.220.101.34",
        "5.188.62.14",
    ]

    BRUTE_IP_POOL = [
        "103.45.78.92",
        "61.177.172.140",
        "218.92.1.180",
    ]

    # 预设漏洞模板
    VULN_TEMPLATES = [
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

    # 预定义异常日志模板
    LOG_TEMPLATES = [
        {
            "type": "login_failure",
            "username": "root",
            "service": "sshd",
            "port": 22,
            "detail": "root 用户 SSH 多次密码错误尝试",
        },
        {
            "type": "login_failure",
            "username": "admin",
            "service": "rdp",
            "port": 3389,
            "detail": "admin 用户 RDP 远程桌面暴力破解",
        },
        {
            "type": "privilege_escalation",
            "username": "www-data",
            "service": "sudo",
            "detail": "www-data 用户尝试执行 sudo 提权操作",
        },
        {
            "type": "sensitive_access",
            "username": "app_user",
            "resource": "/etc/shadow",
            "detail": "app_user 访问影子密码文件 /etc/shadow",
        },
    ]

    def __init__(
        self,
        ddos_source_count: int = 3,
        ddos_rate: int = 150,
        scan_port_range: tuple = (1, 65535),
        scan_speed: int = 50,
        brute_attempts: int = 200,
        brute_target_port: int = 22,
        target_ip: str = "192.168.1.1",
    ):
        """
        Args:
            ddos_source_count:  DDoS 攻击源IP数量
            ddos_rate:          每个源IP每秒请求数
            scan_port_range:    扫描端口范围 (start, end)
            scan_speed:         扫描速度（端口/秒）
            brute_attempts:     暴力破解尝试次数
            brute_target_port:  暴力破解目标端口
            target_ip:          目标 IP
        """
        self.ddos_source_count = ddos_source_count
        self.ddos_rate = ddos_rate
        self.scan_port_range = scan_port_range
        self.scan_speed = scan_speed
        self.brute_attempts = brute_attempts
        self.brute_target_port = brute_target_port
        self.target_ip = target_ip

    def generate_ddos(self) -> List[Dict]:
        """
        生成 DDoS 洪水模拟数据。

        Returns:
            模拟流量包列表
        """
        packets = []
        source_ips = self.DDOS_IP_POOL[: self.ddos_source_count]
        now = time.time()

        for ip in source_ips:
            for i in range(self.ddos_rate):
                packet = {
                    "type": "ddos",
                    "source_ip": ip,
                    "target_ip": self.target_ip,
                    "target_port": random.choice([80, 443, 8080]),
                    "size": random.randint(500, 1500),
                    "attempts": 1,
                    "timestamp": now + (i / self.ddos_rate),
                }
                packets.append(packet)

        return packets

    def generate_port_scan(self) -> List[Dict]:
        """
        生成端口扫描模拟数据。

        Returns:
            模拟流量包列表
        """
        packets = []
        source_ip = random.choice(self.SCAN_IP_POOL)
        now = time.time()

        start_port, end_port = self.scan_port_range
        total_ports = min(self.scan_speed * 2, end_port - start_port + 1)
        scanned_ports = random.sample(range(start_port, end_port + 1), total_ports)

        for i, port in enumerate(scanned_ports):
            packet = {
                "type": "port_scan",
                "source_ip": source_ip,
                "target_ip": self.target_ip,
                "target_port": port,
                "size": random.randint(40, 60),
                "attempts": 1,
                "timestamp": now + (i / self.scan_speed),
            }
            packets.append(packet)

        return packets

    def generate_brute_force(self) -> List[Dict]:
        """
        生成暴力破解模拟数据。

        Returns:
            模拟流量包列表
        """
        packets = []
        source_ip = random.choice(self.BRUTE_IP_POOL)
        now = time.time()

        for i in range(self.brute_attempts):
            packet = {
                "type": "brute_force",
                "source_ip": source_ip,
                "target_ip": self.target_ip,
                "target_port": self.brute_target_port,
                "size": random.randint(200, 800),
                "attempts": self.brute_attempts,
                "timestamp": now + (i * 0.05),
            }
            packets.append(packet)

        return packets

    # ==================== 阶段2新增：漏洞报告 + 异常日志 ====================

    def generate_vuln_reports(self, count: int = 3) -> List[Dict]:
        """
        生成模拟漏洞报告。

        Args:
            count: 生成数量

        Returns:
            漏洞报告列表
        """
        sampled = random.sample(self.VULN_TEMPLATES, min(count, len(self.VULN_TEMPLATES)))
        reports = []

        for template in sampled:
            jitter = random.uniform(-0.5, 0.5)
            cvss_score = round(min(max(template["cvss_base"] + jitter, 0.0), 10.0), 1)
            report = {
                "cve_id": template["cve_id"],
                "service": template["service"],
                "port": template["port"],
                "cvss_score": cvss_score,
                "description": template["description"],
                "affected_version": template["affected_version"],
                "target_ip": self.target_ip,
            }
            reports.append(report)

        return reports

    def generate_log_anomalies(self, count: int = 4) -> List[Dict]:
        """
        生成模拟异常日志事件。

        Args:
            count: 生成数量

        Returns:
            异常日志事件列表
        """
        sampled = random.sample(self.LOG_TEMPLATES, min(count, len(self.LOG_TEMPLATES)))
        anomalies = []
        login_ips = {}

        for template in sampled:
            source_ip = f"10.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            anomaly = {
                "type": template["type"],
                "source_ip": source_ip,
                "target_ip": self.target_ip,
                "username": template.get("username", "unknown"),
                "service": template.get("service", ""),
                "port": template.get("port"),
                "detail": template.get("detail", ""),
            }
            anomalies.append(anomaly)

        return anomalies

    def get_all_scenarios(self) -> Dict[str, List[Dict]]:
        """
        获取所有攻击场景的流量数据。

        Returns:
            {"ddos": [...], "port_scan": [...], "brute_force": [...]}
        """
        return {
            "ddos": self.generate_ddos(),
            "port_scan": self.generate_port_scan(),
            "brute_force": self.generate_brute_force(),
        }

    def get_stage2_data(self) -> Dict[str, List[Dict]]:
        """
        获取阶段2全部数据：流量 + 漏洞 + 日志。

        Returns:
            {"ddos": [...], "port_scan": [...], "brute_force": [...],
             "vuln_reports": [...], "log_anomalies": [...]}
        """
        return {
            **self.get_all_scenarios(),
            "vuln_reports": self.generate_vuln_reports(),
            "log_anomalies": self.generate_log_anomalies(),
        }
