"""
日志审计Agent：模拟安全日志分析，检测异常登录、权限变更、敏感文件访问。
输出标准格式审计告警。

v2 做实：
- 读 Windows 事件日志：用 wevtutil 命令读取最近 100 条
  Security/System/Application 事件
- 筛选登录失败（4625）、权限提升（4672）、服务异常（7034/7031）
  等安全相关事件
- 通过 message_bus 发布告警
"""

import asyncio
import logging
import os
import random
import re
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

# Windows 安全事件 ID → 描述映射
SECURITY_EVENT_MAP: Dict[int, str] = {
    4624: "登录成功",
    4625: "登录失败",
    4634: "注销",
    4648: "显式凭据登录",
    4672: "特殊权限指派（权限提升）",
    4688: "新进程创建",
    4697: "服务安装",
    4720: "用户账户创建",
    4722: "用户账户启用",
    4726: "用户账户删除",
    4732: "安全组添加成员",
    4740: "用户账户锁定",
    4767: "用户账户解锁",
    4776: "凭据验证",
}

SYSTEM_EVENT_MAP: Dict[int, str] = {
    7031: "服务异常终止",
    7034: "服务意外终止",
    7040: "服务启动类型更改",
    7045: "新服务已安装",
}

# 需要告警的事件 ID（Security log）
ALERT_EVENT_IDS: set = {4625, 4672, 4720, 4726, 4740, 4697, 4732, 4776}
# 需要告警的事件 ID（System log）
ALERT_SYSTEM_IDS: set = {7031, 7034, 7045}


class LogAuditorAgent:
    """
    日志审计感知模块 Agent。

    职责：
    1. 订阅异常日志事件（log_anomaly）
    2. 检测异常登录、权限变更、敏感文件访问三类审计异常
    3. 输出标准 ThreatIndicator 告警
    4. 发布 audit_alert 事件供双引擎处理
    """

    # 审计异常类型
    ANOMALY_LOGIN_FAIL = "login_failure"      # 异常登录失败
    ANOMALY_PRIVILEGE = "privilege_escalation" # 权限变更
    ANOMALY_SENSITIVE = "sensitive_access"     # 敏感文件访问

    def __init__(self, config: Config, demo_mode: bool = True):
        """
        Args:
            config: 全局配置对象
            demo_mode: True 时仅保留模拟 log_anomaly 订阅；
                       False 时额外启动 Windows Event Log 读取后台任务。
        """
        self.config = config
        self.bus: MessageBus = get_message_bus()
        self.middleware = SkillMiddleware()
        self.logger: logging.Logger = get_logger("LogAuditor")
        self.demo_mode = demo_mode

        # 登录失败计数窗口: source_ip → count
        self._login_fail_counter: Dict[str, int] = {}

        # 已告警去重
        self._alerted: set = set()

        # 真实事件日志缓存
        self._event_log_cache: List[Dict[str, Any]] = []

        self._running = False
        self._log_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """启动日志审计Agent，订阅异常日志事件。非 demo 模式读取 Windows 事件日志。"""
        self._running = True
        await self.bus.subscribe("log_anomaly", self._handle_log_anomaly)
        self.logger.info("日志审计Agent已启动，正在监听审计事件...")

        if not self.demo_mode:
            self._log_task = asyncio.create_task(self._event_log_loop())
            self.logger.info("Windows 事件日志采集循环已启动")

    async def stop(self) -> None:
        """停止日志审计Agent。"""
        self._running = False
        self.logger.info("日志审计Agent已停止")

    async def _handle_log_anomaly(self, message: Message) -> Optional[Message]:
        """
        处理异常日志事件，分析并生成标准告警。

        Args:
            message: 包含异常日志数据的事件消息

        Returns:
            包含标准化 ThreatIndicator 的 Message，或 None（不触发告警）
        """
        if not self._running:
            return None

        payload = message.payload
        anomaly_type = payload.get("type", "")
        source_ip = payload.get("source_ip", "unknown")
        target_ip = payload.get("target_ip", "192.168.1.1")
        detail = payload.get("detail", "")

        # 登录失败类：需要累计达到阈值才告警
        if anomaly_type == self.ANOMALY_LOGIN_FAIL:
            return await self._handle_login_failure(payload, source_ip, target_ip, detail)

        # 权限变更、敏感文件访问：直接告警
        return await self._handle_direct_anomaly(anomaly_type, payload, source_ip, target_ip, detail)

    async def _handle_login_failure(
        self, payload: dict, source_ip: str, target_ip: str, detail: str
    ) -> Optional[Message]:
        """处理登录失败异常，累计阈值后告警。"""
        self._login_fail_counter[source_ip] = self._login_fail_counter.get(source_ip, 0) + 1
        count = self._login_fail_counter[source_ip]
        threshold = self.config.stage2.audit_login_fail_threshold

        dedup_key = f"login_fail:{source_ip}:{target_ip}"
        if dedup_key in self._alerted:
            return None

        if count >= threshold:
            self._alerted.add(dedup_key)
            severity = AlertSeverity.HIGH if count >= threshold * 2 else AlertSeverity.MEDIUM

            indicator = ThreatIndicator(
                id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
                category=ThreatCategory.AUDIT,
                severity=severity,
                source_ip=source_ip,
                target_ip=target_ip,
                target_port=payload.get("port"),
                description=f"异常登录检测: {source_ip} 在短时间内失败 {count} 次 | {detail}",
                raw_data={
                    "anomaly_type": "login_failure",
                    "failed_count": count,
                    "username": payload.get("username", "unknown"),
                    "source_service": payload.get("service", "sshd"),
                    "auditor_type": "log_auditor",
                },
                detection_time=datetime.now().isoformat(),
            )

            self.logger.info(
                f"审计告警: 登录失败 {source_ip} → {target_ip} ({count}次) | 严重级别: {severity.value}"
            )

            alert_payload = indicator.to_dict()
            alert_payload["source_organ"] = "log_auditor"
            return Message(
                source="LogAuditor",
                target="*",
                type="threat_alert",
                payload=alert_payload,
            )
        else:
            self.logger.debug(f"登录失败计数: {source_ip} = {count}/{threshold}")
            return None

    async def _handle_direct_anomaly(
        self, anomaly_type: str, payload: dict, source_ip: str, target_ip: str, detail: str
    ) -> Optional[Message]:
        """处理权限变更、敏感文件访问等直接告警类异常。"""
        dedup_key = f"{anomaly_type}:{source_ip}:{target_ip}"
        if dedup_key in self._alerted:
            return None
        self._alerted.add(dedup_key)

        if anomaly_type == self.ANOMALY_PRIVILEGE:
            severity = AlertSeverity.HIGH
            desc_prefix = "权限变更检测"
        elif anomaly_type == self.ANOMALY_SENSITIVE:
            severity = AlertSeverity.MEDIUM
            desc_prefix = "敏感文件访问"
        else:
            severity = AlertSeverity.LOW
            desc_prefix = "未知审计事件"

        indicator = ThreatIndicator(
            id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            category=ThreatCategory.AUDIT,
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=payload.get("port"),
            description=f"{desc_prefix}: {detail}",
            raw_data={
                "anomaly_type": anomaly_type,
                "username": payload.get("username", "unknown"),
                "resource": payload.get("resource", ""),
                "auditor_type": "log_auditor",
            },
            detection_time=datetime.now().isoformat(),
        )

        self.logger.info(
            f"审计告警: {desc_prefix} {source_ip} → {target_ip} | 严重级别: {severity.value}"
        )

        alert_payload = indicator.to_dict()
        alert_payload["source_organ"] = "log_auditor"
        return Message(
            source="LogAuditor",
            target="*",
            type="threat_alert",
            payload=alert_payload,
        )

    # ── Windows 事件日志读取 ──

    async def _event_log_loop(self) -> None:
        """后台循环：每 120 秒读取一次 Windows 事件日志。"""
        while self._running:
            try:
                await self._read_windows_events()
            except Exception as e:
                self.logger.error(f"Windows 事件日志读取异常: {e}")
            await asyncio.sleep(120)

    async def _read_windows_events(self) -> None:
        """使用 wevtutil 命令读取 Security / System 事件日志。

        筛选安全相关事件（4625 登录失败、4672 权限提升、
        7031/7034 服务异常）并通过 message_bus 发布告警。
        """
        new_events: List[Dict[str, Any]] = []

        # 读取 Security 日志（最近 100 条）
        security_events = await self._query_wevtutil("Security", 100)
        if security_events:
            for evt in security_events:
                event_id = evt.get("event_id", 0)
                if event_id in ALERT_EVENT_IDS:
                    evt["source_log"] = "Security"
                    new_events.append(evt)

        # 读取 System 日志（最近 100 条）
        system_events = await self._query_wevtutil("System", 100)
        if system_events:
            for evt in system_events:
                event_id = evt.get("event_id", 0)
                if event_id in ALERT_SYSTEM_IDS:
                    evt["source_log"] = "System"
                    new_events.append(evt)

        self._event_log_cache = new_events

        if new_events:
            self.logger.info(f"Windows 事件日志: 发现 {len(new_events)} 条安全相关事件")
            for evt in new_events:
                await self._publish_event_alert(evt)

    async def _query_wevtutil(self, log_name: str, count: int) -> List[Dict[str, Any]]:
        """通过 wevtutil 查询 Windows 事件日志。

        Args:
            log_name: 日志名称（Security / System / Application）
            count: 返回最近 N 条事件

        Returns:
            解析后的事件列表
        """
        events: List[Dict[str, Any]] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "wevtutil", "qe", log_name,
                "/c:{}".format(count),
                "/rd:true", "/f:text",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )

            if proc.returncode != 0:
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                if err_msg and "Access is denied" not in err_msg:
                    self.logger.debug(f"wevtutil {log_name} 查询失败: {err_msg}")
                return events

            text = stdout.decode("utf-8", errors="replace")
            events = self._parse_wevtutil_text(text)
        except asyncio.TimeoutError:
            self.logger.warning(f"wevtutil {log_name} 查询超时")
        except FileNotFoundError:
            self.logger.warning("wevtutil 命令不可用")
        except Exception as e:
            self.logger.debug(f"wevtutil {log_name} 异常: {e}")

        return events

    @staticmethod
    def _parse_wevtutil_text(text: str) -> List[Dict[str, Any]]:
        """解析 wevtutil /f:text 输出。

        每事件以 'Event[' 分隔，提取 EventID、Date、Time 等字段。
        """
        events: List[Dict[str, Any]] = []
        # 按 Event[ 分割
        blocks = re.split(r'\n(?=Event\[\d+\])', text.strip())

        for block in blocks:
            if not block.strip():
                continue

            entry: Dict[str, Any] = {}
            # 提取 EventID
            m = re.search(r'EventID:\s*(\d+)', block)
            if m:
                entry["event_id"] = int(m.group(1))

            # 提取时间戳
            m = re.search(r'Date:\s*(\S+)', block)
            date_str = m.group(1) if m else ""
            m = re.search(r'Time:\s*(\S+)', block)
            time_str = m.group(1) if m else ""
            if date_str:
                entry["timestamp"] = f"{date_str}T{time_str}" if time_str else date_str

            # 提取描述（Message 字段，取前 200 字符）
            m = re.search(r'^(?!EventID|Date|Time|Level)(.+?):\s*(.+)', block, re.MULTILINE)
            if m:
                entry["description"] = f"{m.group(1)}: {m.group(2)}"[:200]
            else:
                # 取 Message 字段
                lines = block.strip().split("\n")
                for line in lines:
                    if ":" in line and not line.startswith("Event"):
                        entry["description"] = line.strip()[:200]
                        break
                if "description" not in entry:
                    entry["description"] = block.strip()[:200]

            # 提取 Level
            m = re.search(r'Level:\s*(\S+)', block)
            if m:
                entry["level"] = m.group(1)

            if entry.get("event_id"):
                events.append(entry)

        return events

    async def _publish_event_alert(self, evt: Dict[str, Any]) -> None:
        """将 Windows 事件日志条目发布为 threat_alert。"""
        event_id = evt.get("event_id", 0)

        # 事件 ID → 攻击类型映射
        if event_id == 4625:
            category = "login_failure"
            severity = AlertSeverity.MEDIUM
        elif event_id in (4720, 4726, 4697, 4732):
            category = "privilege_escalation"
            severity = AlertSeverity.HIGH
        elif event_id == 4672:
            category = "privilege_escalation"
            severity = AlertSeverity.MEDIUM
        elif event_id in (7031, 7034, 7045):
            category = "service_anomaly"
            severity = AlertSeverity.MEDIUM
        else:
            category = "audit_event"
            severity = AlertSeverity.LOW

        dedup_key = f"winevt:{event_id}:{evt.get('timestamp', '')}"
        if dedup_key in self._alerted:
            return
        self._alerted.add(dedup_key)

        indicator = ThreatIndicator(
            id=f"WEVT-{uuid.uuid4().hex[:8].upper()}",
            category=ThreatCategory.AUDIT,
            severity=severity,
            source_ip="local",
            target_ip="localhost",
            description=(
                f"Windows事件 [{evt.get('source_log', '')}] "
                f"EventID={event_id}: {evt.get('description', '')}"
            ),
            raw_data={
                "anomaly_type": category,
                "event_id": event_id,
                "source_log": evt.get("source_log", ""),
                "timestamp": evt.get("timestamp", ""),
                "auditor_type": "log_auditor",
            },
            detection_time=datetime.now().isoformat(),
        )

        alert_payload = indicator.to_dict()
        alert_payload["source_organ"] = "log_auditor"
        await self.bus.publish(Message(
            source="LogAuditor",
            target="*",
            type="threat_alert",
            payload=alert_payload,
        ))

    def get_event_log_cache(self) -> List[Dict[str, Any]]:
        """获取最近一次 Windows 事件日志缓存。"""
        return self._event_log_cache


class LogAnomalySimulator:
    """
    日志异常模拟器。
    向消息总线注入模拟的异常日志事件。
    """

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
            "type": "login_failure",
            "username": "administrator",
            "service": "winrm",
            "port": 5985,
            "detail": "administrator 用户 WinRM 认证失败",
        },
        {
            "type": "privilege_escalation",
            "username": "www-data",
            "service": "sudo",
            "detail": "www-data 用户尝试执行 sudo 提权操作",
        },
        {
            "type": "privilege_escalation",
            "username": "postgres",
            "service": "setuid",
            "detail": "postgres 用户触发 setuid 二进制提权",
        },
        {
            "type": "sensitive_access",
            "username": "app_user",
            "resource": "/etc/shadow",
            "detail": "app_user 访问影子密码文件 /etc/shadow",
        },
        {
            "type": "sensitive_access",
            "username": "nobody",
            "resource": "/var/log/audit/audit.log",
            "detail": "nobody 尝试读取审计日志文件",
        },
        {
            "type": "sensitive_access",
            "username": "deploy",
            "resource": "~/.ssh/id_rsa",
            "detail": "deploy 用户访问 SSH 私钥文件",
        },
    ]

    def __init__(self, config: Config):
        self.config = config
        self.bus = get_message_bus()
        self.logger = get_logger("LogAnomalySimulator")

    async def inject_anomalies(self, target_ip: str = "192.168.1.1") -> List[dict]:
        """
        向消息总线注入模拟异常日志事件。
        登录失败类型会重复发送多次以触发阈值累积。

        Args:
            target_ip: 目标主机 IP

        Returns:
            注入的异常日志列表
        """
        count = self.config.simulator.log_anomaly_count
        sampled = random.sample(self.LOG_TEMPLATES, min(count, len(self.LOG_TEMPLATES)))
        threshold = self.config.stage2.audit_login_fail_threshold

        for template in sampled:
            source_ip = f"10.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            anomaly = {
                **template,
                "source_ip": source_ip,
                "target_ip": target_ip,
            }

            # 登录失败类型：重复发送多次以触发阈值
            if template["type"] == "login_failure":
                repeat_times = threshold + random.randint(1, 3)
                for _ in range(repeat_times):
                    await self.bus.publish(
                        Message(source="LogAnomalySimulator", target="LogAuditor", type="log_anomaly", payload=anomaly)
                    )
                    await asyncio.sleep(0.02)  # 微小延迟模拟时序
                self.logger.info(
                    f"注入异常日志: {template['type']} ({source_ip}) x{repeat_times}"
                )
            else:
                await self.bus.publish(
                    Message(source="LogAnomalySimulator", target="LogAuditor", type="log_anomaly", payload=anomaly)
                )
                self.logger.info(
                    f"注入异常日志: {template['type']} ({source_ip})"
                )

        self.logger.info(f"共注入 {len(sampled)} 类异常日志事件")
        return sampled
