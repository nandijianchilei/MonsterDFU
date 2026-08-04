#!/usr/bin/env python3
"""
事件链记录器模块（从 main.py 拆分）。

订阅消息总线，自动记录完整事件链，供 DFU 运行器汇总展示。
"""

import asyncio
from datetime import datetime
from typing import Optional

from communication.message_bus import Message, MessageBus


class EventChainRecorder:
    """
    事件链记录器：订阅消息总线，自动记录完整事件链。

    阶段2扩展：新增 vuln_alert、audit_alert、schedule_result、forensic_report、
    medic_event 事件类型的记录支持。
    """

    TYPE_STAGE_MAP = {
        "traffic_data":     ("attack",   "攻击流量数据包"),
        "threat_alert":     ("observe",  "观测Agent检测到威胁告警"),
        "merged_threat_alert": ("observe", "事件聚合器输出合并威胁告警"),
        "unhandled_threat": ("observe", "规则引擎未命中的原始告警"),
        "rule_handled": ("left", "规则引擎前置分流快速命中"),
        "defense_plan":     ("left",     "分析引擎输出防御方案"),
        "attack_analysis":  ("right",    "响应引擎输出攻击分析"),
        "isolation_action": ("validate", "校验Agent下发的隔离指令"),
        "action_result":    ("execute",  "处置Agent执行结果"),
        # 阶段2新增事件类型
        "schedule_result":  ("resource", "算力调度Agent执行调度"),
        "forensic_report":  ("forensic", "溯源追踪Agent输出溯源报告"),
        "medic_event":      ("medic",    "医疗Agent自愈系统事件"),
        # 阶段3新增事件类型
        "knowledge_hit":    ("knowledge","知识库命中"),
        "knowledge_promote":("knowledge","冷库升温到热库"),
        "sync_event":       ("sync",     "跨单元知识同步"),
        "dispatch_event":   ("dispatch", "负载分发事件"),
        "cluster_status":   ("cluster",  "集群状态事件"),
        # Phase 1.5 新增事件类型
        "outbound_beacon":  ("outbound", "出站监测发现信标通信"),
        "outbound_exfil":   ("outbound", "出站监测检测到数据外泄"),
        "outbound_domain":  ("outbound", "出站监测命中可疑域名"),
        "outbound_l4_isolate": ("outbound", "L4网络隔离已触发"),
        # 融合增强 v1.1 阶段2 新增事件类型
        "honeypot_trap":    ("deception", "欺骗层蜜罐诱捕事件"),
        # 融合增强 v1.1 阶段3 新增事件类型
        "interference_applied": ("interference", "攻击路径干扰已执行（仅授权环境）"),
        "kill_switch":      ("interference", "全局熔断状态事件"),
    }

    def __init__(self, bus: MessageBus):
        self.events: list = []
        self.bus = bus
        self._lock = asyncio.Lock()
        self._running = False

    async def start(self) -> None:
        """启动全局监听。"""
        self._running = True
        await self.bus.subscribe("*", self._on_message)

    async def stop(self) -> None:
        self._running = False

    async def _on_message(self, msg: Message) -> None:
        """全局消息处理器。"""
        if not self._running:
            return
        msg_type = msg.type
        if msg_type == "traffic_data":
            return
        info = self.TYPE_STAGE_MAP.get(msg_type)
        if info is None:
            return
        stage, label = info

        detail = self._format_detail(msg)
        async with self._lock:
            self.events.append({
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "stage": stage,
                "label": label,
                "detail": detail,
                "source": msg.source,
            })

    def _format_detail(self, msg: Message) -> str:
        """格式化消息详情为可读字符串。"""
        payload = msg.payload
        lines = []
        msg_type = msg.type

        if msg_type == "threat_alert":
            source_organ = payload.get("source_organ", "")
            if source_organ:
                lines.append(f"来源器官: {source_organ}")
            # 兼容新旧格式：旧格式 indicator 在顶层字段，新格式在 payload.indicator
            indicator = payload.get("indicator", {})
            if not indicator:
                # 旧格式兼容
                indicator = payload
            lines.append(f"告警ID: {indicator.get('id') or payload.get('id')}")
            lines.append(f"类别: {indicator.get('category') or payload.get('category')}")
            lines.append(f"级别: {indicator.get('severity') or payload.get('severity')}")
            lines.append(f"源IP: {indicator.get('source_ip') or payload.get('source_ip')}")
            lines.append(f"描述: {indicator.get('description') or payload.get('description', '')}")

        elif msg_type == "unhandled_threat":
            indicator = payload.get("indicator", payload)
            lines.append(f"源IP: {indicator.get('source_ip') or payload.get('source_ip')}")
            lines.append(f"类别: {indicator.get('category') or payload.get('category')}")
            lines.append(f"级别: {indicator.get('severity') or payload.get('severity')}")
            lines.append("规则: 未命中 → 交聚合器")

        elif msg_type == "rule_handled":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"动作: {payload.get('action')}")
            lines.append(f"级别: {payload.get('severity')}")
            lines.append(f"规则: {payload.get('rule_id')}")
            lines.append(f"置信度: {payload.get('confidence', 0):.2f}")

        elif msg_type == "merged_threat_alert":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"聚合告警数: {payload.get('event_count')}")
            lines.append(f"源IP: {payload.get('source_ip')}")
            lines.append(f"类别: {payload.get('category')}")

        elif msg_type == "defense_plan":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"确认级别: {payload.get('severity_confirm')}")
            lines.append(f"处置动作: {payload.get('action')}")
            lines.append(f"目标IP: {payload.get('target_ip')}")
            lines.append(f"算力开销: {payload.get('compute_cost', 0)}")

        elif msg_type == "attack_analysis":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"攻击类型: {payload.get('attack_type')}")
            conf = payload.get('confidence', 0)
            lines.append(f"置信度: {conf:.2f}" if isinstance(conf, float) else f"置信度: {conf}")
            lines.append(f"溯源: {payload.get('root_cause', '')[:80]}")
            actions = payload.get('recommended_actions', [])
            lines.append(f"推荐策略: {', '.join(actions)}")

        elif msg_type == "isolation_action":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"动作: {payload.get('action')}")
            lines.append(f"目标IP: {payload.get('target_ip')}")
            lines.append(f"优先级: {payload.get('priority')}")
            lines.append(f"原因: {payload.get('reason', '')[:80]}")

        elif msg_type == "action_result":
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"目标IP: {payload.get('target_ip')}")
            lines.append(f"动作: {payload.get('action')}")
            lines.append(f"结果: {'成功' if payload.get('success') else '失败'}")
            lines.append(f"说明: {payload.get('message')}")
            lines.append(f"黑名单大小: {payload.get('blacklist_size')}")

        elif msg_type == "schedule_result":
            log_entry = payload.get("log_entry", {})
            rs = payload.get("resource_state", {})
            lines.append(f"调度ID: {log_entry.get('schedule_id')}")
            lines.append(f"目标: {log_entry.get('target_organ')}")
            lines.append(f"动作: {log_entry.get('action')}")
            lines.append(f"CPU: {rs.get('cpu_usage_pct', 0):.1f}%")
            lines.append(f"内存: {rs.get('memory_usage_pct', 0):.1f}%")

        elif msg_type == "forensic_report":
            chain = payload.get("hop_chain", [])
            hops = " → ".join(h.get("ip", "") for h in chain)
            lines.append(f"报告ID: {payload.get('report_id')}")
            lines.append(f"告警ID: {payload.get('alert_id')}")
            lines.append(f"跳板链: {hops}")
            lines.append(f"可信度: {payload.get('confidence', 0):.0%}")
            lines.append(f"根因: {payload.get('root_cause', '')[:100]}")

        elif msg_type == "medic_event":
            lines.append(f"类型: {payload.get('type')}")
            lines.append(f"描述: {payload.get('description')}")

        elif msg_type == "vuln_report":
            lines.append(f"CVE: {payload.get('cve_id')}")
            lines.append(f"服务: {payload.get('service')}")
            lines.append(f"CVSS: {payload.get('cvss_score')}")
            lines.append(f"描述: {payload.get('description', '')[:80]}")

        elif msg_type == "log_anomaly":
            lines.append(f"类型: {payload.get('type')}")
            lines.append(f"用户: {payload.get('username')}")
            lines.append(f"源IP: {payload.get('source_ip')}")
            lines.append(f"详情: {payload.get('detail', '')[:80]}")

        # 阶段3事件格式
        elif msg_type == "knowledge_hit":
            lines.append(f"特征: {payload.get('feature', '')}")
            lines.append(f"来源: {payload.get('source', '')}")
            lines.append(f"耗时: {payload.get('latency_ms', 0):.2f}ms")

        elif msg_type == "knowledge_promote":
            lines.append(f"特征: {payload.get('feature', '')}")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "sync_event":
            lines.append(f"发起方: {payload.get('from_unit', '')}")
            lines.append(f"接收方: {payload.get('to_unit', '')}")
            lines.append(f"同步条目: {payload.get('entry_count', 0)}")
            lines.append(f"延迟: {payload.get('latency_ms', 0):.2f}ms")

        elif msg_type == "dispatch_event":
            lines.append(f"任务ID: {payload.get('task_id', '')}")
            lines.append(f"目标单元: {payload.get('target_unit', '')}")
            lines.append(f"策略: {payload.get('strategy', '')}")

        elif msg_type == "cluster_status":
            lines.append(f"集群规模: {payload.get('total_units', 0)} 单元")
            lines.append(f"活跃: {payload.get('active_units', 0)}")
            lines.append(f"描述: {payload.get('description', '')}")

        # Phase 1.5 出站事件格式
        elif msg_type == "outbound_beacon":
            lines.append(f"源IP: {payload.get('source_ip', '')}")
            lines.append(f"目标IP: {payload.get('dest_ip', '')}")
            lines.append(f"端口: {payload.get('dest_port', '')}")
            lines.append(f"周期: {payload.get('interval_sec', 0)}s")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "outbound_exfil":
            lines.append(f"源IP: {payload.get('source_ip', '')}")
            lines.append(f"目标域名: {payload.get('dest_domain', '')}")
            lines.append(f"外泄字节: {payload.get('bytes_sent', 0)}")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "outbound_domain":
            lines.append(f"源IP: {payload.get('source_ip', '')}")
            lines.append(f"域名: {payload.get('domain', '')}")
            lines.append(f"匹配特征: {payload.get('match_type', '')}")
            lines.append(f"描述: {payload.get('description', '')}")

        elif msg_type == "outbound_l4_isolate":
            lines.append(f"目标IP: {payload.get('target_ip', '')}")
            lines.append(f"原等级: {payload.get('old_level', '')}")
            lines.append(f"新等级: {payload.get('new_level', '')}")
            lines.append(f"原因: {payload.get('reason', '')}")
            lines.append(f"动作: {payload.get('action', '')}")

        return "\n".join(lines) if lines else str(payload)[:200]

    def add_manual_event(self, stage: str, msg: str) -> None:
        """手动添加事件。"""
        self.events.append({
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "stage": stage,
            "label": msg,
            "detail": "",
            "source": "System",
        })

    def add_medic_event(self, event_type: str, description: str, detail: dict = None) -> None:
        """添加医疗Agent事件（通过消息总线发布）。"""
        self.events.append({
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "stage": "medic",
            "label": event_type,
            "detail": description,
            "source": "MedicAgent",
        })

    def print_chain(self) -> None:
        """打印完整事件链。"""
        print("\n" + "=" * 80)
        print("  事件链完整记录")
        print("=" * 80)

        stage_icons = {
            "attack":   "⚡",
            "observe":  "👁 ",
            "left":     "🧠",
            "right":    "🧠",
            "validate": "🔍",
            "execute":  "🛡 ",
            "resource": "⚙ ",
            "forensic": "🔬",
            "medic":    "🏥",
            "knowledge":"📚",
            "sync":     "🔄",
            "dispatch": "📤",
            "cluster":  "🌐",
            "outbound": "🚫",
        }

        for i, event in enumerate(self.events, 1):
            stage = event["stage"]
            icon = stage_icons.get(stage, "  ")
            print(f"\n[{i:02d}] {event['time']} {icon} {event['label']}")
            print(f"     来源: {event['source']}")
            if event["detail"]:
                for line in event["detail"].split("\n"):
                    if line.strip():
                        print(f"       {line.strip()}")

        print("\n" + "=" * 80)
        print(f"  事件链总计: {len(self.events)} 个事件")
        print("=" * 80)

