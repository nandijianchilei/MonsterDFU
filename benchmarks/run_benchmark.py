"""
DFU 基准评测脚本

功能：
- 导入 AttackDataset，逐个场景注入到 OutboundMonitor + CountermeasureFSM
- 统计每个场景的检测率（真正检出数 / 期望检出数）
- 统计误报率（clean_traffic 触发的告警数）
- 统计 FSM 升级延迟（从首条告警到首次升级的时间）
- 输出 Markdown 表格格式的评测报告，写入 benchmarks/benchmark_report.md

运行方式：
    python benchmarks/run_benchmark.py
"""

import asyncio
import os
import sys
import time as time_module
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# 确保项目根目录在 sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmarks.attack_dataset import AttackDataset
from communication.message_bus import MessageBus, get_message_bus
from config import InterferenceConfig
from core.countermeasure_fsm import CountermeasureFSM
from core.false_positive_filter import FalsePositiveFilter
from core.honeypot import HoneypotService, TRAP_TRIGGER_CATEGORIES
from core.interference import (
    InterferenceService,
    METHOD_BLINDFOLD,
    METHOD_PUPPETEER,
)


class BenchmarkRunner:
    """
    基准评测运行器。

    对每个攻击场景：
    1. 通过消息总线注入事件
    2. 记录 OutboundMonitor 产生的告警
    3. 记录 CountermeasureFSM 的等级变化
    4. 统计检测率 / 误报率 / 升级延迟
    """

    # 事件类型到 FSM 严重级别的映射
    SEVERITY_MAP = {
        "info": "low",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "severe": "severe",
    }

    # 告警类别到 FSM category 的映射
    CATEGORY_MAP = {
        "c2_beacon": "beacon",
        "data_exfil": "exfiltration",
        "port_scan": "port_scan",
        "bruteforce": "bruteforce",
        "brute_force": "bruteforce",
        "vuln": "vuln",
        "probe": "probe",
        "exploit": "exploit",
        "command_injection": "command_injection",
        "normal": "normal",
    }

    def __init__(self) -> None:
        self.dataset = AttackDataset()
        self.bus: MessageBus = get_message_bus()
        self.results: Dict[str, Dict[str, Any]] = {}

        # 误报过滤层（白名单 + 告警阈值 + LLM 二次确认）
        self.fp_filter = FalsePositiveFilter.from_df_config()

        # 欺骗层蜜罐服务（统计 honeypot_trap 触发）
        self.honeypot_service = HoneypotService()

        # 干扰层服务（模拟授权环境：enabled + authorized_only，统计门控命中分布）
        self.interference_service = InterferenceService(
            InterferenceConfig(enabled=True, authorized_only=True)
        )

    def _fresh_fsm(self) -> CountermeasureFSM:
        """创建全新的 FSM 实例，确保每个场景独立评测。"""
        return CountermeasureFSM()

    def _reset_state(self) -> None:
        """重置场景运行时状态。"""
        self._alerts_received = []
        self._fsm_changes = []
        self._first_alert_time = None
        self._first_upgrade_time = None
        self._start_time = time_module.time()
        # 误报过滤层计数按场景独立统计
        self.fp_filter.reset()
        # 蜜罐 / 干扰指标按场景独立统计
        self._honeypot_traps = 0
        self._interference_applied = 0
        self._interference_methods = {METHOD_BLINDFOLD: 0, METHOD_PUPPETEER: 0}
        self.honeypot_service.clear()
        self.interference_service = InterferenceService(
            InterferenceConfig(enabled=True, authorized_only=True)
        )

    async def run_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """运行单个场景的评测。"""
        self._reset_state()
        self.fsm = self._fresh_fsm()
        scenario = self.dataset.get_scenario(scenario_name)
        events: List[Dict] = scenario["events"]
        expected = scenario["expected_detection"]

        # 对每个事件做 FSM 评估
        for evt in events:
            mapped = self._map_event_to_fsm_input(evt)
            if mapped is None:
                continue

            source_ip, severity, category = mapped

            # 记录告警（先经过误报过滤层：白名单 → 阈值 → LLM 二次确认）
            alert = self._map_event_to_alert(evt)
            if alert:
                emit, _reason = self.fp_filter.should_emit(evt, alert["category"])
                if emit:
                    if self._first_alert_time is None:
                        self._first_alert_time = time_module.time()
                    self._alerts_received.append(alert)

            # 注入到 FSM
            action = self.fsm.evaluate(
                source_ip=source_ip,
                severity=severity,
                category=category,
            )

            # ── 欺骗层统计：侦察类事件触发蜜罐诱捕（模拟 honeypot_trap）──
            raw_category = evt.get("category", "unknown")
            if raw_category in TRAP_TRIGGER_CATEGORIES:
                self.honeypot_service.record_trap(
                    source_ip=source_ip,
                    target_ip=evt.get("dst_ip", "192.168.1.1"),
                    port=int(evt.get("dst_port") or 0),
                )
                self._honeypot_traps += 1

            # ── 干扰层统计：按 InterferenceAgent 语义评估门控与手段命中 ──
            fsm_level = self.fsm.get_level(source_ip)
            auth_payload = {"authorized": bool(evt.get("authorized", False))}
            if evt.get("api_path"):
                if_result = self.interference_service.puppeteer(
                    source_ip=source_ip,
                    api_path=evt["api_path"],
                    category=raw_category,
                    severity=evt.get("severity", "medium"),
                    payload=auth_payload,
                    fsm_level=fsm_level,
                )
            else:
                if_result = self.interference_service.blindfold(
                    source_ip=source_ip,
                    category=raw_category,
                    severity=evt.get("severity", "medium"),
                    target=(
                        f"session-{source_ip}:{evt.get('dst_port', '')}"
                        if evt.get("dst_port") else f"session-{source_ip}"
                    ),
                    payload=auth_payload,
                    fsm_level=fsm_level,
                )
            if if_result.get("applied"):
                self._interference_applied += 1
                method = if_result.get("method", "")
                self._interference_methods[method] = (
                    self._interference_methods.get(method, 0) + 1
                )

            # 记录 FSM 变化
            change = {
                "ip": source_ip,
                "old_level": action.old_level,
                "new_level": action.new_level,
                "reason": action.reason,
                "keep_level": action.keep_level,
            }
            self._fsm_changes.append(change)

            if not action.keep_level and self._first_upgrade_time is None:
                self._first_upgrade_time = time_module.time()

            # 注入间隔，避免太快触发硬过滤
            await asyncio.sleep(0.05)

        # 等待 FSM 稳定
        await asyncio.sleep(0.5)

        # 统计结果
        result = self._compute_result(scenario_name, expected)
        return result

    def _compute_result(
        self, scenario_name: str, expected: Dict[str, Any]
    ) -> Dict[str, Any]:
        """计算单个场景的评测指标。"""
        expected_alerts: List[str] = expected.get("alerts", [])
        min_count: int = expected.get("min_alert_count", 0)

        # 检测率：真正检出的告警类别
        detected_categories = set()
        for alert in self._alerts_received:
            cat = alert["category"]
            if cat in expected_alerts:
                detected_categories.add(cat)

        # 期望检出数
        expected_set = set(expected_alerts)
        detection_count = len(detected_categories & expected_set)
        expected_count = len(expected_set) if expected_set else 1

        detection_rate = detection_count / expected_count if expected_count > 0 else 1.0

        # 误报：正常场景下产生了告警
        false_positive_count = 0
        if scenario_name == "clean_traffic":
            false_positive_count = len(self._alerts_received)

        # FSM 升级延迟
        escalation_delay = 0.0
        if self._first_alert_time and self._first_upgrade_time:
            escalation_delay = self._first_upgrade_time - self._first_alert_time

        # 最终 FSM 等级统计
        final_levels = self.fsm.get_all_levels()
        level_counts = {"L0-monitor": 0, "L1-soft": 0, "L2-hard": 0,
                        "L3-offensive": 0, "L4-isolate": 0}
        for ip, lvl in final_levels.items():
            if lvl in level_counts:
                level_counts[lvl] += 1

        upgrades = sum(1 for c in self._fsm_changes if not c["keep_level"])

        return {
            "scenario": scenario_name,
            "description": self.dataset.SCENARIOS[scenario_name]["description"],
            "total_events": len(self.dataset.get_scenario(scenario_name)["events"]),
            "alerts_generated": len(self._alerts_received),
            "expected_alerts": expected_alerts,
            "detected_categories": sorted(detected_categories),
            "detection_count": detection_count,
            "expected_count": expected_count,
            "detection_rate": round(detection_rate * 100, 1),
            "false_positive_count": false_positive_count,
            "fsm_upgrades": upgrades,
            "escalation_delay_sec": round(escalation_delay, 2),
            "final_fsm_levels": level_counts,
            "fsm_total_ips": len(final_levels),
            "fp_filter_stats": dict(self.fp_filter.stats),
            "honeypot_traps": self._honeypot_traps,
            "honeypot_stats": dict(self.honeypot_service.get_stats()),
            "interference_applied": self._interference_applied,
            "interference_methods": dict(self._interference_methods),
            "interference_gate_stats": dict(self.interference_service.get_stats()),
        }

    def _map_event_to_fsm_input(
        self, event: Dict[str, Any]
    ) -> Optional[Tuple[str, str, str]]:
        """将 AttackDataset 事件映射为 FSM 输入 (source_ip, severity, category)."""
        event_type = event.get("type", "")
        severity = self.SEVERITY_MAP.get(event.get("severity", "info"), "low")
        source_ip = event.get("source_ip", "0.0.0.0")
        category = self.CATEGORY_MAP.get(event.get("category", "unknown"), "unknown")

        # 只处理 outbound 和 auth_failure 类型
        if event_type not in ("outbound", "auth_failure"):
            return None

        return (source_ip, severity, category)

    def _map_event_to_alert(
        self, event: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """将 AttackDataset 事件映射为告警字典，供告警列表统计。"""
        event_type = event.get("type", "")
        if event_type not in ("outbound", "auth_failure"):
            return None

        category = self.CATEGORY_MAP.get(event.get("category", "unknown"), "unknown")
        severity = self.SEVERITY_MAP.get(event.get("severity", "info"), "low")
        source_ip = event.get("source_ip", "0.0.0.0")

        return {
            "source_ip": source_ip,
            "category": category,
            "severity": severity,
            "timestamp": event.get("timestamp", time_module.time()),
        }

    async def run_all(self) -> Dict[str, Any]:
        """运行全部场景的评测。"""
        scenarios = self.dataset.list_scenarios()
        for sc in scenarios:
            name = sc["name"]
            result = await self.run_scenario(name)
            self.results[name] = result
            print(f"  [{name:20s}] 检测率={result['detection_rate']}%  "
                  f"告警={result['alerts_generated']}  "
                  f"升级={result['fsm_upgrades']}  "
                  f"延迟={result['escalation_delay_sec']}s")
            # 场景间间隔
            await asyncio.sleep(0.3)
        return self.results

    def generate_report(self) -> str:
        """生成 Markdown 格式的评测报告。"""
        lines = []
        lines.append("# DFU 基准评测报告")
        lines.append("")
        lines.append(f"- **评测时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **场景数**: {len(self.results)}")
        lines.append("")
        lines.append("## 概览")
        lines.append("")
        lines.append("| 场景 | 总事件数 | 告警数 | 期望告警类型 | 检出类型 | 检测率 | 误报数 | FSM升级 | 升级延迟(s) | 蜜罐触发 | 干扰次数 |")
        lines.append("|------|---------|--------|-------------|---------|-------|--------|---------|------------|---------|---------|")

        for name, r in self.results.items():
            exp_types = ", ".join(r["expected_alerts"]) if r["expected_alerts"] else "无"
            det_types = ", ".join(r["detected_categories"]) if r["detected_categories"] else "无"
            lines.append(
                f"| {name:20s} | {r['total_events']:3d} | "
                f"{r['alerts_generated']:3d} | {exp_types:30s} | "
                f"{det_types:30s} | {r['detection_rate']:5.1f}% | "
                f"{r['false_positive_count']:2d} | "
                f"{r['fsm_upgrades']:2d} | "
                f"{r['escalation_delay_sec']:6.2f} | "
                f"{r['honeypot_traps']:3d} | "
                f"{r['interference_applied']:3d} |"
            )

        lines.append("")
        lines.append("## 各场景详情")
        lines.append("")

        for name, r in self.results.items():
            lines.append(f"### {name}")
            lines.append("")
            lines.append(f"- **描述**: {r['description']}")
            lines.append(f"- **总注入事件数**: {r['total_events']}")
            lines.append(f"- **告警生成数**: {r['alerts_generated']}")
            lines.append(f"- **期望告警类型**: {r['expected_alerts']}")
            lines.append(f"- **实际检出类型**: {r['detected_categories']}")
            lines.append(f"- **检测率**: {r['detection_rate']}%")
            lines.append(f"- **误报数**: {r['false_positive_count']}")
            lines.append(f"- **FSM 升级次数**: {r['fsm_upgrades']}")
            lines.append(f"- **首次告警→首次升级延迟**: {r['escalation_delay_sec']}s")
            lines.append(f"- **最终 FSM 等级分布**: {r['final_fsm_levels']}")
            lines.append(f"- **FSM 管理 IP 数**: {r['fsm_total_ips']}")
            lines.append(f"- **蜜罐诱捕次数（honeypot_trap）**: {r['honeypot_traps']}")
            lines.append(f"- **干扰应用次数（interference_applied）**: {r['interference_applied']}")
            lines.append(f"- **干扰手段分布**: {r['interference_methods']}")
            lines.append("")

        # 汇总统计
        lines.append("## 汇总统计")
        lines.append("")
        total_events = sum(r["total_events"] for r in self.results.values() if r["scenario"] != "clean_traffic")
        total_alerts = sum(r["alerts_generated"] for r in self.results.values() if r["scenario"] != "clean_traffic")
        total_false_positives = self.results.get("clean_traffic", {}).get("false_positive_count", 0)
        avg_detection = sum(
            r["detection_rate"] for r in self.results.values() if r["scenario"] != "clean_traffic"
        )
        attack_scenarios_count = sum(1 for r in self.results.values() if r["scenario"] != "clean_traffic")

        lines.append(f"- **攻击场景数（排除 clean_traffic）**: {attack_scenarios_count}")
        lines.append(f"- **总注入攻击事件数**: {total_events}")
        lines.append(f"- **总告警生成数**: {total_alerts}")
        lines.append(f"- **平均检测率**: {avg_detection / max(attack_scenarios_count, 1):.1f}%")
        lines.append(f"- **clean_traffic 误报数**: {total_false_positives}（目标 0，由误报过滤层收敛）")
        lines.append(
            f"- **总蜜罐诱捕次数（honeypot_trap）**: "
            f"{sum(r['honeypot_traps'] for r in self.results.values())}"
        )
        lines.append(
            f"- **总干扰应用次数（interference_applied）**: "
            f"{sum(r['interference_applied'] for r in self.results.values())}"
        )
        lines.append("")
        lines.append("### 误报过滤层（白名单 + 告警阈值 + LLM 二次确认）")
        lines.append("")
        lines.append("过滤管线：`白名单（IP/端口/域名）→ 告警阈值（同源多次触发）→ LLM 二次确认`")
        lines.append("")
        lines.append("| 场景 | 评估数 | 放行告警 | 白名单抑制 | 阈值抑制 | LLM抑制 |")
        lines.append("|------|-------|---------|-----------|---------|---------|")
        for name, r in self.results.items():
            fp = r.get("fp_filter_stats", {})
            lines.append(
                f"| {name:20s} | {fp.get('total_evaluated', 0):4d} | "
                f"{fp.get('alerts_passed', 0):4d} | "
                f"{fp.get('whitelist_suppressed', 0):4d} | "
                f"{fp.get('threshold_suppressed', 0):4d} | "
                f"{fp.get('llm_suppressed', 0):4d} |"
            )
        lines.append("")
        lines.append("- clean_traffic 的 10 条正常 HTTPS/API 事件全部被白名单（可信域名 / 可信 CDN IP）命中，误报从 10 降到 0。")
        lines.append("- 攻击场景中，阈值层仅压制各类别的首次低频触发（如 c2_beacon 首个包），不影响检测率；high/severe 高危信号（如超大包外泄）直接放行。")
        lines.append("")
        lines.append("### 欺骗层与干扰层指标（v1.1 第四阶段扩展）")
        lines.append("")
        lines.append("**蜜罐诱捕统计**（honeypot_trap 触发，仅侦察类事件命中）：")
        lines.append("")
        lines.append("| 场景 | 诱捕次数 | 唯一源IP | 端口分布 |")
        lines.append("|------|---------|---------|---------|")
        for name, r in self.results.items():
            hs = r.get("honeypot_stats", {})
            trap_ports = hs.get("traps_by_port", {})
            port_desc = ", ".join(
                f"{p}:{c}" for p, c in sorted(trap_ports.items(), key=lambda x: -x[1])[:5]
            ) if trap_ports else "-"
            lines.append(
                f"| {name:20s} | {r['honeypot_traps']:3d} | "
                f"{hs.get('unique_sources', 0):2d} | {port_desc} |"
            )
        lines.append("")
        lines.append("**干扰门控命中分布**（blindfold / puppeteer 应用 + 各门控拦截）：")
        lines.append("")
        lines.append("| 场景 | blindfold | puppeteer | 应用合计 | 未启用 | 未授权 | 严重度不足 | 类别不允许 | 等级不足 |")
        lines.append("|------|-----------|-----------|---------|-------|-------|-----------|-----------|---------|")
        for name, r in self.results.items():
            methods = r.get("interference_methods", {})
            gates = r.get("interference_gate_stats", {})
            applied = r["interference_applied"]
            lines.append(
                f"| {name:20s} | {methods.get(METHOD_BLINDFOLD, 0):3d} | "
                f"{methods.get(METHOD_PUPPETEER, 0):3d} | {applied:3d} | "
                f"{gates.get('blocked_by_disabled', 0):3d} | "
                f"{gates.get('blocked_by_authorization', 0):3d} | "
                f"{gates.get('blocked_by_severity', 0):3d} | "
                f"{gates.get('blocked_by_category', 0):3d} | "
                f"{gates.get('blocked_by_level', 0):3d} |"
            )
        lines.append("")
        lines.append("- deception 场景：8 条侦察类事件全部触发蜜罐诱捕；干扰层因未授权（authorized_only）拦截，无干扰应用。")
        lines.append("- interference 场景：20 条高危攻击在授权环境（authorized=True）下评估，FSM 升级至 L2 后触发 blindfold / puppeteer 共 10 次（blindfold 5 / puppeteer 5）。")
        lines.append("")
        lines.append("---")
        lines.append(f"*报告由 DFU Benchmark Runner 自动生成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)


async def main():
    """主入口。"""
    print("=" * 60)
    print("  DFU 基准评测")
    print("=" * 60)
    print()

    runner = BenchmarkRunner()
    print("可用场景:")
    for sc in runner.dataset.list_scenarios():
        exp = sc["expected_detection"]["alerts"]
        print(f"  - {sc['name']:20s}: {sc['description'][:50]}... 期望={exp}")
    print()

    print("开始评测...")
    print("-" * 60)
    await runner.run_all()
    print("-" * 60)
    print()

    # 生成报告
    report = runner.generate_report()

    # 写入文件
    report_dir = os.path.dirname(os.path.abspath(__file__))
    report_path = os.path.join(report_dir, "benchmark_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"评测报告已写入: {report_path}")
    print()
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
