"""
第四阶段验证扩展测试（v1.1 · 欺骗层蜜罐 + 攻击路径干扰场景）。

覆盖：
1. AttackDataset 新增 deception / interference 场景的元数据与事件序列
2. deception 事件类别全部命中蜜罐触发白名单（TRAP_TRIGGER_CATEGORIES）
3. interference 事件携带授权标志，区分 blindfold / puppeteer 两类手段
4. 固定种子下事件序列可复现
5. BenchmarkRunner 蜜罐 / 干扰统计指标：
   - deception 场景 honeypot_trap 全量触发、干扰层未授权拦截
   - interference 场景 FSM>=L2 后应用干扰（blindfold / puppeteer 分布）
6. 最终报告表格包含蜜罐触发与干扰次数列
"""

import asyncio
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmarks.attack_dataset import AttackDataset
from benchmarks.run_benchmark import BenchmarkRunner
from core.honeypot import TRAP_TRIGGER_CATEGORIES
from core.interference import METHOD_BLINDFOLD, METHOD_PUPPETEER


class AttackDatasetExtensionTest(unittest.TestCase):
    """AttackDataset 新增场景的元数据与事件序列测试。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ds = AttackDataset()

    def test_new_scenarios_registered(self) -> None:
        """deception / interference 场景应已注册，总场景数从 6 扩展到 8。"""
        self.assertIn("deception", self.ds.SCENARIOS)
        self.assertIn("interference", self.ds.SCENARIOS)
        self.assertEqual(len(self.ds.SCENARIOS), 8)

    def test_deception_metadata(self) -> None:
        """deception 场景应声明蜜罐诱捕期望。"""
        meta = self.ds.SCENARIOS["deception"]["expected_detection"]
        self.assertEqual(meta["expected_honeypot_traps"], 8)

    def test_interference_metadata(self) -> None:
        """interference 场景应声明干扰应用期望与手段分布。"""
        meta = self.ds.SCENARIOS["interference"]["expected_detection"]
        self.assertEqual(meta["expected_interference_applied"], 10)
        self.assertIn(METHOD_BLINDFOLD, meta["expected_methods"])
        self.assertIn(METHOD_PUPPETEER, meta["expected_methods"])

    def test_deception_event_sequence(self) -> None:
        """
        deception 场景：8 条侦察类事件，类别全部命中蜜罐触发白名单，
        分布为 port_scan 3 / brute_force 3 / vuln 2。
        """
        events = self.ds.get_scenario("deception")["events"]
        self.assertEqual(len(events), 8)
        categories = [e["category"] for e in events]
        for cat in categories:
            self.assertIn(cat, TRAP_TRIGGER_CATEGORIES,
                          f"类别 {cat} 不在蜜罐触发白名单中")
        self.assertEqual(categories.count("port_scan"), 3)
        self.assertEqual(categories.count("brute_force"), 3)
        self.assertEqual(categories.count("vuln"), 2)

    def test_interference_event_sequence(self) -> None:
        """
        interference 场景：20 条高危攻击全部携带 authorized=True；
        exploit 10 条（无 api_path → blindfold），
        command_injection 10 条（带 api_path → puppeteer）。
        """
        events = self.ds.get_scenario("interference")["events"]
        self.assertEqual(len(events), 20)
        for e in events:
            self.assertTrue(e.get("authorized", False),
                            "授权环境下事件必须携带 authorized=True")

        exploit = [e for e in events if e["category"] == "exploit"]
        inject = [e for e in events if e["category"] == "command_injection"]
        self.assertEqual(len(exploit), 10)
        self.assertEqual(len(inject), 10)
        for e in exploit:
            self.assertNotIn("api_path", e, "exploit 不应携带 api_path（走 blindfold）")
        for e in inject:
            self.assertIn("api_path", e, "command_injection 必须携带 api_path（走 puppeteer）")

    def test_reproducible_with_fixed_seed(self) -> None:
        """固定种子下，两次生成的事件序列完全一致。"""
        first = self.ds.get_scenario("deception")["events"]
        second = self.ds.get_scenario("deception")["events"]
        self.assertEqual(first, second)
        self.assertEqual(self.ds.get_scenario("interference")["events"],
                         self.ds.get_scenario("interference")["events"])


class BenchmarkExtensionTest(unittest.TestCase):
    """BenchmarkRunner 蜜罐 / 干扰统计指标测试。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = BenchmarkRunner()

    def test_category_map_covers_new_categories(self) -> None:
        """CATEGORY_MAP 应覆盖蜜罐 / 干扰相关类别映射。"""
        for cat in ("brute_force", "vuln", "exploit", "command_injection"):
            self.assertIn(cat, BenchmarkRunner.CATEGORY_MAP)

    def test_deception_honeypot_stats(self) -> None:
        """
        deception 场景：8 条侦察类事件全部触发蜜罐诱捕；
        干扰层因 authorized_only 未授权拦截，干扰应用为 0。
        """
        result = asyncio.run(self.runner.run_scenario("deception"))
        self.assertEqual(result["honeypot_traps"], 8)
        self.assertEqual(result["honeypot_stats"]["total_traps"], 8)
        self.assertEqual(result["honeypot_stats"]["unique_sources"], 3)
        self.assertEqual(result["interference_applied"], 0)
        gates = result["interference_gate_stats"]
        self.assertEqual(gates["blocked_by_authorization"], 8)

    def test_interference_stats(self) -> None:
        """
        interference 场景：授权环境下 20 条高危攻击，FSM 升级至 L2 后
        应用干扰 10 次（blindfold 5 / puppeteer 5），蜜罐不触发。
        """
        result = asyncio.run(self.runner.run_scenario("interference"))
        self.assertEqual(result["interference_applied"], 10)
        self.assertEqual(result["interference_methods"][METHOD_BLINDFOLD], 5)
        self.assertEqual(result["interference_methods"][METHOD_PUPPETEER], 5)
        self.assertEqual(result["honeypot_traps"], 0)
        gates = result["interference_gate_stats"]
        self.assertEqual(gates["blindfold_applied"], 5)
        self.assertEqual(gates["puppeteer_applied"], 5)
        # 前段事件在 FSM 未达 L2 时被等级门控拦截
        self.assertEqual(gates["blocked_by_level"], 10)

    def test_report_contains_honeypot_and_interference_columns(self) -> None:
        """最终报告概览表与详情应包含蜜罐触发 / 干扰次数指标。"""
        self.runner.results = {
            "deception": {
                "scenario": "deception",
                "total_events": 8,
                "alerts_generated": 6,
                "expected_alerts": ["port_scan", "bruteforce"],
                "detected_categories": ["port_scan"],
                "detection_rate": 100.0,
                "false_positive_count": 0,
                "fsm_upgrades": 2,
                "escalation_delay_sec": 0.0,
                "final_fsm_levels": {"L0-monitor": 0, "L1-soft": 0,
                                      "L2-hard": 2, "L3-offensive": 0,
                                      "L4-isolate": 0},
                "fsm_total_ips": 3,
                "honeypot_traps": 8,
                "honeypot_stats": {"total_traps": 8, "unique_sources": 3,
                                   "traps_by_port": {22: 4, 80: 1, 443: 1, 8080: 2}},
                "interference_applied": 0,
                "interference_methods": {METHOD_BLINDFOLD: 0, METHOD_PUPPETEER: 0},
                "interference_gate_stats": {"blocked_by_disabled": 0,
                                            "blocked_by_authorization": 8,
                                            "blocked_by_severity": 0,
                                            "blocked_by_category": 0,
                                            "blocked_by_level": 0},
                "fp_filter_stats": {},
                "description": "欺骗层蜜罐触发",
            },
            "interference": {
                "scenario": "interference",
                "total_events": 20,
                "alerts_generated": 20,
                "expected_alerts": ["exploit", "command_injection"],
                "detected_categories": ["exploit"],
                "detection_rate": 100.0,
                "false_positive_count": 0,
                "fsm_upgrades": 6,
                "escalation_delay_sec": 0.0,
                "final_fsm_levels": {"L0-monitor": 0, "L1-soft": 0,
                                      "L2-hard": 1, "L3-offensive": 0,
                                      "L4-isolate": 0},
                "fsm_total_ips": 2,
                "honeypot_traps": 0,
                "honeypot_stats": {"total_traps": 0, "unique_sources": 0,
                                   "traps_by_port": {}},
                "interference_applied": 10,
                "interference_methods": {METHOD_BLINDFOLD: 5, METHOD_PUPPETEER: 5},
                "interference_gate_stats": {"blocked_by_disabled": 0,
                                            "blocked_by_authorization": 0,
                                            "blocked_by_severity": 0,
                                            "blocked_by_category": 0,
                                            "blocked_by_level": 10},
                "fp_filter_stats": {},
                "description": "攻击路径干扰触发",
            },
        }
        report = self.runner.generate_report()
        # 概览表头包含蜜罐 / 干扰列
        self.assertIn("| 蜜罐触发 | 干扰次数 |", report)
        # 详情包含对应指标行
        self.assertIn("蜜罐诱捕次数（honeypot_trap）", report)
        self.assertIn("干扰应用次数（interference_applied）", report)
        self.assertIn("干扰手段分布", report)
        # 汇总统计包含总蜜罐 / 总干扰
        self.assertIn("总蜜罐诱捕次数（honeypot_trap）", report)
        self.assertIn("总干扰应用次数（interference_applied）", report)


if __name__ == "__main__":
    unittest.main()
