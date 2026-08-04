"""
第四层输出护栏 (OutputGuardLayer) 与门面集成单元测试
覆盖：合法动作放行、非法动作降级、高危动作默认降级/显式放行、
白名单集合、FalsePositiveFilter.validate_action 集成与统计。
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.false_positive_filter import (
    ALLOWED_ACTION_WHITELIST,
    HIGH_RISK_ACTIONS,
    FalsePositiveFilter,
    OutputGuardLayer,
)


class TestOutputGuardLayer(unittest.TestCase):
    def setUp(self):
        self.guard = OutputGuardLayer()

    def test_allowed_action_passes(self):
        safe, reason = self.guard.validate_action({"action": "block_ip", "ip": "1.2.3.4"})
        self.assertEqual(reason, "ok")
        self.assertEqual(safe["action"], "block_ip")

    def test_unknown_action_downgraded_to_alert(self):
        safe, reason = self.guard.validate_action({"action": "delete_database"})
        self.assertEqual(reason, "unknown_action")
        self.assertEqual(safe["action"], "alert")
        self.assertEqual(safe["original_action"], "delete_database")
        self.assertEqual(safe["guard_reason"], "unknown_action")

    def test_high_risk_action_downgraded_by_default(self):
        safe, reason = self.guard.validate_action({"action": "isolate_ip", "ip": "5.6.7.8"})
        self.assertEqual(reason, "blocked_high_risk")
        self.assertEqual(safe["action"], "alert")
        self.assertEqual(safe["original_action"], "isolate_ip")

    def test_high_risk_action_allowed_when_configured(self):
        guard = OutputGuardLayer(allow_high_risk=True)
        safe, reason = guard.validate_action({"action": "isolate_ip"})
        self.assertEqual(reason, "ok")
        self.assertEqual(safe["action"], "isolate_ip")

    def test_disabled_guard_passes_through(self):
        guard = OutputGuardLayer(enabled=False)
        safe, reason = guard.validate_action({"action": "delete_database"})
        self.assertEqual(reason, "guard_disabled")
        self.assertEqual(safe["action"], "delete_database")

    def test_stats_counted(self):
        self.guard.validate_action({"action": "block_ip"})
        self.guard.validate_action({"action": "delete_database"})
        self.guard.validate_action({"action": "sandbox"})
        self.assertEqual(self.guard.stats["actions_checked"], 3)
        self.assertEqual(self.guard.stats["actions_passed"], 1)
        self.assertEqual(self.guard.stats["actions_rejected"], 2)
        self.assertEqual(self.guard.stats["high_risk_flagged"], 1)

    def test_validate_actions_batch(self):
        out = self.guard.validate_actions(
            [
                {"action": "rate_limit", "ip": "1.1.1.1"},
                {"action": "drop_packet"},
                {"action": "shutdown_port", "port": 22},
            ]
        )
        self.assertEqual(out[0]["action"], "rate_limit")
        self.assertEqual(out[1]["action"], "drop_packet")
        self.assertEqual(out[2]["action"], "alert")
        self.assertEqual(out[2]["original_action"], "shutdown_port")

    def test_whitelist_covers_core_actions(self):
        self.assertTrue({"none", "alert", "block_ip", "isolate_ip", "rate_limit",
                         "shutdown_port", "drop_packet", "challenge", "sandbox",
                         "redirect_honeypot", "notify_admin", "remediate"} <= ALLOWED_ACTION_WHITELIST)

    def test_high_risk_actions_subset_of_whitelist(self):
        self.assertTrue(HIGH_RISK_ACTIONS <= ALLOWED_ACTION_WHITELIST)


class TestFalsePositiveFilterIntegration(unittest.TestCase):
    def setUp(self):
        self.fp = FalsePositiveFilter()

    def test_facade_validate_action_unknown(self):
        safe, reason = self.fp.validate_action({"action": "format_disk"})
        self.assertEqual(reason, "unknown_action")
        self.assertEqual(safe["action"], "alert")

    def test_facade_validate_action_high_risk(self):
        safe, reason = self.fp.validate_action({"action": "isolate_ip", "ip": "8.8.8.8"})
        self.assertEqual(reason, "blocked_high_risk")
        self.assertEqual(safe["action"], "alert")

    def test_facade_validate_action_ok(self):
        safe, reason = self.fp.validate_action({"action": "block_ip", "ip": "1.1.1.1"})
        self.assertEqual(reason, "ok")
        self.assertEqual(safe["action"], "block_ip")

    def test_facade_stats(self):
        self.fp.validate_action({"action": "block_ip"})
        self.fp.validate_action({"action": "delete_database"})
        self.fp.validate_action({"action": "sandbox"})
        self.assertEqual(self.fp.stats["output_actions_checked"], 3)
        self.assertEqual(self.fp.stats["output_actions_rejected"], 2)
        self.assertEqual(self.fp.stats["output_high_risk_flagged"], 1)

    def test_stats_report_mentions_output_guard(self):
        self.fp.validate_action({"action": "block_ip"})
        self.assertIn("输出护栏", self.fp.get_stats_report())


if __name__ == "__main__":
    unittest.main()
