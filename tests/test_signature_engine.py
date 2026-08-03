"""
特征规则引擎 (signature_engine) 单元测试
覆盖：Suricata 规则解析、内置/外部规则加载、告警匹配与置信度、
阈值验证、统计信息、攻击类型相关性、工厂函数。
"""

import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.signature_engine import (
    RuleParser,
    SignatureEngine,
    SignatureRule,
    create_engine,
)


class TestRuleParser(unittest.TestCase):
    """规则解析"""

    def test_parse_full_rule(self):
        line = (
            'alert tcp any any -> any any (msg:"ET DOS Possible DDOS Attack"; '
            'threshold:type threshold, track by_src, count 100, seconds 10; '
            'classtype:attempted-dos; sid:2000001; priority:1;)'
        )
        rule = RuleParser.parse_line(line)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.sid, 2000001)
        self.assertEqual(rule.msg, "ET DOS Possible DDOS Attack")
        self.assertEqual(rule.classtype, "attempted-dos")
        self.assertEqual(rule.priority, 1)
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.threshold_count, 100)
        self.assertEqual(rule.threshold_seconds, 10)
        self.assertEqual(rule.threshold_track, "by_src")
        self.assertEqual(rule.category, "ddos")  # attempted-dos → ddos
        self.assertEqual(rule.severity, "critical")  # priority 1 → critical
        self.assertEqual(rule.action, "block_ip")  # ddos → block_ip

    def test_parse_minimal_rule(self):
        rule = RuleParser.parse_line(
            'alert tcp any any -> any any (msg:"test"; sid:1;)'
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.classtype, "unknown")
        self.assertEqual(rule.priority, 3)
        self.assertEqual(rule.severity, "medium")

    def test_parse_missing_sid_returns_none(self):
        self.assertIsNone(RuleParser.parse_line('alert tcp any any -> any any (msg:"no sid";)'))

    def test_parse_comment_and_empty(self):
        self.assertIsNone(RuleParser.parse_line("# comment"))
        self.assertIsNone(RuleParser.parse_line(""))
        self.assertIsNone(RuleParser.parse_line("   "))

    def test_parse_non_alert_line(self):
        self.assertIsNone(RuleParser.parse_line("drop tcp any any -> any any (sid:1;)"))

    def test_infer_type(self):
        cases = {
            "ET DOS Possible DDOS Attack": "ddos",
            "Port Scan Detected": "port_scan",
            "Brute Force Login Attempt": "brute_force",
            "SQL Injection Attempt": "sql_injection",
            "C2 Beacon Activity": "c2_beacon",
            "Malware Traffic": "malware_c2",
            "DNS Tunnel": "dns_tunnel",
            "Data Exfiltration": "data_exfiltration",
            "Something Unknown": "unknown",
        }
        for msg, expected in cases.items():
            self.assertEqual(RuleParser._infer_type(msg), expected, msg)

    def test_content_patterns_extracted(self):
        rule = RuleParser.parse_line(
            'alert tcp any any -> any any (msg:"SQL Injection"; content:"SELECT"; nocase; sid:9;)'
        )
        self.assertEqual(rule.content_patterns, ["select"])

    def test_priority_to_severity_mapping(self):
        self.assertEqual(SignatureRule("sid=1", "m", "unknown", 2, "tcp", "").severity, "high")
        self.assertEqual(SignatureRule("sid=1", "m", "unknown", 4, "tcp", "").severity, "low")
        self.assertEqual(SignatureRule("sid=1", "m", "unknown", 9, "tcp", "").severity, "medium")

    def test_category_mapping(self):
        self.assertEqual(SignatureRule(1, "m", "attempted-recon", 2, "tcp", "").category, "recon")
        self.assertEqual(SignatureRule(1, "m", "trojan-activity", 2, "tcp", "").category, "malware_c2")
        self.assertEqual(SignatureRule(1, "m", "network-scan", 2, "tcp", "").category, "port_scan")

    def test_action_mapping(self):
        self.assertEqual(SignatureRule(1, "m", "trojan-activity", 1, "tcp", "").action, "isolate_host")
        self.assertEqual(SignatureRule(1, "m", "attempted-admin", 1, "tcp", "").action, "block_ip")
        self.assertEqual(SignatureRule(1, "m", "unknown-x", 2, "tcp", "").action, "monitor")

    def test_parse_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False, encoding="utf-8") as f:
            f.write("# comment\n")
            f.write('alert tcp any any -> any any (msg:"Rule A"; sid:10;) \n')
            f.write('alert udp any any -> any any (msg:"Rule B"; sid:11;) \n')
            f.write('garbage line\n')
            path = f.name
        try:
            rules = RuleParser.parse_file(path)
            self.assertEqual(len(rules), 2)
            self.assertEqual({r.sid for r in rules}, {10, 11})
        finally:
            os.unlink(path)


class TestSignatureEngine(unittest.TestCase):
    """规则引擎匹配"""

    def test_builtin_rules_loaded_without_file(self):
        engine = SignatureEngine(rules_path="nonexistent/rules/default.rules")
        stats = engine.get_stats()
        self.assertGreaterEqual(stats["rules_loaded"], 5)

    def test_default_rules_loaded(self):
        engine = SignatureEngine()
        stats = engine.get_stats()
        self.assertGreaterEqual(stats["rules_loaded"], 1)

    def test_match_ddos(self):
        engine = SignatureEngine(rules_path="nonexistent")
        result = engine.match({"type": "ddos", "packets": 150})
        self.assertIsNotNone(result)
        self.assertEqual(result["category"], "ddos")
        self.assertEqual(result["rule_id"], 2000001)
        self.assertGreater(result["confidence"], 0.5)

    def test_match_sql_injection_by_content(self):
        engine = SignatureEngine(rules_path="nonexistent")
        result = engine.match({"type": "sql_injection", "payload": "SELECT * FROM users"})
        self.assertIsNotNone(result)
        self.assertEqual(result["rule_id"], 2000004)
        self.assertGreater(result["confidence"], 0.7)

    def test_no_match_for_unrelated_type(self):
        engine = SignatureEngine(rules_path="nonexistent")
        result = engine.match({"type": "totally_unrelated", "packets": 1000})
        self.assertIsNone(result)

    def test_threshold_reduces_confidence(self):
        engine = SignatureEngine(rules_path="nonexistent")
        # c2 规则 threshold count=5，包数不足时置信度被压低
        result = engine.match({"type": "c2_beacon", "packets": 2})
        self.assertIsNotNone(result)
        self.assertEqual(result["rule_id"], 2000005)
        self.assertLess(result["confidence"], 0.4)

    def test_stats_tracking(self):
        engine = SignatureEngine(rules_path="nonexistent")
        engine.match({"type": "ddos", "packets": 200})
        engine.match({"type": "unrelated", "packets": 1})
        stats = engine.get_stats()
        self.assertEqual(stats["total_checks"], 2)
        self.assertEqual(stats["total_matches"], 1)
        self.assertEqual(stats["hit_rate"], 0.5)
        self.assertIn(2000001, stats["per_rule_hits"])

    def test_load_rules_from_file_appends(self):
        engine = SignatureEngine(rules_path="nonexistent")
        before = engine.get_stats()["rules_loaded"]
        with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False, encoding="utf-8") as f:
            f.write('alert tcp any any -> any any (msg:"Custom"; classtype:network-scan; sid:900001; priority:2;) \n')
            f.write('alert tcp any any -> any any (msg:"Custom2"; classtype:attempted-dos; sid:900002; priority:3;) \n')
            path = f.name
        try:
            loaded = engine.load_rules_from_file(path)
            self.assertEqual(loaded, 2)
            self.assertEqual(engine.get_stats()["rules_loaded"], before + 2)
            result = engine.match({"type": "port_scan", "ports": 40})
            self.assertIsNotNone(result)
        finally:
            os.unlink(path)

    def test_related_type_scores_partial(self):
        engine = SignatureEngine(rules_path="nonexistent")
        # ddos 与 port_scan 相关组 → 部分得分
        result = engine.match({"type": "port_scan", "ports": 500})
        self.assertIsNotNone(result)
        self.assertIn(result["rule_id"], (2000001, 2000002))

    def test_is_related_type(self):
        self.assertTrue(SignatureEngine._is_related_type("ddos", "port_scan"))
        self.assertTrue(SignatureEngine._is_related_type("c2_beacon", "malware_c2"))
        self.assertFalse(SignatureEngine._is_related_type("ddos", "sql_injection"))


class TestCreateEngine(unittest.TestCase):
    """工厂函数 create_engine"""

    def test_create_engine_loads_rules(self):
        engine = create_engine()
        self.assertIsInstance(engine, SignatureEngine)
        self.assertGreaterEqual(engine.get_stats()["rules_loaded"], 1)

    def test_create_engine_with_custom_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, "rules")
            os.makedirs(rules_dir)
            with open(os.path.join(rules_dir, "default.rules"), "w", encoding="utf-8") as f:
                f.write('alert tcp any any -> any any (msg:"OnlyRule"; classtype:network-scan; sid:800001; priority:2;) \n')
            engine = create_engine(rules_dir=rules_dir)
            self.assertEqual(engine.get_stats()["rules_loaded"], 1)


if __name__ == "__main__":
    unittest.main()
