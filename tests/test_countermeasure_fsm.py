"""
反击状态机 (countermeasure_fsm) 单元测试
覆盖：L0-L4 等级与动作映射、告警升级、L2 硬隔离 severity 门槛、
超时降级与防震荡冷却、L4 三闸门判定、FSM 管理器统计与 L4 触发/降级。
"""

import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.countermeasure_fsm import (
    CountermeasureFSM,
    DEFAULT_COOLDOWN_AFTER_UP,
    DEFAULT_DEBOUNCE_DOWN,
    DEFAULT_ESCALATION_COUNT,
    DEFAULT_ESCALATION_TIME,
    DEFAULT_TTL_AFTER_IDLE,
    FSMLevel,
    IPState,
    L2_HARD_LOW_COUNT_CAP,
    L2_HARD_MIN_SEVERITY,
    LEVEL_ACTIONS,
    LEVEL_ORDER,
    L4_L3_PERSIST_THRESHOLD,
    L4_VULN_THRESHOLD,
    L4_WEB_CONFIRM_TIMEOUT,
    PendingAction,
)


class TestConstants(unittest.TestCase):
    """等级常量与动作映射"""

    def test_level_order(self):
        self.assertEqual(LEVEL_ORDER[0], FSMLevel.L0_MONITOR)
        self.assertEqual(LEVEL_ORDER[1], FSMLevel.L1_SOFT)
        self.assertEqual(LEVEL_ORDER[2], FSMLevel.L2_HARD)
        self.assertEqual(LEVEL_ORDER[3], FSMLevel.L3_OFFENSIVE)
        self.assertEqual(LEVEL_ORDER[4], FSMLevel.L4_ISOLATE)

    def test_level_actions(self):
        self.assertEqual(LEVEL_ACTIONS[FSMLevel.L0_MONITOR], "monitor")
        self.assertEqual(LEVEL_ACTIONS[FSMLevel.L1_SOFT], "rate_limit")
        self.assertEqual(LEVEL_ACTIONS[FSMLevel.L2_HARD], "isolate_ip")
        self.assertEqual(LEVEL_ACTIONS[FSMLevel.L3_OFFENSIVE], "block")
        self.assertEqual(LEVEL_ACTIONS[FSMLevel.L4_ISOLATE], "network_isolation")

    def test_threshold_constants(self):
        self.assertEqual(DEFAULT_ESCALATION_COUNT, 3)
        self.assertEqual(DEFAULT_ESCALATION_TIME, 120)
        self.assertEqual(DEFAULT_COOLDOWN_AFTER_UP, 60)
        self.assertEqual(DEFAULT_DEBOUNCE_DOWN, 30)
        self.assertEqual(DEFAULT_TTL_AFTER_IDLE, 300)


class TestIPStateUpdate(unittest.TestCase):
    """IPState.update：告警计数、峰值 severity、升级判定"""

    def test_update_increments_alert_count(self):
        state = IPState("10.0.0.1")
        state.update("low", 100.0)
        self.assertEqual(state.alert_count, 1)
        state.update("low", 101.0)
        self.assertEqual(state.alert_count, 2)

    def test_update_tracks_peak_severity(self):
        state = IPState("10.0.0.1")
        state.update("low", 100.0)
        state.update("high", 101.0)
        self.assertEqual(state.peak_severity, "high")
        # 更低 severity 不回退峰值
        state.update("low", 102.0)
        self.assertEqual(state.peak_severity, "high")

    def test_three_alerts_escalate_to_l1(self):
        state = IPState("10.0.0.1")
        actions = [state.update("medium", t) for t in (100.0, 101.0, 102.0)]
        self.assertTrue(actions[0].keep_level)
        self.assertTrue(actions[1].keep_level)
        self.assertFalse(actions[2].keep_level)
        self.assertEqual(actions[2].new_level, FSMLevel.L1_SOFT)
        self.assertEqual(state.level, FSMLevel.L1_SOFT)

    def test_escalation_resets_alert_count(self):
        state = IPState("10.0.0.1")
        state.update("medium", 100.0)
        state.update("medium", 101.0)
        state.update("medium", 102.0)  # 升级到 L1
        self.assertEqual(state.alert_count, 0)
        # 再触发 3 次（含 high，满足 L2 severity 门槛）→ L2
        state.update("high", 103.0)
        state.update("high", 104.0)
        action = state.update("high", 105.0)
        self.assertEqual(action.new_level, FSMLevel.L2_HARD)

    def test_escalation_by_duration(self):
        """持续攻击 120s 即使告警数不足也升级"""
        state = IPState("10.0.0.1")
        state.first_seen = 1000.0
        state.last_alert = 1000.0
        action = state.update("medium", 1130.0)  # 130s > 120s
        self.assertFalse(action.keep_level)
        self.assertEqual(action.new_level, FSMLevel.L1_SOFT)

    def test_max_level_keeps_level(self):
        """L4 已是最高等级，不再升级"""
        state = IPState("10.0.0.1")
        state.level = FSMLevel.L4_ISOLATE
        state.alert_count = 5
        action = state.update("severe", 100.0)
        self.assertTrue(action.keep_level)
        self.assertEqual(action.new_level, FSMLevel.L4_ISOLATE)


class TestL2SeverityGate(unittest.TestCase):
    """L2 硬隔离 severity 门槛：仅 low 告警不得硬隔离"""

    def test_low_alerts_rejected_for_l2(self):
        """low 告警 3 次升级到 L1 后，再 low 告警拒绝升级 L2"""
        state = IPState("10.0.0.1")
        for t in (100.0, 101.0, 102.0):
            state.update("low", t)  # → L1
        self.assertEqual(state.level, FSMLevel.L1_SOFT)
        for t in (103.0, 104.0, 105.0, 106.0, 107.0, 108.0, 109.0):
            action = state.update("low", t)
            self.assertTrue(action.keep_level, f"t={t} 不应升级 L2")
        self.assertEqual(state.level, FSMLevel.L1_SOFT)
        self.assertIn("未达硬隔离升级条件", action.reason)

    def test_low_alerts_escalate_after_cap(self):
        """全部 low 时累计达 L2_HARD_LOW_COUNT_CAP 次允许升级"""
        state = IPState("10.0.0.1")
        for t in (100.0, 101.0, 102.0):
            state.update("low", t)  # → L1
        self.assertEqual(state.level, FSMLevel.L1_SOFT)
        action = None
        for i in range(L2_HARD_LOW_COUNT_CAP):
            action = state.update("low", 200.0 + i)
        self.assertFalse(action.keep_level)
        self.assertEqual(action.new_level, FSMLevel.L2_HARD)
        self.assertEqual(state.level, FSMLevel.L2_HARD)

    def test_high_severity_allows_l2(self):
        """peak_severity 达 high 时 low/medium 次数不足也允许升级 L2"""
        state = IPState("10.0.0.1")
        state.update("high", 100.0)
        state.update("high", 101.0)
        action = state.update("high", 102.0)  # → L1
        self.assertEqual(action.new_level, FSMLevel.L1_SOFT)
        state.update("high", 103.0)
        state.update("high", 104.0)
        action = state.update("high", 105.0)  # → L2，peak=high 满足门槛
        self.assertEqual(action.new_level, FSMLevel.L2_HARD)

    def test_severity_constants(self):
        self.assertEqual(L2_HARD_MIN_SEVERITY, "high")
        self.assertEqual(L2_HARD_LOW_COUNT_CAP, 8)


class TestTickDowngradeAndAntiOscillation(unittest.TestCase):
    """tick：超时降级、升级后冷却期防震荡、L0 移除"""

    def _make_l1_state(self, last_alert, last_upgrade):
        state = IPState("10.0.0.1")
        state.level = FSMLevel.L1_SOFT
        state.last_alert = last_alert
        state.last_upgrade = last_upgrade
        return state

    def test_timeout_downgrade(self):
        """静默超过 60s 且冷却期已过 → 降级一级"""
        now = 1000.0
        state = self._make_l1_state(last_alert=now - 70, last_upgrade=now - 70)
        action = state.tick(now)
        self.assertIsNotNone(action)
        self.assertEqual(action.old_level, FSMLevel.L1_SOFT)
        self.assertEqual(action.new_level, FSMLevel.L0_MONITOR)
        self.assertEqual(state.level, FSMLevel.L0_MONITOR)

    def test_no_downgrade_within_cooldown(self):
        """升级后 60s 冷却期内即使静默超时也不降级（防震荡）"""
        now = 1000.0
        # last_upgrade 10s 前 → 冷却期未过
        state = self._make_l1_state(last_alert=now - 70, last_upgrade=now - 10)
        action = state.tick(now)
        self.assertIsNone(action)
        self.assertEqual(state.level, FSMLevel.L1_SOFT)

    def test_no_downgrade_within_60s_silence(self):
        """静默不足 60s 不降级"""
        now = 1000.0
        state = self._make_l1_state(last_alert=now - 30, last_upgrade=now - 100)
        action = state.tick(now)
        self.assertIsNone(action)

    def test_tick_downgrade_cascades_to_l0(self):
        """多级降级最终回到 L0"""
        now = 1000.0
        state = IPState("10.0.0.1")
        state.level = FSMLevel.L2_HARD
        state.last_alert = now - 80
        state.last_upgrade = now - 80
        action = state.tick(now)
        self.assertEqual(action.new_level, FSMLevel.L1_SOFT)
        action = state.tick(now)
        self.assertEqual(action.new_level, FSMLevel.L0_MONITOR)

    def test_idle_l0_removed(self):
        """L0 静默超过 TTL → 标记移除"""
        now = 1000.0
        state = IPState("10.0.0.1")
        state.first_seen = now - 400
        state.last_alert = now - 400
        action = state.tick(now)
        self.assertIsNotNone(action)
        self.assertEqual(action.new_level, "REMOVED")
        self.assertEqual(action.action, "remove")

    def test_idle_l0_not_removed_before_ttl(self):
        now = 1000.0
        state = IPState("10.0.0.1")
        state.first_seen = now - 100
        state.last_alert = now - 100
        self.assertIsNone(state.tick(now))


class TestL4TripleGate(unittest.TestCase):
    """L4 三闸门判定（闸门3 对新 IP 默认放行是设计选择）"""

    def _make_l3_state(self):
        state = IPState("10.0.0.1")
        state.level = FSMLevel.L3_OFFENSIVE
        return state

    def test_new_ip_gate3_defaults_open(self):
        """从未触发过 Web 确认检查的新 IP：闸门3 默认放行"""
        state = self._make_l3_state()
        self.assertEqual(state.web_panel_last_check, 0.0)
        passed, reason = state.check_l4_triple_gate(now=1000.0)
        self.assertIn("闸门3", reason)
        self.assertIn("从未确认", reason)
        # 新 IP 闸门3 为 True（放行），但闸门1/2 未满足 → 整体不过
        self.assertFalse(passed)

    def test_all_gates_open(self):
        """三闸门全开 → L4 判定通过"""
        now = 1000.0
        state = self._make_l3_state()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        passed, reason = state.check_l4_triple_gate(now)
        self.assertTrue(passed, reason)
        self.assertIn("闸门1", reason)
        self.assertIn("闸门2", reason)
        self.assertIn("闸门3", reason)

    def test_gate1_vuln_count_insufficient(self):
        """闸门1：漏洞报错次数不足阈值 → 不通过"""
        now = 1000.0
        state = self._make_l3_state()
        for i in range(L4_VULN_THRESHOLD - 1):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        passed, reason = state.check_l4_triple_gate(now)
        self.assertFalse(passed)
        self.assertIn(f"{L4_VULN_THRESHOLD - 1}/{L4_VULN_THRESHOLD}", reason)

    def test_gate2_l3_not_stuck(self):
        """闸门2：L3 未进入无法压制状态 → 不通过"""
        now = 1000.0
        state = self._make_l3_state()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        # l3_unstoppable_since = None → 闸门2 未触发
        passed, reason = state.check_l4_triple_gate(now)
        self.assertFalse(passed)
        self.assertIn("未触发", reason)

    def test_gate2_duration_not_met(self):
        """闸门2：L3 无法压制时长不足 → 不通过"""
        now = 1000.0
        state = self._make_l3_state()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD + 30
        passed, reason = state.check_l4_triple_gate(now)
        self.assertFalse(passed)

    def test_gate3_web_confirmed_blocks(self):
        """闸门3：Web 面板已确认 → 不通过"""
        now = 1000.0
        state = self._make_l3_state()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        state.set_web_panel_confirmed(True, now)  # 已确认
        passed, reason = state.check_l4_triple_gate(now)
        self.assertFalse(passed)
        self.assertIn("闸门3", reason)

    def test_gate3_unconfirmed_within_timeout(self):
        """闸门3：未确认但尚未超过 10 分钟超时 → 不通过"""
        now = 1000.0
        state = self._make_l3_state()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        state.set_web_panel_confirmed(False, now - 60)  # 60s 前检查过，未确认
        passed, reason = state.check_l4_triple_gate(now)
        self.assertFalse(passed)
        self.assertLess(60, L4_WEB_CONFIRM_TIMEOUT)

    def test_gate3_unconfirmed_after_timeout(self):
        """闸门3：未确认且超过 10 分钟超时 → 通过"""
        now = 1000.0
        state = self._make_l3_state()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        state.set_web_panel_confirmed(False, now - L4_WEB_CONFIRM_TIMEOUT - 100)
        passed, reason = state.check_l4_triple_gate(now)
        self.assertTrue(passed, reason)

    def test_l4_constants(self):
        self.assertEqual(L4_VULN_THRESHOLD, 5)
        self.assertEqual(L4_L3_PERSIST_THRESHOLD, 180)
        self.assertEqual(L4_WEB_CONFIRM_TIMEOUT, 600)


class TestCountermeasureFSM(unittest.TestCase):
    """FSM 管理器：evaluate 升级、L4 触发/降级、统计"""

    def test_evaluate_escalates_to_l3(self):
        fsm = CountermeasureFSM()
        for _ in range(9):
            fsm.evaluate("192.168.1.5", severity="high")
        self.assertEqual(fsm.get_level("192.168.1.5"), FSMLevel.L3_OFFENSIVE)

    def test_evaluate_low_severity_stuck_at_l1(self):
        """low 告警升级到 L1 后不再硬隔离升级（severity 门槛）"""
        fsm = CountermeasureFSM()
        for _ in range(3):
            fsm.evaluate("10.0.0.2", severity="low")
        self.assertEqual(fsm.get_level("10.0.0.2"), FSMLevel.L1_SOFT)
        for _ in range(5):
            fsm.evaluate("10.0.0.2", severity="low")
        self.assertEqual(fsm.get_level("10.0.0.2"), FSMLevel.L1_SOFT)

    def test_get_level_unknown_ip(self):
        fsm = CountermeasureFSM()
        self.assertIsNone(fsm.get_level("no.such.ip"))

    def test_get_all_levels(self):
        fsm = CountermeasureFSM()
        fsm.evaluate("1.1.1.1", severity="medium")
        fsm.evaluate("2.2.2.2", severity="medium")
        levels = fsm.get_all_levels()
        self.assertEqual(set(levels.keys()), {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(levels["1.1.1.1"], FSMLevel.L0_MONITOR)

    def _force_l3_state(self, fsm, ip):
        state = fsm._states[ip]
        state.level = FSMLevel.L3_OFFENSIVE
        return state

    def test_check_kill_conditions_not_l3_returns_none(self):
        fsm = CountermeasureFSM()
        fsm.evaluate("1.1.1.1", severity="medium")
        self.assertIsNone(fsm.check_network_kill_conditions("1.1.1.1"))
        self.assertIsNone(fsm.check_network_kill_conditions("unknown.ip"))

    def test_check_kill_conditions_triggers_l4(self):
        """L3 状态下三闸门全开 → 升级 L4 网络隔离"""
        fsm = CountermeasureFSM()
        fsm.evaluate("10.0.0.9", severity="high")
        fsm.evaluate("10.0.0.9", severity="high")
        fsm.evaluate("10.0.0.9", severity="high")  # L1
        fsm.evaluate("10.0.0.9", severity="high")
        fsm.evaluate("10.0.0.9", severity="high")
        fsm.evaluate("10.0.0.9", severity="high")  # L2
        fsm.evaluate("10.0.0.9", severity="high")
        fsm.evaluate("10.0.0.9", severity="high")
        fsm.evaluate("10.0.0.9", severity="high")  # L3
        self.assertEqual(fsm.get_level("10.0.0.9"), FSMLevel.L3_OFFENSIVE)

        state = self._force_l3_state(fsm, "10.0.0.9")
        now = time.time()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10

        action = fsm.check_network_kill_conditions("10.0.0.9")
        self.assertIsNotNone(action)
        self.assertEqual(action.old_level, FSMLevel.L3_OFFENSIVE)
        self.assertEqual(action.new_level, FSMLevel.L4_ISOLATE)
        self.assertEqual(action.action, "network_isolation")
        self.assertEqual(fsm.get_level("10.0.0.9"), FSMLevel.L4_ISOLATE)
        self.assertEqual(fsm._stats["l4_activations"], 1)

    def test_check_kill_conditions_gate3_confirmed_blocks(self):
        """Web 面板已确认 → 即使闸门1/2 满足也不触发 L4"""
        fsm = CountermeasureFSM()
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")
        fsm.evaluate("10.0.0.10", severity="high")  # L3
        state = self._force_l3_state(fsm, "10.0.0.10")
        now = time.time()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        state.set_web_panel_confirmed(True, now)  # 已确认 → 闸门3 关闭

        action = fsm.check_network_kill_conditions("10.0.0.10")
        self.assertIsNone(action)
        self.assertEqual(fsm.get_level("10.0.0.10"), FSMLevel.L3_OFFENSIVE)

    def test_l4_downgrade_when_gate_no_longer_met(self):
        """L4 状态下任一闸门不再满足 → 降级回 L3"""
        fsm = CountermeasureFSM()
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")
        fsm.evaluate("10.0.0.11", severity="high")  # L3
        state = self._force_l3_state(fsm, "10.0.0.11")
        now = time.time()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        state.level = FSMLevel.L4_ISOLATE  # 直接进入 L4
        state.set_web_panel_confirmed(True, now)  # 闸门3 关闭 → 闸门不再全满足

        action = fsm.check_network_kill_conditions("10.0.0.11")
        self.assertIsNotNone(action)
        self.assertEqual(action.old_level, FSMLevel.L4_ISOLATE)
        self.assertEqual(action.new_level, FSMLevel.L3_OFFENSIVE)
        self.assertEqual(fsm.get_level("10.0.0.11"), FSMLevel.L3_OFFENSIVE)
        self.assertEqual(fsm._stats["downgrades"], 1)

    def test_l4_downgrade_not_triggered_when_gates_still_met(self):
        """L4 状态下三闸门仍全部满足 → 保持 L4 不降级"""
        fsm = CountermeasureFSM()
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")
        fsm.evaluate("10.0.0.12", severity="high")  # L3
        state = self._force_l3_state(fsm, "10.0.0.12")
        now = time.time()
        for i in range(L4_VULN_THRESHOLD):
            state.record_vuln_error(now - 10 + i)
        state.l3_unstoppable_since = now - L4_L3_PERSIST_THRESHOLD - 10
        state.level = FSMLevel.L4_ISOLATE  # 直接进入 L4（闸门全满足）

        action = fsm.check_network_kill_conditions("10.0.0.12")
        self.assertIsNone(action)
        self.assertEqual(fsm.get_level("10.0.0.12"), FSMLevel.L4_ISOLATE)

    def test_stats_and_summary(self):
        fsm = CountermeasureFSM()
        for _ in range(3):
            fsm.evaluate("8.8.8.8", severity="high")
        self.assertEqual(fsm._stats["total_ips"], 1)
        self.assertEqual(fsm._stats["upgrades"], 1)
        self.assertEqual(fsm._stats["active_l1"], 1)
        summary = fsm.summary()
        self.assertIn("总IP", summary)
        self.assertIn("L1", summary)

    def test_set_enabled(self):
        fsm = CountermeasureFSM()
        fsm.set_enabled(False)
        self.assertFalse(fsm._enabled)
        fsm.set_enabled(True)
        self.assertTrue(fsm._enabled)

    def test_tick_all_removes_idle(self):
        fsm = CountermeasureFSM()
        fsm.evaluate("1.1.1.1", severity="medium")
        # 直接构造一个已超时的 L0 状态
        state = fsm._states["1.1.1.1"]
        now = time.time()
        state.first_seen = now - DEFAULT_TTL_AFTER_IDLE - 10
        state.last_alert = now - DEFAULT_TTL_AFTER_IDLE - 10
        actions = fsm.tick_all()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].new_level, "REMOVED")
        self.assertNotIn("1.1.1.1", fsm._states)
        self.assertEqual(fsm._stats["removed"], 1)


class TestPendingAction(unittest.TestCase):
    """PendingAction 数据结构"""

    def test_to_dict(self):
        action = PendingAction(
            ip="1.2.3.4",
            old_level=FSMLevel.L1_SOFT,
            new_level=FSMLevel.L2_HARD,
            action="isolate_ip",
            reason="test",
        )
        d = action.to_dict()
        self.assertEqual(d["ip"], "1.2.3.4")
        self.assertEqual(d["old_level"], FSMLevel.L1_SOFT)
        self.assertEqual(d["new_level"], FSMLevel.L2_HARD)
        self.assertEqual(d["action"], "isolate_ip")
        self.assertEqual(d["reason"], "test")
        self.assertFalse(d["keep_level"])


if __name__ == "__main__":
    unittest.main()
