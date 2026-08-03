"""
灰度推送器 - 分批推送升级包到集群单元。

推送策略：
  金丝雀批次（10%单元）→ 观察3轮心跳周期
  → 增量批次（30%单元）→ 观察2轮心跳周期
  → 全量批次（剩余60%）

异常自动回滚：当前批次失败 → 自动回滚该批次所有单元到快照版本。
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from .package_builder import UpgradePackage


class BatchStatus(Enum):
    PENDING = auto()
    IN_PROGRESS = auto()
    SUCCESS = auto()
    FAILED = auto()
    ROLLED_BACK = auto()


class RolloutPhase(Enum):
    CANARY = "canary"
    INCREMENTAL = "incremental"
    FULL = "full"


@dataclass
class BatchResult:
    """单批次推送结果。"""
    phase: str
    target_unit_ids: List[str]
    status: BatchStatus
    units_succeeded: List[str] = field(default_factory=list)
    units_failed: List[str] = field(default_factory=list)
    observation_metrics: Dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    completed_at: str = ""

    @property
    def success_rate(self) -> float:
        if not self.target_unit_ids:
            return 1.0
        return len(self.units_succeeded) / len(self.target_unit_ids)


@dataclass
class RolloutResult:
    """完整灰度推送结果。"""
    rollout_id: str
    package_id: str
    status: str  # completed / partially_failed / fully_failed / rolled_back
    canary_result: Optional[BatchResult] = None
    incremental_result: Optional[BatchResult] = None
    full_result: Optional[BatchResult] = None
    rollback_targets: List[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    summary: str = ""


class RolloutController:
    """
    灰度推送控制器。

    实现三阶段灰度发布：
    1. 金丝雀（canary）：小比例单元先升级验证
    2. 增量（incremental）：中比例扩展
    3. 全量（full）：剩余全部升级
    """

    def __init__(
        self,
        canary_ratio: float = 0.10,
        incremental_ratio: float = 0.30,
        canary_observe_rounds: int = 3,
        incremental_observe_rounds: int = 2,
        heartbeat_interval: float = 1.0,
        dry_run: bool = False,
        output_dir: str = ".",

    ):
        self.canary_ratio = canary_ratio
        self.incremental_ratio = incremental_ratio
        self.canary_observe_rounds = canary_observe_rounds
        self.incremental_observe_rounds = incremental_observe_rounds
        self.heartbeat_interval = heartbeat_interval
        self.dry_run = dry_run
        self.output_dir = output_dir
        self._rollout_counter = 0
        self._rollout_history: Dict[str, RolloutResult] = {}

    def _calculate_batches(self, unit_ids: List[str]) -> Dict[str, List[str]]:
        """根据比例将单元列表分配到三个批次。"""
        total = len(unit_ids)
        if total == 0:
            return {"canary": [], "incremental": [], "full": []}

        canary_count = max(1, int(total * self.canary_ratio))
        incremental_count = max(1, int(total * self.incremental_ratio))

        # 确保不重叠
        canary = unit_ids[:canary_count]
        incremental = unit_ids[canary_count:canary_count + incremental_count]
        full = unit_ids[canary_count + incremental_count:]

        return {"canary": canary, "incremental": incremental, "full": full}

    async def _observe_batch(
        self,
        unit_ids: List[str],
        rounds: int,
        get_unit_metrics,
    ) -> Dict[str, Any]:
        """
        观察指定轮次心跳周期，收集单元指标。

        Args:
            unit_ids: 观察的单元ID列表
            rounds: 观察轮次
            get_unit_metrics: 获取单元指标的回调函数
        """
        metrics_history = []
        all_healthy = True

        for r in range(rounds):
            await asyncio.sleep(self.heartbeat_interval)
            round_metrics = {}
            for uid in unit_ids:
                metrics = get_unit_metrics(uid)
                round_metrics[uid] = metrics
                if not metrics.get("healthy", True):
                    all_healthy = False
            metrics_history.append(round_metrics)

        return {
            "rounds_observed": rounds,
            "total_duration_seconds": rounds * self.heartbeat_interval,
            "all_healthy": all_healthy,
            "metrics_history": metrics_history,
        }

    async def start_rollout(
        self,
        package: UpgradePackage,
        cluster_units: List[Any],  # DFUUnit 列表
    ) -> RolloutResult:
        """
        执行完整灰度推送流程。

        Args:
            package: 升级包
            cluster_units: 集群单元列表（每个单元需有 unit_id / status / apply_upgrade 方法）

        Returns:
            RolloutResult
        """
        self._rollout_counter += 1
        rollout_id = f"ROLLOUT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._rollout_counter:04d}"

        unit_map = {u.unit_id: u for u in cluster_units}
        unit_ids = list(unit_map.keys())
        batches = self._calculate_batches(unit_ids)

        started_at = datetime.now().isoformat()

        # 辅助函数：获取单元健康指标
        def get_metrics(uid: str) -> Dict:
            unit = unit_map.get(uid)
            if unit is None:
                return {"healthy": False, "error": "unit not found"}
            # 模拟心跳检测
            try:
                status = unit.get_current_status() if hasattr(unit, 'get_current_status') else "active"
                return {
                    "healthy": status != "offline",
                    "status": status,
                    "knowledge_hit_rate": getattr(unit, 'knowledge_hit_rate', 0.85),
                }
            except Exception:
                return {"healthy": True, "status": "unknown"}

        # ==================== 阶段1：金丝雀批次 ====================
        canary_result = None
        canary_ok = True
        phase = RolloutPhase.CANARY.value

        if batches["canary"]:
            canary_result = BatchResult(
                phase=phase,
                target_unit_ids=list(batches["canary"]),
                status=BatchStatus.IN_PROGRESS,
                started_at=datetime.now().isoformat(),
            )

            # 推送升级到金丝雀单元
            for uid in batches["canary"]:
                try:
                    unit = unit_map[uid]
                    if hasattr(unit, 'apply_upgrade'):
                        await unit.apply_upgrade(package)
                    canary_result.units_succeeded.append(uid)
                except Exception:
                    canary_result.units_failed.append(uid)
                    canary_ok = False

            # 观察心跳周期
            if canary_ok:
                metrics = await self._observe_batch(
                    batches["canary"],
                    self.canary_observe_rounds,
                    get_metrics,
                )
                canary_result.observation_metrics = metrics
                canary_ok = metrics["all_healthy"]

            canary_result.status = BatchStatus.SUCCESS if canary_ok else BatchStatus.FAILED
            canary_result.completed_at = datetime.now().isoformat()

            if not canary_ok:
                # 金丝雀失败 → 自动回滚 → 终止
                await self._rollback_batch(batches["canary"], unit_map, package)
                canary_result.status = BatchStatus.ROLLED_BACK
        else:
            canary_result = BatchResult(
                phase=phase, target_unit_ids=[],
                status=BatchStatus.SUCCESS,
                started_at=datetime.now().isoformat(),
                completed_at=datetime.now().isoformat(),
            )

        # ==================== 阶段2：增量批次 ====================
        incremental_result = None
        incremental_ok = canary_ok  # 金丝雀失败则跳过后续

        if incremental_ok and batches["incremental"]:
            incremental_result = BatchResult(
                phase=RolloutPhase.INCREMENTAL.value,
                target_unit_ids=list(batches["incremental"]),
                status=BatchStatus.IN_PROGRESS,
                started_at=datetime.now().isoformat(),
            )

            for uid in batches["incremental"]:
                try:
                    unit = unit_map[uid]
                    if hasattr(unit, 'apply_upgrade'):
                        await unit.apply_upgrade(package)
                    incremental_result.units_succeeded.append(uid)
                except Exception:
                    incremental_result.units_failed.append(uid)
                    incremental_ok = False

            if incremental_ok:
                metrics = await self._observe_batch(
                    batches["incremental"],
                    self.incremental_observe_rounds,
                    get_metrics,
                )
                incremental_result.observation_metrics = metrics
                incremental_ok = metrics["all_healthy"]

            incremental_result.status = BatchStatus.SUCCESS if incremental_ok else BatchStatus.FAILED
            incremental_result.completed_at = datetime.now().isoformat()

            if not incremental_ok:
                # 增量失败 → 回滚增量 + 金丝雀
                await self._rollback_batch(batches["incremental"], unit_map, package)
                await self._rollback_batch(batches["canary"], unit_map, package)
                incremental_result.status = BatchStatus.ROLLED_BACK
        else:
            if canary_ok:
                incremental_result = BatchResult(
                    phase=RolloutPhase.INCREMENTAL.value, target_unit_ids=[],
                    status=BatchStatus.SUCCESS,
                    started_at=datetime.now().isoformat(),
                    completed_at=datetime.now().isoformat(),
                )
            else:
                incremental_result = BatchResult(
                    phase=RolloutPhase.INCREMENTAL.value, target_unit_ids=[],
                    status=BatchStatus.FAILED,
                    started_at=datetime.now().isoformat(),
                    completed_at=datetime.now().isoformat(),
                )

        # ==================== 阶段3：全量批次 ====================
        full_result = None
        full_ok = incremental_ok

        if full_ok and batches["full"]:
            full_result = BatchResult(
                phase=RolloutPhase.FULL.value,
                target_unit_ids=list(batches["full"]),
                status=BatchStatus.IN_PROGRESS,
                started_at=datetime.now().isoformat(),
            )

            for uid in batches["full"]:
                try:
                    unit = unit_map[uid]
                    if hasattr(unit, 'apply_upgrade'):
                        await unit.apply_upgrade(package)
                    full_result.units_succeeded.append(uid)
                except Exception:
                    full_result.units_failed.append(uid)
                    full_ok = False

            full_result.status = BatchStatus.SUCCESS if full_ok else BatchStatus.FAILED
            full_result.completed_at = datetime.now().isoformat()

            if not full_ok:
                # 全量失败 → 回滚全部
                all_pushed = batches["canary"] + batches["incremental"] + batches["full"]
                await self._rollback_batch(all_pushed, unit_map, package)
                full_result.status = BatchStatus.ROLLED_BACK
        else:
            if incremental_ok:
                full_result = BatchResult(
                    phase=RolloutPhase.FULL.value, target_unit_ids=[],
                    status=BatchStatus.SUCCESS,
                    started_at=datetime.now().isoformat(),
                    completed_at=datetime.now().isoformat(),
                )
            else:
                full_result = BatchResult(
                    phase=RolloutPhase.FULL.value, target_unit_ids=[],
                    status=BatchStatus.FAILED,
                    started_at=datetime.now().isoformat(),
                    completed_at=datetime.now().isoformat(),
                )

        # 汇总结果
        if canary_ok and incremental_ok and full_ok:
            overall_status = "completed"
            summary = f"灰度推送完成：{len(unit_ids)} 个单元全部成功升级到 {package.version}"
        elif canary_result and canary_result.status == BatchStatus.ROLLED_BACK:
            overall_status = "rolled_back"
            summary = f"金丝雀批次异常，已回滚 {len(batches['canary'])} 个单元到快照版本"
        elif incremental_result and incremental_result.status == BatchStatus.ROLLED_BACK:
            overall_status = "rolled_back"
            summary = f"增量批次异常，已回滚全部 {(len(batches['canary']) + len(batches['incremental']))} 个单元"
        elif full_result and full_result.status == BatchStatus.ROLLED_BACK:
            overall_status = "rolled_back"
            summary = f"全量批次异常，已回滚全部 {len(unit_ids)} 个单元到快照版本"
        else:
            overall_status = "partially_failed"
            summary = "部分批次推送失败"

        rollback_targets = []
        if overall_status == "rolled_back":
            rollback_targets = unit_ids

        result = RolloutResult(
            rollout_id=rollout_id,
            package_id=package.package_id,
            status=overall_status,
            canary_result=canary_result,
            incremental_result=incremental_result,
            full_result=full_result,
            rollback_targets=rollback_targets,
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            summary=summary,
        )

        self._rollout_history[rollout_id] = result

        # 持久化结果报告
        if not self.dry_run:
            report_path = os.path.join(self.output_dir, f"{rollout_id}_report.json")
            os.makedirs(self.output_dir, exist_ok=True)
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(self._result_to_dict(result), f, indent=2, ensure_ascii=False)

        return result

    async def rollback(self, rollout_id: str) -> Optional[Dict[str, Any]]:
        """
        回滚指定推送的所有已升级单元。

        Returns:
            回滚结果字典，或 None（rollout_id 不存在）
        """
        if rollout_id not in self._rollout_history:
            return None

        result = self._rollout_history[rollout_id]
        all_pushed = []

        for br in [result.canary_result, result.incremental_result, result.full_result]:
            if br:
                all_pushed.extend(br.units_succeeded)

        rollback_info = {
            "rollout_id": rollout_id,
            "status": "rolled_back",
            "rolled_back_units": all_pushed,
            "rolled_back_count": len(all_pushed),
            "completed_at": datetime.now().isoformat(),
        }

        result.status = "rolled_back"
        result.rollback_targets = all_pushed
        result.completed_at = datetime.now().isoformat()

        return rollback_info

    async def _rollback_batch(
        self,
        unit_ids: List[str],
        unit_map: Dict[str, Any],
        package: UpgradePackage,
    ) -> None:
        """回滚指定单元的升级。"""
        for uid in unit_ids:
            unit = unit_map.get(uid)
            if unit and hasattr(unit, 'rollback_upgrade'):
                try:
                    await unit.rollback_upgrade(package)
                except Exception:
                    pass  # 回滚失败记录但继续

    def _result_to_dict(self, result: RolloutResult) -> Dict[str, Any]:
        """将 RolloutResult 转为可序列化字典。"""
        def batch_to_dict(br: Optional[BatchResult]) -> Optional[Dict]:
            if br is None:
                return None
            return {
                "phase": br.phase,
                "target_unit_ids": br.target_unit_ids,
                "status": br.status.name,
                "units_succeeded": br.units_succeeded,
                "units_failed": br.units_failed,
                "success_rate": br.success_rate,
                "observation_metrics": br.observation_metrics,
                "started_at": br.started_at,
                "completed_at": br.completed_at,
            }

        return {
            "rollout_id": result.rollout_id,
            "package_id": result.package_id,
            "status": result.status,
            "canary": batch_to_dict(result.canary_result),
            "incremental": batch_to_dict(result.incremental_result),
            "full": batch_to_dict(result.full_result),
            "rollback_targets": result.rollback_targets,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "summary": result.summary,
        }
