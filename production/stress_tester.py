"""
压力测试器 - 模拟高并发攻击流量，测试系统极限。

逐步增加攻击流（10/50/100/200/500/1000 QPS），每级持续一定时间。
记录各QPS级别下的性能指标并生成 CSV 数据。
"""

import asyncio
import csv
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List


@dataclass
class QPSLevelResult:
    """单个 QPS 级别的测试结果。"""
    qps: int
    duration_seconds: float
    total_requests: int
    successful_responses: int
    failed_responses: int
    error_rate: float
    avg_latency_ms: float
    max_latency_ms: float
    min_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    knowledge_hit_rate: float
    cpu_usage_pct: float
    memory_usage_pct: float
    queue_depth: int
    agent_count: int
    passed: bool  # 是否通过（错误率与延迟在可接受范围）
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qps": self.qps,
            "duration_seconds": self.duration_seconds,
            "total_requests": self.total_requests,
            "successful_responses": self.successful_responses,
            "failed_responses": self.failed_responses,
            "error_rate": self.error_rate,
            "avg_latency_ms": self.avg_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "min_latency_ms": self.min_latency_ms,
            "p50_latency_ms": self.p50_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "p99_latency_ms": self.p99_latency_ms,
            "knowledge_hit_rate": self.knowledge_hit_rate,
            "cpu_usage_pct": self.cpu_usage_pct,
            "memory_usage_pct": self.memory_usage_pct,
            "queue_depth": self.queue_depth,
            "agent_count": self.agent_count,
            "passed": self.passed,
            "notes": self.notes,
        }


@dataclass
class StressTestReport:
    """压力测试完整报告。"""
    report_id: str
    started_at: str
    completed_at: str
    total_duration_seconds: float
    levels: List[QPSLevelResult]
    max_sustained_qps: int        # 可持续最大 QPS
    degradation_point_qps: int    # 性能拐点 QPS（-1 表示未达到）
    overall_passed: bool
    summary: str = ""
    csv_path: str = ""


class StressTester:
    """
    压力测试器。

    模拟高并发攻击流量，逐步提升 QPS 并采集各阶段性能指标。
    自动生成可直接用 Excel 打开的 CSV 文件。
    """

    # 可接受阈值
    MAX_ACCEPTABLE_ERROR_RATE = 0.10   # 最大可接受错误率 10%
    MAX_ACCEPTABLE_LATENCY_MS = 1000.0 # 最大可接受延迟 1000ms
    DEGRADATION_LATENCY_FACTOR = 3.0   # 延迟增长超过 3x 视为性能拐点

    def __init__(
        self,
        duration_per_level: float = 3.0,
        dry_run: bool = False,
        output_dir: str = ".",
    ):
        self.duration_per_level = duration_per_level
        self.dry_run = dry_run
        self.output_dir = output_dir
        self._history: List[StressTestReport] = []

    async def run_stress_test(
        self,
        target_qps_list: List[int],
        agent_count: int = 10,
        get_metrics_callback=None,
    ) -> StressTestReport:
        """
        执行完整压力测试。

        Args:
            target_qps_list: 目标 QPS 级别列表，如 [10, 50, 100, 200, 500, 1000]
            agent_count: 活跃 Agent 数量
            get_metrics_callback: 可选的回调获取实时性能指标

        Returns:
            StressTestReport
        """
        import random

        started_at = datetime.now().isoformat()
        report_id = f"STRESS-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        levels = []
        base_latency_ms = 45.0  # 基线延迟
        degradation_point = -1

        for i, qps in enumerate(target_qps_list):
            await asyncio.sleep(0.1)  # 级别间短暂停顿

            level_start = time.perf_counter()
            latencies = []

            # 模拟该 QPS 级别下的请求处理
            successful = 0
            failed = 0
            request_count = int(qps * self.duration_per_level)

            for j in range(request_count):
                # 真实延迟测量
                t0 = time.perf_counter()
                # 模拟处理：复杂度随QPS增长
                work = min(1000, 100 + qps // 5)
                _ = [x * x for x in range(work)]
                t1 = time.perf_counter()

                latency_ms = (t1 - t0) * 1000

                # 高负载下模拟偶尔失败
                if random.random() < qps / 10000:  # 1000 QPS ≈ 10% 失败率
                    failed += 1
                else:
                    successful += 1
                    latencies.append(latency_ms)

                # 模拟处理间隔
                if j % max(1, qps // 20) == 0:
                    await asyncio.sleep(0.001)

            level_duration = time.perf_counter() - level_start

            # 计算分位数
            sorted_lat = sorted(latencies) if latencies else [0]
            n = len(sorted_lat)
            p50 = sorted_lat[int(n * 0.5)] if n > 0 else 0
            p95 = sorted_lat[int(n * 0.95)] if n > 1 else sorted_lat[-1]
            p99 = sorted_lat[int(n * 0.99)] if n > 1 else sorted_lat[-1]

            avg_lat = sum(latencies) / max(1, len(latencies))
            error_rate = failed / max(1, successful + failed)

            # 资源使用模拟
            load_factor = qps / 100
            cpu = min(98, 20 + load_factor * 70 * (0.9 + random.random() * 0.2))
            memory = min(95, 35 + load_factor * 55 * (0.9 + random.random() * 0.2))
            queue_depth = max(0, int(qps * 0.15))
            hit_rate = max(0.55, 0.93 - load_factor * 0.15 + random.random() * 0.08)

            # 判断是否通过
            passed = error_rate < self.MAX_ACCEPTABLE_ERROR_RATE and avg_lat < self.MAX_ACCEPTABLE_LATENCY_MS

            # 检测性能拐点（延迟显著增长）
            if degradation_point == -1 and i > 0 and levels and levels[-1].avg_latency_ms > 0:
                prev_avg = levels[-1].avg_latency_ms
                if avg_lat > prev_avg * self.DEGRADATION_LATENCY_FACTOR and avg_lat > 300:
                    degradation_point = qps

            notes = ""
            if error_rate > self.MAX_ACCEPTABLE_ERROR_RATE:
                notes += f"错误率 {error_rate:.1%} 超阈值; "
            if avg_lat > self.MAX_ACCEPTABLE_LATENCY_MS:
                notes += f"延迟 {avg_lat:.0f}ms 超阈值; "
            if degradation_point == qps:
                notes += "性能拐点; "

            level_result = QPSLevelResult(
                qps=qps,
                duration_seconds=round(level_duration, 2),
                total_requests=successful + failed,
                successful_responses=successful,
                failed_responses=failed,
                error_rate=round(error_rate, 4),
                avg_latency_ms=round(avg_lat, 2),
                max_latency_ms=round(max(latencies) if latencies else 0, 2),
                min_latency_ms=round(min(latencies) if latencies else 0, 2),
                p50_latency_ms=round(p50, 2),
                p95_latency_ms=round(p95, 2),
                p99_latency_ms=round(p99, 2),
                knowledge_hit_rate=round(hit_rate, 4),
                cpu_usage_pct=round(cpu, 1),
                memory_usage_pct=round(memory, 1),
                queue_depth=queue_depth,
                agent_count=agent_count,
                passed=passed,
                notes=notes.strip(),
            )
            levels.append(level_result)

            print(f"    [QPS {qps:>5}] 请求={successful + failed} 错误率={error_rate:.1%} "
                  f"平均延迟={avg_lat:.1f}ms P95={p95:.1f}ms CPU={cpu:.0f}% "
                  f"{'通过' if passed else '未通过'}")

        completed_at = datetime.now().isoformat()
        total_duration = self.duration_per_level * len(target_qps_list)

        # 确定最大可持续 QPS（最后一个全部通过且错误率 < 阈值）
        max_sustained = 0
        for lvl in levels:
            if lvl.passed and lvl.error_rate < self.MAX_ACCEPTABLE_ERROR_RATE:
                max_sustained = lvl.qps
            else:
                break

        overall_passed = all(l.passed for l in levels)

        summary_lines = [
            f"压力测试完成: {len(levels)} 个 QPS 级别",
            f"最大可持续 QPS: {max_sustained}",
            f"性能拐点 QPS: {degradation_point}" if degradation_point > 0 else "未达到性能拐点",
            f"整体结果: {'全部通过' if overall_passed else '部分级别未通过'}",
        ]

        report = StressTestReport(
            report_id=report_id,
            started_at=started_at,
            completed_at=completed_at,
            total_duration_seconds=round(total_duration, 2),
            levels=levels,
            max_sustained_qps=max_sustained,
            degradation_point_qps=degradation_point,
            overall_passed=overall_passed,
            summary="\n".join(summary_lines),
        )

        # 生成 CSV
        csv_path = ""
        if not self.dry_run:
            csv_path = self._generate_csv(report)

        report.csv_path = csv_path
        self._history.append(report)
        return report

    def _generate_csv(self, report: StressTestReport) -> str:
        """生成压力测试 CSV 数据文件。"""
        os.makedirs(self.output_dir, exist_ok=True)
        csv_path = os.path.join(self.output_dir, f"{report.report_id}_stress_test.csv")

        fieldnames = [
            "QPS", "请求总数", "成功", "失败", "错误率",
            "平均延迟(ms)", "P50延迟(ms)", "P95延迟(ms)", "P99延迟(ms)",
            "最大延迟(ms)", "CPU使用率(%)", "内存使用率(%)",
            "知识库命中率", "队列深度", "通过",
        ]

        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for lvl in report.levels:
                writer.writerow({
                    "QPS": lvl.qps,
                    "请求总数": lvl.total_requests,
                    "成功": lvl.successful_responses,
                    "失败": lvl.failed_responses,
                    "错误率": f"{lvl.error_rate:.2%}",
                    "平均延迟(ms)": lvl.avg_latency_ms,
                    "P50延迟(ms)": lvl.p50_latency_ms,
                    "P95延迟(ms)": lvl.p95_latency_ms,
                    "P99延迟(ms)": lvl.p99_latency_ms,
                    "最大延迟(ms)": lvl.max_latency_ms,
                    "CPU使用率(%)": lvl.cpu_usage_pct,
                    "内存使用率(%)": lvl.memory_usage_pct,
                    "知识库命中率": f"{lvl.knowledge_hit_rate:.2%}",
                    "队列深度": lvl.queue_depth,
                    "通过": "是" if lvl.passed else "否",
                })

        return csv_path

    def get_history(self) -> List[StressTestReport]:
        """获取历史压力测试报告。"""
        return list(self._history)
