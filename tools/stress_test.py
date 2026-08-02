"""
DFU 性能压测工具 — 向 RabbitMQ 注入可控 QPS 的 threat_alert，采集全链路指标。

用法:
  python stress_test.py --qps 100 --duration 30
  python stress_test.py --qps 500 --duration 60 --warmup 10

配置来源（优先级由高到低）：
    环境变量 RABBITMQ_URL / PROMETHEUS_URL / OUTPUT_DIR
    config.yaml 中的 rabbitmq.url / prometheus.url
"""

import asyncio
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aio_pika

# ── 攻击模板（与 attack_simulator 对齐） ──

ATTACK_POOL = [
    {"type": "ddos", "severity": "severe", "packets": 550, "dst_port": 80},
    {"type": "ddos", "severity": "high", "packets": 250, "dst_port": 443},
    {"type": "ddos", "severity": "medium", "packets": 120, "dst_port": 8080},
    {"type": "port_scan", "severity": "high", "ports": 80, "dst_port": 22},
    {"type": "port_scan", "severity": "medium", "ports": 35, "dst_port": 3306},
    {"type": "brute_force", "severity": "high", "packets": 80, "dst_port": 22},
    {"type": "brute_force", "severity": "medium", "packets": 40, "dst_port": 3389},
    {"type": "syn_flood", "severity": "high", "syn_count": 600, "dst_port": 80},
    {"type": "data_exfil", "severity": "severe", "mb_transferred": 200, "dst_port": 443},
    {"type": "dns_tunnel", "severity": "high", "queries": 500, "dst_port": 53},
]


@dataclass
class StressResult:
    """单轮压测结果"""
    qps: int
    duration_sec: int
    warmup_sec: int
    total_sent: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    actual_qps: float = 0.0
    latencies: List[float] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""


class DFUStressTester:
    """DFU 压测执行器"""

    EXCHANGE = "dfu.events"

    def __init__(self):
        # RabbitMQ URL：环境变量 > config.yaml > 硬编码兜底
        rabbitmq_url = os.environ.get("RABBITMQ_URL", "")
        if not rabbitmq_url:
            try:
                from config import get_config
                rabbitmq_url = get_config().rabbitmq_url
            except Exception:
                rabbitmq_url = "amqp://dfu:K7mP2xW9qR5tN8bL4jH1@localhost:5672/"
        self.rabbitmq_url = rabbitmq_url

        # Prometheus URL：环境变量 > config.yaml > 硬编码兜底
        prometheus_url = os.environ.get("PROMETHEUS_URL", "")
        if not prometheus_url:
            try:
                from config import get_config
                prometheus_url = get_config().prometheus_url
            except Exception:
                prometheus_url = "http://localhost:9090"
        self.prometheus_url = prometheus_url

        self.output_dir = os.environ.get(
            "OUTPUT_DIR",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "stress_results"),
        )
        os.makedirs(self.output_dir, exist_ok=True)

    def _make_message(self, attack_type: str, severity: str, **kwargs) -> dict:
        """生成标准 threat_alert 消息"""
        src_ip = f"218.92.{os.urandom(1)[0] % 255}.{os.urandom(1)[0] % 255}"
        dst_ip = f"192.168.{os.urandom(1)[0] % 5 + 1}.{os.urandom(1)[0] % 255}"
        return {
            "msg_id": str(uuid.uuid4()),
            "source": "StressTester",
            "target": "*",
            "type": "threat_alert",
            "timestamp": datetime.now().isoformat(),
            "reply_to": None,
            "payload": {
                "alert_id": str(uuid.uuid4()),
                "category": attack_type,
                "severity": severity,
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "raw_data": kwargs,
                "description": f"压测 {attack_type} from {src_ip} (severity={severity})",
                "detected_at": datetime.now().isoformat(),
            },
        }

    async def _run_batch(self, qps: int, duration: int, warmup: int) -> StressResult:
        """执行一轮固定 QPS 的压测"""
        result = StressResult(qps=qps, duration_sec=duration, warmup_sec=warmup)
        result.start_time = datetime.now().isoformat()

        connection = await aio_pika.connect_robust(self.rabbitmq_url)
        channel = await connection.channel(publisher_confirms=False)
        exchange = await channel.declare_exchange(
            self.EXCHANGE, aio_pika.ExchangeType.TOPIC, durable=True
        )

        # 预热
        if warmup > 0:
            print(f"  预热 {warmup}s ...", end=" ", flush=True)
            warmup_start = time.time()
            while time.time() - warmup_start < warmup:
                msg = self._make_message("ddos", "low", packets=10, dst_port=80)
                body = json.dumps(msg, ensure_ascii=False, default=str).encode()
                await exchange.publish(aio_pika.Message(body=body), routing_key="threat_alert")
                await asyncio.sleep(0.01)
            print("done")

        # 正式压测 — 批量并发 + 等间隔控速
        print(f"  压测 {qps} QPS × {duration}s ...", end=" ", flush=True)
        batch_count = 10  # 每秒 10 批
        batch_size = max(1, qps // batch_count)
        batch_interval = 1.0 / batch_count
        deadline = time.time() + duration
        next_batch_ts = time.time()

        async def send_one():
            t0 = time.time()
            msg = self._make_message(**self._pick_attack())
            body = json.dumps(msg, ensure_ascii=False, default=str).encode()
            try:
                await exchange.publish(aio_pika.Message(body=body), routing_key="threat_alert")
                result.total_sent += 1
                result.latencies.append((time.time() - t0) * 1000)
            except Exception:
                result.total_errors += 1

        tasks = []
        while time.time() < deadline:
            batch_tasks = []
            for _ in range(batch_size):
                if time.time() >= deadline:
                    break
                batch_tasks.append(asyncio.create_task(send_one()))
            tasks.extend(batch_tasks)

            # 等待到下一批
            next_batch_ts += batch_interval
            wait = next_batch_ts - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            else:
                # 落后于计划，重置
                next_batch_ts = time.time()

        # 等待所有 pending 任务完成
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        result.actual_qps = result.total_sent / duration
        result.end_time = datetime.now().isoformat()

        result.actual_qps = result.total_sent / duration
        result.end_time = datetime.now().isoformat()

        await channel.close()
        await connection.close()

        # 计算延迟分位数
        if result.latencies:
            sorted_lat = sorted(result.latencies)
            n = len(sorted_lat)
            result.avg_latency_ms = sum(sorted_lat) / n
            result.p50_latency_ms = sorted_lat[int(n * 0.5)]
            result.p95_latency_ms = sorted_lat[int(n * 0.95)]
            result.p99_latency_ms = sorted_lat[int(n * 0.99)]

        print(f"done ({result.total_sent} 条, {result.total_errors} 错误)")
        return result

    def _pick_attack(self) -> dict:
        """随机选取攻击模板"""
        import random
        t = random.choice(ATTACK_POOL)
        return {k: v for k, v in t.items() if k not in ("type", "severity")} | {
            "attack_type": t["type"],
            "severity": t["severity"],
        }

    async def _fetch_prometheus(self, metric: str) -> Optional[float]:
        """拉取 Prometheus 指标"""
        try:
            import urllib.request
            url = f"{self.prometheus_url}/api/v1/query?query={metric}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                if data["status"] == "success" and data["data"]["result"]:
                    return float(data["data"]["result"][0]["value"][1])
        except Exception:
            pass
        return None

    async def run_benchmark(self, qps_list: List[int], duration: int = 30, warmup: int = 5):
        """运行完整基准测试"""
        print("=" * 60)
        print(f"DFU 性能压测 | QPS: {qps_list} | 单轮 {duration}s | 预热 {warmup}s")
        print(f"RabbitMQ: {self.rabbitmq_url}")
        print(f"Prometheus: {self.prometheus_url}")
        print("=" * 60)

        results: List[StressResult] = []

        for qps in qps_list:
            print(f"\n[{qps} QPS]")
            result = await self._run_batch(qps, duration, warmup)
            results.append(result)

            # 采集 Prometheus 指标
            alerts_total = await self._fetch_prometheus("dfu_alerts_total")
            llm_calls = await self._fetch_prometheus("dfu_llm_requests_total")
            print(f"  Prometheus: alerts_total={alerts_total}, llm_calls={llm_calls}")

            # 间隔冷却
            if qps != qps_list[-1]:
                cooldown = 10
                print(f"  冷却 {cooldown}s ...")
                await asyncio.sleep(cooldown)

        self._print_report(results)
        self._save_report(results)

    def _print_report(self, results: List[StressResult]):
        """打印压测报告"""
        print("\n" + "=" * 70)
        print("                     DFU 性能压测报告")
        print("=" * 70)
        print(f"{'QPS':>8} | {'实际QPS':>8} | {'发送量':>8} | {'错误':>6} | {'平均延迟':>8} | {'P50':>8} | {'P95':>8} | {'P99':>8}")
        print("-" * 70)
        for r in results:
            print(
                f"{r.qps:>8} | {r.actual_qps:>8.1f} | {r.total_sent:>8} | "
                f"{r.total_errors:>6} | {r.avg_latency_ms:>8.2f}ms | "
                f"{r.p50_latency_ms:>8.2f}ms | {r.p95_latency_ms:>8.2f}ms | "
                f"{r.p99_latency_ms:>8.2f}ms"
            )
        print("-" * 70)

        # 吞吐拐点分析
        if len(results) >= 2:
            prev = results[0].actual_qps / results[0].qps if results[0].qps else 1
            print(f"\n吞吐效率: {results[0].qps}QPS→{prev:.1%} | ", end="")
            for r in results[1:]:
                eff = r.actual_qps / r.qps if r.qps else 0
                print(f"{r.qps}QPS→{eff:.1%} | ", end="")
            print()

        # 延迟拐点
        if len(results) >= 2:
            print(f"延迟趋势: {results[0].avg_latency_ms:.2f}ms → ", end="")
            for r in results[1:]:
                print(f"{r.avg_latency_ms:.2f}ms → ", end="")
            print()

    def _save_report(self, results: List[StressResult]):
        """保存报告到 JSON"""
        report = []
        for r in results:
            report.append({
                "qps": r.qps,
                "actual_qps": round(r.actual_qps, 1),
                "duration_sec": r.duration_sec,
                "total_sent": r.total_sent,
                "total_errors": r.total_errors,
                "avg_latency_ms": round(r.avg_latency_ms, 2),
                "p50_latency_ms": round(r.p50_latency_ms, 2),
                "p95_latency_ms": round(r.p95_latency_ms, 2),
                "p99_latency_ms": round(r.p99_latency_ms, 2),
                "start_time": r.start_time,
                "end_time": r.end_time,
            })

        path = os.path.join(self.output_dir, "benchmark_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n报告已保存: {path}")


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="DFU 性能压测工具")
    parser.add_argument("--qps", type=int, nargs="+", default=[100, 500, 1000],
                        help="QPS 列表，默认 100 500 1000")
    parser.add_argument("--duration", type=int, default=30,
                        help="单轮压测时长(秒)，默认 30")
    parser.add_argument("--warmup", type=int, default=5,
                        help="预热时长(秒)，默认 5")
    args = parser.parse_args()

    tester = DFUStressTester()
    await tester.run_benchmark(args.qps, args.duration, args.warmup)


if __name__ == "__main__":
    asyncio.run(main())
