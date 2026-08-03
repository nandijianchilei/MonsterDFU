"""
DFU 压力测试工具 — 评估检测→决策→处置管道的吞吐量与延迟。

使用方式:
    python -m tools.stress_test [--rate RPS] [--duration SEC] [--burst N]

默认: 逐步加压 10→50→100→200 RPS，每档持续 15 秒。
"""

import asyncio
import json
import sys
import os
import time
from argparse import ArgumentParser
from dataclasses import dataclass, field
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
from utils.logger import get_logger, DFULogger

logger = get_logger("StressTest")

# ── 攻击场景池 ──

ATTACK_POOL = [
    {"target_ip": "198.51.100.1",  "attack_type": "DDoS",     "source_ip": "203.0.113.1",  "severity": "high"},
    {"target_ip": "198.51.100.2",  "attack_type": "SQL注入",   "source_ip": "203.0.113.2",  "severity": "high"},
    {"target_ip": "198.51.100.3",  "attack_type": "XSS",       "source_ip": "203.0.113.3",  "severity": "medium"},
    {"target_ip": "198.51.100.4",  "attack_type": "暴力破解",  "source_ip": "203.0.113.4",  "severity": "high"},
    {"target_ip": "198.51.100.5",  "attack_type": "端口扫描",  "source_ip": "203.0.113.5",  "severity": "low"},
    {"target_ip": "198.51.100.6",  "attack_type": "CSRF",      "source_ip": "203.0.113.6",  "severity": "medium"},
    {"target_ip": "198.51.100.7",  "attack_type": "CC攻击",    "source_ip": "203.0.113.7",  "severity": "high"},
    {"target_ip": "198.51.100.8",  "attack_type": "木马上传",  "source_ip": "203.0.113.8",  "severity": "critical"},
    {"target_ip": "198.51.100.9",  "attack_type": "DNS劫持",   "source_ip": "203.0.113.9",  "severity": "medium"},
    {"target_ip": "198.51.100.10", "attack_type": "SSH爆破",   "source_ip": "203.0.113.10", "severity": "high"},
    {"target_ip": "198.51.100.11", "attack_type": "WebShell",  "source_ip": "203.0.113.11", "severity": "critical"},
    {"target_ip": "198.51.100.12", "attack_type": "文件包含",  "source_ip": "203.0.113.12", "severity": "high"},
    {"target_ip": "198.51.100.13", "attack_type": "命令注入",  "source_ip": "203.0.113.13", "severity": "critical"},
    {"target_ip": "198.51.100.14", "attack_type": "反序列化",  "source_ip": "203.0.113.14", "severity": "high"},
    {"target_ip": "198.51.100.15", "attack_type": "SSRF",      "source_ip": "203.0.113.15", "severity": "medium"},
]


@dataclass
class LatencyStats:
    """单次测试的延迟统计。"""
    values: list[float] = field(default_factory=list)

    @property
    def count(self) -> int: return len(self.values)

    @property
    def avg_ms(self) -> float:
        return (sum(self.values) / len(self.values) * 1000) if self.values else 0.0

    @property
    def p50_ms(self) -> float:
        if not self.values: return 0.0
        s = sorted(self.values)
        return s[len(s) // 2] * 1000

    @property
    def p95_ms(self) -> float:
        if not self.values: return 0.0
        s = sorted(self.values)
        return s[int(len(s) * 0.95)] * 1000

    @property
    def p99_ms(self) -> float:
        if not self.values: return 0.0
        s = sorted(self.values)
        return s[int(len(s) * 0.99)] * 1000

    @property
    def max_ms(self) -> float:
        return (max(self.values) * 1000) if self.values else 0.0


async def send_attack(session: aiohttp.ClientSession, url: str, attack: dict) -> float:
    """发送单次攻击请求，返回耗时（秒）。"""
    t0 = time.perf_counter()
    try:
        async with session.post(url, json=attack, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            await resp.read()
    except Exception:
        pass
    return time.perf_counter() - t0


async def run_phase(
    url: str,
    rate: int,
    duration: int,
    stats: LatencyStats,
) -> dict:
    """
    以固定速率 (rps) 持续 duration 秒发送攻击。

    Returns:
        dict: {rate, duration, total_sent, total_errors, avg_ms, p50_ms, p95_ms, p99_ms, max_ms}
    """
    interval = 1.0 / rate if rate > 0 else 0
    end_time = time.perf_counter() + duration
    total_sent = 0
    total_errors = 0

    async with aiohttp.ClientSession() as session:
        idx = 0
        while time.perf_counter() < end_time:
            attack = ATTACK_POOL[idx % len(ATTACK_POOL)]
            t0 = time.perf_counter()

            try:
                async with session.post(url, json=attack, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    await resp.read()
                    if resp.status >= 400:
                        total_errors += 1
            except Exception:
                total_errors += 1

            elapsed = time.perf_counter() - t0
            stats.values.append(elapsed)
            total_sent += 1
            idx += 1

            # 限速
            if interval > 0:
                sleep_time = interval - (time.perf_counter() - t0)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

    return {
        "rate": rate,
        "duration_s": duration,
        "total_sent": total_sent,
        "total_errors": total_errors,
        "avg_ms": round(stats.avg_ms, 2),
        "p50_ms": round(stats.p50_ms, 2),
        "p95_ms": round(stats.p95_ms, 2),
        "p99_ms": round(stats.p99_ms, 2),
        "max_ms": round(stats.max_ms, 2),
    }


async def burst_test(url: str, count: int):
    """瞬间爆发测试：同时发送 N 个请求。"""
    attack = ATTACK_POOL[0]
    t0 = time.perf_counter()

    async with aiohttp.ClientSession() as session:
        tasks = [send_attack(session, url, attack) for _ in range(count)]
        results = await asyncio.gather(*tasks)

    total_time = time.perf_counter() - t0
    latencies = [r for r in results]

    print(f"\n  {'='*50}")
    print(f"  爆发测试: {count} 并发请求")
    print(f"  总耗时: {total_time:.2f}s")
    print(f"  实际 RPS: {count / total_time:.0f}")
    print(f"  平均延迟: {sum(latencies)/len(latencies)*1000:.1f}ms")
    print(f"  最大延迟: {max(latencies)*1000:.1f}ms")
    print(f"  最小延迟: {min(latencies)*1000:.1f}ms")

    return {
        "mode": "burst",
        "concurrent": count,
        "total_time_s": round(total_time, 2),
        "effective_rps": round(count / total_time, 1),
        "avg_ms": round(sum(latencies) / len(latencies) * 1000, 2),
        "min_ms": round(min(latencies) * 1000, 2),
        "max_ms": round(max(latencies) * 1000, 2),
    }


async def fetch_metrics(base_url: str) -> dict:
    """拉取 DFU 监控指标。"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base_url}/api/status", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                data = await resp.json()
                return {
                    "total_alerts": data.get("left_brain", {}).get("total_alerts", 0),
                    "blacklist_count": data.get("blacklist_count", 0),
                    "validator_passed": data.get("validator", {}).get("passed", 0),
                    "validator_rejected": data.get("validator", {}).get("rejected", 0),
                }
    except Exception:
        return {}


async def main():
    parser = ArgumentParser(description="DFU 压力测试")
    parser.add_argument("--url", default="http://localhost:8000/api/attack", help="DFU API 地址")
    parser.add_argument("--rate", type=int, default=0, help="固定 RPS (0=逐步加压)")
    parser.add_argument("--duration", type=int, default=15, help="每档持续时间(秒)")
    parser.add_argument("--burst", type=int, default=0, help="爆发测试并发数")
    parser.add_argument("--output", default="", help="结果输出 JSON 文件路径")
    args = parser.parse_args()

    results = []
    base_url = args.url.rsplit("/api/", 1)[0]

    # 读取初始状态
    before = await fetch_metrics(base_url)
    logger.info(f"压测前状态: alerts={before.get('total_alerts',0)}, blacklist={before.get('blacklist_count',0)}")

    if args.burst > 0:
        # ── 爆发测试 ──
        r = await burst_test(args.url, args.burst)
        results.append(r)

    elif args.rate > 0:
        # ── 固定 RPS ──
        stats = LatencyStats()
        r = await run_phase(args.url, args.rate, args.duration, stats)
        results.append(r)
        print(f"\n  固定 {args.rate} RPS × {args.duration}s:")
        print(f"    发送: {r['total_sent']}, 错误: {r['total_errors']}")
        print(f"    平均: {r['avg_ms']}ms, P50: {r['p50_ms']}ms, P95: {r['p95_ms']}ms, P99: {r['p99_ms']}ms")

    else:
        # ── 逐步加压 ──
        phases = [10, 50, 100, 200]
        for rate in phases:
            print(f"\n  >>> 加压至 {rate} RPS，持续 {args.duration}s ...")
            stats = LatencyStats()
            r = await run_phase(args.url, rate, args.duration, stats)
            results.append(r)

            status = "✅" if r["total_errors"] == 0 else f"⚠️ {r['total_errors']} errors"
            print(f"  [{rate} RPS] 发送 {r['total_sent']} | {status}")
            print(f"    延迟: avg={r['avg_ms']}ms p50={r['p50_ms']}ms p95={r['p95_ms']}ms p99={r['p99_ms']}ms max={r['max_ms']}ms")

            # 如果错误率超过 10%，停止继续加压
            error_rate = r["total_errors"] / max(r["total_sent"], 1)
            if error_rate > 0.1:
                print(f"  ⚠️ 错误率 {error_rate:.0%}，停止加压")
                break

    # 读取最终状态
    await asyncio.sleep(2)
    after = await fetch_metrics(base_url)

    # ── 汇总 ──
    print(f"\n{'='*60}")
    print(f"压力测试汇总")
    print(f"{'='*60}")
    print(f"  测试模式: {'爆发' if args.burst else '逐步加压' if not args.rate else f'固定{args.rate}RPS'}")
    print(f"  压测前 → alerts={before.get('total_alerts',0)}, blacklist={before.get('blacklist_count',0)}")
    print(f"  压测后 → alerts={after.get('total_alerts',0)}, blacklist={after.get('blacklist_count',0)}")
    print(f"  新增告警: {after.get('total_alerts',0) - before.get('total_alerts',0)}")

    if not args.burst and len(results) > 1:
        print(f"\n  {'Rate':>6}  {'Sent':>6}  {'Avg':>8}  {'P50':>8}  {'P95':>8}  {'P99':>8}  {'Max':>8}  {'Errors':>7}")
        print(f"  {'-'*70}")
        for r in results:
            print(f"  {r['rate']:>6}  {r['total_sent']:>6}  {r['avg_ms']:>7}ms  {r['p50_ms']:>7}ms  {r['p95_ms']:>7}ms  {r['p99_ms']:>7}ms  {r['max_ms']:>7}ms  {r['total_errors']:>7}")

    # 输出结果文件
    if args.output:
        output_path = args.output
    else:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"stress_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    report = {
        "timestamp": datetime.now().isoformat(),
        "mode": "burst" if args.burst else "ramp" if not args.rate else f"fixed_{args.rate}rps",
        "before": before,
        "after": after,
        "results": results,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\n  报告已保存: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
