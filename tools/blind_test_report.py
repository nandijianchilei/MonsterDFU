"""
盲测回放与误报/漏报统计脚本
============================
输入：盲测事件 JSON + 人工标注文件（JSON）
输出：混淆矩阵（TP/FP/FN/TN）+ 精确率/召回率 + Markdown 统计报告

流程：
  1. 加载事件列表，按时间戳节奏注入 outbound_traffic 消息到总线
  2. 经 OutboundMonitor（含误报过滤层）产出 threat_alert
  3. 与人工标注逐流比对，统计混淆矩阵与精确率/召回率
  4. 生成 tools/blind_test_results/blind_test_report.md 与 .json

用法：
  python tools/blind_test_report.py \
      --events tools/blind_test_data/blind_test_events.json \
      --labels tools/blind_test_data/blind_test_labels.json
"""

import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# 控制台编码自适应（避免 Windows GBK 下中文输出报错）
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from communication.message_bus import Message, get_message_bus
from config import get_config
from organs.observer_outbound import OutboundMonitor

RESULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blind_test_results")


def load_events(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        events = json.load(f)
    if not isinstance(events, list):
        raise ValueError(f"事件文件格式错误（需为 JSON 数组）: {path}")
    return events


def load_labels(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    flows = data.get("flows", data if isinstance(data, list) else [])
    if not flows:
        raise ValueError(f"标注文件缺少 flows: {path}")
    return flows


class AlertCollector:
    """订阅 threat_alert，收集 outbound_monitor 产出的告警。"""

    def __init__(self):
        self.alerts: list = []

    async def __call__(self, msg: Message):
        payload = msg.payload or {}
        original = payload.get("original", {}) or {}
        alert = {
            "source_organ": payload.get("source_organ", msg.source),
            "dst_ip": original.get("dst_ip", payload.get("dst_ip", "")),
            "dst_port": original.get("dst_port", payload.get("dst_port", 0)),
            "category": payload.get("category", ""),
            "severity": payload.get("severity", ""),
            "description": original.get("description", payload.get("description", "")),
            "timestamp": payload.get("timestamp", time.time()),
        }
        self.alerts.append(alert)


def compute_matrix(labels: list, alerts: list) -> dict:
    """将告警与标注逐流比对，输出混淆矩阵。"""
    # 归并：dst_ip → set of categories
    alert_map: dict = {}  # (dst_ip, dst_port) → set(category)
    for a in alerts:
        key = (a["dst_ip"], a["dst_port"])
        alert_map.setdefault(key, set()).add(a["category"])

    flow_rows = []
    for lb in labels:
        dst = lb["dst_ip"]
        port = lb.get("dst_port", 0)
        cat = lb.get("category", "")
        expected = lb.get("expected", False)
        matched_alerts = [a for a in alerts if a["dst_ip"] == dst and a["dst_port"] == port]
        predicted = len(matched_alerts) > 0

        if expected and predicted:
            outcome = "TP"
        elif expected and not predicted:
            outcome = "FN"
        elif not expected and predicted:
            outcome = "FP"
        else:
            outcome = "TN"

        flow_rows.append({
            "id": lb.get("id", ""),
            "dst_ip": dst,
            "dst_port": lb.get("dst_port", 0),
            "category": cat,
            "expected": expected,
            "predicted": predicted,
            "outcome": outcome,
            "alerts": [a["description"] for a in matched_alerts],
            "note": lb.get("note", ""),
        })

    counts = {k: sum(1 for r in flow_rows if r["outcome"] == k) for k in ("TP", "FP", "FN", "TN")}
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    accuracy = (tp + tn) / max(tp + fp + fn + tn, 1)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "confusion_matrix": counts,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "accuracy": round(accuracy, 4),
        "f1": round(f1, 4),
        "flows": flow_rows,
    }


async def run_blind_test(events_path: str, labels_path: str, speed_factor: float,
                         fp_min_triggers: int) -> dict:
    """注入事件 → 收集告警 → 比对标注 → 输出矩阵。"""
    config = get_config()

    # 允许通过命令行覆盖误报过滤层阈值
    fp_cfg = dict(config.false_positive_filter or {})
    threshold = dict(fp_cfg.get("threshold") or {})
    threshold["min_triggers"] = fp_min_triggers
    fp_cfg["threshold"] = threshold
    config.false_positive_filter = fp_cfg

    bus = get_message_bus()
    collector = AlertCollector()
    await bus.subscribe("threat_alert", collector)

    monitor = OutboundMonitor(config)
    await monitor.start()

    # 加载事件并注入
    events = load_events(events_path)
    total = len(events)
    prev_ts = None
    start_wall = time.time()

    for i, ev in enumerate(events):
        ts = ev.get("timestamp", 0)

        # 按时间戳节奏等待
        if prev_ts is not None and speed_factor > 0:
            delta = (ts - prev_ts) / speed_factor
            if delta > 0:
                await asyncio.sleep(min(delta, 5.0))
        prev_ts = ts

        msg = Message(
            source="BlindTest",
            target="OutboundMonitor",
            type="outbound_traffic",
            payload=ev,
        )
        await bus.publish(msg)

    elapsed = time.time() - start_wall
    replay = {
        "total_events": total,
        "injected": total,
        "elapsed_seconds": round(elapsed, 2),
    }

    # 等待消息队列排空
    await asyncio.sleep(0.5)
    await monitor.stop()

    labels = load_labels(labels_path)
    matrix = compute_matrix(labels, collector.alerts)

    return {
        "params": {
            "events": os.path.abspath(events_path),
            "labels": os.path.abspath(labels_path),
            "speed_factor": speed_factor,
            "fp_min_triggers": fp_min_triggers,
        },
        "replay": replay,
        "monitor_stats": dict(monitor.stats),
        "fp_filter_stats": dict(monitor.fp_filter.stats),
        "alerts": collector.alerts,
        **matrix,
    }


def render_markdown(result: dict) -> str:
    cm = result["confusion_matrix"]
    lines = []
    lines.append("# 真实流量盲测报告")
    lines.append("")
    lines.append(f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 事件文件: `{result['params']['events']}`")
    lines.append(f"- 标注文件: `{result['params']['labels']}`")
    lines.append(f"- 回放速度: {result['params']['speed_factor']}x")
    lines.append(f"- 误报过滤阈值 min_triggers: {result['params']['fp_min_triggers']}")
    lines.append("")
    lines.append("## 回放统计")
    lines.append("")
    lines.append(f"- 总事件数: {result['replay']['total_events']}")
    lines.append(f"- 已注入: {result['replay']['injected']}")
    lines.append(f"- 耗时: {result['replay']['elapsed_seconds']:.1f}s")
    lines.append(f"- 检测器告警数: {len(result['alerts'])}")
    fp = result['fp_filter_stats']
    lines.append(f"- 误报过滤层: 评估 {fp.get('total_evaluated', 0)} 次, "
                 f"白名单抑制 {fp.get('whitelist_suppressed', 0)}, "
                 f"阈值抑制 {fp.get('threshold_suppressed', 0)}, "
                 f"LLM 抑制 {fp.get('llm_suppressed', 0)}, "
                 f"放行 {fp.get('alerts_passed', 0)}")
    lines.append("")
    lines.append("## 混淆矩阵")
    lines.append("")
    lines.append("|  | 实际告警（标注） | 实际静默（标注） |")
    lines.append("|---|---|---|")
    lines.append(f"| **系统告警** | TP = {cm['TP']} | FP = {cm['FP']} |")
    lines.append(f"| **系统静默** | FN = {cm['FN']} | TN = {cm['TN']} |")
    lines.append("")
    lines.append("## 指标")
    lines.append("")
    lines.append(f"- 精确率 Precision = {result['precision']:.2%}")
    lines.append(f"- 召回率 Recall = {result['recall']:.2%}")
    lines.append(f"- 准确率 Accuracy = {result['accuracy']:.2%}")
    lines.append(f"- F1 = {result['f1']:.2%}")
    lines.append("")
    lines.append("## 逐流明细")
    lines.append("")
    lines.append("| 流ID | 目标IP | 端口 | 类别 | 标注 | 系统 | 判定 | 告警描述 |")
    lines.append("|------|--------|------|------|------|------|------|----------|")
    for r in result["flows"]:
        predicted = "告警" if r["predicted"] else "静默"
        expected = "告警" if r["expected"] else "静默"
        desc = "; ".join(r["alerts"]) if r["alerts"] else "-"
        lines.append(f"| {r['id']} | {r['dst_ip']} | {r['dst_port']} | {r['category']} | {expected} | {predicted} | {r['outcome']} | {desc} |")
    lines.append("")
    lines.append("## 告警明细")
    lines.append("")
    if result["alerts"]:
        lines.append("| 来源 | 目标IP | 端口 | 类别 | 严重度 | 描述 |")
        lines.append("|------|--------|------|------|--------|------|")
        for a in result["alerts"]:
            lines.append(f"| {a['source_organ']} | {a['dst_ip']} | {a['dst_port']} | {a['category']} | {a['severity']} | {a['description']} |")
    else:
        lines.append("*无告警*")
    return "\n".join(lines)


async def main():
    parser = argparse.ArgumentParser(description="盲测回放与统计")
    parser.add_argument("--events", required=True, help="盲测事件 JSON 文件路径")
    parser.add_argument("--labels", required=True, help="人工标注 JSON 文件路径")
    parser.add_argument("--speed", type=float, default=100.0, help="回放速度倍率（默认 100x）")
    parser.add_argument("--fp-min-triggers", type=int, default=1,
                        help="误报过滤层最小触发次数（盲测默认 1，即不压制）")
    args = parser.parse_args()

    os.makedirs(RESULT_DIR, exist_ok=True)

    result = await run_blind_test(args.events, args.labels, args.speed, args.fp_min_triggers)

    md_path = os.path.join(RESULT_DIR, "blind_test_report.md")
    json_path = os.path.join(RESULT_DIR, "blind_test_report.json")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(result))
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"[盲测报告] MD:  {md_path}")
    print(f"[盲测报告] JSON: {json_path}")
    print()
    cm = result["confusion_matrix"]
    print(f"[混淆矩阵] TP={cm['TP']} FP={cm['FP']} FN={cm['FN']} TN={cm['TN']}")
    print(f"[指标] Precision={result['precision']:.2%} Recall={result['recall']:.2%} F1={result['f1']:.2%}")


if __name__ == "__main__":
    asyncio.run(main())
