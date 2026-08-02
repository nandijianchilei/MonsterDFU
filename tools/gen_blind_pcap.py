"""
盲测数据生成器 — 生成真实流量盲测用的事件 JSON 与人工标注文件。

输出（tools/blind_test_data/ 目录）：
  - blind_test_events.json   出站流量事件列表（直接注入消息总线回放）
  - blind_test_labels.json    人工标注（ground truth）

4 条流量：
  f1  C2 信标：203.0.113.10:4444 周期性小包（应检出 beacon）
  f2  数据外泄：203.0.113.20:443 大包（应检出 exfiltration）
  f3  正常 CDN：104.16.0.1:443   普通 HTTPS（不应告警）
  f4  正常外站：8.8.8.8:443      少量 HTTPS（不应告警）

用法：
  python tools/gen_blind_pcap.py
"""

import json
import os
import sys
import time

# 控制台编码自适应（避免 Windows GBK 下中文输出报错）
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blind_test_data")
os.makedirs(DATA_DIR, exist_ok=True)

EVENTS_PATH = os.path.join(DATA_DIR, "blind_test_events.json")
LABELS_PATH = os.path.join(DATA_DIR, "blind_test_labels.json")

SRC_IP = "192.168.1.10"
BASE_TS = time.time()


def make_event(dst_ip: str, dport: int, size: int, ts: float) -> dict:
    """构造一条 outbound_traffic 事件（与 PacketCapture._packet_handler 输出一致）。"""
    return {
        "dst_ip": dst_ip,
        "dst_port": dport,
        "size": size,
        "timestamp": ts,
        "protocol": "TCP",
    }


def build():
    events = []
    labels = []

    # f1: C2 信标 — 8 个小包，每 2 秒一次（周期性强）
    f1_dst, f1_port = "203.0.113.10", 4444
    for i in range(8):
        events.append(make_event(f1_dst, f1_port, 120, BASE_TS + i * 2.0))
    labels.append({
        "id": "f1",
        "dst_ip": f1_dst,
        "dst_port": f1_port,
        "category": "beacon",
        "expected": True,
        "note": "C2 信标回连（周期小包）",
    })

    # f2: 数据外泄 — 18 个大包（每包 60KB，累计 1.08MB 超窗口阈值 1MB）
    f2_dst, f2_port = "203.0.113.20", 443
    for i in range(18):
        events.append(make_event(f2_dst, f2_port, 60 * 1024, BASE_TS + 10 + i * 1.0))
    labels.append({
        "id": "f2",
        "dst_ip": f2_dst,
        "dst_port": f2_port,
        "category": "exfiltration",
        "expected": True,
        "note": "窗口累计大流量外泄（18×60KB≈1.08MB，60s 窗口阈值 1MB）",
    })

    # f3: 正常 CDN（Cloudflare 网段，白名单）— 5 个普通 HTTPS 小包
    f3_dst, f3_port = "104.16.0.1", 443
    for i in range(5):
        events.append(make_event(f3_dst, f3_port, 900, BASE_TS + 20 + i * 3.0))
    labels.append({
        "id": "f3",
        "dst_ip": f3_dst,
        "dst_port": f3_port,
        "category": "clean",
        "expected": False,
        "note": "正常 CDN HTTPS",
    })

    # f4: 正常外站 — 2 个 HTTPS 小包
    f4_dst, f4_port = "8.8.8.8", 443
    for i in range(2):
        events.append(make_event(f4_dst, f4_port, 700, BASE_TS + 30 + i * 5.0))
    labels.append({
        "id": "f4",
        "dst_ip": f4_dst,
        "dst_port": f4_port,
        "category": "clean",
        "expected": False,
        "note": "正常外部 HTTPS",
    })

    with open(EVENTS_PATH, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, indent=2)
    with open(LABELS_PATH, "w", encoding="utf-8") as f:
        json.dump({"flows": labels}, f, ensure_ascii=False, indent=2)

    print(f"[盲测数据] 事件: {EVENTS_PATH} ({len(events)} 条)")
    print(f"[盲测数据] 标注: {LABELS_PATH} ({len(labels)} 条流)")
    for lb in labels:
        mark = "应告警" if lb["expected"] else "应静默"
        print(f"  - {lb['id']}: {lb['dst_ip']}:{lb['dst_port']} {lb['category']:12s} {mark} | {lb['note']}")


if __name__ == "__main__":
    build()
