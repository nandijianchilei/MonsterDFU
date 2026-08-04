"""
攻击 pcap 生成器 — 生成包含多种攻击模式的训练/测试流量

输出: 同步攻击 + 端口扫描 + SSH 爆破 三合一流量的 pcap 文件
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

try:
    from scapy.all import *
except ImportError:
    print("scapy 未安装，正在安装...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import *

OUTPUT_DIR = os.environ.get("PCAP_OUTPUT", os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "attack_traffic.pcap")

print(f"[Scapy] 生成攻击 pcap: {OUTPUT_FILE}")

pkts = []

# ── 1. SYN Flood (50 packets, 10 source IPs) ──
print("[1/3] SYN Flood: 50 packets, 10 source IPs")
target_ip = "192.168.1.100"
target_port = 80
src_ips = [f"10.0.{i//254}.{i%254+1}" for i in range(10)]

for i in range(50):
    src = src_ips[i % len(src_ips)]
    sport = random.randint(1024, 65535)
    seq = random.randint(1, 2**32 - 1)
    pkts.append(
        IP(src=src, dst=target_ip) /
        TCP(sport=sport, dport=target_port, flags="S", seq=seq)
    )

# ── 2. 端口扫描 (30 ports) ──
print("[2/3] Port scan: 30 ports on 192.168.1.100")
scan_src = "10.0.5.99"
for dport in range(1, 31):
    sport = random.randint(1024, 65535)
    pkts.append(
        IP(src=scan_src, dst=target_ip) /
        TCP(sport=sport, dport=dport, flags="S")
    )

# ── 3. SSH 暴力破解 (3 connections × 20 attempts) ──
print("[3/3] SSH brute force: 3 source IPs × 20 attempts each")
ssh_port = 22
for src_idx in range(3):
    src = f"10.0.{100 + src_idx}.50"
    for attempt in range(20):
        sport = random.randint(1024, 65535)
        seq = random.randint(1, 2**32 - 1)
        # SYN
        pkts.append(
            IP(src=src, dst=target_ip) /
            TCP(sport=sport, dport=ssh_port, flags="S", seq=seq)
        )
        # SYN-ACK (simulated server)
        pkts.append(
            IP(src=target_ip, dst=src) /
            TCP(sport=ssh_port, dport=sport, flags="SA", seq=random.randint(1, 2**32 - 1), ack=seq + 1)
        )
        # ACK from attacker
        pkts.append(
            IP(src=src, dst=target_ip) /
            TCP(sport=sport, dport=ssh_port, flags="A", seq=seq + 1, ack=seq + 1)
        )

# ── 4. 正常流量 (background noise) ──
print("[4/4] Normal traffic: 30 packets")
for _ in range(30):
    src = f"10.0.{random.randint(1, 200)}.{random.randint(1, 254)}"
    dst = f"192.168.1.{random.randint(1, 50)}"
    sport = random.randint(1024, 65535)
    dport = random.choice([80, 443, 8080, 53])
    pkts.append(
        IP(src=src, dst=dst) /
        TCP(sport=sport, dport=dport, flags="PA", seq=random.randint(1, 2**32 - 1))
    )

print(f"\n总数据包: {len(pkts)}")
wrpcap(OUTPUT_FILE, pkts)
print(f"已生成: {OUTPUT_FILE}")
