#!/usr/bin/env python3
"""DFU CLI - 分布式AI防御单元命令行工具."""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


def _get_project_root() -> Path:
    """返回项目根目录（cli.py 所在目录）。"""
    return Path(__file__).resolve().parent


def _print_banner():
    print(
        r"""
   ____  _____ _   _   ____  _   _ _____ ____
  |  _ \|  ___| | | | |  _ \| | | |_   _|  _ \
  | | | | |_  | | | | | |_) | | | | | | | |_) |
  | |_| |  _| | |_| | |  __/| |_| | | | |  __/
  |____/|_|    \___/  |_|    \___/  |_| |_|

  Distributed AI Fighting Unit - Autonomous Defense System
"""
    )


def _check_npcap() -> bool:
    """检查 Npcap 是否已安装，未安装则给出友好提示。"""
    npcap_paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
    ]
    if sys.platform != "win32":
        return True  # 非 Windows 不检查

    for p in npcap_paths:
        if os.path.isdir(p):
            return True

    print("\n[!] 未检测到 Npcap，实时抓包功能将无法使用。")
    print("[!] 请从 https://npcap.com 下载并安装 Npcap。")
    print("    安装时请勾选 \"Install Npcap in WinPcap API-compatible Mode\"。\n")
    return False


def cmd_start(args):
    """一键启动全栈服务（Web + 核心引擎 + 实时抓包）。"""
    _print_banner()
    root = _get_project_root()
    web_server_py = root / "web_server.py"

    if not web_server_py.exists():
        print(f"[!] 未找到 {web_server_py}")
        sys.exit(1)

    # 检查 Npcap（Windows 下抓包依赖）
    npcap_ok = _check_npcap()

    print("[*] 正在启动 DFU 防御系统全栈...")
    print("[*]  Web 管理面板:    http://localhost:8000")
    print("[*]  Live Demo 大屏:  http://localhost:8000/live")
    print("[*]  对比演示页:      http://localhost:8000/compare")
    if npcap_ok:
        print("[*]  实时抓包:        已就绪 (Npcap)")
    else:
        print("[*]  实时抓包:        已禁用 (Npcap 未安装，仅模拟流量可用)")
    print("[*] 按 Ctrl+C 优雅退出\n")

    env = os.environ.copy()
    env.setdefault("DFU_LLM_MOCK_MODE", "true")

    proc = subprocess.Popen(
        [sys.executable, str(web_server_py)],
        cwd=str(root),
        env=env,
    )

    def _signal_handler(sig, frame):
        print("\n[*] 正在关闭 DFU 防御系统...")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[*] 已停止")
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    proc.wait()


def cmd_demo(args):
    """启动演示模式并打开 Live Demo 页面。"""
    _print_banner()
    root = _get_project_root()
    main_py = root / "main.py"

    if not main_py.exists():
        print(f"[!] 未找到 {main_py}")
        sys.exit(1)

    print("[*] 正在启动 DFU 演示模式...\n")

    proc = subprocess.Popen(
        [sys.executable, str(main_py)],
        cwd=str(root),
    )

    # 等待服务启动
    print("[*] 等待服务启动...")
    for i in range(30):
        time.sleep(1)
        try:
            import urllib.request

            req = urllib.request.Request(
                "http://localhost:8000/", method="HEAD"
            )
            urllib.request.urlopen(req, timeout=2)
            print("[+] 服务已就绪")
            break
        except Exception:
            if i == 29:
                print("[!] 服务启动超时，请手动检查")
    else:
        proc.terminate()
        return

    # 打开浏览器
    webbrowser.open("http://localhost:8000/live")
    print("[+] 浏览器已打开 http://localhost:8000/live")

    # 如果带 --attack 标志，注入攻击场景
    if args.attack:
        print("[*] 攻击模式已启用，正在循环注入攻击场景...")
        attack_script = root / "tools" / "inject_attack.py"
        if attack_script.exists():
            subprocess.Popen(
                [sys.executable, str(attack_script), "--loop"],
                cwd=str(root),
            )
            print("[+] 攻击注入进程已启动")
        else:
            # 兜底：直接通过 HTTP 注入演示攻击
            print("[*] 工具脚本未找到，通过 HTTP 注入演示攻击...")
            subprocess.Popen(
                [sys.executable, "-c", """
import json, urllib.request, time, random

ATTACKS = [
    {"type": "port_scan", "src_ip": "10.0.0.1", "dst_port": 22, "severity": 0.7},
    {"type": "ddos_syn", "src_ip": "10.0.0.2", "dst_port": 80, "severity": 0.9},
    {"type": "bruteforce", "src_ip": "10.0.0.3", "dst_port": 443, "severity": 0.8},
    {"type": "data_exfil", "src_ip": "10.0.0.4", "dst_port": 53, "severity": 0.85},
    {"type": "malware_beacon", "src_ip": "10.0.0.5", "dst_port": 8080, "severity": 0.75},
]

while True:
    attack = random.choice(ATTACKS)
    try:
        req = urllib.request.Request(
            "http://localhost:8000/api/inject",
            data=json.dumps(attack).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass
    time.sleep(random.uniform(3, 8))
"""],
                cwd=str(root),
            )

    # 保持前台
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[*] 正在关闭演示...")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[*] 演示已停止")


def cmd_status(args):
    """查看当前服务运行状态。"""
    root = _get_project_root()
    print("[*] DFU 防御系统状态检查\n")

    # 检查 main.py 进程
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess, sys; "
                    "r = subprocess.run(['tasklist', '/NH', '/FO', 'CSV'], "
                    "capture_output=True, text=True); "
                    "cnt = r.stdout.count('python.exe'); "
                    "print(f'Python 进程数: {{cnt}}')"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        print(f"  {result.stdout.strip()}")
    except Exception:
        pass

    # 检查服务端口
    print("  服务端口 (8000): ", end="", flush=True)
    try:
        import urllib.request

        req = urllib.request.Request(
            "http://localhost:8000/", method="HEAD"
        )
        resp = urllib.request.urlopen(req, timeout=3)
        print(f"[运行中] HTTP {resp.status}")
    except Exception as e:
        print(f"[未运行] ({type(e).__name__})")

    # 项目信息
    print(f"\n  项目根目录: {root}")
    print(f"  Python 版本: {sys.version.split()[0]}")

    # 检查关键文件
    key_files = [
        "main.py",
        "web_server.py",
        "config.py",
        "core/brain_left.py",
        "core/brain_right.py",
    ]
    print("\n  关键文件检查:")
    for f in key_files:
        path = root / f
        status = "[✓]" if path.exists() else "[✗]"
        print(f"    {status} {f}")

    print()


def cmd_bench(args):
    """运行基准评测。"""
    _print_banner()
    root = _get_project_root()
    bench_script = root / "benchmarks" / "run_benchmark.py"

    if not bench_script.exists():
        print(f"[!] 未找到基准评测脚本: {bench_script}")
        sys.exit(1)

    print("[*] 正在运行 DFU 基准评测...\n")

    proc = subprocess.Popen(
        [sys.executable, "-u", str(bench_script)],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    # 实时打印输出
    for line in iter(proc.stdout.readline, ""):
        print(line, end="", flush=True)

    proc.wait()
    if proc.returncode == 0:
        print("\n[+] 基准评测完成")
    else:
        print(f"\n[!] 基准评测异常退出 (code={proc.returncode})")


def cmd_install(args):
    """检查并安装依赖。"""
    _print_banner()
    print("[*] 环境依赖检查\n")

    all_ok = True

    # Python
    print(f"  Python    : {sys.version.split()[0]}", end="")
    if sys.version_info >= (3, 10):
        print(" [✓]")
    else:
        print(" [✗] 需要 >= 3.10")
        all_ok = False

    # Node.js
    node_ok = shutil.which("node") is not None
    npm_ok = shutil.which("npm") is not None
    if node_ok and npm_ok:
        node_ver = subprocess.run(
            ["node", "--version"], capture_output=True, text=True
        ).stdout.strip()
        print(f"  Node.js   : {node_ver} [✓]")
    else:
        print("  Node.js   : [✗] 未安装 (部分前端工具需要)")
        all_ok = False

    # Npcap / WinPcap
    npcap_paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
    ]
    npcap_found = any(os.path.isdir(p) for p in npcap_paths)
    if npcap_found:
        print("  Npcap     : [✓] (Scapy 抓包需要)")
    else:
        print("  Npcap     : [✗] 未安装 (Scapy 抓包需要)")
        print("             请从 https://npcap.com 下载安装")
        all_ok = False

    # Docker
    docker_ok = shutil.which("docker") is not None
    if docker_ok:
        docker_ver = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True
        ).stdout.strip()
        print(f"  Docker    : {docker_ver} [✓]")
    else:
        print("  Docker    : [✗] 未安装 (容器化部署需要)")
        all_ok = False

    # Python 依赖
    print("\n[*] Python 依赖检查...")
    req_file = _get_project_root() / "requirements.txt"
    if req_file.exists():
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "list",
                "--format=columns",
            ],
            capture_output=True,
            text=True,
        )
        installed = result.stdout.lower()

        with open(req_file, encoding="utf-8") as f:
            missing = []
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg_name = line.split(">=")[0].split("==")[0].strip().lower()
                if pkg_name not in installed:
                    missing.append(line)

        if missing:
            print(f"  [!] {len(missing)} 个依赖缺失:")
            for dep in missing:
                print(f"      - {dep}")
            print("\n  运行以下命令安装:")
            print(f"      pip install -r {req_file}")
            all_ok = False
        else:
            print("  [✓] 全部依赖已安装")

    if all_ok:
        print("\n[+] 环境检查全部通过！")
    else:
        print("\n[!] 部分依赖缺失，请按提示安装")


def main():
    parser = argparse.ArgumentParser(
        prog="dfu",
        description="DFU - 分布式AI防御单元命令行工具",
    )
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # start
    subparsers.add_parser("start", help="一键启动全部服务")

    # demo
    demo_parser = subparsers.add_parser(
        "demo", help="启动演示模式"
    )
    demo_parser.add_argument(
        "--attack",
        action="store_true",
        help="自动循环注入攻击场景",
    )

    # status
    subparsers.add_parser("status", help="查看服务运行状态")

    # bench
    subparsers.add_parser("bench", help="运行基准评测")

    # install
    subparsers.add_parser("install", help="检查并安装依赖")

    args = parser.parse_args()

    if args.command == "start":
        cmd_start(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "bench":
        cmd_bench(args)
    elif args.command == "install":
        cmd_install(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
