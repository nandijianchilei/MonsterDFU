"""
DFU 防御系统 — 桌面版启动器

将原浏览器 Web 版改造为独立 Windows 桌面软件：
  - 内部启动 FastAPI 服务（uvicorn，仅绑定 127.0.0.1 回环，不暴露局域网）
  - 用 pywebview 创建原生桌面窗口加载管理面板（/monster），不调用系统浏览器
  - 关闭窗口即优雅停止服务并退出进程

启动方式：
    python desktop_launcher.py                  # 默认端口 8000（占用时自动顺延）
    python desktop_launcher.py --port 9000      # 指定端口
    python desktop_launcher.py --no-window      # 仅启动服务不弹窗（调试用）
    python desktop_launcher.py --auto-close-after 30  # 30 秒后自动关窗（验收用）
"""

import argparse
import logging
import os
import socket
import sys
import threading
import time
import urllib.request

# 控制台中文乱码修复：强制 stdout/stderr 使用 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
# PyInstaller 打包后，资源文件位于 _MEIPASS 解压目录
_MEIPASS = getattr(sys, "_MEIPASS", None)
if _MEIPASS:
    PROJECT_ROOT = _MEIPASS
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# 日志目录：打包后写 exe 同目录，开发时写项目 logs/ 目录
if getattr(sys, "frozen", False):
    LOG_DIR = os.path.dirname(sys.executable)
else:
    LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "desktop_launcher.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("desktop_launcher")

try:
    import web_server  # noqa: F401  保留 FastAPI 全部 40+ API / token 认证 / 事件桥接
    import uvicorn
except ImportError as e:
    logger.error("缺少依赖，请先执行: pip install fastapi uvicorn httpx (%s)", e)
    sys.exit(1)

try:
    import webview
except ImportError:
    logger.error("缺少依赖 pywebview，请先执行: pip install pywebview")
    sys.exit(1)

HOST = "127.0.0.1"


def find_free_port(preferred: int = 8000, max_try: int = 10) -> int:
    """优先使用 preferred 端口；被占用则顺延尝试；全部占用时使用系统随机空闲端口。"""
    for port in range(preferred, preferred + max_try):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def wait_server_ready(server_thread, port: str, timeout: float = 90.0) -> bool:
    """轮询 /healthz 直到服务就绪；返回是否就绪。"""
    deadline = time.time() + timeout
    url = f"http://{HOST}:{port}/healthz"
    while time.time() < deadline:
        if server_thread.failed.is_set():
            return False
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


class UvicornServerThread(threading.Thread):
    """在后台线程运行 uvicorn.Server，支持通过 should_exit 优雅停止（触发 lifespan shutdown）。"""

    def __init__(self, app, host: str, port: int):
        super().__init__(daemon=True, name="uvicorn-server")
        self.config = uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="on")
        self.server = uvicorn.Server(self.config)
        self.failed = threading.Event()

    def run(self):
        try:
            self.server.run()
        except Exception as e:
            logger.error("DFU 服务启动失败: %s", e)
            self.failed.set()

    def stop(self, timeout: float = 15.0):
        self.server.should_exit = True
        self.join(timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description="DFU 防御系统 桌面版")
    parser.add_argument("--port", type=int, default=8000, help="服务端口（默认 8000，占用时自动顺延）")
    parser.add_argument("--no-window", action="store_true", help="仅启动服务不弹窗（调试用）")
    parser.add_argument("--auto-close-after", type=int, default=0, help="N 秒后自动关闭窗口（验收用）")
    args = parser.parse_args()

    port = find_free_port(args.port)
    url = f"http://{HOST}:{port}/monster"

    # 1. 后台启动 FastAPI 服务（仅 127.0.0.1）
    server_thread = UvicornServerThread(web_server.app, HOST, port)
    server_thread.start()
    logger.info("DFU 服务启动中: http://%s:%s (仅本机回环)", HOST, port)

    # 2. 等待服务就绪
    if not wait_server_ready(server_thread, str(port)):
        if server_thread.failed.is_set():
            logger.error("DFU 服务启动失败，详见日志: %s", LOG_FILE)
        else:
            logger.error("DFU 服务启动超时（%d 秒），详见日志: %s", 90, LOG_FILE)
        server_thread.stop()
        sys.exit(1)
    logger.info("DFU 服务已就绪: http://%s:%s", HOST, port)

    print(f"\n  DFU 防御系统 桌面版")
    print(f"  管理面板: {url}")
    print(f"  服务仅绑定 127.0.0.1（本机回环）")
    print(f"  关闭窗口即退出进程\n")

    # 3. 仅服务模式（调试）
    if args.no_window:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("收到 Ctrl+C，正在停止服务...")
        finally:
            server_thread.stop()
        return

    # 4. 创建原生桌面窗口（pywebview，不调用系统浏览器）
    window = webview.create_window(
        "DFU 防御系统",
        url,
        width=1400,
        height=900,
        min_size=(1000, 700),
        background_color="#0b1020",
    )

    def on_closed():
        logger.info("桌面窗口已关闭，正在优雅停止服务...")
        server_thread.stop()

    def on_loaded():
        logger.info("管理面板页面加载完成: %s", url)

    window.events.closed += on_closed
    window.events.loaded += on_loaded
    logger.info("桌面窗口已创建: %s", url)

    # 验收用：N 秒后自动关闭窗口，验证“关窗即退出”链路
    if args.auto_close_after > 0:
        def _auto_close():
            time.sleep(args.auto_close_after)
            logger.info("自动关窗计时到（%d 秒），模拟用户关闭窗口", args.auto_close_after)
            try:
                window.destroy()
            except Exception as e:
                logger.warning("自动关闭窗口失败: %s", e)
        threading.Thread(target=_auto_close, daemon=True).start()

    # 阻塞直到窗口关闭（pywebview 主线程消息循环）
    webview.start(debug=False)

    # 5. 窗口关闭后等待服务线程退出（lifespan shutdown 会停止全部 Agent）
    server_thread.stop()
    logger.info("服务已停止，进程退出")
    print("DFU 防御系统已退出")


if __name__ == "__main__":
    main()
