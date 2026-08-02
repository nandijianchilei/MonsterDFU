"""
DFU 标准化日志系统
=================
从 config 读取配置，支持文件轮转 + 彩色控制台双输出。

使用方式：
    from utils.logging_config import get_logger
    logger = get_logger("capturer")
    logger.info("started")
    logger.error("failed", exc_info=True)
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dfuconfig import config


# 控制台颜色（仅在终端支持时启用）
_RESET = "\033[0m"
_COLORS = {
    "DEBUG": "\033[36m",     # 青色
    "INFO": "\033[32m",      # 绿色
    "WARNING": "\033[33m",   # 黄色
    "ERROR": "\033[31m",     # 红色
    "CRITICAL": "\033[1;31m", # 粗体红色
}


class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""

    def format(self, record):
        level_name = record.levelname
        color = _COLORS.get(level_name, "")
        record.levelname = f"{color}{level_name}{_RESET}"
        return super().format(record)


class JsonFormatter(logging.Formatter):
    """JSON 格式日志（生产环境）"""

    def format(self, record):
        import json
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    """
    获取已配置的 logger 实例。
    如果该 logger 已初始化则直接返回，避免重复添加 handler。
    """
    logger = logging.getLogger(name)

    # 如果已经初始化过（有 handler），直接返回
    if logger.handlers:
        return logger

    log_config = config.get("logging", default={})
    level = getattr(logging, log_config.get("level", "INFO").upper(), logging.INFO)
    log_format = log_config.get("format", "%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    log_file = log_config.get("file", "logs/dfu.log")
    max_size = log_config.get("max_size_mb", 100) * 1024 * 1024
    backup_count = log_config.get("backup_count", 5)
    json_output = log_config.get("json_output", False)

    logger.setLevel(level)

    # 确保日志目录存在
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # 文件 handler（带轮转）
    file_formatter = JsonFormatter() if json_output else logging.Formatter(log_format)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=max_size, backupCount=backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # 控制台 handler（带颜色，仅 stdout）
    if is_color_supported():
        console_formatter = ColoredFormatter(log_format)
    else:
        console_formatter = logging.Formatter(log_format)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger


def is_color_supported() -> bool:
    """判断终端是否支持颜色输出"""
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # Windows 10+ 支持 ANSI 颜色（需开启 VT 模式）
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 0x0004 | 0x0001 | 0x0002)
            return True
        except Exception:
            return False
    return True
