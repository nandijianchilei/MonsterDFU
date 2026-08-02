"""
日志工具模块
统一日志格式：[时间] [Agent名] [级别] 消息
同时输出到控制台和文件。
"""

import logging
import logging.handlers
import os
from datetime import datetime
from typing import Optional


class DFULogger:
    """统一日志管理器，封装 Python logging 模块。"""

    _instance: Optional["DFULogger"] = None
    _loggers: dict = {}

    def __new__(cls, log_dir: str = ""):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, log_dir: str = ""):
        if self._initialized:
            return
        self._initialized = True
        self._log_dir = log_dir
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def _build_formatter(self) -> logging.Formatter:
        """构建统一日志格式器。"""
        fmt = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
        return logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    def get_logger(self, agent_name: str) -> logging.Logger:
        """
        获取指定 Agent 的日志器。

        Args:
            agent_name: Agent 名称（如 'TrafficMonitor', 'LeftBrain'）

        Returns:
            配置好的 Logger 实例
        """
        if agent_name in self._loggers:
            return self._loggers[agent_name]

        logger = logging.getLogger(agent_name)
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()

        formatter = self._build_formatter()

        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # 文件处理器（若配置了日志目录）
        if self._log_dir:
            date_str = datetime.now().strftime("%Y%m%d")
            log_file = os.path.join(self._log_dir, f"{agent_name}_{date_str}.log")
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        self._loggers[agent_name] = logger
        return logger


# 便捷函数：延迟初始化全局日志管理器
_global_logger: Optional[DFULogger] = None


def init_global_logger(log_dir: str) -> DFULogger:
    """初始化全局日志管理器。"""
    global _global_logger
    if _global_logger is None:
        _global_logger = DFULogger(log_dir)
    else:
        # 如果已经初始化过（但可能是空 log_dir），补充设置
        if not _global_logger._log_dir and log_dir:
            _global_logger._log_dir = log_dir
            os.makedirs(log_dir, exist_ok=True)
            # 为已存在的 logger 补充文件处理器
            formatter = _global_logger._build_formatter()
            date_str = datetime.now().strftime("%Y%m%d")
            for agent_name, logger in _global_logger._loggers.items():
                has_file = any(isinstance(h, logging.FileHandler) for h in logger.handlers)
                if not has_file:
                    log_file = os.path.join(log_dir, f"{agent_name}_{date_str}.log")
                    fh = logging.FileHandler(log_file, encoding="utf-8")
                    fh.setLevel(logging.DEBUG)
                    fh.setFormatter(formatter)
                    logger.addHandler(fh)
    return _global_logger


def get_logger(agent_name: str) -> logging.Logger:
    """获取全局日志器（若未初始化则使用默认配置）。"""
    global _global_logger
    if _global_logger is None:
        _global_logger = DFULogger("")
    return _global_logger.get_logger(agent_name)
