"""
DFU 全局错误处理
==============
统一异常处理、优雅降级、自愈辅助。
"""

import asyncio
import functools
import traceback
import logging

from utils.logging_config import get_logger

logger = get_logger("error_handler")


class DFUError(Exception):
    """DFU 基础异常"""
    def __init__(self, message: str, component: str = "unknown", recoverable: bool = True):
        self.message = message
        self.component = component
        self.recoverable = recoverable
        super().__init__(f"[{component}] {message}")


class ConfigError(DFUError):
    """配置错误"""
    def __init__(self, message: str):
        super().__init__(message, component="config", recoverable=True)


class ComponentError(DFUError):
    """组件运行时错误"""
    def __init__(self, message: str, component: str, recoverable: bool = True):
        super().__init__(message, component=component, recoverable=recoverable)


def catch_all(func):
    """
    异步函数全局异常捕获装饰器。
    捕获所有未处理的异常，记录完整堆栈，不阻塞主流程。
    """
    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                f"Unhandled error in {func.__name__}: {e}",
                exc_info=True
            )
            return None

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(
                f"Unhandled error in {func.__name__}: {e}",
                exc_info=True
            )
            return None

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    return sync_wrapper


async def safe_call(func, *args, fallback_return=None, **kwargs):
    """
    安全调用：执行函数，失败时返回 fallback 值并记录错误。

    使用方式：
        result = await safe_call(some_async_func, arg1, fallback_return=[])
    """
    try:
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        return func(*args, **kwargs)
    except Exception as e:
        logger.warning(f"safe_call {func.__name__} failed: {e}")
        return fallback_return


class GracefulShutdown:
    """
    优雅关闭管理器。
    注册多个组件的关闭回调，在收到关闭信号时按顺序执行。
    """

    def __init__(self):
        self._shutdown_hooks: list[tuple[str, callable]] = []
        self._shutting_down = False

    def register(self, name: str, hook: callable):
        """注册关闭回调"""
        self._shutdown_hooks.append((name, hook))

    async def shutdown(self, signum=None):
        """执行全部关闭回调"""
        if self._shutting_down:
            return
        self._shutting_down = True
        logger.info(f"Shutting down ({len(self._shutdown_hooks)} hooks)...")
        for name, hook in reversed(self._shutdown_hooks):
            try:
                if asyncio.iscoroutinefunction(hook):
                    await hook()
                else:
                    hook()
                logger.info(f"  ✓ {name} shutdown")
            except Exception as e:
                logger.warning(f"  ✗ {name} shutdown error: {e}")
        logger.info("Shutdown complete.")


# 全局优雅关闭管理器实例
graceful_shutdown = GracefulShutdown()
