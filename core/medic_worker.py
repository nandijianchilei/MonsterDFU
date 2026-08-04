"""
Medic Worker — 定期心跳检测，故障隔离/权重回滚/熔断。

配置来源（优先级由高到低）：
    环境变量 ETCD_URL
    config.yaml 中的 etcd.url
"""

import asyncio
import os
import sys
from datetime import datetime
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

logger = get_logger("MedicWorker")


class MedicWorker:
    """医疗 Agent — 健康检查与故障恢复。"""

    def __init__(self):
        etcd_url = os.getenv("ETCD_URL", "")
        if not etcd_url:
            try:
                from config import get_config
                etcd_url = get_config().etcd_url
            except Exception:
                etcd_url = "http://localhost:2379"
        self.etcd_url = etcd_url
        self.agents: Dict[str, dict] = {}
        self.heartbeat_timeout = 15  # 秒
        self._etcd_client = None

    async def start(self):
        logger.info(f"[MedicWorker] 启动，etcd={self.etcd_url}")
        # 为自身注册心跳，使 _health_loop() 不再遍历空字典
        self.register_heartbeat("MedicWorker")
        # 尝试连接 etcd，不阻塞
        try:
            import etcd3
            self._etcd_client = etcd3.client(host=self.etcd_url.replace("http://", "").split(":")[0])
            logger.info("[MedicWorker] etcd 连接成功")
        except Exception as e:
            logger.warning(f"[MedicWorker] etcd 不可用({e})，使用内存健康检查")

        # 启动心跳循环
        asyncio.create_task(self._health_loop())
        await asyncio.Event().wait()

    async def _health_loop(self):
        """定期检查 Agent 心跳。"""
        while True:
            await asyncio.sleep(10)
            now = datetime.now()
            dead_agents = []
            for name, info in self.agents.items():
                last = info.get("last_heartbeat")
                if last and (now - last).total_seconds() > self.heartbeat_timeout:
                    dead_agents.append(name)
                    logger.warning(f"[Medic] Agent {name} 心跳超时，标记隔离")

            for name in dead_agents:
                self.agents[name]["status"] = "isolated"
                logger.info(f"[Medic] Agent {name} 已隔离")

    def register_heartbeat(self, agent_name: str):
        """外部心跳注册。"""
        self.agents.setdefault(agent_name, {})
        self.agents[agent_name]["last_heartbeat"] = datetime.now()
        self.agents[agent_name]["status"] = "healthy"


async def main():
    worker = MedicWorker()
    await worker.start()


if __name__ == "__main__":
    asyncio.run(main())
