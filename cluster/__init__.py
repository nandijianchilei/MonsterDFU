"""
cluster/ - 单元集群管理模块

包含：
- ClusterRegistry：集群注册中心
- LoadDispatcher：负载分发器
- DFUUnit：数据防御单元实例
"""

from cluster.registry import ClusterRegistry, UnitInfo
from cluster.dispatcher import LoadDispatcher, DispatchStrategy
from cluster.dfu_unit import DFUUnit

__all__ = [
    "ClusterRegistry",
    "UnitInfo",
    "LoadDispatcher",
    "DispatchStrategy",
    "DFUUnit",
]
