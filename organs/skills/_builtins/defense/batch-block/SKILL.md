---
name: batch-block
description: 批量封锁多个 IP（单次上限 100 个，高危操作需人工确认）
metadata:
  dfu:
    name_zh: 批量封锁
    category: defense
    risk_level: high
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 批量封锁 (batch-block)

批量封锁多个 IP（高危，需人工确认，单次上限 100）。

## 参数
| ips | list | 是 | IP 列表（<=100） |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
高危操作，需人工确认；单次上限 100 项。
