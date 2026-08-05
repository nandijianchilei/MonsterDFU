---
name: block-ip
description: 封锁指定 IP（高危操作，需人工确认；目标不能是白名单/受保护地址）
metadata:
  dfu:
    name_zh: 封锁IP
    category: defense
    risk_level: high
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 封锁IP (block-ip)

封锁单个 IP（高危，需人工确认）。

## 参数
| ip | string | 是 | 目标 IP |\n| reason | string | 否 | 封锁原因 |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
高危操作，调用后生成确认令牌等待用户批准；目标不能在受保护名单。
