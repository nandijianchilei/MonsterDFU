---
name: close-port
description: 关闭/限制指定 TCP 端口（高危操作，需人工确认；本地防火墙规则）
metadata:
  dfu:
    name_zh: 关闭端口
    category: defense
    risk_level: high
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 关闭端口 (close-port)

关闭/限制指定端口（高危，需人工确认）。

## 参数
| port | int | 是 | 端口号 1-65535 |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
高危操作，需人工确认。
