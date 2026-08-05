---
name: query-threats
description: 查询最近威胁/告警事件列表（limit 控制条数）
metadata:
  dfu:
    name_zh: 威胁事件
    category: recon
    risk_level: low
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 威胁事件 (query-threats)

查询最近威胁/告警事件，用于回答'现在有什么威胁'类问题。

## 参数
| limit | int | 否 | 返回条数（默认 10） |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
只读，低风险；仅返回 observe/attack/left/right 阶段事件。
