---
name: query-alarm
description: 查询当前告警等级、倒计时与最近告警历史
metadata:
  dfu:
    name_zh: 告警等级
    category: recon
    risk_level: low
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 告警等级 (query-alarm)

查询当前告警等级与倒计时。

## 参数
| - | - | - | 无参数 |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
只读，低风险。
