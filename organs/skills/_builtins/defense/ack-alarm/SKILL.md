---
name: ack-alarm
description: 人工确认当前告警，重置倒计时（管理员确认场景）
metadata:
  dfu:
    name_zh: 确认告警
    category: defense
    risk_level: medium
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 确认告警 (ack-alarm)

人工确认当前告警并重置倒计时。

## 参数
| level | string | 否 | 指定确认等级，缺省全部 |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
中风险：确认后倒计时重置，请确认告警已处理。
