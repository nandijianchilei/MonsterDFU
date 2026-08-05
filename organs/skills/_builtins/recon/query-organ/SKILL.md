---
name: query-organ
description: 查询指定防御器官的状态指标（organ_id: prefrontal/left_brain/right_brain/left_hand/right_hand/medic/self_heal/notifier/alarm/memory/whitelist/skillbox）
metadata:
  dfu:
    name_zh: 查询器官
    category: recon
    risk_level: low
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 查询器官 (query-organ)

查询指定器官的实时状态指标。

## 参数
| organ_id | string | 是 | 器官 ID（prefrontal/left_brain/right_brain/left_hand/right_hand/medic/self_heal/notifier/alarm/memory/whitelist/skillbox） |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
只读，低风险；organ_id 不存在时返回错误。
