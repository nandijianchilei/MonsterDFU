---
name: dispatch-organ
description: 通用调动器官：通过白名单向指定器官派发任务（organ_id + task + params），走 MessageBus 回流
metadata:
  dfu:
    name_zh: 调动器官
    category: dispatch
    risk_level: medium
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 调动器官 (dispatch-organ)

通过白名单调动指定器官执行任务（走 MessageBus）。

## 参数
| organ_id | string | 是 | 目标器官（白名单：brain_left/scanner_vuln/ip_isolation/firewall/medic/whitelist/notifier） |\n| task | string | 是 | 任务名（如 scan/block/notify） |\n| params | dict | 否 | 任务参数 |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
中风险：调动器官前怪兽应确认任务合理；白名单写死在 handler。
