---
name: get-posture
description: 获取 DFU 全局态势：12 器官状态 + 最近事件流 + 运行元信息
metadata:
  dfu:
    name_zh: 全局态势
    category: recon
    risk_level: low
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 全局态势 (get-posture)

获取当前 DFU 全局态势快照（12 器官状态 + 最近事件 + 运行时长）。

## 参数
| force | bool | 否 | 强制刷新态势缓存 |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
只读，低风险；态势带 5s 缓存，force=true 可强制刷新。
