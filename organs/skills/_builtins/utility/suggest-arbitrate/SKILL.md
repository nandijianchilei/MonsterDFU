---
name: suggest-arbitrate
description: 查询左脑/右脑最近建议，展示冲突并给出全局仲裁建议
metadata:
  dfu:
    name_zh: 冲突仲裁
    category: utility
    risk_level: low
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 冲突仲裁 (suggest-arbitrate)

对左脑/右脑建议进行冲突仲裁（全局观测者视角）。

## 参数
| left_advice | dict | 否 | 左脑建议 {action, level} |\n| right_advice | dict | 否 | 右脑建议 {action, level} |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
只读，低风险；仲裁规则：更高级别优先，同级更保守优先。
