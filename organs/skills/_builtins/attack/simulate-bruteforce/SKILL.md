---
name: simulate-bruteforce
description: 防御验证器：模拟连续登录失败，验证规则引擎拦截与右脑快速决策链路（仅本地回环）
metadata:
  dfu:
    name_zh: 模拟暴力破解
    category: attack
    risk_level: medium
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 模拟暴力破解 (simulate-bruteforce)

防御验证器：注入连续登录失败模拟包，验证规则引擎拦截链路。

## 参数
| target | string | 否 | 目标（仅允许 127.0.0.1/::1） |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
防御验证器，非真实攻击；目标硬编码校验仅本地回环。
