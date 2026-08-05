---
name: simulate-ddos
description: 防御验证器：模拟高频 SYN 洪泛到本地端口，验证告警升级与 L4 闸门链路（仅允许 127.0.0.1/::1）
metadata:
  dfu:
    name_zh: 模拟DDoS
    category: attack
    risk_level: medium
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 模拟DDoS (simulate-ddos)

防御验证器：注入高频 SYN 模拟包，验证告警升级与 L4 闸门链路。

## 参数
| target | string | 否 | 目标（仅允许 127.0.0.1/::1） |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
防御验证器，非真实攻击；目标硬编码校验仅本地回环。
