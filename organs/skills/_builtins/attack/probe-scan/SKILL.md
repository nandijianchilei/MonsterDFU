---
name: probe-scan
description: 防御验证器：模拟端口扫描探测，验证 scanner_vuln 发现与左脑分析链路（仅本地/受控内网）
metadata:
  dfu:
    name_zh: 模拟端口探测
    category: attack
    risk_level: medium
    timeout_sec: 30.0
    enabled: true
    handler: scripts/handler.py
---

# 模拟端口探测 (probe-scan)

防御验证器：注入端口探测模拟包，验证漏洞发现与左脑分析链路。

## 参数
| target | string | 否 | 目标（仅允许 127.0.0.1/::1） |

## 输出
返回 {"success": bool, "result": ..., "message": ...} 结构。

## 注意事项
防御验证器，非真实攻击；目标硬编码校验仅本地回环。
