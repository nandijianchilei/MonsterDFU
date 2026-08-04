# DFU 基准评测报告

- **评测时间**: 2026-08-04 14:21:03
- **场景数**: 8

## 概览

| 场景 | 总事件数 | 告警数 | 期望告警类型 | 检出类型 | 检测率 | 误报数 | FSM升级 | 升级延迟(s) | 蜜罐触发 | 干扰次数 |
|------|---------|--------|-------------|---------|-------|--------|---------|------------|---------|---------|
| c2_beacon            |   6 |   5 | beacon                         | beacon                         | 100.0% |  0 |  1 |   0.06 |   0 |   0 |
| data_exfil           |  10 |  10 | exfiltration                   | exfiltration                   | 100.0% |  0 |  3 |   0.12 |   0 |   0 |
| port_scan            |  20 |  19 | port_scan                      | port_scan                      | 100.0% |  0 |  4 |   0.06 |  20 |   0 |
| bruteforce           |  15 |  14 | bruteforce                     | bruteforce                     | 100.0% |  0 |  3 |   0.06 |   0 |   0 |
| mixed_attack         |  51 |  48 | beacon, exfiltration, port_scan, bruteforce | beacon, bruteforce, exfiltration, port_scan | 100.0% |  0 | 11 |   0.25 |  20 |   0 |
| clean_traffic        |  10 |   0 | 无                              | 无                              |   0.0% |  0 |  1 |   0.00 |   0 |   0 |
| deception            |   8 |   6 | port_scan, bruteforce          | bruteforce, port_scan          | 100.0% |  0 |  2 |   0.06 |   8 |   0 |
| interference         |  20 |  20 | exploit, command_injection     | command_injection, exploit     | 100.0% |  0 |  6 |   0.13 |   0 |  10 |

## 各场景详情

### c2_beacon

- **描述**: C2 信标回连 — 6 次等间隔小包回连到可疑端口（4444/8443/31337），模拟远控木马心跳。间隔 3-5s，包大小 64-256 字节。
- **总注入事件数**: 6
- **告警生成数**: 5
- **期望告警类型**: ['beacon']
- **实际检出类型**: ['beacon']
- **检测率**: 100.0%
- **误报数**: 0
- **FSM 升级次数**: 1
- **首次告警→首次升级延迟**: 0.06s
- **最终 FSM 等级分布**: {'L0-monitor': 0, 'L1-soft': 1, 'L2-hard': 0, 'L3-offensive': 0, 'L4-isolate': 0}
- **FSM 管理 IP 数**: 1
- **蜜罐诱捕次数（honeypot_trap）**: 0
- **干扰应用次数（interference_applied）**: 0
- **干扰手段分布**: {'blindfold': 0, 'puppeteer': 0}

### data_exfil

- **描述**: 数据外泄 — 2 次单包大流量（12MB、18MB）+ 8 次窗口累计外泄（6MB/3MB 交替），模拟敏感数据窃取。
- **总注入事件数**: 10
- **告警生成数**: 10
- **期望告警类型**: ['exfiltration']
- **实际检出类型**: ['exfiltration']
- **检测率**: 100.0%
- **误报数**: 0
- **FSM 升级次数**: 3
- **首次告警→首次升级延迟**: 0.12s
- **最终 FSM 等级分布**: {'L0-monitor': 0, 'L1-soft': 0, 'L2-hard': 0, 'L3-offensive': 1, 'L4-isolate': 0}
- **FSM 管理 IP 数**: 1
- **蜜罐诱捕次数（honeypot_trap）**: 0
- **干扰应用次数（interference_applied）**: 0
- **干扰手段分布**: {'blindfold': 0, 'puppeteer': 0}

### port_scan

- **描述**: 端口扫描 — 同一源 IP（10.0.1.100）在 2 秒内探测 20 个不同端口（22/23/25/53/80/.../8080），模拟横向移动侦察。
- **总注入事件数**: 20
- **告警生成数**: 19
- **期望告警类型**: ['port_scan']
- **实际检出类型**: ['port_scan']
- **检测率**: 100.0%
- **误报数**: 0
- **FSM 升级次数**: 4
- **首次告警→首次升级延迟**: 0.06s
- **最终 FSM 等级分布**: {'L0-monitor': 0, 'L1-soft': 0, 'L2-hard': 0, 'L3-offensive': 0, 'L4-isolate': 1}
- **FSM 管理 IP 数**: 1
- **蜜罐诱捕次数（honeypot_trap）**: 20
- **干扰应用次数（interference_applied）**: 0
- **干扰手段分布**: {'blindfold': 0, 'puppeteer': 0}

### bruteforce

- **描述**: 暴力破解 — 15 次快速 SSH 登录失败（10.0.1.200 → 192.168.1.10:22），间隔 0.5-2s，模拟口令爆破。
- **总注入事件数**: 15
- **告警生成数**: 14
- **期望告警类型**: ['bruteforce']
- **实际检出类型**: ['bruteforce']
- **检测率**: 100.0%
- **误报数**: 0
- **FSM 升级次数**: 3
- **首次告警→首次升级延迟**: 0.06s
- **最终 FSM 等级分布**: {'L0-monitor': 0, 'L1-soft': 0, 'L2-hard': 0, 'L3-offensive': 1, 'L4-isolate': 0}
- **FSM 管理 IP 数**: 1
- **蜜罐诱捕次数（honeypot_trap）**: 0
- **干扰应用次数（interference_applied）**: 0
- **干扰手段分布**: {'blindfold': 0, 'puppeteer': 0}

### mixed_attack

- **描述**: 混合攻击 — C2 信标 + 数据外泄 + 端口扫描 + 暴力破解乱序混合，模拟 APT 攻击链，时间跨度约 120 秒。
- **总注入事件数**: 51
- **告警生成数**: 48
- **期望告警类型**: ['beacon', 'exfiltration', 'port_scan', 'bruteforce']
- **实际检出类型**: ['beacon', 'bruteforce', 'exfiltration', 'port_scan']
- **检测率**: 100.0%
- **误报数**: 0
- **FSM 升级次数**: 11
- **首次告警→首次升级延迟**: 0.25s
- **最终 FSM 等级分布**: {'L0-monitor': 0, 'L1-soft': 0, 'L2-hard': 0, 'L3-offensive': 1, 'L4-isolate': 2}
- **FSM 管理 IP 数**: 3
- **蜜罐诱捕次数（honeypot_trap）**: 20
- **干扰应用次数（interference_applied）**: 0
- **干扰手段分布**: {'blindfold': 0, 'puppeteer': 0}

### clean_traffic

- **描述**: 正常流量 — 10 条 HTTPS/API 调用（github/cdn/google/...），用于测试误报率。不应产生任何告警。
- **总注入事件数**: 10
- **告警生成数**: 0
- **期望告警类型**: []
- **实际检出类型**: []
- **检测率**: 0.0%
- **误报数**: 0
- **FSM 升级次数**: 1
- **首次告警→首次升级延迟**: 0.0s
- **最终 FSM 等级分布**: {'L0-monitor': 0, 'L1-soft': 1, 'L2-hard': 0, 'L3-offensive': 0, 'L4-isolate': 0}
- **FSM 管理 IP 数**: 1
- **蜜罐诱捕次数（honeypot_trap）**: 0
- **干扰应用次数（interference_applied）**: 0
- **干扰手段分布**: {'blindfold': 0, 'puppeteer': 0}

### deception

- **描述**: 欺骗层蜜罐触发 — 8 条侦察类攻击（端口扫描 3 条 / 暴力破解 3 条 /漏洞探测 2 条），命中蜜罐触发规则，应触发 honeypot_trap 诱捕记录。
- **总注入事件数**: 8
- **告警生成数**: 6
- **期望告警类型**: ['port_scan', 'bruteforce']
- **实际检出类型**: ['bruteforce', 'port_scan']
- **检测率**: 100.0%
- **误报数**: 0
- **FSM 升级次数**: 2
- **首次告警→首次升级延迟**: 0.06s
- **最终 FSM 等级分布**: {'L0-monitor': 1, 'L1-soft': 2, 'L2-hard': 0, 'L3-offensive': 0, 'L4-isolate': 0}
- **FSM 管理 IP 数**: 3
- **蜜罐诱捕次数（honeypot_trap）**: 8
- **干扰应用次数（interference_applied）**: 0
- **干扰手段分布**: {'blindfold': 0, 'puppeteer': 0}

### interference

- **描述**: 攻击路径干扰触发 — 20 条高危攻击（exploit 10 条 / command_injection 10 条），授权环境下 FSM 升级至 L2 后触发 blindfold/puppeteer 干扰。
- **总注入事件数**: 20
- **告警生成数**: 20
- **期望告警类型**: ['exploit', 'command_injection']
- **实际检出类型**: ['command_injection', 'exploit']
- **检测率**: 100.0%
- **误报数**: 0
- **FSM 升级次数**: 6
- **首次告警→首次升级延迟**: 0.13s
- **最终 FSM 等级分布**: {'L0-monitor': 0, 'L1-soft': 0, 'L2-hard': 0, 'L3-offensive': 2, 'L4-isolate': 0}
- **FSM 管理 IP 数**: 2
- **蜜罐诱捕次数（honeypot_trap）**: 0
- **干扰应用次数（interference_applied）**: 10
- **干扰手段分布**: {'blindfold': 5, 'puppeteer': 5}

## 汇总统计

- **攻击场景数（排除 clean_traffic）**: 7
- **总注入攻击事件数**: 130
- **总告警生成数**: 122
- **平均检测率**: 100.0%
- **clean_traffic 误报数**: 0（目标 0，由误报过滤层收敛）
- **总蜜罐诱捕次数（honeypot_trap）**: 48
- **总干扰应用次数（interference_applied）**: 10

### 误报过滤层（白名单 + 告警阈值 + LLM 二次确认）

过滤管线：`白名单（IP/端口/域名）→ 告警阈值（同源多次触发）→ LLM 二次确认`

| 场景 | 评估数 | 放行告警 | 白名单抑制 | 阈值抑制 | LLM抑制 |
|------|-------|---------|-----------|---------|---------|
| c2_beacon            |    6 |    5 |    0 |    1 |    0 |
| data_exfil           |   10 |   10 |    0 |    0 |    0 |
| port_scan            |   20 |   19 |    0 |    1 |    0 |
| bruteforce           |   15 |   14 |    0 |    1 |    0 |
| mixed_attack         |   51 |   48 |    0 |    3 |    0 |
| clean_traffic        |   10 |    0 |   10 |    0 |    0 |
| deception            |    8 |    6 |    0 |    2 |    0 |
| interference         |   20 |   20 |    0 |    0 |    0 |

- clean_traffic 的 10 条正常 HTTPS/API 事件全部被白名单（可信域名 / 可信 CDN IP）命中，误报从 10 降到 0。
- 攻击场景中，阈值层仅压制各类别的首次低频触发（如 c2_beacon 首个包），不影响检测率；high/severe 高危信号（如超大包外泄）直接放行。

### 欺骗层与干扰层指标（v1.1 第四阶段扩展）

**蜜罐诱捕统计**（honeypot_trap 触发，仅侦察类事件命中）：

| 场景 | 诱捕次数 | 唯一源IP | 端口分布 |
|------|---------|---------|---------|
| c2_beacon            |   0 |  0 | - |
| data_exfil           |   0 |  0 | - |
| port_scan            |  20 |  1 | 22:1, 23:1, 25:1, 53:1, 80:1 |
| bruteforce           |   0 |  0 | - |
| mixed_attack         |  20 |  1 | 22:1, 23:1, 25:1, 53:1, 80:1 |
| clean_traffic        |   0 |  0 | - |
| deception            |   8 |  3 | 22:4, 8080:2, 80:1, 443:1 |
| interference         |   0 |  0 | - |

**干扰门控命中分布**（blindfold / puppeteer 应用 + 各门控拦截）：

| 场景 | blindfold | puppeteer | 应用合计 | 未启用 | 未授权 | 严重度不足 | 类别不允许 | 等级不足 |
|------|-----------|-----------|---------|-------|-------|-----------|-----------|---------|
| c2_beacon            |   0 |   0 |   0 |   0 |   6 |   0 |   0 |   0 |
| data_exfil           |   0 |   0 |   0 |   0 |  10 |   0 |   0 |   0 |
| port_scan            |   0 |   0 |   0 |   0 |  20 |   0 |   0 |   0 |
| bruteforce           |   0 |   0 |   0 |   0 |  15 |   0 |   0 |   0 |
| mixed_attack         |   0 |   0 |   0 |   0 |  51 |   0 |   0 |   0 |
| clean_traffic        |   0 |   0 |   0 |   0 |  10 |   0 |   0 |   0 |
| deception            |   0 |   0 |   0 |   0 |   8 |   0 |   0 |   0 |
| interference         |   5 |   5 |  10 |   0 |   0 |   0 |   0 |  10 |

- deception 场景：8 条侦察类事件全部触发蜜罐诱捕；干扰层因未授权（authorized_only）拦截，无干扰应用。
- interference 场景：20 条高危攻击在授权环境（authorized=True）下评估，FSM 升级至 L2 后触发 blindfold / puppeteer 共 10 次（blindfold 5 / puppeteer 5）。

---
*报告由 DFU Benchmark Runner 自动生成于 2026-08-04 14:21:03*