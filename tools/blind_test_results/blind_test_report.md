# 真实流量盲测报告

- 生成时间: 2026-07-31 10:10:51
- 事件文件: `C:\Users\Administrator\AppData\Roaming\Tencent\Marvis\User\31D153AA579E8673BB6D82EE1DCBF984\workspace\conv_19f129d71db_83259a5394e3\temp\dfu_prototype\tools\blind_test_data\blind_test_events.json`
- 标注文件: `C:\Users\Administrator\AppData\Roaming\Tencent\Marvis\User\31D153AA579E8673BB6D82EE1DCBF984\workspace\conv_19f129d71db_83259a5394e3\temp\dfu_prototype\tools\blind_test_data\blind_test_labels.json`
- 回放速度: 100.0x
- 误报过滤阈值 min_triggers: 1

## 回放统计

- 总事件数: 33
- 已注入: 33
- 耗时: 0.4s
- 检测器告警数: 2
- 误报过滤层: 评估 7 次, 白名单抑制 0, 阈值抑制 0, LLM 抑制 0, 放行 7

## 混淆矩阵

|  | 实际告警（标注） | 实际静默（标注） |
|---|---|---|
| **系统告警** | TP = 2 | FP = 0 |
| **系统静默** | FN = 0 | TN = 2 |

## 指标

- 精确率 Precision = 100.00%
- 召回率 Recall = 100.00%
- 准确率 Accuracy = 100.00%
- F1 = 100.00%

## 逐流明细

| 流ID | 目标IP | 端口 | 类别 | 标注 | 系统 | 判定 | 告警描述 |
|------|--------|------|------|------|------|------|----------|
| f1 | 203.0.113.10 | 4444 | beacon | 告警 | 告警 | TP | 出站信标特征: 203.0.113.10:4444 平均间隔 2.0s, 偏差 0.00, 分数 0.90, 包数 3 |
| f2 | 203.0.113.20 | 443 | exfiltration | 告警 | 告警 | TP | 窗口累计外泄: 203.0.113.20 近 60.0s 共 1105920 字节 (阈值 1048576) |
| f3 | 104.16.0.1 | 443 | clean | 静默 | 静默 | TN | - |
| f4 | 8.8.8.8 | 443 | clean | 静默 | 静默 | TN | - |

## 告警明细

| 来源 | 目标IP | 端口 | 类别 | 严重度 | 描述 |
|------|--------|------|------|--------|------|
| outbound_monitor | 203.0.113.10 | 4444 | beacon | high | 出站信标特征: 203.0.113.10:4444 平均间隔 2.0s, 偏差 0.00, 分数 0.90, 包数 3 |
| outbound_monitor | 203.0.113.20 | 443 | exfiltration | high | 窗口累计外泄: 203.0.113.20 近 60.0s 共 1105920 字节 (阈值 1048576) |