# DFU Prototype 代码审查报告 — Bug 与改进建议

> 审查日期: 2026-08-04 (v2 — 已合并开发模型复核修正)
> 审查范围: 全部源码 (main.py, core/, organs/, config.py, dfuconfig.py, web_server.py 等)
> 代码来源: 混元 AI 生成

---

## 目录

- [核查结果总表](#核查结果总表)
- [一、Bug 清单](#一bug-清单)
  - [🟡 P1 — 中危: alarm_nose 并发竞态](#p1--中危-alarm_nose-并发竞态)
  - [🟢 P2 — 低危: alarm_nose 倒计时属性未初始化 (死字段)](#p2--低危-alarm_nose-倒计时属性未初始化-死字段)
  - [🟢 P2 — 低危: threats[0] 截断 (决策丢失)](#p2--低危-threats0-截断-决策丢失)
  - [🟢 P2 — 低危: _call_log 死字段](#p2--低危-_call_log-死字段)
  - [🟢 P2 — 低危: 端口 8443 逻辑矛盾](#p2--低危-端口-8443-逻辑矛盾)
- [二、误报说明](#二误报说明)
- [三、架构改进建议](#三架构改进建议)
- [四、已修复问题确认](#四已修复问题确认)
- [五、总体评价](#五总体评价)

---

## 核查结果总表

| # | 问题 | Zcode 初判 | 开发模型复核 | 最终结论 |
|---|------|-----------|-------------|---------|
| #1 | FSM `old_level=self._increment(1)` | 🔴 P0 | ❌ **误报** | `_increment`/`_decrement` 均为纯函数(不修改 `self.level`)。降级后 `self.level = new_level`, 再 `_increment(1)` 返回 `new_level+1` = 降级前等级，逻辑正确 |
| #2 | alarm_nose 倒计时属性未初始化 | 🟡 P1 | 属实但零影响 | 属性只在 `_start_countdown` 赋值，但全项目无代码读取它们(`get_status()` 也不读)，不会抛 AttributeError。降为 P2 死字段 |
| #3 | alarm_nose 并发竞态 | 🟡 P1 | ✅ **属实** | 无锁、无幂等保护；`assess` 判定→`await _escalate` 间有协程切换窗口，并发告警可重复升级/重复倒计时。**唯一真中危** |
| #4 | `threats[0]` 截断 | 🟡 P1 | 部分属实 | LLM 和 fallback 均处理全部 threats，但 `decisions[0]` (line 545) 只取第一条决策输出，其余静默丢弃。不算"只处理第一条"(夸大)，但确实丢失批量决策。降为 P2 |
| #5 | `_call_log` 死字段 | 🟢 P2 | ✅ 属实 | 定义 + getter，从未 append |
| #6 | 端口 8443 矛盾 | 🟢 P2 | ✅ 属实 | `false_positive_filter.py` 和 `organs/observer_outbound.py` 两处均有此矛盾 |

---

## 一、Bug 清单

### 🟡 P1 — 中危: alarm_nose 并发竞态

| 项目 | 内容 |
|------|------|
| **文件** | `organs/alarm_nose.py` (全文件) |
| **严重性** | 🟡 中 — 高并发告警时可能重复升级 / 重复启动倒计时 |
| **影响范围** | 真实攻击场景 (短时间大量告警涌入) |

**问题:**

`web_server.py` 通过 `asyncio.create_task(self.alarm_nose.assess(payload))` 触发评估。多个告警同时到达时，多个 `assess()` 协程并发读写共享状态 (`_level`, `_alert_count`, `_window_start`, `_countdown_deadline` 等)。asyncio 虽然单线程，但在 `await` 点 (`_notify()`、`_block_port()`、`asyncio.sleep` 等) 会协程切换，产生竞态。

**触发场景:**

```
T0: assess(告警A) 读到 _level=L1, _alert_count=4
T1: await _notify("L1", ...) — 协程切换
T2: assess(告警B) 读到 _level=L1, _alert_count=5, 判定够L2, 启动倒计时
T3: assess(告警A) 恢复, _alert_count+=1 → 6, 再次检查, 也判定够L2
T4: 两个协程都尝试启动 L2 倒计时 → 重复通知/重复倒计时任务
```

**修复方案 (二选一):**

方案 A — 加 `asyncio.Lock`:

```python
import asyncio

class AlarmNose:
    def __init__(self, ...):
        ...
        self._lock = asyncio.Lock()

    async def assess(self, event: dict) -> None:
        async with self._lock:
            ...

    async def assess_fsm(self, fsm_level: str) -> None:
        async with self._lock:
            ...

    async def assess_health(self, health: dict) -> None:
        async with self._lock:
            ...
```

方案 B — 等级单调保护 (无锁但幂等):

```python
async def _escalate(self, target_level: str, reason: str) -> None:
    if LEVEL_ORDER.index(target_level) <= LEVEL_ORDER.index(self._level):
        return  # 已在此等级或更高，跳过
    ...
```

---

### 🟢 P2 — 低危: alarm_nose 倒计时属性未初始化 (死字段)

| 项目 | 内容 |
|------|------|
| **文件** | `organs/alarm_nose.py` |
| **行号** | `__init__` 约第 59-87 行 |
| **严重性** | 🟢 低 — 当前无运行时影响，但属于潜在隐患 |

**问题:**

`_countdown_next_level` 和 `_countdown_reason` 只在 `_start_countdown()` (约第 275-279 行) 赋值，`__init__` 中未初始化。经全项目搜索，**当前无代码读取这两个属性**（`get_status()` 不读它们），所以不会抛 `AttributeError`。

但如果未来添加代码读取它们 (如日志、调试、前端展示)，可能在倒计时未启动前踩坑。

**修复 (预防性，建议顺手做):**

```python
# 在 __init__ 中添加:
self._countdown_next_level: str = ""
self._countdown_reason: str = ""
```

---

### 🟢 P2 — 低危: `threats[0]` 截断 (决策丢失)

| 项目 | 内容 |
|------|------|
| **文件** | `core/brain_left.py` (约第 414、545 行), `core/brain_right.py` (约第 468 行) |
| **严重性** | 🟢 低 — 原型阶段可接受，生产环境需修复 |

**问题:**

`_build_alert_context(threats)` 和 `_fallback_process(threats)` **都正确处理了全部 threats**，LLM 和 fallback 也返回全部 decisions。但:

```python
# 第 545 行 — 瓶颈
decision = decisions[0]   # 只取第一条决策

# 第 414 行 — 输出只基于第一条 threat
threat = threats[0]       # DefensePlan, 日志, 策略判定 全部只用 threat = threats[0]
```

所有 `decisions[1:]` **被计算后静默丢弃**。对于聚合告警 (DDoS、端口扫描等)，只输出一条 DefensePlan。

**建议:**

原型阶段可接受 (聚合场景下第一条通常也是最严重的)。生产环境建议循环输出:

```python
for threat, decision in zip(threats, decisions):
    # 构建 DefensePlan、日志记录、策略判定
    ...
```

---

### 🟢 P2 — 低危: `_call_log` 死字段

| 项目 | 内容 |
|------|------|
| **文件** | `core/llm_client.py` |
| **行号** | 第 38 行定义, 第 796-798 行返回 |
| **严重性** | 🟢 极低 |

**问题:**

```python
self._call_log: List[Dict[str, Any]] = []  # 第 38 行

def get_call_log(self) -> List[Dict]:       # 第 796-798 行
    """获取调用日志。"""
    return self._call_log                    # 永远返回空列表
```

**建议 (实现而非删除):**

`_call_log` 对 Web 界面展示 LLM 调用统计 (调用次数、延迟、token 消耗) 很实用。建议实现:

```python
# 在 LLM 调用处 (mock 和 real 都加上):
self._call_log.append({
    "timestamp": time.time(),
    "model": self._current_model,
    "prompt_tokens": len(prompt),
    "latency_ms": latency,
    "success": True,
})
```

---

### 🟢 P2 — 低危: 端口 8443 逻辑矛盾

| 项目 | 内容 |
|------|------|
| **文件** | `core/false_positive_filter.py` (第 45、48 行) + `organs/observer_outbound.py` (第 45 行) |
| **严重性** | 🟢 极低 — mock 模式下评分语义矛盾，实际不影响生产 |

**问题:**

8443 同时出现在"可信端口"和"C2 可疑端口"中。8443 是常见替代 HTTPS 端口 (Kubernetes API、管理面板)，不应出现在 C2 列表。

**修复 (两个文件同步改):**

```python
# core/false_positive_filter.py, 第 48 行
C2_SUSPICIOUS_PORTS: set = {4444, 5555, 6666, 7777, 9001, 31337, 1337, 8088, 9999}

# organs/observer_outbound.py, 第 45 行
C2_SUSPICIOUS_PORTS: Set[int] = {4444, 5555, 6666, 7777, 9001, 31337, 1337, 8088, 9999}
```

---

## 二、误报说明

### ~~FSM `old_level=self._increment(1)`~~ — 已确认非 bug

Zcode 初判为 P0，理由是"_increment 有副作用会悄悄改回 self.level"。**实际不是:**

```python
def _increment(self, n: int = 1) -> str:
    idx = LEVEL_ORDER.index(self.level)
    new_idx = min(idx + n, len(LEVEL_ORDER) - 1)
    return LEVEL_ORDER[new_idx]
    # ← 纯函数: 只读 self.level, 不修改, 无副作用

def _decrement(self) -> str:
    idx = LEVEL_ORDER.index(self.level)
    return LEVEL_ORDER[max(idx - 1, 0)]
    # ← 同样纯函数
```

降级流程:
1. `new_level = self._decrement()` → 返回 `level - 1`，self.level 不变
2. `self.level = new_level` → 赋值，self.level 变为降一级
3. `self._increment(1)` → 读当前 self.level (已降一级)，返回 `new_level + 1` = 降级前等级

**逻辑正确。** 虽然写法不优雅 (先改 `self.level` 再用 `_increment` 反推原始值，不如直接 `old = self.level` 清晰)，但结果是对的。

---

## 三、架构改进建议

### 🟡 P1 — 双配置系统统一

| 项目 | 内容 |
|------|------|
| **当前状态** | `config.py` (617行, dataclass) 和 `dfuconfig.py` (225行, dict+YAML链) 并存 |
| **使用者** | 23 个文件用 `config.py`, 2 个文件用 `dfuconfig.py`, `main.py` 两个都用 |
| **已存在计划** | `CODE_REVIEW_AND_IMPROVEMENT_PLAN.md` 中有 6 步迁移方案 |

**建议方向:** 保留 `config.py` (dataclass 类型安全 + 23 个使用方)，**删除 `dfuconfig.py`**。`dfuconfig.py` 是 shadow code，`CODE_REVIEW_AND_IMPROVEMENT_PLAN.md` 也标记了它。将 `dfuconfig.py` 的 YAML→环境变量链式加载能力迁移到 `config.py` 的 `from_yaml()` 方法中。

**工作量:** 3-4 小时

---

### 🟢 P2 — README 项目结构过时

**当前问题:**
- 列出 `organs/fsm.py` — 实际是 `core/countermeasure_fsm.py`
- 列出 `organs/evolver.py` — 实际是 `knowledge/evolver.py`
- 只列了约 6/19 个器官文件
- 未列出 `core/` 目录、`config.py`、`web_server.py`、`desktop_launcher.py` 等关键文件
- 整个目录树与实际代码结构严重不符

**建议:** 按真实文件结构重新生成项目目录树，约 10 分钟。

---

## 四、已修复问题确认

以下问题在之前的迭代中已确认修复:

| 问题 | 文件 | 状态 |
|------|------|:----:|
| `import random` 未使用 | `core/llm_client.py` | ✅ 已删除 |
| medic_worker 空循环 | `core/medic_worker.py` | ✅ 已修复 (start() 调用 register_heartbeat) |
| medic_rollback 半成品 | `core/medic_agent.py` | ✅ 已完成 (_recover_agent 调用 rollback_cb) |
| main.py 1938 行巨文件 | `main.py` | ✅ 已拆分 (→ 273 行入口 + 7 个新模块) |
| 右脑缺干扰指令 | `core/brain_right.py` | ✅ 已补充 (interference.py 571行) |
| Token 静态无过期 | `web_server.py` | ✅ 已修复 (TTL + 自动轮换) |
| 弱 Token 无拒绝 | `main.py` | ✅ 已修复 (_validate_api_token + 黑名单) |
| 编码 GBK 乱码 | 全部新文件 | ✅ 全部 UTF-8 |

---

## 五、总体评价

### 代码质量评分

| 维度 | 评分 | 说明 |
|------|:----:|------|
| **架构设计** | 9/10 | 拆分清晰, 职责边界明确, interference 安全约束专业 |
| **代码可读性** | 8.5/10 | 命名规范, docstring 详尽, 注释信息密度高 |
| **错误处理** | 8/10 | `_safe()` / `_safe_async()` 容错模式好, 单点异常不拖垮整包 |
| **类型标注** | 8/10 | 大部分有类型注解, 优于多数 AI 生成代码 |
| **Bug 密度** | 8.5/10 | 无 P0, 1 个 P1 (并发竞态), 4 个 P2 |
| **安全性** | 8.5/10 | Token 轮换, 弱 Token 拒绝, interference 默认关闭, 意识到位 |
| **一致性** | 7.5/10 | config 双系统并存 (文档计划统一但未执行) |
| **综合** | **8.5/10** | **高于多数 AI 辅助生成的代码, 接近中级工程师水平** |

### 修复优先级 (按性价比排序)

| 优先级 | 事项 | 工作量 | 说明 |
|:------:|------|:------:|------|
| 🔴 **立即** | #3 并发锁 | 15-30 分钟 | 唯一真中危，加 `asyncio.Lock` 或等级单调保护 |
| 🟡 **顺手** | #6 移除 8443 | 1 分钟 | 两个文件同步改，从 C2 列表删除 8443 |
| 🟡 **顺手** | #2 补 2 行初始化 | 2 分钟 | 预防未来踩坑 |
| 🟢 **有空** | #5 实现 `_call_log` | 30 分钟 | 建议实现而非删除，Web 界面 LLM 统计有用 |
| 🟢 **有空** | #4 批量决策输出 | 1-2 小时 | 生产环境需要，原型阶段可暂缓 |
| 🟢 **有空** | README 目录树重生成 | 10 分钟 | 按真实结构重写 |
| 🟡 **大项** | 双配置统一 | 3-4 小时 | 保留 config.py，迁移 YAML 能力，删除 dfuconfig.py |

---

> v1 → v2 修正记录:
> - 撤回 #1 FSM old_level (P0 误报: `_increment`/`_decrement` 均为纯函数)
> - #2 降级 P1→P2 (无代码读取该属性，不会抛异常)
> - #4 修正描述 (不是"只处理第一条"，是"全部计算但只输出第一条")，降级 P1→P2
> - #6 补充 `organs/observer_outbound.py` 同步修改
> - 架构建议: 修正方向为保留 config.py 删除 dfuconfig.py；修正 evolver.py 路径为 knowledge/；确认 .gitignore 已存在
