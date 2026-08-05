# Skill工具箱 + 小怪兽全局Agent — 架构设计方案

> 设计日期: 2026-08-04
> 状态: 待评审
> 关联问题: Skill工具箱是纯UI空壳；小怪兽只是裸LLM代理转发

---

## 目录

- [一、问题诊断](#一问题诊断)
- [二、设计目标](#二设计目标)
- [三、整体架构](#三整体架构)
- [四、Skill工具箱设计](#四skill工具箱设计)
- [五、小怪兽全局Agent设计](#五小怪兽全局agent设计)
- [六、两者如何联动](#六两者如何联动)
- [七、安全约束](#七安全约束)
- [八、配置项](#八配置项)
- [九、API端点](#九api端点)
- [十、前端改造](#十前端改造)
- [十一、文件清单](#十一文件清单)
- [十二、实施阶段](#十二实施阶段)

---

## 一、问题诊断

### Skill工具箱现状

| 组件 | 状态 |
|------|------|
| 前端器官卡片 (monster.html:680) | ✅ 有完整UI定义 |
| 后端数据 (web_server.py:1019) | ❌ 把器官吞吐量伪装成工具列表 |
| `organs/skill_box.py` | ❌ 不存在 |
| SkillConfig 配置 | ❌ 不存在 |
| 工具注册/加载/调用框架 | ❌ 不存在 |
| 动态插件加载 | ❌ 不存在 |
| `/api/skill-box/*` 端点 | ❌ 不存在 |

**核心问题：没有任何机制让外部工具或技能"接入"系统。** 前端写的"接入外部技能与工具链"是一张空头支票。

### 小怪兽全局Agent现状

前端文案承诺:
- "和 Monster 对话，**掌控每一只器官**"
- "问一问小怪兽当前的**防御态势**"

实际 `/api/chat` (web_server.py:1227-1304):
```python
# 把用户消息原样转发到外部LLM，不注入任何DFU状态
response = await httpx.post(llm_url, json=payload)
```

**核心问题：零上下文、零工具调用、零状态感知。** 怪兽不知道系统在防什么、哪个器官什么状态、当前告警什么等级。它只是一个 OpenAI API 套壳代理。

---

## 二、设计目标

### 必须达到

1. **Skill工具箱能真正接入外部工具** — 通过目录扫描或显式注册，加载攻击/防御/侦察工具
2. **小怪兽能感知全局态势** — 对话时注入12器官状态、告警等级、活跃威胁
3. **小怪兽能通过工具调用执行操作** — 不是"裸聊"，而是能用自然语言指挥器官

### 不做的（明确边界）

- 不做自主决策替代双脑（怪兽不越俎代庖做防御决策，那是左脑/右脑的职责）
- 不做自动攻击（工具调用默认只读，高危操作需人工确认）
- 不做多轮复杂规划（原型阶段只做单轮 ReAct，不做多步任务分解）

### 设计原则

- **复用现有架构**：不新建消息总线、不新建配置系统，基于现有 MessageBus + config.py + agent_factory
- **渐进式**：内置工具先行（封装现有器官能力），外部插件后行
- **安全优先**：默认只读、高危确认、全审计、kill-switch联动（与 interference.py 风格一致）

---

## 三、整体架构

```
用户 (自然语言)
    │
    ▼
┌──────────────────────────────────────────────┐
│  MonsterAgent (小怪兽全局Agent)               │
│  core/monster_agent.py                        │
│                                               │
│  1. 注入全局态势上下文                         │
│     ┌─────────────────────────────────┐      │
│     │ gather_global_posture()          │      │
│     │  ├─ alarm_nose.get_status()      │      │
│     │  ├─ medic_agent 健康快照         │      │
│     │  ├─ event_recorder 最近事件      │      │
│     │  ├─ countermeasure_fsm 活跃等级  │      │
│     │  └─ monitor 器官吞吐量           │      │
│     └─────────────────────────────────┘      │
│                                               │
│  2. 获取可用工具列表 (function calling)        │
│     ┌─────────────────────────────────┐      │
│     │ toolbox.get_tool_schemas()       │      │
│     └──────────────┬──────────────────┘      │
│                    │                          │
│  3. 调用 LLM (带上下文 + 工具定义)             │
│     └─ LLM 返回文本回复 或 工具调用请求        │
│                                               │
│  4. 执行工具调用 (如果有)                      │
│                    │                          │
│                    ▼                          │
└────────────────────┼─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│  SkillToolbox (技能工具箱)                     │
│  organs/skill_box.py                          │
│                                               │
│  工具注册表 + 调用执行 + 审计日志              │
│                                               │
│  内置工具 (封装现有器官能力):                   │
│   ├─ block_ip        → actor_ip_isolation     │
│   ├─ close_port      → firewall_executor       │
│   ├─ query_organ     → monitor / 各器官状态     │
│   ├─ query_threats   → event_recorder          │
│   ├─ query_alarm     → alarm_nose              │
│   ├─ ack_alarm       → alarm_nose              │
│   ├─ get_posture     → 全局态势汇总             │
│   └─ llm_analyze     → 左脑/右脑 LLM 推理       │
│                                               │
│  外部插件 (动态加载):                          │
│   └─ skills/ 目录下各 .py 文件                 │
│      每个 define register(toolbox)            │
└──────────────────────────────────────────────┘
                     │
                     ▼  (实际执行操作)
┌──────────────────────────────────────────────┐
│  现有器官 / MessageBus                         │
│  (不改动，工具只是封装它们的调用入口)           │
└──────────────────────────────────────────────┘
```

**核心设计：Skill工具箱是"能力接入层"，小怪兽是"智能协调层"，两者通过 function calling 协议连接。**

---

## 四、Skill工具箱设计

### 4.1 核心数据结构

```python
# organs/skill_box.py

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

@dataclass
class SkillTool:
    """单个技能工具的定义。"""
    tool_id: str                    # 唯一ID，如 "block_ip"
    name_zh: str                    # 中文名，如 "封锁IP"
    name_en: str                    # 英文名
    description: str                # LLM可读的功能描述（function calling用）
    category: str                   # "attack" | "defense" | "recon" | "utility"
    enabled: bool = True            # 启用开关
    risk_level: str = "low"         # "low" | "medium" | "high"
                                    # high = 写操作/有副作用，需人工确认
    timeout_sec: float = 30.0       # 调用超时

    # 实际执行函数: async def(params: dict) -> dict
    handler: Optional[Callable[[Dict], Awaitable[Dict]]] = None

    # 参数schema (OpenAI function calling 格式)
    param_schema: Dict[str, Any] = field(default_factory=lambda: {
        "type": "object",
        "properties": {},
    })

    # 调用统计
    call_count: int = 0
    last_called: float = 0.0
```

### 4.2 SkillToolbox 类

```python
class SkillToolbox:
    """技能工具箱：工具注册、管理、调用、审计。"""

    def __init__(self, config: SkillToolboxConfig):
        self.cfg = config
        self._tools: Dict[str, SkillTool] = {}
        self._call_log: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    # ── 注册管理 ──
    def register(self, tool: SkillTool) -> None:
        """注册一个工具。"""
        self._tools[tool.tool_id] = tool

    def unregister(self, tool_id: str) -> None:
        self._tools.pop(tool_id, None)

    def enable(self, tool_id: str) -> bool:
        tool = self._tools.get(tool_id)
        if tool:
            tool.enabled = True
            return True
        return False

    def disable(self, tool_id: str) -> bool:
        tool = self._tools.get(tool_id)
        if tool:
            tool.enabled = False
            return True
        return False

    # ── 查询 ──
    def list_tools(self, category: str = None,
                   enabled_only: bool = False) -> List[SkillTool]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        if enabled_only:
            tools = [t for t in tools if t.enabled]
        return tools

    def get_tool(self, tool_id: str) -> Optional[SkillTool]:
        return self._tools.get(tool_id)

    def get_tool_schemas_for_llm(self) -> List[Dict[str, Any]]:
        """生成 OpenAI function calling 格式的工具定义列表。
        只返回 enabled=True 的工具。"""
        schemas = []
        for tool in self._tools.values():
            if not tool.enabled:
                continue
            schemas.append({
                "type": "function",
                "function": {
                    "name": tool.tool_id,
                    "description": tool.description,
                    "parameters": tool.param_schema,
                },
            })
        return schemas

    # ── 调用 ──
    async def invoke(self, tool_id: str, params: Dict[str, Any],
                     caller: str = "monster",
                     force: bool = False) -> Dict[str, Any]:
        """调用工具。

        Args:
            tool_id: 工具ID
            params: 参数
            caller: 调用者标识 (monster / user / system)
            force: 是否跳过高危确认 (仅 system 级调用可用)

        Returns:
            {"success": bool, "result": ..., "error": ...,
             "needs_confirm": bool}  # high risk 时 needs_confirm=True
        """
        async with self._lock:
            tool = self._tools.get(tool_id)
            if not tool:
                return {"success": False, "error": f"工具 {tool_id} 不存在"}
            if not tool.enabled:
                return {"success": False, "error": f"工具 {tool_id} 已禁用"}
            if not tool.handler:
                return {"success": False, "error": f"工具 {tool_id} 无执行函数"}

            # 高危操作拦截
            if tool.risk_level == "high" and not force and caller != "system":
                return {
                    "success": False,
                    "needs_confirm": True,
                    "error": f"高危工具 {tool_id} 需要人工确认",
                    "params": params,
                }

            # 执行
            start = time.time()
            try:
                result = await asyncio.wait_for(
                    tool.handler(params),
                    timeout=tool.timeout_sec,
                )
                latency = (time.time() - start) * 1000
                tool.call_count += 1
                tool.last_called = time.time()

                self._log_call(tool_id, params, result, caller,
                               latency, success=True)
                return {"success": True, "result": result, "latency_ms": latency}

            except asyncio.TimeoutError:
                latency = (time.time() - start) * 1000
                self._log_call(tool_id, params, None, caller,
                               latency, success=False, error="超时")
                return {"success": False, "error": "调用超时"}
            except Exception as e:
                latency = (time.time() - start) * 1000
                self._log_call(tool_id, params, None, caller,
                               latency, success=False, error=str(e))
                return {"success": False, "error": str(e)}

    # ── 审计日志 ──
    def _log_call(self, tool_id, params, result, caller,
                  latency_ms, success, error=""):
        entry = {
            "timestamp": time.time(),
            "tool_id": tool_id,
            "caller": caller,
            "params": params,
            "success": success,
            "error": error,
            "latency_ms": round(latency_ms, 1),
            "result_summary": str(result)[:200] if result else "",
        }
        self._call_log.append(entry)
        if len(self._call_log) > self.cfg.call_log_max:
            self._call_log = self._call_log[-self.cfg.call_log_max:]
        logger.info(
            f"[SkillToolbox] {caller} 调用 {tool_id} "
            f"({'成功' if success else '失败:' + error}) {latency_ms:.0f}ms"
        )

    def get_call_log(self, limit: int = 50,
                     tool_id: str = None) -> List[Dict[str, Any]]:
        logs = self._call_log[-limit:]
        if tool_id:
            logs = [l for l in logs if l["tool_id"] == tool_id]
        return logs

    def get_stats(self) -> Dict[str, Any]:
        """工具箱统计 (前端展示用)。"""
        tools = list(self._tools.values())
        return {
            "total_tools": len(tools),
            "enabled": sum(1 for t in tools if t.enabled),
            "by_category": {
                cat: sum(1 for t in tools if t.category == cat)
                for cat in ("attack", "defense", "recon", "utility")
            },
            "total_calls": sum(t.call_count for t in tools),
            "recent_calls": len(self._call_log),
        }
```

### 4.3 动态加载器

```python
import importlib.util
from pathlib import Path

class SkillLoader:
    """从 skills/ 目录扫描并加载技能插件。"""

    def __init__(self, toolbox: SkillToolbox, skills_dir: str):
        self.toolbox = toolbox
        self.skills_dir = Path(skills_dir)

    def load_all(self) -> int:
        """扫描 skills/ 目录，加载所有技能插件。

        每个插件 .py 文件需定义:
            def register(toolbox: SkillToolbox) -> None:
                toolbox.register(SkillTool(...))

        Returns:
            成功加载的插件数量
        """
        if not self.skills_dir.exists():
            logger.info(f"[SkillLoader] skills目录不存在: {self.skills_dir}")
            return 0

        count = 0
        for py_file in sorted(self.skills_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                self._load_file(py_file)
                count += 1
            except Exception as e:
                logger.error(f"[SkillLoader] 加载 {py_file.name} 失败: {e}")
        logger.info(f"[SkillLoader] 已加载 {count} 个技能插件")
        return count

    def _load_file(self, path: Path):
        """动态导入单个技能文件。"""
        module_name = f"skill_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if not hasattr(module, "register"):
            raise ValueError(f"{path.name} 缺少 register() 函数")

        module.register(self.toolbox)
```

### 4.4 内置工具示例

```python
# skills/builtins.py — 内置工具，封装现有器官能力

from organs.skill_box import SkillTool, SkillToolbox


def register(toolbox: SkillToolbox) -> None:
    """注册所有内置工具。"""

    # ── 只读查询类 (risk=low) ──

    toolbox.register(SkillTool(
        tool_id="get_posture",
        name_zh="全局态势",
        name_en="Global Posture",
        description="获取当前系统全局防御态势，包括告警等级、器官健康、"
                    "活跃威胁、最近事件。",
        category="recon",
        risk_level="low",
        handler=_get_posture,
        param_schema={"type": "object", "properties": {}},
    ))

    toolbox.register(SkillTool(
        tool_id="query_organ",
        name_zh="查询器官",
        name_en="Query Organ",
        description="查询指定器官的运行状态和指标。"
                    "参数 organ_id 可选: traffic/vuln_scan/log_audit/ip_isolation等。",
        category="recon",
        risk_level="low",
        handler=_query_organ,
        param_schema={
            "type": "object",
            "properties": {
                "organ_id": {"type": "string",
                             "description": "器官ID，不传则返回全部器官状态"},
            },
        },
    ))

    toolbox.register(SkillTool(
        tool_id="query_threats",
        name_zh="查询威胁",
        name_en="Query Threats",
        description="查询最近的威胁事件和攻击记录。",
        category="recon",
        risk_level="low",
        handler=_query_threats,
        param_schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer",
                          "description": "返回条数，默认20"},
                "source_ip": {"type": "string",
                              "description": "按源IP过滤"},
            },
        },
    ))

    toolbox.register(SkillTool(
        tool_id="query_alarm",
        name_zh="查询告警",
        name_en="Query Alarm",
        description="查询当前报警鼻的告警等级和倒计时状态。",
        category="recon",
        risk_level="low",
        handler=_query_alarm,
        param_schema={"type": "object", "properties": {}},
    ))

    # ── 写操作类 (risk=high，需确认) ──

    toolbox.register(SkillTool(
        tool_id="block_ip",
        name_zh="封锁IP",
        name_en="Block IP",
        description="封锁指定IP地址。高危操作，需人工确认。",
        category="defense",
        risk_level="high",
        handler=_block_ip,
        param_schema={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "要封锁的IP地址"},
                "duration_sec": {"type": "integer",
                                 "description": "封锁时长(秒)，0=永久"},
            },
            "required": ["ip"],
        },
    ))

    toolbox.register(SkillTool(
        tool_id="close_port",
        name_zh="关闭端口",
        name_en="Close Port",
        description="通过防火墙关闭指定端口。高危操作，需人工确认。",
        category="defense",
        risk_level="high",
        handler=_close_port,
        param_schema={
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "端口号"},
                "protocol": {"type": "string",
                             "enum": ["tcp", "udp"],
                             "description": "协议"},
            },
            "required": ["port"],
        },
    ))

    toolbox.register(SkillTool(
        tool_id="ack_alarm",
        name_zh="确认告警",
        name_en="Ack Alarm",
        description="人工确认当前告警，重置倒计时。",
        category="defense",
        risk_level="medium",
        handler=_ack_alarm,
        param_schema={"type": "object", "properties": {}},
    ))
```

各 handler 实现（封装现有器官调用入口）:

```python
# skills/builtins.py 续 — handler 实现

async def _get_posture(params: dict) -> dict:
    """全局态势 — 由 MonsterAgent 注入的 posture 提供者实现。"""
    provider = _get_posture._provider  # 由 runner 注入
    return provider()


async def _query_organ(params: dict) -> dict:
    organ_id = params.get("organ_id", "")
    # 调用 monitor 获取器官状态
    ...


async def _block_ip(params: dict) -> dict:
    ip = params["ip"]
    duration = params.get("duration_sec", 0)
    # 发布到 MessageBus，由 actor_ip_isolation 执行
    bus = get_message_bus()
    await bus.publish(Message(
        source="skill_toolbox",
        target="ip_isolation",
        msg_type="isolation_action",
        payload={"ip": ip, "action": "block", "duration_sec": duration},
    ))
    return {"blocked_ip": ip, "duration_sec": duration}


async def _close_port(params: dict) -> dict:
    port = params["port"]
    proto = params.get("protocol", "tcp")
    # 调用 firewall_executor
    ...
```

### 4.5 外部插件示例

用户自定义的攻击侦察技能:

```python
# skills/nmap_scan.py

import asyncio
from organs.skill_box import SkillTool, SkillToolbox


async def _nmap_scan(params: dict) -> dict:
    target = params["target"]
    scan_type = params.get("scan_type", "-sV")

    proc = await asyncio.create_subprocess_exec(
        "nmap", scan_type, target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    return {
        "exit_code": proc.returncode,
        "output": stdout.decode("utf-8", errors="replace")[:2000],
        "error": stderr.decode("utf-8", errors="replace")[:500],
    }


def register(toolbox: SkillToolbox) -> None:
    toolbox.register(SkillTool(
        tool_id="nmap_scan",
        name_zh="Nmap扫描",
        name_en="Nmap Scan",
        description="对指定目标执行 nmap 端口扫描。需要系统已安装 nmap。",
        category="attack",
        risk_level="high",
        timeout_sec=120.0,
        handler=_nmap_scan,
        param_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "扫描目标 (IP或域名)"},
                "scan_type": {"type": "string",
                              "description": "扫描类型，默认 -sV",
                              "default": "-sV"},
            },
            "required": ["target"],
        },
    ))
```

---

## 五、小怪兽全局Agent设计

### 5.1 MonsterAgent 类

```python
# core/monster_agent.py

from typing import Any, Dict, List, Optional
import time

class MonsterAgent:
    """全局态势Agent：汇聚12器官状态，支持自然语言对话和工具调用。

    职责边界：
    - 汇总全局态势，注入对话上下文
    - 通过工具调用查询/控制器官
    - 不替代双脑做防御决策（那是 brain_left/brain_right 的职责）
    """

    def __init__(
        self,
        config: MonsterAgentConfig,
        toolbox: SkillToolbox,
        bus: MessageBus,
        llm_client: LLMClient,
    ):
        self.cfg = config
        self.toolbox = toolbox
        self.bus = bus
        self.llm = llm_client

        # 会话记忆: session_id → [{"role": "user/assistant/tool", "content": ...}]
        self._sessions: Dict[str, List[Dict]] = {}

        # 全局态势缓存 (TTL 刷新)
        self._posture_cache: Optional[Dict] = None
        self._posture_cache_time: float = 0.0

        # 态势提供者回调 (由 runner 注入各器官查询入口)
        self._posture_providers: Dict[str, Callable] = {}

        self._start_time = time.time()

    # ── 态势提供者注册 ──
    def register_posture_provider(self, name: str,
                                  callback: Callable[[], Dict]) -> None:
        """注册态势数据提供者。

        runner 启动时注入各器官查询入口:
            monster.register_posture_provider("alarm", alarm_nose.get_status)
            monster.register_posture_provider("health", medic.get_health_snapshot)
        """
        self._posture_providers[name] = callback

    # ── 全局态势汇总 ──
    def gather_global_posture(self, force_refresh: bool = False) -> Dict[str, Any]:
        """汇聚12器官状态，生成全局态势快照。

        这是小怪兽的核心能力——"知道系统现在在防什么"。
        """
        now = time.time()
        if (not force_refresh
                and self._posture_cache
                and now - self._posture_cache_time < self.cfg.context_refresh_sec):
            return self._posture_cache

        posture: Dict[str, Any] = {}
        for name, provider in self._posture_providers.items():
            try:
                posture[name] = provider()
            except Exception as e:
                posture[name] = {"error": str(e)}

        posture["_meta"] = {
            "timestamp": now,
            "uptime_sec": now - self._start_time,
            "providers": list(self._posture_providers.keys()),
        }

        self._posture_cache = posture
        self._posture_cache_time = now
        return posture

    def _build_system_prompt(self, posture: Dict) -> str:
        """构建系统提示词，注入全局态势上下文。"""
        posture_text = self._format_posture(posture)

        return f"""你是 DFU 小怪兽，一个仿生分层双脑分布式AI防御战斗单元的全局管理助手。

你可以查看当前系统的防御态势，并通过工具调用查询和控制各个防御器官。

## 当前系统态势
{posture_text}

## 你的能力边界
- 你可以查询任何器官的状态、最近的威胁事件、当前告警等级
- 高危操作（封锁IP、关闭端口）需要人工确认后才能执行
- 你不替代左脑/右脑做防御决策，但可以查询它们的决策结果
- 回答要简洁专业，用中文

## 可用工具
你可以调用以下工具来获取信息或执行操作。工具列表会随系统配置动态变化。"""

    def _format_posture(self, posture: Dict) -> str:
        """把态势字典格式化为可读文本。"""
        lines = []
        alarm = posture.get("alarm", {})
        if alarm:
            lines.append(f"告警等级: {alarm.get('level', 'L0')}")
            if alarm.get("countdown_remaining"):
                lines.append(f"倒计时: {alarm['countdown_remaining']}s")

        health = posture.get("health", {})
        if health:
            total = health.get("total_organs", 0)
            healthy = health.get("healthy_organs", 0)
            lines.append(f"器官健康: {healthy}/{total} 正常")

        threats = posture.get("threats", {})
        if threats:
            lines.append(f"活跃威胁: {threats.get('active_count', 0)}")

        fsm = posture.get("fsm", {})
        if fsm:
            active = fsm.get("active_ips", [])
            lines.append(f"活跃FSM: {len(active)} 个IP")

        if not lines:
            return "(系统刚启动，暂无态势数据)"
        return "\n".join(f"  - {l}" for l in lines)

    # ── 对话主循环 (ReAct 模式) ──
    async def chat(
        self,
        session_id: str,
        user_message: str,
    ) -> Dict[str, Any]:
        """处理用户消息，返回回复。

        ReAct (Reason + Act) 单轮循环:
        1. 注入态势上下文 + 工具定义
        2. 调用 LLM
        3. 如果 LLM 返回工具调用 → 执行 → 结果回灌 → 再次调用 LLM
        4. 返回最终文本回复

        Returns:
            {
                "reply": str,           # 回复文本
                "tools_used": [...],    # 本次调用的工具
                "needs_confirm": [...], # 需确认的高危工具
            }
        """
        history = self._sessions.setdefault(session_id, [])
        history.append({"role": "user", "content": user_message})
        # 截断历史
        if len(history) > self.cfg.max_history * 2:
            history[:] = history[-(self.cfg.max_history * 2):]

        posture = self.gather_global_posture()
        system_prompt = self._build_system_prompt(posture)
        tool_schemas = self.toolbox.get_tool_schemas_for_llm()

        tools_used = []
        needs_confirm = []

        # ReAct 循环 (最多3轮工具调用，防无限循环)
        for _ in range(3):
            llm_response = await self.llm.chat_with_tools(
                system_prompt=system_prompt,
                messages=history,
                tools=tool_schemas,
            )

            # LLM 没要求工具调用 → 直接返回文本
            if not llm_response.get("tool_calls"):
                reply = llm_response.get("content", "")
                history.append({"role": "assistant", "content": reply})
                return {"reply": reply, "tools_used": tools_used,
                        "needs_confirm": needs_confirm}

            # 处理工具调用
            for tool_call in llm_response["tool_calls"]:
                tool_name = tool_call["function"]["name"]
                tool_args = json.loads(tool_call["function"]["arguments"])

                result = await self.toolbox.invoke(
                    tool_name, tool_args, caller="monster"
                )

                tools_used.append({
                    "tool": tool_name,
                    "params": tool_args,
                    "success": result.get("success", False),
                })

                if result.get("needs_confirm"):
                    needs_confirm.append({
                        "tool": tool_name,
                        "params": tool_args,
                    })
                    tool_result_str = f"⚠️ 高危操作需确认: {tool_name}({tool_args})"
                else:
                    tool_result_str = json.dumps(
                        result.get("result", result.get("error")),
                        ensure_ascii=False
                    )

                # 工具结果回灌到对话历史
                history.append({"role": "tool", "name": tool_name,
                                "content": tool_result_str})

            # 继续循环，让 LLM 基于工具结果生成最终回复

        return {
            "reply": "已执行多轮工具调用，请查看工具执行结果。",
            "tools_used": tools_used,
            "needs_confirm": needs_confirm,
        }

    def clear_session(self, session_id: str) -> None:
        """清除会话记忆。"""
        self._sessions.pop(session_id, None)
```

### 5.2 与现有 LLMClient 的集成

现有 `core/llm_client.py` 的 `chat()` 方法不支持 function calling。需要新增方法:

```python
# core/llm_client.py 新增方法

async def chat_with_tools(
    self,
    system_prompt: str,
    messages: List[Dict],
    tools: List[Dict],
) -> Dict[str, Any]:
    """带工具调用的对话 (OpenAI function calling 协议)。

    Returns:
        {
            "content": str,          # 文本回复 (可能为空)
            "tool_calls": [          # 工具调用请求 (可能为空)
                {"function": {"name": "...", "arguments": "..."}},
                ...
            ],
        }
    """
    if self.mock_mode:
        return self._mock_tool_response(system_prompt, messages, tools)

    payload = {
        "model": self.config.model,
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "tools": tools,
        "tool_choice": "auto",
    }

    response = await self._http_post("/chat/completions", payload)
    msg = response["choices"][0]["message"]

    return {
        "content": msg.get("content", ""),
        "tool_calls": msg.get("tool_calls", []),
    }
```

mock 模式下，简单返回"我已收到你的消息"+ 不调用工具，保证无 LLM key 也能跑通。

---

## 六、两者如何联动

### 6.1 Runner 装配流程

```python
# core/runner.py 修改 — 在 start_all_agents 中初始化 toolbox + monster

class DFUPrototypeRunner(ScenarioRunnerMixin):
    def __init__(self, config, recorder, stage, llm_client):
        ...
        # 新增: 工具箱 + 小怪兽
        self.toolbox = SkillToolbox(config.skill_toolbox)
        self.monster = MonsterAgent(
            config.monster_agent,
            toolbox=self.toolbox,
            bus=self.bus,
            llm_client=llm_client,
        )

    async def start_all_agents(self):
        await super().start_all_agents()

        # 1. 加载内置工具
        from skills.builtins import register as register_builtins
        register_builtins(self.toolbox)

        # 2. 注入内置工具的 posture provider (查全局态势用)
        from skills.builtins import _get_posture
        _get_posture._provider = self.monster.gather_global_posture

        # 3. 加载外部插件 (skills/ 目录)
        loader = SkillLoader(self.toolbox, self.config.skill_toolbox.skills_dir)
        loader.load_all()

        # 4. 注册态势提供者
        self.monster.register_posture_provider(
            "alarm", self.alarm_nose.get_status)
        self.monster.register_posture_provider(
            "health", self.medic_agent.get_health_snapshot)
        self.monster.register_posture_provider(
            "threats", self.recorder.get_recent_threats)
        self.monster.register_posture_provider(
            "fsm", self.fsm_manager.get_active_summary)
        self.monster.register_posture_provider(
            "monitor", self.monitor.get_organ_metrics)

        logger.info(f"[Runner] Skill工具箱已就绪: "
                    f"{len(self.toolbox.list_tools())} 个工具, "
                    f"小怪兽已激活")
```

### 6.2 数据流

```
用户: "现在系统在防什么攻击？"
  │
  ▼
web_server.py /api/chat (改造后)
  │ session_id = "browser-xxx"
  │ 调用 self.monster.chat(session_id, "现在系统在防什么攻击？")
  │
  ▼
MonsterAgent.chat()
  │ 1. gather_global_posture() → 获取 alarm/health/threats/fsm 快照
  │ 2. 注入 system_prompt + tool_schemas
  │ 3. 调用 LLM (with tools)
  │
  ▼
LLM 返回: tool_calls=[{name: "query_threats", args: {limit: 5}}]
  │
  ▼
MonsterAgent 执行:
  │ result = await toolbox.invoke("query_threats", {limit: 5})
  │   → handler 调用 event_recorder.get_recent_threats(limit=5)
  │   → 返回 [{ip:1.2.3.4, type:ddos, severity:high}, ...]
  │ 回灌到对话: {"role":"tool", "content":"[{ip:1.2.3.4,...}]"}
  │ 再次调用 LLM
  │
  ▼
LLM 返回文本: "当前有3个活跃威胁: 1.2.3.4 (DDoS高危)、
              5.6.7.8 (端口扫描中危)、9.10.11.12 (暴力破解低危)。"
  │
  ▼
返回前端: {"reply": "...", "tools_used": [{"tool":"query_threats",...}]}
```

高危操作确认流程:

```
用户: "帮我封锁 1.2.3.4"
  │
  ▼
LLM 返回: tool_calls=[{name: "block_ip", args: {ip: "1.2.3.4"}}]
  │
  ▼
MonsterAgent 执行:
  │ result = await toolbox.invoke("block_ip", {ip:"1.2.3.4"})
  │   → risk_level="high", caller="monster", 非 force
  │   → 返回 {needs_confirm: True, error: "高危工具 block_ip 需要人工确认"}
  │
  ▼
MonsterAgent 返回:
  │ {"reply": "封锁 1.2.3.4 是高危操作，已生成确认请求。",
  │  "needs_confirm": [{"tool": "block_ip", "params": {"ip":"1.2.3.4"}}]}
  │
  ▼
前端显示确认按钮: [确认封锁 1.2.3.4] [取消]
  │
  ▼
用户点击确认 → POST /api/skill-box/confirm
  │ body: {tool_id: "block_ip", params: {ip:"1.2.3.4"}, token: "..."}
  │
  ▼
web_server 调用 toolbox.invoke("block_ip", params, caller="user", force=True)
  │ → 实际执行封锁
```

---

## 七、安全约束

与 `interference.py` 风格一致，硬编码不可关闭:

| 约束 | 说明 |
|------|------|
| **默认只读** | 内置工具中查询类 (`query_*`, `get_posture`) 为 low risk，可直接调用 |
| **高危确认** | 写操作 (`block_ip`, `close_port`, `nmap_scan`) 为 high risk，必须人工确认 |
| **调用者分级** | `caller` 分 `monster`/`user`/`system` 三级，只有 `system` 可 `force=True` 跳过确认 |
| **全审计** | 每次 `invoke` 记录 timestamp/tool/caller/params/result/latency 到 `_call_log` |
| **kill-switch 联动** | 全局熔断 (meltdown) 开启时，工具箱自动禁用所有 high risk 工具 |
| **超时保护** | 每个工具有 `timeout_sec`，默认30s，外部命令最长120s |
| **插件沙箱** | 外部插件加载失败不影响系统运行 (`try/except` 包裹) |
| **会话隔离** | 每个 `session_id` 独立记忆，不串扰 |

kill-switch 联动实现:

```python
# organs/skill_box.py

class SkillToolbox:
    def set_meltdown(self, active: bool) -> None:
        """熔断激活时，禁用所有高危工具。"""
        for tool in self._tools.values():
            if tool.risk_level == "high":
                tool.enabled = not active
        logger.warning(f"[SkillToolbox] 熔断{'激活' if active else '解除'}，"
                       f"高危工具已{'禁用' if active else '恢复'}")
```

---

## 八、配置项

新增到 `config.py`:

```python
@dataclass
class SkillToolboxConfig:
    """技能工具箱配置。"""
    skills_dir: str = "skills"           # 外部插件目录
    enable_builtin: bool = True          # 是否加载内置工具
    enable_external: bool = True         # 是否加载外部插件
    call_log_max: int = 500              # 审计日志最大条数
    default_timeout_sec: float = 30.0    # 默认调用超时
    require_confirm_risk: str = "high"   # 需确认的风险等级阈值
    meltdown_disables_high_risk: bool = True  # 熔断时禁用高危工具


@dataclass
class MonsterAgentConfig:
    """小怪兽全局Agent配置。"""
    context_refresh_sec: float = 5.0     # 态势上下文刷新间隔 (秒)
    max_history: int = 20                # 对话历史最大轮数 (user+assistant)
    enable_tool_use: bool = True         # 是否启用工具调用
    max_tool_rounds: int = 3             # 单轮对话最大工具调用轮数
    posture_cache_ttl_sec: float = 5.0   # 态势缓存有效期


# 合并到 Config 主类:
@dataclass
class Config:
    ...
    skill_toolbox: SkillToolboxConfig = field(default_factory=SkillToolboxConfig)
    monster_agent: MonsterAgentConfig = field(default_factory=MonsterAgentConfig)
```

---

## 九、API端点

### 9.1 改造现有端点

**`POST /api/chat`** — 从裸代理改为有状态Agent对话:

```python
@app.post("/api/chat")
async def api_chat(request: Request, _: bool = Depends(verify_token)):
    """小怪兽对话 (改造后)。"""
    body = await request.json()
    session_id = body.get("session_id", "default")
    message = body["message"]

    result = await manager.monster.chat(session_id, message)

    return {
        "reply": result["reply"],
        "tools_used": result.get("tools_used", []),
        "needs_confirm": result.get("needs_confirm", []),
        "session_id": session_id,
    }
```

向后兼容：前端不需要改 `sendChat()` 的调用方式，只是返回结构多了字段。

### 9.2 新增 Skill 工具箱端点

```
GET    /api/skill-box/tools           — 列出所有工具
GET    /api/skill-box/tools/{id}      — 查询单个工具详情
POST   /api/skill-box/tools/{id}/enable   — 启用工具
POST   /api/skill-box/tools/{id}/disable  — 禁用工具
GET    /api/skill-box/call-log        — 查询调用审计日志
GET    /api/skill-box/stats           — 工具箱统计
POST   /api/skill-box/confirm         — 确认高危操作
POST   /api/skill-box/reload          — 重新加载外部插件
```

`/api/skill-box/confirm` 详细:

```python
@app.post("/api/skill-box/confirm")
async def confirm_tool(body: dict, _: bool = Depends(verify_token)):
    """确认高危工具调用。"""
    tool_id = body["tool_id"]
    params = body["params"]
    token = body.get("confirm_token", "")

    # 验证 confirm_token (防 CSRF)
    if not manager.toolbox.verify_confirm_token(tool_id, token):
        raise HTTPException(403, "确认令牌无效或已过期")

    result = await manager.toolbox.invoke(
        tool_id, params, caller="user", force=True
    )
    return result
```

---

## 十、前端改造

### 10.1 Skill工具箱页面 (已有UI骨架)

现有 monster.html 已有 skill-box 器官卡片定义，只需把 demo 数据替换为真实 API 调用:

```javascript
// monster.html — 修改 skill-box 数据获取

async function loadSkillBoxData() {
    const resp = await fetch('/api/skill-box/tools', {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const tools = await resp.json();

    // 渲染工具表格
    const tableRows = tools.map(t => [
        t.name_zh,
        t.category,
        t.enabled ? 'On' : 'Off',
        t.call_count
    ]);

    // 渲染统计
    const stats = await (await fetch('/api/skill-box/stats')).json();

    updateOrganData('skill-box', {
        metrics: [stats.total_tools, stats.enabled, stats.total_calls],
        tableRows: tableRows,
    });
}

// 启用/禁用开关
async function toggleTool(toolId, enable) {
    const endpoint = enable ? 'enable' : 'disable';
    await fetch(`/api/skill-box/tools/${toolId}/${endpoint}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    loadSkillBoxData();
}
```

### 10.2 小怪兽聊天框 (改造)

现有聊天框 UI 不变，但需要处理新的返回结构:

```javascript
// monster.html — 改造 sendChat()

async function sendChat() {
    const message = chatInput.value.trim();
    if (!message) return;

    addMessage('user', message);
    chatInput.value = '';

    const resp = await fetch('/api/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            session_id: currentSessionId,
            message: message
        })
    });

    const data = await resp.json();

    // 显示回复
    addMessage('monster', data.reply);

    // 显示工具调用过程 (如果有)
    if (data.tools_used && data.tools_used.length) {
        for (const t of data.tools_used) {
            const icon = t.success ? '✓' : '✗';
            addMessage('system', `${icon} 调用工具: ${t.tool}`);
        }
    }

    // 显示高危确认按钮 (如果有)
    if (data.needs_confirm && data.needs_confirm.length) {
        for (const c of data.needs_confirm) {
            addConfirmButton(c.tool, c.params);
        }
    }
}

function addConfirmButton(tool, params) {
    const btn = document.createElement('button');
    btn.textContent = `确认执行 ${tool}(${JSON.stringify(params)})`;
    btn.className = 'confirm-btn';
    btn.onclick = async () => {
        await fetch('/api/skill-box/confirm', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ tool_id: tool, params: params })
        });
        btn.remove();
        addMessage('system', `已执行 ${tool}`);
    };
    chatMessages.appendChild(btn);
}
```

---

## 十一、文件清单

| 操作 | 文件 | 预估行数 | 说明 |
|:----:|------|:--------:|------|
| **新增** | `organs/skill_box.py` | ~400 | SkillToolbox + SkillTool + SkillLoader |
| **新增** | `core/monster_agent.py` | ~350 | MonsterAgent 全局态势+对话+ReAct |
| **新增** | `skills/builtins.py` | ~200 | 7个内置工具 (query_*, block_ip, close_port等) |
| **新增** | `skills/_template.py` | ~50 | 插件开发模板 (供用户参考) |
| **新增** | `skills/README.md` | ~80 | 插件开发文档 |
| **修改** | `config.py` | +30 | SkillToolboxConfig + MonsterAgentConfig |
| **修改** | `core/llm_client.py` | +60 | 新增 `chat_with_tools()` 方法 |
| **修改** | `core/runner.py` | +40 | 初始化 toolbox + monster + posture providers |
| **修改** | `web_server.py` | +120 | 改造 /api/chat + 新增 /api/skill-box/* 端点 |
| **修改** | `static/monster.html` | +80 | skill-box 真实数据 + 聊天框工具调用展示 |
| **修改** | `organs/__init__.py` | +2 | 导出 SkillToolbox |

**总计：新增 ~1080 行，修改 ~330 行**

---

## 十二、实施阶段

### 阶段 1: Skill工具箱基础 (2-3天)

**目标：工具注册/调用/审计框架跑通**

- [ ] `organs/skill_box.py` — SkillTool + SkillToolbox + SkillLoader
- [ ] `config.py` — SkillToolboxConfig
- [ ] `skills/builtins.py` — 先实现3个只读工具 (get_posture, query_organ, query_threats)
- [ ] `web_server.py` — `/api/skill-box/tools`、`/stats`、`/call-log` 端点
- [ ] `static/monster.html` — skill-box 器官显示真实工具列表

**验收：前端能看到真实工具列表，能启用/禁用，能看到调用日志。**

### 阶段 2: 小怪兽上下文注入 (2天)

**目标：怪兽能回答"现在系统在防什么"**

- [ ] `core/monster_agent.py` — MonsterAgent 基础类
- [ ] `core/llm_client.py` — `chat_with_tools()` (先只支持文本，mock模式能跑)
- [ ] `core/runner.py` — 注册 posture providers
- [ ] `web_server.py` — 改造 `/api/chat` 调用 `monster.chat()`

**验收：问"现在告警什么等级"、"系统健康吗" → 怪兽能基于真实状态回答。**

### 阶段 3: 工具调用闭环 (2-3天)

**目标：怪兽能通过工具调用查询/操作**

- [ ] `core/llm_client.py` — `chat_with_tools()` 支持 function calling (real模式)
- [ ] `core/monster_agent.py` — ReAct 循环
- [ ] `skills/builtins.py` — 补全 block_ip, close_port, ack_alarm (high risk)
- [ ] `web_server.py` — `/api/skill-box/confirm` 端点
- [ ] `static/monster.html` — 聊天框显示工具调用过程 + 确认按钮

**验收：说"封锁1.2.3.4" → 怪兽请求确认 → 点确认 → 真的封锁。**

### 阶段 4: 外部插件加载 (1-2天)

**目标：用户能自己写技能插件**

- [ ] `SkillLoader` 完善 (错误处理、热重载)
- [ ] `skills/_template.py` — 插件模板
- [ ] `skills/README.md` — 开发文档
- [ ] `web_server.py` — `/api/skill-box/reload` 端点
- [ ] 提供 1-2 个示例插件 (nmap_scan, tcpdump_capture)

**验收：在 skills/ 目录放一个 .py 文件，重启后工具箱自动加载。**

### 阶段 5 (可选): 进阶能力

- 多轮任务规划 (从单轮 ReAct 升级到多步 Plan-Execute)
- 工具调用链 (一个工具的输出作为另一个工具的输入)
- 态势主动推送 (告警升级时怪兽主动通知用户)
- 冲突消解 (左脑说monitor、右脑说block时怪兽仲裁)

---

## 附录：设计决策记录

### 为什么 MonsterAgent 不做成独立的 MessageBus 订阅者？

考虑过让 MonsterAgent 订阅 `merged_threat_alert` 等事件、实时维护全局状态。但:
- 会增加事件处理复杂度
- 态势数据有 TTL 缓存就够了，不需要实时
- 对话场景下按需拉取 (pull) 比事件推送 (push) 更简单可控

**决定：用 posture provider 回调 + TTL 缓存，按需拉取。**

### 为什么工具调用用 OpenAI function calling 协议？

- 现有 LLMClient 已经兼容 OpenAI API
- function calling 是业界标准，DeepSeek/火山引擎/Ollama 都支持
- 不需要自己定义协议

### 为什么高危确认用 confirm_token 而不是简单二次调用？

- 防止 CSRF (用户在别的页面被诱导点击)
- confirm_token 有时效 (默认60秒)，过期需重新请求
- 与 alarm_nose 的 ack 机制风格一致

---

> 本方案待评审。确认后按阶段1开始实施。
