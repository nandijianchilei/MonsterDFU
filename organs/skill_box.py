"""Skill 技能工具箱：技能注册、管理、调用、审计与高危确认。

设计来源：DFU_Skill工具箱与小怪兽全局Agent设计方案_优化版（v2）
- SkillTool：单个技能定义（SKILL.md 标准 + DFU 扩展字段）
- SkillToolbox：注册 / 查询 / 调用 / 高危确认 / 审计 / 熔断联动
- SkillLoader：扫描 skills/ 目录渐进式加载 + 热重载

执行依赖注入：
    技能 handler 统一签名 async def handler(params: dict) -> dict，
    需要访问系统对象（MessageBus / DFUWebManager）时通过
    set_skill_env(**kwargs) 注入全局环境，handler 内 get_skill_env() 取用。
"""
import asyncio
import importlib.util
import logging
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("SkillBox")

# ── 全局技能执行环境（集成方注入）──
_SKILL_ENV: Dict[str, Any] = {}


def set_skill_env(**kwargs: Any) -> None:
    """注入技能执行所需环境（bus / manager / recorder 等）。"""
    _SKILL_ENV.update(kwargs)


def get_skill_env() -> Dict[str, Any]:
    """技能 handler 获取执行环境。"""
    return _SKILL_ENV


@dataclass
class SkillTool:
    """单个技能工具的定义。"""
    tool_id: str                    # 唯一ID (SKILL.md 的 name 字段)
    name_zh: str                    # 中文名
    name_en: str                    # 英文名
    description: str                # LLM 可读的功能描述
    instructions: str = ""          # SKILL.md 全文 (激活时加载)

    # DFU 扩展属性
    category: str = "utility"       # attack | defense | recon | utility | dispatch
    enabled: bool = True
    risk_level: str = "low"         # low | medium | high
    timeout_sec: float = 30.0
    organ_target: str = ""          # dispatch 类技能的目标器官

    # 执行函数: async def(params: dict) -> dict
    handler: Optional[Callable[[Dict], Awaitable[Dict]]] = None

    # 参数 schema (OpenAI function calling 格式)
    param_schema: Dict[str, Any] = field(default_factory=lambda: {
        "type": "object",
        "properties": {},
    })

    # 调用统计
    call_count: int = 0
    last_called: float = 0.0

    # 技能来源路径 (用于前端展示和热重载)
    skill_dir: str = ""


class SkillToolbox:
    """技能工具箱：技能注册、管理、调用、审计。"""

    def __init__(self, config: "SkillToolboxConfig"):
        self.cfg = config
        self._tools: Dict[str, SkillTool] = {}
        self._call_log: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._confirm_tokens: Dict[str, Dict[str, Any]] = {}  # token → {tool_id, params, expire}
        self._ratelimit: Dict[str, List[float]] = {}          # tool_id → [timestamps]
        self._meltdown = False

    # ── 注册管理 ──
    def register(self, tool: SkillTool) -> None:
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
    def list_tools(self, category: Optional[str] = None,
                   enabled_only: bool = False) -> List[SkillTool]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        if enabled_only:
            tools = [t for t in tools if t.enabled]
        return tools

    def get_tool(self, tool_id: str) -> Optional[SkillTool]:
        return self._tools.get(tool_id)

    def get_instructions(self, tool_id: str) -> str:
        """获取技能的详细指令 (SKILL.md 全文)。渐进式加载: 怪兽激活技能时调用。"""
        tool = self._tools.get(tool_id)
        return tool.instructions if tool else ""

    def get_tool_schemas_for_llm(self) -> List[Dict[str, Any]]:
        """生成 OpenAI function calling 格式的工具定义列表。只返回 enabled=True 的技能。"""
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

    # ── 限频（安全约束 #5：每技能最多 5/min）──
    def _check_ratelimit(self, tool_id: str) -> bool:
        if self.cfg.ratelimit_per_min <= 0:
            return True
        now = time.time()
        stamps = [t for t in self._ratelimit.get(tool_id, []) if now - t < 60]
        self._ratelimit[tool_id] = stamps
        if len(stamps) >= self.cfg.ratelimit_per_min:
            return False
        self._ratelimit[tool_id].append(now)
        return True

    # ── 调用 ──
    async def invoke(self, tool_id: str, params: Dict[str, Any],
                     caller: str = "monster",
                     force: bool = False) -> Dict[str, Any]:
        """调用技能。

        Args:
            tool_id: 技能ID
            params: 参数
            caller: 调用者 (monster / user / system)
            force: 是否跳过高危确认 (仅 system 可用)

        Returns:
            {"success": bool, "result": ..., "error": ...,
             "needs_confirm": bool, "confirm_token": ...}
        """
        async with self._lock:
            tool = self._tools.get(tool_id)
            if not tool:
                return {"success": False, "error": f"技能 {tool_id} 不存在"}
            if not tool.enabled:
                return {"success": False, "error": f"技能 {tool_id} 已禁用"}
            if not tool.handler:
                return {"success": False, "error": f"技能 {tool_id} 无执行函数"}
            if self._meltdown and tool.risk_level == "high":
                return {"success": False, "error": "系统熔断中，高危技能已禁用"}
            if not self._check_ratelimit(tool_id):
                return {"success": False,
                        "error": f"技能 {tool_id} 调用频率超限（{self.cfg.ratelimit_per_min}/min）"}

            # 高危操作拦截
            if tool.risk_level == "high" and not force and caller != "system":
                token = self._issue_confirm_token(tool_id, params)
                return {
                    "success": False,
                    "needs_confirm": True,
                    "error": f"高危技能 {tool_id} 需要人工确认",
                    "params": params,
                    "confirm_token": token,
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

    # ── 高危确认 ──
    def _issue_confirm_token(self, tool_id: str, params: dict) -> str:
        """生成一次性确认 token（60秒有效）。"""
        token = secrets.token_hex(8)
        self._confirm_tokens[token] = {
            "tool_id": tool_id,
            "params": params,
            "expire": time.time() + self.cfg.confirm_token_ttl_sec,
        }
        return token

    async def confirm(self, confirm_token: str, approved: bool = True,
                      caller: str = "user") -> Dict[str, Any]:
        """用户确认/取消高危技能执行。

        Args:
            confirm_token: invoke 时下发的确认令牌
            approved: True=确认执行，False=取消
        """
        info = self._confirm_tokens.pop(confirm_token, None)
        if info is None:
            return {"success": False, "error": "确认令牌不存在或已过期"}
        if time.time() > info["expire"]:
            return {"success": False, "error": "确认令牌已过期（60s），请重新发起操作"}
        if not approved:
            self._log_call(info["tool_id"], info["params"], None, caller,
                           0.0, success=False, error="用户取消")
            return {"success": False, "cancelled": True,
                    "message": "操作已取消"}

        # 确认通过：强制重放（跳过确认拦截）
        return await self.invoke(
            info["tool_id"], info["params"], caller=caller, force=True,
        )

    def verify_confirm_token(self, tool_id: str, token: str) -> bool:
        now = time.time()
        self._confirm_tokens = {k: v for k, v in self._confirm_tokens.items()
                                if v["expire"] > now}
        info = self._confirm_tokens.get(token)
        return bool(info and info["tool_id"] == tool_id)

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
                     tool_id: Optional[str] = None) -> List[Dict[str, Any]]:
        logs = self._call_log[-limit:]
        if tool_id:
            logs = [l for l in logs if l["tool_id"] == tool_id]
        return logs

    # ── 统计 (前端展示) ──
    def get_stats(self) -> Dict[str, Any]:
        tools = list(self._tools.values())
        return {
            "total_tools": len(tools),
            "enabled": sum(1 for t in tools if t.enabled),
            "by_category": {
                cat: sum(1 for t in tools if t.category == cat)
                for cat in ("attack", "defense", "recon", "dispatch", "utility")
            },
            "total_calls": sum(t.call_count for t in tools),
            "recent_calls": len(self._call_log),
        }

    def get_status(self) -> Dict[str, Any]:
        """态势 provider 用：返回工具箱精简状态。"""
        stats = self.get_stats()
        return {
            "total_tools": stats["total_tools"],
            "enabled": stats["enabled"],
            "total_calls": stats["total_calls"],
        }

    # ── kill-switch 联动 ──
    def set_meltdown(self, active: bool) -> None:
        """熔断激活时，禁用所有高危技能。"""
        self._meltdown = active
        for tool in self._tools.values():
            if tool.risk_level == "high":
                tool.enabled = not active
        logger.warning(f"[SkillToolbox] 熔断{'激活' if active else '解除'}，"
                       f"高危技能已{'禁用' if active else '恢复'}")


class SkillLoader:
    """扫描 skills/ 目录，加载符合 Agent Skills 标准的技能。"""

    def __init__(self, toolbox: SkillToolbox, skills_dir: str):
        self.toolbox = toolbox
        self.skills_dir = Path(skills_dir)

    def load_all(self) -> int:
        """递归扫描并加载所有技能。

        每个 skill 是一个目录（支持多级嵌套，如 _builtins/recon/get-posture/），
        目录内包含 SKILL.md。
        返回成功加载的技能数量。
        """
        if not self.skills_dir.exists():
            logger.info(f"[SkillLoader] skills 目录不存在: {self.skills_dir}")
            return 0

        count = 0
        for skill_md in sorted(self.skills_dir.rglob("SKILL.md")):
            skill_dir = skill_md.parent
            if skill_dir.name.startswith("."):
                continue
            try:
                self._load_skill(skill_dir, skill_md)
                count += 1
            except Exception as e:
                logger.error(f"[SkillLoader] 加载 {skill_dir.name} 失败: {e}")

        logger.info(f"[SkillLoader] 已加载 {count} 个技能")
        return count

    def reload(self) -> Dict[str, Any]:
        """热重载: 清空非内置技能后重新扫描。"""
        removed = []
        builtin_prefix = str((self.skills_dir / "_builtins").resolve())
        for tid in list(self.toolbox._tools.keys()):
            tool = self.toolbox._tools[tid]
            try:
                is_builtin = str(Path(tool.skill_dir).resolve()).startswith(builtin_prefix)
            except Exception:
                is_builtin = False
            if not is_builtin:
                self.toolbox.unregister(tid)
                removed.append(tid)
        loaded = self.load_all()
        return {"removed": removed, "loaded": loaded}

    def _load_skill(self, skill_dir: Path, skill_md: Path):
        """加载单个技能目录。"""
        # 1. 解析 SKILL.md (YAML frontmatter + markdown body)
        frontmatter, body = self._parse_skill_md(skill_md)

        # 2. 提取标准字段
        name = frontmatter.get("name", skill_dir.name)
        description = frontmatter.get("description", "")

        # 3. 提取 DFU 扩展字段 (有则用，无则默认值)
        dfu_meta = frontmatter.get("metadata", {}).get("dfu", {})

        # 4. 加载 handler
        handler = None
        handler_rel = dfu_meta.get("handler", "scripts/handler.py")
        handler_path = skill_dir / handler_rel
        if handler_path.exists():
            handler = self._load_handler(handler_path)

        # 5. 注册到工具箱
        self.toolbox.register(SkillTool(
            tool_id=name,
            name_zh=dfu_meta.get("name_zh", name),
            name_en=name,
            description=description,
            instructions=body,
            category=dfu_meta.get("category", "utility"),
            risk_level=dfu_meta.get("risk_level", "medium"),
            timeout_sec=dfu_meta.get("timeout_sec", 30.0),
            enabled=dfu_meta.get("enabled", True),
            handler=handler,
            organ_target=dfu_meta.get("organ_target", ""),
            skill_dir=str(skill_dir),
        ))

    def _parse_skill_md(self, path: Path):
        """解析 SKILL.md: YAML frontmatter + markdown body。"""
        content = path.read_text(encoding="utf-8")
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                try:
                    import yaml
                    frontmatter = yaml.safe_load(parts[1]) or {}
                except Exception:
                    frontmatter = {}
                body = parts[2].strip()
                return frontmatter, body
        return {}, content

    def _load_handler(self, path: Path):
        """动态导入 handler.py，返回 handler 异步函数。"""
        module_name = f"skill_handler_{path.parent.parent.name}_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if not hasattr(module, "handler"):
            raise ValueError(f"{path} 缺少 handler() 函数")
        return module.handler
