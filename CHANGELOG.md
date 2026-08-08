# Changelog

本文件记录 MonsterDFU / dfu_prototype 的版本变更历史。

## [0.3.0] - 2026-08-08

### 安全修复批次
- Bootstrap 首访保护：新增 `DFU_BOOTSTRAP_TOKEN` 环境变量 + `X-Bootstrap-Token` / `?bootstrap=` 换取 token，`secrets.compare_digest` 常量时间比较
- SSRF 防护：`_ssrf_check_url()` 拒绝回环 / 私网 / 链路本地 / 云元数据 / 字面量地址（含整数与十六进制字面量归一化、DNS 解析、重定向逐跳复检）
- Bearer 鉴权：`_extract_bearer_token` / `_validate_token` 统一 token 解析与过期校验
- 鉴权白名单精确匹配：`/api/token-usage` 不再被 `/api/token` 前缀连带放行
- iptables 返回契约修复：`_run_iptables` 返回结构统一
- LLM 降级标注：真实调用失败降级时返回体带 `degraded: true`
- 器官独立配置分发：`build_organ_llm_config` 按器官分发独立配置
- 密钥 `.bak` 防护、`.gitignore` 补充 `*.key`

### 回归测试
- 新增 3 个安全回归测试文件（web 27 例 / llm 6 例 / organs 10 例，共 43 例），锁定本轮安全修复行为
- `tests/test_security_regression_web.py`
- `tests/test_security_regression_llm.py`
- `tests/test_security_regression_organs.py`

### 生产化收尾
- 移除 `docker-compose.yml` 中未接入的 rabbitmq 死配置（服务 / volume / depends_on / 环境变量）
- 迁移 `AttackSimulator` 从 `tests/` 至 `core/simulate_attack.py`，解除生产代码对测试目录的依赖
- 拆分可选依赖：`chromadb`、`sentence-transformers` 移入 `[project.optional-dependencies] ml`，安装可选 ML 功能执行 `pip install .[ml]`
- 依赖锁定：新增 `requirements.lock`（pip freeze 生成），保证可复现构建
- `/metrics`（Prometheus 端点）增加 Bearer 认证，与现有 `_check_auth` 统一
- 版本管理：`core/__init__.py` 新增 `__version__ = "0.3.0"`，pyproject 同步升级
- 死代码清理：移除 `LLMClient._call_log`（0 次 append）及 `get_call_log`；`brain_left.py` 决策截断增加空列表保护；`main.py --capture` 参数矛盾修复（BooleanOptionalAction）；`event_aggregator.py` 3 处 `__import__("time")` 改为正常 `import time`
- CI 增加 pip-audit 依赖漏洞扫描步骤（失败不阻断，仅 warning）
