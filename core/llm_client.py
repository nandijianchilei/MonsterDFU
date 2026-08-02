"""
LLM 客户端：统一的 LLM API 调用接口。

支持 OpenAI 兼容 API + 内置 mock 模式。
mock 模式不需要 API key，用智能推理逻辑模拟 LLM 输出，
输出来源标注 [LLM-MOCK]，流程与真实调用完全一致。
"""

import asyncio
import copy
import json
import logging
import random
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import LLMConfig
from utils.logger import get_logger


class LLMClient:
    """
    统一的 LLM API 调用客户端。

    功能：
    - chat(): 文本对话
    - chat_json(): 返回 JSON 格式
    - 自动 mock 模式切换（无 API key 时启用）
    - 超时重试、错误处理
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger: logging.Logger = get_logger("LLMClient")
        self._mock_mode = config.mock_mode or not config.api_key
        self._call_count = 0
        self._fail_count = 0
        self._call_log: List[Dict[str, Any]] = []
        self._current_model = config.model  # 跟踪当前使用的模型
        self._backup_used = False
        self._last_latency_ms: float = 0.0  # 最近一次真实调用的延迟（被外部消费后置零）

        # Token 消耗统计（线程安全）
        self._token_lock = threading.Lock()
        self._token_usage: Dict[str, Any] = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_tokens": 0,
            "total_calls": 0,
            "by_model": {},
        }

        if self._mock_mode:
            self.logger.info("[LLM-MOCK] Mock 模式已激活，不调用真实 API")
        else:
            self.logger.info(
                f"[LLM] 火山引擎真实模式 | API: {config.api_base} | "
                f"主模型(DeepSeek 3.2): {config.model} | "
                f"备用模型(豆包1.8): {config.backup_model}"
            )

    @property
    def mock_mode(self) -> bool:
        return self._mock_mode

    @property
    def call_count(self) -> int:
        return self._call_count

    @property
    def fail_count(self) -> int:
        return self._fail_count

    def set_mock_mode(self, enabled: bool) -> None:
        """强制切换 mock 模式。"""
        if not self.config.api_key and not enabled:
            self.logger.warning("无 API key，无法切换到真实模式，保持 mock")
            return
        self._mock_mode = enabled
        self.logger.info(f"模式切换: {'mock' if enabled else '真实LLM'}")

    def _build_payload(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.3, json_mode: bool = False
    ) -> Dict[str, Any]:
        """构建 API 请求体。"""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        payload = {
            "model": self._current_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.config.max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    async def _call_api_once(
        self, payload: Dict[str, Any], json_mode: bool = False
    ) -> tuple:
        """单次 API 调用（含火山引擎错误码识别）。返回 (content, usage_dict)。"""
        import aiohttp

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }
        url = f"{self.config.api_base.rstrip('/')}/chat/completions"

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    return content, usage
                else:
                    error_text = await resp.text()
                    # 火山引擎特定错误码识别
                    volc_error = self._parse_volc_error(resp.status, error_text)
                    raise RuntimeError(volc_error)

    def _parse_volc_error(self, status_code: int, error_text: str) -> str:
        """解析火山引擎错误响应，返回人类可读错误信息。"""
        # 尝试解析 JSON 错误体
        try:
            error_data = json.loads(error_text)
            error_obj = error_data.get("error", {})
            code = error_obj.get("code", "")
            message = error_obj.get("message", "")
            if code and message:
                return f"火山引擎 API 错误 [{status_code}] code={code}: {message}"
        except (json.JSONDecodeError, AttributeError):
            pass

        # 常见火山引擎 / OpenAI 兼容错误码
        volc_errors = {
            401: "认证失败，API Key 无效或已过期",
            403: "无权限访问该模型端点（endpoint ID 无效或未授权）",
            429: "请求频率超限（Rate Limit），请稍后重试",
            500: "火山引擎内部服务错误",
            502: "火山引擎网关错误",
            503: "火山引擎服务暂时不可用（模型可能正在加载或过载）",
        }
        base_msg = volc_errors.get(status_code, f"未知 HTTP 错误")
        return f"火山引擎 API 错误 [{status_code}] {base_msg}: {error_text[:300]}"

    async def _try_with_backup(
        self, payload: Dict[str, Any], json_mode: bool = False
    ) -> tuple:
        """主模型调用失败时自动切换备用模型重试。返回 (content, usage_dict)。"""
        # 先尝试主模型
        for attempt in range(self.config.max_retries + 1):
            try:
                self._current_model = self.config.model
                self.logger.info(f"[LLM] 调用主模型 DeepSeek 3.2: {self._current_model}")
                return await self._call_api_once(payload, json_mode)
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries:
                    wait = (attempt + 1) * 2
                    self.logger.warning(
                        f"[LLM] 主模型调用失败 (尝试 {attempt + 1}/{self.config.max_retries + 1})，"
                        f"{wait}s 后重试: {e}"
                    )
                    await asyncio.sleep(wait)

        # 主模型全部失败，尝试备用模型
        self.logger.warning(
            f"[LLM] 主模型 DeepSeek 3.2 不可用，切换到备用模型 豆包1.8: {self.config.backup_model}"
        )
        for attempt in range(self.config.max_retries + 1):
            try:
                self._current_model = self.config.backup_model
                self._backup_used = True
                self.logger.info(f"[LLM] 调用备用模型 豆包1.8: {self._current_model}")
                return await self._call_api_once(payload, json_mode)
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries:
                    wait = (attempt + 1) * 2
                    self.logger.warning(
                        f"[LLM] 备用模型调用失败 (尝试 {attempt + 1}/{self.config.max_retries + 1})，"
                        f"{wait}s 后重试: {e}"
                    )
                    await asyncio.sleep(wait)

        raise RuntimeError(
            f"[LLM] 所有模型均调用失败 (主: {self.config.model}, 备: {self.config.backup_model}): {last_error}"
        )

    async def _real_chat(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.3
    ) -> str:
        """真实 API 调用（主模型 → 备用模型 自动降级）。"""
        t0 = time.time()
        payload = self._build_payload(system_prompt, user_prompt, temperature)
        result, usage = await self._try_with_backup(payload)
        self._last_latency_ms = (time.time() - t0) * 1000.0
        self._update_token_usage(usage)
        return result

    async def _real_chat_json(
        self, system_prompt: str, user_prompt: str
    ) -> Dict[str, Any]:
        """真实 API 调用 JSON 模式（主模型 → 备用模型 自动降级）。"""
        t0 = time.time()
        payload = self._build_payload(
            system_prompt, user_prompt, temperature=0.1, json_mode=True
        )
        result, usage = await self._try_with_backup(payload, json_mode=True)
        self._last_latency_ms = (time.time() - t0) * 1000.0
        self._update_token_usage(usage)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
            raise

    async def chat(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.3
    ) -> str:
        """对话接口。mock 模式下用内置逻辑生成模拟输出。"""
        self._call_count += 1
        if self._mock_mode:
            result = self._mock_chat(system_prompt, user_prompt)
            return result
        try:
            result = await self._real_chat(system_prompt, user_prompt, temperature)
            return result
        except Exception as e:
            self._fail_count += 1
            self.logger.error(f"[LLM-ERROR] API 调用失败，降级到 mock: {e}")
            result = self._mock_chat(system_prompt, user_prompt)
            return result

    async def chat_json(
        self, system_prompt: str, user_prompt: str
    ) -> Dict[str, Any]:
        """JSON 对话接口。"""
        self._call_count += 1
        if self._mock_mode:
            result = self._mock_chat_json(system_prompt, user_prompt)
            return result
        try:
            result = await self._real_chat_json(system_prompt, user_prompt)
            return result
        except Exception as e:
            self._fail_count += 1
            self.logger.error(f"[LLM-ERROR] JSON API 调用失败，降级到 mock: {e}")
            result = self._mock_chat_json(system_prompt, user_prompt)
            return result

    # ==================== Token 统计 ====================

    def _update_token_usage(self, usage: Dict[str, Any]) -> None:
        """线程安全地累加 Token 消耗。usage 为 OpenAI 响应中的 usage 字段。"""
        if not usage or self._mock_mode:
            return
        prompt = usage.get("prompt_tokens", 0)
        completion = usage.get("completion_tokens", 0)
        total = usage.get("total_tokens", 0)
        model = self._current_model

        with self._token_lock:
            self._token_usage["total_prompt_tokens"] += prompt
            self._token_usage["total_completion_tokens"] += completion
            self._token_usage["total_tokens"] += total
            self._token_usage["total_calls"] += 1

            if model not in self._token_usage["by_model"]:
                self._token_usage["by_model"][model] = {
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                    "calls": 0,
                }
            self._token_usage["by_model"][model]["prompt_tokens"] += prompt
            self._token_usage["by_model"][model]["completion_tokens"] += completion
            self._token_usage["by_model"][model]["total_tokens"] += total
            self._token_usage["by_model"][model]["calls"] += 1

    def get_token_usage(self) -> Dict[str, Any]:
        """返回当前 Token 消耗统计的深拷贝快照。"""
        with self._token_lock:
            return copy.deepcopy(self._token_usage)

    def reset_token_usage(self) -> None:
        """清零 Token 消耗统计。"""
        with self._token_lock:
            self._token_usage = {
                "total_prompt_tokens": 0,
                "total_completion_tokens": 0,
                "total_tokens": 0,
                "total_calls": 0,
                "by_model": {},
            }

    # ==================== Mock 模式实现 ====================

    def _mock_chat(self, system_prompt: str, user_prompt: str) -> str:
        """mock 模式的文本输出。"""
        # 尝试解析输入中的告警信息
        alerts_info = self._extract_alerts_from_prompt(user_prompt)

        if "左脑" in system_prompt or "分析引擎" in system_prompt or "后勤防御" in system_prompt:
            return self._mock_left_brain_output(alerts_info)
        elif "右脑" in system_prompt or "响应引擎" in system_prompt or "修复反击" in system_prompt:
            return self._mock_right_brain_output(alerts_info)
        else:
            # 通用 mock：生成合理的推理文本
            return self._mock_generic_output(system_prompt, alerts_info)

    def _mock_chat_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """mock 模式的 JSON 输出。"""
        alerts_info = self._extract_alerts_from_prompt(user_prompt)

        if "左脑" in system_prompt or "分析引擎" in system_prompt or "后勤防御" in system_prompt:
            return self._mock_left_brain_json(alerts_info)
        elif "右脑" in system_prompt or "响应引擎" in system_prompt or "修复反击" in system_prompt:
            return self._mock_right_brain_json(alerts_info)
        else:
            return {"result": "mock", "alerts": alerts_info}

    # ---- 告警信息提取 ----

    def _extract_alerts_from_prompt(self, prompt: str) -> List[Dict[str, Any]]:
        """从 prompt 中提取告警信息。"""
        alerts = []
        try:
            data = json.loads(prompt)
            if isinstance(data, list):
                alerts = data
            elif isinstance(data, dict):
                if "alerts" in data:
                    alerts = data["alerts"]
                elif "threats" in data:
                    alerts = data["threats"]
                else:
                    alerts = [data]
        except (json.JSONDecodeError, TypeError):
            pass
        return alerts

    # ---- 分析引擎 Mock 逻辑 ----

    def _mock_left_brain_output(self, alerts: List[Dict]) -> str:
        """分析引擎 mock 文本输出。"""
        result = self._mock_left_brain_json(alerts)
        return json.dumps(result, ensure_ascii=False, indent=2)

    def _mock_left_brain_json(self, alerts: List[Dict]) -> Dict[str, Any]:
        """分析引擎 mock JSON 输出：分级、决策、算力分配。"""
        processed = []
        severities = {"low": 0, "medium": 0, "high": 0, "severe": 0}

        # 基于告警类型和参数的差异化推理库
        for alert in alerts:
            aid = alert.get("id", "UNKNOWN")
            cat = alert.get("category", alert.get("type", "unknown"))
            raw = alert.get("raw_data", {})
            severity = alert.get("severity", "medium")

            # 根据告警参数做差异化 severity 判定
            if cat == "ddos":
                req = raw.get("request_count", raw.get("count", 100))
                if req >= 500:
                    severity = "severe"
                elif req >= 200:
                    severity = "high"
                elif req >= 100:
                    severity = "medium"
                else:
                    severity = "low"
            elif cat == "port_scan":
                ports = raw.get("scanned_port_count", raw.get("unique_ports", 10))
                if ports >= 100:
                    severity = "severe"
                elif ports >= 50:
                    severity = "high"
                elif ports >= 20:
                    severity = "medium"
                else:
                    severity = "low"
            elif cat == "brute_force":
                attempts = raw.get("attempts", 100)
                target_port = raw.get("target_port", 22)
                if attempts >= 500:
                    severity = "severe"
                elif attempts >= 200:
                    severity = "high"
                else:
                    severity = "medium"

            # 根据类别和严重级别决定动作和理由
            action, reason, resource = self._mock_left_action(cat, severity, alert, raw)
            severities[severity] = severities.get(severity, 0) + 1

            processed.append({
                "id": aid,
                "severity": severity,
                "action": action,
                "reason": reason,
                "resource_advice": resource,
            })

        # 汇总建议
        if severities.get("severe", 0) > 0:
            recommendation = (
                f"检测到 {severities['severe']} 项严重威胁，建议立即提升防御等级，"
                f"同步全集群告警，启动应急响应流程。"
            )
        elif severities.get("high", 0) > 0:
            recommendation = (
                f"检测到 {severities['high']} 项高危威胁，建议重点监控并准备资源扩容，"
                f"通知运维团队待命。"
            )
        elif severities.get("medium", 0) > 0:
            recommendation = (
                f"检测到 {severities['medium']} 项中危告警，建议持续监控，"
                f"对可疑 IP 做速率限制。"
            )
        else:
            recommendation = "当前威胁级别较低，维持标准监控策略。"

        return {
            "alerts": processed,
            "summary": {
                "total": len(processed),
                **severities,
                "recommendation": recommendation,
            },
            "reasoning": self._mock_left_reasoning(processed, severities),
        }

    def _mock_left_action(
        self, cat: str, severity: str, alert: Dict, raw: Dict
    ) -> tuple:
        """基于类别+严重级别的差异化动作生成。"""
        source_ip = alert.get("source_ip", "unknown")
        target_ip = alert.get("target_ip", "192.168.1.1")

        if cat == "ddos":
            if severity in ("severe", "high"):
                action = "isolate_ip"
                reason = (
                    f"检测到来自 {source_ip} 的大规模 DDoS 洪水攻击"
                    f"（{raw.get('request_count', raw.get('count', '?'))} 次请求），"
                    f"对目标 {target_ip} 构成严重威胁。该攻击流量特征与已知僵尸网络行为高度吻合，"
                    f"建议立即隔离源IP，同时启用流量清洗，并将此攻击特征同步至集群所有单元。"
                )
                resource = "分配 4 核 8G 用于深度包检测和数据包捕获取证"
            elif severity == "medium":
                action = "rate_limit"
                reason = (
                    f"检测到来自 {source_ip} 的中等规模 DDoS 流量"
                    f"（{raw.get('request_count', raw.get('count', '?'))} 次请求）。"
                    f"建议对源 IP 实施速率限制（100 req/s），同时监控是否有升级趋势。"
                )
                resource = "分配 1 核 2G 用于流量速率监控"
            else:
                action = "monitor"
                reason = (
                    f"检测到来自 {source_ip} 的低强度异常流量，可能为探测行为。"
                    f"建议持续监控，记录流量特征用于后续分析。"
                )
                resource = "分配 0.5 核 1G 用于日志采样"

        elif cat == "port_scan":
            ports = raw.get("scanned_port_count", raw.get("unique_ports", "?"))
            if severity in ("severe", "high"):
                action = "isolate_ip"
                reason = (
                    f"检测到来自 {source_ip} 的大规模端口扫描行为"
                    f"（已扫描 {ports} 个不同端口），覆盖全端口范围，"
                    f"疑似攻击前侦察行为。攻击者可能正在测绘网络拓扑，"
                    f"建议立即隔离并启动溯源追踪。"
                )
                resource = "分配 2 核 4G 用于端口扫描溯源分析"
            elif severity == "medium":
                action = "rate_limit"
                reason = (
                    f"检测到来自 {source_ip} 的选择性端口扫描"
                    f"（{ports} 个端口），可能为漏洞探测。"
                    f"建议限速并记录扫描目标端口列表。"
                )
                resource = "分配 1 核 2G 用于端口监控"
            else:
                action = "monitor"
                reason = (
                    f"检测到来自 {source_ip} 的轻量端口探测，"
                    f"建议记录并加入观察列表。"
                )
                resource = "分配 0.5 核 1G 用于日志记录"

        elif cat == "brute_force":
            attempts = raw.get("attempts", "?")
            target_port = raw.get("target_port", 22)
            service = "SSH" if target_port == 22 else ("RDP" if target_port == 3389 else f"端口{target_port}")
            if severity in ("severe", "high"):
                action = "isolate_ip"
                reason = (
                    f"检测到来自 {source_ip} 对 {service} 服务的持续暴力破解攻击"
                    f"（{attempts} 次认证尝试），尝试凭证数量远超阈值。"
                    f"该 IP 属于已知恶意 IP 段，建议立即隔离并提取攻击样本"
                    f"（密码字典、攻击工具指纹）用于威胁情报更新。"
                )
                resource = "分配 2 核 4G 用于攻击样本采集与特征提取"
            elif severity == "medium":
                action = "isolate_ip"
                reason = (
                    f"检测到来自 {source_ip} 对 {service} 服务的暴力破解尝试"
                    f"（{attempts} 次），超过安全阈值。建议隔离以防止凭据泄露。"
                )
                resource = "分配 1 核 2G 用于日志审计"
            else:
                action = "monitor"
                reason = (
                    f"检测到来自 {source_ip} 的少量认证失败，"
                    f"建议监控并在连续失败后自动锁定。"
                )
                resource = "分配 0.3 核 0.5G 用于认证日志"

        elif cat == "vuln":
            cve = raw.get("cve_id", "CVE-UNKNOWN")
            cvss = raw.get("cvss_score", 5.0)
            if severity in ("severe", "high"):
                action = "isolate_ip"
                reason = (
                    f"检测到 {cve}（CVSS {cvss}）漏洞利用尝试，"
                    f"来源 {source_ip}。该漏洞可导致远程代码执行，危害极高。"
                    f"建议立即隔离源IP，并对受影响服务做紧急补丁评估。"
                )
                resource = "分配 2 核 4G 用于漏洞复现验证"
            else:
                action = "monitor"
                reason = f"检测到 {cve} 漏洞扫描，建议记录并评估影响范围。"
                resource = "分配 0.5 核 1G 用于漏洞信息搜集"

        elif cat == "audit":
            anomaly = raw.get("anomaly_type", "unknown")
            if severity in ("severe", "high"):
                action = "isolate_ip"
                reason = (
                    f"日志审计检测到高危异常事件（{anomaly}），来源 {source_ip}。"
                    f"建议立即隔离并启动内部安全审查。"
                )
                resource = "分配 1 核 2G 用于审计日志深度分析"
            else:
                action = "monitor"
                reason = f"日志审计检测到异常事件（{anomaly}），建议监控并记录。"
                resource = "分配 0.3 核 0.5G 用于日志采样"

        else:
            action = "monitor"
            reason = f"检测到未知类型攻击（{cat}），来源 {source_ip}，建议监控分析。"
            resource = "分配 0.5 核 1G 用于未知威胁分析"

        return action, reason, resource

    def _mock_left_reasoning(
        self, alerts: List[Dict], severities: Dict[str, int]
    ) -> str:
        """生成分析引擎推理链。"""
        total = len(alerts)
        parts = [
            f"分析引擎推理链 (共 {total} 条告警):",
            "1. 告警接收与预处理：解析观测Agent上报的威胁告警，提取关键元数据（源IP、目标端口、告警类型、原始严重级别）。",
        ]

        for i, alert in enumerate(alerts, 1):
            parts.append(
                f"   {1 + i}. 告警 {alert['id']}: 类型={alert.get('category', alert.get('type', '?'))}, "
                f"源IP={alert.get('source_ip', '?')}, 二次确认级别={alert.get('severity', alert.get('severity', '?'))}"
            )

        parts.append(
            f"   {2 + total}. 综合判定: "
            + (
                f"发现 {severities.get('severe', 0) + severities.get('high', 0)} 项需立即处置的威胁，"
                f"已输出对应防御方案。建议将处置策略同步至集群所有防御单元。"
                if severities.get("severe", 0) + severities.get("high", 0) > 0
                else "当前无高优先级威胁，维持标准监控策略。"
            )
        )

        parts.append(
            f"   {3 + total}. 存证: 所有告警和决策已写入 JSONL 日志，"
            f"包含完整事件链和时间戳，满足合规审计要求。"
        )

        return "\n".join(parts)

    # ---- 响应引擎 Mock 逻辑 ----

    def _mock_right_brain_output(self, alerts: List[Dict]) -> str:
        """响应引擎 mock 文本输出。"""
        result = self._mock_right_brain_json(alerts)
        return json.dumps(result, ensure_ascii=False, indent=2)

    def _mock_right_brain_json(self, alerts: List[Dict]) -> Dict[str, Any]:
        """响应引擎 mock JSON 输出：溯源、漏洞关联、拦截策略。"""
        threats = []
        for alert in alerts:
            aid = alert.get("id", "UNKNOWN")
            cat = alert.get("category", alert.get("type", "unknown"))
            source_ip = alert.get("source_ip", "unknown")
            raw = alert.get("raw_data", {})

            attack_type, trace, vulns, counters = self._mock_right_analysis(
                cat, source_ip, raw
            )

            # 动态置信度（基于数据完整性）
            confidence = 0.85
            if "request_count" in raw or "attempts" in raw:
                confidence += 0.05
            if "target_port" in raw and "source_ip" in raw:
                confidence += 0.03
            confidence = min(confidence, 0.98)

            threats.append({
                "alert_id": aid,
                "attack_type": attack_type,
                "trace": trace,
                "vulnerabilities": vulns,
                "countermeasures": counters,
                "confidence": round(confidence, 2),
            })

        return {
            "threats": threats,
            "trace": {
                "summary": self._mock_right_trace_summary(threats),
                "method": "多维关联分析 + 威胁情报匹配 + 攻击路径重建",
            },
            "countermeasures": self._mock_right_global_counters(threats),
            "confidence": round(
                sum(t["confidence"] for t in threats) / max(len(threats), 1), 2
            ),
            "reasoning": self._mock_right_reasoning(threats),
        }

    def _mock_right_analysis(
        self, cat: str, source_ip: str, raw: Dict
    ) -> tuple:
        """响应引擎单告警分析：攻击类型、溯源、漏洞、策略。"""
        # 根据 IP 末位做差异化的溯源推断
        try:
            last_octet = int(source_ip.split(".")[-1])
        except (ValueError, IndexError):
            last_octet = 0

        if cat == "ddos":
            req = raw.get("request_count", raw.get("count", "?"))
            if last_octet < 50:
                trace = (
                    f"攻击源 IP {source_ip} 属于低段地址范围，"
                    f"与已知僵尸网络 C2 节点 IP 段重合。"
                    f"请求量 {req}，流量模式呈脉冲式波动，"
                    f"符合 Mirai 变种僵尸网络的行为特征。"
                    f"跳板链推断：{source_ip} → 代理节点（疑似）→ 目标"
                )
            else:
                trace = (
                    f"攻击源 IP {source_ip} 归属云服务商网段，"
                    f"疑似利用云主机作为攻击跳板。"
                    f"请求量 {req}，特征为 HTTP GET Flood，"
                    f"User-Agent 伪造为常见浏览器。"
                    f"跳板链推断：{source_ip}（云主机）→ 目标"
                )
            attack_type = "HTTP洪水攻击（中等规模）" if req and int(str(req).replace("?","0")) < 1000 else "HTTP洪水攻击（大规模）"
            vulns = ["未限制请求频率", "无CDN/WAF防护", "无流量清洗机制", "Web服务器并发连接数未设上限"]
            counters = ["立即隔离源IP", "启用CDN流量清洗", "配置速率限制（100 req/s）", "部署Web应用防火墙规则", "将攻击特征同步至集群"]

        elif cat == "port_scan":
            ports = raw.get("scanned_port_count", raw.get("unique_ports", "?"))
            if last_octet < 50:
                trace = (
                    f"源 IP {source_ip} 发起了覆盖 {ports} 个端口的大范围扫描，"
                    f"扫描模式为 TCP SYN 半开扫描，速率均匀，"
                    f"符合自动化扫描工具（如 masscan）的行为模式。"
                    f"IP 归属地：境外数据中心，疑似为攻击前情报搜集阶段。"
                )
            else:
                trace = (
                    f"源 IP {source_ip} 发起了选择性端口扫描（{ports} 端口），"
                    f"目标集中在 SSH(22)、RDP(3389)、MySQL(3306) 等常见服务端口，"
                    f"疑似在寻找弱口令或未打补丁的服务入口。"
                )
            attack_type = "全端口扫描（高危）" if ports and int(str(ports).replace("?","0")) >= 100 else "选择性端口扫描"
            vulns = ["防火墙规则过宽", "暴露过多端口", "未启用端口敲门机制", "缺少入侵检测系统"]
            counters = ["隔离扫描源IP", "收缩防火墙规则（最小开放原则）", "启用端口敲门", "部署IDS告警规则", "对开放端口做服务加固"]

        elif cat == "brute_force":
            attempts = raw.get("attempts", "?")
            target_port = raw.get("target_port", 22)
            service = "SSH" if target_port == 22 else ("RDP" if target_port == 3389 else f"端口{target_port}")
            trace = (
                f"源 IP {source_ip} 针对 {service} 服务发起了 {attempts} 次认证尝试，"
                f"使用常见用户名+密码字典（root/admin/administrator），"
                f"攻击间隔均匀（~50ms），符合自动化爆破工具（hydra/medusa）特征。"
                f"该 IP 在最近 24 小时内已被多个威胁情报源标记为恶意。"
                f"跳板链推断：{source_ip} → 目标（直连，无中间跳板）"
            )
            attack_type = f"{service}暴力破解"
            vulns = ["弱密码策略", "无账户锁定机制", "未启用多因素认证", "SSH 允许密码登录"]
            counters = ["立即隔离源IP", "强制启用密钥认证", "配置 fail2ban 自动封禁", "启用多因素认证", "采集攻击密码字典用于特征更新"]

        elif cat == "vuln":
            cve = raw.get("cve_id", "CVE-UNKNOWN")
            cvss = raw.get("cvss_score", 5.0)
            service = raw.get("service", "unknown")
            trace = (
                f"扫描器 {source_ip} 探测到 {cve}（CVSS {cvss}）漏洞存在于 {service} 服务，"
                f"该漏洞利用条件简单，无需认证即可触发，"
                f"建议立即评估受影响版本并做补丁/缓解。"
            )
            attack_type = f"{'严重' if cvss >= 9 else '高危' if cvss >= 7 else '中危'}漏洞利用 {cve} ({service})"
            vulns = ["服务版本过旧", "未及时打补丁", "缺少漏洞管理流程"]
            counters = ["隔离扫描源IP", "紧急评估补丁可行性", "配置虚拟补丁（WAF规则）", "服务降级/限流"]

        else:
            trace = f"来源 {source_ip} 的未知类型威胁，需进一步分析。"
            attack_type = "未知攻击类型"
            vulns = ["需进一步调查"]
            counters = ["监控", "日志记录"]

        return attack_type, trace, vulns, counters

    def _mock_right_trace_summary(self, threats: List[Dict]) -> str:
        """溯源汇总。"""
        ips = list(set(t.get("alert_id", "") for t in threats if "alert_id" in t))
        attack_types = list(set(t.get("attack_type", "") for t in threats))
        return (
            f"基于 {len(ips)} 个告警的多维关联分析，识别到 {len(attack_types)} 种攻击类型。"
            f"攻击路径已通过跳板链分析和威胁情报交叉验证进行确认。"
            f"建议将此溯源报告同步至 SIEM/态势感知平台。"
        )

    def _mock_right_global_counters(self, threats: List[Dict]) -> List[str]:
        """全局拦截策略汇总。"""
        all_counters = []
        for t in threats:
            all_counters.extend(t.get("countermeasures", []))
        # 去重
        seen = set()
        unique = []
        for c in all_counters:
            if c not in seen:
                seen.add(c)
                unique.append(c)
        return unique[:10]  # 最多 10 条

    def _mock_right_reasoning(self, threats: List[Dict]) -> str:
        """生成响应引擎推理链。"""
        parts = [
            f"响应引擎推理链 (共 {len(threats)} 条分析):",
            "1. 威胁指标接收：从观测Agent获取结构化告警数据。",
        ]
        for i, t in enumerate(threats, 1):
            parts.append(
                f"   {1 + i}. {t['alert_id']}: 判定为 {t['attack_type']}，"
                f"置信度 {t['confidence']}，"
                f"漏洞关联 {len(t.get('vulnerabilities', []))} 项，"
                f"建议 {len(t.get('countermeasures', []))} 条拦截策略。"
            )
        parts.append(
            f"   {2 + len(threats)}. 综合: 全部威胁分析完成，"
            f"平均置信度 {sum(t['confidence'] for t in threats) / max(len(threats), 1):.2f}，"
            f"拦截策略已输出。"
        )
        return "\n".join(parts)

    # ---- 通用 Mock ----

    def _mock_generic_output(
        self, system_prompt: str, alerts: List[Dict]
    ) -> str:
        """通用 mock 输出。"""
        count = len(alerts) if alerts else 0
        return json.dumps({
            "analysis": f"基于 {count} 条输入的综合分析结果",
            "conclusion": "分析完成，请查看详细报告。",
            "source": "[LLM-MOCK]",
        }, ensure_ascii=False)

    # ---- 工具方法 ----

    def get_call_log(self) -> List[Dict]:
        """获取调用日志。"""
        return self._call_log

    def get_status_line(self) -> str:
        """获取状态摘要行。"""
        mode = "mock" if self._mock_mode else "火山引擎"
        model_label = self._current_model
        backup_note = " [备用]" if self._backup_used else ""
        return (
            f"[LLM] 模式: {mode}{backup_note} | 模型: {model_label} | "
            f"调用次数: {self._call_count} | 失败: {self._fail_count}"
        )
