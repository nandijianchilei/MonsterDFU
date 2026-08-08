import argparse
import asyncio
import os
import sys
from typing import List, Optional

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from communication.message_bus import get_message_bus
from config import get_config, get_llm_config
from core.event_recorder import EventChainRecorder
from core.llm_client import LLMClient
from core.runner import DFUPrototypeRunner
from utils.logger import init_global_logger


_WEAK_TOKEN_BLACKLIST = frozenset({
    "dfu-default-token-change-me",
    "change-me",
    "your-token-here",
    "changeme",
    "default-token",
    "admin",
    "password",
    "123456",
})


def _validate_api_token() -> None:
    """在系统启动时强制校验 auth.api_token。

    若 token 为空或等于弱默认值，立即报错并提示用户设置
    DFU_AUTH__API_TOKEN 环境变量或修改 config/default_config.yaml。
    """
    from dfuconfig import config as dfu_cfg

    token = str(dfu_cfg.get("auth.api_token", "")).strip()

    if not token:
        raise RuntimeError(
            "安全配置错误：auth.api_token 为空。\n"
            "请设置环境变量 DFU_AUTH__API_TOKEN 或修改 config/default_config.yaml 中的 auth.api_token。\n"
            "警告：使用空 token 会导致 API 认证形同虚设。"
        )

    if token.lower() in _WEAK_TOKEN_BLACKLIST:
        raise RuntimeError(
            f"安全配置错误：auth.api_token 为弱默认值 ({token})，禁止启动。\n"
            "请设置环境变量 DFU_AUTH__API_TOKEN 或修改 config/default_config.yaml 中的 auth.api_token。\n"
            "警告：使用默认 token 会让攻击者绕过 API 认证。"
        )


async def async_main(
    stage: int = 2,
    scenario: str = "all",
    fault_sim: bool = False,
    qps: Optional[List[int]] = None,
    dry_run: bool = False,
    pcap_path: str = "",
    listen: bool = False,
    mock: bool = False,
    model: Optional[str] = None,
    capture: bool = False,
) -> None:
    """
    异步主函数。

    Args:
        stage:     运行阶段 (1=仅核心Agent, 2=全套Agent含器官+医疗, 3=集群化+冷热知识库, 4=灰度升级+生产就绪, 'realtime'=真实流量接入)
        scenario:  攻击场景 (all / ddos / port_scan / brute_force)
        fault_sim: 是否运行故障模拟 (仅 stage2 有效)
        qps:       覆盖默认压力测试 QPS 级别列表 (仅 stage4 有效)
        dry_run:   干跑模式，跳过实际文件写入 (仅 stage4 有效)
        pcap_path: pcap/pcapng 文件路径 (仅 realtime 有效)
        listen:    启动在线监听模式 (仅 realtime 有效)
    """
    # 初始化日志
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    init_global_logger(log_dir)

    stage_desc_map = {
        1: "阶段1 - 核心Agent",
        2: "阶段2 - 全套Agent（感知模块扩展+医疗自愈）",
        3: "阶段3 - 集群化与冷热知识库",
        4: "阶段4 - 灰度升级与生产就绪",
        "realtime": "真实流量接入 - pcap离线分析 + 在线监听",
    }
    stage_desc = stage_desc_map.get(stage, f"阶段{stage}")

    print("\n" + "=" * 80)
    print("  多智能体分层分布式AI防御系统")
    print("  DFU (Dual-Brain Distributed AI Defense Fighting Unit)")
    print(f"  {stage_desc}")
    print("=" * 80)

    # 加载配置
    config = get_config()
    os.makedirs(config.log_dir, exist_ok=True)

    # ===== 强制 API Token 校验 =====
    _validate_api_token()

    # 初始化 LLM 客户端
    llm_config = get_llm_config()
    if model:
        llm_config.model = model
    if mock:
        llm_config.mock_mode = True
    llm_client = LLMClient(llm_config)
    mode_label = "mock" if llm_client.mock_mode else "real"
    print(f"\n  [LLM] 模式: {mode_label} | 模型: {llm_client.config.model}")

    # 创建事件链记录器
    bus = get_message_bus()
    recorder = EventChainRecorder(bus)

    # 创建运行器
    runner = DFUPrototypeRunner(config, recorder, stage=stage, llm_client=llm_client)

    try:
        # 启动所有 Agent
        await runner.start_all_agents()
        agent_count_map = {1: 6, 2: 10, 3: 10, 4: 10, "realtime": 5}
        agent_count = agent_count_map.get(stage, 10)
        print(f"\n  系统初始化完成，{agent_count} 个 Agent 已上线")
        if stage == "realtime":
            print("  真实流量接入模式: RealtimeTraffic + LeftBrain + RightBrain + Validator + IPIsolation")
        elif stage >= 2:
            print("  医疗Agent自愈系统已激活，正在后台监控所有Agent健康状态")
        if stage != "realtime" and stage >= 3:
            print(f"  集群模式: {len(runner.units)} 个 DFUUnit 已部署，知识库已就绪")
        if stage != "realtime" and stage >= 4:
            print(f"  生产就绪模式: 灰度升级引擎已就绪，输出目录 {config.stage4.production_output_dir}")
        print()

        # 运行场景
        if stage == "realtime":
            await runner.run_realtime(pcap_path=pcap_path, listen=listen)
        elif stage >= 4:
            # 阶段4：灰度升级与生产就绪完整流程
            runner.config.stage4.dry_run = dry_run
            await runner.run_stage4_upgrade_and_production(qps_list=qps)
        elif stage >= 3:
            # 阶段3：依次运行三个场景
            await runner.run_stage3_knowledge_test()
            await asyncio.sleep(0.5)
            await runner.run_stage3_cross_unit_sync()
            await asyncio.sleep(0.5)
            await runner.run_stage3_load_distribution()
        elif fault_sim and stage >= 2:
            # 故障模拟模式：先运行多感知模块协同，再做故障模拟
            await runner.run_stage2_multi_organ()
            await asyncio.sleep(1.0)
            await runner.run_fault_simulation()
        elif stage >= 2:
            await runner.run_stage2_multi_organ()
        else:
            if scenario == "all":
                await runner.run_all_scenarios()
            else:
                await runner.run_scenario(scenario)

        # 额外等待确保最后的异步任务完成
        await asyncio.sleep(1.0)

        # 打印事件链
        recorder.print_chain()

        # 打印运行摘要
        await runner.print_summary()

    except KeyboardInterrupt:
        print("\n\n用户中断，正在关闭...")
    except Exception as e:
        print(f"\n\n运行出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await runner.stop_all_agents()
        print("\n  原型演示结束。\n")


def main() -> None:
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        description="多智能体分层分布式AI防御系统 - 原型"
    )
    parser.add_argument(
        "--stage",
        type=str,
        default="2",
        choices=["1", "2", "3", "4", "realtime"],
        help="运行阶段: 1=仅核心Agent, 2=全套Agent含感知模块扩展+医疗自愈, 3=集群化与冷热知识库, 4=灰度升级+生产就绪, realtime=真实流量接入（默认: 2）",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="all",
        choices=["all", "ddos", "port_scan", "brute_force"],
        help="选择攻击场景（默认: all。stage2/stage3/stage4 时自动使用对应场景）",
    )
    parser.add_argument(
        "--fault-sim",
        action="store_true",
        help="启用故障模拟（仅 stage2 有效），随机杀死Agent并验证医疗Agent自愈全链路",
    )
    parser.add_argument(
        "--qps",
        type=str,
        default=None,
        help="覆盖压力测试 QPS 级别列表（仅 stage4 有效），逗号分隔。默认: 10,50,100,200,500,1000",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="干跑模式（仅 stage4 有效），跳过实际文件写入",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default="",
        help="pcap/pcapng 文件路径（仅 realtime 有效），离线分析模式",
    )
    parser.add_argument(
        "--listen",
        action="store_true",
        help="启动在线监听模式（仅 realtime 有效），接收 JSON 格式流量日志",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=None,
        help="在线监听端口（仅 realtime 有效），覆盖默认配置",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="强制启用 LLM mock 模式（默认自动检测：有 API key 用真实LLM，没有用 mock）",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="覆盖 LLMConfig 中的模型名称（如 gpt-4、hunyuan-lite 等）",
    )
    parser.add_argument(
        "--capture",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="启用在线抓包模式（默认开启），通过 scapy 实时捕获网络数据包。需安装 Npcap；使用 --no-capture 关闭",
    )
    args = parser.parse_args()

    # 解析 --stage 为 int 或保持 str
    stage = int(args.stage) if args.stage.isdigit() else args.stage

    # 解析 --qps 参数
    qps_list = None
    if args.qps:
        qps_list = [int(x.strip()) for x in args.qps.split(",")]

    asyncio.run(async_main(stage, args.scenario, args.fault_sim, qps_list, args.dry_run,
                           pcap_path=args.pcap, listen=args.listen,
                           mock=args.mock, model=args.model, capture=args.capture))


if __name__ == "__main__":
    main()
