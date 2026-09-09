#!/usr/bin/env python3
"""server-kit 异步变更任务命令行入口。"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable, Protocol, TextIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from control_plane.client import AgentClient, AgentError  # noqa: E402


TASK_ID_PATTERN = re.compile(r"task-[0-9a-f]{32}\Z")
TERMINAL_STATES = frozenset(
    {"succeeded", "failed", "invalidated", "cancelled", "expired", "interrupted"}
)


class Client(Protocol):
    def request(
        self, action: str, params: dict[str, object]
    ) -> dict[str, object]: ...


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="server-kit", description="异步变更任务")
    value.add_argument("--socket", default="/run/server-kit/manager.sock")
    subcommands = value.add_subparsers(dest="command", required=True)

    service = subcommands.add_parser("service", help="启动、停止或重启托管服务")
    service.add_argument("service_id")
    service.add_argument("operation", choices=("start", "stop", "restart"))
    service.add_argument("--yes", action="store_true", help="确认 root 端影响预览")
    service.add_argument("--detach", action="store_true", help="提交后立即返回任务标识")

    task = subcommands.add_parser("task", help="查询一条任务")
    task.add_argument("task_id")
    task.add_argument("--wait", action="store_true", help="持续等待到终态")
    task.add_argument("--cancel", action="store_true", help="取消待确认或排队中的任务")

    subcommands.add_parser("tasks", help="列出最近任务")
    subcommands.add_parser("active", help=argparse.SUPPRESS)
    return value


def run(
    argv: list[str] | None = None,
    *,
    client: Client | None = None,
    output: TextIO = sys.stdout,
    actor: str | None = None,
    input_func: Callable[[str], str] = input,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    args = parser().parse_args(argv)
    actual_client = client or AgentClient(args.socket)
    actual_actor = actor or _actor()
    try:
        if args.command == "service":
            task = actual_client.request(
                "task.preview",
                {
                    "action": "service.change",
                    "arguments": {
                        "service_id": args.service_id,
                        "operation": args.operation,
                    },
                    "actor": actual_actor,
                },
            )
            _print_preview(task, output)
            if not args.yes and input_func("确认执行？输入 yes：").strip().lower() != "yes":
                print("已取消，任务没有执行。", file=output)
                return 1
            task = actual_client.request(
                "task.confirm",
                {"task_id": task["id"], "actor": actual_actor},
            )
            print(f"任务已提交：{task['id']}", file=output)
            if args.detach:
                print(f"稍后查询：server-kit task {task['id']}", file=output)
                return 0
            return _wait(actual_client, str(task["id"]), output, sleep)
        if args.command == "task":
            if not TASK_ID_PATTERN.fullmatch(args.task_id):
                print("错误：任务标识格式不正确。", file=output)
                return 2
            if args.cancel:
                task = actual_client.request(
                    "task.cancel", {"task_id": args.task_id, "actor": actual_actor}
                )
                _print_task(task, output)
                return 0
            if args.wait:
                return _wait(actual_client, args.task_id, output, sleep)
            task = actual_client.request("task.get", {"task_id": args.task_id})
            _print_task(task, output)
            failed_terminal = (
                task.get("terminal") is True and task.get("state") != "succeeded"
            )
            return 1 if failed_terminal else 0
        if args.command == "active":
            result = actual_client.request("task.active", {})
            if result.get("active") is True:
                print("存在活动变更任务。", file=output)
                return 3
            print("没有活动变更任务。", file=output)
            return 0
        result = actual_client.request("task.list", {})
        items = result.get("items", [])
        if not isinstance(items, list) or not items:
            print("暂无异步变更任务。", file=output)
            return 0
        for task in items:
            if isinstance(task, dict):
                title = task.get("preview", {}).get("title", task.get("action", "变更任务"))
                print(f"{task.get('id')}  {task.get('state_label')}  {title}", file=output)
        return 0
    except AgentError as error:
        if args.command == "active" and error.code == "unknown_action":
            print("旧管理代理尚未提供任务队列；允许首次迁移到任务引擎。", file=output)
            return 4
        print(f"错误：{error}", file=output)
        return 1


def _wait(
    client: Client,
    task_id: str,
    output: TextIO,
    sleep: Callable[[float], None],
) -> int:
    last_state = ""
    while True:
        task = client.request("task.get", {"task_id": task_id})
        state = str(task.get("state", ""))
        if state != last_state:
            _print_task(task, output)
            last_state = state
        if state in TERMINAL_STATES or task.get("terminal") is True:
            if state == "succeeded":
                print("任务成功。", file=output)
                return 0
            print("任务失败。", file=output)
            return 1
        sleep(0.5)


def _print_preview(task: dict[str, object], output: TextIO) -> None:
    preview = task.get("preview", {})
    if not isinstance(preview, dict):
        preview = {}
    print(str(preview.get("title", "变更任务")), file=output)
    summary = preview.get("summary")
    if summary:
        print(str(summary), file=output)
    facts = preview.get("facts", {})
    if isinstance(facts, dict):
        for label, value in facts.items():
            print(f"  {label}：{value}", file=output)


def _print_task(task: dict[str, object], output: TextIO) -> None:
    print(f"{task.get('id')}  {task.get('state_label', task.get('state', '未知'))}", file=output)
    preview = task.get("preview", {})
    if isinstance(preview, dict) and isinstance(preview.get("stages"), list):
        print(
            "部署阶段：" + " → ".join(str(item) for item in preview["stages"]),
            file=output,
        )
    progress = task.get("progress", {})
    if isinstance(progress, dict) and progress.get("message"):
        print(str(progress["message"]), file=output)
    error = task.get("error", {})
    if isinstance(error, dict) and error.get("message"):
        print(f"错误：{error['message']}", file=output)
    result = task.get("result", {})
    if isinstance(result, dict) and isinstance(result.get("service"), dict):
        print(f"实际状态：{result['service'].get('state', '未知')}", file=output)
    elif isinstance(result, dict) and result.get("resource_id"):
        print(
            f"文件资源：{result.get('operation', 'change')} {result['resource_id']}",
            file=output,
        )
    elif isinstance(result, dict) and result.get("fingerprint"):
        print(
            f"SSH 客户端：{result.get('type', '未知')} · {result['fingerprint']} · "
            f"{result.get('name', '未命名')}",
            file=output,
        )
    elif isinstance(result, dict) and result.get("kind") and result.get("name"):
        print(
            f"内网节点：{result['name']} · {result.get('operation', 'change')}",
            file=output,
        )
    elif isinstance(result, dict) and result.get("client") and result.get("target"):
        print(
            f"访问授权：{result['client']} → {result['target']} · "
            f"{result.get('operation', 'change')}",
            file=output,
        )
    elif isinstance(result, dict) and result.get("operation") == "sync":
        print("发布订阅：同步完成", file=output)
    elif isinstance(result, dict) and result.get("operation") == "rotate":
        print(f"发布订阅：{result.get('name', '未知')} · 令牌已轮换", file=output)
    elif isinstance(result, dict) and result.get("operation") == "set-state":
        print(
            f"发布订阅：{result.get('name', '未知')} · {result.get('state', '未知')}",
            file=output,
        )
    elif isinstance(result, dict) and result.get("verified") is True:
        print(f"配置备份：{result.get('backup_id', '未知')} · 校验通过", file=output)
    elif isinstance(result, dict) and result.get("download_name"):
        print(f"配置备份：{result.get('backup_id', '未知')} · 创建完成", file=output)
    elif isinstance(result, dict) and result.get("deleted") is True:
        print(f"配置备份：{result.get('backup_id', '未知')} · 已删除", file=output)
    elif (
        isinstance(result, dict)
        and isinstance(result.get("verification"), dict)
        and {"facts", "nftables"}.issubset(result["verification"])
    ):
        verification = result["verification"]
        facts = "通过" if verification.get("facts") is True else "不一致"
        nftables = "通过" if verification.get("nftables") is True else "不一致"
        print(f"防火墙端口：事实配置 {facts} · nftables {nftables}", file=output)
    if isinstance(result, dict) and result.get("transaction_type"):
        state = "等待独立连接确认" if result.get("state") == "pending" else "空闲"
        print(
            f"安全事务：{result['transaction_type']} · "
            f"{result.get('operation', '状态更新')} · {state}",
            file=output,
        )
    if isinstance(result, dict) and result.get("operation") in {
        "restore_apply", "restore_confirm", "restore_rollback"
    }:
        state = "等待独立连接确认或自动回滚" if result.get("state") == "pending" else "空闲"
        print(f"配置恢复：{result['operation']} · {state}", file=output)
    if (
        isinstance(result, dict)
        and result.get("service_id")
        and isinstance(result.get("verification"), dict)
    ):
        verification = result["verification"]
        snapshot = "通过" if verification.get("snapshot") is True else "不一致"
        inventory = "通过" if verification.get("inventory") is True else "不一致"
        print(f"部署核验：主机快照 {snapshot} · 服务清单 {inventory}", file=output)


def _actor() -> str:
    for name in ("SERVER_KIT_ACTOR", "SUDO_USER", "USER"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return "root"


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
