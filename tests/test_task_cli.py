from __future__ import annotations

import io
import unittest

from control_plane.client import AgentError
from control_plane.task_cli import run


class FakeClient:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, object]]] = []
        self.states = iter(("queued", "running", "succeeded"))

    def request(self, action: str, params: dict[str, object]) -> dict[str, object]:
        self.requests.append((action, params))
        task_id = "task-" + "a" * 32
        if action == "task.preview":
            return {
                "id": task_id,
                "state": "waiting_confirmation",
                "state_label": "待确认",
                "terminal": False,
                "preview": {
                    "title": "停止 Clash 订阅",
                    "summary": "后台执行",
                    "facts": {"当前状态": "运行中", "目标状态": "已停止"},
                },
            }
        if action == "task.confirm":
            return {"id": task_id, "state": "queued", "state_label": "排队中", "terminal": False}
        if action == "task.cancel":
            return {
                "id": task_id,
                "state": "cancelled",
                "state_label": "已取消",
                "terminal": True,
                "progress": {"message": "任务已取消。"},
            }
        if action == "task.get":
            state = next(self.states)
            return {
                "id": task_id,
                "state": state,
                "state_label": {"queued": "排队中", "running": "执行中", "succeeded": "成功"}[state],
                "terminal": state == "succeeded",
                "progress": {"message": f"状态：{state}"},
                "result": {"service": {"state": "已停止"}} if state == "succeeded" else {},
                "preview": {"title": "停止 Clash 订阅"},
            }
        if action == "task.list":
            return {"items": []}
        if action == "task.active":
            return {"active": True}
        raise AssertionError(action)


class TaskCliTests(unittest.TestCase):
    def test_service_defaults_to_confirm_and_wait_for_terminal_state(self) -> None:
        client = FakeClient()
        output = io.StringIO()
        result = run(
            ["service", "clash", "stop", "--yes"],
            client=client,
            output=output,
            actor="owner",
            sleep=lambda _seconds: None,
        )

        self.assertEqual(result, 0)
        self.assertIn("停止 Clash 订阅", output.getvalue())
        self.assertIn("任务成功", output.getvalue())
        self.assertEqual(client.requests[0][0], "task.preview")
        self.assertEqual(client.requests[1][0], "task.confirm")
        self.assertEqual([item[0] for item in client.requests].count("task.get"), 3)

    def test_detach_returns_id_without_polling(self) -> None:
        client = FakeClient()
        output = io.StringIO()
        result = run(
            ["service", "clash", "restart", "--yes", "--detach"],
            client=client,
            output=output,
            actor="root",
        )

        self.assertEqual(result, 0)
        self.assertIn("task-" + "a" * 32, output.getvalue())
        self.assertNotIn("task.get", [item[0] for item in client.requests])

    def test_task_command_queries_detached_task(self) -> None:
        client = FakeClient()
        output = io.StringIO()
        result = run(
            ["task", "task-" + "a" * 32],
            client=client,
            output=output,
        )
        self.assertEqual(result, 0)
        self.assertIn("排队中", output.getvalue())

    def test_task_can_cancel_before_running(self) -> None:
        client = FakeClient()
        output = io.StringIO()
        result = run(
            ["task", "task-" + "a" * 32, "--cancel"],
            client=client,
            output=output,
            actor="owner",
        )
        self.assertEqual(result, 0)
        self.assertIn("已取消", output.getvalue())
        self.assertEqual(client.requests[-1][0], "task.cancel")

    def test_active_command_uses_distinct_exit_status(self) -> None:
        output = io.StringIO()
        self.assertEqual(run(["active"], client=FakeClient(), output=output), 3)
        self.assertIn("存在活动", output.getvalue())

    def test_active_command_identifies_legacy_agent_without_hiding_other_errors(self) -> None:
        class ErrorClient(FakeClient):
            def __init__(self, code: str) -> None:
                super().__init__()
                self.code = code

            def request(self, action, params):
                raise AgentError("测试错误", self.code)

        legacy_output = io.StringIO()
        self.assertEqual(
            run(["active"], client=ErrorClient("unknown_action"), output=legacy_output),
            4,
        )
        self.assertIn("旧管理代理", legacy_output.getvalue())
        self.assertEqual(
            run(["active"], client=ErrorClient("agent_error"), output=io.StringIO()),
            1,
        )

    def test_deployment_task_prints_same_stages_and_verification_as_web(self) -> None:
        class DeploymentClient(FakeClient):
            def request(self, action, params):
                if action != "task.get":
                    return super().request(action, params)
                return {
                    "id": "task-" + "a" * 32,
                    "state": "succeeded", "state_label": "成功", "terminal": True,
                    "progress": {"message": "任务成功。"},
                    "preview": {"stages": ["校验", "安装", "配置", "启动", "验证"]},
                    "result": {
                        "service_id": "clash", "service": {"state": "运行中"},
                        "verification": {"snapshot": True, "inventory": True},
                    },
                }

        output = io.StringIO()
        self.assertEqual(
            run(["task", "task-" + "a" * 32], client=DeploymentClient(), output=output),
            0,
        )
        self.assertIn("校验 → 安装 → 配置 → 启动 → 验证", output.getvalue())
        self.assertIn("主机快照 通过 · 服务清单 通过", output.getvalue())

    def test_interrupted_verification_is_not_mislabeled_as_firewall_result(self) -> None:
        class InterruptedClient(FakeClient):
            def request(self, action, params):
                return {
                    "id": "task-" + "a" * 32,
                    "state": "interrupted", "state_label": "执行中断",
                    "terminal": True,
                    "progress": {"message": "代理重启时任务仍在执行。"},
                    "error": {"message": "系统未自动重复执行。"},
                    "preview": {"title": "重启 Clash 订阅"},
                    "result": {"verification": {
                        "verified": True, "fact_digest": "a" * 64,
                    }},
                }

        output = io.StringIO()
        self.assertEqual(
            run(
                ["task", "task-" + "a" * 32],
                client=InterruptedClient(), output=output,
            ),
            1,
        )
        self.assertNotIn("防火墙端口", output.getvalue())


if __name__ == "__main__":
    unittest.main()
