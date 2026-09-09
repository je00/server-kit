from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from control_plane.errors import TaskExecutionError
from control_plane.tasks import ChangeTaskEngine, PreparedAction, TaskEngineError
from control_plane.task_crypto import TaskPayloadCipher


class TaskEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.sequence = iter(range(1, 100))

    def engine(self, *, fail: bool = False) -> ChangeTaskEngine:
        def prepare(
            protocol_action: str, arguments: dict[str, object], actor: str
        ) -> PreparedAction:
            return PreparedAction(
                canonical_action="service.stop",
                params={
                    "service_id": arguments["service_id"],
                    "operation": arguments["operation"],
                    "actor": actor,
                    "confirmed": True,
                },
                preview={
                    "title": "停止 Clash 订阅",
                    "summary": "服务将停止，配置不会删除。",
                    "facts": {"当前状态": "运行中", "目标状态": "已停止"},
                },
                fact_digest="a" * 64,
                timeout_seconds=180,
            )

        def execute(
            protocol_action: str, params: dict[str, object]
        ) -> dict[str, object]:
            self.calls.append((protocol_action, params))
            if fail:
                raise RuntimeError("包含敏感路径的底层异常")
            return {
                "service": {"id": "clash", "label": "Clash 订阅", "state": "已停止"},
                "operation": "stop",
            }

        return ChangeTaskEngine(
            Path(self.temp_dir.name) / "tasks.sqlite3",
            prepare,
            execute,
            start_worker=False,
            id_factory=lambda: f"task-{next(self.sequence):032x}",
        )

    def test_preview_is_persisted_with_root_generated_facts(self) -> None:
        engine = self.engine()
        task = engine.preview(
            "service.change",
            {"service_id": "clash", "operation": "stop"},
            "owner",
        )

        self.assertEqual(task["state"], "waiting_confirmation")
        self.assertEqual(task["preview"]["facts"]["当前状态"], "运行中")
        self.assertNotIn("params", task)
        stored = engine.get(task["id"])
        self.assertEqual(stored["id"], task["id"])
        self.assertEqual(
            [item["to_state"] for item in stored["transitions"]],
            ["waiting_confirmation"],
        )

    def test_repeated_confirmation_and_processing_execute_only_once(self) -> None:
        engine = self.engine()
        preview = engine.preview(
            "service.change",
            {"service_id": "clash", "operation": "stop"},
            "owner",
        )

        first = engine.confirm(preview["id"], "owner")
        second = engine.confirm(preview["id"], "owner")
        self.assertEqual(first["state"], "queued")
        self.assertEqual(second["state"], "queued")
        self.assertTrue(engine.process_one())
        self.assertFalse(engine.process_one())
        finished = engine.get(preview["id"])

        self.assertEqual(finished["state"], "succeeded")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(
            [item["to_state"] for item in finished["transitions"]],
            ["waiting_confirmation", "queued", "running", "succeeded"],
        )

    def test_rollback_action_waits_for_external_confirmation_and_reconciles(self) -> None:
        transaction_id = "a" * 64
        transaction_state = {
            "state": "idle", "last_outcome": "", "transaction_id": transaction_id,
        }

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.public_endpoint.apply",
                params={"operation": "apply", "actor": actor},
                preview={"title": "稳定公网入口", "summary": "回滚保护", "facts": {}},
                fact_digest="a" * 64,
                timeout_seconds=240,
                supports_rollback=True,
            )

        def execute(_action, _params):
            transaction_state["state"] = "pending"
            return {
                "state": "pending", "remaining_seconds": 300,
                "transaction_id": transaction_id,
            }

        def inspect(_action, _params):
            return {"fact_digest": "a" * 64, **transaction_state}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback.sqlite3", prepare, execute, inspect,
            start_worker=False, id_factory=lambda: "task-" + "9" * 32,
        )
        task = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(task["id"], "owner")
        self.assertTrue(engine.process_one())
        waiting = engine.get(task["id"])
        self.assertEqual(waiting["state"], "waiting_rollback_confirmation")
        self.assertFalse(waiting["terminal"])
        transaction_state.update(
            state="idle", last_outcome="confirmed", transaction_id="b" * 64,
        )
        stale = engine.get(task["id"])
        self.assertEqual(stale["state"], "waiting_rollback_confirmation")
        self.assertFalse(stale["terminal"])
        transaction_state.update(transaction_id=transaction_id)
        confirmed = engine.get(task["id"])
        self.assertEqual(confirmed["state"], "confirmed")
        self.assertTrue(confirmed["terminal"])

    def test_rollback_action_lost_response_keeps_pending_transaction_guarded(self) -> None:
        transaction_state = {"state": "idle", "last_outcome": ""}
        identifiers = iter(("task-" + "d" * 32, "task-" + "e" * 32))

        def prepare(action, _arguments, actor):
            rollback = action == "network.public_endpoint.change"
            return PreparedAction(
                canonical_action=(
                    "network.public_endpoint.apply"
                    if rollback else "service.clash.restart"
                ),
                params={"actor": actor},
                preview={"title": "测试变更", "summary": "事务保护", "facts": {}},
                fact_digest=("a" if rollback else "b") * 64,
                timeout_seconds=240,
                supports_rollback=rollback,
            )

        def execute(action, _params):
            if action == "network.public_endpoint.change":
                transaction_state["state"] = "pending"
                raise RuntimeError("底层事务已生效，但执行响应丢失")
            return {"ok": True}

        def inspect(action, _params):
            result = {
                "fact_digest": (
                    "a" if action == "network.public_endpoint.change" else "b"
                ) * 64,
            }
            if action == "network.public_endpoint.change":
                result.update(transaction_state)
            return result

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback-lost-response.sqlite3",
            prepare, execute, inspect, start_worker=False,
            id_factory=lambda: next(identifiers),
        )
        protected = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(protected["id"], "owner")
        self.assertTrue(engine.process_one())

        waiting = engine.get(protected["id"])
        self.assertEqual(waiting["state"], "waiting_rollback_confirmation")
        self.assertTrue(engine.has_active_tasks())

        ordinary = engine.preview("service.change", {}, "owner")
        engine.confirm(ordinary["id"], "owner")
        self.assertFalse(engine.process_one())
        self.assertEqual(engine.get(ordinary["id"])["state"], "queued")

    def test_rollback_action_reconciles_without_opening_task_detail(self) -> None:
        transaction_state = {"state": "pending", "last_outcome": ""}

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.public_endpoint.apply",
                params={"operation": "apply", "actor": actor},
                preview={"title": "稳定公网入口", "summary": "回滚保护", "facts": {}},
                fact_digest="a" * 64,
                timeout_seconds=240,
                supports_rollback=True,
            )

        def inspect(_action, _params):
            return {"fact_digest": "a" * 64, **transaction_state}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback-active.sqlite3", prepare,
            lambda _action, _params: {"state": "pending", "remaining_seconds": 300},
            inspect, start_worker=False, id_factory=lambda: "task-" + "8" * 32,
        )
        task = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(task["id"], "owner")
        self.assertTrue(engine.process_one())
        self.assertTrue(engine.has_active_tasks())

        transaction_state.update(state="idle", last_outcome="automatic_rollback")
        self.assertFalse(engine.has_active_tasks())
        self.assertEqual(engine.list()["items"][0]["state"], "rolled_back")

    def test_rollback_inspection_failure_before_deadline_keeps_guard_active(self) -> None:
        transaction_state = {"state": "idle", "last_outcome": ""}
        inspection_failed = False

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.public_endpoint.apply",
                params={"operation": "apply", "actor": actor},
                preview={"title": "稳定公网入口", "summary": "回滚保护", "facts": {}},
                fact_digest="a" * 64, timeout_seconds=240, supports_rollback=True,
            )

        def execute(_action, _params):
            transaction_state["state"] = "pending"
            return {
                "state": "pending", "remaining_seconds": 300,
                "expires_at": "2099-01-01T00:00:00+00:00",
            }

        def inspect(_action, _params):
            nonlocal inspection_failed
            if transaction_state["state"] == "pending" and not inspection_failed:
                inspection_failed = True
                raise RuntimeError("temporary status failure")
            return {"fact_digest": "a" * 64, **transaction_state}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback-transient.sqlite3",
            prepare, execute, inspect, start_worker=False,
            id_factory=lambda: "task-" + "1" * 32,
        )
        task = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(task["id"], "owner")
        self.assertTrue(engine.process_one())

        waiting = engine.get(task["id"])
        self.assertEqual(waiting["state"], "waiting_rollback_confirmation")
        self.assertTrue(engine.has_active_tasks())

        transaction_state.update(state="idle", last_outcome="automatic_rollback")
        self.assertEqual(engine.get(task["id"])["state"], "rolled_back")

    def test_rollback_inspection_failure_after_deadline_keeps_guard_active(self) -> None:
        inspection_failed = False
        transaction_state = {"state": "pending", "last_outcome": ""}

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.public_endpoint.apply",
                params={"operation": "apply", "actor": actor},
                preview={"title": "稳定公网入口", "summary": "回滚保护", "facts": {}},
                fact_digest="a" * 64, timeout_seconds=240, supports_rollback=True,
            )

        def inspect(_action, _params):
            nonlocal inspection_failed
            if not inspection_failed:
                inspection_failed = True
                raise RuntimeError("rollback status unavailable")
            return {"fact_digest": "a" * 64, **transaction_state}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback-expired-inspection.sqlite3",
            prepare,
            lambda *_args: {
                "state": "pending", "remaining_seconds": 0,
                "expires_at": "2000-01-01T00:00:00+00:00",
            },
            inspect, start_worker=False,
            id_factory=lambda: "task-" + "3" * 32,
        )
        task = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(task["id"], "owner")
        self.assertTrue(engine.process_one())

        self.assertEqual(engine.get(task["id"])["state"], "waiting_rollback_confirmation")
        self.assertTrue(engine.has_active_tasks())
        transaction_state.update(state="idle", last_outcome="automatic_rollback")
        self.assertEqual(engine.get(task["id"])["state"], "rolled_back")

    def test_rollback_reconcile_terminates_honestly_without_durable_outcome(self) -> None:
        transaction_state = {"state": "pending", "last_outcome": ""}

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.public_endpoint.apply",
                params={"operation": "apply", "actor": actor},
                preview={"title": "稳定公网入口", "summary": "回滚保护", "facts": {}},
                fact_digest="a" * 64, timeout_seconds=240, supports_rollback=True,
            )

        def inspect(_action, _params):
            return {"fact_digest": "a" * 64, **transaction_state}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback-indeterminate.sqlite3", prepare,
            lambda *_args: {"state": "pending", "remaining_seconds": 300}, inspect,
            start_worker=False, id_factory=lambda: "task-" + "2" * 32,
        )
        task = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(task["id"], "owner")
        self.assertTrue(engine.process_one())

        transaction_state.update(state="idle", last_outcome="")
        reconciled = engine.get(task["id"])

        self.assertEqual(reconciled["state"], "interrupted")
        self.assertTrue(reconciled["terminal"])
        self.assertEqual(reconciled["error"]["code"], "rollback_outcome_indeterminate")
        self.assertNotIn("confirmed", [item["to_state"] for item in reconciled["transitions"]])
        self.assertNotIn("rolled_back", [item["to_state"] for item in reconciled["transitions"]])
        self.assertFalse(engine.has_active_tasks())

    def test_queued_tasks_wait_until_rollback_window_finishes(self) -> None:
        transaction_state = {"state": "idle", "last_outcome": ""}
        identifiers = iter(("task-" + "6" * 32, "task-" + "5" * 32))

        def prepare(action, _arguments, actor):
            if action == "network.public_endpoint.change":
                return PreparedAction(
                    canonical_action="network.public_endpoint.apply",
                    params={"operation": "apply", "actor": actor},
                    preview={"title": "稳定公网入口", "summary": "回滚保护", "facts": {}},
                    fact_digest="a" * 64, timeout_seconds=240, supports_rollback=True,
                )
            return PreparedAction(
                canonical_action="service.clash.restart",
                params={"service_id": "clash", "operation": "restart", "actor": actor},
                preview={"title": "重启 Clash", "summary": "普通任务", "facts": {}},
                fact_digest="b" * 64, timeout_seconds=120,
            )

        executed = []
        def execute(action, _params):
            executed.append(action)
            if action.startswith("network.public_endpoint"):
                transaction_state["state"] = "pending"
                return {"state": "pending", "remaining_seconds": 300}
            return {"ok": True}

        def inspect(action, _params):
            digest = "a" * 64 if action.startswith("network.public_endpoint") else "b" * 64
            return {"fact_digest": digest, **(transaction_state if action.startswith("network.public_endpoint") else {})}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback-queue.sqlite3", prepare, execute,
            inspect, start_worker=False, id_factory=lambda: next(identifiers),
        )
        protected = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(protected["id"], "owner")
        self.assertTrue(engine.process_one())
        after_apply = engine.get(protected["id"])
        self.assertEqual(
            after_apply["state"], "waiting_rollback_confirmation",
            msg=str(after_apply),
        )
        queued = engine.preview("service.change", {}, "owner")
        engine.confirm(queued["id"], "owner")
        self.assertEqual(engine.get(protected["id"])["state"], "waiting_rollback_confirmation")
        with engine._connection() as connection:
            guarded_count = connection.execute(
                "SELECT COUNT(*) FROM tasks WHERE state = 'waiting_rollback_confirmation'"
            ).fetchone()[0]
        self.assertEqual(guarded_count, 1)
        self.assertFalse(engine.process_one())
        self.assertEqual(executed, ["network.public_endpoint.change"])
        self.assertEqual(engine.get(queued["id"])["state"], "queued")

        transaction_state.update(state="idle", last_outcome="confirmed")
        engine.get(protected["id"])
        self.assertTrue(engine.process_one())
        self.assertEqual(executed[-1], "service.change")

    def test_endpoint_confirm_task_can_run_during_rollback_window(self) -> None:
        identifiers = iter(("task-" + "4" * 32, "task-" + "3" * 32))
        transaction_state = {"state": "idle", "last_outcome": ""}

        def prepare(_action, arguments, actor):
            operation = str(arguments.get("operation", "apply"))
            return PreparedAction(
                canonical_action=f"network.public_endpoint.{operation}",
                params={"operation": operation, "actor": actor},
                preview={"title": operation, "summary": "事务", "facts": {}},
                fact_digest="a" * 64, timeout_seconds=240,
                supports_rollback=operation == "apply",
            )

        def execute(_action, params):
            operation = params["operation"]
            if operation == "apply":
                transaction_state["state"] = "pending"
                return {"state": "pending", "remaining_seconds": 300}
            transaction_state.update(state="idle", last_outcome="confirmed")
            return {"state": "idle", "last_outcome": "confirmed"}

        def inspect(_action, _params):
            return {"fact_digest": "a" * 64, **transaction_state}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "rollback-confirm.sqlite3", prepare, execute,
            inspect, start_worker=False, id_factory=lambda: next(identifiers),
        )
        apply = engine.preview(
            "network.public_endpoint.change", {"operation": "apply"}, "owner"
        )
        engine.confirm(apply["id"], "owner")
        self.assertTrue(engine.process_one())
        confirm = engine.preview(
            "network.public_endpoint.change", {"operation": "confirm"}, "owner"
        )
        engine.confirm(confirm["id"], "owner")
        self.assertTrue(engine.process_one())
        self.assertEqual(engine.get(confirm["id"])["state"], "succeeded")
        self.assertFalse(engine.process_one())
        with engine._connection() as connection:
            apply_state = connection.execute(
                "SELECT state FROM tasks WHERE id = ?", (apply["id"],)
            ).fetchone()["state"]
        self.assertEqual(apply_state, "confirmed")

    def test_security_confirm_bypasses_guard_while_unrelated_queue_stays_blocked(self) -> None:
        identifiers = iter(
            ("task-" + "a" * 32, "task-" + "b" * 32, "task-" + "c" * 32)
        )
        transaction_id = "d" * 64
        transaction_state = {
            "state": "idle", "last_outcome": "", "transaction_id": "",
        }
        executed = []

        def prepare(action, arguments, actor):
            if action == "security.transaction.change":
                operation = str(arguments.get("operation", "apply"))
                return PreparedAction(
                    canonical_action=f"security.vless_listener.{operation}",
                    params={"operation": operation, "actor": actor},
                    preview={"title": operation, "summary": "VLESS 监听事务", "facts": {}},
                    fact_digest="a" * 64,
                    timeout_seconds=180,
                    supports_rollback=operation == "apply",
                )
            return PreparedAction(
                canonical_action="service.clash.restart",
                params={"operation": "restart", "actor": actor},
                preview={"title": "重启", "summary": "普通任务", "facts": {}},
                fact_digest="b" * 64,
                timeout_seconds=120,
            )

        def execute(action, params):
            executed.append((action, params["operation"]))
            if action == "security.transaction.change":
                if params["operation"] == "apply":
                    transaction_state.update(
                        state="pending", last_outcome="",
                        transaction_id=transaction_id,
                    )
                    return {
                        "state": "pending", "remaining_seconds": 300,
                        "transaction_id": transaction_id, "last_outcome": "",
                    }
                transaction_state.update(
                    state="idle", last_outcome="confirmed",
                    transaction_id=transaction_id,
                )
                return dict(transaction_state)
            return {"ok": True}

        def inspect(action, _params):
            if action == "security.transaction.change":
                return {"fact_digest": "a" * 64, **transaction_state}
            return {"fact_digest": "b" * 64}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "security-rollback-guard.sqlite3",
            prepare, execute, inspect, start_worker=False,
            id_factory=lambda: next(identifiers),
        )
        apply = engine.preview(
            "security.transaction.change", {"operation": "apply"}, "owner"
        )
        engine.confirm(apply["id"], "owner")
        self.assertTrue(engine.process_one())

        ordinary = engine.preview("service.change", {"operation": "restart"}, "owner")
        engine.confirm(ordinary["id"], "owner")
        confirm = engine.preview(
            "security.transaction.change", {"operation": "confirm"}, "second-admin"
        )
        engine.confirm(confirm["id"], "second-admin")

        self.assertTrue(engine.process_one())
        self.assertEqual(engine.get(confirm["id"])["state"], "succeeded")
        self.assertEqual(engine.get(ordinary["id"])["state"], "queued")
        self.assertEqual(engine.get(apply["id"])["state"], "confirmed")
        self.assertTrue(engine.process_one())
        self.assertEqual(executed[-1], ("service.change", "restart"))

    def test_reopen_recovers_running_rollback_action_into_waiting_window(self) -> None:
        database = Path(self.temp_dir.name) / "rollback-recovery.sqlite3"

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.public_endpoint.apply",
                params={"operation": "apply", "actor": actor},
                preview={"title": "稳定公网入口", "summary": "回滚保护", "facts": {}},
                fact_digest="a" * 64,
                timeout_seconds=240,
                supports_rollback=True,
            )

        engine = ChangeTaskEngine(
            database, prepare, lambda *_args: {}, start_worker=False,
            id_factory=lambda: "task-" + "7" * 32,
        )
        task = engine.preview("network.public_endpoint.change", {}, "owner")
        engine.confirm(task["id"], "owner")
        claimed = engine._claim_next()
        self.assertIsNotNone(claimed)
        engine.close()

        recovered = ChangeTaskEngine(
            database,
            lambda *_args: (_ for _ in ()).throw(AssertionError("不应重新预览")),
            lambda *_args: (_ for _ in ()).throw(AssertionError("不应自动重放")),
            lambda *_args: {
                "fact_digest": "a" * 64, "state": "pending", "last_outcome": "",
            },
            start_worker=False,
        )
        stored = recovered.get(task["id"])
        self.assertEqual(stored["state"], "waiting_rollback_confirmation")
        self.assertFalse(stored["terminal"])

    def test_actor_cannot_confirm_another_users_task(self) -> None:
        engine = self.engine()
        task = engine.preview(
            "service.change",
            {"service_id": "clash", "operation": "stop"},
            "owner",
        )
        with self.assertRaisesRegex(TaskEngineError, "发起人"):
            engine.confirm(task["id"], "other-admin")

    def test_equal_admin_can_take_over_pending_security_task(self) -> None:
        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="security.firewall.rollback",
                params={"actor": actor, "operation": "rollback"},
                preview={"title": "立即回滚防火墙", "summary": "后台执行", "facts": {}},
                fact_digest="c" * 64,
                timeout_seconds=180,
            )

        identifiers = iter(("task-" + "d" * 32, "task-" + "e" * 32))
        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "security-tasks.sqlite3",
            prepare,
            lambda _action, _params: {"state": "idle"},
            start_worker=False,
            id_factory=lambda: next(identifiers),
        )
        task = engine.preview("security.transaction.change", {}, "owner")
        self.assertEqual(engine.confirm(task["id"], "second-admin")["state"], "queued")
        second = engine.preview("security.transaction.change", {}, "owner")
        self.assertEqual(engine.cancel(second["id"], "second-admin")["state"], "cancelled")

    def test_failure_is_redacted_and_persisted(self) -> None:
        engine = self.engine(fail=True)
        task = engine.preview(
            "service.change",
            {"service_id": "clash", "operation": "stop"},
            "owner",
        )
        engine.confirm(task["id"], "owner")
        engine.process_one()

        failed = engine.get(task["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["error"]["message"], "任务执行失败。")
        self.assertNotIn("敏感路径", str(failed))

    def test_safe_execution_failure_keeps_diagnostic_code_and_message(self) -> None:
        def prepare(_action, arguments, actor):
            return PreparedAction(
                canonical_action="network.proxy.update",
                params={"actor": actor, "operation": arguments["operation"]},
                preview={"title": "新增出口节点", "summary": "刷新订阅", "facts": {}},
                fact_digest="a" * 64,
                timeout_seconds=240,
            )

        def execute(_action, _params):
            raise TaskExecutionError(
                "proxy_input_invalid",
                "代理资源内容校验失败：出口节点缺少有效的 port。",
            )

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "safe-error-tasks.sqlite3",
            prepare,
            execute,
            start_worker=False,
            id_factory=lambda: "task-" + "8" * 32,
        )
        task = engine.preview("network.proxy.change", {"operation": "exit_add"}, "owner")
        engine.confirm(task["id"], "owner")
        engine.process_one()

        failed = engine.get(task["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["error"]["code"], "proxy_input_invalid")
        self.assertIn("缺少有效的 port", failed["error"]["message"])

    def test_current_state_and_transitions_survive_reopen(self) -> None:
        engine = self.engine()
        task = engine.preview(
            "service.change",
            {"service_id": "clash", "operation": "stop"},
            "owner",
        )
        engine.confirm(task["id"], "owner")
        engine.close()

        reopened = self.engine()
        stored = reopened.get(task["id"])
        self.assertEqual(stored["state"], "queued")
        self.assertEqual(len(stored["transitions"]), 2)

    def test_background_worker_does_not_hold_confirmation_request(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="service.restart",
                params={
                    "service_id": "clash", "operation": "restart",
                    "actor": actor, "confirmed": True,
                },
                preview={"title": "重启 Clash 订阅", "summary": "后台执行", "facts": {}},
                fact_digest="b" * 64,
                timeout_seconds=180,
            )

        def execute(_action, _params):
            started.set()
            release.wait(timeout=2.0)
            return {"operation": "restart"}

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "async.sqlite3",
            prepare,
            execute,
            id_factory=lambda: "task-" + "f" * 32,
        )
        self.addCleanup(release.set)
        self.addCleanup(engine.close)
        task = engine.preview(
            "service.change",
            {"service_id": "clash", "operation": "restart"},
            "owner",
        )

        confirmed = engine.confirm(task["id"], "owner")
        self.assertIn(confirmed["state"], {"queued", "running"})
        self.assertTrue(started.wait(timeout=1.0))
        self.assertEqual(engine.get(task["id"])["state"], "running")
        release.set()
        for _index in range(100):
            if engine.get(task["id"])["state"] == "succeeded":
                break
            time.sleep(0.01)
        self.assertEqual(engine.get(task["id"])["state"], "succeeded")

    def test_queue_is_bounded_and_fifo(self) -> None:
        engine = self.engine()
        engine._queue_limit = 1
        first = engine.preview(
            "service.change", {"service_id": "clash", "operation": "stop"}, "owner"
        )
        second = engine.preview(
            "service.change", {"service_id": "file", "operation": "stop"}, "owner"
        )
        engine.confirm(first["id"], "owner")
        with self.assertRaisesRegex(TaskEngineError, "队列已满"):
            engine.confirm(second["id"], "owner")
        engine.process_one()
        engine.confirm(second["id"], "owner")
        engine.process_one()
        self.assertEqual(
            [params["service_id"] for _action, params in self.calls],
            ["clash", "file"],
        )

    def test_waiting_and_queued_can_cancel_but_running_cannot(self) -> None:
        engine = self.engine()
        waiting = engine.preview(
            "service.change", {"service_id": "clash", "operation": "stop"}, "owner"
        )
        self.assertEqual(engine.cancel(waiting["id"], "owner")["state"], "cancelled")

        queued = engine.preview(
            "service.change", {"service_id": "file", "operation": "stop"}, "owner"
        )
        engine.confirm(queued["id"], "owner")
        self.assertEqual(engine.cancel(queued["id"], "owner")["state"], "cancelled")

        running = engine.preview(
            "service.change", {"service_id": "git", "operation": "stop"}, "owner"
        )
        engine.confirm(running["id"], "owner")
        engine._claim_next()
        with self.assertRaisesRegex(TaskEngineError, "不能被通用强制停止"):
            engine.cancel(running["id"], "owner")

    def test_changed_facts_invalidate_without_execution(self) -> None:
        engine = self.engine()
        engine._inspect_action = lambda _action, _params: {
            "fact_digest": "c" * 64,
            "verified": True,
        }
        task = engine.preview(
            "service.change", {"service_id": "clash", "operation": "stop"}, "owner"
        )
        engine.confirm(task["id"], "owner")
        self.assertTrue(engine.process_one())
        stored = engine.get(task["id"])
        self.assertEqual(stored["state"], "invalidated")
        self.assertEqual(self.calls, [])

    def test_reopen_marks_running_interrupted_and_only_verifies(self) -> None:
        engine = self.engine()
        task = engine.preview(
            "service.change", {"service_id": "clash", "operation": "stop"}, "owner"
        )
        engine.confirm(task["id"], "owner")
        engine._claim_next()
        engine.close()
        verified: list[str] = []

        def inspect(_action, _params):
            verified.append("called")
            return {"fact_digest": "a" * 64, "verified": True, "result_matches": False}

        recovered = ChangeTaskEngine(
            Path(self.temp_dir.name) / "tasks.sqlite3",
            lambda *_args: (_ for _ in ()).throw(AssertionError("不应重新预览")),
            lambda *_args: (_ for _ in ()).throw(AssertionError("不应自动重放")),
            inspect,
            start_worker=False,
        )
        stored = recovered.get(task["id"])
        self.assertEqual(stored["state"], "interrupted")
        self.assertEqual(verified, ["called"])
        self.assertFalse(stored["result"]["verification"]["result_matches"])

    def test_confirmation_expires_and_terminal_details_are_purged(self) -> None:
        now = [1_700_000_000.0]
        engine = self.engine()
        engine._clock = lambda: now[0]
        engine._confirmation_ttl_seconds = 300
        engine._detail_retention_seconds = 10
        task = engine.preview(
            "service.change", {"service_id": "clash", "operation": "stop"}, "owner"
        )
        now[0] += 301
        expired = engine.get(task["id"])
        self.assertEqual(expired["state"], "expired")
        now[0] += 11
        purged = engine.get(task["id"])
        self.assertTrue(purged["details_purged"])
        self.assertEqual(purged["preview"], {})
        self.assertEqual(
            [item["to_state"] for item in purged["transitions"]],
            ["waiting_confirmation", "expired"],
        )

    def test_active_tasks_excludes_terminal_tasks(self) -> None:
        engine = self.engine()
        task = engine.preview(
            "service.change", {"service_id": "clash", "operation": "stop"}, "owner"
        )
        self.assertTrue(engine.has_active_tasks())
        engine.cancel(task["id"], "owner")
        self.assertFalse(engine.has_active_tasks())

    def test_sensitive_payload_is_encrypted_recovers_and_is_deleted_at_terminal(self) -> None:
        database = Path(self.temp_dir.name) / "sensitive.sqlite3"
        key_path = Path(self.temp_dir.name) / "task-payload.key"
        secret = "https://airport.test/sub?token=plain-secret"
        executed: list[dict[str, object]] = []

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.proxy.update",
                params={"actor": actor, "confirmed": True},
                preview={"title": "更新代理资源", "summary": "脱敏预览", "facts": {}},
                fact_digest="d" * 64,
                timeout_seconds=240,
                sensitive_params={"airport_url": secret, "exit_proxy_yaml": ""},
            )

        cipher = TaskPayloadCipher(key_path)
        engine = ChangeTaskEngine(
            database,
            prepare,
            lambda _action, params: executed.append(dict(params)) or {"configured": True},
            payload_cipher=cipher,
            start_worker=False,
            id_factory=lambda: "task-" + "e" * 32,
        )
        task = engine.preview("network.proxy.update", {}, "owner")
        self.assertNotIn(secret.encode(), database.read_bytes())
        engine.confirm(task["id"], "owner")
        engine.close()

        reopened = ChangeTaskEngine(
            database,
            prepare,
            lambda _action, params: executed.append(dict(params)) or {"configured": True},
            payload_cipher=TaskPayloadCipher(key_path),
            start_worker=False,
        )
        self.assertTrue(reopened.process_one())
        self.assertEqual(executed[0]["airport_url"], secret)
        self.assertNotIn(secret, str(reopened.get(task["id"])))
        with reopened._connection() as connection:
            ciphertext = connection.execute(
                "SELECT payload_ciphertext FROM tasks WHERE id = ?", (task["id"],)
            ).fetchone()[0]
        self.assertEqual(ciphertext, "")
        self.assertNotIn(secret.encode(), database.read_bytes())

    def test_cancelling_sensitive_task_immediately_deletes_ciphertext(self) -> None:
        database = Path(self.temp_dir.name) / "cancel-sensitive.sqlite3"
        cipher = TaskPayloadCipher(Path(self.temp_dir.name) / "cancel.key")

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="network.proxy.update",
                params={"actor": actor, "confirmed": True},
                preview={"title": "更新代理资源"},
                fact_digest="f" * 64,
                timeout_seconds=240,
                sensitive_params={"airport_url": "secret", "exit_proxy_yaml": ""},
            )

        engine = ChangeTaskEngine(
            database,
            prepare,
            lambda _action, _params: {},
            payload_cipher=cipher,
            start_worker=False,
            id_factory=lambda: "task-" + "f" * 32,
        )
        task = engine.preview("network.proxy.update", {}, "owner")
        engine.cancel(task["id"], "owner")
        with engine._connection() as connection:
            ciphertext = connection.execute(
                "SELECT payload_ciphertext FROM tasks WHERE id = ?", (task["id"],)
            ).fetchone()[0]
        self.assertEqual(ciphertext, "")

    def test_cancelled_task_cleans_up_staged_resource(self) -> None:
        cleaned: list[tuple[str, str]] = []

        def prepare(_action, _arguments, actor):
            return PreparedAction(
                canonical_action="file.add",
                params={
                    "operation": "add",
                    "upload_id": "a" * 32,
                    "actor": actor,
                    "confirmed": True,
                },
                preview={"title": "发布文件"},
                fact_digest="a" * 64,
                timeout_seconds=900,
            )

        engine = ChangeTaskEngine(
            Path(self.temp_dir.name) / "cleanup.sqlite3",
            prepare,
            lambda _action, _params: {"published": True},
            cleanup_action=lambda action, params: cleaned.append(
                (action, str(params["upload_id"]))
            ),
            start_worker=False,
            id_factory=lambda: "task-" + "1" * 32,
        )
        cancelled = engine.preview("file.resource.change", {}, "owner")
        engine.cancel(cancelled["id"], "owner")
        self.assertEqual(cleaned, [("file.resource.change", "a" * 32)])


if __name__ == "__main__":
    unittest.main()
