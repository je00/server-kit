"""受管主机异步变更任务的持久化状态机。"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping, Protocol

from .errors import TaskExecutionError


LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())
TASK_ID_PATTERN = re.compile(r"task-[0-9a-f]{32}\Z")
TERMINAL_STATES = frozenset({
    "succeeded", "failed", "invalidated", "cancelled", "expired", "interrupted",
    "confirmed", "rolled_back",
})
STATE_LABELS = {
    "waiting_confirmation": "待确认",
    "queued": "排队中",
    "running": "执行中",
    "succeeded": "成功",
    "failed": "失败",
    "invalidated": "已失效",
    "cancelled": "已取消",
    "expired": "已过期",
    "interrupted": "执行中断",
    "waiting_rollback_confirmation": "等待回滚确认",
    "confirmed": "已确认",
    "rolled_back": "已回滚",
}
TRANSITION_MESSAGES = {
    "waiting_confirmation": "影响预览已生成，等待确认。",
    "queued": "任务已确认，等待后台执行。",
    "running": "任务正在执行。",
    "succeeded": "任务执行并核验成功。",
    "failed": "任务执行失败。",
    "invalidated": "执行前事实已变化，请重新预览。",
    "cancelled": "任务已取消。",
    "expired": "确认窗口已过期，请重新预览。",
    "interrupted": "代理重启时任务仍在执行，已停止自动重放并核验当前事实。",
    "waiting_rollback_confirmation": "变更已生效，等待独立连接确认；超时将自动回滚。",
    "confirmed": "变更已由独立连接确认保留。",
    "rolled_back": "变更已回滚。",
}


class TaskEngineError(ValueError):
    """表示任务请求无效或当前状态不允许该操作。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class PreparedAction:
    """root 端完成校验后交给任务 module 的脱敏执行计划。"""

    canonical_action: str
    params: Mapping[str, object]
    preview: Mapping[str, object]
    fact_digest: str
    timeout_seconds: int
    sensitive_params: Mapping[str, object] | None = None
    supports_rollback: bool = False


PrepareAction = Callable[[str, dict[str, object], str], PreparedAction]
ExecuteAction = Callable[[str, dict[str, object]], dict[str, object]]
InspectAction = Callable[[str, dict[str, object]], dict[str, object]]
CleanupAction = Callable[[str, dict[str, object]], None]


class PayloadCipher(Protocol):
    def encrypt(self, task_id: str, payload: Mapping[str, object]) -> str: ...

    def decrypt(self, task_id: str, token: str) -> dict[str, object]: ...


class ChangeTaskEngine:
    """用小接口封装任务持久化、幂等状态迁移和单 worker 执行。"""

    def __init__(
        self,
        database_path: str | Path,
        prepare_action: PrepareAction,
        execute_action: ExecuteAction,
        inspect_action: InspectAction | None = None,
        payload_cipher: PayloadCipher | None = None,
        cleanup_action: CleanupAction | None = None,
        *,
        start_worker: bool = True,
        id_factory: Callable[[], str] | None = None,
        clock: Callable[[], float] = time.time,
        queue_limit: int = 32,
        confirmation_ttl_seconds: int = 300,
        detail_retention_seconds: int = 7 * 24 * 60 * 60,
    ) -> None:
        self._database_path = Path(database_path)
        self._prepare_action = prepare_action
        self._execute_action = execute_action
        self._inspect_action = inspect_action
        self._payload_cipher = payload_cipher
        self._cleanup_action = cleanup_action
        self._id_factory = id_factory or (lambda: f"task-{uuid.uuid4().hex}")
        self._clock = clock
        self._queue_limit = max(1, int(queue_limit))
        self._confirmation_ttl_seconds = max(1, int(confirmation_ttl_seconds))
        self._detail_retention_seconds = max(1, int(detail_retention_seconds))
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._execution_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._initialize_database()
        self._recover_running_tasks()
        if start_worker:
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="server-kit-change-task-worker",
                daemon=True,
            )
            self._worker.start()

    def preview(
        self, protocol_action: str, arguments: dict[str, object], actor: str
    ) -> dict[str, object]:
        """根据 root 端实时事实创建一条待确认任务。"""

        prepared = self._prepare_action(protocol_action, dict(arguments), actor)
        task_id = self._id_factory()
        if not TASK_ID_PATTERN.fullmatch(task_id):
            raise RuntimeError("任务标识生成器返回了无效标识")
        now = self._timestamp()
        sensitive_payload = dict(prepared.sensitive_params or {})
        if sensitive_payload and self._payload_cipher is None:
            raise RuntimeError("敏感任务没有配置机器密钥")
        payload_ciphertext = (
            self._payload_cipher.encrypt(task_id, sensitive_payload)
            if sensitive_payload and self._payload_cipher is not None
            else ""
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO tasks (
                    id, protocol_action, canonical_action, actor, params_json,
                    preview_json, fact_digest, timeout_seconds, state,
                    result_json, error_code, error_message,
                    created_at, updated_at, started_at, finished_at,
                    confirmation_deadline, detail_purge_after, details_purged,
                    payload_ciphertext, supports_rollback
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', ?, ?, '', '', ?, 0, 0, ?, ?)
                """,
                (
                    task_id,
                    protocol_action,
                    prepared.canonical_action,
                    actor,
                    self._dump(dict(prepared.params)),
                    self._dump(dict(prepared.preview)),
                    prepared.fact_digest,
                    prepared.timeout_seconds,
                    "waiting_confirmation",
                    now,
                    now,
                    self._clock() + self._confirmation_ttl_seconds,
                    payload_ciphertext,
                    int(prepared.supports_rollback),
                ),
            )
            self._insert_transition(
                connection, task_id, None, "waiting_confirmation", now
            )
            connection.commit()
        return self.get(task_id)

    def confirm(self, task_id: str, actor: str) -> dict[str, object]:
        """幂等确认任务；重复确认不会再次排队或执行。"""

        self._validate_task_id(task_id)
        self._run_maintenance()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT actor, state, protocol_action FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise TaskEngineError("not_found", "变更任务不存在。")
            if (
                row["actor"] != actor
                and row["protocol_action"] != "security.transaction.change"
            ):
                raise TaskEngineError("forbidden", "只有任务发起人可以确认该任务。")
            if row["state"] == "waiting_confirmation":
                active_count = connection.execute(
                    "SELECT COUNT(*) FROM tasks WHERE state IN ('queued', 'running')"
                ).fetchone()[0]
                if active_count >= self._queue_limit:
                    raise TaskEngineError(
                        "queue_full", "变更任务队列已满，请稍后重试。"
                    )
                now = self._timestamp()
                connection.execute(
                    "UPDATE tasks SET state = 'queued', updated_at = ? WHERE id = ?",
                    (now, task_id),
                )
                self._insert_transition(
                    connection, task_id, "waiting_confirmation", "queued", now
                )
            connection.commit()
        self._wake.set()
        return self.get(task_id)

    def cancel(self, task_id: str, actor: str) -> dict[str, object]:
        """取消本人尚未开始执行的任务；执行中任务不会被强制终止。"""

        self._validate_task_id(task_id)
        self._run_maintenance()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT actor, state, protocol_action, params_json FROM tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise TaskEngineError("not_found", "变更任务不存在。")
            if (
                row["actor"] != actor
                and row["protocol_action"] != "security.transaction.change"
            ):
                raise TaskEngineError("forbidden", "只有任务发起人可以取消该任务。")
            state = str(row["state"])
            if state == "running":
                raise TaskEngineError(
                    "operation_forbidden", "执行中任务不能被通用强制停止。"
                )
            if state in {"waiting_confirmation", "queued"}:
                now = self._timestamp()
                connection.execute(
                    """
                    UPDATE tasks SET state = 'cancelled', updated_at = ?, finished_at = ?,
                        detail_purge_after = ?, payload_ciphertext = '' WHERE id = ?
                    """,
                    (
                        now,
                        now,
                        self._clock() + self._detail_retention_seconds,
                        task_id,
                    ),
                )
                self._insert_transition(connection, task_id, state, "cancelled", now)
            connection.commit()
        if state in {"waiting_confirmation", "queued"}:
            self._cleanup(
                str(row["protocol_action"]), self._load_object(str(row["params_json"]))
            )
        return self.get(task_id)

    def get(self, task_id: str) -> dict[str, object]:
        """读取一条脱敏任务详情和追加式迁移记录。"""

        self._validate_task_id(task_id)
        self._run_maintenance()
        self._reconcile_rollback_task(task_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise TaskEngineError("not_found", "变更任务不存在。")
            transitions = connection.execute(
                """
                SELECT from_state, to_state, occurred_at, message
                FROM task_transitions WHERE task_id = ? ORDER BY id ASC
                """,
                (task_id,),
            ).fetchall()
        return self._serialize(row, transitions=transitions)

    def list(self, limit: int = 100) -> dict[str, object]:
        """按创建时间倒序读取任务摘要。"""

        self._run_maintenance()
        self._reconcile_rollback_tasks()
        safe_limit = max(1, min(int(limit), 200))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return {"items": [self._serialize(row) for row in rows]}

    def process_one(self) -> bool:
        """原子领取并执行一条排队任务；主要供 worker 和测试共用。"""

        self._run_maintenance()
        self._reconcile_rollback_tasks()
        if not self._execution_lock.acquire(blocking=False):
            return False
        try:
            claimed = self._claim_next()
            if claimed is None:
                return False
            task_id = str(claimed["id"])
            try:
                params = self._load_object(str(claimed["params_json"]))
                if claimed["payload_ciphertext"]:
                    if self._payload_cipher is None:
                        raise RuntimeError("敏感任务没有配置机器密钥")
                    params.update(
                        self._payload_cipher.decrypt(
                            task_id, str(claimed["payload_ciphertext"])
                        )
                    )
                inspection = self._inspect(
                    protocol_action=str(claimed["protocol_action"]), params=params
                )
                if (
                    inspection is not None
                    and inspection.get("fact_digest") != str(claimed["fact_digest"])
                ):
                    self._finish(
                        task_id, "invalidated", {"verification": inspection},
                        "facts_changed", "执行前事实已变化，请重新预览。",
                    )
                    return True
                result = self._execute_action(str(claimed["protocol_action"]), params)
                if not isinstance(result, dict):
                    raise TypeError("任务执行结果必须是对象")
            except TaskExecutionError as exc:
                LOGGER.warning(
                    "异步变更任务执行未完成：%s（%s）", task_id, exc.code
                )
                if bool(claimed["supports_rollback"]) and self._recover_rollback_execution(
                    task_id, str(claimed["protocol_action"]), params
                ):
                    return True
                self._finish(task_id, "failed", {}, exc.code, exc.message)
            except Exception:
                LOGGER.exception("异步变更任务执行失败：%s", task_id)
                if bool(claimed["supports_rollback"]) and self._recover_rollback_execution(
                    task_id, str(claimed["protocol_action"]), params
                ):
                    return True
                self._finish(task_id, "failed", {}, "task_failed", "任务执行失败。")
            else:
                if bool(claimed["supports_rollback"]):
                    if result.get("state") != "pending":
                        self._finish(
                            task_id, "failed", {}, "rollback_window_missing",
                            "高风险变更没有进入回滚窗口。",
                        )
                    else:
                        self._wait_for_rollback_confirmation(task_id, result)
                else:
                    self._finish(task_id, "succeeded", result, "", "")
            return True
        finally:
            self._execution_lock.release()

    def close(self) -> None:
        """停止本进程 worker；不会删除任何持久状态。"""

        self._stop.set()
        self._wake.set()
        if self._worker is not None and self._worker.is_alive():
            self._worker.join(timeout=2.0)

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            processed = self.process_one()
            if processed:
                continue
            self._wake.wait(timeout=1.0)
            self._wake.clear()

    def has_active_tasks(self) -> bool:
        """返回是否存在会阻止管理平面生命周期操作的活动任务。"""

        self._run_maintenance()
        self._reconcile_rollback_tasks()
        with self._connection() as connection:
            count = connection.execute(
                """
                SELECT COUNT(*) FROM tasks
                WHERE state IN ('waiting_confirmation', 'queued', 'running', 'waiting_rollback_confirmation')
                """
            ).fetchone()[0]
        return bool(count)

    def _claim_next(self) -> sqlite3.Row | None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM tasks
                WHERE state = 'queued'
                  AND (
                      (
                          protocol_action IN (
                              'network.public_endpoint.change',
                              'security.transaction.change'
                          )
                          AND supports_rollback = 0
                      )
                      OR NOT EXISTS (
                          SELECT 1 FROM tasks AS guarded
                          WHERE guarded.state = 'waiting_rollback_confirmation'
                      )
                  )
                ORDER BY created_at ASC, rowid ASC LIMIT 1
                """
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            now = self._timestamp()
            connection.execute(
                """
                UPDATE tasks
                SET state = 'running', updated_at = ?, started_at = ?
                WHERE id = ? AND state = 'queued'
                """,
                (now, now, row["id"]),
            )
            self._insert_transition(
                connection, str(row["id"]), "queued", "running", now
            )
            connection.commit()
        with self._connection() as connection:
            return connection.execute(
                "SELECT * FROM tasks WHERE id = ?", (row["id"],)
            ).fetchone()

    def _finish(
        self,
        task_id: str,
        state: str,
        result: Mapping[str, object],
        error_code: str,
        error_message: str,
    ) -> None:
        if state not in TERMINAL_STATES:
            raise RuntimeError("任务只能结束为终态")
        now = self._timestamp()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT state, protocol_action, params_json FROM tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
            if current is None or current["state"] != "running":
                raise RuntimeError("任务不在执行中，不能结束")
            connection.execute(
                """
                UPDATE tasks SET state = ?, result_json = ?, error_code = ?,
                    error_message = ?, updated_at = ?, finished_at = ?,
                    detail_purge_after = ?, payload_ciphertext = ''
                WHERE id = ?
                """,
                (
                    state,
                    self._dump(dict(result)) if result else "",
                    error_code,
                    error_message,
                    now,
                    now,
                    self._clock() + self._detail_retention_seconds,
                    task_id,
                ),
            )
            self._insert_transition(connection, task_id, "running", state, now)
            connection.commit()
        self._cleanup(
            str(current["protocol_action"]),
            self._load_object(str(current["params_json"])),
        )

    def _initialize_database(self) -> None:
        self._database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self._database_path.parent, 0o700)
        except OSError:
            pass
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    protocol_action TEXT NOT NULL,
                    canonical_action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    params_json TEXT NOT NULL,
                    preview_json TEXT NOT NULL,
                    fact_digest TEXT NOT NULL,
                    timeout_seconds INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    error_code TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS tasks_state_created_idx
                    ON tasks(state, created_at);
                CREATE TABLE IF NOT EXISTS task_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS task_transitions_task_idx
                    ON task_transitions(task_id, id);
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(tasks)").fetchall()
            }
            for name, declaration in (
                ("confirmation_deadline", "REAL NOT NULL DEFAULT 0"),
                ("detail_purge_after", "REAL NOT NULL DEFAULT 0"),
                ("details_purged", "INTEGER NOT NULL DEFAULT 0"),
                ("payload_ciphertext", "TEXT NOT NULL DEFAULT ''"),
                ("supports_rollback", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE tasks ADD COLUMN {name} {declaration}"
                    )
            now = self._clock()
            connection.execute(
                """
                UPDATE tasks SET confirmation_deadline = ?
                WHERE state = 'waiting_confirmation' AND confirmation_deadline = 0
                """,
                (now + self._confirmation_ttl_seconds,),
            )
            connection.execute(
                """
                UPDATE tasks SET detail_purge_after = ?
                WHERE state IN ('succeeded', 'failed', 'invalidated', 'cancelled', 'expired', 'interrupted', 'confirmed', 'rolled_back')
                  AND detail_purge_after = 0 AND details_purged = 0
                """,
                (now + self._detail_retention_seconds,),
            )
        try:
            os.chmod(self._database_path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self._database_path,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _insert_transition(
        connection: sqlite3.Connection,
        task_id: str,
        from_state: str | None,
        to_state: str,
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO task_transitions (
                task_id, from_state, to_state, occurred_at, message
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                task_id,
                from_state,
                to_state,
                occurred_at,
                TRANSITION_MESSAGES[to_state],
            ),
        )

    @staticmethod
    def _dump(value: Mapping[str, object]) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _load_object(raw: str) -> dict[str, object]:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError("任务持久化对象格式无效")
        return value

    def _timestamp(self) -> str:
        seconds = self._clock()
        whole = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
        return f"{whole}.{int(seconds % 1 * 1000):03d}Z"

    @staticmethod
    def _validate_task_id(task_id: str) -> None:
        if not isinstance(task_id, str) or not TASK_ID_PATTERN.fullmatch(task_id):
            raise TaskEngineError("invalid_params", "任务标识格式不正确。")

    def _serialize(
        self,
        row: sqlite3.Row,
        *,
        transitions: list[sqlite3.Row] | None = None,
    ) -> dict[str, object]:
        preview = self._load_object(str(row["preview_json"])) if row["preview_json"] else {}
        result = (
            self._load_object(str(row["result_json"]))
            if row["result_json"]
            else {}
        )
        task: dict[str, object] = {
            "id": row["id"],
            "action": row["canonical_action"],
            "actor": row["actor"],
            "state": row["state"],
            "state_label": STATE_LABELS.get(str(row["state"]), str(row["state"])),
            "progress": {
                "stage": row["state"],
                "message": TRANSITION_MESSAGES.get(str(row["state"]), "状态已更新。"),
            },
            "preview": preview,
            "result": result,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "terminal": row["state"] in TERMINAL_STATES,
            "details_purged": bool(row["details_purged"]),
        }
        if row["error_code"]:
            task["error"] = {
                "code": row["error_code"],
                "message": row["error_message"],
            }
        if transitions is not None:
            task["transitions"] = [
                {
                    "from_state": item["from_state"],
                    "to_state": item["to_state"],
                    "occurred_at": item["occurred_at"],
                    "message": item["message"],
                }
                for item in transitions
            ]
        return task

    def _inspect(
        self, *, protocol_action: str, params: dict[str, object]
    ) -> dict[str, object] | None:
        if self._inspect_action is None:
            return None
        result = self._inspect_action(protocol_action, dict(params))
        if not isinstance(result, dict) or not isinstance(
            result.get("fact_digest"), str
        ):
            raise RuntimeError("任务事实核验结果格式无效")
        return result

    def _recover_running_tasks(self) -> None:
        """把上次进程遗留的执行中任务标记为中断，并只核验、不重放。"""

        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, protocol_action, params_json FROM tasks WHERE state = 'running'"
            ).fetchall()
        for row in rows:
            verification: dict[str, object] = {}
            try:
                inspected = self._inspect(
                    protocol_action=str(row["protocol_action"]),
                    params=self._load_object(str(row["params_json"])),
                )
                verification = inspected or {"verified": False}
            except Exception:
                LOGGER.exception("执行中断任务事实核验失败：%s", row["id"])
                verification = {"verified": False}
            if verification.get("state") == "pending":
                self._wait_for_rollback_confirmation(
                    str(row["id"]), {"verification": verification, **verification}
                )
            else:
                self._finish(
                    str(row["id"]), "interrupted", {"verification": verification},
                    "execution_interrupted", "代理重启中断了任务；系统未自动重复执行。",
                )

    def _recover_rollback_execution(
        self, task_id: str, protocol_action: str, params: dict[str, object]
    ) -> bool:
        """执行响应不确定时，以持久事务事实收敛，绝不重放高风险动作。"""

        try:
            inspection = self._inspect(
                protocol_action=protocol_action, params=params
            )
        except Exception:
            LOGGER.exception("回滚任务执行异常后的事实核验失败：%s", task_id)
            return False
        if inspection is None:
            return False
        if inspection.get("state") == "pending":
            self._wait_for_rollback_confirmation(
                task_id, {"verification": inspection, **inspection}
            )
            return True
        outcome = str(inspection.get("last_outcome", ""))
        terminal_state = (
            "confirmed" if outcome == "confirmed"
            else "rolled_back" if outcome in {"rolled_back", "automatic_rollback"}
            else ""
        )
        if terminal_state:
            self._finish(task_id, terminal_state, inspection, "", "")
            return True
        return False

    def _wait_for_rollback_confirmation(
        self, task_id: str, result: Mapping[str, object]
    ) -> None:
        now = self._timestamp()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT state FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None or current["state"] != "running":
                raise RuntimeError("任务不在执行中，不能进入回滚窗口")
            connection.execute(
                """
                UPDATE tasks SET state = 'waiting_rollback_confirmation', result_json = ?,
                    updated_at = ?, payload_ciphertext = '' WHERE id = ?
                """,
                (self._dump(dict(result)), now, task_id),
            )
            self._insert_transition(
                connection, task_id, "running", "waiting_rollback_confirmation", now
            )
            connection.commit()

    def _reconcile_rollback_task(self, task_id: str) -> None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT protocol_action, params_json, result_json, state FROM tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
        if row is None or row["state"] != "waiting_rollback_confirmation":
            return
        previous_result = self._load_object(str(row["result_json"]))
        expected_transaction_id = previous_result.get("transaction_id")
        try:
            inspection = self._inspect(
                protocol_action=str(row["protocol_action"]),
                params=self._load_object(str(row["params_json"])),
            )
        except Exception:
            LOGGER.exception("回滚窗口任务状态核验失败：%s", task_id)
            return
        if (
            isinstance(expected_transaction_id, str)
            and expected_transaction_id
            and (inspection or {}).get("transaction_id") != expected_transaction_id
        ):
            LOGGER.warning("忽略事务标识不匹配的回滚结果：%s", task_id)
            return
        if inspection is not None and inspection.get("state") == "pending":
            return
        outcome = str((inspection or {}).get("last_outcome", ""))
        state = "confirmed" if outcome == "confirmed" else (
            "rolled_back" if outcome in {"rolled_back", "automatic_rollback"} else ""
        )
        if state:
            self._finish_waiting_rollback(task_id, state, inspection or {})
        else:
            self._finish_waiting_rollback(
                task_id, "interrupted", {"verified": False},
                "rollback_outcome_indeterminate", "回滚事务已非待确认状态，但缺少可信的持久化结果。",
            )

    def _reconcile_rollback_tasks(self) -> None:
        with self._connection() as connection:
            task_ids = [
                str(row["id"])
                for row in connection.execute(
                    "SELECT id FROM tasks WHERE state = 'waiting_rollback_confirmation'"
                ).fetchall()
            ]
        for task_id in task_ids:
            self._reconcile_rollback_task(task_id)

    def _finish_waiting_rollback(
        self, task_id: str, state: str, result: Mapping[str, object],
        error_code: str = "", error_message: str = "",
    ) -> None:
        now = self._timestamp()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT state FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if current is None or current["state"] != "waiting_rollback_confirmation":
                connection.commit()
                return
            connection.execute(
                """
                UPDATE tasks SET state = ?, result_json = ?, error_code = ?, error_message = ?,
                    updated_at = ?, finished_at = ?, detail_purge_after = ? WHERE id = ?
                """,
                (
                    state, self._dump(dict(result)), error_code, error_message, now, now,
                    self._clock() + self._detail_retention_seconds, task_id,
                ),
            )
            self._insert_transition(
                connection, task_id, "waiting_rollback_confirmation", state, now
            )
            connection.commit()

    def _run_maintenance(self) -> None:
        """推进确认过期并清空超过保留期的敏感详情。"""

        now_seconds = self._clock()
        now = self._timestamp()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            expired = connection.execute(
                """
                SELECT id, protocol_action, params_json FROM tasks
                WHERE state = 'waiting_confirmation' AND confirmation_deadline <= ?
                """,
                (now_seconds,),
            ).fetchall()
            for row in expired:
                task_id = str(row["id"])
                connection.execute(
                    """
                    UPDATE tasks SET state = 'expired', updated_at = ?, finished_at = ?,
                        detail_purge_after = ?, payload_ciphertext = '' WHERE id = ?
                    """,
                    (now, now, now_seconds + self._detail_retention_seconds, task_id),
                )
                self._insert_transition(
                    connection, task_id, "waiting_confirmation", "expired", now
                )
            connection.execute(
                """
                UPDATE tasks SET params_json = '', preview_json = '', result_json = '',
                    error_code = '', error_message = '', details_purged = 1
                WHERE state IN ('succeeded', 'failed', 'invalidated', 'cancelled', 'expired', 'interrupted', 'confirmed', 'rolled_back')
                  AND details_purged = 0 AND detail_purge_after > 0
                  AND detail_purge_after <= ?
                """,
                (now_seconds,),
            )
            connection.commit()
        for row in expired:
            self._cleanup(
                str(row["protocol_action"]), self._load_object(str(row["params_json"]))
            )

    def _cleanup(self, protocol_action: str, params: dict[str, object]) -> None:
        if self._cleanup_action is None:
            return
        try:
            self._cleanup_action(protocol_action, dict(params))
        except Exception:
            LOGGER.exception("异步任务暂存资源清理失败：%s", protocol_action)
