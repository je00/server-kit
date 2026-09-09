from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from control_plane.task_crypto import TaskPayloadCipher


class TaskPayloadCipherTests(unittest.TestCase):
    def test_machine_key_survives_reopen_and_task_id_is_authenticated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "task-payload.key"
            first = TaskPayloadCipher(key_path)
            token = first.encrypt("task-" + "a" * 32, {"password": "绝密值"})
            second = TaskPayloadCipher(key_path)

            self.assertEqual(
                second.decrypt("task-" + "a" * 32, token),
                {"password": "绝密值"},
            )
            with self.assertRaisesRegex(ValueError, "认证失败"):
                second.decrypt("task-" + "b" * 32, token)
            self.assertEqual(len(key_path.read_bytes()), 32)
            if os.name != "nt":
                self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)

    def test_invalid_existing_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "task-payload.key"
            key_path.write_bytes(b"too-short")
            with self.assertRaisesRegex(RuntimeError, "长度无效"):
                TaskPayloadCipher(key_path)
