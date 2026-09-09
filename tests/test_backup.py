"""验证加密备份模块的固定接口和完整性保护。"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sqlite3
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

from lib import server_kit_backup as backup_module
from lib.server_kit_backup import BackupError, BackupStore, SOURCES


class FakeScheduler:
    def __init__(self) -> None:
        self.scheduled: list[int] = []
        self.cancelled = 0

    def schedule(self, seconds: int) -> None:
        self.scheduled.append(seconds)

    def cancel(self) -> None:
        self.cancelled += 1


class BackupStoreTests(unittest.TestCase):
    def test_task_database_machine_key_and_payload_are_not_backup_sources(self) -> None:
        source_paths = {source.path for source in SOURCES}
        self.assertNotIn("/var/lib/server-kit-agent", source_paths)
        self.assertFalse(
            any(path.startswith("/var/lib/server-kit-agent/") for path in source_paths)
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.backups = self.root / "backups"
        (self.root / "etc/server-kit").mkdir(parents=True)
        (self.root / "etc/server-kit/ports.conf").write_text(
            "SSH_PUBLIC_PORT=62222\n", encoding="utf-8"
        )
        (self.root / "etc/server-kit/ports.conf").chmod(0o600)
        database = self.root / "var/lib/server-kit-web/db.sqlite3"
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        connection.execute("create table account (name text)")
        connection.execute("insert into account values ('owner')")
        connection.commit()
        connection.close()
        self.store = BackupStore(self.backups, self.root)
        self.passphrase = "测试恢复口令-长度超过十六个字符"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _convert_to_legacy(self, created: dict[str, object]) -> Path:
        path = self.backups / str(created["download_name"])
        header, archive = self.store._decrypt(path, self.passphrase)
        manifest, payloads = self.store._archive_files(archive)
        legacy_path = "etc/amneziawg/clients/legacy-main.conf"
        legacy_secret = b"PrivateKey = LEGACY-CLIENT-SECRET\n"
        manifest.append({
            "path": legacy_path, "category": "amneziawg", "size": len(legacy_secret),
            "mode": 0o600, "sha256": hashlib.sha256(legacy_secret).hexdigest(),
        })
        payloads[legacy_path] = legacy_secret
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as output:
            manifest_bytes = backup_module._json_bytes({"schema_version": 1, "files": manifest})
            self.store._add_bytes(output, "manifest.json", manifest_bytes, 0o600, 0)
            for item in manifest:
                relative = str(item["path"])
                self.store._add_bytes(output, f"files/{relative}", payloads[relative], int(item["mode"]), 0)
        archive = buffer.getvalue()
        header = {key: value for key, value in header.items() if key != "key_custody"}
        header["format_version"] = backup_module.LEGACY_FORMAT_VERSION
        header["categories"] = sorted(set(header["categories"]) | {"amneziawg"})
        header["file_count"] = len(manifest)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        header["salt"] = base64.b64encode(salt).decode("ascii")
        header["nonce"] = base64.b64encode(nonce).decode("ascii")
        aad = backup_module._json_bytes(header)
        encrypted = backup_module.AESGCM(
            backup_module._derive_key(self.passphrase, salt)
        ).encrypt(nonce, archive, aad)
        path.write_bytes(backup_module.MAGIC + struct.pack(">I", len(aad)) + aad + encrypted)
        return path

    def test_create_list_verify_and_preview_without_plaintext_leak(self) -> None:
        created = self.store.create(self.passphrase)
        self.assertEqual(created["format_version"], 2)
        self.assertEqual(created["client_private_keys"], "excluded")
        self.assertEqual(created["assurance_state"], "awaiting_verification")
        backup_path = self.backups / created["download_name"]
        self.assertTrue(backup_path.is_file())
        self.assertNotIn(b"SSH_PUBLIC_PORT", backup_path.read_bytes())

        listed = self.store.list()
        self.assertEqual(listed["items"][0]["backup_id"], created["backup_id"])
        verified = self.store.verify(created["backup_id"], self.passphrase)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["assurance_state"], "verified")
        self.assertEqual(verified["verified_file_count"], 2)

        source = self.root / "etc/server-kit/ports.conf"
        source.write_text("SSH_PUBLIC_PORT=63333\n", encoding="utf-8")
        preview = self.store.preview_restore(created["backup_id"], self.passphrase)
        self.assertEqual(preview["backup"]["assurance_state"], "cleanup_ready")
        self.assertEqual(preview["changed_count"], 1)
        self.assertEqual(preview["online_changed_count"], 1)
        self.assertEqual(preview["offline_changed_count"], 0)
        self.assertFalse(preview["writes_enabled"])
        self.assertEqual(source.read_text(encoding="utf-8"), "SSH_PUBLIC_PORT=63333\n")

    def test_client_private_material_is_excluded_and_server_custody_blocks_creation(self) -> None:
        awg = self.root / "etc/amneziawg"
        (awg / "clients").mkdir(parents=True)
        (awg / "removed").mkdir()
        (awg / "clients/desk-main.conf").write_text("PrivateKey = CLIENT-SECRET\n", encoding="utf-8")
        (awg / "removed/desk-main.conf.old").write_text("PrivateKey = REMOVED-SECRET\n", encoding="utf-8")
        (awg / "enrollments.json").write_text('{"preshared_key":"PENDING-SECRET"}', encoding="utf-8")
        (awg / "rotations.json").write_text('{"preshared_key":"ROTATION-SECRET"}', encoding="utf-8")
        (awg / ".credentials.tmp").write_text("TEMP-SECRET", encoding="utf-8")
        (awg / "server_private.key").write_text("SERVER-PRIVATE", encoding="utf-8")
        credentials = awg / "peer-credentials.tsv"
        credentials.write_text("desk\tPUBLIC\tPSK-SECRET\tclient\n", encoding="utf-8")

        created = self.store.create(self.passphrase)
        path = self.backups / created["download_name"]
        header, archive = self.store._decrypt(path, self.passphrase)
        manifest, payloads = self.store._archive_files(archive)
        paths = {item["path"] for item in manifest}
        self.assertIn("etc/amneziawg/server_private.key", paths)
        self.assertNotIn("etc/amneziawg/clients/desk-main.conf", paths)
        self.assertNotIn("etc/amneziawg/removed/desk-main.conf.old", paths)
        self.assertNotIn("etc/amneziawg/enrollments.json", paths)
        self.assertNotIn("etc/amneziawg/rotations.json", paths)
        self.assertNotIn("etc/amneziawg/.credentials.tmp", paths)
        public_values = json.dumps([
            created,
            self.store.verify(created["backup_id"], self.passphrase),
            self.store.preview_restore(created["backup_id"], self.passphrase),
        ], ensure_ascii=False)
        for secret in ("CLIENT-SECRET", "REMOVED-SECRET", "PENDING-SECRET", "ROTATION-SECRET", "PSK-SECRET"):
            self.assertNotIn(secret, public_values)
        self.assertEqual(header["key_custody"]["client_private_keys"], "excluded")
        self.assertIn(b"SERVER-PRIVATE", payloads["etc/amneziawg/server_private.key"])

        credentials.write_text("desk\tPUBLIC\tPSK\tserver\n", encoding="utf-8")
        with self.assertRaisesRegex(BackupError, "凭据不符合安全要求"):
            self.store.create(self.passphrase)

    def test_existing_peer_without_custody_record_blocks_new_backup(self) -> None:
        awg = self.root / "etc/amneziawg"
        awg.mkdir(parents=True)
        (awg / "peers.tsv").write_text("desk\t10.20.0.10\n", encoding="utf-8")
        (awg / "peer-credentials.tsv").write_text("", encoding="utf-8")
        with self.assertRaisesRegex(BackupError, "缺少安全凭据记录"):
            self.store.create(self.passphrase)

    def test_legacy_backup_can_be_listed_verified_and_previewed_but_not_restored(self) -> None:
        created = self.store.create(self.passphrase)
        self._convert_to_legacy(created)
        listed = self.store.list()["items"][0]
        self.assertEqual(listed["assurance_state"], "legacy")
        self.assertFalse(listed["restore_allowed"])
        self.assertEqual(listed["client_private_keys"], "may_be_included")
        self.assertTrue(self.store.verify(created["backup_id"], self.passphrase)["verified"])
        preview = self.store.preview_restore(created["backup_id"], self.passphrase)
        self.assertTrue(any(
            item["path"] == "/etc/amneziawg/clients/legacy-main.conf"
            for item in preview["changes"]
        ))
        self.assertNotIn("LEGACY-CLIENT-SECRET", json.dumps(preview, ensure_ascii=False))
        source = self.root / "etc/server-kit/ports.conf"
        source.write_text("SSH_PUBLIC_PORT=63333\n", encoding="utf-8")
        writable = BackupStore(
            self.backups, self.root, scheduler=FakeScheduler(), writes_enabled=True
        )
        with self.assertRaisesRegex(BackupError, "旧格式备份可能含客户端私钥"):
            writable.apply_restore(created["backup_id"], self.passphrase)
        self.assertEqual(source.read_text(encoding="utf-8"), "SSH_PUBLIC_PORT=63333\n")

    def test_wrong_passphrase_and_tampering_are_rejected(self) -> None:
        created = self.store.create(self.passphrase)
        with self.assertRaisesRegex(BackupError, "口令错误.*篡改"):
            self.store.verify(created["backup_id"], "另一个恢复口令-同样超过十六字符")

        path = self.backups / created["download_name"]
        damaged = bytearray(path.read_bytes())
        damaged[-1] ^= 1
        path.write_bytes(damaged)
        with self.assertRaisesRegex(BackupError, "口令错误.*篡改"):
            self.store.verify(created["backup_id"], self.passphrase)

    def test_backup_id_cannot_escape_fixed_directory(self) -> None:
        with self.assertRaisesRegex(BackupError, "标识格式"):
            self.store.verify("../../etc/shadow", self.passphrase)

    def test_delete_removes_only_registered_backup(self) -> None:
        created = self.store.create(self.passphrase)
        deleted = self.store.delete(created["backup_id"])
        self.assertEqual(
            deleted,
            {
                "schema_version": 1,
                "backup_id": created["backup_id"],
                "deleted": True,
            },
        )
        self.assertFalse((self.backups / created["download_name"]).exists())
        with self.assertRaisesRegex(BackupError, "备份不存在"):
            self.store.delete(created["backup_id"])

    def test_delete_is_blocked_while_restore_transaction_is_pending(self) -> None:
        created = self.store.create(self.passphrase)
        source = self.root / "etc/server-kit/ports.conf"
        source.write_text("SSH_PUBLIC_PORT=63333\n", encoding="utf-8")
        writable = BackupStore(
            self.backups, self.root, scheduler=FakeScheduler(), writes_enabled=True
        )
        writable.apply_restore(created["backup_id"], self.passphrase)
        with self.assertRaisesRegex(BackupError, "恢复事务"):
            writable.delete(created["backup_id"])

    def test_restore_apply_and_rollback_restore_original_current_state(self) -> None:
        created = self.store.create(self.passphrase)
        source = self.root / "etc/server-kit/ports.conf"
        source.write_text("SSH_PUBLIC_PORT=63333\n", encoding="utf-8")
        scheduler = FakeScheduler()
        writable = BackupStore(
            self.backups, self.root, scheduler=scheduler,
            rollback_seconds=300, writes_enabled=True,
        )
        pending = writable.apply_restore(created["backup_id"], self.passphrase)
        self.assertEqual(pending["state"], "pending")
        self.assertEqual(scheduler.scheduled, [300])
        self.assertEqual(source.read_text(encoding="utf-8"), "SSH_PUBLIC_PORT=62222\n")

        rolled_back = writable.rollback_restore()
        self.assertEqual(rolled_back["state"], "idle")
        self.assertEqual(rolled_back["last_outcome"], "rolled_back")
        self.assertEqual(source.read_text(encoding="utf-8"), "SSH_PUBLIC_PORT=63333\n")
        self.assertEqual(scheduler.cancelled, 1)
        self.assertFalse((self.backups / "restore-transaction.json").exists())

    def test_restore_confirm_keeps_backup_content_and_removes_plain_rollback(self) -> None:
        created = self.store.create(self.passphrase)
        source = self.root / "etc/server-kit/ports.conf"
        source.write_text("SSH_PUBLIC_PORT=64444\n", encoding="utf-8")
        scheduler = FakeScheduler()
        writable = BackupStore(
            self.backups, self.root, scheduler=scheduler, writes_enabled=True
        )
        writable.apply_restore(created["backup_id"], self.passphrase)
        confirmed = writable.confirm_restore()
        self.assertEqual(confirmed["last_outcome"], "confirmed")
        self.assertEqual(source.read_text(encoding="utf-8"), "SSH_PUBLIC_PORT=62222\n")
        self.assertFalse(list(self.backups.glob(".restore-rollback-*.tar")))

    def test_restore_validation_failure_rolls_back_without_leaving_transaction(self) -> None:
        invalid = self.root / "etc/server-kit/invalid.json"
        invalid.write_text("not-json", encoding="utf-8")
        invalid.chmod(0o600)
        created = self.store.create(self.passphrase)
        invalid.write_text('{"safe":true}', encoding="utf-8")
        writable = BackupStore(
            self.backups, self.root, scheduler=FakeScheduler(), writes_enabled=True
        )
        with self.assertRaisesRegex(BackupError, "JSON 配置校验失败"):
            writable.apply_restore(created["backup_id"], self.passphrase)
        self.assertEqual(invalid.read_text(encoding="utf-8"), '{"safe":true}')
        self.assertEqual(writable.restore_status()["state"], "idle")

    def test_restore_writes_are_disabled_by_default(self) -> None:
        created = self.store.create(self.passphrase)
        with self.assertRaisesRegex(BackupError, "只允许恢复预览"):
            self.store.apply_restore(created["backup_id"], self.passphrase)

    def test_online_restore_never_replaces_active_management_database(self) -> None:
        created = self.store.create(self.passphrase)
        database = self.root / "var/lib/server-kit-web/db.sqlite3"
        connection = sqlite3.connect(database)
        connection.execute("insert into account values ('new-session')")
        connection.commit()
        connection.close()
        preview = self.store.preview_restore(created["backup_id"], self.passphrase)
        self.assertEqual(preview["online_changed_count"], 0)
        self.assertEqual(preview["offline_changed_count"], 1)
        writable = BackupStore(
            self.backups, self.root, scheduler=FakeScheduler(), writes_enabled=True
        )
        with self.assertRaisesRegex(BackupError, "只能从控制台离线恢复"):
            writable.apply_restore(created["backup_id"], self.passphrase)
        connection = sqlite3.connect(database)
        try:
            self.assertEqual(
                connection.execute("select count(*) from account").fetchone()[0], 2
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
