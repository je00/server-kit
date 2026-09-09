#!/usr/bin/env python3
"""验证稳定公网入口事务备份清单与恢复事实核验。"""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_public_endpoint_transaction import (
    create_manifest,
    sync_restored,
    verify_manifest,
    verify_restored,
)


class PublicEndpointTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.transaction = self.root / "transaction"
        self.transaction.mkdir()
        self.fact_backup = self.transaction / "public-endpoint.backup"
        self.config_backup = self.transaction / "clash-config.backup"
        self.payload_backup = self.transaction / "clash-subscriptions.backup"
        self.file_config_backup = self.transaction / "file-config.backup"
        self.certificate_backup = self.transaction / "certificate.backup"
        self.key_backup = self.transaction / "key.backup"
        self.certificate_fact_backup = self.transaction / "certificate-fact.backup"
        self.manifest = self.transaction / "backup-manifest.json"
        self.metadata = self.transaction / "metadata.json"
        self.endpoint = self.root / "etc" / "public-endpoint.json"
        self.config = self.root / "clash" / "config.json"
        self.payload = self.root / "data" / "clash-subscriptions"
        self.file_config = self.root / "clash" / "file-config.json"
        self.certificate = self.root / "clash" / "server.crt"
        self.key = self.root / "clash" / "server.key"
        self.certificate_fact = self.root / "clash" / "certificate-ip"

    def arguments(self, operation: str, **changes: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "operation": operation,
            "manifest": self.manifest,
            "metadata": self.metadata,
            "fact_backup": self.fact_backup,
            "clash_config_backup": self.config_backup,
            "clash_payload_backup": self.payload_backup,
            "file_config_backup": self.file_config_backup,
            "certificate_backup": self.certificate_backup,
            "key_backup": self.key_backup,
            "certificate_fact_backup": self.certificate_fact_backup,
            "endpoint": self.endpoint,
            "clash_config": self.config,
            "clash_payload": self.payload,
            "file_config": self.file_config,
            "certificate": self.certificate,
            "key": self.key,
            "certificate_fact": self.certificate_fact,
            "fact_existed": True,
            "clash_backed_up": True,
            "file_config_existed": True,
            "certificate_existed": True,
            "key_existed": True,
            "certificate_fact_existed": True,
        }
        values.update(changes)
        return argparse.Namespace(**values)

    def create_complete_transaction(self) -> None:
        self.fact_backup.write_text('{"fqdn":"old.example.com"}\n', encoding="utf-8")
        self.config_backup.write_text('{"endpoint":"old"}\n', encoding="utf-8")
        self.payload_backup.mkdir()
        (self.payload_backup / "empty").mkdir(mode=0o750)
        (self.payload_backup / "client.yaml").write_text("old publication\n", encoding="utf-8")
        self.file_config_backup.write_text('{"server_address":"old.example.com"}\n', encoding="utf-8")
        self.certificate_backup.write_text("old certificate\n", encoding="utf-8")
        self.key_backup.write_text("old key\n", encoding="utf-8")
        self.certificate_fact_backup.write_text("old.example.com\n", encoding="utf-8")
        digest = create_manifest(self.arguments("create"))
        self.metadata.write_text(json.dumps({
            "fact_existed": True, "clash_backed_up": True,
            "file_config_existed": True, "certificate_existed": True,
            "key_existed": True, "certificate_fact_existed": True,
            "backup_manifest_sha256": digest,
        }), encoding="utf-8")

    def test_complete_manifest_detects_content_tampering(self) -> None:
        self.create_complete_transaction()
        verify_manifest(self.arguments("verify"))

        self.config_backup.write_text('{"truncated":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "摘要"):
            verify_manifest(self.arguments("verify"))

    def test_restored_state_must_equal_manifest(self) -> None:
        self.create_complete_transaction()
        self.endpoint.parent.mkdir()
        self.config.parent.mkdir()
        self.payload.mkdir(parents=True)
        self.endpoint.write_bytes(self.fact_backup.read_bytes())
        self.config.write_bytes(self.config_backup.read_bytes())
        (self.payload / "client.yaml").write_bytes(
            (self.payload_backup / "client.yaml").read_bytes()
        )
        (self.payload / "empty").mkdir(mode=0o750)
        self.file_config.write_bytes(self.file_config_backup.read_bytes())
        self.certificate.write_bytes(self.certificate_backup.read_bytes())
        self.key.write_bytes(self.key_backup.read_bytes())
        self.certificate_fact.write_bytes(self.certificate_fact_backup.read_bytes())
        sync_restored(self.arguments("sync-restored"))
        verify_restored(self.arguments("verify-restored"))

        (self.payload / "client.yaml").write_text("new publication\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "在线内容"):
            verify_restored(self.arguments("verify-restored"))

    def test_manifest_detects_empty_directory_and_mode_tampering(self) -> None:
        self.create_complete_transaction()
        verify_manifest(self.arguments("verify"))

        (self.payload_backup / "empty").rmdir()
        with self.assertRaisesRegex(ValueError, "摘要"):
            verify_manifest(self.arguments("verify"))

        (self.payload_backup / "empty").mkdir(mode=0o750)
        verify_manifest(self.arguments("verify"))
        (self.payload_backup / "empty").chmod(0o700)
        with self.assertRaisesRegex(ValueError, "摘要"):
            verify_manifest(self.arguments("verify"))

    def test_no_prior_fact_and_no_clash_require_empty_restored_scope(self) -> None:
        digest = create_manifest(self.arguments(
            "create", fact_existed=False, clash_backed_up=False,
            file_config_existed=False, certificate_existed=False,
            key_existed=False, certificate_fact_existed=False,
        ))
        self.metadata.write_text(json.dumps({
            "fact_existed": False, "clash_backed_up": False,
            "file_config_existed": False, "certificate_existed": False,
            "key_existed": False, "certificate_fact_existed": False,
            "backup_manifest_sha256": digest,
        }), encoding="utf-8")
        verify_manifest(self.arguments("verify"))
        verify_restored(self.arguments("verify-restored"))

        self.endpoint.parent.mkdir()
        self.endpoint.write_text('{"fqdn":"unexpected.example.com"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "未被移除"):
            verify_restored(self.arguments("verify-restored"))

        self.endpoint.unlink()
        self.endpoint.symlink_to(self.root / "missing-endpoint-target")
        with self.assertRaisesRegex(ValueError, "未被移除"):
            verify_restored(self.arguments("verify-restored"))

        self.endpoint.unlink()
        self.config.parent.mkdir()
        self.config.write_text('{"unexpected":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Clash 配置"):
            verify_restored(self.arguments("verify-restored"))


if __name__ == "__main__":
    unittest.main()
