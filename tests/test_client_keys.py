#!/usr/bin/env python3
"""验证普通节点密钥安全约束。"""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_client_keys import verify_client_key_policy


def key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class ClientKeyPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.awg = self.root / "etc/amneziawg"
        self.awg.mkdir(parents=True)

    def test_empty_install_passes(self) -> None:
        result = verify_client_key_policy(self.root)
        self.assertTrue(result["ready"])
        self.assertEqual(result["peer_count"], 0)

    def test_missing_custody_and_client_config_are_rejected_without_leaking_value(self) -> None:
        (self.awg / "peers.tsv").write_text("legacy\t10.20.0.10\n", encoding="utf-8")
        clients = self.awg / "clients"
        clients.mkdir()
        (clients / "legacy-main.conf").write_text("PrivateKey = CLIENT-SECRET\n", encoding="utf-8")
        result = verify_client_key_policy(self.root)
        self.assertFalse(result["ready"])
        summary = "；".join(result["checklist"])
        self.assertIn("缺少安全凭据记录", summary)
        self.assertIn("管理链路出现客户端私钥字段", summary)
        self.assertNotIn("CLIENT-SECRET", summary)

    def test_client_custody_passes(self) -> None:
        (self.awg / "peers.tsv").write_text("desk\t10.20.0.10\n", encoding="utf-8")
        (self.awg / "peer-credentials.tsv").write_text(
            f"desk\t{key(1)}\t{key(2)}\tclient\n", encoding="utf-8"
        )
        result = verify_client_key_policy(self.root)
        self.assertTrue(result["ready"])
        self.assertEqual(result["peer_count"], 1)

    def test_static_program_field_name_is_not_mistaken_for_persisted_key(self) -> None:
        static = self.root / "var/lib/server-kit-web/static"
        static.mkdir(parents=True)
        (static / "awg.js").write_text(
            'const payload = {"client_private_key": generatedPrivateKey};\n',
            encoding="utf-8",
        )
        self.assertTrue(verify_client_key_policy(self.root)["ready"])

    def test_runtime_data_with_private_key_field_is_rejected(self) -> None:
        state = self.root / "var/lib/server-kit-web"
        state.mkdir(parents=True)
        (state / "unexpected.json").write_text(
            '{"client_private_key":"CLIENT-SECRET"}\n', encoding="utf-8"
        )
        result = verify_client_key_policy(self.root)
        self.assertFalse(result["ready"])
        self.assertIn("unexpected.json", "；".join(result["checklist"]))


if __name__ == "__main__":
    unittest.main()
