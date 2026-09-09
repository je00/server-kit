#!/usr/bin/env python3
"""验证 root SSH 公钥只经暂存确认后原子写入。"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lib.server_kit_ssh_keys import add_key, delete_key, list_keys, preview, rename_key


class SshKeysTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.authorized = root / "root" / ".ssh" / "authorized_keys"
        self.pending = root / "pending"
        private = root / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)],
            check=True,
        )
        self.public_key = private.with_suffix(".pub").read_text(encoding="utf-8").strip()
        second_private = root / "id_ed25519_second"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(second_private)],
            check=True,
        )
        self.second_public_key = second_private.with_suffix(".pub").read_text(encoding="utf-8").strip()

    def capture(self, callback, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            callback(*args)
        return json.loads(output.getvalue())

    def test_preview_and_add_never_put_raw_key_in_response(self) -> None:
        with patch("sys.stdin", io.StringIO(json.dumps({"public_key": self.public_key}))):
            staged = self.capture(preview, self.authorized, self.pending)
        self.assertRegex(staged["fingerprint"], r"^SHA256:")
        self.assertNotIn(self.public_key, json.dumps(staged))
        self.assertFalse(self.authorized.exists())

        added = self.capture(add_key, self.authorized, self.pending, staged["pending_token"])
        self.assertTrue(added["added"])
        self.assertEqual(self.authorized.read_text(encoding="utf-8").strip(), self.public_key)
        if os.name != "nt":
            self.assertEqual(self.authorized.stat().st_mode & 0o777, 0o600)

    def test_duplicate_key_is_not_appended(self) -> None:
        self.authorized.parent.mkdir(parents=True)
        self.authorized.write_text(self.public_key + "\n", encoding="utf-8")
        with patch("sys.stdin", io.StringIO(json.dumps({"public_key": self.public_key}))):
            staged = self.capture(preview, self.authorized, self.pending)
        self.assertTrue(staged["duplicate"])
        result = self.capture(add_key, self.authorized, self.pending, staged["pending_token"])
        self.assertFalse(result["added"])
        self.assertEqual(len(self.authorized.read_text(encoding="utf-8").splitlines()), 1)

    def test_list_exposes_only_fingerprint_and_comment(self) -> None:
        self.authorized.parent.mkdir(parents=True)
        self.authorized.write_text(self.public_key + "\n", encoding="utf-8")
        result = self.capture(list_keys, self.authorized, self.pending)
        self.assertEqual(len(result["items"]), 1)
        self.assertRegex(result["items"][0]["fingerprint"], r"^SHA256:")
        self.assertNotIn(self.public_key, json.dumps(result))

    def test_list_silently_skips_malformed_existing_key(self) -> None:
        self.authorized.parent.mkdir(parents=True)
        self.authorized.write_text(
            "ssh-ed25519 不是-base64 已损坏\n" + self.public_key + "\n",
            encoding="utf-8",
        )
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = self.capture(list_keys, self.authorized, self.pending)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(errors.getvalue(), "")

    def test_rejects_multiline_and_unsupported_key(self) -> None:
        for value in (self.public_key + "\nssh-ed25519 AAAA", "command=x ssh-ed25519 AAAA"):
            with patch("sys.stdin", io.StringIO(json.dumps({"public_key": value}))):
                with self.assertRaises(SystemExit):
                    preview(self.authorized, self.pending)

    def test_delete_preserves_other_keys_and_protects_last_key(self) -> None:
        self.authorized.parent.mkdir(parents=True)
        self.authorized.write_text(
            self.public_key + "\n" + self.second_public_key + "\n", encoding="utf-8"
        )
        listing = self.capture(list_keys, self.authorized, self.pending)
        self.assertTrue(all(item["deletable"] for item in listing["items"]))
        deleted = self.capture(
            delete_key, self.authorized, self.pending, listing["items"][0]["key_id"]
        )
        self.assertTrue(deleted["deleted"])
        self.assertEqual(self.authorized.read_text(encoding="utf-8").strip(), self.second_public_key)
        remaining = self.capture(list_keys, self.authorized, self.pending)
        self.assertFalse(remaining["items"][0]["deletable"])
        with self.assertRaises(SystemExit):
            delete_key(self.authorized, self.pending, remaining["items"][0]["key_id"])

    def test_rename_changes_only_comment(self) -> None:
        self.authorized.parent.mkdir(parents=True)
        self.authorized.write_text(self.public_key + "\n", encoding="utf-8")
        listing = self.capture(list_keys, self.authorized, self.pending)
        with patch("sys.stdin", io.StringIO(json.dumps({"name": "家庭台式机"}))):
            renamed = self.capture(
                rename_key, self.authorized, self.pending, listing["items"][0]["key_id"]
            )
        self.assertTrue(renamed["renamed"])
        self.assertEqual(renamed["name"], "家庭台式机")
        original_parts = self.public_key.split(maxsplit=2)
        updated_parts = self.authorized.read_text(encoding="utf-8").split(maxsplit=2)
        self.assertEqual(updated_parts[:2], original_parts[:2])
        self.assertEqual(updated_parts[2].strip(), "家庭台式机")


if __name__ == "__main__":
    unittest.main()
