import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lib.server_kit_file_resources import FileResourceError, add, detach, overview, purge


class FileResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "config.json"
        self.data = self.root / "data"
        self.data.mkdir()
        first = self.data / "shared-file.yaml"
        first.write_bytes(b"first")
        self.config.write_text(json.dumps({
            "port": 52541,
            "server_address": "10.20.0.1",
            "token": "a" * 64,
            "download_name": "shared_file.yaml",
            "payload_path": str(first),
            "sha256": "1" * 64,
            "file_size": 5,
            "cert_path": "/cert",
            "key_path": "/key",
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_add_normalizes_legacy_and_keeps_multiple_resources(self) -> None:
        upload = self.root / "upload"
        upload.write_bytes(b"second payload")
        with patch("lib.server_kit_file_resources.os.chown") as chown:
            result = add(self.config, upload, "second.bin", True, 3600, self.data, 1024)
        payload_calls = [
            call for call in chown.call_args_list
            if Path(call.args[0]) == Path(result["payload_path"])
        ]
        self.assertEqual(len(payload_calls), 1)
        self.assertEqual(payload_calls[0].args[1:], (0, self.config.stat().st_gid))
        state = overview(self.config, "运行中")
        self.assertEqual(len(state["items"]), 2)
        self.assertEqual(state["items"][1]["resource_id"], result["resource_id"])
        self.assertTrue(state["items"][1]["cdn_cache"])
        saved = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(saved["mode"], "file")
        self.assertNotIn("token", saved)

    def test_detach_then_purge_removes_only_selected_payload(self) -> None:
        upload = self.root / "upload"
        upload.write_bytes(b"second")
        with patch("lib.server_kit_file_resources.os.chown"):
            added = add(self.config, upload, "second.bin", False, 86400, self.data, 1024)
        detached = detach(self.config, added["resource_id"])
        self.assertTrue(Path(detached["payload_path"]).exists())
        purge(Path(detached["payload_path"]), self.data)
        self.assertFalse(Path(detached["payload_path"]).exists())
        self.assertEqual(len(overview(self.config, "运行中")["items"]), 1)

    def test_rejects_oversized_upload_without_leaving_file(self) -> None:
        upload = self.root / "upload"
        upload.write_bytes(b"12345")
        with self.assertRaises(FileResourceError):
            add(self.config, upload, "large.bin", True, 3600, self.data, 4)
        self.assertEqual(list((self.data / "files").glob("file-*")), [])

    def test_can_delete_last_resource_and_keep_empty_service(self) -> None:
        resource_id = overview(self.config, "运行中")["items"][0]["resource_id"]
        detached = detach(self.config, resource_id)
        purge(Path(detached["payload_path"]), self.data)
        self.assertEqual(overview(self.config, "运行中")["items"], [])


if __name__ == "__main__":
    unittest.main()
