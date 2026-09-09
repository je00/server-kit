#!/usr/bin/env python3
"""验证多机场事实目录、旧配置迁移和脱敏状态。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lib.server_kit_proxy_resources import (
    ProxyResourceError,
    normalized_config,
    overview,
    reveal,
    selected_exit_ids,
    test_resources,
    update,
)


EXIT_YAML = "type: socks5\nserver: exit.example.test\nport: 1080\nusername: user\npassword: secret\n"


class ProxyResourceTests(unittest.TestCase):
    def bootstrap(self, path: Path) -> dict:
        return update(path, {
            "airport_url": "https://user:secret@example.test/sub?token=private",
            "exit_proxy_yaml": EXIT_YAML,
        })

    def test_legacy_bootstrap_migrates_and_overview_hides_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            result = self.bootstrap(path)
            self.assertTrue(result["configured"])
            self.assertEqual(result["airports"][0]["host"], "example.test")
            self.assertEqual(result["airports"][0]["countries"], ["all"])
            encoded = json.dumps(overview(path), ensure_ascii=False)
            self.assertNotIn("private", encoded)
            self.assertNotIn("password", encoded)
            self.assertNotIn("user:secret", encoded)
            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stored["version"], 4)
            self.assertNotIn("airport_url", stored)
            self.assertNotIn("exit_proxy", stored)
            self.assertEqual(stored["exits"][0]["proxy"]["dialer-proxy"], "MID")
            self.assertEqual(stored["default_exit_id"], stored["exits"][0]["id"])
            self.assertEqual(
                stored["exits"][0]["proxy"]["name"],
                "EXIT.Default",
            )

    def test_add_update_disable_and_delete_multiple_airports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            self.bootstrap(path)
            added = update(path, {
                "operation": "airport_add", "airport_name": "备用机场",
                "airport_url": "https://backup.test/sub?token=two",
                "airport_enabled": True, "countries": ["hk", "jp"],
            })
            airport = added["airports"][1]
            self.assertEqual(added["airport_count"], 2)
            self.assertEqual(airport["country_labels"], ["香港", "日本"])
            updated = update(path, {
                "operation": "airport_update", "airport_id": airport["id"],
                "airport_name": "备用二号", "airport_url": "",
                "airport_enabled": False, "countries": ["all", "us"],
            })
            self.assertEqual(updated["active_airport_count"], 1)
            self.assertEqual(updated["airports"][1]["countries"], ["all"])
            deleted = update(path, {"operation": "airport_delete", "airport_id": airport["id"]})
            self.assertEqual(deleted["airport_count"], 1)

    def test_sensitive_reveal_returns_only_requested_airport_or_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            overview_result = self.bootstrap(path)
            airport = overview_result["airports"][0]

            link = reveal(path, "airport-link", airport["id"])
            self.assertEqual(link["resource"], "proxy_airport_link")
            self.assertEqual(
                link["value"],
                "https://user:secret@example.test/sub?token=private",
            )
            exit_config = reveal(path, "exit-config", "current")
            self.assertEqual(exit_config["resource"], "proxy_exit_config")
            self.assertIn("password: secret", exit_config["value"])
            self.assertIn("dialer-proxy: MID", exit_config["value"])
            with self.assertRaisesRegex(ProxyResourceError, "不存在"):
                reveal(path, "airport-link", "ffffffffffff")

    def test_multiple_exits_default_selection_and_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            initial = self.bootstrap(path)
            first_id = initial["default_exit_id"]
            added = update(path, {
                "operation": "exit_add", "exit_id": "", "exit_name": "Backup",
                "exit_default": False, "exit_proxy_yaml": EXIT_YAML.replace("1080", "1081"),
            })
            second_id = next(item["id"] for item in added["exits"] if item["id"] != first_id)
            self.assertEqual(
                normalized_config(path)["exits"][1]["proxy"]["name"],
                "EXIT.Backup",
            )
            update(path, {
                "operation": "exit_update", "exit_id": second_id,
                "exit_name": "Renamed Backup", "exit_default": False,
                "exit_proxy_yaml": "",
            })
            self.assertEqual(
                normalized_config(path)["exits"][1]["proxy"]["name"],
                "EXIT.Renamed.Backup",
            )
            selected = update(path, {
                "operation": "node_exits_set", "awg_name": "home-phone",
                "exit_ids": [first_id, second_id],
            })
            stored = normalized_config(path)
            self.assertEqual(stored["awg_exit_selections"]["home-phone"], [first_id, second_id])
            self.assertEqual(selected["exit_count"], 2)
            update(path, {
                "operation": "node_exits_set", "awg_name": "direct-phone",
                "exit_ids": [],
            })
            stored = normalized_config(path)
            self.assertEqual(stored["awg_exit_selections"]["direct-phone"], [])
            self.assertEqual(selected_exit_ids(stored, "direct-phone"), [])
            promoted = update(path, {"operation": "exit_delete", "exit_id": first_id})
            self.assertEqual(promoted["default_exit_id"], second_id)
            self.assertEqual(normalized_config(path)["awg_exit_selections"]["home-phone"], [second_id])
            with self.assertRaisesRegex(ProxyResourceError, "至少保留"):
                update(path, {"operation": "exit_delete", "exit_id": second_id})

    def test_exit_publish_names_are_readable_and_must_be_unambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            self.bootstrap(path)
            update(path, {
                "operation": "exit_add", "exit_id": "", "exit_name": "example-us",
                "exit_default": False, "exit_proxy_yaml": EXIT_YAML.replace("1080", "1081"),
            })
            self.assertEqual(
                normalized_config(path)["exits"][1]["proxy"]["name"],
                "EXIT.example.us",
            )
            with self.assertRaisesRegex(ProxyResourceError, "英文字母或数字"):
                update(path, {
                    "operation": "exit_add", "exit_id": "", "exit_name": "纯中文出口",
                    "exit_default": False, "exit_proxy_yaml": EXIT_YAML,
                })
            with self.assertRaisesRegex(ProxyResourceError, "重复的发布名称"):
                update(path, {
                    "operation": "exit_add", "exit_id": "", "exit_name": "example us",
                    "exit_default": False, "exit_proxy_yaml": EXIT_YAML,
                })

    def test_duplicate_names_and_empty_country_selection_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            self.bootstrap(path)
            with self.assertRaisesRegex(ProxyResourceError, "名称重复"):
                update(path, {
                    "operation": "airport_add", "airport_name": "默认机场",
                    "airport_url": "https://other.test/sub", "airport_enabled": True,
                    "countries": ["hk"],
                })
            with self.assertRaisesRegex(ProxyResourceError, "至少选择"):
                update(path, {
                    "operation": "airport_add", "airport_name": "其他",
                    "airport_url": "https://other.test/sub", "airport_enabled": True,
                    "countries": [],
                })

    def test_old_version_two_is_read_without_immediate_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            path.write_text(json.dumps({
                "version": 2, "airport_url": "https://old.test/sub",
                "exit_proxy": {"type": "http", "server": "exit.test", "port": 8080},
            }), encoding="utf-8")
            config = normalized_config(path)
            self.assertEqual(config["airports"][0]["url"], "https://old.test/sub")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], 2)

    def test_health_returns_each_airport_and_ignores_disabled_failure_for_all_ok(self) -> None:
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _size): return b"x"

        class Connection:
            def __enter__(self): return self
            def __exit__(self, *_args): return False

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash-inputs.json"
            self.bootstrap(path)
            added = update(path, {
                "operation": "airport_add", "airport_name": "停用机场",
                "airport_url": "https://disabled.test/sub", "airport_enabled": False,
                "countries": ["all"],
            })
            disabled_id = added["airports"][1]["id"]

            def open_resource(request, timeout):
                if "disabled.test" in request.full_url:
                    raise OSError("不可达")
                return Response()

            with patch("lib.server_kit_proxy_resources.urlopen", side_effect=open_resource), patch(
                "lib.server_kit_proxy_resources.socket.create_connection", return_value=Connection()
            ):
                result = test_resources(path)
            self.assertTrue(result["all_ok"])
            self.assertEqual(len(result["airports"]), 2)
            disabled = next(item for item in result["airports"] if item["id"] == disabled_id)
            self.assertFalse(disabled["ok"])
            self.assertFalse(disabled["enabled"])


if __name__ == "__main__":
    unittest.main()
