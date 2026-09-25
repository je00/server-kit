#!/usr/bin/env python3
"""验证 Clash 敏感资源只按单节点、单用途返回。"""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_secret_resources import (
    PNG_SIGNATURE,
    SecretResourceError,
    build_clash_subscription_resource,
    build_file_download_resource,
)


class SecretResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = Path(self.temporary.name) / "clash.json"
        self.config.write_text(json.dumps({
            "mode": "clash", "server_address": "203.0.113.188", "port": 52541,
            "downloads": [{"peer_name": "home-iphone", "download_name": "手机 订阅.yaml", "token": "a" * 64}],
        }), encoding="utf-8")

    def test_link_only_returns_selected_node_and_does_not_render_qr(self) -> None:
        calls: list[str] = []
        result = build_clash_subscription_resource(
            self.config, "subscription-link", "home-iphone",
            lambda value: calls.append(value) or PNG_SIGNATURE,
        )
        self.assertEqual(calls, [])
        self.assertEqual(result["item_id"], "home-iphone")
        self.assertIn("%E6%89%8B%E6%9C%BA%20%E8%AE%A2%E9%98%85.yaml", result["value"])
        self.assertNotIn("image_base64", result)

    def test_qr_returns_png_without_original_link(self) -> None:
        png = PNG_SIGNATURE + b"\x00\x00\x00\rIHDR" + (128).to_bytes(4, "big") * 2
        result = build_clash_subscription_resource(
            self.config, "subscription-qr", "home-iphone", lambda _value: png
        )
        self.assertEqual(base64.b64decode(result["image_base64"]), png)
        self.assertNotIn("value", result)
        self.assertNotIn("url", json.dumps(result))

    def test_invalid_or_missing_node_is_rejected(self) -> None:
        with self.assertRaisesRegex(SecretResourceError, "节点标识"):
            build_clash_subscription_resource(self.config, "subscription-link", "../bad", lambda _: PNG_SIGNATURE)
        with self.assertRaisesRegex(SecretResourceError, "不存在"):
            build_clash_subscription_resource(self.config, "subscription-link", "missing", lambda _: PNG_SIGNATURE)

    def test_file_resource_link_and_qr_are_selected_by_opaque_id(self) -> None:
        path = Path(self.temporary.name) / "files.json"
        path.write_text(json.dumps({
            "mode": "file", "server_address": "10.20.0.1", "port": 8443,
            "downloads": [{
                "resource_id": "file-1234567890abcdef", "token": "b" * 64,
                "download_name": "large file.bin",
            }],
        }), encoding="utf-8")
        link = build_file_download_resource(path, "file-link", "file-1234567890abcdef", lambda _: PNG_SIGNATURE)
        self.assertEqual(link["resource"], "file_download_link")
        self.assertIn("large%20file.bin", link["value"])
        png = PNG_SIGNATURE + b"\x00\x00\x00\rIHDR" + (128).to_bytes(4, "big") * 2
        qr = build_file_download_resource(path, "file-qr", "file-1234567890abcdef", lambda _: png)
        self.assertEqual(qr["resource"], "file_download_qr")
        self.assertNotIn("value", qr)


if __name__ == "__main__":
    unittest.main()
