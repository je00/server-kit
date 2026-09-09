#!/usr/bin/env python3
"""验证管理网站内置 AWG 生成器不会把客户端私钥放进登记信息。"""

from __future__ import annotations

import base64
import json
import subprocess
import unittest
from pathlib import Path

from lib.server_kit_bootstrap import decode_enrollment_token


class WebKeyGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.awg = self.root / "web" / "static" / "awg.js"
        self.app = self.root / "web" / "static" / "app.js"

    def run_node(self, source: str) -> str:
        completed = subprocess.run(
            ["node", "-e", source], check=True, capture_output=True, text=True,
        )
        return completed.stdout.strip()

    def test_registration_token_excludes_private_key(self) -> None:
        source = (
            "globalThis.crypto=require('crypto').webcrypto;"
            f"require({json.dumps(str(self.awg))});"
            "const keys=serverKitAwg.generateKeyMaterial();"
            "console.log(JSON.stringify({keys,token:serverKitAwg.enrollmentToken("
            "'home-laptop','10.20.0.23',keys)}));"
        )
        value = json.loads(self.run_node(source))
        enrollment = decode_enrollment_token(value["token"], "home-laptop")
        self.assertEqual(enrollment.public_key, value["keys"]["publicKey"])
        padding = "=" * (-len(value["token"]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(value["token"] + padding))
        self.assertNotIn("private_key", payload)
        self.assertNotIn(value["keys"]["privateKey"], json.dumps(payload))

    def test_two_profiles_share_one_local_identity(self) -> None:
        context = {
            "schema_version": 1,
            "network": "10.20.0.0/24",
            "suggested_address": "10.20.0.23",
            "prefix": 24,
            "mtu": 1280,
            "server_public_key": base64.b64encode(bytes([7]) * 32).decode(),
            "endpoints": [
                {"profile": "main", "host": "203.0.113.10", "port": 443},
                {"profile": "backup1", "host": "203.0.113.10", "port": 1848},
            ],
            "obfuscation": {
                "Jc": 4, "Jmin": 40, "Jmax": 70, "S1": 55, "S2": 50,
                "S3": 24, "S4": 13, "H1": 1001, "H2": 1002,
                "H3": 1003, "H4": 1004, "I1": "<b 0x01020304>",
            },
        }
        source = (
            "globalThis.crypto=require('crypto').webcrypto;"
            f"require({json.dumps(str(self.awg))});"
            f"const context=serverKitAwg.parseBootstrapContext({json.dumps(json.dumps(context))});"
            "const keys=serverKitAwg.generateKeyMaterial();"
            "console.log(JSON.stringify(context.endpoints.map(endpoint=>"
            "serverKitAwg.renderConfig(context,'10.20.0.23',endpoint,keys))));"
        )
        profiles = json.loads(self.run_node(source))
        self.assertEqual(len(profiles), 2)
        private_lines = {
            next(line for line in profile.splitlines() if line.startswith("PrivateKey = "))
            for profile in profiles
        }
        self.assertEqual(len(private_lines), 1)
        self.assertIn("Endpoint = 203.0.113.10:443", profiles[0])
        self.assertIn("Endpoint = 203.0.113.10:1848", profiles[1])

    def test_page_flow_uses_short_lived_tab_storage(self) -> None:
        source = self.app.read_text(encoding="utf-8")
        self.assertIn("window.sessionStorage", source)
        self.assertIn("5 * 60 * 1000", source)
        self.assertIn("downloadGeneratedText", source)
        self.assertIn("data-awg-enrollment-token", source)
        self.assertNotIn("localStorage", source)


if __name__ == "__main__":
    unittest.main()
