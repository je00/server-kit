#!/usr/bin/env python3
"""验证通用 AWG 节点登记信息不会携带客户端私钥。"""

from __future__ import annotations

import base64
import json
import unittest

from lib.server_kit_bootstrap import BootstrapError, decode_enrollment_token


def key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


def token(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class BootstrapEnrollmentTests(unittest.TestCase):
    def test_valid_client_held_enrollment_token_is_decoded(self) -> None:
        value = {
            "format": "server-kit-awg-enrollment-v1",
            "name": "admin-home",
            "address": "10.20.0.2",
            "public_key": key(1),
            "preshared_key": key(2),
        }
        enrollment = decode_enrollment_token(token(value), "admin-home")
        self.assertEqual(enrollment.address, "10.20.0.2")
        self.assertEqual(enrollment.public_key, key(1))

    def test_web_import_can_decode_without_an_expected_name(self) -> None:
        value = {
            "format": "server-kit-awg-enrollment-v1",
            "name": "home-laptop",
            "address": "10.20.0.88",
            "public_key": key(1),
            "preshared_key": key(2),
        }
        enrollment = decode_enrollment_token(token(value))
        self.assertEqual(enrollment.name, "home-laptop")

    def test_legacy_bootstrap_token_remains_accepted(self) -> None:
        value = {
            "format": "server-kit-awg-bootstrap-v1",
            "name": "admin-home",
            "address": "10.20.0.2",
            "public_key": key(1),
            "preshared_key": key(2),
        }
        self.assertEqual(decode_enrollment_token(token(value), "admin-home").name, "admin-home")

    def test_private_key_extra_field_and_name_mismatch_are_rejected(self) -> None:
        value = {
            "format": "server-kit-awg-enrollment-v1",
            "name": "admin-home",
            "address": "10.20.0.2",
            "public_key": key(1),
            "preshared_key": key(2),
            "private_key": key(3),
        }
        with self.assertRaisesRegex(BootstrapError, "字段"):
            decode_enrollment_token(token(value), "admin-home")
        del value["private_key"]
        with self.assertRaisesRegex(BootstrapError, "名称"):
            decode_enrollment_token(token(value), "other-admin")

    def test_invalid_key_length_is_rejected(self) -> None:
        value = {
            "format": "server-kit-awg-enrollment-v1",
            "name": "admin-home",
            "address": "10.20.0.2",
            "public_key": base64.b64encode(b"short").decode("ascii"),
            "preshared_key": key(2),
        }
        with self.assertRaisesRegex(BootstrapError, "公钥"):
            decode_enrollment_token(token(value), "admin-home")


if __name__ == "__main__":
    unittest.main()
