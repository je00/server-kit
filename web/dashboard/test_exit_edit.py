"""Exit edits preserve advanced options and keep credential reads explicit."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .views import _exit_proxy_yaml_from_post


EXIT_ID = "333333333333"
LOGIN_PASSWORD = "test-password-only"
BASE_PROXY = {
    "name": "preserved-proxy-name",
    "type": "socks5",
    "server": "old.example.com",
    "port": 1080,
    "username": "private-old-user",
    "password": "private-old-password",
    "tls": True,
    "skip-cert-verify": False,
    "udp": False,
    "dialer-proxy": "upstream-chain",
    "interface-name": "eth9",
    "unknown-option": {"list": ["value", 7, False], "flag": None},
}
TASK_PREVIEW = {
    "id": "task-" + "a" * 32,
    "state": "waiting_confirmation",
    "state_label": "待确认",
    "preview": {
        "title": "更新出口节点",
        "summary": "确认更新出口节点并刷新订阅。",
        "facts": {"出口": "更新后的出口"},
    },
}
SAFE_RESOURCES = {
    "configured": True,
    "revision": "a" * 64,
    "airport_count": 0,
    "active_airport_count": 0,
    "airports": [],
    "country_options": [],
    "exit_count": 1,
    "default_exit_id": EXIT_ID,
    "exit": {"configured": True, "type": "socks5", "server": "old.example.com", "port": 1080},
    "exits": [{
        "id": EXIT_ID, "name": "默认出口", "default": True,
        "type": "socks5", "server": "old.example.com", "port": 1080,
    }],
}


def field_values(**overrides):
    return {
        "operation": "exit_update",
        "exit_id": EXIT_ID,
        "exit_name": "更新后的出口",
        "exit_input_mode": "fields",
        "exit_proxy_base": json.dumps(BASE_PROXY),
        "exit_field_type": "socks5",
        "exit_field_server": "new.example.com",
        "exit_field_port": "2080",
        "exit_field_username": "private-new-user",
        "exit_field_password": "private-new-password",
        "confirmed": "yes",
        "password": LOGIN_PASSWORD,
        **overrides,
    }


class ExitFieldReplacementTests(SimpleTestCase):
    def test_update_preserves_advanced_options_and_overlays_only_basic_fields(self):
        result = json.loads(_exit_proxy_yaml_from_post(field_values(), "exit_update"))
        self.assertEqual(result, {
            **BASE_PROXY,
            "server": "new.example.com", "port": 2080,
            "username": "private-new-user", "password": "private-new-password",
        })
        self.assertIs(result["udp"], False)

    def test_update_removes_both_credentials_when_both_are_empty(self):
        result = json.loads(_exit_proxy_yaml_from_post(field_values(
            exit_field_username="", exit_field_password="",
        ), "exit_update"))
        self.assertNotIn("username", result)
        self.assertNotIn("password", result)
        self.assertEqual(result["unknown-option"], BASE_PROXY["unknown-option"])

    def test_update_does_not_invent_udp_or_tls_defaults(self):
        result = json.loads(_exit_proxy_yaml_from_post(field_values(
            exit_proxy_base=json.dumps({"type": "socks5", "server": "old.test", "port": 1080}),
        ), "exit_update"))
        self.assertNotIn("udp", result)
        self.assertNotIn("tls", result)

    def test_update_requires_valid_socks5_json_object_without_nuls(self):
        bad_bases = (
            "", "{private-old-password", "null", "true", "[]", '"secret"', "{}",
            '{"type":"http"}', '{"type":false}',
            '{"type":"socks5","password":"private-old-password\u0000"}',
            '{"type":"socks5","nested":[{"value":"\\u0000"}]}',
            '{"type":"socks5","\\u0000":"value"}',
            '{"type":"socks5","nested":NaN}',
            '{"type":"socks5","nested":Infinity}',
            '{"type":"socks5","nested":1e10000}',
        )
        for raw_base in bad_bases:
            with self.subTest(raw_base=raw_base[:60]):
                with self.assertRaises(ValueError) as caught:
                    _exit_proxy_yaml_from_post(field_values(exit_proxy_base=raw_base), "exit_update")
                self.assertNotIn("private-old-password", str(caught.exception))

    def test_update_rejects_missing_base(self):
        values = field_values()
        del values["exit_proxy_base"]
        with self.assertRaisesRegex(ValueError, "请先读取当前出口配置"):
            _exit_proxy_yaml_from_post(values, "exit_update")

    def test_update_rejects_invalid_fields_and_partial_credentials(self):
        invalid_fields = (
            {"exit_input_mode": "unknown"}, {"exit_field_type": "http"},
            {"exit_field_server": ""}, {"exit_field_server": "bad server.test"},
            {"exit_field_server": "bad\x00.test"}, {"exit_field_server": "x" * 254},
            {"exit_field_port": "0"}, {"exit_field_port": "65536"},
            {"exit_field_port": "true"}, {"exit_field_port": "01080"},
            {"exit_field_username": ""}, {"exit_field_password": ""},
            {"exit_field_username": "x" * 257}, {"exit_field_password": "x" * 257},
            {"exit_field_password": "invalid\x00credential"},
        )
        for values in invalid_fields:
            with self.subTest(values=values), self.assertRaises(ValueError):
                _exit_proxy_yaml_from_post(field_values(**values), "exit_update")

    def test_update_limits_both_base_and_final_replacement(self):
        with self.assertRaisesRegex(ValueError, "配置过长"):
            _exit_proxy_yaml_from_post(field_values(exit_proxy_base="x" * 65537), "exit_update")

        base = {"type": "socks5", "server": "a", "port": 1, "advanced": ""}
        compact = json.dumps(base, separators=(",", ":"))
        base["advanced"] = "x" * (65530 - len(compact))
        raw_base = json.dumps(base, separators=(",", ":"))
        self.assertEqual(len(raw_base), 65530)
        with self.assertRaisesRegex(ValueError, "配置过长"):
            _exit_proxy_yaml_from_post(field_values(exit_proxy_base=raw_base), "exit_update")

    def test_add_keeps_existing_yaml_and_udp_default_without_base(self):
        values = field_values(exit_field_username="alice", exit_field_password="p@ss: #word")
        del values["exit_proxy_base"]
        self.assertEqual(_exit_proxy_yaml_from_post(values, "exit_add"), (
            'type: "socks5"\nserver: "new.example.com"\nport: 2080\n'
            'username: "alice"\npassword: "p@ss: #word"\nudp: true\n'
        ))

    def test_yaml_and_legacy_inputs_are_passed_through_without_base(self):
        for operation in ("exit_add", "exit_update", "airport_update", "set"):
            for raw_yaml in ("", "type: http\nserver: other.example.com\nport: 80\n"):
                with self.subTest(operation=operation, raw_yaml=raw_yaml):
                    values = {"exit_proxy_yaml": raw_yaml}
                    self.assertEqual(_exit_proxy_yaml_from_post(values, operation), raw_yaml)
                    values["exit_input_mode"] = "yaml"
                    self.assertEqual(_exit_proxy_yaml_from_post(values, operation), raw_yaml)


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ExitEditAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model().objects
        cls.owner = users.create_superuser("exit-owner", password=LOGIN_PASSWORD)
        cls.admin = users.create_user("exit-admin", password=LOGIN_PASSWORD, is_staff=True)
        cls.viewer = users.create_user("exit-viewer", password=LOGIN_PASSWORD)

    def setUp(self):
        self.client.force_login(self.owner)
        self.url = reverse("network-proxy-resources")

    def unlock(self):
        session = self.client.session
        session["sensitive_resource_unlocked_at"] = int(time.time())
        session.save()

    @patch("dashboard.views.reveal_proxy_resource")
    @patch("dashboard.views.proxy_resources", return_value=SAFE_RESOURCES)
    def test_page_never_reads_or_renders_credentials_even_when_unlocked(self, resources, reveal):
        for unlocked in (False, True):
            if unlocked:
                self.unlock()
            with self.subTest(unlocked=unlocked):
                response = self.client.get(self.url)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "old.example.com")
                self.assertIn("no-store", response["Cache-Control"])
                for secret in ("private-old-user", "private-old-password", "upstream-chain"):
                    self.assertNotContains(response, secret)
        self.assertEqual(resources.call_count, 2)
        reveal.assert_not_called()

    @patch("dashboard.views.reveal_proxy_resource")
    @patch("dashboard.views.preview_proxy_change_task", return_value=TASK_PREVIEW)
    def test_rename_with_blank_yaml_keeps_configuration_without_secret_read(self, preview, reveal):
        response = self.client.post(self.url, {
            "operation": "exit_update", "exit_id": EXIT_ID,
            "exit_name": "更新后的出口", "exit_proxy_yaml": "",
            "confirmed": "yes", "password": LOGIN_PASSWORD,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(preview.call_args.args[0]["exit_proxy_yaml"], "")
        self.assertEqual(preview.call_args.args[0]["exit_name"], "更新后的出口")
        self.assertEqual(preview.call_args.args[1], "exit-owner")
        reveal.assert_not_called()

    @patch("dashboard.views.reveal_proxy_resource")
    @patch("dashboard.views.preview_proxy_change_task", return_value=TASK_PREVIEW)
    def test_field_edit_reaches_existing_preview_without_echoing_or_storing_secrets(self, preview, reveal):
        response = self.client.post(self.url, field_values())
        self.assertEqual(response.status_code, 200)
        submitted = preview.call_args.args[0]
        self.assertEqual(submitted["operation"], "exit_update")
        self.assertEqual(submitted["exit_id"], EXIT_ID)
        self.assertIs(json.loads(submitted["exit_proxy_yaml"])["udp"], False)
        self.assertNotIn("exit_proxy_base", submitted)
        for secret in ("private-old-password", "private-new-password", "private-new-user"):
            self.assertNotContains(response, secret)
            self.assertNotIn(secret, json.dumps(dict(self.client.session)))
        reveal.assert_not_called()

    @patch("dashboard.views.preview_proxy_change_task")
    def test_update_preserves_confirmation_password_and_role_gates(self, preview):
        for values in ({"confirmed": ""}, {"password": "wrong"}):
            with self.subTest(values=values):
                response = self.client.post(self.url, field_values(**values))
                self.assertEqual(response.status_code, 302)
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.post(self.url, field_values()).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.post(self.url, field_values()).status_code, 302)
        preview.assert_not_called()

    @patch("dashboard.views.preview_proxy_change_task", return_value=TASK_PREVIEW)
    def test_staff_can_still_submit_full_replacement_through_existing_gate(self, preview):
        self.client.force_login(self.admin)
        response = self.client.post(self.url, field_values())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(preview.call_args.args[1], "exit-admin")

    @patch("dashboard.views.reveal_proxy_resource")
    @patch("dashboard.views.preview_proxy_change_task")
    def test_invalid_base_blocks_task_and_only_reports_safe_error(self, preview, reveal):
        response = self.client.post(self.url, field_values(exit_proxy_base='{"private-old-password"'))
        self.assertEqual(response.status_code, 302)
        errors = [str(item) for item in get_messages(response.wsgi_request)]
        self.assertEqual(errors, ["当前出口配置无效，请重新读取后编辑。"])
        self.assertNotIn("private-old-password", json.dumps(dict(self.client.session)))
        preview.assert_not_called()
        reveal.assert_not_called()

    @patch("dashboard.views.reveal_proxy_resource")
    def test_load_requires_superuser_unlock_and_post_and_returns_uncached_proxy(self, reveal):
        reveal.return_value = {
            "resource": "proxy_exit_config", "item_id": EXIT_ID,
            "name": "默认出口", "value": "sensitive YAML", "proxy": BASE_PROXY,
        }
        url = reverse("network-proxy-secret", args=[EXIT_ID, "exit"])
        self.assertEqual(self.client.get(url).status_code, 405)
        locked = self.client.post(url)
        self.assertEqual(locked.status_code, 403)
        self.assertEqual(locked.json()["code"], "sensitive_unlock_required")
        self.assertIn("no-store", locked["Cache-Control"])
        self.unlock()
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["proxy"], BASE_PROXY)
        self.assertIn("no-store", response["Cache-Control"])
        reveal.assert_called_once_with("exit_config", EXIT_ID, "exit-owner")

        reveal.reset_mock()
        self.client.force_login(self.admin)
        self.unlock()
        forbidden = self.client.post(url)
        self.assertEqual(forbidden.status_code, 403)
        self.assertIn("no-store", forbidden["Cache-Control"])
        reveal.assert_not_called()
