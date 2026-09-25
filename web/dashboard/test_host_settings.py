"""The first-login SSH tunnel must work with production Host validation."""

from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.exceptions import DisallowedHost
from django.test import RequestFactory, SimpleTestCase, override_settings


class HostSettingsTests(SimpleTestCase):
    def load_settings(self, *, testing=False, allowed_hosts="10.20.0.1"):
        settings_path = Path(__file__).resolve().parents[1] / "server_kit_web" / "settings.py"
        with tempfile.TemporaryDirectory(prefix="server-kit-host-settings-") as directory:
            secret_path = Path(directory) / "secret-key"
            secret_path.write_text("host-validation-test-secret-" * 3, encoding="utf-8")
            environment = {
                "SERVER_KIT_TESTING": "1" if testing else "0",
                "SERVER_KIT_ALLOWED_HOSTS": allowed_hosts,
                "SERVER_KIT_SECRET_KEY_FILE": str(secret_path),
                "SERVER_KIT_WEB_STATE": directory,
            }
            with patch.dict(os.environ, environment):
                spec = importlib.util.spec_from_file_location("host_settings_under_test", settings_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            return module

    def test_production_explicit_awg_host_keeps_first_login_loopback_hosts(self):
        configured = self.load_settings()
        self.assertFalse(configured.TESTING)
        self.assertEqual(configured.ALLOWED_HOSTS, ["10.20.0.1", "127.0.0.1", "localhost"])
        with override_settings(ALLOWED_HOSTS=configured.ALLOWED_HOSTS):
            for host in ("10.20.0.1:9080", "127.0.0.1:9080", "localhost:9080"):
                with self.subTest(host=host):
                    self.assertEqual(RequestFactory().get("/", HTTP_HOST=host).get_host(), host)

    def test_production_rejects_unconfigured_hosts(self):
        configured = self.load_settings()
        with override_settings(ALLOWED_HOSTS=configured.ALLOWED_HOSTS):
            for host in ("untrusted.example", "testserver", "10.20.0.2", "127.0.0.2", "localhost.example"):
                with self.subTest(host=host), self.assertRaises(DisallowedHost):
                    RequestFactory().get("/", HTTP_HOST=host).get_host()

    def test_custom_awg_host_is_preserved_and_loopback_hosts_are_not_duplicated(self):
        configured = self.load_settings(allowed_hosts="10.42.0.1, localhost,127.0.0.1,10.42.0.1")
        self.assertEqual(configured.ALLOWED_HOSTS, ["10.42.0.1", "localhost", "127.0.0.1"])
        self.assertNotIn("*", configured.ALLOWED_HOSTS)

    def test_testing_only_adds_testserver_to_production_hosts(self):
        production = self.load_settings()
        testing = self.load_settings(testing=True)
        self.assertEqual(testing.ALLOWED_HOSTS, [*production.ALLOWED_HOSTS, "testserver"])
