#!/usr/bin/env python3
"""出口 DNS worker 在主 Xray 切换前后的事务边界。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lib.server_kit_exit_dns import ExitDNSLifecycleError, Lifecycle, UNIT_NAME


PRIMARY = "111111111111"
SECONDARY = "222222222222"


def worker(port: int) -> dict:
    return {"inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                           "settings": {"auth": "password", "accounts": [{"user": "local", "pass": "secret"}]}}],
            "outbounds": [{"protocol": "freedom"}]}


class FakeLifecycle(Lifecycle):
    def __init__(self, args):
        super().__init__(args)
        self.actions = []
        self.services = {}
        self.probe_failure = False

    def systemctl(self, *arguments, check=True):
        self.actions.append(arguments)
        if arguments[0] == "daemon-reload":
            return True
        service = arguments[-1]
        state = self.services.setdefault(service, {"active": False, "enabled": False})
        if arguments[0] == "is-active":
            return state["active"]
        if arguments[0] == "is-enabled":
            return state["enabled"]
        if arguments[0] in {"start", "restart"}:
            state["active"] = True
        if arguments[0] == "stop" or "--now" in arguments:
            state["active"] = False
        if arguments[0] in {"enable", "disable"}:
            state["enabled"] = arguments[0] == "enable"
        return True

    def probe(self, exit_id):
        self.actions.append(("probe", exit_id))
        if self.probe_failure:
            raise ExitDNSLifecycleError("synthetic DNS probe failure")


class ExitDNSLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.args = argparse.Namespace(worker_dir=self.root / "workers", transaction=self.root / "transaction",
                                       systemd_dir=self.root / "systemd", xray_bin=Path("/usr/local/bin/xray"),
                                       systemctl_bin=Path("/usr/bin/systemctl"), probe_host="example.com",
                                       probe_port=443, probe_timeout=25)
        self.args.systemd_dir.mkdir()
        self.manager = FakeLifecycle(self.args)
        self.validation = patch("lib.server_kit_exit_dns.subprocess.run")
        self.run = self.validation.start()
        self.addCleanup(self.validation.stop)
        self.run.return_value.returncode = 0

    def seed(self, exit_id, value, active=True, enabled=True):
        self.args.worker_dir.mkdir(exist_ok=True)
        path = self.args.worker_dir / f"{exit_id}.json"
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
        self.manager.services[self.manager._service(exit_id)] = {"active": active, "enabled": enabled}
        return path.read_bytes()

    def test_failed_candidate_validation_makes_no_service_or_installed_changes(self):
        previous = self.seed(PRIMARY, worker(25001))
        self.run.return_value.returncode = 23
        with self.assertRaises(ExitDNSLifecycleError):
            self.manager.prepare({PRIMARY: worker(25002)})
        self.assertFalse(self.manager.actions)
        self.assertEqual((self.args.worker_dir / f"{PRIMARY}.json").read_bytes(), previous)

    def test_probe_failure_can_restore_previous_worker_and_service_states(self):
        previous = self.seed(PRIMARY, worker(25001), active=True, enabled=False)
        old_unit = self.args.systemd_dir / UNIT_NAME
        old_unit.write_text("old unit\n")
        self.manager.prepare({PRIMARY: worker(25002), SECONDARY: worker(25003)})
        self.manager.probe_failure = True
        with self.assertRaises(ExitDNSLifecycleError):
            self.manager.apply()
        self.manager.rollback()
        self.assertEqual((self.args.worker_dir / f"{PRIMARY}.json").read_bytes(), previous)
        self.assertFalse((self.args.worker_dir / f"{SECONDARY}.json").exists())
        self.assertEqual(old_unit.read_text(), "old unit\n")
        self.assertEqual(self.manager.services[self.manager._service(PRIMARY)], {"active": True, "enabled": False})
        self.assertEqual(self.manager.services[self.manager._service(SECONDARY)], {"active": False, "enabled": False})

    def test_stale_workers_remain_until_commit_and_rollback_restores_them(self):
        previous = self.seed(PRIMARY, worker(25001))
        (self.args.systemd_dir / UNIT_NAME).write_text("old unit\n")
        self.manager.prepare({})
        self.manager.apply()
        self.assertTrue(self.manager.services[self.manager._service(PRIMARY)]["active"])
        self.assertTrue((self.args.worker_dir / f"{PRIMARY}.json").exists())
        self.manager.commit()
        self.assertFalse(self.manager.services[self.manager._service(PRIMARY)]["active"])
        self.assertFalse((self.args.worker_dir / f"{PRIMARY}.json").exists())
        self.manager.rollback()
        self.assertEqual((self.args.worker_dir / f"{PRIMARY}.json").read_bytes(), previous)
        self.assertTrue(self.manager.services[self.manager._service(PRIMARY)]["active"])

    def test_unchanged_worker_is_not_restarted(self):
        self.seed(PRIMARY, worker(25001))
        self.manager.prepare({PRIMARY: worker(25001)})
        self.manager.apply()
        self.manager.commit()
        self.assertNotIn(("restart", self.manager._service(PRIMARY)), self.manager.actions)
        self.assertIn(("probe", PRIMARY), self.manager.actions)
        self.assertEqual((self.args.worker_dir / f"{PRIMARY}.json").stat().st_mode & 0o777, 0o600)

    def test_empty_mode_has_no_service_mutation(self):
        self.manager.prepare({})
        self.manager.apply()
        self.manager.commit()
        self.assertFalse(self.manager.actions)
        self.assertFalse((self.args.systemd_dir / UNIT_NAME).exists())

    def test_rejects_externally_bound_worker_before_touching_services(self):
        value = worker(25001)
        value["inbounds"][0]["listen"] = "0.0.0.0"
        with self.assertRaises(ExitDNSLifecycleError):
            self.manager.prepare({PRIMARY: value})
        self.assertFalse(self.manager.actions)

    def test_rejects_unauthenticated_worker_before_touching_services(self):
        value = worker(25001)
        value["inbounds"][0]["settings"] = {"auth": "noauth"}
        with self.assertRaises(ExitDNSLifecycleError):
            self.manager.prepare({PRIMARY: value})
        self.assertFalse(self.manager.actions)

    def test_rejects_gateway_alias_with_any_private_answer(self):
        value = worker(25001)
        value["outbounds"] = [{"protocol": "socks", "settings": {
            "servers": [{"address": "proxy.example", "port": 45001}],
        }}]
        self.run.return_value.stdout = b'["1.1.1.1", "127.0.0.1"]'
        with self.assertRaisesRegex(ExitDNSLifecycleError, "代理循环"):
            self.manager.prepare({PRIMARY: value})
        self.assertFalse(self.manager.actions)
        self.run.assert_called_once()

    def test_socks_acknowledgement_without_remote_tls_is_not_healthy(self):
        self.seed(PRIMARY, worker(25001))
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.recv.side_effect = [b"\x05\x02", b"\x01\x00", b"\x05\x00\x00\x01", b"\x00" * 6]
        tls_context = MagicMock()
        tls_context.wrap_socket.side_effect = ssl.SSLError("outbound never connected")
        with patch("lib.server_kit_exit_dns.socket.create_connection", return_value=stream), \
                patch("lib.server_kit_exit_dns.ssl.create_default_context", return_value=tls_context):
            with self.assertRaises(ExitDNSLifecycleError):
                Lifecycle.probe(self.manager, PRIMARY)
        tls_context.wrap_socket.assert_called_once_with(stream, server_hostname="example.com")


if __name__ == "__main__":
    unittest.main()
