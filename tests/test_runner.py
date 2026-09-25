#!/usr/bin/env python3
"""验证生产脚本适配器只执行登记参数并留下哈希链审计。"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

from control_plane.errors import TaskExecutionError
from control_plane.runner import ScriptRunner


SNAPSHOT = {
    "schema_version": 1,
    "services": [{"id": "clash", "state": "已停止"}],
}


class ScriptRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.audit_path = Path(self.temporary.name) / "audit" / "actions.jsonl"
        self.manager_path = str(Path(self.temporary.name) / "server-kit-manager.sh")

    def completed(self, arguments: list[str], stdout: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")

    @staticmethod
    def enrollment_payload(*profiles: tuple[str, int]) -> dict:
        return {
            "schema_version": 1,
            "server_public_key": "A" * 43 + "=",
            "endpoints": [
                {"profile": profile, "host": "vpn.example.com", "port": port}
                for profile, port in profiles
            ],
        }

    def test_enrollment_context_accepts_current_two_endpoints_and_legacy_third(self) -> None:
        for profiles in (
            (("main", 443), ("backup1", 1848)),
            (("main", 443), ("backup1", 8443), ("backup2", 1848)),
        ):
            with self.subTest(profiles=profiles):
                payload = self.enrollment_payload(*profiles)
                executor = Mock(return_value=self.completed([], json.dumps(payload)))
                runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
                self.assertEqual(runner.enrollment_context(), payload)

    def test_enrollment_context_rejects_wrong_profiles_invalid_ports_and_secrets(self) -> None:
        payloads = [
            self.enrollment_payload(("main", 443)),
            self.enrollment_payload(("main", 443), ("backup2", 1848)),
            self.enrollment_payload(("main", 443), ("backup1", 0)),
            {**self.enrollment_payload(("main", 443), ("backup1", 1848)), "private_key": "secret"},
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                executor = Mock(return_value=self.completed([], json.dumps(payload)))
                runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
                with self.assertRaises(RuntimeError):
                    runner.enrollment_context()

    @staticmethod
    def proxy_overview() -> dict:
        return {
            "schema_version": 3, "revision": "a" * 64, "configured": True,
            "airport_count": 1, "active_airport_count": 1,
            "airports": [{
                "id": "111111111111", "name": "主用机场", "host": "airport.test",
                "enabled": True, "countries": ["hk"], "country_labels": ["香港"],
            }],
            "country_options": [{"id": "all", "label": "全部地区"}, {"id": "hk", "label": "香港"}],
            "exit": {"configured": True, "type": "socks5", "server": "exit.test", "port": 1080},
            "exit_count": 1, "default_exit_id": "333333333333",
            "exits": [{"id": "333333333333", "name": "默认出口", "default": True,
                "type": "socks5", "server": "exit.test", "port": 1080}],
        }

    def test_airport_catalog_update_uses_stdin_and_never_argv(self) -> None:
        payload = self.proxy_overview()
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        values = {
            "operation": "airport_add", "airport_id": "", "airport_name": "备用机场",
            "airport_url": "https://airport.test/sub?token=secret", "airport_enabled": True,
            "countries": ["hk"], "exit_proxy_yaml": "",
            "exit_id": "", "exit_name": "", "exit_default": False,
            "awg_name": "", "exit_ids": [],
        }
        result = runner.update_proxy_resources(values, "owner")
        self.assertEqual(result["airport_count"], 1)
        self.assertEqual(executor.call_args.args[0], [self.manager_path, "network", "proxy", "update", "--json"])
        self.assertNotIn("secret", " ".join(executor.call_args.args[0]))
        self.assertEqual(json.loads(executor.call_args.kwargs["input"]), values)
        self.assertNotIn("secret", self.audit_path.read_text(encoding="utf-8"))

    def test_proxy_update_surfaces_only_marked_input_diagnostic(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr=(
                "parser debug: password=must-not-leak\n"
                "SERVER_KIT_DIAGNOSTIC:proxy_input_invalid:出口节点缺少有效的 port。\n"
                "错误：机场资源内容无效，未刷新订阅。\n"
            ),
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=Mock(return_value=completed),
        )

        with self.assertRaises(TaskExecutionError) as raised:
            runner.update_proxy_resources({}, "owner")

        self.assertEqual(raised.exception.code, "proxy_input_invalid")
        self.assertIn("出口节点缺少有效的 port", raised.exception.message)
        self.assertNotIn("password", raised.exception.message)
        self.assertNotIn("must-not-leak", self.audit_path.read_text(encoding="utf-8"))

    def test_proxy_update_reports_relay_stage_without_command_output(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr=(
                "xray output with credential=must-not-leak\n"
                "SERVER_KIT_DIAGNOSTIC:proxy_relay_refresh_failed\n"
            ),
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=Mock(return_value=completed),
        )

        with self.assertRaises(TaskExecutionError) as raised:
            runner.update_proxy_resources({}, "owner")

        self.assertEqual(raised.exception.code, "proxy_relay_refresh_failed")
        self.assertIn("VLESS 中转出口刷新失败", raised.exception.message)
        self.assertNotIn("credential", raised.exception.message)

    def test_proxy_update_unmarked_failure_stays_redacted(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="password=must-not-leak\n"
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=Mock(return_value=completed),
        )

        with self.assertRaises(TaskExecutionError) as raised:
            runner.update_proxy_resources({}, "owner")

        self.assertEqual(raised.exception.code, "proxy_update_failed")
        self.assertNotIn("must-not-leak", raised.exception.message)

    def test_airport_health_accepts_partial_failure_schema(self) -> None:
        payload = {
            "schema_version": 3,
            "airports": [
                {"id": "111111111111", "name": "主用", "enabled": True, "ok": True, "status": "HTTP 200"},
                {"id": "222222222222", "name": "备用", "enabled": False, "ok": False, "status": "连接失败"},
            ],
            "exits": [{"id": "333333333333", "name": "默认出口", "default": True,
                "ok": True, "status": "TCP 可达"}], "all_ok": True,
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        result = runner.test_proxy_resources("owner")
        self.assertTrue(result["all_ok"])
        self.assertFalse(result["airports"][1]["ok"])

    def test_network_overview_accepts_client_held_node_projection(self) -> None:
        payload = {
            "schema_version": 1,
            "writes_enabled": True,
            "subscriptions_configured": True,
            "sync_available": True,
            "pending_vless": False,
            "pending_access": False,
            "management_peer": "home-desk",
            "management_port": 9080,
            "exit_options": [{"id": "333333333333", "name": "默认出口", "default": True}],
            "host_records": [{"address": "192.168.0.103", "domains": ["git.example.com"]}],
            "enrollment_history": [{
                "name": "home-laptop2", "state": "已生效",
                "completed_at": "2026-08-09T21:19:14Z",
            }],
            "summary": {
                "awg_active": 1, "awg_disabled": 0,
                "vless_active": 0, "vless_disabled": 0,
                "disabled_total": 0, "published": 0, "stale": 1,
                "pending_enrollment": 0,
            },
            "nodes": [{
                "name": "home-laptop2", "kind": "awg",
                "kind_label": "AmneziaWG", "address": "10.20.0.3",
                "state": "已启用", "published": False,
                "publication_state": "待同步",
                "detail": "普通双向节点 · 虚拟 IP 10.20.0.3",
                "protected": False, "permissions": [],
                "access_mode": "unrestricted", "custody": "client",
                "public_key_fingerprint": "0123456789abcdef",
                "domains": ["nas.internal.example"],
                "legacy_stash": False,
                "clean_mode": False,
                "exit_ids": ["333333333333"], "exit_names": ["默认出口"],
            }],
            "publications": [],
            "subscription_items": [{
                "name": "home-laptop2", "kind": "awg",
                "kind_label": "AmneziaWG", "state": "待同步",
                "published": False, "resource_id": "home-laptop2",
            }],
            "targets": [{"name": "all", "label": "全部节点"}],
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )

        self.assertEqual(runner.network_overview(), payload)

    def test_awg_all_access_uses_fixed_arguments(self) -> None:
        response = {
            "schema_version": 1, "operation": "allow",
            "client": "home-desk", "target": "all",
        }
        executor = Mock(return_value=self.completed([], json.dumps(response)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )
        self.assertEqual(
            runner.change_network_permission(
                "allow", "home-desk", "all", "", "", "owner"
            ),
            response,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "network", "permission", "allow",
            "home-desk", "all", "--json",
        ])
        self.assertIn("permission_allow", self.audit_path.read_text(encoding="utf-8"))

    def test_public_endpoint_change_uses_fixed_argv_and_audits_only_operation(self) -> None:
        payload = {
            "schema_version": 1, "operation": "apply", "fqdn": "vpn.example.com",
            "transaction_id": "b" * 64,
            "subscriptions_refreshed": True, "state": "pending",
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(), "remaining_seconds": 300,
            "rollback_seconds": 300, "independent_session": False,
            "last_outcome": "",
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        self.assertEqual(
            runner.change_public_endpoint("apply", "vpn.example.com", "owner", "a" * 64),
            payload,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "network", "public-endpoint", "apply", "--json",
        ])
        self.assertEqual(json.loads(executor.call_args.kwargs["input"]), {
            "fqdn": "vpn.example.com", "session_id": "a" * 64, "actor": "owner",
            "transaction_id": "",
        })
        self.assertEqual(executor.call_args.kwargs["timeout"], 240.0)
        record = self.audit_path.read_text(encoding="utf-8")
        self.assertIn("public_endpoint_apply", record)
        self.assertNotIn("vpn.example.com", record)

    def test_public_endpoint_change_audits_success_with_malformed_response_as_indeterminate(self) -> None:
        for response, message in (("not-json", "响应无效"), ("[]", "版本不受支持")):
            with self.subTest(response=response):
                self.audit_path.unlink(missing_ok=True)
                executor = Mock(return_value=self.completed([], response))
                runner = ScriptRunner(
                    self.manager_path, audit_path=str(self.audit_path), executor=executor
                )
                with self.assertRaisesRegex(RuntimeError, message):
                    runner.change_public_endpoint("apply", "vpn.example.com", "owner", "a" * 64)
                record = self.audit_path.read_text(encoding="utf-8")
                self.assertIn("indeterminate", record)
                self.assertNotIn("vpn.example.com", record)

    def test_public_endpoint_change_rejects_boolean_timing_as_indeterminate(self) -> None:
        payload = {
            "schema_version": 1, "operation": "apply", "fqdn": "vpn.example.com",
            "transaction_id": "b" * 64,
            "subscriptions_refreshed": True, "state": "pending",
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(), "remaining_seconds": True,
            "rollback_seconds": 300, "independent_session": False,
            "last_outcome": "",
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)

        with self.assertRaisesRegex(RuntimeError, "版本不受支持"):
            runner.change_public_endpoint("apply", "vpn.example.com", "owner", "a" * 64)

        record = self.audit_path.read_text(encoding="utf-8")
        self.assertIn("indeterminate", record)
        self.assertNotIn("vpn.example.com", record)

    def test_public_endpoint_change_rejects_incoherent_response_as_indeterminate(self) -> None:
        base = {
            "schema_version": 1, "operation": "apply", "fqdn": "vpn.example.com",
            "transaction_id": "b" * 64,
            "subscriptions_refreshed": True, "state": "pending",
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(), "remaining_seconds": 300,
            "rollback_seconds": 300, "independent_session": False,
            "last_outcome": "",
        }
        invalid_changes = (
            {"remaining_seconds": -1},
            {"remaining_seconds": 301},
            {"rollback_seconds": 59},
            {"rollback_seconds": 3601},
            {"expires_at": "not-a-timestamp"},
            {"expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()},
            {"last_outcome": "confirmed"},
            {"fqdn": "other.example.com"},
            {"transaction_id": "not-safe"},
        )
        for changes in invalid_changes:
            with self.subTest(changes=changes):
                self.audit_path.unlink(missing_ok=True)
                payload = {**base, **changes}
                executor = Mock(return_value=self.completed([], json.dumps(payload)))
                runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
                with self.assertRaisesRegex(RuntimeError, "版本不受支持"):
                    runner.change_public_endpoint("apply", "vpn.example.com", "owner", "a" * 64)
                record = self.audit_path.read_text(encoding="utf-8")
                self.assertIn("indeterminate", record)
                self.assertNotIn("vpn.example.com", record)

    def test_awg_public_key_import_passes_psk_only_through_stdin(self) -> None:
        public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        preshared_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        response = {
            "schema_version": 1, "kind": "awg", "operation": "import",
            "name": "client-held",
        }
        executor = Mock(return_value=self.completed([], json.dumps(response)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )
        self.assertEqual(
            runner.import_network_node(
                "client-held", "10.20.0.23", public_key, preshared_key, "owner"
            ),
            response,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "network", "node", "awg", "import", "client-held",
            "10.20.0.23", public_key, "--json",
        ])
        self.assertEqual(executor.call_args.kwargs["input"], f"{preshared_key}\n")
        self.assertNotIn(preshared_key, " ".join(executor.call_args.args[0]))
        self.assertNotIn(preshared_key, self.audit_path.read_text(encoding="utf-8"))

    def test_node_domain_update_uses_fixed_json_argument(self) -> None:
        domains = ["nas.internal.example", "git.example.com"]
        payload = {
            "schema_version": 1, "operation": "set", "name": "home-nas",
            "address": "10.20.0.103", "domains": domains,
            "subscriptions_refreshed": True,
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )
        self.assertEqual(runner.change_node_domains("home-nas", domains, "owner"), payload)
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "network", "domains", "set", "home-nas",
            '["nas.internal.example","git.example.com"]', "--json",
        ])

    def test_address_domain_update_uses_canonical_ip_and_fixed_json_argument(self) -> None:
        domains = ["git.example.com", "*.internal.example"]
        payload = {
            "schema_version": 1, "operation": "set-address",
            "address": "2001:db8::103", "domains": domains,
            "subscriptions_refreshed": True,
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )
        self.assertEqual(
            runner.change_address_domains("2001:0db8::103", domains, "owner"), payload
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "network", "domains", "set-address", "2001:db8::103",
            '["git.example.com","*.internal.example"]', "--json",
        ])

    def test_all_nodes_can_use_specific_ports(self) -> None:
        response = {
            "schema_version": 1, "operation": "allow",
            "client": "home-desk", "target": "all",
        }
        executor = Mock(return_value=self.completed([], json.dumps(response)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )
        runner.change_network_permission(
            "allow", "home-desk", "all", "22,443", "tcp", "owner"
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "network", "permission", "allow",
            "home-desk", "all", "22,443", "tcp", "--json",
        ])

    def test_exact_permission_delete_includes_protocol_and_ports(self) -> None:
        response = {
            "schema_version": 1, "operation": "deny",
            "client": "home-desk", "target": "all",
        }
        executor = Mock(return_value=self.completed([], json.dumps(response)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )
        runner.change_network_permission(
            "deny", "home-desk", "all", "53", "udp", "owner"
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "network", "permission", "deny",
            "home-desk", "all", "53", "udp", "--json",
        ])

    def test_change_service_uses_fixed_argv_and_writes_audit_chain(self) -> None:
        executor = Mock(
            side_effect=[
                self.completed(["manager", "stop", "clash"]),
                self.completed(["manager", "snapshot", "--json"], json.dumps(SNAPSHOT)),
            ]
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )

        result = runner.change_service("clash", "stop", "owner")

        self.assertEqual(result, SNAPSHOT)
        self.assertEqual(executor.call_args_list[0].args[0], [
            self.manager_path, "stop", "clash"
        ])
        self.assertEqual(executor.call_args_list[1].args[0], [
            self.manager_path, "snapshot", "--json"
        ])
        record = json.loads(self.audit_path.read_text(encoding="utf-8"))
        self.assertEqual(record["actor"], "owner")
        self.assertEqual(record["service_id"], "clash")
        self.assertEqual(record["operation"], "stop")
        self.assertEqual(record["outcome"], "success")
        self.assertEqual(record["previous_hash"], "0" * 64)
        self.assertRegex(record["hash"], r"^[0-9a-f]{64}$")

    def test_repeated_actions_link_to_previous_audit_hash(self) -> None:
        executor = Mock(
            side_effect=[
                self.completed(["manager", "stop", "clash"]),
                self.completed(["manager", "snapshot", "--json"], json.dumps(SNAPSHOT)),
                self.completed(["manager", "start", "clash"]),
                self.completed(["manager", "snapshot", "--json"], json.dumps(SNAPSHOT)),
            ]
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )
        runner.change_service("clash", "stop", "owner")
        runner.change_service("clash", "start", "owner")
        records = [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(records[1]["previous_hash"], records[0]["hash"])
        audit = runner.audit_log()
        self.assertTrue(audit["chain_valid"])
        self.assertEqual([item["operation"] for item in audit["items"]], ["start", "stop"])
        self.assertNotIn("hash", audit["items"][0])

    def test_audit_reader_rejects_tampered_chain(self) -> None:
        executor = Mock(side_effect=[
            self.completed([]), self.completed([], json.dumps(SNAPSHOT)),
        ])
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        runner.change_service("clash", "stop", "owner")
        content = self.audit_path.read_text(encoding="utf-8").replace('"outcome":"success"', '"outcome":"failed"')
        self.audit_path.write_text(content, encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "审计日志链已损坏"):
            runner.audit_log()

    def test_runner_rejects_unregistered_values_before_subprocess(self) -> None:
        executor = Mock()
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )
        with self.assertRaises(ValueError):
            runner.change_service("ssh", "stop", "owner")
        with self.assertRaises(ValueError):
            runner.change_service("clash", "shell", "owner")
        executor.assert_not_called()

    def test_service_inventory_uses_registered_read_only_command(self) -> None:
        inventory = {
            "schema_version": 1,
            "service_id": "mosh",
            "facts": {"活动会话": "0"},
            "items": [],
        }
        executor = Mock(
            return_value=self.completed(
                ["manager", "inventory", "mosh", "--json"],
                json.dumps(inventory),
            )
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )
        self.assertEqual(runner.service_inventory("mosh"), inventory)
        self.assertEqual(
            executor.call_args.args[0],
            [self.manager_path, "inventory", "mosh", "--json"],
        )

    def test_file_resources_returns_embedded_service_state_without_snapshot(self) -> None:
        overview = {
            "schema_version": 1,
            "configured": True,
            "address": "10.20.0.1",
            "port": 8443,
            "service_state": "运行中",
            "items": [],
        }
        executor = Mock(return_value=self.completed(
            ["manager", "file", "overview", "--json"], json.dumps(overview),
        ))
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )

        self.assertEqual(runner.file_resources(), overview)
        self.assertEqual(executor.call_count, 1)
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "file", "overview", "--json",
        ])

    def test_secret_reveal_uses_fixed_argv_and_audits_without_url(self) -> None:
        secret = {
            "schema_version": 1,
            "resource": "clash_subscription_link",
            "item_id": "phone",
            "name": "phone",
            "value": "https://example.test/secret-token/phone.yaml",
        }
        executor = Mock(
            return_value=self.completed(
                ["manager", "reveal", "clash", "subscription-link", "phone", "--json"],
                json.dumps(secret),
            )
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )

        self.assertEqual(
            runner.reveal_resource("clash", "subscription_link", "phone", "owner"),
            secret,
        )
        self.assertEqual(
            executor.call_args.args[0],
            [self.manager_path, "reveal", "clash", "subscription-link", "phone", "--json"],
        )
        audit = self.audit_path.read_text(encoding="utf-8")
        self.assertIn("copy_subscription_link", audit)
        self.assertNotIn("secret-token", audit)

    def test_runner_rejects_unregistered_secret_without_subprocess(self) -> None:
        executor = Mock()
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )
        with self.assertRaises(ValueError):
            runner.reveal_resource("ssh", "repository", "repo", "owner")
        executor.assert_not_called()

    def test_proxy_secret_reveal_uses_same_fixed_interface_and_redacted_audit(self) -> None:
        response = {
            "schema_version": 1,
            "resource": "proxy_exit_config",
            "item_id": "current",
            "name": "当前出口节点",
            "value": "type: socks5\npassword: private-password\n",
        }
        executor = Mock(return_value=self.completed([], json.dumps(response)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor,
        )

        self.assertEqual(
            runner.reveal_resource("clash", "exit_config", "current", "owner"),
            response,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "reveal", "clash", "exit-config", "current", "--json",
        ])
        audit = self.audit_path.read_text(encoding="utf-8")
        self.assertIn("reveal_proxy_exit_config", audit)
        self.assertNotIn("private-password", audit)

    def test_exit_reveal_accepts_structured_proxy_with_unchanged_yaml_value(self) -> None:
        response = {
            "schema_version": 1, "resource": "proxy_exit_config",
            "item_id": "333333333333", "name": "Exit",
            "value": "type: socks5\npassword: private-password\n",
            "proxy": {
                "name": "EXIT.Exit", "type": "socks5", "server": "exit.test",
                "port": 1080, "password": "private-password", "dialer-proxy": "MID",
                "tls": True, "ws-opts": {"headers": {"Authorization": "private-token"}},
                "alpn": ["h2", "http/1.1"],
            },
        }
        executor = Mock(return_value=self.completed([], json.dumps(response)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor,
        )
        self.assertEqual(
            runner.reveal_resource("clash", "exit_config", "333333333333", "owner"),
            response,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "reveal", "clash", "exit-config", "333333333333", "--json",
        ])
        audit = self.audit_path.read_text(encoding="utf-8")
        for secret in ("private-password", "private-token", "ws-opts"):
            self.assertNotIn(secret, audit)

    def test_reveal_rejects_malformed_proxy_or_extra_response_fields(self) -> None:
        response = {
            "schema_version": 1, "resource": "proxy_exit_config",
            "item_id": "333333333333", "name": "Exit",
            "value": "password: private-password\n",
        }
        invalid_responses = [
            {**response, "proxy": proxy} for proxy in (None, [], "private-password", 42, True)
        ] + [
            {**response, "unexpected": "private-password"},
            {**response, "proxy": {}, "unexpected": "private-password"},
            {**response, "proxy": {}, "value": {}},
            {**response, "proxy": {}, "schema_version": 2},
            {**response, "proxy": {}, "item_id": "444444444444"},
        ]
        for payload in invalid_responses:
            with self.subTest(payload=payload):
                executor = Mock(return_value=self.completed([], json.dumps(payload)))
                runner = ScriptRunner(
                    self.manager_path, audit_path=str(self.audit_path), executor=executor,
                )
                with self.assertRaisesRegex(RuntimeError, "响应版本"):
                    runner.reveal_resource("clash", "exit_config", "333333333333", "owner")
        audit = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn("private-password", audit)
        self.assertTrue(all(json.loads(line)["outcome"] == "failed" for line in audit.splitlines()))

    def test_structured_proxy_is_not_accepted_for_other_sensitive_resources(self) -> None:
        for resource, response_resource in (
            ("airport_link", "proxy_airport_link"),
            ("subscription_link", "clash_subscription_link"),
        ):
            with self.subTest(resource=resource):
                response = {
                    "schema_version": 1, "resource": response_resource,
                    "item_id": "333333333333", "name": "Example",
                    "value": "https://example.test/private-token",
                    "proxy": {"password": "private-password"},
                }
                runner = ScriptRunner(
                    self.manager_path, audit_path=str(self.audit_path),
                    executor=Mock(return_value=self.completed([], json.dumps(response))),
                )
                with self.assertRaisesRegex(RuntimeError, "响应版本"):
                    runner.reveal_resource("clash", resource, "333333333333", "owner")
        audit = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn("private-password", audit)
        self.assertNotIn("private-token", audit)

    def test_failed_command_is_audited_without_exposing_output(self) -> None:
        executor = Mock(
            return_value=subprocess.CompletedProcess(
                ["manager", "stop", "clash"],
                1,
                stdout="",
                stderr="/etc/server-kit/secret",
            )
        )
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )
        with self.assertRaisesRegex(RuntimeError, "服务操作失败") as captured:
            runner.change_service("clash", "stop", "owner")
        self.assertNotIn("secret", str(captured.exception))
        record = json.loads(self.audit_path.read_text(encoding="utf-8"))
        self.assertEqual(record["outcome"], "failed")
        self.assertNotIn("secret", json.dumps(record))

    def test_security_transaction_uses_fixed_argv_and_propagates_write_gate(self) -> None:
        payload = {
            "schema_version": 1, "transaction_type": "firewall", "title": "防火墙",
            "state": "idle", "expires_at": "", "remaining_seconds": 0,
            "writes_enabled": True, "rollback_seconds": 300, "changes": [], "verifications": [],
            "ready": True, "blockers": [], "independent_session": True,
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor,
            high_risk_writes=True,
        )
        self.assertEqual(runner.manage_transaction("firewall", "preview", "owner"), payload)
        self.assertEqual(
            executor.call_args.args[0],
            [self.manager_path, "transaction", "firewall", "preview", "--json"],
        )
        self.assertEqual(executor.call_args.kwargs["env"]["SERVER_KIT_HIGH_RISK_WRITES"], "1")
        self.assertIn('"actor":"owner"', executor.call_args.kwargs["input"])
        self.assertIn("transaction_firewall_preview", self.audit_path.read_text(encoding="utf-8"))

    def test_security_apply_requires_pending_state_after_execution(self) -> None:
        payload = {
            "schema_version": 1, "transaction_type": "ssh_auth", "title": "SSH 认证",
            "state": "idle", "expires_at": "", "remaining_seconds": 0,
            "writes_enabled": True, "rollback_seconds": 300,
            "changes": [], "verifications": [], "ready": True, "blockers": [],
            "independent_session": True,
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor,
            high_risk_writes=True,
        )
        with self.assertRaisesRegex(RuntimeError, "状态核验"):
            runner.manage_transaction("ssh_auth", "apply", "owner", "a" * 64)
        self.assertIn("failed", self.audit_path.read_text(encoding="utf-8"))

    def test_vless_listener_transaction_uses_fixed_argv_without_public_endpoint_fields(self) -> None:
        payload = {
            "schema_version": 1,
            "transaction_type": "vless_listener",
            "title": "VLESS 公网监听迁移",
            "state": "pending",
            "expires_at": "2026-08-14T12:05:00+00:00",
            "remaining_seconds": 300,
            "writes_enabled": True,
            "rollback_seconds": 300,
            "changes": [{
                "label": "公网监听地址", "current": "203.0.113.10",
                "target": "0.0.0.0", "changed": True,
            }],
            "verifications": ["独立 VLESS 连接"],
            "ready": True,
            "blockers": [],
            "independent_session": False,
            "transaction_id": "f" * 64,
            "last_outcome": "",
        }
        executor = Mock(return_value=self.completed([], json.dumps(payload)))
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor,
            high_risk_writes=True,
        )

        self.assertEqual(
            runner.manage_transaction(
                "vless_listener", "apply", "owner", "a" * 64
            ),
            payload,
        )
        self.assertEqual(
            executor.call_args.args[0],
            [
                self.manager_path, "transaction", "vless_listener", "apply",
                "--json",
            ],
        )
        self.assertEqual(
            json.loads(executor.call_args.kwargs["input"]),
            {"session_id": "a" * 64, "actor": "owner"},
        )

    def test_firewall_port_commands_use_fixed_argv_and_support_permanent(self) -> None:
        payload = {"schema_version": 1, "firewall_active": True, "items": []}
        changed = {**payload, "verification": {"facts": True, "nftables": True}}
        executor = Mock(side_effect=lambda command, **_kwargs: self.completed(
            command, json.dumps(payload if command[1:3] == ["firewall-port", "list"] else changed)
        ))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)

        self.assertEqual(runner.firewall_ports(), payload)
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "firewall-port", "list", "--json",
        ])
        self.assertEqual(
            runner.change_firewall_port("open", 5201, "public", "both", 3600, "owner"),
            changed,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "firewall-port", "open", "5201", "public", "both", "3600", "--json",
        ])
        self.assertEqual(
            runner.change_firewall_port("open", 5202, "amneziawg", "tcp", 0, "owner"),
            changed,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "firewall-port", "open", "5202", "amneziawg", "tcp", "permanent", "--json",
        ])
        self.assertIn("custom_port_open", self.audit_path.read_text(encoding="utf-8"))

    def test_ssh_key_operations_use_stdin_fixed_argv_and_redacted_audit(self) -> None:
        key_id = "key-" + "a" * 64
        listing = {"schema_version": 1, "items": [{
            "type": "ssh-ed25519", "fingerprint": "SHA256:test", "name": "家庭台式机",
            "key_id": key_id, "deletable": True,
        }]}
        preview = {
            "schema_version": 1, "pending_token": "b" * 32, "type": "ssh-ed25519",
            "fingerprint": "SHA256:test", "name": "家庭台式机",
            "duplicate": False, "expires_in": 300,
        }
        renamed = {
            "schema_version": 1, "renamed": True, "key_id": key_id,
            "type": "ssh-ed25519", "fingerprint": "SHA256:test", "name": "新名字",
        }
        executor = Mock(side_effect=[
            self.completed([], json.dumps(listing)),
            self.completed([], json.dumps(preview)),
            self.completed([], json.dumps(renamed)),
        ])
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        self.assertEqual(runner.ssh_keys(), listing)
        public_key = "ssh-ed25519 AAAA-private-looking-public-value 家庭台式机"
        self.assertEqual(runner.preview_ssh_key(public_key, "owner"), preview)
        self.assertEqual(executor.call_args_list[1].args[0], [
            self.manager_path, "ssh-key", "preview", "--json",
        ])
        self.assertIn(public_key, executor.call_args_list[1].kwargs["input"])
        self.assertNotIn(public_key, self.audit_path.read_text(encoding="utf-8"))
        self.assertEqual(runner.change_ssh_key("rename", key_id, "新名字", "owner"), renamed)
        self.assertEqual(executor.call_args_list[2].args[0], [
            self.manager_path, "ssh-key", "rename", key_id, "--json",
        ])
        self.assertEqual(json.loads(executor.call_args_list[2].kwargs["input"]), {"name": "新名字"})
        self.assertIn("ssh_key_rename", self.audit_path.read_text(encoding="utf-8"))

    def test_backup_passphrase_uses_stdin_and_never_enters_argv_or_audit(self) -> None:
        result = {
            "backup_id": "backup-20260807T120000Z-1234abcd",
            "format_version": 2,
            "created_at": "2026-08-07T12:00:00+00:00",
            "host": "test", "cipher": "AES-256-GCM", "categories": ["server-kit"],
            "file_count": 1, "size": 200, "download_name": "backup-20260807T120000Z-1234abcd.skb",
            "key_custody_version": 2, "client_private_keys": "excluded",
            "restore_allowed": True, "assurance_state": "awaiting_verification",
        }
        envelope = {"schema_version": 1, "ok": True, "result": result}
        executor = Mock(return_value=self.completed([], json.dumps(envelope)))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        passphrase = "绝不能进入参数或日志的恢复口令"
        self.assertEqual(runner.manage_backup("create", "", passphrase, "owner"), result)
        self.assertEqual(
            executor.call_args.args[0],
            [self.manager_path, "backup", "create", "--json"],
        )
        input_payload = json.loads(executor.call_args.kwargs["input"])
        self.assertEqual(input_payload["passphrase"], passphrase)
        self.assertEqual(input_payload["actor"], "owner")
        self.assertNotIn(passphrase, self.audit_path.read_text(encoding="utf-8"))

    def test_backup_response_rejects_unregistered_secret_fields(self) -> None:
        result = {
            "backup_id": "backup-20260807T120000Z-1234abcd",
            "format_version": 2,
            "created_at": "2026-08-07T12:00:00+00:00",
            "host": "test", "cipher": "AES-256-GCM", "categories": ["amneziawg"],
            "file_count": 1, "size": 200,
            "download_name": "backup-20260807T120000Z-1234abcd.skb",
            "key_custody_version": 2, "client_private_keys": "excluded",
            "restore_allowed": True, "assurance_state": "awaiting_verification",
            "preshared_key": "不应离开备份模块",
        }
        executor = Mock(return_value=self.completed([], json.dumps({
            "schema_version": 1, "ok": True, "result": result,
        })))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        with self.assertRaisesRegex(RuntimeError, "响应版本不受支持"):
            runner.manage_backup("create", "", "安全恢复口令-长度超过十六字符", "owner")

    def test_restore_status_uses_registered_read_only_command(self) -> None:
        payload = {
            "schema_version": 1, "state": "idle", "backup_id": "", "expires_at": "",
            "remaining_seconds": 0, "rollback_seconds": 300, "changed_count": 0,
            "categories": [], "verifications": [], "writes_enabled": False,
            "last_outcome": "",
            "independent_session": True,
        }
        envelope = {"schema_version": 1, "ok": True, "result": payload}
        executor = Mock(return_value=self.completed([], json.dumps(envelope)))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        self.assertEqual(runner.manage_backup("restore_status", "", "", "owner"), payload)
        self.assertEqual(
            executor.call_args.args[0],
            [self.manager_path, "backup", "restore-status", "--json"],
        )
        self.assertEqual(json.loads(executor.call_args.kwargs["input"])["actor"], "owner")

    def test_delete_backup_uses_fixed_argv_and_audit(self) -> None:
        backup_id = "backup-20260807T120000Z-1234abcd"
        payload = {
            "schema_version": 1,
            "backup_id": backup_id,
            "deleted": True,
        }
        envelope = {"schema_version": 1, "ok": True, "result": payload}
        executor = Mock(return_value=self.completed([], json.dumps(envelope)))
        runner = ScriptRunner(
            self.manager_path,
            audit_path=str(self.audit_path),
            executor=executor,
        )
        self.assertEqual(
            runner.manage_backup("delete", backup_id, "", "owner"), payload
        )
        self.assertEqual(
            executor.call_args.args[0],
            [self.manager_path, "backup", "delete", backup_id, "--json"],
        )
        self.assertEqual(json.loads(executor.call_args.kwargs["input"])["actor"], "owner")
        self.assertIn("backup_delete", self.audit_path.read_text(encoding="utf-8"))

    def test_clash_deployment_passes_secrets_only_through_stdin(self) -> None:
        response = {"schema_version": 1, "service_id": "clash", "state": "completed"}
        snapshot = {
            "schema_version": 1,
            "services": [{"id": "clash", "label": "Clash 订阅", "state": "运行中"}],
        }
        inventory = {"schema_version": 1, "service_id": "clash", "facts": {}, "items": []}
        executor = Mock(side_effect=[
            self.completed([], json.dumps(response)),
            self.completed([], json.dumps(snapshot)),
            self.completed([], json.dumps(inventory)),
        ])
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        values = {
            "port": "8444", "airport_url": "https://example.test/private-token",
            "exit_proxy_yaml": "type: socks5\nserver: exit.test\nport: 1080\npassword: secret",
        }
        result = runner.deploy_service("clash", values, "owner")
        self.assertEqual(result["service"]["state"], "运行中")
        self.assertEqual(result["verification"], {"snapshot": True, "inventory": True})
        self.assertEqual(
            executor.call_args_list[0].args[0],
            [self.manager_path, "deploy", "clash", "8444", "--json"],
        )
        self.assertNotIn("private-token", " ".join(executor.call_args_list[0].args[0]))
        self.assertIn("private-token", executor.call_args_list[0].kwargs["input"])
        audit = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn("private-token", audit)
        self.assertNotIn("secret", audit)

    def test_deployment_fails_when_actual_service_is_not_running(self) -> None:
        response = {"schema_version": 1, "service_id": "mosh", "state": "completed"}
        snapshot = {
            "schema_version": 1,
            "services": [{"id": "mosh", "label": "Mosh 终端", "state": "未安装"}],
        }
        inventory = {"schema_version": 1, "service_id": "mosh", "facts": {}, "items": []}
        executor = Mock(side_effect=[
            self.completed([], json.dumps(response)),
            self.completed([], json.dumps(snapshot)),
            self.completed([], json.dumps(inventory)),
        ])
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        with self.assertRaisesRegex(RuntimeError, "运行状态核验"):
            runner.deploy_service("mosh", {}, "owner")
        self.assertIn("failed", self.audit_path.read_text(encoding="utf-8"))

    def test_file_resource_add_uses_fixed_argv_and_audit(self) -> None:
        response = {"schema_version": 1, "operation": "add", "resource_id": "file-1234567890abcdef"}
        executor = Mock(return_value=self.completed([], json.dumps(response)))
        runner = ScriptRunner(self.manager_path, audit_path=str(self.audit_path), executor=executor)
        self.assertEqual(
            runner.change_file_resource("add", "a" * 32, "large.bin", True, 86400, "", "owner"),
            response,
        )
        self.assertEqual(executor.call_args.args[0], [
            self.manager_path, "file", "add", "a" * 32, "large.bin", "true", "86400", "--json",
        ])
        self.assertIn("file_resource_add", self.audit_path.read_text(encoding="utf-8"))

    def test_file_upload_facts_and_cleanup_use_opaque_identifier(self) -> None:
        facts = {
            "schema_version": 1,
            "upload_id": "a" * 32,
            "size": 80 * 1024 * 1024,
            "sha256": "b" * 64,
        }
        executor = Mock(side_effect=[
            self.completed([], json.dumps(facts)),
            self.completed([], '{"schema_version":1,"discarded":true}'),
        ])
        runner = ScriptRunner(
            self.manager_path, audit_path=str(self.audit_path), executor=executor
        )
        self.assertEqual(runner.file_upload_facts("a" * 32), facts)
        runner.discard_file_upload("a" * 32)
        self.assertEqual(executor.call_args_list[0].args[0], [
            self.manager_path, "file", "inspect-upload", "a" * 32, "--json",
        ])
        self.assertEqual(executor.call_args_list[1].args[0], [
            self.manager_path, "file", "discard-upload", "a" * 32, "--json",
        ])


if __name__ == "__main__":
    unittest.main()
