"""Batch additions are bounded, append-only and one persistent mutation task."""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from control_plane.core import ControlPlane
from control_plane.errors import TaskExecutionError
from control_plane.runner import ScriptRunner
from control_plane.tasks import ChangeTaskEngine, TaskEngineError
from lib import awg_access, vless_access
from lib.server_kit_permission_batch import PermissionBatchError, normalize_rules
from tests.test_control_plane import FakeRunner, request


RULES = [
    {"target": "vps", "network": "tcp", "ports": "443,22,8000-8002"},
    {"target": "desk", "network": "udp", "ports": "53"},
]


class BatchValidationTests(unittest.TestCase):
    def test_canonical_and_blank_all_protocol(self):
        self.assertEqual(normalize_rules(RULES)[0]["ports"], "22,443,8000-8002")
        self.assertEqual(normalize_rules([{"target": "vps", "network": "", "ports": ""}])[0]["network"], "all")

    def test_invalid_shape_bounds_and_duplicate_rows(self):
        bad = [None, {}, [], RULES * 11, [None], [{**RULES[0], "operation": "deny"}],
               [{**RULES[0], "network": "all"}], [{**RULES[0], "ports": "0"}],
               [{**RULES[0], "ports": "8002-8000"}], [{**RULES[0], "ports": ""}],
               [{**RULES[0], "network": "icmp"}], [RULES[0], {**RULES[0], "ports": "22,8000-8002,443"}]]
        for rules in bad:
            with self.subTest(rules=rules), self.assertRaises(PermissionBatchError):
                normalize_rules(rules)
        self.assertEqual(len(normalize_rules([{**RULES[0], "ports": str(port)} for port in range(1, 21)])), 20)


class BatchPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.active, self.pending = self.root / "active.json", self.root / "pending.json"
        self.peers, self.state = self.root / "peers.tsv", self.root / "state"
        self.peers.write_text("phone\t10.20.0.2\ndesk\t10.20.0.3\n")
        self.state.write_text("AWG_SERVER_IP=10.20.0.1\n")
        self.original = {"version": 1, "clients": {
            "phone": {"mode": "restricted", "enabled": True, "allow": [
                {"target": "vps", "network": "tcp", "ports": [22, 9080], "ip": "10.20.0.1"},
            ]},
            "desk": {"mode": "unrestricted", "enabled": True, "allow": []},
        }}
        self.active.write_text(json.dumps(self.original))

    def stage(self, module, rules):
        args = argparse.Namespace(active=self.active, pending=self.pending, peers=self.peers,
            peer_db=self.peers, awg_state=self.state, client="phone", name="phone",
            server_ip="10.20.0.1", network_cidr="10.20.0.0/24")
        with patch("sys.stdin", io.StringIO(json.dumps(rules))):
            module.allow_batch(args)

    def test_each_helper_preserves_existing_clients_rules_and_access_mode(self):
        original_bytes = self.active.read_bytes()
        for module in (awg_access, vless_access):
            with self.subTest(module=module.__name__):
                self.stage(module, RULES)
                candidate = json.loads(self.pending.read_text())
                self.assertEqual(candidate["clients"]["desk"], self.original["clients"]["desk"])
                self.assertEqual(candidate["clients"]["phone"]["mode"], "restricted")
                self.assertEqual(candidate["clients"]["phone"]["allow"][0], self.original["clients"]["phone"]["allow"][0])
                self.assertEqual(len(candidate["clients"]["phone"]["allow"]), 3)
                self.assertEqual(self.active.read_bytes(), original_bytes)
                self.pending.unlink()

    def test_invalid_later_row_never_writes_partial_candidate(self):
        original_bytes = self.active.read_bytes()
        for module in (awg_access, vless_access):
            for row in ({**RULES[1], "target": "missing"}, {**RULES[1], "target": "phone"},
                        {**RULES[1], "ports": "0"}, {"target": "vps", "network": "tcp", "ports": "9080,22"}):
                with self.subTest(module=module.__name__, row=row), self.assertRaises((ValueError, RuntimeError)):
                    self.stage(module, [RULES[0], row])
                self.assertFalse(self.pending.exists())
                self.assertEqual(self.active.read_bytes(), original_bytes)

    def test_pending_candidate_is_never_overwritten(self):
        self.pending.write_text('{"reserved": true}')
        for module in (awg_access, vless_access):
            with self.assertRaises(RuntimeError):
                self.stage(module, RULES)
            self.assertEqual(self.pending.read_text(), '{"reserved": true}')

    def test_all_can_only_broaden_awg_management_access(self):
        self.stage(awg_access, [{"target": "all", "network": "all", "ports": ""}, RULES[0]])
        candidate = json.loads(self.pending.read_text())
        self.assertEqual(candidate["clients"]["phone"]["mode"], "unrestricted")
        self.assertEqual(candidate["clients"]["phone"]["allow"][0], self.original["clients"]["phone"]["allow"][0])

    def test_disabled_vless_is_rejected(self):
        self.original["clients"]["phone"]["enabled"] = False
        self.active.write_text(json.dumps(self.original))
        with self.assertRaises(RuntimeError):
            self.stage(vless_access, RULES)
        self.assertFalse(self.pending.exists())


class BatchRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.batch_calls = []

    def add_network_permissions(self, client, rules, actor):
        self.batch_calls.append((client, rules, actor))
        return {"schema_version": 1, "operation": "batch", "client": client}


class BatchTaskTests(unittest.TestCase):
    def setUp(self):
        self.runner = BatchRunner()
        self.plane = ControlPlane(self.runner, {1001})
        self.arguments = {"client": "iphone", "rules": [RULES[0], {**RULES[1], "target": "home-desk"}]}

    def test_preview_contains_single_source_and_all_normalized_rows(self):
        task = self.plane.prepare_task_action("network.permission.batch", self.arguments, "owner")
        self.assertEqual(task.canonical_action, "network.permission.batch")
        self.assertEqual(task.preview["facts"]["来源节点"], "iphone")
        self.assertEqual(task.preview["facts"]["新增规则"], "2")
        self.assertIn("TCP 22,443,8000-8002", task.preview["facts"]["规则 1"])
        self.assertEqual(self.runner.batch_calls, [])

    def test_bad_final_row_existing_duplicate_self_and_disabled_rejected(self):
        for target in ("missing", "iphone"):
            with self.assertRaises(TaskEngineError):
                self.plane.prepare_task_action("network.permission.batch", {
                    **self.arguments, "rules": [RULES[0], {**RULES[1], "target": target}],
                }, "owner")
        with self.assertRaises(TaskEngineError):
            self.plane.prepare_task_action("network.permission.batch", {"client": "home-desk", "rules": [{"target": "all", "network": "all", "ports": ""}]}, "owner")
        overview = self.runner.network_overview()
        overview["nodes"][1]["state"] = "已停用"
        self.runner.network_overview = lambda: overview
        with self.assertRaises(TaskEngineError):
            self.plane.prepare_task_action("network.permission.batch", self.arguments, "owner")
        self.assertEqual(self.runner.batch_calls, [])

    def engine(self, root):
        engine = ChangeTaskEngine(root / "tasks.sqlite3", self.plane.prepare_task_action,
            self.plane.execute_task_action, self.plane.inspect_task_action, start_worker=False)
        self.addCleanup(engine.close)
        return engine

    def test_confirm_applies_once_and_cannot_be_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = self.engine(Path(directory))
            task = engine.preview("network.permission.batch", self.arguments, "owner")
            with self.assertRaises(TaskEngineError):
                engine.confirm(task["id"], "other")
            engine.confirm(task["id"], "owner")
            engine.confirm(task["id"], "owner")
            self.assertTrue(engine.process_one())
            self.assertEqual(engine.get(task["id"])["state"], "succeeded")
            self.assertEqual(len(self.runner.batch_calls), 1)
            self.assertEqual(self.runner.permission_changes, [])
            self.assertFalse(engine.process_one())

    def test_fact_change_invalidates_all_additions_before_any_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = self.engine(Path(directory))
            task = engine.preview("network.permission.batch", self.arguments, "owner")
            self.runner.home_permissions.append({"target": "vps", "network": "tcp", "ports": [1234]})
            engine.confirm(task["id"], "owner")
            engine.process_one()
            self.assertEqual(engine.get(task["id"])["state"], "invalidated")
            self.assertEqual(self.runner.batch_calls, [])

    def test_protocol_action_cannot_bypass_persistent_task(self):
        response = self.plane.handle(request(action="network.permission.batch", params={
            **self.arguments, "actor": "owner", "confirmed": True,
        }), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")

    def test_runner_stdin_is_one_call_and_canonical(self):
        response = {"schema_version": 1, "operation": "batch", "client": "iphone"}
        executor = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(response), ""))
        with tempfile.TemporaryDirectory() as directory:
            runner = ScriptRunner("/test/manager", audit_path=f"{directory}/audit.jsonl", executor=executor)
            runner.add_network_permissions("iphone", self.arguments["rules"], "owner")
            executor.assert_called_once()
            self.assertEqual(executor.call_args.args[0], ["/test/manager", "network", "permission", "batch", "iphone", "--json"])
            self.assertEqual(json.loads(executor.call_args.kwargs["input"])[0]["ports"], "22,443,8000-8002")
            executor.reset_mock()
            with self.assertRaises(PermissionBatchError):
                runner.add_network_permissions("iphone", [RULES[0], {**RULES[1], "ports": "0"}], "owner")
            executor.assert_not_called()

    def test_runner_surfaces_only_allowlisted_recovery_diagnostic(self):
        executor = Mock(return_value=subprocess.CompletedProcess([], 1, "", "private details\nSERVER_KIT_DIAGNOSTIC:permission_recovery_required\n"))
        with tempfile.TemporaryDirectory() as directory:
            runner = ScriptRunner("/test/manager", audit_path=f"{directory}/audit.jsonl", executor=executor)
            with self.assertRaises(TaskExecutionError) as raised:
                runner.add_network_permissions("iphone", self.arguments["rules"], "owner")
            self.assertEqual(raised.exception.code, "permission_recovery_required")
            self.assertNotIn("private", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
