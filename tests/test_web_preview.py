"""The visual-review fixture server must never fall back to live management."""

from __future__ import annotations

import json
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_agent_server import PreviewAgent, serve
from preview_fixtures import SERVICE_IDS, TASK_IDS, build_fixtures


class WebPreviewTests(unittest.TestCase):
    def test_complete_page_intents_are_available(self):
        agent = PreviewAgent()
        for intent in ("overview", "network", "proxy", "file"):
            response = agent.dispatch("host.read", {"intent": intent})
            self.assertIsInstance(response["view"], dict)
        for service_id in SERVICE_IDS:
            response = agent.dispatch("host.read", {"intent": "service", "service_id": service_id})
            self.assertEqual(response["view"]["service"]["id"], service_id)

    def test_unknown_actions_never_fall_back_to_real_commands(self):
        agent = PreviewAgent()
        for action in ("exec", "systemctl", "service.change", "ssh.connect", "__import__", "network.proxy.fetch"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                agent.dispatch(action, {"command": "must-not-run"})

    def test_task_inputs_never_retain_secrets(self):
        agent = PreviewAgent()
        response = agent.dispatch("task.preview", {"action": "network.proxy.update", "actor": "test-secret-actor",
            "arguments": {"password": "test-secret-password", "airport_url": "https://example.invalid/test-secret-token"}})
        self.assertNotIn("test-secret", json.dumps(response))
        self.assertNotIn("test-secret", json.dumps(agent.data))
        finished = agent.dispatch("task.confirm", {"task_id": response["id"], "actor": "preview"})
        self.assertEqual(finished["state"], "succeeded")

    def test_unknown_task_actions_rejected(self):
        with self.assertRaises(ValueError):
            PreviewAgent().dispatch("task.preview", {"action": "exec", "arguments": {}})

    def preview_batch(self, agent, rules=None, **arguments):
        return agent.dispatch("task.preview", {
            "action": "network.permission.batch", "actor": "preview-operator",
            "arguments": {"client": "iphone-travel", "rules": rules if rules is not None else [
                {"target": "vps", "network": "tcp", "ports": "9080,22"},
                {"target": "home-desktop", "network": "udp", "ports": "8000-8002"},
            ], **arguments},
        })

    def test_batch_preview_has_actual_source_actor_and_each_rule_but_no_mutation(self):
        agent = PreviewAgent()
        before = copy.deepcopy(agent.data["network"])
        task = self.preview_batch(agent, password="test-secret-password", private_key="test-secret-key")
        self.assertEqual(task["action"], "network.permission.batch")
        self.assertEqual(task["actor"], "preview-operator")
        self.assertEqual(task["preview"]["facts"]["来源节点"], "iphone-travel")
        self.assertEqual(task["preview"]["facts"]["规则数量"], 2)
        self.assertIn("VPS 本机 · TCP · 22, 9080", task["preview"]["facts"]["规则 1"])
        self.assertIn("home-desktop · UDP · 8000-8002", task["preview"]["facts"]["规则 2"])
        self.assertEqual(agent.data["network"], before)
        self.assertNotIn("arguments", task)
        self.assertNotIn("test-secret", json.dumps(agent.data))
        self.assertNotIn("test-secret", json.dumps(agent._permission_batches))

    def test_batch_confirm_appends_once_and_preserves_task_preview(self):
        agent = PreviewAgent()
        task = self.preview_batch(agent)
        before = copy.deepcopy(agent.data["network"]["nodes"])
        finished = agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview-operator"})
        self.assertEqual(finished["action"], "network.permission.batch")
        self.assertEqual(finished["actor"], "preview-operator")
        self.assertEqual(finished["preview"], task["preview"])
        self.assertEqual(finished["state"], "succeeded")
        self.assertEqual(finished["result"], {"client": "iphone-travel", "added_count": 2})
        nodes = agent.dispatch("host.read", {"intent": "network"})["view"]["nodes"]
        self.assertEqual(nodes[:3], before[:3])
        self.assertEqual(nodes[4:], before[4:])
        self.assertEqual(nodes[3]["permissions"][:2], before[3]["permissions"])
        self.assertEqual(nodes[3]["permissions"][-2:], [
            {"target": "vps", "target_label": "VPS 本机", "ip": "10.20.0.1", "network": "tcp", "network_label": "TCP", "ports": [22, 9080], "ports_label": "22, 9080"},
            {"target": "home-desktop", "target_label": "home-desktop", "ip": "10.20.0.10", "network": "udp", "network_label": "UDP", "ports": [8000, 8001, 8002], "ports_label": "8000-8002"},
        ])
        duplicate = agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview-operator"})
        self.assertEqual(duplicate, finished)
        self.assertEqual(agent.data["network"]["nodes"], nodes)
        self.assertNotIn(task["id"], agent._permission_batches)

    def test_batch_rejects_invalid_or_duplicate_rules_before_creating_task(self):
        for arguments in (
            {"rules": []}, {"rules": [{}] * 21}, {"client": "not-a-node"}, {"client": "retired-laptop"},
            {"rules": [{"target": "unknown", "network": "tcp", "ports": "22"}]},
            {"rules": [{"target": "iphone-travel", "network": "tcp", "ports": "22"}]},
            {"rules": [{"target": "vps", "network": "icmp", "ports": ""}]},
            {"rules": [{"target": "vps", "network": "tcp", "ports": "9000-8000"}]},
            {"rules": [{"target": "vps", "network": "all", "ports": "22"}]},
            {"rules": [{"target": "vps", "network": "udp", "ports": "53"}]},
            {"rules": [{"target": "vps", "network": "tcp", "ports": "22,80"},
                       {"target": "vps", "network": "tcp", "ports": "80,22"}]},
        ):
            with self.subTest(arguments=arguments):
                agent = PreviewAgent()
                before = copy.deepcopy(agent.data)
                with self.assertRaises(ValueError):
                    self.preview_batch(agent, **arguments)
                self.assertEqual(agent.data, before)
                self.assertEqual(agent._permission_batches, {})

    def test_batch_confirm_rechecks_all_rules_before_appending(self):
        agent = PreviewAgent()
        task = self.preview_batch(agent)
        subject = next(node for node in agent.data["network"]["nodes"] if node["name"] == "iphone-travel")
        subject["permissions"].append(copy.deepcopy(agent._permission_batches[task["id"]]["rules"][-1]))
        before = copy.deepcopy(agent.data["network"])
        with self.assertRaises(ValueError):
            agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview-operator"})
        self.assertEqual(agent.data["network"], before)
        self.assertEqual(agent.data["tasks"][task["id"]]["state"], "waiting_confirmation")

    def test_batch_cancel_and_wrong_actor_do_not_mutate_permissions(self):
        agent = PreviewAgent()
        task = self.preview_batch(agent)
        before = copy.deepcopy(agent.data["network"])
        with self.assertRaises(ValueError):
            agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "other-operator"})
        cancelled = agent.dispatch("task.cancel", {"task_id": task["id"], "actor": "preview-operator"})
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertEqual(cancelled["preview"], task["preview"])
        self.assertEqual(cancelled["action"], "network.permission.batch")
        self.assertEqual(agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview-operator"}), cancelled)
        self.assertEqual(agent.data["network"], before)
        self.assertEqual(agent._permission_batches, {})

    def test_batch_all_protocols_and_scenario_reset_are_safe(self):
        agent = PreviewAgent()
        task = self.preview_batch(agent, [{"target": "home-desktop", "network": "all", "ports": ""}])
        self.assertIn("全部协议 · 全部端口", task["preview"]["facts"]["规则 1"])
        agent.set_scenario("rich")
        self.assertEqual(agent._permission_batches, {})
        with self.assertRaises(KeyError):
            agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview-operator"})

    def test_inline_permission_delete_has_canonical_action_and_updates_fixture_once(self):
        agent = PreviewAgent()
        task = agent.dispatch("task.preview", {"action": "network.permission.change", "actor": "preview-admin",
            "arguments": {"operation": "deny", "client": "iphone-travel", "target": "vps", "network": "udp", "ports": "53"}})
        self.assertEqual(task["action"], "network.permission.deny")
        self.assertEqual(task["actor"], "preview-admin")
        self.assertEqual(len(agent.data["network"]["nodes"][3]["permissions"]), 2)
        result = agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview-admin"})
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(len(agent.data["network"]["nodes"][3]["permissions"]), 1)
        self.assertEqual(agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview-admin"}), result)

    def test_inline_domain_and_exit_selection_changes_only_synthetic_state(self):
        agent = PreviewAgent()
        for action, arguments in (
            ("network.node.domains", {"name": "nas-storage-primary", "domains": ["new-nas.internal.example"]}),
            ("network.address.domains", {"address": "192.0.2.44", "domains": ["new-host.internal.example"]}),
            ("network.proxy.update", {"operation": "node_exits_set", "awg_name": "iphone-travel", "exit_ids": ["444444444444"]}),
        ):
            task = agent.dispatch("task.preview", {"action": action, "actor": "preview", "arguments": arguments})
            agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview"})
        self.assertEqual(agent.data["network"]["nodes"][2]["domains"], ["new-nas.internal.example"])
        self.assertIn({"address": "192.0.2.44", "domains": ["new-host.internal.example"]}, agent.data["network"]["host_records"])
        self.assertEqual(agent.data["network"]["nodes"][3]["exit_ids"], ["444444444444"])
        self.assertEqual(agent.data["network"]["nodes"][3]["exit_names"], ["dedicated-eu-failover"])

    def test_inline_proxy_preview_does_not_retain_yaml_or_credentials(self):
        agent = PreviewAgent()
        task = agent.dispatch("task.preview", {"action": "network.proxy.update", "actor": "preview", "arguments": {
            "operation": "exit_update", "exit_id": "333333333333", "exit_name": "renamed-preview-exit",
            "exit_proxy_yaml": "password: test-secret-password", "airport_url": "https://example.invalid/test-secret-token",
            "password": "test-secret-account", "exit_default": True}})
        self.assertNotIn("test-secret", json.dumps(agent.data))
        self.assertNotIn("test-secret", json.dumps(agent._inline_changes))
        self.assertNotIn("exit_proxy_yaml", json.dumps(task))
        agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "preview"})
        self.assertEqual(agent.data["proxy"]["exits"][0]["name"], "renamed-preview-exit")
        self.assertEqual(agent._inline_changes, {})

    def test_inline_cancel_and_reset_do_not_apply_saved_changes(self):
        agent = PreviewAgent()
        before = copy.deepcopy(agent.data["network"])
        task = agent.dispatch("task.preview", {"action": "network.node.domains", "actor": "preview", "arguments": {
            "name": "nas-storage-primary", "domains": ["not-applied.internal.example"]}})
        with self.assertRaises(ValueError):
            agent.dispatch("task.confirm", {"task_id": task["id"], "actor": "other-admin"})
        agent.dispatch("task.cancel", {"task_id": task["id"], "actor": "preview"})
        self.assertEqual(agent.data["network"], before)
        self.assertEqual(agent._inline_changes, {})
        agent.set_scenario("rich")
        self.assertEqual(agent._inline_changes, {})

    def test_read_responses_are_independent_copies(self):
        agent = PreviewAgent()
        response = agent.dispatch("host.read", {"intent": "network"})
        response["view"]["nodes"].clear()
        self.assertEqual(len(agent.data["network"]["nodes"]), 5)

    def test_empty_scenario_clears_primary_inventories(self):
        data = build_fixtures("empty")
        for key in ("nodes", "publications", "subscription_items", "host_records"):
            self.assertEqual(data["network"][key], [])
        self.assertEqual(data["proxy"]["airports"], [])
        self.assertEqual(data["file"]["items"], [])
        self.assertEqual(data["tasks"], {})

    def test_error_scenario_fails_closed(self):
        agent = PreviewAgent("error")
        for action in ("host.read", "task.list", "security.transaction", "backup.manage"):
            with self.assertRaises(ValueError):
                agent.dispatch(action, {})

    def test_pending_scenario_has_distinct_rollback_states(self):
        data = build_fixtures("pending")
        self.assertTrue(data["network"]["pending_access"])
        self.assertTrue(data["network"]["pending_vless"])
        self.assertEqual(data["endpoint_transaction"]["state"], "pending")
        self.assertEqual(data["transactions"]["firewall"]["state"], "pending")
        self.assertEqual(data["restore"]["state"], "pending")

    def test_eight_task_states_have_deterministic_urls(self):
        agent = PreviewAgent()
        for state, task_id in TASK_IDS.items():
            self.assertEqual(agent.dispatch("task.get", {"task_id": task_id})["state"], state)

    def test_scenario_switch_resets_only_in_memory(self):
        agent = PreviewAgent()
        agent.set_scenario("empty")
        self.assertEqual(agent.data["network"]["nodes"], [])
        agent.set_scenario("rich")
        self.assertEqual(len(agent.data["network"]["nodes"]), 5)
        with self.assertRaises(ValueError):
            agent.set_scenario("production")

    def test_preexisting_socket_path_is_never_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "existing.sock"
            candidate.touch()
            with self.assertRaises(ValueError):
                serve(str(candidate))
            self.assertTrue(candidate.exists())

    def test_relative_socket_path_is_rejected(self):
        with self.assertRaises(ValueError):
            serve("manager.sock")


if __name__ == "__main__":
    unittest.main()
