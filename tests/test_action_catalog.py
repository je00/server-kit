from __future__ import annotations

import inspect
import re
import unittest

from control_plane.actions import (
    ActionCatalogError,
    ActionKind,
    ChangeLevel,
    registered_actions,
    registered_protocol_actions,
    resolve_action,
    validate_action_request,
)
from control_plane.core import ControlPlane


EXPECTED_PROTOCOL_ACTIONS = frozenset({
    "audit.event",
    "audit.list",
    "backup.manage",
    "backup.restore.change",
    "deployment.install",
    "file.resource.change",
    "file.resources.overview",
    "firewall.port.change",
    "firewall.ports.overview",
    "managed.port.change",
    "managed.ports.overview",
    "host.read",
    "network.node.change",
    "network.node.import",
    "network.node.domains",
    "network.address.domains",
    "network.enrollment.context",
    "network.overview",
    "network.telemetry",
    "network.duckdns.status",
    "network.duckdns.change",
    "network.public_endpoint.status",
    "network.public_endpoint.transaction.status",
    "network.public_endpoint.change",
    "network.permission.change",
    "network.permission.batch",
    "network.proxy.overview",
    "network.proxy.test",
    "network.proxy.update",
    "network.subscription.rotate",
    "network.subscription.state",
    "network.subscriptions.sync",
    "security.transaction",
    "security.transaction.change",
    "service.change",
    "service.describe",
    "service.reveal",
    "ssh.key.change",
    "ssh.key.preview",
    "ssh.keys.overview",
    "system.snapshot",
    "task.confirm",
    "task.cancel",
    "task.active",
    "task.get",
    "task.list",
    "task.preview",
})

EXPECTED_CHANGE_ACTIONS = frozenset({
    "network.permission.batch",
    "backup.create",
    "backup.delete",
    "backup.restore_apply",
    "backup.restore_confirm",
    "backup.restore_rollback",
    "backup.verify",
    "deployment.file.install",
    "deployment.mosh.install",
    "deployment.proxy.install",
    "deployment.vless.install",
    "file.add",
    "file.delete",
    "firewall.port.close",
    "firewall.port.open",
    "managed.port.change",
    "network.node.awg.add",
    "network.node.awg.disable",
    "network.node.awg.enable",
    "network.node.awg.clean-disable",
    "network.node.awg.clean-enable",
    "network.node.awg.remove",
    "network.node.awg.set-management",
    "network.node.awg.import",
    "network.node.domains",
    "network.address.domains",
    "network.node.vless.add",
    "network.node.vless.compat-disable",
    "network.node.vless.compat-enable",
    "network.node.vless.clean-disable",
    "network.node.vless.clean-enable",
    "network.node.vless.disable",
    "network.node.vless.enable",
    "network.node.vless.remove",
    "network.permission.allow",
    "network.permission.deny",
    "network.duckdns.configure",
    "network.duckdns.update",
    "network.duckdns.disable",
    "network.duckdns.delete",
    "network.public_endpoint.apply",
    "network.public_endpoint.confirm",
    "network.public_endpoint.rollback",
    "network.proxy.update",
    "network.subscription.disable",
    "network.subscription.enable",
    "network.subscription.rotate",
    "network.subscriptions.sync",
    "security.firewall.apply",
    "security.firewall.confirm",
    "security.firewall.rollback",
    "security.ssh_auth.apply",
    "security.ssh_auth.confirm",
    "security.ssh_auth.rollback",
    "security.ssh_listener.apply",
    "security.ssh_listener.confirm",
    "security.ssh_listener.rollback",
    "security.vless_listener.apply",
    "security.vless_listener.confirm",
    "security.vless_listener.rollback",
    "service.restart",
    "service.start",
    "service.stop",
    "ssh.key.add",
    "ssh.key.delete",
    "ssh.key.rename",
})


class ActionCatalogTests(unittest.TestCase):
    def test_catalog_covers_protocol_and_change_actions(self) -> None:
        self.assertEqual(registered_protocol_actions(), EXPECTED_PROTOCOL_ACTIONS)
        actions = registered_actions()
        self.assertEqual(len(actions), len({action.name for action in actions}))
        changes = {
            action.name
            for action in actions
            if action.kind is ActionKind.CHANGE
        }
        self.assertEqual(changes, EXPECTED_CHANGE_ACTIONS)

    def test_vless_listener_transaction_has_no_public_endpoint_parameters(self) -> None:
        action = validate_action_request(
            "security.transaction.change",
            {
                "transaction_type": "vless_listener",
                "operation": "apply",
                "session_id": "a" * 64,
                "actor": "owner",
                "confirmed": True,
            },
        )
        self.assertEqual(action.name, "security.vless_listener.apply")
        with self.assertRaises(ActionCatalogError):
            validate_action_request(
                "security.transaction.change",
                {
                    "transaction_type": "vless_listener",
                    "operation": "apply",
                    "session_id": "a" * 64,
                    "public_ip": "203.0.113.10",
                    "public_port": "443",
                    "actor": "owner",
                    "confirmed": True,
                },
            )

    def test_catalog_matches_every_control_plane_dispatch_branch(self) -> None:
        source = inspect.getsource(ControlPlane._dispatch)
        dispatched = frozenset(re.findall(r'if action == "([^"]+)"', source))
        task_only_protocols = {
            action.protocol_action
            for action in registered_actions()
            if action.task_only
        }
        self.assertEqual(
            dispatched | task_only_protocols,
            registered_protocol_actions(),
        )
        for mutation in (
            "change_service", "update_proxy_resources", "deploy_service",
            "change_file_resource", "change_network_node",
            "change_network_permission", "sync_network_subscriptions",
            "rotate_network_subscription", "set_network_subscription_state",
            "change_firewall_port", "change_ssh_key",
            "change_managed_port",
        ):
            self.assertNotIn(f"self._runner.{mutation}(", source)

    def test_every_change_exposes_task_engine_metadata(self) -> None:
        for action in registered_actions():
            if action.kind is not ActionKind.CHANGE:
                continue
            with self.subTest(action=action.name):
                self.assertIsNotNone(action.change_level)
                self.assertTrue(action.preview)
                self.assertTrue(action.fact_scope)
                self.assertTrue(action.validator)
                self.assertTrue(action.executor)
                self.assertTrue(action.verifier)
                self.assertTrue(action.task_only)
                self.assertFalse(action.sync_confirmation_required)
                self.assertFalse(action.sync_confirmation_message)
                self.assertGreater(action.timeout_seconds, 0)

    def test_rollback_capability_is_independent_from_change_level(self) -> None:
        firewall_apply = resolve_action(
            "security.transaction.change",
            {"transaction_type": "firewall", "operation": "apply"},
        )
        firewall_confirm = resolve_action(
            "security.transaction.change",
            {"transaction_type": "firewall", "operation": "confirm"},
        )
        self.assertIs(firewall_apply.change_level, ChangeLevel.ROLLBACK)
        self.assertTrue(firewall_apply.supports_rollback)
        self.assertIs(firewall_confirm.change_level, ChangeLevel.ROLLBACK)
        self.assertFalse(firewall_confirm.supports_rollback)

        endpoint_apply = resolve_action(
            "network.public_endpoint.change", {"operation": "apply"}
        )
        endpoint_confirm = resolve_action(
            "network.public_endpoint.change", {"operation": "confirm"}
        )
        endpoint_rollback = resolve_action(
            "network.public_endpoint.change", {"operation": "rollback"}
        )
        self.assertIs(endpoint_apply.change_level, ChangeLevel.ROLLBACK)
        self.assertTrue(endpoint_apply.supports_rollback)
        self.assertIs(endpoint_confirm.change_level, ChangeLevel.ROLLBACK)
        self.assertFalse(endpoint_confirm.supports_rollback)
        self.assertIs(endpoint_rollback.change_level, ChangeLevel.ROLLBACK)

    def test_change_levels_follow_the_accepted_risk_table(self) -> None:
        self.assertIs(
            resolve_action("file.resource.change", {"operation": "add"}).change_level,
            ChangeLevel.ROUTINE,
        )
        self.assertIs(
            resolve_action("ssh.key.change", {"operation": "rename"}).change_level,
            ChangeLevel.ROUTINE,
        )
        self.assertIs(
            resolve_action("network.node.change", {"kind": "vless", "operation": "remove"}).change_level,
            ChangeLevel.CONFIRMATION,
        )
        self.assertIs(
            resolve_action("security.transaction.change", {"transaction_type": "firewall", "operation": "apply"}).change_level,
            ChangeLevel.ROLLBACK,
        )
        self.assertIs(
            resolve_action("backup.restore.change", {"operation": "restore_apply"}).change_level,
            ChangeLevel.ROLLBACK,
        )

    def test_sensitive_fields_and_lifecycle_exceptions_are_explicit(self) -> None:
        proxy = resolve_action("network.proxy.update", {})
        self.assertEqual(proxy.sensitive_fields, frozenset({"airport_url", "exit_proxy_yaml"}))
        backup = resolve_action("backup.manage", {"operation": "create"})
        self.assertEqual(backup.sensitive_fields, frozenset({"passphrase"}))
        protocol_actions = registered_protocol_actions()
        self.assertNotIn("management.initialize", protocol_actions)
        self.assertNotIn("management.update", protocol_actions)
        self.assertNotIn("management.uninstall", protocol_actions)

    def test_sensitive_read_actions_explicitly_require_sync_confirmation(self) -> None:
        reveal = resolve_action("service.reveal", {})
        preview_restore = resolve_action(
            "backup.manage", {"operation": "preview_restore"}
        )
        backup_list = resolve_action("backup.manage", {"operation": "list"})
        self.assertTrue(reveal.sync_confirmation_required)
        self.assertTrue(preview_restore.sync_confirmation_required)
        self.assertFalse(backup_list.sync_confirmation_required)

    def test_unknown_actions_variants_and_caller_levels_are_rejected(self) -> None:
        with self.assertRaisesRegex(ActionCatalogError, "动作未登记"):
            resolve_action("shell.execute", {})
        with self.assertRaisesRegex(ActionCatalogError, "动作未登记"):
            resolve_action("ssh.key.change", {"operation": "replace"})
        with self.assertRaisesRegex(ActionCatalogError, "变更等级不能由调用方指定"):
            resolve_action("file.resource.change", {"operation": "add", "change_level": "rollback"})


if __name__ == "__main__":
    unittest.main()
