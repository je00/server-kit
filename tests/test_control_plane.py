#!/usr/bin/env python3
"""验证管理代理只允许经过模式校验的登记动作。"""

from __future__ import annotations

import unittest
import sys
import tempfile
import json
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))

from control_plane.core import ControlPlane
from control_plane.tasks import ChangeTaskEngine, TaskEngineError
from control_plane.task_crypto import TaskPayloadCipher


class FakeTaskEngine:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def preview(self, action, arguments, actor):
        self.calls.append(("preview", action, arguments, actor))
        return {"id": "task-" + "a" * 32, "state": "waiting_confirmation"}

    def confirm(self, task_id, actor):
        self.calls.append(("confirm", task_id, actor))
        return {"id": task_id, "state": "queued"}

    def cancel(self, task_id, actor):
        self.calls.append(("cancel", task_id, actor))
        return {"id": task_id, "state": "cancelled"}

    def get(self, task_id):
        self.calls.append(("get", task_id))
        return {"id": task_id, "state": "running"}

    def list(self):
        self.calls.append(("list",))
        return {"items": []}

    def has_active_tasks(self):
        self.calls.append(("active",))
        return True


class FakeRunner:
    def __init__(self) -> None:
        self.calls = 0
        self.changes: list[tuple[str, str, str]] = []
        self.reveals: list[tuple[str, str, str, str]] = []
        self.transactions: list[tuple[str, str, str]] = []
        self.backups: list[tuple[str, str, str, str]] = []
        self.backup_items: list[dict[str, object]] = [{
            "backup_id": "backup-20260807T120000Z-1234abcd",
            "format_version": 2,
            "created_at": "2026-08-07T12:00:00+00:00",
            "host": "test-host", "cipher": "AES-256-GCM",
            "categories": ["server-kit"], "file_count": 3,
            "size": 4096,
            "download_name": "backup-20260807T120000Z-1234abcd.skb",
            "key_custody_version": 2, "client_private_keys": "excluded",
            "restore_allowed": True, "assurance_state": "cleanup_ready",
        }]
        self.state = "运行中"
        self.network_changes: list[tuple[str, str, str, str, str]] = []
        self.network_imports: list[tuple[str, str, str, str, str]] = []
        self.node_domain_changes: list[tuple[str, list[str], str]] = []
        self.node_domains: dict[str, list[str]] = {"home-desk": ["old.example.com"]}
        self.address_domain_changes: list[tuple[str, list[str], str]] = []
        self.address_domains: dict[str, list[str]] = {}
        self.enrollment_requests: list[dict[str, object]] = []
        self.subscription_syncs: list[str] = []
        self.permission_changes: list[tuple[str, str, str, str, str, str]] = []
        self.subscription_rotations: list[tuple[str, str]] = []
        self.subscription_states: list[tuple[str, str, str]] = []
        self.file_changes: list[tuple[object, ...]] = []
        self.discarded_uploads: list[str] = []
        self.firewall_port_changes: list[tuple[object, ...]] = []
        self.managed_port_changes: list[tuple[object, ...]] = []
        self.ssh_key_changes: list[tuple[str, str, str, str]] = []
        self.ssh_key_previews: list[tuple[str, str]] = []
        self.proxy_updates: list[tuple[str, str, str]] = []
        self.network_revision = 1
        self.public_endpoint_fqdn = ""
        self.public_endpoint_transaction_id = ""
        self.duckdns_configured = False
        self.duckdns_enabled = False
        self.duckdns_changes: list[tuple[str, str, str, str, str, str, str, str]] = []
        self.home_permissions: list[dict[str, object]] = [{
            "target": "all", "target_label": "全部节点", "ip": "",
            "ports": [], "ports_label": "全部端口", "network": "all",
            "network_label": "全部协议",
        }]
        self.firewall_base_port = 0
        self.firewall_items: list[dict[str, object]] = []
        self.deployment_calls: list[tuple[str, dict[str, object], str]] = []
        self.deployment_states = {"mosh": "未安装", "file": "未安装"}
        self.transaction_states = {
            "ssh_auth": "idle", "ssh_listener": "idle", "firewall": "idle",
            "vless_listener": "idle",
        }
        self.transaction_sessions: dict[str, str] = {}
        self.restore_state = "idle"
        self.restore_session = ""

    def snapshot(self) -> dict[str, object]:
        self.calls += 1
        result = {
            "schema_version": 1,
            "generated_at": f"sample-{self.calls}",
            "services": [
                {"id": "amneziawg", "label": "AmneziaWG", "state": "运行中", "ports": [{"protocol": "udp", "port": "443"}]},
                {"id": "management", "label": "管理网站", "state": "运行中", "ports": [{"protocol": "tcp", "port": "9080"}]},
                {"id": "ssh", "label": "系统 SSH", "state": "运行中", "ports": [{"protocol": "tcp", "port": "22"}]},
                {"id": "clash", "label": "Clash 订阅", "state": self.state, "ports": [{"protocol": "tcp", "port": "8444"}]},
                {"id": "vless", "label": "Xray / VLESS", "state": "运行中", "ports": [{"protocol": "tcp", "port": "443"}]},
                {"id": "mosh", "label": "Mosh 终端", "state": self.deployment_states["mosh"], "ports": []},
                {"id": "file", "label": "普通文件", "state": self.deployment_states["file"], "ports": []},
            ],
        }
        return result

    def public_endpoint_status(self):
        return {"schema_version": 1, "configured": bool(self.public_endpoint_fqdn), "fqdn": self.public_endpoint_fqdn, "current_ipv4": "203.0.113.10", "dns_ipv4s": [], "matches_current_ipv4": None, "dns_ttl": None, "dns_ttl_status": "未知", "diagnostics": [], "recovery_hint": "等待 TTL"}

    def duckdns_status(self):
        return {
            "schema_version": 2, "configured": self.duckdns_configured,
            "enabled": self.duckdns_enabled,
            "provider": "duckdns" if self.duckdns_configured else "",
            "provider_label": "DuckDNS" if self.duckdns_configured else "未配置",
            "fqdn": "gateway-demo.duckdns.org" if self.duckdns_configured else "",
            "zone": "", "record": "", "credentials_present": self.duckdns_configured,
            "token_present": self.duckdns_configured, "last_result": "",
            "last_update_at": "", "last_ipv4": "", "dns_ipv4s": [],
            "dns_matches_last_ipv4": None, "timer_state": "disabled",
            "next_run": "", "diagnostics": [],
        }

    def change_duckdns(self, operation, provider, fqdn, token, secret_id, secret_key, zone, actor):
        self.duckdns_changes.append((operation, provider, fqdn, token, secret_id, secret_key, zone, actor))
        if operation == "configure":
            self.duckdns_configured = self.duckdns_enabled = True
        elif operation == "disable":
            self.duckdns_enabled = False
        elif operation == "delete":
            self.duckdns_configured = self.duckdns_enabled = False
        return {"operation": operation}

    def public_endpoint_transaction_status(self, actor, session_id):
        return {
            "schema_version": 1, "operation": "status",
            "state": "idle", "fqdn": self.public_endpoint_fqdn,
            "subscriptions_refreshed": False, "expires_at": "",
            "remaining_seconds": 0, "rollback_seconds": 300,
            "independent_session": True, "last_outcome": "",
            "transaction_id": self.public_endpoint_transaction_id,
        }

    def change_public_endpoint(
        self, operation, fqdn, actor, session_id="", transaction_id=""
    ):
        if operation == "apply":
            self.public_endpoint_fqdn = fqdn
            self.public_endpoint_transaction_id = "b" * 64
        return {
            "schema_version": 1, "operation": operation, "state": "pending" if operation == "apply" else "idle",
            "transaction_id": self.public_endpoint_transaction_id,
            "fqdn": self.public_endpoint_fqdn, "subscriptions_refreshed": True,
            "expires_at": "2026-08-13T12:05:00+00:00" if operation == "apply" else "",
            "remaining_seconds": 300 if operation == "apply" else 0,
            "rollback_seconds": 300, "independent_session": operation != "apply",
            "last_outcome": "" if operation == "apply" else operation + "ed",
        }

    def change_service(self, service_id: str, operation: str, actor: str) -> dict[str, object]:
        self.changes.append((service_id, operation, actor))
        if operation == "stop":
            self.state = "已停止"
        elif operation in {"start", "restart"}:
            self.state = "运行中"
        return self.snapshot()

    def service_inventory(self, service_id: str) -> dict[str, object]:
        if service_id == "firewall":
            state = str(self.firewall_base_port) if self.firewall_base_port else "无"
            return {
                "schema_version": 1, "service_id": service_id,
                "facts": {"方案": "nftables 独立 inet 规则表"},
                "items": [{"name": "公网入口", "state": state, "detail": "公网 · TCP"}],
            }
        return {
            "schema_version": 1,
            "service_id": service_id,
            "facts": {"测试事实": "安全值"},
            "items": [],
        }

    def reveal_resource(
        self, service_id: str, resource: str, item_id: str, actor: str
    ) -> dict[str, object]:
        self.reveals.append((service_id, resource, item_id, actor))
        return {
            "schema_version": 1,
            "resource": "clash_subscription_qr",
            "item_id": item_id,
            "name": "phone",
            "image_base64": "iVBORw0KGgo=",
        }

    def file_resources(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "configured": True,
            "address": "10.20.0.1",
            "port": 52541,
            "service_state": "运行中",
            "items": [{
                "resource_id": "file-1234567890abcdef",
                "name": "large.bin",
                "size": 7,
                "cdn_cache": True,
                "cache_ttl": 86400,
            }],
        }

    def change_file_resource(self, operation, upload_id, download_name, cdn_cache, cache_ttl, resource_id, actor):
        self.file_changes.append((operation, upload_id, download_name, cdn_cache, cache_ttl, resource_id, actor))
        return {"schema_version": 1, "operation": operation, "resource_id": resource_id or "file-1234567890abcdef"}

    def file_upload_facts(self, upload_id):
        return {
            "schema_version": 1,
            "upload_id": upload_id,
            "size": 7,
            "sha256": "a" * 64,
        }

    def discard_file_upload(self, upload_id):
        self.discarded_uploads.append(upload_id)

    def deploy_service(self, service_id, values, actor):
        self.deployment_calls.append((service_id, dict(values), actor))
        if service_id == "clash":
            self.state = "运行中"
        elif service_id in self.deployment_states:
            self.deployment_states[service_id] = "运行中"
        service = next(item for item in self.snapshot()["services"] if item["id"] == service_id)
        return {
            "schema_version": 1, "service_id": service_id, "state": "completed",
            "service": service,
            "verification": {"snapshot": True, "inventory": True},
        }

    def proxy_resources(self) -> dict[str, object]:
        return {
            "schema_version": 3,
            "revision": "a" * 64,
            "configured": True,
            "airport_count": 1,
            "active_airport_count": 1,
            "airports": [{
                "id": "111111111111", "name": "主用机场", "host": "airport.test",
                "enabled": True, "countries": ["hk"], "country_labels": ["香港"],
            }],
            "country_options": [{"id": "hk", "label": "香港"}],
            "exit": {
                "configured": True,
                "type": "socks5",
                "server": "exit.test",
                "port": 1080,
            },
            "exit_count": 1, "default_exit_id": "333333333333",
            "exits": [{"id": "333333333333", "name": "默认出口", "default": True,
                "type": "socks5", "server": "exit.test", "port": 1080}],
        }

    def update_proxy_resources(self, values, actor):
        self.proxy_updates.append((dict(values), actor))
        return self.proxy_resources()

    def firewall_ports(self) -> dict[str, object]:
        return {"schema_version": 1, "firewall_active": True, "items": list(self.firewall_items)}

    def change_firewall_port(self, operation, port, scope, protocol, duration_seconds, actor):
        self.firewall_port_changes.append((operation, port, scope, protocol, duration_seconds, actor))
        return {
            "schema_version": 1, "firewall_active": True,
            "items": list(self.firewall_items),
            "verification": {"facts": True, "nftables": True},
        }

    def managed_ports(self) -> dict[str, object]:
        return {
            "schema_version": 1, "revision": "c" * 64,
            "items": [{
                "id": "clash", "service_id": "clash", "label": "Clash 订阅端口",
                "protocol": "tcp", "scope": "public", "port": 8444,
                "minimum": 1, "maximum": 65535, "installed": True,
                "active": True, "listening": True, "restart_required": True,
                "impact": "订阅链接端口会变化。",
            }],
            "occupied": [],
        }

    def change_managed_port(self, target_id, port, revision, actor):
        self.managed_port_changes.append((target_id, port, revision, actor))
        return {"changed": True, "plan": {}, "overview": self.managed_ports()}

    def ssh_keys(self):
        return {"schema_version": 1, "items": [
            {
                "type": "ssh-ed25519",
                "fingerprint": "SHA256:test-one",
                "name": "家庭台式机",
                "key_id": "key-" + "a" * 64,
                "deletable": True,
            },
            {
                "type": "ssh-ed25519",
                "fingerprint": "SHA256:last-key",
                "name": "最后密钥",
                "key_id": "key-" + "b" * 64,
                "deletable": False,
            },
        ]}

    def preview_ssh_key(self, public_key, actor):
        self.ssh_key_previews.append((public_key, actor))
        return {
            "schema_version": 1, "pending_token": "a" * 32,
            "type": "ssh-ed25519", "fingerprint": "SHA256:test",
            "name": "家庭台式机", "duplicate": False, "expires_in": 300,
        }

    def change_ssh_key(self, operation, item_id, name, actor):
        self.ssh_key_changes.append((operation, item_id, name, actor))
        field = {"add": "added", "rename": "renamed", "delete": "deleted"}[operation]
        return {"schema_version": 1, field: True, "key_id": "key-" + "a" * 64,
                "type": "ssh-ed25519", "fingerprint": "SHA256:test", "name": name or "家庭台式机"}

    def manage_transaction(
        self, transaction_type: str, operation: str, actor: str,
        session_id: str = "", public_ip: str = "", public_port: str = "",
    ) -> dict[str, object]:
        self.transactions.append((transaction_type, operation, actor))
        if operation == "apply":
            self.transaction_states[transaction_type] = "pending"
            self.transaction_sessions[transaction_type] = session_id
        elif operation in {"confirm", "rollback"}:
            self.transaction_states[transaction_type] = "idle"
            self.transaction_sessions.pop(transaction_type, None)
        result = {
            "schema_version": 1,
            "transaction_type": transaction_type,
            "title": transaction_type,
            "state": self.transaction_states[transaction_type],
            "expires_at": "2026-08-08T12:05:00+00:00" if self.transaction_states[transaction_type] == "pending" else "",
            "remaining_seconds": 300 if self.transaction_states[transaction_type] == "pending" else 0,
            "writes_enabled": True,
            "rollback_seconds": 300,
            "changes": [{"label": "测试项", "current": "旧值", "target": "新值", "changed": True}],
            "verifications": ["独立 SSH 连接"],
            "ready": True,
            "blockers": [],
            "independent_session": self.transaction_sessions.get(transaction_type) != session_id,
        }
        if transaction_type == "vless_listener":
            result["transaction_id"] = "f" * 64 if self.transaction_states[transaction_type] == "pending" else ""
            result["last_outcome"] = (
                "confirmed" if operation == "confirm"
                else "rolled_back" if operation == "rollback"
                else ""
            )
        return result

    def manage_backup(
        self, operation: str, backup_id: str, passphrase: str, actor: str,
        session_id: str = "",
    ) -> dict[str, object]:
        self.backups.append((operation, backup_id, passphrase, actor))
        if operation == "list":
            return {"schema_version": 1, "items": list(self.backup_items)}
        if operation == "create":
            item = {
                "backup_id": "backup-20260808T120000Z-abcdef12",
                "format_version": 2,
                "created_at": "2026-08-08T12:00:00+00:00",
                "host": "test-host", "cipher": "AES-256-GCM",
                "categories": ["server-kit"], "file_count": 3,
                "size": 8192,
                "download_name": "backup-20260808T120000Z-abcdef12.skb",
                "key_custody_version": 2, "client_private_keys": "excluded",
                "restore_allowed": True, "assurance_state": "awaiting_verification",
            }
            self.backup_items.insert(0, item)
            return item
        if operation == "verify":
            item = next(item for item in self.backup_items if item["backup_id"] == backup_id)
            return {**item, "verified": True, "verified_file_count": item["file_count"]}
        if operation == "delete":
            self.backup_items = [item for item in self.backup_items if item["backup_id"] != backup_id]
            return {"schema_version": 1, "backup_id": backup_id, "deleted": True}
        if operation == "preview_restore":
            return {
                "schema_version": 1, "backup": {"backup_id": backup_id},
                "changes": [{"path": "/etc/server-kit/ports.json", "category": "server-kit", "state": "将覆盖（内容不同）"}],
                "changed_count": 1, "online_changed_count": 1,
                "offline_changed_count": 0, "writes_enabled": False,
            }
        if operation == "restore_apply":
            self.restore_state = "pending"
            self.restore_session = session_id
        elif operation in {"restore_confirm", "restore_rollback"}:
            self.restore_state = "idle"
            self.restore_session = ""
        return {
            "schema_version": 1, "state": self.restore_state,
            "backup_id": self.backup_items[0]["backup_id"] if self.restore_state == "pending" else "",
            "expires_at": "2026-08-08T12:05:00+00:00" if self.restore_state == "pending" else "",
            "remaining_seconds": 300 if self.restore_state == "pending" else 0,
            "rollback_seconds": 300, "changed_count": 1 if self.restore_state == "pending" else 0,
            "categories": ["server-kit"] if self.restore_state == "pending" else [],
            "verifications": ["关键事实配置"] if self.restore_state == "pending" else [],
            "writes_enabled": True, "last_outcome": "",
            "independent_session": self.restore_session != session_id,
        }

    def network_overview(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "revision": self.network_revision,
            "management_peer": "home-desk",
            "management_port": 9080,
            "host_records": [
                {"address": address, "domains": list(domains)}
                for address, domains in self.address_domains.items()
            ],
            "nodes": [
                {"name": "home-desk", "kind": "awg", "address": "10.20.0.101", "state": "已启用", "protected": True, "permissions": self.home_permissions, "access_mode": "unrestricted", "domains": list(self.node_domains.get("home-desk", [])), "legacy_stash": False, "clean_mode": False},
                {"name": "iphone", "kind": "vless", "address": "—", "state": "已启用", "protected": False, "permissions": [], "access_mode": "restricted", "domains": [], "legacy_stash": False, "clean_mode": False},
            ],
            "targets": [
                {"name": "all", "label": "全部节点"},
                {"name": "vps", "label": "VPS 本机"},
                {"name": "home-desk", "label": "home-desk"},
            ],
            "publications": [],
            "subscription_items": [
                {
                    "name": "home-desk", "kind": "awg", "kind_label": "AmneziaWG",
                    "state": "已发布", "published": True, "resource_id": "home-desk",
                },
                {
                    "name": "iphone", "kind": "vless", "kind_label": "VLESS",
                    "state": "待同步", "published": False, "resource_id": "iphone",
                },
            ],
        }

    def audit_log(self) -> dict[str, object]:
        return {"schema_version": 1, "chain_valid": True, "items": []}

    def change_network_node(self, kind: str, operation: str, name: str, address: str, actor: str) -> dict[str, object]:
        self.network_changes.append((kind, operation, name, address, actor))
        return {"schema_version": 1, "kind": kind, "operation": operation, "name": name}

    def import_network_node(self, name: str, address: str, public_key: str, preshared_key: str, actor: str) -> dict[str, object]:
        self.network_imports.append((name, address, public_key, preshared_key, actor))
        return {"schema_version": 1, "kind": "awg", "operation": "import", "name": name}

    def change_node_domains(self, name: str, domains: list[str], actor: str) -> dict[str, object]:
        self.node_domains[name] = list(domains)
        self.node_domain_changes.append((name, list(domains), actor))
        return {
            "schema_version": 1, "operation": "set", "name": name,
            "address": "10.20.0.101", "domains": list(domains),
            "subscriptions_refreshed": True,
        }

    def change_address_domains(self, address: str, domains: list[str], actor: str) -> dict[str, object]:
        if domains:
            self.address_domains[address] = list(domains)
        else:
            self.address_domains.pop(address, None)
        self.address_domain_changes.append((address, list(domains), actor))
        return {
            "schema_version": 1, "operation": "set-address", "address": address,
            "domains": list(domains), "subscriptions_refreshed": True,
        }

    def enrollment_context(self) -> dict[str, object]:
        return {
            "schema_version": 1, "network": "10.20.0.0/24", "server_ip": "10.20.0.1",
            "suggested_address": "10.20.0.23", "prefix": 24,
            "server_public_key": "A" * 43 + "=", "mtu": 1280,
            "endpoints": [{"profile": name, "host": "203.0.113.1", "port": port}
                          for name, port in (("main", 443), ("backup1", 1848))],
            "obfuscation": {},
        }

    def enrollment_overview(self) -> dict[str, object]:
        return {"schema_version": 1, "items": []}

    def enroll_signed_network_node(self, envelope: dict[str, object]) -> dict[str, object]:
        self.enrollment_requests.append(envelope)
        return {"schema_version": 1, "kind": "awg", "operation": "enroll", "name": "new-node", "state": "pending", "expires_in": 300}

    def sync_network_subscriptions(self, actor: str) -> dict[str, object]:
        self.subscription_syncs.append(actor)
        return {"schema_version": 1, "operation": "sync", "state": "completed"}

    def change_network_permission(self, operation: str, client: str, target: str, ports: str, network: str, actor: str) -> dict[str, object]:
        self.permission_changes.append((operation, client, target, ports, network, actor))
        return {"schema_version": 1, "operation": operation, "client": client, "target": target}

    def rotate_network_subscription(self, name: str, actor: str) -> dict[str, object]:
        self.subscription_rotations.append((name, actor))
        return {"schema_version": 1, "operation": "rotate", "name": name}

    def set_network_subscription_state(self, name: str, state: str, actor: str) -> dict[str, object]:
        self.subscription_states.append((name, state, actor))
        return {"schema_version": 1, "operation": "set-state", "name": name, "state": state}


def request(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "request_id": "test-1",
        "action": "system.snapshot",
        "params": {},
    }
    value.update(overrides)
    return value


class ControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = FakeRunner()
        self.tasks = FakeTaskEngine()
        self.plane = ControlPlane(
            self.runner, {0, 1001}, task_engine=self.tasks
        )

    def test_task_protocol_uses_registered_task_engine_interface(self) -> None:
        preview = self.plane.handle(
            request(
                action="task.preview",
                params={
                    "action": "service.change",
                    "arguments": {"service_id": "clash", "operation": "stop"},
                    "actor": "owner",
                },
            ),
            1001,
        )
        task_id = "task-" + "a" * 32
        confirmed = self.plane.handle(
            request(
                action="task.confirm",
                params={"task_id": task_id, "actor": "owner"},
            ),
            1001,
        )
        detail = self.plane.handle(
            request(action="task.get", params={"task_id": task_id}),
            1001,
        )
        listing = self.plane.handle(
            request(action="task.list", params={}),
            1001,
        )
        cancelled = self.plane.handle(
            request(
                action="task.cancel",
                params={"task_id": task_id, "actor": "owner"},
            ),
            1001,
        )
        active = self.plane.handle(
            request(action="task.active", params={}),
            1001,
        )

        self.assertTrue(preview["ok"])
        self.assertEqual(confirmed["result"]["state"], "queued")
        self.assertEqual(detail["result"]["state"], "running")
        self.assertEqual(listing["result"], {"items": []})
        self.assertEqual(cancelled["result"]["state"], "cancelled")
        self.assertTrue(active["result"]["active"])
        self.assertEqual(len(self.tasks.calls), 6)

    def test_public_endpoint_is_read_only_and_changes_prepare_rollback_task(self) -> None:
        status = self.plane.handle(request(action="network.public_endpoint.status", params={}), 1001)
        self.assertFalse(status["result"]["configured"])
        transaction = self.plane.handle(request(
            action="network.public_endpoint.transaction.status",
            params={"actor": "owner", "session_id": "a" * 64},
        ), 1001)
        self.assertEqual(transaction["result"]["state"], "idle")
        prepared = self.plane.prepare_task_action(
            "network.public_endpoint.change",
            {"operation": "apply", "fqdn": "VPN.Example.com.", "session_id": "a" * 64},
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "network.public_endpoint.apply")
        self.assertEqual(prepared.params["fqdn"], "vpn.example.com")
        self.assertEqual(prepared.params["transaction_id"], "")
        self.assertTrue(prepared.supports_rollback)
        self.assertIn("客户端影响", prepared.preview["facts"])
        self.assertEqual(prepared.timeout_seconds, 240)

    def test_public_endpoint_cannot_enter_existing_subscription_wildcard(self) -> None:
        self.runner.node_domains["home-desk"] = ["*.managed.example.com"]
        with self.assertRaisesRegex(TaskEngineError, "覆盖 VPS 域名"):
            self.plane.prepare_task_action(
                "network.public_endpoint.change",
                {
                    "operation": "apply", "fqdn": "gateway-demo.managed.example.com",
                    "session_id": "a" * 64,
                },
                "owner",
            )

    def test_duckdns_token_is_only_in_encrypted_sensitive_payload(self) -> None:
        token = "12345678-1234-1234-1234-123456789abc"
        status = self.plane.handle(
            request(action="network.duckdns.status", params={}), 1001
        )
        self.assertFalse(status["result"]["token_present"])
        prepared = self.plane.prepare_task_action(
            "network.duckdns.change",
            {
                "operation": "configure", "provider": "duckdns", "token": token,
                "fqdn": "", "secret_id": "", "secret_key": "", "zone": "",
            }, "owner",
        )
        self.assertEqual(prepared.canonical_action, "network.duckdns.configure")
        self.assertEqual(prepared.params["token"], "")
        self.assertEqual(prepared.sensitive_params, {
            "provider": "duckdns", "fqdn": "", "token": token, "secret_id": "",
            "secret_key": "", "zone": "",
        })
        self.assertNotIn(token, json.dumps(prepared.preview, ensure_ascii=False))

        execution = {**prepared.params, **prepared.sensitive_params}
        self.plane.execute_task_action("network.duckdns.change", execution)
        self.assertEqual(self.runner.duckdns_changes, [
            ("configure", "duckdns", "", token, "", "", "", "owner")
        ])

    def test_dnspod_credentials_are_only_in_encrypted_sensitive_payload(self) -> None:
        secret_id = "AKIDEXAMPLE1234567890123456789012"
        secret_key = "example-secret-key-value-1234567890"
        prepared = self.plane.prepare_task_action(
            "network.duckdns.change",
            {
                "operation": "configure", "provider": "dnspod", "token": "",
                "fqdn": "gateway-demo.managed.example.com",
                "secret_id": secret_id, "secret_key": secret_key, "zone": "managed.example.com",
            }, "owner",
        )
        self.assertEqual(prepared.params["secret_id"], "")
        self.assertEqual(prepared.params["secret_key"], "")
        self.assertEqual(prepared.sensitive_params, {
            "provider": "dnspod", "fqdn": "gateway-demo.managed.example.com", "token": "", "secret_id": secret_id,
            "secret_key": secret_key, "zone": "managed.example.com",
        })
        rendered = json.dumps(prepared.preview, ensure_ascii=False)
        self.assertNotIn(secret_id, rendered)
        self.assertNotIn(secret_key, rendered)

    def test_dnspod_domain_cannot_enter_existing_subscription_wildcard(self) -> None:
        self.runner.node_domains["home-desk"] = ["*.managed.example.com"]
        with self.assertRaisesRegex(TaskEngineError, "覆盖 VPS 域名"):
            self.plane.prepare_task_action(
                "network.duckdns.change",
                {
                    "operation": "configure", "provider": "dnspod",
                    "fqdn": "gateway-demo.managed.example.com", "token": "",
                    "secret_id": "AKIDEXAMPLE1234567890123456789012",
                    "secret_key": "example-secret-key-value-1234567890",
                    "zone": "managed.example.com",
                }, "owner",
            )

    def test_root_prepares_service_preview_from_live_facts(self) -> None:
        prepared = self.plane.prepare_task_action(
            "service.change",
            {"service_id": "clash", "operation": "stop"},
            "owner",
        )

        self.assertEqual(prepared.canonical_action, "service.stop")
        self.assertEqual(prepared.preview["facts"]["当前状态"], "运行中")
        self.assertEqual(prepared.preview["facts"]["目标状态"], "已停止")
        self.assertRegex(prepared.fact_digest, r"^[0-9a-f]{64}$")

        current = self.plane.inspect_task_action(
            "service.change", dict(prepared.params)
        )
        self.assertEqual(current["fact_digest"], prepared.fact_digest)
        self.runner.state = "已停止"
        changed = self.plane.inspect_task_action(
            "service.change", dict(prepared.params)
        )
        self.assertNotEqual(changed["fact_digest"], prepared.fact_digest)
        self.assertTrue(changed["result_matches"])
        self.runner.state = "运行中"
        result = self.plane.execute_task_action(
            "service.change", dict(prepared.params)
        )
        self.assertEqual(result["service"]["state"], "已停止")
        self.assertEqual(self.runner.changes, [("clash", "stop", "owner")])

    def test_root_prepares_sensitive_proxy_task_without_plaintext_params(self) -> None:
        airport_url = "https://airport.test/sub?token=private"
        exit_yaml = "type: socks5\nserver: exit.test\nport: 1080\npassword: secret"
        prepared = self.plane.prepare_task_action(
            "network.proxy.update",
            {
                "operation": "airport_add", "airport_id": "",
                "airport_name": "备用机场", "airport_url": airport_url,
                "airport_enabled": True, "countries": ["hk", "jp"],
                "exit_proxy_yaml": "",
                "exit_id": "", "exit_name": "", "exit_default": False,
                "awg_name": "", "exit_ids": [],
            },
            "owner",
        )

        self.assertEqual(prepared.canonical_action, "network.proxy.update")
        self.assertNotIn("airport_url", prepared.params)
        self.assertEqual(prepared.sensitive_params["airport_url"], airport_url)
        self.assertNotIn("private", str(prepared.preview))
        inspected = self.plane.inspect_task_action(
            "network.proxy.update", dict(prepared.params)
        )
        self.assertEqual(inspected["fact_digest"], prepared.fact_digest)
        result = self.plane.execute_task_action(
            "network.proxy.update",
            {**prepared.params, **dict(prepared.sensitive_params)},
        )
        self.assertTrue(result["configured"])
        self.assertEqual(self.runner.proxy_updates[0][0]["airport_url"], airport_url)
        self.assertEqual(self.runner.proxy_updates[0][0]["countries"], ["hk", "jp"])
        self.assertEqual(self.runner.proxy_updates[0][1], "owner")

    def test_airport_update_rejects_unknown_target_and_empty_countries(self) -> None:
        base = {
            "operation": "airport_update", "airport_id": "999999999999",
            "airport_name": "不存在", "airport_url": "", "airport_enabled": True,
            "countries": ["hk"], "exit_proxy_yaml": "",
            "exit_id": "", "exit_name": "", "exit_default": False,
            "awg_name": "", "exit_ids": [],
        }
        with self.assertRaisesRegex(TaskEngineError, "不存在"):
            self.plane.prepare_task_action("network.proxy.update", base, "owner")
        empty = {
            **base, "airport_id": "111111111111", "airport_name": "主用机场",
            "countries": [],
        }
        with self.assertRaisesRegex(TaskEngineError, "国家选择"):
            self.plane.prepare_task_action("network.proxy.update", empty, "owner")

    def test_exit_update_accepts_blank_connection_and_keeps_sensitive_task_contract(self) -> None:
        for exit_yaml in (
            "", " \t\n",
            "type: socks5\nserver: exit.test\nport: 1080\npassword: hidden-password\n",
        ):
            with self.subTest(exit_yaml=exit_yaml):
                values = {
                    "operation": "exit_update", "airport_id": "", "airport_name": "",
                    "airport_url": "", "airport_enabled": False, "countries": [],
                    "exit_id": "333333333333", "exit_name": "Renamed Exit",
                    "exit_default": False, "exit_proxy_yaml": exit_yaml,
                    "awg_name": "", "exit_ids": [],
                }
                prepared = self.plane.prepare_task_action("network.proxy.update", values, "owner")
                self.assertEqual(prepared.canonical_action, "network.proxy.update")
                self.assertNotIn("exit_proxy_yaml", prepared.params)
                self.assertNotIn("airport_url", prepared.params)
                self.assertEqual(prepared.sensitive_params, {
                    "airport_url": "", "exit_proxy_yaml": exit_yaml,
                })
                self.assertEqual(prepared.preview["facts"]["出口"], "Renamed Exit")
                self.assertNotIn("hidden-password", json.dumps(prepared.preview))
                inspected = self.plane.inspect_task_action(
                    "network.proxy.update", dict(prepared.params)
                )
                self.assertEqual(inspected["fact_digest"], prepared.fact_digest)
                self.plane.execute_task_action(
                    "network.proxy.update", {**prepared.params, **prepared.sensitive_params}
                )
                self.assertEqual(self.runner.proxy_updates[-1], (values, "owner"))

    def test_exit_add_still_requires_connection_configuration(self) -> None:
        for exit_yaml in ("", " \t\n"):
            with self.subTest(exit_yaml=exit_yaml):
                with self.assertRaisesRegex(TaskEngineError, "出口名称或节点内容无效"):
                    self.plane.prepare_task_action("network.proxy.update", {
                        "operation": "exit_add", "airport_id": "", "airport_name": "",
                        "airport_url": "", "airport_enabled": False, "countries": [],
                        "exit_id": "", "exit_name": "New Exit", "exit_default": False,
                        "exit_proxy_yaml": exit_yaml, "awg_name": "", "exit_ids": [],
                    }, "owner")
        self.assertEqual(self.runner.proxy_updates, [])

    def test_exit_credentials_stay_encrypted_in_task_storage_and_out_of_public_results(self) -> None:
        secret = "exit-password-must-never-appear-in-plaintext"
        exit_yaml = f"type: socks5\nserver: exit.test\nport: 1080\npassword: {secret}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plane = ControlPlane(self.runner, {1001})
            engine = ChangeTaskEngine(
                root / "tasks.sqlite3",
                plane.prepare_task_action,
                plane.execute_task_action,
                plane.inspect_task_action,
                TaskPayloadCipher(root / "task-payload.key"),
                start_worker=False,
            )
            try:
                task = engine.preview("network.proxy.update", {
                    "operation": "exit_update", "airport_id": "", "airport_name": "",
                    "airport_url": "", "airport_enabled": False, "countries": [],
                    "exit_id": "333333333333", "exit_name": "Renamed Exit",
                    "exit_default": False, "exit_proxy_yaml": exit_yaml,
                    "awg_name": "", "exit_ids": [],
                }, "owner")
                self.assertNotIn(secret, json.dumps(task, ensure_ascii=False))
                self.assertNotIn(secret.encode("utf-8"), (root / "tasks.sqlite3").read_bytes())
                engine.confirm(str(task["id"]), "owner")
                self.assertTrue(engine.process_one())
                detail = engine.get(str(task["id"]))
                self.assertEqual(detail["state"], "succeeded")
                self.assertNotIn(secret, json.dumps(detail, ensure_ascii=False))
                self.assertNotIn(secret.encode("utf-8"), (root / "tasks.sqlite3").read_bytes())
                self.assertEqual(self.runner.proxy_updates[-1][0]["exit_proxy_yaml"], exit_yaml)
            finally:
                engine.close()

    def test_node_multi_exit_task_accepts_awg_and_vless_targets(self) -> None:
        values = {
            "operation": "node_exits_set", "airport_id": "", "airport_name": "",
            "airport_url": "", "airport_enabled": False, "countries": [],
            "exit_id": "", "exit_name": "", "exit_default": False,
            "exit_proxy_yaml": "", "awg_name": "home-desk",
            "exit_ids": ["333333333333"],
        }
        prepared = self.plane.prepare_task_action("network.proxy.update", values, "owner")
        self.assertEqual(prepared.preview["facts"]["中转路径"], "默认出口")
        self.plane.execute_task_action(
            "network.proxy.update", {**prepared.params, **prepared.sensitive_params}
        )
        self.assertEqual(self.runner.proxy_updates[-1][0]["exit_ids"], ["333333333333"])
        vless = self.plane.prepare_task_action(
            "network.proxy.update", {**values, "awg_name": "iphone"}, "owner"
        )
        self.assertEqual(vless.preview["facts"]["订阅节点"], "iphone")
        direct = self.plane.prepare_task_action(
            "network.proxy.update", {**values, "exit_ids": []}, "owner"
        )
        self.assertEqual(
            direct.preview["facts"]["中转路径"],
            "VPS MID（不使用额外出口）",
        )
        with self.assertRaisesRegex(TaskEngineError, "订阅节点不存在"):
            self.plane.prepare_task_action(
                "network.proxy.update", {**values, "awg_name": "missing"}, "owner"
            )

    def test_root_prepares_file_add_and_delete_with_live_facts(self) -> None:
        add_arguments = {
            "operation": "add",
            "upload_id": "a" * 32,
            "download_name": "large.bin",
            "cdn_cache": True,
            "cache_ttl": 86400,
            "resource_id": "",
        }
        added = self.plane.prepare_task_action(
            "file.resource.change", add_arguments, "owner"
        )
        self.assertEqual(added.canonical_action, "file.add")
        self.assertEqual(added.params["_upload_sha256"], "a" * 64)
        self.assertEqual(
            self.plane.inspect_task_action(
                "file.resource.change", dict(added.params)
            )["fact_digest"],
            added.fact_digest,
        )
        self.plane.cleanup_task_action(
            "file.resource.change", dict(added.params)
        )
        self.assertEqual(self.runner.discarded_uploads, ["a" * 32])

        deleted = self.plane.prepare_task_action(
            "file.resource.change",
            {
                "operation": "delete",
                "upload_id": "",
                "download_name": "",
                "cdn_cache": False,
                "cache_ttl": 86400,
                "resource_id": "file-1234567890abcdef",
            },
            "owner",
        )
        self.assertEqual(deleted.canonical_action, "file.delete")
        self.assertIn("不主动清除", str(deleted.preview))

    def test_root_prepares_redacted_ssh_tasks_and_protects_last_key(self) -> None:
        public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest 家庭台式机"
        added = self.plane.prepare_task_action(
            "ssh.key.change",
            {
                "operation": "add",
                "item_id": "",
                "name": "家庭台式机",
                "public_key": public_key,
            },
            "owner",
        )
        self.assertEqual(added.canonical_action, "ssh.key.add")
        self.assertNotIn(public_key, str(added.params))
        self.assertEqual(added.sensitive_params["public_key"], public_key)
        self.assertIn("SHA256:test", str(added.preview))
        self.assertNotIn("AAAAC3", str(added.preview))

        renamed = self.plane.prepare_task_action(
            "ssh.key.change",
            {
                "operation": "rename",
                "item_id": "key-" + "a" * 64,
                "name": "新名称",
                "public_key": "",
            },
            "owner",
        )
        self.assertEqual(renamed.canonical_action, "ssh.key.rename")

        with self.assertRaisesRegex(TaskEngineError, "最后一把"):
            self.plane.prepare_task_action(
                "ssh.key.change",
                {
                    "operation": "delete",
                    "item_id": "key-" + "b" * 64,
                    "name": "",
                    "public_key": "",
                },
                "owner",
            )

    def test_root_prepares_network_tasks_from_live_facts(self) -> None:
        with self.assertRaisesRegex(TaskEngineError, "公钥导入"):
            self.plane.prepare_task_action(
                "network.node.change",
                {
                    "kind": "awg", "operation": "add",
                    "name": "legacy", "address": "10.20.0.20",
                },
                "owner",
            )
        added = self.plane.prepare_task_action(
            "network.node.change",
            {
                "kind": "vless", "operation": "add",
                "name": "new-phone", "address": "",
            },
            "owner",
        )
        self.assertEqual(added.canonical_action, "network.node.vless.add")
        self.assertEqual(added.preview["facts"]["默认授权"], "无内网访问授权")
        self.assertEqual(added.preview["facts"]["订阅发布"], "提交后自动刷新全部订阅")
        inspected = self.plane.inspect_task_action(
            "network.node.change", dict(added.params)
        )
        self.assertEqual(inspected["fact_digest"], added.fact_digest)

        compatibility = self.plane.prepare_task_action(
            "network.node.change",
            {
                "kind": "vless", "operation": "compat-enable",
                "name": "iphone", "address": "",
            },
            "owner",
        )
        self.assertEqual(
            compatibility.canonical_action,
            "network.node.vless.compat-enable",
        )
        self.assertEqual(
            compatibility.preview["facts"]["操作"],
            "启用旧版 Stash 兼容",
        )
        self.assertEqual(
            compatibility.preview["facts"]["订阅发布"],
            "提交后自动刷新全部订阅",
        )

        clean_mode = self.plane.prepare_task_action(
            "network.node.change",
            {
                "kind": "awg", "operation": "clean-enable",
                "name": "home-desk", "address": "",
            },
            "owner",
        )
        self.assertEqual(
            clean_mode.canonical_action,
            "network.node.awg.clean-enable",
        )
        self.assertEqual(clean_mode.preview["facts"]["操作"], "启用订阅纯净模式")
        self.assertEqual(
            clean_mode.preview["facts"]["订阅发布"],
            "提交后自动刷新全部订阅",
        )

        permission = self.plane.prepare_task_action(
            "network.permission.change",
            {
                "operation": "allow", "client": "iphone",
                "target": "home-desk", "ports": "22,443", "network": "tcp",
            },
            "owner",
        )
        self.assertEqual(permission.canonical_action, "network.permission.allow")
        self.assertEqual(permission.preview["facts"]["端口"], "22,443")
        self.runner.network_revision += 1
        changed = self.plane.inspect_task_action(
            "network.permission.change", dict(permission.params)
        )
        self.assertNotEqual(changed["fact_digest"], permission.fact_digest)

    def test_node_domains_are_normalized_and_refresh_all_subscriptions(self) -> None:
        prepared = self.plane.prepare_task_action(
            "network.node.domains",
            {"name": "home-desk", "domains": ["*.INTERNAL.EXAMPLE.", "git.example.com"]},
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "network.node.domains")
        self.assertEqual(prepared.params["domains"], ["*.internal.example", "git.example.com"])
        self.assertEqual(prepared.preview["facts"]["虚拟 IP"], "10.20.0.101")
        self.assertIn("全部 Clash", prepared.preview["facts"]["订阅影响"])
        self.assertIn("VPS", prepared.preview["facts"]["通配符保护"])
        inspected = self.plane.inspect_task_action(
            "network.node.domains", dict(prepared.params)
        )
        self.assertEqual(inspected["fact_digest"], prepared.fact_digest)
        result = self.plane.execute_task_action(
            "network.node.domains", dict(prepared.params)
        )
        self.assertTrue(result["subscriptions_refreshed"])
        self.assertEqual(self.runner.node_domain_changes, [
            ("home-desk", ["*.internal.example", "git.example.com"], "owner")
        ])

    def test_arbitrary_ip_domains_are_normalized_and_refresh_all_subscriptions(self) -> None:
        prepared = self.plane.prepare_task_action(
            "network.address.domains",
            {
                "address": "2001:0db8::103",
                "domains": ["GIT.EXAMPLE.COM.", "*.INTERNAL.EXAMPLE."],
            },
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "network.address.domains")
        self.assertEqual(prepared.params["address"], "2001:db8::103")
        self.assertEqual(
            prepared.params["domains"], ["git.example.com", "*.internal.example"]
        )
        self.assertEqual(prepared.preview["facts"]["目标 IP"], "2001:db8::103")
        result = self.plane.execute_task_action(
            "network.address.domains", dict(prepared.params)
        )
        self.assertTrue(result["subscriptions_refreshed"])
        self.assertEqual(self.runner.address_domain_changes, [
            ("2001:db8::103", ["git.example.com", "*.internal.example"], "owner")
        ])

    def test_arbitrary_ip_domains_reject_duplicates_owned_by_nodes(self) -> None:
        with self.assertRaisesRegex(TaskEngineError, "已属于节点 home-desk"):
            self.plane.prepare_task_action(
                "network.address.domains",
                {"address": "192.168.0.103", "domains": ["old.example.com"]},
                "owner",
            )

    def test_node_domain_wildcard_cannot_cover_vps_hostname(self) -> None:
        self.runner.public_endpoint_fqdn = "gateway-demo.managed.example.com"
        with self.assertRaisesRegex(TaskEngineError, "覆盖 VPS 域名"):
            self.plane.prepare_task_action(
                "network.node.domains",
                {"name": "home-desk", "domains": ["*.managed.example.com"]},
                "owner",
            )

    def test_root_can_transfer_management_entry_to_active_client_held_awg_node(self) -> None:
        original_overview = self.runner.network_overview

        def overview_with_replacement() -> dict[str, object]:
            overview = original_overview()
            overview["nodes"].append({
                "name": "home-laptop2",
                "kind": "awg",
                "state": "已启用",
                "protected": False,
                "custody": "client",
                "permissions": [],
                "access_mode": "unrestricted",
            })
            overview["targets"].append({"name": "home-laptop2", "label": "home-laptop2"})
            return overview

        self.runner.network_overview = overview_with_replacement
        prepared = self.plane.prepare_task_action(
            "network.node.change",
            {
                "kind": "awg",
                "operation": "set-management",
                "name": "home-laptop2",
                "address": "",
            },
            "owner",
        )

        self.assertEqual(prepared.canonical_action, "network.node.awg.set-management")
        self.assertEqual(prepared.preview["facts"]["原管理入口"], "home-desk")
        self.assertEqual(prepared.preview["facts"]["新管理入口"], "home-laptop2")
        result = self.plane.execute_task_action(
            "network.node.change", dict(prepared.params)
        )
        self.assertEqual(result["name"], "home-laptop2")
        self.assertIn(("awg", "set-management", "home-laptop2", "", "owner"), self.runner.network_changes)

    def test_root_prepares_client_held_awg_import_without_plaintext_psk(self) -> None:
        public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        preshared_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        prepared = self.plane.prepare_task_action(
            "network.node.import",
            {
                "name": "client-held", "address": "10.20.0.23",
                "public_key": public_key, "preshared_key": preshared_key,
            },
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "network.node.awg.import")
        self.assertEqual(prepared.params["preshared_key"], "")
        self.assertEqual(prepared.sensitive_params, {"preshared_key": preshared_key})
        self.assertNotIn("密钥托管", prepared.preview["facts"])
        self.assertEqual(
            prepared.preview["facts"]["订阅发布"],
            "登记成功后自动刷新全部订阅",
        )
        self.assertRegex(prepared.preview["facts"]["公钥指纹"], r"^[0-9a-f]{16}$")
        self.assertNotIn(preshared_key, json.dumps(prepared.preview, ensure_ascii=False))
        inspected = self.plane.inspect_task_action(
            "network.node.import", {**prepared.params, "preshared_key": preshared_key}
        )
        self.assertEqual(inspected["fact_digest"], prepared.fact_digest)

    def test_root_protects_management_node_and_rejects_invalid_permission(self) -> None:
        with self.assertRaisesRegex(TaskEngineError, "管理入口"):
            self.plane.prepare_task_action(
                "network.node.change",
                {
                    "kind": "awg", "operation": "disable",
                    "name": "home-desk", "address": "",
                },
                "owner",
            )
        permission = self.plane.prepare_task_action(
            "network.permission.change",
            {
                "operation": "allow", "client": "home-desk",
                "target": "vps", "ports": "22", "network": "tcp",
            },
            "owner",
        )
        additive_rule = self.plane.prepare_task_action(
            "network.permission.change",
            {
                "operation": "allow", "client": "home-desk",
                "target": "all", "ports": "22", "network": "tcp",
            },
            "owner",
        )
        self.assertEqual(additive_rule.preview["title"], "新增访问权限")
        limited_all = self.plane.prepare_task_action(
            "network.permission.change",
            {
                "operation": "allow", "client": "home-desk",
                "target": "all", "ports": "22,9080", "network": "tcp",
            },
            "owner",
        )
        self.assertEqual(limited_all.preview["facts"]["目标"], "全部节点")
        self.assertEqual(limited_all.preview["facts"]["端口"], "22,9080")
        with self.assertRaisesRegex(TaskEngineError, "管理入口"):
            self.plane.prepare_task_action(
                "network.permission.change",
                {
                    "operation": "deny", "client": "home-desk", "target": "all",
                    "ports": "", "network": "",
                },
                "owner",
            )
        self.runner.home_permissions.append({
            "target": "vps", "ip": "10.20.0.1", "ports": [22, 9080],
            "target_label": "VPS 本机", "network": "tcp",
            "network_label": "TCP", "ports_label": "22, 9080",
        })
        permission = self.plane.prepare_task_action(
            "network.permission.change",
            {
                "operation": "deny", "client": "home-desk", "target": "all",
                "ports": "", "network": "all",
            },
            "owner",
        )
        self.assertEqual(permission.canonical_action, "network.permission.deny")
        self.assertEqual(permission.preview["facts"]["目标"], "全部节点")
        result = self.plane.execute_task_action(
            "network.permission.change", dict(permission.params)
        )
        self.assertEqual(result["target"], "all")
        self.assertEqual(
            self.runner.permission_changes[-1],
            ("deny", "home-desk", "all", "", "all", "owner"),
        )

    def test_permission_ranges_are_canonical_and_duplicates_are_rejected(self) -> None:
        params = {"operation": "allow", "client": "home-desk", "target": "vps",
                  "ports": "8002-8004, 22,8000-8002", "network": "tcp"}
        prepared = self.plane.prepare_task_action("network.permission.change", params, "owner")
        self.assertEqual(prepared.params["ports"], "22,8000-8004")
        self.assertEqual(prepared.preview["facts"]["端口"], "22,8000-8004")
        self.plane.execute_task_action("network.permission.change", dict(prepared.params))
        self.assertEqual(self.runner.permission_changes[-1][3], "22,8000-8004")
        self.runner.home_permissions.append({
            "target": "vps", "ip": "10.20.0.1", "ports": [22, *range(8000, 8005)],
            "target_label": "VPS 本机", "network": "tcp", "network_label": "TCP", "ports_label": "22, 8000-8004",
        })
        with self.assertRaisesRegex(TaskEngineError, "已经存在"):
            self.plane.prepare_task_action("network.permission.change", params, "owner")
        deletion = self.plane.prepare_task_action("network.permission.change", {**params, "operation": "deny"}, "owner")
        self.assertEqual(deletion.params["ports"], "22,8000-8004")
        for ports in ("8005-8000", "0-22", "65535-65536", "22,,443"):
            with self.subTest(ports=ports), self.assertRaises(TaskEngineError):
                self.plane.prepare_task_action("network.permission.change", {**params, "ports": ports}, "owner")

    def test_full_port_range_does_not_expand_task_arguments(self) -> None:
        prepared = self.plane.prepare_task_action("network.permission.change", {
            "operation": "allow", "client": "home-desk", "target": "vps", "ports": "1-65535", "network": "tcp",
        }, "owner")
        self.assertEqual(prepared.params["ports"], "1-65535")
        self.assertEqual(prepared.params["network"], "tcp")

    def test_root_prepares_subscription_publication_tasks_without_secrets(self) -> None:
        synced = self.plane.prepare_task_action(
            "network.subscriptions.sync", {}, "owner"
        )
        self.assertEqual(synced.canonical_action, "network.subscriptions.sync")
        self.assertIn("home-desk", synced.preview["facts"]["保留现有链接"])
        self.assertIn("iphone", synced.preview["facts"]["新增或刷新"])
        self.assertNotIn("token", str(synced.preview).lower())

        rotated = self.plane.prepare_task_action(
            "network.subscription.rotate", {"name": "home-desk"}, "owner"
        )
        self.assertEqual(rotated.canonical_action, "network.subscription.rotate")
        self.assertEqual(rotated.preview["facts"]["旧链接"], "成功后立即失效")

        disabled = self.plane.prepare_task_action(
            "network.subscription.state",
            {"name": "home-desk", "state": "disabled"},
            "owner",
        )
        self.assertEqual(disabled.canonical_action, "network.subscription.disable")
        self.assertEqual(disabled.preview["facts"]["节点网络状态"], "不变")
        result = self.plane.execute_task_action(
            "network.subscription.state", dict(disabled.params)
        )
        self.assertEqual(result["state"], "disabled")
        self.assertEqual(self.runner.subscription_states, [("home-desk", "disabled", "owner")])

    def test_root_rejects_rotating_unpublished_subscription(self) -> None:
        with self.assertRaisesRegex(TaskEngineError, "正在发布"):
            self.plane.prepare_task_action(
                "network.subscription.rotate", {"name": "iphone"}, "owner"
            )

    def test_backup_tasks_encrypt_passphrase_and_bind_delete_facts(self) -> None:
        secret = "测试任务恢复口令-长度超过十六个字符"
        created = self.plane.prepare_task_action(
            "backup.manage",
            {"operation": "create", "backup_id": "", "passphrase": secret},
            "owner",
        )
        self.assertEqual(created.canonical_action, "backup.create")
        self.assertNotIn(secret, str(created.params))
        self.assertEqual(created.sensitive_params, {"passphrase": secret})
        self.assertIn("不纳入备份", str(created.preview))

        backup_id = "backup-20260807T120000Z-1234abcd"
        deleted = self.plane.prepare_task_action(
            "backup.manage",
            {"operation": "delete", "backup_id": backup_id, "passphrase": ""},
            "owner",
        )
        self.assertEqual(deleted.canonical_action, "backup.delete")
        self.assertEqual(deleted.preview["facts"]["大小"], "4096 字节")
        self.runner.backup_items[0]["size"] = 8192
        changed = self.plane.inspect_task_action("backup.manage", dict(deleted.params))
        self.assertNotEqual(changed["fact_digest"], deleted.fact_digest)

    def test_backup_task_database_never_contains_plaintext_passphrase(self) -> None:
        secret = "数据库中绝不能出现的恢复口令-123456"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plane = ControlPlane(self.runner, {1001})
            engine = ChangeTaskEngine(
                root / "tasks.sqlite3",
                plane.prepare_task_action,
                plane.execute_task_action,
                plane.inspect_task_action,
                TaskPayloadCipher(root / "task-payload.key"),
                start_worker=False,
                id_factory=lambda: "task-" + "c" * 32,
            )
            task = engine.preview(
                "backup.manage",
                {"operation": "create", "backup_id": "", "passphrase": secret},
                "owner",
            )
            self.assertNotIn(secret.encode("utf-8"), (root / "tasks.sqlite3").read_bytes())
            engine.confirm(str(task["id"]), "owner")
            self.assertTrue(engine.process_one())
            detail = engine.get(str(task["id"]))
            self.assertEqual(detail["state"], "succeeded")
            self.assertNotIn(secret.encode("utf-8"), (root / "tasks.sqlite3").read_bytes())
            engine.close()

    def test_client_psk_never_enters_task_database_or_public_result(self) -> None:
        secret = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plane = ControlPlane(self.runner, {1001})
            engine = ChangeTaskEngine(
                root / "tasks.sqlite3",
                plane.prepare_task_action,
                plane.execute_task_action,
                plane.inspect_task_action,
                TaskPayloadCipher(root / "task-payload.key"),
                start_worker=False,
                id_factory=lambda: "task-" + "d" * 32,
            )
            task = engine.preview(
                "network.node.import",
                {
                    "name": "client-held", "address": "10.20.0.23",
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "preshared_key": secret,
                },
                "owner",
            )
            database = (root / "tasks.sqlite3").read_bytes()
            self.assertNotIn(secret.encode("utf-8"), database)
            self.assertNotIn(secret, json.dumps(task, ensure_ascii=False))
            engine.confirm(str(task["id"]), "owner")
            self.assertTrue(engine.process_one())
            detail = engine.get(str(task["id"]))
            self.assertNotIn(secret, json.dumps(detail, ensure_ascii=False))
            self.assertNotIn(secret.encode("utf-8"), (root / "tasks.sqlite3").read_bytes())
            engine.close()

    def test_backup_restore_task_redacts_passphrase_and_requires_independent_session(self) -> None:
        secret = "配置恢复任务口令-绝不能进入明文数据库"
        backup_id = "backup-20260807T120000Z-1234abcd"
        origin_session = "d" * 64
        prepared = self.plane.prepare_task_action(
            "backup.restore.change",
            {
                "operation": "restore_apply", "backup_id": backup_id,
                "passphrase": secret, "session_id": origin_session,
            },
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "backup.restore_apply")
        self.assertNotIn(secret, str(prepared.params))
        self.assertEqual(prepared.sensitive_params, {"passphrase": secret})
        self.assertEqual(prepared.preview["facts"]["变更数量"], "1")
        applied = self.plane.execute_task_action(
            "backup.restore.change",
            {**prepared.params, **dict(prepared.sensitive_params)},
        )
        self.assertEqual(applied["state"], "pending")
        with self.assertRaisesRegex(TaskEngineError, "另一条独立"):
            self.plane.prepare_task_action(
                "backup.restore.change",
                {
                    "operation": "restore_confirm", "backup_id": "",
                    "passphrase": "", "session_id": origin_session,
                },
                "owner",
            )
        confirmation = self.plane.prepare_task_action(
            "backup.restore.change",
            {
                "operation": "restore_confirm", "backup_id": "",
                "passphrase": "", "session_id": "e" * 64,
            },
            "second-admin",
        )
        confirmed = self.plane.execute_task_action(
            "backup.restore.change", dict(confirmation.params)
        )
        self.assertEqual(confirmed["state"], "idle")

    def test_backup_restore_wrong_passphrase_returns_explicit_error(self) -> None:
        original = self.runner.manage_backup

        def fail_preview(operation, backup_id, passphrase, actor, session_id=""):
            if operation == "preview_restore":
                raise RuntimeError("底层解密失败")
            return original(operation, backup_id, passphrase, actor, session_id)

        self.runner.manage_backup = fail_preview
        with self.assertRaisesRegex(TaskEngineError, "恢复口令错误或备份不可用"):
            self.plane.prepare_task_action(
                "backup.restore.change",
                {
                    "operation": "restore_apply",
                    "backup_id": "backup-20260807T120000Z-1234abcd",
                    "passphrase": "wrong-passphrase-2026!",
                    "session_id": "a" * 64,
                },
                "owner",
            )

    def test_firewall_port_task_previews_scope_protocol_duration_and_occupancy(self) -> None:
        prepared = self.plane.prepare_task_action(
            "firewall.port.change",
            {
                "operation": "open", "port": 5201, "scope": "public",
                "protocol": "both", "duration_seconds": 0,
            },
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "firewall.port.open")
        self.assertEqual(prepared.preview["facts"]["访问范围"], "公网")
        self.assertEqual(prepared.preview["facts"]["协议"], "TCP + UDP")
        self.assertEqual(prepared.preview["facts"]["期限"], "永久")
        self.assertEqual(prepared.preview["facts"]["现有占用"], "未占用")
        inspected = self.plane.inspect_task_action(
            "firewall.port.change", dict(prepared.params)
        )
        self.assertEqual(inspected["fact_digest"], prepared.fact_digest)

    def test_firewall_port_task_protects_base_policy_and_rechecks_facts(self) -> None:
        self.runner.firewall_base_port = 5201
        with self.assertRaisesRegex(TaskEngineError, "基础策略"):
            self.plane.prepare_task_action(
                "firewall.port.change",
                {
                    "operation": "close", "port": 5201, "scope": "public",
                    "protocol": "tcp", "duration_seconds": 0,
                },
                "owner",
            )
        self.runner.firewall_base_port = 0
        self.runner.firewall_items = [{
            "scope": "public", "scope_label": "公网", "protocol": "tcp",
            "port": 5202, "duration": "temporary", "expires_at": "",
            "remaining_seconds": 120, "active": True,
        }]
        prepared = self.plane.prepare_task_action(
            "firewall.port.change",
            {
                "operation": "close", "port": 5202, "scope": "public",
                "protocol": "tcp", "duration_seconds": 0,
            },
            "owner",
        )
        self.runner.firewall_items[0]["expires_at"] = "2026-08-09T12:00:00+00:00"
        inspected = self.plane.inspect_task_action(
            "firewall.port.change", dict(prepared.params)
        )
        self.assertNotEqual(inspected["fact_digest"], prepared.fact_digest)

    def test_托管服务端口预览绑定当前事实版本(self) -> None:
        prepared = self.plane.prepare_task_action(
            "managed.port.change", {"target_id": "clash", "port": 52541}, "owner"
        )
        self.assertEqual(prepared.canonical_action, "managed.port.change")
        self.assertEqual(prepared.preview["facts"]["当前端口"], "8444/TCP")
        self.assertEqual(prepared.preview["facts"]["新端口"], "52541/TCP")
        self.assertEqual(prepared.params["_revision"], "c" * 64)
        inspected = self.plane.inspect_task_action(
            "managed.port.change", dict(prepared.params)
        )
        self.assertEqual(inspected["fact_digest"], prepared.fact_digest)

    def test_deployment_task_redacts_secrets_and_rechecks_stable_facts(self) -> None:
        self.runner.state = "未安装"
        secret_url = "https://airport.test/sub?token=private"
        secret_yaml = "type: socks5\nserver: exit.test\nport: 1080\npassword: secret"
        prepared = self.plane.prepare_task_action(
            "deployment.install",
            {
                "service_id": "clash", "port": "9443", "server_name": "",
                "airport_url": secret_url,
                "exit_proxy_yaml": secret_yaml, "upload_id": "", "download_name": "",
            },
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "deployment.proxy.install")
        self.assertEqual(prepared.preview["stages"], ["校验", "安装", "配置", "启动", "验证"])
        self.assertNotIn("private", str(prepared.params))
        self.assertNotIn("secret", str(prepared.preview))
        self.assertEqual(prepared.sensitive_params["airport_url"], secret_url)
        # 仅重新采样时间变化，不应让待执行任务失效。
        inspected = self.plane.inspect_task_action(
            "deployment.install", dict(prepared.params)
        )
        self.assertEqual(inspected["fact_digest"], prepared.fact_digest)
        result = self.plane.execute_task_action(
            "deployment.install",
            {**prepared.params, **dict(prepared.sensitive_params)},
        )
        self.assertEqual(result["service"]["state"], "运行中")
        self.assertEqual(self.runner.deployment_calls[0][1]["airport_url"], secret_url)

    def test_file_deployment_binds_upload_and_cleanup(self) -> None:
        prepared = self.plane.prepare_task_action(
            "deployment.install",
            {
                "service_id": "file", "port": "9443", "server_name": "",
                "airport_url": "",
                "exit_proxy_yaml": "", "upload_id": "a" * 32,
                "download_name": "shared_file.yaml",
            },
            "owner",
        )
        self.assertEqual(prepared.params["_upload_sha256"], "a" * 64)
        self.plane.cleanup_task_action("deployment.install", dict(prepared.params))
        self.assertEqual(self.runner.discarded_uploads, ["a" * 32])

    def test_deployment_rejects_tcp_conflict(self) -> None:
        with self.assertRaisesRegex(TaskEngineError, "端口已被占用"):
            self.plane.prepare_task_action(
                "deployment.install",
                {
                    "service_id": "file", "port": "8444", "server_name": "",
                    "airport_url": "",
                    "exit_proxy_yaml": "", "upload_id": "a" * 32,
                    "download_name": "shared_file.yaml",
                },
                "owner",
            )

    def test_real_task_engine_executes_service_change_end_to_end_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plane = ControlPlane(self.runner, {1001})
            engine = ChangeTaskEngine(
                Path(directory) / "tasks.sqlite3",
                plane.prepare_task_action,
                plane.execute_task_action,
                start_worker=False,
                id_factory=lambda: "task-" + "b" * 32,
            )
            plane.attach_task_engine(engine)
            preview = plane.handle(
                request(
                    action="task.preview",
                    params={
                        "action": "service.change",
                        "arguments": {"service_id": "clash", "operation": "stop"},
                        "actor": "owner",
                    },
                ),
                1001,
            )["result"]
            for _index in range(2):
                plane.handle(
                    request(
                        action="task.confirm",
                        params={"task_id": preview["id"], "actor": "owner"},
                    ),
                    1001,
                )
            self.assertTrue(engine.process_one())
            self.assertFalse(engine.process_one())
            detail = plane.handle(
                request(action="task.get", params={"task_id": preview["id"]}),
                1001,
            )["result"]

        self.assertEqual(detail["state"], "succeeded")
        self.assertEqual(self.runner.changes, [("clash", "stop", "owner")])

    def test_authorized_snapshot(self) -> None:
        response = self.plane.handle(request(), 1001)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["schema_version"], 1)
        self.assertEqual(self.runner.calls, 1)

    def test_host_read_exposes_page_intent_instead_of_collection_details(self) -> None:
        response = self.plane.handle(
            request(action="host.read", params={"intent": "service", "service_id": "clash"}),
            1001,
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["intent"], "service")
        self.assertEqual(response["result"]["view"]["service"]["id"], "clash")
        self.assertEqual(response["result"]["components"], ["snapshot", "inventory:clash", "managed_ports"])

        invalid = self.plane.handle(
            request(action="host.read", params={"intent": "network", "service_id": "ssh"}),
            1001,
        )
        self.assertFalse(invalid["ok"])
        self.assertEqual(invalid["error"]["code"], "invalid_params")

    def test_manageable_service_describes_state_dependent_operations(self) -> None:
        response = self.plane.handle(
            request(action="service.describe", params={"service_id": "clash"}),
            1001,
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["service"]["id"], "clash")
        self.assertEqual(response["result"]["allowed_operations"], ["stop", "restart"])
        self.assertEqual(response["result"]["restriction"], "")
        self.assertEqual(response["result"]["inventory"]["facts"], {"测试事实": "安全值"})

        self.runner.state = "已停止"
        response = self.plane.handle(
            request(action="service.describe", params={"service_id": "clash"}),
            1001,
        )
        self.assertEqual(response["result"]["allowed_operations"], ["start"])

    def test_protected_and_missing_services_are_read_only(self) -> None:
        protected = self.plane.handle(
            request(action="service.describe", params={"service_id": "vless"}),
            1001,
        )
        self.assertTrue(protected["ok"])
        self.assertEqual(protected["result"]["allowed_operations"], [])
        self.assertIn("回滚窗口", protected["result"]["restriction"])

        missing = self.plane.handle(
            request(action="service.describe", params={"service_id": "file"}),
            1001,
        )
        self.assertEqual(missing["result"]["allowed_operations"], [])
        self.assertIn("尚未安装", missing["result"]["restriction"])

    def test_confirmed_service_change_cannot_bypass_task_engine(self) -> None:
        response = self.plane.handle(
            request(
                action="service.change",
                params={
                    "service_id": "clash",
                    "operation": "stop",
                    "actor": "owner",
                    "confirmed": True,
                },
            ),
            1001,
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.changes, [])

    def test_service_change_always_requires_task_engine(self) -> None:
        base = {
            "service_id": "clash",
            "operation": "stop",
            "actor": "owner",
            "confirmed": False,
        }
        response = self.plane.handle(
            request(action="service.change", params=base),
            1001,
        )
        self.assertEqual(response["error"]["code"], "operation_forbidden")

        protected = dict(base, service_id="vless", confirmed=True)
        response = self.plane.handle(
            request(action="service.change", params=protected),
            1001,
        )
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.changes, [])

    def test_service_requests_reject_unknown_fields_ids_and_operations(self) -> None:
        response = self.plane.handle(
            request(
                action="service.describe",
                params={"service_id": "clash", "command": "id"},
            ),
            1001,
        )
        self.assertEqual(response["error"]["code"], "invalid_params")

        response = self.plane.handle(
            request(action="service.describe", params={"service_id": "unknown"}),
            1001,
        )
        self.assertEqual(response["error"]["code"], "not_found")

        response = self.plane.handle(
            request(
                action="service.change",
                params={
                    "service_id": "clash",
                    "operation": "shell",
                    "actor": "owner",
                    "confirmed": True,
                },
            ),
            1001,
        )
        self.assertEqual(response["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.changes, [])

    def test_confirmed_registered_secret_reveal_reaches_runner(self) -> None:
        response = self.plane.handle(
            request(
                action="service.reveal",
                params={
                    "service_id": "clash",
                    "resource": "subscription_qr",
                    "item_id": "phone",
                    "actor": "owner",
                    "confirmed": True,
                },
            ),
            1001,
        )
        self.assertTrue(response["ok"])
        self.assertEqual(
            self.runner.reveals,
            [("clash", "subscription_qr", "phone", "owner")],
        )
        self.assertEqual(response["result"]["item_id"], "phone")

    def test_secret_reveal_rejects_other_services_resources_and_missing_confirmation(self) -> None:
        base = {
            "service_id": "clash",
            "resource": "subscription_link",
            "item_id": "phone",
            "actor": "owner",
            "confirmed": False,
        }
        response = self.plane.handle(
            request(action="service.reveal", params=base),
            1001,
        )
        self.assertEqual(response["error"]["code"], "confirmation_required")

        response = self.plane.handle(
            request(
                action="service.reveal",
                params=dict(base, service_id="ssh", confirmed=True),
            ),
            1001,
        )
        self.assertEqual(response["error"]["code"], "operation_forbidden")

        response = self.plane.handle(
            request(
                action="service.reveal",
                params=dict(
                    base,
                    service_id="amneziawg",
                    resource="client_config",
                    confirmed=True,
                ),
            ),
            1001,
        )
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.reveals, [])

    def test_proxy_airport_link_is_a_registered_confirmed_secret(self) -> None:
        response = self.plane.handle(
            request(
                action="service.reveal",
                params={
                    "service_id": "clash",
                    "resource": "airport_link",
                    "item_id": "111111111111",
                    "actor": "owner",
                    "confirmed": True,
                },
            ),
            1001,
        )
        self.assertTrue(response["ok"])
        self.assertEqual(
            self.runner.reveals,
            [("clash", "airport_link", "111111111111", "owner")],
        )

    def test_unauthorized_caller_never_reaches_runner(self) -> None:
        response = self.plane.handle(request(), 2001)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "forbidden")
        self.assertEqual(self.runner.calls, 0)

    def test_network_changes_cannot_bypass_task_engine(self) -> None:
        params = {"kind": "awg", "operation": "add", "name": "desk", "address": "10.20.0.20", "actor": "owner", "confirmed": True}
        response = self.plane.handle(request(action="network.node.change", params=params), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.network_changes, [])
        rejected = self.plane.handle(request(action="network.node.change", params=dict(params, operation="shell")), 1001)
        self.assertEqual(rejected["error"]["code"], "operation_forbidden")
        unconfirmed = self.plane.handle(request(action="network.node.change", params=dict(params, confirmed=False)), 1001)
        self.assertEqual(unconfirmed["error"]["code"], "operation_forbidden")

    def test_task_only_guard_precedes_legacy_value_validation(self) -> None:
        response = self.plane.handle(
            request(
                action="network.node.change",
                params={
                    "kind": "awg",
                    "operation": "add",
                    "name": "非法 名称",
                    "address": "",
                    "actor": "owner",
                    "confirmed": False,
                },
            ),
            1001,
        )
        self.assertEqual(response["error"]["code"], "operation_forbidden")

    def test_subscription_sync_cannot_bypass_task_engine(self) -> None:
        params = {"actor": "owner", "confirmed": True}
        response = self.plane.handle(request(action="network.subscriptions.sync", params=params), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.subscription_syncs, [])

    def test_every_registered_change_protocol_rejects_direct_execution(self) -> None:
        cases = {
            "service.change": {
                "service_id": "clash", "operation": "stop", "actor": "owner",
                "confirmed": True,
            },
            "network.proxy.update": {
                "operation": "airport_add", "airport_id": "", "airport_name": "主用",
                "airport_url": "https://example.test/sub", "airport_enabled": True,
                "countries": ["all"], "exit_proxy_yaml": "",
                "exit_id": "", "exit_name": "", "exit_default": False,
                "awg_name": "", "exit_ids": [],
                "actor": "owner", "confirmed": True,
            },
            "file.resource.change": {
                "operation": "delete", "upload_id": "", "download_name": "",
                "cdn_cache": False, "cache_ttl": 300,
                "resource_id": "file-1234567890abcdef", "actor": "owner",
                "confirmed": True,
            },
            "ssh.key.change": {
                "operation": "delete", "item_id": "key-" + "b" * 64,
                "name": "", "actor": "owner", "confirmed": True,
            },
            "network.node.change": {
                "kind": "awg", "operation": "add", "name": "desk",
                "address": "10.20.0.20", "actor": "owner", "confirmed": True,
            },
            "network.node.domains": {
                "name": "desk", "domains": ["*.example.com"],
                "actor": "owner", "confirmed": True,
            },
            "network.address.domains": {
                "address": "192.168.0.103", "domains": ["git.example.com"],
                "actor": "owner", "confirmed": True,
            },
            "network.permission.change": {
                "operation": "allow", "client": "phone", "target": "desk",
                "ports": "22", "network": "tcp", "actor": "owner",
                "confirmed": True,
            },
            "network.subscriptions.sync": {"actor": "owner", "confirmed": True},
            "network.subscription.rotate": {
                "name": "phone", "actor": "owner", "confirmed": True,
            },
            "network.subscription.state": {
                "name": "phone", "state": "disabled", "actor": "owner",
                "confirmed": True,
            },
            "backup.manage": {
                "operation": "create", "backup_id": "",
                "passphrase": "1234567890abcdef", "actor": "owner",
                "confirmed": True,
            },
            "firewall.port.change": {
                "operation": "open", "port": 5201, "scope": "public",
                "protocol": "tcp", "duration_seconds": 60, "actor": "owner",
                "confirmed": True,
            },
            "managed.port.change": {
                "target_id": "clash", "port": 52541,
                "actor": "owner", "confirmed": True,
            },
            "deployment.install": {
                "service_id": "mosh", "port": "", "server_name": "",
                "airport_url": "",
                "exit_proxy_yaml": "", "upload_id": "", "download_name": "",
                "actor": "owner", "confirmed": True,
            },
            "security.transaction.change": {
                "transaction_type": "firewall", "operation": "apply",
                "session_id": "a" * 64, "public_ip": "", "public_port": "",
                "actor": "owner", "confirmed": True,
            },
            "backup.restore.change": {
                "operation": "restore_rollback", "backup_id": "",
                "passphrase": "", "session_id": "a" * 64,
                "actor": "owner", "confirmed": True,
            },
        }
        for action, params in cases.items():
            with self.subTest(action=action):
                response = self.plane.handle(
                    request(action=action, params=params), 1001
                )
                self.assertEqual(
                    response["error"]["code"], "operation_forbidden"
                )

    def test_unregistered_task_actions_and_caller_change_levels_are_rejected(self) -> None:
        with self.assertRaisesRegex(TaskEngineError, "动作未登记"):
            self.plane.execute_task_action(
                "shell.execute", {"actor": "owner", "confirmed": True}
            )
        params = {
            "service_id": "clash", "operation": "stop", "actor": "owner",
            "confirmed": True, "change_level": "routine",
        }
        response = self.plane.handle(
            request(action="service.change", params=params), 1001
        )
        self.assertEqual(response["error"]["code"], "invalid_params")
        with self.assertRaisesRegex(TaskEngineError, "变更等级不能由调用方指定"):
            self.plane.execute_task_action("service.change", params)

    def test_security_transaction_requires_registered_type_and_confirmation(self) -> None:
        base = {"transaction_type": "firewall", "operation": "apply", "actor": "owner", "confirmed": False}
        response = self.plane.handle(request(action="security.transaction", params=base), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        response = self.plane.handle(
            request(action="security.transaction", params=dict(base, transaction_type="shell", confirmed=True)), 1001
        )
        self.assertEqual(response["error"]["code"], "operation_forbidden")

    def test_security_transaction_task_requires_independent_confirmation_session(self) -> None:
        origin_session = "a" * 64
        apply_task = self.plane.prepare_task_action(
            "security.transaction.change",
            {
                "transaction_type": "ssh_auth", "operation": "apply",
                "session_id": origin_session, "public_ip": "", "public_port": "",
            },
            "owner",
        )
        self.assertEqual(apply_task.canonical_action, "security.ssh_auth.apply")
        self.assertIn("独立", apply_task.preview["facts"]["独立连接"])
        result = self.plane.execute_task_action(
            "security.transaction.change", dict(apply_task.params)
        )
        self.assertEqual(result["state"], "pending")
        with self.assertRaisesRegex(TaskEngineError, "另一条独立"):
            self.plane.prepare_task_action(
                "security.transaction.change",
                {
                    "transaction_type": "ssh_auth", "operation": "confirm",
                    "session_id": origin_session, "public_ip": "", "public_port": "",
                },
                "owner",
            )
        confirm_task = self.plane.prepare_task_action(
            "security.transaction.change",
            {
                "transaction_type": "ssh_auth", "operation": "confirm",
                "session_id": "b" * 64, "public_ip": "", "public_port": "",
            },
            "second-admin",
        )
        confirmed = self.plane.execute_task_action(
            "security.transaction.change", dict(confirm_task.params)
        )
        self.assertEqual(confirmed["state"], "idle")

    def test_ssh_listener_task_validates_high_port_and_preserves_awg_22(self) -> None:
        with self.assertRaisesRegex(TaskEngineError, "临时端口"):
            self.plane.prepare_task_action(
                "security.transaction.change",
                {
                    "transaction_type": "ssh_listener", "operation": "apply",
                    "session_id": "c" * 64, "public_ip": "203.0.113.10",
                    "public_port": "50800",
                },
                "owner",
            )
        prepared = self.plane.prepare_task_action(
            "security.transaction.change",
            {
                "transaction_type": "ssh_listener", "operation": "apply",
                "session_id": "c" * 64, "public_ip": "203.0.113.10",
                "public_port": "62222",
            },
            "owner",
        )
        self.assertEqual(prepared.preview["facts"]["AWG 监听"], "保持 22 端口")
        self.assertRegex(prepared.fact_digest, r"^[0-9a-f]{64}$")

        detected = self.plane.prepare_task_action(
            "security.transaction.change",
            {
                "transaction_type": "ssh_listener", "operation": "apply",
                "session_id": "c" * 64, "public_ip": "",
                "public_port": "62222",
            },
            "owner",
        )
        self.assertEqual(detected.params["public_ip"], "203.0.113.10")
        self.assertEqual(
            detected.preview["facts"]["公网监听"], "203.0.113.10:62222"
        )

    def test_vless_listener_uses_security_task_without_public_endpoint_parameters(self) -> None:
        prepared = self.plane.prepare_task_action(
            "security.transaction.change",
            {
                "transaction_type": "vless_listener",
                "operation": "apply",
                "session_id": "d" * 64,
            },
            "owner",
        )
        self.assertEqual(prepared.canonical_action, "security.vless_listener.apply")
        self.assertNotIn("public_ip", prepared.params)
        self.assertNotIn("public_port", prepared.params)
        self.assertTrue(prepared.supports_rollback)
        result = self.plane.execute_task_action(
            "security.transaction.change", dict(prepared.params)
        )
        self.assertEqual(result["transaction_id"], "f" * 64)
        inspection = self.plane.inspect_task_action(
            "security.transaction.change", dict(prepared.params)
        )
        self.assertEqual(inspection["transaction_id"], "f" * 64)
        self.assertEqual(inspection["last_outcome"], "")

    def test_firewall_port_changes_cannot_bypass_task_engine(self) -> None:
        overview = self.plane.handle(request(action="firewall.ports.overview"), 1001)
        self.assertTrue(overview["ok"])
        temporary = {
            "operation": "open", "port": 5201, "scope": "public",
            "protocol": "both", "duration_seconds": 3600,
            "actor": "owner", "confirmed": True,
        }
        response = self.plane.handle(request(action="firewall.port.change", params=temporary), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        permanent = dict(
            temporary, port=5202, scope="amneziawg", protocol="tcp",
            duration_seconds=0,
        )
        response = self.plane.handle(request(action="firewall.port.change", params=permanent), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.firewall_port_changes, [])

    def test_firewall_port_direct_path_is_always_rejected(self) -> None:
        valid = {
            "operation": "open", "port": 5201, "scope": "public",
            "protocol": "tcp", "duration_seconds": 3600,
            "actor": "owner", "confirmed": True,
        }
        for overrides in (
            {"port": 70000}, {"scope": "all"}, {"protocol": "icmp"},
            {"duration_seconds": 30}, {"confirmed": False},
        ):
            response = self.plane.handle(
                request(action="firewall.port.change", params={**valid, **overrides}), 1001
            )
            self.assertFalse(response["ok"])
        self.assertEqual(self.runner.firewall_port_changes, [])

    def test_ssh_key_list_and_preview_remain_read_only(self) -> None:
        self.assertTrue(self.plane.handle(request(action="ssh.keys.overview"), 1001)["ok"])
        public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest 家庭台式机"
        preview = self.plane.handle(request(
            action="ssh.key.preview", params={"public_key": public_key, "actor": "owner"}
        ), 1001)
        self.assertTrue(preview["ok"])
        key_id = "key-" + "b" * 64
        response = self.plane.handle(request(action="ssh.key.change", params={
            "operation": "delete", "item_id": key_id, "name": "",
            "actor": "owner", "confirmed": True,
        }), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.ssh_key_changes, [])

    def test_ssh_key_preview_validates_input_and_changes_require_tasks(self) -> None:
        preview = self.plane.handle(request(action="ssh.key.preview", params={
            "public_key": "ssh-ed25519 AAAA\nssh-rsa BBBB", "actor": "owner",
        }), 1001)
        self.assertEqual(preview["error"]["code"], "invalid_params")
        base = {
            "operation": "rename", "item_id": "key-" + "b" * 64,
            "name": "", "actor": "owner", "confirmed": True,
        }
        invalid_name = self.plane.handle(request(action="ssh.key.change", params=base), 1001)
        self.assertEqual(invalid_name["error"]["code"], "operation_forbidden")
        unconfirmed = self.plane.handle(request(
            action="ssh.key.change", params={**base, "name": "有效名字", "confirmed": False}
        ), 1001)
        self.assertEqual(unconfirmed["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.ssh_key_changes, [])

    def test_backup_changes_require_tasks_and_status_remains_read_only(self) -> None:
        params = {
            "operation": "create", "backup_id": "", "passphrase": "安全恢复口令-至少十六个字符-请妥善保管",
            "actor": "owner", "confirmed": True,
        }
        response = self.plane.handle(request(action="backup.manage", params=params), 1001)
        self.assertEqual(response["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.backups, [])
        invalid = self.plane.handle(
            request(action="backup.manage", params=dict(params, operation="verify", backup_id="../../shadow")), 1001
        )
        self.assertEqual(invalid["error"]["code"], "operation_forbidden")
        unconfirmed = self.plane.handle(
            request(action="backup.manage", params=dict(params, confirmed=False)), 1001
        )
        self.assertEqual(unconfirmed["error"]["code"], "operation_forbidden")

        status_params = {
            "operation": "restore_status", "backup_id": "", "passphrase": "",
            "actor": "owner", "confirmed": False,
        }
        status = self.plane.handle(
            request(action="backup.manage", params=status_params), 1001
        )
        self.assertTrue(status["ok"])
        self.assertEqual(self.runner.backups[-1], ("restore_status", "", "", "owner"))
        apply_params = dict(
            params,
            operation="restore_apply",
            backup_id="backup-20260807T120000Z-1234abcd",
            confirmed=False,
        )
        apply = self.plane.handle(
            request(action="backup.manage", params=apply_params), 1001
        )
        self.assertEqual(apply["error"]["code"], "operation_forbidden")

        delete_params = {
            "operation": "delete",
            "backup_id": "backup-20260807T120000Z-1234abcd",
            "passphrase": "",
            "actor": "owner",
            "confirmed": True,
        }
        deleted = self.plane.handle(
            request(action="backup.manage", params=delete_params), 1001
        )
        self.assertEqual(deleted["error"]["code"], "operation_forbidden")
        missing_confirmation = self.plane.handle(
            request(
                action="backup.manage",
                params=dict(delete_params, confirmed=False),
            ),
            1001,
        )
        self.assertEqual(
            missing_confirmation["error"]["code"], "operation_forbidden"
        )

    def test_unknown_action_is_rejected(self) -> None:
        response = self.plane.handle(request(action="shell.run"), 1001)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "unknown_action")
        self.assertEqual(self.runner.calls, 0)

    def test_file_resource_changes_cannot_bypass_task_engine(self) -> None:
        overview = self.plane.handle(request(action="file.resources.overview"), 1001)
        self.assertTrue(overview["ok"])
        common = {
            "operation": "add", "upload_id": "a" * 32,
            "download_name": "large.bin", "cdn_cache": True,
            "cache_ttl": 86400, "resource_id": "", "actor": "owner",
            "confirmed": True,
        }
        added = self.plane.handle(request(action="file.resource.change", params=common), 1001)
        self.assertEqual(added["error"]["code"], "operation_forbidden")
        deleted = self.plane.handle(request(action="file.resource.change", params={
            **common, "operation": "delete", "upload_id": "", "download_name": "",
            "resource_id": "file-1234567890abcdef", "cdn_cache": False,
        }), 1001)
        self.assertEqual(deleted["error"]["code"], "operation_forbidden")
        invalid = self.plane.handle(request(action="file.resource.change", params={
            **common, "cache_ttl": 10,
        }), 1001)
        self.assertEqual(invalid["error"]["code"], "operation_forbidden")
        self.assertEqual(self.runner.file_changes, [])

    def test_snapshot_rejects_params_and_unknown_fields(self) -> None:
        response = self.plane.handle(request(params={"command": "id"}), 1001)
        self.assertEqual(response["error"]["code"], "invalid_params")
        extra = request()
        extra["environment"] = {"PATH": "/tmp"}
        response = self.plane.handle(extra, 1001)
        self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertEqual(self.runner.calls, 0)

    def test_internal_errors_are_redacted(self) -> None:
        class BrokenRunner:
            def snapshot(self) -> dict[str, object]:
                raise RuntimeError("/etc/server-kit/secret")

        response = ControlPlane(BrokenRunner(), {0}).handle(request(), 0)
        self.assertEqual(response["error"]["code"], "internal_error")
        self.assertNotIn("secret", response["error"]["message"])


if __name__ == "__main__":
    unittest.main()
