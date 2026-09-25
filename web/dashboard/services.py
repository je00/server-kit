"""通过唯一管理 seam 读取和变更托管服务。"""

from __future__ import annotations

from typing import Any

from django.conf import settings

from control_plane.client import AgentClient


def read_host(intent: str, service_id: str = "") -> dict[str, Any]:
    """按页面意图读取完整视图，页面无需了解底层事实组合。"""
    result = AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "host.read", {"intent": intent, "service_id": service_id}
    )
    view = result.get("view")
    if not isinstance(view, dict):
        raise RuntimeError("管理代理返回了无效主机视图")
    return view


def describe_service(service_id: str) -> dict[str, Any]:
    return read_host("service", service_id)


def preview_change_task(
    service_id: str, operation: str, actor: str
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "service.change",
            "arguments": {"service_id": service_id, "operation": operation},
            "actor": actor,
        },
    )


def confirm_change_task(task_id: str, actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.confirm", {"task_id": task_id, "actor": actor}
    )


def cancel_change_task(task_id: str, actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.cancel", {"task_id": task_id, "actor": actor}
    )


def change_task(task_id: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.get", {"task_id": task_id}
    )


def change_tasks() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request("task.list", {})


def reveal_clash_resource(resource: str, item_id: str, actor: str) -> dict[str, Any]:
    client = AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=30.0)
    return client.request(
        "service.reveal",
        {
            "service_id": "clash",
            "resource": resource,
            "item_id": item_id,
            "actor": actor,
            "confirmed": True,
        },
    )


def file_resources() -> dict[str, Any]:
    return read_host("file")


def preview_file_change_task(
    operation: str, upload_id: str, download_name: str, cdn_cache: bool,
    cache_ttl: int, resource_id: str, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=910.0).request(
        "task.preview",
        {
            "action": "file.resource.change",
            "arguments": {
                "operation": operation,
                "upload_id": upload_id,
                "download_name": download_name,
                "cdn_cache": cdn_cache,
                "cache_ttl": cache_ttl,
                "resource_id": resource_id,
            },
            "actor": actor,
        },
    )


def reveal_file_resource(resource: str, item_id: str, actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=30.0).request(
        "service.reveal",
        {
            "service_id": "file", "resource": resource, "item_id": item_id,
            "actor": actor, "confirmed": True,
        },
    )


def network_overview() -> dict[str, Any]:
    return read_host("network")


def public_endpoint_status() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request("network.public_endpoint.status", {})


def public_endpoint_transaction_status(actor: str, session_id: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "network.public_endpoint.transaction.status",
        {"actor": actor, "session_id": session_id},
    )


def duckdns_status() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request("network.duckdns.status", {})


def preview_duckdns_task(
    operation: str, provider: str, fqdn: str, token: str, secret_id: str,
    secret_key: str, zone: str, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=35.0).request(
        "task.preview",
        {
            "action": "network.duckdns.change",
            "arguments": {
                "operation": operation, "provider": provider, "fqdn": fqdn, "token": token,
                "secret_id": secret_id, "secret_key": secret_key, "zone": zone,
            },
            "actor": actor,
        },
    )


def preview_public_endpoint_task(
    operation: str, fqdn: str, session_id: str, actor: str
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview", {
            "action": "network.public_endpoint.change",
            "arguments": {
                "operation": operation, "fqdn": fqdn, "session_id": session_id,
            },
            "actor": actor,
        }
    )


def enrollment_context() -> dict[str, Any]:
    """返回网页内置密钥生成器创建客户端配置所需的公开参数。"""
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request("network.enrollment.context", {})


def enrollment_overview() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request("network.enrollment.overview", {})


def preview_network_node_task(
    kind: str, operation: str, name: str, address: str, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.node.change",
            "arguments": {
                "kind": kind,
                "operation": operation,
                "name": name,
                "address": address,
            },
            "actor": actor,
        },
    )


def preview_node_domains_task(
    name: str, domains: list[str], actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.node.domains",
            "arguments": {"name": name, "domains": domains},
            "actor": actor,
        },
    )


def preview_address_domains_task(
    address: str, domains: list[str], actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.address.domains",
            "arguments": {"address": address, "domains": domains},
            "actor": actor,
        },
    )


def preview_network_node_import_task(
    name: str, address: str, public_key: str, preshared_key: str, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.node.import",
            "arguments": {
                "name": name, "address": address, "public_key": public_key,
                "preshared_key": preshared_key,
            },
            "actor": actor,
        },
    )


def preview_network_permission_task(
    operation: str, client_name: str, target: str, ports: str,
    network: str, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.permission.change",
            "arguments": {
                "operation": operation,
                "client": client_name,
                "target": target,
                "ports": ports,
                "network": network,
            },
            "actor": actor,
        },
    )


def preview_network_permission_batch_task(
    client_name: str, rules: list[dict[str, str]], actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {"action": "network.permission.batch", "arguments": {"client": client_name, "rules": rules}, "actor": actor},
    )


def preview_subscription_sync_task(actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {"action": "network.subscriptions.sync", "arguments": {}, "actor": actor},
    )


def preview_subscription_rotate_task(name: str, actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.subscription.rotate",
            "arguments": {"name": name},
            "actor": actor,
        },
    )


def preview_subscription_state_task(
    name: str, state: str, actor: str
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.subscription.state",
            "arguments": {"name": name, "state": state},
            "actor": actor,
        },
    )


def audit_log() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request("audit.list", {})


def record_audit_event(operation: str, actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "audit.event", {"service_id": "accounts", "operation": operation, "actor": actor}
    )


def proxy_resources() -> dict[str, Any]:
    return read_host("proxy")


def reveal_proxy_resource(resource: str, item_id: str, actor: str) -> dict[str, Any]:
    """通过统一敏感资源 seam 领取机场链接或出口配置。"""

    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=30.0).request(
        "service.reveal",
        {
            "service_id": "clash",
            "resource": resource,
            "item_id": item_id,
            "actor": actor,
            "confirmed": True,
        },
    )


def test_proxy_resources(actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=35.0).request(
        "network.proxy.test", {"actor": actor}
    )


def preview_proxy_change_task(
    values: dict[str, object], actor: str
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "network.proxy.update",
            "arguments": values,
            "actor": actor,
        },
    )


def preview_node_exits_task(name: str, exit_ids: list[str], actor: str) -> dict[str, Any]:
    """Preview a node exit selection through the transactional proxy updater."""
    return preview_proxy_change_task({
        "operation": "node_exits_set",
        "airport_id": "", "airport_name": "", "airport_url": "",
        "airport_enabled": False, "countries": [],
        "exit_id": "", "exit_name": "", "exit_default": False,
        "exit_proxy_yaml": "", "awg_name": name, "exit_ids": exit_ids,
    }, actor)


def preview_deployment_task(
    service_id: str, values: dict[str, str], actor: str
) -> dict[str, Any]:
    arguments = {
        "service_id": service_id,
        "port": values.get("port", ""),
        "server_name": values.get("server_name", ""),
        "public_key": values.get("public_key", ""),
        "allow_push": values.get("allow_push", ""),
        "airport_url": values.get("airport_url", ""),
        "exit_proxy_yaml": values.get("exit_proxy_yaml", ""),
        "upload_id": values.get("upload_id", ""),
        "download_name": values.get("download_name", ""),
    }
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {"action": "deployment.install", "arguments": arguments, "actor": actor},
    )


def manage_security_transaction(
    transaction_type: str, operation: str, actor: str
) -> dict[str, Any]:
    client = AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=190.0)
    return client.request(
        "security.transaction",
        {
            "transaction_type": transaction_type,
            "operation": operation,
            "actor": actor,
            "confirmed": operation in {"apply", "confirm", "rollback"},
        },
    )


def preview_security_transaction_task(
    transaction_type: str, operation: str, session_id: str,
    public_ip: str, public_port: str, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "task.preview",
        {
            "action": "security.transaction.change",
            "arguments": {
                "transaction_type": transaction_type,
                "operation": operation,
                "session_id": session_id,
                "public_ip": public_ip,
                "public_port": public_port,
            },
            "actor": actor,
        },
    )


def firewall_ports() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "firewall.ports.overview", {}
    )


def managed_ports() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "managed.ports.overview", {}
    )


def preview_managed_port_task(target_id: str, port: int, actor: str) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=35.0).request(
        "task.preview",
        {
            "action": "managed.port.change",
            "arguments": {"target_id": target_id, "port": port},
            "actor": actor,
        },
    )


def preview_firewall_port_task(
    operation: str, port: int, scope: str, protocol: str,
    duration_seconds: int, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=35.0).request(
        "task.preview",
        {
            "action": "firewall.port.change",
            "arguments": {
                "operation": operation, "port": port, "scope": scope,
                "protocol": protocol, "duration_seconds": duration_seconds,
            },
            "actor": actor,
        },
    )


def ssh_keys() -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET).request(
        "ssh.keys.overview", {}
    )


def preview_ssh_key_change_task(
    operation: str, item_id: str, name: str, public_key: str, actor: str
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=35.0).request(
        "task.preview",
        {
            "action": "ssh.key.change",
            "arguments": {
                "operation": operation,
                "item_id": item_id,
                "name": name,
                "public_key": public_key,
            },
            "actor": actor,
        },
    )


def manage_backup(
    operation: str, actor: str, backup_id: str = "", passphrase: str = ""
) -> dict[str, Any]:
    client = AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=190.0)
    return client.request(
        "backup.manage",
        {
            "operation": operation,
            "backup_id": backup_id,
            "passphrase": passphrase,
            "actor": actor,
            "confirmed": operation not in {"list", "restore_status"},
        },
    )


def preview_backup_task(
    operation: str, backup_id: str, passphrase: str, actor: str
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=190.0).request(
        "task.preview",
        {
            "action": "backup.manage",
            "arguments": {
                "operation": operation,
                "backup_id": backup_id,
                "passphrase": passphrase,
            },
            "actor": actor,
        },
    )


def preview_backup_restore_task(
    operation: str, backup_id: str, passphrase: str,
    session_id: str, actor: str,
) -> dict[str, Any]:
    return AgentClient(settings.SERVER_KIT_AGENT_SOCKET, timeout=190.0).request(
        "task.preview",
        {
            "action": "backup.restore.change",
            "arguments": {
                "operation": operation, "backup_id": backup_id,
                "passphrase": passphrase, "session_id": session_id,
            },
            "actor": actor,
        },
    )
