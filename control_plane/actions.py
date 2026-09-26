"""受管主机动作的权威目录。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class ActionKind(str, Enum):
    """动作对受管主机的影响类型。"""

    READ = "read"
    EVENT = "event"
    CHANGE = "change"


class ChangeLevel(str, Enum):
    """由 root 管理端决定的变更等级。"""

    ROUTINE = "routine"
    CONFIRMATION = "confirmation"
    ROLLBACK = "rollback"


class ActionCatalogError(ValueError):
    """表示动作未登记或目录请求无效。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ActionDefinition:
    """任务引擎理解一个动作所需的稳定元数据。"""

    name: str
    protocol_action: str
    kind: ActionKind
    parameter_fields: frozenset[str]
    change_level: ChangeLevel | None = None
    preview: str = ""
    fact_scope: str = ""
    validator: str = ""
    executor: str = ""
    verifier: str = ""
    sensitive_fields: frozenset[str] = frozenset()
    supports_rollback: bool = False
    task_only: bool = False
    sync_confirmation_required: bool = False
    sync_confirmation_message: str = ""
    timeout_seconds: int = 15


@dataclass(frozen=True)
class _ActionRoute:
    protocol_action: str
    parameter_fields: frozenset[str]
    invalid_params_message: str
    invalid_variant_code: str = "operation_forbidden"
    invalid_variant_message: str = "动作未登记。"
    definition: ActionDefinition | None = None
    selectors: tuple[str, ...] = ()
    variants: Mapping[tuple[str, ...], ActionDefinition] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def resolve(self, params: Mapping[str, object]) -> ActionDefinition:
        if self.definition is not None:
            return self.definition
        key = tuple(str(params.get(selector, "")) for selector in self.selectors)
        definition = self.variants.get(key)
        if definition is None:
            raise ActionCatalogError(
                self.invalid_variant_code,
                self.invalid_variant_message,
            )
        return definition


def _definition(
    name: str,
    protocol_action: str,
    fields: frozenset[str],
    *,
    kind: ActionKind = ActionKind.READ,
    level: ChangeLevel | None = None,
    preview: str = "",
    fact_scope: str = "",
    validator: str = "",
    executor: str,
    verifier: str = "",
    sensitive: frozenset[str] = frozenset(),
    supports_rollback: bool = False,
    task_only: bool = False,
    sync_confirmation_required: bool = False,
    sync_confirmation_message: str = "",
    timeout: int = 15,
) -> ActionDefinition:
    return ActionDefinition(
        name=name,
        protocol_action=protocol_action,
        kind=kind,
        parameter_fields=fields,
        change_level=level,
        preview=preview,
        fact_scope=fact_scope,
        validator=validator or f"validate:{protocol_action}",
        executor=executor,
        verifier=verifier,
        sensitive_fields=sensitive,
        supports_rollback=supports_rollback,
        task_only=task_only,
        sync_confirmation_required=sync_confirmation_required,
        sync_confirmation_message=sync_confirmation_message,
        timeout_seconds=timeout,
    )


def _change(
    name: str,
    protocol_action: str,
    fields: frozenset[str],
    level: ChangeLevel,
    *,
    preview: str,
    fact_scope: str,
    executor: str,
    verifier: str,
    sensitive: frozenset[str] = frozenset(),
    supports_rollback: bool = False,
    timeout: int = 180,
) -> ActionDefinition:
    return _definition(
        name,
        protocol_action,
        fields,
        kind=ActionKind.CHANGE,
        level=level,
        preview=preview,
        fact_scope=fact_scope,
        executor=executor,
        verifier=verifier,
        sensitive=sensitive,
        supports_rollback=supports_rollback,
        task_only=True,
        timeout=timeout,
    )


def _variants(
    protocol_action: str,
    fields: frozenset[str],
    selectors: tuple[str, ...],
    definitions: list[tuple[tuple[str, ...], ActionDefinition]],
    invalid_params_message: str,
    *,
    invalid_variant_code: str = "operation_forbidden",
    invalid_variant_message: str = "动作未登记。",
) -> _ActionRoute:
    return _ActionRoute(
        protocol_action=protocol_action,
        parameter_fields=fields,
        invalid_params_message=invalid_params_message,
        invalid_variant_code=invalid_variant_code,
        invalid_variant_message=invalid_variant_message,
        selectors=selectors,
        variants=MappingProxyType(dict(definitions)),
    )


EMPTY = frozenset()
ACTOR = frozenset({"actor"})
PUBLIC_ENDPOINT_STATUS_FIELDS = frozenset()
PUBLIC_ENDPOINT_TRANSACTION_STATUS_FIELDS = frozenset({"actor", "session_id"})
PUBLIC_ENDPOINT_CHANGE_FIELDS = frozenset(
    {"operation", "fqdn", "session_id", "transaction_id", "actor", "confirmed"}
)
DYNAMIC_DNS_CHANGE_FIELDS = frozenset({
    "operation", "provider", "fqdn", "token", "secret_id", "secret_key", "zone",
    "actor", "confirmed",
})
SERVICE_DESCRIBE_FIELDS = frozenset({"service_id"})
HOST_READ_FIELDS = frozenset({"intent", "service_id"})
SERVICE_CHANGE_FIELDS = frozenset({"service_id", "operation", "actor", "confirmed"})
SERVICE_REVEAL_FIELDS = frozenset({"service_id", "resource", "item_id", "actor", "confirmed"})
FILE_CHANGE_FIELDS = frozenset({
    "operation", "upload_id", "download_name", "cdn_cache", "cache_ttl",
    "resource_id", "actor", "confirmed",
})
AUDIT_EVENT_FIELDS = frozenset({"service_id", "operation", "actor"})
PROXY_UPDATE_FIELDS = frozenset({
    "operation", "airport_id", "airport_name", "airport_url",
    "airport_enabled", "countries", "exit_id", "exit_name", "exit_default",
    "exit_proxy_yaml", "awg_name", "exit_ids", "actor", "confirmed",
})
DEPLOYMENT_FIELDS = frozenset({
    "service_id", "port", "server_name",
    "airport_url", "exit_proxy_yaml", "upload_id", "download_name",
    "actor", "confirmed",
})
NODE_CHANGE_FIELDS = frozenset({"kind", "operation", "name", "address", "actor", "confirmed"})
NODE_IMPORT_FIELDS = frozenset({
    "name", "address", "public_key", "preshared_key", "actor", "confirmed",
})
NODE_DOMAIN_FIELDS = frozenset({"name", "domains", "actor", "confirmed"})
ADDRESS_DOMAIN_FIELDS = frozenset({"address", "domains", "actor", "confirmed"})
CONFIRMED_ACTOR_FIELDS = frozenset({"actor", "confirmed"})
PERMISSION_FIELDS = frozenset({
    "operation", "client", "target", "ports", "network", "actor", "confirmed",
})
PERMISSION_BATCH_FIELDS = frozenset({"client", "rules", "actor", "confirmed"})
SUBSCRIPTION_ITEM_FIELDS = frozenset({"name", "actor", "confirmed"})
SUBSCRIPTION_STATE_FIELDS = frozenset({"name", "state", "actor", "confirmed"})
FIREWALL_PORT_FIELDS = frozenset({
    "operation", "port", "scope", "protocol", "duration_seconds", "actor", "confirmed",
})
MANAGED_PORT_FIELDS = frozenset({"target_id", "port", "actor", "confirmed"})
SSH_PREVIEW_FIELDS = frozenset({"public_key", "actor"})
SSH_CHANGE_FIELDS = frozenset({"operation", "item_id", "name", "actor", "confirmed"})
SECURITY_FIELDS = frozenset({"transaction_type", "operation", "actor", "confirmed"})
SECURITY_CHANGE_FIELDS = frozenset({
    "transaction_type", "operation", "session_id", "public_ip", "public_port",
    "actor", "confirmed",
})
VLESS_LISTENER_CHANGE_FIELDS = frozenset({
    "transaction_type", "operation", "session_id", "actor", "confirmed",
})
BACKUP_FIELDS = frozenset({"operation", "backup_id", "passphrase", "actor", "confirmed"})
BACKUP_RESTORE_FIELDS = frozenset({
    "operation", "backup_id", "passphrase", "session_id", "actor", "confirmed",
})
TASK_PREVIEW_FIELDS = frozenset({"action", "arguments", "actor"})
TASK_CONFIRM_FIELDS = frozenset({"task_id", "actor"})
TASK_CANCEL_FIELDS = frozenset({"task_id", "actor"})
TASK_GET_FIELDS = frozenset({"task_id"})


_routes: dict[str, _ActionRoute] = {}


def _register(route: _ActionRoute) -> None:
    if route.protocol_action in _routes:
        raise RuntimeError(f"动作重复登记：{route.protocol_action}")
    _routes[route.protocol_action] = route


def _single(definition: ActionDefinition, message: str) -> None:
    _register(_ActionRoute(
        protocol_action=definition.protocol_action,
        parameter_fields=definition.parameter_fields,
        invalid_params_message=message,
        definition=definition,
    ))


_single(_definition(
    "system.snapshot", "system.snapshot", EMPTY, executor="snapshot",
), "system.snapshot 不接受参数。")
_single(_definition(
    "host.read", "host.read", HOST_READ_FIELDS, executor="managed_host_read_model",
), "host.read 参数不正确。")
_single(_definition(
    "task.preview", "task.preview", TASK_PREVIEW_FIELDS, kind=ActionKind.EVENT,
    executor="change_task.preview",
), "task.preview 参数不正确。")
_single(_definition(
    "task.confirm", "task.confirm", TASK_CONFIRM_FIELDS, kind=ActionKind.EVENT,
    executor="change_task.confirm",
), "task.confirm 参数不正确。")
_single(_definition(
    "task.cancel", "task.cancel", TASK_CANCEL_FIELDS, kind=ActionKind.EVENT,
    executor="change_task.cancel",
), "task.cancel 参数不正确。")
_single(_definition(
    "task.get", "task.get", TASK_GET_FIELDS, executor="change_task.get",
), "task.get 参数不正确。")
_single(_definition(
    "task.list", "task.list", EMPTY, executor="change_task.list",
), "task.list 不接受参数。")
_single(_definition(
    "task.active", "task.active", EMPTY, executor="change_task.active",
), "task.active 不接受参数。")
_single(_definition(
    "service.describe", "service.describe", SERVICE_DESCRIBE_FIELDS,
    executor="snapshot+service_inventory", verifier="describe_service",
), "service.describe 参数不正确。")

service_changes = [
    ((operation,), _change(
        f"service.{operation}", "service.change", SERVICE_CHANGE_FIELDS,
        ChangeLevel.CONFIRMATION, preview="managed_service", fact_scope="managed_service",
        executor="change_service", verifier="snapshot+service_inventory",
    ))
    for operation in ("start", "stop", "restart")
]
_register(_variants(
    "service.change", SERVICE_CHANGE_FIELDS, ("operation",), service_changes,
    "service.change 参数不正确。",
    invalid_variant_code="invalid_params",
    invalid_variant_message="服务操作不受支持。",
))
_single(_definition(
    "managed.ports.overview", "managed.ports.overview", EMPTY,
    executor="managed_ports",
), "managed.ports.overview 不接受参数。")
_single(_change(
    "managed.port.change", "managed.port.change", MANAGED_PORT_FIELDS,
    ChangeLevel.CONFIRMATION, preview="managed_port", fact_scope="managed_ports",
    executor="change_managed_port", verifier="managed_ports", timeout=240,
), "managed.port.change 参数不正确。")
_single(_definition(
    "service.reveal", "service.reveal", SERVICE_REVEAL_FIELDS,
    executor="reveal_resource", sensitive=frozenset({"resource"}),
    sync_confirmation_required=True,
    sync_confirmation_message="敏感资源展示需要明确确认。", timeout=30,
), "service.reveal 参数不正确。")
_single(_definition(
    "file.resources.overview", "file.resources.overview", EMPTY,
    executor="file_resources",
), "file.resources.overview 不接受参数。")

file_changes = [
    (("add",), _change(
        "file.add", "file.resource.change", FILE_CHANGE_FIELDS, ChangeLevel.ROUTINE,
        preview="file_resource", fact_scope="file_resources", executor="change_file_resource",
        verifier="file_resources", timeout=900,
    )),
    (("delete",), _change(
        "file.delete", "file.resource.change", FILE_CHANGE_FIELDS, ChangeLevel.CONFIRMATION,
        preview="file_resource", fact_scope="file_resources", executor="change_file_resource",
        verifier="file_resources", timeout=900,
    )),
]
_register(_variants(
    "file.resource.change", FILE_CHANGE_FIELDS, ("operation",), file_changes,
    "file.resource.change 参数不正确。",
    invalid_variant_message="文件资源动作未登记。",
))
_single(_definition(
    "network.overview", "network.overview", EMPTY, executor="network_overview",
), "network.overview 不接受参数。")
_single(_definition(
    "network.telemetry", "network.telemetry", EMPTY, executor="network_telemetry",
), "network.telemetry 不接受参数。")
_single(_definition(
    "audit.list", "audit.list", EMPTY, executor="audit_log",
), "audit.list 不接受参数。")
_single(_definition(
    "audit.event", "audit.event", AUDIT_EVENT_FIELDS, kind=ActionKind.EVENT,
    executor="record_event",
), "audit.event 参数不正确。")
_single(_definition(
    "network.enrollment.context", "network.enrollment.context", EMPTY,
    executor="enrollment_context",
), "network.enrollment.context 不接受参数。")
_single(_definition(
    "network.proxy.overview", "network.proxy.overview", EMPTY,
    executor="proxy_resources",
), "network.proxy.overview 不接受参数。")
_single(_definition(
    "network.proxy.test", "network.proxy.test", ACTOR,
    executor="test_proxy_resources", timeout=30,
), "network.proxy.test 参数不正确。")
_single(_change(
    "network.proxy.update", "network.proxy.update", PROXY_UPDATE_FIELDS,
    ChangeLevel.CONFIRMATION, preview="proxy_resources", fact_scope="proxy_resources",
    executor="update_proxy_resources", verifier="proxy_resources",
    sensitive=frozenset({"airport_url", "exit_proxy_yaml"}), timeout=240,
), "network.proxy.update 参数不正确。")

deployment_changes = []
for service_id, name, sensitive in (
    ("vless", "deployment.vless.install", EMPTY),
    ("clash", "deployment.proxy.install", frozenset({"airport_url", "exit_proxy_yaml"})),
    ("mosh", "deployment.mosh.install", EMPTY),
    ("file", "deployment.file.install", EMPTY),
):
    deployment_changes.append(((service_id,), _change(
        name, "deployment.install", DEPLOYMENT_FIELDS, ChangeLevel.CONFIRMATION,
        preview="deployment", fact_scope=f"managed_service:{service_id}",
        executor="deploy_service", verifier="snapshot+service_inventory",
        sensitive=sensitive, timeout=900,
    )))
_register(_variants(
    "deployment.install", DEPLOYMENT_FIELDS, ("service_id",), deployment_changes,
    "deployment.install 参数不正确。",
    invalid_variant_message="部署服务未登记。",
))

node_changes = []
for kind in ("awg", "vless"):
    operations = (
        "add", "enable", "disable", "remove", "set-management",
        "clean-enable", "clean-disable",
    ) if kind == "awg" else (
        "add", "enable", "disable", "remove", "compat-enable", "compat-disable",
        "clean-enable", "clean-disable",
    )
    for operation in operations:
        node_changes.append(((kind, operation), _change(
            f"network.node.{kind}.{operation}", "network.node.change", NODE_CHANGE_FIELDS,
            ChangeLevel.CONFIRMATION, preview="network_node", fact_scope="network",
            executor="change_network_node", verifier="network_overview",
        )))
_register(_variants(
    "network.node.change", NODE_CHANGE_FIELDS, ("kind", "operation"), node_changes,
    "network.node.change 参数不正确。",
    invalid_variant_message="节点动作未登记。",
))
_single(_change(
    "network.node.awg.import", "network.node.import", NODE_IMPORT_FIELDS,
    ChangeLevel.CONFIRMATION, preview="network_node_import", fact_scope="network",
    executor="import_network_node", verifier="network_overview",
    sensitive=frozenset({"preshared_key"}),
), "network.node.import 参数不正确。")
_single(_change(
    "network.node.domains", "network.node.domains", NODE_DOMAIN_FIELDS,
    ChangeLevel.CONFIRMATION, preview="node_domains", fact_scope="network",
    executor="change_node_domains", verifier="network_overview", timeout=240,
), "network.node.domains 参数不正确。")
_single(_change(
    "network.address.domains", "network.address.domains", ADDRESS_DOMAIN_FIELDS,
    ChangeLevel.CONFIRMATION, preview="address_domains", fact_scope="network",
    executor="change_address_domains", verifier="network_overview", timeout=240,
), "network.address.domains 参数不正确。")
_single(_definition(
    "network.public_endpoint.status", "network.public_endpoint.status",
    PUBLIC_ENDPOINT_STATUS_FIELDS, executor="public_endpoint_status",
), "network.public_endpoint.status 不接受参数。")
_single(_definition(
    "network.public_endpoint.transaction.status",
    "network.public_endpoint.transaction.status",
    PUBLIC_ENDPOINT_TRANSACTION_STATUS_FIELDS,
    executor="public_endpoint_transaction_status",
), "network.public_endpoint.transaction.status 参数不正确。")
_single(_definition(
    "network.duckdns.status", "network.duckdns.status", EMPTY,
    executor="duckdns_status",
), "network.duckdns.status 不接受参数。")
duckdns_changes = [
    ((operation,), _change(
        f"network.duckdns.{operation}", "network.duckdns.change",
        DYNAMIC_DNS_CHANGE_FIELDS, ChangeLevel.ROUTINE,
        preview="duckdns", fact_scope="duckdns",
        executor="change_duckdns", verifier="duckdns_status",
        sensitive=frozenset({"token", "secret_id", "secret_key"}), timeout=45,
    ))
    for operation in ("configure", "update", "disable", "delete")
]
_register(_variants(
    "network.duckdns.change", DYNAMIC_DNS_CHANGE_FIELDS, ("operation",),
    duckdns_changes, "network.duckdns.change 参数不正确。",
    invalid_variant_message="动态 DNS 动作未登记。",
))
public_endpoint_changes = [
    ((operation,), _change(
        f"network.public_endpoint.{operation}", "network.public_endpoint.change",
        PUBLIC_ENDPOINT_CHANGE_FIELDS, ChangeLevel.ROLLBACK,
        preview="public_endpoint", fact_scope="public_endpoint",
        executor="change_public_endpoint", verifier="public_endpoint_status",
        supports_rollback=operation == "apply", timeout=240,
    ))
    for operation in ("apply", "confirm", "rollback")
]
_register(_variants(
    "network.public_endpoint.change", PUBLIC_ENDPOINT_CHANGE_FIELDS, ("operation",),
    public_endpoint_changes, "network.public_endpoint.change 参数不正确。",
    invalid_variant_message="稳定公网入口动作未登记。",
))
_single(_change(
    "network.subscriptions.sync", "network.subscriptions.sync", CONFIRMED_ACTOR_FIELDS,
    ChangeLevel.CONFIRMATION, preview="subscriptions", fact_scope="network",
    executor="sync_network_subscriptions", verifier="network_overview",
), "network.subscriptions.sync 参数不正确。")

permission_changes = [
    ((operation,), _change(
        f"network.permission.{operation}", "network.permission.change", PERMISSION_FIELDS,
        ChangeLevel.CONFIRMATION, preview="network_permission", fact_scope="network",
        executor="change_network_permission", verifier="network_overview",
    ))
    for operation in ("allow", "deny")
]
_register(_variants(
    "network.permission.change", PERMISSION_FIELDS, ("operation",), permission_changes,
    "network.permission.change 参数不正确。",
    invalid_variant_message="权限动作未登记。",
))
_single(_change(
    "network.permission.batch", "network.permission.batch", PERMISSION_BATCH_FIELDS,
    ChangeLevel.CONFIRMATION, preview="network_permission_batch", fact_scope="network",
    executor="add_network_permissions", verifier="network_overview",
), "network.permission.batch 参数不正确。")
_single(_change(
    "network.subscription.rotate", "network.subscription.rotate", SUBSCRIPTION_ITEM_FIELDS,
    ChangeLevel.CONFIRMATION, preview="subscription", fact_scope="network",
    executor="rotate_network_subscription", verifier="network_overview",
), "network.subscription.rotate 参数不正确。")

subscription_state_changes = [
    (("enabled",), _change(
        "network.subscription.enable", "network.subscription.state", SUBSCRIPTION_STATE_FIELDS,
        ChangeLevel.CONFIRMATION, preview="subscription", fact_scope="network",
        executor="set_network_subscription_state", verifier="network_overview",
    )),
    (("disabled",), _change(
        "network.subscription.disable", "network.subscription.state", SUBSCRIPTION_STATE_FIELDS,
        ChangeLevel.CONFIRMATION, preview="subscription", fact_scope="network",
        executor="set_network_subscription_state", verifier="network_overview",
    )),
]
_register(_variants(
    "network.subscription.state", SUBSCRIPTION_STATE_FIELDS, ("state",),
    subscription_state_changes, "network.subscription.state 参数不正确。",
    invalid_variant_code="invalid_params",
    invalid_variant_message="订阅发布状态参数不正确。",
))
_single(_definition(
    "firewall.ports.overview", "firewall.ports.overview", EMPTY,
    executor="firewall_ports",
), "firewall.ports.overview 不接受参数。")

firewall_port_changes = [
    ((operation,), _change(
        f"firewall.port.{operation}", "firewall.port.change", FIREWALL_PORT_FIELDS,
        ChangeLevel.CONFIRMATION, preview="firewall_port", fact_scope="firewall_ports",
        executor="change_firewall_port", verifier="firewall_ports", timeout=30,
    ))
    for operation in ("open", "close")
]
_register(_variants(
    "firewall.port.change", FIREWALL_PORT_FIELDS, ("operation",), firewall_port_changes,
    "firewall.port.change 参数不正确。",
    invalid_variant_message="自定义端口动作未登记。",
))
_single(_definition(
    "ssh.keys.overview", "ssh.keys.overview", EMPTY, executor="ssh_keys",
), "ssh.keys.overview 不接受参数。")
_single(_definition(
    "ssh.key.preview", "ssh.key.preview", SSH_PREVIEW_FIELDS,
    executor="preview_ssh_key", sensitive=frozenset({"public_key"}), timeout=30,
), "ssh.key.preview 参数不正确。")

ssh_key_changes = []
for operation, level in (
    ("add", ChangeLevel.CONFIRMATION),
    ("rename", ChangeLevel.ROUTINE),
    ("delete", ChangeLevel.CONFIRMATION),
):
    ssh_key_changes.append(((operation,), _change(
        f"ssh.key.{operation}", "ssh.key.change", SSH_CHANGE_FIELDS, level,
        preview="ssh_key", fact_scope="ssh_keys", executor="change_ssh_key",
        verifier="ssh_keys", timeout=30,
    )))
_register(_variants(
    "ssh.key.change", SSH_CHANGE_FIELDS, ("operation",), ssh_key_changes,
    "ssh.key.change 参数不正确。",
    invalid_variant_message="SSH 公钥动作未登记。",
))
security_reads = []
security_changes = []
for transaction_type in ("ssh_auth", "ssh_listener", "firewall", "vless_listener"):
    for operation in ("status", "preview"):
        canonical_type = transaction_type
        name = f"security.{canonical_type}.{operation}"
        security_reads.append(((transaction_type, operation), _definition(
            name, "security.transaction", SECURITY_FIELDS,
            executor="manage_transaction", timeout=180,
        )))
_register(_variants(
    "security.transaction", SECURITY_FIELDS, ("transaction_type", "operation"),
    security_reads, "security.transaction 参数不正确。",
    invalid_variant_message="安全事务未登记。",
))
for transaction_type in ("ssh_auth", "ssh_listener", "firewall", "vless_listener"):
    for operation in ("apply", "confirm", "rollback"):
        fields = (
            VLESS_LISTENER_CHANGE_FIELDS
            if transaction_type == "vless_listener"
            else SECURITY_CHANGE_FIELDS
        )
        security_changes.append(((transaction_type, operation), _change(
            f"security.{transaction_type}.{operation}",
            "security.transaction.change", fields,
            ChangeLevel.ROLLBACK,
            preview="security_transaction", fact_scope=f"security:{transaction_type}",
            executor="manage_transaction", verifier="manage_transaction",
            supports_rollback=operation == "apply", timeout=180,
        )))
_register(_variants(
    "security.transaction.change", SECURITY_CHANGE_FIELDS,
    ("transaction_type", "operation"), security_changes,
    "security.transaction.change 参数不正确。",
    invalid_variant_message="安全事务变更未登记。",
))

backup_actions = []
for operation in (
    "list", "create", "verify", "delete", "preview_restore", "restore_status",
):
    name = f"backup.{operation}"
    sensitive = frozenset({"passphrase"}) if operation in {
        "create", "verify", "preview_restore", "restore_apply",
    } else EMPTY
    if operation in {"list", "preview_restore", "restore_status"}:
        definition = _definition(
            name, "backup.manage", BACKUP_FIELDS, executor="manage_backup",
            sensitive=sensitive,
            sync_confirmation_required=operation == "preview_restore",
            sync_confirmation_message=(
                "备份操作需要明确确认。" if operation == "preview_restore" else ""
            ),
            timeout=180,
        )
    else:
        level = (
            ChangeLevel.ROUTINE if operation in {"create", "verify"}
            else ChangeLevel.CONFIRMATION if operation == "delete"
            else ChangeLevel.ROLLBACK
        )
        definition = _change(
            name, "backup.manage", BACKUP_FIELDS, level, preview="backup",
            fact_scope="backups", executor="manage_backup", verifier="manage_backup",
            sensitive=sensitive, supports_rollback=operation == "restore_apply",
            timeout=180,
        )
    backup_actions.append(((operation,), definition))
_register(_variants(
    "backup.manage", BACKUP_FIELDS, ("operation",), backup_actions,
    "backup.manage 参数不正确。",
    invalid_variant_message="备份动作未登记。",
))

backup_restore_actions = []
for operation in ("restore_apply", "restore_confirm", "restore_rollback"):
    sensitive = frozenset({"passphrase"}) if operation == "restore_apply" else EMPTY
    backup_restore_actions.append(((operation,), _change(
        f"backup.{operation}", "backup.restore.change", BACKUP_RESTORE_FIELDS,
        ChangeLevel.ROLLBACK, preview="backup_restore", fact_scope="backup_restore",
        executor="manage_backup", verifier="manage_backup",
        sensitive=sensitive, supports_rollback=operation == "restore_apply",
        timeout=180,
    )))
_register(_variants(
    "backup.restore.change", BACKUP_RESTORE_FIELDS, ("operation",),
    backup_restore_actions, "backup.restore.change 参数不正确。",
    invalid_variant_message="配置恢复动作未登记。",
))


ACTION_CATALOG: Mapping[str, _ActionRoute] = MappingProxyType(_routes.copy())


def registered_protocol_actions() -> frozenset[str]:
    """返回协议层唯一登记的全部动作。"""

    return frozenset(ACTION_CATALOG)


def registered_actions() -> tuple[ActionDefinition, ...]:
    """返回按规范名称排序的全部动作定义。"""

    definitions: list[ActionDefinition] = []
    for route in ACTION_CATALOG.values():
        if route.definition is not None:
            definitions.append(route.definition)
        else:
            definitions.extend(route.variants.values())
    return tuple(sorted(definitions, key=lambda item: item.name))


def resolve_action(
    protocol_action: str, params: Mapping[str, object]
) -> ActionDefinition:
    """根据协议动作和不可变选择字段解析唯一动作定义。"""

    if "change_level" in params:
        raise ActionCatalogError("invalid_params", "变更等级不能由调用方指定。")
    route = ACTION_CATALOG.get(protocol_action)
    if route is None:
        raise ActionCatalogError("unknown_action", "动作未登记。")
    return route.resolve(params)


def validate_action_request(
    protocol_action: str, params: Mapping[str, object]
) -> ActionDefinition:
    """校验协议字段集合并返回唯一动作定义。"""

    if "change_level" in params:
        raise ActionCatalogError("invalid_params", "变更等级不能由调用方指定。")
    route = ACTION_CATALOG.get(protocol_action)
    if route is None:
        raise ActionCatalogError("unknown_action", "动作未登记。")
    definition = route.resolve(params)
    if set(params) != definition.parameter_fields:
        raise ActionCatalogError("invalid_params", route.invalid_params_message)
    return definition
