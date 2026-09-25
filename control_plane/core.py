#!/usr/bin/env python3
"""管理代理的请求校验与动作分派。"""

from __future__ import annotations

import hashlib
import base64
import binascii
import json
import logging
import ipaddress
import re
from typing import Any, Protocol

from lib.server_kit_proxy_resources import COUNTRY_IDS
from lib.server_kit_node_domains import (
    NodeDomainError, normalize_domains, validate_wildcard_conflicts,
)
from lib.server_kit_public_endpoint import normalize_fqdn
from lib.server_kit_port_ranges import PortRangeError, format_ports, parse_ports
from lib.server_kit_permission_batch import PermissionBatchError, normalize_rules

from .actions import ActionCatalogError, ActionDefinition, validate_action_request
from .tasks import PreparedAction, TaskEngineError
from .read_model import ManagedHostReadModel


PROTOCOL_VERSION = 1
REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
ACTOR_PATTERN = re.compile(r"[A-Za-z0-9_@.+-]{1,150}\Z")
ITEM_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
SESSION_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
RESOURCE_ITEM_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,72}\Z")
NETWORK_PROTOCOLS = frozenset({"tcp", "udp"})
FIREWALL_PORT_SCOPES = frozenset({"public", "amneziawg"})
FIREWALL_PORT_PROTOCOLS = frozenset({"tcp", "udp", "both"})
SERVICE_IDS = frozenset(
    {
        "amneziawg",
        "management",
        "vless",
        "clash",
        "file",
        "mosh",
        "cert-renew",
        "firewall",
        "ssh",
    }
)
CHANGEABLE_SERVICE_IDS = frozenset({"clash", "file", "mosh"})
BACKUP_ID_PATTERN = re.compile(r"backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
READ_ONLY_REASONS = {
    "amneziawg": "AWG 是管理入口，变更前必须具备回滚窗口。",
    "management": "管理网站不能从自身页面启停。",
    "vless": "VLESS 是网络入口，变更前必须具备回滚窗口。",
    "cert-renew": "证书续期由定时器托管，本阶段保持只读。",
    "firewall": "基础策略通过防火墙事务管理；自定义端口使用独立确认流程。",
    "ssh": "监听与认证策略通过 SSH 事务管理；客户端公钥使用独立确认流程。",
}
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


class RequestError(Exception):
    """表示可以安全返回给调用者的请求错误。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Runner(Protocol):
    """固定管理动作的执行适配器接口。"""

    def snapshot(self) -> dict[str, Any]:
        """读取当前受管主机快照。"""

    def change_service(
        self, service_id: str, operation: str, actor: str
    ) -> dict[str, Any]:
        """执行已登记服务动作并返回最新主机快照。"""

    def service_inventory(self, service_id: str) -> dict[str, Any]:
        """读取单个服务的脱敏专用清单。"""

    def reveal_resource(
        self, service_id: str, resource: str, item_id: str, actor: str
    ) -> dict[str, Any]:
        """按需读取经过登记的敏感资源并留下审计。"""

    def file_resources(self) -> dict[str, Any]:
        """读取普通文件资源脱敏清单。"""

    def file_upload_facts(self, upload_id: str) -> dict[str, Any]:
        """读取不可伪造暂存标识所指向文件的大小与摘要。"""

    def discard_file_upload(self, upload_id: str) -> None:
        """幂等清理普通文件暂存目录。"""

    def change_file_resource(
        self, operation: str, upload_id: str, download_name: str,
        cdn_cache: bool, cache_ttl: int, resource_id: str, actor: str,
    ) -> dict[str, Any]:
        """新增或删除普通文件资源。"""

    def manage_transaction(
        self, transaction_type: str, operation: str, actor: str,
        session_id: str = "", public_ip: str = "", public_port: str = "",
    ) -> dict[str, Any]:
        """读取或推进经过登记的安全事务。"""

    def firewall_ports(self) -> dict[str, Any]:
        """读取当前自定义防火墙端口。"""

    def change_firewall_port(
        self, operation: str, port: int, scope: str, protocol: str,
        duration_seconds: int, actor: str,
    ) -> dict[str, Any]:
        """开放或关闭经过严格校验的自定义端口。"""

    def managed_ports(self) -> dict[str, Any]:
        """读取 Clash、文件和 AWG 备用入口的可维护端口。"""

    def change_managed_port(
        self, target_id: str, port: int, revision: str, actor: str,
    ) -> dict[str, Any]:
        """按预览事实版本原子修改一个托管服务端口。"""

    def ssh_keys(self) -> dict[str, Any]:
        """读取 root SSH 客户端公钥的脱敏清单。"""

    def preview_ssh_key(self, public_key: str, actor: str) -> dict[str, Any]:
        """校验并短期暂存一条待添加公钥。"""

    def change_ssh_key(
        self, operation: str, item_id: str, name: str, actor: str
    ) -> dict[str, Any]:
        """添加、改名或删除一个登记的 SSH 公钥客户端。"""

    def manage_backup(
        self, operation: str, backup_id: str, passphrase: str, actor: str,
        session_id: str = "",
    ) -> dict[str, Any]:
        """创建、校验或预览恢复加密配置备份。"""

    def network_overview(self) -> dict[str, Any]:
        """读取脱敏节点与订阅发布状态。"""

    def public_endpoint_status(self) -> dict[str, Any]:
        """读取稳定公网入口及 DNS 诊断。"""

    def duckdns_status(self) -> dict[str, Any]:
        """读取不含凭据的动态 DNS 自动更新状态。"""

    def change_duckdns(
        self, operation: str, provider: str, fqdn: str, token: str, secret_id: str,
        secret_key: str, zone: str, actor: str,
    ) -> dict[str, Any]:
        """验证并配置、运行、停用或删除动态 DNS 自动更新。"""

    def public_endpoint_transaction_status(
        self, actor: str, session_id: str
    ) -> dict[str, Any]:
        """读取稳定公网入口回滚事务状态。"""

    def change_public_endpoint(
        self, operation: str, fqdn: str, actor: str, session_id: str,
        transaction_id: str = "",
    ) -> dict[str, Any]:
        """设置或清除稳定公网入口事实。"""

    def audit_log(self) -> dict[str, Any]:
        """读取经过哈希链校验的最近管理动作。"""

    def record_event(self, service_id: str, operation: str, actor: str) -> dict[str, Any]:
        """记录不含敏感值的网页本地状态变更。"""

    def enrollment_context(self) -> dict[str, Any]:
        """读取网页内置密钥生成器所需的公开服务端参数。"""

    def proxy_resources(self) -> dict[str, Any]:
        """读取不含凭据的机场资源状态。"""

    def test_proxy_resources(self, actor: str) -> dict[str, Any]:
        """测试机场 HTTP 与出口 TCP 可达性，不返回凭据。"""

    def update_proxy_resources(
        self, values: dict[str, object], actor: str
    ) -> dict[str, Any]:
        """原子变更机场目录并刷新订阅。"""

    def deploy_service(self, service_id: str, values: dict[str, Any], actor: str) -> dict[str, Any]:
        """用登记字段安装首次部署服务。"""

    def change_network_node(
        self, kind: str, operation: str, name: str, address: str, actor: str,
    ) -> dict[str, Any]:
        """执行登记的节点变更。"""

    def import_network_node(
        self, name: str, address: str, public_key: str, preshared_key: str, actor: str,
    ) -> dict[str, Any]:
        """导入由客户端持有私钥的 AWG 节点。"""

    def change_node_domains(
        self, name: str, domains: list[str], actor: str
    ) -> dict[str, Any]:
        """替换普通 AWG 节点的订阅强制解析记录并刷新订阅。"""

    def change_address_domains(
        self, address: str, domains: list[str], actor: str
    ) -> dict[str, Any]:
        """替换任意 IP 的订阅强制解析记录并刷新订阅。"""

    def sync_network_subscriptions(self, actor: str) -> dict[str, Any]:
        """按当前节点状态原子同步订阅。"""

    def rotate_network_subscription(self, name: str, actor: str) -> dict[str, Any]:
        """只轮换指定节点的订阅令牌。"""

    def set_network_subscription_state(self, name: str, state: str, actor: str) -> dict[str, Any]:
        """单独启用或停用指定节点的订阅发布。"""

    def change_network_permission(
        self, operation: str, client: str, target: str, ports: str,
        network: str, actor: str,
    ) -> dict[str, Any]:
        """变更普通 AWG 或 VLESS 节点的访问策略。"""

    def add_network_permissions(
        self, client: str, rules: list[dict[str, str]], actor: str,
    ) -> dict[str, Any]:
        """一次应用全部新增权限，保留已有规则。"""


class TaskEngine(Protocol):
    """控制面调用异步任务 module 所需的最小接口。"""

    def preview(
        self, protocol_action: str, arguments: dict[str, object], actor: str
    ) -> dict[str, object]: ...

    def confirm(self, task_id: str, actor: str) -> dict[str, object]: ...

    def cancel(self, task_id: str, actor: str) -> dict[str, object]: ...

    def get(self, task_id: str) -> dict[str, object]: ...

    def list(self) -> dict[str, object]: ...

    def has_active_tasks(self) -> bool: ...


class ControlPlane:
    """隐藏鉴权、请求模式和动作分派的管理模块。"""

    def __init__(
        self,
        runner: Runner,
        allowed_uids: set[int],
        *,
        task_engine: TaskEngine | None = None,
    ) -> None:
        self._runner = runner
        self._allowed_uids = frozenset(allowed_uids)
        self._task_engine = task_engine
        self._read_model = ManagedHostReadModel(runner, self._describe_service)

    def attach_task_engine(self, task_engine: TaskEngine) -> None:
        """仅供代理启动阶段完成任务 module 的循环装配。"""

        if self._task_engine is not None:
            raise RuntimeError("任务 module 已经装配")
        self._task_engine = task_engine

    def prepare_task_action(
        self, protocol_action: str, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        """根据实时事实为任务 module 生成唯一的脱敏执行计划。"""

        if protocol_action == "network.proxy.update":
            return self._prepare_proxy_task(arguments, actor)
        if protocol_action == "network.duckdns.change":
            return self._prepare_duckdns_task(arguments, actor)
        if protocol_action == "file.resource.change":
            return self._prepare_file_task(arguments, actor)
        if protocol_action == "ssh.key.change":
            return self._prepare_ssh_key_task(arguments, actor)
        if protocol_action == "network.public_endpoint.change":
            operation = arguments.get("operation")
            fqdn = arguments.get("fqdn")
            session_id = arguments.get("session_id")
            if (
                operation not in {"apply", "confirm", "rollback"}
                or not isinstance(fqdn, str)
                or not isinstance(session_id, str)
                or not SESSION_ID_PATTERN.fullmatch(session_id)
            ):
                raise TaskEngineError("invalid_params", "稳定公网入口参数不正确。")
            if operation == "apply" and fqdn:
                try:
                    fqdn = normalize_fqdn(fqdn)
                    overview = self._runner.network_overview()
                    validate_wildcard_conflicts([
                        str(domain)
                        for item in overview.get("nodes", [])
                        if isinstance(item, dict) and item.get("kind") == "awg"
                        for domain in item.get("domains", [])
                    ], [fqdn])
                except (ValueError, NodeDomainError) as error:
                    raise TaskEngineError("invalid_params", str(error)) from error
            elif operation != "apply" and fqdn:
                raise TaskEngineError("invalid_params", "确认或回滚稳定公网入口不接受域名。")
            status = self._runner.public_endpoint_transaction_status(actor, session_id)
            if operation == "apply" and status.get("state") != "idle":
                raise TaskEngineError("operation_forbidden", "已有待确认的稳定公网入口事务。")
            transaction_id = ""
            if operation != "apply":
                if status.get("state") != "pending":
                    raise TaskEngineError("operation_forbidden", "当前没有待确认的稳定公网入口事务。")
                transaction_id = str(status.get("transaction_id", ""))
                if re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None:
                    raise TaskEngineError("operation_forbidden", "稳定公网入口事务标识无效。")
                if operation == "confirm" and not status.get("independent_session"):
                    raise TaskEngineError(
                        "operation_forbidden", "必须从另一条独立登录连接确认稳定公网入口。"
                    )
            params = {
                "operation": operation, "fqdn": fqdn, "session_id": session_id,
                "transaction_id": transaction_id, "actor": actor, "confirmed": True,
            }
            try:
                definition = validate_action_request(protocol_action, params)
            except ActionCatalogError as error:
                raise TaskEngineError(error.code, error.message) from error
            current = str(status.get("fqdn", "")) or "未配置"
            target = fqdn or "恢复使用当前公网 IPv4"
            titles = {"apply": "变更稳定公网入口", "confirm": "确认保留稳定公网入口", "rollback": "立即回滚稳定公网入口"}
            return PreparedAction(
                canonical_action=definition.name, params=params,
                preview={"title": titles[str(operation)], "summary": "稳定公网入口、HTTPS 证书、Clash/文件服务地址和全部订阅由同一回滚事务保护；最终确认必须来自另一条登录连接。", "facts": {"当前入口": current, "变更后": target if operation == "apply" else current, "联动范围": "AWG/VLESS 公网入口、HTTPS 证书、Clash/文件服务地址及全部订阅", "客户端影响": "已发布订阅会自动迁移；旧 AWG 客户端配置仍需重新下载或手动更新 Endpoint 主机", "自动回滚期限": f"{status.get('rollback_seconds', 300)} 秒", "独立连接": "最终确认必须来自另一条独立登录连接"}},
                fact_digest=self._public_endpoint_digest(params, status),
                timeout_seconds=definition.timeout_seconds,
                supports_rollback=definition.supports_rollback,
            )
        if protocol_action in {
            "network.node.change", "network.node.import",
            "network.node.domains", "network.address.domains",
            "network.permission.change",
            "network.permission.batch",
        }:
            return self._prepare_network_task(protocol_action, arguments, actor)
        if protocol_action in {
            "network.subscriptions.sync",
            "network.subscription.rotate",
            "network.subscription.state",
        }:
            return self._prepare_subscription_task(protocol_action, arguments, actor)
        if protocol_action == "backup.manage":
            return self._prepare_backup_task(arguments, actor)
        if protocol_action == "backup.restore.change":
            return self._prepare_restore_task(arguments, actor)
        if protocol_action == "firewall.port.change":
            return self._prepare_firewall_port_task(arguments, actor)
        if protocol_action == "managed.port.change":
            return self._prepare_managed_port_task(arguments, actor)
        if protocol_action == "security.transaction.change":
            return self._prepare_security_task(arguments, actor)
        if protocol_action == "deployment.install":
            return self._prepare_deployment_task(arguments, actor)
        if protocol_action != "service.change":
            raise TaskEngineError("operation_forbidden", "该动作尚未接入异步任务。")
        if set(arguments) != {"service_id", "operation"}:
            raise TaskEngineError("invalid_params", "托管服务任务参数不正确。")
        if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
            raise TaskEngineError("invalid_params", "操作账号格式不正确。")
        service_id = self._service_id(arguments.get("service_id"))
        operation = arguments.get("operation")
        params = {
            "service_id": service_id,
            "operation": operation,
            "actor": actor,
            "confirmed": True,
        }
        try:
            definition = validate_action_request(protocol_action, params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        description = self._task_service_description(service_id)
        if operation not in description["allowed_operations"]:
            raise TaskEngineError("operation_forbidden", "当前服务不允许执行该操作。")
        operation_labels = {"start": "启动", "stop": "停止", "restart": "重启"}
        target_states = {"start": "运行中", "stop": "已停止", "restart": "运行中"}
        service = description["service"]
        facts = {
            "当前状态": service["state"],
            "目标状态": target_states[str(operation)],
            "服务": service["label"],
        }
        fact_digest = self._service_fact_digest(service_id, operation, description)
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            preview={
                "title": f"{operation_labels[str(operation)]} {service['label']}",
                "summary": "任务将在后台执行；关闭页面不会中断操作。",
                "facts": facts,
            },
            fact_digest=fact_digest,
            timeout_seconds=definition.timeout_seconds,
        )

    def _prepare_deployment_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        value_fields = {
            "port", "server_name", "airport_url",
            "exit_proxy_yaml", "upload_id", "download_name",
        }
        if set(arguments) != {"service_id", *value_fields}:
            raise TaskEngineError("invalid_params", "部署任务参数不正确。")
        service_id = arguments.get("service_id")
        if service_id not in {"vless", "clash", "mosh", "file"}:
            raise TaskEngineError("operation_forbidden", "部署服务未登记。")
        values = {key: arguments.get(key) for key in value_fields}
        if not all(isinstance(value, str) for value in values.values()):
            raise TaskEngineError("invalid_params", "部署字段格式不正确。")
        params = {
            "service_id": service_id, **values,
            "actor": actor, "confirmed": True,
        }
        try:
            definition = validate_action_request("deployment.install", params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        self._validate_deployment_values(str(service_id), values)
        snapshot = self._runner.snapshot()
        services = {
            item.get("id"): item for item in snapshot.get("services", [])
            if isinstance(item, dict)
        }
        current = services.get(service_id)
        if not isinstance(current, dict):
            raise TaskEngineError("not_found", "部署目标没有出现在主机事实快照中。")
        if current.get("state") != "未安装":
            raise TaskEngineError("operation_forbidden", "目标服务已经安装，部署向导不会覆盖现有配置。")
        dependencies = {
            "vless": ("amneziawg", "management"),
            "clash": ("vless",),
            "mosh": ("amneziawg", "ssh"),
            "file": (),
        }[str(service_id)]
        missing = [
            name for name in dependencies
            if not isinstance(services.get(name), dict)
            or services[name].get("state") not in {"运行中", "已停止"}
        ]
        if missing:
            raise TaskEngineError("operation_forbidden", f"请先部署依赖服务：{'、'.join(missing)}。")
        port = int(values["port"]) if values["port"].isdigit() else 0
        conflicts = self._deployment_port_conflicts(port, str(service_id), services)
        if conflicts:
            raise TaskEngineError("operation_forbidden", f"端口已被占用：{'、'.join(conflicts)}。")
        task_params = dict(params)
        sensitive_params: dict[str, object] = {}
        if service_id == "clash":
            sensitive_params = {
                "airport_url": values["airport_url"],
                "exit_proxy_yaml": values["exit_proxy_yaml"],
            }
            task_params["airport_url"] = ""
            task_params["exit_proxy_yaml"] = ""
        upload_facts: dict[str, Any] | None = None
        if service_id == "file":
            upload_facts = self._runner.file_upload_facts(str(values["upload_id"]))
            task_params["_upload_size"] = upload_facts["size"]
            task_params["_upload_sha256"] = upload_facts["sha256"]
        labels = {
            "vless": "公网 VLESS REALITY", "clash": "Clash 订阅",
            "mosh": "Mosh 终端", "file": "普通文件服务",
        }
        facts = {
            "服务": labels[str(service_id)], "当前状态": "未安装",
            "端口": str(port) if port else "固定 AWG 端口范围",
            "依赖预检": "通过", "端口占用": "无冲突",
        }
        if upload_facts is not None:
            facts["暂存文件"] = f"{values['download_name']} · {upload_facts['size']} 字节"
        return PreparedAction(
            canonical_action=definition.name,
            params=task_params,
            preview={
                "title": f"部署 {labels[str(service_id)]}",
                "summary": "部署将在后台依次完成校验、安装、配置、启动和验证；关闭页面不会中断。",
                "facts": facts,
                "stages": ["校验", "安装", "配置", "启动", "验证"],
            },
            fact_digest=self._deployment_fact_digest(
                params, snapshot, current, upload_facts
            ),
            timeout_seconds=definition.timeout_seconds,
            sensitive_params=sensitive_params or None,
        )

    @staticmethod
    def _validate_deployment_values(
        service_id: str, values: dict[str, object]
    ) -> None:
        text = {key: str(value) for key, value in values.items()}
        if any("\x00" in value for value in text.values()):
            raise TaskEngineError("invalid_params", "部署字段包含无效字符。")
        if (
            len(text["exit_proxy_yaml"]) > 65536
            or len(text["airport_url"]) > 8192
        ):
            raise TaskEngineError("invalid_params", "部署字段过长。")
        if service_id in {"vless", "clash", "file"} and (
            not text["port"].isdigit() or not 1 <= int(text["port"]) <= 65535
        ):
            raise TaskEngineError("invalid_params", "服务端口无效。")
        if service_id == "vless" and (
            not re.fullmatch(r"[A-Za-z0-9.-]{3,253}", text["server_name"])
            or "." not in text["server_name"]
        ):
            raise TaskEngineError("invalid_params", "REALITY 伪装域名无效。")
        if service_id == "clash" and (
            not text["airport_url"].strip() or not text["exit_proxy_yaml"].strip()
        ):
            raise TaskEngineError("invalid_params", "Clash 首次安装需要机场链接和完整出口节点。")
        if service_id == "file" and (
            not re.fullmatch(r"[0-9a-f]{32}", text["upload_id"])
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", text["download_name"])
        ):
            raise TaskEngineError("invalid_params", "上传标识或下载文件名无效。")

    @classmethod
    def _deployment_port_conflicts(
        cls, port: int, service_id: str, services: dict[object, dict[str, Any]]
    ) -> list[str]:
        # Mosh 使用脚本登记的固定 UDP 范围。
        if port == 0 or service_id == "mosh":
            return []
        conflicts = []
        for identifier, service in services.items():
            if identifier == service_id or service.get("state") == "未安装":
                continue
            for item in service.get("ports", []):
                if not isinstance(item, dict):
                    continue
                # 首次部署的 VLESS、Clash 与文件服务均为 TCP。TCP 与 AWG 的
                # 同号 UDP 入口可以共存，不能误报端口冲突。
                if str(item.get("protocol", "")).lower() != "tcp":
                    continue
                value = str(item.get("port", ""))
                if cls._port_expression_contains(value, port):
                    conflicts.append(f"{service.get('label', identifier)} {value}")
                    break
        return conflicts

    @staticmethod
    def _port_expression_contains(expression: str, port: int) -> bool:
        for part in re.split(r"[/,\s]+", expression):
            if part.isdigit() and int(part) == port:
                return True
            match = re.fullmatch(r"(\d+)-(\d+)", part)
            if match and int(match.group(1)) <= port <= int(match.group(2)):
                return True
        return False

    @staticmethod
    def _deployment_fact_digest(
        params: dict[str, object], snapshot: dict[str, Any],
        current: dict[str, Any], upload_facts: dict[str, Any] | None,
    ) -> str:
        services = [
            {
                key: item.get(key)
                for key in ("id", "label", "state", "autostart", "ports", "detail")
                if key in item
            }
            for item in snapshot.get("services", [])
            if isinstance(item, dict)
        ]
        source = {
            "params": {
                key: value for key, value in params.items()
                if key not in {
                    "actor", "confirmed", "airport_url", "exit_proxy_yaml", "public_key"
                }
            },
            # 排除 generated_at 等易变字段，避免仅因重新采样时间不同而让
            # 尚未执行的部署任务失效。
            "services": services,
            "current": current,
            "upload": upload_facts,
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    def _prepare_proxy_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        expected = {
            "operation", "airport_id", "airport_name", "airport_url",
            "airport_enabled", "countries", "exit_id", "exit_name",
            "exit_default", "exit_proxy_yaml", "awg_name", "exit_ids",
        }
        if set(arguments) != expected:
            raise TaskEngineError("invalid_params", "机场资源任务参数不正确。")
        params = {**arguments, "actor": actor, "confirmed": True}
        try:
            definition = validate_action_request("network.proxy.update", params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        self._validate_proxy_update_values(params)
        current = self._runner.proxy_resources()
        operation = str(params["operation"])
        operation_labels = {
            "airport_add": "新增机场",
            "airport_update": "更新机场",
            "airport_delete": "删除机场",
            "exit_add": "新增出口节点", "exit_update": "更新出口节点",
            "exit_delete": "删除出口节点", "exit_set_default": "设为默认出口",
            "node_exits_set": "更新节点出口",
        }
        current_airport = next((
            item for item in current.get("airports", [])
            if isinstance(item, dict) and item.get("id") == params.get("airport_id")
        ), {})
        if operation in {"airport_update", "airport_delete"} and not current_airport:
            raise TaskEngineError("invalid_params", "要管理的机场不存在。")
        if operation in {"airport_add", "airport_update"}:
            duplicate = next((
                item for item in current.get("airports", [])
                if isinstance(item, dict)
                and str(item.get("name", "")).casefold() == str(params["airport_name"]).strip().casefold()
                and item.get("id") != params.get("airport_id")
            ), None)
            if duplicate:
                raise TaskEngineError("invalid_params", "机场名称已存在。")
        exits = [item for item in current.get("exits", []) if isinstance(item, dict)]
        current_exit = next((item for item in exits if item.get("id") == params.get("exit_id")), {})
        if operation in {"exit_update", "exit_delete", "exit_set_default"} and not current_exit:
            raise TaskEngineError("invalid_params", "要管理的出口节点不存在。")
        if operation in {"exit_add", "exit_update"}:
            duplicate = next((item for item in exits
                if str(item.get("name", "")).casefold() == str(params["exit_name"]).strip().casefold()
                and item.get("id") != params.get("exit_id")), None)
            if duplicate:
                raise TaskEngineError("invalid_params", "出口节点名称已存在。")
        subject_name = str(params.get("airport_name", "")) or str(current_airport.get("name", "")) or "—"
        facts = {
            "动作": operation_labels[operation],
            "发布订阅": "全部刷新",
        }
        if operation.startswith("airport_"):
            facts.update({"机场": subject_name, "当前机场数": str(current.get("airport_count", 0))})
        elif operation == "node_exits_set":
            selected = [item for item in exits if item.get("id") in params["exit_ids"]]
            if len(selected) != len(params["exit_ids"]):
                raise TaskEngineError("invalid_params", "选择中包含不存在的出口节点。")
            network = self._runner.network_overview()
            node = next((item for item in network.get("nodes", [])
                if isinstance(item, dict) and item.get("kind") in {"awg", "vless"}
                and item.get("name") == params["awg_name"]), None)
            if node is None:
                raise TaskEngineError("invalid_params", "要配置的订阅节点不存在。")
            names = [str(item.get("name", "")) for item in selected]
            facts.update({
                "订阅节点": str(params["awg_name"]),
                "中转路径": "、".join(names) if names else "VPS MID（不使用额外出口）",
            })
        else:
            facts.update({
                "出口": str(params.get("exit_name", "")) or str(current_exit.get("name", "")),
                "当前出口数": str(current.get("exit_count", 0)),
                "VLESS 中转": "按出口生成独立身份与路由",
            })
        return PreparedAction(
            canonical_action=definition.name,
            params={
                key: value for key, value in params.items()
                if key not in {"airport_url", "exit_proxy_yaml"}
            },
            preview={
                "title": operation_labels[operation],
                "summary": "敏感凭据已加密暂存；执行成功后刷新全部发布订阅。",
                "facts": facts,
            },
            fact_digest=self._proxy_fact_digest(current),
            timeout_seconds=definition.timeout_seconds,
            sensitive_params={
                "airport_url": params["airport_url"],
                "exit_proxy_yaml": params["exit_proxy_yaml"],
            },
        )

    def _prepare_file_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        expected_fields = {
            "operation", "upload_id", "download_name", "cdn_cache", "cache_ttl",
            "resource_id",
        }
        if set(arguments) != expected_fields:
            raise TaskEngineError("invalid_params", "普通文件任务参数不正确。")
        params = {**arguments, "actor": actor, "confirmed": True}
        try:
            definition = validate_action_request("file.resource.change", params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        self._validate_file_change_values(params)
        operation = str(params["operation"])
        current = self._runner.file_resources()
        task_params = dict(params)
        if operation == "add":
            upload_facts = self._runner.file_upload_facts(str(params["upload_id"]))
            task_params["_upload_size"] = upload_facts["size"]
            task_params["_upload_sha256"] = upload_facts["sha256"]
            subject = upload_facts
            title = f"发布文件 {params['download_name']}"
            facts = {
                "下载名称": params["download_name"],
                "文件大小": f"{upload_facts['size']} B",
                "CDN 缓存": "允许" if params["cdn_cache"] else "禁止",
                "缓存有效期": f"{params['cache_ttl']} 秒",
            }
        else:
            matches = [
                item for item in current.get("items", [])
                if item.get("resource_id") == params["resource_id"]
            ]
            if len(matches) != 1:
                raise TaskEngineError("not_found", "普通文件资源不存在。")
            subject = matches[0]
            title = f"删除文件 {subject.get('name', params['resource_id'])}"
            facts = {
                "文件": subject.get("name", params["resource_id"]),
                "源站": "执行后删除",
                "第三方 CDN": "不主动清除，可能保留到缓存到期",
            }
        return PreparedAction(
            canonical_action=definition.name,
            params=task_params,
            preview={
                "title": title,
                "summary": "任务将在后台执行，并在执行前重新核验文件事实。",
                "facts": facts,
            },
            fact_digest=self._file_fact_digest(params, subject, current),
            timeout_seconds=definition.timeout_seconds,
        )

    def _prepare_ssh_key_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        if set(arguments) != {"operation", "item_id", "name", "public_key"}:
            raise TaskEngineError("invalid_params", "SSH 公钥任务参数不正确。")
        operation = arguments.get("operation")
        item_id = arguments.get("item_id")
        name = arguments.get("name")
        public_key = arguments.get("public_key")
        if operation not in {"add", "rename", "delete"}:
            raise TaskEngineError("invalid_params", "SSH 公钥动作未登记。")
        listing = self._runner.ssh_keys()
        sensitive_params: dict[str, object] | None = None
        if operation == "add":
            if not isinstance(public_key, str):
                raise TaskEngineError("invalid_params", "SSH 公钥格式不正确。")
            preview = self._runner.preview_ssh_key(public_key, actor)
            safe_item = {
                key: preview[key]
                for key in ("type", "fingerprint", "name", "duplicate")
            }
            item_id = ""
            name = ""
            sensitive_params = {"public_key": public_key}
        else:
            if public_key != "" or not isinstance(item_id, str):
                raise TaskEngineError("invalid_params", "SSH 公钥参数不正确。")
            matches = [
                item for item in listing.get("items", [])
                if item.get("key_id") == item_id
            ]
            if len(matches) != 1:
                raise TaskEngineError("not_found", "SSH 客户端不存在。")
            safe_item = matches[0]
            if operation == "delete" and not safe_item.get("deletable"):
                raise TaskEngineError(
                    "operation_forbidden", "最后一把有效的 root SSH 公钥不能删除。"
                )
            if operation == "delete":
                name = ""
            elif not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
                raise TaskEngineError("invalid_params", "SSH 客户端名称无效。")
            name = str(name).strip()
        params = {
            "operation": operation,
            "item_id": item_id,
            "name": name,
            "actor": actor,
            "confirmed": True,
            "_type": safe_item.get("type", ""),
            "_fingerprint": safe_item.get("fingerprint", ""),
            "_display_name": safe_item.get("name", ""),
            "_duplicate": bool(safe_item.get("duplicate", False)),
        }
        catalog_params = {
            key: value for key, value in params.items() if not key.startswith("_")
        }
        try:
            definition = validate_action_request("ssh.key.change", catalog_params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        labels = {"add": "添加", "rename": "修改名字", "delete": "删除"}
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            preview={
                "title": f"{labels[str(operation)]} SSH 客户端",
                "summary": "任务详情只保留密钥类型、指纹和脱敏名称。",
                "facts": {
                    "名称": name or safe_item.get("name", "未命名客户端"),
                    "类型": safe_item.get("type", ""),
                    "指纹": safe_item.get("fingerprint", ""),
                    "重复": "是" if safe_item.get("duplicate") else "否",
                },
            },
            fact_digest=self._ssh_key_fact_digest(params, listing),
            timeout_seconds=definition.timeout_seconds,
            sensitive_params=sensitive_params,
        )

    def _prepare_network_task(
        self, protocol_action: str, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        params = {**arguments, "actor": actor, "confirmed": True}
        try:
            definition = validate_action_request(protocol_action, params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        overview = self._runner.network_overview()
        nodes = [item for item in overview.get("nodes", []) if isinstance(item, dict)]
        sensitive_params: dict[str, object] | None = None
        if protocol_action == "network.permission.batch":
            client = params.get("client")
            if not isinstance(client, str) or not ITEM_ID_PATTERN.fullmatch(client):
                raise TaskEngineError("invalid_params", "来源节点参数不正确。")
            clients = [item for item in nodes if item.get("name") == client]
            if len(clients) != 1 or clients[0].get("state") != "已启用":
                raise TaskEngineError("invalid_params", "只有已启用节点可以配置访问授权。")
            subject = clients[0]
            try:
                rules = normalize_rules(params.get("rules"))
            except PermissionBatchError as error:
                raise TaskEngineError("invalid_params", str(error)) from error
            targets = {
                item.get("name") for item in overview.get("targets", [])
                if isinstance(item, dict)
            }
            existing = [item for item in subject.get("permissions", []) if isinstance(item, dict)]
            facts = {"来源节点": client, "新增规则": str(len(rules)), "已有权限": "全部保留；不修改管理入口"}
            for index, rule in enumerate(rules, 1):
                if rule["target"] not in targets or rule["target"] == client:
                    raise TaskEngineError("not_found", f"第 {index} 条权限目标不存在或不能选择节点自身。")
                ports = parse_ports(rule["ports"]) if rule["ports"] else []
                if any(
                    item.get("target") == rule["target"] and item.get("network") == rule["network"]
                    and item.get("ports") == ports for item in existing
                ) or (
                    subject.get("kind") == "awg" and subject.get("access_mode") == "unrestricted"
                    and rule["target"] == "all" and rule["network"] == "all"
                ):
                    raise TaskEngineError("invalid_params", f"第 {index} 条访问权限已经存在。")
                target_label = "全部节点" if rule["target"] == "all" else rule["target"]
                detail = "全部协议与端口" if rule["network"] == "all" else f"{rule['network'].upper()} {rule['ports']}"
                facts[f"规则 {index}"] = f"{target_label} · {detail}"
            params["rules"] = rules
            title = f"新增 {len(rules)} 条访问权限"
        elif protocol_action in {"network.node.domains", "network.address.domains"}:
            if protocol_action == "network.address.domains":
                address = params.get("address")
                domains = params.get("domains")
                if not isinstance(address, str):
                    raise TaskEngineError("invalid_params", "目标 IP 格式不正确。")
                try:
                    clean_address = str(ipaddress.ip_address(address.strip()))
                    clean_domains = normalize_domains(domains)
                    public_endpoint = self._runner.public_endpoint_status()
                    dynamic_dns = self._runner.duckdns_status()
                    validate_wildcard_conflicts(clean_domains, [
                        str(public_endpoint.get("fqdn", "")),
                        str(dynamic_dns.get("fqdn", "")),
                    ])
                except (ValueError, NodeDomainError) as error:
                    raise TaskEngineError("invalid_params", str(error)) from error
                for item in nodes:
                    duplicate = next((
                        domain for domain in clean_domains
                        if domain in item.get("domains", [])
                    ), "")
                    if duplicate:
                        raise TaskEngineError(
                            "invalid_params",
                            f"域名 {duplicate} 已属于节点 {item.get('name', '')}。",
                        )
                records = [
                    item for item in overview.get("host_records", [])
                    if isinstance(item, dict)
                ]
                for item in records:
                    if item.get("address") == clean_address:
                        continue
                    duplicate = next((
                        domain for domain in clean_domains
                        if domain in item.get("domains", [])
                    ), "")
                    if duplicate:
                        raise TaskEngineError(
                            "invalid_params",
                            f"域名 {duplicate} 已解析到 {item.get('address', '')}。",
                        )
                current = next((
                    item for item in records if item.get("address") == clean_address
                ), {})
                params["address"] = clean_address
                params["domains"] = clean_domains
                facts = {
                    "目标 IP": clean_address,
                    "当前强制解析": "、".join(current.get("domains", [])) or "未配置",
                    "目标强制解析": "、".join(clean_domains) or "删除该 IP 的全部记录",
                    "订阅影响": "自动刷新全部 Clash/Stash 发布文件",
                    "通配符保护": "不得覆盖 VPS 稳定入口或动态 DNS 域名",
                }
                title = f"更新 {clean_address} 的全局强制解析"
            else:
                name = params.get("name")
                domains = params.get("domains")
                if not isinstance(name, str) or not ITEM_ID_PATTERN.fullmatch(name):
                    raise TaskEngineError("invalid_params", "节点名称格式不正确。")
                try:
                    clean_domains = normalize_domains(domains)
                    public_endpoint = self._runner.public_endpoint_status()
                    dynamic_dns = self._runner.duckdns_status()
                    validate_wildcard_conflicts(clean_domains, [
                        str(public_endpoint.get("fqdn", "")),
                        str(dynamic_dns.get("fqdn", "")),
                    ])
                except NodeDomainError as error:
                    raise TaskEngineError("invalid_params", str(error)) from error
                matches = [
                    item for item in nodes
                    if item.get("name") == name and item.get("kind") == "awg"
                ]
                if len(matches) != 1:
                    raise TaskEngineError("not_found", "普通 AWG 节点不存在。")
                for item in nodes:
                    if item.get("name") == name:
                        continue
                    duplicate = next((
                        domain for domain in clean_domains
                        if domain in item.get("domains", [])
                    ), "")
                    if duplicate:
                        raise TaskEngineError(
                            "invalid_params",
                            f"域名 {duplicate} 已属于节点 {item.get('name', '')}。",
                        )
                for item in overview.get("host_records", []):
                    if not isinstance(item, dict):
                        continue
                    duplicate = next((
                        domain for domain in clean_domains
                        if domain in item.get("domains", [])
                    ), "")
                    if duplicate:
                        raise TaskEngineError(
                            "invalid_params",
                            f"域名 {duplicate} 已解析到 {item.get('address', '')}。",
                        )
                params["domains"] = clean_domains
                subject = matches[0]
                facts = {
                    "节点": name,
                    "虚拟 IP": str(subject.get("address", "")),
                    "当前强制解析": "、".join(subject.get("domains", [])) or "未配置",
                    "目标强制解析": "、".join(clean_domains) or "清空全部记录",
                    "订阅影响": "自动刷新全部 Clash/Stash 发布文件",
                    "通配符保护": "不得覆盖 VPS 稳定入口或动态 DNS 域名",
                }
                title = f"更新节点 {name} 的订阅强制解析"
        elif protocol_action == "network.node.import":
            name = params.get("name")
            address = params.get("address")
            public_key = params.get("public_key")
            preshared_key = params.get("preshared_key")
            if (
                not isinstance(name, str) or not ITEM_ID_PATTERN.fullmatch(name)
                or not isinstance(address, str) or not isinstance(public_key, str)
                or not isinstance(preshared_key, str)
                or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public_key)
                or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", preshared_key)
            ):
                raise TaskEngineError("invalid_params", "AWG 公钥导入参数不正确。")
            if any(item.get("name") == name for item in nodes):
                raise TaskEngineError("invalid_params", "节点名称已经存在。")
            if address:
                try:
                    ipaddress.ip_address(address)
                except ValueError as error:
                    raise TaskEngineError("invalid_params", "节点地址无效。") from error
            try:
                decoded_public_key = base64.b64decode(public_key, validate=True)
                decoded_psk = base64.b64decode(preshared_key, validate=True)
            except (ValueError, binascii.Error) as error:
                raise TaskEngineError("invalid_params", "AWG 密钥编码无效。") from error
            if len(decoded_public_key) != 32 or len(decoded_psk) != 32:
                raise TaskEngineError("invalid_params", "AWG 密钥长度无效。")
            public_fingerprint = hashlib.sha256(decoded_public_key).hexdigest()[:16]
            sensitive_params = {"preshared_key": preshared_key}
            params["preshared_key"] = ""
            subject = {"name": name, "kind": "awg", "new": True, "custody": "client"}
            facts = {
                "节点": name, "类型": "普通双向节点", "操作": "导入",
                "默认授权": "全部节点和全部端口",
                "订阅发布": "登记成功后自动刷新全部订阅",
                "公钥指纹": public_fingerprint,
            }
            title = f"导入节点 {name}"
        elif protocol_action == "network.node.change":
            kind = params.get("kind")
            operation = params.get("operation")
            name = params.get("name")
            address = params.get("address")
            if (
                kind not in {"awg", "vless"}
                or operation not in {
                    "add", "enable", "disable", "remove", "set-management",
                    "compat-enable", "compat-disable", "clean-enable", "clean-disable",
                }
                or not isinstance(name, str)
                or not ITEM_ID_PATTERN.fullmatch(name)
                or not isinstance(address, str)
            ):
                raise TaskEngineError("invalid_params", "节点参数不正确。")
            if kind == "awg" and operation == "add":
                raise TaskEngineError(
                    "operation_forbidden",
                    "AWG 节点必须使用网页内置生成器或公钥导入。",
                )
            if operation == "set-management" and kind != "awg":
                raise TaskEngineError("invalid_params", "只有普通 AWG 节点可以设为管理入口。")
            if operation in {"compat-enable", "compat-disable"} and kind != "vless":
                raise TaskEngineError("invalid_params", "只有 VLESS 节点支持旧版 Stash 兼容。")
            matches = [item for item in nodes if item.get("name") == name]
            sensitive_params = None
            if operation == "add":
                if matches:
                    raise TaskEngineError("invalid_params", "节点名称已经存在。")
                if kind == "awg" and address:
                    try:
                        ipaddress.ip_address(address)
                    except ValueError as error:
                        raise TaskEngineError("invalid_params", "节点地址无效。") from error
                elif address:
                    raise TaskEngineError("invalid_params", "当前节点类型不接受地址。")
                subject: dict[str, Any] = {"name": name, "kind": kind, "new": True}
            elif operation == "set-management":
                if len(matches) != 1 or matches[0].get("kind") != "awg":
                    raise TaskEngineError("not_found", "目标普通节点不存在。")
                subject = matches[0]
                if overview.get("management_peer") == name or subject.get("protected") is True:
                    raise TaskEngineError("invalid_params", "该节点已经是管理入口。")
                if subject.get("state") != "已启用":
                    raise TaskEngineError("operation_forbidden", "只有已启用节点可以接管管理入口。")
                if subject.get("custody") != "client":
                    raise TaskEngineError(
                        "operation_forbidden", "新管理入口的节点凭据不符合安全要求。"
                    )
                management_port = overview.get("management_port")
                required_ports = {22}
                if isinstance(management_port, int) and 1 <= management_port <= 65535:
                    required_ports.add(management_port)
                has_management_access = subject.get("access_mode") == "unrestricted" or any(
                    permission.get("target") in {"all", "vps"}
                    and (
                        permission.get("network") == "all"
                        or (
                            permission.get("network") == "tcp"
                            and isinstance(permission.get("ports"), list)
                            and required_ports.issubset(set(permission["ports"]))
                        )
                    )
                    for permission in subject.get("permissions", [])
                    if isinstance(permission, dict)
                )
                if not has_management_access:
                    required_label = ",".join(str(port) for port in sorted(required_ports))
                    raise TaskEngineError(
                        "operation_forbidden",
                        f"新管理入口必须允许访问 VPS TCP {required_label}。",
                    )
                if address:
                    raise TaskEngineError("invalid_params", "管理入口转交不接受节点地址。")
            else:
                if len(matches) != 1 or matches[0].get("kind") != kind:
                    raise TaskEngineError("not_found", "节点不存在或类型不匹配。")
                subject = matches[0]
                if operation in {"disable", "remove"} and (
                    subject.get("protected") is True
                    or overview.get("management_peer") == name
                ):
                    raise TaskEngineError(
                        "operation_forbidden", "当前管理员节点或最后管理入口不能停用或删除。"
                    )
                if address:
                    raise TaskEngineError("invalid_params", "当前操作不接受节点地址。")
                if operation == "compat-enable" and subject.get("legacy_stash") is True:
                    raise TaskEngineError("invalid_params", "该节点已经启用旧版 Stash 兼容。")
                if operation == "compat-disable" and subject.get("legacy_stash") is not True:
                    raise TaskEngineError("invalid_params", "该节点尚未启用旧版 Stash 兼容。")
                if operation == "clean-enable" and subject.get("clean_mode") is True:
                    raise TaskEngineError("invalid_params", "该节点已经启用纯净模式。")
                if operation == "clean-disable" and subject.get("clean_mode") is not True:
                    raise TaskEngineError("invalid_params", "该节点尚未启用纯净模式。")
            labels = {
                "add": "新增", "enable": "启用", "disable": "停用", "remove": "删除",
                "set-management": "设为管理入口",
                "compat-enable": "启用旧版 Stash 兼容",
                "compat-disable": "关闭旧版 Stash 兼容",
                "clean-enable": "启用订阅纯净模式",
                "clean-disable": "关闭订阅纯净模式",
            }
            if operation == "set-management":
                facts = {
                    "原管理入口": str(overview.get("management_peer", "")),
                    "新管理入口": name,
                    "管理连接": "执行前再次核验节点状态与访问权限",
                }
            else:
                publication_effect = (
                    "提交后自动刷新全部订阅"
                    if operation in {
                        "add",
                        "compat-enable", "compat-disable", "clean-enable", "clean-disable",
                    }
                    else "本任务不会自动同步"
                )
                facts = {
                    "节点": name,
                    "类型": "普通双向节点" if kind == "awg" else "VLESS 受限节点",
                    "操作": labels[str(operation)],
                    "默认授权": "无内网访问授权" if kind == "vless" and operation == "add" else "保持现状",
                    "订阅发布": publication_effect,
                }
            title = f"{labels[str(operation)]}节点 {name}"
        else:
            operation = params.get("operation")
            client = params.get("client")
            target = params.get("target")
            ports = params.get("ports")
            network = params.get("network")
            if (
                operation not in {"allow", "deny"}
                or not isinstance(client, str)
                or not ITEM_ID_PATTERN.fullmatch(client)
                or not isinstance(target, str)
                or not isinstance(ports, str)
                or not isinstance(network, str)
            ):
                raise TaskEngineError("invalid_params", "访问授权参数不正确。")
            clients = [item for item in nodes if item.get("name") == client]
            targets = {
                item.get("name") for item in overview.get("targets", [])
                if isinstance(item, dict)
            }
            if len(clients) != 1 or clients[0].get("state") != "已启用":
                raise TaskEngineError("invalid_params", "只有已启用节点可以配置访问授权。")
            subject = clients[0]
            if target not in targets or target == client:
                raise TaskEngineError("not_found", "访问目标不存在或不能选择节点自身。")
            if network == "all":
                if ports:
                    raise TaskEngineError("invalid_params", "全部协议权限不接受端口列表。")
            elif network in {"tcp", "udp"}:
                if not ports:
                    raise TaskEngineError("invalid_params", "指定协议时必须填写端口。")
                try:
                    ports = format_ports(parse_ports(ports))
                except PortRangeError as error:
                    raise TaskEngineError("invalid_params", str(error)) from error
                params["ports"] = ports
            elif ports or network:
                raise TaskEngineError("invalid_params", "访问授权协议与端口不匹配。")

            desired_network = network or "all"
            desired_ports = parse_ports(ports) if ports else []
            permissions = [
                permission for permission in subject.get("permissions", [])
                if isinstance(permission, dict)
            ]

            def matches_rule(permission: dict[str, Any]) -> bool:
                return (
                    permission.get("target") == target
                    and permission.get("network") == desired_network
                    and permission.get("ports") == desired_ports
                )

            if operation == "allow" and any(matches_rule(permission) for permission in permissions):
                raise TaskEngineError("invalid_params", "相同的访问权限已经存在。")
            if operation == "deny" and network and not any(
                matches_rule(permission) for permission in permissions
            ):
                raise TaskEngineError("not_found", "要删除的访问权限已经不存在。")

            removes_default_access = (
                operation == "deny"
                and target == "all"
                and subject.get("access_mode") == "unrestricted"
                and (not network or network == "all")
            )
            if removes_default_access and subject.get("kind") == "awg" and subject.get("protected") is True:
                management_port = overview.get("management_port")
                required_ports = {22}
                if isinstance(management_port, int) and 1 <= management_port <= 65535:
                    required_ports.add(management_port)
                remaining_permissions = [
                    permission for permission in permissions
                    if not (
                        permission.get("target") == target
                        if not network
                        else matches_rule(permission)
                    )
                ]
                preserves_management = any(
                    permission.get("target") in {"all", "vps"}
                    and permission.get("network") in {"all", "tcp"}
                    and isinstance(permission.get("ports"), list)
                    and (
                        permission.get("network") == "all"
                        or required_ports.issubset(set(permission["ports"]))
                    )
                    for permission in remaining_permissions
                )
                if not preserves_management:
                    required_label = ",".join(str(port) for port in sorted(required_ports))
                    raise TaskEngineError(
                        "operation_forbidden",
                        f"管理入口撤销全部访问前，必须先允许访问 VPS TCP {required_label}。",
                    )
            title = f"{'新增' if operation == 'allow' else '删除'}访问权限"
            facts = {
                "来源节点": client,
                "节点类型": "普通 AWG" if subject.get("kind") == "awg" else "VLESS",
                "目标": "全部节点" if target == "all" else target,
                "协议": desired_network.upper() if desired_network != "all" else "全部协议",
                "端口": ports or ("该目标全部规则" if operation == "deny" and not network else "全部端口"),
            }
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            preview={
                "title": title,
                "summary": "执行前会重新核验节点、目标、协议、端口和管理入口事实。",
                "facts": facts,
            },
            fact_digest=self._network_fact_digest(params, overview),
            timeout_seconds=definition.timeout_seconds,
            sensitive_params=sensitive_params,
        )

    def _prepare_subscription_task(
        self, protocol_action: str, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        params = {**arguments, "actor": actor, "confirmed": True}
        try:
            definition = validate_action_request(protocol_action, params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        overview = self._runner.network_overview()
        items = [
            item for item in overview.get("subscription_items", [])
            if isinstance(item, dict)
        ]
        if protocol_action == "network.subscriptions.sync":
            if arguments:
                raise TaskEngineError("invalid_params", "订阅同步不接受额外参数。")
            affected = [item for item in items if item.get("state") != "发布已停用"]
            retained = [item for item in affected if item.get("published") is True]
            pending = [item for item in affected if item.get("published") is not True]
            title = "同步全部发布订阅"
            facts = {
                "受影响订阅": self._item_names(affected),
                "保留现有链接": self._item_names(retained),
                "新增或刷新": self._item_names(pending),
                "停用发布": "不变",
            }
        else:
            name = params.get("name")
            if not isinstance(name, str) or not ITEM_ID_PATTERN.fullmatch(name):
                raise TaskEngineError("invalid_params", "订阅名称格式不正确。")
            matches = [item for item in items if item.get("name") == name]
            if len(matches) != 1:
                raise TaskEngineError("not_found", "发布订阅不存在。")
            item = matches[0]
            if protocol_action == "network.subscription.rotate":
                if set(arguments) != {"name"} or item.get("published") is not True:
                    raise TaskEngineError("operation_forbidden", "只有正在发布的订阅可以轮换令牌。")
                title = f"轮换 {name} 的订阅令牌"
                facts = {
                    "受影响订阅": name,
                    "当前状态": item.get("state", "未知"),
                    "旧链接": "成功后立即失效",
                    "其他订阅": "不变",
                }
            else:
                state = params.get("state")
                if set(arguments) != {"name", "state"} or state not in {"enabled", "disabled"}:
                    raise TaskEngineError("invalid_params", "发布状态参数不正确。")
                title = f"{'恢复' if state == 'enabled' else '停用'} {name} 的订阅发布"
                facts = {
                    "受影响订阅": name,
                    "当前状态": item.get("state", "未知"),
                    "目标状态": "恢复发布并生成新链接" if state == "enabled" else "停止提供链接",
                    "节点网络状态": "不变",
                }
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            preview={
                "title": title,
                "summary": "预览只显示订阅名称和发布影响，不包含访问令牌或完整链接。",
                "facts": facts,
            },
            fact_digest=self._network_fact_digest(params, overview),
            timeout_seconds=definition.timeout_seconds,
        )

    def _prepare_backup_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        if set(arguments) != {"operation", "backup_id", "passphrase"}:
            raise TaskEngineError("invalid_params", "备份任务参数不正确。")
        operation = arguments.get("operation")
        backup_id = arguments.get("backup_id")
        passphrase = arguments.get("passphrase")
        if operation not in {"create", "verify", "delete"}:
            raise TaskEngineError("operation_forbidden", "该备份动作尚未接入异步任务。")
        if not isinstance(backup_id, str) or (
            operation in {"verify", "delete"}
            and not BACKUP_ID_PATTERN.fullmatch(backup_id)
        ) or (operation == "create" and backup_id):
            raise TaskEngineError("invalid_params", "备份标识格式不正确。")
        if not isinstance(passphrase, str) or (
            operation in {"create", "verify"}
            and (not 16 <= len(passphrase) <= 256 or "\x00" in passphrase)
        ) or (operation == "delete" and passphrase):
            raise TaskEngineError("invalid_params", "恢复口令格式不正确。")
        catalog_params = {
            "operation": operation,
            "backup_id": backup_id,
            "passphrase": passphrase,
            "actor": actor,
            "confirmed": True,
        }
        try:
            definition = validate_action_request("backup.manage", catalog_params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        listing = self._runner.manage_backup("list", "", "", actor)
        matches = [
            item for item in listing.get("items", [])
            if isinstance(item, dict) and item.get("backup_id") == backup_id
        ]
        if operation in {"verify", "delete"} and len(matches) != 1:
            raise TaskEngineError("not_found", "配置备份不存在。")
        subject = matches[0] if matches else {"existing_count": len(listing.get("items", []))}
        labels = {"create": "创建加密配置备份", "verify": "校验配置备份", "delete": "删除配置备份"}
        if operation == "create":
            facts = {
                "现有备份": f"{len(listing.get('items', []))} 份",
                "加密方式": "AES-256-GCM",
                "任务状态与加密载荷": "不纳入备份",
            }
        else:
            facts = {
                "备份标识": backup_id,
                "创建时间": subject.get("created_at", "未知"),
                "大小": f"{subject.get('size', 0)} 字节",
                "加密方式": subject.get("cipher", "未知"),
            }
        return PreparedAction(
            canonical_action=definition.name,
            params={
                "operation": operation,
                "backup_id": backup_id,
                "passphrase": "",
                "actor": actor,
                "confirmed": True,
            },
            preview={
                "title": labels[str(operation)],
                "summary": "任务在后台执行；恢复口令只保存在 root 机器密钥加密的短期载荷中。",
                "facts": facts,
            },
            fact_digest=self._backup_fact_digest(operation, backup_id, subject, listing),
            timeout_seconds=definition.timeout_seconds,
            sensitive_params=(
                {"passphrase": passphrase}
                if operation in {"create", "verify"} else None
            ),
        )

    def _prepare_restore_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        if set(arguments) != {"operation", "backup_id", "passphrase", "session_id"}:
            raise TaskEngineError("invalid_params", "配置恢复任务参数不正确。")
        operation = arguments.get("operation")
        backup_id = arguments.get("backup_id")
        passphrase = arguments.get("passphrase")
        session_id = arguments.get("session_id")
        if operation not in {"restore_apply", "restore_confirm", "restore_rollback"}:
            raise TaskEngineError("operation_forbidden", "配置恢复动作未登记。")
        if not isinstance(session_id, str) or not SESSION_ID_PATTERN.fullmatch(session_id):
            raise TaskEngineError("invalid_params", "独立连接标识无效。")
        if operation == "restore_apply":
            if not isinstance(backup_id, str) or not BACKUP_ID_PATTERN.fullmatch(backup_id):
                raise TaskEngineError("invalid_params", "备份标识格式不正确。")
            if (
                not isinstance(passphrase, str)
                or not 16 <= len(passphrase) <= 256
                or any(char in passphrase for char in ("\x00", "\r", "\n"))
            ):
                raise TaskEngineError("invalid_params", "恢复口令格式不正确。")
        elif backup_id != "" or passphrase != "":
            raise TaskEngineError("invalid_params", "确认和回滚不接受备份标识或口令。")
        params = {
            "operation": operation, "backup_id": backup_id,
            "passphrase": passphrase, "session_id": session_id,
            "actor": actor, "confirmed": True,
        }
        try:
            definition = validate_action_request("backup.restore.change", params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        listing = self._runner.manage_backup("list", "", "", actor, session_id)
        if operation == "restore_apply":
            matches = [
                item for item in listing.get("items", [])
                if isinstance(item, dict) and item.get("backup_id") == backup_id
            ]
            if len(matches) != 1:
                raise TaskEngineError("not_found", "配置备份不存在。")
            status = self._runner.manage_backup(
                "restore_status", "", "", actor, session_id
            )
            if status.get("state") != "idle":
                raise TaskEngineError("operation_forbidden", "已有待确认配置恢复，请先确认或回滚。")
            if not status.get("writes_enabled"):
                raise TaskEngineError("operation_forbidden", "当前主机未启用配置恢复写入。")
            try:
                preview = self._runner.manage_backup(
                    "preview_restore", str(backup_id), str(passphrase), actor,
                    session_id,
                )
            except RuntimeError as error:
                raise TaskEngineError(
                    "invalid_params", "恢复口令错误或备份不可用。"
                ) from error
            categories = matches[0].get("categories", [])
            facts = {
                "备份标识": str(backup_id),
                "覆盖类别": "、".join(str(item) for item in categories) or "无",
                "变更数量": str(preview.get("changed_count", 0)),
                "在线生效": str(preview.get("online_changed_count", 0)),
                "需离线处理": str(preview.get("offline_changed_count", 0)),
                "自动回滚期限": f"{status.get('rollback_seconds', 300)} 秒",
            }
            title = "应用配置备份并启动自动回滚"
            subject: dict[str, Any] = {
                "backup": matches[0], "preview": preview, "status": status,
            }
        else:
            status = self._runner.manage_backup(
                "restore_status", "", "", actor, session_id
            )
            if status.get("state") != "pending":
                raise TaskEngineError("operation_forbidden", "当前没有待确认配置恢复。")
            if operation == "restore_confirm" and not status.get("independent_session"):
                raise TaskEngineError(
                    "operation_forbidden", "必须从另一条独立登录连接确认配置恢复。"
                )
            facts = {
                "备份标识": status.get("backup_id", "未知"),
                "已变更": str(status.get("changed_count", 0)),
                "覆盖类别": "、".join(str(item) for item in status.get("categories", [])) or "无",
                "剩余回滚时间": f"{status.get('remaining_seconds', 0)} 秒",
                "独立连接": "确认必须来自另一条独立登录连接",
            }
            title = "确认保留配置恢复" if operation == "restore_confirm" else "立即回滚配置恢复"
            subject = {"status": status}
        task_params = dict(params)
        task_params["passphrase"] = ""
        return PreparedAction(
            canonical_action=definition.name,
            params=task_params,
            preview={
                "title": title,
                "summary": "恢复由独立 systemd 计时器保护；任务中断不会自动重新应用备份。",
                "facts": facts,
            },
            fact_digest=self._backup_restore_digest(params, listing, subject),
            timeout_seconds=definition.timeout_seconds,
            sensitive_params=(
                {"passphrase": passphrase} if operation == "restore_apply" else None
            ),
        )

    @staticmethod
    def _backup_restore_digest(
        params: dict[str, object], listing: dict[str, Any], subject: dict[str, Any]
    ) -> str:
        stable_subject = json.loads(json.dumps(subject, ensure_ascii=False))
        status = stable_subject.get("status")
        if isinstance(status, dict):
            status.pop("remaining_seconds", None)
            status.pop("expires_at", None)
        source = {
            "params": {
                key: value for key, value in params.items()
                if key not in {"actor", "confirmed", "session_id", "passphrase"}
            },
            "listing": listing.get("items", []),
            "subject": stable_subject,
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    def _prepare_firewall_port_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        expected = {
            "operation", "port", "scope", "protocol", "duration_seconds"
        }
        if set(arguments) != expected:
            raise TaskEngineError("invalid_params", "自定义端口任务参数不正确。")
        params = {**arguments, "actor": actor, "confirmed": True}
        try:
            definition = validate_action_request("firewall.port.change", params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        operation = params.get("operation")
        port = params.get("port")
        scope = params.get("scope")
        protocol = params.get("protocol")
        duration = params.get("duration_seconds")
        if (
            operation not in {"open", "close"}
            or not isinstance(port, int) or isinstance(port, bool)
            or not 1 <= port <= 65535
            or scope not in {"public", "amneziawg"}
            or protocol not in {"tcp", "udp", "both"}
            or not isinstance(duration, int) or isinstance(duration, bool)
            or (operation == "open" and duration != 0 and not 60 <= duration <= 604800)
            or (operation == "close" and duration != 0)
        ):
            raise TaskEngineError("invalid_params", "自定义端口参数不正确。")
        current = self._runner.firewall_ports()
        inventory = self._runner.service_inventory("firewall")
        protocols = {"tcp", "udp"} if protocol == "both" else {str(protocol)}
        base_protocols = {
            item_protocol for item_protocol in protocols
            if self._firewall_inventory_has_port(inventory, str(scope), item_protocol, port)
        }
        matches = [
            item for item in current.get("items", [])
            if isinstance(item, dict)
            and item.get("scope") == scope
            and item.get("protocol") in protocols
            and item.get("port") == port
        ]
        if base_protocols:
            raise TaskEngineError(
                "operation_forbidden",
                "该端口已由基础策略或托管服务使用，不能作为自定义端口变更。",
            )
        if operation == "close" and not matches:
            raise TaskEngineError("not_found", "自定义端口规则不存在。")
        scope_label = "公网" if scope == "public" else "AmneziaWG 内网"
        protocol_label = str(protocol).upper().replace("BOTH", "TCP + UDP")
        if operation == "open":
            duration_label = "永久" if duration == 0 else f"{duration} 秒"
            title = f"开放 {scope_label} {protocol_label} {port}"
        else:
            duration_label = "立即关闭"
            title = f"关闭 {scope_label} {protocol_label} {port}"
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            preview={
                "title": title,
                "summary": "执行后会同时核验自定义端口事实配置与 nftables 实际集合。",
                "facts": {
                    "端口": str(port), "访问范围": scope_label,
                    "协议": protocol_label, "期限": duration_label,
                    "现有占用": self._firewall_match_summary(matches),
                    "基础策略或托管服务": "未占用",
                },
            },
            fact_digest=self._firewall_fact_digest(params, current, inventory),
            timeout_seconds=definition.timeout_seconds,
        )

    def _prepare_managed_port_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        if set(arguments) != {"target_id", "port"}:
            raise TaskEngineError("invalid_params", "服务端口任务参数不正确。")
        params = {**arguments, "actor": actor, "confirmed": True}
        try:
            definition = validate_action_request("managed.port.change", params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        target_id = params.get("target_id")
        port = params.get("port")
        if (
            target_id not in {"clash", "file", "awg-backup1", "awg-backup2"}
            or not isinstance(port, int) or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            raise TaskEngineError("invalid_params", "服务端口参数不正确。")
        overview = self._runner.managed_ports()
        item = next(
            (value for value in overview.get("items", []) if value.get("id") == target_id),
            None,
        )
        if not isinstance(item, dict) or not item.get("installed"):
            raise TaskEngineError("not_found", "对应服务尚未安装。")
        maximum = int(item.get("maximum", 65535))
        if not int(item.get("minimum", 1)) <= port <= maximum:
            raise TaskEngineError("invalid_params", f"该端口必须在 1–{maximum} 之间。")
        if item.get("port") == port:
            raise TaskEngineError("invalid_params", "新端口与当前端口相同。")
        conflicts = [
            value for value in overview.get("items", [])
            if isinstance(value, dict) and value.get("id") != target_id
            and value.get("installed") and value.get("protocol") == item.get("protocol")
            and value.get("port") == port
        ]
        conflicts.extend(
            value for value in overview.get("occupied", [])
            if isinstance(value, dict) and value.get("id") != {
                "clash": "clash-subscription", "file": "file-service",
                "awg-backup1": "amneziawg-backup1", "awg-backup2": "amneziawg-backup2",
            }[str(target_id)]
            and value.get("protocol") == item.get("protocol") and value.get("port") == port
        )
        if conflicts:
            raise TaskEngineError("conflict", "该端口已被同协议服务占用。")
        params["_revision"] = str(overview.get("revision", ""))
        restart = "会短暂重启该下载服务" if item.get("restart_required") else "不会重启 AWG 主隧道"
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            preview={
                "title": f"修改{item.get('label', '服务端口')}",
                "summary": f"将同步更新端口事实和主机防火墙；{restart}。",
                "facts": {
                    "当前端口": f"{item.get('port')}/{str(item.get('protocol')).upper()}",
                    "新端口": f"{port}/{str(item.get('protocol')).upper()}",
                    "开放范围": "公网",
                    "客户端影响": str(item.get("impact", "")),
                },
            },
            fact_digest=self._managed_port_fact_digest(params, overview),
            timeout_seconds=definition.timeout_seconds,
        )

    def _prepare_security_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        normalized_arguments = dict(arguments)
        transaction_type = arguments.get("transaction_type")
        expected = {"transaction_type", "operation", "session_id"}
        if transaction_type != "vless_listener":
            expected.update({"public_ip", "public_port"})
        if set(arguments) != expected:
            raise TaskEngineError("invalid_params", "安全事务任务参数不正确。")
        operation = arguments.get("operation")
        session_id = arguments.get("session_id")
        public_ip = arguments.get("public_ip", "")
        public_port = arguments.get("public_port", "")
        if transaction_type not in {
            "ssh_auth", "ssh_listener", "firewall", "vless_listener",
        }:
            raise TaskEngineError("operation_forbidden", "安全事务未登记。")
        if operation not in {"apply", "confirm", "rollback"}:
            raise TaskEngineError("invalid_params", "安全事务动作未登记。")
        if not isinstance(session_id, str) or not SESSION_ID_PATTERN.fullmatch(session_id):
            raise TaskEngineError("invalid_params", "独立连接标识无效。")
        if not isinstance(public_ip, str) or not isinstance(public_port, str):
            raise TaskEngineError("invalid_params", "SSH 监听参数格式不正确。")
        if transaction_type == "ssh_listener" and operation == "apply":
            if not public_ip:
                endpoint = self._runner.public_endpoint_status()
                detected = endpoint.get("current_ipv4", "")
                if not isinstance(detected, str) or not detected:
                    diagnostics = "、".join(
                        str(item) for item in endpoint.get("diagnostics", [])
                    )
                    raise TaskEngineError(
                        "invalid_params",
                        diagnostics or "无法自动检测本机公网 SSH IPv4。",
                    )
                public_ip = detected
                normalized_arguments["public_ip"] = public_ip
            try:
                address = ipaddress.ip_address(public_ip)
            except ValueError as error:
                raise TaskEngineError("invalid_params", "公网 SSH IPv4 无效。") from error
            if address.version != 4 or (
                not public_port.isdigit()
                or not 1024 <= int(public_port) <= 65535
                or 32768 <= int(public_port) <= 60999
            ):
                raise TaskEngineError("invalid_params", "公网 SSH 端口无效或位于临时端口范围。")
        elif public_ip or public_port:
            raise TaskEngineError("invalid_params", "当前安全事务不接受 SSH 监听参数。")
        params = {**normalized_arguments, "actor": actor, "confirmed": True}
        try:
            definition = validate_action_request("security.transaction.change", params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        read_operation = "preview" if operation == "apply" else "status"
        transaction = self._runner.manage_transaction(
            str(transaction_type), read_operation, actor, session_id,
            public_ip, public_port,
        )
        if operation == "apply":
            if transaction.get("state") != "idle":
                raise TaskEngineError("operation_forbidden", "已有待确认事务，请先确认或回滚。")
            if not transaction.get("writes_enabled") or not transaction.get("ready"):
                blockers = "、".join(str(item) for item in transaction.get("blockers", []))
                raise TaskEngineError(
                    "operation_forbidden", blockers or "当前主机未启用高风险安全变更。"
                )
        else:
            if transaction.get("state") != "pending":
                raise TaskEngineError("operation_forbidden", "当前没有待确认的安全事务。")
            if operation == "confirm" and not transaction.get("independent_session"):
                raise TaskEngineError(
                    "operation_forbidden", "必须从另一条独立登录连接确认，原发起会话不能确认。"
                )
        labels = {
            "ssh_auth": "SSH 仅公钥认证",
            "ssh_listener": "SSH 公网/内网监听",
            "firewall": "nftables 主机防火墙",
            "vless_listener": "VLESS 公网监听迁移",
        }
        operation_labels = {"apply": "应用", "confirm": "确认保留", "rollback": "立即回滚"}
        facts = {
            "安全事务": labels[str(transaction_type)],
            "操作": operation_labels[str(operation)],
            "自动回滚期限": f"{transaction.get('rollback_seconds', 300)} 秒",
            "独立连接": "最终确认必须来自另一条独立登录连接",
            "验证项目": "、".join(str(item) for item in transaction.get("verifications", [])),
        }
        if transaction_type == "ssh_listener" and operation == "apply":
            facts["公网监听"] = f"{public_ip}:{public_port}"
            facts["AWG 监听"] = "保持 22 端口"
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            preview={
                "title": f"{operation_labels[str(operation)]} {labels[str(transaction_type)]}",
                "summary": "任务由独立 systemd 回滚计时器保护；关闭网页、网络中断或管理代理重启都不会取消自动回滚。",
                "facts": facts,
                "changes": transaction.get("changes", []),
            },
            fact_digest=self._security_fact_digest(params, transaction),
            timeout_seconds=definition.timeout_seconds,
            supports_rollback=definition.supports_rollback,
        )

    @staticmethod
    def _security_fact_digest(
        params: dict[str, object], transaction: dict[str, Any]
    ) -> str:
        stable_transaction = {
            key: transaction.get(key)
            for key in (
                "transaction_type", "state", "writes_enabled", "rollback_seconds",
                "changes", "verifications", "ready", "blockers", "independent_session",
                "transaction_id", "last_outcome",
            )
        }
        source = {
            "params": {
                key: value for key, value in params.items()
                if key not in {"actor", "confirmed", "session_id"}
            },
            "transaction": stable_transaction,
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _item_names(items: list[dict[str, Any]]) -> str:
        names = [str(item.get("name")) for item in items if item.get("name")]
        return "、".join(names) if names else "无"

    def execute_task_action(
        self, protocol_action: str, params: dict[str, object]
    ) -> dict[str, object]:
        """执行任务模块已持久化的登记动作。"""

        self._read_model.invalidate()

        try:
            definition = validate_action_request(
                protocol_action,
                self._catalog_params_for_task(protocol_action, params),
            )
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        if not definition.task_only:
            raise TaskEngineError("operation_forbidden", "该动作不是受管主机变更。")
        if protocol_action == "ssh.key.change" and params.get("operation") == "add":
            public_key = params.get("public_key")
            if not isinstance(public_key, str):
                raise TaskEngineError("invalid_params", "SSH 公钥载荷不存在。")
            preview = self._runner.preview_ssh_key(public_key, str(params.get("actor", "")))
            if preview.get("fingerprint") != params.get("_fingerprint"):
                raise TaskEngineError("facts_changed", "SSH 公钥指纹已变化。")
            return self._runner.change_ssh_key(
                "add", str(preview["pending_token"]), "", str(params["actor"])
            )
        if protocol_action == "security.transaction.change":
            result = self._runner.manage_transaction(
                str(params.get("transaction_type", "")),
                str(params.get("operation", "")),
                str(params.get("actor", "")),
                str(params.get("session_id", "")),
                str(params.get("public_ip", "")),
                str(params.get("public_port", "")),
            )
            return {**result, "operation": params.get("operation")}
        if protocol_action == "backup.restore.change":
            result = self._runner.manage_backup(
                str(params.get("operation", "")),
                str(params.get("backup_id", "")),
                str(params.get("passphrase", "")),
                str(params.get("actor", "")),
                str(params.get("session_id", "")),
            )
            return {**result, "operation": params.get("operation")}
        actor = str(params.get("actor", ""))
        if protocol_action == "service.change":
            service_id = self._service_id(params.get("service_id"))
            operation = str(params.get("operation", ""))
            before = self._describe_service(
                self._runner.snapshot(), service_id,
                self._runner.service_inventory(service_id),
            )
            if operation not in before["allowed_operations"]:
                raise TaskEngineError(
                    "operation_forbidden", "当前服务不允许执行该操作。"
                )
            latest = self._runner.change_service(service_id, operation, actor)
            after = self._describe_service(
                latest, service_id, self._runner.service_inventory(service_id)
            )
            return {"service": after["service"], "operation": operation}
        if protocol_action == "network.proxy.update":
            values = {
                key: params.get(key) for key in {
                    "operation", "airport_id", "airport_name", "airport_url",
                    "airport_enabled", "countries", "exit_id", "exit_name",
                    "exit_default", "exit_proxy_yaml", "awg_name", "exit_ids",
                }
            }
            return self._runner.update_proxy_resources(values, actor)
        if protocol_action == "network.duckdns.change":
            return self._runner.change_duckdns(
                str(params.get("operation", "")), str(params.get("provider", "")),
                str(params.get("fqdn", "")), str(params.get("token", "")),
                str(params.get("secret_id", "")),
                str(params.get("secret_key", "")), str(params.get("zone", "")), actor,
            )
        if protocol_action == "file.resource.change":
            return self._runner.change_file_resource(
                str(params.get("operation", "")),
                str(params.get("upload_id", "")),
                str(params.get("download_name", "")),
                bool(params.get("cdn_cache")), int(params.get("cache_ttl", 0)),
                str(params.get("resource_id", "")), actor,
            )
        if protocol_action == "ssh.key.change":
            return self._runner.change_ssh_key(
                str(params.get("operation", "")), str(params.get("item_id", "")),
                str(params.get("name", "")).strip(), actor,
            )
        if protocol_action == "network.node.change":
            return self._runner.change_network_node(
                str(params.get("kind", "")), str(params.get("operation", "")),
                str(params.get("name", "")), str(params.get("address", "")), actor,
            )
        if protocol_action == "network.node.import":
            return self._runner.import_network_node(
                str(params.get("name", "")), str(params.get("address", "")),
                str(params.get("public_key", "")), str(params.get("preshared_key", "")), actor,
            )
        if protocol_action == "network.node.domains":
            domains = params.get("domains", [])
            if not isinstance(domains, list):
                raise TaskEngineError("invalid_params", "节点域名参数不正确。")
            return self._runner.change_node_domains(
                str(params.get("name", "")), [str(item) for item in domains], actor
            )
        if protocol_action == "network.address.domains":
            domains = params.get("domains", [])
            if not isinstance(domains, list):
                raise TaskEngineError("invalid_params", "自定义强制解析参数不正确。")
            return self._runner.change_address_domains(
                str(params.get("address", "")), [str(item) for item in domains], actor
            )
        if protocol_action == "network.public_endpoint.change":
            return self._runner.change_public_endpoint(
                str(params.get("operation", "")), str(params.get("fqdn", "")), actor,
                str(params.get("session_id", "")), str(params.get("transaction_id", "")),
            )
        if protocol_action == "network.permission.change":
            return self._runner.change_network_permission(
                str(params.get("operation", "")), str(params.get("client", "")),
                str(params.get("target", "")), str(params.get("ports", "")),
                str(params.get("network", "")), actor,
            )
        if protocol_action == "network.permission.batch":
            return self._runner.add_network_permissions(
                str(params.get("client", "")), normalize_rules(params.get("rules")), actor,
            )
        if protocol_action == "network.subscriptions.sync":
            return self._runner.sync_network_subscriptions(actor)
        if protocol_action == "network.subscription.rotate":
            return self._runner.rotate_network_subscription(
                str(params.get("name", "")), actor
            )
        if protocol_action == "network.subscription.state":
            return self._runner.set_network_subscription_state(
                str(params.get("name", "")), str(params.get("state", "")), actor
            )
        if protocol_action == "backup.manage":
            return self._runner.manage_backup(
                str(params.get("operation", "")), str(params.get("backup_id", "")),
                str(params.get("passphrase", "")), actor,
            )
        if protocol_action == "firewall.port.change":
            return self._runner.change_firewall_port(
                str(params.get("operation", "")), int(params.get("port", 0)),
                str(params.get("scope", "")), str(params.get("protocol", "")),
                int(params.get("duration_seconds", 0)), actor,
            )
        if protocol_action == "managed.port.change":
            return self._runner.change_managed_port(
                str(params.get("target_id", "")), int(params.get("port", 0)),
                str(params.get("_revision", "")), actor,
            )
        if protocol_action == "deployment.install":
            value_fields = {
                "port", "server_name", "airport_url",
                "exit_proxy_yaml", "upload_id", "download_name",
            }
            values = {key: str(params.get(key, "")) for key in value_fields}
            return self._runner.deploy_service(
                str(params.get("service_id", "")), values, actor
            )
        raise TaskEngineError("operation_forbidden", "该动作尚未接入异步任务。")

    @staticmethod
    def _catalog_params_for_task(
        protocol_action: str, params: dict[str, object]
    ) -> dict[str, object]:
        """删除任务引擎内部事实字段，恢复动作目录定义的参数集合。"""

        catalog = {
            key: value for key, value in params.items() if not key.startswith("_")
        }
        if protocol_action == "ssh.key.change":
            catalog.pop("public_key", None)
        return catalog

    def inspect_task_action(
        self, protocol_action: str, params: dict[str, object]
    ) -> dict[str, object]:
        """执行前或崩溃恢复时重新读取事实，不触发任何变更。"""

        # 执行后核验与崩溃恢复都必须绕过变更前的进程内只读缓存。
        self._read_model.invalidate()

        if protocol_action == "network.proxy.update":
            current = self._runner.proxy_resources()
            return {
                "fact_digest": self._proxy_fact_digest(current),
                "verified": True,
                "configured": bool(current.get("configured")),
            }
        if protocol_action == "network.duckdns.change":
            current = self._runner.duckdns_status()
            return {
                "fact_digest": self._duckdns_fact_digest(params, current),
                "verified": True,
            }
        if protocol_action == "file.resource.change":
            operation = params.get("operation")
            current = self._runner.file_resources()
            if operation == "add":
                subject = self._runner.file_upload_facts(str(params.get("upload_id", "")))
            else:
                matches = [
                    item for item in current.get("items", [])
                    if item.get("resource_id") == params.get("resource_id")
                ]
                subject = matches[0] if len(matches) == 1 else {"missing": True}
            clean_params = {
                key: value for key, value in params.items() if not key.startswith("_")
            }
            return {
                "fact_digest": self._file_fact_digest(clean_params, subject, current),
                "verified": True,
                "resource_present": not bool(subject.get("missing")),
            }
        if protocol_action == "ssh.key.change":
            listing = self._runner.ssh_keys()
            return {
                "fact_digest": self._ssh_key_fact_digest(params, listing),
                "verified": True,
            }
        if protocol_action == "backup.manage":
            actor = str(params.get("actor", ""))
            operation = str(params.get("operation", ""))
            backup_id = str(params.get("backup_id", ""))
            listing = self._runner.manage_backup("list", "", "", actor)
            matches = [
                item for item in listing.get("items", [])
                if isinstance(item, dict) and item.get("backup_id") == backup_id
            ]
            if matches:
                subject = matches[0]
            elif operation == "create":
                subject = {"existing_count": len(listing.get("items", []))}
            else:
                subject = {"missing": True}
            return {
                "fact_digest": self._backup_fact_digest(
                    operation, backup_id, subject, listing
                ),
                "verified": True,
                "backup_present": len(matches) == 1,
            }
        if protocol_action == "firewall.port.change":
            current = self._runner.firewall_ports()
            inventory = self._runner.service_inventory("firewall")
            return {
                "fact_digest": self._firewall_fact_digest(params, current, inventory),
                "verified": True,
            }
        if protocol_action == "managed.port.change":
            current = self._runner.managed_ports()
            return {
                "fact_digest": self._managed_port_fact_digest(params, current),
                "verified": True,
            }
        if protocol_action == "deployment.install":
            snapshot = self._runner.snapshot()
            service_id = str(params.get("service_id", ""))
            matches = [
                item for item in snapshot.get("services", [])
                if isinstance(item, dict) and item.get("id") == service_id
            ]
            current = matches[0] if len(matches) == 1 else {"missing": True}
            upload_facts = None
            if service_id == "file":
                upload_facts = self._runner.file_upload_facts(
                    str(params.get("upload_id", ""))
                )
            return {
                "fact_digest": self._deployment_fact_digest(
                    params, snapshot, current, upload_facts
                ),
                "verified": True,
            }
        if protocol_action == "security.transaction.change":
            transaction = self._runner.manage_transaction(
                str(params.get("transaction_type", "")), "status",
                str(params.get("actor", "")), str(params.get("session_id", "")),
                str(params.get("public_ip", "")), str(params.get("public_port", "")),
            )
            inspection = {
                "fact_digest": self._security_fact_digest(params, transaction),
                "verified": True,
                "state": transaction.get("state"),
            }
            if params.get("transaction_type") == "vless_listener":
                inspection.update({
                    "transaction_id": transaction.get("transaction_id"),
                    "last_outcome": transaction.get("last_outcome"),
                    "expires_at": transaction.get("expires_at"),
                    "remaining_seconds": transaction.get("remaining_seconds"),
                    "rollback_seconds": transaction.get("rollback_seconds"),
                })
            return inspection
        if protocol_action == "backup.restore.change":
            actor = str(params.get("actor", ""))
            session_id = str(params.get("session_id", ""))
            operation = str(params.get("operation", ""))
            listing = self._runner.manage_backup("list", "", "", actor, session_id)
            status = self._runner.manage_backup(
                "restore_status", "", "", actor, session_id
            )
            if operation == "restore_apply":
                matches = [
                    item for item in listing.get("items", [])
                    if isinstance(item, dict)
                    and item.get("backup_id") == params.get("backup_id")
                ]
                preview = self._runner.manage_backup(
                    "preview_restore", str(params.get("backup_id", "")),
                    str(params.get("passphrase", "")), actor, session_id,
                )
                subject = {
                    "backup": matches[0] if len(matches) == 1 else {"missing": True},
                    "preview": preview, "status": status,
                }
            else:
                subject = {"status": status}
            return {
                "fact_digest": self._backup_restore_digest(params, listing, subject),
                "verified": True,
                "state": status.get("state"),
            }
        if protocol_action in {
            "network.node.change",
            "network.node.import",
            "network.node.domains",
            "network.address.domains",
            "network.permission.change",
            "network.permission.batch",
            "network.subscriptions.sync",
            "network.subscription.rotate",
            "network.subscription.state",
            "network.public_endpoint.change",
        }:
            if protocol_action == "network.public_endpoint.change":
                overview = self._runner.public_endpoint_transaction_status(
                    str(params.get("actor", "")), str(params.get("session_id", ""))
                )
                return {
                    "fact_digest": self._public_endpoint_digest(params, overview),
                    "verified": True,
                    "state": overview.get("state"),
                    "last_outcome": overview.get("last_outcome"),
                    "expires_at": overview.get("expires_at"),
                    "remaining_seconds": overview.get("remaining_seconds"),
                    "rollback_seconds": overview.get("rollback_seconds"),
                    "transaction_id": overview.get("transaction_id"),
                }
            overview = self._runner.network_overview()
            return {
                "fact_digest": self._network_fact_digest(params, overview),
                "verified": True,
            }
        if protocol_action != "service.change":
            raise TaskEngineError("operation_forbidden", "该动作尚未接入事实核验。")
        service_id = self._service_id(params.get("service_id"))
        operation = params.get("operation")
        if operation not in {"start", "stop", "restart"}:
            raise TaskEngineError("invalid_params", "服务操作不受支持。")
        description = self._task_service_description(service_id)
        expected_state = {"start": "运行中", "stop": "已停止", "restart": "运行中"}[
            str(operation)
        ]
        actual_state = str(description["service"]["state"])
        return {
            "fact_digest": self._service_fact_digest(
                service_id, operation, description
            ),
            "verified": True,
            "result_matches": actual_state == expected_state,
            "actual_state": actual_state,
            "expected_state": expected_state,
        }

    def _task_service_description(self, service_id: str) -> dict[str, Any]:
        return self._describe_service(
            self._runner.snapshot(),
            service_id,
            self._runner.service_inventory(service_id),
        )

    @staticmethod
    def _service_fact_digest(
        service_id: str, operation: object, description: dict[str, Any]
    ) -> str:
        digest_source = {
            "service_id": service_id,
            "state": description["service"]["state"],
            "operation": operation,
            "allowed_operations": description["allowed_operations"],
        }
        return hashlib.sha256(
            json.dumps(
                digest_source,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def _prepare_duckdns_task(
        self, arguments: dict[str, object], actor: str
    ) -> PreparedAction:
        if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
            raise TaskEngineError("invalid_params", "操作账号格式不正确。")
        expected_fields = {"operation", "provider", "fqdn", "token", "secret_id", "secret_key", "zone"}
        if set(arguments) != expected_fields:
            raise TaskEngineError("invalid_params", "动态 DNS 任务参数不正确。")
        operation = arguments.get("operation")
        provider = arguments.get("provider")
        fqdn = arguments.get("fqdn")
        token = arguments.get("token")
        secret_id = arguments.get("secret_id")
        secret_key = arguments.get("secret_key")
        zone = arguments.get("zone")
        if operation not in {"configure", "update", "disable", "delete"}:
            raise TaskEngineError("operation_forbidden", "动态 DNS 动作未登记。")
        values = (provider, fqdn, token, secret_id, secret_key, zone)
        if not all(isinstance(value, str) for value in values) or any(
            len(value) > 256 or any(char in value for char in "\x00\r\n") for value in values
        ):
            raise TaskEngineError("invalid_params", "动态 DNS 凭据格式无效。")
        if operation == "configure":
            provider = provider.strip()
            fqdn = fqdn.strip()
            token = token.strip()
            secret_id = secret_id.strip()
            secret_key = secret_key.strip()
            zone = zone.strip().lower().rstrip(".")
            if provider == "duckdns":
                if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", token):
                    raise TaskEngineError("invalid_params", "DuckDNS Token 格式无效。")
                fqdn = secret_id = secret_key = zone = ""
            elif provider == "dnspod":
                try:
                    fqdn = normalize_fqdn(fqdn)
                    overview = self._runner.network_overview()
                    validate_wildcard_conflicts([
                        str(domain)
                        for item in overview.get("nodes", [])
                        if isinstance(item, dict) and item.get("kind") == "awg"
                        for domain in item.get("domains", [])
                    ], [fqdn])
                except (ValueError, NodeDomainError) as error:
                    raise TaskEngineError("invalid_params", str(error)) from error
                if (
                    not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", secret_id)
                    or not re.fullmatch(r"[^\x00\r\n]{16,256}", secret_key)
                    or not re.fullmatch(
                        r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
                        zone,
                    )
                    or not (fqdn == zone or fqdn.endswith("." + zone))
                ):
                    raise TaskEngineError("invalid_params", "DNSPod 凭据或主域名格式无效。")
                token = ""
            else:
                raise TaskEngineError("invalid_params", "动态 DNS 提供商不受支持。")
        elif any(values):
            raise TaskEngineError("invalid_params", "该动态 DNS 动作不接受提供商或凭据。")
        params = {
            "operation": operation, "provider": "", "fqdn": "", "token": "", "secret_id": "",
            "secret_key": "", "zone": "", "actor": actor, "confirmed": True,
        }
        catalog_params = {
            **params, "provider": provider, "fqdn": fqdn, "token": token, "secret_id": secret_id,
            "secret_key": secret_key, "zone": zone,
        }
        try:
            definition = validate_action_request("network.duckdns.change", catalog_params)
        except ActionCatalogError as error:
            raise TaskEngineError(error.code, error.message) from error
        current = self._runner.duckdns_status()
        labels = {
            "configure": "验证并启用动态 DNS", "update": "立即更新动态 DNS",
            "disable": "停用动态 DNS 自动更新", "delete": "删除动态 DNS 凭据",
        }
        summaries = {
            "configure": "先向所选 DNS 提供商验证候选凭据并真实更新；成功后才替换现有凭据并启用每分钟更新。",
            "update": "立即用本机默认路由公网 IPv4 更新已配置的 DNS 记录。",
            "disable": "停止定时更新，但保留 root-only 凭据，之后可重新配置启用。",
            "delete": "停止定时更新，并删除 VPS 上保存的凭据和本地更新状态。",
        }
        provider_label = {"dnspod": "腾讯云 DNSPod", "duckdns": "DuckDNS"}.get(
            str(provider), str(current.get("provider_label", "未配置"))
        )
        return PreparedAction(
            canonical_action=definition.name,
            params=params,
            sensitive_params={
                "provider": provider, "fqdn": fqdn, "token": token, "secret_id": secret_id,
                "secret_key": secret_key, "zone": zone,
            } if operation == "configure" else None,
            preview={
                "title": labels[str(operation)], "summary": summaries[str(operation)],
                "facts": {
                    "域名": (
                        str(fqdn) if operation == "configure" and fqdn
                        else (str(current.get("fqdn", "")) or "使用稳定公网入口")
                    ),
                    "提供商": provider_label,
                    "当前状态": "已启用" if current.get("enabled") else ("已停用" if current.get("configured") else "未配置"),
                    "凭据": "候选凭据已加密暂存" if operation == "configure" else ("将删除" if operation == "delete" else "不会回显"),
                    "网络影响": "不重启 AWG、SSH、Xray，不修改防火墙或订阅",
                },
            },
            fact_digest=self._duckdns_fact_digest(params, current),
            timeout_seconds=definition.timeout_seconds,
        )

    @staticmethod
    def _duckdns_fact_digest(params: dict[str, object], status: dict[str, Any]) -> str:
        source = {
            "operation": params.get("operation"),
            "configured": status.get("configured"), "enabled": status.get("enabled"),
            "provider": status.get("provider"), "fqdn": status.get("fqdn"),
            "credentials_present": status.get("credentials_present"),
        }
        return hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _proxy_fact_digest(overview: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(
                overview,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _validate_proxy_update_values(params: dict[str, object]) -> None:
        operation = params.get("operation")
        airport_id = params.get("airport_id")
        airport_name = params.get("airport_name")
        airport_url = params.get("airport_url")
        airport_enabled = params.get("airport_enabled")
        countries = params.get("countries")
        exit_id = params.get("exit_id")
        exit_name = params.get("exit_name")
        exit_default = params.get("exit_default")
        exit_proxy_yaml = params.get("exit_proxy_yaml")
        awg_name = params.get("awg_name")
        exit_ids = params.get("exit_ids")
        actor = params.get("actor")
        if operation not in {"airport_add", "airport_update", "airport_delete", "exit_add", "exit_update", "exit_delete", "exit_set_default", "node_exits_set"}:
            raise TaskEngineError("invalid_params", "机场资源动作未登记。")
        if (
            not isinstance(airport_url, str)
            or len(airport_url) > 8192
            or "\x00" in airport_url
        ):
            raise TaskEngineError("invalid_params", "机场链接格式不正确。")
        if (
            not isinstance(exit_proxy_yaml, str)
            or len(exit_proxy_yaml) > 65536
            or "\x00" in exit_proxy_yaml
        ):
            raise TaskEngineError("invalid_params", "出口节点内容格式不正确。")
        if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
            raise TaskEngineError("invalid_params", "操作账号格式不正确。")
        if operation == "airport_add":
            if airport_id != "" or not airport_url.strip():
                raise TaskEngineError("invalid_params", "新增机场必须提供订阅链接。")
        elif operation in {"airport_update", "airport_delete"}:
            if not isinstance(airport_id, str) or not re.fullmatch(r"[a-f0-9]{12}", airport_id):
                raise TaskEngineError("invalid_params", "机场标识无效。")
        if operation in {"airport_add", "airport_update"}:
            if (
                not isinstance(airport_name, str)
                or not 1 <= len(airport_name.strip()) <= 40
                or not isinstance(airport_enabled, bool)
                or not isinstance(countries, list)
                or not countries
                or any(not isinstance(item, str) or item not in COUNTRY_IDS for item in countries)
            ):
                raise TaskEngineError("invalid_params", "机场名称、启用状态或国家选择无效。")
        elif airport_name != "" or airport_enabled is not False or countries != []:
            raise TaskEngineError("invalid_params", "该动作包含无关机场字段。")
        exit_ops = {"exit_add", "exit_update", "exit_delete", "exit_set_default"}
        if operation in exit_ops:
            if airport_id != "" or airport_name != "" or airport_url != "" or airport_enabled is not False or countries != [] or awg_name != "" or exit_ids != []:
                raise TaskEngineError("invalid_params", "出口节点变更包含无关字段。")
            if operation != "exit_add" and (not isinstance(exit_id, str) or not re.fullmatch(r"[a-f0-9]{12}", exit_id)):
                raise TaskEngineError("invalid_params", "出口节点标识无效。")
            if operation == "exit_add" and exit_id != "":
                raise TaskEngineError("invalid_params", "新增出口节点不能指定标识。")
            if operation in {"exit_add", "exit_update"}:
                if not isinstance(exit_name, str) or not 1 <= len(exit_name.strip()) <= 40 or not exit_proxy_yaml.strip() or not isinstance(exit_default, bool):
                    raise TaskEngineError("invalid_params", "出口名称或节点内容无效。")
            elif exit_name != "" or exit_proxy_yaml != "" or exit_default is not False:
                raise TaskEngineError("invalid_params", "该出口动作包含无关字段。")
        elif operation == "node_exits_set":
            if any((airport_id != "", airport_name != "", airport_url != "", airport_enabled is not False, countries != [], exit_id != "", exit_name != "", exit_default is not False, exit_proxy_yaml != "")):
                raise TaskEngineError("invalid_params", "节点出口变更包含无关字段。")
            if not isinstance(awg_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", awg_name):
                raise TaskEngineError("invalid_params", "AWG 节点名称无效。")
            if not isinstance(exit_ids, list) or len(exit_ids) > 16 or any(not isinstance(item, str) or not re.fullmatch(r"[a-f0-9]{12}", item) for item in exit_ids) or len(set(exit_ids)) != len(exit_ids):
                raise TaskEngineError("invalid_params", "节点中转出口选择无效。")
        else:
            if any((exit_id != "", exit_name != "", exit_default is not False, awg_name != "", exit_ids != [])) or exit_proxy_yaml != "":
                raise TaskEngineError("invalid_params", "机场变更不接受出口节点字段。")

    @staticmethod
    def _validate_file_change_values(params: dict[str, object]) -> None:
        operation = params.get("operation")
        upload_id = params.get("upload_id")
        download_name = params.get("download_name")
        cdn_cache = params.get("cdn_cache")
        cache_ttl = params.get("cache_ttl")
        resource_id = params.get("resource_id")
        actor = params.get("actor")
        if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
            raise TaskEngineError("invalid_params", "操作账号格式不正确。")
        if (
            not isinstance(cdn_cache, bool)
            or not isinstance(cache_ttl, int)
            or not 300 <= cache_ttl <= 2_592_000
        ):
            raise TaskEngineError("invalid_params", "CDN 缓存设置无效。")
        if operation == "add":
            if not isinstance(upload_id, str) or not re.fullmatch(
                r"[0-9a-f]{32}", upload_id
            ):
                raise TaskEngineError("invalid_params", "上传标识无效。")
            if not isinstance(download_name, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", download_name
            ):
                raise TaskEngineError("invalid_params", "下载文件名无效。")
            if resource_id != "":
                raise TaskEngineError("invalid_params", "新增文件不接受资源标识。")
        elif (
            upload_id != ""
            or download_name != ""
            or not isinstance(resource_id, str)
            or not re.fullmatch(r"file-[0-9a-f]{16}", resource_id)
        ):
            raise TaskEngineError("invalid_params", "删除文件参数无效。")

    @staticmethod
    def _file_fact_digest(
        params: dict[str, object], subject: dict[str, Any], overview: dict[str, Any]
    ) -> str:
        source = {
            "operation": params.get("operation"),
            "upload_id": params.get("upload_id"),
            "download_name": params.get("download_name"),
            "cdn_cache": params.get("cdn_cache"),
            "cache_ttl": params.get("cache_ttl"),
            "resource_id": params.get("resource_id"),
            "subject": subject,
            "service_state": overview.get("service_state"),
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    def cleanup_task_action(
        self, protocol_action: str, params: dict[str, object]
    ) -> None:
        """幂等清理任务专属暂存资源。"""

        is_file_resource = (
            protocol_action == "file.resource.change"
            and params.get("operation") == "add"
        )
        is_file_deployment = (
            protocol_action == "deployment.install"
            and params.get("service_id") == "file"
        )
        if is_file_resource or is_file_deployment:
            upload_id = params.get("upload_id")
            if isinstance(upload_id, str) and re.fullmatch(r"[0-9a-f]{32}", upload_id):
                self._runner.discard_file_upload(upload_id)

    @staticmethod
    def _ssh_key_fact_digest(
        params: dict[str, object], listing: dict[str, Any]
    ) -> str:
        source = {
            "operation": params.get("operation"),
            "item_id": params.get("item_id"),
            "name": params.get("name"),
            "type": params.get("_type"),
            "fingerprint": params.get("_fingerprint"),
            "duplicate": params.get("_duplicate"),
            "keys": listing.get("items", []),
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _public_endpoint_digest(
        params: dict[str, object], status: dict[str, Any]
    ) -> str:
        stable_status = {
            key: status.get(key) for key in (
                "state", "fqdn", "rollback_seconds", "subscriptions_refreshed",
                "independent_session", "last_outcome", "transaction_id",
            )
        }
        source = {
            "params": {
                key: value for key, value in params.items()
                if key not in {"actor", "confirmed", "session_id"}
            },
            "status": stable_status,
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _network_fact_digest(
        params: dict[str, object], overview: dict[str, Any]
    ) -> str:
        source = {
            "params": {
                key: value for key, value in params.items()
                if key not in {"actor", "confirmed", "preshared_key"}
            },
            "overview": overview,
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _backup_fact_digest(
        operation: object, backup_id: object, subject: dict[str, Any],
        listing: dict[str, Any],
    ) -> str:
        source = {
            "operation": operation,
            "backup_id": backup_id,
            "subject": subject,
            "items": listing.get("items", []),
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _firewall_match_summary(items: list[dict[str, Any]]) -> str:
        if not items:
            return "未占用"
        values = []
        for item in items:
            duration = "永久" if item.get("duration") == "permanent" else "临时"
            values.append(f"{str(item.get('protocol', '')).upper()} {duration}")
        return "、".join(values)

    @staticmethod
    def _firewall_inventory_has_port(
        inventory: dict[str, Any], scope: str, protocol: str, port: int
    ) -> bool:
        expected_name = "公网入口" if scope == "public" else "内网入口"
        expected_detail = "公网" if scope == "public" else "AWG 内网"
        for item in inventory.get("items", []):
            if (
                not isinstance(item, dict)
                or item.get("name") != expected_name
                or expected_detail not in str(item.get("detail", ""))
                or protocol.upper() not in str(item.get("detail", "")).upper()
            ):
                continue
            for part in re.split(r"[/,\s]+", str(item.get("state", ""))):
                if part.isdigit() and int(part) == port:
                    return True
                match = re.fullmatch(r"(\d+)-(\d+)", part)
                if match and int(match.group(1)) <= port <= int(match.group(2)):
                    return True
        return False

    @staticmethod
    def _firewall_fact_digest(
        params: dict[str, object], current: dict[str, Any], inventory: dict[str, Any]
    ) -> str:
        stable_current = {
            **current,
            "items": [
                {
                    key: value for key, value in item.items()
                    if key != "remaining_seconds"
                }
                for item in current.get("items", []) if isinstance(item, dict)
            ],
        }
        source = {
            "params": {
                key: value for key, value in params.items()
                if key not in {"actor", "confirmed"}
            },
            "custom_ports": stable_current,
            "base_policy": inventory,
        }
        return hashlib.sha256(
            json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _managed_port_fact_digest(params: dict[str, object], overview: dict[str, Any]) -> str:
        source = {
            "target_id": params.get("target_id"),
            "port": params.get("port"),
            "revision": overview.get("revision", ""),
        }
        return hashlib.sha256(
            json.dumps(source, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def handle(self, request: object, caller_uid: int) -> dict[str, Any]:
        """校验调用者和请求，并返回稳定协议响应。"""
        request_id = self._request_id_or_fallback(request)
        try:
            self._authorize(caller_uid)
            validated = self._validate_request(request)
            result = self._dispatch(validated["action"], validated["params"])
            return {
                "version": PROTOCOL_VERSION,
                "request_id": validated["request_id"],
                "ok": True,
                "result": result,
            }
        except (RequestError, TaskEngineError) as exc:
            return {
                "version": PROTOCOL_VERSION,
                "request_id": request_id,
                "ok": False,
                "error": {"code": exc.code, "message": exc.message},
            }
        except Exception:
            # 具体异常只进入本机日志，协议响应不得泄露路径、命令或配置内容。
            LOGGER.exception("管理代理执行登记动作失败")
            return {
                "version": PROTOCOL_VERSION,
                "request_id": request_id,
                "ok": False,
                "error": {"code": "internal_error", "message": "管理代理执行失败。"},
            }

    @staticmethod
    def _request_id_or_fallback(request: object) -> str:
        if isinstance(request, dict):
            value = request.get("request_id")
            if isinstance(value, str) and REQUEST_ID_PATTERN.fullmatch(value):
                return value
        return "invalid-request"

    def _authorize(self, caller_uid: int) -> None:
        if caller_uid not in self._allowed_uids:
            raise RequestError("forbidden", "调用者无权使用管理代理。")

    @staticmethod
    def _validate_request(request: object) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise RequestError("invalid_request", "请求必须是 JSON 对象。")
        expected = {"version", "request_id", "action", "params"}
        if set(request) != expected:
            raise RequestError("invalid_request", "请求字段不完整或包含未知字段。")
        if request.get("version") != PROTOCOL_VERSION:
            raise RequestError("unsupported_version", "管理协议版本不受支持。")
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not REQUEST_ID_PATTERN.fullmatch(request_id):
            raise RequestError("invalid_request", "request_id 格式不正确。")
        action = request.get("action")
        if not isinstance(action, str):
            raise RequestError("invalid_request", "action 格式不正确。")
        params = request.get("params")
        if not isinstance(params, dict):
            raise RequestError("invalid_request", "params 必须是 JSON 对象。")
        return {
            "request_id": request_id,
            "action": action,
            "params": params,
        }

    def _dispatch(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            definition = validate_action_request(action, params)
        except ActionCatalogError as error:
            raise RequestError(error.code, error.message) from error
        if definition.task_only:
            raise RequestError(
                "operation_forbidden",
                "受管主机变更只能通过 task.preview 创建任务。",
            )
        if action == "task.preview":
            protocol_action = params.get("action")
            arguments = params.get("arguments")
            actor = params.get("actor")
            if not isinstance(protocol_action, str) or not isinstance(arguments, dict):
                raise RequestError("invalid_params", "任务预览参数不正确。")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            return self._tasks().preview(protocol_action, arguments, actor)
        if action == "task.confirm":
            task_id = params.get("task_id")
            actor = params.get("actor")
            if not isinstance(task_id, str):
                raise RequestError("invalid_params", "任务标识格式不正确。")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            return self._tasks().confirm(task_id, actor)
        if action == "task.cancel":
            task_id = params.get("task_id")
            actor = params.get("actor")
            if not isinstance(task_id, str):
                raise RequestError("invalid_params", "任务标识格式不正确。")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            return self._tasks().cancel(task_id, actor)
        if action == "task.get":
            task_id = params.get("task_id")
            if not isinstance(task_id, str):
                raise RequestError("invalid_params", "任务标识格式不正确。")
            return self._tasks().get(task_id)
        if action == "task.list":
            return self._tasks().list()
        if action == "task.active":
            return {"active": self._tasks().has_active_tasks()}
        if action == "system.snapshot":
            return self._runner.snapshot()
        if action == "host.read":
            intent = params.get("intent")
            service_id = params.get("service_id")
            if not isinstance(intent, str) or not isinstance(service_id, str):
                raise RequestError("invalid_params", "主机读取参数不正确。")
            if intent == "service":
                service_id = self._service_id(service_id)
            elif service_id:
                raise RequestError("invalid_params", "该读取意图不接受服务标识。")
            try:
                return self._read_model.read(intent, service_id)
            except ValueError as error:
                raise RequestError("invalid_params", str(error)) from error
        if action == "service.describe":
            service_id = self._service_id(params.get("service_id"))
            return self._describe_service(
                self._runner.snapshot(),
                service_id,
                self._runner.service_inventory(service_id),
            )
        if action == "service.reveal":
            service_id = self._service_id(params.get("service_id"))
            resource = params.get("resource")
            item_id = params.get("item_id")
            actor = params.get("actor")
            allowed_resources = {
                "clash": {
                    "subscription_link", "subscription_qr",
                    "airport_link", "exit_config",
                },
                "file": {"download_link", "download_qr"},
            }
            if resource not in allowed_resources.get(service_id, set()):
                raise RequestError("operation_forbidden", "敏感资源未登记。")
            if not isinstance(item_id, str) or not RESOURCE_ITEM_ID_PATTERN.fullmatch(item_id):
                raise RequestError("invalid_params", "节点标识格式不正确。")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            self._require_sync_confirmation(definition, params)
            return self._runner.reveal_resource(service_id, resource, item_id, actor)
        if action == "file.resources.overview":
            return self._runner.file_resources()
        if action == "network.overview":
            return self._runner.network_overview()
        if action == "network.public_endpoint.status":
            return self._runner.public_endpoint_status()
        if action == "network.public_endpoint.transaction.status":
            actor = params.get("actor")
            session_id = params.get("session_id")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            if not isinstance(session_id, str) or not SESSION_ID_PATTERN.fullmatch(session_id):
                raise RequestError("invalid_params", "安全会话格式不正确。")
            return self._runner.public_endpoint_transaction_status(actor, session_id)
        if action == "network.duckdns.status":
            return self._runner.duckdns_status()
        if action == "audit.list":
            return self._runner.audit_log()
        if action == "audit.event":
            service_id = params.get("service_id")
            operation = params.get("operation")
            actor = params.get("actor")
            if service_id != "accounts" or operation not in {"account_create", "account_enable", "account_disable", "account_password_reset"}:
                raise RequestError("operation_forbidden", "审计事件未登记。")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            return self._runner.record_event(service_id, operation, actor)
        if action == "network.enrollment.context":
            return self._runner.enrollment_context()
        if action == "network.proxy.overview":
            return self._runner.proxy_resources()
        if action == "network.proxy.test":
            actor = params.get("actor")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            return self._runner.test_proxy_resources(actor)
        if action == "firewall.ports.overview":
            return self._runner.firewall_ports()
        if action == "managed.ports.overview":
            return self._runner.managed_ports()
        if action == "ssh.keys.overview":
            return self._runner.ssh_keys()
        if action == "ssh.key.preview":
            public_key = params.get("public_key")
            actor = params.get("actor")
            if (
                not isinstance(public_key, str)
                or not 1 <= len(public_key.encode("utf-8")) <= 16384
                or any(char in public_key for char in ("\x00", "\r", "\n"))
            ):
                raise RequestError("invalid_params", "SSH 公钥必须是完整的一行。")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            return self._runner.preview_ssh_key(public_key, actor)
        if action == "security.transaction":
            transaction_type = params.get("transaction_type")
            operation = params.get("operation")
            actor = params.get("actor")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            return self._runner.manage_transaction(transaction_type, operation, actor)
        if action == "backup.manage":
            operation = params.get("operation")
            backup_id = params.get("backup_id")
            passphrase = params.get("passphrase")
            actor = params.get("actor")
            if not isinstance(actor, str) or not ACTOR_PATTERN.fullmatch(actor):
                raise RequestError("invalid_params", "操作账号格式不正确。")
            if operation == "preview_restore":
                if (
                    not isinstance(backup_id, str)
                    or not BACKUP_ID_PATTERN.fullmatch(backup_id)
                    or not isinstance(passphrase, str)
                    or not 16 <= len(passphrase) <= 256
                    or "\x00" in passphrase
                ):
                    raise RequestError("invalid_params", "备份预览参数不正确。")
                self._require_sync_confirmation(definition, params)
            elif backup_id != "" or passphrase != "":
                raise RequestError("invalid_params", "备份读取参数不正确。")
            return self._runner.manage_backup(
                str(operation), str(backup_id), str(passphrase), actor
            )
        raise RequestError("unknown_action", "动作未登记。")

    def _tasks(self) -> TaskEngine:
        if self._task_engine is None:
            raise RequestError("operation_unavailable", "异步任务 module 尚未启动。")
        return self._task_engine

    @staticmethod
    def _require_sync_confirmation(
        definition: ActionDefinition, params: dict[str, Any]
    ) -> None:
        """在异步任务接管前保留旧同步协议的确认行为。"""

        if (
            definition.sync_confirmation_required
            and params.get("confirmed") is not True
        ):
            raise RequestError(
                "confirmation_required",
                definition.sync_confirmation_message,
            )

    @staticmethod
    def _service_id(value: object) -> str:
        if not isinstance(value, str) or value not in SERVICE_IDS:
            raise RequestError("not_found", "托管服务不存在。")
        return value

    @staticmethod
    def _describe_service(
        snapshot: dict[str, Any],
        service_id: str,
        inventory: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        services = snapshot.get("services")
        if not isinstance(services, list):
            raise RuntimeError("主机快照缺少托管服务")
        service = next(
            (
                item
                for item in services
                if isinstance(item, dict) and item.get("id") == service_id
            ),
            None,
        )
        if service is None:
            raise RequestError("not_found", "托管服务不存在。")
        state = service.get("state")
        operations: list[str] = []
        restriction = READ_ONLY_REASONS.get(service_id, "")
        if state == "未安装":
            restriction = "服务尚未安装，请使用后续安装向导。"
        elif service_id in CHANGEABLE_SERVICE_IDS:
            restriction = ""
            if state == "运行中":
                operations = ["stop", "restart"]
            elif state == "已停止":
                operations = ["start"]
            elif state == "失败":
                operations = ["start", "restart"]
        return {
            "service": service,
            "allowed_operations": operations,
            "restriction": restriction,
            "inventory": inventory or {
                "schema_version": 1,
                "service_id": service_id,
                "facts": {},
                "items": [],
            },
        }
