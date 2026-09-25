#!/usr/bin/env python3
"""调用固定 server-kit 脚本动作的生产适配器。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from control_plane.errors import TaskExecutionError
from lib.server_kit_audit import append_audit
from lib.server_kit_permission_batch import normalize_rules
from lib.server_kit_topology_facts import valid_topology_context


CHANGEABLE_SERVICE_IDS = frozenset({"clash", "file", "mosh"})
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
SERVICE_OPERATIONS = frozenset({"start", "stop", "restart"})
Executor = Callable[..., subprocess.CompletedProcess[str]]
NODE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
PUBLIC_FQDN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
TRANSACTION_ID_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SAFE_DIAGNOSTIC_PREFIX = "SERVER_KIT_DIAGNOSTIC:"
PROXY_UPDATE_DIAGNOSTICS = {
    "proxy_write_disabled": "代理资源写操作未启用；服务器配置没有变更。",
    "proxy_module_missing": "服务器缺少代理资源管理模块；服务器配置没有变更。",
    "proxy_service_missing": "Clash 订阅服务尚未安装，无法发布出口节点。",
    "proxy_storage_failed": (
        "代理资源配置文件无法读取或写入；服务器没有进入订阅刷新阶段。"
        "请检查磁盘空间、文件权限和配置目录状态。"
    ),
    "proxy_relay_refresh_failed": (
        "VLESS 中转出口刷新失败；原代理资源配置已恢复。"
        "请检查出口类型、服务器、端口和认证字段。"
    ),
    "proxy_subscription_refresh_failed": (
        "Clash 订阅生成或发布校验失败；原代理资源配置和订阅已恢复。"
    ),
}


class ScriptRunner:
    """只执行代码中登记的参数数组，永不接收 Shell 命令。"""

    def __init__(
        self,
        manager_path: str,
        timeout: float = 15.0,
        audit_path: str = "/var/log/server-kit/management-actions.jsonl",
        executor: Executor = subprocess.run,
        high_risk_writes: bool = False,
        network_writes: bool = False,
    ) -> None:
        path = Path(manager_path)
        if not path.is_absolute():
            raise ValueError("总管脚本必须使用绝对路径")
        audit = Path(audit_path)
        if not audit.is_absolute():
            raise ValueError("审计日志必须使用绝对路径")
        self._manager_path = str(path)
        self._timeout = timeout
        self._audit_path = audit
        self._executor = executor
        self._high_risk_writes = high_risk_writes
        self._network_writes = network_writes

    def _environment(self) -> dict[str, str]:
        return {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "SERVER_KIT_CONTROL": "1",
            "SERVER_KIT_HIGH_RISK_WRITES": "1" if self._high_risk_writes else "0",
            "SERVER_KIT_NETWORK_WRITES": "1" if self._network_writes else "0",
        }

    def _run(
        self, arguments: list[str], timeout: float, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self._executor(
            [self._manager_path, *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=self._environment(),
            cwd="/",
            input=input_text,
        )

    @staticmethod
    def _proxy_update_error(stderr: str) -> TaskExecutionError:
        """只解析管理脚本明确标记为可公开的诊断，忽略其余底层输出。"""

        for line in stderr.splitlines():
            if not line.startswith(SAFE_DIAGNOSTIC_PREFIX):
                continue
            diagnostic = line.removeprefix(SAFE_DIAGNOSTIC_PREFIX)
            code, separator, detail = diagnostic.partition(":")
            if code == "proxy_input_invalid" and separator:
                safe_detail = detail.strip()
                if (
                    safe_detail
                    and len(safe_detail) <= 180
                    and not any(character in safe_detail for character in "\x00\r\n")
                ):
                    return TaskExecutionError(
                        code,
                        f"代理资源内容校验失败：{safe_detail} 未刷新任何订阅。",
                    )
            message = PROXY_UPDATE_DIAGNOSTICS.get(code)
            if message is not None:
                return TaskExecutionError(code, message)
        return TaskExecutionError(
            "proxy_update_failed",
            "代理资源更新失败，但管理脚本没有返回可公开的阶段诊断；服务器未展示底层输出，以避免泄露订阅链接或出口凭据。",
        )

    def snapshot(self) -> dict[str, Any]:
        completed = self._run(["snapshot", "--json"], self._timeout)
        if completed.returncode != 0:
            raise RuntimeError("总管脚本无法生成快照")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("总管脚本返回了无效 JSON") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise RuntimeError("总管脚本快照版本不受支持")
        return payload

    def service_inventory(self, service_id: str) -> dict[str, Any]:
        if service_id not in SERVICE_IDS:
            raise ValueError("托管服务未登记")
        completed = self._run(["inventory", service_id, "--json"], self._timeout)
        if completed.returncode != 0:
            raise RuntimeError("总管脚本无法生成服务清单")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("总管脚本返回了无效服务清单") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != 1
            or payload.get("service_id") != service_id
        ):
            raise RuntimeError("总管脚本服务清单版本不受支持")
        return payload

    def reveal_resource(
        self, service_id: str, resource: str, item_id: str, actor: str
    ) -> dict[str, Any]:
        resources = {
            "subscription_link": (
                "subscription-link",
                "clash_subscription_link",
                "copy_subscription_link",
                "value",
            ),
            "subscription_qr": (
                "subscription-qr",
                "clash_subscription_qr",
                "reveal_subscription_qr",
                "image_base64",
            ),
            "airport_link": (
                "airport-link",
                "proxy_airport_link",
                "copy_proxy_airport_link",
                "value",
            ),
            "exit_config": (
                "exit-config",
                "proxy_exit_config",
                "reveal_proxy_exit_config",
                "value",
            ),
            "download_link": (
                "file-link", "file_download_link", "copy_file_link", "value",
            ),
            "download_qr": (
                "file-qr", "file_download_qr", "reveal_file_qr", "image_base64",
            ),
        }
        if (service_id == "clash" and resource not in {
            "subscription_link", "subscription_qr", "airport_link", "exit_config",
        }) or \
           (service_id == "file" and resource not in {"download_link", "download_qr"}) or \
           service_id not in {"clash", "file"}:
            raise ValueError("敏感资源未登记")
        if not actor or len(actor) > 150 or not item_id or len(item_id) > 73:
            raise ValueError("操作账号格式不正确")
        manager_resource, response_resource, operation, value_key = resources[resource]
        try:
            completed = self._run(
                ["reveal", service_id, manager_resource, item_id, "--json"],
                self._timeout,
            )
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, service_id, operation, "timeout")
            raise RuntimeError("敏感资源读取超时") from exc
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 750_000:
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("敏感资源读取失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("敏感资源响应格式无效") from exc
        expected_keys = {"schema_version", "resource", "item_id", "name", value_key}
        valid = (
            isinstance(payload, dict)
            and (
                set(payload) == expected_keys
                or (
                    resource == "exit_config"
                    and set(payload) == expected_keys | {"proxy"}
                    and isinstance(payload["proxy"], dict)
                )
            )
            and payload.get("schema_version") == 1
            and payload.get("resource") == response_resource
            and payload.get("item_id") == item_id
            and all(isinstance(payload.get(key), str) for key in {"item_id", "name", value_key})
        )
        if not valid:
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("敏感资源响应版本不受支持")
        self._append_audit(actor, service_id, operation, "success")
        return payload

    def file_resources(self) -> dict[str, Any]:
        completed = self._run(["file", "overview", "--json"], self._timeout)
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 100_000:
            raise RuntimeError("无法读取普通文件资源")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("普通文件资源响应无效") from exc
        valid = (
            isinstance(payload, dict)
            and set(payload) == {
                "schema_version", "configured", "address", "port",
                "service_state", "items",
            }
            and payload.get("schema_version") == 1
            and payload.get("configured") is True
            and isinstance(payload.get("address"), str)
            and isinstance(payload.get("port"), int)
            and payload.get("service_state") in {"运行中", "已停止", "失败", "未安装"}
            and isinstance(payload.get("items"), list)
            and all(
                isinstance(item, dict)
                and set(item) == {"resource_id", "name", "size", "cdn_cache", "cache_ttl"}
                and isinstance(item.get("resource_id"), str)
                and re.fullmatch(r"file-[0-9a-f]{16}", item["resource_id"])
                and isinstance(item.get("name"), str)
                and isinstance(item.get("size"), int) and item["size"] >= 0
                and isinstance(item.get("cdn_cache"), bool)
                and isinstance(item.get("cache_ttl"), int)
                for item in payload.get("items", [])
            )
        )
        if not valid:
            raise RuntimeError("普通文件资源响应版本不受支持")
        return payload

    def change_file_resource(
        self, operation: str, upload_id: str, download_name: str,
        cdn_cache: bool, cache_ttl: int, resource_id: str, actor: str,
    ) -> dict[str, Any]:
        arguments = ["file", operation]
        if operation == "add":
            arguments.extend([upload_id, download_name, "true" if cdn_cache else "false", str(cache_ttl)])
        else:
            arguments.append(resource_id)
        arguments.append("--json")
        audit_operation = f"file_resource_{operation}"
        try:
            completed = self._run(arguments, 900.0 if operation == "add" else 190.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "file", audit_operation, "timeout")
            raise RuntimeError("文件资源操作超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "file", audit_operation, "failed")
            raise RuntimeError("文件资源操作失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "file", audit_operation, "failed")
            raise RuntimeError("文件资源操作响应无效") from exc
        expected_id = resource_id if operation == "delete" else payload.get("resource_id")
        if payload != {"schema_version": 1, "operation": operation, "resource_id": expected_id} or not isinstance(expected_id, str) or not re.fullmatch(r"file-[0-9a-f]{16}", expected_id):
            self._append_audit(actor, "file", audit_operation, "failed")
            raise RuntimeError("文件资源操作响应版本不受支持")
        self._append_audit(actor, "file", audit_operation, "success")
        return payload

    def file_upload_facts(self, upload_id: str) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{32}", upload_id):
            raise ValueError("上传标识无效")
        completed = self._run(["file", "inspect-upload", upload_id, "--json"], 900.0)
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 1024:
            raise RuntimeError("无法核验暂存文件")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("暂存文件事实格式无效") from exc
        valid = (
            isinstance(payload, dict)
            and payload.get("schema_version") == 1
            and payload.get("upload_id") == upload_id
            and isinstance(payload.get("size"), int)
            and payload["size"] > 0
            and isinstance(payload.get("sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", payload["sha256"])
        )
        if not valid:
            raise RuntimeError("暂存文件事实版本不受支持")
        return payload

    def discard_file_upload(self, upload_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{32}", upload_id):
            raise ValueError("上传标识无效")
        completed = self._run(["file", "discard-upload", upload_id, "--json"], 30.0)
        if completed.returncode != 0:
            raise RuntimeError("无法清理暂存文件")

    def network_overview(self) -> dict[str, Any]:
        completed = self._run(["network", "overview", "--json"], self._timeout)
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 300_000:
            raise RuntimeError("无法读取节点与订阅状态")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("节点与订阅状态格式无效") from exc
        required = {
            "schema_version", "writes_enabled", "subscriptions_configured",
            "sync_available", "pending_vless", "pending_access", "management_peer", "management_port", "summary",
            "nodes", "publications", "subscription_items", "targets",
            "enrollment_history", "exit_options", "host_records",
        }
        if (
            not isinstance(payload, dict)
            or set(payload) not in (required, required | {"topology_context"})
            or ("topology_context" in payload and not valid_topology_context(payload["topology_context"]))
            or payload.get("schema_version") != 1
            or not all(isinstance(payload.get(key), bool) for key in {
                "writes_enabled", "subscriptions_configured", "sync_available", "pending_vless", "pending_access"
            })
            or not isinstance(payload.get("summary"), dict)
            or not isinstance(payload.get("nodes"), list)
            or not isinstance(payload.get("publications"), list)
            or not isinstance(payload.get("subscription_items"), list)
            or not isinstance(payload.get("targets"), list)
            or not isinstance(payload.get("enrollment_history"), list)
            or not isinstance(payload.get("exit_options"), list)
            or not isinstance(payload.get("host_records"), list)
            or not all(
                isinstance(item, dict)
                and set(item) == {"address", "domains"}
                and isinstance(item.get("address"), str)
                and isinstance(item.get("domains"), list)
                and all(isinstance(domain, str) for domain in item["domains"])
                for item in payload.get("host_records", [])
            )
            or not all(
                isinstance(item, dict)
                and set(item) == {"id", "name", "default"}
                and isinstance(item.get("id"), str)
                and re.fullmatch(r"[a-f0-9]{12}", item["id"])
                and isinstance(item.get("name"), str)
                and isinstance(item.get("default"), bool)
                for item in payload.get("exit_options", [])
            )
            or not isinstance(payload.get("management_peer"), str)
            or not isinstance(payload.get("management_port"), int)
            or not 0 <= payload.get("management_port", 0) <= 65535
            or set(payload.get("summary", {})) != {
                "awg_active", "awg_disabled", "vless_active", "vless_disabled",
                "disabled_total", "published", "stale",
                "pending_enrollment",
            }
            or not all(isinstance(value, int) and value >= 0 for value in payload.get("summary", {}).values())
            or not all(
                isinstance(item, dict)
                and set(item) == {
                    "name", "kind", "kind_label", "address", "state",
                    "published", "publication_state", "detail", "protected",
                    "permissions", "access_mode", "custody",
                    "public_key_fingerprint", "domains", "legacy_stash", "clean_mode",
                    "exit_ids", "exit_names",
                }
                and isinstance(item.get("name"), str)
                and NODE_NAME_PATTERN.fullmatch(item["name"])
                and item.get("kind") in {"awg", "vless"}
                and item.get("state") in {
                    "已启用", "已禁用", "等待首次握手",
                }
                and isinstance(item.get("published"), bool)
                and isinstance(item.get("protected"), bool)
                and isinstance(item.get("legacy_stash"), bool)
                and isinstance(item.get("clean_mode"), bool)
                and isinstance(item.get("exit_ids"), list)
                and isinstance(item.get("exit_names"), list)
                and all(isinstance(value, str) for value in item["exit_ids"] + item["exit_names"])
                and isinstance(item.get("permissions"), list)
                and isinstance(item.get("domains"), list)
                and all(isinstance(domain, str) and 1 <= len(domain) <= 255 for domain in item["domains"])
                and item.get("access_mode") in {"unrestricted", "restricted"}
                and item.get("custody") in {"", "client"}
                and isinstance(item.get("public_key_fingerprint"), str)
                and re.fullmatch(r"(?:[0-9a-f]{16})?", item["public_key_fingerprint"])
                and all(isinstance(item.get(key), str) for key in {
                    "kind_label", "address", "publication_state", "detail",
                })
                and all(
                    isinstance(permission, dict)
                    and set(permission) == {"target", "target_label", "ip", "ports", "ports_label", "network", "network_label"}
                    and isinstance(permission.get("target"), str)
                    and NODE_NAME_PATTERN.fullmatch(permission["target"])
                    and isinstance(permission.get("ip"), str)
                    and isinstance(permission.get("ports"), list)
                    and all(isinstance(port, int) and 1 <= port <= 65535 for port in permission["ports"])
                    and permission.get("network") in {"tcp", "udp", "all"}
                    and all(isinstance(permission.get(key), str) for key in {"target_label", "ports_label", "network_label"})
                    for permission in item.get("permissions", [])
                )
                for item in payload.get("nodes", [])
            )
            or not all(
                isinstance(item, dict)
                and set(item) == {"name", "state", "completed_at"}
                and isinstance(item.get("name"), str)
                and NODE_NAME_PATTERN.fullmatch(item["name"])
                and item.get("state") in {"已生效", "已超时"}
                and isinstance(item.get("completed_at"), str)
                for item in payload.get("enrollment_history", [])
            )
            or not all(
                isinstance(item, dict)
                and set(item) == {"name", "kind", "kind_label", "state", "resource_id"}
                and item.get("kind") in {"awg", "vless"}
                and item.get("state") == "已发布"
                and isinstance(item.get("name"), str)
                and NODE_NAME_PATTERN.fullmatch(item["name"])
                and item.get("resource_id") == item.get("name")
                and isinstance(item.get("kind_label"), str)
                for item in payload.get("publications", [])
            )
            or not all(
                isinstance(item, dict)
                and set(item) == {"name", "kind", "kind_label", "state", "published", "resource_id"}
                and isinstance(item.get("name"), str)
                and NODE_NAME_PATTERN.fullmatch(item["name"])
                and item.get("kind") in {"awg", "vless"}
                and isinstance(item.get("kind_label"), str)
                and item.get("state") in {"已发布", "待同步", "待同步停用", "发布已停用"}
                and isinstance(item.get("published"), bool)
                and item.get("resource_id") == item.get("name")
                for item in payload.get("subscription_items", [])
            )
            or not all(
                isinstance(item, dict)
                and set(item) == {"name", "label"}
                and isinstance(item.get("name"), str)
                and NODE_NAME_PATTERN.fullmatch(item["name"])
                and isinstance(item.get("label"), str)
                for item in payload.get("targets", [])
            )
        ):
            raise RuntimeError("节点与订阅状态版本不受支持")
        return payload

    def public_endpoint_status(self) -> dict[str, Any]:
        completed = self._run(["network", "public-endpoint", "status", "--json"], self._timeout)
        if completed.returncode != 0:
            raise RuntimeError("无法读取稳定公网入口状态")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("稳定公网入口状态格式无效") from exc
        required = {"schema_version", "configured", "fqdn", "current_ipv4", "dns_ipv4s", "matches_current_ipv4", "dns_ttl", "dns_ttl_status", "diagnostics", "recovery_hint"}
        if (
            not isinstance(payload, dict) or set(payload) != required
            or payload.get("schema_version") != 1
            or not isinstance(payload.get("configured"), bool)
            or not isinstance(payload.get("fqdn"), str)
            or not isinstance(payload.get("current_ipv4"), str)
            or not isinstance(payload.get("dns_ipv4s"), list)
            or not all(isinstance(item, str) for item in payload.get("dns_ipv4s", []))
            or (payload.get("matches_current_ipv4") is not None and not isinstance(payload.get("matches_current_ipv4"), bool))
            or payload.get("dns_ttl") is not None
            or not isinstance(payload.get("diagnostics"), list)
            or not all(isinstance(item, str) for item in payload.get("diagnostics", []))
            or not all(isinstance(payload.get(key), str) for key in {"dns_ttl_status", "recovery_hint"})
        ):
            raise RuntimeError("稳定公网入口状态版本不受支持")
        return payload

    def duckdns_status(self) -> dict[str, Any]:
        completed = self._run(["network", "duckdns", "status", "--json"], self._timeout)
        if completed.returncode != 0:
            raise RuntimeError("无法读取动态 DNS 自动更新状态")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("动态 DNS 自动更新状态格式无效") from exc
        expected = {
            "schema_version", "configured", "enabled", "provider", "provider_label",
            "fqdn", "zone", "record", "credentials_present", "token_present",
            "last_result", "last_update_at", "last_ipv4", "dns_ipv4s",
            "dns_matches_last_ipv4", "timer_state", "next_run", "diagnostics",
        }
        if (
            not isinstance(payload, dict) or set(payload) != expected
            or payload.get("schema_version") != 2
            or not all(isinstance(payload.get(key), bool) for key in {"configured", "enabled", "credentials_present", "token_present"})
            or not all(isinstance(payload.get(key), str) for key in {"provider", "provider_label", "fqdn", "zone", "record", "last_result", "last_update_at", "last_ipv4", "timer_state", "next_run"})
            or not isinstance(payload.get("dns_ipv4s"), list)
            or not all(isinstance(item, str) for item in payload.get("dns_ipv4s", []))
            or (payload.get("dns_matches_last_ipv4") is not None and not isinstance(payload.get("dns_matches_last_ipv4"), bool))
            or not isinstance(payload.get("diagnostics"), list)
            or not all(isinstance(item, str) for item in payload.get("diagnostics", []))
        ):
            raise RuntimeError("动态 DNS 自动更新状态版本不受支持")
        return payload

    @staticmethod
    def _duckdns_error(stderr: str) -> TaskExecutionError:
        allowed = {
            "DuckDNS Token 格式无效。": "duckdns_token_invalid",
            "稳定公网入口不是 duckdns.org 域名，不能启用 DuckDNS 自动更新。": "duckdns_domain_invalid",
            "当前只支持单个 DuckDNS 子域名。": "duckdns_domain_invalid",
            "无法连接 DuckDNS 更新接口。": "duckdns_api_unreachable",
            "DuckDNS 拒绝了更新请求，请检查域名归属和 Token。": "duckdns_credentials_rejected",
            "无法读取本机默认路由公网 IPv4。": "duckdns_public_ip_unavailable",
            "本机默认路由源地址不是公网 IPv4。": "duckdns_public_ip_unavailable",
            "DuckDNS 自动更新尚未启用。": "duckdns_not_enabled",
            "动态 DNS 自动更新尚未启用。": "dynamic_dns_not_enabled",
            "DNSPod SecretId 格式无效。": "dnspod_secret_id_invalid",
            "DNSPod SecretKey 格式无效。": "dnspod_secret_key_invalid",
            "DNSPod 主域名格式无效。": "dnspod_zone_invalid",
            "稳定公网入口不属于填写的 DNSPod 主域名。": "dnspod_zone_mismatch",
            "DNSPod 主机记录格式无效。": "dnspod_record_invalid",
            "DNSPod 找不到稳定公网入口对应的 A 记录。": "dnspod_record_missing",
            "DNSPod 返回的记录列表无效。": "dnspod_record_invalid",
            "DNSPod 存在多条同名记录，拒绝自动选择或覆盖。": "dnspod_record_ambiguous",
            "DNSPod 已有同名的非默认线路 A 记录或其他类型记录。": "dnspod_record_conflict",
            "DNSPod 已存在冲突记录，无法自动创建 A 记录。": "dnspod_record_conflict",
            "DNSPod 找不到填写的主域名。": "dnspod_zone_missing",
            "DNSPod 返回的 A 记录信息无效。": "dnspod_record_invalid",
            "DNSPod 创建 A 记录后没有返回有效 RecordId。": "dnspod_create_invalid",
            "请输入 DNSPod 目标完整域名。": "dnspod_fqdn_required",
            "无法连接腾讯云 DNSPod API。": "dnspod_api_unreachable",
            "腾讯云 DNSPod API 返回了无效响应。": "dnspod_api_invalid",
            "DNSPod 拒绝了凭据，请检查 SecretId、SecretKey 和最小权限策略。": "dnspod_credentials_rejected",
            "DNSPod API 拒绝了请求，请检查凭据权限和记录状态。": "dnspod_request_rejected",
            "动态 DNS 提供商不受支持。": "dynamic_dns_provider_invalid",
        }
        for message, code in allowed.items():
            if message in stderr:
                return TaskExecutionError(code, message)
        for line in stderr.splitlines():
            message = line.strip()
            if re.fullmatch(
                r"通配符 \*\.[a-z0-9.-]+ 会覆盖 VPS 域名 [a-z0-9.-]+，拒绝保存。",
                message,
            ):
                return TaskExecutionError("dynamic_dns_wildcard_conflict", message)
        return TaskExecutionError("dynamic_dns_failed", "动态 DNS 自动更新操作失败。")

    def change_duckdns(
        self, operation: str, provider: str, fqdn: str, token: str, secret_id: str,
        secret_key: str, zone: str, actor: str,
    ) -> dict[str, Any]:
        if operation not in {"configure", "update", "disable", "delete"} or not actor or len(actor) > 150:
            raise ValueError("动态 DNS 自动更新参数格式不正确")
        input_text = json.dumps({
            "provider": provider, "fqdn": fqdn, "token": token, "secret_id": secret_id,
            "secret_key": secret_key, "zone": zone,
        }, separators=(",", ":")) + "\n" if operation == "configure" else None
        completed = self._run(["network", "duckdns", operation, "--json"], 30.0, input_text)
        audit_operation = f"duckdns_{operation}"
        if completed.returncode != 0:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise self._duckdns_error(completed.stderr)
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", audit_operation, "indeterminate")
            raise RuntimeError("动态 DNS 自动更新响应无效") from exc
        expected = {
            "configure": {"schema_version", "operation", "configured", "enabled", "provider", "fqdn", "last_ipv4", "record_created"},
            "update": {"schema_version", "operation", "configured", "enabled", "provider", "last_ipv4", "last_update_at"},
            "disable": {"schema_version", "operation", "configured", "enabled", "provider"},
            "delete": {"schema_version", "operation", "configured", "enabled", "provider"},
        }[operation]
        if (
            not isinstance(payload, dict) or set(payload) != expected
            or payload.get("schema_version") != 2 or payload.get("operation") != operation
            or not isinstance(payload.get("configured"), bool)
            or not isinstance(payload.get("enabled"), bool)
            or not isinstance(payload.get("provider"), str)
            or (operation == "configure" and not isinstance(payload.get("record_created"), bool))
            or any(not isinstance(payload.get(key), str) for key in expected & {"fqdn", "last_ipv4", "last_update_at"})
            or (operation in {"configure", "update"} and (payload.get("configured") is not True or payload.get("enabled") is not True))
            or (operation in {"disable", "delete"} and payload.get("enabled") is not False)
        ):
            self._append_audit(actor, "network", audit_operation, "indeterminate")
            raise RuntimeError("动态 DNS 自动更新响应版本不受支持")
        self._append_audit(actor, "network", audit_operation, "success")
        return payload

    def public_endpoint_transaction_status(
        self, actor: str, session_id: str
    ) -> dict[str, Any]:
        return self.change_public_endpoint("status", "", actor, session_id, "")

    def change_public_endpoint(
        self, operation: str, fqdn: str, actor: str, session_id: str,
        transaction_id: str = "",
    ) -> dict[str, Any]:
        if (
            operation not in {"status", "apply", "confirm", "rollback"}
            or not actor or len(actor) > 150
            or re.fullmatch(r"[0-9a-f]{64}", session_id) is None
            or (operation != "apply" and fqdn)
            or (transaction_id and TRANSACTION_ID_PATTERN.fullmatch(transaction_id) is None)
            or (operation in {"confirm", "rollback"} and not transaction_id)
            or (operation in {"status", "apply"} and transaction_id)
        ):
            raise ValueError("稳定公网入口参数格式不正确")
        command_operation = "transaction-status" if operation == "status" else operation
        arguments = ["network", "public-endpoint", command_operation, "--json"]
        request_text = json.dumps(
            {
                "fqdn": fqdn, "session_id": session_id, "actor": actor,
                "transaction_id": transaction_id,
            },
            ensure_ascii=False, separators=(",", ":"),
        ) + "\n"
        audit_operation = f"public_endpoint_{operation}"
        completed = self._run(arguments, 240.0, request_text)
        if completed.returncode != 0:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("稳定公网入口变更失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", audit_operation, "indeterminate")
            raise RuntimeError("稳定公网入口变更响应无效") from exc
        expected = {
            "schema_version", "operation", "fqdn", "subscriptions_refreshed", "state",
            "expires_at", "remaining_seconds", "rollback_seconds", "independent_session",
            "last_outcome", "transaction_id",
        }
        expires_at_valid = False
        expires_at_consistent = False
        if isinstance(payload, dict) and isinstance(payload.get("expires_at"), str):
            try:
                parsed_expiry = datetime.fromisoformat(payload["expires_at"])
                expires_at_valid = parsed_expiry.tzinfo is not None
                response_remaining = payload.get("remaining_seconds")
                if expires_at_valid and type(response_remaining) is int:
                    seconds_until_expiry = (
                        parsed_expiry - datetime.now(parsed_expiry.tzinfo)
                    ).total_seconds()
                    expires_at_consistent = abs(seconds_until_expiry - response_remaining) <= 5
            except ValueError:
                pass
        response_fqdn = payload.get("fqdn") if isinstance(payload, dict) else None
        response_state = payload.get("state") if isinstance(payload, dict) else None
        remaining = payload.get("remaining_seconds") if isinstance(payload, dict) else None
        rollback = payload.get("rollback_seconds") if isinstance(payload, dict) else None
        outcome = payload.get("last_outcome") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict) or set(payload) != expected
            or payload.get("schema_version") != 1
            or payload.get("operation") != operation
            or not isinstance(payload.get("fqdn"), str)
            or not isinstance(payload.get("subscriptions_refreshed"), bool)
            or payload.get("state") not in {"idle", "pending"}
            or not isinstance(payload.get("expires_at"), str)
            or type(payload.get("remaining_seconds")) is not int
            or type(payload.get("rollback_seconds")) is not int
            or not isinstance(payload.get("independent_session"), bool)
            or payload.get("last_outcome") not in {"", "confirmed", "rolled_back", "automatic_rollback"}
            or not isinstance(payload.get("transaction_id"), str)
            or (
                payload.get("transaction_id") != ""
                and TRANSACTION_ID_PATTERN.fullmatch(payload.get("transaction_id", "")) is None
            )
            or (operation == "apply" and payload.get("state") != "pending")
            or (operation in {"confirm", "rollback"} and payload.get("state") != "idle")
            or not 60 <= rollback <= 3600
            or not 0 <= remaining <= rollback
            or (response_fqdn != "" and PUBLIC_FQDN_PATTERN.fullmatch(response_fqdn) is None)
            or (operation == "apply" and response_fqdn != fqdn)
            or (response_state == "pending" and (not expires_at_valid or not expires_at_consistent or outcome != ""))
            or (response_state == "idle" and (payload.get("expires_at") != "" or remaining != 0 or not payload.get("independent_session")))
            or (operation == "confirm" and outcome != "confirmed")
            or (operation == "rollback" and outcome != "rolled_back")
            or (operation == "apply" and not payload.get("transaction_id"))
            or (
                operation in {"confirm", "rollback"}
                and payload.get("transaction_id") != transaction_id
            )
        ):
            self._append_audit(actor, "network", audit_operation, "indeterminate")
            raise RuntimeError("稳定公网入口变更响应版本不受支持")
        self._append_audit(actor, "network", audit_operation, "success")
        return payload

    def audit_log(self) -> dict[str, Any]:
        path = self._audit_path
        if not path.exists():
            return {"schema_version": 1, "chain_valid": True, "items": []}
        if path.is_symlink() or path.stat().st_size > 20_000_000:
            raise RuntimeError("审计日志路径或大小无效")
        previous_hash = "0" * 64
        items: list[dict[str, str]] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise RuntimeError("无法读取审计日志") from exc
        for line in lines:
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError("审计日志链已损坏") from exc
            expected_keys = {"timestamp", "actor", "service_id", "operation", "outcome", "previous_hash", "hash"}
            if not isinstance(record, dict) or set(record) != expected_keys or record.get("previous_hash") != previous_hash:
                raise RuntimeError("审计日志链已损坏")
            supplied_hash = record.pop("hash")
            canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            calculated_hash = hashlib.sha256(canonical).hexdigest()
            if supplied_hash != calculated_hash:
                raise RuntimeError("审计日志链已损坏")
            previous_hash = supplied_hash
            public = {key: record[key] for key in ("timestamp", "actor", "service_id", "operation", "outcome")}
            if not all(isinstance(value, str) and len(value) <= 200 for value in public.values()):
                raise RuntimeError("审计日志字段无效")
            items.append(public)
        return {"schema_version": 1, "chain_valid": True, "items": list(reversed(items[-200:]))}

    def record_event(self, service_id: str, operation: str, actor: str) -> dict[str, Any]:
        if service_id != "accounts" or operation not in {"account_create", "account_enable", "account_disable", "account_password_reset"}:
            raise ValueError("审计事件未登记")
        if not actor or len(actor) > 150:
            raise ValueError("操作账号格式不正确")
        self._append_audit(actor, service_id, operation, "success")
        return {"schema_version": 1, "service_id": service_id, "operation": operation}

    @staticmethod
    def _validate_proxy_overview(payload: object) -> dict[str, Any]:
        expected = {
            "schema_version", "revision", "configured", "airport_count", "active_airport_count",
            "airports", "country_options", "exit", "exit_count", "default_exit_id", "exits",
        }
        if not isinstance(payload, dict) or set(payload) != expected:
            raise RuntimeError("机场资源状态版本不受支持")
        airports = payload.get("airports")
        country_options = payload.get("country_options")
        exit_node = payload.get("exit")
        exits = payload.get("exits")
        valid = (
            payload.get("schema_version") == 3
            and isinstance(payload.get("revision"), str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", payload.get("revision", "")))
            and isinstance(payload.get("configured"), bool)
            and isinstance(payload.get("airport_count"), int)
            and isinstance(payload.get("active_airport_count"), int)
            and isinstance(airports, list)
            and all(
                isinstance(item, dict)
                and set(item) == {"id", "name", "host", "enabled", "countries", "country_labels"}
                and all(isinstance(item.get(key), str) for key in {"id", "name", "host"})
                and isinstance(item.get("enabled"), bool)
                and isinstance(item.get("countries"), list)
                and isinstance(item.get("country_labels"), list)
                and all(isinstance(value, str) for value in item["countries"] + item["country_labels"])
                for item in airports
            )
            and isinstance(country_options, list)
            and all(
                isinstance(item, dict) and set(item) == {"id", "label"}
                and all(isinstance(item.get(key), str) for key in {"id", "label"})
                for item in country_options
            )
            and isinstance(exit_node, dict) and set(exit_node) == {"configured", "type", "server", "port"}
            and isinstance(exit_node.get("configured"), bool)
            and all(isinstance(exit_node.get(key), str) for key in {"type", "server"})
            and isinstance(exit_node.get("port"), int) and 0 <= exit_node.get("port") <= 65535
            and isinstance(payload.get("exit_count"), int)
            and isinstance(payload.get("default_exit_id"), str)
            and isinstance(exits, list)
            and all(
                isinstance(item, dict)
                and set(item) == {"id", "name", "default", "type", "server", "port"}
                and all(isinstance(item.get(key), str) for key in {"id", "name", "type", "server"})
                and isinstance(item.get("default"), bool)
                and isinstance(item.get("port"), int) and 1 <= item["port"] <= 65535
                for item in exits
            )
        )
        if not valid:
            raise RuntimeError("机场资源状态版本不受支持")
        if payload["airport_count"] != len(airports) or not 0 <= payload["active_airport_count"] <= len(airports):
            raise RuntimeError("机场资源状态计数无效")
        if payload["exit_count"] != len(exits) or sum(1 for item in exits if item["default"]) != (1 if exits else 0):
            raise RuntimeError("出口节点状态计数无效")
        return payload

    def enrollment_context(self) -> dict[str, Any]:
        completed = self._run(["network", "enrollment", "context", "--json"], self._timeout)
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 64_000:
            raise RuntimeError("无法读取 AWG 节点登记参数")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("AWG 节点登记参数响应无效") from exc
        endpoints = payload.get("endpoints") if isinstance(payload, dict) else None
        endpoint_profiles = (
            [item.get("profile") for item in endpoints]
            if isinstance(endpoints, list) and all(isinstance(item, dict) for item in endpoints)
            else []
        )
        if (
            not isinstance(payload, dict) or payload.get("schema_version") != 1
            or endpoint_profiles not in (["main", "backup1"], ["main", "backup1", "backup2"])
            or not all(
                isinstance(item.get("host"), str)
                and 1 <= len(item["host"]) <= 253
                and not re.search(r"\s", item["host"])
                and type(item.get("port")) is int
                and 1 <= item["port"] <= 65_535
                for item in endpoints
            )
            or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", str(payload.get("server_public_key", "")))
        ):
            raise RuntimeError("AWG 节点登记参数版本不受支持")
        encoded = json.dumps(payload, ensure_ascii=False).lower()
        if "private" in encoded or "preshared" in encoded:
            raise RuntimeError("AWG 节点登记参数包含秘密字段")
        return payload

    def proxy_resources(self) -> dict[str, Any]:
        completed = self._run(["network", "proxy", "overview", "--json"], self._timeout)
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 20_000:
            raise RuntimeError("无法读取机场资源状态")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("机场资源状态格式无效") from exc
        return self._validate_proxy_overview(payload)

    def test_proxy_resources(self, actor: str) -> dict[str, Any]:
        if not actor or len(actor) > 150:
            raise ValueError("操作账号格式不正确")
        try:
            completed = self._run(["network", "proxy", "test", "--json"], 30.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "clash", "proxy_resources_test", "timeout")
            raise RuntimeError("机场资源测试超时") from exc
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 10_000:
            self._append_audit(actor, "clash", "proxy_resources_test", "failed")
            raise RuntimeError("机场资源测试失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "clash", "proxy_resources_test", "failed")
            raise RuntimeError("机场资源测试响应无效") from exc
        airports = payload.get("airports") if isinstance(payload, dict) else None
        exits = payload.get("exits") if isinstance(payload, dict) else None
        valid = (
            isinstance(payload, dict) and set(payload) == {"schema_version", "airports", "exits", "all_ok"}
            and payload.get("schema_version") == 3 and isinstance(payload.get("all_ok"), bool)
            and isinstance(airports, list)
            and all(
                isinstance(item, dict)
                and set(item) == {"id", "name", "enabled", "ok", "status"}
                and all(isinstance(item.get(key), str) for key in {"id", "name", "status"})
                and isinstance(item.get("enabled"), bool) and isinstance(item.get("ok"), bool)
                for item in airports
            )
            and isinstance(exits, list)
            and all(
                isinstance(item, dict)
                and set(item) == {"id", "name", "default", "ok", "status"}
                and all(isinstance(item.get(key), str) for key in {"id", "name", "status"})
                and isinstance(item.get("default"), bool)
                and isinstance(item.get("ok"), bool)
                for item in exits
            )
        )
        if not valid:
            self._append_audit(actor, "clash", "proxy_resources_test", "failed")
            raise RuntimeError("机场资源测试响应版本不受支持")
        self._append_audit(actor, "clash", "proxy_resources_test", "success" if payload["all_ok"] else "failed")
        return payload

    def update_proxy_resources(self, values: dict[str, object], actor: str) -> dict[str, Any]:
        if not actor or len(actor) > 150 or not isinstance(values, dict):
            raise ValueError("机场资源参数格式不正确")
        input_text = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
        if len(input_text.encode("utf-8")) > 80_000:
            raise ValueError("机场资源参数过长")
        try:
            completed = self._run(["network", "proxy", "update", "--json"], 240.0, input_text)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "clash", "proxy_resources_update", "timeout")
            raise TaskExecutionError(
                "proxy_update_timeout",
                "代理资源更新在 240 秒内没有完成；请重新读取实际状态后再试，避免重复提交。",
            ) from exc
        if completed.returncode != 0:
            self._append_audit(actor, "clash", "proxy_resources_update", "failed")
            raise self._proxy_update_error(completed.stderr)
        if len(completed.stdout.encode("utf-8")) > 20_000:
            self._append_audit(actor, "clash", "proxy_resources_update", "failed")
            raise TaskExecutionError(
                "proxy_update_response_too_large",
                "代理资源更新返回的数据异常过大，管理代理拒绝接收；请重新读取实际状态。",
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "clash", "proxy_resources_update", "failed")
            raise TaskExecutionError(
                "proxy_update_response_invalid",
                "代理资源可能已经更新，但管理代理无法解析核验结果；请重新读取实际状态，避免重复提交。",
            ) from exc
        try:
            result = self._validate_proxy_overview(payload)
        except RuntimeError as exc:
            self._append_audit(actor, "clash", "proxy_resources_update", "failed")
            raise TaskExecutionError(
                "proxy_update_verification_failed",
                "代理资源可能已经更新，但返回结果未通过结构核验；请重新读取实际状态，避免重复提交。",
            ) from exc
        self._append_audit(actor, "clash", "proxy_resources_update", "success")
        return result

    def deploy_service(self, service_id: str, values: dict[str, Any], actor: str) -> dict[str, Any]:
        if service_id not in {"vless", "clash", "mosh", "file"} or not actor or len(actor) > 150:
            raise ValueError("部署服务未登记")
        input_text = None
        if service_id == "vless":
            arguments = ["deploy", "vless", values["port"], values["server_name"], "--json"]
        elif service_id == "clash":
            arguments = ["deploy", "clash", values["port"], "--json"]
            input_text = json.dumps(
                {"airport_url": values["airport_url"], "exit_proxy_yaml": values["exit_proxy_yaml"]},
                ensure_ascii=False, separators=(",", ":"),
            )
        elif service_id == "mosh":
            arguments = ["deploy", "mosh", "--json"]
        else:
            arguments = ["deploy", "file", values["port"], values["upload_id"], values["download_name"], "--json"]
        operation = f"deploy_{service_id}"
        try:
            completed = self._run(arguments, 900.0, input_text)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, service_id, operation, "timeout")
            raise RuntimeError("服务安装超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("服务安装失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("服务安装响应无效") from exc
        if payload != {"schema_version": 1, "service_id": service_id, "state": "completed"}:
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("服务安装响应版本不受支持")
        try:
            snapshot = self.snapshot()
            inventory = self.service_inventory(service_id)
        except (RuntimeError, ValueError) as exc:
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("服务安装完成，但无法核验实际状态") from exc
        matches = [
            item for item in snapshot.get("services", [])
            if isinstance(item, dict) and item.get("id") == service_id
        ]
        if len(matches) != 1 or matches[0].get("state") != "运行中":
            self._append_audit(actor, service_id, operation, "failed")
            raise RuntimeError("服务安装未通过运行状态核验")
        result = {
            **payload,
            "service": matches[0],
            "verification": {
                "snapshot": True,
                "inventory": inventory.get("service_id") == service_id,
            },
        }
        self._append_audit(actor, service_id, operation, "success")
        return result

    def change_network_node(
        self, kind: str, operation: str, name: str, address: str, actor: str,
    ) -> dict[str, Any]:
        if kind not in {"awg", "vless"} or operation not in {
            "add", "enable", "disable", "remove", "set-management",
            "compat-enable", "compat-disable", "clean-enable", "clean-disable",
        }:
            raise ValueError("节点动作未登记")
        if not NODE_NAME_PATTERN.fullmatch(name) or not actor or len(actor) > 150:
            raise ValueError("节点参数格式不正确")
        arguments = ["network", "node", kind, operation, name]
        if address:
            arguments.append(address)
        arguments.append("--json")
        audit_operation = f"node_{kind}_{operation}"
        try:
            completed = self._run(arguments, 180.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", audit_operation, "timeout")
            raise RuntimeError("节点操作超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("节点操作失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("节点操作响应无效") from exc
        if payload != {"schema_version": 1, "kind": kind, "operation": operation, "name": name}:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("节点操作响应版本不受支持")
        self._append_audit(actor, "network", audit_operation, "success")
        return payload

    def import_network_node(
        self, name: str, address: str, public_key: str, preshared_key: str, actor: str,
    ) -> dict[str, Any]:
        if not NODE_NAME_PATTERN.fullmatch(name) or not actor or len(actor) > 150:
            raise ValueError("节点参数格式不正确")
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public_key) or not re.fullmatch(
            r"[A-Za-z0-9+/]{43}=", preshared_key
        ):
            raise ValueError("AWG 密钥格式不正确")
        arguments = ["network", "node", "awg", "import", name, address, public_key, "--json"]
        try:
            completed = self._run(arguments, 180.0, input_text=f"{preshared_key}\n")
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", "node_awg_import", "timeout")
            raise RuntimeError("节点导入超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", "node_awg_import", "failed")
            raise RuntimeError("节点导入失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("节点导入响应无效") from exc
        if payload != {"schema_version": 1, "kind": "awg", "operation": "import", "name": name}:
            raise RuntimeError("节点导入响应版本不受支持")
        self._append_audit(actor, "network", "node_awg_import", "success")
        return payload

    def change_node_domains(
        self, name: str, domains: list[str], actor: str
    ) -> dict[str, Any]:
        if not NODE_NAME_PATTERN.fullmatch(name) or not actor or len(actor) > 150:
            raise ValueError("节点域名参数格式不正确")
        if not isinstance(domains, list) or any(not isinstance(item, str) for item in domains):
            raise ValueError("节点域名列表格式不正确")
        encoded = json.dumps(domains, ensure_ascii=True, separators=(",", ":"))
        audit_operation = "node_domains_set"
        try:
            completed = self._run(
                ["network", "domains", "set", name, encoded, "--json"], 240.0
            )
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", audit_operation, "timeout")
            raise RuntimeError("节点域名更新超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("节点域名更新失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("节点域名响应无效") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != 1
            or payload.get("operation") != "set"
            or payload.get("name") != name
            or payload.get("domains") != domains
            or not isinstance(payload.get("address"), str)
            or not isinstance(payload.get("subscriptions_refreshed"), bool)
        ):
            raise RuntimeError("节点域名响应版本不受支持")
        self._append_audit(actor, "network", audit_operation, "success")
        return payload

    def change_address_domains(
        self, address: str, domains: list[str], actor: str
    ) -> dict[str, Any]:
        try:
            clean_address = str(ipaddress.ip_address(address))
        except ValueError as error:
            raise ValueError("目标 IP 格式不正确") from error
        if not actor or len(actor) > 150:
            raise ValueError("操作账号格式不正确")
        if not isinstance(domains, list) or any(not isinstance(item, str) for item in domains):
            raise ValueError("自定义强制解析域名列表格式不正确")
        encoded = json.dumps(domains, ensure_ascii=True, separators=(",", ":"))
        audit_operation = "address_domains_set"
        try:
            completed = self._run(
                ["network", "domains", "set-address", clean_address, encoded, "--json"],
                240.0,
            )
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", audit_operation, "timeout")
            raise RuntimeError("自定义强制解析更新超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("自定义强制解析更新失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("自定义强制解析响应无效") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != 1
            or payload.get("operation") != "set-address"
            or payload.get("address") != clean_address
            or payload.get("domains") != domains
            or not isinstance(payload.get("subscriptions_refreshed"), bool)
        ):
            raise RuntimeError("自定义强制解析响应版本不受支持")
        self._append_audit(actor, "network", audit_operation, "success")
        return payload

    def sync_network_subscriptions(self, actor: str) -> dict[str, Any]:
        try:
            completed = self._run(["network", "subscriptions", "sync", "--json"], 180.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", "subscriptions_sync", "timeout")
            raise RuntimeError("订阅同步超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", "subscriptions_sync", "failed")
            raise RuntimeError("订阅同步失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", "subscriptions_sync", "failed")
            raise RuntimeError("订阅同步响应无效") from exc
        if payload != {"schema_version": 1, "operation": "sync", "state": "completed"}:
            self._append_audit(actor, "network", "subscriptions_sync", "failed")
            raise RuntimeError("订阅同步响应版本不受支持")
        self._append_audit(actor, "network", "subscriptions_sync", "success")
        return payload

    def rotate_network_subscription(self, name: str, actor: str) -> dict[str, Any]:
        if not NODE_NAME_PATTERN.fullmatch(name) or not actor or len(actor) > 150:
            raise ValueError("订阅参数格式不正确")
        try:
            completed = self._run(["network", "subscriptions", "rotate", name, "--json"], 180.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", "subscription_rotate", "timeout")
            raise RuntimeError("订阅令牌轮换超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", "subscription_rotate", "failed")
            raise RuntimeError("订阅令牌轮换失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", "subscription_rotate", "failed")
            raise RuntimeError("订阅令牌轮换响应无效") from exc
        if payload != {"schema_version": 1, "operation": "rotate", "name": name}:
            self._append_audit(actor, "network", "subscription_rotate", "failed")
            raise RuntimeError("订阅令牌轮换响应版本不受支持")
        self._append_audit(actor, "network", "subscription_rotate", "success")
        return payload

    def set_network_subscription_state(self, name: str, state: str, actor: str) -> dict[str, Any]:
        if not NODE_NAME_PATTERN.fullmatch(name) or state not in {"enabled", "disabled"} or not actor or len(actor) > 150:
            raise ValueError("订阅发布状态参数不正确")
        operation = "subscription_enable" if state == "enabled" else "subscription_disable"
        try:
            completed = self._run(["network", "subscriptions", "set-state", name, state, "--json"], 240.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", operation, "timeout")
            raise RuntimeError("订阅发布状态切换超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", operation, "failed")
            raise RuntimeError("订阅发布状态切换失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", operation, "failed")
            raise RuntimeError("订阅发布状态响应无效") from exc
        expected = {"schema_version": 1, "operation": "set-state", "name": name, "state": state}
        if payload != expected:
            self._append_audit(actor, "network", operation, "failed")
            raise RuntimeError("订阅发布状态响应版本不受支持")
        self._append_audit(actor, "network", operation, "success")
        return payload

    def change_network_permission(
        self, operation: str, client: str, target: str, ports: str,
        network: str, actor: str,
    ) -> dict[str, Any]:
        if operation not in {"allow", "deny"}:
            raise ValueError("权限动作未登记")
        if not NODE_NAME_PATTERN.fullmatch(client) or not actor or len(actor) > 150:
            raise ValueError("权限参数格式不正确")
        if not NODE_NAME_PATTERN.fullmatch(target):
            raise ValueError("权限参数格式不正确")
        if network == "all":
            if ports:
                raise ValueError("权限参数格式不正确")
        elif network in {"tcp", "udp"}:
            if not ports:
                raise ValueError("权限参数格式不正确")
        elif ports or network:
            raise ValueError("权限参数格式不正确")
        arguments = ["network", "permission", operation, client, target]
        if network:
            arguments.extend([ports, network])
        arguments.append("--json")
        audit_operation = f"permission_{operation}"
        try:
            completed = self._run(arguments, 180.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", audit_operation, "timeout")
            raise RuntimeError("权限操作超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("权限操作失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("权限操作响应无效") from exc
        expected = {"schema_version": 1, "operation": operation, "client": client, "target": target}
        if payload != expected:
            self._append_audit(actor, "network", audit_operation, "failed")
            raise RuntimeError("权限操作响应版本不受支持")
        self._append_audit(actor, "network", audit_operation, "success")
        return payload

    def add_network_permissions(
        self, client: str, rules: list[dict[str, str]], actor: str,
    ) -> dict[str, Any]:
        if not isinstance(client, str) or not NODE_NAME_PATTERN.fullmatch(client) or not actor or len(actor) > 150:
            raise ValueError("权限参数格式不正确")
        rules = normalize_rules(rules)
        arguments = ["network", "permission", "batch", client, "--json"]
        try:
            completed = self._run(arguments, 180.0, json.dumps(rules, ensure_ascii=False))
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "network", "permission_batch", "timeout")
            raise RuntimeError("批量权限操作超时，请重新读取实际状态") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "network", "permission_batch", "failed")
            if "SERVER_KIT_DIAGNOSTIC:permission_recovery_required" in completed.stderr.splitlines():
                raise TaskExecutionError(
                    "permission_recovery_required",
                    "批量权限应用失败，自动恢复未能完成。请不要重复提交；使用现有管理连接检查服务与保留的策略备份。",
                )
            raise TaskExecutionError("permission_batch_failed", "批量权限操作失败；请重新读取实际状态后重新预览。")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "network", "permission_batch", "failed")
            raise RuntimeError("批量权限操作响应无效") from exc
        expected = {"schema_version": 1, "operation": "batch", "client": client}
        if payload != expected:
            self._append_audit(actor, "network", "permission_batch", "failed")
            raise RuntimeError("批量权限操作响应版本不受支持")
        self._append_audit(actor, "network", "permission_batch", "success")
        return payload

    def change_service(
        self, service_id: str, operation: str, actor: str
    ) -> dict[str, Any]:
        if service_id not in CHANGEABLE_SERVICE_IDS or operation not in SERVICE_OPERATIONS:
            raise ValueError("服务动作未登记")
        if not actor or len(actor) > 150:
            raise ValueError("操作账号格式不正确")
        try:
            completed = self._run([operation, service_id], 180.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, service_id, operation, "timeout")
            raise RuntimeError("服务操作超时，实际状态需要重新读取") from exc
        outcome = "success" if completed.returncode == 0 else "failed"
        self._append_audit(actor, service_id, operation, outcome)
        if completed.returncode != 0:
            raise RuntimeError("服务操作失败，请查看 root 审计和服务日志")
        return self.snapshot()

    def manage_transaction(
        self, transaction_type: str, operation: str, actor: str,
        session_id: str = "", public_ip: str = "", public_port: str = "",
    ) -> dict[str, Any]:
        transaction_types = {"ssh_auth", "ssh_listener", "firewall", "vless_listener"}
        operations = {"status", "preview", "apply", "confirm", "rollback"}
        if transaction_type not in transaction_types or operation not in operations:
            raise ValueError("安全事务动作未登记")
        if not actor or len(actor) > 150:
            raise ValueError("操作账号格式不正确")
        audit_operation = f"transaction_{transaction_type}_{operation}"
        timeout = 180.0 if operation in {"preview", "apply", "confirm", "rollback"} else self._timeout
        request = {"session_id": session_id, "actor": actor}
        if transaction_type != "vless_listener":
            request.update({"public_ip": public_ip, "public_port": public_port})
        input_text = json.dumps(
            request,
            ensure_ascii=False, separators=(",", ":"),
        )
        try:
            completed = self._run(
                ["transaction", transaction_type, operation, "--json"],
                timeout, input_text,
            )
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "security", audit_operation, "timeout")
            raise RuntimeError("安全事务操作超时，实际状态需要重新读取") from exc
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 200_000:
            self._append_audit(actor, "security", audit_operation, "failed")
            raise RuntimeError("安全事务操作失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "security", audit_operation, "failed")
            raise RuntimeError("安全事务响应格式无效") from exc
        expected = {
            "schema_version", "transaction_type", "title", "state", "expires_at",
            "remaining_seconds", "writes_enabled", "rollback_seconds", "changes", "verifications",
            "ready", "blockers", "independent_session",
        }
        if transaction_type == "vless_listener":
            expected.update({"transaction_id", "last_outcome"})
        valid = (
            isinstance(payload, dict)
            and set(payload) == expected
            and payload.get("schema_version") == 1
            and payload.get("transaction_type") == transaction_type
            and payload.get("state") in {"idle", "pending"}
            and isinstance(payload.get("writes_enabled"), bool)
            and isinstance(payload.get("ready"), bool)
            and isinstance(payload.get("independent_session"), bool)
            and isinstance(payload.get("remaining_seconds"), int)
            and isinstance(payload.get("changes"), list)
            and isinstance(payload.get("verifications"), list)
            and isinstance(payload.get("blockers"), list)
            and isinstance(payload.get("title"), str)
            and isinstance(payload.get("expires_at"), str)
            and isinstance(payload.get("rollback_seconds"), int)
            and 60 <= payload.get("rollback_seconds", 0) <= 3600
            and all(
                isinstance(item, dict)
                and set(item) == {"label", "current", "target", "changed"}
                and all(isinstance(item.get(key), str) for key in {"label", "current", "target"})
                and isinstance(item.get("changed"), bool)
                for item in payload.get("changes", [])
            )
            and all(isinstance(item, str) for item in payload.get("verifications", []))
            and all(isinstance(item, str) for item in payload.get("blockers", []))
        )
        if valid and transaction_type == "vless_listener":
            transaction_id = payload.get("transaction_id")
            last_outcome = payload.get("last_outcome")
            valid = (
                isinstance(transaction_id, str)
                and (not transaction_id or TRANSACTION_ID_PATTERN.fullmatch(transaction_id) is not None)
                and last_outcome in {"", "confirmed", "rolled_back", "automatic_rollback"}
                and (
                    payload.get("state") != "pending"
                    or bool(transaction_id) and last_outcome == ""
                )
            )
        if not valid:
            self._append_audit(actor, "security", audit_operation, "failed")
            raise RuntimeError("安全事务响应版本不受支持")
        expected_states = {"apply": "pending", "confirm": "idle", "rollback": "idle"}
        if operation in expected_states and payload.get("state") != expected_states[operation]:
            self._append_audit(actor, "security", audit_operation, "failed")
            raise RuntimeError("安全事务执行后状态核验失败")
        if transaction_type == "vless_listener" and (
            (operation == "apply" and not payload.get("transaction_id"))
            or (operation == "confirm" and payload.get("last_outcome") != "confirmed")
            or (operation == "rollback" and payload.get("last_outcome") != "rolled_back")
        ):
            self._append_audit(actor, "security", audit_operation, "failed")
            raise RuntimeError("安全事务执行后结果核验失败")
        self._append_audit(actor, "security", audit_operation, "success")
        return payload

    @staticmethod
    def _validate_firewall_ports_payload(payload: object) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "firewall_active", "items"
        } or payload.get("schema_version") != 1 or not isinstance(payload.get("firewall_active"), bool):
            raise RuntimeError("自定义防火墙端口响应版本不受支持")
        items = payload.get("items")
        valid = isinstance(items, list) and all(
            isinstance(item, dict)
            and set(item) == {
                "scope", "scope_label", "protocol", "port", "duration",
                "expires_at", "remaining_seconds", "active",
            }
            and item.get("scope") in {"public", "amneziawg"}
            and item.get("protocol") in {"tcp", "udp"}
            and isinstance(item.get("port"), int)
            and 1 <= item.get("port", 0) <= 65535
            and item.get("duration") in {"temporary", "permanent"}
            and isinstance(item.get("expires_at"), str)
            and isinstance(item.get("remaining_seconds"), int)
            and isinstance(item.get("active"), bool)
            for item in items
        )
        if not valid:
            raise RuntimeError("自定义防火墙端口响应版本不受支持")
        return payload

    def firewall_ports(self) -> dict[str, Any]:
        completed = self._run(["firewall-port", "list", "--json"], self._timeout)
        if completed.returncode != 0:
            raise RuntimeError("无法读取自定义防火墙端口")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("自定义防火墙端口响应无效") from exc
        return self._validate_firewall_ports_payload(payload)

    @classmethod
    def _validate_firewall_change_payload(cls, payload: object) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "firewall_active", "items", "verification"
        }:
            raise RuntimeError("自定义防火墙端口变更响应版本不受支持")
        verification = payload.get("verification")
        if (
            not isinstance(verification, dict)
            or set(verification) != {"facts", "nftables"}
            or verification.get("facts") is not True
            or verification.get("nftables") is not True
        ):
            raise RuntimeError("自定义防火墙端口事实与 nftables 规则不一致")
        base = {
            key: value for key, value in payload.items() if key != "verification"
        }
        cls._validate_firewall_ports_payload(base)
        return payload

    def change_firewall_port(
        self, operation: str, port: int, scope: str, protocol: str,
        duration_seconds: int, actor: str,
    ) -> dict[str, Any]:
        if operation not in {"open", "close"} or scope not in {"public", "amneziawg"} or protocol not in {"tcp", "udp", "both"}:
            raise ValueError("自定义防火墙端口动作未登记")
        arguments = ["firewall-port", operation, str(port), scope, protocol]
        if operation == "open":
            arguments.append("permanent" if duration_seconds == 0 else str(duration_seconds))
        arguments.append("--json")
        try:
            completed = self._run(arguments, self._timeout)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "firewall", f"custom_port_{operation}", "timeout")
            raise RuntimeError("自定义防火墙端口操作超时") from exc
        if completed.returncode != 0:
            self._append_audit(actor, "firewall", f"custom_port_{operation}", "failed")
            raise RuntimeError("自定义防火墙端口操作失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "firewall", f"custom_port_{operation}", "failed")
            raise RuntimeError("自定义防火墙端口响应无效") from exc
        try:
            result = self._validate_firewall_change_payload(payload)
        except RuntimeError:
            self._append_audit(actor, "firewall", f"custom_port_{operation}", "failed")
            raise
        self._append_audit(actor, "firewall", f"custom_port_{operation}", "success")
        return result

    @staticmethod
    def _validate_managed_ports_payload(payload: object) -> dict[str, Any]:
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "revision", "items", "occupied"}
            or payload.get("schema_version") != 1
            or re.fullmatch(r"[0-9a-f]{64}", str(payload.get("revision", ""))) is None
        ):
            raise RuntimeError("托管服务端口响应版本不受支持")
        items = payload.get("items")
        required = {
            "id", "service_id", "label", "protocol", "scope", "port", "minimum",
            "maximum", "installed", "active", "listening", "restart_required", "impact",
        }
        if not isinstance(items, list) or not all(
            isinstance(item, dict) and set(item) == required
            and item.get("id") in {"clash", "file", "awg-backup1", "awg-backup2"}
            and item.get("service_id") in {"clash", "file", "amneziawg"}
            and item.get("protocol") in {"tcp", "udp"}
            and item.get("scope") == "public"
            and (item.get("port") is None or isinstance(item.get("port"), int))
            and all(isinstance(item.get(key), bool) for key in {
                "installed", "active", "listening", "restart_required"
            })
            and all(isinstance(item.get(key), str) for key in {"label", "impact"})
            for item in items
        ):
            raise RuntimeError("托管服务端口项目格式无效")
        if not isinstance(payload.get("occupied"), list):
            raise RuntimeError("托管端口占用事实格式无效")
        return payload

    def managed_ports(self) -> dict[str, Any]:
        completed = self._run(["managed-port", "list", "--json"], self._timeout)
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 500_000:
            raise RuntimeError("无法读取托管服务端口")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("托管服务端口响应无效") from exc
        return self._validate_managed_ports_payload(payload)

    def change_managed_port(
        self, target_id: str, port: int, revision: str, actor: str,
    ) -> dict[str, Any]:
        if target_id not in {"clash", "file", "awg-backup1", "awg-backup2"}:
            raise ValueError("托管服务端口目标未登记")
        arguments = ["managed-port", "change", target_id, str(port), revision, "--json"]
        try:
            completed = self._run(arguments, 240.0)
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, target_id, "managed_port_change", "timeout")
            raise RuntimeError("托管服务端口操作超时，系统可能正在自动回滚") from exc
        if completed.returncode != 0:
            self._append_audit(actor, target_id, "managed_port_change", "failed")
            raise RuntimeError("托管服务端口操作失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, target_id, "managed_port_change", "failed")
            raise RuntimeError("托管服务端口变更响应无效") from exc
        if not isinstance(payload, dict) or set(payload) != {"changed", "plan", "overview"} or payload.get("changed") is not True:
            raise RuntimeError("托管服务端口变更响应版本不受支持")
        self._validate_managed_ports_payload(payload.get("overview"))
        self._append_audit(actor, target_id, "managed_port_change", "success")
        return payload

    @staticmethod
    def _validate_ssh_keys_payload(payload: object) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"schema_version", "items"} or payload.get("schema_version") != 1:
            raise RuntimeError("SSH 公钥清单版本不受支持")
        items = payload.get("items")
        key_types = {
            "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
        }
        valid = isinstance(items, list) and all(
            isinstance(item, dict)
            and set(item) == {"type", "fingerprint", "name", "key_id", "deletable"}
            and item.get("type") in key_types
            and isinstance(item.get("fingerprint"), str)
            and str(item.get("fingerprint", "")).startswith("SHA256:")
            and isinstance(item.get("name"), str)
            and isinstance(item.get("key_id"), str)
            and re.fullmatch(r"key-[0-9a-f]{64}", str(item.get("key_id", ""))) is not None
            and isinstance(item.get("deletable"), bool)
            for item in items
        )
        if not valid:
            raise RuntimeError("SSH 公钥清单版本不受支持")
        return payload

    def ssh_keys(self) -> dict[str, Any]:
        completed = self._run(["ssh-key", "list", "--json"], self._timeout)
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 900_000:
            raise RuntimeError("无法读取 SSH 公钥清单")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("SSH 公钥清单响应无效") from exc
        return self._validate_ssh_keys_payload(payload)

    def preview_ssh_key(self, public_key: str, actor: str) -> dict[str, Any]:
        if (
            not isinstance(public_key, str)
            or not 1 <= len(public_key.encode("utf-8")) <= 16384
            or any(char in public_key for char in ("\x00", "\r", "\n"))
            or not actor
            or len(actor) > 150
        ):
            raise ValueError("SSH 公钥预览参数无效")
        request_text = json.dumps({"public_key": public_key}, ensure_ascii=False, separators=(",", ":")) + "\n"
        completed = self._run(["ssh-key", "preview", "--json"], self._timeout, request_text)
        if completed.returncode != 0:
            self._append_audit(actor, "ssh", "ssh_key_preview", "failed")
            raise RuntimeError("SSH 公钥校验失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "ssh", "ssh_key_preview", "failed")
            raise RuntimeError("SSH 公钥预览响应无效") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {
                "schema_version", "pending_token", "type", "fingerprint",
                "name", "duplicate", "expires_in",
            }
            or payload.get("schema_version") != 1
            or re.fullmatch(r"[A-Za-z0-9_-]{20,80}", str(payload.get("pending_token", ""))) is None
            or not str(payload.get("fingerprint", "")).startswith("SHA256:")
            or not isinstance(payload.get("type"), str)
            or not isinstance(payload.get("name"), str)
            or not 1 <= len(payload.get("name", "")) <= 128
            or not isinstance(payload.get("duplicate"), bool)
            or payload.get("expires_in") != 300
        ):
            self._append_audit(actor, "ssh", "ssh_key_preview", "failed")
            raise RuntimeError("SSH 公钥预览版本不受支持")
        self._append_audit(actor, "ssh", "ssh_key_preview", "success")
        return payload

    def change_ssh_key(
        self, operation: str, item_id: str, name: str, actor: str
    ) -> dict[str, Any]:
        if operation not in {"add", "rename", "delete"} or not actor or len(actor) > 150:
            raise ValueError("SSH 公钥动作未登记")
        if operation == "add":
            valid_id = re.fullmatch(r"[A-Za-z0-9_-]{20,80}", item_id)
        else:
            valid_id = re.fullmatch(r"key-[0-9a-f]{64}", item_id)
        if valid_id is None or (operation == "rename" and not 1 <= len(name.strip()) <= 64) or (operation != "rename" and name):
            raise ValueError("SSH 公钥动作参数无效")
        input_text = None
        if operation == "rename":
            input_text = json.dumps({"name": name.strip()}, ensure_ascii=False, separators=(",", ":")) + "\n"
        completed = self._run(["ssh-key", operation, item_id, "--json"], self._timeout, input_text)
        audit_operation = f"ssh_key_{operation}"
        if completed.returncode != 0:
            self._append_audit(actor, "ssh", audit_operation, "failed")
            raise RuntimeError("SSH 公钥操作失败")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "ssh", audit_operation, "failed")
            raise RuntimeError("SSH 公钥操作响应无效") from exc
        state_field = {"add": "added", "rename": "renamed", "delete": "deleted"}[operation]
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", state_field, "key_id", "type", "fingerprint", "name"}
            or payload.get("schema_version") != 1
            or not isinstance(payload.get(state_field), bool)
            or re.fullmatch(r"key-[0-9a-f]{64}", str(payload.get("key_id", ""))) is None
            or not str(payload.get("fingerprint", "")).startswith("SHA256:")
            or not isinstance(payload.get("type"), str)
            or not isinstance(payload.get("name"), str)
        ):
            self._append_audit(actor, "ssh", audit_operation, "failed")
            raise RuntimeError("SSH 公钥操作响应版本不受支持")
        self._append_audit(actor, "ssh", audit_operation, "success")
        return payload

    def manage_backup(
        self, operation: str, backup_id: str, passphrase: str, actor: str,
        session_id: str = "",
    ) -> dict[str, Any]:
        operations = {
            "list", "create", "verify", "delete", "preview_restore", "restore_status",
            "restore_apply", "restore_confirm", "restore_rollback",
        }
        if operation not in operations or not actor or len(actor) > 150:
            raise ValueError("备份动作未登记")
        arguments = ["backup", operation.replace("_", "-")]
        if backup_id:
            arguments.append(backup_id)
        arguments.append("--json")
        audit_operation = f"backup_{operation}"
        input_text = json.dumps(
            {"passphrase": passphrase, "session_id": session_id, "actor": actor},
            ensure_ascii=False, separators=(",", ":"),
        )
        try:
            completed = self._run(
                arguments,
                180.0 if operation not in {"list", "restore_status"} else self._timeout,
                input_text,
            )
        except subprocess.TimeoutExpired as exc:
            self._append_audit(actor, "backup", audit_operation, "timeout")
            raise RuntimeError("备份操作超时") from exc
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 900_000:
            self._append_audit(actor, "backup", audit_operation, "failed")
            raise RuntimeError("备份操作失败")
        try:
            envelope = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self._append_audit(actor, "backup", audit_operation, "failed")
            raise RuntimeError("备份响应格式无效") from exc
        payload = envelope.get("result") if isinstance(envelope, dict) else None
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"schema_version", "ok", "result"}
            or envelope.get("schema_version") != 1
            or envelope.get("ok") is not True
            or not isinstance(payload, dict)
        ):
            self._append_audit(actor, "backup", audit_operation, "failed")
            raise RuntimeError("备份响应版本不受支持")
        backup_fields = {
            "backup_id", "format_version", "created_at", "host", "cipher",
            "categories", "file_count", "size", "download_name",
            "key_custody_version", "client_private_keys", "restore_allowed",
            "assurance_state",
        }

        def valid_backup(value: object, extra: set[str] | None = None) -> bool:
            if not isinstance(value, dict) or set(value) != backup_fields | (extra or set()):
                return False
            return (
                value.get("format_version") in {1, 2}
                and value.get("key_custody_version") in {1, 2}
                and value.get("client_private_keys") in {"excluded", "may_be_included"}
                and isinstance(value.get("restore_allowed"), bool)
                and value.get("assurance_state") in {
                    "legacy", "awaiting_verification", "verified", "cleanup_ready",
                }
            )

        if operation == "list":
            items = payload.get("items")
            valid = (
                set(payload) == {"schema_version", "items"}
                and payload.get("schema_version") == 1
                and isinstance(items, list)
                and all(valid_backup(item) for item in items)
            )
        elif operation == "delete":
            valid = (
                set(payload) == {"schema_version", "backup_id", "deleted"}
                and payload.get("schema_version") == 1
                and payload.get("backup_id") == backup_id
                and payload.get("deleted") is True
            )
        elif operation == "preview_restore":
            changes = payload.get("changes")
            valid = set(payload) == {
                "schema_version", "backup", "changes", "changed_count",
                "online_changed_count", "offline_changed_count", "writes_enabled",
            } and (
                payload.get("writes_enabled") is False
                and valid_backup(payload.get("backup"))
                and isinstance(changes, list)
                and all(
                    isinstance(item, dict)
                    and set(item) == {"path", "category", "state"}
                    for item in changes
                )
            )
        elif operation in {"restore_status", "restore_apply", "restore_confirm", "restore_rollback"}:
            expected = {
                "schema_version", "state", "backup_id", "expires_at",
                "remaining_seconds", "rollback_seconds", "changed_count",
                "categories", "verifications", "writes_enabled", "last_outcome",
                "independent_session",
            }
            valid = (
                set(payload) == expected
                and payload.get("schema_version") == 1
                and payload.get("state") in {"idle", "pending"}
                and isinstance(payload.get("writes_enabled"), bool)
                and isinstance(payload.get("remaining_seconds"), int)
                and isinstance(payload.get("rollback_seconds"), int)
                and isinstance(payload.get("changed_count"), int)
                and isinstance(payload.get("categories"), list)
                and isinstance(payload.get("verifications"), list)
                and isinstance(payload.get("independent_session"), bool)
            )
        else:
            extra = {"verified", "verified_file_count"} if operation == "verify" else set()
            valid = valid_backup(payload, extra) and (
                operation != "verify" or payload.get("verified") is True
            )
        if not valid:
            self._append_audit(actor, "backup", audit_operation, "failed")
            raise RuntimeError("备份响应版本不受支持")
        expected_states = {
            "restore_apply": "pending",
            "restore_confirm": "idle",
            "restore_rollback": "idle",
        }
        if operation in expected_states and payload.get("state") != expected_states[operation]:
            self._append_audit(actor, "backup", audit_operation, "failed")
            raise RuntimeError("配置恢复执行后状态核验失败")
        self._append_audit(actor, "backup", audit_operation, "success")
        return payload

    def _append_audit(
        self, actor: str, service_id: str, operation: str, outcome: str
    ) -> None:
        append_audit(self._audit_path, actor, service_id, operation, outcome)
