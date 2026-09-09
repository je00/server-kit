#!/usr/bin/env python3
"""维护普通 AWG 节点的订阅强制解析记录。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
MAX_DOMAINS_PER_NODE = 32
MAX_CUSTOM_ADDRESSES = 64


class NodeDomainError(Exception):
    """表示可安全返回给管理员的域名配置错误。"""


def normalize_domain(value: object) -> str:
    if not isinstance(value, str):
        raise NodeDomainError("域名必须是文本。")
    domain = value.strip().lower().rstrip(".")
    wildcard = domain.startswith("*.")
    if wildcard:
        domain = domain[2:]
    if not domain or len(domain) > 253 or "*" in domain:
        raise NodeDomainError("域名格式不正确；通配符只能写在开头的 *. 中。")
    labels = domain.split(".")
    if len(labels) < 2 or any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise NodeDomainError("必须填写完整域名；通配符只能写在开头的 *. 中。")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise NodeDomainError("域名不能填写 IP 地址。")
    return f"*.{domain}" if wildcard else domain


def normalize_domains(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_DOMAINS_PER_NODE:
        raise NodeDomainError(f"每个节点最多配置 {MAX_DOMAINS_PER_NODE} 个域名。")
    result: list[str] = []
    for item in value:
        domain = normalize_domain(item)
        if domain not in result:
            result.append(domain)
    return result


def normalize_address(value: object) -> str:
    if not isinstance(value, str):
        raise NodeDomainError("目标 IP 必须是文本。")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as error:
        raise NodeDomainError("目标 IP 格式不正确。") from error


def validate_wildcard_conflicts(domains: list[str], reserved_hosts: list[str]) -> None:
    """拒绝覆盖 VPS 自身公网域名的通配符，精确记录不受影响。"""

    normalized_hosts: list[str] = []
    for value in reserved_hosts:
        if not isinstance(value, str) or not value.strip():
            continue
        host = normalize_domain(value)
        if not host.startswith("*.") and host not in normalized_hosts:
            normalized_hosts.append(host)
    for domain in domains:
        if not domain.startswith("*."):
            continue
        suffix = domain[2:]
        conflict = next((
            host for host in normalized_hosts
            if host == suffix or host.endswith("." + suffix)
        ), "")
        if conflict:
            raise NodeDomainError(
                f"通配符 {domain} 会覆盖 VPS 域名 {conflict}，拒绝保存。"
            )


def reserved_hosts_from_paths(paths: list[Path]) -> list[str]:
    result: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise NodeDomainError("VPS 公网域名配置无法读取，拒绝保存通配符。") from error
        fqdn = value.get("fqdn") if isinstance(value, dict) else None
        if isinstance(fqdn, str) and fqdn.strip() and fqdn not in result:
            result.append(fqdn)
    return result


def _load_config(path: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    if not path.is_file():
        return {}, {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise NodeDomainError("节点域名配置无法读取。") from error
    if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("nodes"), dict):
        raise NodeDomainError("节点域名配置版本不受支持。")
    result: dict[str, list[str]] = {}
    addresses: dict[str, list[str]] = {}
    owners: dict[str, str] = {}
    for name, domains in value["nodes"].items():
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
            raise NodeDomainError("节点域名配置包含无效节点名称。")
        clean = normalize_domains(domains)
        for domain in clean:
            if domain in owners and owners[domain] != name:
                raise NodeDomainError(f"域名 {domain} 被多个节点重复使用。")
            owners[domain] = name
        if clean:
            result[name] = clean
    raw_addresses = value.get("addresses", {})
    if not isinstance(raw_addresses, dict) or len(raw_addresses) > MAX_CUSTOM_ADDRESSES:
        raise NodeDomainError(f"自定义目标最多配置 {MAX_CUSTOM_ADDRESSES} 个 IP。")
    for raw_address, domains in raw_addresses.items():
        address = normalize_address(raw_address)
        if address in addresses:
            raise NodeDomainError(f"目标 IP {address} 重复。")
        clean = normalize_domains(domains)
        for domain in clean:
            if domain in owners:
                raise NodeDomainError(f"域名 {domain} 被多个目标重复使用。")
            owners[domain] = address
        if clean:
            addresses[address] = clean
    return result, addresses


def load_state(path: Path) -> dict[str, list[str]]:
    return _load_config(path)[0]


def load_address_state(path: Path) -> dict[str, list[str]]:
    return _load_config(path)[1]


def load_peers(*paths: Path) -> dict[str, str]:
    peers: dict[str, str] = {}
    for path in paths:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            fields = raw.split("\t")
            if len(fields) != 2 or not NAME_PATTERN.fullmatch(fields[0]):
                continue
            try:
                address = str(ipaddress.ip_address(fields[1]))
            except ValueError:
                continue
            peers[fields[0]] = address
    return peers


def atomic_write(
    path: Path, nodes: dict[str, list[str]], addresses: dict[str, list[str]] | None = None,
) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                {"version": 1, "nodes": nodes, "addresses": addresses or {}},
                handle, ensure_ascii=False, indent=2,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        try:
            directory = os.open(path.parent, os.O_RDONLY)
        except OSError:  # Windows 不支持以只读文件描述符打开目录
            directory = -1
        if directory >= 0:
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def overview(path: Path, active: Path, disabled: Path) -> dict[str, Any]:
    nodes, addresses = _load_config(path)
    peers = load_peers(active, disabled)
    items = [
        {"name": name, "address": address, "domains": list(nodes.get(name, []))}
        for name, address in sorted(peers.items())
    ]
    return {
        "schema_version": 1,
        "items": items,
        "addresses": [
            {"address": address, "domains": list(domains)}
            for address, domains in sorted(addresses.items())
        ],
    }


def set_domains(
    path: Path, active: Path, disabled: Path, name: str, domains: list[str],
    reserved_hosts: list[str] | None = None,
) -> dict[str, Any]:
    if not NAME_PATTERN.fullmatch(name):
        raise NodeDomainError("节点名称格式不正确。")
    peers = load_peers(active, disabled)
    if name not in peers:
        raise NodeDomainError("只有现有普通 AWG 节点可以配置域名。")
    clean = normalize_domains(domains)
    validate_wildcard_conflicts(clean, reserved_hosts or [])
    nodes, addresses = _load_config(path)
    for owner, values in nodes.items():
        if owner == name:
            continue
        duplicate = next((domain for domain in clean if domain in values), "")
        if duplicate:
            raise NodeDomainError(f"域名 {duplicate} 已属于节点 {owner}。")
    for address, values in addresses.items():
        duplicate = next((domain for domain in clean if domain in values), "")
        if duplicate:
            raise NodeDomainError(f"域名 {duplicate} 已解析到 {address}。")
    if clean:
        nodes[name] = clean
    else:
        nodes.pop(name, None)
    atomic_write(path, nodes, addresses)
    return {
        "schema_version": 1,
        "operation": "set",
        "name": name,
        "address": peers[name],
        "domains": clean,
    }


def set_address_domains(
    path: Path, address: str, domains: list[str],
    reserved_hosts: list[str] | None = None,
) -> dict[str, Any]:
    clean_address = normalize_address(address)
    clean = normalize_domains(domains)
    validate_wildcard_conflicts(clean, reserved_hosts or [])
    nodes, addresses = _load_config(path)
    for owner, values in nodes.items():
        duplicate = next((domain for domain in clean if domain in values), "")
        if duplicate:
            raise NodeDomainError(f"域名 {duplicate} 已属于节点 {owner}。")
    for existing_address, values in addresses.items():
        if existing_address == clean_address:
            continue
        duplicate = next((domain for domain in clean if domain in values), "")
        if duplicate:
            raise NodeDomainError(f"域名 {duplicate} 已解析到 {existing_address}。")
    if clean:
        addresses[clean_address] = clean
    else:
        addresses.pop(clean_address, None)
    atomic_write(path, nodes, addresses)
    return {
        "schema_version": 1,
        "operation": "set-address",
        "address": clean_address,
        "domains": clean,
    }


def delete_node(path: Path, name: str) -> dict[str, Any]:
    nodes, addresses = _load_config(path)
    removed = nodes.pop(name, [])
    atomic_write(path, nodes, addresses)
    return {
        "schema_version": 1, "operation": "delete-node",
        "name": name, "removed": len(removed),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("overview", "set", "set-address", "delete-node", "validate-host"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--active", type=Path, required=True)
    parser.add_argument("--disabled", type=Path, required=True)
    parser.add_argument("--name", default="")
    parser.add_argument("--address", default="")
    parser.add_argument("--domains-json", default="[]")
    parser.add_argument("--public-endpoint-config", type=Path)
    parser.add_argument("--dynamic-dns-config", type=Path)
    parser.add_argument("--reserved-host", default="")
    args = parser.parse_args()
    try:
        if args.operation == "overview":
            result = overview(args.config, args.active, args.disabled)
        elif args.operation == "set":
            raw = json.loads(args.domains_json)
            reserved_hosts = reserved_hosts_from_paths([
                path for path in (args.public_endpoint_config, args.dynamic_dns_config)
                if path is not None
            ])
            result = set_domains(
                args.config, args.active, args.disabled, args.name, raw, reserved_hosts,
            )
        elif args.operation == "set-address":
            raw = json.loads(args.domains_json)
            reserved_hosts = reserved_hosts_from_paths([
                path for path in (args.public_endpoint_config, args.dynamic_dns_config)
                if path is not None
            ])
            result = set_address_domains(
                args.config, args.address, raw, reserved_hosts,
            )
        elif args.operation == "delete-node":
            result = delete_node(args.config, args.name)
        else:
            nodes, addresses = _load_config(args.config)
            validate_wildcard_conflicts(
                [
                    domain
                    for groups in (nodes, addresses)
                    for domains in groups.values()
                    for domain in domains
                ],
                [args.reserved_host],
            )
            result = {
                "schema_version": 1, "operation": "validate-host", "valid": True,
                "reserved_host": normalize_domain(args.reserved_host),
            }
    except (NodeDomainError, OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
