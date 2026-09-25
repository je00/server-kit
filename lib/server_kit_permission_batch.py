"""Validate an all-add permission batch before any candidate policy is written."""

from __future__ import annotations

import json
import re

try:
    from lib.server_kit_port_ranges import PortRangeError, format_ports, parse_ports
except ModuleNotFoundError:
    from server_kit_port_ranges import PortRangeError, format_ports, parse_ports


MAX_RULES = 20
MAX_INPUT_BYTES = 100_000
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class PermissionBatchError(ValueError):
    """A safe, user-correctable batch error."""


def normalize_rules(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RULES:
        raise PermissionBatchError("每批必须包含 1–20 条访问权限。")
    result = []
    seen = set()
    for index, rule in enumerate(value, 1):
        if not isinstance(rule, dict) or set(rule) != {"target", "network", "ports"}:
            raise PermissionBatchError(f"第 {index} 条权限参数不正确。")
        target, network, ports = rule["target"], rule["network"], rule["ports"]
        if not isinstance(target, str) or not NAME_PATTERN.fullmatch(target):
            raise PermissionBatchError(f"第 {index} 条权限目标名称不正确。")
        if not isinstance(network, str) or not isinstance(ports, str):
            raise PermissionBatchError(f"第 {index} 条权限协议与端口不正确。")
        network = network or "all"
        if network == "all":
            if ports:
                raise PermissionBatchError(f"第 {index} 条权限：全部协议不接受端口列表。")
        elif network in {"tcp", "udp"}:
            try:
                ports = format_ports(parse_ports(ports))
            except PortRangeError as error:
                raise PermissionBatchError(f"第 {index} 条权限：{error}") from error
        else:
            raise PermissionBatchError(f"第 {index} 条权限协议不正确。")
        identity = (target, network, ports)
        if identity in seen:
            raise PermissionBatchError(f"第 {index} 条权限与本批其他规则重复。")
        seen.add(identity)
        result.append({"target": target, "network": network, "ports": ports})
    return result


def read_rules(stream) -> list[dict[str, str]]:
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
        raise PermissionBatchError("批量权限请求过大。")
    try:
        return normalize_rules(json.loads(raw))
    except (ValueError, TypeError) as error:
        if isinstance(error, PermissionBatchError):
            raise
        raise PermissionBatchError("批量权限 JSON 格式不正确。") from error


def append_rule(entries: list[dict], rule: dict[str, str], address: str) -> None:
    ports = parse_ports(rule["ports"]) if rule["ports"] else []
    if any(
        isinstance(item, dict)
        and item.get("target") == rule["target"]
        and item.get("network") == rule["network"]
        and item.get("ports") == ports
        for item in entries
    ):
        raise PermissionBatchError(f"相同的访问权限已经存在：{rule['target']}。")
    entries.append({**rule, "ports": ports, "ip": address})
