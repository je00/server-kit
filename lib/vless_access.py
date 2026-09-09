#!/usr/bin/env python3
"""管理 VLESS 客户端及其对 AmneziaWG 内网的最小访问权限。"""

from __future__ import annotations

import argparse
import copy
import difflib
import ipaddress
import json
import os
import re
import sys
import uuid
from pathlib import Path

try:
    from lib.server_kit_node_domains import (
        NodeDomainError, load_address_state, load_state as load_node_domain_state,
    )
except ModuleNotFoundError:  # 直接执行 lib/vless_access.py 时
    from server_kit_node_domains import (
        NodeDomainError, load_address_state, load_state as load_node_domain_state,
    )


MANAGED_EMAIL_PREFIX = "server-kit-vless:"
MANAGED_OUTBOUND_PREFIX = "server-kit-vless-"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class PolicyError(RuntimeError):
    """表示用户可修正的策略错误。"""


def load_json(path: Path, default: dict | None = None) -> dict:
    if not path.exists():
        if default is None:
            raise PolicyError(f"文件不存在：{path}")
        return copy.deepcopy(default)
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"无法读取 JSON：{path}：{exc}") from exc
    if not isinstance(value, dict):
        raise PolicyError(f"JSON 顶层必须是对象：{path}")
    return value


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def empty_policy() -> dict:
    return {"version": 1, "clients": {}}


def validate_name(name: str, label: str = "名称") -> str:
    if not NAME_RE.fullmatch(name):
        raise PolicyError(f"{label}只能包含字母、数字、点、下划线和连字符，最长 64 个字符。")
    return name


def normalize_policy(policy: dict) -> dict:
    policy.setdefault("version", 1)
    clients = policy.setdefault("clients", {})
    if not isinstance(clients, dict):
        raise PolicyError("策略中的 clients 必须是对象。")
    return policy


def pending_policy(active_path: Path, pending_path: Path) -> dict:
    if pending_path.exists():
        return normalize_policy(load_json(pending_path))
    return normalize_policy(load_json(active_path, empty_policy()))


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item.isdigit() or not 1 <= int(item) <= 65535:
            raise PolicyError(f"无效端口：{item or '(空)'}")
        ports.add(int(item))
    return sorted(ports)


def parse_awg_peers(path: Path) -> dict[str, str]:
    peers: dict[str, str] = {}
    if not path.exists():
        return peers
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) < 2:
                continue
            name, address = fields[0], fields[1]
            try:
                peers[name] = str(ipaddress.ip_interface(address).ip)
            except ValueError:
                continue
    return peers


def load_internal_domain_hosts(node_domains_path: Path, peer_db: Path) -> dict[str, str]:
    """把强制解析记录转为 Xray DNS hosts，并忽略已移除节点的残留状态。"""

    try:
        domains_by_node = load_node_domain_state(node_domains_path)
        domains_by_address = load_address_state(node_domains_path)
    except NodeDomainError as exc:
        raise PolicyError(str(exc)) from exc
    peers = parse_awg_peers(peer_db)
    result: dict[str, str] = {}
    for name, domains in domains_by_node.items():
        address = peers.get(name)
        if not address:
            continue
        for domain in domains:
            key = f"domain:{domain[2:]}" if domain.startswith("*.") else domain
            result[key] = address
    for address, domains in domains_by_address.items():
        for domain in domains:
            key = f"domain:{domain[2:]}" if domain.startswith("*.") else domain
            result[key] = address
    return result


def read_awg_server_ip(state_path: Path) -> str:
    if state_path.exists():
        pattern = re.compile(r"^(?:AWG_SERVER_IP|SERVER_ADDRESS)=['\"]?([^'\"/\s]+)")
        with state_path.open(encoding="utf-8") as handle:
            for line in handle:
                match = pattern.match(line.strip())
                if match:
                    return str(ipaddress.ip_address(match.group(1)))
    return "10.20.0.1"


def read_awg_network(state_path: Path) -> str:
    if state_path.exists():
        pattern = re.compile(r"^AWG_SUBNET_CIDR=['\"]?([^'\"\s]+)")
        with state_path.open(encoding="utf-8") as handle:
            for line in handle:
                match = pattern.match(line.strip())
                if match:
                    return str(ipaddress.ip_network(match.group(1), strict=False))
    return "10.20.0.0/24"


def resolve_target(target: str, peer_db: Path, state_path: Path) -> tuple[str, str]:
    validate_name(target, "目标节点名")
    if target == "all":
        return target, read_awg_network(state_path)
    if target == "vps":
        return target, read_awg_server_ip(state_path)
    peers = parse_awg_peers(peer_db)
    if target not in peers:
        known = "、".join(["vps", *sorted(peers)])
        raise PolicyError(f"找不到目标节点 {target}。当前可选：{known}")
    return target, peers[target]


def client_add(args: argparse.Namespace) -> None:
    name = validate_name(args.name, "客户端名")
    policy = pending_policy(args.active, args.pending)
    if name in policy["clients"]:
        raise PolicyError(f"客户端已存在：{name}")
    client_id = args.uuid or str(uuid.uuid4())
    try:
        client_id = str(uuid.UUID(client_id))
    except ValueError as exc:
        raise PolicyError("UUID 格式不正确。") from exc
    policy["clients"][name] = {
        "uuid": client_id,
        "email": f"{MANAGED_EMAIL_PREFIX}{name}",
        "enabled": True,
        "legacy_stash": False,
        "allow": [],
    }
    write_json(args.pending, policy)
    print(f"已创建待应用客户端：{name}")
    print(f"UUID：{client_id}")
    print("当前没有内网权限；请先执行 allow，再执行 plan 和 apply。")


def client_remove(args: argparse.Namespace) -> None:
    name = validate_name(args.name, "客户端名")
    policy = pending_policy(args.active, args.pending)
    if policy["clients"].pop(name, None) is None:
        raise PolicyError(f"客户端不存在：{name}")
    write_json(args.pending, policy)
    print(f"已在待应用策略中删除客户端：{name}")


def client_set_enabled(args: argparse.Namespace) -> None:
    name = validate_name(args.name, "客户端名")
    policy = pending_policy(args.active, args.pending)
    client = policy["clients"].get(name)
    if client is None:
        raise PolicyError(f"客户端不存在：{name}")
    enabled = args.command == "client-enable"
    if client.get("enabled", True) is enabled:
        raise PolicyError(f"客户端已经{'启用' if enabled else '禁用'}：{name}")
    client["enabled"] = enabled
    write_json(args.pending, policy)
    print(f"已在待应用策略中{'启用' if enabled else '禁用'}客户端：{name}")


def client_set_compatibility(args: argparse.Namespace) -> None:
    """切换单个订阅的旧版 Stash YAML 投影，不改变 Xray 访问权限。"""

    name = validate_name(args.name, "客户端名")
    policy = pending_policy(args.active, args.pending)
    client = policy["clients"].get(name)
    if client is None:
        raise PolicyError(f"客户端不存在：{name}")
    enabled = args.command == "client-compat-enable"
    if client.get("legacy_stash", False) is enabled:
        raise PolicyError(f"客户端已经{'启用' if enabled else '关闭'}旧版 Stash 兼容：{name}")
    client["legacy_stash"] = enabled
    write_json(args.pending, policy)
    print(f"已在待应用策略中{'启用' if enabled else '关闭'}旧版 Stash 兼容：{name}")


def allow_target(args: argparse.Namespace) -> None:
    name = validate_name(args.name, "客户端名")
    target, target_ip = resolve_target(args.target, args.peer_db, args.awg_state)
    if not args.ports:
        ports: list[int] = []
        network = "all"
    else:
        ports = parse_ports(args.ports)
        network = args.network
    policy = pending_policy(args.active, args.pending)
    client = policy["clients"].get(name)
    if client is None:
        raise PolicyError(f"客户端不存在：{name}")
    entries = client.setdefault("allow", [])
    entry = {
        "target": target,
        "ip": target_ip,
        "ports": ports,
        "network": network,
    }
    if any(
        item.get("target") == target
        and item.get("network") == network
        and item.get("ports") == ports
        for item in entries
        if isinstance(item, dict)
    ):
        raise PolicyError(f"相同权限已经存在：{name} -> {target}")
    entries.append(entry)
    client["allow"] = sorted(
        entries,
        key=lambda item: (
            str(item.get("target", "")), str(item.get("network", "")),
            tuple(item.get("ports", [])),
        ),
    )
    write_json(args.pending, policy)
    description = (
        "全部协议与端口"
        if network == "all"
        else f"{network.upper()} {','.join(map(str, ports))}"
    )
    print(f"已加入待应用权限：{name} -> {target} ({target_ip})，{description}")


def deny_target(args: argparse.Namespace) -> None:
    name = validate_name(args.name, "客户端名")
    target = validate_name(args.target, "目标节点名")
    policy = pending_policy(args.active, args.pending)
    client = policy["clients"].get(name)
    if client is None:
        raise PolicyError(f"客户端不存在：{name}")
    old = client.setdefault("allow", [])
    if args.network:
        if args.network == "all":
            if args.ports:
                raise PolicyError("全部协议权限不接受端口列表。")
            ports: list[int] = []
        else:
            ports = parse_ports(args.ports)
        client["allow"] = [
            item for item in old
            if not (
                item.get("target") == target
                and item.get("network") == args.network
                and item.get("ports") == ports
            )
        ]
    else:
        client["allow"] = [item for item in old if item.get("target") != target]
    if len(old) == len(client["allow"]):
        raise PolicyError(f"未找到权限：{name} -> {target}")
    write_json(args.pending, policy)
    print(f"已从待应用策略删除权限：{name} -> {target}")


def policy_lines(policy: dict, reveal: bool = False) -> list[str]:
    lines: list[str] = []
    clients = normalize_policy(policy)["clients"]
    if not clients:
        return ["（没有受管 VLESS 客户端）"]
    for name in sorted(clients):
        client = clients[name]
        suffix = f"，UUID {client.get('uuid', '')}" if reveal else ""
        lines.append(f"{name}{suffix}")
        lines.append(
            "  订阅语法：旧版 Stash 兼容"
            if client.get("legacy_stash", False)
            else "  订阅语法：现代 Mihomo / Stash"
        )
        allows = client.get("allow", [])
        if not allows:
            lines.append("  内网权限：无")
        for item in allows:
            target_label = "全部节点" if item.get("target") == "all" else f"{item.get('target')} ({item.get('ip')})"
            if item.get("network") == "all":
                lines.append(f"  -> {target_label} 全部端口")
                continue
            ports = ",".join(str(port) for port in item.get("ports", []))
            network = str(item.get("network", "tcp")).upper()
            lines.append(f"  -> {target_label} {network} {ports}")
    return lines


def list_clients(args: argparse.Namespace) -> None:
    path = args.pending if args.pending.exists() else args.active
    policy = load_json(path, empty_policy())
    print(f"策略来源：{path}")
    print("\n".join(policy_lines(policy, reveal=False)))


def show_client(args: argparse.Namespace) -> None:
    name = validate_name(args.name, "客户端名")
    path = args.pending if args.pending.exists() else args.active
    policy = normalize_policy(load_json(path, empty_policy()))
    client = policy["clients"].get(name)
    if client is None:
        raise PolicyError(f"客户端不存在：{name}")
    print("\n".join(policy_lines({"version": 1, "clients": {name: client}}, reveal=args.reveal)))


def plan(args: argparse.Namespace) -> None:
    active = normalize_policy(load_json(args.active, empty_policy()))
    pending = pending_policy(args.active, args.pending)
    before = policy_lines(active)
    after = policy_lines(pending)
    diff = list(difflib.unified_diff(before, after, fromfile="当前策略", tofile="待应用策略", lineterm=""))
    if not diff:
        print("没有待应用变化。")
        return
    print("\n".join(diff))


def safe_tag(name: str) -> str:
    return MANAGED_OUTBOUND_PREFIX + re.sub(r"[^A-Za-z0-9_.-]", "-", name)


def apply_internal_domain_hosts(
    config: dict, mappings: dict[str, str], awg_network: str
) -> None:
    """替换 Xray 中由 server-kit 管理的全局强制解析记录。"""

    network = ipaddress.ip_network(awg_network, strict=False)
    dns = config.get("dns")
    if dns is not None and not isinstance(dns, dict):
        raise PolicyError("Xray 配置的 dns 必须是对象。")
    existing_hosts = dns.get("hosts", {}) if isinstance(dns, dict) else {}
    if not isinstance(existing_hosts, dict):
        raise PolicyError("Xray 配置的 dns.hosts 必须是对象。")

    def is_managed_address(value: object) -> bool:
        values = value if isinstance(value, list) else [value]
        if not values:
            return False
        try:
            return all(ipaddress.ip_address(item) in network for item in values)
        except (TypeError, ValueError):
            return False

    retained = {
        key: value for key, value in existing_hosts.items()
        if not is_managed_address(value)
    }
    if not mappings and len(retained) == len(existing_hosts):
        return
    dns = config.setdefault("dns", {})
    dns["hosts"] = {**retained, **mappings}
    dns.setdefault("servers", ["localhost"])


def render_config(
    config: dict, policy: dict, public_tag: str, awg_network: str,
    internal_hosts: dict[str, str] | None = None,
) -> dict:
    result = copy.deepcopy(config)
    if internal_hosts is not None:
        apply_internal_domain_hosts(result, internal_hosts, awg_network)
    clients = normalize_policy(policy)["clients"]
    inbounds = [
        item for item in result.get("inbounds", [])
        if item.get("tag") == public_tag
        or str(item.get("tag", "")).startswith(f"{public_tag}-")
    ]
    inbound = next((item for item in inbounds if item.get("tag") == public_tag), None)
    if inbound is None:
        raise PolicyError(f"未找到公网 VLESS 入站：{public_tag}")
    if inbound.get("protocol") != "vless":
        raise PolicyError(f"入站 {public_tag} 不是 VLESS。")

    settings = inbound.setdefault("settings", {})
    existing_clients = settings.setdefault("clients", [])
    if not isinstance(existing_clients, list):
        raise PolicyError(f"入站 {public_tag} 的 settings.clients 格式不正确。")
    unmanaged = [
        item for item in existing_clients
        if not str(item.get("email", "")).startswith(MANAGED_EMAIL_PREFIX)
    ]
    default_flow = next((item.get("flow", "") for item in unmanaged if item.get("flow")), "")
    managed_clients = []
    for name in sorted(clients):
        client = clients[name]
        if not client.get("enabled", True):
            continue
        entry = {"id": client["uuid"], "email": client["email"]}
        if default_flow:
            entry["flow"] = default_flow
        managed_clients.append(entry)
    settings["clients"] = unmanaged + managed_clients
    for sibling in inbounds:
        if sibling is inbound:
            continue
        if sibling.get("protocol") != "vless":
            raise PolicyError(f"入站 {sibling.get('tag', '')} 不是 VLESS。")
        sibling_settings = sibling.setdefault("settings", {})
        sibling_clients = sibling_settings.setdefault("clients", [])
        if not isinstance(sibling_clients, list):
            raise PolicyError(
                f"入站 {sibling.get('tag', '')} 的 settings.clients 格式不正确。"
            )
        sibling_settings["clients"] = copy.deepcopy(settings["clients"])

    outbounds = result.setdefault("outbounds", [])
    result["outbounds"] = [
        item for item in outbounds
        if not str(item.get("tag", "")).startswith(MANAGED_OUTBOUND_PREFIX)
    ]
    managed_emails = {client.get("email") for client in clients.values()}
    routing = result.setdefault("routing", {})
    if clients:
        # 域名目标必须先解析后再匹配 AWG IP 权限，防止绕过内网拒绝规则。
        routing["domainStrategy"] = "IPIfNonMatch"
    old_rules = routing.setdefault("rules", [])
    retained_rules = []
    for rule in old_rules:
        users = set(rule.get("user", [])) if isinstance(rule.get("user", []), list) else set()
        if str(rule.get("outboundTag", "")).startswith(MANAGED_OUTBOUND_PREFIX):
            continue
        if users & managed_emails:
            continue
        retained_rules.append(rule)

    managed_rules = []
    for name in sorted(clients):
        client = clients[name]
        if not client.get("enabled", True):
            continue
        tag = safe_tag(name)
        permissions = sorted(
            client.get("allow", []),
            key=lambda item: (str(item.get("target", "")), str(item.get("ip", ""))),
        )
        for permission in permissions:
            target_ip = (
                awg_network
                if permission.get("target") == "all"
                else f"{ipaddress.ip_address(permission['ip'])}/32"
            )
            rule = {
                "type": "field",
                "user": [client["email"]],
                "ip": [target_ip],
                "outboundTag": tag,
            }
            if permission.get("network") != "all":
                rule["network"] = permission.get("network", "tcp")
                rule["port"] = ",".join(str(port) for port in permission["ports"])
            managed_rules.append(rule)
        # 允许规则必须位于内网拒绝规则之前；未命中的 AWG 地址统一阻断。
        managed_rules.append({
            "type": "field",
            "user": [client["email"]],
            "ip": [awg_network],
            "outboundTag": "block",
        })
        # 仅限制 AWG 内网，受限客户端访问公网时仍使用独立直连出站。
        managed_rules.append({
            "type": "field",
            "user": [client["email"]],
            "outboundTag": tag,
        })
        result["outbounds"].append({
            "tag": tag,
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIP"},
        })
    routing["rules"] = managed_rules + retained_rules
    return result


def render(args: argparse.Namespace) -> None:
    config = load_json(args.config)
    policy = (
        normalize_policy(load_json(args.active, empty_policy()))
        if args.active_only else pending_policy(args.active, args.pending)
    )
    internal_hosts = load_internal_domain_hosts(args.node_domains, args.peer_db)
    rendered = render_config(
        config, policy, args.public_tag, args.awg_network, internal_hosts
    )
    write_json(args.output, rendered)
    print(args.output)


def commit(args: argparse.Namespace) -> None:
    policy = pending_policy(args.active, args.pending)
    write_json(args.active, policy)
    try:
        args.pending.unlink()
    except FileNotFoundError:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active", type=Path, required=True)
    parser.add_argument("--pending", type=Path, required=True)
    parser.add_argument("--peer-db", type=Path, required=True)
    parser.add_argument("--awg-state", type=Path, required=True)
    parser.add_argument(
        "--node-domains", type=Path,
        default=Path("/etc/server-kit/node-domains.json"),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    command = subparsers.add_parser("client-add")
    command.add_argument("name")
    command.add_argument("--uuid")
    command.set_defaults(function=client_add)

    command = subparsers.add_parser("client-remove")
    command.add_argument("name")
    command.set_defaults(function=client_remove)

    for action in ("client-enable", "client-disable"):
        command = subparsers.add_parser(action)
        command.add_argument("name")
        command.set_defaults(function=client_set_enabled)

    for action in ("client-compat-enable", "client-compat-disable"):
        command = subparsers.add_parser(action)
        command.add_argument("name")
        command.set_defaults(function=client_set_compatibility)

    command = subparsers.add_parser("allow")
    command.add_argument("name")
    command.add_argument("target")
    command.add_argument("ports", nargs="?", default="")
    command.add_argument("network", nargs="?", choices=("tcp", "udp", "tcp,udp"), default="tcp")
    command.set_defaults(function=allow_target)

    command = subparsers.add_parser("deny")
    command.add_argument("name")
    command.add_argument("target")
    command.add_argument("ports", nargs="?", default="")
    command.add_argument("network", nargs="?", choices=("all", "tcp", "udp"))
    command.set_defaults(function=deny_target)

    command = subparsers.add_parser("list")
    command.set_defaults(function=list_clients)

    command = subparsers.add_parser("show")
    command.add_argument("name")
    command.add_argument("--reveal", action="store_true")
    command.set_defaults(function=show_client)

    command = subparsers.add_parser("plan")
    command.set_defaults(function=plan)

    command = subparsers.add_parser("render")
    command.add_argument("--config", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--public-tag", default="vless-public")
    command.add_argument("--awg-network", default="10.20.0.0/24")
    command.add_argument("--active-only", action="store_true")
    command.set_defaults(function=render)

    command = subparsers.add_parser("commit")
    command.set_defaults(function=commit)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.function(args)
    except PolicyError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
