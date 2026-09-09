#!/usr/bin/env python3
"""管理 AmneziaWG 普通节点的按来源访问策略并生成 nftables 规则。"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import re
import sys
from pathlib import Path


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


class PolicyError(RuntimeError):
    """表示可由用户修正的访问策略错误。"""


def empty_policy() -> dict:
    return {"version": 1, "clients": {}}


def load_json(path: Path, default: dict | None = None) -> dict:
    if not path.exists():
        if default is None:
            raise PolicyError(f"文件不存在：{path}")
        return copy.deepcopy(default)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"无法读取策略：{path}") from exc
    if not isinstance(value, dict):
        raise PolicyError("策略顶层必须是对象。")
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


def validate_name(value: str, label: str) -> str:
    if not NAME_RE.fullmatch(value):
        raise PolicyError(f"{label}格式不正确。")
    return value


def normalize_policy(value: dict) -> dict:
    if value.get("version", 1) != 1:
        raise PolicyError("策略版本不受支持。")
    clients = value.setdefault("clients", {})
    value["version"] = 1
    if not isinstance(clients, dict):
        raise PolicyError("策略中的 clients 必须是对象。")
    for name, client in clients.items():
        validate_name(name, "节点名称")
        if not isinstance(client, dict):
            raise PolicyError(f"节点 {name} 的策略格式不正确。")
        if client.get("mode", "unrestricted") not in {"unrestricted", "restricted"}:
            raise PolicyError(f"节点 {name} 的访问模式无效。")
        if not isinstance(client.setdefault("allow", []), list):
            raise PolicyError(f"节点 {name} 的允许列表格式不正确。")
    return value


def pending_policy(active: Path, pending: Path) -> dict:
    source = pending if pending.exists() else active
    return normalize_policy(load_json(source, empty_policy()))


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item.isdigit() or not 1 <= int(item) <= 65535:
            raise PolicyError(f"无效端口：{item or '(空)'}")
        ports.add(int(item))
    return sorted(ports)


def parse_peers(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2 or not NAME_RE.fullmatch(fields[0]):
            continue
        try:
            result[fields[0]] = str(ipaddress.ip_address(fields[1]))
        except ValueError:
            continue
    return result


def require_client(name: str, peers: dict[str, str]) -> None:
    validate_name(name, "节点名称")
    if name not in peers:
        raise PolicyError(f"找不到已启用的 AmneziaWG 节点：{name}")


def resolve_target(
    target: str, peers: dict[str, str], server_ip: str, network_cidr: str,
) -> tuple[str, str]:
    validate_name(target, "目标名称")
    if target == "all":
        return target, str(ipaddress.ip_network(network_cidr, strict=False))
    if target == "vps":
        return target, str(ipaddress.ip_address(server_ip))
    if target not in peers:
        raise PolicyError(f"找不到已启用的目标节点：{target}")
    return target, peers[target]


def change(args: argparse.Namespace) -> None:
    peers = parse_peers(args.peers)
    require_client(args.client, peers)
    policy = pending_policy(args.active, args.pending)
    client = policy["clients"].setdefault(
        args.client, {"mode": "unrestricted", "allow": []}
    )
    client.setdefault("allow", [])
    if args.operation == "mode":
        if len(args.arguments) != 1 or args.arguments[0] not in {"unrestricted", "restricted"}:
            raise PolicyError("访问模式只能是 unrestricted 或 restricted。")
        client["mode"] = args.arguments[0]
    elif args.operation == "allow":
        if len(args.arguments) == 1:
            target_name = args.arguments[0]
            ports: list[int] = []
            network = "all"
        elif len(args.arguments) == 3:
            target_name, ports_text, network = args.arguments
            ports = parse_ports(ports_text)
        else:
            raise PolicyError("allow 需要目标，或目标、端口列表和协议。")
        target, address = resolve_target(
            target_name, peers, args.server_ip, args.network_cidr,
        )
        if target == args.client:
            raise PolicyError("不能把节点自身作为访问目标。")
        if network not in {"all", "tcp", "udp"}:
            raise PolicyError("协议只能是全部、TCP 或 UDP。")
        if target == "all" and network == "all":
            client["mode"] = "unrestricted"
            write_json(args.pending, policy)
            return
        entries = client["allow"]
        entry = {
            "target": target,
            "ip": address,
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
            raise PolicyError(f"相同权限已经存在：{args.client} -> {target}")
        entries.append(entry)
        client["allow"] = sorted(
            entries,
            key=lambda item: (
                str(item.get("target", "")).lower(),
                str(item.get("network", "")), tuple(item.get("ports", [])),
            ),
        )
    else:
        if len(args.arguments) not in {1, 3}:
            raise PolicyError("deny 需要目标，或目标、端口列表和协议。")
        target_name = validate_name(args.arguments[0], "目标名称")
        before = client["allow"]
        exact = len(args.arguments) == 3
        if exact:
            ports_text, network = args.arguments[1:]
            if network == "all":
                if ports_text:
                    raise PolicyError("全部协议权限不接受端口列表。")
                ports = []
            elif network in {"tcp", "udp"}:
                ports = parse_ports(ports_text)
            else:
                raise PolicyError("协议只能是全部、TCP 或 UDP。")
            client["allow"] = [
                item for item in before
                if not (
                    item.get("target") == target_name
                    and item.get("network") == network
                    and item.get("ports") == ports
                )
            ]
        else:
            client["allow"] = [item for item in before if item.get("target") != target_name]
        removed_default_all = (
            target_name == "all"
            and client.get("mode", "unrestricted") == "unrestricted"
            and (not exact or network == "all")
        )
        if removed_default_all:
            client["mode"] = "restricted"
        if len(before) == len(client["allow"]) and not removed_default_all:
            raise PolicyError(f"未找到权限：{args.client} -> {target_name}")
    write_json(args.pending, policy)


def clean_permissions(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if not isinstance(item, dict):
            continue
        target = item.get("target")
        network = item.get("network")
        ports = item.get("ports")
        try:
            address = (
                str(ipaddress.ip_network(item.get("ip", ""), strict=False))
                if target == "all"
                else str(ipaddress.ip_address(item.get("ip", "")))
            )
        except ValueError:
            continue
        if (
            not isinstance(target, str) or not NAME_RE.fullmatch(target)
            or network not in {"all", "tcp", "udp"} or not isinstance(ports, list)
        ):
            continue
        clean_ports = sorted({port for port in ports if isinstance(port, int) and 1 <= port <= 65535})
        if clean_ports or network == "all":
            result.append({"target": target, "ip": address, "ports": clean_ports, "network": network})
    return sorted(result, key=lambda item: item["target"].lower())


def nft_port_set(ports: list[int]) -> str:
    return "{ " + ", ".join(str(port) for port in ports) + " }"


def render_nft(args: argparse.Namespace) -> None:
    if not IFACE_RE.fullmatch(args.iface):
        raise PolicyError("AWG 接口名称无效。")
    server_ip = str(ipaddress.ip_address(args.server_ip))
    peers = parse_peers(args.peers)
    policy = normalize_policy(load_json(args.policy, empty_policy()))
    public_ports: list[int] = []
    for raw in args.public_ports.split(","):
        if not raw:
            continue
        value = int(raw)
        if value not in public_ports:
            public_ports.append(value)
    if not public_ports or any(not 1 <= value <= 65535 for value in public_ports):
        raise PolicyError("AWG 公网端口无效。")
    input_rules: list[str] = []
    forward_rules: list[str] = []
    restricted: list[tuple[str, str, dict]] = []
    for name, client in sorted(policy["clients"].items()):
        if client.get("mode", "unrestricted") != "restricted" or name not in peers:
            continue
        restricted.append((name, peers[name], client))
    for name, source_ip, client in restricted:
        for permission in clean_permissions(client.get("allow", [])):
            target = permission["target"]
            if target == "all":
                target_ip = permission["ip"]
                destinations = (input_rules, forward_rules)
            elif target == "vps":
                target_ip = server_ip
                destinations = (input_rules,)
            elif target in peers:
                target_ip = peers[target]
                destinations = (forward_rules,)
            else:
                continue
            proto = permission["network"]
            port_match = (
                ""
                if proto == "all"
                else f'{proto} dport {nft_port_set(permission["ports"])} '
            )
            for destination in destinations:
                destination.append(
                    f'    iifname "{args.iface}" ip saddr {source_ip} ip daddr {target_ip} '
                    f'{port_match}counter accept comment "server-kit {name} -> {target}"'
                )
        input_rules.append(
            f'    iifname "{args.iface}" ip saddr {source_ip} ip daddr {server_ip} '
            f'counter drop comment "server-kit 限制 {name} 访问 VPS"'
        )
        forward_rules.append(
            f'    iifname "{args.iface}" oifname "{args.iface}" ip saddr {source_ip} '
            f'counter drop comment "server-kit 限制 {name} 横向访问"'
        )
    lines = [
        "#!/usr/sbin/nft -f",
        "# 此文件由 server-kit 生成，请勿直接修改。",
        "table inet server_kit_amneziawg_filter { }",
        "flush table inet server_kit_amneziawg_filter",
        "table ip server_kit_amneziawg_nat { }",
        "flush table ip server_kit_amneziawg_nat",
        "",
        "table inet server_kit_amneziawg_filter {",
        "  chain input {",
        "    type filter hook input priority -5; policy accept;",
        "    ct state established,related counter accept",
        f"    udp dport {nft_port_set(public_ports)} counter accept comment \"server-kit AmneziaWG 公网入口\"",
        *input_rules,
        "  }",
        "",
        "  chain forward {",
        "    type filter hook forward priority -5; policy accept;",
        "    ct state established,related counter accept",
        *forward_rules,
        f'    iifname "{args.iface}" oifname "{args.iface}" counter accept comment "server-kit AWG 普通节点互访"',
        "  }",
        "}",
        "",
        "table ip server_kit_amneziawg_nat {",
        "  chain prerouting {",
        "    type nat hook prerouting priority dstnat; policy accept;",
    ]
    for port in public_ports[1:]:
        lines.append(
            f"    udp dport {port} counter redirect to :{public_ports[0]} "
            f"comment \"server-kit AWG 备用入口\""
        )
    lines.extend(["  }", "}", ""])
    temporary = args.output.with_name(f".{args.output.name}.tmp.{os.getpid()}")
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, args.output)


def commit(args: argparse.Namespace) -> None:
    policy = pending_policy(args.active, args.pending)
    write_json(args.active, policy)
    args.pending.unlink(missing_ok=True)


def discard(args: argparse.Namespace) -> None:
    args.pending.unlink(missing_ok=True)


def forget(args: argparse.Namespace) -> None:
    """删除已移除节点遗留的策略，保证同名新节点仍从完全互通开始。"""
    client = validate_name(args.client, "节点名称")
    policy = pending_policy(args.active, args.pending)
    policy["clients"].pop(client, None)
    for value in policy["clients"].values():
        if not isinstance(value, dict) or not isinstance(value.get("allow"), list):
            continue
        value["allow"] = [
            item for item in value["allow"]
            if not isinstance(item, dict) or item.get("target") != client
        ]
    write_json(args.pending, policy)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active", type=Path, required=True)
    parser.add_argument("--pending", type=Path, required=True)
    parser.add_argument("--peers", type=Path, required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--network-cidr", default="10.20.0.0/24")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("change")
    command.add_argument("operation", choices=("mode", "allow", "deny"))
    command.add_argument("client")
    command.add_argument("arguments", nargs="*")
    command.set_defaults(function=change)
    command = commands.add_parser("render-nft")
    command.add_argument("--policy", type=Path, required=True)
    command.add_argument("--iface", required=True)
    command.add_argument("--public-ports", required=True)
    command.add_argument("--output", type=Path, required=True)
    command.set_defaults(function=render_nft)
    commands.add_parser("commit").set_defaults(function=commit)
    commands.add_parser("discard").set_defaults(function=discard)
    command = commands.add_parser("forget")
    command.add_argument("client")
    command.set_defaults(function=forget)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.function(args)
    except (PolicyError, OSError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
