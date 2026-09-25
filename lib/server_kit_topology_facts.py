"""Read only the explicit, credential-free facts needed by the topology view.

An all-nodes VLESS rule is confirmed against the saved Xray configuration, not
the policy's historical ``allow.ip`` or an assumed AWG subnet. This is a config
proof, never an observation of a running process or network reachability.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import uuid
from pathlib import Path

try:
    from .vless_access import MANAGED_EMAIL_PREFIX, render_config, safe_tag
except ImportError:  # Direct execution of the network overview helper.
    from vless_access import MANAGED_EMAIL_PREFIX, render_config, safe_tag


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_STATE_KEY = re.compile(r"(?:export\s+)?(?:AWG_SERVER_IP|SERVER_ADDRESS)\b")
_ASSIGNMENT = re.compile(r"(?:export\s+)?(?:AWG_SERVER_IP|SERVER_ADDRESS)\s*=\s*(.*)\Z")
_STATE_LIMIT = 64 * 1024
_XRAY_LIMIT = 4 * 1024 * 1024


def _address(value: object) -> str:
    if not isinstance(value, str) or "%" in value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _network(value: object) -> str:
    if not isinstance(value, str) or "%" in value:
        return ""
    try:
        return str(ipaddress.ip_network(value, strict=True))
    except ValueError:
        return ""


def _uuid_value(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return ""


def valid_topology_context(value: object) -> bool:
    """Accept exactly the public fact schema, including canonical IP spelling."""
    if not isinstance(value, dict) or set(value) != {"hub_address", "vless_networks"}:
        return False
    address, networks = value["hub_address"], value["vless_networks"]
    if not isinstance(address, str) or (address and _address(address) != address):
        return False
    return isinstance(networks, dict) and all(
        isinstance(name, str) and _NAME.fullmatch(name) is not None
        and isinstance(cidr, str) and bool(cidr) and _network(cidr) == cidr
        for name, cidr in networks.items()
    )


def _read_text(path: Path | None, limit: int) -> str | None:
    if path is None:
        return None
    try:
        with path.open(encoding="utf-8") as source:
            text = source.read(limit + 1)
    except (OSError, UnicodeError):
        return None
    return text if len(text) <= limit else None


def _hub_address(path: Path | None) -> str:
    text = _read_text(path, _STATE_LIMIT)
    if text is None:
        return ""
    addresses = set()
    for line in text.splitlines():
        line = line.strip()
        if not _STATE_KEY.match(line):
            continue
        match = _ASSIGNMENT.fullmatch(line)
        if match is None:
            return ""
        try:
            values = shlex.split(match[1], comments=True, posix=True)
            if len(values) != 1 or "%" in values[0]:
                return ""
            address = str(ipaddress.ip_interface(values[0]).ip)
        except ValueError:
            return ""
        addresses.add(address)
    return addresses.pop() if len(addresses) == 1 else ""


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("Non-JSON constant")


def _xray_config(path: Path | None) -> dict:
    text = _read_text(path, _XRAY_LIMIT)
    if text is None:
        return {}
    try:
        value = json.loads(text,
                           object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _client_policy(name: object, client: object) -> dict | None:
    if not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(client, dict):
        return None
    if client.get("enabled", True) is not True or client.get("email") != MANAGED_EMAIL_PREFIX + name:
        return None
    identifier = client.get("uuid")
    if not isinstance(identifier, str) or not identifier or _uuid_value(identifier) != identifier:
        return None
    permissions = client.get("allow")
    if not isinstance(permissions, list) or not permissions:
        return None
    has_all = False
    for permission in permissions:
        if not isinstance(permission, dict) or set(permission) != {"target", "ip", "network", "ports"}:
            return None
        target, address = permission["target"], permission["ip"]
        protocol, ports = permission["network"], permission["ports"]
        if not isinstance(target, str) or not _NAME.fullmatch(target):
            return None
        if not isinstance(protocol, str) or protocol not in {"all", "tcp", "udp", "tcp,udp"}:
            return None
        if not isinstance(ports, list) or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            return None
        if (protocol == "all" and ports) or (protocol != "all" and not ports):
            return None
        # The old all-rule address must be well formed, but it is never used to
        # discover the effective network. Only the actual guard provides that.
        if target == "all":
            if not _network(address):
                return None
            has_all = True
        elif not _address(address):
            return None
    if not has_all:
        return None
    return {"uuid": identifier, "email": client["email"], "enabled": True,
            "allow": [dict(permission) for permission in permissions]}


def _inbound_identity(config: dict, client: dict) -> bool:
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or not inbounds:
        return False
    found = False
    for inbound in inbounds:
        if not isinstance(inbound, dict) or not isinstance(inbound.get("settings", {}), dict):
            return False
        entries = inbound.get("settings", {}).get("clients", [])
        if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
            return False
        identities = [item for item in entries
                      if _uuid_value(item.get("id")) == client["uuid"] or item.get("email") == client["email"]]
        if len(identities) > 1:
            return False
        for item in identities:
            if (inbound.get("protocol") != "vless" or item.get("id") != client["uuid"]
                    or item.get("email") != client["email"] or not set(item) <= {"id", "email", "flow"}
                    or ("flow" in item and not isinstance(item["flow"], str))):
                return False
            found = True
    return found


def _outbounds_match(config: dict, expected: dict, tag: str) -> bool:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or any(not isinstance(item, dict) for item in outbounds):
        return False
    direct = [item for item in outbounds if item.get("tag") == tag]
    blocks = [item for item in outbounds if item.get("tag") == "block"]
    if direct != [expected] or len(blocks) != 1:
        return False
    block = blocks[0]
    if block.get("protocol") != "blackhole" or not set(block) <= {"tag", "protocol", "settings"}:
        return False
    settings = block.get("settings", {})
    return settings == {} or settings in ({"response": {"type": "none"}}, {"response": {"type": "http"}})


def _confirmed_network(config: dict, name: str, client: dict, rules: list[dict]) -> str:
    email, tag = client["email"], safe_tag(name)
    guards = [rule for rule in rules
              if set(rule) == {"type", "user", "ip", "outboundTag"}
              and rule.get("type") == "field" and rule.get("user") == [email]
              and rule.get("outboundTag") == "block"]
    if len(guards) != 1:
        return ""
    addresses = guards[0]["ip"]
    if not isinstance(addresses, list) or len(addresses) != 1:
        return ""
    cidr = _network(addresses[0])
    if not cidr or cidr != addresses[0] or not _inbound_identity(config, client):
        return ""

    # Use the authoritative renderer; no credential or original config is ever
    # returned. Its synthetic inbound is only a way to obtain the routing proof.
    rendered = render_config(
        {"inbounds": [{"tag": "topology-proof", "protocol": "vless", "settings": {"clients": []}}]},
        {"version": 1, "clients": {name: client}}, "topology-proof", cidr,
    )
    expected = rendered["routing"]["rules"]
    if not _outbounds_match(config, rendered["outbounds"][0], tag):
        return ""
    indices = []
    for index, rule in enumerate(rules):
        users = rule.get("user", [])
        if rule.get("outboundTag") == tag or (isinstance(users, list) and email in users) or users == email:
            indices.append(index)
    if [rules[index] for index in indices] != expected:
        return ""
    own_indices = set(indices)
    # Xray is first-match. Before this client's catch-all fallback, only rules
    # explicitly scoped to other users can safely be skipped. Later global
    # rules cannot shadow that fallback and need not be interpreted here.
    for index, rule in enumerate(rules[:indices[-1] + 1]):
        if index in own_indices:
            continue
        users = rule.get("user")
        if (not isinstance(users, list) or not users
                or any(not isinstance(user, str) or not user for user in users) or email in users):
            return ""
    return cidr


def collect_topology_context(awg_state: Path | None, xray_config: Path | None, clients: dict) -> dict:
    """Read saved configuration only, omitting every fact that is not proven."""
    result = {"hub_address": _hub_address(awg_state), "vless_networks": {}}
    config = _xray_config(xray_config)
    routing = config.get("routing")
    if not isinstance(clients, dict) or not isinstance(routing, dict) or routing.get("domainStrategy") != "IPIfNonMatch":
        return result
    rules = routing.get("rules")
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        return result
    for name, raw in clients.items():
        client = _client_policy(name, raw)
        if client is None:
            continue
        if any(other_name != name and isinstance(other, dict)
               and (other.get("email") == client["email"] or _uuid_value(other.get("uuid")) == client["uuid"])
               for other_name, other in clients.items()):
            continue
        try:
            cidr = _confirmed_network(config, name, client, rules)
        except (ValueError, TypeError, KeyError, RuntimeError, RecursionError):
            # Optional display evidence must never take down the node overview.
            # Do not print the exception: renderer errors may quote input data.
            cidr = ""
        if cidr:
            result["vless_networks"][name] = cidr
    return result
