#!/usr/bin/env python3
"""集中采集、校验并投影 server-kit 端口事实。"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol


SCHEMA_VERSION = 1
EXPOSURE_LABELS = {
    "public": "公网",
    "amneziawg": "AWG 内网",
    "private": "私网",
    "loopback": "仅本机",
}
REQUIRED_PUBLIC_IDS = frozenset(
    {
        "ssh-public",
        "clash-subscription",
        "amneziawg-primary",
        "amneziawg-backup1",
    }
)


class PortFactsError(RuntimeError):
    """表示端口事实缺失、损坏或不满足安全策略。"""


@dataclass(frozen=True)
class PortFactSources:
    """生产 adapter 读取的事实配置路径。"""

    security: Path
    awg: Path
    mosh: Path
    management: Path
    xray: Path = Path("/usr/local/etc/xray/config.json")
    file_service: Path = Path("/etc/secure-file-service/config.json")
    clash_service: Path = Path("/etc/secure-file-service/clash-config.json")


class ObservationAdapter(Protocol):
    """端口事实 module 使用的主机观察 seam。"""

    def sockets(self) -> list[dict[str, object]]: ...

    def unit_states(self, units: Iterable[str]) -> dict[str, dict[str, bool]]: ...


class CommandObservationAdapter:
    """通过 ss 与一次 systemctl show 读取 Linux 运行事实。"""

    def __init__(self, ss_bin: str = "/usr/bin/ss", systemctl_bin: str = "/usr/bin/systemctl") -> None:
        self.ss_bin = ss_bin
        self.systemctl_bin = systemctl_bin

    def sockets(self) -> list[dict[str, object]]:
        try:
            text = subprocess.check_output(
                [self.ss_bin, "-H", "-lntup"], text=True, stderr=subprocess.DEVNULL
            )
        except (OSError, subprocess.CalledProcessError):
            return []
        sockets: list[dict[str, object]] = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].lower() not in {"tcp", "udp"}:
                continue
            endpoint = _split_endpoint(parts[4])
            if endpoint is None:
                continue
            process_match = re.search(r'users:\(\(\"([^\"]+)', line)
            sockets.append(
                {
                    "protocol": parts[0].lower(),
                    "address": endpoint[0],
                    "port": endpoint[1],
                    "process": process_match.group(1) if process_match else "未知",
                }
            )
        return sockets

    def unit_states(self, units: Iterable[str]) -> dict[str, dict[str, bool]]:
        states = {
            unit: {"enabled": False, "active": False}
            for unit in sorted(set(units)) if unit
        }
        if not states:
            return states
        try:
            result = subprocess.run(
                [
                    self.systemctl_bin,
                    "show",
                    "--all",
                    "--property=Id",
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=UnitFileState",
                    *states,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
        except OSError:
            return states
        for block in result.stdout.split("\n\n"):
            values = dict(
                line.split("=", 1) for line in block.splitlines() if "=" in line
            )
            unit = values.get("Id", "")
            if unit not in states or values.get("LoadState") == "not-found":
                continue
            states[unit] = {
                "enabled": values.get("UnitFileState", "").startswith("enabled"),
                "active": values.get("ActiveState") == "active",
            }
        return states


class PortFacts:
    """端口事实的唯一读取、推导和投影 interface。"""

    def __init__(self, document: dict[str, object]) -> None:
        self.document = _validate_document(document)

    @classmethod
    def collect(cls, sources: PortFactSources, observer: ObservationAdapter) -> "PortFacts":
        actual = observer.sockets()
        listeners: list[dict[str, object]] = []
        outbound: list[dict[str, object]] = []
        awg = _shell_values(sources.awg)
        mosh = _shell_values(sources.mosh)
        management = _shell_values(sources.management)
        awg_subnet = awg.get("AWG_SUBNET_CIDR", "")
        try:
            awg_network = ipaddress.ip_network(awg_subnet, strict=False)
        except ValueError:
            awg_network = None

        def add_listener(
            identifier: str,
            service: str,
            protocol: str,
            addresses: Iterable[object],
            port: object,
            scope: str,
            source: object,
            purpose: str,
            used_by: list[str] | None = None,
            redirect_to: int | None = None,
        ) -> None:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                return
            normalized_addresses = [str(item) for item in addresses if item]
            if not normalized_addresses:
                return
            listeners.append(
                {
                    "id": identifier,
                    "service": service,
                    "protocol": protocol,
                    "bind_addresses": normalized_addresses,
                    "port": port,
                    "exposure": scope,
                    "source": str(source),
                    "purpose": purpose,
                    "used_by": used_by or [service],
                    "enabled": False,
                    "service_active": False,
                    "listening": False,
                    "redirect_to": redirect_to,
                }
            )

        security = _load_json(sources.security).get("ssh", {})
        if isinstance(security, dict) and security:
            add_listener(
                "ssh-amneziawg",
                "ssh.service",
                "tcp",
                [security.get("amneziawg_address")],
                _safe_int(security.get("amneziawg_port"), 22),
                "amneziawg",
                security.get("config_path", str(sources.security)),
                "AmneziaWG 内网 SSH",
                ["ssh.service"],
            )
            add_listener(
                "ssh-public",
                "ssh.service",
                "tcp",
                [security.get("public_bind_address", security.get("public_address"))],
                _safe_int(security.get("public_port")),
                "public",
                security.get("config_path", str(sources.security)),
                "公网 SSH 救援入口",
            )
        else:
            for item in actual:
                if item.get("protocol") == "tcp" and item.get("process") == "sshd":
                    add_listener(
                        f'ssh-{item.get("address")}-{item.get("port")}',
                        "ssh.service",
                        "tcp",
                        [item.get("address")],
                        item.get("port"),
                        _exposure(str(item.get("address", "")), awg_network),
                        "/etc/ssh/sshd_config",
                        "当前 SSH 监听",
                        ["ssh.service"],
                    )

        awg_primary = _safe_int(awg.get("AWG_PRIMARY_PORT"))
        if awg_primary:
            awg_unit = f'awg-quick@{awg.get("AWG_IFACE", "awg0")}.service'
            add_listener(
                "amneziawg-primary", awg_unit, "udp", ["0.0.0.0", "::"],
                awg_primary, "public", sources.awg, "AmneziaWG 主入口",
            )
            for suffix, key in (("backup1", "AWG_BACKUP_PORT1"), ("backup2", "AWG_BACKUP_PORT2")):
                backup_port = _safe_int(awg.get(key))
                if backup_port:
                    add_listener(
                        f"amneziawg-{suffix}", awg_unit, "udp", ["0.0.0.0", "::"],
                        backup_port, "public", sources.awg,
                        f"AmneziaWG {suffix} nftables 转发入口", redirect_to=awg_primary,
                    )

        _add_mosh_listeners(listeners, add_listener, awg, mosh, awg_network, sources.mosh)

        if management.get("MANAGEMENT_ENABLED") == "yes":
            management_port = _safe_int(management.get("MANAGEMENT_PORT"))
            management_ip = management.get("MANAGEMENT_AWG_IP", "")
            if management_port and management_ip == awg.get("AWG_SERVER_IP", ""):
                add_listener(
                    "management-web", "server-kit-web.service", "tcp", [management_ip],
                    management_port, "amneziawg", sources.management,
                    "server-kit 内网管理网站",
                )

        xray = _load_json(sources.xray)
        inbounds = xray.get("inbounds", [])
        if isinstance(inbounds, list):
            for index, inbound in enumerate(inbounds):
                if not isinstance(inbound, dict):
                    continue
                port = _safe_int(inbound.get("port"))
                address = str(inbound.get("listen", "0.0.0.0"))
                stream = inbound.get("streamSettings", {})
                stream = stream if isinstance(stream, dict) else {}
                inbound_protocol = str(inbound.get("protocol", "入站"))
                settings = inbound.get("settings", {})
                settings = settings if isinstance(settings, dict) else {}
                if inbound_protocol == "shadowsocks":
                    requested_networks = {
                        item.strip().lower()
                        for item in str(settings.get("network", "tcp,udp")).split(",")
                    }
                    protocols = [item for item in ("tcp", "udp") if item in requested_networks]
                else:
                    protocols = ["udp" if stream.get("network", "tcp") in {"kcp", "quic"} else "tcp"]
                for listener_protocol in protocols:
                    identifier = (
                        f"xray-{index}-{listener_protocol}"
                        if len(protocols) > 1 else f"xray-{index}"
                    )
                    add_listener(
                        identifier, "xray.service", listener_protocol, [address], port,
                        _exposure(address, awg_network), sources.xray,
                        f"Xray {inbound_protocol} 服务",
                    )
                reality = stream.get("realitySettings", {})
                reality = reality if isinstance(reality, dict) else {}
                target = reality.get("target") or reality.get("dest")
                if isinstance(target, str) and target:
                    host, separator, port_text = target.rpartition(":")
                    target_port = _safe_int(port_text, 443)
                    outbound.append(
                        {
                            "id": f"xray-reality-{index}",
                            "service": "xray.service",
                            "protocol": "tcp",
                            "destination": host if separator else target,
                            "port": target_port,
                            "purpose": "REALITY 目标站点",
                            "source": str(sources.xray),
                        }
                    )

        for identifier, path, unit, purpose in (
            ("file-service", sources.file_service, "secure-file-service.service", "普通文件下载"),
            ("clash-subscription", sources.clash_service, "secure-clash-service.service", "Clash 订阅下载"),
        ):
            port = _safe_int(_load_json(path).get("port"))
            if port:
                add_listener(identifier, unit, "tcp", ["0.0.0.0"], port, "public", path, purpose)

        units = {
            str(item["service"])
            for item in listeners if item.get("service") and not item.get("on_demand")
        }
        unit_states = observer.unit_states(units)
        for listener in listeners:
            if listener.get("on_demand"):
                continue
            state = unit_states.get(str(listener["service"]), {"enabled": False, "active": False})
            listener["enabled"] = state["enabled"]
            listener["service_active"] = state["active"]
            listener["listening"] = any(_socket_matches(item, listener) for item in actual)

        unmanaged = []
        for item in actual:
            if any(_socket_matches(item, listener, use_redirect=False) for listener in listeners):
                continue
            if item.get("protocol") == "udp" and item.get("process") == "xray":
                continue
            unmanaged.append(
                {
                    **item,
                    "exposure": _exposure(str(item.get("address", "")), awg_network),
                    "firewall_action": "不要自动放行",
                }
            )

        listeners.sort(key=lambda item: (int(item["port"]), str(item["protocol"]), str(item["id"])))
        unmanaged.sort(key=lambda item: (int(item["port"]), str(item["protocol"]), str(item["address"])))
        return cls(
            {
                "schema_version": SCHEMA_VERSION,
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "policy": {
                    "authoritative_for_server_kit": True,
                    "unmanaged_firewall_action": "deny_by_default",
                    "dynamic_source_ports_recorded": False,
                    "secrets_recorded": False,
                },
                "listeners": listeners,
                "outbound_requirements": outbound,
                "observed_unmanaged": unmanaged,
            }
        )

    @classmethod
    def load(cls, path: Path) -> "PortFacts":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PortFactsError(f"无法读取端口事实清单：{path}") from exc
        if not isinstance(value, dict):
            raise PortFactsError("端口事实清单根节点必须是对象。")
        return cls(value)

    def write(self, path: Path) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(self.document, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def service_summaries(self) -> dict[str, str]:
        grouped: dict[tuple[str, tuple[str, str, bool, bool]], set[int]] = defaultdict(set)
        for item in self.listeners:
            key = (
                str(item["protocol"]).upper(), str(item["exposure"]),
                bool(item["listening"]), bool(item.get("on_demand")),
            )
            grouped[(str(item["service"]), key)].add(int(item["port"]))
        by_unit: dict[str, list[str]] = defaultdict(list)
        for (unit, (protocol, exposure, listening, on_demand)), ports in grouped.items():
            scope = EXPOSURE_LABELS.get(exposure, exposure)
            state = "监听中" if listening else ("按需" if on_demand else "未监听")
            by_unit[unit].append(f"{protocol} {compact_ports(ports)} · {scope} · {state}")
        return {unit: "|".join(values) for unit, values in by_unit.items()}

    def firewall_sets(self, rules: str = "") -> dict[tuple[str, str], set[int]]:
        grouped: dict[tuple[str, str], set[int]] = defaultdict(set)
        if rules:
            for key, name in (
                (("public", "TCP"), "public_tcp_ports"),
                (("public", "UDP"), "public_udp_ports"),
                (("amneziawg", "TCP"), "awg_tcp_ports"),
                (("amneziawg", "UDP"), "awg_udp_ports"),
            ):
                grouped[key] = _read_nft_set(rules, name)
            return grouped
        for item in self.listeners:
            if not item.get("enabled") or not item.get("service_active"):
                continue
            scope = str(item["exposure"])
            protocol = str(item["protocol"]).upper()
            if scope not in {"public", "amneziawg"} or protocol not in {"TCP", "UDP"}:
                continue
            if not item.get("listening") and not item.get("on_demand"):
                continue
            port = int(item["port"])
            if scope == "public" and port in {80, 32117}:
                continue
            grouped[(scope, protocol)].add(port)
        return grouped

    def firewall_rows(self, rules: str = "") -> list[tuple[str, str, str, str]]:
        grouped = self.firewall_sets(rules)
        default_drop = bool(
            (rules and re.search(r"hook\s+input[^;]*;\s*policy\s+drop\s*;", rules))
            or self.policy.get("unmanaged_firewall_action") == "deny_by_default"
        )
        action = "拒绝" if default_drop else "未知"
        return [
            ("默认入站", "全部", "全部", action),
            ("已有连接", "全部", "TCP/UDP", "放行"),
            ("公网入口", "公网", "TCP", compact_ports(grouped[("public", "TCP")])),
            ("公网入口", "公网", "UDP", compact_ports(grouped[("public", "UDP")])),
            ("内网入口", "AWG", "TCP", compact_ports(grouped[("amneziawg", "TCP")])),
            ("内网入口", "AWG", "UDP", compact_ports(grouped[("amneziawg", "UDP")])),
            ("诊断报文", "全部", "ICMP", "限速放行"),
            ("未登记入口", "全部", "TCP/UDP", action),
        ]

    def render_nft(
        self, public_interface: str, public_ipv4: str,
        awg_interface: str, awg_ipv4: str, awg_subnet: str,
    ) -> str:
        for name, value in (("公网", public_interface), ("AWG", awg_interface)):
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", value):
                raise PortFactsError(f"{name}接口名无效")
        public = ipaddress.ip_address(public_ipv4)
        awg_address = ipaddress.ip_address(awg_ipv4)
        awg_network = ipaddress.ip_network(awg_subnet, strict=False)
        if public.version != 4 or awg_address.version != 4 or awg_address not in awg_network:
            raise PortFactsError("防火墙地址或 AWG 网段无效")
        if self.policy.get("unmanaged_firewall_action") != "deny_by_default":
            raise PortFactsError("端口事实清单没有默认拒绝未托管监听")
        sets = self.firewall_sets()
        active_ids = {
            str(item["id"]) for item in self.listeners
            if item["exposure"] == "public" and item.get("enabled")
            and item.get("service_active") and item.get("listening")
        }
        missing = REQUIRED_PUBLIC_IDS - active_ids
        if missing:
            raise PortFactsError(f"缺少必要公网服务：{sorted(missing)}")
        if not any(identifier.startswith("xray-") for identifier in active_ids):
            raise PortFactsError("缺少正在监听的公网 Xray 服务")

        def elements(scope: str, protocol: str) -> str:
            return ", ".join(str(value) for value in sorted(sets[(scope, protocol)]))

        awg_tcp = elements("amneziawg", "TCP")
        awg_udp = elements("amneziawg", "UDP")
        awg_tcp_line = f"        elements = {{ {awg_tcp} }}\n" if awg_tcp else ""
        awg_udp_line = f"        elements = {{ {awg_udp} }}\n" if awg_udp else ""
        return f'''# 此文件由 debian_firewall_manager.sh 生成，请勿直接修改。
table inet server_kit_filter {{
    set public_tcp_ports {{
        type inet_service
        elements = {{ {elements("public", "TCP")} }}
    }}

    set public_udp_ports {{
        type inet_service
        elements = {{ {elements("public", "UDP")} }}
    }}

    set awg_tcp_ports {{
        type inet_service
{awg_tcp_line}    }}

    set awg_udp_ports {{
        type inet_service
{awg_udp_line}    }}

    set temporary_public_tcp_ports {{ type inet_service; flags timeout; timeout 15m; }}
    set temporary_public_udp_ports {{ type inet_service; flags timeout; timeout 15m; }}
    set temporary_awg_tcp_ports {{ type inet_service; flags timeout; timeout 15m; }}
    set temporary_awg_udp_ports {{ type inet_service; flags timeout; timeout 15m; }}

    chain input {{
        type filter hook input priority 10; policy drop;
        ct state invalid counter drop
        ct state established,related counter accept
        iifname "lo" counter accept
        icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} counter accept
        icmp type echo-request limit rate 5/second burst 10 packets counter accept
        icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} counter accept
        icmpv6 type echo-request limit rate 5/second burst 10 packets counter accept
        meta nfproto ipv4 iifname "{public_interface}" tcp dport @public_tcp_ports counter accept
        meta nfproto ipv4 iifname "{public_interface}" tcp dport @temporary_public_tcp_ports counter accept
        meta nfproto ipv4 iifname "{public_interface}" udp dport @public_udp_ports counter accept
        meta nfproto ipv4 iifname "{public_interface}" udp dport @temporary_public_udp_ports counter accept
        iifname "{awg_interface}" ip saddr {awg_network} ip daddr {awg_address} tcp dport @awg_tcp_ports counter accept
        iifname "{awg_interface}" ip saddr {awg_network} ip daddr {awg_address} tcp dport @temporary_awg_tcp_ports counter accept
        iifname "{awg_interface}" ip saddr {awg_network} ip daddr {awg_address} udp dport @awg_udp_ports counter accept
        iifname "{awg_interface}" ip saddr {awg_network} ip daddr {awg_address} udp dport @temporary_awg_udp_ports counter accept
        iifname "{awg_interface}" ip saddr {awg_network} ip daddr {awg_address} icmp type echo-request counter accept
    }}
}}
'''

    def audit_lines(self) -> tuple[list[str], bool]:
        lines: list[str] = []
        failed = False
        for item in self.listeners:
            if item.get("service_active") and not item.get("listening") and not item.get("on_demand"):
                lines.append(f'异常：{item["id"]} 服务运行但未监听 {item["protocol"]}/{item["port"]}')
                failed = True
        for item in self.unmanaged:
            prefix = "提示：仅回环监听" if item.get("exposure") == "loopback" else "警告：未托管监听"
            lines.append(f'{prefix} {item["protocol"]}/{item["address"]}:{item["port"]} 进程={item["process"]}')
            if item.get("exposure") != "loopback":
                failed = True
        if not failed:
            lines.append("端口审计通过：未发现监听漂移或未托管端口。")
        return lines, failed

    @property
    def listeners(self) -> list[dict[str, object]]:
        return self.document["listeners"]  # type: ignore[return-value]

    @property
    def unmanaged(self) -> list[dict[str, object]]:
        return self.document["observed_unmanaged"]  # type: ignore[return-value]

    @property
    def policy(self) -> dict[str, object]:
        return self.document["policy"]  # type: ignore[return-value]


def compact_ports(values: Iterable[int]) -> str:
    """把连续端口压缩为稳定的人类可读范围。"""
    numbers = sorted(set(values))
    if not numbers:
        return "无"
    parts: list[str] = []
    start = previous = numbers[0]
    for value in numbers[1:]:
        if value == previous + 1:
            previous = value
            continue
        parts.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = value
    parts.append(str(start) if start == previous else f"{start}-{previous}")
    return "/".join(parts)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _shell_values(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        try:
            parts = shlex.split(raw_value, posix=True)
        except ValueError:
            continue
        if len(parts) == 1:
            values[key] = parts[0]
    return values


def _safe_int(value: object, default: int = 0) -> int:
    try:
        result = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return result if 1 <= result <= 65535 else default


def _split_endpoint(value: str) -> tuple[str, int] | None:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        address, port = value[1:].rsplit("]:", 1)
    else:
        try:
            address, port = value.rsplit(":", 1)
        except ValueError:
            return None
    try:
        return address, int(port)
    except ValueError:
        return None


def _exposure(address: str, awg_network: ipaddress._BaseNetwork | None) -> str:
    if address in {"127.0.0.1", "::1"}:
        return "loopback"
    if address in {"0.0.0.0", "::", "*"}:
        return "public"
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return "public"
    if awg_network and value in awg_network:
        return "amneziawg"
    return "private" if value.is_private else "public"


def _address_matches(actual: str, managed: Iterable[object]) -> bool:
    aliases = {"*": {"0.0.0.0", "::", "*"}, "0.0.0.0": {"0.0.0.0", "*"}, "::": {"::", "*"}}
    return any(actual == str(value) or actual in aliases.get(str(value), set()) for value in managed)


def _socket_matches(actual: dict[str, object], listener: dict[str, object], *, use_redirect: bool = True) -> bool:
    target_port = listener.get("redirect_to") if use_redirect else None
    target_port = target_port or listener.get("port")
    return (
        actual.get("protocol") == listener.get("protocol")
        and actual.get("port") == target_port
        and _address_matches(str(actual.get("address", "")), listener.get("bind_addresses", []))
    )


def _add_mosh_listeners(
    listeners: list[dict[str, object]], add_listener, awg: dict[str, str],
    mosh: dict[str, str], awg_network: ipaddress._BaseNetwork | None, source: Path,
) -> None:
    if not mosh:
        return
    start = _safe_int(mosh.get("MOSH_PORT_START", mosh.get("MOSH_PORT", "")))
    end = _safe_int(mosh.get("MOSH_PORT_END", start))
    mosh_ip = mosh.get("MOSH_BIND_IP", "")
    valid_boundary = (
        mosh_ip == awg.get("AWG_SERVER_IP", "")
        and mosh.get("MOSH_INTERFACE", "") == awg.get("AWG_IFACE", "awg0")
        and mosh.get("MOSH_SUBNET_CIDR", "") == awg.get("AWG_SUBNET_CIDR", "")
        and awg_network is not None
    )
    if not valid_boundary or not (1 <= start <= end <= 65535 and end - start < 100):
        return
    enabled = mosh.get("MOSH_ENABLED") == "yes"
    for port in range(start, end + 1):
        add_listener(
            "mosh-awg" if port == start else f"mosh-awg-{port}",
            "server-kit-mosh", "udp", [mosh_ip], port, "amneziawg", source,
            "Mosh 按需远程终端", ["server-kit-mosh"],
        )
        listeners[-1].update(enabled=enabled, service_active=enabled, on_demand=True)


def _read_nft_set(rules: str, name: str) -> set[int]:
    match = re.search(rf"set\s+{re.escape(name)}\s*\{{(.*?)\n\s*\}}", rules, re.DOTALL)
    if not match:
        return set()
    elements = re.search(r"elements\s*=\s*\{([^}]*)\}", match.group(1), re.DOTALL)
    if not elements:
        return set()
    return {
        int(value) for value in re.findall(r"(?<![\w.])(\d{1,5})(?![\w.])", elements.group(1))
        if 1 <= int(value) <= 65535
    }


def _validate_document(value: dict[str, object]) -> dict[str, object]:
    if value.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise PortFactsError("端口事实清单版本不受支持。")
    value.setdefault("schema_version", SCHEMA_VERSION)
    value.setdefault("generated_at", "")
    value.setdefault("policy", {})
    value.setdefault("listeners", [])
    value.setdefault("outbound_requirements", [])
    value.setdefault("observed_unmanaged", [])
    policy = value.get("policy")
    listeners = value.get("listeners")
    outbound = value.get("outbound_requirements")
    unmanaged = value.get("observed_unmanaged")
    if not isinstance(policy, dict) or not isinstance(listeners, list) or not isinstance(outbound, list) or not isinstance(unmanaged, list):
        raise PortFactsError("端口事实清单结构不完整。")
    for item in listeners:
        if not isinstance(item, dict) or not {
            "protocol", "port", "exposure", "enabled", "service_active", "listening",
        }.issubset(item):
            raise PortFactsError("端口监听条目结构不正确。")
        item.setdefault("id", f'{item["protocol"]}-{item["port"]}')
        item.setdefault("service", str(item["id"]))
        if "bind_addresses" not in item:
            item["bind_addresses"] = [
                "0.0.0.0" if item.get("exposure") == "public" else "10.20.0.1"
            ]
        if item["protocol"] not in {"tcp", "udp"} or item["exposure"] not in EXPOSURE_LABELS:
            raise PortFactsError("端口监听条目的协议或范围无效。")
        if not isinstance(item["port"], int) or not 1 <= item["port"] <= 65535:
            raise PortFactsError("端口监听条目的端口无效。")
    return value


def _read_rules(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


def _show_ports(facts: PortFacts, path: Path) -> None:
    print("=== server-kit 端口清单 ===")
    for item in facts.listeners:
        addresses = ",".join(str(value) for value in item["bind_addresses"])
        state = "监听中" if item["listening"] else ("按需" if item.get("on_demand") else "未监听")
        print(f'{str(item["protocol"]).upper():3} {addresses}:{item["port"]:<5} {item["exposure"]:<9} {state:<4} {item.get("purpose", "-")}')
    print("\n未托管监听：")
    if not facts.unmanaged:
        print("  无")
    for item in facts.unmanaged:
        print(f'  {str(item["protocol"]).upper()} {item["address"]}:{item["port"]} 进程={item["process"]}（不会自动放行）')
    print(f"\n清单文件：{path}")


def _show_compact(facts: PortFacts) -> None:
    for item in facts.listeners:
        addresses = ",".join(str(value) for value in item["bind_addresses"])
        state = "监听中" if item["listening"] else ("按需" if item.get("on_demand") else "未监听")
        scope = EXPOSURE_LABELS.get(str(item["exposure"]), str(item["exposure"]))
        print(f'- {str(item["protocol"]).upper()} {addresses}:{item["port"]}')
        print(f"  {scope} · {state}")
        print(f'  {item.get("purpose", "-")}')
    print("\n未托管监听")
    if not facts.unmanaged:
        print("  无")
    for item in facts.unmanaged:
        print(f'- {str(item["protocol"]).upper()} {item["address"]}:{item["port"]}')
        print(f'  进程：{item.get("process", "未知")}')


def _listener_rows(facts: PortFacts) -> None:
    print("协议\t监听地址\t端口\t范围\t状态\t用途")
    for item in facts.listeners:
        addresses = ",".join(str(value) for value in item["bind_addresses"])
        state = "监听中" if item["listening"] else ("按需" if item.get("on_demand") else "未监听")
        scope = EXPOSURE_LABELS.get(str(item["exposure"]), str(item["exposure"]))
        print(f'{str(item["protocol"]).upper()}\t{addresses}\t{item["port"]}\t{scope}\t{state}\t{item.get("purpose", "-")}')


def _unmanaged_rows(facts: PortFacts) -> None:
    print("协议\t监听地址\t端口\t进程\t处理")
    if not facts.unmanaged:
        print("-\t-\t-\t-\t无")
    for item in facts.unmanaged:
        print(f'{str(item["protocol"]).upper()}\t{item["address"]}\t{item["port"]}\t{item.get("process", "未知")}\t不自动放行')


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="server-kit 端口事实清单")
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--output", required=True)
    collect.add_argument("--security", required=True)
    collect.add_argument("--awg", required=True)
    collect.add_argument("--mosh", required=True)
    collect.add_argument("--management", required=True)
    collect.add_argument("--ss", default="/usr/bin/ss")
    collect.add_argument("--systemctl", default="/usr/bin/systemctl")
    project = commands.add_parser("project")
    project.add_argument("view", choices=(
        "service-summary", "firewall-rows", "show", "show-compact",
        "listener-rows", "unmanaged-rows", "audit",
    ))
    project.add_argument("--ports", required=True)
    project.add_argument("--rules", default="")
    render = commands.add_parser("render-nft")
    render.add_argument("--ports", required=True)
    render.add_argument("--output", required=True)
    render.add_argument("--public-interface", required=True)
    render.add_argument("--public-ipv4", required=True)
    render.add_argument("--awg-interface", required=True)
    render.add_argument("--awg-ipv4", required=True)
    render.add_argument("--awg-subnet", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "collect":
            facts = PortFacts.collect(
                PortFactSources(
                    security=Path(args.security), awg=Path(args.awg),
                    mosh=Path(args.mosh), management=Path(args.management),
                ),
                CommandObservationAdapter(args.ss, args.systemctl),
            )
            facts.write(Path(args.output))
            return 0
        facts = PortFacts.load(Path(args.ports))
        if args.command == "render-nft":
            Path(args.output).write_text(
                facts.render_nft(
                    args.public_interface, args.public_ipv4,
                    args.awg_interface, args.awg_ipv4, args.awg_subnet,
                ),
                encoding="utf-8", newline="\n",
            )
            return 0
        if args.view == "service-summary":
            for unit, summary in facts.service_summaries().items():
                print(f"{unit}\t{summary}")
        elif args.view == "firewall-rows":
            for row in facts.firewall_rows(_read_rules(args.rules)):
                print("\t".join(row))
        elif args.view == "show":
            _show_ports(facts, Path(args.ports))
        elif args.view == "show-compact":
            _show_compact(facts)
        elif args.view == "listener-rows":
            _listener_rows(facts)
        elif args.view == "unmanaged-rows":
            _unmanaged_rows(facts)
        elif args.view == "audit":
            lines, failed = facts.audit_lines()
            print("\n".join(lines))
            return int(failed)
        return 0
    except (PortFactsError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
