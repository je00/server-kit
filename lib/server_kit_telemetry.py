#!/usr/bin/env python3
"""Read-only, bounded node ↔ VPS telemetry, independent of inventory generation.

Rates are bytes/second from the node's perspective: AWG receive is upload,
AWG transmit is download. Counters and peer identities never leave this module.
VLESS stays unavailable until a separately authorized statistics source exists.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import math
import os
import re
import selectors
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
IFACE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
KEY_PATTERN = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
BOOT_PATTERN = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
MAX_INPUT_BYTES = 512_000
COMMAND_TIMEOUT_SECONDS = 1.0
REFRESH_SECONDS = 2.0
MAX_INTERVAL_SECONDS = 10.0
MAX_COUNTER = (1 << 64) - 1
COMMAND_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
}


@dataclass(frozen=True)
class TelemetryPaths:
    manager_state: Path = Path("/etc/amneziawg/manager.conf")
    awg_active: Path = Path("/etc/amneziawg/peers.tsv")
    awg_disabled: Path = Path("/etc/amneziawg/peers.disabled.tsv")
    awg_enrollments: Path = Path("/etc/amneziawg/enrollments.json")
    vless_policy: Path = Path("/etc/server-kit/vless-access.json")
    sys_class_net: Path = Path("/sys/class/net")
    boot_id: Path = Path("/proc/sys/kernel/random/boot_id")


@dataclass(frozen=True)
class CounterObservation:
    """Private sampling fact; only the explicit public projection may be returned."""

    id: str
    state: str
    last_seen_at: int | None = None
    source: str = "none"
    received: int | None = None
    sent: int | None = None
    identity: tuple[str, ...] | None = None


def bounded_command(arguments: list[str]) -> str | None:
    """Never shell out or buffer unbounded stdout/stderr; do not expose errors."""

    process: subprocess.Popen[bytes] | None = None
    try:
        deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
        process = subprocess.Popen(
            arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=COMMAND_ENV, cwd="/", close_fds=True,
        )
        assert process.stdout is not None
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                if not selector.select(remaining):
                    return None
                chunk = os.read(process.stdout.fileno(), min(65_536, MAX_INPUT_BYTES + 1 - len(output)))
                if not chunk:
                    selector.unregister(process.stdout)
                    break
                output.extend(chunk)
                if len(output) > MAX_INPUT_BYTES:
                    return None
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            return None
        return output.decode("utf-8")
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass
            if process.stdout is not None:
                process.stdout.close()


def _read_text(path: Path, *, optional: bool = False) -> str | None:
    try:
        with path.open("rb") as handle:
            value = handle.read(MAX_INPUT_BYTES + 1)
        return value.decode("utf-8") if len(value) <= MAX_INPUT_BYTES else None
    except FileNotFoundError:
        return "" if optional else None
    except (OSError, UnicodeError):
        return None


def _object(path: Path, *, optional: bool = False) -> dict[str, Any] | None:
    value = _read_text(path, optional=optional)
    if value == "" and optional:
        return {}
    try:
        result = json.loads(value) if value is not None else None
    except (ValueError, RecursionError):
        return None
    return result if isinstance(result, dict) else None


def _registry(path: Path, *, optional: bool = False) -> dict[str, str | None] | None:
    value = _read_text(path, optional=optional)
    if value is None:
        return None
    result: dict[str, str | None] = {}
    for line in value.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if not NAME_PATTERN.fullmatch(fields[0]):
            return None
        name = fields[0]
        try:
            address = str(ipaddress.ip_address(fields[1])) if len(fields) == 2 else None
        except ValueError:
            address = None
        result[name] = None if name in result else address
    return result


def _rows(text: str | None, columns: int) -> dict[str, list[str]] | None:
    if text is None or not isinstance(text, str) or len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        return None
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split(None, columns - 1)
        if len(fields) != columns or not KEY_PATTERN.fullmatch(fields[0]) or fields[0] in result:
            return None
        result[fields[0]] = fields[1:]
    return result


def _counter(value: str) -> int:
    if not re.fullmatch(r"[0-9]{1,20}", value):
        raise ValueError("invalid counter")
    number = int(value)
    if number > MAX_COUNTER:
        raise ValueError("invalid counter")
    return number


class AWGTelemetryCollector:
    """Only three allow-listed AWG reads, plus small local registry/sysfs files."""

    def __init__(
        self, paths: TelemetryPaths | None = None,
        command: Callable[[list[str]], str | None] = bounded_command,
    ) -> None:
        self.paths = paths or TelemetryPaths()
        self._command = command

    def _interface(self) -> str | None:
        text = _read_text(self.paths.manager_state)
        if text is None:
            return None
        matches = []
        for line in text.splitlines():
            match = re.fullmatch(r"\s*AWG_IFACE=(.*)", line)
            if match:
                value = match.group(1).strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                matches.append(value)
        return matches[0] if len(matches) == 1 and IFACE_PATTERN.fullmatch(matches[0]) else None

    def _interface_identity(self, interface: str) -> tuple[str, ...] | None:
        boot = _read_text(self.paths.boot_id)
        index = _read_text(self.paths.sys_class_net / interface / "ifindex")
        if boot is None or index is None:
            return None
        boot, index = boot.strip(), index.strip()
        if not BOOT_PATTERN.fullmatch(boot) or not re.fullmatch(r"[1-9][0-9]{0,9}", index):
            return None
        return boot, interface, index

    def _runtime(self, interface: str) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[str, list[str]]] | None:
        try:
            allowed = _rows(self._command(["awg", "show", interface, "allowed-ips"]), 2)
            if allowed is None:
                return None
            handshakes = _rows(self._command(["awg", "show", interface, "latest-handshakes"]), 2)
            if handshakes is None:
                return None
            transfer = _rows(self._command(["awg", "show", interface, "transfer"]), 3)
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
        return (allowed, handshakes, transfer) if transfer is not None else None

    def collect(self, now: float) -> list[CounterObservation]:
        active = _registry(self.paths.awg_active, optional=True)
        disabled = _registry(self.paths.awg_disabled, optional=True)
        enrollment = _object(self.paths.awg_enrollments, optional=True)
        pending = enrollment.get("items", {}) if enrollment is not None else None
        if not isinstance(pending, dict):
            pending = None
        active, active_ok = active or {}, active is not None
        disabled, disabled_ok = disabled or {}, disabled is not None
        rows: dict[str, CounterObservation] = {}
        for name in active:
            state = "pending" if pending is not None and name in pending else "unknown"
            rows[name] = CounterObservation(f"awg:{name}", state)
        for name in disabled:
            rows[name] = CounterObservation(f"awg:{name}", "disabled")

        interface = self._interface() if active else None
        identity = self._interface_identity(interface) if interface else None
        runtime = (
            self._runtime(interface)
            if interface and identity and active_ok and disabled_ok and pending is not None
            else None
        )
        if runtime is not None and self._interface_identity(interface) == identity:
            allowed, handshakes, transfer = runtime
            by_address: dict[str, set[str]] = {}
            by_key: dict[str, set[str]] = {}
            registered = set(active.values()) - {None}
            invalid_keys: set[str] = set()
            for key, fields in allowed.items():
                routes = fields[0].replace(",", " ").split()
                if routes == ["(none)"]:
                    continue
                for route in routes:
                    try:
                        network = ipaddress.ip_network(route, strict=True)
                    except ValueError:
                        invalid_keys.add(key)
                        continue
                    # Never attribute an entire subnet to a registered host.
                    if network.prefixlen == network.max_prefixlen:
                        address = str(network.network_address)
                        if address in registered:
                            by_address.setdefault(address, set()).add(key)
                            by_key.setdefault(key, set()).add(address)
            address_names: dict[str | None, list[str]] = {}
            for name, address in active.items():
                address_names.setdefault(address, []).append(name)
            for name, address in disabled.items():
                if name not in active:
                    address_names.setdefault(address, []).append(name)
            for name, address in active.items():
                if rows[name].state != "unknown" or address is None or len(address_names[address]) != 1:
                    continue
                keys = by_address.get(address, set())
                if len(keys) != 1:
                    continue
                key = next(iter(keys))
                if key in invalid_keys or len(by_key[key]) != 1 or key not in handshakes or key not in transfer:
                    continue
                try:
                    last_seen = _counter(handshakes[key][0])
                    received, sent = (_counter(value) for value in transfer[key])
                    if last_seen > now + 5:
                        continue
                except ValueError:
                    continue
                state = "never" if last_seen == 0 else "recent" if now - last_seen <= 180 else "idle"
                rows[name] = CounterObservation(
                    f"awg:{name}", state, last_seen or None, "awg", received, sent,
                    (*identity, key, address),
                )

        result = list(rows.values())
        policy = _object(self.paths.vless_policy, optional=True)
        clients = policy.get("clients", {}) if policy is not None else {}
        if isinstance(clients, dict):
            for name, client in clients.items():
                if isinstance(name, str) and NAME_PATTERN.fullmatch(name) and isinstance(client, dict):
                    state = "unsupported" if client.get("enabled", True) is True else "disabled"
                    result.append(CounterObservation(f"vless:{name}", state))
        return sorted(result, key=lambda item: item.id.lower())


class NetworkTelemetrySampler:
    """One per agent runner; serialize collection and share a two-second cache."""

    def __init__(
        self, collector: AWGTelemetryCollector | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._collector = collector or AWGTelemetryCollector()
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._lock = threading.Lock()
        self._cached: dict[str, Any] | None = None
        self._cached_at: float | None = None
        self._baseline: dict[str, tuple[CounterObservation, float]] = {}

    def read(self) -> dict[str, Any]:
        with self._lock:
            now = self._monotonic()
            if self._cached is not None and self._cached_at is not None and 0 <= now - self._cached_at < REFRESH_SECONDS:
                return copy.deepcopy(self._cached)
            observations = self._collector.collect(self._wall_clock())
            sampled = self._monotonic()
            nodes = []
            baseline: dict[str, tuple[CounterObservation, float]] = {}
            for observation in observations:
                row = {
                    "id": observation.id, "state": observation.state,
                    "last_seen_at": observation.last_seen_at,
                    "upload_bps": None, "download_bps": None,
                    "rate_status": "unavailable", "source": observation.source,
                }
                if (
                    observation.state in {"recent", "idle", "never"}
                    and observation.received is not None and observation.sent is not None
                    and observation.identity is not None
                ):
                    row["rate_status"] = "warming_up"
                    previous = self._baseline.get(observation.id)
                    if previous is not None:
                        old, old_at = previous
                        elapsed = sampled - old_at
                        if (
                            old.identity != observation.identity or not 0 < elapsed <= MAX_INTERVAL_SECONDS
                            or observation.received < old.received or observation.sent < old.sent
                        ):
                            row["rate_status"] = "reset"
                        else:
                            upload = (observation.received - old.received) / elapsed
                            download = (observation.sent - old.sent) / elapsed
                            if math.isfinite(upload) and math.isfinite(download):
                                row.update(upload_bps=upload, download_bps=download, rate_status="ok")
                                if upload > 0 or download > 0:
                                    row["state"] = "active"
                    baseline[observation.id] = observation, sampled
                nodes.append(row)
            self._baseline = baseline
            self._cached_at = sampled
            self._cached = {
                "schema_version": 1,
                "sampled_at": datetime.fromtimestamp(self._wall_clock(), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "refresh_ms": int(REFRESH_SECONDS * 1000),
                "stale_after_ms": 8000,
                "nodes": nodes,
            }
            return copy.deepcopy(self._cached)
