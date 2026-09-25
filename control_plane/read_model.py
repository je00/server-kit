#!/usr/bin/env python3
"""按页面意图构建受管主机只读模型，并隐藏采集成本与缓存策略。"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol


class HostFactsAdapter(Protocol):
    """读取模型依赖的主机事实 adapter。"""

    def snapshot(self) -> dict[str, Any]: ...
    def service_inventory(self, service_id: str) -> dict[str, Any]: ...
    def file_resources(self) -> dict[str, Any]: ...
    def network_overview(self) -> dict[str, Any]: ...
    def proxy_resources(self) -> dict[str, Any]: ...
    def firewall_ports(self) -> dict[str, Any]: ...
    def managed_ports(self) -> dict[str, Any]: ...
    def ssh_keys(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class _CachedFact:
    value: dict[str, Any]
    expires_at: float


class ManagedHostReadModel:
    """网页只表达读取意图；本 module 决定事实组合、校验和短期复用。"""

    INTENTS = frozenset({"overview", "service", "network", "file", "proxy"})

    def __init__(
        self,
        adapter: HostFactsAdapter,
        describe_service: Callable[[dict[str, Any], str, dict[str, Any]], dict[str, Any]],
        *,
        ttl_seconds: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._adapter = adapter
        self._describe_service = describe_service
        self._ttl = max(0.0, ttl_seconds)
        self._clock = clock
        self._cache: dict[tuple[str, str], _CachedFact] = {}

    def invalidate(self) -> None:
        """主机发生变更后丢弃全部进程内只读事实。"""
        self._cache.clear()

    def read(self, intent: str, service_id: str = "") -> dict[str, Any]:
        if intent not in self.INTENTS:
            raise ValueError("主机读取意图未登记")
        components: list[str]
        if intent == "overview":
            view = self._fact("snapshot", "", self._adapter.snapshot)
            components = ["snapshot"]
        elif intent == "network":
            view = self._fact("network", "", self._adapter.network_overview)
            components = ["network"]
        elif intent == "file":
            view = self._fact("file", "", self._adapter.file_resources)
            components = ["file"]
        elif intent == "proxy":
            view = self._fact(
                "proxy", "", self._adapter.proxy_resources,
                expected_schema_versions=frozenset({3}),
            )
            components = ["proxy"]
        else:
            if not service_id:
                raise ValueError("服务详情读取缺少服务标识")
            snapshot = self._fact("snapshot", "", self._adapter.snapshot)
            inventory = self._fact(
                "inventory", service_id,
                lambda: self._adapter.service_inventory(service_id),
            )
            view = self._describe_service(snapshot, service_id, inventory)
            components = ["snapshot", f"inventory:{service_id}"]
            if service_id == "firewall":
                view = {**view, "firewall_ports": self._fact(
                    "firewall_ports", "", self._adapter.firewall_ports
                )}
                components.append("firewall_ports")
            elif service_id in {"amneziawg", "clash", "file"}:
                view = {**view, "managed_ports": self._fact(
                    "managed_ports", "", self._adapter.managed_ports
                )}
                components.append("managed_ports")
            elif service_id == "ssh":
                view = {**view, "ssh_keys": self._fact("ssh_keys", "", self._adapter.ssh_keys)}
                components.append("ssh_keys")
        return {
            "schema_version": 1,
            "intent": intent,
            "fresh_for_ms": int(self._ttl * 1000),
            "components": components,
            "view": view,
        }

    def _fact(
        self, kind: str, identifier: str, loader: Callable[[], dict[str, Any]],
        *, expected_schema_versions: frozenset[int] = frozenset({1}),
    ) -> dict[str, Any]:
        key = (kind, identifier)
        now = self._clock()
        cached = self._cache.get(key)
        if cached and cached.expires_at >= now:
            return cached.value
        value = loader()
        if not isinstance(value, dict) or value.get("schema_version") not in expected_schema_versions:
            raise RuntimeError(f"主机事实版本不受支持：{kind}")
        self._cache[key] = _CachedFact(value=value, expires_at=self._clock() + self._ttl)
        return value
