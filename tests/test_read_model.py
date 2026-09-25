#!/usr/bin/env python3
"""验证受管主机读取模型按意图组合事实并短期复用。"""

from __future__ import annotations

import unittest

from control_plane.read_model import ManagedHostReadModel


class FactAdapter:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _value(self, name: str, **extra):
        self.calls.append(name)
        return {"schema_version": 1, **extra}

    def snapshot(self):
        return self._value("snapshot", services=[{"id": "ssh", "state": "运行中"}])

    def service_inventory(self, service_id):
        return self._value(f"inventory:{service_id}", service_id=service_id, facts={}, items=[])

    def file_resources(self):
        return self._value("file", items=[])

    def network_overview(self):
        return self._value("network", nodes=[])

    def proxy_resources(self):
        self.calls.append("proxy")
        return {"schema_version": 3, "configured": False}

    def firewall_ports(self):
        return self._value("firewall_ports", items=[])

    def managed_ports(self):
        return self._value("managed_ports", items=[])

    def ssh_keys(self):
        return self._value("ssh_keys", items=[])


def describe(snapshot, service_id, inventory):
    service = next(item for item in snapshot["services"] if item["id"] == service_id)
    return {"service": service, "inventory": inventory}


class ManagedHostReadModelTests(unittest.TestCase):
    def test_service_intent_owns_collection_plan_and_reuses_facts(self) -> None:
        adapter = FactAdapter()
        model = ManagedHostReadModel(adapter, describe, ttl_seconds=5)
        first = model.read("service", "ssh")
        second = model.read("service", "ssh")
        self.assertEqual(first["components"], ["snapshot", "inventory:ssh", "ssh_keys"])
        self.assertEqual(second["view"]["ssh_keys"]["items"], [])
        self.assertEqual(adapter.calls, ["snapshot", "inventory:ssh", "ssh_keys"])

    def test_invalidation_forces_fresh_collection(self) -> None:
        adapter = FactAdapter()
        model = ManagedHostReadModel(adapter, describe, ttl_seconds=5)
        model.read("overview")
        model.invalidate()
        model.read("overview")
        self.assertEqual(adapter.calls, ["snapshot", "snapshot"])

    def test_端口服务详情复用统一端口事实(self) -> None:
        adapter = FactAdapter()
        adapter.snapshot = lambda: adapter._value("snapshot", services=[{"id": "clash", "state": "运行中"}])
        result = ManagedHostReadModel(adapter, describe, ttl_seconds=5).read("service", "clash")
        self.assertEqual(result["components"], ["snapshot", "inventory:clash", "managed_ports"])

    def test_unregistered_intent_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ManagedHostReadModel(FactAdapter(), describe).read("raw-command")

    def test_proxy_intent_accepts_catalog_schema_three(self) -> None:
        model = ManagedHostReadModel(FactAdapter(), describe)
        result = model.read("proxy")
        self.assertEqual(result["view"]["schema_version"], 3)

    def test_slow_collection_gets_full_ttl_after_completion_then_refreshes(self) -> None:
        adapter = FactAdapter()
        clock = [10.0]

        def slow_snapshot():
            clock[0] += 2.0
            return adapter._value("snapshot", services=[])

        adapter.snapshot = slow_snapshot
        model = ManagedHostReadModel(adapter, describe, ttl_seconds=1.0, clock=lambda: clock[0])
        model.read("overview")
        model.read("overview")
        self.assertEqual(adapter.calls, ["snapshot"])
        clock[0] += 0.9
        model.read("overview")
        self.assertEqual(adapter.calls, ["snapshot"])
        clock[0] += 0.2
        model.read("overview")
        self.assertEqual(adapter.calls, ["snapshot", "snapshot"])
        model.read("overview")
        self.assertEqual(adapter.calls, ["snapshot", "snapshot"])


if __name__ == "__main__":
    unittest.main()
