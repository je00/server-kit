#!/usr/bin/env python3
"""Local-only in-memory agent. Never imports or runs host management commands."""

from __future__ import annotations

import argparse
import copy
import json
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.server_kit_port_ranges import format_ports, parse_ports
from preview_fixtures import build_fixtures, make_task


class PreviewAgent:
    """A deliberately separate, fail-closed implementation of the agent protocol."""

    def __init__(self, scenario: str = "rich") -> None:
        self.lock = threading.RLock()
        self.set_scenario(scenario)

    def set_scenario(self, scenario: str) -> None:
        if scenario not in {"rich", "empty", "error", "pending"}:
            raise ValueError("Unknown preview scenario")
        with self.lock:
            self.scenario = scenario
            self.data = build_fixtures(scenario)
            self._telemetry_started = time.monotonic()
            self._permission_batches: dict[str, dict] = {}
            self._inline_changes: dict[str, dict] = {}

    def dispatch(self, action: str, params: dict) -> dict:
        with self.lock:
            return copy.deepcopy(self._dispatch(action, params))

    def _dispatch(self, action: str, params: dict) -> dict:
        if self.scenario == "error":
            raise ValueError("模拟管理代理不可用；仅限本地预览。")
        if action == "host.read":
            intent = params.get("intent")
            view = self.describe(params["service_id"]) if intent == "service" else self.data[intent]
            return {"schema_version": 1, "intent": intent, "fresh_for_ms": 1000,
                    "components": [intent], "view": view}
        if action == "system.snapshot":
            return self.data["overview"]
        if action == "network.telemetry":
            if params:
                raise ValueError("实时采样不接受参数。")
            nodes = []
            warming = time.monotonic() - self._telemetry_started < 2
            now = time.time()
            for index, node in enumerate(self.data["network"]["nodes"]):
                state = ("disabled" if node["state"] == "已禁用" else
                         "pending" if node["state"] == "等待首次握手" else
                         "unsupported" if node["kind"] == "vless" else "active")
                sampled = state == "active" and not warming
                nodes.append({"id": f"{node['kind']}:{node['name']}", "state": state,
                              "source": "awg" if node["kind"] == "awg" else "none",
                              "last_seen_at": int(now - 25) if state == "active" else None,
                              "rate_status": "ok" if sampled else "warming_up" if state == "active" else "unavailable",
                              "upload_bps": (index + 1) * 1024 + int(now / 2) % 8 * 128 if sampled else None,
                              "download_bps": (index + 1) * 1024 * 96 if sampled else None})
            return {"schema_version": 1, "sampled_at": datetime.now(timezone.utc).isoformat(),
                    "refresh_ms": 2000, "stale_after_ms": 8000, "nodes": nodes}
        if action == "service.describe":
            return self.describe(params["service_id"])
        reads = {"network.public_endpoint.status": "endpoint",
                 "network.public_endpoint.transaction.status": "endpoint_transaction",
                 "network.duckdns.status": "duckdns", "network.enrollment.context": "enrollment",
                 "network.enrollment.overview": "network", "firewall.ports.overview": "firewall_ports",
                 "ssh.keys.overview": "ssh_keys", "managed.ports.overview": "managed_ports", "audit.list": "audit"}
        if action in reads:
            return self.data[reads[action]]
        if action == "security.transaction":
            if params.get("operation", "status") not in {"status", "preview"}:
                raise ValueError("预览代理不执行主机变更。")
            return self.data["transactions"][params["transaction_type"]]
        if action == "backup.manage":
            if params["operation"] == "list":
                return self.data["backups"]
            if params["operation"] == "restore_status":
                return self.data["restore"]
            raise ValueError("预览代理不读取或写入真实备份。")
        if action == "network.proxy.test":
            return {"schema_version": 2, "airports": [
                {**item, "ok": item["enabled"], "status": "模拟 HTTP 200" if item["enabled"] else "模拟连接超时"}
                for item in self.data["proxy"]["airports"]],
                "exits": [{**item, "ok": True, "status": "模拟 TCP 可达"} for item in self.data["proxy"]["exits"]],
                "exit": {"ok": True, "status": "模拟 TCP 可达"}, "all_ok": False}
        if action == "task.list":
            return {"items": list(self.data["tasks"].values())}
        if action == "task.get":
            return self.data["tasks"][params["task_id"]]
        if action == "task.preview":
            # Do not echo passwords, keys, URLs or arbitrary request payloads.
            allowed = {"service.change", "file.resource.change", "network.duckdns.change",
                       "network.public_endpoint.change", "network.node.change", "network.node.domains",
                       "network.address.domains", "network.node.import", "network.permission.change",
                       "network.permission.batch",
                       "network.subscriptions.sync", "network.subscription.rotate", "network.subscription.state",
                       "network.proxy.update", "deployment.install", "security.transaction.change",
                       "managed.port.change", "firewall.port.change", "ssh.key.change", "backup.manage",
                       "backup.restore.change"}
            if params.get("action") not in allowed:
                raise ValueError("动作未登记；不会转发到真实管理代理。")
            task = make_task("waiting_confirmation", "task-" + uuid.uuid4().hex)
            task["action"] = params["action"]
            task["actor"] = "preview"
            inline = self.prepare_inline_change(params["action"], params.get("arguments", {}))
            if inline is not None:
                task["action"] = inline["action"]
                task["actor"] = params.get("actor", "preview")
                task["preview"] = {"title": inline["title"], "summary": "仅在本地合成数据中模拟，不连接真实服务。", "facts": inline["facts"]}
                self._inline_changes[task["id"]] = inline
            if params["action"] == "network.permission.batch":
                batch = self.prepare_permission_batch(params.get("arguments"))
                actor = params.get("actor")
                if not isinstance(actor, str) or not actor:
                    raise ValueError("批量预览需要当前操作者。")
                task["actor"] = actor
                task["preview"] = {
                    "title": f"新增 {len(batch['rules'])} 条访问权限",
                    "summary": "仅在本地内存中模拟追加；现有权限和管理连接保持不变。",
                    "facts": {"来源节点": batch["client"], "规则数量": len(batch["rules"]),
                              **{f"规则 {index}": f"{rule['target_label']} · {rule['network_label']} · {rule['ports_label']}"
                                 for index, rule in enumerate(batch["rules"], 1)}},
                    "stages": ["核验全部规则", "统一追加权限", "更新本页权限列表"],
                }
                # Store only normalized, allow-listed data, outside every read response.
                self._permission_batches[task["id"]] = batch
            self.data["tasks"][task["id"]] = task
            return task
        if action in {"task.confirm", "task.cancel"}:
            task = self.data["tasks"][params["task_id"]]
            if task.get("terminal"):
                return task
            batch = self._permission_batches.get(task["id"])
            inline = self._inline_changes.get(task["id"])
            if (batch or inline) and params.get("actor") != task["actor"]:
                raise ValueError("操作者与批量预览不匹配。")
            state = "succeeded" if action == "task.confirm" else "cancelled"
            if batch and action == "task.confirm":
                # In-memory simulation only. Recheck every rule before appending any.
                checked = self.prepare_permission_batch({"client": batch["client"], "rules": [
                    {"target": rule["target"], "network": rule["network"],
                     "ports": format_ports(rule["ports"])} for rule in batch["rules"]]})
                node = next(node for node in self.data["network"]["nodes"] if node["name"] == checked["client"])
                node["permissions"].extend(copy.deepcopy(checked["rules"]))
            if inline and action == "task.confirm":
                self.apply_inline_change(inline)
            transition = make_task(state, task["id"])
            task.update({key: value for key, value in transition.items()
                         if key not in {"action", "actor", "preview", "created_at"}})
            if batch:
                task["result"] = {"client": batch["client"], "added_count": len(batch["rules"])} if state == "succeeded" else {}
                self._permission_batches.pop(task["id"], None)
            if inline:
                task["result"] = {"preview_only": True}
                self._inline_changes.pop(task["id"], None)
            return task
        if action == "audit.event":
            return {"recorded": True, "preview_only": True}
        if action == "service.reveal":
            if params.get("resource") == "exit_config":
                item_id = params.get("item_id")
                item = next((item for item in self.data["proxy"]["exits"]
                             if item["id"] == item_id or item_id == "current" and item["default"]), None)
                if item is None:
                    raise ValueError("模拟出口不存在。")
                # Generated only for an explicit reveal; no supplied credentials are
                # stored, and public fixture/task responses never contain this map.
                proxy = ({"type": "vless", "server": item["server"], "port": 443,
                          "uuid": "00000000-0000-4000-8000-000000000001", "tls": True,
                          "servername": "preview-tls.example", "network": "ws",
                          "ws-opts": {"path": "/preview-only", "headers": {"Host": "preview-tls.example"}}}
                         if item["id"] == "444444444444" else
                         {"type": "socks5", "server": item["server"], "port": item["port"],
                          "username": "synthetic-preview-user", "password": "synthetic-preview-exit-secret",
                          "udp": False, "tls": True, "skip-cert-verify": False,
                          "interface-name": "preview0", "smux": {"enabled": False}})
                # JSON values are valid YAML scalars/flow collections, so no
                # additional YAML dependency is needed by the preview launcher.
                value = "".join(f"{key}: {json.dumps(value)}\n" for key, value in proxy.items())
                return {"schema_version": 1, "resource": "exit_config", "item_id": item["id"],
                        "name": item["name"], "value": value,
                        "proxy": proxy}
            return {"schema_version": 1, "resource": params.get("resource", ""),
                    "item_id": params.get("item_id", ""), "name": "仅供预览的合成资源",
                    "value": "https://downloads.example/preview-only/resource.yaml",
                    "image_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a9nEAAAAASUVORK5CYII="}
        raise ValueError("动作未登记；不会转发到真实管理代理。")

    def describe(self, service_id: str) -> dict:
        return self.data["descriptions"][service_id]

    def prepare_inline_change(self, action: str, arguments: dict) -> dict | None:
        """Allow-list non-secret synthetic mutations for same-page editor QA."""
        if not isinstance(arguments, dict):
            return None
        change = {"action": action, "title": "预览合成数据变更", "facts": {}}
        if action == "network.node.domains":
            name = arguments.get("name")
            if not any(node["name"] == name for node in self.data["network"]["nodes"]):
                raise ValueError("模拟节点不存在。")
            domains = arguments.get("domains", [])
            if not isinstance(domains, list) or any(not isinstance(domain, str) for domain in domains):
                raise ValueError("模拟域名格式无效。")
            return {**change, "name": name, "domains": domains[:32], "title": "更新节点域名映射",
                    "facts": {"节点": name, "域名": ", ".join(domains) or "清空"}}
        if action == "network.address.domains":
            import ipaddress
            address = str(ipaddress.ip_address(arguments.get("address", "")))
            domains = arguments.get("domains", [])
            if not isinstance(domains, list) or any(not isinstance(domain, str) for domain in domains):
                raise ValueError("模拟域名格式无效。")
            return {**change, "address": address, "domains": domains[:32], "title": "更新自定义 IP 映射",
                    "facts": {"地址": address, "域名": ", ".join(domains) or "删除"}}
        if action == "network.permission.change" and arguments.get("operation") == "deny":
            client, target, network = (arguments.get(key) for key in ("client", "target", "network"))
            subject = next((node for node in self.data["network"]["nodes"] if node["name"] == client), None)
            ports = parse_ports(arguments["ports"]) if network != "all" else []
            if not subject or not any(rule["target"] == target and rule["network"] == network and rule["ports"] == ports for rule in subject["permissions"]):
                raise ValueError("模拟权限不存在。")
            if subject["protected"] and target == "all":
                raise ValueError("本地预览保留受保护管理入口。")
            return {**change, "action": "network.permission.deny", "client": client, "target": target,
                    "network": network, "ports": ports, "title": "删除单条访问权限",
                    "facts": {"来源节点": client, "目标": target, "协议": network, "端口": format_ports(ports) or "全部端口"}}
        if action != "network.proxy.update":
            return None
        operation = arguments.get("operation")
        if operation == "node_exits_set":
            name, ids = arguments.get("awg_name"), arguments.get("exit_ids", [])
            known = {item["id"]: item["name"] for item in self.data["proxy"]["exits"]}
            if not isinstance(ids, list) or any(value not in known for value in ids):
                raise ValueError("模拟出口不存在。")
            if not any(node["name"] == name for node in self.data["network"]["nodes"]):
                raise ValueError("模拟节点不存在。")
            return {**change, "operation": operation, "name": name, "exit_ids": ids,
                    "title": "更新节点出口选择", "facts": {"节点": name, "出口": ", ".join(known[value] for value in ids) or "VPS MID"}}
        if operation not in {"airport_add", "airport_update", "airport_delete", "exit_add", "exit_update", "exit_delete", "exit_set_default"}:
            return None
        airport = operation.startswith("airport_")
        kind = "airport" if airport else "exit"
        items = self.data["proxy"]["airports" if airport else "exits"]
        item_id = arguments.get(kind + "_id") or uuid.uuid4().hex[:12]
        item = next((item for item in items if item["id"] == item_id), None)
        if operation not in {"airport_add", "exit_add"} and item is None:
            raise ValueError("模拟代理资源不存在。")
        name = arguments.get(kind + "_name") or (item["name"] if item else "preview-resource")
        # Never retain airport_url, YAML, proxy credentials, passwords or arbitrary fields.
        change.update(operation=operation, item_id=item_id, name=name,
                      title="更新模拟代理资源", facts={"资源": name, "操作": operation})
        if airport:
            known = {item["id"] for item in self.data["proxy"]["country_options"]}
            countries = arguments.get("countries", [])
            if not isinstance(countries, list) or any(value not in known for value in countries):
                raise ValueError("模拟地区无效。")
            change.update(countries=countries, enabled=bool(arguments.get("airport_enabled")))
        else:
            change["default"] = bool(arguments.get("exit_default"))
        return change

    def apply_inline_change(self, change: dict) -> None:
        """Apply only to fixture dictionaries. No files, commands or network I/O."""
        action = change["action"]
        network = self.data["network"]
        if action == "network.node.domains":
            next(node for node in network["nodes"] if node["name"] == change["name"])["domains"] = list(change["domains"])
        elif action == "network.address.domains":
            network["host_records"] = [item for item in network["host_records"] if item["address"] != change["address"]]
            if change["domains"]:
                network["host_records"].append({"address": change["address"], "domains": list(change["domains"])})
        elif action == "network.permission.deny":
            node = next(node for node in network["nodes"] if node["name"] == change["client"])
            node["permissions"] = [rule for rule in node["permissions"] if not all(rule[key] == change[key] for key in ("target", "network", "ports"))]
        elif change.get("operation") == "node_exits_set":
            node = next(node for node in network["nodes"] if node["name"] == change["name"])
            node["exit_ids"] = list(change["exit_ids"])
            node["exit_names"] = [item["name"] for item in self.data["proxy"]["exits"] if item["id"] in change["exit_ids"]]
        else:
            proxy = self.data["proxy"]
            airport = change["operation"].startswith("airport_")
            key = "airports" if airport else "exits"
            item = next((item for item in proxy[key] if item["id"] == change["item_id"]), None)
            if change["operation"].endswith("_delete"):
                proxy[key] = [item for item in proxy[key] if item["id"] != change["item_id"]]
            else:
                if item is None:
                    item = {"id": change["item_id"], "host": "preview-airport.example"} if airport else {
                        "id": change["item_id"], "server": "preview-exit.example", "type": "socks5", "port": 1080, "default": False}
                    proxy[key].append(item)
                item["name"] = change["name"]
                if airport:
                    labels = {item["id"]: item["label"] for item in proxy["country_options"]}
                    item.update(enabled=change["enabled"], countries=list(change["countries"]),
                                country_labels=[labels[value] for value in change["countries"]])
                elif change["default"] or change["operation"] == "exit_set_default":
                    for option in proxy["exits"]:
                        option["default"] = option["id"] == item["id"]
            proxy.update(airport_count=len(proxy["airports"]), active_airport_count=sum(item["enabled"] for item in proxy["airports"]), exit_count=len(proxy["exits"]))
            network["exit_options"] = copy.deepcopy(proxy["exits"])

    def prepare_permission_batch(self, arguments: dict | None) -> dict:
        """Validate synthetic permissions without invoking any production manager."""
        if not isinstance(arguments, dict):
            raise ValueError("批量权限参数无效。")
        client, rules = arguments.get("client"), arguments.get("rules")
        nodes = self.data["network"]["nodes"]
        subject = next((node for node in nodes if node["name"] == client), None)
        if subject is None or subject["state"] != "已启用":
            raise ValueError("只有已启用节点可以添加权限。")
        if not isinstance(rules, list) or not 1 <= len(rules) <= 20:
            raise ValueError("请添加 1–20 条规则。")
        targets = {item["name"]: item["label"] for item in self.data["network"]["targets"]}
        node_ips = {node["name"]: node["address"] for node in nodes}
        node_ips.update(vps="10.20.0.1", all="")
        seen = {(item["target"], item["network"], tuple(item["ports"])) for item in subject["permissions"]}
        prepared = []
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError("批量权限规则无效。")
            target, network, spec = rule.get("target"), rule.get("network"), rule.get("ports", "")
            if not isinstance(target, str) or target not in targets or target == client:
                raise ValueError("访问目标不存在或不能选择节点自身。")
            if not isinstance(network, str) or network not in {"all", "tcp", "udp"} or not isinstance(spec, str):
                raise ValueError("权限协议或端口无效。")
            if network == "all" and spec:
                raise ValueError("全部协议权限不接受端口列表。")
            ports = [] if network == "all" else parse_ports(spec)
            signature = (target, network, tuple(ports))
            if signature in seen:
                raise ValueError("相同的访问权限已经存在或在草稿中重复。")
            seen.add(signature)
            prepared.append({"target": target, "target_label": "全部节点" if target == "all" else "VPS 本机" if target == "vps" else target,
                             "ip": node_ips.get(target, ""), "network": network,
                             "network_label": "全部协议" if network == "all" else network.upper(),
                             "ports": ports, "ports_label": format_ports(ports, ", ") if ports else "全部端口"})
        return {"client": client, "rules": prepared}


def serve(socket_path: str, agent: PreviewAgent | None = None,
          ready: threading.Event | None = None) -> None:
    """Bind a new socket only; never unlink or replace an existing agent socket."""
    socket_file = Path(socket_path)
    if not socket_file.is_absolute() or socket_file.exists() or socket_file.is_symlink():
        raise ValueError("Preview requires a new absolute socket path")
    agent = agent or PreviewAgent()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(socket_path)
        socket_file.chmod(0o600)
        listener.listen(8)
        if ready:
            ready.set()
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                request = {}
                try:
                    line = connection.makefile("rb").readline(1024 * 1024)
                    request = json.loads(line.decode("utf-8"))
                    result = agent.dispatch(request["action"], request.get("params", {}))
                    response = {"version": 1, "request_id": request["request_id"], "ok": True, "result": result}
                except (KeyError, TypeError, ValueError, OSError):
                    response = {"version": 1, "request_id": request.get("request_id", "invalid-request"),
                                "ok": False, "error": {"code": "preview_unavailable",
                                "message": "本地演示：请求不可用，未访问真实服务器。"}}
                try:
                    connection.sendall(json.dumps(response, ensure_ascii=False).encode() + b"\n")
                except OSError:
                    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket_path")
    parser.add_argument("--scenario", choices=("rich", "empty", "error", "pending"), default="rich")
    args = parser.parse_args()
    serve(args.socket_path, PreviewAgent(args.scenario))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
