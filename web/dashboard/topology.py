"""Project saved node permissions into a credential-free, read-only topology."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from lib.server_kit_port_ranges import format_ports
from lib.server_kit_topology_facts import valid_topology_context


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_STATES = {"已启用": "enabled", "已禁用": "disabled", "等待首次握手": "pending"}
_NOTE = "权限视图不是连通性测试；应答流量不代表允许反向发起连接。节点活动与速率单独采样，近期握手不等于实时连通。"


def _result(status: str, label: str, summary: str, scopes=None, warnings=None) -> dict[str, Any]:
    return {
        "status": status, "label": label, "summary": summary,
        "scopes": list(dict.fromkeys(scopes or [])),
        "warnings": list(dict.fromkeys(warnings or [])),
    }


def _address(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _rules(raw: dict) -> tuple[list[dict], bool]:
    """Ignore unknown fields and refuse to interpret malformed rule fragments."""
    permissions = raw.get("permissions")
    if not isinstance(permissions, list):
        return [], True
    rules, malformed = [], False
    for item in permissions:
        if not isinstance(item, dict):
            malformed = True
            continue
        target, network, ports = item.get("target"), item.get("network"), item.get("ports")
        if (
            not isinstance(target, str) or not _NAME.fullmatch(target)
            or not isinstance(network, str) or network not in {"all", "tcp", "udp"}
            or not isinstance(ports, list)
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
            or (network != "all" and not ports)
            or not isinstance(item.get("ip"), str)
        ):
            malformed = True
            continue
        try:
            address = (
                ipaddress.ip_network(item["ip"], strict=False)
                if target == "all" else ipaddress.ip_address(item["ip"])
            )
        except ValueError:
            malformed = True
            continue
        rules.append({"target": target, "network": network, "ports": ports, "ip": address})
    return rules, malformed


def _scopes(rules: list[dict]) -> list[str]:
    if any(rule["network"] == "all" for rule in rules):
        return ["全部协议 · 全部端口"]
    result = []
    for protocol in ("tcp", "udp"):
        ports = {port for rule in rules if rule["network"] == protocol for port in rule["ports"]}
        if ports:
            result.append(f"{protocol.upper()} · {format_ports(sorted(ports), separator=', ')}")
    return result


def _policy_access(source: dict, target: dict, raw: dict, rules: list[dict], malformed: bool,
                   awg_by_name: dict[str, dict], effective_network=None) -> dict:
    if target["kind"] == "vless":
        return _result("not_applicable", "不适用", "VLESS 是访问入口，没有可供其他节点访问的内网目标地址。")
    if source["kind"] == "hub":
        return _result("unknown", "未检测", "节点授权策略不控制 VPS 发起的访问，实际连通性未检测。")
    if source["kind"] == "awg" and not source["address"]:
        return _result("unknown", "地址未知", "来源节点缺少有效内网地址，无法核实授权范围。")
    mode = raw.get("access_mode")
    if source["kind"] == "awg" and mode == "unrestricted":
        if target["kind"] != "hub" and not target["address"]:
            return _result("unknown", "地址未知", "目标节点缺少有效内网地址，无法核实授权范围。")
        return _result("allowed", "全范围授权", "来源节点未限制访问 VPS 和 AWG 节点。", ["全部协议 · 全部端口"])
    if source["kind"] == "awg" and mode != "restricted":
        return _result("unknown", "配置未知", "来源节点的访问模式无效或未提供。")

    warnings = ["部分权限记录格式无效，无法完整判断授权范围。"] if malformed else []
    matched, uncertain = [], []
    destination_ip = ipaddress.ip_address(target["address"]) if target["address"] else None
    for rule in rules:
        name = rule["target"]
        if source["kind"] == "awg":
            if name == "vps":
                if target["kind"] == "hub":
                    matched.append(rule)
            elif name == "all":
                if destination_ip is None:
                    uncertain.append(rule)
                elif destination_ip in rule["ip"]:
                    matched.append(rule)
            elif name not in awg_by_name:
                warnings.append("存在指向已移除 AWG 节点的权限，该记录不会生成目标授权。")
            elif name == target["name"]:
                if destination_ip is None:
                    uncertain.append(rule)
                else:
                    matched.append(rule)
        else:
            # Xray enforces saved IPs; the display name is not a routing condition.
            if name not in {"vps", "all"}:
                named = awg_by_name.get(name)
                if named is None or named["address"] != str(rule["ip"]):
                    warnings.append("有 VLESS 规则的目标名称与当前节点地址不一致；按保存的 IP 判断。")
            if name == "all":
                # The saved CIDR can be stale. Only use a per-client network
                # proved against its rendered allow/guard/fallback rules.
                if effective_network is None or destination_ip is None:
                    uncertain.append(rule)
                elif destination_ip in effective_network:
                    matched.append(rule)
            elif destination_ip is None:
                uncertain.append(rule)
            elif destination_ip == rule["ip"]:
                matched.append(rule)

    scopes = _scopes(matched)
    if any(rule["network"] == "all" for rule in matched):
        return _result("allowed", "全范围授权", "当前配置允许来源向此目标发起全部协议、全部端口的访问。", scopes, warnings)
    if matched:
        if uncertain:
            warnings.append("另有规则缺少当前地址或网段依据，其他范围尚无法确认。")
        return _result("partial", "部分范围授权", "当前配置允许来源在列出的协议和端口范围内访问目标。", scopes, warnings)
    if uncertain:
        if source["kind"] == "vless" and effective_network is None and any(rule["target"] == "all" for rule in uncertain):
            return _result("unknown", "网段待核实", "VLESS 的全部节点规则使用实际网段；渲染配置缺失或与保存权限不一致，不能以保存的网段确认匹配。", _scopes(uncertain), warnings)
        detail = "中心节点的内网地址未提供" if target["kind"] == "hub" else "目标节点的内网地址无效或未提供"
        return _result("unknown", "范围待核实", f"{detail}，无法核实保存的 IP / 网段规则是否匹配。", _scopes(uncertain), warnings)
    if malformed or (target["kind"] != "hub" and not target["address"]):
        return _result("unknown", "配置待核实", "现有资料不足以完整判断此方向的权限。", warnings=warnings)
    return _result("denied", "未授权", "当前保存的权限配置没有允许此方向发起访问的规则。", warnings=warnings)


def _access(source: dict, target: dict, records: dict[str, tuple], awg_by_name: dict[str, dict]) -> dict:
    raw, rules, malformed, network = records.get(source["id"], ({}, [], False, None))
    result = _policy_access(source, target, raw, rules, malformed, awg_by_name, network)
    if result["status"] == "not_applicable":
        return result
    states = {source["availability"], target["availability"]}
    if "disabled" in states:
        return _result("inactive", "节点已禁用", "来源或目标已禁用；显示的范围仅为保留配置，不能据此发起访问。", result["scopes"], result["warnings"])
    if "pending" in states:
        return _result("unknown", "等待首次握手", "来源或目标仍在等待首次握手；配置范围不代表已经连通。", result["scopes"], result["warnings"])
    if "unknown" in states:
        return _result("unknown", "节点状态未知", "来源或目标状态无效或未提供，暂不能确认授权关系。", result["scopes"], result["warnings"])
    return result


def _relationship(forward: dict, reverse: dict) -> tuple[str, str]:
    first, second = forward["status"], reverse["status"]
    authorized = {"allowed", "partial"}
    if first in authorized and second in authorized:
        return "mutual", "双向全范围授权" if first == second == "allowed" else "双向授权 · 存在范围限制"
    if "inactive" in {first, second}:
        return "unknown", "节点已禁用"
    if "unknown" in {first, second}:
        return "unknown", "部分方向已授权 · 其余待核实" if first in authorized or second in authorized else "授权关系待核实"
    if first in authorized:
        return "outbound", "向此节点全范围授权" if first == "allowed" else "向此节点部分范围授权"
    if second in authorized:
        return "inbound", "来自此节点全范围授权" if second == "allowed" else "来自此节点部分范围授权"
    if first == second == "not_applicable":
        return "not_applicable", "无可访问的目标地址"
    return "denied", "未配置可发起的授权"


def build_topology(overview: object, selected_id: str = "") -> dict[str, Any]:
    """Project all confirmed access links and selected details without probing."""
    overview = overview if isinstance(overview, dict) else {}
    context = overview.get("topology_context")
    context = context if valid_topology_context(context) else {"hub_address": "", "vless_networks": {}}
    hub = {"id": "hub", "name": "VPS", "kind": "hub", "kind_label": "中心节点", "address": context["hub_address"],
           "state": "服务端", "availability": "hub", "protected": False, "online_label": "未检测"}
    nodes, records, warnings = [hub], {}, []
    raw_nodes = overview.get("nodes", [])
    if not isinstance(raw_nodes, list):
        raw_nodes = []
        warnings.append("节点资料格式无效，暂时无法展示节点。")
    for raw in raw_nodes:
        if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str) or raw["kind"] not in {"awg", "vless"}:
            warnings.append("部分节点资料无效，未加入图中。")
            continue
        name, kind = raw.get("name"), raw["kind"]
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            warnings.append("部分节点资料无效，未加入图中。")
            continue
        identifier = f"{kind}:{name}"
        if identifier in records:
            warnings.append("存在重复节点资料，仅展示首条记录。")
            continue
        state = raw.get("state")
        state = state if isinstance(state, str) and state in _STATES else "未知"
        node = {"id": identifier, "name": name, "kind": kind,
                "kind_label": "AmneziaWG" if kind == "awg" else "VLESS",
                "address": _address(raw.get("address")) if kind == "awg" else "",
                "state": state, "availability": _STATES.get(state, "unknown"),
                "protected": kind == "awg" and raw.get("protected") is True, "online_label": "未检测"}
        nodes.append(node)
        rules, malformed = _rules(raw) if not (kind == "awg" and raw.get("access_mode") == "unrestricted") else ([], False)
        network = context["vless_networks"].get(name) if kind == "vless" else None
        records[identifier] = (raw, rules, malformed, ipaddress.ip_network(network) if network else None)
    by_id = {node["id"]: node for node in nodes}
    selected = by_id.get(selected_id) if isinstance(selected_id, str) else None
    selected = selected or next((node for node in nodes[1:] if node["protected"]), None)
    selected = selected or (nodes[1] if len(nodes) > 1 else hub)
    awg_by_name = {node["name"]: node for node in nodes if node["kind"] == "awg"}
    relations = []
    for target in nodes:
        if target["id"] == selected["id"]:
            continue
        forward = _access(selected, target, records, awg_by_name)
        reverse = _access(target, selected, records, awg_by_name)
        relation, label = _relationship(forward, reverse)
        relations.append({"node": target, "forward": forward, "reverse": reverse, "relation": relation, "label": label})
    # Keep the whole graph independent of selection, reusing its detailed checks.
    # Hub-origin, VLESS-target and inactive pairs cannot produce confirmed links.
    selected_access = {}
    for relation in relations:
        target_id = relation["node"]["id"]
        selected_access[selected["id"], target_id] = relation["forward"]
        selected_access[target_id, selected["id"]] = relation["reverse"]
    sources = [node for node in nodes if node["availability"] == "enabled"
               and (node["kind"] == "vless" or node["address"])]
    targets = [node for node in nodes if node["kind"] == "hub"
               or (node["kind"] == "awg" and node["availability"] == "enabled" and node["address"])]
    links = []
    for source in sources:
        for target in targets:
            if source["id"] == target["id"]:
                continue
            access = selected_access.get((source["id"], target["id"]))
            if access is None:
                access = _access(source, target, records, awg_by_name)
            if access["status"] in {"allowed", "partial"}:
                scopes = list(access["scopes"])
                links.append({"source": source["id"], "target": target["id"],
                              "status": access["status"], "label": "；".join(scopes), "scopes": scopes})
    if overview.get("pending_access") is True:
        warnings.append("AWG 有待应用的权限变更；本图仍按当前保存的活动配置展示。")
    if overview.get("pending_vless") is True:
        warnings.append("VLESS 有待应用的变更；本图仍按当前保存的活动配置展示。")
    summary = {"nodes": len(nodes) - 1, "awg": 0, "vless": 0, "enabled": 0, "disabled": 0, "pending": 0}
    for node in nodes[1:]:
        summary[node["kind"]] += 1
        if node["availability"] in {"enabled", "disabled", "pending"}:
            summary[node["availability"]] += 1
    return {"nodes": nodes, "selected_id": selected["id"], "selected": selected, "relations": relations, "links": links, "summary": summary,
            "warnings": list(dict.fromkeys(warnings)), "note": _NOTE}
