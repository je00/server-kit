"""Task return links derived from public task facts, never request URLs.

Remember only an allowlisted destination key, not the task payload: this keeps
the source reachable during a later agent outage without retaining secrets.
"""

from collections.abc import Mapping
import re

from django.urls import reverse


_SESSION_KEY = "task_return_destinations"
_MAX_REMEMBERED = 20
_TASK_ID = re.compile(r"task-[a-f0-9]{32}\Z")
_DESTINATIONS = {
    "nodes": ("network-nodes", "内网节点", ""),
    "proxy": ("network-proxy-resources", "代理资源", ""),
    "domains": ("network-subscriptions", "域名管理", "#host-records"),
    "endpoint": ("network-subscriptions", "域名管理", "#public-endpoint"),
    "ddns": ("network-subscriptions", "域名管理", "#dynamic-dns"),
    "files": ("file-resources", "文件资源", ""),
    "backups": ("backups", "备份", ""),
    "deploy": ("deployment-wizard", "部署向导", ""),
    "security": ("security-transactions", "安全事务", ""),
    "dashboard": ("dashboard", "服务总览", ""),
}
_SERVICE_LABELS = {
    "AmneziaWG": "amneziawg", "管理网站": "management",
    "Xray / VLESS": "vless", "公网 VLESS REALITY": "vless",
    "Clash 订阅": "clash", "普通文件": "file", "普通文件服务": "file",
    "Mosh 终端": "mosh", "证书续期": "cert-renew",
    "主机防火墙": "firewall", "系统 SSH": "ssh",
}
_SERVICE_IDS = frozenset(_SERVICE_LABELS.values())
_MANAGED_PORT_TITLES = {
    "修改Clash 订阅端口": "clash",
    "修改普通文件端口": "file",
    "修改AWG 备用入口 1": "amneziawg",
    "修改AWG 备用入口 2": "amneziawg",
}


def _mapping(value):
    return value if isinstance(value, Mapping) else {}


def _destination_key(task):
    task = _mapping(task)
    action = task.get("action")
    if not isinstance(action, str):
        return ""
    preview = _mapping(task.get("preview"))
    facts = _mapping(preview.get("facts"))
    result = _mapping(task.get("result"))
    if action in {"network.node.domains", "network.address.domains"}:
        return "domains"
    if action.startswith("network.public_endpoint."):
        return "endpoint"
    if action.startswith("network.duckdns."):
        return "ddns"
    if action == "network.proxy.update":
        # Node exit selection shares the proxy action, but its controls live on
        # the node page. No parsing of user-supplied names or summaries needed.
        return "nodes" if "订阅节点" in facts or result.get("operation") == "node_exits_set" else "proxy"
    if action.startswith(("network.node.", "network.permission.", "network.subscription.", "network.subscriptions.")):
        return "nodes"
    if action.startswith("deployment."):
        return "deploy"
    if action.startswith("file."):
        return "files"
    if action.startswith("backup."):
        return "backups"
    if action.startswith("security."):
        return "security"
    if action.startswith("firewall.port."):
        return "service:firewall"
    if action.startswith("ssh.key."):
        return "service:ssh"
    if action == "managed.port.change":
        plan = _mapping(result.get("plan"))
        service_id = plan.get("service_id")
        if not isinstance(service_id, str) or service_id not in _SERVICE_IDS:
            title = preview.get("title")
            service_id = _MANAGED_PORT_TITLES.get(title, "") if isinstance(title, str) else ""
        return f"service:{service_id}:ports" if service_id else "dashboard"
    if action in {"service.start", "service.stop", "service.restart"}:
        service_id = _mapping(result.get("service")).get("id") or result.get("service_id")
        if not isinstance(service_id, str) or service_id not in _SERVICE_IDS:
            label = facts.get("服务")
            service_id = _SERVICE_LABELS.get(label, "") if isinstance(label, str) else ""
        return f"service:{service_id}" if service_id else "dashboard"
    return ""


def _destination(key):
    if not isinstance(key, str):
        return None
    if key in _DESTINATIONS:
        route, label, fragment = _DESTINATIONS[key]
        return {"url": reverse(route) + fragment, "label": label}
    parts = key.split(":")
    if len(parts) in {2, 3} and parts[0] == "service" and parts[1] in _SERVICE_IDS:
        if len(parts) == 3 and parts[2] != "ports":
            return None
        fragment = "#managed-ports" if len(parts) == 3 else ""
        return {"url": reverse("service-detail", kwargs={"service_id": parts[1]}) + fragment, "label": "服务详情"}
    return None


def task_navigation_context(task, session, task_id):
    """Return template context; retain at most 20 non-sensitive destination keys.

    Pass ``task=None`` only when the agent cannot return the task. An unknown
    action or a never-seen task gets the existing audit fallback, not a guessed
    destination. Repeated read-only polling does not rewrite the session.
    """
    previous = _mapping(session.get(_SESSION_KEY))
    if task is None:
        return {"task_origin": _destination(previous.get(task_id))}
    key = _destination_key(task)
    destination = _destination(key)
    if destination and isinstance(task_id, str) and _TASK_ID.fullmatch(task_id):
        if previous.get(task_id) != key:
            remembered = {
                identifier: value for identifier, value in previous.items()
                if isinstance(identifier, str) and _TASK_ID.fullmatch(identifier)
                and _destination(value)
            }
            remembered[task_id] = key
            session[_SESSION_KEY] = dict(list(remembered.items())[-_MAX_REMEMBERED:])
    return {"task_origin": destination}
