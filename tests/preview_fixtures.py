"""Synthetic visual-review data; never reads host configuration or credentials."""

from __future__ import annotations

from datetime import datetime, timezone


LONG_NAME = "office-workstation-development-team-01"
SERVICE_IDS = ("amneziawg", "management", "vless", "clash", "file", "mosh", "ssh", "firewall")
TASK_STATES = ("waiting_confirmation", "queued", "running", "succeeded", "failed", "cancelled", "waiting_rollback_confirmation", "rolled_back")
TASK_IDS = {state: "task-" + format(index, "032x") for index, state in enumerate(TASK_STATES, 1)}


def make_task(state: str, task_id: str | None = None) -> dict:
    labels = {"waiting_confirmation": "待确认", "queued": "排队中", "running": "执行中",
              "succeeded": "成功", "failed": "失败", "cancelled": "已取消",
              "waiting_rollback_confirmation": "等待回滚确认", "rolled_back": "已回滚"}
    task = {
        "id": task_id or TASK_IDS[state], "action": "network.permission.allow", "actor": "preview",
        "state": state, "state_label": labels[state],
        "terminal": state in {"succeeded", "failed", "cancelled", "rolled_back"},
        "preview": {"title": "为开发工作站新增内网访问权限", "summary": "这是一项仅在本地内存中模拟的变更，不会修改任何真实节点或服务。",
                    "facts": {"受限节点": LONG_NAME, "目标": "nas-storage-primary", "端口": "22,443,8000-8010", "协议": "TCP", "连接保护": "现有管理入口保持不变"},
                    "stages": ["核验当前权限", "校验候选配置", "应用并验证"]},
        "progress": {"message": "正在校验候选配置…" if state == "running" else labels[state]},
        "created_at": "2026-09-24T09:41:05.000Z", "result": {},
        "transitions": [{"to_state": "waiting_confirmation", "message": "已生成影响预览", "occurred_at": "2026-09-24T09:41:05.000Z"}],
    }
    if state == "failed":
        task["error"] = {"code": "preview_validation_failed", "message": "模拟校验失败：目标节点已离线。原访问策略已保留，可检查节点连接后重试。"}
    if state == "succeeded":
        task["result"] = {"client": LONG_NAME, "target": "nas-storage-primary", "operation": "allow"}
    if state == "waiting_rollback_confirmation":
        task["action"] = "network.public_endpoint.apply"
        task["result"] = {"remaining_seconds": 240}
    return task


def build_fixtures(scenario: str = "rich") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    labels = ("AmneziaWG", "管理网站", "Xray / VLESS", "Clash 订阅", "文件分享", "Mosh 终端", "系统 SSH", "主机防火墙")
    services = [{"id": key, "label": label, "state": "已停止" if key == "file" else "运行中", "autostart": "按需" if key == "mosh" else "自启",
                 "detail": "仅公钥认证 · 内网管理入口受保护" if key == "ssh" else "配置与实际状态一致",
                 "ports": [{"protocol": "tcp", "port": "9080" if key == "management" else "443", "scope": "AWG 内网" if key == "management" else "公网", "state": "监听中"}]}
                for key, label in zip(SERVICE_IDS, labels)]
    snapshot = {"schema_version": 1, "summary": {"running": 7, "stopped": 1, "failed": 0, "missing": 0}, "services": services,
                "resources": {"cpu": {"cores": 4, "load_1": 0.82, "load_5": 0.46, "load_15": 0.38},
                              "memory": {"total_bytes": 4 * 1024**3, "used_bytes": 1879048192, "usage_percent": 43.75},
                              "disk": {"total_bytes": 80 * 1024**3, "used_bytes": 23 * 1024**3, "usage_percent": 28.75}, "uptime_seconds": 3841532}}
    exits = [{"id": "333333333333", "name": "dedicated-us-primary", "default": True, "type": "socks5", "server": "us-egress.example", "port": 1080},
             {"id": "444444444444", "name": "dedicated-eu-failover", "default": False, "type": "vless", "server": "eu-backup-egress-with-a-long-name.example", "port": 443}]
    names = ["home-desktop", LONG_NAME, "nas-storage-primary", "iphone-travel", "retired-laptop"]
    nodes = []
    for index, name in enumerate(names):
        awg = index < 3
        node = {"name": name, "kind": "awg" if awg else "vless", "kind_label": "AmneziaWG" if awg else "VLESS",
                "address": f"10.20.0.{index + 10}" if awg else "—", "state": "已禁用" if index == 4 else "已启用",
                "published": index < 3, "publication_state": "已发布" if index < 3 else "待同步",
                "detail": "普通双向节点" if awg else "单向访问节点 · 2 条内网授权", "protected": index == 0,
                "access_mode": "unrestricted" if index == 0 else "restricted", "custody": "client", "public_key_fingerprint": "0123456789abcdef",
                "domains": ["nas.internal.example", "backup-storage.internal.example"] if index == 2 else [],
                "legacy_stash": False, "clean_mode": False, "exit_ids": [exits[0]["id"]], "exit_names": [exits[0]["name"]],
                "permissions": [{"target": "all", "target_label": "全部节点", "ip": "", "ports": [], "ports_label": "全部端口", "network": "all", "network_label": "全部协议"}] if index == 0 else [
                    {"target": "nas-storage-primary", "target_label": "nas-storage-primary", "ip": "10.20.0.12", "ports": [22, 443, *range(8000, 8011)], "ports_label": "22, 443, 8000-8010", "network": "tcp", "network_label": "TCP"},
                    {"target": "vps", "target_label": "VPS 本机", "ip": "10.20.0.1", "ports": [53], "ports_label": "53", "network": "udp", "network_label": "UDP"}]}
        nodes.append(node)
    network = {"schema_version": 1, "writes_enabled": True, "subscriptions_configured": True, "sync_available": True,
               "pending_vless": False, "pending_access": False, "management_peer": names[0], "management_port": 9080, "exit_options": exits, "nodes": nodes,
               "summary": {"awg_active": 3, "awg_disabled": 0, "vless_active": 1, "vless_disabled": 1, "disabled_total": 1, "published": 3, "stale": 1},
               "host_records": [{"address": "192.168.50.12", "domains": ["git.internal.example", "*.build-cache.internal.example"]},
                                {"address": "2001:db8:100:200::50", "domains": ["ipv6-storage.internal.example"]}],
               "publications": [{"name": n["name"], "kind": n["kind"], "kind_label": n["kind_label"], "state": n["publication_state"], "resource_id": n["name"]} for n in nodes if n["published"]],
               "subscription_items": [{**n, "resource_id": n["name"]} for n in nodes],
               "targets": [{"name": "all", "label": "全部节点"}, {"name": "vps", "label": "VPS 本机"}] + [{"name": n["name"], "label": n["name"] + " · " + n["address"]} for n in nodes[:3]],
               "enrollment_history": [{"name": "new-tablet", "state": "已超时", "completed_at": now}], "pending_enrollments": []}
    countries = [("all", "全部地区"), ("hk", "香港"), ("tw", "台湾"), ("jp", "日本"), ("sg", "新加坡"), ("us", "美国"), ("de", "德国"), ("fr", "法国"), ("kr", "韩国"), ("uk", "英国")]
    proxy = {"schema_version": 2, "revision": "a" * 64, "configured": True, "airport_count": 3, "active_airport_count": 2,
             "airports": [{"id": str(index + 1) * 12, "name": name, "host": host, "enabled": index != 2, "countries": ["hk", "jp", "sg", "us", "de"], "country_labels": ["香港", "日本", "新加坡", "美国", "德国"]}
                          for index, (name, host) in enumerate([("主用机场 · 日常与远程办公", "primary-subscription.example"), ("备用机场 · 亚太与欧美跨地区线路", "subscription-with-a-deliberately-long-hostname.example"), ("归档机场", "archived.example")])],
             "country_options": [{"id": code, "label": label} for code, label in countries], "exits": exits, "exit_count": 2, "exit": {**exits[0], "configured": True}}
    files = {"schema_version": 1, "configured": True, "address": "downloads.example", "port": 8443, "service_state": "运行中",
             "items": [{"resource_id": "file-" + format(i, "016x"), "name": name, "size": size, "cdn_cache": cache, "cache_ttl": 86400}
                       for i, (name, size, cache) in enumerate([("server-kit-client-configuration-guide-2026-09-final-reviewed.zip", 92 * 1024**2, True), ("quickstart.txt", 2048, False), ("offline-installer-linux-arm64.tar.gz", 980 * 1024**2, True)], 1)]}
    firewall_ports = {"schema_version": 1, "firewall_active": True, "items": [
        {"scope": "public", "scope_label": "公网", "protocol": "tcp", "port": 5201, "duration": "temporary", "remaining_seconds": 3450, "active": True, "expires_at": now},
        {"scope": "amneziawg", "scope_label": "AmneziaWG 内网", "protocol": "udp", "port": 5202, "duration": "permanent", "remaining_seconds": 0, "active": True, "expires_at": ""}]}
    ssh_keys = {"schema_version": 1, "items": [{"type": "ssh-ed25519", "fingerprint": "SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghi", "name": name, "key_id": "key-" + str(i) * 64, "deletable": i != 1} for i, name in enumerate(["管理工作站（受保护）", "开发笔记本 - development-team-workstation", "应急恢复密钥"], 1)]}
    managed_ports = {"schema_version": 1, "items": [{"target_id": key, "service_id": key, "label": label, "port": port, "protocol": "udp" if key == "amneziawg" else "tcp", "scope": "public", "scope_label": "公网", "changeable": True} for key, label, port in [("amneziawg", "AWG 入口", 51820), ("clash", "Clash 订阅", 52541), ("file", "文件分享", 8443)]]}
    descriptions = {}
    for service in services:
        key = service["id"]
        descriptions[key] = {"service": service, "allowed_operations": ["start"] if key == "file" else ["stop", "restart"] if key in {"clash", "mosh"} else [],
                             "restriction": "网络入口受保护，修改前需经过独立确认与回滚验证。" if key in {"amneziawg", "management", "vless", "ssh", "firewall"} else "",
                             "inventory": {"schema_version": 1, "service_id": key, "facts": {"运行模式": "已托管", "连接保护": "已开启", "配置核验": "通过"},
                                           "items": [{"name": n["name"], "state": n["state"], "detail": n["detail"], "resource_id": n["name"]} for n in nodes[:3]]},
                             "firewall_ports": firewall_ports, "ssh_keys": ssh_keys, "managed_ports": managed_ports}
    endpoint = {"configured": True, "fqdn": "vpn-gateway-development.example", "current_ipv4": "203.0.113.10", "dns_ipv4s": ["203.0.113.10"], "matches_current_ipv4": True, "dns_ttl_status": "60 秒", "diagnostics": [], "recovery_hint": "开机后会立即上报新的公网地址。"}
    duckdns = {"configured": True, "enabled": True, "provider": "dnspod", "provider_label": "腾讯云 DNSPod", "fqdn": endpoint["fqdn"], "zone": "example", "record": "vpn-gateway-development", "credentials_present": True, "last_result": "ok", "last_update_at": now, "last_ipv4": "203.0.113.10", "dns_ipv4s": ["203.0.113.10"], "timer_state": "enabled", "diagnostics": []}
    titles = {"ssh_auth": "SSH 仅公钥认证", "ssh_listener": "SSH 公网 / 内网监听", "firewall": "主机防火墙", "vless_listener": "VLESS 公网监听迁移"}
    transactions = {key: {"schema_version": 1, "transaction_type": key, "title": title, "state": "idle", "expires_at": "", "remaining_seconds": 0, "writes_enabled": True, "ready": True, "blockers": [], "rollback_seconds": 300, "independent_session": True, "changes": [{"label": "公网监听", "current": "原配置", "target": "候选配置", "changed": True}], "verifications": ["新建公网 SSH 连接", "新建 AWG 内网 SSH 连接"]} for key, title in titles.items()}
    backups = {"schema_version": 1, "items": [{"backup_id": "backup-20260924T094100Z-1234abcd", "format_version": 2, "created_at": now, "host": "preview-host", "cipher": "AES-256-GCM", "categories": ["amneziawg", "management", "server-kit", "firewall"], "file_count": 24, "size": 327680, "download_name": "backup-20260924T094100Z-1234abcd.skb", "key_custody_version": 2, "client_private_keys": "excluded", "restore_allowed": True, "assurance_state": "cleanup_ready"}]}
    restore = {"schema_version": 1, "state": "idle", "backup_id": "", "expires_at": "", "remaining_seconds": 0, "rollback_seconds": 300, "changed_count": 0, "categories": [], "verifications": [], "writes_enabled": True, "last_outcome": ""}
    endpoint_transaction = {"state": "idle", "remaining_seconds": 0, "rollback_seconds": 300, "independent_session": True, "last_outcome": ""}
    if scenario == "pending":
        network.update(pending_access=True, pending_vless=True)
        transactions["firewall"].update(state="pending", remaining_seconds=240)
        endpoint_transaction.update(state="pending", remaining_seconds=240)
        restore.update(state="pending", remaining_seconds=240, backup_id=backups["items"][0]["backup_id"], changed_count=3, categories=["server-kit"], verifications=["请使用另一条连接核验内网"])
    result = {"overview": snapshot, "network": network, "proxy": proxy, "file": files, "descriptions": descriptions,
              "endpoint": endpoint, "endpoint_transaction": endpoint_transaction, "duckdns": duckdns,
              "firewall_ports": firewall_ports, "ssh_keys": ssh_keys, "managed_ports": managed_ports,
              "transactions": transactions, "backups": backups, "restore": restore,
              "enrollment": {"schema_version": 1, "suggested_address": "10.20.0.20/32", "server_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "endpoint": "vpn-gateway-development.example:51820", "address": "10.20.0.20/32", "allowed_ips": "10.20.0.0/24", "dns": "10.20.0.1", "mtu": 1280},
              "tasks": {TASK_IDS[state]: make_task(state) for state in TASK_STATES},
              "audit": {"chain_valid": True, "items": [{"operation": "network.permission.allow", "timestamp": now, "actor": "preview", "service_id": "network", "outcome": outcome} for outcome in ("success", "timeout", "failed")]}}
    if scenario == "empty":
        for key in ("nodes", "publications", "subscription_items", "host_records", "enrollment_history"):
            network[key] = []
        network["summary"] = {key: 0 for key in network["summary"]}
        proxy.update(airports=[], exits=[], airport_count=0, active_airport_count=0, exit_count=0, configured=False)
        for group in (files, backups, firewall_ports, ssh_keys, result["audit"]):
            group["items"] = []
        result["tasks"] = {}
        endpoint.update(configured=False, fqdn="", dns_ipv4s=[], matches_current_ipv4=None)
        duckdns.update(configured=False, enabled=False, credentials_present=False, fqdn="", provider_label="未配置")
        for description in descriptions.values():
            description["inventory"]["items"] = []
    return result
