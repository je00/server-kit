"""验证只读页面的认证和管理代理隔离。"""

from __future__ import annotations

import re
import io
import json
import base64
import copy
import tempfile
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher, make_password
from django.contrib.messages import get_messages
from django.test import TestCase, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from control_plane.client import AgentError


SNAPSHOT = {
    "schema_version": 1,
    "summary": {"running": 1, "stopped": 0, "failed": 0, "missing": 1},
    "services": [
        {
            "id": "amneziawg",
            "label": "AmneziaWG",
            "state": "运行中",
            "autostart": "自启",
            "detail": "1 个普通节点",
            "ports": [],
        }
    ],
}

RESOURCE_SNAPSHOT = {
    **SNAPSHOT,
    "resources": {
        "cpu": {"cores": 4, "load_1": 0.42, "load_5": 0.31, "load_15": 0.2},
        "memory": {
            "total_bytes": 2 * 1024**3,
            "used_bytes": 1024**3,
            "usage_percent": 50.0,
        },
        "disk": {
            "total_bytes": 40 * 1024**3,
            "used_bytes": 10 * 1024**3,
            "usage_percent": 25.0,
        },
        "uptime_seconds": 90061,
    },
}

CLASH_DESCRIPTION = {
    "service": {
        "id": "clash",
        "label": "Clash 订阅",
        "state": "运行中",
        "autostart": "自启",
        "detail": "3 个订阅链接",
        "ports": [
            {"protocol": "tcp", "port": "52541", "scope": "公网", "state": "监听中"}
        ],
    },
    "allowed_operations": ["stop", "restart"],
    "restriction": "",
    "inventory": {
        "schema_version": 1,
        "service_id": "clash",
        "facts": {"订阅数量": "3"},
        "items": [
            {"name": "home-desk", "state": "已发布", "detail": "home.yaml · AWG · 2.0 KiB", "resource_id": "home-desk"}
        ],
    },
}

VLESS_DESCRIPTION = {
    "service": {
        "id": "vless",
        "label": "Xray / VLESS",
        "state": "运行中",
        "autostart": "自启",
        "detail": "1 个受限客户端",
        "ports": [],
    },
    "allowed_operations": [],
    "restriction": "VLESS 是网络入口，变更前必须具备回滚窗口。",
}

FIREWALL_DESCRIPTION = {
    "service": {
        "id": "firewall",
        "label": "主机防火墙",
        "state": "运行中",
        "autostart": "自启",
        "detail": "只读保护项",
        "ports": [],
    },
    "allowed_operations": [],
    "restriction": "基础策略通过防火墙事务管理；自定义端口使用独立确认流程。",
    "inventory": {
        "schema_version": 1,
        "service_id": "firewall",
        "facts": {
            "方案": "nftables 独立 inet 规则表",
            "规则表": "inet server_kit_filter",
            "默认入站": "拒绝",
            "原始查看命令": "nft list table inet server_kit_filter",
        },
        "items": [
            {"name": "公网入口", "state": "443/52541/62222", "detail": "公网 · TCP"},
            {"name": "内网入口", "state": "22/9080", "detail": "AWG 内网 · TCP"},
        ],
    },
}
FIREWALL_PORTS = {
    "schema_version": 1,
    "firewall_active": True,
    "items": [
        {
            "scope": "public", "scope_label": "公网", "protocol": "tcp",
            "port": 5201, "duration": "temporary",
            "expires_at": "2026-08-07T14:00:00+00:00",
            "remaining_seconds": 3500, "active": True,
        },
        {
            "scope": "amneziawg", "scope_label": "AmneziaWG 内网", "protocol": "udp",
            "port": 5202, "duration": "permanent", "expires_at": "",
            "remaining_seconds": 0, "active": True,
        },
    ],
}
FIREWALL_PORT_TASK_PREVIEW = {
    "id": "task-" + "a" * 32, "action": "firewall.port.open",
    "actor": "owner", "state": "waiting_confirmation",
    "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "开放 公网 TCP + UDP 5201",
        "summary": "执行后会同时核验自定义端口事实配置与 nftables 实际集合。",
        "facts": {
            "端口": "5201", "访问范围": "公网", "协议": "TCP + UDP",
            "期限": "永久", "现有占用": "未占用",
            "基础策略或托管服务": "未占用",
        },
    },
}
SSH_DESCRIPTION = {
    "service": {
        "id": "ssh", "label": "系统 SSH", "state": "运行中", "autostart": "受保护",
        "detail": "仅公钥认证", "ports": [],
    },
    "allowed_operations": [],
    "restriction": "监听与认证策略通过 SSH 事务管理；客户端公钥使用独立确认流程。",
    "inventory": {"schema_version": 1, "service_id": "ssh", "facts": {"登录认证": "仅 SSH 公钥"}, "items": []},
}
SSH_KEY_ID = "key-" + "a" * 64
SSH_KEYS = {
    "schema_version": 1,
    "items": [{
        "type": "ssh-ed25519", "fingerprint": "SHA256:test-fingerprint",
        "name": "家庭台式机", "key_id": SSH_KEY_ID, "deletable": True,
    }],
}
SSH_KEY_PREVIEW = {
    "schema_version": 1, "pending_token": "b" * 32, "type": "ssh-ed25519",
    "fingerprint": "SHA256:new-fingerprint", "name": "新笔记本",
    "duplicate": False, "expires_in": 300,
}
SSH_KEY_TASK_PREVIEW = {
    "id": "task-" + "a" * 32,
    "action": "ssh.key.add",
    "actor": "owner",
    "state": "waiting_confirmation",
    "state_label": "待确认",
    "terminal": False,
    "preview": {
        "title": "添加 SSH 客户端",
        "summary": "任务详情只保留密钥类型、指纹和脱敏名称。",
        "facts": {
            "名称": "新笔记本",
            "类型": "ssh-ed25519",
            "指纹": "SHA256:new-fingerprint",
            "重复": "否",
        },
    },
}

CLASH_LINK_RESOURCE = {
    "schema_version": 1,
    "resource": "clash_subscription_link",
    "item_id": "home-desk",
    "name": "home-desk",
    "value": "https://203.0.113.188:52541/secret-token/home.yaml",
}
CLASH_QR_RESOURCE = {"schema_version": 1, "resource": "clash_subscription_qr", "item_id": "home-desk", "name": "home-desk", "image_base64": "iVBORw0KGgo="}

SSH_TRANSACTION = {
    "schema_version": 1, "transaction_type": "ssh_auth", "title": "SSH 仅公钥认证",
    "state": "idle", "expires_at": "", "remaining_seconds": 0,
    "writes_enabled": False, "rollback_seconds": 300,
    "ready": True, "blockers": [],
    "changes": [{"label": "密码登录", "current": "yes", "target": "禁用", "changed": True}],
    "verifications": ["新建公网 SSH 连接", "新建 AWG 内网 SSH 连接"],
    "independent_session": True,
}
SSH_LISTENER_TRANSACTION = {
    **SSH_TRANSACTION,
    "transaction_type": "ssh_listener", "title": "SSH 公网/内网监听",
}
FIREWALL_TRANSACTION = {
    "schema_version": 1, "transaction_type": "firewall", "title": "nftables 主机防火墙",
    "state": "pending", "expires_at": "2026-08-07T12:05:00+00:00", "remaining_seconds": 240,
    "writes_enabled": True, "rollback_seconds": 300,
    "ready": True, "blockers": [],
    "changes": [{"label": "公网 TCP", "current": "443", "target": "443/62222", "changed": True}],
    "verifications": ["公网 SSH", "AWG SSH"],
    "independent_session": True,
}
VLESS_LISTENER_TRANSACTION = {
    **SSH_TRANSACTION,
    "transaction_type": "vless_listener", "title": "VLESS 公网监听迁移",
    "transaction_id": "", "last_outcome": "",
}
BACKUP_LIST = {
    "schema_version": 1,
    "items": [{
        "backup_id": "backup-20260807T120000Z-1234abcd",
        "format_version": 2,
        "created_at": "2026-08-07T12:00:00+00:00", "host": "test",
        "cipher": "AES-256-GCM", "categories": ["amneziawg", "management"],
        "file_count": 8, "size": 4096,
        "download_name": "backup-20260807T120000Z-1234abcd.skb",
        "key_custody_version": 2, "client_private_keys": "excluded",
        "restore_allowed": True, "assurance_state": "cleanup_ready",
    }],
}
IDLE_RESTORE = {
    "schema_version": 1, "state": "idle", "backup_id": "", "expires_at": "",
    "remaining_seconds": 0, "rollback_seconds": 300, "changed_count": 0,
    "categories": [], "verifications": [], "writes_enabled": False,
    "last_outcome": "",
}
WRITABLE_IDLE_RESTORE = dict(IDLE_RESTORE, writes_enabled=True)
RESTORE_PREVIEW = {
    "schema_version": 1,
    "backup": BACKUP_LIST["items"][0],
    "changes": [{"path": "/etc/server-kit/ports.json", "category": "server-kit", "state": "将覆盖（内容不同）"}],
    "changed_count": 1,
    "online_changed_count": 1,
    "offline_changed_count": 0,
    "writes_enabled": False,
}
PENDING_RESTORE = {
    **WRITABLE_IDLE_RESTORE,
    "state": "pending", "backup_id": "backup-20260807T120000Z-1234abcd",
    "expires_at": "2026-08-07T12:05:00+00:00", "remaining_seconds": 240,
    "changed_count": 1, "categories": ["server-kit"],
    "verifications": ["确认 AWG 新连接"],
}
RESTORE_TASK_PREVIEW = {
    "id": "task-" + "a" * 32, "action": "backup.restore_apply", "actor": "owner",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "应用配置备份并启动自动回滚",
        "summary": "恢复由独立 systemd 计时器保护；任务中断不会自动重新应用备份。",
        "facts": {
            "备份标识": "backup-20260807T120000Z-1234abcd",
            "覆盖类别": "server-kit", "变更数量": "3",
            "在线生效": "2", "需离线处理": "1", "自动回滚期限": "300 秒",
        },
    },
}
NETWORK_OVERVIEW = {
    "schema_version": 1, "writes_enabled": True, "subscriptions_configured": True,
    "sync_available": True, "pending_vless": False, "pending_access": False,
    "management_peer": "home-desk", "management_port": 9080,
    "exit_options": [{"id": "333333333333", "name": "默认出口", "default": True}],
    "host_records": [{"address": "192.168.0.103", "domains": ["git.example.com"]}],
    "summary": {"awg_active": 1, "awg_disabled": 0, "vless_active": 1, "vless_disabled": 0, "disabled_total": 0, "published": 1, "stale": 1},
    "nodes": [
        {"name": "home-desk", "kind": "awg", "kind_label": "AmneziaWG", "address": "10.20.0.10", "state": "已启用", "published": True, "publication_state": "已发布", "detail": "普通双向节点 · 虚拟 IP 10.20.0.10", "protected": True, "permissions": [{"target": "all", "target_label": "全部节点", "ip": "", "ports": [], "ports_label": "全部端口", "network": "all", "network_label": "全部协议"}], "access_mode": "unrestricted", "custody": "client", "public_key_fingerprint": "0123456789abcdef", "domains": ["nas.internal.example"], "legacy_stash": False, "clean_mode": False, "exit_ids": ["333333333333"], "exit_names": ["默认出口"]},
        {"name": "iphone", "kind": "vless", "kind_label": "VLESS", "address": "—", "state": "已启用", "published": False, "publication_state": "待同步", "detail": "单向访问节点 · 1 条内网授权", "protected": False, "permissions": [{"target": "home-desk", "target_label": "home-desk", "ip": "10.20.0.10", "ports": [22], "ports_label": "22", "network": "tcp", "network_label": "TCP"}], "access_mode": "restricted", "domains": [], "legacy_stash": False, "clean_mode": False, "exit_ids": ["333333333333"], "exit_names": ["默认出口"]},
    ],
    "publications": [{"name": "home-desk", "kind": "awg", "kind_label": "AmneziaWG", "state": "已发布", "resource_id": "home-desk"}],
    "subscription_items": [
        {"name": "home-desk", "kind": "awg", "kind_label": "AmneziaWG", "state": "已发布", "published": True, "resource_id": "home-desk"},
        {"name": "iphone", "kind": "vless", "kind_label": "VLESS", "state": "待同步", "published": False, "resource_id": "iphone"},
    ],
    "targets": [{"name": "all", "label": "全部节点"}, {"name": "vps", "label": "VPS 本机"}, {"name": "home-desk", "label": "home-desk · 10.20.0.10"}],
}
FILE_RESOURCES = {
    "schema_version": 1, "configured": True, "address": "10.20.0.1", "port": 8443,
    "service_state": "运行中",
    "items": [{
        "resource_id": "file-1234567890abcdef", "name": "large.bin",
        "size": 80 * 1024 * 1024, "cdn_cache": True, "cache_ttl": 86400,
    }],
}
FILE_RESOURCES_STOPPED = {**FILE_RESOURCES, "service_state": "已停止"}
TASK_ID = "task-" + "a" * 32
NETWORK_NODE_TASK_PREVIEW = {
    "id": TASK_ID, "action": "network.node.vless.add", "actor": "owner",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "新增节点 phone",
        "summary": "执行前会重新核验节点、目标、协议、端口和管理入口事实。",
        "facts": {
            "节点": "phone", "类型": "VLESS 单向节点", "操作": "新增",
            "默认授权": "保持现状", "订阅发布": "提交后自动刷新全部订阅",
        },
    },
}
NETWORK_PERMISSION_TASK_PREVIEW = {
    "id": TASK_ID, "action": "network.permission.allow", "actor": "admin",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "新增访问权限",
        "summary": "执行前会重新核验节点、目标、协议、端口和管理入口事实。",
        "facts": {
            "受限节点": "iphone", "目标": "home-desk",
            "协议": "TCP", "端口": "22,443", "订阅发布": "本任务不会自动同步",
        },
    },
}
MANAGED_PORT_TASK_PREVIEW = {
    "id": TASK_ID, "action": "managed.port.change", "actor": "owner",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "修改Clash 订阅端口",
        "summary": "将同步更新端口事实和主机防火墙；会短暂重启该下载服务。",
        "facts": {
            "当前端口": "52541/TCP", "新端口": "52542/TCP",
            "开放范围": "公网", "客户端影响": "订阅链接端口会变化。",
        },
    },
}
SUBSCRIPTION_SYNC_TASK_PREVIEW = {
    "id": TASK_ID, "action": "network.subscriptions.sync", "actor": "owner",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "同步全部发布订阅",
        "summary": "预览只显示订阅名称和发布影响，不包含访问令牌或完整链接。",
        "facts": {
            "受影响订阅": "home-desk、iphone", "保留现有链接": "home-desk",
            "新增或刷新": "iphone", "停用发布": "不变",
        },
    },
}
SUBSCRIPTION_ROTATE_TASK_PREVIEW = {
    "id": TASK_ID, "action": "network.subscription.rotate", "actor": "owner",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "轮换 home-desk 的订阅令牌",
        "summary": "预览只显示订阅名称和发布影响，不包含访问令牌或完整链接。",
        "facts": {
            "受影响订阅": "home-desk", "当前状态": "已发布",
            "旧链接": "成功后立即失效", "其他订阅": "不变",
        },
    },
}
SUBSCRIPTION_STATE_TASK_PREVIEW = {
    "id": TASK_ID, "action": "network.subscription.disable", "actor": "owner",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "停用 home-desk 的订阅发布",
        "summary": "预览只显示订阅名称和发布影响，不包含访问令牌或完整链接。",
        "facts": {
            "受影响订阅": "home-desk", "当前状态": "已发布",
            "目标状态": "停止提供链接", "节点网络状态": "不变",
        },
    },
}
BACKUP_CREATE_TASK_PREVIEW = {
    "id": TASK_ID, "action": "backup.create", "actor": "owner",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {
        "title": "创建加密配置备份",
        "summary": "任务在后台执行；恢复口令只保存在 root 机器密钥加密的短期载荷中。",
        "facts": {
            "现有备份": "1 份", "加密方式": "AES-256-GCM",
            "任务状态与加密载荷": "不纳入备份",
        },
    },
}
BACKUP_VERIFY_TASK_PREVIEW = {
    **BACKUP_CREATE_TASK_PREVIEW,
    "action": "backup.verify",
    "preview": {
        "title": "校验配置备份",
        "summary": "任务在后台执行；恢复口令只保存在 root 机器密钥加密的短期载荷中。",
        "facts": {
            "备份标识": "backup-20260807T120000Z-1234abcd",
            "创建时间": "2026-08-07T12:00:00+00:00",
            "大小": "4096 字节", "加密方式": "AES-256-GCM",
        },
    },
}
BACKUP_DELETE_TASK_PREVIEW = {
    **BACKUP_VERIFY_TASK_PREVIEW,
    "action": "backup.delete",
    "preview": {**BACKUP_VERIFY_TASK_PREVIEW["preview"], "title": "删除配置备份"},
}
SERVICE_TASK_PREVIEW = {
    "id": TASK_ID,
    "action": "service.stop",
    "actor": "owner",
    "state": "waiting_confirmation",
    "state_label": "待确认",
    "terminal": False,
    "preview": {
        "title": "停止 Clash 订阅",
        "summary": "任务将在后台执行；关闭页面不会中断操作。",
        "facts": {"当前状态": "运行中", "目标状态": "已停止", "服务": "Clash 订阅"},
    },
    "progress": {"stage": "waiting_confirmation", "message": "影响预览已生成，等待确认。"},
    "result": {},
    "transitions": [],
}


class DashboardTests(TestCase):
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_superuser(
            "owner", password="test-password-only"
        )
        self.viewer = get_user_model().objects.create_user(
            "viewer", password="test-password-only"
        )
        self.admin = get_user_model().objects.create_user(
            "admin", password="test-password-only", is_staff=True
        )

    def test_management_passwords_use_argon2id(self) -> None:
        encoded = make_password("test-password-only")
        self.assertEqual(identify_hasher(encoded).algorithm, "argon2")

    def test_existing_pbkdf2_password_upgrades_after_verification(self) -> None:
        self.user.password = make_password(
            "test-password-only", hasher="pbkdf2_sha256"
        )
        self.user.save(update_fields=["password"])

        self.assertTrue(self.user.check_password("test-password-only"))
        self.user.refresh_from_db()
        self.assertEqual(identify_hasher(self.user.password).algorithm, "argon2")

    def unlock_sensitive_resources(self) -> None:
        session = self.client.session
        session["sensitive_resource_unlocked_at"] = int(time.time())
        session.save()

    def test_badges_use_real_vertical_centering(self) -> None:
        css_path = Path(__file__).resolve().parents[1] / "static" / "app.css"
        css = css_path.read_text(encoding="utf-8")
        badge_rule = css.split(".stage-badge, .status-pill {", 1)[1].split("}", 1)[0]
        for declaration in (
            "display: inline-flex",
            "align-items: center",
            "justify-content: center",
            "min-height: 2rem",
            "line-height: 1",
        ):
            self.assertIn(declaration, badge_rule)
        card_title_rule = css.split(".card-title {", 1)[1].split("}", 1)[0]
        self.assertIn("align-items: flex-start", card_title_rule)

    def test_dashboard_requires_login(self) -> None:
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, f"{reverse('login')}?next=/")

    @patch("dashboard.views.read_snapshot", return_value={"services": []})
    def test_three_themes_are_available_and_persisted_in_browser(self, _snapshot) -> None:
        login = self.client.get(reverse("login"))
        self.assertContains(login, 'data-theme-value="dark"', count=1)
        self.assertContains(login, 'data-theme-value="light"', count=1)
        self.assertContains(login, 'data-theme-value="sky"', count=1)
        login_html = login.content.decode("utf-8")
        self.assertLess(login_html.index("theme.js"), login_html.index("app.css"))

        self.client.force_login(self.viewer)
        dashboard = self.client.get(reverse("dashboard"))
        self.assertContains(dashboard, "data-theme-picker", count=2)
        self.assertContains(dashboard, 'data-theme-value="dark"', count=2)
        self.assertContains(dashboard, 'data-theme-value="light"', count=2)
        self.assertContains(dashboard, 'data-theme-value="sky"', count=2)

        static_root = Path(__file__).resolve().parents[1] / "static"
        theme_js = (static_root / "theme.js").read_text(encoding="utf-8")
        self.assertIn('server-kit-theme', theme_js)
        self.assertIn('document.documentElement.dataset.theme', theme_js)
        self.assertIn('window.localStorage.setItem', theme_js)
        css = (static_root / "app.css").read_text(encoding="utf-8")
        self.assertIn(':root[data-theme="light"]', css)
        self.assertIn(':root[data-theme="sky"]', css)
        self.assertIn('.mobile-theme-picker', css)

    def test_node_deployment_guide_requires_login(self) -> None:
        response = self.client.get(reverse("node-deployment-guide"))
        self.assertRedirects(
            response,
            f"{reverse('login')}?next={reverse('node-deployment-guide')}",
        )

    @patch("dashboard.views.read_snapshot", return_value={"services": []})
    def test_deployment_wizard_contains_node_guide_without_duplicate_navigation(self, _snapshot) -> None:
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("deployment-wizard"))
        self.assertContains(response, 'class="deployment-tabs"', count=1)
        self.assertContains(response, 'href="/guides/nodes/">节点接入指引</a>', count=1)
        self.assertContains(response, 'class="nav-item active" href="/deploy/" aria-current="page"', count=2)
        html = response.content.decode()
        for container in ('<nav aria-label="主导航">', '<div class="mobile-menu-links">'):
            self.assertRegex(html, re.escape(container) + r'[\s\S]*?<a class="nav-item active" href="/deploy/" aria-current="page">[\s\S]*?<span>部署向导</span>')
        self.assertNotContains(response, '>节点部署指引</a>')
        self.assertNotContains(response, '>指引</a>')
        css = (Path(__file__).resolve().parents[1] / "static" / "app.css").read_text(encoding="utf-8")
        tabs_rule = css.split(".deployment-tabs {", 1)[1].split("}", 1)[0]
        tab_link_rule = css.split(".deployment-tabs a {", 1)[1].split("}", 1)[0]
        self.assertIn("margin: 1.15rem 0 1.35rem", tabs_rule)
        self.assertIn("min-height: 2.8rem", tab_link_rule)
        self.assertIn("font-size: .84rem", tab_link_rule)
        self.assertIn(".deployment-tabs + .wizard-steps { margin-top: 0; }", css)

    def test_node_deployment_guide_uses_compact_cross_platform_flow(self) -> None:
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("node-deployment-guide"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "首次配置")
        self.assertContains(response, "把设备接入内网")
        self.assertContains(response, "节点接入指引")
        self.assertContains(response, reverse("deployment-wizard"))
        self.assertContains(response, 'class="nav-item active" href="/deploy/" aria-current="page"', count=2)
        self.assertContains(response, '<span>部署向导</span>', count=2)
        self.assertContains(response, 'href="/guides/nodes/" aria-current="page">节点接入指引</a>', count=1)
        self.assertNotContains(response, 'href="/guides/nodes/">节点部署指引</a>')
        self.assertContains(response, "需要哪个客户端，就在对应的导入步骤安装")
        self.assertContains(response, "按顺序完成", count=1)
        for label in (">Windows</h2>", ">Linux</h2>", ">Mac</h2>", ">iPhone</h2>", ">Android</h2>"):
            self.assertContains(response, label)
        self.assertContains(response, "FlClash")
        self.assertContains(response, "10.20.0.0/24")
        self.assertContains(response, "Mixed")
        self.assertContains(response, "any:53")
        self.assertContains(response, "VPS 公网 IP")
        self.assertContains(response, "不要排除")
        self.assertContains(response, "设置 → 隧道 → 跳过路由")
        self.assertContains(response, "10.0.0.0/8")
        self.assertContains(response, "下载全平台脚本包", count=4)
        self.assertContains(response, "菜单操作：", count=4)
        self.assertContains(response, "进入菜单后按提示", count=4)
        self.assertContains(response, "双击 windows\\server-kit-ssh.cmd", count=1)
        self.assertContains(response, "sudo bash ./linux/server-kit-node-linux.sh", count=8)
        self.assertContains(response, "sudo zsh ./macos/server-kit-ssh.sh", count=1)
        self.assertContains(response, "自动识别同目录的主/备两份配置", count=1)
        self.assertContains(response, "启用主入口并设置开机自启", count=1)
        self.assertContains(response, "按需安装 Git、Vim、Codex、Claude Code、OpenClaw、Hermes、tmux、Mosh 和 Docker", count=1)
        self.assertContains(response, "输入 yes 后才执行", count=1)
        self.assertContains(response, "将中文用户目录切换为英文", count=1)
        self.assertContains(response, "userdirs-english --yes", count=1)
        self.assertContains(response, "开关自启", count=1)
        self.assertContains(response, "linux/server-kit-node-linux.sh lid-ignore", count=1)
        self.assertContains(response, "linux/server-kit-node-linux.sh lid-default", count=1)
        self.assertContains(response, "Windows 会自动连接吗？", count=1)
        self.assertContains(response, "启动类型应为“自动”", count=1)
        self.assertContains(response, "会保留 5 分钟自动回滚", count=3)
        self.assertContains(response, "只有 SSH 公钥认证能阻止掌握中转 VPS 的人", count=3)
        self.assertContains(response, "查看监听/端口/防火墙/公钥/密码认证", count=3)
        self.assertContains(response, "安全启用仅公钥认证", count=3)
        self.assertContains(response, "SSH 管理（可选）", count=3)
        self.assertContains(response, 'class="guide-step-kind"', count=23)
        self.assertContains(response, 'class="guide-safety-grid"', count=1)
        self.assertContains(response, "不要只用 Ping 判断", count=1)
        self.assertNotContains(response, "不知道选哪种节点")
        self.assertNotContains(response, "进入管理页面，完成后返回")
        self.assertNotContains(response, "官方安装链接")
        self.assertNotContains(response, "以后需要更换 SSH 密钥")
        self.assertNotContains(response, "自动化调用：不打开菜单")
        self.assertNotContains(response, "下载后双击")
        self.assertNotContains(response, "复制启动命令")
        self.assertNotContains(response, "SSH 综合管理菜单")
        self.assertNotContains(response, "登录其他设备")
        self.assertNotContains(response, "允许登录本机")
        self.assertNotContains(response, 'data-sshd-port')
        self.assertNotContains(response, 'data-sshd-enable-command-template')
        self.assertContains(response, reverse("sshd-script-archive-download"), count=4)
        self.assertContains(response, reverse("linux-node-script-download"), count=2)
        self.assertContains(
            response,
            "wget http://testserver"
            + reverse("linux-node-script-download"),
            count=1,
        )
        for platform in ("windows", "macos", "android"):
            self.assertNotContains(response, reverse("sshd-script-download", args=[platform]))
        for platform in ("linux", "macos", "android"):
            self.assertNotContains(response, f'id="cmd-{platform}-sshd-menu"')
        self.assertNotContains(response, "powershell -ExecutionPolicy Bypass -File")
        self.assertContains(response, reverse("network-nodes"))
        self.assertContains(response, reverse("network-subscriptions"))
        self.assertContains(response, 'class="guide-step-apps"', count=8)
        self.assertContains(response, 'class="guide-step-open"', count=10)
        self.assertContains(response, "在新标签打开", count=10)
        self.assertNotContains(response, "guide-downloads")
        self.assertNotContains(response, '<details class="guide-extra" open')
        self.assertNotContains(response, "最终验收清单")
        html = response.content.decode("utf-8")
        manager_links = re.findall(r"<a[^>]*data-guide-manager-link[^>]*>", html)
        self.assertEqual(len(manager_links), 10)
        for link in manager_links:
            self.assertIn('target="_blank"', link)
            self.assertIn('rel="noopener noreferrer"', link)
        self.assertContains(response, "data-guide-return")
        self.assertNotContains(response, "安装两个客户端")
        self.assertNotContains(response, "安装 Stash</strong>")

        for platform in ("windows", "linux", "macos"):
            node_step = html.split(f'id="guide-{platform}-node"', 1)[1].split("</li>", 1)[0]
            subscription_step = html.split(f'id="guide-{platform}-subscription"', 1)[1].split("</li>", 1)[0]
            self.assertIn("AmneziaWG", node_step)
            self.assertIn("#node-create", node_step)
            self.assertIn("Clash Verge", subscription_step)
            self.assertIn("#subscription-list", subscription_step)
        linux_node_step = html.split('id="guide-linux-node"', 1)[1].split("</li>", 1)[0]
        linux_script_url = reverse("linux-node-script-download")
        self.assertIn(linux_script_url, linux_node_step)
        self.assertIn("直接运行 Linux 综合脚本进入菜单", linux_node_step)
        self.assertIn("安装或更新 AWG，并导入双入口配置", linux_node_step)
        self.assertIn("sudo bash ./linux/server-kit-node-linux.sh", linux_node_step)
        self.assertIn("sudo bash ./linux/server-kit-node-linux.sh awg-install ./linux", linux_node_step)
        iphone_node = html.split('id="guide-iphone-node"', 1)[1].split("</li>", 1)[0]
        iphone_subscription = html.split('id="guide-iphone-subscription"', 1)[1].split("</li>", 1)[0]
        android_node = html.split('id="guide-android-node"', 1)[1].split("</li>", 1)[0]
        android_subscription = html.split('id="guide-android-subscription"', 1)[1].split("</li>", 1)[0]
        self.assertNotIn("guide-step-apps", iphone_node)
        self.assertIn("Stash", iphone_subscription)
        self.assertNotIn("guide-step-apps", android_node)
        self.assertIn("FlClash", android_subscription)

        js_path = Path(__file__).resolve().parents[1] / "static" / "app.js"
        js = js_path.read_text(encoding="utf-8")
        self.assertIn("server-kit-guide-return", js)
        self.assertIn("returnStep", js)
        self.assertIn('matchMedia("(max-width: 900px)")', js)
        self.assertNotIn("data-sshd-port", js)
        self.assertNotIn("__SSH_PORT__", js)

        css_path = Path(__file__).resolve().parents[1] / "static" / "app.css"
        css = css_path.read_text(encoding="utf-8")
        shared_action_rule = css.split(
            ".guide-step-apps a, .guide-step-open {", 1
        )[1].split("}", 1)[0]
        for declaration in ("display: inline-flex", "min-height: 2.75rem", "justify-content: center"):
            self.assertIn(declaration, shared_action_rule)
        step_rule = css.split(".guide-steps > li {", 1)[1].split("}", 1)[0]
        self.assertIn("border-top: 1px solid var(--line)", step_rule)
        self.assertNotIn("border-radius", step_rule)
        self.assertNotIn("background:", step_rule)
        self.assertIn(".guide-choice-grid, .guide-safety-grid", css)
        self.assertIn("grid-template-columns: 1fr", css)
        self.assertNotIn(".sshd-", css)

    def test_sshd_manager_downloads_manage_service_firewall_and_status(self) -> None:
        self.client.force_login(self.viewer)
        expected = {
            "windows": ("Start-Service sshd", "HNetCfg.FWRule", "Stop-Service sshd", "Get-ServerKitListeners", "Get-AuthorizedKeyEntries"),
            "linux": ('"$SYSTEMCTL_BIN" restart ssh', "ufw allow", '"$SYSTEMCTL_BIN" disable --now ssh.socket', "ss -H -ltn", "key_entries", "reconcile_network", "OnUnitActiveSec=30s"),
            "macos": ("launchctl bootstrap", "socketfilterfw --add", "launchctl bootout", "launchctl print", "key_entries"),
            "android": ("sshd", "只监听 AWG 地址", "pkill -x sshd", "pgrep -x sshd", "key_entries"),
        }
        for platform, markers in expected.items():
            response = self.client.get(reverse("sshd-script-download", args=[platform]))
            self.assertEqual(response.status_code, 200)
            script = response.content.decode("utf-8")
            if platform == "windows":
                self.assertTrue(response.content.startswith(b"@echo off\r\n"))
                marker = "###SERVER_KIT_POWERSHELL###"
                self.assertEqual(script.count(marker), 1)
                extracted_payload = script.split(marker, 1)[1].lstrip("\r\n")
                self.assertTrue(extracted_payload.startswith("# server-kit Windows SSH 综合管理器"))
                self.assertIn("function ConvertTo-ServerKitSshdConfig", extracted_payload)
                self.assertIn("[regex]::Match($Content, '(?m)^[\\t ]*Match[\\t ]+')", extracted_payload)
                self.assertIn("ConvertTo-ServerKitSshdConfig -Content $content", extracted_payload)
                self.assertIn("$kept = @(", extracted_payload)
                self.assertIn("[string[]]$kept", extracted_payload)
                self.assertIn("SERVER_KIT_CALLER_PROFILE", script)
                self.assertIn("function Get-ManageableAuthorizedAccounts", extracted_payload)
                self.assertIn("function Select-AuthorizedAccount", extracted_payload)
                self.assertIn("标准用户（独立公钥文件）", extracted_payload)
                self.assertIn("管理员（共享公钥文件）", extracted_payload)
                self.assertIn('return Join-Path $account.Profile ".ssh\\authorized_keys"', extracted_payload)
                self.assertNotIn("允许登录当前 Windows 管理员账户的公钥", extracted_payload)
                self.assertNotIn("按回车返回菜单", extracted_payload)
                self.assertIn("function Write-ServerKitMenu", extracted_payload)
                self.assertIn("m / ?  重新显示菜单", extracted_payload)
                self.assertIn("下一步：1–14 操作 · m/? 菜单 · 0 退出", extracted_payload)
                self.assertIn('$choice = Read-Host ">"', extracted_payload)
                self.assertRegex(extracted_payload, r"function Show-ServerKitMenu \{\r?\n\s+Clear-Host\r?\n\s+Write-ServerKitMenu\r?\n\s+while")
                self.assertIn("server-kit-ssh.cmd", response["Content-Disposition"])
            else:
                self.assertIn('ACTION="${1:-menu}"', script)
                self.assertIn("select_authorized_account", script)
                self.assertIn("write_menu", script)
                self.assertIn("show_menu", script)
                self.assertIn("公钥账户：", script)
                expected_range = "1–8" if platform == "android" else "1–14"
                self.assertIn(f"下一步：{expected_range} 操作 · m/? 菜单 · 0 退出", script)
            self.assertIn("10.20.0", script)
            self.assertNotIn("__SSH_PORT__", script)
            self.assertIn("enable", script)
            self.assertIn("disable", script)
            self.assertIn("status", script)
            self.assertIn("keygen", script)
            self.assertIn("id_ed25519", script)
            self.assertNotIn("id_ed25519_server_kit", script)
            self.assertIn("key-list", script)
            self.assertIn("key-add", script)
            self.assertIn("key-remove", script)
            if platform in {"windows", "linux", "macos"}:
                self.assertIn("network-list", script)
                self.assertIn("network-add", script)
                self.assertIn("network-remove", script)
            for marker in markers:
                self.assertIn(marker, script)
            self.assertIn("attachment", response["Content-Disposition"])
            self.assertIn("no-store", response["Cache-Control"])

    def test_sshd_manager_download_requires_login_and_rejects_unknown_platform(self) -> None:
        url = reverse("sshd-script-download", args=["macos"])
        response = self.client.get(url)
        self.assertRedirects(response, f"{reverse('login')}?next={url}")
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(reverse("sshd-script-download", args=["unknown"])).status_code, 404)

    def test_all_platform_script_archive_requires_login_and_contains_every_platform(self) -> None:
        url = reverse("sshd-script-archive-download")
        response = self.client.get(url)
        self.assertRedirects(response, f"{reverse('login')}?next={url}")

        self.client.force_login(self.viewer)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/zip")
        self.assertIn("server-kit-node-scripts.zip", response["Content-Disposition"])
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(set(archive.namelist()), {
                "README.txt",
                "windows/server-kit-ssh.cmd",
                "linux/server-kit-node-linux.sh",
                "macos/server-kit-ssh.sh",
                "android-termux/server-kit-ssh.sh",
            })
        self.assertIn("no-store", response["Cache-Control"])

    def test_linux_node_manager_combines_awg_install_and_ssh(self) -> None:
        self.client.force_login(self.viewer)
        response = self.client.get(reverse("linux-node-script-download"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("server-kit-node-linux.sh", response["Content-Disposition"])
        self.assertIn(b"apt-get install -y amneziawg", response.content)
        self.assertIn(b"network-add", response.content)

    def test_linux_node_manager_direct_link_supports_anonymous_wget(self) -> None:
        url = reverse("linux-node-script-download")
        self.assertTrue(url.endswith("/server-kit-node-linux.sh"))
        response = self.client.get(url, HTTP_USER_AGENT="Wget/1.21.4")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/x-shellscript; charset=utf-8")
        self.assertIn("server-kit-node-linux.sh", response["Content-Disposition"])
        self.assertIn(b"devtools-install", response.content)
        self.assertIn(b"openclaw", response.content)
        self.assertIn(b"hermes", response.content)

        legacy = self.client.get(reverse("linux-node-script-download-legacy"))
        self.assertEqual(legacy.status_code, 200)
        self.assertEqual(legacy.content, response.content)

    @patch("dashboard.views.read_snapshot", return_value=SNAPSHOT)
    def test_authenticated_user_sees_snapshot(self, _reader) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "AmneziaWG")
        self.assertContains(response, "内网管理平面")
        self.assertContains(response, reverse("service-detail", args=["amneziawg"]))

    @patch("dashboard.views.read_snapshot", return_value=RESOURCE_SNAPSHOT)
    def test_dashboard_shows_resources_without_duplicate_service_tab(self, _reader) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "资源占用")
        self.assertContains(response, "1 分钟负载")
        self.assertContains(response, "50%")
        self.assertContains(response, "25%")
        self.assertContains(response, "运行 1 天")
        self.assertNotContains(response, 'href="/#services">托管服务</a>')

    @patch("dashboard.views.network_overview")
    def test_permission_delete_form_uses_compact_range(self, overview) -> None:
        data = copy.deepcopy(NETWORK_OVERVIEW)
        phone = next(node for node in data["nodes"] if node["name"] == "iphone")
        phone["permissions"][0].update({"ports": list(range(1, 65536)), "ports_label": "1-65535"})
        overview.return_value = data
        self.client.force_login(self.admin)
        response = self.client.get(reverse("network-nodes"))
        self.assertContains(response, 'name="ports" value="1-65535"')
        self.assertNotContains(response, 'name="ports" value="1,2,3,4')

    @patch("dashboard.views.duckdns_status", return_value={
        "configured": False, "enabled": False, "fqdn": "", "provider_label": "未配置",
        "credentials_present": False, "dns_ipv4s": [], "timer_state": "disabled",
        "diagnostics": [],
    })
    @patch("dashboard.views.public_endpoint_status", return_value={
        "configured": False, "fqdn": "", "current_ipv4": "203.0.113.10",
        "dns_ipv4s": [], "matches_current_ipv4": None,
        "dns_ttl_status": "未配置", "diagnostics": [], "recovery_hint": "尚未配置稳定入口。",
    })
    @patch("dashboard.views.network_overview", return_value=NETWORK_OVERVIEW)
    def test_network_pages_show_nodes_without_secrets(self, _overview, _endpoint, _ddns) -> None:
        self.client.force_login(self.user)
        nodes = self.client.get(reverse("network-nodes"))
        self.assertContains(nodes, "home-desk")
        self.assertContains(
            nodes,
            f'{reverse("service-detail", args=["amneziawg"])}#managed-ports',
        )
        self.assertContains(nodes, "维护 AWG 备用入口")
        self.assertNotContains(nodes, "配置与二维码已锁定")
        self.assertNotContains(nodes, "客户端持钥")
        self.assertNotContains(nodes, "旧式服务端持钥节点")
        self.assertNotContains(nodes, "验证身份后继续")
        self.assertContains(nodes, "预览新增")
        self.assertContains(nodes, "管理入口")
        self.assertContains(nodes, "全部节点")
        self.assertContains(nodes, "可一次添加多个目标或协议", count=2)
        self.assertNotContains(nodes, "访问模式")
        self.assertNotContains(nodes, "按允许列表限制")
        self.assertContains(nodes, "展开节点即可管理访问权限、出口和订阅")
        self.assertNotContains(nodes, "全局订阅强制解析")
        self.assertNotContains(nodes, "稳定公网入口")
        self.assertNotContains(nodes, "动态 DNS 自动更新")
        self.assertContains(nodes, '<option value="all">全部节点</option>', count=2)
        self.assertContains(nodes, '<option value="all">全部协议与端口</option>', count=2)
        self.assertContains(nodes, 'class="permission-add-panel"', count=2)
        self.assertContains(nodes, "新增访问权限", count=2)
        self.assertContains(nodes, 'placeholder="例如 22,443,8000-8010"', count=2)
        self.assertContains(nodes, "范围含起止端口，可用英文逗号混合。", count=2)
        self.assertContains(nodes, 'name="network" value="tcp"')
        self.assertContains(nodes, 'name="ports" value="22"')
        self.assertContains(nodes, 'class="network-node-card node-config-panel"', count=2)
        self.assertContains(nodes, 'class="node-card-summary"', count=2)
        self.assertContains(nodes, 'class="copy-button node-config-trigger">配置</span>', count=2)
        self.assertContains(nodes, 'class="node-setting-group node-preference-group"', count=2)
        self.assertContains(nodes, 'class="node-config-card node-exit-card"', count=2)
        self.assertContains(nodes, 'class="node-config-card node-permission-card"', count=2)
        self.assertNotContains(nodes, 'class="node-config-card node-exit-card" open')
        self.assertNotContains(nodes, 'class="node-config-card node-permission-card" open')
        self.assertContains(nodes, 'class="node-config-card-summary"', count=4)
        self.assertContains(nodes, 'class="node-config-card-body node-exit-settings"', count=2)
        self.assertContains(nodes, 'class="node-config-card-body node-permission-settings"', count=2)
        self.assertContains(nodes, "节点设置", count=2)
        self.assertContains(nodes, "订阅兼容模式")
        self.assertContains(nodes, "启用旧版兼容")
        self.assertContains(nodes, 'value="compat-enable"')
        self.assertContains(nodes, "订阅纯净模式", count=2)
        self.assertContains(nodes, "启用纯净模式", count=2)
        self.assertContains(nodes, 'value="clean-enable"', count=2)
        self.assertContains(nodes, "node-mode-settings", count=5)
        self.assertContains(nodes, "node-publication-settings", count=2)
        self.assertContains(nodes, "node-mode-action", count=3)
        self.assertContains(nodes, "node-exit-settings", count=2)
        self.assertContains(nodes, "node-exit-form", count=2)
        self.assertContains(nodes, "可选中转出口")
        self.assertContains(nodes, "默认使用 VPS MID", count=2)
        self.assertContains(nodes, "额外代理出口（可不选）", count=2)
        self.assertContains(nodes, "不重启 Xray")
        self.assertNotContains(nodes, "第一组")
        self.assertNotContains(nodes, "第二组")
        self.assertContains(nodes, 'class="permission-row first-permission-row"')
        self.assertContains(nodes, 'id="node-create" class="node-create-panel"', count=1)
        self.assertNotContains(nodes, 'id="node-create" class="node-create-panel" open')
        html = nodes.content.decode("utf-8")
        self.assertLess(html.index('id="node-create"'), html.index("<h2>现有节点</h2>"))
        summaries = re.findall(r'<summary class="node-card-summary">(.*?)</summary>', html, re.S)
        self.assertEqual(len(summaries), 2)
        self.assertTrue(all("<form" not in summary for summary in summaries))
        self.assertTrue(all("配置" in summary for summary in summaries))
        marker = '<details class="network-node-card node-config-panel"'
        starts = [match.start() for match in re.finditer(re.escape(marker), html)]
        node_cards = [
            html[start:starts[index + 1] if index + 1 < len(starts) else len(html)]
            for index, start in enumerate(starts)
        ]
        self.assertEqual(len(node_cards), 2)
        self.assertTrue(
            all(
                card.index("订阅纯净模式") < card.index("<strong>订阅链接</strong>")
                for card in node_cards
            )
        )
        self.assertTrue(
            all(
                card.index("<strong>订阅链接</strong>") < card.index("访问权限")
                for card in node_cards
            )
        )
        js = (Path(__file__).resolve().parents[1] / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('payload.code === "sensitive_unlock_required"', js)
        self.assertIn("new FormData(form)", js)
        self.assertIn('window.location.hash === "#node-create"', js)
        css = (Path(__file__).resolve().parents[1] / "static" / "app.css").read_text(encoding="utf-8")
        self.assertIn(".node-create-panel > summary", css)
        self.assertIn(".node-config-body", css)
        self.assertIn(".node-config-card-summary", css)
        self.assertIn(".node-config-card[open] .node-config-card-chevron", css)
        self.assertIn(
            ".node-config-body { display: grid; grid-template-columns: 1fr;",
            css,
        )
        self.assertIn(".permission-add-panel", css)
        self.assertIn(".permission-form { display: grid;", css)
        self.assertNotIn('data-required-checkbox-group', html)
        self.assertIn(".node-exit-form", css)
        self.assertIn(".node-publication-settings > .item-actions { display: flex;", css)
        self.assertIn("flex-wrap: nowrap;", css)
        self.assertIn(".node-setting-group { min-width: 0; padding: 0; border: 0;", css)
        self.assertNotIn('请至少选择一个出口', js)
        self.assertContains(nodes, "订阅链接")
        self.assertContains(nodes, "复制链接")
        self.assertContains(nodes, "显示二维码")
        self.assertContains(nodes, "验证身份后获取订阅")
        self.assertContains(nodes, "修复发布差异")
        self.assertContains(nodes, 'data-secret-label="复制订阅链接"')
        self.assertNotContains(nodes, "secret-token")
        self.unlock_sensitive_resources()
        subscriptions = self.client.get(reverse("network-subscriptions"))
        self.assertContains(subscriptions, "域名管理")
        self.assertContains(subscriptions, "稳定公网入口")
        self.assertContains(subscriptions, "动态 DNS 自动更新")
        self.assertContains(subscriptions, "全局订阅强制解析")
        self.assertContains(subscriptions, 'value="nas.internal.example"')
        self.assertContains(subscriptions, "保存全局记录")
        self.assertContains(subscriptions, "请选择服务商")
        self.assertContains(subscriptions, 'data-dynamic-dns-fields="dnspod" hidden disabled')
        self.assertContains(subscriptions, 'data-dynamic-dns-fields="duckdns" hidden disabled')
        self.assertNotContains(subscriptions, "逐节点订阅")
        self.assertNotContains(subscriptions, "复制链接")
        self.assertNotContains(subscriptions, "验证身份后获取订阅")
        self.assertNotContains(subscriptions, "secret-token")

    @patch("dashboard.views.preview_node_exits_task", return_value=NETWORK_NODE_TASK_PREVIEW)
    def test_awg_exit_selection_creates_transactional_preview(self, preview) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-node-exits-preview"), {
            "name": "home-desk", "exit_ids": ["333333333333", "444444444444"],
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "刷新 Xray 中转身份和全部订阅")
        preview.assert_called_once_with(
            "home-desk", ["333333333333", "444444444444"], "owner"
        )

    @patch("dashboard.views.public_endpoint_transaction_status", return_value={
        "state": "idle", "remaining_seconds": 0, "rollback_seconds": 300,
        "independent_session": False, "last_outcome": "confirmed",
    })
    @patch("dashboard.views.public_endpoint_status", return_value={
        "configured": True, "fqdn": "root.example.com",
        "current_ipv4": "192.0.2.116", "dns_ipv4s": ["192.0.2.116"],
        "matches_current_ipv4": True, "dns_ttl_status": "正常",
        "diagnostics": [], "recovery_hint": "入口稳定。",
    })
    @patch("dashboard.views.network_overview", return_value=NETWORK_OVERVIEW)
    def test_stable_public_endpoint_hides_transaction_actions(
        self, _overview, _endpoint, _transaction,
    ) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("network-subscriptions"))
        self.assertContains(response, "已稳定")
        self.assertContains(response, "预览变更入口")
        self.assertContains(response, "预览清除配置")
        self.assertNotContains(response, "确认保留")
        self.assertNotContains(response, "立即恢复原入口")
        self.assertNotContains(response, "5 分钟回滚")

    @patch("dashboard.views.public_endpoint_transaction_status", return_value={
        "state": "pending", "remaining_seconds": 240, "rollback_seconds": 300,
        "independent_session": True, "last_outcome": "",
    })
    @patch("dashboard.views.public_endpoint_status", return_value={
        "configured": True, "fqdn": "new.example.com",
        "current_ipv4": "192.0.2.116", "dns_ipv4s": ["192.0.2.116"],
        "matches_current_ipv4": True, "dns_ttl_status": "正常",
        "diagnostics": [], "recovery_hint": "等待确认。",
    })
    @patch("dashboard.views.network_overview", return_value=NETWORK_OVERVIEW)
    def test_pending_public_endpoint_only_shows_transaction_actions(
        self, _overview, _endpoint, _transaction,
    ) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("network-subscriptions"))
        self.assertContains(response, "等待确认")
        self.assertContains(response, 'data-countdown="240"')
        self.assertContains(response, "独立连接确认保留")
        self.assertContains(response, "立即恢复原入口")
        self.assertNotContains(response, "预览变更入口")
        self.assertNotContains(response, "预览清除配置")

    @patch("dashboard.views.preview_node_exits_task", return_value=NETWORK_NODE_TASK_PREVIEW)
    def test_empty_exit_selection_uses_vps_mid(self, preview) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-node-exits-preview"), {
            "name": "home-desk",
        })
        self.assertEqual(response.status_code, 200)
        preview.assert_called_once_with("home-desk", [], "owner")

    @patch("dashboard.views.network_overview", return_value=NETWORK_OVERVIEW)
    def test_subscription_actions_remain_visible_until_on_demand_unlock(self, _overview) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("network-nodes"))
        self.assertContains(response, "复制链接")
        self.assertContains(response, "显示二维码")
        self.assertContains(response, "验证身份后获取订阅")
        self.assertContains(response, 'data-secret-label="复制订阅链接"')
        self.assertNotContains(response, "订阅链接与二维码已锁定")

    @patch("dashboard.views.duckdns_status", return_value={
        "configured": False, "enabled": False, "fqdn": "", "provider_label": "未配置",
        "credentials_present": False, "dns_ipv4s": [], "timer_state": "disabled",
        "diagnostics": [],
    })
    @patch("dashboard.views.public_endpoint_status", return_value={
        "configured": False, "fqdn": "", "current_ipv4": "203.0.113.10",
        "dns_ipv4s": [], "matches_current_ipv4": None,
        "dns_ttl_status": "未配置", "diagnostics": [], "recovery_hint": "尚未配置稳定入口。",
    })
    @patch("dashboard.views.public_endpoint_transaction_status", return_value={
        "state": "idle", "remaining_seconds": 0, "rollback_seconds": 300,
        "independent_session": False, "last_outcome": "",
    })
    @patch("dashboard.views.enrollment_context", return_value={
        "schema_version": 1, "network": "10.20.0.0/24",
        "suggested_address": "10.20.0.23", "prefix": 24, "mtu": 1280,
        "server_public_key": "A" * 43 + "=", "endpoints": [], "obfuscation": {},
    })
    @patch("dashboard.views.network_overview", return_value=NETWORK_OVERVIEW)
    def test_node_page_embeds_key_generation_without_extension_handoff(
        self, _overview, _context, _transaction, _endpoint, _ddns,
    ) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("network-nodes"))
        self.assertContains(response, "推荐 · 网页内置")
        self.assertContains(response, "生成客户端配置")
        self.assertContains(response, "下载主配置并预览登记")
        self.assertNotContains(response, "高级手动导入")
        self.assertNotContains(response, 'name="public_key"')
        self.assertContains(response, "10.20.0.23")
        self.assertContains(response, 'data-awg-enrollment-token')
        self.assertNotContains(response, 'class="public-endpoint-actions"')
        publication = self.client.get(reverse("network-subscriptions"))
        self.assertContains(publication, 'class="public-endpoint-actions"')
        self.assertContains(publication, 'class="public-endpoint-apply-form"')
        self.assertNotContains(publication, "确认保留")
        self.assertNotContains(response, "复制公开参数")
        self.assertNotContains(response, "浏览器工具栏")
        self.assertNotContains(response, "配对")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_network_node_task", return_value=NETWORK_NODE_TASK_PREVIEW)
    def test_node_change_uses_persisted_task_confirmation(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        preview = self.client.post(reverse("network-node-preview"), {
            "kind": "vless", "operation": "add", "name": "phone", "address": "",
        })
        self.assertContains(preview, "新增节点 phone")
        self.assertContains(preview, "自动刷新全部订阅")
        self.assertContains(preview, "新增节点与订阅发布在同一个任务中完成")
        response = self.client.post(reverse("network-node-execute"), {"task_id": TASK_ID})
        self.assertRedirects(response, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        preview_task.assert_called_once_with("vless", "add", "phone", "", "owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.preview_network_node_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.node.vless.compat-enable",
        "preview": {
            "title": "启用旧版 Stash 兼容节点 iphone",
            "summary": "执行前重新核验。",
            "facts": {"操作": "启用旧版 Stash 兼容"},
        },
    })
    def test_vless_legacy_compatibility_action_is_accepted(self, preview_task) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-node-preview"), {
            "kind": "vless", "operation": "compat-enable",
            "name": "iphone", "address": "",
        })
        self.assertContains(response, "启用旧版 Stash 兼容")
        preview_task.assert_called_once_with(
            "vless", "compat-enable", "iphone", "", "owner",
        )

    @patch("dashboard.views.preview_network_node_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.node.awg.clean-enable",
        "preview": {
            "title": "启用订阅纯净模式节点 home-desk",
            "summary": "执行前重新核验。",
            "facts": {"操作": "启用订阅纯净模式"},
        },
    })
    def test_per_node_clean_mode_action_is_accepted(self, preview_task) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-node-preview"), {
            "kind": "awg", "operation": "clean-enable",
            "name": "home-desk", "address": "",
        })
        self.assertContains(response, "启用订阅纯净模式")
        preview_task.assert_called_once_with(
            "awg", "clean-enable", "home-desk", "", "owner",
        )

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_public_endpoint_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.public_endpoint.apply",
        "preview": {
            "title": "变更稳定公网入口", "summary": "回滚保护",
            "facts": {"自动回滚期限": "300 秒"},
        },
    })
    def test_public_endpoint_uses_session_bound_rollback_tasks(
        self, preview_task, confirm
    ) -> None:
        self.client.force_login(self.user)
        for operation, fqdn in (
            ("apply", "vpn.example.com"), ("confirm", ""), ("rollback", ""),
        ):
            with self.subTest(operation=operation):
                preview_task.reset_mock()
                response = self.client.post(reverse("network-public-endpoint-preview"), {
                    "operation": operation, "fqdn": fqdn,
                })
                self.assertEqual(response.status_code, 200)
                args = preview_task.call_args.args
                self.assertEqual(args[0:2], (operation, fqdn))
                self.assertRegex(args[2], r"^[0-9a-f]{64}$")
                self.assertEqual(args[3], "owner")

        response = self.client.post(
            reverse("network-public-endpoint-execute"), {"task_id": TASK_ID}
        )
        self.assertRedirects(
            response, reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.preview_public_endpoint_task")
    def test_viewer_cannot_create_public_endpoint_task(self, preview_task) -> None:
        self.client.force_login(self.viewer)
        response = self.client.post(reverse("network-public-endpoint-preview"), {
            "operation": "apply", "fqdn": "vpn.example.com",
        })
        self.assertEqual(response.status_code, 403)
        preview_task.assert_not_called()

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_duckdns_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.duckdns.configure",
        "preview": {
            "title": "验证并启用 DuckDNS", "summary": "验证候选凭据",
            "facts": {"Token": "候选 Token 已加密暂存"},
        },
    })
    def test_duckdns_token_uses_encrypted_task_preview(
        self, preview_task, confirm
    ) -> None:
        token = "12345678-1234-1234-1234-123456789abc"
        self.client.force_login(self.user)
        preview = self.client.post(reverse("network-duckdns-preview"), {
            "operation": "configure", "provider": "duckdns", "token": token,
        })
        self.assertEqual(preview.status_code, 200)
        self.assertNotContains(preview, token)
        self.assertContains(preview, "候选 Token 已加密暂存")
        preview_task.assert_called_once_with(
            "configure", "duckdns", "", token, "", "", "", "owner"
        )

        applied = self.client.post(
            reverse("network-duckdns-execute"), {"task_id": TASK_ID}
        )
        self.assertRedirects(
            applied, reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.preview_duckdns_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.duckdns.configure",
        "preview": {
            "title": "验证并启用动态 DNS", "summary": "验证候选凭据",
            "facts": {"凭据": "候选凭据已加密暂存"},
        },
    })
    def test_dnspod_secrets_use_encrypted_task_preview(self, preview_task) -> None:
        secret_id = "AKIDEXAMPLE1234567890123456789012"
        secret_key = "example-secret-key-value-1234567890"
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-duckdns-preview"), {
            "operation": "configure", "provider": "dnspod",
            "fqdn": "gateway-demo.example.com", "zone": "example.com",
            "secret_id": secret_id, "secret_key": secret_key,
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, secret_id)
        self.assertNotContains(response, secret_key)
        preview_task.assert_called_once_with(
            "configure", "dnspod", "gateway-demo.example.com", "", secret_id,
            secret_key, "example.com", "owner"
        )

    @patch("dashboard.views.preview_duckdns_task")
    def test_viewer_cannot_submit_duckdns_token(self, preview_task) -> None:
        self.client.force_login(self.viewer)
        response = self.client.post(reverse("network-duckdns-preview"), {
            "operation": "configure", "provider": "duckdns",
            "token": "12345678-1234-1234-1234-123456789abc",
        })
        self.assertEqual(response.status_code, 403)
        preview_task.assert_not_called()

    @patch("dashboard.views.preview_network_node_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.node.awg.set-management",
        "preview": {
            **NETWORK_NODE_TASK_PREVIEW["preview"],
            "title": "设为管理入口节点 home-laptop2",
            "facts": {
                "原管理入口": "home-desk",
                "新管理入口": "home-laptop2",
            },
        },
    })
    def test_client_held_awg_node_can_preview_management_transfer(self, preview_task) -> None:
        overview = {
            **NETWORK_OVERVIEW,
            "nodes": [
                *NETWORK_OVERVIEW["nodes"],
                {
                    "name": "home-laptop2", "kind": "awg", "kind_label": "AmneziaWG",
                    "address": "10.20.0.3", "state": "已启用", "published": False,
                    "publication_state": "待同步", "detail": "普通双向节点 · 虚拟 IP 10.20.0.3",
                    "protected": False, "custody": "client",
                    "permissions": [], "access_mode": "unrestricted",
                },
            ],
        }
        self.client.force_login(self.user)
        with patch("dashboard.views.network_overview", return_value=overview):
            page = self.client.get(reverse("network-nodes"))
            self.assertContains(page, "设为管理入口")
            html = page.content.decode("utf-8")
            card = html[html.rindex('<details class="network-node-card node-config-panel"'):]
            actions = card.split('<div class="node-actions-inline">', 1)[1].split("</div>", 1)[0]
            self.assertIn("设为管理入口", actions)
            self.assertIn("禁用节点", actions)
            self.assertIn("删除节点", actions)
            response = self.client.post(reverse("network-node-preview"), {
                "kind": "awg", "operation": "set-management",
                "name": "home-laptop2", "address": "",
            })
        self.assertContains(response, "原管理入口")
        self.assertContains(response, "home-laptop2")
        preview_task.assert_called_once_with(
            "awg", "set-management", "home-laptop2", "", "owner"
        )

    @patch("dashboard.views.preview_node_domains_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.node.domains",
        "preview": {
            "title": "更新节点 home-desk 的订阅强制解析",
            "summary": "更新后自动刷新订阅。",
            "facts": {
                "节点": "home-desk", "虚拟 IP": "10.20.0.10",
                "目标强制解析": "nas.internal.example、git.example.com",
                "订阅影响": "自动刷新全部 Clash/Stash 发布文件",
            },
        },
    })
    def test_node_domain_update_uses_task_confirmation(self, preview_domains) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-node-domains-preview"), {
            "name": "home-desk", "domains": "NAS.INTERNAL.EXAMPLE, git.example.com",
        })
        self.assertContains(response, "更新节点 home-desk 的订阅强制解析")
        self.assertContains(response, "自动刷新全部 Clash")
        self.assertContains(response, reverse("network-node-domains-execute"))
        preview_domains.assert_called_once_with(
            "home-desk", ["NAS.INTERNAL.EXAMPLE", "git.example.com"], "owner"
        )

    @patch("dashboard.views.network_overview", return_value=NETWORK_OVERVIEW)
    @patch("dashboard.views.preview_address_domains_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "action": "network.address.domains",
        "preview": {
            "title": "更新 192.168.0.103 的全局强制解析",
            "summary": "更新后自动刷新订阅。",
            "facts": {
                "目标 IP": "192.168.0.103",
                "目标强制解析": "git.example.com",
            },
        },
    })
    def test_arbitrary_ip_domain_mapping_uses_task_confirmation(
        self, preview_domains, _overview,
    ) -> None:
        self.client.force_login(self.user)
        page = self.client.get(reverse("network-subscriptions"))
        self.assertContains(page, "解析到自定义 IP")
        self.assertContains(page, "192.168.0.103")
        self.assertContains(page, "添加自定义解析")
        response = self.client.post(reverse("network-address-domains-preview"), {
            "address": "192.168.0.103",
            "domains": "git.example.com",
        })
        self.assertContains(response, "更新 192.168.0.103 的全局强制解析")
        self.assertContains(response, reverse("network-node-domains-execute"))
        preview_domains.assert_called_once_with(
            "192.168.0.103", ["git.example.com"], "owner"
        )

    def test_handshake_timeout_notice_is_persistently_dismissed_for_account(self) -> None:
        recent_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60),
        )
        overview = {
            **NETWORK_OVERVIEW,
            "enrollment_history": [{
                "name": "old-laptop", "state": "已超时",
                "completed_at": recent_at,
            }],
        }
        self.client.force_login(self.user)
        with patch("dashboard.views.network_overview", return_value=overview):
            page = self.client.get(reverse("network-nodes"))
            self.assertContains(page, "old-laptop 首次握手已超时")
            match = re.search(r'name="notice_id" value="([0-9a-f]{16})"', page.content.decode())
            self.assertIsNotNone(match)
            response = self.client.post(reverse("network-notice-dismiss"), {
                "notice_id": match.group(1),
            })
            self.assertRedirects(response, reverse("network-nodes"), fetch_redirect_response=False)
            hidden = self.client.get(reverse("network-nodes"))
            self.assertNotContains(hidden, "old-laptop 首次握手已超时")
            self.client.logout()
            self.client.force_login(self.user)
            hidden_after_new_session = self.client.get(reverse("network-nodes"))
            self.assertNotContains(hidden_after_new_session, "old-laptop 首次握手已超时")

    def test_stale_handshake_timeout_history_is_not_repeated_as_notice(self) -> None:
        overview = {
            **NETWORK_OVERVIEW,
            "enrollment_history": [{
                "name": "stale-laptop", "state": "已超时",
                "completed_at": "2020-01-01T00:00:00Z",
            }],
        }
        self.client.force_login(self.user)
        with patch("dashboard.views.network_overview", return_value=overview):
            page = self.client.get(reverse("network-nodes"))
        self.assertNotContains(page, "stale-laptop 首次握手已超时")

    def test_expired_session_post_returns_to_source_page_after_login(self) -> None:
        self.client.logout()
        source = reverse("backups")
        response = self.client.post(
            reverse("network-notice-dismiss"),
            {"notice_id": "a" * 16},
            HTTP_REFERER=f"http://testserver{source}",
        )
        self.assertRedirects(
            response,
            f"{reverse('login')}?next=%2Fbackups%2F",
            fetch_redirect_response=False,
        )

    @patch("dashboard.views.preview_network_node_task")
    def test_server_held_awg_add_is_rejected_before_task_creation(self, preview_task) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-node-preview"), {
            "kind": "awg", "operation": "add", "name": "legacy", "address": "10.20.0.20",
        })
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "网页内置生成器或公钥导入", status_code=400)
        preview_task.assert_not_called()

    @patch("dashboard.views.preview_network_node_import_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "preview": {
            **NETWORK_NODE_TASK_PREVIEW["preview"],
            "title": "导入节点 client-held",
            "facts": {
                "节点": "client-held",
                "公钥指纹": "0123456789abcdef",
            },
        },
    })
    def test_client_held_node_import_uses_sensitive_task(self, preview_import) -> None:
        self.client.force_login(self.user)
        public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        preshared_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        response = self.client.post(reverse("network-node-preview"), {
            "kind": "awg", "operation": "import", "name": "client-held",
            "address": "10.20.0.23", "public_key": public_key,
            "preshared_key": preshared_key,
        })
        self.assertContains(response, "导入节点 client-held")
        self.assertNotContains(response, "客户端持钥")
        self.assertNotContains(response, preshared_key)
        preview_import.assert_called_once_with(
            "client-held", "10.20.0.23", public_key, preshared_key, "owner"
        )

    @patch("dashboard.views.preview_network_node_import_task", return_value={
        **NETWORK_NODE_TASK_PREVIEW,
        "preview": {**NETWORK_NODE_TASK_PREVIEW["preview"], "title": "登记节点 laptop"},
    })
    def test_local_generator_registration_can_be_pasted_as_one_value(self, preview_import) -> None:
        self.client.force_login(self.user)
        public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        preshared_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        payload = {
            "format": "server-kit-awg-enrollment-v1", "name": "laptop",
            "address": "10.20.0.24", "public_key": public_key,
            "preshared_key": preshared_key,
        }
        token = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        response = self.client.post(reverse("network-node-preview"), {
            "kind": "awg", "operation": "import", "enrollment_token": token,
        })
        self.assertContains(response, "登记节点 laptop")
        self.assertNotContains(response, preshared_key)
        preview_import.assert_called_once_with(
            "laptop", "10.20.0.24", public_key, preshared_key, "owner"
        )

    @patch("dashboard.views.describe_service", return_value=CLASH_DESCRIPTION)
    def test_service_detail_requires_login_and_shows_real_capabilities(self, _describe) -> None:
        url = reverse("service-detail", args=["clash"])
        response = self.client.get(url)
        self.assertRedirects(response, f"{reverse('login')}?next={url}")

        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertContains(response, "Clash 订阅")
        self.assertContains(response, "TCP 52541")
        self.assertContains(response, "停止")
        self.assertContains(response, "重启")
        self.assertContains(response, "脱敏事实清单")
        self.assertContains(response, "home-desk")
        self.assertContains(response, "复制链接")
        self.assertContains(response, "显示二维码")
        self.assertNotContains(response, "secret-token")

    @patch("dashboard.views.describe_service", return_value={
        **CLASH_DESCRIPTION,
        "managed_ports": {
            "schema_version": 1, "revision": "a" * 64, "occupied": [],
            "items": [{
                "id": "clash", "service_id": "clash", "label": "Clash 订阅端口",
                "protocol": "tcp", "scope": "public", "port": 52541,
                "minimum": 1, "maximum": 65535, "installed": True,
                "active": True, "listening": True, "restart_required": True,
                "impact": "订阅链接端口会变化。",
            }],
        },
    })
    def test_service_detail_shows_managed_port_editor(self, _describe) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("service-detail", args=["clash"]))
        self.assertContains(response, "端口维护")
        self.assertContains(response, "Clash 订阅端口")
        self.assertContains(response, "预览修改")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_managed_port_task", return_value=MANAGED_PORT_TASK_PREVIEW)
    def test_managed_port_change_uses_preview_task(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        preview = self.client.post(reverse("managed-port-preview"), {
            "target_id": "clash", "service_id": "clash", "port": "52542",
        })
        self.assertContains(preview, "修改Clash 订阅端口")
        self.assertContains(preview, "公网或上游网络仍可能封禁新端口")
        preview_task.assert_called_once_with("clash", 52542, "owner")
        result = self.client.post(reverse("managed-port-execute"), {
            "task_id": TASK_ID, "service_id": "clash",
        })
        self.assertRedirects(
            result, reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.describe_service", return_value=VLESS_DESCRIPTION)
    def test_protected_service_explains_why_actions_are_disabled(self, _describe) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("service-detail", args=["vless"]))
        self.assertContains(response, "必须具备回滚窗口")
        self.assertNotContains(response, "确认执行")

    @patch("dashboard.views.firewall_ports", return_value=FIREWALL_PORTS)
    @patch("dashboard.views.describe_service", return_value=FIREWALL_DESCRIPTION)
    def test_firewall_detail_shows_effective_policy(self, _describe, _ports) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("service-detail", args=["firewall"]))
        self.assertContains(response, "nftables 独立 inet 规则表")
        self.assertContains(response, "nft list table inet server_kit_filter")
        self.assertContains(response, "443/52541/62222")
        self.assertContains(response, "22/9080")
        self.assertContains(response, "自定义端口使用独立确认流程")
        self.assertContains(response, "开放临时或永久端口")
        self.assertContains(response, "TCP 5201")
        self.assertContains(response, "剩余 59 分钟")
        self.assertContains(response, "UDP 5202")
        self.assertContains(response, "永久")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_firewall_port_task", return_value=FIREWALL_PORT_TASK_PREVIEW)
    def test_firewall_port_permanent_rule_uses_persisted_task(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        preview = self.client.post(reverse("firewall-port-preview"), {
            "operation": "open", "port": "5201", "scope": "public",
            "protocol": "both", "duration": "permanent",
        })
        self.assertContains(preview, "公网端口")
        self.assertContains(preview, "永久")
        self.assertContains(preview, "nftables")
        response = self.client.post(reverse("firewall-port-execute"), {"task_id": TASK_ID})
        self.assertRedirects(
            response, reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        preview_task.assert_called_once_with("open", 5201, "public", "both", 0, "owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.preview_firewall_port_task")
    def test_firewall_port_rejects_invalid_values_and_viewer(self, preview_task) -> None:
        self.client.force_login(self.user)
        invalid = self.client.post(reverse("firewall-port-preview"), {
            "operation": "open", "port": "5201", "scope": "public",
            "protocol": "tcp", "duration": "forever-ish",
        })
        self.assertEqual(invalid.status_code, 400)
        self.client.force_login(self.viewer)
        denied = self.client.post(reverse("firewall-port-preview"), {
            "operation": "open", "port": "5201", "scope": "public",
            "protocol": "tcp", "duration": "3600",
        })
        self.assertEqual(denied.status_code, 403)
        preview_task.assert_not_called()

    @patch("dashboard.views.ssh_keys", return_value=SSH_KEYS)
    @patch("dashboard.views.describe_service", return_value=SSH_DESCRIPTION)
    def test_ssh_detail_lists_clients_without_public_key_and_offers_actions(self, _describe, _keys) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("service-detail", args=["ssh"]))
        self.assertContains(response, "公钥登录列表")
        self.assertContains(response, "家庭台式机")
        self.assertContains(response, "公钥类型")
        self.assertContains(response, "ssh-ed25519")
        self.assertContains(response, "SHA256:test-fingerprint")
        self.assertContains(response, "校验并添加")
        self.assertContains(response, "修改名字")
        self.assertContains(response, "删除")
        self.assertNotContains(response, "AAAAC3")

    @patch("dashboard.views.preview_ssh_key_change_task", return_value=SSH_KEY_TASK_PREVIEW)
    def test_ssh_key_add_uses_fingerprint_confirmation_without_raw_key(self, preview) -> None:
        self.client.force_login(self.user)
        public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest 原备注"
        response = self.client.post(reverse("ssh-key-preview"), {
            "operation": "add", "name": "新笔记本", "public_key": public_key,
        })
        self.assertContains(response, "SHA256:new-fingerprint")
        self.assertContains(response, "新笔记本")
        self.assertNotContains(response, "AAAAC3Nza")
        preview.assert_called_once_with(
            "add", "", "", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest 新笔记本", "owner"
        )

    @patch("dashboard.views.confirm_change_task")
    def test_ssh_key_add_confirms_persisted_task(self, confirm) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("ssh-key-execute"), {"task_id": TASK_ID})
        self.assertRedirects(
            response,
            reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_ssh_key_change_task", return_value=SSH_KEY_TASK_PREVIEW)
    def test_ssh_key_rename_auto_queues_and_delete_requires_confirmation(
        self, preview, confirm
    ) -> None:
        self.client.force_login(self.user)
        renamed = self.client.post(reverse("ssh-key-preview"), {
            "operation": "rename", "item_id": SSH_KEY_ID, "name": "办公室电脑",
        })
        self.assertRedirects(
            renamed,
            reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")
        deleted = self.client.post(reverse("ssh-key-preview"), {
            "operation": "delete", "item_id": SSH_KEY_ID,
        })
        self.assertContains(deleted, "确认提交任务")

    @patch("dashboard.views.preview_ssh_key_change_task", side_effect=AgentError("最后一把", "operation_forbidden"))
    def test_ssh_key_delete_protects_last_key_and_viewer_is_denied(self, _preview) -> None:
        self.client.force_login(self.user)
        protected = self.client.post(reverse("ssh-key-preview"), {
            "operation": "delete", "item_id": SSH_KEY_ID,
        })
        self.assertRedirects(
            protected, reverse("service-detail", args=["ssh"]),
            fetch_redirect_response=False,
        )
        self.client.force_login(self.viewer)
        denied = self.client.post(reverse("ssh-key-preview"), {
            "operation": "rename", "item_id": SSH_KEY_ID, "name": "越权",
        })
        self.assertEqual(denied.status_code, 403)

    @patch("dashboard.views.reveal_clash_resource", return_value=CLASH_LINK_RESOURCE)
    def test_superuser_can_copy_one_clash_link_without_rendering_it(self, reveal) -> None:
        self.client.force_login(self.user)
        self.unlock_sensitive_resources()
        response = self.client.post(reverse("clash-subscription-copy", args=["home-desk"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["value"], CLASH_LINK_RESOURCE["value"])
        self.assertIn("no-store", response["Cache-Control"])
        reveal.assert_called_once_with("subscription_link", "home-desk", "owner")

    @patch("dashboard.views.reveal_clash_resource", return_value=CLASH_QR_RESOURCE)
    def test_superuser_can_show_square_png_qr_without_link(self, reveal) -> None:
        self.client.force_login(self.user)
        self.unlock_sensitive_resources()
        response = self.client.post(reverse("clash-subscription-qr", args=["home-desk"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["image_base64"], "iVBORw0KGgo=")
        self.assertNotIn("value", response.json())
        self.assertNotIn("url", response.content.decode())
        reveal.assert_called_once_with("subscription_qr", "home-desk", "owner")

    @patch("dashboard.views.reveal_clash_resource")
    def test_viewer_cannot_read_clash_resources(self, reveal) -> None:
        self.client.force_login(self.viewer)
        for name in ("clash-subscription-copy", "clash-subscription-qr"):
            response = self.client.post(reverse(name, args=["home-desk"]))
            self.assertEqual(response.status_code, 403)
        reveal.assert_not_called()

    @patch("dashboard.views.manage_backup")
    def test_backup_page_is_superuser_only_and_never_renders_passphrase(self, manager) -> None:
        manager.side_effect = [BACKUP_LIST, IDLE_RESTORE]
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(reverse("backups")).status_code, 403)
        self.client.force_login(self.user)
        response = self.client.get(reverse("backups"))
        self.assertContains(response, "加密配置备份")
        self.assertContains(response, "下载密文")
        self.assertContains(response, 'class="backup-actions"')
        self.assertContains(response, "AES-256-GCM")
        self.assertContains(response, "可清理旧备份")
        self.assertContains(response, "不包含客户端私钥")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(
            [item.args for item in manager.call_args_list],
            [("list", "owner"), ("restore_status", "owner")],
        )

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_backup_task", return_value=BACKUP_CREATE_TASK_PREVIEW)
    def test_create_backup_encrypts_secret_and_queues_routine_task(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        secret = "测试网页恢复口令-超过十六个字符"
        response = self.client.post(reverse("backups"), {
            "operation": "create", "passphrase": secret,
            "passphrase_confirmation": secret,
        })
        self.assertRedirects(response, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        self.assertNotIn(secret, response.content.decode())
        preview_task.assert_called_once_with("create", "", secret, "owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_backup_task", return_value=BACKUP_DELETE_TASK_PREVIEW)
    def test_delete_backup_requires_root_task_preview_and_superuser(self, preview_task, confirm) -> None:
        backup_id = BACKUP_LIST["items"][0]["backup_id"]
        self.client.force_login(self.viewer)
        denied = self.client.post(
            reverse("backup-delete-preview", args=[backup_id])
        )
        self.assertEqual(denied.status_code, 403)

        self.client.force_login(self.user)
        preview = self.client.post(
            reverse("backup-delete-preview", args=[backup_id])
        )
        self.assertContains(preview, "删除配置备份")
        self.assertContains(preview, backup_id)
        deleted = self.client.post(
            reverse("backup-delete-execute", args=[backup_id]),
            {"task_id": TASK_ID},
        )
        self.assertRedirects(deleted, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        preview_task.assert_called_once_with("delete", backup_id, "", "owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_backup_task", return_value=BACKUP_VERIFY_TASK_PREVIEW)
    def test_verify_backup_queues_routine_task(self, preview_task, confirm) -> None:
        backup_id = BACKUP_LIST["items"][0]["backup_id"]
        secret = "测试网页恢复口令-超过十六个字符"
        self.client.force_login(self.user)
        response = self.client.post(reverse("backups"), {
            "operation": "verify", "backup_id": backup_id, "passphrase": secret,
        })
        self.assertRedirects(response, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        preview_task.assert_called_once_with("verify", backup_id, secret, "owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    def test_encrypted_backup_download_rejects_traversal_and_viewer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup_id = "backup-20260807T120000Z-1234abcd"
            path = Path(directory) / f"{backup_id}.skb"
            path.write_bytes(b"SKBACKUP1-encrypted")
            with override_settings(SERVER_KIT_BACKUP_DIR=Path(directory)):
                self.client.force_login(self.viewer)
                self.assertEqual(self.client.get(reverse("backup-download", args=[backup_id])).status_code, 403)
                self.client.force_login(self.user)
                response = self.client.get(reverse("backup-download", args=[backup_id]))
                self.assertEqual(response.status_code, 200)
                self.assertIn("attachment", response["Content-Disposition"])
                self.assertEqual(b"".join(response.streaming_content), b"SKBACKUP1-encrypted")
                response.close()

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_backup_restore_task", return_value=RESTORE_TASK_PREVIEW)
    @patch("dashboard.views.manage_backup")
    def test_restore_uses_encrypted_durable_task_and_enters_pending_window(
        self, manager, preview_task, confirm
    ) -> None:
        backup_id = BACKUP_LIST["items"][0]["backup_id"]
        secret = "测试恢复事务口令-超过十六个字符-安全"
        manager.side_effect = [BACKUP_LIST, WRITABLE_IDLE_RESTORE]
        self.client.force_login(self.user)
        preview = self.client.post(reverse("backups"), {
            "operation": "preview_restore", "backup_id": backup_id,
            "passphrase": secret,
        })
        self.assertContains(preview, "应用并启动自动回滚")
        self.assertContains(preview, f'value="{TASK_ID}"')
        preview_task.assert_called_once()

        applied = self.client.post(reverse("backups"), {
            "operation": "restore_apply", "task_id": TASK_ID,
        })
        self.assertRedirects(
            applied, reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")

        manager.side_effect = [BACKUP_LIST, PENDING_RESTORE]
        pending = self.client.get(reverse("backups"))
        self.assertContains(pending, "等待新连接验证")
        self.assertContains(pending, "240")

    @patch("dashboard.views.describe_service", return_value=CLASH_DESCRIPTION)
    def test_normal_clash_detail_never_contains_secret_link(self, _describe) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("service-detail", args=["clash"]))
        self.assertNotContains(response, "secret-token")
        self.assertContains(response, "显示二维码")
        self.assertNotContains(response, "https://203.0.113.188:52541")

    @patch("dashboard.views.public_endpoint_status", return_value={
        "current_ipv4": "203.0.113.10", "diagnostics": [],
    })
    @patch("dashboard.views.manage_security_transaction")
    def test_security_page_shows_preview_gate_and_pending_countdown(
        self, manage, _endpoint_status
    ) -> None:
        manage.side_effect = [
            SSH_TRANSACTION, SSH_LISTENER_TRANSACTION, FIREWALL_TRANSACTION,
            VLESS_LISTENER_TRANSACTION,
        ]
        self.client.force_login(self.user)
        response = self.client.get(reverse("security-transactions"))
        self.assertContains(response, "SSH 仅公钥认证")
        self.assertContains(response, "VLESS 公网监听迁移")
        self.assertContains(response, "当前服务器只开放预览")
        self.assertContains(response, 'data-countdown="240"')
        self.assertContains(response, "确认持久化")
        self.assertContains(response, "/security/transactions/vless_listener/preview/")
        self.assertContains(response, "检测到的公网 IPv4")
        self.assertContains(response, 'value="203.0.113.10" readonly')
        self.assertContains(response, 'value="62222" required')
        self.assertNotContains(response, 'name="public_ip"')

    @patch("dashboard.views.preview_security_transaction_task", return_value=SERVICE_TASK_PREVIEW)
    def test_vless_listener_preview_uses_existing_security_flow_without_endpoint_fields(
        self, preview_task
    ) -> None:
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("security-transaction-preview", args=["vless_listener"]),
            {"operation": "preview", "public_ip": "203.0.113.10", "public_port": "443"},
        )
        self.assertEqual(response.status_code, 200)
        preview_task.assert_called_once()
        args = preview_task.call_args.args
        self.assertEqual(args[0:2], ("vless_listener", "apply"))
        self.assertEqual(args[3:5], ("", ""))

    @patch("dashboard.views.preview_security_transaction_task", return_value=SERVICE_TASK_PREVIEW)
    def test_ssh_listener_preview_ignores_browser_public_ip(self, preview_task) -> None:
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("security-transaction-preview", args=["ssh_listener"]),
            {
                "operation": "preview", "public_ip": "198.51.100.99",
                "public_port": "62222",
            },
        )
        self.assertEqual(response.status_code, 200)
        args = preview_task.call_args.args
        self.assertEqual(args[0:2], ("ssh_listener", "apply"))
        self.assertEqual(args[3:5], ("", "62222"))

    @patch(
        "dashboard.views.preview_security_transaction_task",
        side_effect=AgentError("当前主机未启用高风险安全变更", code="operation_forbidden"),
    )
    def test_disabled_high_risk_write_stops_after_preview(self, preview_task) -> None:
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("security-transaction-preview", args=["ssh_auth"]),
            {"operation": "preview"},
        )
        self.assertRedirects(response, reverse("security-transactions"), fetch_redirect_response=False)
        preview_task.assert_called_once()

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_security_transaction_task", return_value=SERVICE_TASK_PREVIEW)
    def test_confirm_uses_durable_task_and_redirects_to_status(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        preview = self.client.post(
            reverse("security-transaction-preview", args=["firewall"]),
            {"operation": "confirm"},
        )
        self.assertContains(preview, "确认并持久化")
        execute = self.client.post(
            reverse("security-transaction-execute", args=["firewall"]),
            {"task_id": TASK_ID},
        )
        self.assertRedirects(
            execute, reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        preview_task.assert_called_once()
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.preview_security_transaction_task")
    def test_viewer_cannot_preview_security_changes(self, preview_task) -> None:
        self.client.force_login(self.viewer)
        response = self.client.post(
            reverse("security-transaction-preview", args=["firewall"]),
            {"operation": "preview"},
        )
        self.assertEqual(response.status_code, 403)
        preview_task.assert_not_called()

    @patch(
        "dashboard.views.describe_service",
        side_effect=AgentError("代理暂时不可用", code="agent_unavailable"),
    )
    @patch(
        "dashboard.views.preview_change_task",
        side_effect=AgentError("代理暂时不可用", code="agent_unavailable"),
    )
    def test_service_pages_hide_agent_errors(self, _preview, _describe) -> None:
        self.client.force_login(self.user)

        response = self.client.get(reverse("service-detail", args=["clash"]))
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "暂时无法读取服务详情", status_code=503)

        response = self.client.post(
            reverse("service-action-preview", args=["clash"]),
            {"operation": "stop"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "暂时无法生成任务预览", status_code=503)

    @patch("dashboard.views.preview_change_task", return_value=SERVICE_TASK_PREVIEW)
    def test_action_preview_requires_superuser_and_uses_root_preview(self, preview) -> None:
        url = reverse("service-action-preview", args=["clash"])
        self.client.force_login(self.viewer)
        response = self.client.post(url, {"operation": "stop"})
        self.assertEqual(response.status_code, 403)

        self.client.force_login(self.user)
        response = self.client.post(url, {"operation": "stop"})
        self.assertContains(response, "确认停止 Clash 订阅")
        self.assertContains(response, "任务将在后台执行")
        self.assertContains(response, "确认执行")
        preview.assert_called_once_with("clash", "stop", "owner")

    @patch("dashboard.views.confirm_change_task")
    def test_confirmed_action_queues_then_redirects_to_task(self, confirm) -> None:
        confirm.return_value = {**SERVICE_TASK_PREVIEW, "state": "queued", "state_label": "排队中"}
        self.client.force_login(self.user)
        url = reverse("service-action-execute", args=["clash"])

        response = self.client.post(
            url,
            {"task_id": TASK_ID},
        )

        self.assertRedirects(
            response,
            reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.confirm_change_task")
    def test_execute_rejects_invalid_task_and_non_superuser(self, confirm) -> None:
        url = reverse("service-action-execute", args=["clash"])
        self.client.force_login(self.user)
        response = self.client.post(url, {"task_id": "错误标识"})
        self.assertEqual(response.status_code, 400)

        self.client.force_login(self.viewer)
        response = self.client.post(url, {"task_id": TASK_ID})
        self.assertEqual(response.status_code, 403)
        confirm.assert_not_called()

    @patch("dashboard.views.change_task", return_value=SERVICE_TASK_PREVIEW)
    def test_task_detail_shows_progress_and_root_preview(self, _task) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("change-task-detail", args=[TASK_ID]))
        self.assertContains(response, "停止 Clash 订阅")
        self.assertContains(response, "影响预览已生成")
        self.assertContains(response, "当前状态")
        self.assertContains(response, "取消任务")

    @patch(
        "dashboard.views.change_task",
        return_value={
            **SERVICE_TASK_PREVIEW,
            "state": "failed",
            "state_label": "失败",
            "terminal": True,
            "progress": {"stage": "failed", "message": "任务执行失败。"},
            "error": {
                "code": "proxy_input_invalid",
                "message": "代理资源内容校验失败：出口节点缺少有效的 port。",
            },
        },
    )
    def test_task_detail_shows_safe_failure_reason_and_diagnostic_code(self, _task) -> None:
        self.client.force_login(self.user)

        response = self.client.get(reverse("change-task-detail", args=[TASK_ID]))

        self.assertContains(response, "失败原因")
        self.assertContains(response, "出口节点缺少有效的 port")
        self.assertContains(response, "proxy_input_invalid")
        self.assertContains(response, "底层命令输出不会写入任务详情")

    @patch("dashboard.views.cancel_change_task")
    @patch("dashboard.views.change_task", return_value=SERVICE_TASK_PREVIEW)
    def test_admin_can_cancel_own_waiting_task(self, _task, cancel) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(reverse("change-task-cancel", args=[TASK_ID]))
        self.assertRedirects(
            response,
            reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        cancel.assert_called_once_with(TASK_ID, "admin")

    @patch("dashboard.views.cancel_change_task")
    @patch(
        "dashboard.views.change_task",
        return_value={**SERVICE_TASK_PREVIEW, "action": "security.firewall.apply"},
    )
    def test_non_superuser_cannot_take_over_security_task(self, _task, cancel) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(reverse("change-task-cancel", args=[TASK_ID]))
        self.assertEqual(response.status_code, 403)
        cancel.assert_not_called()

    @patch(
        "dashboard.views.audit_log",
        return_value={"chain_valid": True, "items": []},
    )
    @patch(
        "dashboard.views.change_tasks",
        return_value={"items": [SERVICE_TASK_PREVIEW]},
    )
    def test_task_audit_lists_persisted_tasks(self, _tasks, _audit) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("task-audit"))
        self.assertContains(response, "最近任务")
        self.assertContains(response, "停止 Clash 订阅")
        self.assertContains(response, TASK_ID)

    @patch("dashboard.views.preview_proxy_change_task", return_value=SERVICE_TASK_PREVIEW)
    def test_proxy_credentials_create_redacted_task_preview(self, preview) -> None:
        airport_url = "https://airport.test/sub?token=private-token"
        exit_yaml = "type: socks5\nserver: exit.test\npassword: private-password"
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("network-proxy-resources"),
            {
                "operation": "airport_add",
                "airport_name": "主用机场",
                "airport_enabled": "yes",
                "countries": ["hk", "jp"],
                "airport_url": airport_url,
                "password": "test-password-only",
                "confirmed": "yes",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "脱敏影响预览")
        self.assertNotContains(response, "private-token")
        preview.assert_called_once_with({
            "operation": "airport_add", "airport_id": "", "airport_name": "主用机场",
            "airport_url": airport_url, "airport_enabled": True,
            "countries": ["hk", "jp"], "exit_id": "", "exit_name": "",
            "exit_default": False, "exit_proxy_yaml": "", "awg_name": "", "exit_ids": [],
        }, "owner")

    @patch("dashboard.views.proxy_resources")
    def test_proxy_resource_page_is_progressive_and_lists_safe_facts(self, resources) -> None:
        resources.return_value = {
            "schema_version": 3, "revision": "a" * 64, "configured": True,
            "airport_count": 2, "active_airport_count": 1,
            "airports": [
                {"id": "111111111111", "name": "主用机场", "host": "a.test", "enabled": True, "countries": ["hk", "jp"], "country_labels": ["香港", "日本"]},
                {"id": "222222222222", "name": "备用机场", "host": "b.test", "enabled": False, "countries": ["all"], "country_labels": ["全部地区"]},
            ],
            "country_options": [{"id": "all", "label": "全部地区"}, {"id": "hk", "label": "香港"}, {"id": "jp", "label": "日本"}],
            "exit": {"configured": True, "type": "socks5", "server": "exit.test", "port": 1080},
            "exit_count": 1, "default_exit_id": "333333333333",
            "exits": [{"id": "333333333333", "name": "默认出口", "default": True,
                "type": "socks5", "server": "exit.test", "port": 1080}],
        }
        self.client.force_login(self.user)
        response = self.client.get(reverse("network-proxy-resources"))
        self.assertContains(response, "代理资源")
        self.assertContains(response, "主用机场")
        self.assertContains(response, "备用机场")
        self.assertContains(response, "香港 · 日本")
        self.assertContains(response, "出口节点目录")
        self.assertContains(response, "按字段输入")
        self.assertContains(response, "YAML 格式参考")
        self.assertContains(response, "server: proxy.example.com", count=1)
        self.assertNotContains(response, 'placeholder="type: socks5', html=False)
        self.assertContains(response, '<details class="proxy-create-panel">', html=False)
        self.assertNotContains(response, '<details class="proxy-create-panel" open>', html=False)
        self.assertContains(response, "查看链接")
        self.assertContains(response, "data-sensitive-auth-modal")
        self.assertNotContains(response, "token=")

        self.unlock_sensitive_resources()
        response = self.client.get(reverse("network-proxy-resources"))
        self.assertContains(response, "查看链接", count=2)
        self.assertContains(response, "复制链接", count=2)
        self.assertContains(response, "查看配置")
        self.assertContains(response, "复制配置")

    @patch("dashboard.views.preview_proxy_change_task", return_value=SERVICE_TASK_PREVIEW)
    def test_exit_can_be_added_from_socks_fields_without_exposing_credentials(
        self, preview
    ) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-proxy-resources"), {
            "operation": "exit_add",
            "exit_name": "美国住宅出口",
            "exit_input_mode": "fields",
            "exit_field_type": "socks5",
            "exit_field_server": "proxy.example.com",
            "exit_field_port": "1080",
            "exit_field_username": "alice",
            "exit_field_password": "p@ss: #word",
            "exit_default": "yes",
            "password": "test-password-only",
            "confirmed": "yes",
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "p@ss: #word")
        preview.assert_called_once_with({
            "operation": "exit_add", "airport_id": "", "airport_name": "",
            "airport_url": "", "airport_enabled": False, "countries": [],
            "exit_id": "", "exit_name": "美国住宅出口", "exit_default": True,
            "exit_proxy_yaml": (
                'type: "socks5"\nserver: "proxy.example.com"\nport: 1080\n'
                'username: "alice"\npassword: "p@ss: #word"\nudp: true\n'
            ),
            "awg_name": "", "exit_ids": [],
        }, "owner")

    @patch("dashboard.views.preview_proxy_change_task")
    def test_exit_field_mode_rejects_partial_credentials(self, preview) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-proxy-resources"), {
            "operation": "exit_add", "exit_name": "测试出口",
            "exit_input_mode": "fields", "exit_field_type": "socks5",
            "exit_field_server": "proxy.example.com", "exit_field_port": "1080",
            "exit_field_username": "alice", "exit_field_password": "",
            "password": "test-password-only", "confirmed": "yes",
        })
        self.assertRedirects(
            response, reverse("network-proxy-resources"),
            fetch_redirect_response=False,
        )
        self.assertIn(
            "SOCKS5 账号和密码必须同时填写或同时留空。",
            [str(message) for message in get_messages(response.wsgi_request)],
        )
        preview.assert_not_called()

    @patch("dashboard.views.reveal_proxy_resource", return_value={
        "schema_version": 1, "resource": "proxy_airport_link",
        "item_id": "111111111111", "name": "主用机场",
        "value": "https://airport.test/sub?token=private",
    })
    def test_proxy_secret_requires_unlock_and_disables_cache(self, reveal_resource) -> None:
        self.client.force_login(self.user)
        url = reverse("network-proxy-secret", args=["111111111111", "link"])
        self.assertEqual(self.client.post(url).status_code, 403)
        self.unlock_sensitive_resources()
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "主用机场")
        self.assertIn("no-store", response["Cache-Control"])
        reveal_resource.assert_called_once_with(
            "airport_link", "111111111111", "owner"
        )

    @patch("dashboard.views.preview_proxy_change_task", return_value=SERVICE_TASK_PREVIEW)
    def test_airport_selection_update_is_sent_as_one_change(self, preview) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("network-proxy-resources"), {
            "operation": "airport_update", "airport_id": "111111111111",
            "airport_name": "主用机场", "airport_enabled": "yes",
            "countries": ["sg", "us"], "airport_url": "",
            "password": "test-password-only", "confirmed": "yes",
        })
        self.assertEqual(response.status_code, 200)
        preview.assert_called_once_with({
            "operation": "airport_update", "airport_id": "111111111111",
            "airport_name": "主用机场", "airport_url": "", "airport_enabled": True,
            "countries": ["sg", "us"], "exit_id": "", "exit_name": "",
            "exit_default": False, "exit_proxy_yaml": "", "awg_name": "", "exit_ids": [],
        }, "owner")

    @patch("dashboard.views.confirm_change_task")
    def test_proxy_task_confirmation_redirects_without_resubmitting_secrets(
        self, confirm
    ) -> None:
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("network-proxy-resource-execute"), {"task_id": TASK_ID}
        )
        self.assertRedirects(
            response,
            reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        confirm.assert_called_once_with(TASK_ID, "owner")

    def test_health_does_not_expose_snapshot(self) -> None:
        response = self.client.get(reverse("health"))
        self.assertJSONEqual(response.content, {"status": "ok"})

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_network_permission_task", return_value=NETWORK_PERMISSION_TASK_PREVIEW)
    def test_admin_can_preview_and_queue_vless_permission(self, preview_task, confirm) -> None:
        self.client.force_login(self.admin)
        preview = self.client.post(reverse("network-permission-preview"), {
            "operation": "allow", "client": "iphone", "target": "home-desk",
            "port_mode": "tcp", "ports": "443, 22,22",
        })
        self.assertContains(preview, "新增访问权限")
        response = self.client.post(reverse("network-permission-execute"), {"task_id": TASK_ID})
        self.assertRedirects(response, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        preview_task.assert_called_once_with("allow", "iphone", "home-desk", "22,443", "tcp", "admin")
        confirm.assert_called_once_with(TASK_ID, "admin")

    @patch("dashboard.views.preview_network_permission_task", return_value=NETWORK_PERMISSION_TASK_PREVIEW)
    def test_admin_can_delete_one_exact_permission_rule(self, preview_task) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(reverse("network-permission-preview"), {
            "operation": "deny", "client": "iphone", "target": "home-desk",
            "network": "tcp", "ports": "443,22",
        })
        self.assertEqual(response.status_code, 200)
        preview_task.assert_called_once_with(
            "deny", "iphone", "home-desk", "22,443", "tcp", "admin"
        )

    @patch("dashboard.views.preview_network_permission_task", return_value=NETWORK_PERMISSION_TASK_PREVIEW)
    def test_permission_form_supports_ranges_and_exact_range_deletion(self, preview_task) -> None:
        self.client.force_login(self.admin)
        for operation in ("allow", "deny"):
            preview_task.reset_mock()
            response = self.client.post(reverse("network-permission-preview"), {
                "operation": operation, "client": "iphone", "target": "home-desk",
                "port_mode": "udp", "network": "udp", "ports": "22,8005,8000-8004,8002-8003",
            })
            self.assertEqual(response.status_code, 200)
            preview_task.assert_called_once_with(operation, "iphone", "home-desk", "22,8000-8005", "udp", "admin")

    @patch("dashboard.views.preview_network_permission_task")
    def test_invalid_port_ranges_never_create_tasks(self, preview_task) -> None:
        self.client.force_login(self.admin)
        for ports in ("23-22", "0-22", "65535-65536", "22-", "22,,443"):
            response = self.client.post(reverse("network-permission-preview"), {
                "operation": "allow", "client": "iphone", "target": "home-desk",
                "port_mode": "tcp", "ports": ports,
            })
            self.assertEqual(response.status_code, 400)
        preview_task.assert_not_called()

    @patch("dashboard.views.preview_network_permission_task", return_value=NETWORK_PERMISSION_TASK_PREVIEW)
    def test_admin_can_allow_vless_to_all_nodes(self, preview_task) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(reverse("network-permission-preview"), {
            "operation": "allow", "client": "iphone", "target": "all", "port_mode": "all",
        })
        self.assertEqual(response.status_code, 200)
        preview_task.assert_called_once_with(
            "allow", "iphone", "all", "", "", "admin"
        )

    @patch("dashboard.views.preview_network_permission_task", return_value=NETWORK_PERMISSION_TASK_PREVIEW)
    def test_admin_can_limit_all_nodes_to_specific_ports(self, preview_task) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(reverse("network-permission-preview"), {
            "operation": "allow", "client": "iphone", "target": "all",
            "port_mode": "specific", "network": "tcp", "ports": "443,22",
        })
        self.assertEqual(response.status_code, 200)
        preview_task.assert_called_once_with(
            "allow", "iphone", "all", "22,443", "tcp", "admin"
        )

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_subscription_sync_task", return_value=SUBSCRIPTION_SYNC_TASK_PREVIEW)
    def test_subscription_sync_uses_persisted_task(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        preview = self.client.post(reverse("network-subscription-preview"))
        self.assertContains(preview, "同步全部发布订阅")
        self.assertContains(preview, "home-desk、iphone")
        self.assertNotContains(preview, "secret-token")
        response = self.client.post(
            reverse("network-subscription-execute"), {"task_id": TASK_ID}
        )
        self.assertRedirects(response, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        preview_task.assert_called_once_with("owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_subscription_rotate_task", return_value=SUBSCRIPTION_ROTATE_TASK_PREVIEW)
    def test_subscription_rotate_clears_sensitive_unlock_when_queued(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        session = self.client.session
        session["sensitive_resource_unlocked_at"] = int(time.time())
        session.save()
        preview = self.client.post(
            reverse("network-subscription-rotate-preview", args=["home-desk"])
        )
        self.assertContains(preview, "成功后立即失效")
        response = self.client.post(
            reverse("network-subscription-rotate-execute", args=["home-desk"]),
            {"task_id": TASK_ID},
        )
        self.assertRedirects(response, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        self.assertNotIn("sensitive_resource_unlocked_at", self.client.session)
        preview_task.assert_called_once_with("home-desk", "owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_subscription_state_task", return_value=SUBSCRIPTION_STATE_TASK_PREVIEW)
    def test_subscription_disable_preserves_node_and_clears_unlock(self, preview_task, confirm) -> None:
        self.client.force_login(self.user)
        session = self.client.session
        session["sensitive_resource_unlocked_at"] = int(time.time())
        session.save()
        preview = self.client.post(
            reverse("network-subscription-state-preview", args=["home-desk"]),
            {"state": "disabled"},
        )
        self.assertContains(preview, "节点网络状态")
        response = self.client.post(
            reverse("network-subscription-state-execute", args=["home-desk"]),
            {"task_id": TASK_ID, "state": "disabled"},
        )
        self.assertRedirects(response, reverse("change-task-detail", args=[TASK_ID]), fetch_redirect_response=False)
        self.assertNotIn("sensitive_resource_unlocked_at", self.client.session)
        preview_task.assert_called_once_with("home-desk", "disabled", "owner")
        confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.confirm_change_task")
    def test_subscription_state_execute_get_recovers_without_running_task(self, confirm) -> None:
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("network-subscription-state-execute", args=["home-desk"])
        )
        self.assertRedirects(
            response, reverse("network-nodes"), fetch_redirect_response=False
        )
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any("确认请求未提交" in str(item) for item in messages))
        confirm.assert_not_called()

    def test_sensitive_resources_require_recent_password_reauthentication(self) -> None:
        self.client.force_login(self.user)
        locked = self.client.post(reverse("clash-subscription-copy", args=["home-desk"]))
        self.assertEqual(locked.status_code, 403)
        self.assertEqual(locked.json()["code"], "sensitive_unlock_required")
        wrong = self.client.post(reverse("sensitive-unlock"), {
            "destination": "nodes", "password": "wrong-password",
        })
        self.assertRedirects(wrong, reverse("network-nodes"), fetch_redirect_response=False)
        self.assertNotIn("sensitive_resource_unlocked_at", self.client.session)
        correct = self.client.post(reverse("sensitive-unlock"), {
            "destination": "nodes", "password": "test-password-only",
        })
        self.assertRedirects(correct, reverse("network-nodes"), fetch_redirect_response=False)
        self.assertIn("sensitive_resource_unlocked_at", self.client.session)

    @patch("dashboard.views.record_audit_event")
    def test_superuser_can_create_admin_and_account_change_is_audited(self, audit) -> None:
        self.client.force_login(self.user)
        response = self.client.post(reverse("accounts"), {
            "operation": "create", "username": "operator", "role": "admin",
            "new_password": "unique-management-password-2026",
            "current_password": "test-password-only", "confirmed": "yes",
        })
        self.assertRedirects(response, reverse("accounts"), fetch_redirect_response=False)
        created = get_user_model().objects.get(username="operator")
        self.assertTrue(created.is_staff)
        self.assertFalse(created.is_superuser)
        audit.assert_called_once_with("account_create", "owner")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_deployment_task", return_value=SERVICE_TASK_PREVIEW)
    @patch("dashboard.views.read_snapshot", return_value={"services": []})
    def test_file_deployment_stages_upload_with_opaque_id(
        self, _snapshot, preview_task, confirm
    ) -> None:
        self.client.force_login(self.user)
        with tempfile.TemporaryDirectory() as directory, override_settings(SERVER_KIT_UPLOAD_DIR=Path(directory)):
            response = self.client.post(reverse("deployment-wizard"), {
                "service_id": "file", "port": "8443",
                "password": "test-password-only", "confirmed": "yes",
                "payload": SimpleUploadedFile("测试 文件.yaml", b"rules:\n  - MATCH,DIRECT\n"),
            })
            self.assertRedirects(
                response, reverse("change-task-detail", args=[TASK_ID]),
                fetch_redirect_response=False,
            )
            values = preview_task.call_args.args[1]
            self.assertRegex(values["upload_id"], r"^[0-9a-f]{32}$")
            self.assertEqual(values["download_name"], "yaml")
            self.assertTrue((Path(directory) / values["upload_id"] / "payload").is_file())
            preview_task.assert_called_once()
            confirm.assert_called_once_with(TASK_ID, "owner")

    @patch("dashboard.views.file_resources", return_value=FILE_RESOURCES)
    @patch("dashboard.views.describe_service", side_effect=AssertionError("文件页不应生成完整主机快照"))
    def test_file_resource_page_hides_links_and_shows_cdn_state(self, describe, _resources) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("file-resources"))
        describe.assert_not_called()
        self.assertContains(response, "80.0 MiB")
        self.assertContains(response, "CDN 缓存 1 天")
        self.assertContains(response, "运行中")
        self.assertContains(response, "可下载")
        self.assertNotContains(response, "https://10.20.0.1")
        self.assertContains(response, "复制链接")
        self.assertContains(response, "data-sensitive-auth-modal")
        self.unlock_sensitive_resources()
        response = self.client.get(reverse("file-resources"))
        self.assertContains(response, "复制链接")
        self.assertContains(response, "显示二维码")
        self.assertContains(response, 'class="item-state"')
        self.assertContains(response, 'class="item-actions"')

    @patch("dashboard.views.file_resources", return_value=FILE_RESOURCES_STOPPED)
    @patch("dashboard.views.describe_service", side_effect=AssertionError("文件页不应生成完整主机快照"))
    def test_file_resource_page_uses_actual_stopped_service_state(self, describe, _resources) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("file-resources"))
        describe.assert_not_called()
        self.assertContains(response, "已停止")
        self.assertContains(response, "暂不可下载")
        self.assertNotContains(response, ">已发布<")

    @patch("dashboard.views.confirm_change_task")
    @patch("dashboard.views.preview_file_change_task", return_value=SERVICE_TASK_PREVIEW)
    def test_file_resource_add_and_delete_use_staged_upload_and_tasks(
        self, preview_task, confirm
    ) -> None:
        self.client.force_login(self.user)
        with tempfile.TemporaryDirectory() as directory, override_settings(
            SERVER_KIT_UPLOAD_DIR=Path(directory), SERVER_KIT_MAX_UPLOAD_BYTES=2 * 1024**3,
        ):
            response = self.client.post(reverse("file-resource-add"), {
                "payload": SimpleUploadedFile("large.bin", b"payload"),
                "download_name": "large.bin", "cdn_cache": "yes", "cache_ttl": "86400",
                "password": "test-password-only", "confirmed": "yes",
            })
            self.assertRedirects(
                response,
                reverse("change-task-detail", args=[TASK_ID]),
                fetch_redirect_response=False,
            )
            self.assertEqual(preview_task.call_args.args[0], "add")
            self.assertTrue((Path(directory) / preview_task.call_args.args[1] / "payload").is_file())
            confirm.assert_called_with(TASK_ID, "owner")
        delete_preview = self.client.post(reverse("file-resource-delete-preview", args=["file-1234567890abcdef"]))
        self.assertContains(delete_preview, "第三方 CDN 已缓存副本")
        response = self.client.post(reverse("file-resource-delete-execute", args=["file-1234567890abcdef"]), {
            "task_id": TASK_ID, "confirmed": "yes", "password": "test-password-only",
        })
        self.assertRedirects(
            response,
            reverse("change-task-detail", args=[TASK_ID]),
            fetch_redirect_response=False,
        )
        self.assertEqual(preview_task.call_args.args[0], "delete")

    @patch("dashboard.views.reveal_file_resource", return_value={
        "schema_version": 1, "resource": "file_download_link",
        "item_id": "file-1234567890abcdef", "name": "large.bin", "value": "https://secret/link",
    })
    def test_file_link_requires_unlock_and_is_not_cached(self, reveal) -> None:
        self.client.force_login(self.user)
        url = reverse("file-resource-secret", args=["file-1234567890abcdef", "link"])
        self.assertEqual(self.client.post(url).status_code, 403)
        self.unlock_sensitive_resources()
        response = self.client.post(url)
        self.assertEqual(response.json()["value"], "https://secret/link")
        self.assertIn("no-store", response["Cache-Control"])
        reveal.assert_called_once()
