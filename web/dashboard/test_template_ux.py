"""Template-only UX contracts; synthetic data and no management-agent access."""

from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

from django.template.loader import get_template, render_to_string
from django.test import RequestFactory, SimpleTestCase


class ElementCollector(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        self.elements.append((tag, dict(attributes)))

    def matching(self, tag, **attributes):
        return [
            element for element_tag, element in self.elements
            if element_tag == tag
            and all(element.get(key) == value for key, value in attributes.items())
        ]


class TemplateExperienceTests(SimpleTestCase):
    def render_page(self, template, context=None, *, role="superuser"):
        request = RequestFactory().get("/")
        request.user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=role == "superuser",
            is_staff=role in {"superuser", "admin"},
            username="demo-admin",
            pk=1,
        )
        return render_to_string(
            f"dashboard/{template}", context or {}, request=request,
        )

    def test_business_templates_compile_and_expose_skip_navigation_target(self):
        directory = Path(__file__).resolve().parents[1] / "templates" / "dashboard"
        for path in directory.glob("*.html"):
            if path.name.startswith("_"):
                continue
            with self.subTest(template=path.name):
                get_template(f"dashboard/{path.name}")
                self.assertEqual(path.read_text().count('id="main-content"'), 1)
                self.assertIn('tabindex="-1"', path.read_text())

    def test_permission_creation_defaults_to_explicit_tcp_ports(self):
        html = self.render_page("network_nodes.html", {
            "network": {
                "writes_enabled": True,
                "subscriptions_configured": True,
                "nodes": [{
                    "name": "demo-laptop", "kind": "awg", "kind_label": "普通节点",
                    "state": "已启用", "permissions": [],
                    "available_targets": [{"name": "vps", "label": "VPS"}],
                }],
            },
        })
        fields = ElementCollector(html)
        ports = fields.matching("input", name="ports")
        self.assertEqual(len(ports), 1)
        self.assertIn("required", ports[0])
        self.assertNotIn("disabled", ports[0])
        self.assertLess(html.index('value="tcp"'), html.index('value="all"'))
        self.assertIn("全部协议与端口", html)
        self.assertIn("例如 22,443,8000-8010", html)
        self.assertIn("data-filter-input", html)
        self.assertIn("data-filter-label=\"demo-laptop", html)
        self.assertIn("data-permission-batch", html)
        self.assertIn("data-permission-review", html)
        self.assertIn("data-permission-result", html)
        self.assertIn("＋ 再加一条", html)
        self.assertIn("无需离开本页", html)
        self.assertIn('<option value="" disabled selected>选择访问目标</option>', html)

    def test_read_only_node_empty_state_does_not_offer_hidden_creation(self):
        html = self.render_page("network_nodes.html", {
            "network": {"nodes": [], "writes_enabled": True},
        }, role="viewer")
        self.assertIn("请联系管理员添加设备", html)
        self.assertNotIn("展开上方“新增节点”开始创建", html)
        self.assertNotIn("data-awg-generator-form", html)

    def test_exit_only_catalog_still_offers_connectivity_test(self):
        html = self.render_page("network_proxy_resources.html", {
            "proxy": {"airport_count": 0, "exit_count": 1, "airports": [], "exits": []},
        })
        self.assertIn("测试全部连接", html)
        self.assertIn('id="airport-resources"', html)
        self.assertIn('id="exit-resources"', html)
        self.assertIn("data-filter-empty", html)
        self.assertRegex(html, r'<textarea[^>]*name="exit_proxy_yaml"[^>]*></textarea>')
        self.assertNotRegex(html, r'<textarea[^>]*>type: socks5')

    def test_unconfigured_files_provide_deployment_path_not_unlock_form(self):
        html = self.render_page("file_resources.html", {
            "files": {"configured": False, "items": []},
            "file_service": {"state": "未安装"},
        })
        self.assertIn("前往部署向导", html)
        self.assertNotIn('name="destination" value="files"', html)
        self.assertNotIn('name="payload"', html)

    def test_accounts_identify_current_user_and_label_password_fields(self):
        html = self.render_page("accounts.html", {"accounts": [
            SimpleNamespace(pk=1, username="demo-admin", is_active=True, is_staff=True, is_superuser=True),
            SimpleNamespace(pk=2, username="demo-viewer", is_active=True, is_staff=False, is_superuser=False),
        ]})
        self.assertIn("当前账号</span>", html)
        self.assertIn("demo-viewer 将无法登录管理网站", html)
        self.assertIn('<details class="danger-zone"', html)
        self.assertNotIn('placeholder="当前账号密码"', html)

    def test_task_refresh_is_explicit_and_terminal_tasks_stop_polling(self):
        context = {"task": {
            "id": "demo-task", "terminal": False, "state": "running",
            "state_label": "执行中", "preview": {"title": "演示任务", "facts": {}},
            "progress": {"message": "检查配置"}, "transitions": [],
        }}
        html = self.render_page("change_task_detail.html", context)
        self.assertIn("data-task-live", html)
        self.assertIn("data-task-refresh-toggle", html)
        self.assertIn("data-task-refresh-status", html)
        context["task"]["terminal"] = True
        html = self.render_page("change_task_detail.html", context)
        self.assertIn("data-task-live", html)
        self.assertNotIn("data-task-refresh-toggle", html)
        self.assertNotIn('data-task-refresh="true"', html)

    def test_backup_pending_is_not_labeled_as_already_rolling_back(self):
        html = self.render_page("backups.html", {
            "restore_transaction": {"state": "pending", "remaining_seconds": 250},
            "backups": [],
        })
        self.assertIn("等待确认", html)
        self.assertNotIn("自动回滚中", html)

    def test_dns_settings_have_stable_section_targets_and_generic_examples(self):
        html = self.render_page("network_subscriptions.html", {
            "network": {"writes_enabled": True, "nodes": [], "host_records": []},
            "public_endpoint": {"fqdn": ""},
        })
        for target in ("public-endpoint", "dynamic-dns", "host-records"):
            self.assertIn(f'id="{target}"', html)
            self.assertIn(f'href="#{target}"', html)
        self.assertIn('placeholder="vpn.example.com"', html)
        self.assertIn('placeholder="example.com"', html)

    def test_installed_stopped_services_offer_recovery_not_reinstallation(self):
        services = {
            identifier: {"state": "已停止" if index % 2 else "失败"}
            for index, identifier in enumerate(("vless", "clash", "mosh", "file"))
        }
        html = self.render_page("deployment_wizard.html", {"services": services})
        self.assertEqual(html.count("检查并恢复服务"), 4)
        self.assertNotIn('name="service_id"', html)
        for identifier in services:
            self.assertIn(f'href="/services/{identifier}/"', html)

    def test_failed_snapshots_show_unknown_not_fake_empty_inventory(self):
        for template in ("network_nodes.html", "network_proxy_resources.html", "network_subscriptions.html", "file_resources.html", "backups.html", "index.html", "deployment_wizard.html", "task_audit.html"):
            with self.subTest(template=template):
                html = self.render_page(template, {
                    "snapshot_error": "演示读取失败", "network_snapshot_error": True,
                    "public_endpoint_error": True, "duckdns_error": True,
                    "backups_error": True, "restore_status_error": True,
                    "audit_error": True, "tasks_error": True,
                })
                self.assertIn("无法加载当前状态", html)
                self.assertIn("重新加载", html)
                self.assertNotIn("还没有", html)
                self.assertNotIn("暂无管理动作", html)
                self.assertNotIn("校验失败", html)
                main = html.split('<main id="main-content"', 1)[1].split('</main>', 1)[0]
                self.assertNotIn('name="password"', main)
                self.assertNotIn('data-list-filter', html)

    def test_pending_restore_is_kept_when_only_backup_listing_fails(self):
        html = self.render_page("backups.html", {
            "snapshot_error": "演示列表读取失败", "backups_error": True,
            "restore_status_error": False,
            "restore_transaction": {"state": "pending", "remaining_seconds": 120},
        })
        self.assertIn("等待新连接验证", html)
        self.assertIn('value="restore_rollback"', html)
        self.assertIn("备份数量未知", html)
        self.assertNotIn('value="create"', html)

    def test_rollback_warning_precedes_details_and_links_to_correct_page(self):
        task = {
            "id": "demo-task", "terminal": False, "state": "waiting_rollback_confirmation",
            "state_label": "等待确认", "action": "network.public_endpoint.apply",
            "preview": {"title": "演示入口变更", "facts": {"目标": "vpn.example.com"}},
            "result": {"state": "pending", "remaining_seconds": 180},
        }
        html = self.render_page("change_task_detail.html", {"task": task})
        self.assertLess(html.index('class="alert warning"'), html.index('class="fact-grid"'))
        self.assertIn('href="/network/subscriptions/#public-endpoint"', html)
        self.assertIn("原发起会话不能确认", html)
