"""Task context remains reachable without following arbitrary return URLs."""

from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, TestCase

from control_plane.client import AgentError
from .task_navigation import task_navigation_context


TASK_ID = "task-" + "a" * 32


class TaskNavigationTests(SimpleTestCase):
    def origin(self, action, **task):
        return task_navigation_context({"action": action, **task}, {}, TASK_ID)["task_origin"]

    def test_action_families_return_to_the_actual_controls(self):
        cases = {
            "network.node.awg.add": ("/network/nodes/", "内网节点"),
            "network.node.vless.remove": ("/network/nodes/", "内网节点"),
            "network.permission.batch": ("/network/nodes/", "内网节点"),
            "network.subscriptions.sync": ("/network/nodes/", "内网节点"),
            "network.subscription.rotate": ("/network/nodes/", "内网节点"),
            "network.proxy.update": ("/network/proxy/", "代理资源"),
            "network.node.domains": ("/network/subscriptions/#host-records", "域名管理"),
            "network.address.domains": ("/network/subscriptions/#host-records", "域名管理"),
            "network.duckdns.configure": ("/network/subscriptions/#dynamic-dns", "域名管理"),
            "network.public_endpoint.apply": ("/network/subscriptions/#public-endpoint", "域名管理"),
            "file.add": ("/files/", "文件资源"),
            "backup.restore_apply": ("/backups/", "备份"),
            "deployment.proxy.install": ("/deploy/", "部署向导"),
            "security.ssh_auth.apply": ("/security/transactions/", "安全事务"),
            "firewall.port.open": ("/services/firewall/", "服务详情"),
            "ssh.key.rename": ("/services/ssh/", "服务详情"),
        }
        for action, (url, label) in cases.items():
            with self.subTest(action=action):
                self.assertEqual(self.origin(action), {"url": url, "label": label})

    def test_node_exit_assignment_returns_to_nodes_not_proxy_catalog(self):
        self.assertEqual(self.origin("network.proxy.update", preview={
            "facts": {"订阅节点": "demo-laptop"},
        })["url"], "/network/nodes/")
        self.assertEqual(self.origin("network.proxy.update", result={
            "operation": "node_exits_set",
        })["url"], "/network/nodes/")

    def test_service_result_id_or_exact_public_label_can_identify_service(self):
        for task in (
            {"result": {"service": {"id": "clash"}}},
            {"preview": {"facts": {"服务": "Clash 订阅"}}},
        ):
            with self.subTest(task=task):
                self.assertEqual(self.origin("service.restart", **task)["url"], "/services/clash/")
        self.assertEqual(self.origin("managed.port.change", preview={
            "title": "修改AWG 备用入口 2",
        })["url"], "/services/amneziawg/#managed-ports")

    def test_untrusted_url_or_unknown_service_is_never_a_destination(self):
        destination = self.origin("service.restart", result={
            "service": {"id": "//example.com/"},
        }, preview={"facts": {"服务": "https://example.com"}}, next="https://example.com")
        self.assertEqual(destination, {"url": "/", "label": "服务总览"})
        self.assertIsNone(self.origin("unknown.action", result={"service_id": "clash"}))
        for invalid in (None, "invalid", [], {"action": []}, {"action": "service.start", "preview": []}):
            with self.subTest(invalid=invalid):
                task_navigation_context(invalid, {}, TASK_ID)

    def test_session_remembers_only_destination_keys_with_a_fixed_limit(self):
        session = {}
        for number in range(25):
            identifier = f"task-{number:032x}"
            task_navigation_context({
                "action": "network.permission.allow", "preview": {"secret": "must-not-retain"},
            }, session, identifier)
        remembered = session["task_return_destinations"]
        self.assertEqual(len(remembered), 20)
        self.assertNotIn("task-" + "0" * 32, remembered)
        self.assertEqual(set(remembered.values()), {"nodes"})
        self.assertNotIn("must-not-retain", str(session))
        previous = session["task_return_destinations"]
        task_navigation_context({"action": "network.permission.allow"}, session, "task-" + f"{24:032x}")
        self.assertIs(session["task_return_destinations"], previous)

    def test_unavailable_task_uses_only_an_allowlisted_remembered_key(self):
        session = {"task_return_destinations": {TASK_ID: "nodes"}}
        self.assertEqual(task_navigation_context(None, session, TASK_ID)["task_origin"]["url"], "/network/nodes/")
        for invalid in ("https://example.com", "//example.com", "service:../../", {"url": "/evil"}):
            session["task_return_destinations"][TASK_ID] = invalid
            self.assertIsNone(task_navigation_context(None, session, TASK_ID)["task_origin"])
        self.assertIsNone(task_navigation_context(None, {}, TASK_ID)["task_origin"])

    def test_templates_offer_origin_plus_audit_without_resubmission(self):
        request = RequestFactory().get("/")
        request.user = SimpleNamespace(is_authenticated=True, is_superuser=True, username="demo")
        for template in ("change_task_detail.html", "task_unavailable.html"):
            with self.subTest(template=template):
                html = render_to_string("dashboard/" + template, {
                    "task_id": TASK_ID,
                    "task": {"id": TASK_ID, "terminal": True, "state": "failed"},
                    "task_origin": {"url": "/network/nodes/", "label": "内网节点"},
                }, request=request)
                self.assertIn("← 返回内网节点", html)
                self.assertIn('href="/audit/"', html)
                self.assertNotIn('action="/tasks/', html)


class TaskNavigationViewTests(TestCase):
    def setUp(self):
        self.client.force_login(get_user_model().objects.create_user(username="demo-navigation"))

    @patch("dashboard.views.change_task")
    def test_read_then_agent_outage_preserves_context_without_repeat_submit(self, read_task):
        read_task.return_value = {
            "id": TASK_ID, "action": "network.permission.allow", "state": "failed",
            "terminal": True, "preview": {"title": "访问授权"},
        }
        response = self.client.get(f"/tasks/{TASK_ID}/?next=https://example.com")
        self.assertContains(response, "← 返回内网节点")
        self.assertNotContains(response, "https://example.com")
        read_task.side_effect = AgentError("Unavailable", "agent_error")
        unavailable = self.client.get(f"/tasks/{TASK_ID}/")
        self.assertContains(unavailable, "← 返回内网节点", status_code=503)
        self.assertContains(unavailable, "不会再次执行", status_code=503)
        self.assertContains(unavailable, 'href="/audit/"', status_code=503)
        self.assertIn("no-store", unavailable["Cache-Control"])
