"""Topology endpoints expose configured access facts through one read only."""

from copy import deepcopy
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from control_plane.client import AgentError


NETWORK = {
    "nodes": [
        {"name": "desktop", "kind": "awg", "kind_label": "AmneziaWG",
         "address": "10.44.0.20", "state": "已启用", "protected": True,
         "access_mode": "unrestricted", "permissions": [],
         "private_key": "must-not-project-private-key", "domains": ["must-not-project.example"]},
        {"name": "phone", "kind": "vless", "kind_label": "VLESS",
         "address": "—", "state": "已启用", "protected": False,
         "access_mode": "restricted", "permissions": []},
    ],
    "pending_access": False, "pending_vless": False,
    "exit_options": [{"password": "must-not-project-proxy-password"}],
    "server_public_key": "must-not-project-key-material",
}


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class TopologyViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model().objects
        cls.viewer = users.create_user("topology-viewer", password="test-only-password")
        cls.staff = users.create_user("topology-staff", password="test-only-password", is_staff=True)
        cls.owner = users.create_superuser("topology-owner", password="test-only-password")

    def setUp(self):
        self.url = reverse("network-topology")
        self.client.force_login(self.viewer)

    @patch("dashboard.topology_views.network_overview", return_value=NETWORK)
    def test_all_authenticated_roles_can_read_safe_projection_once(self, read):
        before = deepcopy(NETWORK)
        for user in (self.viewer, self.staff, self.owner):
            self.client.force_login(user)
            for as_json in (False, True):
                with self.subTest(user=user.username, as_json=as_json):
                    read.reset_mock()
                    response = self.client.get(self.url, {"format": "json"} if as_json else {})
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("no-store", response["Cache-Control"])
                    self.assertNotIn("must-not-project", response.content.decode())
                    read.assert_called_once_with()
                    if as_json:
                        value = response.json()
                        self.assertEqual(value["selected_id"], "awg:desktop")
                        self.assertIn("observed_at", value)
                        self.assertEqual(len(value["nodes"]), 3)
                    else:
                        self.assertContains(response, "data-topology-root")
                        self.assertContains(response, "未检测")
        self.assertEqual(NETWORK, before)

    @patch("dashboard.topology_views.network_overview")
    def test_anonymous_and_non_get_requests_never_read(self, read):
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                self.assertEqual(getattr(self.client, method)(self.url).status_code, 405)
        self.client.logout()
        for query in ({}, {"format": "json"}):
            response = self.client.get(self.url, query)
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response["Location"].startswith(reverse("login")))
        read.assert_not_called()

    @patch("dashboard.topology_views.network_overview", return_value=NETWORK)
    def test_selection_and_unknown_id_remain_read_only(self, read):
        response = self.client.get(self.url, {"format": "json", "node": "vless:phone"})
        self.assertEqual(response.json()["selected_id"], "vless:phone")
        response = self.client.get(self.url, {"format": "json", "node": "not-a-node"})
        self.assertEqual(response.json()["selected_id"], "awg:desktop")
        self.assertEqual(read.call_count, 2)

    @patch("dashboard.topology_views.network_overview")
    def test_read_failures_return_noncacheable_generic_error_without_fake_nodes(self, read):
        for failure in (AgentError("must-not-project-socket", "unavailable"),
                        OSError("must-not-project-path"), RuntimeError("must-not-project-key")):
            read.side_effect = failure
            for as_json in (False, True):
                with self.subTest(failure=type(failure), as_json=as_json):
                    response = self.client.get(self.url, {"format": "json"} if as_json else {})
                    self.assertEqual(response.status_code, 503)
                    self.assertIn("no-store", response["Cache-Control"])
                    self.assertNotIn("must-not-project", response.content.decode())
                    if as_json:
                        self.assertEqual(response.json()["code"], "snapshot_unavailable")
                        self.assertNotIn("nodes", response.json())
                    else:
                        self.assertContains(response, "暂时无法读取", status_code=503)

    @patch("dashboard.topology_views.network_overview")
    def test_malformed_snapshot_is_not_a_valid_empty_network(self, read):
        for value in (None, [], {}, {"nodes": None}, {"nodes": {}}):
            read.return_value = value
            with self.subTest(value=value):
                response = self.client.get(self.url, {"format": "json"})
                self.assertEqual(response.status_code, 503)

    @patch("dashboard.topology_views.network_overview", return_value={"nodes": []})
    def test_real_empty_snapshot_keeps_hub_and_reports_zero_clients(self, read):
        response = self.client.get(self.url, {"format": "json"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["selected_id"], "hub")
        self.assertEqual(response.json()["summary"]["nodes"], 0)
        self.assertEqual(response.json()["relations"], [])
