"""JSON permission batches stay scoped, validated, CSRF protected and in place."""

import copy
import json
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from control_plane.client import AgentError


TASK_ID = "task-" + "b" * 32
TASK = {
    "id": TASK_ID, "action": "network.permission.batch", "actor": "batch-admin",
    "state": "waiting_confirmation", "state_label": "待确认", "terminal": False,
    "preview": {"title": "新增 2 条访问权限", "facts": {"来源节点": "phone"}},
}
RULES = [
    {"target": "home-desk", "network": "tcp", "ports": "22,443,8000-8010"},
    {"target": "vps", "network": "udp", "ports": "53"},
]
PERMISSIONS = [{
    "target": "home-desk", "target_label": "home-desk", "ip": "10.20.0.10",
    "network": "tcp", "network_label": "TCP", "ports": [22], "ports_label": "22",
}]


class PermissionBatchAPITests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model()
        cls.admin = users.objects.create_user(username="batch-admin", is_staff=True)
        cls.owner = users.objects.create_superuser(username="batch-owner")
        cls.viewer = users.objects.create_user(username="batch-viewer")

    def setUp(self):
        self.client.force_login(self.admin)
        self.preview_url = reverse("network-permission-batch-preview")
        self.execute_url = reverse("network-permission-batch-execute")
        self.status_url = reverse("network-permission-batch-status", args=[TASK_ID])
        self.preview = self._patch("preview_network_permission_batch_task", return_value=copy.deepcopy(TASK))
        self.read = self._patch("change_task", return_value=copy.deepcopy(TASK))
        self.confirm = self._patch("confirm_change_task", return_value={**copy.deepcopy(TASK), "state": "queued"})
        self.overview = self._patch("network_overview", return_value={"nodes": [
            {"name": "unrelated", "permissions": [{"target": "private-other-node"}]},
            {"name": "phone", "permissions": PERMISSIONS},
        ], "unrelated_secret": "do-not-return"})

    def _patch(self, name, **kwargs):
        patcher = patch("dashboard.views." + name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _post_preview(self, body=None):
        return self.client.post(self.preview_url, body if body is not None else {
            "client": "phone", "rules": copy.deepcopy(RULES),
        }, content_type="application/json")

    def _post_execute(self, body=None):
        return self.client.post(self.execute_url, body if body is not None else {
            "task_id": TASK_ID,
        }, content_type="application/json")

    def _succeeded(self):
        self.read.return_value.update(state="succeeded", terminal=True)

    def test_preview_normalizes_all_rules_in_one_request(self):
        response = self._post_preview({"client": " phone ", "rules": [
            {"target": " home-desk ", "network": " TCP ", "ports": "81,80,22,80-82"},
            {"target": "vps", "network": "all", "ports": ""},
        ]})
        self.assertEqual(response.status_code, 200)
        self.preview.assert_called_once_with("phone", [
            {"target": "home-desk", "network": "tcp", "ports": "22,80-82"},
            {"target": "vps", "network": "all", "ports": ""},
        ], "batch-admin")
        self.assertEqual(response.json()["task"], TASK)
        self.assertEqual(response.json()["status_url"], self.status_url)
        self.assertEqual(response.json()["task_url"], f"/tasks/{TASK_ID}/")
        self.assertIn("no-store", response["Cache-Control"])
        self.confirm.assert_not_called()

    def test_one_and_twenty_rules_are_allowed(self):
        for count in (1, 20):
            with self.subTest(count=count):
                response = self._post_preview({"client": "phone", "rules": [
                    {"target": f"node-{i}", "network": "tcp", "ports": "22"}
                    for i in range(count)
                ]})
                self.assertEqual(response.status_code, 200)

    def test_invalid_top_level_payloads_never_reach_agent(self):
        for body in ([], None, "phone", 4, {}, {"client": "phone"},
                     {"client": 22, "rules": RULES}, {"client": "../phone", "rules": RULES},
                     {"client": "phone", "rules": []}, {"client": "phone", "rules": RULES * 11},
                     {"client": "phone", "rules": {}},
                     {"client": "phone", "rules": RULES, "actor": "someone-else"}):
            with self.subTest(body=body):
                response = self.client.post(self.preview_url, json.dumps(body), content_type="application/json")
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.json())
        self.preview.assert_not_called()

    def test_malformed_json_and_wrong_content_type(self):
        for body in ("{", b"\xff", ""):
            with self.subTest(body=body):
                response = self.client.post(self.preview_url, body, content_type="application/json")
                self.assertEqual(response.status_code, 400)
        response = self.client.post(self.preview_url, {"client": "phone"})
        self.assertEqual(response.status_code, 400)
        self.preview.assert_not_called()

    def test_oversized_request_rejected(self):
        response = self.client.post(self.preview_url, " " * 1_048_577, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.preview.assert_not_called()

    def test_invalid_later_rule_rejects_entire_batch(self):
        invalid_rules = [
            None, [], "tcp", {}, {**RULES[0], "extra": "ignored?"},
            {**RULES[0], "target": "../root"}, {**RULES[0], "target": None},
            {**RULES[0], "network": "icmp"}, {**RULES[0], "network": ""},
            {**RULES[0], "network": "all"}, {**RULES[0], "ports": [22]},
            {**RULES[0], "ports": ""}, {**RULES[0], "ports": "90-80"},
            {**RULES[0], "ports": "65536"}, {**RULES[0], "ports": "0"},
        ]
        for rule in invalid_rules:
            with self.subTest(rule=rule):
                response = self._post_preview({"client": "phone", "rules": [RULES[1], rule]})
                self.assertEqual(response.status_code, 400)
        self.preview.assert_not_called()
        self.confirm.assert_not_called()

    def test_semantically_duplicate_batch_rules_are_rejected(self):
        response = self._post_preview({"client": "phone", "rules": [
            {"target": "vps", "network": "tcp", "ports": "80,81,82"},
            {"target": "vps", "network": "TCP", "ports": "80-82"},
        ]})
        self.assertEqual(response.status_code, 400)
        self.preview.assert_not_called()

    def test_unauthenticated_api_calls_return_json_not_redirects(self):
        self.client.logout()
        for response in (self._post_preview(), self._post_execute(), self.client.get(self.status_url),
                         self.client.post(self.preview_url), self.client.post(self.execute_url)):
            self.assertEqual(response.status_code, 401)
            self.assertIn("error", response.json())
            self.assertNotIn("Location", response)
            self.assertIn("no-store", response["Cache-Control"])
        self.preview.assert_not_called()
        self.read.assert_not_called()
        self.confirm.assert_not_called()

    def test_viewer_cannot_preview_execute_or_read_batch_details(self):
        self.client.force_login(self.viewer)
        for response in (self._post_preview(), self._post_execute(), self.client.get(self.status_url)):
            self.assertEqual(response.status_code, 403)
            self.assertIn("error", response.json())
        self.preview.assert_not_called()
        self.read.assert_not_called()

    def test_superuser_can_preview(self):
        self.client.force_login(self.owner)
        self.assertEqual(self._post_preview().status_code, 200)
        self.assertEqual(self.preview.call_args.args[-1], "batch-owner")

    def test_wrong_methods_are_json_405_without_agent_calls(self):
        for response in (self.client.get(self.preview_url), self.client.get(self.execute_url),
                         self.client.post(self.status_url)):
            self.assertEqual(response.status_code, 405)
            self.assertIn("error", response.json())
            self.assertIn(response["Allow"], ("GET", "POST"))
        self.preview.assert_not_called()
        self.read.assert_not_called()

    def test_csrf_is_required_for_both_write_endpoints(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        for url, data in ((self.preview_url, {"client": "phone", "rules": RULES}),
                          (self.execute_url, {"task_id": TASK_ID})):
            response = client.post(url, data, content_type="application/json")
            self.assertEqual(response.status_code, 403)
        self.preview.assert_not_called()
        self.confirm.assert_not_called()
        # Obtain a genuine token without disabling middleware.
        client.logout()
        client.get("/login/")
        token = client.cookies[settings.CSRF_COOKIE_NAME].value
        client.force_login(self.admin)
        response = client.post(self.preview_url, {"client": "phone", "rules": RULES},
                               content_type="application/json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200)

    def test_execute_confirms_exact_owned_batch_and_returns_json(self):
        response = self._post_execute()
        self.assertEqual(response.status_code, 200)
        self.read.assert_called_once_with(TASK_ID)
        self.confirm.assert_called_once_with(TASK_ID, "batch-admin")
        self.assertEqual(response.json()["task"]["state"], "queued")
        self.assertNotIn("Location", response)
        self.assertIn("no-store", response["Cache-Control"])

    def test_execute_invalid_id_or_fields_never_calls_agent(self):
        for body in ({"task_id": "../task"}, {"task_id": None}, [],
                     {"task_id": TASK_ID, "client": "other"}, {}):
            with self.subTest(body=body):
                self.assertEqual(self._post_execute(body).status_code, 400)
        self.read.assert_not_called()
        self.confirm.assert_not_called()

    def test_foreign_actor_or_wrong_action_or_mismatched_task_is_not_exposed(self):
        for field, value in (("actor", "another-admin"), ("action", "service.change"),
                             ("id", "task-" + "c" * 32)):
            with self.subTest(field=field):
                self.read.return_value = {**TASK, field: value, "secret": "never-return-this"}
                for response in (self._post_execute(), self.client.get(self.status_url)):
                    self.assertEqual(response.status_code, 404)
                    self.assertNotIn("task", response.json())
                    self.assertNotContains(response, "never-return-this", status_code=404)
        self.confirm.assert_not_called()
        self.overview.assert_not_called()

    def test_execute_retries_do_not_confirm_again_or_create_new_work(self):
        for state in ("queued", "running", "succeeded", "failed", "invalidated", "expired", "cancelled", "interrupted"):
            with self.subTest(state=state):
                self.read.return_value = {**TASK, "state": state}
                for _ in range(2):
                    response = self._post_execute()
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["task"]["state"], state)
        self.confirm.assert_not_called()
        self.preview.assert_not_called()

    def test_status_pending_is_read_only_and_never_fetches_permissions(self):
        response = self.client.get(self.status_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["task"], TASK)
        self.assertNotIn("permissions", response.json())
        self.assertIn("no-store", response["Cache-Control"])
        self.confirm.assert_not_called()
        self.overview.assert_not_called()

    def test_status_success_reads_only_source_permissions_from_authoritative_snapshot(self):
        self._succeeded()
        response = self.client.get(self.status_url + "?client=unrelated")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["client"], "phone")
        self.assertEqual(response.json()["permissions"], PERMISSIONS)
        self.assertNotContains(response, "private-other-node")
        self.assertNotContains(response, "do-not-return")
        self.overview.assert_called_once_with()

    def test_success_empty_permissions_is_allowed_only_from_real_node(self):
        self._succeeded()
        self.overview.return_value = {"nodes": [{"name": "phone", "permissions": []}]}
        response = self.client.get(self.status_url)
        self.assertEqual(response.json()["permissions"], [])
        self.assertNotIn("permissions_error", response.json())

    def test_success_refresh_failure_keeps_success_without_faking_empty_rules(self):
        self._succeeded()
        for error in (AgentError("internal socket details"), OSError("socket not found")):
            with self.subTest(error=type(error)):
                self.overview.side_effect = error
                response = self.client.get(self.status_url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["task"]["state"], "succeeded")
                self.assertIn("permissions_error", response.json())
                self.assertNotIn("permissions", response.json())

    def test_missing_or_malformed_node_cannot_masquerade_as_empty_permissions(self):
        self._succeeded()
        for overview in ({}, {"nodes": []}, {"nodes": "broken"},
                         {"nodes": [{"name": "phone"}]},
                         {"nodes": [{"name": "phone", "permissions": ["bad"]}]}):
            with self.subTest(overview=overview):
                self.overview.return_value = overview
                response = self.client.get(self.status_url)
                self.assertIn("permissions_error", response.json())
                self.assertNotIn("permissions", response.json())

    def test_missing_purged_or_malformed_source_facts_do_not_fetch_other_nodes(self):
        self._succeeded()
        for preview in ({}, None, {"facts": []}, {"facts": {"来源节点": "../root"}}):
            with self.subTest(preview=preview):
                self.read.return_value["preview"] = preview
                response = self.client.get(self.status_url)
                self.assertIn("permissions_error", response.json())
                self.assertNotIn("permissions", response.json())
        self.overview.assert_not_called()

    def test_invalid_status_id_never_calls_agent(self):
        response = self.client.get(reverse("network-permission-batch-status", args=["bad-id"]))
        self.assertEqual(response.status_code, 400)
        self.read.assert_not_called()

    def test_preview_agent_errors_have_actionable_json_status(self):
        for error, status in ((AgentError("bad rule", "invalid_params"), 400),
                              (AgentError("locked", "operation_forbidden"), 400),
                              (AgentError("queue", "queue_full"), 409),
                              (AgentError("gone", "not_found"), 404),
                              (AgentError("socket credentials"), 503), (OSError("not connected"), 503)):
            with self.subTest(status=status, error=error):
                self.preview.side_effect = error
                response = self._post_preview()
                self.assertEqual(response.status_code, status)
                self.assertIn("error", response.json())
                if status == 503:
                    self.assertNotContains(response, str(error), status_code=503)

    def test_execute_and_status_agent_outage_do_not_mutate_or_redirect(self):
        self.read.side_effect = AgentError("down")
        for response in (self._post_execute(), self.client.get(self.status_url)):
            self.assertEqual(response.status_code, 503)
            self.assertIn("error", response.json())
            self.assertNotIn("Location", response)
        self.confirm.assert_not_called()

    def test_confirmation_failure_does_not_auto_retry(self):
        self.confirm.side_effect = AgentError("queue full", "queue_full")
        response = self._post_execute()
        self.assertEqual(response.status_code, 409)
        self.confirm.assert_called_once_with(TASK_ID, "batch-admin")
        self.preview.assert_not_called()
