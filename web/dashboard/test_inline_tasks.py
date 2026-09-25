"""Same-page bridge preserves existing confirmation and ownership boundaries."""
import copy
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from control_plane.client import AgentError


TASK_ID = "task-" + "c" * 32
TASK = {"id": TASK_ID, "actor": "inline-owner", "action": "network.node.domains",
        "state": "waiting_confirmation", "terminal": False, "preview": {"facts": {}}}


class InlineTaskTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = get_user_model().objects.create_superuser("inline-owner", password="not-real-password-2026")
        cls.viewer = get_user_model().objects.create_user("inline-viewer", password="not-real-password-2026")

    def setUp(self):
        self.client.force_login(self.owner)
        self.execute = reverse("inline-task-execute")
        self.status = reverse("inline-task-status", args=[TASK_ID])
        self.read_patch = patch("dashboard.inline_tasks.change_task", return_value=copy.deepcopy(TASK))
        self.confirm_patch = patch("dashboard.inline_tasks.confirm_change_task", return_value={**TASK, "state": "queued"})
        self.read = self.read_patch.start()
        self.confirm = self.confirm_patch.start()
        self.addCleanup(self.read_patch.stop)
        self.addCleanup(self.confirm_patch.stop)

    def post(self, data=None):
        return self.client.post(self.execute, data or {"task_id": TASK_ID}, content_type="application/json")

    def test_own_preview_confirmation_and_status_are_json_and_no_store(self):
        result = self.post()
        self.assertEqual(result.status_code, 200)
        self.confirm.assert_called_once_with(TASK_ID, self.owner.username)
        self.assertEqual(result.json()["status_url"], self.status)
        self.assertIn("no-store", result["Cache-Control"])
        self.assertNotIn("Location", result)
        self.assertEqual(self.client.get(self.status).json()["task"]["id"], TASK_ID)

    def test_pending_completed_retries_never_reconfirm(self):
        for state in ("queued", "running", "succeeded", "failed", "invalidated", "expired"):
            self.read.return_value = {**TASK, "state": state}
            self.assertEqual(self.post().status_code, 200)
        self.confirm.assert_not_called()

    def test_foreign_and_high_risk_tasks_are_never_confirmed(self):
        for task in ({**TASK, "actor": "somebody-else"}, {**TASK, "id": "task-" + "d" * 32},
                     *({**TASK, "action": action} for action in ("network.public_endpoint.apply", "backup.restore_apply", "security.ssh_auth.apply", "network.node.awg.remove", "network.permission.batch"))):
            self.read.return_value = task
            self.assertEqual(self.post().status_code, 404)
            self.assertEqual(self.client.get(self.status).status_code, 404)
        self.confirm.assert_not_called()

    def test_viewer_and_logged_out_requests_do_not_reach_agent(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.post().status_code, 403)
        self.assertEqual(self.client.get(self.status).status_code, 403)
        self.client.logout()
        for result in (self.post(), self.client.get(self.status)):
            self.assertEqual(result.status_code, 401)
            self.assertEqual(result["Content-Type"], "application/json")
            self.assertIn("no-store", result["Cache-Control"])
        self.read.assert_not_called()

    def test_bad_payload_and_method_do_not_reach_agent(self):
        for body in ('{', '[]', '{}', '{"task_id":2}', '{"task_id":"bad"}', '{"task_id":"' + TASK_ID + '","confirmed":true}'):
            self.assertEqual(self.client.post(self.execute, body, content_type="application/json").status_code, 400)
        self.assertEqual(self.client.post(self.execute, {"task_id": TASK_ID}).status_code, 400)
        self.assertEqual(self.client.get(self.execute).status_code, 405)
        self.assertEqual(self.client.post(self.status).status_code, 405)
        self.read.assert_not_called()

    def test_csrf_is_required(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.owner)
        self.assertEqual(client.post(self.execute, {"task_id": TASK_ID}, content_type="application/json").status_code, 403)
        self.read.assert_not_called()

    def test_agent_outage_is_not_success_or_auto_retry(self):
        self.read.side_effect = AgentError("agent_unavailable", "private details")
        result = self.post()
        self.assertEqual(result.status_code, 503)
        self.assertNotContains(result, "private details", status_code=503)
        self.confirm.assert_not_called()

    def test_all_allowlisted_task_types_supported(self):
        for action in ("network.node.domains", "network.address.domains", "network.proxy.update", "network.permission.deny"):
            self.read.return_value = {**TASK, "action": action}
            self.assertEqual(self.post().status_code, 200)
