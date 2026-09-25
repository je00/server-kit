"""Unavailable-agent UX must preserve HTTP semantics and never resubmit work."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from control_plane.client import AgentError


class TaskErrorPageTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="demo", password="test-only-password")
        self.client.force_login(user)

    @patch("dashboard.views.change_task", side_effect=AgentError("unavailable", "agent_error"))
    def test_agent_failure_keeps_navigation_and_read_only_retry(self, request):
        task_id = "task-" + "a" * 32
        response = self.client.get(f"/tasks/{task_id}/")
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "不代表任务失败", status_code=503)
        self.assertContains(response, f'href="/tasks/{task_id}/"', status_code=503)
        self.assertContains(response, 'id="main-content"', status_code=503)
        self.assertContains(response, 'href="/audit/"', status_code=503)
        self.assertNotContains(response, 'data-task-refresh', status_code=503)
        self.assertNotContains(response, 'action="/tasks/', status_code=503)
        self.assertIn("no-store", response["Cache-Control"])


class PartialSnapshotPageTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_superuser(username="demo-admin", password="test-only-password")
        self.client.force_login(user)

    @patch("dashboard.views.manage_backup")
    def test_backup_list_failure_does_not_hide_pending_restore(self, manage):
        def read(operation, _actor):
            if operation == "list":
                raise AgentError("Unavailable")
            return {"state": "pending", "remaining_seconds": 220, "writes_enabled": True}
        manage.side_effect = read
        response = self.client.get("/backups/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["backups_error"])
        self.assertFalse(response.context["restore_status_error"])
        self.assertContains(response, "等待确认")
        self.assertContains(response, 'value="restore_rollback"')

    @patch("dashboard.views.manage_backup")
    def test_unknown_restore_status_is_not_idle(self, manage):
        def read(operation, _actor):
            if operation == "restore_status":
                raise AgentError("Unavailable")
            return {"items": []}
        manage.side_effect = read
        response = self.client.get("/backups/")
        self.assertEqual(response.context["restore_transaction"]["state"], "unknown")
        self.assertTrue(response.context["restore_status_error"])
        self.assertNotContains(response, 'value="restore_apply"')
        self.assertNotContains(response, 'value="restore_confirm"')

    @patch("dashboard.views.audit_log", side_effect=AgentError("Unavailable"))
    @patch("dashboard.views.change_tasks", return_value={"items": [{
        "id": "task-" + "b" * 32, "preview": {"title": "演示任务仍在运行"},
        "actor": "demo-admin", "state_label": "运行中",
    }]})
    def test_audit_failure_does_not_hide_active_tasks(self, _tasks, _audit):
        response = self.client.get("/audit/")
        self.assertTrue(response.context["audit_error"])
        self.assertFalse(response.context["tasks_error"])
        self.assertContains(response, "演示任务仍在运行")
