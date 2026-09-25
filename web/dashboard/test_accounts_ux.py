"""Account forms keep drafts in place without weakening identity checks."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from control_plane.client import AgentError


CURRENT_PASSWORD = "unique-owner-auth-password-2026"
NEW_PASSWORD = "unique-new-management-password-2026"


class AccountsUXTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model()
        cls.owner = users.objects.create_superuser(username="accounts-owner", password=CURRENT_PASSWORD)
        cls.target = users.objects.create_user(username="accounts-operator", password=NEW_PASSWORD, is_staff=True)
        cls.viewer = users.objects.create_user(username="accounts-viewer", password=NEW_PASSWORD)

    def setUp(self):
        self.client.force_login(self.owner)
        self.url = reverse("accounts")
        patcher = patch("dashboard.views.record_audit_event")
        self.audit = patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, operation="create", *, ajax=True, **extra):
        data = {
            "operation": operation, "username": "new-operator", "role": "admin",
            "new_password": NEW_PASSWORD, "current_password": CURRENT_PASSWORD,
            "confirmed": "yes", "user_id": self.target.pk,
            **extra,
        }
        return self.client.post(self.url, data, HTTP_ACCEPT="application/json" if ajax else "text/html")

    def assertNoPasswords(self, response):
        for secret in (CURRENT_PASSWORD, NEW_PASSWORD):
            self.assertNotContains(response, secret, status_code=response.status_code)
        self.assertNotIn("new_password", self.client.session)
        self.assertNotIn("current_password", self.client.session)

    def test_create_returns_safe_json_without_navigation(self):
        response = self.post()
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertTrue(result["ok"])
        self.assertEqual(result["operation"], "create")
        self.assertEqual(result["account"]["username"], "new-operator")
        self.assertEqual(result["account"]["role"], "admin")
        self.assertNotIn("Location", response)
        self.assertIn("no-store", response["Cache-Control"])
        user = get_user_model().objects.get(username="new-operator")
        self.assertTrue(user.check_password(NEW_PASSWORD))
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.audit.assert_called_once_with("account_create", "accounts-owner")
        self.assertNoPasswords(response)

    def test_invalid_current_password_keeps_create_values_in_html(self):
        response = self.post(ajax=False, current_password="wrong", username="typed-identity", role="viewer")
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, 'value="typed-identity"', status_code=400)
        self.assertContains(response, 'value="viewer" selected', status_code=400)
        self.assertNotContains(response, 'value="wrong"', status_code=400)
        self.assertNotIn("Location", response)
        self.assertNoPasswords(response)
        self.assertFalse(get_user_model().objects.filter(username="typed-identity").exists())
        self.audit.assert_not_called()

    def test_validation_errors_return_json_and_do_not_leak_form_values(self):
        cases = (
            {"current_password": "wrong"}, {"confirmed": "no"},
            {"new_password": "short"}, {"role": "root"}, {"username": "invalid/name"},
            {"username": self.target.username},
        )
        for extra in cases:
            with self.subTest(extra=list(extra)):
                response = self.post(**extra)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(set(response.json()), {"ok", "error"})
                self.assertFalse(response.json()["ok"])
                self.assertNoPasswords(response)
        self.audit.assert_not_called()

    def test_html_escapes_retained_username(self):
        response = self.post(ajax=False, username='"><script>alert(1)</script>')
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "&lt;script&gt;", status_code=400)
        self.assertNotContains(response, "<script>alert(1)</script>", status_code=400)

    def test_legacy_success_still_redirects(self):
        response = self.post(ajax=False)
        self.assertRedirects(response, self.url, fetch_redirect_response=False)

    def test_reset_failure_leaves_matching_details_open_without_password_values(self):
        response = self.post("reset_password", ajax=False, new_password="short")
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, '<details open>\n              <summary class="copy-button">重置密码</summary>', status_code=400)
        self.assertNoPasswords(response)
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password(NEW_PASSWORD))
        self.audit.assert_not_called()

    def test_toggle_failure_preserves_open_operation(self):
        response = self.post("disable", ajax=False, current_password="wrong")
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, 'data-account-toggle open', status_code=400)
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)

    def test_enable_disable_updates_only_target_with_same_role(self):
        for operation, active in (("disable", False), ("enable", True)):
            with self.subTest(operation=operation):
                response = self.post(operation)
                self.assertEqual(response.status_code, 200)
                account = response.json()["account"]
                self.assertEqual(account["id"], self.target.pk)
                self.assertEqual(account["is_active"], active)
                self.assertEqual(account["role"], "admin")
                self.target.refresh_from_db()
                self.assertEqual(self.target.is_active, active)
                self.owner.refresh_from_db()
                self.assertTrue(self.owner.is_active)

    def test_cannot_disable_current_user(self):
        response = self.post("disable", user_id=self.owner.pk)
        self.assertEqual(response.status_code, 400)
        self.assertIn("不能停用当前", response.json()["error"])
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.is_active)
        self.audit.assert_not_called()

    def test_last_active_superuser_safety_check_remains(self):
        # A stale request identity must not bypass the DB's last-superuser check.
        other = get_user_model().objects.create_superuser(username="last-superuser", password=NEW_PASSWORD)
        get_user_model().objects.filter(pk=self.owner.pk).update(is_active=False)
        from django.test import RequestFactory
        from dashboard.views import accounts
        request = RequestFactory().post(self.url, {
            "operation": "disable", "user_id": other.pk, "confirmed": "yes",
            "current_password": CURRENT_PASSWORD,
        }, HTTP_ACCEPT="application/json")
        request.user = self.owner
        response = accounts(request)
        self.assertEqual(response.status_code, 400)
        import json
        self.assertIn("必须至少保留", json.loads(response.content)["error"])
        other.refresh_from_db()
        self.assertTrue(other.is_active)

    def test_reset_password_preserves_current_session_and_invalidates_another(self):
        other_session = Client()
        other_session.force_login(self.owner)
        response = self.post("reset_password", user_id=self.owner.pk)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["account"]["is_current"])
        self.assertEqual(self.client.get(self.url).status_code, 200)
        self.assertEqual(other_session.get(self.url).status_code, 302)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password(NEW_PASSWORD))
        self.assertNoPasswords(response)

    def test_audit_failure_rolls_back_and_returns_retryable_error(self):
        for error in (AgentError("private diagnostic"), OSError("private socket")):
            with self.subTest(error=type(error)):
                self.audit.side_effect = error
                response = self.post()
                self.assertEqual(response.status_code, 503)
                self.assertIn("已回滚", response.json()["error"])
                self.assertNotContains(response, str(error), status_code=503)
                self.assertFalse(get_user_model().objects.filter(username="new-operator").exists())
                self.assertNoPasswords(response)

    def test_audit_failure_rolls_back_password_reset_and_keeps_session(self):
        self.audit.side_effect = AgentError("offline")
        response = self.post("reset_password", user_id=self.owner.pk)
        self.assertEqual(response.status_code, 503)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password(CURRENT_PASSWORD))
        self.assertEqual(self.client.get(self.url).status_code, 200)

    def test_viewer_and_admin_cannot_use_json_account_actions(self):
        for user in (self.viewer, self.target):
            with self.subTest(user=user.username):
                self.client.force_login(user)
                response = self.post(current_password=NEW_PASSWORD)
                self.assertEqual(response.status_code, 403)
                self.assertFalse(response.json()["ok"])
        self.audit.assert_not_called()

    def test_bad_action_or_target_never_changes_accounts(self):
        for operation, identifier in (("delete", self.target.pk), ("disable", "bad"),
                                      ("reset_password", 999999), ("disable", "9" * 80)):
            with self.subTest(operation=operation, identifier=identifier):
                response = self.post(operation, user_id=identifier)
                self.assertEqual(response.status_code, 400)
        self.audit.assert_not_called()

    def test_ajax_still_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.owner)
        response = client.post(self.url, {
            "operation": "disable", "user_id": self.target.pk,
            "current_password": CURRENT_PASSWORD, "confirmed": "yes",
        }, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 403)
        self.audit.assert_not_called()

    def test_html_always_renders_blank_password_inputs(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'src="/static/accounts.js"')
        self.assertContains(response, 'data-account-form')
        self.assertNoPasswords(response)
        from html.parser import HTMLParser
        class PasswordParser(HTMLParser):
            def handle_starttag(inner_self, tag, attrs):
                values = dict(attrs)
                if tag == "input" and values.get("type") == "password":
                    self.assertNotIn("value", values)
        PasswordParser().feed(response.content.decode())
