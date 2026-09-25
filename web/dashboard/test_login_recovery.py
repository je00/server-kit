"""A stale login tab must not turn an established session into a 403 page."""

from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from .services import read_host


class LoginRecoveryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="login-demo", password="Local-test-password-2026!"
        )

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.client.get("/login/")
        self.old_token = self.client.cookies[settings.CSRF_COOKIE_NAME].value
        self.form = {
            "username": self.user.username,
            "password": "Local-test-password-2026!",
            "csrfmiddlewaretoken": self.old_token,
            "next": "/guides/nodes/?platform=linux#linux",
        }

    def login(self):
        response = self.client.post("/login/", self.form, HTTP_ORIGIN="http://testserver")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], self.form["next"])
        self.assertNotEqual(self.old_token, self.client.cookies[settings.CSRF_COOKIE_NAME].value)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

    def test_normal_login_with_csrf_keeps_deep_link(self):
        self.login()

    def test_stale_login_recovers_without_authenticating_or_rotating_session_again(self):
        self.login()
        session_key = self.client.session.session_key
        token = self.client.cookies[settings.CSRF_COOKIE_NAME].value
        with patch("django.contrib.auth.views.auth_login") as authenticate_again:
            response = self.client.post("/login/", self.form, HTTP_ORIGIN="http://testserver")
        authenticate_again.assert_not_called()
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response["Location"], self.form["next"])
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(self.client.session.session_key, session_key)
        self.assertEqual(self.client.cookies[settings.CSRF_COOKIE_NAME].value, token)
        self.assertEqual(self.client.get(response["Location"]).status_code, 200)

    def test_same_origin_referer_can_recover_when_origin_is_absent(self):
        self.login()
        response = self.client.post("/login/", self.form, HTTP_REFERER="http://testserver/login/")
        self.assertEqual(response.status_code, 303)

    def test_anonymous_bad_csrf_does_not_authenticate(self):
        response = self.client.post("/login/", {**self.form, "csrfmiddlewaretoken": "x" * 32},
                                    HTTP_ORIGIN="http://testserver")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_valid_csrf_wrong_password_remains_on_login(self):
        response = self.client.post("/login/", {**self.form, "password": "incorrect"},
                                    HTTP_ORIGIN="http://testserver")
        self.assertContains(response, "用户名或密码不正确")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_stale_login_requires_exact_same_origin(self):
        self.login()
        for headers in (
            {}, {"HTTP_ORIGIN": "null"}, {"HTTP_ORIGIN": "http://evil.example"},
            {"HTTP_ORIGIN": "http://testserver:9999"},
            {"HTTP_ORIGIN": "http://evil.example", "HTTP_REFERER": "http://testserver/login/"},
            {"HTTP_REFERER": "http://testserver.evil.example/login/"},
            {"HTTP_REFERER": "http://testserver@evil.example/login/"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.client.post("/login/", self.form, **headers).status_code, 403)

    def test_stale_login_cannot_switch_accounts(self):
        self.login()
        response = self.client.post("/login/", {**self.form, "username": "someone-else"},
                                    HTTP_ORIGIN="http://testserver")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

    def test_other_stale_forms_are_rejected_and_never_replayed(self):
        self.login()
        with patch("dashboard.views.preview_change_task") as change:
            response = self.client.post("/services/ssh/actions/preview/", self.form,
                                        HTTP_ORIGIN="http://testserver")
        self.assertEqual(response.status_code, 403)
        change.assert_not_called()

    def test_recovery_rejects_external_redirects(self):
        self.login()
        for target in ("https://evil.example/", "//evil.example/", "javascript:alert(1)"):
            with self.subTest(target=target):
                response = self.client.post("/login/", {**self.form, "next": target},
                                            HTTP_ORIGIN="http://testserver")
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response["Location"], "/")

    def test_authenticated_login_never_redirects_back_to_auth_endpoints(self):
        self.login()
        for target in (
            "/login/", "/login/?next=/login/", "/login", "/logout/", "http://testserver/login/",
            "#section", "?next=%23section", "/network/../login/", "/log%69n/",
        ):
            with self.subTest(target=target):
                response = self.client.get("/login/", {"next": target})
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response["Location"], "/")
                response = self.client.post("/login/", {**self.form, "next": target},
                                            HTTP_ORIGIN="http://testserver")
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response["Location"], "/")

    @patch("dashboard.services.AgentClient")
    def test_home_read_allows_the_collectors_fifteen_second_deadline(self, client):
        client.return_value.request.return_value = {"view": {"services": []}}
        self.assertEqual(read_host("overview"), {"services": []})
        timeout = client.call_args.kwargs.get("timeout", 5.0)
        self.assertGreater(timeout, 15.0)
        self.assertLessEqual(timeout, 30.0)
        client.return_value.request.assert_called_once_with("host.read", {"intent": "overview", "service_id": ""})

    @patch("dashboard.views.read_snapshot", side_effect=TimeoutError("synthetic slow collector"))
    def test_unavailable_collector_keeps_the_dashboard_and_session(self, snapshot):
        self.login()
        response = self.client.get("/")
        self.assertContains(response, "无法加载当前状态")
        self.assertContains(response, 'href="/network/nodes/"')
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

    @patch("dashboard.services.AgentClient")
    def test_cold_deep_link_transport_error_keeps_page_navigation(self, client):
        self.login()
        client.return_value.request.side_effect = TimeoutError("synthetic slow collector")
        response = self.client.get("/network/nodes/")
        self.assertContains(response, "暂时无法读取节点与订阅状态")
        self.assertContains(response, 'href="/"')
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))
