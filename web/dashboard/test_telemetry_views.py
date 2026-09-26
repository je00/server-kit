"""Live rates stay read-only, strictly typed, and credential-free."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from control_plane.client import AgentError


PAYLOAD = {"schema_version": 1, "sampled_at": "2026-09-25T18:00:00+00:00",
           "refresh_ms": 2000, "stale_after_ms": 8000,
           "nodes": [{"id": "awg:desktop", "state": "recent", "last_seen_at": 1790359190,
                      "upload_bps": 1024.5, "download_bps": 2048.0, "rate_status": "ok", "source": "awg"},
                     {"id": "vless:phone", "state": "unsupported", "last_seen_at": None,
                      "upload_bps": None, "download_bps": None, "rate_status": "unavailable", "source": "none"}]}


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class TelemetryViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model().objects
        cls.users = [users.create_user("rate-viewer", password="test-only-password"),
                     users.create_user("rate-staff", password="test-only-password", is_staff=True),
                     users.create_superuser("rate-owner", password="test-only-password")]

    def setUp(self):
        self.url = reverse("network-telemetry")
        self.client.force_login(self.users[0])
        self.now = datetime(2026, 9, 25, 18, tzinfo=timezone.utc)
        clock = patch("dashboard.telemetry_views.server_now", return_value=self.now)
        self.clock = clock.start()
        self.addCleanup(clock.stop)

    @patch("dashboard.telemetry_views.network_telemetry", return_value=PAYLOAD)
    def test_all_roles_read_one_lightweight_snapshot_without_config_or_writes(self, read):
        with patch("dashboard.services.network_overview", side_effect=AssertionError("must not read config")):
            for user in self.users:
                self.client.force_login(user)
                read.reset_mock()
                response = self.client.get(self.url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), {**PAYLOAD, "sample_age_ms": 0})
                self.assertIn("no-store", response["Cache-Control"])
                read.assert_called_once_with()

    @patch("dashboard.telemetry_views.network_telemetry")
    def test_authentication_and_get_only(self, read):
        for method in ("post", "put", "patch", "delete"):
            self.assertEqual(getattr(self.client, method)(self.url).status_code, 405)
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)
        read.assert_not_called()

    @patch("dashboard.telemetry_views.network_telemetry")
    def test_private_fields_never_escape_the_projection(self, read):
        packet = deepcopy(PAYLOAD)
        packet["private_key"] = "sensitive-sentinel"
        packet["nodes"][0].update(uuid="sensitive-sentinel", public_key="sensitive-sentinel",
                                  token="sensitive-sentinel", command_stderr="sensitive-sentinel")
        read.return_value = packet
        self.assertEqual(self.client.get(self.url).json(), {**PAYLOAD, "sample_age_ms": 0})
        self.assertIn("private_key", packet)

    @patch("dashboard.telemetry_views.network_telemetry")
    def test_bad_and_unavailable_samples_are_not_zero_traffic(self, read):
        packets = [None, {}, {**PAYLOAD, "schema_version": True}, {**PAYLOAD, "sampled_at": "2026-09-25"},
                   {**PAYLOAD, "refresh_ms": 0}, {**PAYLOAD, "nodes": PAYLOAD["nodes"] * 2}]
        for update in ({"upload_bps": -1}, {"upload_bps": True}, {"upload_bps": float("nan")},
                       {"download_bps": float("inf")}, {"id": "awg:../private"}, {"rate_status": "unavailable"},
                       {"state": "unsupported"}, {"state": "disabled"}, {"source": "xray"},
                       {"last_seen_at": False}, {"last_seen_at": -1}):
            packet = deepcopy(PAYLOAD)
            packet["nodes"][0].update(update)
            packets.append(packet)
        for packet in packets:
            with self.subTest(packet=packet):
                read.return_value = packet
                response = self.client.get(self.url)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["code"], "telemetry_unavailable")
                self.assertNotIn("nodes", response.json())
                self.assertIn("no-store", response["Cache-Control"])

    @patch("dashboard.telemetry_views.network_telemetry")
    def test_errors_never_expose_host_details(self, read):
        for error in (AgentError("private-secret", "offline"), OSError("private-secret"), RuntimeError("private-secret")):
            read.side_effect = error
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("private-secret", response.content.decode())

    @patch("dashboard.telemetry_views.network_telemetry")
    def test_initial_reset_and_valid_zero_are_distinct(self, read):
        for rate_status in ("warming_up", "reset", "unavailable"):
            packet = deepcopy(PAYLOAD)
            packet["nodes"][0].update(rate_status=rate_status, upload_bps=None, download_bps=None)
            read.return_value = packet
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)
            self.assertIsNone(response.json()["nodes"][0]["upload_bps"])
        packet["nodes"][0].update(rate_status="ok", upload_bps=0, download_bps=0)
        read.return_value = packet
        self.assertEqual(self.client.get(self.url).json()["nodes"][0]["upload_bps"], 0)

    @patch("dashboard.telemetry_views.network_telemetry", return_value=PAYLOAD)
    def test_age_is_computed_on_vps_and_advances_for_a_cached_sample(self, read):
        for milliseconds in (0, 1950, 8000, 30000, 90_000_000):
            self.clock.return_value = self.now + timedelta(milliseconds=milliseconds)
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["sample_age_ms"], min(milliseconds, 86_400_000))
            self.assertEqual(response.json()["sampled_at"], PAYLOAD["sampled_at"])

    @patch("dashboard.telemetry_views.network_telemetry")
    def test_age_is_server_owned_and_timezone_independent(self, read):
        packet = deepcopy(PAYLOAD)
        packet.update(sampled_at="2026-09-26T02:00:00+08:00", sample_age_ms=999999)
        read.return_value = packet
        self.assertEqual(self.client.get(self.url).json()["sample_age_ms"], 0)
        # Tiny server clock adjustments cannot generate invalid negative ages.
        self.clock.return_value = self.now - timedelta(milliseconds=1)
        self.assertEqual(self.client.get(self.url).json()["sample_age_ms"], 0)
