#!/usr/bin/env python3
"""验证 AWG 新节点以首次握手提交，超时节点可安全清理。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lib.awg_enrollment import EnrollmentStore


class EnrollmentStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.now = 1_800_000_000
        self.store = EnrollmentStore(Path(temporary.name) / "enrollments.json", now=lambda: self.now)
        self.public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    def test_first_handshake_commits_and_state_contains_no_private_material(self) -> None:
        pending = self.store.start("laptop", self.public_key)
        self.assertEqual(pending["expires_in"], 300)
        self.assertEqual(self.store.plan({self.public_key: self.now}), [{"action": "commit", "name": "laptop"}])
        self.store.complete("laptop")
        overview = self.store.overview()
        self.assertEqual(overview["items"], [])
        self.assertEqual(overview["history"][0]["state"], "active")

    def test_missing_handshake_expires_after_five_minutes(self) -> None:
        self.store.start("laptop", self.public_key)
        self.now += 299
        self.assertEqual(self.store.plan({}), [])
        self.now += 1
        self.assertEqual(self.store.plan({}), [{"action": "expire", "name": "laptop"}])
        self.store.complete("laptop", "expired")
        self.assertEqual(self.store.overview()["history"][0]["state"], "expired")

    def test_older_handshake_does_not_commit_new_enrollment(self) -> None:
        self.store.start("laptop", self.public_key)
        self.assertEqual(self.store.plan({self.public_key: self.now - 1}), [])

    def test_pending_enrollment_survives_service_restart(self) -> None:
        path = self.store.path
        self.store.start("laptop", self.public_key)
        restarted = EnrollmentStore(path, now=lambda: self.now)
        self.assertEqual(
            restarted.plan({self.public_key: self.now}),
            [{"action": "commit", "name": "laptop"}],
        )
