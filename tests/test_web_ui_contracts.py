#!/usr/bin/env python3
"""Offline browser-behaviour regressions; no VPS, network, or third-party DOM package."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("node"), "Node.js is needed for browser behaviour tests")
class WebUiContractsTests(unittest.TestCase):
    def run_contract(self, name: str) -> None:
        result = subprocess.run(
            ["node", str(ROOT / "tests" / "web_ui_contracts.js"), name],
            cwd=ROOT, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_theme_works_with_disabled_storage(self) -> None:
        self.run_contract("theme-storage-disabled")

    def test_theme_restores_only_supported_values(self) -> None:
        self.run_contract("theme-restore")

    def test_generated_configuration_handles_disabled_session_storage(self) -> None:
        self.run_contract("bundle-storage-disabled")

    def test_expired_generated_configuration_is_removed(self) -> None:
        self.run_contract("bundle-expired")

    def test_malformed_generated_configuration_is_discarded(self) -> None:
        self.run_contract("bundle-malformed")

    def test_generated_configuration_expires_without_a_page_reload(self) -> None:
        self.run_contract("bundle-live-expiration")

    def test_modal_returns_focus_and_traps_keyboard_navigation(self) -> None:
        self.run_contract("modal-focus")

    def test_closing_sensitive_modals_removes_secret_material(self) -> None:
        self.run_contract("modal-secret-cleanup")

    def test_duplicate_submit_guard_keeps_clicked_operation_in_payload(self) -> None:
        self.run_contract("form-submit-payload")

    def test_cancelled_validation_does_not_lock_the_form(self) -> None:
        self.run_contract("form-validation-cancelled")

    def test_logout_discards_temporary_client_configuration(self) -> None:
        self.run_contract("logout-clears-bundle")

    def test_list_filter_is_case_insensitive_and_escape_restores_items(self) -> None:
        self.run_contract("list-filter")

    def test_task_poll_updates_content_every_five_seconds_without_navigation(self) -> None:
        self.run_contract("task-poll-interval")

    def test_task_poll_pause_resume_preserves_toggle_focus(self) -> None:
        self.run_contract("task-poll-pause-resume")

    def test_task_poll_respects_selection_before_and_during_requests(self) -> None:
        self.run_contract("task-poll-selection")

    def test_task_poll_errors_preserve_existing_content(self) -> None:
        self.run_contract("task-poll-errors")

    def test_time_labels_follow_browser_timezone_and_keep_original(self) -> None:
        self.run_contract("local-time")


if __name__ == "__main__":
    unittest.main()
