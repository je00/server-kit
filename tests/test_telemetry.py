#!/usr/bin/env python3
"""Fast live telemetry must stay bounded, read-only, scoped and honest."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from control_plane.runner import ScriptRunner
from lib.server_kit_telemetry import (
    AWGTelemetryCollector, CounterObservation, MAX_INPUT_BYTES,
    NetworkTelemetrySampler, TelemetryPaths, bounded_command,
)


KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="
NOW = 1_800_000_000
BOOT = "11111111-2222-3333-4444-555555555555"


class TelemetryCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.paths = TelemetryPaths(
            manager_state=self.root / "manager.conf",
            awg_active=self.root / "peers.tsv",
            awg_disabled=self.root / "disabled.tsv",
            awg_enrollments=self.root / "enrollments.json",
            vless_policy=self.root / "vless.json",
            sys_class_net=self.root / "net",
            boot_id=self.root / "boot_id",
        )
        (self.paths.sys_class_net / "awg0").mkdir(parents=True)
        (self.paths.sys_class_net / "awg0" / "ifindex").write_text("7\n")
        self.paths.manager_state.write_text("AWG_IFACE=awg0\n")
        self.paths.boot_id.write_text(BOOT + "\n")
        self.paths.awg_active.write_text("desk\t10.20.0.2\nphone\t10.20.0.3\n")
        self.outputs = {
            "allowed-ips": f"{KEY_A}\t10.20.0.2/32\n{KEY_B}\t10.20.0.3/32\n",
            "latest-handshakes": f"{KEY_A}\t{NOW - 30}\n{KEY_B}\t0\n",
            "transfer": f"{KEY_A}\t1000\t4000\n{KEY_B}\t0\t0\n",
        }
        self.command = Mock(side_effect=lambda args: self.outputs[args[-1]])
        self.collector = AWGTelemetryCollector(self.paths, self.command)

    def rows(self) -> dict[str, CounterObservation]:
        return {row.id: row for row in self.collector.collect(NOW)}

    def assertUnknown(self, rows: dict[str, CounterObservation], node: str = "awg:desk") -> None:
        self.assertEqual(rows[node].state, "unknown")
        self.assertIsNone(rows[node].received)
        self.assertIsNone(rows[node].sent)
        self.assertIsNone(rows[node].last_seen_at)

    def test_only_three_fixed_awg_commands_no_inventory_or_dump(self) -> None:
        rows = self.rows()
        self.assertEqual(rows["awg:desk"].state, "recent")
        self.assertEqual(rows["awg:desk"].received, 1000)
        self.assertEqual(rows["awg:desk"].sent, 4000)
        self.assertEqual(rows["awg:phone"].state, "never")
        self.assertEqual(self.command.call_args_list, [
            unittest.mock.call(["awg", "show", "awg0", "allowed-ips"]),
            unittest.mock.call(["awg", "show", "awg0", "latest-handshakes"]),
            unittest.mock.call(["awg", "show", "awg0", "transfer"]),
        ])

    def test_current_interface_is_read_each_sample_and_never_shell_evaluated(self) -> None:
        for value in ('"awg0"', "'awg0'", "awg0"):
            self.paths.manager_state.write_text(f"AWG_IFACE={value}\n")
            self.assertEqual(self.rows()["awg:desk"].state, "recent")
        for value in ("../awg0", "awg0;echo secret", "$(id)", "-x", "a" * 16, "", "awg0\nAWG_IFACE=other"):
            with self.subTest(value=value):
                self.command.reset_mock()
                self.paths.manager_state.write_text(f"AWG_IFACE={value}\n")
                self.assertUnknown(self.rows())
                self.command.assert_not_called()

    def test_interface_identity_missing_or_changed_during_read_is_unknown(self) -> None:
        self.paths.boot_id.unlink()
        self.assertUnknown(self.rows())
        self.command.assert_not_called()
        self.paths.boot_id.write_text(BOOT)
        def changing(args):
            if args[-1] == "transfer":
                (self.paths.sys_class_net / "awg0" / "ifindex").write_text("8")
            return self.outputs[args[-1]]
        self.command.side_effect = changing
        self.assertUnknown(self.rows())

    def test_recent_boundary_idle_never_and_future_handshakes(self) -> None:
        for age, state in ((0, "recent"), (180, "recent"), (181, "idle"), (NOW, "never"), (-60, "unknown")):
            with self.subTest(age=age):
                self.outputs["latest-handshakes"] = f"{KEY_A}\t{NOW - age}\n"
                self.assertEqual(self.rows()["awg:desk"].state, state)

    def test_disabled_and_pending_are_null_even_if_kernel_has_counters(self) -> None:
        self.paths.awg_disabled.write_text("desk\t10.20.0.2\n")
        self.paths.awg_enrollments.write_text(json.dumps({"schema_version": 1, "items": {"phone": {"public_key": KEY_B}}}))
        rows = self.rows()
        self.assertEqual(rows["awg:desk"].state, "disabled")
        self.assertEqual(rows["awg:phone"].state, "pending")
        self.assertTrue(all(row.received is None and row.sent is None for row in rows.values()))

    def test_disabled_only_and_vless_do_not_run_awg_commands(self) -> None:
        self.paths.awg_active.write_text("")
        self.paths.awg_disabled.write_text("desk\t10.20.0.2\n")
        self.paths.vless_policy.write_text(json.dumps({"clients": {
            "phone": {"enabled": True, "uuid": "SECRET-UUID"},
            "old-phone": {"enabled": False}, "invalid name": {}, "invalid": "not an object",
        }}))
        rows = self.rows()
        self.assertEqual(set(rows), {"awg:desk", "vless:phone", "vless:old-phone"})
        self.assertEqual(rows["vless:phone"].state, "unsupported")
        self.assertEqual(rows["vless:old-phone"].state, "disabled")
        self.assertEqual(rows["vless:phone"].source, "none")
        self.command.assert_not_called()

    def test_errors_timeouts_invalid_or_large_runtime_output_fail_closed(self) -> None:
        for result in (None, "SECRET", "X" * (MAX_INPUT_BYTES + 1), f"{KEY_A}\t-1\n"):
            with self.subTest(result=str(result)[:40]):
                self.outputs["latest-handshakes"] = result
                self.assertUnknown(self.rows())
        for error in (OSError("SECRET"), subprocess.TimeoutExpired("SECRET", 1), ValueError("SECRET")):
            self.command.side_effect = error
            self.assertUnknown(self.rows())

    def test_no_ip_or_key_ambiguity_is_allowed(self) -> None:
        cases = (
            # Broad routes never identify a host.
            f"{KEY_A}\t10.20.0.0/24\n",
            # Two keys claim the same registered host.
            f"{KEY_A}\t10.20.0.2/32\n{KEY_B}\t10.20.0.2/32\n",
            # One key claims two registered nodes.
            f"{KEY_A}\t10.20.0.2/32, 10.20.0.3/32\n",
            # A malformed route is not partially accepted.
            f"{KEY_A}\t10.20.0.2/32, SECRET\n",
            # Duplicated key rows are not silently merged.
            f"{KEY_A}\t10.20.0.2/32\n{KEY_A}\t10.20.0.2/32\n",
            f"{KEY_A}\t(none)\n",
        )
        for value in cases:
            with self.subTest(value=value):
                self.outputs["allowed-ips"] = value
                self.assertUnknown(self.rows())

    def test_duplicate_names_or_registered_addresses_fail_closed(self) -> None:
        for contents in (
            "desk\t10.20.0.2\ndesk\t10.20.0.2\n",
            "desk\t10.20.0.2\nother\t10.20.0.2\n",
            "desk\tinvalid\n",
        ):
            self.paths.awg_active.write_text(contents)
            self.assertUnknown(self.rows())

    def test_disabled_registry_address_conflict_is_not_attributed_to_active_node(self) -> None:
        self.paths.awg_disabled.write_text("old-desk\t10.20.0.2\n")
        rows = self.rows()
        self.assertUnknown(rows)
        self.assertEqual(rows["awg:old-desk"].state, "disabled")

    def test_key_missing_from_any_of_three_reads_is_unknown_not_idle(self) -> None:
        for field in self.outputs:
            with self.subTest(field=field):
                original = self.outputs[field]
                self.outputs[field] = ""
                self.assertUnknown(self.rows())
                self.outputs[field] = original

    def test_negative_noninteger_and_excessive_counters_not_accepted(self) -> None:
        for value in ("-1", "1.5", "nan", "inf", "1e10", "1" * 100, str(1 << 64)):
            with self.subTest(value=value):
                self.outputs["transfer"] = f"{KEY_A}\t{value}\t0\n"
                self.assertUnknown(self.rows())

    def test_corrupt_optional_state_does_not_guess_enabled_or_pending(self) -> None:
        for path, value in ((self.paths.awg_disabled, "invalid name\t10.20.0.2\n"), (self.paths.awg_enrollments, "{")):
            with self.subTest(path=path):
                path.write_text(value)
                self.assertUnknown(self.rows())
                path.unlink()

    def test_host_route_ipv6_supported_without_subnet_containment(self) -> None:
        self.paths.awg_active.write_text("desk\tfd00::2\n")
        self.outputs["allowed-ips"] = f"{KEY_A}\tfd00::2/128\n"
        self.assertEqual(self.rows()["awg:desk"].state, "recent")
        self.outputs["allowed-ips"] = f"{KEY_A}\tfd00::/64\n"
        self.assertUnknown(self.rows())

    def test_registry_files_are_bounded(self) -> None:
        self.paths.manager_state.write_text("A" * (MAX_INPUT_BYTES + 1))
        self.assertUnknown(self.rows())
        self.command.assert_not_called()

    def test_unmanaged_peer_not_projected(self) -> None:
        self.paths.awg_active.write_text("desk\t10.20.0.2\n")
        self.assertEqual(set(self.rows()), {"awg:desk"})


class TelemetrySamplerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = 100.0
        self.wall = float(NOW)
        self.fact = CounterObservation(
            "awg:desk", "recent", NOW - 30, "awg", 100, 200,
            (BOOT, "awg0", "7", KEY_A, "10.20.0.2"),
        )
        self.collector = Mock()
        self.collector.collect.side_effect = lambda now: [self.fact]
        self.sampler = NetworkTelemetrySampler(self.collector, lambda: self.clock, lambda: self.wall)

    def read(self, *, advance: float = 0) -> dict:
        self.clock += advance
        self.wall += advance
        return self.sampler.read()["nodes"][0]

    def test_first_sample_returns_immediately_without_fake_zero(self) -> None:
        with patch("time.sleep", side_effect=AssertionError("must not sleep")):
            result = self.sampler.read()
        self.assertEqual(set(result), {"schema_version", "sampled_at", "refresh_ms", "stale_after_ms", "nodes"})
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["refresh_ms"], 2000)
        self.assertEqual(result["stale_after_ms"], 8000)
        self.assertTrue(result["sampled_at"].endswith("Z"))
        self.assertEqual(result["nodes"][0]["rate_status"], "warming_up")
        self.assertIsNone(result["nodes"][0]["upload_bps"])
        self.assertIsNone(result["nodes"][0]["download_bps"])

    def test_node_upload_uses_server_received_and_download_uses_sent(self) -> None:
        self.read()
        self.fact = replace(self.fact, received=612, sent=2248)
        result = self.read(advance=2)
        self.assertEqual(result["upload_bps"], 256.0)
        self.assertEqual(result["download_bps"], 1024.0)
        self.assertEqual(result["state"], "active")
        self.assertEqual(result["rate_status"], "ok")

    def test_valid_zero_is_distinct_from_unavailable_and_recent_is_not_online(self) -> None:
        self.read()
        result = self.read(advance=2)
        self.assertEqual(result["upload_bps"], 0.0)
        self.assertEqual(result["download_bps"], 0.0)
        self.assertEqual(result["state"], "recent")
        self.fact = replace(self.fact, state="idle")
        self.assertEqual(self.read(advance=2)["state"], "idle")

    def test_cache_does_not_extend_the_sample_time_or_delta_baseline(self) -> None:
        first = self.sampler.read()
        for _ in range(19):
            self.clock += 0.1
            self.assertEqual(self.sampler.read(), first)
        self.assertEqual(self.collector.collect.call_count, 1)
        self.clock = 104.0
        self.fact = replace(self.fact, received=500, sent=1000)
        result = self.sampler.read()["nodes"][0]
        self.assertEqual(result["upload_bps"], 100.0)
        self.assertEqual(result["download_bps"], 200.0)
        self.assertEqual(self.collector.collect.call_count, 2)

    def test_payload_copy_cannot_poison_other_readers(self) -> None:
        result = self.sampler.read()
        result["nodes"][0]["upload_bps"] = 999
        result["nodes"].append({"secret": "x"})
        result["sampled_at"] = "poison"
        fresh = self.sampler.read()
        self.assertEqual(len(fresh["nodes"]), 1)
        self.assertIsNone(fresh["nodes"][0]["upload_bps"])
        self.assertNotEqual(fresh["sampled_at"], "poison")

    def test_many_concurrent_readers_share_a_single_collection(self) -> None:
        entered, release = threading.Event(), threading.Event()
        def collect(now):
            entered.set()
            self.assertTrue(release.wait(2))
            return [self.fact]
        self.collector.collect.side_effect = collect
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(self.sampler.read) for _ in range(10)]
            self.assertTrue(entered.wait(2))
            release.set()
            results = [future.result(timeout=2) for future in futures]
        self.assertEqual(self.collector.collect.call_count, 1)
        self.assertTrue(all(result == results[0] for result in results))

    def test_counter_drop_or_peer_boot_interface_change_resets_without_zero(self) -> None:
        changes = (
            {"received": 0}, {"sent": 0},
            {"identity": ("new-boot", "awg0", "7", KEY_A, "10.20.0.2")},
            {"identity": (BOOT, "awg0", "8", KEY_A, "10.20.0.2")},
            {"identity": (BOOT, "new-iface", "7", KEY_A, "10.20.0.2")},
            {"identity": (BOOT, "awg0", "7", KEY_B, "10.20.0.2")},
            {"identity": (BOOT, "awg0", "7", KEY_A, "10.20.0.4")},
        )
        initial = self.fact
        for change in changes:
            with self.subTest(change=change):
                self.fact = initial
                self.sampler = NetworkTelemetrySampler(self.collector, lambda: self.clock, lambda: self.wall)
                self.read()
                self.fact = replace(initial, **change)
                reset = self.read(advance=2)
                self.assertEqual(reset["rate_status"], "reset")
                self.assertIsNone(reset["upload_bps"])
                self.assertIsNone(reset["download_bps"])
                self.assertEqual(self.read(advance=2)["rate_status"], "ok")

    def test_long_resume_rebaselines_instead_of_displaying_stale_average(self) -> None:
        self.read()
        self.fact = replace(self.fact, received=9000)
        self.assertEqual(self.read(advance=10.1)["rate_status"], "reset")
        self.fact = replace(self.fact, received=9400)
        self.assertEqual(self.read(advance=2)["upload_bps"], 200.0)

    def test_exact_ten_second_interval_is_still_valid(self) -> None:
        self.read()
        self.fact = replace(self.fact, received=1100)
        self.assertEqual(self.read(advance=10)["upload_bps"], 100.0)

    def test_wall_clock_corrections_do_not_change_rate_denominator(self) -> None:
        self.read()
        self.fact = replace(self.fact, received=300)
        self.wall -= 3600
        self.assertEqual(self.read(advance=2)["upload_bps"], 100.0)

    def test_monotonic_clock_reversal_invalidates_cache_and_baseline(self) -> None:
        self.read()
        self.assertEqual(self.read(advance=-1)["rate_status"], "reset")

    def test_unknown_disabled_pending_unsupported_never_show_number(self) -> None:
        initial = self.fact
        for state in ("unknown", "disabled", "pending", "unsupported"):
            with self.subTest(state=state):
                self.fact = initial
                self.read(advance=2)
                self.fact = replace(initial, state=state)
                result = self.read(advance=2)
                self.assertEqual(result["rate_status"], "unavailable")
                self.assertIsNone(result["upload_bps"])
                self.assertIsNone(result["download_bps"])
                self.fact = initial
                self.assertEqual(self.read(advance=2)["rate_status"], "warming_up")

    def test_missing_node_or_counter_drops_baseline(self) -> None:
        self.read()
        original = self.fact
        self.fact = replace(self.fact, received=None)
        self.assertEqual(self.read(advance=2)["rate_status"], "unavailable")
        self.fact = original
        self.assertEqual(self.read(advance=2)["rate_status"], "warming_up")
        self.collector.collect.side_effect = lambda now: []
        self.clock += 2
        self.assertEqual(self.sampler.read()["nodes"], [])
        self.collector.collect.side_effect = lambda now: [self.fact]
        self.assertEqual(self.read(advance=2)["rate_status"], "warming_up")

    def test_public_payload_has_only_documented_fields_and_no_identifiers_or_totals(self) -> None:
        result = self.sampler.read()
        expected = {"id", "state", "last_seen_at", "upload_bps", "download_bps", "rate_status", "source"}
        self.assertEqual(set(result["nodes"][0]), expected)
        serialized = json.dumps(result)
        for value in (KEY_A, BOOT, "10.20.0.2", "awg0", "received", "sent", "identity", "private", "uuid", "email", "hub"):
            self.assertNotIn(value, serialized)


class BoundedTelemetryCommandTests(unittest.TestCase):
    def test_success_and_no_ambient_sensitive_environment(self) -> None:
        with patch.dict("os.environ", {"TELEMETRY_TEST_SECRET": "private"}):
            result = bounded_command([sys.executable, "-c", "import os; print(os.environ.get('TELEMETRY_TEST_SECRET', 'safe'))"])
        self.assertEqual(result, "safe\n")

    def test_failure_stderr_non_utf8_and_missing_command_return_none(self) -> None:
        for arguments in (
            ["/does/not/exist"],
            [sys.executable, "-c", "import sys; print('secret', file=sys.stderr); sys.exit(1)"],
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff')"],
        ):
            self.assertIsNone(bounded_command(arguments))

    def test_output_limit_is_enforced_before_buffering_whole_output(self) -> None:
        self.assertIsNone(bounded_command([sys.executable, "-c", f"import sys; sys.stdout.write('X' * {MAX_INPUT_BYTES + 1})"]))

    def test_timeout_is_at_most_one_second_plus_process_cleanup(self) -> None:
        started = time.monotonic()
        self.assertIsNone(bounded_command([sys.executable, "-c", "import time; time.sleep(10)"]))
        self.assertLess(time.monotonic() - started, 2)

    def test_closed_stdout_does_not_allow_child_to_run_past_timeout(self) -> None:
        started = time.monotonic()
        self.assertIsNone(bounded_command([sys.executable, "-c", "import os,time; os.close(1); time.sleep(10)"]))
        self.assertLess(time.monotonic() - started, 2)


class TelemetryRunnerTests(unittest.TestCase):
    def test_lazy_shared_sampler_does_not_start_manager_or_write_audit(self) -> None:
        executor = Mock(side_effect=AssertionError("manager must not run"))
        runner = ScriptRunner("/opt/server-kit/server-kit-manager.sh", executor=executor)
        with patch("lib.server_kit_telemetry.NetworkTelemetrySampler") as factory:
            factory.return_value.read.return_value = {"schema_version": 1, "nodes": []}
            for _ in range(5):
                self.assertEqual(runner.network_telemetry(), {"schema_version": 1, "nodes": []})
            factory.assert_called_once_with()
            self.assertEqual(factory.return_value.read.call_count, 5)
        executor.assert_not_called()

    def test_concurrent_initialization_still_creates_only_one_sampler(self) -> None:
        runner = ScriptRunner("/opt/server-kit/server-kit-manager.sh")
        with patch("lib.server_kit_telemetry.NetworkTelemetrySampler") as factory:
            factory.return_value.read.return_value = {"schema_version": 1, "nodes": []}
            with ThreadPoolExecutor(max_workers=10) as pool:
                results = list(pool.map(lambda _: runner.network_telemetry(), range(20)))
            factory.assert_called_once_with()
            self.assertEqual(len(results), 20)


if __name__ == "__main__":
    unittest.main()
