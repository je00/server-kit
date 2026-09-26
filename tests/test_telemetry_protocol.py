"""Live sampling is one registered, parameter-free read, not a change task."""

import unittest
from unittest.mock import Mock

from control_plane.actions import ActionKind, validate_action_request
from control_plane.core import ControlPlane


class TelemetryProtocolTests(unittest.TestCase):
    def test_catalog_marks_sampling_as_read_only(self):
        definition = validate_action_request("network.telemetry", {})
        self.assertEqual(definition.kind, ActionKind.READ)
        self.assertFalse(definition.task_only)

    def test_sampling_uses_telemetry_not_full_overview(self):
        runner = Mock()
        runner.network_telemetry.return_value = {"schema_version": 1, "nodes": []}
        plane = ControlPlane(runner, {123})
        result = plane.handle({"version": 1, "request_id": "live-sample",
                               "action": "network.telemetry", "params": {}}, 123)
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"], runner.network_telemetry.return_value)
        runner.network_telemetry.assert_called_once_with()
        runner.network_overview.assert_not_called()

    def test_untrusted_identity_or_parameters_never_sample(self):
        for uid, params in ((456, {}), (123, {"interface": "arbitrary"}), (123, {"reset": True})):
            with self.subTest(uid=uid, params=params):
                runner = Mock()
                response = ControlPlane(runner, {123}).handle({"version": 1, "request_id": "live-sample",
                                                             "action": "network.telemetry", "params": params}, uid)
                self.assertFalse(response["ok"])
                runner.network_telemetry.assert_not_called()


if __name__ == "__main__":
    unittest.main()
