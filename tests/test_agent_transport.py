"""A disconnected local client must not stop or replay the management agent."""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from control_plane import agent
from control_plane.core import ControlPlane


class StopServing(Exception):
    """End the otherwise infinite accept loop after the expected connections."""


def request_line(identifier="a"):
    return json.dumps({
        "version": 1, "request_id": identifier * 32,
        "action": "system.snapshot", "params": {},
    }).encode() + b"\n"


class AgentTransportTests(unittest.TestCase):
    @contextmanager
    def server(self, plane, *, connections=2, uid=1001):
        with tempfile.TemporaryDirectory(prefix="sk-agent-", dir="/tmp") as directory:
            path = str(Path(directory) / "socket")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)
            listener.listen(4)
            listener.settimeout(2)
            accepted = []
            errors = []

            class BoundedListener:
                def accept(self):
                    if len(accepted) >= connections:
                        raise StopServing()
                    connection, address = listener.accept()
                    accepted.append(connection)
                    return connection, address

            def run():
                try:
                    agent.serve(BoundedListener(), plane)
                except StopServing:
                    pass
                except BaseException as error:
                    errors.append(error)

            with patch.object(agent, "peer_uid", return_value=uid) as peer_uid, patch.object(
                agent, "CONNECTION_IO_TIMEOUT_SECONDS", 0.05, create=True,
            ):
                worker = threading.Thread(target=run, daemon=True)
                worker.start()
                try:
                    yield path, worker, errors, peer_uid
                finally:
                    for connection in accepted:
                        try:
                            connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        connection.close()
                    listener.close()
                    worker.join(2)

    def connect(self, path):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.settimeout(1)
        connection.connect(path)
        return connection

    def receive(self, connection):
        with connection.makefile("rb") as response:
            return json.loads(response.readline())

    def assert_finished(self, worker, errors):
        worker.join(1)
        self.assertFalse(worker.is_alive(), "agent did not finish the expected requests")
        self.assertEqual(errors, [])

    def test_timed_out_client_does_not_stop_agent_or_replay_its_action(self):
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        calls = []

        def handle(request, uid):
            calls.append((request["request_id"], uid))
            if len(calls) == 1:
                entered.set()
                if not release.wait(1):
                    raise AssertionError("test did not release the slow request")
            return {"ok": True, "request_id": request["request_id"], "result": {}}

        with self.server(Mock(handle=handle)) as (path, worker, errors, peer_uid):
            first = self.connect(path)
            first.sendall(request_line("a"))
            self.assertTrue(entered.wait(1))
            first.settimeout(0.01)
            with self.assertRaises(TimeoutError):
                first.recv(1)
            first.shutdown(socket.SHUT_RDWR)
            first.close()
            second = self.connect(path)
            second.sendall(request_line("b"))
            release.set()
            self.assertTrue(self.receive(second)["ok"])
            self.assert_finished(worker, errors)
            self.assertEqual(calls, [("a" * 32, 1001), ("b" * 32, 1001)])
            self.assertEqual(peer_uid.call_count, 2)

    def test_incomplete_idle_request_times_out_without_dispatching(self):
        runner = Mock()
        runner.snapshot.return_value = {"schema_version": 1, "services": []}
        with self.server(ControlPlane(runner, {1001})) as (path, worker, errors, _):
            first = self.connect(path)
            first.sendall(b'{"version":')
            second = self.connect(path)
            second.sendall(request_line())
            self.assertEqual(first.recv(1), b"")
            self.assertTrue(self.receive(second)["ok"])
            self.assert_finished(worker, errors)
            runner.snapshot.assert_called_once_with()

    def test_nonreading_client_write_timeout_keeps_next_request_available(self):
        calls = []

        def handle(request, uid):
            calls.append(request["request_id"])
            return {"ok": True, "result": {"data": "x" * (2 * 1024 * 1024) if len(calls) == 1 else "ok"}}

        with self.server(Mock(handle=handle)) as (path, worker, errors, _):
            first = self.connect(path)
            first.sendall(request_line("a"))
            second = self.connect(path)
            second.sendall(request_line("b"))
            self.assertEqual(self.receive(second)["result"]["data"], "ok")
            self.assert_finished(worker, errors)
            self.assertEqual(calls, ["a" * 32, "b" * 32])

    def test_truncated_malformed_and_invalid_requests_never_execute_actions(self):
        for payload in (b'{"version":1}', b"not-json\n", b"\xff\n", b"{}\n{}\n", b"[]\n"):
            with self.subTest(payload=payload):
                runner = Mock()
                with self.server(ControlPlane(runner, {1001}), connections=1) as (path, worker, errors, _):
                    client = self.connect(path)
                    client.sendall(payload)
                    if b"\n" not in payload:
                        client.shutdown(socket.SHUT_WR)
                    response = self.receive(client)
                    self.assertFalse(response["ok"])
                    self.assertEqual(response["error"]["code"], "invalid_request")
                    self.assert_finished(worker, errors)
                    self.assertEqual(runner.mock_calls, [])

    def test_unauthorized_kernel_identity_never_executes_actions(self):
        runner = Mock()
        with self.server(ControlPlane(runner, {1001}), connections=1, uid=2002) as (path, worker, errors, peer_uid):
            client = self.connect(path)
            client.sendall(request_line())
            response = self.receive(client)
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], "forbidden")
            self.assert_finished(worker, errors)
            peer_uid.assert_called_once()
            self.assertEqual(runner.mock_calls, [])

    def test_listener_accept_failure_is_not_hidden(self):
        listener = Mock()
        failure = OSError("listener failed")
        listener.accept.side_effect = failure
        with self.assertRaises(OSError) as raised:
            agent.serve(listener, Mock())
        self.assertIs(raised.exception, failure)


if __name__ == "__main__":
    unittest.main()
