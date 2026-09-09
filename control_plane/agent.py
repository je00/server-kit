#!/usr/bin/env python3
"""通过本机 Unix Socket 提供受限管理动作。"""

from __future__ import annotations

import argparse
import grp
import json
import logging
import os
import pwd
import socket
import sqlite3
import stat
import struct
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from control_plane.core import ControlPlane  # noqa: E402
from control_plane.runner import ScriptRunner  # noqa: E402
from control_plane.tasks import ChangeTaskEngine  # noqa: E402
from control_plane.task_crypto import TaskPayloadCipher  # noqa: E402


MAX_REQUEST_BYTES = 65_536


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="server-kit 受限 root 管理代理")
    parser.add_argument("--socket", default="/run/server-kit/manager.sock")
    parser.add_argument("--web-user", default="server-kit-web")
    parser.add_argument("--manager", default="/usr/local/bin/server-kit-manager.sh")
    parser.add_argument(
        "--task-db",
        default=os.environ.get(
            "SERVER_KIT_TASK_DB", "/var/lib/server-kit-agent/tasks.sqlite3"
        ),
    )
    parser.add_argument(
        "--task-key",
        default=os.environ.get(
            "SERVER_KIT_TASK_KEY", "/var/lib/server-kit-agent/task-payload.key"
        ),
    )
    parser.add_argument("--systemd-socket", action="store_true")
    return parser.parse_args()


def peer_uid(connection: socket.socket) -> int:
    """从 Linux 内核读取 Unix Socket 对端身份。"""
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("当前系统不支持 SO_PEERCRED")
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def receive_request(connection: socket.socket) -> object:
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("请求超过大小限制")
    line, separator, remainder = bytes(data).partition(b"\n")
    if not separator or remainder:
        raise ValueError("请求必须是单行 JSON")
    return json.loads(line.decode("utf-8"))


def send_response(connection: socket.socket, response: dict[str, object]) -> None:
    encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    connection.sendall(encoded + b"\n")


def direct_listener(path_text: str, web_gid: int) -> socket.socket:
    path = Path(path_text)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        mode = path.lstat().st_mode
        if not stat.S_ISSOCK(mode):
            raise RuntimeError(f"Socket 路径已存在且不是套接字：{path}")
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chown(path, 0, web_gid)
    os.chmod(path, 0o660)
    listener.listen(16)
    return listener


def activated_listener() -> socket.socket:
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("没有收到唯一的 systemd Socket")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def serve(listener: socket.socket, plane: ControlPlane) -> None:
    while True:
        connection, _address = listener.accept()
        with connection:
            try:
                request = receive_request(connection)
                response = plane.handle(request, peer_uid(connection))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                response = {
                    "version": 1,
                    "request_id": "invalid-request",
                    "ok": False,
                    "error": {"code": "invalid_request", "message": "请求不是有效的单行 JSON。"},
                }
            send_response(connection, response)


def main() -> int:
    if os.geteuid() != 0:
        print("管理代理必须以 root 运行。", file=sys.stderr)
        return 1
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    task_engine: ChangeTaskEngine | None = None
    try:
        web_account = pwd.getpwnam(args.web_user)
        web_group = grp.getgrnam(args.web_user)
        runner = ScriptRunner(
            args.manager,
            high_risk_writes=os.environ.get("SERVER_KIT_HIGH_RISK_WRITES") == "1",
            network_writes=os.environ.get("SERVER_KIT_NETWORK_WRITES") == "1",
        )
        plane = ControlPlane(runner, {0, web_account.pw_uid})
        task_engine = ChangeTaskEngine(
            args.task_db,
            plane.prepare_task_action,
            plane.execute_task_action,
            plane.inspect_task_action,
            TaskPayloadCipher(args.task_key),
            plane.cleanup_task_action,
        )
        plane.attach_task_engine(task_engine)
        listener = activated_listener() if args.systemd_socket else direct_listener(args.socket, web_group.gr_gid)
        with listener:
            serve(listener, plane)
    except (KeyError, OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        print(f"管理代理启动失败：{exc}", file=sys.stderr)
        return 1
    finally:
        if task_engine is not None:
            task_engine.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
