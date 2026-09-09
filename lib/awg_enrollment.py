#!/usr/bin/env python3
"""维护 AWG 节点首次握手确认状态，不保存客户端私钥或预共享密钥。"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
KEY_PATTERN = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
ENROLLMENT_TTL_SECONDS = 300


class EnrollmentError(ValueError):
    """表示首次握手状态格式或操作无效。"""


def utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EnrollmentStore:
    def __init__(self, path: Path, now: Callable[[], float] = time.time) -> None:
        self.path = path
        self._now = now

    def start(self, name: str, public_key: str) -> dict[str, object]:
        if not NAME_PATTERN.fullmatch(name) or not KEY_PATTERN.fullmatch(public_key):
            raise EnrollmentError("节点首次握手参数无效。")
        state = self._read()
        now = int(self._now())
        state["items"][name] = {
            "public_key": public_key, "created_epoch": now,
            "expires_epoch": now + ENROLLMENT_TTL_SECONDS,
        }
        state["history"] = [item for item in state["history"] if item.get("name") != name]
        self._write(state)
        return {
            "schema_version": 1, "name": name, "state": "pending",
            "expires_at": utc(now + ENROLLMENT_TTL_SECONDS),
            "expires_in": ENROLLMENT_TTL_SECONDS,
        }

    def plan(self, handshakes: dict[str, int]) -> list[dict[str, str]]:
        state = self._read()
        now = int(self._now())
        actions = []
        for name, item in state["items"].items():
            handshake = int(handshakes.get(str(item["public_key"]), 0))
            if handshake >= int(item["created_epoch"]):
                actions.append({"action": "commit", "name": name})
            elif now >= int(item["expires_epoch"]):
                actions.append({"action": "expire", "name": name})
        return actions

    def complete(self, name: str, outcome: str = "active") -> None:
        if outcome not in {"active", "expired"}:
            raise EnrollmentError("节点首次握手结果无效。")
        state = self._read()
        if name in state["items"]:
            del state["items"][name]
            state["history"] = [item for item in state["history"] if item.get("name") != name]
            state["history"].insert(0, {
                "name": name, "state": outcome, "completed_epoch": int(self._now()),
            })
            state["history"] = state["history"][:50]
            self._write(state)

    def overview(self) -> dict[str, object]:
        state = self._read()
        now = int(self._now())
        return {
            "schema_version": 1,
            "items": [
                {
                    "name": name, "state": "pending",
                    "expires_at": utc(int(item["expires_epoch"])),
                    "remaining_seconds": max(0, int(item["expires_epoch"]) - now),
                }
                for name, item in sorted(state["items"].items())
            ],
            "history": [
                {
                    "name": item["name"], "state": item["state"],
                    "completed_at": utc(int(item["completed_epoch"])),
                }
                for item in state["history"]
            ],
        }

    def _read(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": 1, "items": {}, "history": []}
        except (OSError, ValueError) as error:
            raise EnrollmentError("节点首次握手状态无法读取。") from error
        if value.get("schema_version") != 1 or not isinstance(value.get("items"), dict):
            raise EnrollmentError("节点首次握手状态版本无效。")
        value.setdefault("history", [])
        if not isinstance(value["history"], list):
            raise EnrollmentError("节点首次握手历史无效。")
        for name, item in value["items"].items():
            if (
                not isinstance(name, str) or not NAME_PATTERN.fullmatch(name)
                or not isinstance(item, dict)
                or set(item) != {"public_key", "created_epoch", "expires_epoch"}
                or not KEY_PATTERN.fullmatch(str(item.get("public_key", "")))
                or not isinstance(item.get("created_epoch"), int)
                or not isinstance(item.get("expires_epoch"), int)
            ):
                raise EnrollmentError("节点首次握手状态内容无效。")
        for item in value["history"]:
            if (
                not isinstance(item, dict) or set(item) != {"name", "state", "completed_epoch"}
                or not NAME_PATTERN.fullmatch(str(item.get("name", "")))
                or item.get("state") not in {"active", "expired"}
                or not isinstance(item.get("completed_epoch"), int)
            ):
                raise EnrollmentError("节点首次握手历史内容无效。")
        return value

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                json.dump(value, output, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="AWG 首次握手状态管理")
    parser.add_argument("operation", choices=("start", "plan", "complete", "overview"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--name", default="")
    parser.add_argument("--public-key", default="")
    parser.add_argument("--outcome", choices=("active", "expired"), default="active")
    args = parser.parse_args()
    store = EnrollmentStore(args.state)
    try:
        if args.operation == "start":
            result: object = store.start(args.name, args.public_key)
        elif args.operation == "plan":
            raw = json.load(sys.stdin)
            if not isinstance(raw, dict) or any(not isinstance(value, int) for value in raw.values()):
                raise EnrollmentError("握手事实格式无效。")
            result = {"schema_version": 1, "actions": store.plan(raw)}
        elif args.operation == "complete":
            store.complete(args.name, args.outcome)
            result = {"schema_version": 1, "name": args.name, "completed": True}
        else:
            result = store.overview()
    except (EnrollmentError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
