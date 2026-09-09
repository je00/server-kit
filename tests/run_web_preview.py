#!/usr/bin/env python3
"""在单个测试进程中启动页面预览和代理替身。"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import uvicorn


REPO_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = REPO_DIR / "web"
TESTS_DIR = REPO_DIR / "tests"
sys.path.insert(0, str(REPO_DIR))
sys.path.insert(0, str(WEB_DIR))
sys.path.insert(0, str(TESTS_DIR))

from fake_agent_server import serve  # noqa: E402


def main() -> int:
    socket_path = os.environ["SERVER_KIT_AGENT_SOCKET"]
    threading.Thread(target=serve, args=(socket_path,), daemon=True).start()
    uvicorn.run(
        "server_kit_web.asgi:application",
        host="127.0.0.1",
        port=8765,
        server_header=False,
        log_level="warning",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
