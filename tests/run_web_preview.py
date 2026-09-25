#!/usr/bin/env python3
"""Run a complete, isolated visual preview: python tests/run_web_preview.py.

Only 127.0.0.1 is accepted. State, secrets and fake-agent socket are always
created under a new temporary directory, ignoring inherited production paths.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
import threading
from pathlib import Path

import uvicorn


REPO_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = REPO_DIR / "web"
TESTS_DIR = REPO_DIR / "tests"
sys.path.insert(0, str(REPO_DIR))
sys.path.insert(0, str(WEB_DIR))
sys.path.insert(0, str(TESTS_DIR))

from fake_agent_server import PreviewAgent, serve  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--scenario", choices=("rich", "empty", "error", "pending"), default="rich")
    parser.add_argument("--check", action="store_true", help="Render the full fixture route inventory without serving HTTP")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose an unprivileged local port (1024–65535)")
    # macOS UNIX socket paths have a short length limit, so use /tmp explicitly.
    with tempfile.TemporaryDirectory(prefix="server-kit-preview-", dir="/tmp") as directory:
        state_dir = Path(directory)
        os.chmod(state_dir, 0o700)
        socket_path = str(state_dir / "agent.sock")
        os.environ.update({
            "DJANGO_SETTINGS_MODULE": "server_kit_web.settings", "SERVER_KIT_TESTING": "1",
            "SERVER_KIT_WEB_STATE": directory, "SERVER_KIT_AGENT_SOCKET": socket_path,
            "SERVER_KIT_SECRET_KEY_FILE": str(state_dir / "no-production-secret"),
            "SERVER_KIT_BACKUP_DIR": str(state_dir / "backups"),
            "SERVER_KIT_ALLOWED_HOSTS": "127.0.0.1,localhost", "SERVER_KIT_MAX_UPLOAD_BYTES": str(8 * 1024 * 1024),
        })
        import django
        django.setup()
        from django.conf import settings
        from django.contrib.auth import get_user_model
        from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
        from django.core.asgi import get_asgi_application
        from django.core.management import call_command
        settings.ROOT_URLCONF = "preview_urls"
        # No shared browser login/CSRF cookies with another local server.
        settings.SESSION_COOKIE_NAME = f"server_kit_preview_{args.port}"
        settings.CSRF_COOKIE_NAME = f"server_kit_preview_csrf_{args.port}"
        settings.SECRET_KEY = secrets.token_urlsafe(48)
        # Recompile templates on each request during collaborative visual edits.
        settings.TEMPLATES[0]["APP_DIRS"] = False
        settings.TEMPLATES[0]["OPTIONS"]["loaders"] = [
            "django.template.loaders.filesystem.Loader", "django.template.loaders.app_directories.Loader",
        ]
        call_command("migrate", verbosity=0, interactive=False)
        password = "Preview-only-2026!"
        get_user_model().objects.create_superuser("preview", email="preview@example.invalid", password=password)
        get_user_model().objects.create_user("viewer", email="viewer@example.invalid", password=password)
        get_user_model().objects.create_user("administrator-with-long-name", password=password, is_staff=True)
        agent = PreviewAgent(args.scenario)
        ready = threading.Event()
        threading.Thread(target=serve, args=(socket_path, agent, ready), daemon=True).start()
        if not ready.wait(5):
            raise RuntimeError("Isolated preview agent failed to start; refusing fallback")
        import preview_urls
        preview_urls.AGENT = agent
        if args.check:
            from django.test import Client
            client = Client()
            client.force_login(get_user_model().objects.get(username="preview"))
            for route in preview_urls.PAGES:
                response = client.get(route)
                if response.status_code != 200:
                    raise RuntimeError(f"Preview route {route}: HTTP {response.status_code}")
            print(f"PASS: {len(preview_urls.PAGES)} preview pages rendered with isolated fixtures", flush=True)
            return 0
        print(f"LOCAL PREVIEW ONLY: http://127.0.0.1:{args.port}/__preview__/", flush=True)
        print(f"Login: preview / {password} (viewer uses the same demo password)", flush=True)
        print(f"Scenario: {args.scenario}; temporary state: {directory}", flush=True)
        print("No production socket, configuration, credentials, shell commands or network probes are used.", flush=True)
        uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host="127.0.0.1", port=args.port,
                    server_header=False, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
