#!/usr/bin/env python3
"""Django 管理入口。"""

from __future__ import annotations

import os
import sys
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "server_kit_web.settings")

from django.core.management import execute_from_command_line  # noqa: E402


if __name__ == "__main__":
    execute_from_command_line(sys.argv)
