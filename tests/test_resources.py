#!/usr/bin/env python3
"""验证主机资源快照只读取固定的系统事实。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lib.server_kit_resources import collect_resources


class ResourceSnapshotTests(unittest.TestCase):
    def test_collects_load_memory_disk_and_uptime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "loadavg").write_text(
                "0.42 0.31 0.20 1/100 123\n", encoding="ascii"
            )
            (proc / "meminfo").write_text(
                "MemTotal:       2097152 kB\nMemAvailable:   1048576 kB\n",
                encoding="ascii",
            )
            (proc / "uptime").write_text("90061.50 100.00\n", encoding="ascii")
            with patch("lib.server_kit_resources.os.cpu_count", return_value=4), patch(
                "lib.server_kit_resources.shutil.disk_usage",
                return_value=(40 * 1024**3, 10 * 1024**3, 30 * 1024**3),
            ):
                resources = collect_resources(proc, Path("/"))

        self.assertEqual(resources["cpu"]["cores"], 4)
        self.assertEqual(resources["cpu"]["load_1"], 0.42)
        self.assertEqual(resources["memory"]["usage_percent"], 50.0)
        self.assertEqual(resources["disk"]["usage_percent"], 25.0)
        self.assertEqual(resources["uptime_seconds"], 90061)


if __name__ == "__main__":
    unittest.main()
