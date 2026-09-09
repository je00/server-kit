#!/usr/bin/env python3
"""验证节点发布状态在升级和切换时保留独立纯净模式。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_publication_state import (
    PublicationStateError,
    load,
    set_clean_mode,
    set_publication,
)


class PublicationStateTests(unittest.TestCase):
    def test_legacy_state_migrates_without_losing_disabled_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "publications.json"
            path.write_text('{"version":1,"disabled":["home-nas"]}\n', encoding="utf-8")
            set_clean_mode(path, "iphone", True)
            self.assertEqual(load(path), {
                "version": 1,
                "disabled": ["home-nas"],
                "clean_mode": ["iphone"],
            })
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_publication_and_clean_switches_do_not_overwrite_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "publications.json"
            set_clean_mode(path, "desk", True)
            set_publication(path, "home-nas", False)
            set_clean_mode(path, "desk", False)
            self.assertEqual(json.loads(path.read_text()), {
                "version": 1,
                "disabled": ["home-nas"],
                "clean_mode": [],
            })

    def test_invalid_state_is_rejected_instead_of_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "publications.json"
            path.write_text('{"version":1,"disabled":"home-nas"}\n', encoding="utf-8")
            with self.assertRaises(PublicationStateError):
                set_clean_mode(path, "desk", True)


if __name__ == "__main__":
    unittest.main()
