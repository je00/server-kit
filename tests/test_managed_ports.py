import json
import tempfile
import unittest
from pathlib import Path

from lib.server_kit_managed_ports import ManagedPortError, build_overview, build_plan


class ManagedPortsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.awg = root / "manager.conf"
        self.file = root / "file.json"
        self.clash = root / "clash.json"
        self.ports = root / "ports.json"
        self.awg.write_text("AWG_PRIMARY_PORT=443\nAWG_BACKUP_PORT1=1848\nAWG_BACKUP_PORT2=\n", encoding="utf-8")
        self.file.write_text('{"port":8443}', encoding="utf-8")
        self.clash.write_text('{"port":52541}', encoding="utf-8")
        self.ports.write_text(json.dumps({"listeners": [], "observed_unmanaged": []}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def overview(self):
        return build_overview(self.awg, self.file, self.clash, self.ports)

    def test_同一数字的_tcp_和_udp_可以共存(self):
        plan = build_plan(self.overview(), "file", 1848)
        self.assertEqual(plan["new_port"], 1848)

    def test_备用入口限制为低位端口(self):
        with self.assertRaisesRegex(ManagedPortError, "1–9999"):
            build_plan(self.overview(), "awg-backup1", 10000)

    def test_同协议托管端口冲突会被拒绝(self):
        with self.assertRaisesRegex(ManagedPortError, "Clash"):
            build_plan(self.overview(), "file", 52541)

    def test_未安装服务不能修改(self):
        self.file.unlink()
        with self.assertRaisesRegex(ManagedPortError, "尚未安装"):
            build_plan(self.overview(), "file", 9000)

    def test_revision_忽略事实生成时间(self):
        first = self.overview()["revision"]
        self.ports.write_text(json.dumps({"generated_at": "later", "listeners": [], "observed_unmanaged": []}), encoding="utf-8")
        self.assertEqual(first, self.overview()["revision"])

    def test_未托管的同协议监听也会阻止变更(self):
        self.ports.write_text(json.dumps({
            "listeners": [],
            "observed_unmanaged": [{"protocol": "tcp", "port": 9000, "address": "0.0.0.0", "process": "test"}],
        }), encoding="utf-8")
        with self.assertRaisesRegex(ManagedPortError, "test"):
            build_plan(self.overview(), "file", 9000)


if __name__ == "__main__":
    unittest.main()
