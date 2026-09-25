"""Port range parsing is shared by the website, task engine and CLI."""
import random
import subprocess
import sys
import unittest

from lib.server_kit_port_ranges import PortRangeError, format_ports, normalize_ports, parse_ports


class PortRangeTests(unittest.TestCase):
    def test_single_list_mixed_overlap_and_inclusive_endpoints(self):
        self.assertEqual(parse_ports("443, 22,22"), [22, 443])
        self.assertEqual(parse_ports("8002-8004, 22, 8000 - 8002, 8005"), [22, *range(8000, 8006)])
        self.assertEqual(normalize_ports("8002-8004,22,8000-8002,8005"), "22,8000-8005")
        self.assertEqual(normalize_ports("00022,443-443"), "22,443")

    def test_full_range_stays_compact_and_is_not_all_protocols(self):
        ports = parse_ports("1-65535,1-65535")
        self.assertEqual(len(ports), 65535)
        self.assertEqual((ports[0], ports[-1]), (1, 65535))
        self.assertEqual(format_ports(ports), "1-65535")

    def test_invalid_ranges_are_rejected(self):
        for value in (None, "", " ", "0", "65536", "0-10", "1-65536", "23-22", "22-", "-22",
                      "22,,443", "22,", ",22", "1-2-3", "1:3", "22;443", "22，443", "²", "1.5", "1e3", "*", "1" * 65536):
            with self.subTest(value=str(value)[:20]), self.assertRaises(PortRangeError):
                parse_ports(value)

    def test_format_never_opens_gaps(self):
        self.assertEqual(format_ports([22, 24, 25, 26, 443], separator=", "), "22, 24-26, 443")
        randomizer = random.Random(20260922)
        for _ in range(100):
            ports = randomizer.sample(range(1, 1000), 120)
            self.assertEqual(parse_ports(format_ports(ports)), sorted(ports))

    def test_cli_normalizes_and_rejects_without_echoing_input(self):
        result = subprocess.run([sys.executable, "lib/server_kit_port_ranges.py", "82,80-81,22"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "22,80-82")
        result = subprocess.run([sys.executable, "lib/server_kit_port_ranges.py", "22;private-marker"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("private-marker", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
