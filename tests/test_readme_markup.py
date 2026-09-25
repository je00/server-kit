"""Guard the known GFM punctuation-boundary regression, without network access.

This targeted source lint does not replace checking GitHub's rendered HTML.
"""

import re
import unicodedata
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


def risky_strong_boundaries(source):
    problems = []
    in_fence = False
    for number, line in enumerate(source.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in re.finditer(r"\*\*([^*\n]+)\*\*(\w)", line):
            if unicodedata.category(match[1][-1]).startswith("P"):
                problems.append(number)
    return problems


class ReadmeMarkupTests(unittest.TestCase):
    def test_detects_punctuation_inside_strong_touching_text(self):
        self.assertEqual(risky_strong_boundaries("- **内网互联：**AWG"), [1])
        self.assertEqual(risky_strong_boundaries("- **统一管理：**部署向导"), [1])

    def test_accepts_punctuation_outside_or_followed_by_space(self):
        for source in ("- **内网互联**：AWG", "- **Private network:** AWG",
                       "**整句说明。**", "在**自己电脑**上运行"):
            with self.subTest(source=source):
                self.assertEqual(risky_strong_boundaries(source), [])

    def test_ignores_fenced_examples(self):
        self.assertEqual(risky_strong_boundaries("```markdown\n**示例：**文字\n```"), [])

    def test_both_readmes_avoid_the_known_gfm_boundary_problem(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("README.md", "README.en.md"):
            with self.subTest(document=name):
                self.assertEqual(risky_strong_boundaries((root / name).read_text()), [])

    def test_readmes_use_explicit_links_instead_of_bold_bare_urls(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("README.md", "README.en.md"):
            with self.subTest(document=name):
                # GFM autolinks can consume closing ** beside Chinese punctuation.
                self.assertNotRegex((root / name).read_text(), r"\*\*https?://[^*\s]+\*\*")

    def test_both_readmes_link_accessible_star_topology_diagrams(self):
        root = Path(__file__).resolve().parents[1]
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        for name, language, topology in (("README.md", "zh", "星形"),
                                         ("README.en.md", "en", "star")):
            with self.subTest(document=name):
                source = (root / name).read_text()
                image = f"docs/images/network-map-{language}.svg"
                self.assertIn(topology, source.lower())
                self.assertIn(f"]({image})", source)
                diagram = ET.parse(root / image).getroot()
                self.assertEqual(diagram.attrib.get("role"), "img")
                self.assertEqual(diagram.attrib.get("aria-labelledby"), "title desc")
                for tag in ("title", "desc"):
                    element = diagram.find(f"svg:{tag}", namespace)
                    self.assertIsNotNone(element)
                    self.assertEqual(element.attrib.get("id"), tag)
                    self.assertTrue(element.text.strip())
                description = diagram.find("svg:desc", namespace).text
                self.assertIn("VPS", description)
                self.assertIn("P2P", description)

    def test_topology_arrowheads_leave_visible_straight_shafts(self):
        root = Path(__file__).resolve().parents[1]
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        for language in ("zh", "en"):
            with self.subTest(language=language):
                diagram = ET.parse(root / f"docs/images/network-map-{language}.svg").getroot()
                marker = diagram.find(".//svg:marker[@id='arrow']", namespace)
                # The default strokeWidth units magnified both heads until
                # they touched, making a short two-way link look like a spindle.
                self.assertEqual(marker.attrib.get("markerUnits"), "userSpaceOnUse")
                self.assertEqual(marker.attrib.get("orient"), "auto-start-reverse")
                head_width = float(marker.attrib["markerWidth"])
                self.assertGreater(head_width, 0)
                lines = diagram.findall("svg:path[@class='line']", namespace)
                self.assertEqual(sum("marker-start" in line.attrib for line in lines), 4)
                self.assertEqual(len(lines), 6)
                for line in lines:
                    match = re.fullmatch(r"M([\d.]+) ([\d.]+) ([HV])([\d.]+)", line.attrib["d"])
                    self.assertIsNotNone(match)
                    x, y, direction, end = match.groups()
                    length = abs(float(end) - float(x if direction == "H" else y))
                    heads = sum(key in line.attrib for key in ("marker-start", "marker-end"))
                    # Conservatively subtract entire marker boxes. 16 SVG
                    # units remain visible even when the image is scaled down.
                    self.assertGreaterEqual(length - heads * head_width, 16)


if __name__ == "__main__":
    unittest.main()
