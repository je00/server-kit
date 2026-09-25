"""Guard the known GFM punctuation-boundary regression, without network access.

This targeted source lint does not replace checking GitHub's rendered HTML.
"""

import re
import unicodedata
import unittest
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


if __name__ == "__main__":
    unittest.main()
