#!/usr/bin/env python3
"""Shared inclusive port-list/range syntax; persisted policies remain integer lists."""

from __future__ import annotations

import re
import sys


MAX_SPEC_LENGTH = 65535
ITEM = re.compile(r"([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?")
ERROR = "端口格式无效，请输入 1–65535 的端口或范围（如 22,443,8000-8010），范围起点不能大于终点。"


class PortRangeError(ValueError):
    """Invalid port specification; safe to show without echoing raw input."""


def parse_ports(value: str) -> list[int]:
    if not isinstance(value, str) or not value or len(value) > MAX_SPEC_LENGTH:
        raise PortRangeError(ERROR)
    intervals = []
    for item in value.split(","):
        match = ITEM.fullmatch(item.strip())
        if match is None:
            raise PortRangeError(ERROR)
        start = int(match[1])
        end = int(match[2]) if match[2] is not None else start
        if not 1 <= start <= end <= 65535:
            raise PortRangeError(ERROR)
        intervals.append((start, end))
    # Merge before expansion: repeated full ranges must not cause repeated work.
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [port for start, end in merged for port in range(start, end + 1)]


def format_ports(ports: list[int], separator: str = ",") -> str:
    """Compact without opening gaps, e.g. [22, 80, 81, 82] -> 22,80-82."""
    ordered = sorted(set(ports))
    if not ordered:
        return ""
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ordered):
        raise PortRangeError(ERROR)
    result = []
    start = end = ordered[0]
    for port in ordered[1:]:
        if port == end + 1:
            end = port
        else:
            result.append(str(start) if start == end else f"{start}-{end}")
            start = end = port
    result.append(str(start) if start == end else f"{start}-{end}")
    return separator.join(result)


def normalize_ports(value: str) -> str:
    return format_ports(parse_ports(value))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise PortRangeError(ERROR)
        print(normalize_ports(sys.argv[1]))
    except PortRangeError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
