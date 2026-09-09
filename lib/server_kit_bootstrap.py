#!/usr/bin/env python3
"""解析网页内置密钥生成器输出的 AWG 节点登记信息。"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys
from dataclasses import dataclass


NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
KEY_PATTERN = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{80,4096}\Z")


class BootstrapError(ValueError):
    """表示节点登记信息无效。"""


@dataclass(frozen=True)
class BootstrapEnrollment:
    name: str
    address: str
    public_key: str
    preshared_key: str


def decode_enrollment_token(
    token: str, expected_name: str | None = None,
) -> BootstrapEnrollment:
    if not TOKEN_PATTERN.fullmatch(token):
        raise BootstrapError("AWG 节点登记信息格式无效。")
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as exc:
        raise BootstrapError("AWG 节点登记信息无法解码。") from exc
    if not isinstance(value, dict) or set(value) != {
        "format", "name", "address", "public_key", "preshared_key",
    } or value.get("format") not in {
        "server-kit-awg-enrollment-v1", "server-kit-awg-bootstrap-v1",
    }:
        raise BootstrapError("AWG 节点登记信息字段无效。")
    name = value.get("name")
    address = value.get("address")
    public_key = value.get("public_key")
    preshared_key = value.get("preshared_key")
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise BootstrapError("AWG 节点登记信息中的名称无效。")
    if expected_name is not None and name != expected_name:
        raise BootstrapError("登记信息中的节点名称与初始化输入不一致。")
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise BootstrapError("AWG 节点登记地址无效。") from exc
    if parsed_address.version != 4:
        raise BootstrapError("AWG 节点登记地址必须是 IPv4。")
    for label, key in (("客户端公钥", public_key), ("预共享密钥", preshared_key)):
        if not isinstance(key, str) or not KEY_PATTERN.fullmatch(key):
            raise BootstrapError(f"{label}格式无效。")
        try:
            decoded = base64.b64decode(key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BootstrapError(f"{label}编码无效。") from exc
        if len(decoded) != 32:
            raise BootstrapError(f"{label}长度无效。")
    return BootstrapEnrollment(name, str(parsed_address), public_key, preshared_key)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("decode",))
    parser.add_argument("--expected-name", required=True)
    args = parser.parse_args()
    token = sys.stdin.readline(4097).strip()
    try:
        result = decode_enrollment_token(token, args.expected_name)
    except BootstrapError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    for value in (result.name, result.address, result.public_key, result.preshared_key):
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
