#!/usr/bin/env python3
"""管理稳定公网入口事实，并提供不会因网络失败而中断的只读诊断。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_fqdn(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("稳定入口域名格式不正确。") from error
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or len(labels) < 2 or any(not LABEL.fullmatch(x) for x in labels):
        raise ValueError("稳定入口必须是完整主机名（FQDN），不能包含协议、端口或路径。")
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        return ascii_name
    raise ValueError("稳定入口必须是 FQDN，不能是 IP 地址。")


def load(path: Path, *, strict: bool = False) -> str:
    if not path.exists():
        return ""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("稳定公网入口事实文件版本无效。")
        return normalize_fqdn(value.get("fqdn", ""))
    except (OSError, ValueError, AttributeError, TypeError) as error:
        if strict:
            raise ValueError("稳定公网入口事实文件无效。") from error
        return ""


def atomic_write(path: Path, fqdn: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump({"schema_version": 1, "fqdn": fqdn}, target, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def current_ipv4() -> tuple[str, str]:
    testing = os.environ.get("SERVER_KIT_TESTING") == "1"
    if testing and "SERVER_KIT_PUBLIC_IPV4" in os.environ:
        candidate = os.environ["SERVER_KIT_PUBLIC_IPV4"]
    else:
        try:
            completed = subprocess.run(
                ["ip", "-4", "route", "get", "1.1.1.1"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return "", f"无法读取本机默认路由 IPv4：{type(error).__name__}"
        match = re.search(r"(?:^|\s)src\s+(\S+)", completed.stdout) if completed.returncode == 0 else None
        if match is None:
            return "", "本机默认路由没有可识别的 IPv4 源地址。"
        candidate = match.group(1)
    try:
        address = ipaddress.ip_address(candidate)
        if address.version != 4:
            return "", "本机默认路由源地址不是 IPv4。"
        warning = (
            "本机默认路由源地址不是可路由公网 IPv4；VPS 位于 NAT 后时请以云控制台地址为准。"
            if not address.is_global else ""
        )
        return str(address), warning
    except ValueError:
        return "", "无法取得有效的本机默认路由 IPv4。"


def resolve_ipv4s(fqdn: str) -> tuple[list[str], str]:
    if not fqdn:
        return [], ""
    if os.environ.get("SERVER_KIT_TESTING") == "1" and "SERVER_KIT_DNS_IPV4S" in os.environ:
        raw = os.environ["SERVER_KIT_DNS_IPV4S"].split(",")
        error = os.environ.get("SERVER_KIT_DNS_ERROR", "")
    else:
        try:
            completed = subprocess.run(
                [os.environ.get("SERVER_KIT_GETENT_BIN", "/usr/bin/getent"), "ahostsv4", fqdn],
                check=False, capture_output=True, text=True, timeout=2,
            )
        except subprocess.TimeoutExpired:
            return [], "FQDN IPv4 解析超时（2 秒）。"
        except OSError as exc:
            return [], f"FQDN IPv4 解析失败：{exc}"
        if completed.returncode != 0:
            detail = completed.stderr.strip() or f"getent 退出码 {completed.returncode}"
            return [], f"FQDN IPv4 解析失败：{detail}"
        raw = [line.split()[0] for line in completed.stdout.splitlines() if line.split()]
        error = ""
    values: set[str] = set()
    for candidate in raw:
        try:
            address = ipaddress.ip_address(candidate.strip())
            if address.version == 4:
                values.add(str(address))
        except ValueError:
            continue
    return sorted(values, key=lambda value: int(ipaddress.ip_address(value))), error


def status(path: Path) -> dict[str, object]:
    try:
        fqdn = load(path, strict=True)
        config_error = ""
    except ValueError:
        fqdn = ""
        config_error = "稳定公网入口事实文件无效；当前按未配置处理。"
    current, current_error = current_ipv4()
    answers, dns_error = resolve_ipv4s(fqdn)

    diagnostics = [value for value in (config_error, current_error, dns_error) if value]
    matches = current in answers if fqdn and current and answers else None
    return {
        "schema_version": 1,
        "configured": bool(fqdn),
        "fqdn": fqdn,
        "current_ipv4": current,
        "dns_ipv4s": answers,
        "matches_current_ipv4": matches,
        "dns_ttl": None,
        "dns_ttl_status": "未知（Python 标准库解析接口不提供可靠 TTL）",
        "diagnostics": diagnostics,
        "recovery_hint": "DNS 缓存受 TTL 和递归解析器影响；变更 A 记录后等待解析一致并从外部验证入口。",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("status", "set", "clear", "get"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--fqdn", default="")
    args = parser.parse_args()
    if args.operation == "set":
        fqdn = normalize_fqdn(args.fqdn)
        atomic_write(args.config, fqdn)
        result = {"schema_version": 1, "operation": "set", "fqdn": fqdn}
    elif args.operation == "clear":
        try:
            args.config.unlink()
        except FileNotFoundError:
            pass
        else:
            directory = os.open(args.config.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        result = {"schema_version": 1, "operation": "clear", "fqdn": ""}
    elif args.operation == "get":
        print(load(args.config, strict=True))
        return 0
    else:
        result = status(args.config)
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        raise SystemExit(str(error)) from error
