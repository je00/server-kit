#!/usr/bin/env python3
"""事务化维护每个出口的独立 Xray DNS worker。"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class ExitDNSLifecycleError(RuntimeError):
    pass


EXIT_ID = re.compile(r"[0-9a-f]{12}\Z")
UNIT_NAME = "server-kit-exit-dns@.service"


def _write(path: Path, content: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _json(path: Path, value: dict) -> None:
    _write(path, (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode())


class Lifecycle:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.directory = args.worker_dir
        self.transaction = args.transaction
        self.manifest_path = self.transaction / "manifest.json"
        self.unit = args.systemd_dir / UNIT_NAME

    def systemctl(self, *arguments: str, check: bool = True) -> bool:
        result = subprocess.run([str(self.args.systemctl_bin), *arguments],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check and result.returncode:
            raise ExitDNSLifecycleError(f"出口 DNS 服务操作失败：{arguments[0]}。")
        return result.returncode == 0

    def _service(self, exit_id: str) -> str:
        return f"server-kit-exit-dns@{exit_id}.service"

    def _template(self) -> bytes:
        for path in (self.args.xray_bin, self.directory):
            if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)):
                raise ExitDNSLifecycleError("出口 DNS 的系统路径含不支持的字符。")
        return ("[Unit]\nDescription=server-kit exit-consistent DNS (%i)\n"
                "After=network.target\nStartLimitIntervalSec=0\n\n"
                "[Service]\nType=simple\nUser=root\nUMask=0077\n"
                f"ExecStart={self.args.xray_bin} run -config {self.directory}/%i.json\n"
                "Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray\n"
                "Restart=on-failure\nRestartSec=1\nNoNewPrivileges=true\n"
                "PrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n"
                "LimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n").encode()

    def _load(self) -> dict:
        if not self.manifest_path.is_file():
            raise ExitDNSLifecycleError("出口 DNS 事务尚未准备。")
        value = json.loads(self.manifest_path.read_text())
        if value.get("worker_dir") != str(self.directory) or value.get("unit_path") != str(self.unit):
            raise ExitDNSLifecycleError("出口 DNS 事务的目标路径不匹配。")
        return value

    def _validate_gateways(self, workers: dict[str, dict]) -> None:
        gateways = {
            server["address"]
            for worker in workers.values()
            for outbound in worker.get("outbounds", []) if outbound.get("protocol") == "socks"
            for server in outbound.get("settings", {}).get("servers", [])
        }
        for gateway in gateways:
            try:
                addresses = [ipaddress.ip_address(gateway)]
            except ValueError:
                try:
                    result = subprocess.run(
                        [sys.executable, "-c", "import json,socket,sys; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))", gateway],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8, check=True,
                    )
                    addresses = [ipaddress.ip_address(item) for item in json.loads(result.stdout)]
                except (subprocess.SubprocessError, ValueError) as error:
                    raise ExitDNSLifecycleError("出口 DNS SOCKS 网关启动解析失败。") from error
            if not addresses or any(not address.is_global for address in addresses):
                raise ExitDNSLifecycleError("出口 DNS SOCKS 网关解析到本机或非公网地址，拒绝可能的代理循环。")

    def prepare(self, workers: dict[str, dict] | None = None) -> None:
        if workers is None:
            from lib.server_kit_relay import render_exit_dns_workers
            workers = render_exit_dns_workers(self.args.config, self.args.clash_inputs)
        if self.manifest_path.exists():
            raise ExitDNSLifecycleError("出口 DNS 事务已存在，拒绝覆盖。")
        self.transaction.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.transaction.chmod(0o700)
        self._validate_gateways(workers)
        candidates = self.transaction / "candidates"
        backups = self.transaction / "backups"
        candidates.mkdir(mode=0o700)
        backups.mkdir(mode=0o700)
        ports: set[int] = set()
        for exit_id, worker in workers.items():
            if not EXIT_ID.fullmatch(exit_id):
                raise ExitDNSLifecycleError("出口 DNS ID 格式无效。")
            inbounds = worker.get("inbounds", [])
            if len(inbounds) != 1 or inbounds[0].get("listen") != "127.0.0.1" or inbounds[0].get("protocol") != "socks":
                raise ExitDNSLifecycleError("出口 DNS worker 必须只开放回环 SOCKS 入站。")
            settings = inbounds[0].get("settings", {})
            accounts = settings.get("accounts", [])
            if settings.get("auth") != "password" or len(accounts) != 1 or any(
                not isinstance(accounts[0].get(key), str) or not 1 <= len(accounts[0][key].encode()) <= 255
                for key in ("user", "pass")
            ):
                raise ExitDNSLifecycleError("出口 DNS worker 必须使用独立的回环认证。")
            port = inbounds[0].get("port")
            if not isinstance(port, int) or not 1024 <= port <= 65535 or port in ports:
                raise ExitDNSLifecycleError("出口 DNS worker 端口无效或冲突。")
            ports.add(port)
            candidate = candidates / f"{exit_id}.json"
            _json(candidate, worker)
            result = subprocess.run([str(self.args.xray_bin), "run", "-test", "-config", str(candidate)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode:
                raise ExitDNSLifecycleError(f"出口 DNS worker {exit_id} 的 Xray 配置校验失败。")
        old = {}
        if self.directory.exists():
            for path in sorted(self.directory.glob("*.json")):
                if not EXIT_ID.fullmatch(path.stem):
                    continue
                if path.is_symlink() or not path.is_file():
                    raise ExitDNSLifecycleError("出口 DNS 配置路径类型异常。")
                _write(backups / path.name, path.read_bytes())
                service = self._service(path.stem)
                old[path.stem] = {"active": self.systemctl("is-active", "--quiet", service, check=False),
                                  "enabled": self.systemctl("is-enabled", "--quiet", service, check=False)}
        unit_existed = self.unit.exists()
        if unit_existed:
            _write(backups / UNIT_NAME, self.unit.read_bytes())
        _json(self.manifest_path, {"worker_dir": str(self.directory), "unit_path": str(self.unit),
                                  "desired": sorted(workers), "old": old,
                                  "unit_existed": unit_existed, "phase": "prepared", "changed": []})

    def apply(self) -> None:
        manifest = self._load()
        if manifest["phase"] != "prepared":
            raise ExitDNSLifecycleError("出口 DNS 事务不能重复应用。")
        manifest["phase"] = "applying"
        _json(self.manifest_path, manifest)
        if not manifest["desired"]:
            return
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        template = self._template()
        if not self.unit.exists() or self.unit.read_bytes() != template:
            _write(self.unit, template, 0o644)
            self.systemctl("daemon-reload")
        for exit_id in manifest["desired"]:
            candidate = self.transaction / "candidates" / f"{exit_id}.json"
            installed = self.directory / candidate.name
            changed = not installed.exists() or installed.read_bytes() != candidate.read_bytes()
            if changed:
                manifest["changed"].append(exit_id)
                _json(self.manifest_path, manifest)
                _write(installed, candidate.read_bytes())
            else:
                installed.chmod(0o600)
            service = self._service(exit_id)
            self.systemctl("enable", service)
            self.systemctl("restart" if changed else "start", service)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(manifest["desired"]))) as pool:
            futures = [pool.submit(self.probe, exit_id) for exit_id in manifest["desired"]]
            for future in futures:
                future.result()

    def probe(self, exit_id: str) -> None:
        config = json.loads((self.directory / f"{exit_id}.json").read_text())
        inbound = config["inbounds"][0]
        accounts = inbound.get("settings", {}).get("accounts", [])
        if not accounts or not accounts[0].get("user") or not accounts[0].get("pass"):
            raise ExitDNSLifecycleError("出口 DNS 回环入站缺少独立认证。")
        user, password = accounts[0]["user"].encode(), accounts[0]["pass"].encode()
        deadline = time.monotonic() + self.args.probe_timeout
        listen_deadline = min(deadline, time.monotonic() + 8)
        connection = None
        while time.monotonic() < listen_deadline:
            try:
                connection = socket.create_connection(("127.0.0.1", inbound["port"]), timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        if connection is None:
            raise ExitDNSLifecycleError(f"出口 DNS worker {exit_id} 未能监听回环端口。")

        def read_exact(stream: socket.socket, count: int) -> bytes:
            result = b""
            while len(result) < count:
                stream.settimeout(max(0.001, deadline - time.monotonic()))
                part = stream.recv(count - len(result))
                if not part:
                    raise OSError("SOCKS response ended")
                result += part
            return result

        try:
            with connection as stream:
                stream.settimeout(max(0.001, deadline - time.monotonic()))
                stream.sendall(b"\x05\x01\x02")
                if read_exact(stream, 2) != b"\x05\x02":
                    raise OSError("SOCKS authentication method mismatch")
                stream.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
                if read_exact(stream, 2) != b"\x01\x00":
                    raise OSError("SOCKS authentication failed")
                host = self.args.probe_host.encode("idna")
                stream.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + self.args.probe_port.to_bytes(2, "big"))
                reply = read_exact(stream, 4)
                if reply[:2] != b"\x05\x00":
                    raise OSError("SOCKS domain connection failed")
                if reply[3] == 1:
                    read_exact(stream, 4 + 2)
                elif reply[3] == 4:
                    read_exact(stream, 16 + 2)
                elif reply[3] == 3:
                    read_exact(stream, read_exact(stream, 1)[0] + 2)
                else:
                    raise OSError("SOCKS bound address invalid")
                # Xray can acknowledge SOCKS CONNECT before resolving/dialing.
                # Only a verified remote TLS/HTTP response proves the DNS path works.
                stream.settimeout(max(0.001, deadline - time.monotonic()))
                with ssl.create_default_context().wrap_socket(stream, server_hostname=self.args.probe_host) as secure:
                    secure.settimeout(max(0.001, deadline - time.monotonic()))
                    secure.sendall(f"HEAD / HTTP/1.1\r\nHost: {self.args.probe_host}\r\nConnection: close\r\n\r\n".encode("ascii"))
                    status = b""
                    while b"\r\n" not in status and len(status) < 1024:
                        secure.settimeout(max(0.001, deadline - time.monotonic()))
                        part = secure.recv(1024)
                        if not part:
                            break
                        status += part
                    if not re.match(rb"HTTP/1\.[01] [23][0-9][0-9](?: |\r)", status):
                        raise OSError("HTTPS probe did not return a successful response")
            self.systemctl("is-active", "--quiet", self._service(exit_id))
        except (OSError, ValueError) as error:
            raise ExitDNSLifecycleError(f"出口 DNS worker {exit_id} 的域名建链探测失败。") from error

    def commit(self) -> None:
        manifest = self._load()
        if manifest["phase"] != "applying":
            raise ExitDNSLifecycleError("出口 DNS 事务尚未应用。")
        for exit_id in sorted(set(manifest["old"]) - set(manifest["desired"])):
            self.systemctl("disable", "--now", self._service(exit_id))
            (self.directory / f"{exit_id}.json").unlink(missing_ok=True)
        manifest["phase"] = "committed"
        _json(self.manifest_path, manifest)

    def rollback(self) -> None:
        if not self.manifest_path.exists():
            return
        manifest = self._load()
        if manifest["phase"] in {"prepared", "rolled-back"}:
            return
        if not manifest["desired"] and not manifest["old"]:
            manifest["phase"] = "rolled-back"
            _json(self.manifest_path, manifest)
            return
        errors = []
        for exit_id in sorted(set(manifest["desired"]) - set(manifest["old"])):
            if not self.systemctl("disable", "--now", self._service(exit_id), check=False):
                errors.append(exit_id)
            (self.directory / f"{exit_id}.json").unlink(missing_ok=True)
        for exit_id in manifest["old"]:
            backup = self.transaction / "backups" / f"{exit_id}.json"
            _write(self.directory / backup.name, backup.read_bytes())
        if manifest["unit_existed"]:
            _write(self.unit, (self.transaction / "backups" / UNIT_NAME).read_bytes(), 0o644)
        else:
            self.unit.unlink(missing_ok=True)
        self.systemctl("daemon-reload")
        for exit_id, previous in manifest["old"].items():
            service = self._service(exit_id)
            self.systemctl("enable" if previous["enabled"] else "disable", service)
            if previous["active"]:
                self.systemctl("restart" if exit_id in manifest["changed"] or exit_id not in manifest["desired"] else "start", service)
            else:
                self.systemctl("stop", service)
        manifest["phase"] = "rolled-back"
        _json(self.manifest_path, manifest)
        if errors:
            raise ExitDNSLifecycleError("部分新增出口 DNS worker 停止失败，请检查服务状态。")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "apply", "commit", "rollback"))
    parser.add_argument("--config", type=Path, default=Path("/etc/server-kit/server-relay.json"))
    parser.add_argument("--clash-inputs", type=Path, default=Path("/etc/server-kit/clash-inputs.json"))
    parser.add_argument("--worker-dir", type=Path, default=Path("/etc/server-kit/exit-dns"))
    parser.add_argument("--systemd-dir", type=Path, default=Path("/etc/systemd/system"))
    parser.add_argument("--transaction", type=Path, required=True)
    parser.add_argument("--xray-bin", type=Path, default=Path("/usr/local/bin/xray"))
    parser.add_argument("--systemctl-bin", type=Path, default=Path("/usr/bin/systemctl"))
    parser.add_argument("--probe-host", default="example.com")
    parser.add_argument("--probe-port", type=int, default=443)
    parser.add_argument("--probe-timeout", type=float, default=25)
    args = parser.parse_args()
    try:
        getattr(Lifecycle(args), args.command)()
    except (ExitDNSLifecycleError, OSError, ValueError) as error:
        parser.exit(1, f"出口 DNS 生命周期操作失败：{error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
