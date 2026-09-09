#!/usr/bin/env python3
"""安全保存动态 DNS 凭据，并用本机默认路由 IPv4 更新稳定公网入口。

文件名和 CLI 路径保留 ``duckdns`` 是为了兼容已部署的定时器；配置格式 v2
同时支持 DuckDNS 与腾讯云 DNSPod。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.server_kit_public_endpoint import current_ipv4, normalize_fqdn, resolve_ipv4s
from lib.server_kit_node_domains import (
    NodeDomainError, load_address_state, load_state as load_node_domain_state,
    validate_wildcard_conflicts,
)


TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
SECRET_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
SECRET_KEY_PATTERN = re.compile(r"[^\x00\r\n]{16,256}\Z")
DUCKDNS_SUFFIX = ".duckdns.org"
DEFAULT_DUCKDNS_API = "https://www.duckdns.org/update"
DNSPOD_HOST = "dnspod.tencentcloudapi.com"
DNSPOD_VERSION = "2021-03-23"
DNSPOD_SERVICE = "dnspod"


class DuckDnsError(ValueError):
    """可安全展示给管理员的动态 DNS 配置错误。"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def atomic_json(path: Path, value: dict[str, object], mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(value, target, ensure_ascii=False, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def duckdns_domain(fqdn: str) -> str:
    normalized = normalize_fqdn(fqdn)
    if not normalized.endswith(DUCKDNS_SUFFIX):
        raise DuckDnsError("稳定公网入口不是 duckdns.org 域名，不能启用 DuckDNS 自动更新。")
    domain = normalized[: -len(DUCKDNS_SUFFIX)]
    if not domain or "." in domain:
        raise DuckDnsError("当前只支持单个 DuckDNS 子域名。")
    return domain


def validate_token(token: object) -> str:
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token.strip()):
        raise DuckDnsError("DuckDNS Token 格式无效。")
    return token.strip()


def validate_secret_id(secret_id: object) -> str:
    if not isinstance(secret_id, str) or not SECRET_ID_PATTERN.fullmatch(secret_id.strip()):
        raise DuckDnsError("DNSPod SecretId 格式无效。")
    return secret_id.strip()


def validate_secret_key(secret_key: object) -> str:
    if not isinstance(secret_key, str) or not SECRET_KEY_PATTERN.fullmatch(secret_key.strip()):
        raise DuckDnsError("DNSPod SecretKey 格式无效。")
    return secret_key.strip()


def dnspod_record(fqdn: str, zone: object) -> tuple[str, str]:
    normalized = normalize_fqdn(fqdn)
    if not isinstance(zone, str):
        raise DuckDnsError("DNSPod 主域名格式无效。")
    normalized_zone = normalize_fqdn(zone)
    if normalized == normalized_zone:
        return normalized_zone, "@"
    suffix = "." + normalized_zone
    if not normalized.endswith(suffix):
        raise DuckDnsError("稳定公网入口不属于填写的 DNSPod 主域名。")
    record = normalized[: -len(suffix)]
    if not record or len(record) > 253:
        raise DuckDnsError("DNSPod 主机记录格式无效。")
    return normalized_zone, record


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as error:
        raise DuckDnsError("动态 DNS 配置文件无法读取。") from error
    if not isinstance(value, dict):
        raise DuckDnsError("动态 DNS 配置文件版本无效。")
    return value


def load_config(path: Path) -> dict[str, object]:
    value = read_json(path)
    if not value:
        return {}
    # v1 是已经部署的 DuckDNS 格式，读取时无损兼容。
    if value.get("schema_version") == 1:
        if not isinstance(value.get("enabled"), bool) or not isinstance(value.get("fqdn"), str):
            raise DuckDnsError("动态 DNS 配置文件版本无效。")
        fqdn = normalize_fqdn(value["fqdn"])
        duckdns_domain(fqdn)
        return {
            "schema_version": 2, "provider": "duckdns", "enabled": value["enabled"],
            "fqdn": fqdn, "token": validate_token(value.get("token")),
        }
    if (
        value.get("schema_version") != 2
        or value.get("provider") not in {"duckdns", "dnspod"}
        or not isinstance(value.get("enabled"), bool)
        or not isinstance(value.get("fqdn"), str)
    ):
        raise DuckDnsError("动态 DNS 配置文件版本无效。")
    fqdn = normalize_fqdn(value["fqdn"])
    if value["provider"] == "duckdns":
        duckdns_domain(fqdn)
        return {
            "schema_version": 2, "provider": "duckdns", "enabled": value["enabled"],
            "fqdn": fqdn, "token": validate_token(value.get("token")),
        }
    zone, record = dnspod_record(fqdn, value.get("zone"))
    record_id = value.get("record_id")
    record_line = value.get("record_line")
    if not isinstance(record_id, int) or record_id <= 0 or not isinstance(record_line, str) or not record_line:
        raise DuckDnsError("DNSPod 记录信息无效，请重新配置。")
    return {
        "schema_version": 2, "provider": "dnspod", "enabled": value["enabled"],
        "fqdn": fqdn, "zone": zone, "record": record,
        "record_id": record_id, "record_line": record_line,
        "secret_id": validate_secret_id(value.get("secret_id")),
        "secret_key": validate_secret_key(value.get("secret_key")),
    }


def duckdns_api_update(fqdn: str, token: str, ipv4: str) -> None:
    domain = duckdns_domain(fqdn)
    testing_response = os.environ.get("SERVER_KIT_DUCKDNS_API_RESPONSE")
    if os.environ.get("SERVER_KIT_TESTING") == "1" and testing_response is not None:
        response_text = testing_response
    else:
        query = urllib.parse.urlencode({"domains": domain, "token": token, "ip": ipv4, "verbose": "true"})
        request = urllib.request.Request(
            f"{os.environ.get('SERVER_KIT_DUCKDNS_API', DEFAULT_DUCKDNS_API)}?{query}",
            headers={"User-Agent": "server-kit-dynamic-dns/2"},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=10) as response:
                response_text = response.read(4096).decode("utf-8", "replace")
        except Exception as error:
            # urllib 的异常可能包含完整 URL；绝不能让 Token 进入日志或控制面响应。
            raise DuckDnsError("无法连接 DuckDNS 更新接口。") from error
    first_line = response_text.strip().splitlines()[0].strip().upper() if response_text.strip() else ""
    if first_line != "OK":
        raise DuckDnsError("DuckDNS 拒绝了更新请求，请检查域名归属和 Token。")


def _hmac_sha256(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def dnspod_api_request(action: str, payload: dict[str, object], secret_id: str, secret_key: str) -> dict[str, object]:
    test_responses = os.environ.get("SERVER_KIT_DNSPOD_API_RESPONSES")
    if os.environ.get("SERVER_KIT_TESTING") == "1" and test_responses is not None:
        try:
            result = json.loads(test_responses)[action]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise DuckDnsError("DNSPod 测试响应无效。") from error
    else:
        timestamp = int(time.time())
        date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        canonical_headers = "content-type:application/json; charset=utf-8\nhost:" + DNSPOD_HOST + "\n"
        signed_headers = "content-type;host"
        canonical_request = "\n".join((
            "POST", "/", "", canonical_headers, signed_headers,
            hashlib.sha256(body.encode("utf-8")).hexdigest(),
        ))
        credential_scope = f"{date}/{DNSPOD_SERVICE}/tc3_request"
        string_to_sign = "\n".join((
            "TC3-HMAC-SHA256", str(timestamp), credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ))
        secret_date = _hmac_sha256(("TC3" + secret_key).encode("utf-8"), date)
        secret_service = _hmac_sha256(secret_date, DNSPOD_SERVICE)
        secret_signing = _hmac_sha256(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = (
            f"TC3-HMAC-SHA256 Credential={secret_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        request = urllib.request.Request(
            "https://" + DNSPOD_HOST,
            data=body.encode("utf-8"), method="POST",
            headers={
                "Authorization": authorization, "Content-Type": "application/json; charset=utf-8",
                "Host": DNSPOD_HOST, "X-TC-Action": action,
                "X-TC-Timestamp": str(timestamp), "X-TC-Version": DNSPOD_VERSION,
                "User-Agent": "server-kit-dynamic-dns/2",
            },
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=12) as response:
                result = json.loads(response.read(65536).decode("utf-8", "replace"))
        except Exception as error:
            # Authorization 含 SecretId；不传播 urllib 的原始异常文本。
            raise DuckDnsError("无法连接腾讯云 DNSPod API。") from error
    if not isinstance(result, dict) or not isinstance(result.get("Response"), dict):
        raise DuckDnsError("腾讯云 DNSPod API 返回了无效响应。")
    response = result["Response"]
    api_error = response.get("Error")
    if isinstance(api_error, dict):
        code = str(api_error.get("Code", ""))
        if "AuthFailure" in code or "Unauthorized" in code:
            raise DuckDnsError("DNSPod 拒绝了凭据，请检查 SecretId、SecretKey 和最小权限策略。")
        if "DomainRecordExist" in code:
            raise DuckDnsError("DNSPod 已存在冲突记录，无法自动创建 A 记录。")
        if "DomainNot" in code or "DomainInvalid" in code:
            raise DuckDnsError("DNSPod 找不到填写的主域名。")
        raise DuckDnsError("DNSPod API 拒绝了请求，请检查凭据权限和记录状态。")
    return response


def dnspod_find_record(
    fqdn: str, zone: str, secret_id: str, secret_key: str,
) -> tuple[str, int, str] | None:
    normalized_zone, record = dnspod_record(fqdn, zone)
    response = dnspod_api_request(
        "DescribeRecordList",
        {"Domain": normalized_zone, "SubDomain": record, "Limit": 100, "ErrorOnEmpty": "no"},
        secret_id, secret_key,
    )
    records = response.get("RecordList")
    if not isinstance(records, list):
        raise DuckDnsError("DNSPod 返回的记录列表无效。")
    matches = [item for item in records if isinstance(item, dict) and item.get("Name") == record]
    if not matches:
        return None
    if len(matches) != 1:
        raise DuckDnsError("DNSPod 存在多条同名记录，拒绝自动选择或覆盖。")
    selected = matches[0]
    if selected.get("Type") != "A" or selected.get("Line") != "默认":
        raise DuckDnsError("DNSPod 已有同名的非默认线路 A 记录或其他类型记录。")
    record_id = selected.get("RecordId")
    record_line = selected.get("Line")
    if not isinstance(record_id, int) or record_id <= 0 or not isinstance(record_line, str) or not record_line:
        raise DuckDnsError("DNSPod 返回的 A 记录信息无效。")
    return record, record_id, record_line


def dnspod_create_record(
    fqdn: str, zone: str, secret_id: str, secret_key: str, ipv4: str,
) -> tuple[str, int, str]:
    normalized_zone, record = dnspod_record(fqdn, zone)
    response = dnspod_api_request(
        "CreateRecord",
        {
            "Domain": normalized_zone, "SubDomain": record, "RecordType": "A",
            "RecordLine": "默认", "Value": ipv4,
        },
        secret_id, secret_key,
    )
    record_id = response.get("RecordId")
    if not isinstance(record_id, int) or record_id <= 0:
        raise DuckDnsError("DNSPod 创建 A 记录后没有返回有效 RecordId。")
    return record, record_id, "默认"


def dnspod_api_update(config: dict[str, object], ipv4: str) -> None:
    dnspod_api_request(
        "ModifyDynamicDNS",
        {
            "Domain": config["zone"], "SubDomain": config["record"],
            "RecordId": config["record_id"], "RecordLine": config["record_line"], "Value": ipv4,
        },
        str(config["secret_id"]), str(config["secret_key"]),
    )


def route_public_ipv4() -> str:
    ipv4, warning = current_ipv4()
    try:
        address = ipaddress.ip_address(ipv4)
    except ValueError as error:
        raise DuckDnsError("无法读取本机默认路由公网 IPv4。") from error
    if address.version != 4 or not address.is_global:
        raise DuckDnsError(warning or "本机默认路由源地址不是公网 IPv4。")
    return str(address)


def perform_update(config: dict[str, object], state_path: Path) -> dict[str, object]:
    if not config or config.get("enabled") is not True:
        raise DuckDnsError("动态 DNS 自动更新尚未启用。")
    ipv4 = route_public_ipv4()
    if config.get("provider") == "duckdns":
        duckdns_api_update(str(config["fqdn"]), str(config["token"]), ipv4)
    elif config.get("provider") == "dnspod":
        dnspod_api_update(config, ipv4)
    else:
        raise DuckDnsError("动态 DNS 提供商不受支持。")
    state = {
        "schema_version": 2, "provider": config["provider"], "last_result": "success",
        "last_update_at": utc_now(), "last_ipv4": ipv4, "last_error": "",
    }
    atomic_json(state_path, state)
    return state


def public_status(config_path: Path, state_path: Path) -> dict[str, object]:
    diagnostics: list[str] = []
    try:
        config = load_config(config_path)
    except DuckDnsError as error:
        config = {}
        diagnostics.append(str(error))
    try:
        state = read_json(state_path)
    except DuckDnsError as error:
        state = {}
        diagnostics.append(str(error))
    fqdn = str(config.get("fqdn", ""))
    resolved, resolve_error = resolve_ipv4s(fqdn)
    if resolve_error:
        diagnostics.append(resolve_error)
    last_ipv4 = str(state.get("last_ipv4", ""))
    provider = str(config.get("provider", ""))
    return {
        "schema_version": 2, "configured": bool(config), "enabled": config.get("enabled") is True,
        "provider": provider, "provider_label": {"duckdns": "DuckDNS", "dnspod": "腾讯云 DNSPod"}.get(provider, "未配置"),
        "fqdn": fqdn, "zone": str(config.get("zone", "")), "record": str(config.get("record", "")),
        "credentials_present": bool(config), "token_present": provider == "duckdns" and bool(config),
        "last_result": str(state.get("last_result", "")), "last_update_at": str(state.get("last_update_at", "")),
        "last_ipv4": last_ipv4, "dns_ipv4s": resolved,
        "dns_matches_last_ipv4": last_ipv4 in resolved if last_ipv4 and resolved else None,
        "timer_state": os.environ.get("SERVER_KIT_DUCKDNS_TIMER_STATE", "unknown"),
        "next_run": os.environ.get("SERVER_KIT_DUCKDNS_NEXT_RUN", ""), "diagnostics": diagnostics,
    }


def validate_subscription_wildcards(
    node_domains_path: Path | None, fqdn: str,
) -> None:
    if node_domains_path is None or not node_domains_path.is_file():
        return
    try:
        nodes = load_node_domain_state(node_domains_path)
        addresses = load_address_state(node_domains_path)
        validate_wildcard_conflicts(
            [
                domain
                for groups in (nodes, addresses)
                for domains in groups.values()
                for domain in domains
            ],
            [fqdn],
        )
    except NodeDomainError as error:
        raise DuckDnsError(str(error)) from error


def configure(
    config_path: Path, state_path: Path, fqdn: str,
    node_domains_path: Path | None = None,
) -> dict[str, object]:
    try:
        request = json.load(os.fdopen(os.dup(0), encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DuckDnsError("动态 DNS 配置请求不是有效 JSON。") from error
    required = {"provider", "token", "secret_id", "secret_key", "zone", "fqdn"}
    if not isinstance(request, dict) or set(request) != required:
        raise DuckDnsError("动态 DNS 配置请求字段无效。")
    provider = request.get("provider")
    record_created = False
    if provider == "duckdns":
        normalized = normalize_fqdn(fqdn)
        validate_subscription_wildcards(node_domains_path, normalized)
        duckdns_domain(normalized)
        candidate = {
            "schema_version": 2, "provider": "duckdns", "enabled": True,
            "fqdn": normalized, "token": validate_token(request.get("token")),
        }
    elif provider == "dnspod":
        requested_fqdn = request.get("fqdn")
        if not isinstance(requested_fqdn, str) or not requested_fqdn.strip():
            raise DuckDnsError("请输入 DNSPod 目标完整域名。")
        normalized = normalize_fqdn(requested_fqdn)
        validate_subscription_wildcards(node_domains_path, normalized)
        secret_id = validate_secret_id(request.get("secret_id"))
        secret_key = validate_secret_key(request.get("secret_key"))
        zone, _record = dnspod_record(normalized, request.get("zone"))
        found = dnspod_find_record(normalized, zone, secret_id, secret_key)
        if found is None:
            found = dnspod_create_record(
                normalized, zone, secret_id, secret_key, route_public_ipv4(),
            )
            record_created = True
        record, record_id, record_line = found
        candidate = {
            "schema_version": 2, "provider": "dnspod", "enabled": True,
            "fqdn": normalized, "zone": zone, "record": record,
            "record_id": record_id, "record_line": record_line,
            "secret_id": secret_id, "secret_key": secret_key,
        }
    else:
        raise DuckDnsError("动态 DNS 提供商不受支持。")
    # 先用候选凭据真实更新；成功后才原子替换已有配置。
    result = perform_update(candidate, state_path)
    atomic_json(config_path, candidate)
    return {
        "schema_version": 2, "operation": "configure", "configured": True,
        "enabled": True, "provider": provider, "fqdn": normalized, "last_ipv4": result["last_ipv4"],
        "record_created": record_created,
    }


def set_disabled(config_path: Path) -> dict[str, object]:
    config = load_config(config_path)
    provider = str(config.get("provider", ""))
    if config:
        config["enabled"] = False
        atomic_json(config_path, config)
    return {"schema_version": 2, "operation": "disable", "configured": bool(config), "enabled": False, "provider": provider}


def delete(config_path: Path, state_path: Path) -> dict[str, object]:
    provider = ""
    try:
        provider = str(load_config(config_path).get("provider", ""))
    except DuckDnsError:
        pass
    for path in (config_path, state_path):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return {"schema_version": 2, "operation": "delete", "configured": False, "enabled": False, "provider": provider}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("status", "configure", "update", "disable", "delete"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--fqdn", default="")
    parser.add_argument("--node-domains-config", type=Path)
    args = parser.parse_args()
    if args.operation == "status":
        result = public_status(args.config, args.state)
    elif args.operation == "configure":
        result = configure(args.config, args.state, args.fqdn, args.node_domains_config)
    elif args.operation == "update":
        config = load_config(args.config)
        state = perform_update(config, args.state)
        result = {
            "schema_version": 2, "operation": "update", "configured": True,
            "enabled": True, "provider": config["provider"], "last_ipv4": state["last_ipv4"],
            "last_update_at": state["last_update_at"],
        }
    elif args.operation == "disable":
        result = set_disabled(args.config)
    else:
        result = delete(args.config, args.state)
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DuckDnsError as error:
        print(str(error), file=os.sys.stderr)
        raise SystemExit(1) from error
