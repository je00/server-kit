#!/usr/bin/env python3
"""管理机场资源事实目录；任何状态输出都不得包含订阅凭据。"""

from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import socket
import sys
import unicodedata
from io import StringIO
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


CONFIG_VERSION = 4
MAX_AIRPORTS = 8
MAX_EXITS = 16
AIRPORT_ID_PATTERN = re.compile(r"^[a-f0-9]{12}$")
AIRPORT_NAME_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,40}$")
EXIT_ID_PATTERN = AIRPORT_ID_PATTERN
EXIT_NAME_PATTERN = AIRPORT_NAME_PATTERN
NODE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
COUNTRY_CATALOG = (
    {"id": "all", "label": "全部地区", "filter": ""},
    {"id": "hk", "label": "香港", "filter": r"(?i)香港|港|HK|Hong\s*Kong"},
    {"id": "tw", "label": "台湾", "filter": r"(?i)台湾|台|TW|Taiwan"},
    {"id": "jp", "label": "日本", "filter": r"(?i)日本|日|JP|Japan|Tokyo|Osaka"},
    {"id": "sg", "label": "新加坡", "filter": r"(?i)新加坡|狮城|SG|Singapore"},
    {"id": "us", "label": "美国", "filter": r"(?i)美国|美|US|USA|United\s*States"},
    {"id": "kr", "label": "韩国", "filter": r"(?i)韩国|韩|KR|Korea|Seoul"},
    {"id": "uk", "label": "英国", "filter": r"(?i)英国|英|UK|United\s*Kingdom|London"},
    {"id": "de", "label": "德国", "filter": r"(?i)德国|德|DE|Germany|Frankfurt"},
    {"id": "fr", "label": "法国", "filter": r"(?i)法国|法|FR|France|Paris"},
    {"id": "ca", "label": "加拿大", "filter": r"(?i)加拿大|加|CA|Canada"},
    {"id": "au", "label": "澳大利亚", "filter": r"(?i)澳大利亚|澳洲|澳|AU|Australia|Sydney"},
    {"id": "ru", "label": "俄罗斯", "filter": r"(?i)俄罗斯|俄|RU|Russia|Moscow"},
    {"id": "in", "label": "印度", "filter": r"(?i)印度|印|IN|India|Mumbai"},
)
COUNTRY_BY_ID = {item["id"]: item for item in COUNTRY_CATALOG}
COUNTRY_IDS = frozenset(COUNTRY_BY_ID)


class ProxyResourceError(RuntimeError):
    """表示可以安全展示给操作者的机场资源错误。"""


def _raw_config(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _legacy_airport(url: str) -> dict:
    return {
        "id": "000000000001",
        "name": "默认机场",
        "url": url,
        "enabled": True,
        "countries": ["all"],
    }


def load_config(path: Path) -> dict:
    """读取并在内存中迁移旧格式；只有写操作才落盘。"""

    value = _raw_config(path)
    if value.get("version") in {3, CONFIG_VERSION} and isinstance(value.get("airports"), list):
        airports = value.get("airports", [])
    else:
        legacy_url = value.get("airport_url", "")
        airports = [_legacy_airport(legacy_url)] if isinstance(legacy_url, str) and legacy_url else []
    if value.get("version") == CONFIG_VERSION and isinstance(value.get("exits"), list):
        exits = value.get("exits", [])
        default_exit_id = value.get("default_exit_id", "")
        awg_exit_selections = value.get("awg_exit_selections", {})
    else:
        legacy_exit = value.get("exit_proxy", {})
        exits = ([{
            "id": "000000000001",
            "name": "默认出口",
            "proxy": legacy_exit,
        }] if isinstance(legacy_exit, dict) and legacy_exit else [])
        default_exit_id = "000000000001" if exits else ""
        awg_exit_selections = {}
    return {
        "version": CONFIG_VERSION,
        "airports": airports if isinstance(airports, list) else [],
        "exits": exits if isinstance(exits, list) else [],
        "default_exit_id": default_exit_id if isinstance(default_exit_id, str) else "",
        "awg_exit_selections": (
            awg_exit_selections if isinstance(awg_exit_selections, dict) else {}
        ),
    }


def _normalize_countries(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ProxyResourceError("启用机场时至少选择一个国家或地区。")
    countries: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in COUNTRY_BY_ID:
            raise ProxyResourceError("机场包含不受支持的国家或地区。")
        if item not in countries:
            countries.append(item)
    return ["all"] if "all" in countries else countries


def _normalize_airport(value: object) -> dict:
    if not isinstance(value, dict):
        raise ProxyResourceError("机场记录格式无效。")
    airport_id = value.get("id")
    name = value.get("name")
    url = value.get("url")
    enabled = value.get("enabled")
    countries = value.get("countries")
    if not isinstance(airport_id, str) or not AIRPORT_ID_PATTERN.fullmatch(airport_id):
        raise ProxyResourceError("机场标识无效。")
    if not isinstance(name, str) or not AIRPORT_NAME_PATTERN.fullmatch(name.strip()):
        raise ProxyResourceError("机场名称必须是 1–40 个可显示字符。")
    if not isinstance(url, str) or len(url) > 8192 or "\x00" in url:
        raise ProxyResourceError("机场订阅链接格式无效。")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ProxyResourceError("机场订阅必须是有效的 HTTP 或 HTTPS 链接。")
    if not isinstance(enabled, bool):
        raise ProxyResourceError("机场启用状态无效。")
    normalized_countries = _normalize_countries(countries)
    result = {
        "id": airport_id,
        "name": name.strip(),
        "url": url,
        "enabled": enabled,
        "countries": normalized_countries,
    }
    if "bootstrap_dns" in value:
        try:
            try:
                from .stash_bootstrap import normalize_inventory
            except ImportError:
                from stash_bootstrap import normalize_inventory
            inventory = normalize_inventory(value["bootstrap_dns"], url)
        except ValueError as error:
            raise ProxyResourceError(str(error)) from None
        if inventory is not None:
            result["bootstrap_dns"] = inventory
    return result


def exit_publish_token(display_name: str) -> str:
    """Return a readable ASCII token derived from the resource display name."""

    if not isinstance(display_name, str):
        raise ProxyResourceError("出口节点名称无效。")
    clean_name = display_name.strip()
    if clean_name in {"默认", "默认出口"}:
        return "Default"
    ascii_name = unicodedata.normalize("NFKD", clean_name).encode(
        "ascii", "ignore"
    ).decode("ascii")
    token = re.sub(r"[^A-Za-z0-9]+", ".", ascii_name).strip(".")
    if not token:
        raise ProxyResourceError(
            "出口节点名称必须包含英文字母或数字，发布名称会直接使用该名称。"
        )
    return token


def exit_proxy_name(display_name: str) -> str:
    return f"EXIT.{exit_publish_token(display_name)}"


def _normalize_exit(value: object) -> dict:
    if not isinstance(value, dict):
        raise ProxyResourceError("出口节点记录格式无效。")
    exit_id = value.get("id")
    name = value.get("name")
    if not isinstance(exit_id, str) or not EXIT_ID_PATTERN.fullmatch(exit_id):
        raise ProxyResourceError("出口节点标识无效。")
    if not isinstance(name, str) or not EXIT_NAME_PATTERN.fullmatch(name.strip()):
        raise ProxyResourceError("出口节点名称必须是 1–40 个可显示字符。")
    clean_name = name.strip()
    return {
        "id": exit_id,
        "name": clean_name,
        "proxy": normalize_proxy(value.get("proxy"), exit_proxy_name(clean_name)),
    }


def selected_exit_ids(config: dict, node_name: str) -> list[str]:
    """返回节点显式选择；显式空列表表示 VPS MID，无覆盖记录才跟随默认出口。"""

    selections = config.get("awg_exit_selections", {})
    if isinstance(selections, dict) and node_name in selections:
        value = selections[node_name]
        return list(value) if isinstance(value, list) else []
    default_exit_id = config.get("default_exit_id", "")
    return [default_exit_id] if isinstance(default_exit_id, str) and default_exit_id else []


def default_exit_proxy(config: dict) -> dict:
    default_exit_id = config.get("default_exit_id", "")
    exit_node = next((
        item for item in config.get("exits", [])
        if isinstance(item, dict) and item.get("id") == default_exit_id
    ), None)
    if not isinstance(exit_node, dict) or not isinstance(exit_node.get("proxy"), dict):
        raise ProxyResourceError("当前没有有效的默认出口节点。")
    return exit_node["proxy"]


def normalized_config(path: Path) -> dict:
    config = load_config(path)
    airports: list[dict] = []
    names: set[str] = set()
    identifiers: set[str] = set()
    for value in config["airports"]:
        airport = _normalize_airport(value)
        folded_name = airport["name"].casefold()
        if airport["id"] in identifiers or folded_name in names:
            raise ProxyResourceError("机场标识或名称重复。")
        identifiers.add(airport["id"])
        names.add(folded_name)
        airports.append(airport)
    if len(airports) > MAX_AIRPORTS:
        raise ProxyResourceError(f"最多管理 {MAX_AIRPORTS} 个机场。")
    config["airports"] = airports
    exits: list[dict] = []
    exit_names: set[str] = set()
    exit_publish_names: set[str] = set()
    exit_identifiers: set[str] = set()
    for value in config["exits"]:
        exit_node = _normalize_exit(value)
        folded_name = exit_node["name"].casefold()
        folded_publish_name = exit_node["proxy"]["name"].casefold()
        if exit_node["id"] in exit_identifiers or folded_name in exit_names:
            raise ProxyResourceError("出口节点标识或名称重复。")
        if folded_publish_name in exit_publish_names:
            raise ProxyResourceError("出口节点名称生成了重复的发布名称，请使用不同的英文名称。")
        exit_identifiers.add(exit_node["id"])
        exit_names.add(folded_name)
        exit_publish_names.add(folded_publish_name)
        exits.append(exit_node)
    if len(exits) > MAX_EXITS:
        raise ProxyResourceError(f"最多管理 {MAX_EXITS} 个出口节点。")
    default_exit_id = config.get("default_exit_id", "")
    if exits and default_exit_id not in exit_identifiers:
        raise ProxyResourceError("默认出口节点不存在。")
    if not exits and default_exit_id:
        raise ProxyResourceError("没有出口节点时不能设置默认出口。")
    selections = config.get("awg_exit_selections", {})
    if not isinstance(selections, dict):
        raise ProxyResourceError("节点出口选择格式无效。")
    clean_selections: dict[str, list[str]] = {}
    for node_name, identifiers_value in selections.items():
        if not isinstance(node_name, str) or not NODE_NAME_PATTERN.fullmatch(node_name):
            raise ProxyResourceError("节点出口选择包含无效节点名称。")
        if not isinstance(identifiers_value, list):
            raise ProxyResourceError("节点出口选择必须是列表。")
        clean_identifiers: list[str] = []
        for exit_id in identifiers_value:
            if not isinstance(exit_id, str) or exit_id not in exit_identifiers:
                raise ProxyResourceError("节点出口选择包含不存在的出口节点。")
            if exit_id not in clean_identifiers:
                clean_identifiers.append(exit_id)
        clean_selections[node_name] = clean_identifiers
    config["exits"] = exits
    config["default_exit_id"] = default_exit_id
    config["awg_exit_selections"] = clean_selections
    return config


def _safe_airport(airport: dict) -> dict:
    try:
        host = urlsplit(airport["url"]).hostname or ""
    except ValueError:
        host = ""
    return {
        "id": airport["id"],
        "name": airport["name"],
        "host": host[:253],
        "enabled": airport["enabled"],
        "countries": list(airport["countries"]),
        "country_labels": [COUNTRY_BY_ID[item]["label"] for item in airport["countries"]],
    }


def _safe_exit(exit_node: dict, default_exit_id: str) -> dict:
    proxy = exit_node["proxy"]
    return {
        "id": exit_node["id"],
        "name": exit_node["name"],
        "default": exit_node["id"] == default_exit_id,
        "type": str(proxy.get("type", ""))[:32],
        "server": str(proxy.get("server", ""))[:253],
        "port": proxy.get("port", 0),
    }


def overview(path: Path) -> dict[str, object]:
    try:
        config = normalized_config(path)
    except ProxyResourceError:
        config = {
            "version": CONFIG_VERSION, "airports": [], "exits": [],
            "default_exit_id": "", "awg_exit_selections": {},
        }
    airports = [_safe_airport(item) for item in config["airports"]]
    exits = [_safe_exit(item, config["default_exit_id"]) for item in config["exits"]]
    active_count = sum(1 for item in airports if item["enabled"])
    default_exit = next((item for item in exits if item["default"]), {})
    revision = hashlib.sha256(json.dumps(
        config, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return {
        "schema_version": 3,
        "revision": revision,
        "configured": bool(airports and default_exit),
        "airport_count": len(airports),
        "active_airport_count": active_count,
        "airports": airports,
        "country_options": [
            {"id": item["id"], "label": item["label"]} for item in COUNTRY_CATALOG
        ],
        "exit_count": len(exits),
        "default_exit_id": config["default_exit_id"],
        "exits": exits,
        "exit": {
            "configured": bool(default_exit),
            "type": str(default_exit.get("type", "")),
            "server": str(default_exit.get("server", "")),
            "port": int(default_exit.get("port", 0)),
        },
    }


def reveal(path: Path, resource: str, item_id: str) -> dict[str, object]:
    """按固定资源类型返回敏感值；调用方负责权限、会话解锁和审计。"""

    config = normalized_config(path)
    if resource == "airport-link":
        airport = next(
            (item for item in config["airports"] if item["id"] == item_id),
            None,
        )
        if airport is None:
            raise ProxyResourceError("机场不存在或已被删除。")
        return {
            "schema_version": 1,
            "resource": "proxy_airport_link",
            "item_id": item_id,
            "name": airport["name"],
            "value": airport["url"],
        }
    if resource == "exit-config":
        if item_id == "current":
            item_id = config["default_exit_id"]
        exit_node = next((item for item in config["exits"] if item["id"] == item_id), None)
        if exit_node is None:
            raise ProxyResourceError("出口节点不存在或已被删除。")
        proxy = exit_node["proxy"]
        try:
            from ruamel.yaml import YAML

            stream = StringIO()
            yaml = YAML()
            yaml.default_flow_style = False
            yaml.dump(proxy, stream)
            value = stream.getvalue()
        except ImportError:
            # JSON 是 YAML 1.2 的合法子集；最小环境仍能复制后直接粘贴回更新表单。
            value = json.dumps(proxy, ensure_ascii=False, indent=2) + "\n"
        except Exception as exc:
            raise ProxyResourceError("出口节点配置无法安全呈现。") from exc
        return {
            "schema_version": 1,
            "resource": "proxy_exit_config",
            "item_id": exit_node["id"],
            "name": exit_node["name"],
            "value": value,
            "proxy": proxy,
        }
    raise ProxyResourceError("敏感代理资源未登记。")


def normalize_proxy(proxy: object, proxy_name: str = "chain.mid.proxy") -> dict:
    if isinstance(proxy, list) and len(proxy) == 1:
        proxy = proxy[0]
    if isinstance(proxy, dict) and set(proxy) == {"proxies"} and isinstance(proxy["proxies"], list) and len(proxy["proxies"]) == 1:
        proxy = proxy["proxies"][0]
    if not isinstance(proxy, dict):
        raise ProxyResourceError("请粘贴一个完整出口节点，或只包含一个节点的 proxies/list。")
    proxy_type = proxy.get("type", "")
    server = proxy.get("server", "")
    port = proxy.get("port")
    # 兼容早期 server-kit 仅保存 server/port/username/password 的 SOCKS5 格式。
    legacy_split = not proxy_type and isinstance(server, str) and bool(server)
    if not proxy_type and isinstance(server, str) and server:
        proxy_type = "socks5"
    if not isinstance(proxy_type, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", proxy_type):
        raise ProxyResourceError("出口节点缺少有效的 type。")
    if not isinstance(server, str) or not server or any(character.isspace() for character in server):
        raise ProxyResourceError("出口节点缺少有效的 server。")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ProxyResourceError("出口节点缺少有效的 port。")
    result = {"name": proxy_name, "type": proxy_type.lower()}
    for key, value in proxy.items():
        if key not in {"name", "type", "dialer-proxy"}:
            result[key] = value
    if legacy_split:
        result.setdefault("udp", True)
    result["dialer-proxy"] = "MID"
    try:
        json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ProxyResourceError("出口节点包含无法保存的值。") from exc
    return result


def _parse_exit_proxy(text: str, proxy_name: str = "chain.mid.proxy") -> dict:
    if not isinstance(text, str) or len(text) > 65536 or "\x00" in text:
        raise ProxyResourceError("出口节点内容过长或包含无效字符。")
    try:
        from ruamel.yaml import YAML
        proxy = YAML(typ="safe").load(text)
    except Exception as exc:
        raise ProxyResourceError("出口节点 YAML 无法解析。") from exc
    return normalize_proxy(proxy, proxy_name)


def _new_airport_id(existing: set[str]) -> str:
    while True:
        candidate = secrets.token_hex(6)
        if candidate not in existing:
            return candidate


def _new_exit_id(existing: set[str]) -> str:
    return _new_airport_id(existing)


def _legacy_update(config: dict, payload: dict) -> dict:
    airport_url = payload.get("airport_url")
    exit_proxy_yaml = payload.get("exit_proxy_yaml")
    if not isinstance(airport_url, str) or not isinstance(exit_proxy_yaml, str):
        raise ProxyResourceError("机场资源内容格式不正确。")
    if airport_url.strip():
        if config["airports"]:
            config["airports"][0]["url"] = airport_url.strip()
        else:
            config["airports"].append(_legacy_airport(airport_url.strip()))
    if not config["airports"]:
        raise ProxyResourceError("当前没有可沿用的机场，请提供订阅链接。")
    if exit_proxy_yaml.strip():
        if config["exits"]:
            target = next(
                item for item in config["exits"]
                if item.get("id") == config.get("default_exit_id")
            )
            target["proxy"] = _parse_exit_proxy(
                exit_proxy_yaml, exit_proxy_name(str(target.get("name", "")))
            )
        else:
            exit_id = _new_exit_id(set())
            name = "默认出口"
            config["exits"] = [{
                "id": exit_id, "name": name,
                "proxy": _parse_exit_proxy(exit_proxy_yaml, exit_proxy_name(name)),
            }]
            config["default_exit_id"] = exit_id
    elif not config.get("exits"):
        raise ProxyResourceError("当前没有可沿用的出口节点，请粘贴完整 YAML。")
    return config


def _apply_operation(config: dict, payload: dict) -> dict:
    operation = payload.get("operation")
    airports = config["airports"]
    if operation in {"airport_add", "airport_update"}:
        name = payload.get("airport_name")
        url = payload.get("airport_url")
        enabled = payload.get("airport_enabled")
        countries = payload.get("countries")
        if not isinstance(name, str) or not isinstance(url, str) or not isinstance(enabled, bool):
            raise ProxyResourceError("机场资源内容格式不正确。")
        if operation == "airport_add":
            airport_id = _new_airport_id({item.get("id", "") for item in airports if isinstance(item, dict)})
            airports.append({
                "id": airport_id, "name": name, "url": url,
                "enabled": enabled, "countries": countries,
            })
        else:
            airport_id = payload.get("airport_id")
            target = next((item for item in airports if isinstance(item, dict) and item.get("id") == airport_id), None)
            if target is None:
                raise ProxyResourceError("要修改的机场不存在。")
            target.update({"name": name, "enabled": enabled, "countries": countries})
            if url.strip():
                target["url"] = url.strip()
    elif operation == "airport_bootstrap_update":
        target = next((item for item in airports if isinstance(item, dict) and item.get("id") == payload.get("airport_id")), None)
        if target is None:
            raise ProxyResourceError("要修改的机场不存在。")
        inventory = payload.get("bootstrap_dns")
        if not isinstance(inventory, dict) or inventory.get("url_sha256") != hashlib.sha256(target["url"].encode()).hexdigest():
            raise ProxyResourceError("节点 DNS 清单与当前订阅不一致。")
        target["bootstrap_dns"] = inventory
    elif operation == "airport_delete":
        airport_id = payload.get("airport_id")
        if not isinstance(airport_id, str) or not AIRPORT_ID_PATTERN.fullmatch(airport_id):
            raise ProxyResourceError("机场标识无效。")
        remaining = [item for item in airports if not (isinstance(item, dict) and item.get("id") == airport_id)]
        if len(remaining) == len(airports):
            raise ProxyResourceError("要删除的机场不存在。")
        config["airports"] = remaining
    elif operation in {"exit_add", "exit_update"}:
        exit_id = payload.get("exit_id")
        name = payload.get("exit_name")
        exit_proxy_yaml = payload.get("exit_proxy_yaml")
        make_default = payload.get("exit_default")
        if (
            not isinstance(name, str)
            or not isinstance(exit_proxy_yaml, str)
            or not isinstance(make_default, bool)
        ):
            raise ProxyResourceError("出口节点内容格式不正确。")
        clean_name = name.strip()
        if operation == "exit_add":
            if not exit_proxy_yaml.strip():
                raise ProxyResourceError("新增出口节点需要完整 YAML。")
            exit_id = _new_exit_id({
                item.get("id", "") for item in config["exits"] if isinstance(item, dict)
            })
            config["exits"].append({
                "id": exit_id,
                "name": clean_name,
                "proxy": _parse_exit_proxy(exit_proxy_yaml, exit_proxy_name(clean_name)),
            })
            if len(config["exits"]) == 1 or make_default:
                config["default_exit_id"] = exit_id
        else:
            target = next((
                item for item in config["exits"]
                if isinstance(item, dict) and item.get("id") == exit_id
            ), None)
            if target is None:
                raise ProxyResourceError("要修改的出口节点不存在。")
            target["name"] = clean_name
            if exit_proxy_yaml.strip():
                target["proxy"] = _parse_exit_proxy(
                    exit_proxy_yaml, exit_proxy_name(clean_name)
                )
            elif isinstance(target.get("proxy"), dict):
                target["proxy"]["name"] = exit_proxy_name(clean_name)
            if make_default:
                config["default_exit_id"] = exit_id
    elif operation == "exit_set_default":
        exit_id = payload.get("exit_id")
        if not any(
            isinstance(item, dict) and item.get("id") == exit_id
            for item in config["exits"]
        ):
            raise ProxyResourceError("要设为默认的出口节点不存在。")
        config["default_exit_id"] = exit_id
    elif operation == "exit_delete":
        exit_id = payload.get("exit_id")
        remaining = [
            item for item in config["exits"]
            if not (isinstance(item, dict) and item.get("id") == exit_id)
        ]
        if len(remaining) == len(config["exits"]):
            raise ProxyResourceError("要删除的出口节点不存在。")
        if not remaining:
            raise ProxyResourceError("至少保留一个出口节点；请先添加替代出口。")
        config["exits"] = remaining
        if config.get("default_exit_id") == exit_id:
            config["default_exit_id"] = str(remaining[0]["id"])
        for node_name, selected in list(config["awg_exit_selections"].items()):
            if isinstance(selected, list):
                remaining_selection = [
                    item for item in selected if item != exit_id
                ]
                if remaining_selection:
                    config["awg_exit_selections"][node_name] = remaining_selection
                else:
                    config["awg_exit_selections"][node_name] = []
    elif operation == "node_exits_set":
        node_name = payload.get("awg_name")
        exit_ids = payload.get("exit_ids")
        if not isinstance(node_name, str) or not NODE_NAME_PATTERN.fullmatch(node_name):
            raise ProxyResourceError("节点名称无效。")
        if not isinstance(exit_ids, list):
            raise ProxyResourceError("节点中转出口选择格式无效。")
        known = {
            item.get("id") for item in config["exits"] if isinstance(item, dict)
        }
        if any(not isinstance(item, str) or item not in known for item in exit_ids):
            raise ProxyResourceError("节点出口选择包含不存在的出口节点。")
        config["awg_exit_selections"][node_name] = list(dict.fromkeys(exit_ids))
    else:
        raise ProxyResourceError("机场资源动作未登记。")
    return config


def _write_config(path: Path, config: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def update(path: Path, payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ProxyResourceError("机场资源请求格式不正确。")
    config = load_config(path)
    if set(payload) == {"airport_url", "exit_proxy_yaml"}:
        config = _legacy_update(config, payload)
    else:
        config = _apply_operation(config, payload)
    # 所有写操作都会同时完成旧格式迁移和全目录一致性校验。
    temporary_config = {**config, "version": CONFIG_VERSION}
    airports = temporary_config.get("airports", [])
    checked_path = path.with_name(f".{path.name}.validate.{os.getpid()}")
    try:
        _write_config(checked_path, temporary_config)
        validated = normalized_config(checked_path)
    finally:
        try:
            checked_path.unlink()
        except FileNotFoundError:
            pass
    _write_config(path, validated)
    return overview(path)


def _test_airport(airport: dict) -> dict:
    ok = False
    status = "连接失败"
    try:
        request = Request(airport["url"], headers={"Range": "bytes=0-0", "User-Agent": "server-kit-health/1"})
        with urlopen(request, timeout=8) as response:
            response.read(1)
            status = f"HTTP {response.status}"
            ok = 200 <= response.status < 500
    except HTTPError as exc:
        status = f"HTTP {exc.code}"
        ok = 200 <= exc.code < 500
    except (URLError, OSError, ValueError):
        pass
    safe = _safe_airport(airport)
    return {"id": safe["id"], "name": safe["name"], "enabled": safe["enabled"], "ok": ok, "status": status}


def test_resources(path: Path) -> dict[str, object]:
    config = normalized_config(path)
    airports = config["airports"]
    with ThreadPoolExecutor(max_workers=min(4, max(1, len(airports)))) as executor:
        airport_results = list(executor.map(_test_airport, airports))
    exit_results = []
    for exit_node in config["exits"]:
        proxy = exit_node["proxy"]
        exit_ok = False
        exit_status = "未配置"
        server = proxy.get("server")
        port = proxy.get("port")
        if isinstance(server, str) and server and isinstance(port, int) and 1 <= port <= 65535:
            try:
                with socket.create_connection((server, port), timeout=8):
                    pass
                exit_ok = True
                exit_status = "TCP 可达"
            except OSError:
                exit_status = "连接失败"
        exit_results.append({
            "id": exit_node["id"], "name": exit_node["name"],
            "default": exit_node["id"] == config["default_exit_id"],
            "ok": exit_ok, "status": exit_status,
        })
    enabled_results = [item for item in airport_results if item["enabled"]]
    return {
        "schema_version": 3,
        "airports": airport_results,
        "exits": exit_results,
        "all_ok": (
            bool(enabled_results)
            and all(item["ok"] for item in enabled_results)
            and bool(exit_results)
            and all(item["ok"] for item in exit_results)
        ),
    }


def main() -> int:
    if len(sys.argv) not in {3, 5} or sys.argv[1] not in {"overview", "update", "test", "reveal"}:
        print("机场资源参数不正确。", file=sys.stderr)
        return 1
    path = Path(sys.argv[2])
    try:
        if sys.argv[1] == "reveal":
            if len(sys.argv) != 5:
                raise ProxyResourceError("敏感代理资源参数不正确。")
            result = reveal(path, sys.argv[3], sys.argv[4])
        elif len(sys.argv) != 3:
            raise ProxyResourceError("机场资源参数不正确。")
        elif sys.argv[1] == "overview":
            result = overview(path)
        elif sys.argv[1] == "test":
            result = test_resources(path)
        else:
            result = update(path, json.load(sys.stdin))
    except ProxyResourceError as exc:
        if sys.argv[1] == "update":
            print(f"SERVER_KIT_DIAGNOSTIC:proxy_input_invalid:{exc}", file=sys.stderr)
        else:
            print(str(exc), file=sys.stderr)
        return 1
    except (ValueError, json.JSONDecodeError):
        # 解析异常可能包含原始输入，只返回固定提示。
        if sys.argv[1] == "update":
            print("SERVER_KIT_DIAGNOSTIC:proxy_input_invalid:请求 JSON 或配置文件格式无效。", file=sys.stderr)
        else:
            print("机场资源读取失败。", file=sys.stderr)
        return 1
    except OSError:
        # 文件系统异常可能包含路径，只返回阶段代码。
        if sys.argv[1] == "update":
            print("SERVER_KIT_DIAGNOSTIC:proxy_storage_failed", file=sys.stderr)
        else:
            print("机场资源读取失败。", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
