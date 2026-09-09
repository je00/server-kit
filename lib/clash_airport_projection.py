#!/usr/bin/env python3
"""把机场资源目录投影为 Mihomo provider、国家组和 PROXY 成员。"""

from __future__ import annotations

import copy

from ruamel.yaml.comments import CommentedMap, CommentedSeq

try:
    from .server_kit_proxy_resources import COUNTRY_BY_ID, ProxyResourceError
except ImportError:  # 直接执行调用方位于 lib 目录时
    from server_kit_proxy_resources import COUNTRY_BY_ID, ProxyResourceError


PROVIDER_PREFIX = "airport-"
GROUP_PREFIX = "机场 · "
LEGACY_PROVIDER = "airport"
LEGACY_GROUP = "plane-tw"


def _named_group(groups: list, name: str) -> dict:
    for group in groups:
        if isinstance(group, dict) and group.get("name") == name:
            return group
    raise ProxyResourceError(f"Clash 骨架缺少 {name} 策略组。")


def _provider_template(providers: dict) -> dict:
    legacy = providers.get(LEGACY_PROVIDER)
    if isinstance(legacy, dict):
        return copy.deepcopy(legacy)
    for key, value in providers.items():
        if isinstance(key, str) and key.startswith(PROVIDER_PREFIX) and isinstance(value, dict):
            return copy.deepcopy(value)
    return CommentedMap({
        "type": "http",
        "interval": 3600,
        "health-check": CommentedMap({
            "enable": True,
            "url": "https://8.8.8.8/generate_204",
            "interval": 300,
            "lazy": False,
        }),
    })


def _make_provider(template: dict, airport: dict) -> CommentedMap:
    provider = copy.deepcopy(template)
    if not isinstance(provider, CommentedMap):
        provider = CommentedMap(provider)
    provider["type"] = "http"
    provider["url"] = airport["url"]
    provider["path"] = f"./proxy_providers/{PROVIDER_PREFIX}{airport['id']}.yaml"
    provider.pop("filter", None)
    provider.pop("exclude-filter", None)
    override = provider.get("override")
    if not isinstance(override, dict):
        override = CommentedMap()
        provider["override"] = override
    override["additional-prefix"] = f"[{airport['name']}] "
    return provider


def _make_country_group(airport: dict, country_id: str, provider_name: str) -> CommentedMap:
    country = COUNTRY_BY_ID[country_id]
    group = CommentedMap({
        "name": f"{GROUP_PREFIX}{airport['name']} · {country['label']}",
        "type": "url-test",
        "use": CommentedSeq([provider_name]),
        "url": "https://8.8.8.8/generate_204",
        "interval": 300,
        "lazy": False,
        "tolerance": 50,
    })
    if country["filter"]:
        group["filter"] = country["filter"]
    return group


def apply_airport_projection(config: dict, catalog: dict) -> list[str]:
    """原地更新 Clash 配置并返回加入 PROXY 的机场国家组名称。"""

    providers = config.get("proxy-providers")
    groups = config.get("proxy-groups")
    airports = catalog.get("airports")
    if not isinstance(providers, dict):
        raise ProxyResourceError("Clash 骨架缺少 proxy-providers。")
    if not isinstance(groups, list):
        raise ProxyResourceError("Clash 骨架缺少 proxy-groups。")
    if not isinstance(airports, list):
        raise ProxyResourceError("机场资源目录格式无效。")

    template = _provider_template(providers)
    retained_providers = CommentedMap()
    for key, value in providers.items():
        if key == LEGACY_PROVIDER or (isinstance(key, str) and key.startswith(PROVIDER_PREFIX)):
            continue
        retained_providers[key] = value

    generated_groups: list[CommentedMap] = []
    generated_names: list[str] = []
    for airport in airports:
        if not isinstance(airport, dict) or not airport.get("enabled"):
            continue
        provider_name = f"{PROVIDER_PREFIX}{airport['id']}"
        retained_providers[provider_name] = _make_provider(template, airport)
        for country_id in airport["countries"]:
            group = _make_country_group(airport, country_id, provider_name)
            generated_groups.append(group)
            generated_names.append(group["name"])

    config["proxy-providers"] = retained_providers
    retained_groups = CommentedSeq(
        group for group in groups
        if not (
            isinstance(group, dict)
            and (
                group.get("name") == LEGACY_GROUP
                or str(group.get("name", "")).startswith(GROUP_PREFIX)
            )
        )
    )
    proxy_group = _named_group(retained_groups, "PROXY")
    proxies = proxy_group.get("proxies")
    if not isinstance(proxies, list):
        proxies = CommentedSeq()
        proxy_group["proxies"] = proxies
    proxies[:] = [
        value for value in proxies
        if isinstance(value, str) and value != LEGACY_GROUP and not value.startswith(GROUP_PREFIX)
    ]
    proxies.extend(generated_names)
    proxy_group.pop("use", None)

    mid_group = _named_group(retained_groups, "MID")
    mid_index = retained_groups.index(mid_group)
    for offset, group in enumerate(generated_groups, 1):
        retained_groups.insert(mid_index + offset, group)
    config["proxy-groups"] = retained_groups
    return generated_names


def apply_clean_projection(config: dict) -> None:
    """移除机场入口，并隐藏 PROXY 中所有可被误选的 MID 出口。"""

    providers = config.get("proxy-providers")
    groups = config.get("proxy-groups")
    if not isinstance(providers, dict):
        raise ProxyResourceError("Clash 配置缺少 proxy-providers。")
    if not isinstance(groups, list):
        raise ProxyResourceError("Clash 配置缺少 proxy-groups。")

    config["proxy-providers"] = CommentedMap(
        (key, value)
        for key, value in providers.items()
        if key != LEGACY_PROVIDER
        and not (isinstance(key, str) and key.startswith(PROVIDER_PREFIX))
    )
    retained_groups = CommentedSeq(
        group for group in groups
        if not (
            isinstance(group, dict)
            and (
                group.get("name") == LEGACY_GROUP
                or str(group.get("name", "")).startswith(GROUP_PREFIX)
            )
        )
    )
    proxy_group = _named_group(retained_groups, "PROXY")
    proxies = proxy_group.get("proxies")
    if not isinstance(proxies, list):
        raise ProxyResourceError("Clash 配置的 PROXY 成员必须是列表。")
    proxies[:] = [
        value for value in proxies
        if isinstance(value, str)
        and value not in {LEGACY_GROUP, "MID", "chain.mid.proxy"}
        and not value.startswith("EXIT.")
        and not value.startswith(GROUP_PREFIX)
    ]
    proxy_group.pop("use", None)
    config_proxies = config.get("proxies")
    if not isinstance(config_proxies, list):
        raise ProxyResourceError("Clash 配置缺少 proxies。")
    config_proxies[:] = [
        value for value in config_proxies
        if not (
            isinstance(value, dict)
            and isinstance(value.get("name"), str)
            and (
                value.get("name") == "chain.mid.proxy"
                or value.get("name").startswith("EXIT.")
            )
        )
    ]
    config["proxy-groups"] = retained_groups
