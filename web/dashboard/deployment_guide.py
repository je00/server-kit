"""把跨平台接入流程建模为稳定旅程，平台差异只存在于本模块。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformGuide:
    platform: str
    tab: str
    eyebrow: str
    title: str
    description: str
    badge: str
    steps: tuple[dict[str, object], ...]


APP_CATALOG = {
    "awg-windows": ("AmneziaWG", "下载 Windows x64 版 ↗", "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest"),
    "awg-linux": ("AmneziaWG", "综合脚本会自动安装 · 查看项目 ↗", "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module"),
    "awg-macos": ("AmneziaWG", "从 Mac App Store 安装 ↗", "https://apps.apple.com/app/amneziawg/id6478942365"),
    "clash-windows": ("Clash Verge", "下载 Windows x64 正常版 ↗", "https://github.com/Clash-Verge-rev/clash-verge-rev/releases/latest"),
    "clash-linux": ("Clash Verge", "选择 DEB 或 RPM ↗", "https://github.com/Clash-Verge-rev/clash-verge-rev/releases/latest"),
    "clash-macos": ("Clash Verge", "选择 Intel 或 Apple 芯片版 ↗", "https://github.com/Clash-Verge-rev/clash-verge-rev/releases/latest"),
    "stash-macos": ("Stash（可选）", "已有用户可继续使用 ↗", "https://apps.apple.com/app/stash-rule-based-proxy/id1596063349?platform=mac"),
    "stash-ios": ("Stash", "从 App Store 安装 ↗", "https://apps.apple.com/app/stash-rule-based-proxy/id1596063349"),
    "flclash-android": ("FlClash", "多数手机选择 arm64-v8a APK ↗", "https://github.com/chen08209/FlClash/releases/latest"),
}


def _apps(*keys: str) -> tuple[dict[str, str], ...]:
    return tuple(
        {"name": APP_CATALOG[key][0], "note": APP_CATALOG[key][1], "url": APP_CATALOG[key][2]}
        for key in keys
    )


def _manager_step(
    platform: str,
    role: str,
    *,
    apps: tuple[dict[str, str], ...] = (),
    vless: bool = False,
) -> dict[str, object]:
    node = role == "node"
    if platform == "linux" and node:
        text = (
            "先下载主/备两个入口配置和全平台脚本包。解压后直接运行 Linux 综合脚本进入菜单，"
            "选择“安装或更新 AWG，并导入双入口配置”；脚本会自动安装 AmneziaWG、导入配置并启用主入口。"
        )
    elif vless and node:
        text = "创建以本设备命名的 VLESS 节点，只授权确实需要访问的设备和端口。"
    elif node:
        text = "先安装本步骤的 AmneziaWG，再创建普通节点；下载主/备两个入口并全部导入，只开启主入口。"
    else:
        text = "先安装本步骤的代理客户端，再找到与本设备同名的订阅；从 URL 导入，手机也可以扫描二维码。"
    return {
        "role": role,
        "kind": "授权" if vless and node else "内网" if node else "订阅",
        "type": "manager",
        "title": "创建 VLESS 节点" if vless and node else "创建并导入 AWG 节点" if node else "安装并导入本机订阅",
        "text": text,
        "apps": apps,
        "manager_url": "network-nodes" if node else "network-subscriptions",
        "manager_anchor": "node-create" if node else "subscription-list",
        "button": "打开节点管理" if node else "领取订阅",
        "element_id": f"guide-{platform}-{role}",
        "linux_awg_setup": bool(platform == "linux" and node),
        "windows_awg_autostart": bool(platform == "windows" and node),
    }


def _ssh_step(platform: str) -> dict[str, object]:
    return {
        "role": "ssh", "kind": "可选", "type": "ssh", "title": "SSH 管理（可选）",
        "text": "脚本可安装 SSH、调整端口和允许来源网段、管理公钥；关闭密码认证时会保留 5 分钟自动回滚。", "platform": platform,
    }


def build_deployment_journey() -> tuple[PlatformGuide, ...]:
    """返回顺序稳定、可由模板直接呈现的五平台接入旅程。"""
    clash = {
        "role": "tunnel", "kind": "必做", "type": "clash_tun",
        "title": "开启虚拟网卡模式",
    }
    guides = (
        PlatformGuide("windows", "Windows", "Windows 10 / 11", "Windows", "使用 AWG 节点，设备之间可以双向访问。", "AWG", (
            _manager_step("windows", "node", apps=_apps("awg-windows")),
            _manager_step("windows", "subscription", apps=_apps("clash-windows")),
            clash,
            {"role": "verify", "kind": "验证", "type": "text", "title": "确认接入成功", "text": "开启 AmneziaWG 和 Clash Verge 虚拟网卡模式。网页能访问、SSH 能连接 10.20.0.1 即完成；不要只用 Ping 判断。"},
            _ssh_step("windows"),
        )),
        PlatformGuide("linux", "Linux", "Debian / Ubuntu", "Linux", "使用 AWG 节点，设备之间可以双向访问。", "AWG", (
            _manager_step("linux", "node", apps=_apps("awg-linux")),
            _manager_step("linux", "subscription", apps=_apps("clash-linux")),
            clash,
            {"role": "verify", "kind": "验证", "type": "text", "title": "确认接入成功", "text": "AWG 和 Clash Verge 都开启后，用 SSH 连接 10.20.0.1；能建立连接即完成。"},
            _ssh_step("linux"),
        )),
        PlatformGuide("macos", "Mac", "macOS", "Mac", "推荐使用 AmneziaWG 与 Clash Verge；已有 Stash 也可继续使用。", "AWG", (
            _manager_step("macos", "node", apps=_apps("awg-macos")),
            _manager_step("macos", "subscription", apps=_apps("clash-macos", "stash-macos")),
            {**clash, "stash_note": True},
            {"role": "verify", "kind": "验证", "type": "text", "title": "确认接入成功", "text": "开启 AWG 和代理客户端，用 SSH 连接 10.20.0.1；能建立连接即完成。"},
            _ssh_step("macos"),
        )),
        PlatformGuide("iphone", "iPhone", "iOS 16+", "iPhone", "Stash 通过 VLESS 访问明确授权的内网设备。", "VLESS", (
            _manager_step("iphone", "node", vless=True),
            _manager_step("iphone", "subscription", apps=_apps("stash-ios"), vless=True),
            {"role": "tunnel", "kind": "必做", "type": "stash_route", "title": "删除冲突的跳过路由"},
            {"role": "verify", "kind": "验证", "type": "text", "title": "确认授权生效", "text": "连接已授权的 10.20.0.x。已授权设备应能连接，未授权设备必须失败。"},
        )),
        PlatformGuide("android", "Android", "Android 7+", "Android", "FlClash 通过 VLESS 访问明确授权的内网设备。", "VLESS", (
            _manager_step("android", "node", vless=True),
            _manager_step("android", "subscription", apps=_apps("flclash-android"), vless=True),
            {"role": "tunnel", "kind": "导入", "type": "text", "title": "启用订阅", "text": "打开“FlClash → 配置 → 从 URL 导入”，粘贴链接并启用。"},
            {"role": "verify", "kind": "验证", "type": "text", "title": "确认授权生效", "text": "连接已授权的 10.20.0.x。已授权设备应能连接，未授权设备必须失败。"},
        )),
    )
    _validate_journey(guides)
    return guides


def _validate_journey(guides: tuple[PlatformGuide, ...]) -> None:
    required = ("node", "subscription", "tunnel", "verify")
    for guide in guides:
        roles = tuple(str(step["role"]) for step in guide.steps)
        if roles[:4] != required or "software" in roles:
            raise RuntimeError(f"{guide.platform} 接入旅程顺序不完整")
        subscription = guide.steps[1]
        if not subscription.get("apps"):
            raise RuntimeError(f"{guide.platform} 的订阅步骤缺少客户端")
        if guide.badge == "AWG":
            if not guide.steps[0].get("apps") or roles[-1] != "ssh":
                raise RuntimeError(f"{guide.platform} 缺少 AWG 客户端或 SSH 管理步骤")
