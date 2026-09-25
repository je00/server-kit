"""Preview-only routes. Imported exclusively by tests/run_web_preview.py."""

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse
from django.shortcuts import render
from django.urls import path
from django.utils.html import format_html, format_html_join

from preview_fixtures import SERVICE_IDS, TASK_IDS, make_task
from server_kit_web.urls import urlpatterns as production_patterns


AGENT = None
CONFIRMS = {
    "service": "service_confirm", "network": "network_task_confirm",
    "subscription": "subscription_task_confirm", "proxy": "proxy_resource_confirm",
    "firewall": "firewall_port_confirm", "managed-port": "managed_port_confirm",
    "ssh-key": "ssh_key_task_confirm", "file": "file_task_confirm",
    "backup": "backup_delete_confirm", "security": "security_transaction_confirm",
    "legacy-network": "network_confirm", "legacy-ssh": "ssh_key_confirm", "legacy-file": "file_delete_confirm",
}
PAGES = ["/", "/network/nodes/", "/network/subscriptions/", "/network/proxy/", "/files/",
         "/guides/nodes/", "/deploy/", "/audit/", "/accounts/", "/backups/", "/security/transactions/"]
PAGES += [f"/services/{key}/" for key in SERVICE_IDS]
PAGES += [f"/tasks/{task_id}/" for task_id in TASK_IDS.values()]
PAGES += [f"/__preview__/confirm/{key}/" for key in CONFIRMS]


@login_required
def preview_index(request):
    links = format_html_join("", '<li><a href="{}">{}</a></li>', ((route, route) for route in PAGES))
    scenarios = format_html_join("", '<li><a href="/__preview__/scenario/{}/">{}</a></li>', ((key, key) for key in ("rich", "empty", "error", "pending")))
    return HttpResponse(format_html('<!doctype html><html lang="zh"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local visual preview</title><body style="font:16px/1.7 system-ui;max-width:960px;margin:40px auto;padding:0 20px"><h1>本地视觉审查 · 合成数据</h1><p>仅本机临时环境，不读取或操作 VPS。当前场景：<strong>{}</strong>。切换场景会重置所有预览浏览器的数据。</p><h2>场景</h2><ul>{}</ul><h2>页面清单</h2><ul>{}</ul></body></html>', AGENT.scenario, scenarios, links))


@login_required
def preview_scenario(request, scenario):
    if scenario not in {"rich", "empty", "error", "pending"}:
        raise Http404
    AGENT.set_scenario(scenario)
    return preview_index(request)


@login_required
def preview_confirm(request, kind):
    template = CONFIRMS.get(kind)
    if not template:
        raise Http404
    task = make_task("waiting_confirmation")
    context = {"task": task, "active_page": "nodes", "service_id": "clash", "operation": "open", "scope": "public",
               "target_type": "permission", "client_name": "iphone-travel", "target": "nas-storage-primary",
               "ports": "22,443,8000-8010", "network": "TCP", "operation_label": "新增访问权限",
               "name": "office-workstation-development-team-01", "kind_label": "AmneziaWG", "address": "10.20.0.11",
               "item_id": "home-desktop", "state": "disabled", "transaction_type": "firewall",
               "backup_id": "backup-20260924T094100Z-1234abcd", "resource_id": "file-0000000000000001",
               "change": {"operation": "delete", "operation_label": "删除", "name": "development-team-workstation", "type": "ssh-ed25519", "fingerprint": "SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghi"},
               "item": {"name": "server-kit-client-configuration-guide-2026-09-final-reviewed.zip", "resource_id": "file-0000000000000001", "size_label": "92 MiB", "cdn_cache": True, "cache_label": "24 小时"}}
    if kind == "subscription":
        context["target_type"] = "rotate"
    # Distinct realistic facts exercise IDs, fingerprints and filenames that
    # do not occur in the shared network-permission fixture.
    variants = {
        "service": ("重启 Clash 订阅", "dashboard", {"服务": "Clash 订阅", "当前状态": "运行中", "目标状态": "运行中", "影响": "下载连接短暂中断，内网连接保持不变"}),
        "subscription": ("轮换 home-desktop 的订阅令牌", "nodes", {"受影响订阅": "home-desktop", "旧链接": "成功后立即失效", "其他订阅": "不变"}),
        "proxy": ("更新主用机场的国家与地区", "proxy", {"机场": "主用机场 · 日常与远程办公", "加入地区": "香港、日本、新加坡、美国、德国、法国", "出口": "dedicated-us-primary", "发布订阅": "全部刷新"}),
        "firewall": ("开放公网 TCP + UDP 5201", "dashboard", {"端口": "5201", "访问范围": "公网", "协议": "TCP + UDP", "期限": "1 小时", "现有占用": "未占用"}),
        "managed-port": ("修改 Clash 订阅端口", "dashboard", {"当前端口": "52541/TCP", "新端口": "52542/TCP", "开放范围": "公网", "客户端影响": "订阅链接端口会变化，请更新客户端链接"}),
        "ssh-key": ("删除开发笔记本 SSH 公钥", "dashboard", {"客户端名称": "development-team-workstation", "密钥类型": "ssh-ed25519", "SHA256 指纹": "SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghi", "影响": "该设备将无法建立新的 SSH 连接"}),
        "file": ("删除源站文件", "files", {"文件名称": context["item"]["name"], "文件大小": "92 MiB", "资源标识": context["resource_id"], "CDN 缓存": "最多保留 24 小时"}),
        "backup": ("删除加密配置备份", "backups", {"备份标识": context["backup_id"], "创建时间": "2026-09-24T09:41:05.000Z", "加密方式": "AES-256-GCM", "覆盖类别": "amneziawg、management、server-kit、firewall", "私钥托管": "不含客户端私钥"}),
        "security": ("应用主机防火墙变更", "security", {"规则表": "inet server_kit_filter", "公网 TCP": "443,52541,61212", "内网 TCP": "22,9080", "回滚窗口": "300 秒", "最终确认": "必须通过另一条独立连接"}),
    }
    if kind in variants:
        title, active_page, facts = variants[kind]
        task["preview"]["title"] = title
        task["preview"]["facts"] = facts
        context["active_page"] = active_page
    if kind == "security":
        context.update(operation="apply", operation_label="应用主机防火墙变更")
        task["preview"]["changes"] = [{"label": "公网 TCP", "current": "443", "target": "443,52541,61212", "changed": True}]
    return render(request, f"dashboard/{template}.html", context)


urlpatterns = [path("__preview__/", preview_index), path("__preview__/scenario/<str:scenario>/", preview_scenario),
               path("__preview__/confirm/<str:kind>/", preview_confirm), *production_patterns]
