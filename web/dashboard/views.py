"""总览和健康检查页面。"""

from __future__ import annotations

import secrets
import hashlib
import json
import os
import shutil
import time
import re
import ipaddress
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import RequestDataTooBig, ValidationError
from django.db import IntegrityError, transaction
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from .models import DismissedNetworkNotice
from .task_navigation import task_navigation_context
from django.views.decorators.http import require_http_methods

from control_plane.client import AgentError
from lib.server_kit_bootstrap import BootstrapError, decode_enrollment_token
from lib.server_kit_port_ranges import PortRangeError, normalize_ports

from .snapshot import read_snapshot
from .ssh_scripts import SshScriptBundle
from .deployment_guide import build_deployment_journey
from .services import (
    change_task,
    change_tasks,
    cancel_change_task,
    confirm_change_task,
    describe_service,
    preview_change_task,
    manage_backup,
    manage_security_transaction,
    firewall_ports,
    preview_firewall_port_task,
    preview_managed_port_task,
    ssh_keys,
    preview_ssh_key_change_task,
    preview_backup_task,
    preview_backup_restore_task,
    network_overview,
    public_endpoint_status,
    public_endpoint_transaction_status,
    duckdns_status,
    preview_duckdns_task,
    preview_public_endpoint_task,
    enrollment_context,
    preview_network_node_task,
    preview_node_domains_task,
    preview_address_domains_task,
    preview_network_node_import_task,
    preview_network_permission_task,
    preview_network_permission_batch_task,
    preview_subscription_sync_task,
    preview_subscription_rotate_task,
    preview_subscription_state_task,
    audit_log,
    record_audit_event,
    proxy_resources,
    reveal_proxy_resource,
    test_proxy_resources,
    preview_proxy_change_task,
    preview_node_exits_task,
    preview_security_transaction_task,
    preview_deployment_task,
    reveal_clash_resource,
    file_resources,
    preview_file_change_task,
    reveal_file_resource,
)


NETWORK_NOTICE_MAX_AGE_SECONDS = 2 * 60 * 60
NETWORK_NOTICE_STATES = {
    "enrollment_history": {"已超时"},
}


def _network_notice_is_recent(event):
    """只把刚发生的网络事件提升为页面提醒。"""
    completed_at = str(event.get("completed_at", "")).strip()
    if not completed_at:
        return False
    try:
        completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if completed.tzinfo is None:
        completed = completed.replace(tzinfo=timezone.utc)
    age_seconds = time.time() - completed.timestamp()
    return -300 <= age_seconds <= NETWORK_NOTICE_MAX_AGE_SECONDS


OPERATION_LABELS = {
    "start": "启动",
    "stop": "停止",
    "restart": "重启",
}
CONFIRMATION_MAX_AGE = 300
TRANSACTION_LABELS = {
    "ssh_auth": "SSH 认证", "ssh_listener": "SSH 监听", "firewall": "主机防火墙",
    "vless_listener": "VLESS 公网监听",
}
TRANSACTION_OPERATION_LABELS = {
    "apply": "应用并启动自动回滚",
    "confirm": "确认并持久化",
    "rollback": "立即回滚",
}
BACKUP_ID_PATTERN = re.compile(r"backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
SENSITIVE_UNLOCK_SESSION_KEY = "sensitive_resource_unlocked_at"
SENSITIVE_UNLOCK_MAX_AGE = 300
NODE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
NODE_OPERATION_LABELS = {
    "add": "新增", "import": "导入", "enable": "启用", "disable": "禁用",
    "remove": "删除", "set-management": "设为管理入口",
    "compat-enable": "启用旧版 Stash 兼容",
    "compat-disable": "关闭旧版 Stash 兼容",
    "clean-enable": "启用订阅纯净模式",
    "clean-disable": "关闭订阅纯净模式",
}
NODE_KIND_LABELS = {"awg": "AmneziaWG 普通节点", "vless": "VLESS 单向节点"}
FILE_RESOURCE_PATTERN = re.compile(r"file-[0-9a-f]{16}\Z")
FIREWALL_PORT_SCOPES = {
    "public": "公网",
    "amneziawg": "AmneziaWG 内网",
}
FIREWALL_PORT_PROTOCOLS = {
    "tcp": "TCP",
    "udp": "UDP",
    "both": "TCP + UDP",
}
FIREWALL_PORT_DURATIONS = {
    "3600": "1 小时",
    "14400": "4 小时",
    "86400": "1 天",
    "604800": "7 天",
    "permanent": "永久",
}
TASK_ID_PATTERN = re.compile(r"task-[0-9a-f]{32}\Z")
SSH_KEY_ID_PATTERN = re.compile(r"key-[0-9a-f]{64}\Z")
def _can_manage(user) -> bool:
    return bool(user.is_superuser or user.is_staff)


def _operations(description):
    return [
        {"id": item, "label": OPERATION_LABELS[item]}
        for item in description.get("allowed_operations", [])
        if item in OPERATION_LABELS
    ]


def _raise_404_if_missing(error: AgentError):
    if error.code == "not_found":
        raise Http404("托管服务不存在")


def _safe_upload_name(value: str) -> str:
    original = value.replace("\\", "/").rsplit("/", 1)[-1]
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", original).strip("._") or "shared_file.bin"
    safe_name = safe_name[:128]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", safe_name):
        raise ValueError("文件名无法安全规范化。")
    return safe_name


def _stage_upload(uploaded) -> tuple[str, Path]:
    if uploaded is None or not 1 <= uploaded.size <= settings.SERVER_KIT_MAX_UPLOAD_BYTES:
        raise ValueError("上传文件必须为 1 B–2 GiB。")
    upload_id = secrets.token_hex(16)
    upload_dir = settings.SERVER_KIT_UPLOAD_DIR / upload_id
    settings.SERVER_KIT_UPLOAD_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(settings.SERVER_KIT_UPLOAD_DIR, 0o700)
    upload_dir.mkdir(mode=0o700)
    payload_path = upload_dir / "payload"
    with payload_path.open("xb") as target:
        for chunk in uploaded.chunks():
            target.write(chunk)
        target.flush()
        os.fsync(target.fileno())
    os.chmod(payload_path, 0o600)
    return upload_id, upload_dir


def _detail_context(description):
    return {
        "description": description,
        "service": description["service"],
        "operations": _operations(description),
        "active_page": "dashboard",
    }


def _format_bytes(value) -> str:
    if not isinstance(value, int) or value < 0:
        return "—"
    for divisor, suffix in ((1024**3, "GiB"), (1024**2, "MiB")):
        if value >= divisor:
            return f"{value / divisor:.1f} {suffix}"
    return f"{value / 1024:.0f} KiB"


def _format_uptime(value) -> tuple[str, str]:
    if not isinstance(value, int) or value < 0:
        return "—", "暂不可用"
    days, remainder = divmod(value, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"运行 {days} 天", f"{hours} 小时 {minutes} 分钟"
    if hours:
        return f"运行 {hours} 小时", f"{minutes} 分钟"
    return f"运行 {minutes} 分钟", "持续在线"


def _format_firewall_duration(item: dict[str, object]) -> str:
    if item.get("duration") == "permanent":
        return "永久"
    remaining = item.get("remaining_seconds")
    if not isinstance(remaining, int) or remaining <= 0:
        return "即将到期"
    if remaining >= 86400:
        return f"剩余 {(remaining + 86399) // 86400} 天"
    if remaining >= 3600:
        return f"剩余 {(remaining + 3599) // 3600} 小时"
    return f"剩余 {(remaining + 59) // 60} 分钟"


def _valid_ssh_client_name(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and 1 <= len(value.strip()) <= 64
        and not any(unicodedata.category(char).startswith("C") for char in value.strip())
    )


def _resource_cards(snapshot) -> list[dict[str, object]]:
    resources = snapshot.get("resources") if isinstance(snapshot, dict) else None
    resources = resources if isinstance(resources, dict) else {}
    cpu = resources.get("cpu") if isinstance(resources.get("cpu"), dict) else {}
    memory = resources.get("memory") if isinstance(resources.get("memory"), dict) else {}
    disk = resources.get("disk") if isinstance(resources.get("disk"), dict) else {}

    def percent(value):
        return value if isinstance(value, (int, float)) and 0 <= value <= 100 else None

    load_1 = cpu.get("load_1")
    load_value = f"{load_1:.2f}" if isinstance(load_1, (int, float)) else "—"
    cores = cpu.get("cores") if isinstance(cpu.get("cores"), int) else 0
    load_5 = cpu.get("load_5")
    cpu_detail = (
        f"{cores} 核 · 5 分钟 {load_5:.2f}"
        if cores and isinstance(load_5, (int, float))
        else "暂不可用"
    )
    cpu_meter = min(100.0, load_1 * 100.0 / cores) if cores and isinstance(load_1, (int, float)) else None
    memory_percent = percent(memory.get("usage_percent"))
    disk_percent = percent(disk.get("usage_percent"))
    uptime_value, uptime_detail = _format_uptime(resources.get("uptime_seconds"))
    return [
        {
            "label": "1 分钟负载",
            "value": load_value,
            "detail": cpu_detail,
            "meter": cpu_meter,
            "has_meter": cpu_meter is not None,
        },
        {
            "label": "内存",
            "value": f"{memory_percent:g}%" if memory_percent is not None else "—",
            "detail": f"{_format_bytes(memory.get('used_bytes'))} / {_format_bytes(memory.get('total_bytes'))}",
            "meter": memory_percent,
            "has_meter": memory_percent is not None,
        },
        {
            "label": "系统磁盘",
            "value": f"{disk_percent:g}%" if disk_percent is not None else "—",
            "detail": f"{_format_bytes(disk.get('used_bytes'))} / {_format_bytes(disk.get('total_bytes'))}",
            "meter": disk_percent,
            "has_meter": disk_percent is not None,
        },
        {
            "label": "在线时长",
            "value": uptime_value,
            "detail": uptime_detail,
            "meter": None,
            "has_meter": False,
        },
    ]


def health(request):
    """只报告 Web 进程健康，不暴露主机配置。"""
    return JsonResponse({"status": "ok"})


@login_required
def dashboard(request):
    error = ""
    snapshot = {"summary": {}, "services": []}
    try:
        snapshot = read_snapshot()
    except (AgentError, OSError):
        error = "暂时无法读取主机状态，请检查管理代理。"
    return render(
        request,
        "dashboard/index.html",
        {
            "snapshot": snapshot,
            "resource_cards": _resource_cards(snapshot),
            "snapshot_error": error,
            "active_page": "dashboard",
        },
    )


@login_required
def node_deployment_guide(request):
    """按设备给出普通节点、受限节点和 SSH 的最短部署路径。"""
    return render(
        request,
        "dashboard/node_deployment_guide.html",
        {
            "active_page": "deploy",
            "platform_guides": build_deployment_journey(),
            "linux_node_script_url": request.build_absolute_uri(
                reverse("linux-node-script-download")
            ),
        },
    )


def _script_download_response(download):
    """统一生成不可嗅探、不会被中间缓存长期保存的脚本下载响应。"""
    response = HttpResponse(download.payload, content_type=download.content_type)
    response["Content-Disposition"] = f'attachment; filename="{download.filename}"'
    response["Cache-Control"] = "no-store, max-age=0"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@never_cache
def linux_node_script_download(request):
    """公开下载不含凭据的 Linux 节点综合脚本，供 wget 等工具使用。"""
    try:
        download = SshScriptBundle(
            Path(__file__).resolve().parent / "script_templates"
        ).download("linux")
    except (OSError, RuntimeError) as error:
        raise Http404("Linux 节点综合脚本暂不可用") from error
    return _script_download_response(download)


@login_required
@never_cache
def sshd_script_download(request, platform):
    """下载不含固定端口的跨动作 SSH 管理脚本。"""
    try:
        download = SshScriptBundle(
            Path(__file__).resolve().parent / "script_templates"
        ).download(platform)
    except ValueError:
        raise Http404("不支持该系统")
    except (OSError, RuntimeError) as error:
        raise Http404("SSH 管理脚本暂不可用") from error
    return _script_download_response(download)


@login_required
@never_cache
def sshd_script_archive_download(request):
    """一次下载所有受支持平台的节点管理脚本。"""
    try:
        download = SshScriptBundle(
            Path(__file__).resolve().parent / "script_templates"
        ).download_all()
    except (OSError, RuntimeError) as error:
        raise Http404("节点管理脚本包暂不可用") from error
    return _script_download_response(download)


def _sensitive_unlocked(request) -> bool:
    issued_at = request.session.get(SENSITIVE_UNLOCK_SESSION_KEY)
    return isinstance(issued_at, int) and 0 <= int(time.time()) - issued_at <= SENSITIVE_UNLOCK_MAX_AGE


def _sensitive_unlock_required_response() -> JsonResponse:
    """为所有按需敏感操作返回统一的二次验证信号。"""
    response = JsonResponse({
        "code": "sensitive_unlock_required",
        "error": "请验证当前账号密码后继续。",
    }, status=403)
    response["Cache-Control"] = "no-store, max-age=0"
    return response


def _network_context(request, active_page):
    try:
        overview = network_overview()
    except AgentError:
        overview = {"summary": {}, "nodes": [], "publications": [], "targets": []}
        error = "暂时无法读取节点与订阅状态，请检查管理代理。"
    else:
        error = ""
    network_snapshot_error = bool(error)
    targets = overview.get("targets", []) if isinstance(overview, dict) else []
    for node in overview.get("nodes", []) if isinstance(overview, dict) else []:
        if isinstance(node, dict):
            node["available_targets"] = [
                target for target in targets
                if isinstance(target, dict) and target.get("name") != node.get("name")
            ]
    dismissed_ids = set(
        DismissedNetworkNotice.objects.filter(user=request.user)
        .values_list("notice_id", flat=True)[:1000]
    )
    for history_name in ("enrollment_history",):
        visible = []
        for event in overview.get(history_name, []) if isinstance(overview, dict) else []:
            if not isinstance(event, dict):
                continue
            if (
                event.get("state") in NETWORK_NOTICE_STATES[history_name]
                and not _network_notice_is_recent(event)
            ):
                continue
            source = f"{history_name}:{event.get('name', '')}:{event.get('state', '')}:{event.get('completed_at', '')}"
            notice_id = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
            if notice_id in dismissed_ids:
                continue
            event["notice_id"] = notice_id
            visible.append(event)
        overview[history_name] = visible
    generator_context_json = ""
    generator_suggested_address = ""
    if active_page == "nodes" and _can_manage(request.user):
        try:
            generator_context = enrollment_context()
            generator_context_json = json.dumps(
                generator_context, ensure_ascii=False, separators=(",", ":"),
            )
            generator_suggested_address = str(generator_context.get("suggested_address", ""))
        except (AgentError, OSError, AttributeError):
            if not error:
                error = "节点状态可用，但暂时无法读取本地密钥生成参数。"
    public_endpoint_error = False
    try:
        endpoint_status = public_endpoint_status()
    except (AgentError, OSError):
        public_endpoint_error = True
        endpoint_status = {"configured": False, "fqdn": "", "current_ipv4": "", "dns_ipv4s": [], "matches_current_ipv4": None, "dns_ttl_status": "暂不可用", "diagnostics": ["稳定公网入口诊断暂不可用。"], "recovery_hint": "只读诊断失败不会影响节点管理。"}
    endpoint_transaction = {
        "state": "idle", "remaining_seconds": 0, "rollback_seconds": 300,
        "independent_session": False, "last_outcome": "",
    }
    if active_page == "subscriptions":
        try:
            endpoint_transaction = public_endpoint_transaction_status(
                request.user.get_username(), _security_session_id(request),
            )
        except (AgentError, OSError):
            endpoint_transaction = {
                "state": "unknown", "remaining_seconds": 0,
                "rollback_seconds": 300, "independent_session": False,
                "last_outcome": "",
            }
    duckdns_error = False
    try:
        duckdns = duckdns_status()
    except (AgentError, OSError):
        duckdns_error = True
        duckdns = {
            "configured": False, "enabled": False, "provider": "", "provider_label": "未配置",
            "fqdn": "", "zone": "", "record": "", "credentials_present": False,
            "token_present": False,
            "last_result": "", "last_update_at": "", "last_ipv4": "",
            "dns_ipv4s": [], "dns_matches_last_ipv4": None,
            "timer_state": "unknown", "next_run": "",
            "diagnostics": ["动态 DNS 自动更新状态暂不可用。"],
        }
    return {
        "network": overview,
        "snapshot_error": error,
        "network_snapshot_error": network_snapshot_error,
        "active_page": active_page,
        "sensitive_unlocked": _sensitive_unlocked(request),
        "generator_context_json": generator_context_json,
        "generator_suggested_address": generator_suggested_address,
        "public_endpoint": endpoint_status,
        "public_endpoint_error": public_endpoint_error,
        "public_endpoint_transaction": endpoint_transaction,
        "duckdns": duckdns,
        "duckdns_error": duckdns_error,
    }


@login_required
@never_cache
def network_nodes(request):
    """统一查看普通节点和 VLESS 单向节点。"""
    return render(request, "dashboard/network_nodes.html", _network_context(request, "nodes"))


@login_required
@require_POST
def network_notice_dismiss(request):
    notice_id = request.POST.get("notice_id", "")
    if not re.fullmatch(r"[0-9a-f]{16}", notice_id):
        return HttpResponseBadRequest("提示标识无效。")
    DismissedNetworkNotice.objects.get_or_create(
        user=request.user,
        notice_id=notice_id,
    )
    # 每个账号只保留最近 1000 条，避免历史事件无限增长。
    stale_ids = list(
        DismissedNetworkNotice.objects.filter(user=request.user)
        .values_list("id", flat=True)[1000:]
    )
    if stale_ids:
        DismissedNetworkNotice.objects.filter(id__in=stale_ids).delete()
    return redirect("network-nodes")


@login_required
@never_cache
def network_subscriptions(request):
    """集中管理稳定入口、动态 DNS 和全局强制解析。"""
    return render(request, "dashboard/network_subscriptions.html", _network_context(request, "subscriptions"))


@login_required
@never_cache
def task_audit(request):
    """展示经过 root 哈希链校验的最近管理动作。"""
    errors = []
    audit_error = False
    tasks_error = False
    try:
        result = audit_log()
    except AgentError:
        result = {"chain_valid": False, "items": []}
        audit_error = True
        errors.append("暂时无法读取或验证管理审计链。")
    try:
        tasks = change_tasks()
    except AgentError:
        tasks = {"items": []}
        tasks_error = True
        errors.append("暂时无法读取异步任务。")
    response = render(request, "dashboard/task_audit.html", {
        "audit": result, "tasks": tasks, "snapshot_error": " ".join(errors),
        "audit_error": audit_error, "tasks_error": tasks_error,
        "active_page": "audit",
    })
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@never_cache
def network_proxy_resources(request):
    """管理代理资源；敏感输入不进入会话、普通页面或审计。"""
    if request.method == "POST":
        if not _can_manage(request.user):
            return HttpResponseForbidden("只有管理员可以更新代理资源。")
        if request.POST.get("operation") == "test":
            try:
                result = test_proxy_resources(request.user.get_username())
            except AgentError:
                messages.error(request, "代理资源连通性测试无法完成。")
            else:
                level = messages.success if result.get("all_ok") else messages.warning
                airport_status = "；".join(
                    f"{item['name']}：{item['status']}" for item in result.get("airports", [])
                ) or "尚无机场"
                exit_status = "；".join(
                    f"{item['name']}：{item['status']}" for item in result.get("exits", [])
                ) or "尚无出口"
                level(request, f"{airport_status}；{exit_status}。")
        elif request.POST.get("confirmed") != "yes":
            messages.error(request, "请先确认更新会刷新全部订阅。")
        elif not request.user.check_password(request.POST.get("password", "")):
            messages.error(request, "当前账号密码不正确，未保存任何内容。")
        else:
            operation = request.POST.get("operation", "")
            try:
                exit_proxy_yaml = _exit_proxy_yaml_from_post(request.POST, operation)
            except ValueError as error:
                messages.error(request, str(error))
                return redirect("network-proxy-resources")
            values = {
                "operation": operation,
                "airport_id": request.POST.get("airport_id", ""),
                "airport_name": request.POST.get("airport_name", "").strip(),
                "airport_url": request.POST.get("airport_url", "").strip(),
                "airport_enabled": request.POST.get("airport_enabled") == "yes",
                "countries": request.POST.getlist("countries"),
                "exit_id": request.POST.get("exit_id", ""),
                "exit_name": request.POST.get("exit_name", "").strip(),
                "exit_default": request.POST.get("exit_default") == "yes",
                "exit_proxy_yaml": exit_proxy_yaml,
                "awg_name": "",
                "exit_ids": [],
            }
            airport_url = str(values["airport_url"])
            exit_proxy_yaml = str(values["exit_proxy_yaml"])
            if len(airport_url) > 8192 or len(exit_proxy_yaml) > 65536:
                messages.error(request, "粘贴内容过长，未保存任何内容。")
            else:
                try:
                    task = preview_proxy_change_task(
                        values, request.user.get_username()
                    )
                except AgentError:
                    messages.error(request, "代理资源验证失败，未创建变更任务。")
                else:
                    return render(
                        request,
                        "dashboard/proxy_resource_confirm.html",
                        {"task": task, "active_page": "proxy"},
                    )
        return redirect("network-proxy-resources")
    try:
        result = proxy_resources()
    except AgentError:
        result = {
            "configured": False, "revision": "", "airport_count": 0, "active_airport_count": 0,
            "airports": [], "country_options": [], "exit": {}, "exits": [],
            "exit_count": 0, "default_exit_id": "",
        }
        error = "暂时无法读取代理资源状态。"
    else:
        error = ""
    response = render(request, "dashboard/network_proxy_resources.html", {
        "proxy": result,
        "snapshot_error": error,
        "active_page": "proxy",
        "sensitive_unlocked": _sensitive_unlocked(request),
    })
    response["Cache-Control"] = "no-store, max-age=0"
    return response


def _exit_proxy_yaml_from_post(post, operation: str) -> str:
    """Build the existing sensitive YAML argument from the optional field editor."""

    raw_yaml = post.get("exit_proxy_yaml", "")
    if operation not in {"exit_add", "exit_update"}:
        return raw_yaml
    mode = post.get("exit_input_mode", "yaml")
    if mode == "yaml":
        return raw_yaml
    if mode != "fields":
        raise ValueError("出口节点输入方式无效，未保存任何内容。")
    if post.get("exit_field_type", "") != "socks5":
        raise ValueError("按字段输入当前只支持 SOCKS5 出口。")

    server = post.get("exit_field_server", "").strip()
    port_text = post.get("exit_field_port", "").strip()
    username = post.get("exit_field_username", "")
    password = post.get("exit_field_password", "")
    if (
        not server
        or len(server) > 253
        or any(character.isspace() for character in server)
        or "\x00" in server
    ):
        raise ValueError("请输入有效的 SOCKS5 服务器域名或 IP。")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ValueError("请输入 1–65535 的 SOCKS5 端口。") from error
    if not 1 <= port <= 65535 or str(port) != port_text:
        raise ValueError("请输入 1–65535 的 SOCKS5 端口。")
    if len(username) > 256 or len(password) > 256 or "\x00" in username + password:
        raise ValueError("SOCKS5 账号或密码过长或包含无效字符。")
    if bool(username) != bool(password):
        raise ValueError("SOCKS5 账号和密码必须同时填写或同时留空。")

    values: list[tuple[str, object]] = [
        ("type", "socks5"), ("server", server), ("port", port),
    ]
    if username:
        values.extend((("username", username), ("password", password)))
    values.append(("udp", True))
    return "\n".join(
        f"{key}: {json.dumps(value, ensure_ascii=False)}" for key, value in values
    ) + "\n"


@login_required
@require_POST
def network_proxy_resource_execute(request):
    """确认已加密保存的代理资源任务并立即返回任务详情。"""

    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以更新代理资源。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("代理资源任务标识无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError:
        messages.error(request, "任务确认失败，请重新提交代理资源。")
        return redirect("network-proxy-resources")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
@never_cache
def network_proxy_secret(request, item_id, resource):
    """短时解锁后按需返回机场链接或当前出口节点配置。"""

    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以读取代理资源凭据。")
    if not _sensitive_unlocked(request):
        return _sensitive_unlock_required_response()
    resource_name = {
        "link": "airport_link",
        "exit": "exit_config",
    }.get(resource)
    if resource_name is None or (
        resource_name == "exit_config" and item_id != "current"
        and not re.fullmatch(r"[a-f0-9]{12}", item_id)
    ):
        raise Http404("代理资源不存在")
    try:
        result = reveal_proxy_resource(
            resource_name, item_id, request.user.get_username()
        )
    except AgentError:
        response = JsonResponse({"error": "暂时无法读取代理资源。"}, status=503)
    else:
        response = JsonResponse(result)
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@never_cache
def deployment_wizard(request):
    """按依赖顺序安装登记服务；敏感输入只经过一次请求。"""
    if request.method == "POST":
        if not request.user.is_superuser:
            return HttpResponseForbidden("只有超级管理员可以安装服务。")
        service_id = request.POST.get("service_id", "")
        if service_id not in {"vless", "clash", "mosh", "file"}:
            return HttpResponseBadRequest("部署服务无效。")
        if request.POST.get("confirmed") != "yes":
            messages.error(request, "请先确认安装会修改服务器。")
        elif not request.user.check_password(request.POST.get("password", "")):
            messages.error(request, "当前账号密码不正确，未执行安装。")
        else:
            values = {
                key: request.POST.get(key, "")
                for key in (
                    "port", "server_name",
                    "airport_url", "exit_proxy_yaml", "upload_id", "download_name",
                )
            }
            if any(len(value) > 65536 or "\x00" in value for value in values.values()):
                messages.error(request, "部署输入过长或包含无效字符。")
            else:
                upload_dir = None
                task = None
                try:
                    if service_id == "file":
                        uploaded = request.FILES.get("payload")
                        if uploaded is None or not 1 <= uploaded.size <= settings.SERVER_KIT_MAX_UPLOAD_BYTES:
                            raise ValueError("上传文件必须为 1 B–2 GiB。")
                        original = uploaded.name.replace("\\", "/").rsplit("/", 1)[-1]
                        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", original).strip("._")
                        if not safe_name:
                            safe_name = "shared_file.yaml"
                        safe_name = safe_name[:128]
                        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", safe_name):
                            raise ValueError("文件名无法安全规范化。")
                        upload_id = secrets.token_hex(16)
                        upload_dir = settings.SERVER_KIT_UPLOAD_DIR / upload_id
                        settings.SERVER_KIT_UPLOAD_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
                        os.chmod(settings.SERVER_KIT_UPLOAD_DIR, 0o700)
                        upload_dir.mkdir(mode=0o700)
                        payload_path = upload_dir / "payload"
                        with payload_path.open("xb") as target:
                            for chunk in uploaded.chunks():
                                target.write(chunk)
                            target.flush()
                            os.fsync(target.fileno())
                        os.chmod(payload_path, 0o600)
                        values["upload_id"] = upload_id
                        values["download_name"] = safe_name
                    task = preview_deployment_task(
                        service_id, values, request.user.get_username()
                    )
                    confirm_change_task(task["id"], request.user.get_username())
                except ValueError as exc:
                    if upload_dir is not None:
                        shutil.rmtree(upload_dir, ignore_errors=True)
                    messages.error(request, str(exc))
                except AgentError:
                    if task is not None:
                        try:
                            cancel_change_task(task["id"], request.user.get_username())
                        except AgentError:
                            pass
                    elif upload_dir is not None:
                        shutil.rmtree(upload_dir, ignore_errors=True)
                    messages.error(request, "部署任务创建失败；现有服务没有被覆盖。")
                else:
                    messages.success(request, f"{service_id} 部署任务已进入后台队列。")
                    return redirect("change-task-detail", task_id=task["id"])
        return redirect("deployment-wizard")
    try:
        snapshot = read_snapshot()
    except (AgentError, OSError):
        snapshot = {"services": []}
        error = "暂时无法读取主机状态。"
    else:
        error = ""
    services = {item.get("id"): item for item in snapshot.get("services", []) if isinstance(item, dict)}
    response = render(request, "dashboard/deployment_wizard.html", {
        "services": services, "snapshot_error": error, "active_page": "deploy",
    })
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@require_POST
@never_cache
def sensitive_unlock(request):
    """用当前账号密码短时解锁配置、链接和二维码。"""
    wants_json = "application/json" in request.headers.get("Accept", "")
    if not request.user.is_superuser:
        if wants_json:
            return JsonResponse({"ok": False, "error": "只有超级管理员可以解锁敏感资源。"}, status=403)
        return HttpResponseForbidden("只有超级管理员可以解锁敏感资源。")
    destination = request.POST.get("destination", "subscriptions")
    destinations = {
        "subscriptions": "network-subscriptions",
        "nodes": "network-nodes",
        "files": "file-resources",
        "proxy": "network-proxy-resources",
    }
    if destination not in destinations:
        if wants_json:
            return JsonResponse({"ok": False, "error": "返回页面无效。"}, status=400)
        return HttpResponseBadRequest("返回页面无效。")
    if not request.user.check_password(request.POST.get("password", "")):
        request.session.pop(SENSITIVE_UNLOCK_SESSION_KEY, None)
        if wants_json:
            return JsonResponse({"ok": False, "error": "当前账号密码不正确。"}, status=403)
        messages.error(request, "当前账号密码不正确，敏感资源仍保持锁定。")
    else:
        request.session[SENSITIVE_UNLOCK_SESSION_KEY] = int(time.time())
        if wants_json:
            response = JsonResponse({"ok": True, "expires_in": SENSITIVE_UNLOCK_MAX_AGE})
            response["Cache-Control"] = "no-store, max-age=0"
            return response
        messages.success(request, "敏感资源已解锁 5 分钟；离开设备前请退出管理网站。")
    return redirect(destinations[destination])


@login_required
@never_cache
def file_resource_list(request):
    """显示普通文件资源，不把访问令牌写入页面。"""
    errors = []
    try:
        state = file_resources()
    except AgentError:
        state = {
            "items": [], "configured": False, "address": "", "port": 0,
            "service_state": "状态未知",
        }
        errors.append("暂时无法读取普通文件资源；服务可能尚未安装。")
    service = {
        "id": "file",
        "label": "普通文件",
        "state": state.get("service_state", "状态未知"),
    }
    service_running = service.get("state") == "运行中"
    for item in state.get("items", []):
        if isinstance(item, dict):
            item["size_label"] = _format_bytes(item.get("size"))
            cache_duration = _format_uptime(item.get("cache_ttl"))[0].removeprefix("运行 ")
            item["cache_label"] = (
                f"CDN 缓存 {cache_duration}"
                if item.get("cdn_cache") else "不允许 CDN 缓存"
            )
            item["availability"] = "可下载" if service_running else "暂不可下载"
    response = render(request, "dashboard/file_resources.html", {
        "files": state,
        "file_service": service,
        "service_running": service_running,
        "snapshot_error": " ".join(errors),
        "active_page": "files",
        "sensitive_unlocked": _sensitive_unlocked(request),
        "max_upload_label": _format_bytes(settings.SERVER_KIT_MAX_UPLOAD_BYTES),
        "max_upload_bytes": settings.SERVER_KIT_MAX_UPLOAD_BYTES,
    })
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@require_POST
@never_cache
def file_resource_add(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以新增文件资源。")
    if request.POST.get("confirmed") != "yes" or not request.user.check_password(request.POST.get("password", "")):
        messages.error(request, "请确认操作并输入正确的当前账号密码。")
        return redirect("file-resources")
    upload_dir = None
    task = None
    try:
        uploaded = request.FILES.get("payload")
        download_name = _safe_upload_name(request.POST.get("download_name", "") or (uploaded.name if uploaded else ""))
        ttl = int(request.POST.get("cache_ttl", "86400"))
        if not 300 <= ttl <= 2_592_000:
            raise ValueError("CDN 缓存时间必须为 5 分钟至 30 天。")
        upload_id, upload_dir = _stage_upload(uploaded)
        task = preview_file_change_task(
            "add", upload_id, download_name,
            request.POST.get("cdn_cache") == "yes", ttl, "",
            request.user.get_username(),
        )
    except (ValueError, AgentError) as exc:
        if upload_dir is not None:
            shutil.rmtree(upload_dir, ignore_errors=True)
        messages.error(request, str(exc) if isinstance(exc, ValueError) else "文件资源发布失败；原有资源未受影响。")
        return redirect("file-resources")
    try:
        confirm_change_task(task["id"], request.user.get_username())
    except AgentError:
        try:
            cancel_change_task(task["id"], request.user.get_username())
        except AgentError:
            pass
        messages.error(request, "文件发布任务未能排队；暂存文件将由任务过期清理。")
        return redirect("change-task-detail", task_id=task["id"])
    messages.success(request, f"{download_name} 已进入后台发布队列。")
    return redirect("change-task-detail", task_id=task["id"])


@login_required
@require_POST
@never_cache
def file_resource_delete_preview(request, resource_id):
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以删除文件资源。")
    if not FILE_RESOURCE_PATTERN.fullmatch(resource_id):
        raise Http404("文件资源不存在")
    try:
        task = preview_file_change_task(
            "delete", "", "", False, 86400, resource_id,
            request.user.get_username(),
        )
    except AgentError as error:
        _raise_404_if_missing(error)
        messages.error(request, "暂时无法生成删除预览。")
        return redirect("file-resources")
    return render(request, "dashboard/file_task_confirm.html", {
        "task": task, "resource_id": resource_id, "active_page": "files",
    })


@login_required
@require_POST
@never_cache
def file_resource_delete_execute(request, resource_id):
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以删除文件资源。")
    task_id = request.POST.get("task_id", "")
    valid = (
        TASK_ID_PATTERN.fullmatch(task_id)
        and request.POST.get("confirmed") == "yes"
        and request.user.check_password(request.POST.get("password", ""))
    )
    if not valid:
        messages.error(request, "删除确认已失效或账号密码不正确。")
        return redirect("file-resources")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError:
        messages.error(request, "文件资源删除失败；请重新读取实际状态。")
    else:
        messages.success(request, "删除任务已提交；CDN 已缓存副本不会被主动清除。")
        return redirect("change-task-detail", task_id=task_id)
    return redirect("file-resources")


@login_required
@require_POST
@never_cache
def file_resource_secret(request, resource_id, resource):
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以读取文件链接。")
    if not _sensitive_unlocked(request):
        return _sensitive_unlock_required_response()
    mapping = {"link": ("download_link", "value"), "qr": ("download_qr", "image_base64")}
    if resource not in mapping or not FILE_RESOURCE_PATTERN.fullmatch(resource_id):
        raise Http404("文件资源不存在")
    requested, key = mapping[resource]
    try:
        payload = reveal_file_resource(requested, resource_id, request.user.get_username())
    except AgentError as error:
        _raise_404_if_missing(error)
        return JsonResponse({"error": "文件链接读取失败。"}, status=503)
    response = JsonResponse(payload)
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@never_cache
def accounts(request):
    """维护超级管理员、管理员和只读账号。"""
    wants_json = "application/json" in request.headers.get("Accept", "")
    if not request.user.is_superuser:
        if wants_json:
            return JsonResponse({"ok": False, "error": "只有超级管理员可以维护账号。"}, status=403)
        return HttpResponseForbidden("只有超级管理员可以维护账号。")
    User = get_user_model()
    form_state = {}
    error = ""
    response_status = 200
    if request.method == "POST":
        operation = request.POST.get("operation", "")
        # Preserve only public form values for the HTML fallback. Passwords are
        # never returned, stored in a session, or included in audit metadata.
        form_state = {
            "operation": operation,
            "username": request.POST.get("username", "")[:150],
            "role": request.POST.get("role", "admin"),
            "user_id": request.POST.get("user_id", "")[:20],
        }
        target = None
        try:
            if request.POST.get("confirmed") != "yes" or not request.user.check_password(request.POST.get("current_password", "")):
                raise ValidationError("当前账号密码或确认项无效，未修改账号。")
            with transaction.atomic():
                if operation == "create":
                    username = request.POST.get("username", "").strip()
                    role = request.POST.get("role", "viewer")
                    password = request.POST.get("new_password", "")
                    if not re.fullmatch(r"[A-Za-z0-9@.+_-]{1,150}", username) or role not in {"superuser", "admin", "viewer"}:
                        raise ValidationError("账号名称或角色无效。")
                    if User.objects.filter(username=username).exists():
                        raise ValidationError("账号名称已存在。")
                    provisional = User(username=username)
                    validate_password(password, provisional)
                    provisional.is_active = True
                    provisional.is_staff = role in {"superuser", "admin"}
                    provisional.is_superuser = role == "superuser"
                    provisional.set_password(password)
                    provisional.save()
                    record_audit_event("account_create", request.user.get_username())
                    target = provisional
                    message = f"账号 {username} 已创建。"
                elif operation in {"enable", "disable"}:
                    target = User.objects.select_for_update().get(pk=int(request.POST.get("user_id", "0")))
                    if target.pk == request.user.pk and operation == "disable":
                        raise ValidationError("不能停用当前登录账号。")
                    if target.is_superuser and operation == "disable" and User.objects.filter(is_superuser=True, is_active=True).count() <= 1:
                        raise ValidationError("必须至少保留一个启用的超级管理员。")
                    target.is_active = operation == "enable"
                    target.save(update_fields=["is_active"])
                    record_audit_event(f"account_{operation}", request.user.get_username())
                    message = f"账号 {target.username} 已{operation == 'enable' and '启用' or '停用'}。"
                elif operation == "reset_password":
                    target = User.objects.select_for_update().get(pk=int(request.POST.get("user_id", "0")))
                    password = request.POST.get("new_password", "")
                    validate_password(password, target)
                    target.set_password(password)
                    target.save(update_fields=["password"])
                    record_audit_event("account_password_reset", request.user.get_username())
                    message = f"账号 {target.username} 的密码已重置。"
                else:
                    raise ValidationError("账号动作无效。")
        except (AgentError, OSError):
            error = "审计代理不可用，账号修改已回滚。"
            response_status = 503
        except IntegrityError:
            error = "账号名称已存在，请换一个名称。"
            response_status = 400
        except (User.DoesNotExist, ValueError, OverflowError, ValidationError) as exc:
            error = exc.messages[0] if isinstance(exc, ValidationError) else "目标账号不存在。"
            response_status = 400
        if error:
            if wants_json:
                return JsonResponse({"ok": False, "error": error}, status=response_status)
        else:
            if operation == "reset_password" and target.pk == request.user.pk:
                # Keep this authenticated session after its own password change;
                # Django rotates its session key and invalidates other sessions.
                update_session_auth_hash(request, target)
            if wants_json:
                return JsonResponse({
                    "ok": True, "message": message, "operation": operation,
                    "account": {
                        "id": target.pk, "username": target.username,
                        "role": "superuser" if target.is_superuser else "admin" if target.is_staff else "viewer",
                        "is_active": target.is_active, "is_current": target.pk == request.user.pk,
                    },
                })
            messages.success(request, message)
            return redirect("accounts")
    response = render(request, "dashboard/accounts.html", {
        "accounts": User.objects.order_by("username"), "active_page": "accounts",
        "account_form": form_state, "account_error": error,
    }, status=response_status)
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@require_POST
def network_node_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更节点。")
    kind = request.POST.get("kind", "")
    operation = request.POST.get("operation", "")
    name = request.POST.get("name", "").strip()
    address = request.POST.get("address", "").strip()
    public_key = request.POST.get("public_key", "").strip()
    preshared_key = request.POST.get("preshared_key", "").strip()
    enrollment_token = request.POST.get("enrollment_token", "").strip()
    if kind == "awg" and operation == "import" and enrollment_token:
        try:
            enrollment = decode_enrollment_token(enrollment_token)
        except BootstrapError as error:
            return HttpResponseBadRequest(str(error))
        name = enrollment.name
        address = enrollment.address
        public_key = enrollment.public_key
        preshared_key = enrollment.preshared_key
    if kind not in NODE_KIND_LABELS or operation not in NODE_OPERATION_LABELS or not NODE_PATTERN.fullmatch(name):
        return HttpResponseBadRequest("节点动作或名称无效。")
    if kind == "awg" and operation == "add":
        return HttpResponseBadRequest("普通节点必须使用网页内置生成器或公钥导入。")
    if address:
        if kind != "awg" or operation not in {"add", "import"}:
            return HttpResponseBadRequest("当前操作不接受节点地址。")
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            return HttpResponseBadRequest("节点地址无效。")
    if operation == "import":
        if kind != "awg" or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public_key) or not re.fullmatch(
            r"[A-Za-z0-9+/]{43}=", preshared_key
        ):
            return HttpResponseBadRequest("AWG 公钥或预共享密钥格式无效。")
    elif public_key or preshared_key:
        return HttpResponseBadRequest("当前节点操作不接受密钥。")
    try:
        if operation == "import":
            task = preview_network_node_import_task(
                name, address, public_key, preshared_key, request.user.get_username(),
            )
        else:
            task = preview_network_node_task(
                kind, operation, name, address, request.user.get_username(),
            )
    except AgentError as error:
        messages.error(request, str(error) or "节点事实核验失败，未创建变更任务。")
        return redirect("network-nodes")
    return render(request, "dashboard/network_task_confirm.html", {
        "task": task, "target_type": "node", "operation": operation,
        "active_page": "nodes",
    })


@login_required
@require_POST
def network_node_execute(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更节点。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("节点变更确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "节点任务确认失败。")
        return redirect("network-nodes")
    messages.success(request, "节点变更已进入队列；新增节点成功后会自动刷新发布订阅。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def network_node_exits_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更节点出口。")
    name = request.POST.get("name", "").strip()
    exit_ids = request.POST.getlist("exit_ids")
    if not NODE_PATTERN.fullmatch(name) or len(exit_ids) > 16 or any(
        not re.fullmatch(r"[a-f0-9]{12}", item) for item in exit_ids
    ):
        return HttpResponseBadRequest("节点名称或出口选择无效。")
    try:
        task = preview_node_exits_task(name, exit_ids, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "节点出口事实核验失败，未创建变更任务。")
        return redirect("network-nodes")
    return render(request, "dashboard/network_task_confirm.html", {
        "task": task, "target_type": "exits", "operation": "set-exits",
        "active_page": "nodes",
    })


@login_required
@require_POST
def network_node_exits_execute(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更节点出口。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("节点出口变更确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "节点出口任务确认失败。")
        return redirect("network-nodes")
    messages.success(request, "节点出口变更已进入队列；Xray 中转与订阅会一并刷新。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def network_node_domains_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更节点域名。")
    name = request.POST.get("name", "").strip()
    if not NODE_PATTERN.fullmatch(name):
        return HttpResponseBadRequest("节点名称无效。")
    raw = request.POST.get("domains", "")
    domains = [value for value in re.split(r"[\s,，]+", raw.strip()) if value]
    try:
        task = preview_node_domains_task(
            name, domains, request.user.get_username()
        )
    except AgentError as error:
        messages.error(request, str(error) or "节点域名事实核验失败，未创建变更任务。")
        return redirect("network-subscriptions")
    return render(request, "dashboard/network_task_confirm.html", {
        "task": task, "target_type": "domains", "operation": "set-domains",
        "active_page": "subscriptions",
    })


@login_required
@require_POST
def network_address_domains_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更全局强制解析。")
    address = request.POST.get("address", "").strip()
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        return HttpResponseBadRequest("目标 IP 格式不正确。")
    raw = request.POST.get("domains", "")
    domains = [value for value in re.split(r"[\s,，]+", raw.strip()) if value]
    try:
        task = preview_address_domains_task(
            address, domains, request.user.get_username()
        )
    except AgentError as error:
        messages.error(request, str(error) or "自定义强制解析事实核验失败，未创建变更任务。")
        return redirect("network-subscriptions")
    return render(request, "dashboard/network_task_confirm.html", {
        "task": task, "target_type": "domains", "operation": "set-address",
        "active_page": "subscriptions",
    })


@login_required
@require_POST
def network_node_domains_execute(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更全局强制解析。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("强制解析确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "强制解析任务确认失败。")
        return redirect("network-subscriptions")
    messages.success(request, "全局强制解析更新已进入队列；成功后会刷新全部订阅。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def network_public_endpoint_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更稳定公网入口。")
    operation = request.POST.get("operation", "")
    fqdn = request.POST.get("fqdn", "").strip()
    if operation not in {"apply", "clear", "confirm", "rollback"}:
        return HttpResponseBadRequest("稳定公网入口动作无效。")
    if operation == "clear":
        operation = "apply"
        fqdn = ""
    elif operation != "apply":
        fqdn = ""
    try:
        task = preview_public_endpoint_task(
            operation, fqdn, _security_session_id(request),
            request.user.get_username(),
        )
    except AgentError as error:
        messages.error(request, str(error) or "稳定公网入口事实核验失败。")
        return redirect("network-subscriptions")
    return render(request, "dashboard/network_task_confirm.html", {
        "task": task, "target_type": "public-endpoint", "operation": operation,
        "active_page": "subscriptions",
    })


@login_required
@require_POST
def network_public_endpoint_execute(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更稳定公网入口。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("稳定公网入口确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "稳定公网入口任务确认失败。")
        return redirect("network-subscriptions")
    messages.success(request, "稳定公网入口联动事务已进入队列；应用后必须从另一条独立登录连接确认，否则会自动回滚入口、HTTPS 证书和全部发布链接。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def network_duckdns_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更动态 DNS 自动更新。")
    operation = request.POST.get("operation", "")
    provider = request.POST.get("provider", "").strip()
    fqdn = request.POST.get("fqdn", "").strip()
    token = request.POST.get("token", "").strip()
    secret_id = request.POST.get("secret_id", "").strip()
    secret_key = request.POST.get("secret_key", "").strip()
    zone = request.POST.get("zone", "").strip()
    if operation not in {"configure", "update", "disable", "delete"}:
        return HttpResponseBadRequest("动态 DNS 动作无效。")
    if operation == "configure":
        if provider == "duckdns" and not token:
            messages.error(request, "请输入 DuckDNS Token。")
            return redirect("network-subscriptions")
        if provider == "dnspod" and not (fqdn and secret_id and secret_key and zone):
            messages.error(request, "请输入 DNSPod 目标完整域名、主域名、SecretId 和 SecretKey。")
            return redirect("network-subscriptions")
        if provider not in {"duckdns", "dnspod"}:
            messages.error(request, "请选择受支持的动态 DNS 提供商。")
            return redirect("network-subscriptions")
    if operation != "configure":
        provider = fqdn = token = secret_id = secret_key = zone = ""
    try:
        task = preview_duckdns_task(
            operation, provider, fqdn, token, secret_id, secret_key, zone,
            request.user.get_username(),
        )
    except AgentError as error:
        messages.error(request, str(error) or "动态 DNS 自动更新操作失败。")
        return redirect("network-subscriptions")
    return render(request, "dashboard/network_task_confirm.html", {
        "task": task, "target_type": "duckdns", "operation": operation,
        "active_page": "subscriptions",
    })


@login_required
@require_POST
def network_duckdns_execute(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更动态 DNS 自动更新。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("动态 DNS 任务确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "动态 DNS 任务确认失败。")
        return redirect("network-subscriptions")
    messages.success(request, "动态 DNS 任务已进入队列；执行时会再次核验状态。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def network_permission_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更访问权限。")
    operation = request.POST.get("operation", "")
    client_name = request.POST.get("client", "").strip()
    target = request.POST.get("target", "").strip()
    port_mode = request.POST.get("port_mode", "")
    network = request.POST.get("network", "").lower()
    ports = ""
    if operation not in {"allow", "deny"} or not NODE_PATTERN.fullmatch(client_name):
        return HttpResponseBadRequest("权限动作或节点名称无效。")
    if not NODE_PATTERN.fullmatch(target):
        return HttpResponseBadRequest("权限目标无效。")
    if operation == "allow" and port_mode == "all":
        network = ""
    elif operation == "allow" and port_mode in {"tcp", "udp"}:
        network = port_mode
    elif operation == "allow" and (
        port_mode != "specific" or network not in {"tcp", "udp"}
    ):
        return HttpResponseBadRequest("权限协议无效。")
    elif operation == "deny" and network not in {"", "all", "tcp", "udp"}:
        return HttpResponseBadRequest("待删除权限的协议无效。")
    if network in {"tcp", "udp"}:
        try:
            ports = normalize_ports(request.POST.get("ports", ""))
        except PortRangeError as error:
            return HttpResponseBadRequest(str(error))
    try:
        task = preview_network_permission_task(
            operation, client_name, target, ports, network,
            request.user.get_username(),
        )
    except AgentError as error:
        messages.error(request, str(error) or "访问授权事实核验失败，未创建变更任务。")
        return redirect("network-nodes")
    return render(request, "dashboard/network_task_confirm.html", {
        "task": task, "target_type": "permission", "operation": operation,
        "active_page": "nodes",
    })


@login_required
@require_POST
def network_permission_execute(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更访问权限。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("权限变更确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "访问授权任务确认失败。")
        return redirect("network-nodes")
    messages.success(request, "访问授权变更已进入队列；执行失败时保留原有策略。")
    return redirect("change-task-detail", task_id=task_id)


def _permission_batch_gate(request, method):
    """Same-page APIs never redirect to a login page or accept viewer writes."""
    if not request.user.is_authenticated:
        return JsonResponse({"error": "登录已失效，请重新登录后继续。"}, status=401)
    if not _can_manage(request.user):
        return JsonResponse({"error": "只有管理员可以变更访问权限。"}, status=403)
    if request.method != method:
        response = JsonResponse({"error": "请求方法无效。"}, status=405)
        response["Allow"] = method
        return response
    return None


def _permission_batch_body(request, fields):
    if request.content_type != "application/json":
        raise ValueError("请使用 JSON 提交权限规则。")
    try:
        body = request.body
        if len(body) > 1_048_576:
            raise ValueError("权限请求过大，请减少端口表达式长度。")
        data = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError, RequestDataTooBig) as error:
        raise ValueError("权限请求格式无效。") from error
    if not isinstance(data, dict) or set(data) != fields:
        raise ValueError("权限请求字段无效。")
    return data


def _permission_batch_error(error):
    code = getattr(error, "code", "agent_error")
    if code in {"invalid_params", "operation_forbidden"}:
        return JsonResponse({"error": str(error) or "权限规则无效。"}, status=400)
    if code in {"not_found", "forbidden"}:
        return JsonResponse({"error": "权限任务不存在或不可访问。"}, status=404)
    if code in {"queue_full", "facts_changed", "conflict"}:
        return JsonResponse({"error": str(error) or "状态已变化，请重新预览。"}, status=409)
    return JsonResponse({"error": "暂时无法连接管理代理，请稍后重试；不要重复创建任务。"}, status=503)


def _permission_batch_own_task(task, task_id, actor):
    # Task ownership and action come from root's immutable task record, never
    # from a posted client name or browser session metadata.
    return (
        isinstance(task, dict) and task.get("id") == task_id
        and task.get("action") == "network.permission.batch"
        and task.get("actor") == actor
    )


def _permission_batch_payload(task):
    return {
        "task": task,
        "status_url": reverse("network-permission-batch-status", args=[task["id"]]),
        "task_url": reverse("change-task-detail", args=[task["id"]]),
    }


@never_cache
def network_permission_batch_preview(request):
    rejected = _permission_batch_gate(request, "POST")
    if rejected is not None:
        return rejected
    try:
        data = _permission_batch_body(request, {"client", "rules"})
        client = data["client"]
        if not isinstance(client, str) or not NODE_PATTERN.fullmatch(client.strip()):
            raise ValueError("节点名称无效。")
        client = client.strip()
        rules = data["rules"]
        if not isinstance(rules, list) or not 1 <= len(rules) <= 20:
            raise ValueError("每次请添加 1–20 条权限规则。")
        normalized = []
        seen = set()
        for index, rule in enumerate(rules, 1):
            if not isinstance(rule, dict) or set(rule) != {"target", "network", "ports"}:
                raise ValueError(f"第 {index} 条权限规则字段无效。")
            if any(not isinstance(value, str) for value in rule.values()):
                raise ValueError(f"第 {index} 条权限规则格式无效。")
            target, network, ports = (rule[key].strip() for key in ("target", "network", "ports"))
            network = network.lower()
            if not NODE_PATTERN.fullmatch(target):
                raise ValueError(f"第 {index} 条权限目标无效。")
            if network not in {"tcp", "udp", "all"}:
                raise ValueError(f"第 {index} 条权限协议无效。")
            if network == "all":
                if ports:
                    raise ValueError(f"第 {index} 条全部协议规则不能指定端口。")
            else:
                try:
                    ports = normalize_ports(ports)
                except PortRangeError as error:
                    raise ValueError(f"第 {index} 条：{error}") from error
            key = (target, network, ports)
            if key in seen:
                raise ValueError(f"第 {index} 条与前面的规则重复。")
            seen.add(key)
            normalized.append({"target": target, "network": network, "ports": ports})
    except ValueError as error:
        return JsonResponse({"error": str(error)}, status=400)
    try:
        task = preview_network_permission_batch_task(client, normalized, request.user.get_username())
    except (AgentError, OSError) as error:
        return _permission_batch_error(error)
    return JsonResponse(_permission_batch_payload(task))


@never_cache
def network_permission_batch_execute(request):
    rejected = _permission_batch_gate(request, "POST")
    if rejected is not None:
        return rejected
    try:
        data = _permission_batch_body(request, {"task_id"})
        task_id = data["task_id"]
        if not isinstance(task_id, str) or not TASK_ID_PATTERN.fullmatch(task_id):
            raise ValueError("权限任务确认无效。")
    except ValueError as error:
        return JsonResponse({"error": str(error)}, status=400)
    actor = request.user.get_username()
    try:
        task = change_task(task_id)
        if not _permission_batch_own_task(task, task_id, actor):
            return JsonResponse({"error": "权限任务不存在或不可访问。"}, status=404)
        # A retry observes the same queued/running/completed task. Only the
        # original confirmation can queue it; the root API is idempotent too.
        if task.get("state") == "waiting_confirmation":
            task = confirm_change_task(task_id, actor)
    except (AgentError, OSError) as error:
        return _permission_batch_error(error)
    return JsonResponse(_permission_batch_payload(task))


@never_cache
def network_permission_batch_status(request, task_id):
    rejected = _permission_batch_gate(request, "GET")
    if rejected is not None:
        return rejected
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return JsonResponse({"error": "权限任务标识无效。"}, status=400)
    try:
        task = change_task(task_id)
    except (AgentError, OSError) as error:
        return _permission_batch_error(error)
    if not _permission_batch_own_task(task, task_id, request.user.get_username()):
        return JsonResponse({"error": "权限任务不存在或不可访问。"}, status=404)
    payload = _permission_batch_payload(task)
    if task.get("state") == "succeeded":
        preview = task.get("preview", {})
        facts = preview.get("facts", {}) if isinstance(preview, dict) else {}
        client = facts.get("来源节点") if isinstance(facts, dict) else None
        if not isinstance(client, str) or not NODE_PATTERN.fullmatch(client):
            payload["permissions_error"] = "任务明细已不可用，请重新加载节点页核验当前权限。"
        else:
            payload["client"] = client
            try:
                overview = network_overview()
                nodes = overview.get("nodes")
                node = next((
                    item for item in nodes
                    if isinstance(item, dict) and item.get("name") == client
                ), None) if isinstance(nodes, list) else None
                permissions = node.get("permissions") if node is not None else None
                if not isinstance(permissions, list) or any(not isinstance(item, dict) for item in permissions):
                    payload["permissions_error"] = "暂时无法核验该节点的权限，请重试读取。"
                else:
                    payload["permissions"] = permissions
            except (AgentError, OSError):
                payload["permissions_error"] = "任务已成功，但最新权限暂时读取失败；请重试读取，不要重复提交。"
    return JsonResponse(payload)


@login_required
@require_POST
def network_subscription_preview(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以同步订阅。")
    try:
        task = preview_subscription_sync_task(request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "订阅事实核验失败，未创建同步任务。")
        return redirect("network-nodes")
    return render(request, "dashboard/subscription_task_confirm.html", {
        "task": task, "target_type": "sync", "active_page": "nodes",
    })


@login_required
@require_POST
def network_subscription_execute(request):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以同步订阅。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("订阅同步确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "订阅同步任务确认失败。")
        return redirect("network-nodes")
    messages.success(request, "订阅同步已进入队列，现有链接在成功前保持可用。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def network_subscription_rotate_preview(request, item_id):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以轮换订阅令牌。")
    if not NODE_PATTERN.fullmatch(item_id):
        raise Http404("订阅不存在")
    try:
        task = preview_subscription_rotate_task(item_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "订阅事实核验失败，未创建轮换任务。")
        return redirect("network-nodes")
    return render(request, "dashboard/subscription_task_confirm.html", {
        "task": task, "target_type": "rotate", "item_id": item_id,
        "active_page": "nodes",
    })


@login_required
@require_POST
def network_subscription_rotate_execute(request, item_id):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以轮换订阅令牌。")
    task_id = request.POST.get("task_id", "")
    if not NODE_PATTERN.fullmatch(item_id) or not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("订阅令牌轮换确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "订阅令牌轮换任务确认失败。")
        return redirect("network-nodes")
    request.session.pop(SENSITIVE_UNLOCK_SESSION_KEY, None)
    messages.success(request, f"{item_id} 的令牌轮换已进入队列，旧链接仅在成功后失效。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def network_subscription_state_preview(request, item_id):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以切换订阅发布状态。")
    state = request.POST.get("state", "")
    if not NODE_PATTERN.fullmatch(item_id) or state not in {"enabled", "disabled"}:
        return HttpResponseBadRequest("订阅发布状态无效。")
    try:
        task = preview_subscription_state_task(
            item_id, state, request.user.get_username()
        )
    except AgentError as error:
        messages.error(request, str(error) or "订阅事实核验失败，未创建状态任务。")
        return redirect("network-nodes")
    return render(request, "dashboard/subscription_task_confirm.html", {
        "task": task, "target_type": "state", "item_id": item_id,
        "state": state, "active_page": "nodes",
    })


@login_required
@require_http_methods(["GET", "POST"])
def network_subscription_state_execute(request, item_id):
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以切换订阅发布状态。")
    if request.method == "GET":
        messages.warning(request, "确认请求未提交，订阅发布状态没有变化；请重新操作。")
        return redirect("network-nodes")
    task_id = request.POST.get("task_id", "")
    state = request.POST.get("state", "")
    if (
        not NODE_PATTERN.fullmatch(item_id)
        or state not in {"enabled", "disabled"}
        or not TASK_ID_PATTERN.fullmatch(task_id)
    ):
        return HttpResponseBadRequest("订阅发布状态确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "订阅发布状态任务确认失败。")
        return redirect("network-nodes")
    if state == "disabled":
        request.session.pop(SENSITIVE_UNLOCK_SESSION_KEY, None)
    label = "恢复发布" if state == "enabled" else "停用发布"
    messages.success(request, f"{item_id} 的{label}任务已进入队列；节点网络状态不变。")
    return redirect("change-task-detail", task_id=task_id)


def _read_transactions(actor):
    return [
        manage_security_transaction(transaction_type, "status", actor)
        for transaction_type in (
            "ssh_auth", "ssh_listener", "firewall", "vless_listener",
        )
    ]


def _security_session_id(request) -> str:
    """把当前登录会话转换为不出 root 边界的固定连接标识。"""

    if request.session.session_key is None:
        request.session.create()
    value = f"server-kit-security:{request.session.session_key}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@login_required
def security_transactions(request):
    """显示高风险安全事务的事实状态和回滚窗口。"""
    try:
        transactions = _read_transactions(request.user.get_username())
    except AgentError:
        transactions = []
        error = "暂时无法读取安全事务，请检查管理代理。"
    else:
        error = ""
    detected_public_ipv4 = ""
    public_ipv4_diagnostic = ""
    try:
        endpoint = public_endpoint_status()
    except AgentError:
        public_ipv4_diagnostic = "公网 IPv4 暂时无法读取；提交时管理代理会重新检测。"
    else:
        detected_public_ipv4 = str(endpoint.get("current_ipv4", ""))
        diagnostics = endpoint.get("diagnostics", [])
        if isinstance(diagnostics, list):
            public_ipv4_diagnostic = "；".join(str(item) for item in diagnostics)
    suggested_public_port = "62222"
    for transaction in transactions:
        if transaction.get("transaction_type") != "ssh_listener":
            continue
        for change in transaction.get("changes", []):
            if change.get("label") == "公网 SSH 端口":
                candidate = str(change.get("target", ""))
                if candidate.isdigit():
                    suggested_public_port = candidate
                break
        break
    return render(
        request,
        "dashboard/security_transactions.html",
        {
            "transactions": transactions,
            "snapshot_error": error,
            "active_page": "security",
            "detected_public_ipv4": detected_public_ipv4,
            "public_ipv4_diagnostic": public_ipv4_diagnostic,
            "suggested_public_port": suggested_public_port,
        },
    )


@login_required
@never_cache
def backups(request):
    """创建、校验和下载加密配置备份。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以管理配置备份。")
    restore_task = None
    if request.method == "POST":
        operation = request.POST.get("operation", "")
        backup_id = request.POST.get("backup_id", "")
        passphrase = request.POST.get("passphrase", "")
        if operation not in {
            "create", "verify", "preview_restore", "restore_apply",
            "restore_confirm", "restore_rollback",
        }:
            return HttpResponseBadRequest("备份动作无效。")
        if operation == "restore_apply":
            task_id = request.POST.get("task_id", "")
            if not TASK_ID_PATTERN.fullmatch(task_id):
                return HttpResponseBadRequest("配置恢复任务确认无效。")
            try:
                confirm_change_task(task_id, request.user.get_username())
            except AgentError as error:
                messages.error(request, str(error) or "配置恢复任务确认失败。")
            else:
                messages.success(request, "配置恢复任务已进入后台队列；自动回滚计时器将独立运行。")
                return redirect("change-task-detail", task_id=task_id)
        elif operation == "create" and passphrase != request.POST.get("passphrase_confirmation", ""):
            messages.error(request, "两次输入的恢复口令不一致，未创建备份。")
        elif operation in {"create", "verify", "preview_restore"} and (
            not 16 <= len(passphrase) <= 256
            or any(char in passphrase for char in ("\x00", "\r", "\n"))
        ):
            messages.error(request, "恢复口令必须为 16–256 个字符。")
        elif operation in {"verify", "preview_restore"} and not BACKUP_ID_PATTERN.fullmatch(backup_id):
            return HttpResponseBadRequest("备份标识无效。")
        elif operation in {"create", "verify"}:
            try:
                task = preview_backup_task(
                    operation, backup_id, passphrase,
                    request.user.get_username(),
                )
                confirm_change_task(task["id"], request.user.get_username())
            except (AgentError, KeyError):
                messages.error(request, "备份任务创建失败：口令、备份事实或管理代理状态无效。")
            else:
                messages.success(request, "备份任务已进入后台队列，恢复口令不会写入任务明文。")
                return redirect("change-task-detail", task_id=task["id"])
        elif operation == "preview_restore":
            try:
                restore_task = preview_backup_restore_task(
                    "restore_apply", backup_id, passphrase,
                    _security_session_id(request), request.user.get_username(),
                )
            except AgentError as error:
                messages.error(request, str(error) or "恢复预览失败：口令错误、文件被篡改或写入未启用。")
        elif operation in {"restore_confirm", "restore_rollback"}:
            try:
                task = preview_backup_restore_task(
                    operation, "", "", _security_session_id(request),
                    request.user.get_username(),
                )
                confirm_change_task(task["id"], request.user.get_username())
            except (AgentError, KeyError) as error:
                messages.error(request, str(error) or "配置恢复确认失败，请检查独立连接和回滚状态。")
            else:
                messages.success(request, "配置恢复确认任务已进入后台队列。")
                return redirect("change-task-detail", task_id=task["id"])
    errors = []
    backups_error = False
    restore_status_error = False
    try:
        listing = manage_backup("list", request.user.get_username())
    except AgentError:
        listing = {"items": []}
        backups_error = True
        errors.append("暂时无法读取备份列表，请稍后重试。")
    try:
        restore_transaction = manage_backup(
            "restore_status", request.user.get_username()
        )
    except AgentError:
        restore_transaction = {"state": "unknown", "writes_enabled": False}
        restore_status_error = True
        errors.append("配置恢复事务状态暂不可用，请勿重复提交恢复操作。")
    response = render(
        request,
        "dashboard/backups.html",
        {
            "backups": listing.get("items", []),
            "restore_task": restore_task,
            "restore_transaction": restore_transaction,
            "snapshot_error": " ".join(errors),
            "backups_error": backups_error,
            "restore_status_error": restore_status_error,
            "active_page": "backups",
        },
    )
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@never_cache
def backup_download(request, backup_id):
    """只下载固定目录中由 root 创建的加密容器。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以下载配置备份。")
    if not BACKUP_ID_PATTERN.fullmatch(backup_id):
        raise Http404("备份不存在")
    path = settings.SERVER_KIT_BACKUP_DIR / f"{backup_id}.skb"
    if path.is_symlink() or not path.is_file():
        raise Http404("备份不存在")
    response = FileResponse(path.open("rb"), as_attachment=True, filename=path.name)
    response["Cache-Control"] = "no-store, max-age=0"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@login_required
@require_POST
@never_cache
def backup_delete_preview(request, backup_id):
    """由 root 读取备份事实并创建耐久删除任务。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以删除配置备份。")
    if not BACKUP_ID_PATTERN.fullmatch(backup_id):
        raise Http404("备份不存在")
    try:
        task = preview_backup_task("delete", backup_id, "", request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "暂时无法读取配置备份，未创建删除任务。")
        return redirect("backups")
    return render(
        request,
        "dashboard/backup_delete_confirm.html",
        {
            "task": task,
            "backup_id": backup_id,
            "active_page": "backups",
        },
    )


@login_required
@require_POST
@never_cache
def backup_delete_execute(request, backup_id):
    """确认 root 已持久化的单个备份删除任务。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以删除配置备份。")
    task_id = request.POST.get("task_id", "")
    if not BACKUP_ID_PATTERN.fullmatch(backup_id) or not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("备份删除确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "备份删除任务确认失败。")
        return redirect("backups")
    messages.success(request, "配置备份删除任务已进入队列。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
def security_transaction_preview(request, transaction_type):
    """由 root 读取事实并创建受自动回滚保护的异步任务。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以推进安全事务。")
    if transaction_type not in TRANSACTION_LABELS:
        raise Http404("安全事务不存在")
    requested = request.POST.get("operation", "preview")
    if requested not in {"preview", "confirm", "rollback"}:
        return HttpResponseBadRequest("安全事务动作无效。")
    operation = "apply" if requested == "preview" else requested
    # 公网地址属于 root 主机事实，不能接受浏览器提供或覆盖。
    public_ip = ""
    public_port = request.POST.get("public_port", "") if transaction_type == "ssh_listener" and operation == "apply" else ""
    try:
        task = preview_security_transaction_task(
            transaction_type, operation, _security_session_id(request),
            public_ip, public_port, request.user.get_username(),
        )
    except AgentError as error:
        messages.error(request, str(error) or "无法生成安全事务任务，未执行任何变更。")
        return redirect("security-transactions")
    return render(
        request,
        "dashboard/security_transaction_confirm.html",
        {
            "task": task,
            "transaction_type": transaction_type,
            "operation": operation,
            "operation_label": TRANSACTION_OPERATION_LABELS[operation],
            "active_page": "security",
        },
    )


@login_required
@require_POST
def security_transaction_execute(request, transaction_type):
    """确认 root 已持久化的安全事务任务并立即返回详情。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以推进安全事务。")
    task_id = request.POST.get("task_id", "")
    if transaction_type not in TRANSACTION_LABELS or not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("安全事务确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "安全事务任务确认失败。")
        return redirect("security-transactions")
    messages.success(request, "安全事务任务已进入后台队列；自动回滚计时器独立运行。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
def service_detail(request, service_id):
    """显示事实状态和管理代理返回的动作能力。"""
    try:
        description = describe_service(service_id)
    except AgentError as error:
        _raise_404_if_missing(error)
        return render(
            request,
            "dashboard/service_detail.html",
            {
                "snapshot_error": "暂时无法读取服务详情，请检查管理代理。",
                "active_page": "dashboard",
            },
            status=503,
        )
    context = _detail_context(description)
    if service_id == "firewall":
        ports = description.get("firewall_ports")
        if not isinstance(ports, dict):
            # 兼容尚未升级 host.read 的代理；新版读取模型不会走第二次请求。
            try:
                ports = firewall_ports()
            except AgentError:
                ports = {"firewall_active": False, "items": []}
                context["firewall_ports_error"] = "暂时无法读取自定义端口。"
        for item in ports.get("items", []):
            if isinstance(item, dict):
                item["duration_label"] = _format_firewall_duration(item)
        context.update({
            "firewall_ports": ports,
            "firewall_port_scopes": FIREWALL_PORT_SCOPES,
            "firewall_port_protocols": FIREWALL_PORT_PROTOCOLS,
            "firewall_port_durations": FIREWALL_PORT_DURATIONS,
        })
    elif service_id == "ssh":
        keys = description.get("ssh_keys")
        if not isinstance(keys, dict):
            # 兼容滚动升级期间的旧代理。
            try:
                keys = ssh_keys()
            except AgentError:
                keys = {"items": []}
                context["ssh_keys_error"] = "暂时无法读取 SSH 客户端公钥。"
        context["ssh_keys"] = keys
    elif service_id in {"amneziawg", "clash", "file"}:
        ports = description.get("managed_ports")
        if not isinstance(ports, dict):
            ports = {"items": []}
            context["managed_ports_error"] = "管理代理尚未返回可维护端口。"
        context["managed_ports"] = {
            **ports,
            "items": [
                item for item in ports.get("items", [])
                if isinstance(item, dict) and item.get("service_id") == service_id
            ],
        }
    return render(
        request,
        "dashboard/service_detail.html",
        context,
    )


@login_required
@require_POST
@never_cache
def firewall_port_preview(request):
    """请求 root 根据事实配置和基础策略生成端口影响预览。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以变更防火墙端口。")
    operation = request.POST.get("operation", "")
    scope = request.POST.get("scope", "")
    protocol = request.POST.get("protocol", "")
    duration_value = request.POST.get("duration", "")
    try:
        port = int(request.POST.get("port", ""))
    except ValueError:
        return HttpResponseBadRequest("端口号无效。")
    if (
        operation not in {"open", "close"}
        or not 1 <= port <= 65535
        or scope not in FIREWALL_PORT_SCOPES
        or protocol not in FIREWALL_PORT_PROTOCOLS
    ):
        return HttpResponseBadRequest("自定义端口参数无效。")
    if operation == "open":
        if duration_value not in FIREWALL_PORT_DURATIONS:
            return HttpResponseBadRequest("开放时长无效。")
        duration_seconds = 0 if duration_value == "permanent" else int(duration_value)
        duration_label = FIREWALL_PORT_DURATIONS[duration_value]
    else:
        duration_seconds = 0
        duration_label = "立即关闭"
    try:
        task = preview_firewall_port_task(
            operation, port, scope, protocol, duration_seconds,
            request.user.get_username(),
        )
    except AgentError as error:
        messages.error(request, str(error) or "端口事实核验失败，未创建变更任务。")
        return redirect("service-detail", service_id="firewall")
    return render(request, "dashboard/firewall_port_confirm.html", {
        "task": task, "operation": operation, "scope": scope,
        "active_page": "dashboard",
    })


@login_required
@require_POST
@never_cache
def firewall_port_execute(request):
    """确认 root 已持久化的自定义端口任务。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以变更防火墙端口。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("自定义端口确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "端口变更任务确认失败。")
        return redirect("service-detail", service_id="firewall")
    messages.success(request, "端口变更已进入队列，完成后会核验事实配置和 nftables 规则。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
@never_cache
def managed_port_preview(request):
    """根据实时监听和配置事实预览托管服务端口变更。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以变更托管服务端口。")
    target_id = request.POST.get("target_id", "")
    service_id = request.POST.get("service_id", "")
    targets = {
        "clash": "clash", "file": "file",
        "awg-backup1": "amneziawg", "awg-backup2": "amneziawg",
    }
    if target_id not in targets or service_id != targets[target_id]:
        return HttpResponseBadRequest("托管服务端口目标无效。")
    try:
        port = int(request.POST.get("port", ""))
    except ValueError:
        return HttpResponseBadRequest("端口号无效。")
    if not 1 <= port <= 65535:
        return HttpResponseBadRequest("端口号无效。")
    try:
        task = preview_managed_port_task(target_id, port, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "端口事实核验失败，未创建变更任务。")
        return redirect("service-detail", service_id=service_id)
    return render(request, "dashboard/managed_port_confirm.html", {
        "task": task, "service_id": service_id, "active_page": "dashboard",
    })


@login_required
@require_POST
@never_cache
def managed_port_execute(request):
    """确认托管服务端口任务。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以变更托管服务端口。")
    task_id = request.POST.get("task_id", "")
    service_id = request.POST.get("service_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id) or service_id not in {"amneziawg", "clash", "file"}:
        return HttpResponseBadRequest("托管服务端口确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        messages.error(request, str(error) or "端口变更任务确认失败。")
        return redirect("service-detail", service_id=service_id)
    messages.success(request, "端口变更已进入队列；失败时会自动恢复旧端口和防火墙。")
    return redirect("change-task-detail", task_id=task_id)


@login_required
@require_POST
@never_cache
def ssh_key_preview(request):
    """请求 root 生成 SSH 公钥任务的脱敏影响预览。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以管理 SSH 客户端。")
    operation = request.POST.get("operation", "")
    item_id = request.POST.get("item_id", "")
    name = request.POST.get("name", "").strip()
    if operation not in {"add", "rename", "delete"}:
        return HttpResponseBadRequest("SSH 客户端动作无效。")
    if operation in {"add", "rename"} and not _valid_ssh_client_name(name):
        return HttpResponseBadRequest("客户端名称必须为 1–64 个可见字符。")
    public_key = ""
    if operation == "add":
        public_key = request.POST.get("public_key", "").strip()
        if any(char in public_key for char in ("\x00", "\r", "\n")):
            return HttpResponseBadRequest("SSH 公钥必须是完整的一行。")
        parts = public_key.split(maxsplit=2)
        if len(parts) < 2:
            return HttpResponseBadRequest("SSH 公钥格式无效。")
        public_key = f"{parts[0]} {parts[1]} {name}"
    else:
        if not SSH_KEY_ID_PATTERN.fullmatch(item_id):
            return HttpResponseBadRequest("SSH 客户端标识无效。")
        if operation == "delete":
            name = ""
    try:
        task = preview_ssh_key_change_task(
            operation, item_id, name if operation == "rename" else "",
            public_key, request.user.get_username(),
        )
    except AgentError as error:
        _raise_404_if_missing(error)
        messages.error(request, "SSH 公钥校验失败或最后一把有效公钥受保护。")
        return redirect("service-detail", service_id="ssh")
    if operation == "rename":
        try:
            confirm_change_task(task["id"], request.user.get_username())
        except AgentError:
            messages.error(request, "SSH 客户端改名任务无法排队。")
        return redirect("change-task-detail", task_id=task["id"])
    return render(request, "dashboard/ssh_key_task_confirm.html", {
        "task": task, "active_page": "dashboard",
    })


@login_required
@require_POST
@never_cache
def ssh_key_execute(request):
    """确认 root 已持久化的 SSH 公钥新增或删除任务。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以管理 SSH 客户端。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("SSH 客户端确认无效。")
    try:
        confirm_change_task(task_id, request.user.get_username())
    except AgentError:
        messages.error(request, "SSH 客户端任务确认失败，请重新生成预览。")
    else:
        messages.success(request, "SSH 客户端任务已提交。")
        return redirect("change-task-detail", task_id=task_id)
    return redirect("service-detail", service_id="ssh")


@login_required
@require_POST
@never_cache
def _clash_resource(request, item_id, resource):
    """只向超级管理员返回单个节点的单项敏感资源。"""
    if not request.user.is_superuser:
        return HttpResponseForbidden("只有超级管理员可以读取订阅资源。")
    if not _sensitive_unlocked(request):
        return _sensitive_unlock_required_response()
    try:
        result = reveal_clash_resource(resource, item_id, request.user.get_username())
    except AgentError as error:
        _raise_404_if_missing(error)
        response = JsonResponse({"error": "暂时无法读取订阅资源。"}, status=503)
    else:
        response = JsonResponse(result)
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@require_POST
@never_cache
def clash_subscription_copy(request, item_id):
    return _clash_resource(request, item_id, "subscription_link")


@login_required
@require_POST
@never_cache
def clash_subscription_qr(request, item_id):
    return _clash_resource(request, item_id, "subscription_qr")


@login_required
@require_POST
def service_action_preview(request, service_id):
    """请求 root 管理端根据实时事实生成任务影响预览。"""
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更服务。")
    operation = request.POST.get("operation", "")
    if operation not in OPERATION_LABELS:
        return HttpResponseBadRequest("服务操作不受支持。")
    try:
        task = preview_change_task(
            service_id, operation, request.user.get_username()
        )
    except AgentError as error:
        _raise_404_if_missing(error)
        status = 400 if error.code in {"invalid_params", "operation_forbidden"} else 503
        return HttpResponseBadRequest(str(error)) if status == 400 else HttpResponse(
            "暂时无法生成任务预览，请检查管理代理。", status=503
        )
    return render(
        request,
        "dashboard/service_confirm.html",
        {
            "task": task,
            "service_id": service_id,
            "operation": operation,
            "operation_label": OPERATION_LABELS[operation],
            "active_page": "services",
        },
    )


@login_required
@require_POST
def service_action_execute(request, service_id):
    """幂等确认 root 端已经持久化的服务变更任务。"""
    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以变更服务。")
    task_id = request.POST.get("task_id", "")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        return HttpResponseBadRequest("服务变更任务标识无效。")
    try:
        task = confirm_change_task(task_id, request.user.get_username())
    except AgentError as error:
        _raise_404_if_missing(error)
        messages.error(request, "任务确认失败，请重新生成影响预览。")
        return redirect("service-detail", service_id=service_id)
    else:
        messages.success(
            request,
            f"任务已提交后台执行：{task['id']}。",
        )
    return redirect("change-task-detail", task_id=task_id)


@login_required
@never_cache
def change_task_detail(request, task_id):
    """显示 root 端持久化的脱敏任务进度和迁移记录。"""

    if not TASK_ID_PATTERN.fullmatch(task_id):
        raise Http404
    try:
        task = change_task(task_id)
    except AgentError as error:
        _raise_404_if_missing(error)
        return render(
            request,
            "dashboard/task_unavailable.html",
            {"active_page": "audit", "task_id": task_id,
             **task_navigation_context(None, request.session, task_id)},
            status=503,
        )
    response = render(
        request,
        "dashboard/change_task_detail.html",
        {"task": task, "active_page": "audit",
         **task_navigation_context(task, request.session, task_id)},
    )
    response["Cache-Control"] = "no-store, max-age=0"
    return response


@login_required
@require_POST
def change_task_cancel(request, task_id):
    """取消尚未执行的任务；安全事务只允许超级管理员接管。"""

    if not _can_manage(request.user):
        return HttpResponseForbidden("只有管理员可以取消任务。")
    if not TASK_ID_PATTERN.fullmatch(task_id):
        raise Http404
    try:
        task = change_task(task_id)
        if str(task.get("action", "")).startswith("security.") and not request.user.is_superuser:
            return HttpResponseForbidden("只有超级管理员可以接管安全事务任务。")
        cancel_change_task(task_id, request.user.get_username())
    except AgentError as error:
        _raise_404_if_missing(error)
        messages.error(request, "任务无法取消；它可能已经开始执行。")
    else:
        messages.success(request, "任务已取消。")
    return redirect("change-task-detail", task_id=task_id)
