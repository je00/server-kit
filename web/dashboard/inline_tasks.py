"""Narrow, owner-scoped JSON bridge for existing low-risk preview forms."""

import json

from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.cache import never_cache

from control_plane.client import AgentError
from control_plane.tasks import TASK_ID_PATTERN
from .services import change_task, confirm_change_task


INLINE_ACTIONS = frozenset({
    "network.proxy.update", "network.node.domains", "network.address.domains",
    "network.permission.deny",
})


def gate(request, method):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "登录已失效，请在新标签页登录后重试；当前输入已保留。"}, status=401)
    if not (request.user.is_staff or request.user.is_superuser):
        return JsonResponse({"error": "只有管理员可以操作这些任务。"}, status=403)
    if request.method != method:
        response = JsonResponse({"error": "请求方法无效。"}, status=405)
        response["Allow"] = method
        return response


def owned_task(request, task_id):
    if not isinstance(task_id, str) or not TASK_ID_PATTERN.fullmatch(task_id):
        raise ValueError("任务标识无效。")
    task = change_task(task_id)
    if (task.get("id") != task_id or task.get("actor") != request.user.get_username()
            or task.get("action") not in INLINE_ACTIONS):
        return None
    return task


def payload(task):
    return {"task": task, "status_url": reverse("inline-task-status", args=[task["id"]]),
            "task_url": reverse("change-task-detail", args=[task["id"]])}


def failure(error):
    status = 404 if getattr(error, "code", "") in {"not_found", "forbidden"} else 503
    return JsonResponse({"error": "暂时无法读取或确认任务，请查询原任务状态，不要重复提交。"}, status=status)


@never_cache
def execute(request):
    denied = gate(request, "POST")
    if denied is not None:
        return denied
    try:
        if request.content_type != "application/json" or len(request.body) > 1024:
            raise ValueError("任务确认格式无效。")
        data = json.loads(request.body)
        if not isinstance(data, dict) or set(data) != {"task_id"}:
            raise ValueError("任务确认字段无效。")
        task = owned_task(request, data["task_id"])
        if task is None:
            return JsonResponse({"error": "该任务不支持当前操作或不属于当前账号。"}, status=404)
        if task.get("state") == "waiting_confirmation":
            task = confirm_change_task(task["id"], request.user.get_username())
        return JsonResponse(payload(task))
    except (ValueError, UnicodeError, RequestDataTooBig) as error:
        return JsonResponse({"error": str(error)}, status=400)
    except (AgentError, OSError) as error:
        return failure(error)


@never_cache
def status(request, task_id):
    denied = gate(request, "GET")
    if denied is not None:
        return denied
    try:
        task = owned_task(request, task_id)
        if task is None:
            return JsonResponse({"error": "该任务不支持当前操作或不属于当前账号。"}, status=404)
        return JsonResponse(payload(task))
    except ValueError as error:
        return JsonResponse({"error": str(error)}, status=400)
    except (AgentError, OSError) as error:
        return failure(error)
