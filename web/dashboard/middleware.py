"""管理网站的会话失效保护。"""

from urllib.parse import urlencode, urlsplit

from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.cache import add_never_cache_headers


class SafeExpiredPostMiddleware:
    """会话在提交表单前过期时，登录后回到来源页而非重放 GET。"""

    SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        login_path = resolve_url(settings.LOGIN_URL)
        if (
            request.method not in self.SAFE_METHODS
            and request.path != login_path
            and not request.user.is_authenticated
        ):
            if request.path in {
                reverse("network-permission-batch-preview"),
                reverse("network-permission-batch-execute"),
                reverse("inline-task-execute"),
            }:
                response = JsonResponse({"error": "登录已失效，请重新登录后继续。"}, status=401)
                add_never_cache_headers(response)
                return response
            target = "/"
            referer = request.META.get("HTTP_REFERER", "")
            if referer and url_has_allowed_host_and_scheme(
                referer,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                parsed = urlsplit(referer)
                target = parsed.path or "/"
                if parsed.query:
                    target = f"{target}?{parsed.query}"
            return HttpResponseRedirect(f"{login_path}?{urlencode({'next': target})}")
        return self.get_response(request)
