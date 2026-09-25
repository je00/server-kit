"""Recover stale login forms without accepting an unverified login request."""

from posixpath import normpath
from urllib.parse import unquote, urljoin, urlsplit

from django.contrib.auth.views import LoginView
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.cache import add_never_cache_headers
from django.views.csrf import csrf_failure as default_csrf_failure


class ConsoleLoginView(LoginView):
    def get_redirect_url(self):
        target = super().get_redirect_url()  # Retain Django's host/scheme checks.
        if not target:
            return ""
        # Match the browser's relative-URL handling, including ?query, #hash
        # and dot segments, before excluding the authentication endpoints.
        destination = urljoin(self.request.build_absolute_uri(), target)
        path = normpath(unquote(urlsplit(destination).path)).rstrip("/")
        if path in {reverse("login").rstrip("/"), reverse("logout").rstrip("/")}:
            # A bookmarked /login/?next=/login/ otherwise fails after success.
            return ""
        return target


def _same_origin(request):
    expected = f"{request.scheme}://{request.get_host()}"
    origin = request.META.get("HTTP_ORIGIN")
    if origin is not None:
        return origin == expected
    try:
        referer = urlsplit(request.META.get("HTTP_REFERER", ""))
    except ValueError:
        return False
    return f"{referer.scheme}://{referer.netloc}" == expected


def csrf_failure(request, reason=""):
    """Discard a same-account stale login POST, then navigate with GET only.

    Logging in rotates CSRF tokens in other open tabs. An existing authenticated
    session can already GET its landing page; this does not authenticate, consume
    the submitted password, switch accounts, or replay any management action.
    All anonymous, cross-origin and non-login failures retain the normal 403.
    """
    if (
        request.method == "POST"
        and request.path == reverse("login")
        and request.user.is_authenticated
        and _same_origin(request)
        and request.POST.get("username") == request.user.get_username()
    ):
        view = ConsoleLoginView()
        view.setup(request)
        response = HttpResponseRedirect(view.get_success_url(), status=303)
        add_never_cache_headers(response)
        return response
    return default_csrf_failure(request, reason=reason)
