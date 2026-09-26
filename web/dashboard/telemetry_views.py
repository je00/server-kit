"""Authenticated, read-only node rates; no configuration or active probes."""

import math
import re
from datetime import datetime

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils.timezone import now as server_now
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from control_plane.client import AgentError

from .services import network_telemetry


NODE_ID = re.compile(r"(?:awg|vless):[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
STATES = {"active", "recent", "idle", "never", "disabled", "pending", "unknown", "unsupported"}
RATE_STATES = {"ok", "warming_up", "unavailable", "reset"}


def number(value, maximum=1e15):
    return type(value) in (float, int) and math.isfinite(value) and 0 <= value <= maximum


def public_telemetry(value):
    """Allowlist the browser payload even if an adapter adds private fields."""
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("Invalid telemetry schema")
    sampled_at = value.get("sampled_at")
    if not isinstance(sampled_at, str) or len(sampled_at) > 40:
        raise ValueError("Invalid sample time")
    observed = datetime.fromisoformat(sampled_at.replace("Z", "+00:00"))
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("Sample time requires timezone")
    if (type(value.get("refresh_ms")) is not int or value["refresh_ms"] != 2000
            or type(value.get("stale_after_ms")) is not int or value["stale_after_ms"] != 8000):
        raise ValueError("Invalid telemetry interval")
    if not isinstance(value.get("nodes"), list) or len(value["nodes"]) > 4096:
        raise ValueError("Invalid telemetry nodes")
    nodes, seen = [], set()
    for node in value["nodes"]:
        if not isinstance(node, dict):
            raise ValueError("Invalid telemetry node")
        identifier = node.get("id")
        if not isinstance(identifier, str) or not NODE_ID.fullmatch(identifier) or identifier in seen:
            raise ValueError("Invalid or duplicate node")
        seen.add(identifier)
        state, source, rate_status = node.get("state"), node.get("source"), node.get("rate_status")
        if state not in STATES or source not in {"awg", "xray", "none"} or rate_status not in RATE_STATES:
            raise ValueError("Invalid telemetry state")
        last_seen = node.get("last_seen_at")
        if last_seen is not None and not number(last_seen, 1e12):
            raise ValueError("Invalid activity time")
        upload, download = node.get("upload_bps"), node.get("download_bps")
        if rate_status == "ok":
            if (not number(upload) or not number(download) or source == "none"
                    or state in {"disabled", "pending", "unknown", "unsupported"}
                    or (source == "awg") != identifier.startswith("awg:")):
                raise ValueError("Invalid sampled rates")
        elif upload is not None or download is not None:
            raise ValueError("Unsampled rates must be null")
        nodes.append({"id": identifier, "state": state, "source": source,
                      "rate_status": rate_status, "last_seen_at": last_seen,
                      "upload_bps": upload, "download_bps": download})
    # The sampler and web service share the VPS clock. Browsers need not share
    # it: comparing sampled_at with a phone's Date.now() can expire fresh data.
    age_ms = max(0, math.ceil((server_now() - observed).total_seconds() * 1000))
    return {"schema_version": 1, "sampled_at": sampled_at, "sample_age_ms": min(age_ms, 86_400_000), "refresh_ms": 2000,
            "stale_after_ms": 8000, "nodes": nodes}


@login_required
@never_cache
@require_GET
def node_telemetry(request):
    try:
        payload = public_telemetry(network_telemetry())
    except (AgentError, OSError, RuntimeError, ValueError, TypeError, OverflowError):
        return JsonResponse({"code": "telemetry_unavailable", "error": "暂时无法读取实时状态，请稍后重试。"}, status=503)
    return JsonResponse(payload)
