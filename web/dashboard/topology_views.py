"""Read-only node topology; never initiates probes or configuration changes."""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from control_plane.client import AgentError

from .services import network_overview
from .topology import build_topology


@login_required
@never_cache
@require_GET
def node_connections(request):
    as_json = request.GET.get("format") == "json"
    try:
        snapshot = network_overview()
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("nodes"), list):
            raise ValueError("Invalid node snapshot")
        topology = build_topology(snapshot, request.GET.get("node", ""))
        topology["observed_at"] = timezone.now().isoformat()
    except (AgentError, OSError, RuntimeError, ValueError, TypeError):
        error = "暂时无法读取节点连接关系，请稍后重试。"
        if as_json:
            return JsonResponse({"code": "snapshot_unavailable", "error": error}, status=503)
        return render(request, "dashboard/network_topology.html", {
            "active_page": "nodes", "topology": None, "topology_error": error,
        }, status=503)
    if as_json:
        return JsonResponse(topology)
    return render(request, "dashboard/network_topology.html", {
        "active_page": "nodes", "topology": topology, "topology_error": "",
        "observed_at": topology["observed_at"],
    })
