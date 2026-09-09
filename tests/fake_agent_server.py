#!/usr/bin/env python3
"""仅供本地页面预览使用的管理代理替身。"""

from __future__ import annotations

import argparse
import json
import os
import socket
import uuid


SNAPSHOT = {
    "schema_version": 1,
    "summary": {"running": 7, "stopped": 0, "failed": 0, "missing": 2},
    "services": [
        {"id": "amneziawg", "label": "AmneziaWG", "state": "运行中", "autostart": "自启", "detail": "2 个普通节点", "ports": []},
        {"id": "management", "label": "管理网站", "state": "运行中", "autostart": "自启", "detail": "内网 TCP 9080", "ports": []},
        {"id": "vless", "label": "Xray / VLESS", "state": "运行中", "autostart": "自启", "detail": "1 个受限节点", "ports": []},
        {"id": "clash", "label": "Clash 订阅", "state": "运行中", "autostart": "自启", "detail": "3 个发布订阅", "ports": []},
        {"id": "mosh", "label": "Mosh 终端", "state": "运行中", "autostart": "按需", "detail": "UDP 60001-60010（按需分配）", "ports": []},
    ],
}

CHANGEABLE = {"clash", "file", "mosh"}
TASKS: dict[str, dict[str, object]] = {}
PROXY_RESOURCES = {
    "schema_version": 2,
    "revision": "a" * 64,
    "configured": True,
    "airport_count": 2,
    "active_airport_count": 1,
    "airports": [
        {"id": "111111111111", "name": "主用机场", "host": "primary.example", "enabled": True, "countries": ["hk", "jp", "sg"], "country_labels": ["香港", "日本", "新加坡"]},
        {"id": "222222222222", "name": "备用机场", "host": "backup.example", "enabled": False, "countries": ["all"], "country_labels": ["全部地区"]},
    ],
    "country_options": [
        {"id": "all", "label": "全部地区"}, {"id": "hk", "label": "香港"},
        {"id": "tw", "label": "台湾"}, {"id": "jp", "label": "日本"},
        {"id": "sg", "label": "新加坡"}, {"id": "us", "label": "美国"},
        {"id": "kr", "label": "韩国"}, {"id": "uk", "label": "英国"},
    ],
    "exit": {"configured": True, "type": "socks5", "server": "exit.example", "port": 1080},
}


def describe(service_id: str) -> dict[str, object]:
    service = next((item for item in SNAPSHOT["services"] if item["id"] == service_id), None)
    if service is None:
        raise KeyError(service_id)
    operations: list[str] = []
    restriction = ""
    if service["state"] == "未安装":
        restriction = "服务尚未安装，请使用后续安装向导。"
    elif service_id in CHANGEABLE:
        operations = ["stop", "restart"] if service["state"] == "运行中" else ["start"]
    else:
        restriction = "此服务在当前阶段保持只读。"
    return {
        "service": service,
        "allowed_operations": operations,
        "restriction": restriction,
    }


def serve(socket_path: str) -> None:
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(socket_path)
        listener.listen(4)
        while True:
            connection, _ = listener.accept()
            with connection:
                request = json.loads(connection.makefile("rb").readline().decode("utf-8"))
                try:
                    if request["action"] == "system.snapshot":
                        result = SNAPSHOT
                    elif request["action"] == "host.read" and request["params"].get("intent") == "proxy":
                        result = {"schema_version": 1, "intent": "proxy", "fresh_for_ms": 1000, "components": ["proxy"], "view": PROXY_RESOURCES}
                    elif request["action"] == "network.proxy.test":
                        result = {
                            "schema_version": 2,
                            "airports": [
                                {"id": item["id"], "name": item["name"], "enabled": item["enabled"], "ok": item["enabled"], "status": "HTTP 200" if item["enabled"] else "连接失败"}
                                for item in PROXY_RESOURCES["airports"]
                            ],
                            "exit": {"ok": True, "status": "TCP 可达"},
                            "all_ok": True,
                        }
                    elif request["action"] == "service.describe":
                        result = describe(request["params"]["service_id"])
                    elif request["action"] == "service.change":
                        details = describe(request["params"]["service_id"])
                        operation = request["params"]["operation"]
                        if operation not in details["allowed_operations"]:
                            raise ValueError("操作不允许")
                        details["service"]["state"] = "已停止" if operation == "stop" else "运行中"
                        result = {"service": details["service"], "operation": operation}
                    elif request["action"] == "task.preview":
                        arguments = request["params"]["arguments"]
                        task_id = f"task-{uuid.uuid4().hex}"
                        if request["params"].get("action") == "network.proxy.update":
                            operation = arguments["operation"]
                            title = {
                                "airport_add": "新增机场", "airport_update": "更新机场",
                                "airport_delete": "删除机场", "exit_update": "更新出口节点",
                            }[operation]
                            facts = {"动作": title, "发布订阅": "全部刷新"}
                            action = "network.proxy.update"
                        else:
                            details = describe(arguments["service_id"])
                            operation = arguments["operation"]
                            if operation not in details["allowed_operations"]:
                                raise ValueError("操作不允许")
                            target = "已停止" if operation == "stop" else "运行中"
                            operation_label = {"start": "启动", "stop": "停止", "restart": "重启"}[operation]
                            title = f"{operation_label} {details['service']['label']}"
                            facts = {"当前状态": details["service"]["state"], "目标状态": target}
                            action = f"service.{operation}"
                        result = {
                            "id": task_id,
                            "action": action,
                            "actor": request["params"]["actor"],
                            "state": "waiting_confirmation",
                            "state_label": "待确认",
                            "terminal": False,
                            "preview": {
                                "title": title,
                                "summary": "任务将在后台执行；关闭页面不会中断操作。",
                                "facts": facts,
                            },
                            "progress": {"message": "影响预览已生成，等待确认。"},
                            "result": {},
                            "transitions": [],
                            "created_at": "2026-08-08T00:00:00.000Z",
                        }
                        TASKS[task_id] = result
                    elif request["action"] == "task.confirm":
                        result = TASKS[request["params"]["task_id"]]
                        result["state"] = "succeeded"
                        result["state_label"] = "成功"
                        result["terminal"] = True
                        result["progress"] = {"message": "任务执行并核验成功。"}
                        result["transitions"] = [
                            {"to_state": "succeeded", "message": "任务执行并核验成功。", "occurred_at": "2026-08-08T00:00:01.000Z"}
                        ]
                    elif request["action"] == "task.get":
                        result = TASKS[request["params"]["task_id"]]
                    elif request["action"] == "task.list":
                        result = {"items": list(TASKS.values())}
                    elif request["action"] == "service.reveal":
                        if request["params"].get("service_id") != "clash":
                            raise ValueError("敏感资源不允许")
                        item_id = request["params"]["item_id"]
                        if request["params"]["resource"] == "subscription_link":
                            result = {"schema_version": 1, "resource": "clash_subscription_link", "item_id": item_id, "name": item_id, "value": "https://203.0.113.10:52541/preview-token/clash.yaml"}
                        elif request["params"]["resource"] == "airport_link":
                            result = {"schema_version": 1, "resource": "proxy_airport_link", "item_id": item_id, "name": "主用机场", "value": "https://primary.example/sub?token=preview"}
                        elif request["params"]["resource"] == "exit_config":
                            result = {"schema_version": 1, "resource": "proxy_exit_config", "item_id": item_id, "name": "当前出口节点", "value": "type: socks5\nserver: exit.example\nport: 1080\n"}
                        else:
                            result = {"schema_version": 1, "resource": "clash_subscription_qr", "item_id": item_id, "name": item_id, "image_base64": "iVBORw0KGgo="}
                    elif request["action"] == "security.transaction":
                        transaction_type = request["params"]["transaction_type"]
                        result = {
                            "schema_version": 1,
                            "transaction_type": transaction_type,
                            "title": "SSH 仅公钥认证" if transaction_type == "ssh_auth" else "nftables 主机防火墙",
                            "state": "idle",
                            "expires_at": "",
                            "remaining_seconds": 0,
                            "writes_enabled": False,
                            "ready": True,
                            "blockers": [],
                            "rollback_seconds": 300,
                            "changes": [],
                            "verifications": [],
                        }
                    else:
                        raise ValueError("动作未登记")
                    response = {
                        "version": 1,
                        "request_id": request["request_id"],
                        "ok": True,
                        "result": result,
                    }
                except (KeyError, ValueError):
                    response = {
                        "version": 1,
                        "request_id": request.get("request_id", "invalid-request"),
                        "ok": False,
                        "error": {"code": "invalid_request", "message": "预览请求无效。"},
                    }
                connection.sendall(
                    json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("socket_path")
    args = parser.parse_args()
    serve(args.socket_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
