#!/usr/bin/env python3
"""管理网站使用的 Unix Socket 客户端。"""

from __future__ import annotations

import json
import socket
import uuid
from typing import Any


class AgentError(Exception):
    """管理代理拒绝或无法完成请求。"""

    def __init__(self, message: str, code: str = "agent_error") -> None:
        super().__init__(message)
        self.code = code


class AgentClient:
    def __init__(self, socket_path: str, timeout: float = 5.0) -> None:
        self._socket_path = socket_path
        self._timeout = timeout

    def request(self, action: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        payload = {
            "version": 1,
            "request_id": request_id,
            "action": action,
            "params": params or {},
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self._timeout)
            connection.connect(self._socket_path)
            connection.sendall(encoded + b"\n")
            response_file = connection.makefile("rb")
            line = response_file.readline(1_048_577)
        if not line or len(line) > 1_048_576:
            raise AgentError("管理代理响应为空或过大。")
        try:
            response = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentError("管理代理响应格式无效。") from exc
        if response.get("request_id") != request_id:
            raise AgentError("管理代理响应与请求不匹配。")
        if not response.get("ok"):
            error = response.get("error", {})
            raise AgentError(
                str(error.get("message", "管理代理拒绝请求。")),
                str(error.get("code", "agent_error")),
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise AgentError("管理代理结果格式无效。")
        return result
