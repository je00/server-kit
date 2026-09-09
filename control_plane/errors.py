"""跨管理脚本、执行适配器和任务引擎传递的安全诊断。"""

from __future__ import annotations

import re


ERROR_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")


class TaskExecutionError(RuntimeError):
    """允许写入任务详情的、已经脱敏的执行错误。"""

    def __init__(self, code: str, message: str) -> None:
        if not isinstance(code, str) or not ERROR_CODE_PATTERN.fullmatch(code):
            raise ValueError("任务执行错误码格式不正确")
        if (
            not isinstance(message, str)
            or not message.strip()
            or len(message) > 320
            or any(character in message for character in "\x00\r\n")
        ):
            raise ValueError("任务执行错误提示格式不正确")
        normalized = message.strip()
        super().__init__(normalized)
        self.code = code
        self.message = normalized
