"""使用独立 root 机器密钥保护异步任务的短期敏感载荷。"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TaskPayloadCipher:
    """以任务标识为附加认证数据封装 AES-256-GCM。"""

    KEY_BYTES = 32
    NONCE_BYTES = 12

    def __init__(self, key_path: str | Path) -> None:
        self._path = Path(key_path)
        self._key = self._load_or_create_key()

    def encrypt(self, task_id: str, payload: Mapping[str, object]) -> str:
        plaintext = json.dumps(
            dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        nonce = os.urandom(self.NONCE_BYTES)
        ciphertext = AESGCM(self._key).encrypt(
            nonce, plaintext, task_id.encode("ascii")
        )
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, task_id: str, token: str) -> dict[str, object]:
        try:
            container = base64.b64decode(token, altchars=b"-_", validate=True)
            nonce = container[: self.NONCE_BYTES]
            ciphertext = container[self.NONCE_BYTES :]
            if len(nonce) != self.NONCE_BYTES or len(ciphertext) < 16:
                raise ValueError
            plaintext = AESGCM(self._key).decrypt(
                nonce, ciphertext, task_id.encode("ascii")
            )
            value = json.loads(plaintext)
        except Exception as error:
            raise ValueError("任务敏感载荷无法解密或认证失败") from error
        if not isinstance(value, dict):
            raise ValueError("任务敏感载荷格式无效")
        return value

    def _load_or_create_key(self) -> bytes:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:
            pass
        if self._path.is_symlink():
            raise RuntimeError("任务机器密钥不能是符号链接")
        try:
            descriptor = os.open(
                self._path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except FileExistsError:
            pass
        else:
            try:
                key_material = memoryview(os.urandom(self.KEY_BYTES))
                while key_material:
                    written = os.write(descriptor, key_material)
                    if written <= 0:
                        raise OSError("写入任务机器密钥失败")
                    key_material = key_material[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        metadata = self._path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("任务机器密钥不是普通文件")
        key = self._path.read_bytes()
        if len(key) != self.KEY_BYTES:
            raise RuntimeError("任务机器密钥长度无效")
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass
        return key
