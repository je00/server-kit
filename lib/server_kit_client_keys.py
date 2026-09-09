#!/usr/bin/env python3
"""验证普通节点始终由客户端持有私钥。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .server_kit_key_leak_gate import scan_client_private_material
except ImportError:  # 直接执行脚本时 lib 目录本身位于模块搜索路径
    from server_kit_key_leak_gate import scan_client_private_material


class ClientKeyPolicyError(ValueError):
    """表示普通节点密钥安全约束未满足。"""


def verify_client_key_policy(root: Path) -> dict[str, object]:
    """返回脱敏检查结果；任何普通节点都必须有合规凭据记录。"""

    root = root.resolve()
    findings = scan_client_private_material(root)
    checklist = [f"{item.path}：{item.reason}" for item in findings]
    peer_count = 0
    for filename in ("peers.tsv", "peers.disabled.tsv"):
        path = root / "etc/amneziawg" / filename
        try:
            peer_count += sum(1 for row in path.read_text(encoding="utf-8").splitlines() if row.strip())
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError) as exc:
            raise ClientKeyPolicyError(f"节点清单不可读：{path}") from exc
    return {
        "schema_version": 1,
        "ready": not checklist,
        "reason": "AWG 节点凭据安全约束已满足" if not checklist else "AWG 节点凭据安全约束未满足",
        "peer_count": peer_count,
        "checklist": checklist,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "status"))
    parser.add_argument("--root", type=Path, default=Path("/"))
    args = parser.parse_args()
    try:
        result = verify_client_key_policy(args.root)
    except (ClientKeyPolicyError, OSError, ValueError) as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    ok = args.operation == "status" or result["ready"] is True
    print(json.dumps({"schema_version": 1, "ok": ok, "result": result}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
