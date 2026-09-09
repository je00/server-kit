#!/usr/bin/env python3
"""可复现地构建并校验 server-kit 浏览器扩展发布包。"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "browser_extension"
RUNTIME_FILES = (
    "manifest.json",
    "popup.html",
    "popup.css",
    "popup.js",
    "service_worker.js",
    "session_store.js",
    "awg.js",
    "icons/icon-16.png",
    "icons/icon-32.png",
    "icons/icon-48.png",
    "icons/icon-128.png",
    "vendor/qrcode.js",
)
FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files() -> list[dict[str, object]]:
    files = []
    for relative in RUNTIME_FILES:
        path = SOURCE / relative
        if not path.is_file():
            raise RuntimeError(f"扩展运行文件缺失：{relative}")
        files.append({"path": relative, "size": path.stat().st_size, "sha256": digest(path)})
    return files


def source_tree_sha256(files: list[dict[str, object]]) -> str:
    canonical = "".join(f"{item['path']}\0{item['sha256']}\n" for item in files)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build(output: Path) -> dict[str, object]:
    files = source_files()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for item in files:
            relative = str(item["path"])
            info = zipfile.ZipInfo(relative, FIXED_TIME)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (SOURCE / relative).read_bytes())
    manifest = json.loads((SOURCE / "manifest.json").read_text(encoding="utf-8"))
    return {
        "schema_version": 1,
        "name": manifest["name"],
        "version": manifest["version"],
        "package": output.name,
        "package_size": output.stat().st_size,
        "package_sha256": digest(output),
        "source_tree_sha256": source_tree_sha256(files),
        "files": files,
    }


def verify(release_manifest: Path) -> dict[str, object]:
    expected = json.loads(release_manifest.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / str(expected.get("package", "extension.zip"))
        actual = build(output)
    checked = (
        "schema_version", "name", "version", "package", "package_size",
        "package_sha256", "source_tree_sha256", "files",
    )
    differences = [key for key in checked if expected.get(key) != actual.get(key)]
    if differences:
        raise RuntimeError("发布清单与当前源码不一致：" + "、".join(differences))
    return actual


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="构建或校验浏览器扩展发布包")
    subparsers = parser.add_subparsers(dest="action", required=True)
    build_parser = subparsers.add_parser("build", help="生成可复现 ZIP 与清单")
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--manifest-output", type=Path, help="同时写入发布清单")
    verify_parser = subparsers.add_parser("verify", help="按仓库清单重建并校验")
    verify_parser.add_argument("--manifest", type=Path, default=SOURCE / "release-manifest.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = build(args.output) if args.action == "build" else verify(args.manifest)
    if args.action == "build" and args.manifest_output:
        args.manifest_output.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
