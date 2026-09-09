#!/usr/bin/env bash
# 验证 Linux SSH 允许网段可使用任意 IPv4 CIDR，并保留防锁死保护。
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
MANAGER="${ROOT_DIR}/web/dashboard/script_templates/server-kit-ssh-linux.sh"
TEST_DIR="$(mktemp -d)"
trap 'rm -f "${TEST_DIR}/networks" "${TEST_DIR}/sshd.conf"; rmdir "${TEST_DIR}" 2>/dev/null || true' EXIT

run_manager() {
  SERVER_KIT_TESTING=1 \
  SERVER_KIT_SSH_NETWORKS_FILE="${TEST_DIR}/networks" \
  SERVER_KIT_SSH_CONFIG="${TEST_DIR}/sshd.conf" \
  bash "$MANAGER" "$@"
}

run_manager network-add 192.168.50.0/24 >/dev/null
list_output="$(run_manager network-list)"
grep -Fq '10.20.0.0/24 · 初始值，可替换' <<<"$list_output" || { echo "初始网段缺失" >&2; exit 1; }
grep -Fq '192.168.50.0/24' <<<"$list_output" || { echo "新增网段未保存" >&2; exit 1; }

if run_manager network-add 300.1.1.0/24 >/dev/null 2>&1; then
  echo "无效 CIDR 被错误接受" >&2
  exit 1
fi
run_manager network-remove 10.20.0.0/24 >/dev/null
if run_manager network-list | grep -Fq '10.20.0.0/24'; then
  echo "初始网段未能删除" >&2
  exit 1
fi

if run_manager network-remove 192.168.50.0/24 >/dev/null 2>&1; then
  echo "最后一个允许网段不应被删除" >&2
  exit 1
fi

echo "通过：Linux SSH 允许任意 IPv4 网段，并防止删除最后一个网段。"
