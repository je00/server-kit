#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANAGER="${REPO_DIR}/server-kit-manager.sh"

fail() {
  echo "失败：$1" >&2
  exit 1
}

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT
fake_security="${test_dir}/security-manager.sh"
fake_bin="${test_dir}/bin"
mkdir -p "${fake_bin}"
printf '#!/usr/bin/env bash\nexit 0\n' >"${fake_bin}/flock"
chmod +x "${fake_bin}/flock"

cat >"${fake_security}" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  ssh-auth-plan) ;;
  harden-ssh-auth)
    python3 - "${SSH_AUTH_TRANSACTION_PATH}" <<'PYTHON'
import json
import sys
from datetime import datetime, timezone
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump({"created_at": datetime.now(timezone.utc).isoformat()}, output)
PYTHON
    ;;
  confirm-ssh-auth|rollback-ssh-auth)
    rm -f -- "${SSH_AUTH_TRANSACTION_PATH}"
    ;;
  *) exit 1 ;;
esac
BASH
chmod +x "${fake_security}"

printf 'PasswordAuthentication yes\n' >"${test_dir}/ssh-auth.conf"
printf 'table inet server_kit_filter {}\n' >"${test_dir}/firewall.nft"
printf '{}\n' >"${test_dir}/ports.json"
printf '{}\n' >"${test_dir}/security.json"

common_env=(
  SERVER_KIT_CONTROL=1
  SERVER_KIT_TESTING=1
  PATH="${fake_bin}:${PATH}"
  SERVER_KIT_HIGH_RISK_WRITES=1
  SECURITY_MANAGER="${fake_security}"
  SSH_AUTH_CONFIG="${test_dir}/ssh-auth.conf"
  SSH_AUTH_TRANSACTION="${test_dir}/ssh-auth-transaction.json"
  SSH_AUTH_TRANSACTION_PATH="${test_dir}/ssh-auth-transaction.json"
  SSH_TRANSACTION="${test_dir}/ssh-transaction.json"
  SECURITY_CONFIG="${test_dir}/security.json"
  SECURITY_CONTEXT_DIR="${test_dir}/contexts"
  MANAGEMENT_LOCK_PATH="${test_dir}/management-change.lock"
  FIREWALL_ACTIVE_RULES="${test_dir}/firewall.nft"
  FIREWALL_CANDIDATE_RULES="${test_dir}/firewall.nft"
  FIREWALL_TRANSACTION="${test_dir}/firewall-transaction.json"
  PORTS_PATH="${test_dir}/ports.json"
)

origin_session="$(printf 'a%.0s' {1..64})"
second_session="$(printf 'b%.0s' {1..64})"
request_json() {
  local session_id="$1"
  printf '{"session_id":"%s","actor":"owner","public_ip":"","public_port":""}\n' "${session_id}"
}

apply_result="$(request_json "${origin_session}" | env "${common_env[@]}" bash "${MANAGER}" transaction ssh_auth apply --json)"
APPLY_RESULT="${apply_result}" python3 - <<'PYTHON' || fail "应用后没有进入待确认状态"
import json
import os
value = json.loads(os.environ["APPLY_RESULT"])
assert value["state"] == "pending"
assert value["independent_session"] is False
PYTHON
[[ -r "${test_dir}/contexts/ssh_auth.json" ]] || fail "没有持久化发起会话保护记录"

if request_json "${origin_session}" | env "${common_env[@]}" bash "${MANAGER}" transaction ssh_auth confirm --json >/dev/null 2>&1; then
  fail "原发起会话越权确认了安全事务"
fi
[[ -r "${test_dir}/ssh-auth-transaction.json" ]] || fail "拒绝同会话确认时错误地结束了事务"

confirm_result="$(request_json "${second_session}" | env "${common_env[@]}" bash "${MANAGER}" transaction ssh_auth confirm --json)"
CONFIRM_RESULT="${confirm_result}" python3 - <<'PYTHON' || fail "独立会话确认结果无效"
import json
import os
value = json.loads(os.environ["CONFIRM_RESULT"])
assert value["state"] == "idle"
PYTHON
[[ ! -e "${test_dir}/contexts/ssh_auth.json" ]] || fail "确认后没有清理会话保护记录"

echo "通过：安全事务拒绝原会话确认，并允许独立连接接管。"
