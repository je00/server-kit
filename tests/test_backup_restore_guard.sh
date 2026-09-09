#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANAGER="${REPO_DIR}/server-kit-manager.sh"
test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

fail() { echo "失败：$1" >&2; exit 1; }

mkdir -p "${test_dir}/bin"
printf '#!/usr/bin/env bash\nexit 0\n' >"${test_dir}/bin/flock"
chmod +x "${test_dir}/bin/flock"

fake_backup="${test_dir}/backup.py"
cat >"${fake_backup}" <<'PYTHON'
#!/usr/bin/env python3
import json
import os
import sys

operation = sys.argv[1]
state_path = os.environ["FAKE_RESTORE_STATE"]
backup_id = "backup-20260808T120000Z-abcdef12"
if operation == "restore-apply":
    open(state_path, "w", encoding="utf-8").write("pending")
    state, outcome = "pending", ""
elif operation == "restore-confirm":
    try: os.unlink(state_path)
    except FileNotFoundError: pass
    state, outcome = "idle", "confirmed"
elif operation == "restore-rollback":
    try: os.unlink(state_path)
    except FileNotFoundError: pass
    state, outcome = "idle", "rolled_back"
elif operation == "restore-status":
    state = "pending" if os.path.exists(state_path) else "idle"
    outcome = ""
else:
    raise SystemExit(2)
result = {
    "schema_version": 1, "state": state,
    "backup_id": backup_id if state == "pending" else "",
    "expires_at": "2026-08-08T12:05:00+00:00" if state == "pending" else "",
    "remaining_seconds": 300 if state == "pending" else 0,
    "rollback_seconds": 300, "changed_count": 2 if state == "pending" else 0,
    "categories": ["server-kit"] if state == "pending" else [],
    "verifications": ["关键事实配置"] if state == "pending" else [],
    "writes_enabled": True, "last_outcome": outcome,
}
json.dump({"schema_version": 1, "ok": True, "result": result}, sys.stdout, separators=(",", ":"))
print()
PYTHON

common_env=(
  SERVER_KIT_CONTROL=1 SERVER_KIT_TESTING=1 SERVER_KIT_HIGH_RISK_WRITES=1
  PATH="${test_dir}/bin:${PATH}"
  BACKUP_HELPER="${fake_backup}" BACKUP_DIR="${test_dir}/backups"
  BACKUP_CONTEXT_PATH="${test_dir}/contexts/backup_restore.json"
  SECURITY_CONTEXT_DIR="${test_dir}/contexts"
  MANAGEMENT_LOCK_PATH="${test_dir}/management-change.lock"
  FAKE_RESTORE_STATE="${test_dir}/restore.state"
)
origin_session="$(printf 'c%.0s' {1..64})"
second_session="$(printf 'd%.0s' {1..64})"
backup_id="backup-20260808T120000Z-abcdef12"
request_json() {
  printf '{"passphrase":"测试恢复口令-长度超过十六个字符","session_id":"%s","actor":"owner"}\n' "$1"
}

applied="$(request_json "${origin_session}" | env "${common_env[@]}" bash "${MANAGER}" backup restore-apply "${backup_id}" --json)"
APPLIED="${applied}" python3 - <<'PYTHON' || fail "恢复应用结果不正确"
import json, os
result = json.loads(os.environ["APPLIED"])["result"]
assert result["state"] == "pending"
assert result["independent_session"] is False
PYTHON

if request_json "${origin_session}" | env "${common_env[@]}" bash "${MANAGER}" backup restore-confirm --json >/dev/null 2>&1; then
  fail "原发起会话越权确认了配置恢复"
fi
[[ -r "${test_dir}/restore.state" ]] || fail "拒绝原会话时错误地回滚或确认了恢复"

confirmed="$(request_json "${second_session}" | env "${common_env[@]}" bash "${MANAGER}" backup restore-confirm --json)"
CONFIRMED="${confirmed}" python3 - <<'PYTHON' || fail "独立连接确认结果不正确"
import json, os
result = json.loads(os.environ["CONFIRMED"])["result"]
assert result["state"] == "idle"
assert result["last_outcome"] == "confirmed"
PYTHON
[[ ! -e "${test_dir}/contexts/backup_restore.json" ]] || fail "确认后没有清理恢复会话记录"

echo "通过：配置恢复拒绝原会话确认，并允许独立连接接管。"
