#!/usr/bin/env bash
# 验证 Debian/Ubuntu 合盖策略使用独立配置片段，并且可以恢复默认值。
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEST_DIR="$(mktemp -d)"
MANAGER="${TEST_DIR}/server-kit-node-linux.sh"
LID_CONFIG="${TEST_DIR}/logind.conf.d/80-server-kit-lid.conf"
SYSTEMCTL_LOG="${TEST_DIR}/systemctl.log"
trap 'rm -f "${MANAGER}" "${LID_CONFIG}" "${SYSTEMCTL_LOG}" "${TEST_DIR}/bin/systemctl"; rmdir "${TEST_DIR}/logind.conf.d" "${TEST_DIR}/bin" "${TEST_DIR}" 2>/dev/null || true' EXIT
mkdir -p "${TEST_DIR}/bin"

PYTHONPATH="$ROOT_DIR" python3 - "$ROOT_DIR" "$MANAGER" <<'PY'
import sys
from pathlib import Path

from web.dashboard.ssh_scripts import SshScriptBundle

root = Path(sys.argv[1])
Path(sys.argv[2]).write_bytes(
    SshScriptBundle(root / "web/dashboard/script_templates").download("linux").payload
)
PY

cat >"${TEST_DIR}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${SERVER_KIT_LID_SYSTEMCTL_LOG}"
EOF
chmod +x "${TEST_DIR}/bin/systemctl"

COMMON_ENV=(
  PATH="${TEST_DIR}/bin:${PATH}"
  SERVER_KIT_LID_CONFIG="$LID_CONFIG"
  SERVER_KIT_LID_SYSTEMCTL_LOG="$SYSTEMCTL_LOG"
)

env "${COMMON_ENV[@]}" bash "$MANAGER" lid-ignore >/dev/null
grep -Fxq 'HandleLidSwitch=ignore' "$LID_CONFIG"
grep -Fxq 'HandleLidSwitchExternalPower=ignore' "$LID_CONFIG"
grep -Fxq 'HandleLidSwitchDocked=ignore' "$LID_CONFIG"
grep -Fq 'kill --kill-whom=main --signal=HUP systemd-logind.service' "$SYSTEMCTL_LOG"
env "${COMMON_ENV[@]}" bash "$MANAGER" lid-status | grep -Fq '合盖策略：不休眠'
env "${COMMON_ENV[@]}" bash "$MANAGER" lid-default >/dev/null
[[ ! -e "$LID_CONFIG" ]]

echo "通过：Linux 合盖不休眠可启用、查看并恢复系统默认。"
