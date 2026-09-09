#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
MANAGER="${TEST_DIR}/server-kit-node-linux.sh"
SOURCE_DIR="${TEST_DIR}/downloads"
CONFIG_DIR="${TEST_DIR}/etc/amnezia/amneziawg"
BIN_DIR="${TEST_DIR}/bin"
STATE_FILE="${TEST_DIR}/active-unit"
ENABLED_FILE="${TEST_DIR}/enabled-unit"
trap 'rm -rf "${TEST_DIR}"' EXIT
mkdir -p "$SOURCE_DIR" "$CONFIG_DIR" "$BIN_DIR"

PYTHONPATH="$ROOT_DIR" python3 - "$ROOT_DIR" "$MANAGER" <<'PY'
import sys
from pathlib import Path

from web.dashboard.ssh_scripts import SshScriptBundle

root = Path(sys.argv[1])
target = Path(sys.argv[2])
target.write_bytes(SshScriptBundle(root / "web/dashboard/script_templates").download("linux").payload)
PY

cat >"${BIN_DIR}/awg-quick" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == "strip" && -f "$2" ]]
grep -q '^Jc = ' "$2"
EOF

cat >"${BIN_DIR}/awg" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "show" && "$3" == "endpoints" ]]; then
  echo "peer 203.0.113.10:443"
elif [[ "$1" == "show" && "$3" == "latest-handshakes" ]]; then
  echo "peer 1760000000"
fi
EOF

cat >"${BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state_file="${SERVER_KIT_AWG_TEST_STATE}"
enabled_file="${SERVER_KIT_AWG_TEST_ENABLED_STATE}"
command_name="$1"
shift
case "$command_name" in
  list-unit-files) echo 'awg-quick@.service enabled' ;;
  is-active)
    [[ "${1:-}" != "--quiet" ]] || shift
    [[ -f "$state_file" && "$(cat "$state_file")" == "$1" ]]
    ;;
  is-enabled)
    [[ "${1:-}" != "--quiet" ]] || shift
    [[ -f "$enabled_file" && "$(cat "$enabled_file")" == "$1" ]]
    ;;
  disable)
    stop_now=0
    if [[ "${1:-}" == "--now" ]]; then stop_now=1; shift; fi
    [[ ! -f "$enabled_file" || "$(cat "$enabled_file")" != "$1" ]] || rm -f "$enabled_file"
    if (( stop_now == 1 )); then
      [[ ! -f "$state_file" || "$(cat "$state_file")" != "$1" ]] || rm -f "$state_file"
    fi
    ;;
  enable)
    start_now=0
    if [[ "${1:-}" == "--now" ]]; then start_now=1; shift; fi
    echo "$1" >"$enabled_file"
    if (( start_now == 1 )); then echo "$1" >"$state_file"; fi
    ;;
  *) exit 2 ;;
esac
EOF

cat >"${BIN_DIR}/journalctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${BIN_DIR}"/*

write_profile() {
  local profile="$1" port="$2"
  cat >"${SOURCE_DIR}/a-very-long-linux-node-name-${profile}.conf" <<EOF
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.20.0.88/24
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 55
S2 = 50
S3 = 24
S4 = 13
H1 = 1001
H2 = 1002
H3 = 1003
H4 = 1004
I1 = <b 0x01020304>

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Endpoint = 203.0.113.10:${port}
AllowedIPs = 10.20.0.0/24
PersistentKeepalive = 25
EOF
}

write_profile main 443
write_profile backup1 1848
echo "不应删除" >"${CONFIG_DIR}/unrelated.conf"

COMMON_ENV=(
  SERVER_KIT_AWG_TESTING=1
  SERVER_KIT_AWG_CONFIG_DIR="$CONFIG_DIR"
  SERVER_KIT_AWG_QUICK_COMMAND="${BIN_DIR}/awg-quick"
  SERVER_KIT_AWG_COMMAND="${BIN_DIR}/awg"
  SERVER_KIT_AWG_SYSTEMCTL_COMMAND="${BIN_DIR}/systemctl"
  SERVER_KIT_AWG_JOURNALCTL_COMMAND="${BIN_DIR}/journalctl"
  SERVER_KIT_AWG_TEST_STATE="$STATE_FILE"
  SERVER_KIT_AWG_TEST_ENABLED_STATE="$ENABLED_FILE"
)

install_output="$(env "${COMMON_ENV[@]}" bash "$MANAGER" awg-install "$SOURCE_DIR")"
grep -q '配置完成：主入口已连接并设置为开机自启' <<<"$install_output"
[[ "$(cat "$STATE_FILE")" == 'awg-quick@sk-awg-main.service' ]]
[[ "$(cat "$ENABLED_FILE")" == 'awg-quick@sk-awg-main.service' ]]
for interface in sk-awg-main sk-awg-backup1; do
  [[ -f "${CONFIG_DIR}/${interface}.conf" ]]
  if [[ "$(uname -s)" != MINGW* ]]; then
    [[ "$(stat -c %a "${CONFIG_DIR}/${interface}.conf")" == "600" ]]
  fi
done

status_output="$(env "${COMMON_ENV[@]}" bash "$MANAGER" awg-status)"
grep -q '当前入口：主入口' <<<"$status_output"
grep -q '主入口.*已连接.*开机自启' <<<"$status_output"

env "${COMMON_ENV[@]}" bash "$MANAGER" awg-autostart off >/dev/null
[[ -f "$STATE_FILE" && ! -f "$ENABLED_FILE" ]]
env "${COMMON_ENV[@]}" bash "$MANAGER" awg-autostart on >/dev/null
[[ "$(cat "$ENABLED_FILE")" == 'awg-quick@sk-awg-main.service' ]]

switch_output="$(env "${COMMON_ENV[@]}" bash "$MANAGER" awg-use backup1)"
grep -q '已切换到 备用 1' <<<"$switch_output"
[[ "$(cat "$STATE_FILE")" == 'awg-quick@sk-awg-backup1.service' ]]

env "${COMMON_ENV[@]}" bash "$MANAGER" awg-disable >/dev/null
[[ ! -f "$STATE_FILE" ]]
for interface in sk-awg-main sk-awg-backup1; do
  [[ -f "${CONFIG_DIR}/${interface}.conf" ]]
done

enable_output="$(env "${COMMON_ENV[@]}" bash "$MANAGER" awg-enable)"
grep -q '已启动主入口并设置为开机自启' <<<"$enable_output"
[[ "$(cat "$STATE_FILE")" == 'awg-quick@sk-awg-main.service' ]]
[[ "$(cat "$ENABLED_FILE")" == 'awg-quick@sk-awg-main.service' ]]

env "${COMMON_ENV[@]}" bash "$MANAGER" awg-autostart off >/dev/null
enable_output="$(env "${COMMON_ENV[@]}" bash "$MANAGER" awg-enable main)"
grep -q '主入口已经运行，已恢复开机自启' <<<"$enable_output"
[[ "$(cat "$STATE_FILE")" == 'awg-quick@sk-awg-main.service' ]]
[[ "$(cat "$ENABLED_FILE")" == 'awg-quick@sk-awg-main.service' ]]

env "${COMMON_ENV[@]}" bash "$MANAGER" awg-remove --yes >/dev/null
for interface in sk-awg-main sk-awg-backup1 sk-awg-backup2; do
  [[ ! -e "${CONFIG_DIR}/${interface}.conf" ]]
done
[[ -f "${CONFIG_DIR}/unrelated.conf" ]]

unsafe_dir="${TEST_DIR}/unsafe"
mkdir -p "$unsafe_dir"
for profile in main backup1; do
  cp "${SOURCE_DIR}/a-very-long-linux-node-name-${profile}.conf" "${unsafe_dir}/unsafe-${profile}.conf"
done
sed -i '/^Address = /a PostUp = touch /tmp/should-not-run' "${unsafe_dir}/unsafe-main.conf"
if env "${COMMON_ENV[@]}" bash "$MANAGER" awg-install "$unsafe_dir" >"${TEST_DIR}/unsafe.log" 2>&1; then
  echo "失败：带有可执行钩子的配置被接受。" >&2
  exit 1
fi
grep -q '不允许包含可执行钩子' "${TEST_DIR}/unsafe.log"

echo "Linux 节点综合管理器的 AWG 配置测试通过。"
