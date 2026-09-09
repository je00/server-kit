#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_SCRIPT_DIR="${SCRIPT_DIR}"
MANAGER_PATH="${SCRIPT_DIR}/../debian_security_manager.sh"
# shellcheck disable=SC1090
source "${MANAGER_PATH}"
ORIGINAL_REFRESH_PORTS="$(declare -f refresh_ports)"

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

if [[ "${MSYSTEM:-}" != "" || "$(uname -s)" == "Darwin" ]]; then
  install() {
    local directory_mode=0
    local operands=()
    while (($#)); do
      case "$1" in
        -d) directory_mode=1; shift ;;
        -m|-o|-g) shift 2 ;;
        --) shift ;;
        *) operands+=("$1"); shift ;;
      esac
    done
    if (( directory_mode )); then
      mkdir -p -- "${operands[@]}"
    else
      cp -- "${operands[${#operands[@]}-2]}" "${operands[${#operands[@]}-1]}"
    fi
  }
  chown() { return 0; }
fi

SERVER_KIT_DIR="${test_dir}/server-kit"
SECURITY_CONFIG_PATH="${SERVER_KIT_DIR}/security.json"
SSH_DROPIN_PATH="${test_dir}/sshd_config.d/20-server-kit-listen.conf"
SSH_ORDERING_PATH="${test_dir}/systemd/ssh.service.d/20-server-kit-ordering.conf"
SSH_AUTH_DROPIN_PATH="${test_dir}/sshd_config.d/30-server-kit-auth.conf"
SSH_AUTH_TRANSACTION_PATH="${SERVER_KIT_DIR}/ssh-auth-transaction.json"
SSH_AUTH_BACKUP_DIR="${test_dir}/backups/ssh-auth"
ROOT_AUTHORIZED_KEYS_PATH="${test_dir}/root/.ssh/authorized_keys"
SYSTEMCTL_BIN="/usr/bin/true"

write_ssh_dropin final 203.0.113.10 62222 10.20.0.1
grep -Fxq 'ListenAddress 10.20.0.1:22' "${SSH_DROPIN_PATH}"
grep -Fxq 'ListenAddress 0.0.0.0:62222' "${SSH_DROPIN_PATH}"
if grep -Fxq 'ListenAddress 203.0.113.10:62222' "${SSH_DROPIN_PATH}"; then
  echo "失败：最终 SSH 配置仍绑定易变公网 IP。"
  exit 1
fi
if grep -Fxq 'ListenAddress 0.0.0.0:22' "${SSH_DROPIN_PATH}"; then
  echo "失败：最终 SSH 配置重新开放了公网 22。"
  exit 1
fi

write_security_config active 203.0.113.10 62222 10.20.0.1
write_ssh_ordering_dropin
grep -Fq 'After=network-online.target awg-quick@awg0.service' \
  "${SSH_ORDERING_PATH}" || {
  echo "失败：SSH 没有等待隧道接口启动。"
  exit 1
}
python3 - "${SECURITY_CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    ssh = json.load(source)["ssh"]
assert "wireguard_address" not in ssh
assert ssh["amneziawg_address"] == "10.20.0.1"
assert ssh["public_address"] == "203.0.113.10"
assert ssh["public_bind_address"] == "0.0.0.0"
assert ssh["public_port"] == 62222
PYTHON

port_scan="${test_dir}/ss-port-scan"
cat > "${port_scan}" <<'BASH'
#!/usr/bin/env bash
printf 'LISTEN 0 128 10.20.0.1:62222 0.0.0.0:* users:(("other",pid=1,fd=3))\n'
BASH
chmod +x "${port_scan}"
SS_BIN="${port_scan}"
[[ "$(listener_line_by_port 62222)" == *'"other"'* ]] || {
  echo "失败：SSH 通配监听预检没有发现其他本地地址上的端口占用。"
  exit 1
}

echo "通过：SSH 最终配置只保留 AmneziaWG 和公网高位入口。"
echo "通过：公网 22 不会因加入 AWG 监听而重新开放。"

# SSH 公网端口切换必须先临时放行，再原子确认防火墙；回滚同时恢复安全元数据。
(
  transaction_dir="${test_dir}/ssh-firewall-transaction"
  install -d "${transaction_dir}/server-kit" "${transaction_dir}/sshd_config.d"
  SERVER_KIT_DIR="${transaction_dir}/server-kit"
  SECURITY_CONFIG_PATH="${SERVER_KIT_DIR}/security.json"
  SSH_TRANSACTION_PATH="${SERVER_KIT_DIR}/ssh-transaction.json"
  SSH_BACKUP_DIR="${SERVER_KIT_DIR}/backups/ssh"
  SSH_DROPIN_PATH="${transaction_dir}/sshd_config.d/20-server-kit-listen.conf"
  SSH_ORDERING_PATH="${transaction_dir}/ssh.service.d/20-server-kit-ordering.conf"
  FIREWALL_TRANSACTION_PATH="${SERVER_KIT_DIR}/firewall-transaction.json"
  FIREWALL_MANAGER="${transaction_dir}/firewall-manager"
  FIREWALL_ACTION_LOG="${transaction_dir}/firewall-actions.log"
  FIREWALL_FAIL_APPLY="${transaction_dir}/fail-apply"
  export FIREWALL_TRANSACTION_PATH FIREWALL_ACTION_LOG FIREWALL_FAIL_APPLY
  SYSTEMCTL_BIN="/usr/bin/true"
  SSHD_BIN="/usr/bin/true"
  ROLLBACK_SECONDS=300

  cat > "${FIREWALL_MANAGER}" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${FIREWALL_ACTION_LOG}"
case "${1:-}" in
  open-transaction-temporary|close-transaction-temporary) ;;
  apply)
    [[ ! -e "${FIREWALL_FAIL_APPLY}" ]] || exit 1
    printf '{}\n' > "${FIREWALL_TRANSACTION_PATH}"
    ;;
  confirm|rollback) rm -f -- "${FIREWALL_TRANSACTION_PATH}" ;;
  *) exit 1 ;;
esac
BASH
  chmod +x "${FIREWALL_MANAGER}"

  detect_public_ipv4() { printf '203.0.113.10\n'; }
  detect_amneziawg_ipv4() { printf '10.20.0.1\n'; }
  address_is_local() { return 0; }
  schedule_rollback() { return 0; }
  cancel_rollback() { return 0; }
  validate_and_reload_ssh() { return 0; }
  refresh_ports() { return 0; }
  listener_exists() {
    grep -Fxq "ListenAddress $1:$2" "${SSH_DROPIN_PATH}"
  }

  write_ssh_dropin final 203.0.113.10 62222 10.20.0.1
  write_security_config active 203.0.113.10 62222 10.20.0.1
  install_ssh 203.0.113.10 63333 >/dev/null
  grep -Fxq 'open-transaction-temporary 63333 300 --yes' "${FIREWALL_ACTION_LOG}" || {
    echo "失败：SSH 切换没有先临时放行新公网端口。" >&2
    exit 1
  }
  rollback_ssh >/dev/null
  grep -Fxq 'ListenAddress 0.0.0.0:62222' "${SSH_DROPIN_PATH}"
  python3 - "${SECURITY_CONFIG_PATH}" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert json.load(source)["ssh"]["public_port"] == 62222
PYTHON

  install_ssh 203.0.113.10 63333 >/dev/null
  confirm_ssh --yes >/dev/null
  grep -Fxq 'apply --yes' "${FIREWALL_ACTION_LOG}"
  grep -Fxq 'confirm --yes' "${FIREWALL_ACTION_LOG}"
  grep -Fxq 'ListenAddress 10.20.0.1:22' "${SSH_DROPIN_PATH}"
  grep -Fxq 'ListenAddress 0.0.0.0:63333' "${SSH_DROPIN_PATH}"
  [[ ! -e "${SSH_TRANSACTION_PATH}" ]]
  python3 - "${SECURITY_CONFIG_PATH}" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    ssh = json.load(source)["ssh"]
assert ssh["status"] == "active"
assert ssh["public_port"] == 63333
PYTHON

  write_security_config staged 203.0.113.10 64444 10.20.0.1
  reconcile_ssh_security >/dev/null
  python3 - "${SECURITY_CONFIG_PATH}" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    ssh = json.load(source)["ssh"]
assert ssh["status"] == "active"
assert ssh["public_port"] == 63333
PYTHON

  touch "${FIREWALL_FAIL_APPLY}"
  install_ssh 203.0.113.10 64444 >/dev/null
  if confirm_ssh --yes >/dev/null 2>&1; then
    echo "失败：防火墙应用失败时 SSH 切换仍报告成功。" >&2
    exit 1
  fi
  grep -Fxq 'ListenAddress 0.0.0.0:63333' "${SSH_DROPIN_PATH}"
  python3 - "${SECURITY_CONFIG_PATH}" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert json.load(source)["ssh"]["public_port"] == 63333
PYTHON
)
echo "通过：SSH 监听事务联动临时与永久防火墙规则，并能完整恢复元数据。"

# SSH 认证加固必须只允许公钥，并能独立恢复原认证文件。
install -d "$(dirname -- "${ROOT_AUTHORIZED_KEYS_PATH}")"
printf 'ssh-ed25519 test-key\n' > "${ROOT_AUTHORIZED_KEYS_PATH}"
[[ "$(root_authorized_key_count)" == "1" ]]
write_ssh_auth_dropin
grep -Fxq 'PubkeyAuthentication yes' "${SSH_AUTH_DROPIN_PATH}"
grep -Fxq 'PasswordAuthentication no' "${SSH_AUTH_DROPIN_PATH}"
grep -Fxq 'KbdInteractiveAuthentication no' "${SSH_AUTH_DROPIN_PATH}"
grep -Fxq 'PermitRootLogin prohibit-password' "${SSH_AUTH_DROPIN_PATH}"
grep -Fxq 'AuthenticationMethods publickey' "${SSH_AUTH_DROPIN_PATH}"
grep -Fxq 'MaxAuthTries 3' "${SSH_AUTH_DROPIN_PATH}"

fake_sshd="${test_dir}/sshd"
cat > "${fake_sshd}" <<'BASH'
#!/usr/bin/env bash
if [[ "${1:-}" == "-T" ]]; then
  cat <<'EOF'
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin prohibit-password
authenticationmethods publickey
maxauthtries 3
EOF
  exit 0
fi
exit 0
BASH
chmod +x "${fake_sshd}"
SSHD_BIN="${fake_sshd}"
ssh_auth_is_hardened

printf 'PasswordAuthentication yes\n' > "${SSH_AUTH_DROPIN_PATH}"
create_ssh_auth_transaction
printf 'PasswordAuthentication no\n' > "${SSH_AUTH_DROPIN_PATH}"
restore_ssh_auth_transaction_backup
grep -Fxq 'PasswordAuthentication yes' "${SSH_AUTH_DROPIN_PATH}"
rm -f -- "${SSH_AUTH_TRANSACTION_PATH}"

echo "通过：SSH 认证加固只启用公钥，并使用独立事务回滚。"

# SSH 客户端公钥支持脱敏列表、暂存添加、改名和删除，并保护最后一把密钥。
SSH_KEY_PENDING_DIR="${test_dir}/ssh-key-pending"
first_private="${test_dir}/client-first"
second_private="${test_dir}/client-second"
ssh-keygen -q -t ed25519 -N '' -C 'client-first' -f "${first_private}"
ssh-keygen -q -t ed25519 -N '' -C 'client-second' -f "${second_private}"
cp "${first_private}.pub" "${ROOT_AUTHORIZED_KEYS_PATH}"
list_json="$(manage_root_ssh_key list --json)"
first_id="$(LIST_JSON="${list_json}" python3 -c 'import json,os; print(json.loads(os.environ["LIST_JSON"])["items"][0]["key_id"])')"
preview_json="$(PUBLIC_KEY="$(<"${second_private}.pub")" python3 -c 'import json,os; print(json.dumps({"public_key": os.environ["PUBLIC_KEY"]}, ensure_ascii=False))' | manage_root_ssh_key preview --json)"
pending_token="$(PREVIEW_JSON="${preview_json}" python3 -c 'import json,os; print(json.loads(os.environ["PREVIEW_JSON"])["pending_token"])')"
manage_root_ssh_key add "${pending_token}" --yes --json >/dev/null
[[ "$(manage_root_ssh_key list --json)" == *'"deletable":true'* ]]
printf '{"name":"renamed-client"}\n' | manage_root_ssh_key rename "${first_id}" --yes --json >/dev/null
grep -Fq 'renamed-client' "${ROOT_AUTHORIZED_KEYS_PATH}"
second_id="$(manage_root_ssh_key list --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["items"][1]["key_id"])')"
manage_root_ssh_key delete "${second_id}" --yes --json >/dev/null
if manage_root_ssh_key delete "${first_id}" --yes --json >/dev/null 2>&1; then
  echo "失败：最后一把有效 root SSH 公钥可以被删除。"
  exit 1
fi
echo "通过：SSH 客户端公钥支持列表、添加、改名和删除，最后一把有效公钥受保护。"

grep -Fq 'if address in {"0.0.0.0", "::", "*"}' "${TEST_SCRIPT_DIR}/../lib/server_kit_port_facts.py" || {
  echo "失败：端口清单没有把通配监听归类为公网。"
  exit 1
}

# Mosh 是按需启动的 AWG 内网服务；未监听时不应被端口审计视为异常。
eval "${ORIGINAL_REFRESH_PORTS}"
port_test_dir="${test_dir}/mosh-port-registry"
install -d "${port_test_dir}/server-kit"
SERVER_KIT_DIR="${port_test_dir}/server-kit"
PORTS_PATH="${SERVER_KIT_DIR}/ports.json"
SECURITY_CONFIG_PATH="${SERVER_KIT_DIR}/security.json"
AWG_STATE_PATH="${port_test_dir}/awg.conf"
MOSH_STATE_PATH="${SERVER_KIT_DIR}/mosh.conf"
MANAGEMENT_STATE_PATH="${SERVER_KIT_DIR}/management.conf"
SS_BIN="${port_test_dir}/ss"
SYSTEMCTL_BIN="${port_test_dir}/systemctl"
SYSTEMCTL_CALL_LOG="${port_test_dir}/systemctl.log"
export SYSTEMCTL_CALL_LOG
cat > "${AWG_STATE_PATH}" <<'EOF'
AWG_IFACE=awg0
AWG_SERVER_IP=10.20.0.1
AWG_SUBNET_CIDR=10.20.0.0/24
EOF
cat > "${MOSH_STATE_PATH}" <<'EOF'
MOSH_ENABLED=yes
MOSH_PORT=60001
MOSH_PORT_START=60001
MOSH_PORT_END=60010
MOSH_BIND_IP=10.20.0.1
MOSH_INTERFACE=awg0
MOSH_SUBNET_CIDR=10.20.0.0/24
EOF
cat > "${MANAGEMENT_STATE_PATH}" <<'EOF'
MANAGEMENT_ENABLED=yes
MANAGEMENT_AWG_IP=10.20.0.1
MANAGEMENT_PORT=9080
EOF
cat > "${SS_BIN}" <<'BASH'
#!/usr/bin/env bash
exit 0
BASH
if [[ -n "${MSYSTEM:-}" ]]; then
  # Windows Python 不能直接执行无扩展名的 Bash 测试替身，改用 cmd 保持真实的批量子进程边界。
  SYSTEMCTL_BIN="${port_test_dir}/systemctl.cmd"
  SYSTEMCTL_CALL_LOG_NATIVE="$(cygpath -w "${SYSTEMCTL_CALL_LOG}")"
  export SYSTEMCTL_CALL_LOG_NATIVE
  cat > "${SYSTEMCTL_BIN}" <<'CMD'
@echo off
>>"%SYSTEMCTL_CALL_LOG_NATIVE%" echo %*
echo Id=server-kit-web.service
echo LoadState=loaded
echo ActiveState=inactive
echo UnitFileState=disabled
echo.
exit /b 0
CMD
else
  cat > "${SYSTEMCTL_BIN}" <<'BASH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SYSTEMCTL_CALL_LOG}"
case "${1:-}" in
  show)
    shift
    for argument in "$@"; do
      case "${argument}" in
        *.service|*.timer)
          printf 'Id=%s\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n\n' "${argument}"
          ;;
      esac
    done
    ;;
  is-active|is-enabled) exit 0 ;;
  *) exit 1 ;;
esac
BASH
fi
chmod +x "${SS_BIN}" "${SYSTEMCTL_BIN}"

refresh_ports --quiet
[[ "$(wc -l < "${SYSTEMCTL_CALL_LOG}")" == "1" ]] || {
  echo "失败：端口清单仍在逐个查询 systemd 单元。"
  exit 1
}
grep -q '^show ' "${SYSTEMCTL_CALL_LOG}" || {
  echo "失败：端口清单没有批量查询 systemd 单元。"
  exit 1
}
python3 - "${PORTS_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    listeners = json.load(source)["listeners"]
mosh_listeners = [item for item in listeners if item["service"] == "server-kit-mosh"]
assert [item["port"] for item in mosh_listeners] == list(range(60001, 60011))
assert mosh_listeners[0]["id"] == "mosh-awg"
assert mosh_listeners[-1]["id"] == "mosh-awg-60010"
mosh = mosh_listeners[0]
management = next(item for item in listeners if item["id"] == "management-web")
assert mosh["service"] == "server-kit-mosh"
assert mosh["protocol"] == "udp"
assert mosh["port"] == 60001
assert mosh["bind_addresses"] == ["10.20.0.1"]
assert mosh["exposure"] == "amneziawg"
assert mosh["enabled"] is True
assert mosh["service_active"] is True
assert mosh["listening"] is False
assert mosh["on_demand"] is True
assert management["service"] == "server-kit-web.service"
assert management["protocol"] == "tcp"
assert management["port"] == 9080
assert management["bind_addresses"] == ["10.20.0.1"]
assert management["exposure"] == "amneziawg"
PYTHON
audit_ports >/dev/null

echo "通过：Mosh 端口登记为 AWG 按需服务，未启动会话时不会产生审计误报。"
echo "通过：管理网站端口登记为 AWG 内网服务，不会归类为公网入口。"
