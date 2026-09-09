#!/usr/bin/env bash

set -euo pipefail

SERVER_KIT_DIR="${SERVER_KIT_DIR:-/etc/server-kit}"
PORTS_PATH="${PORTS_PATH:-${SERVER_KIT_DIR}/ports.json}"
SECURITY_CONFIG_PATH="${SECURITY_CONFIG_PATH:-${SERVER_KIT_DIR}/security.json}"
SSH_TRANSACTION_PATH="${SSH_TRANSACTION_PATH:-${SERVER_KIT_DIR}/ssh-transaction.json}"
SSH_BACKUP_DIR="${SSH_BACKUP_DIR:-${SERVER_KIT_DIR}/backups/ssh}"
SSH_DROPIN_PATH="${SSH_DROPIN_PATH:-/etc/ssh/sshd_config.d/20-server-kit-listen.conf}"
SSH_ORDERING_PATH="${SSH_ORDERING_PATH:-/etc/systemd/system/ssh.service.d/20-server-kit-ordering.conf}"
SSH_AUTH_TRANSACTION_PATH="${SSH_AUTH_TRANSACTION_PATH:-${SERVER_KIT_DIR}/ssh-auth-transaction.json}"
SSH_AUTH_BACKUP_DIR="${SSH_AUTH_BACKUP_DIR:-${SERVER_KIT_DIR}/backups/ssh-auth}"
SSH_AUTH_DROPIN_PATH="${SSH_AUTH_DROPIN_PATH:-/etc/ssh/sshd_config.d/30-server-kit-auth.conf}"
ROOT_AUTHORIZED_KEYS_PATH="${ROOT_AUTHORIZED_KEYS_PATH:-/root/.ssh/authorized_keys}"
SSH_KEY_PENDING_DIR="${SSH_KEY_PENDING_DIR:-/run/server-kit/ssh-key-pending}"
SSH_SERVICE="${SSH_SERVICE:-ssh.service}"
SSH_PUBLIC_PORT_DEFAULT="${SSH_PUBLIC_PORT_DEFAULT:-62222}"
AWG_INTERFACE="${AWG_INTERFACE:-awg0}"
AWG_STATE_PATH="${AWG_STATE_PATH:-/etc/amneziawg/manager.conf}"
MOSH_STATE_PATH="${MOSH_STATE_PATH:-${SERVER_KIT_DIR}/mosh.conf}"
MANAGEMENT_STATE_PATH="${MANAGEMENT_STATE_PATH:-${SERVER_KIT_DIR}/management.conf}"
ROLLBACK_SECONDS="${ROLLBACK_SECONDS:-300}"
ROLLBACK_UNIT="server-kit-ssh-rollback"
SSH_AUTH_ROLLBACK_UNIT="server-kit-ssh-auth-rollback"
SS_BIN="${SS_BIN:-/usr/bin/ss}"
SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-/usr/bin/systemctl}"

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_PATH}" ]]; do
  SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
  SCRIPT_PATH="$(readlink -- "${SCRIPT_PATH}")"
  [[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="${SCRIPT_LINK_DIR}/${SCRIPT_PATH}"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename -- "${SCRIPT_PATH}")"
SSH_KEYS_HELPER="${SSH_KEYS_HELPER:-${SCRIPT_DIR}/lib/server_kit_ssh_keys.py}"
PORT_FACTS_HELPER="${PORT_FACTS_HELPER:-${SCRIPT_DIR}/lib/server_kit_port_facts.py}"
FIREWALL_MANAGER="${FIREWALL_MANAGER:-${SCRIPT_DIR}/debian_firewall_manager.sh}"
FIREWALL_TRANSACTION_PATH="${FIREWALL_TRANSACTION_PATH:-${SERVER_KIT_DIR}/firewall-transaction.json}"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "请使用 root 运行此脚本。" >&2
    exit 1
  fi
}

check_debian() {
  if [[ ! -r /etc/os-release ]]; then
    echo "无法识别当前系统。" >&2
    exit 1
  fi
  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" != "debian" ]] && [[ "${ID_LIKE:-}" != *"debian"* ]]; then
    echo "此脚本仅支持 Debian 或 Debian 系发行版。" >&2
    exit 1
  fi
}

validate_ipv4() {
  python3 - "$1" <<'PYTHON'
import ipaddress
import sys

try:
    value = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if value.version == 4 else 1)
PYTHON
}

validate_port() {
  local port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] && (( 10#${port} >= 1 && 10#${port} <= 65535 ))
}

read_shell_value() {
  local path="$1"
  local key="$2"
  python3 - "${path}" "${key}" <<'PYTHON'
import shlex
import sys

path, wanted = sys.argv[1:]
try:
    lines = open(path, encoding="utf-8").readlines()
except OSError:
    raise SystemExit(1)
for raw_line in lines:
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    if key != wanted:
        continue
    try:
        parts = shlex.split(value, posix=True)
    except ValueError:
        raise SystemExit(1)
    if len(parts) == 1:
        print(parts[0])
        raise SystemExit(0)
raise SystemExit(1)
PYTHON
}

detect_public_ipv4() {
  ip -4 route get 1.1.1.1 2>/dev/null |
    sed -n 's/.*[[:space:]]src[[:space:]]\([^[:space:]]*\).*/\1/p' | head -n 1
}

detect_amneziawg_ipv4() {
  local address=""
  address="$(read_shell_value "${AWG_STATE_PATH}" AWG_SERVER_IP 2>/dev/null || true)"
  if [[ -z "${address}" ]]; then
    address="$(ip -o -4 address show dev "${AWG_INTERFACE}" 2>/dev/null |
      awk '{print $4}' | cut -d/ -f1 | head -n 1)"
  fi
  printf '%s\n' "${address}"
}

address_is_local() {
  ip -o -4 address show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq -- "$1"
}

listener_line() {
  local address="$1"
  local port="$2"
  "${SS_BIN}" -H -lntp 2>/dev/null |
    awk -v endpoint="${address}:${port}" '$4 == endpoint {print; exit}'
}

listener_exists() {
  [[ -n "$(listener_line "$1" "$2")" ]]
}

listener_is_sshd() {
  local line=""
  line="$(listener_line "$1" "$2")"
  [[ "${line}" == *'"sshd"'* ]]
}

listener_line_by_port() {
  local port="$1"
  "${SS_BIN}" -H -lntp 2>/dev/null |
    awk -v suffix=":${port}" '$4 ~ (suffix "$") {print; exit}'
}

write_ssh_auth_dropin() {
  local temp_path=""

  install -d -m 755 "$(dirname -- "${SSH_AUTH_DROPIN_PATH}")"
  temp_path="$(mktemp "$(dirname -- "${SSH_AUTH_DROPIN_PATH}")/.30-server-kit-auth.XXXXXX")"
  printf '%s\n' \
    '# 此文件由 debian_security_manager.sh 管理，请勿直接修改。' \
    'PubkeyAuthentication yes' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'PermitRootLogin prohibit-password' \
    'AuthenticationMethods publickey' \
    'MaxAuthTries 3' > "${temp_path}"
  install -m 600 -o root -g root "${temp_path}" "${SSH_AUTH_DROPIN_PATH}"
  rm -f -- "${temp_path}"
}

root_authorized_key_count() {
  [[ -r "${ROOT_AUTHORIZED_KEYS_PATH}" ]] || { echo 0; return 0; }
  awk 'NF && $1 !~ /^#/ { count++ } END { print count + 0 }' \
    "${ROOT_AUTHORIZED_KEYS_PATH}"
}

ssh_auth_is_hardened() {
  local effective=""
  effective="$("${SSHD_BIN}" -T 2>/dev/null)" || return 1
  grep -Fxq 'pubkeyauthentication yes' <<< "${effective}" &&
    grep -Fxq 'passwordauthentication no' <<< "${effective}" &&
    grep -Fxq 'kbdinteractiveauthentication no' <<< "${effective}" &&
    grep -Eq '^permitrootlogin (prohibit-password|without-password)$' <<< "${effective}" &&
    grep -Fxq 'authenticationmethods publickey' <<< "${effective}" &&
    grep -Fxq 'maxauthtries 3' <<< "${effective}"
}

write_ssh_dropin() {
  local mode="$1"
  local public_ip="$2"
  local public_port="$3"
  local amneziawg_ip="$4"
  local temp_path=""

  install -d -m 755 "$(dirname -- "${SSH_DROPIN_PATH}")"
  temp_path="$(mktemp "$(dirname -- "${SSH_DROPIN_PATH}")/.20-server-kit-listen.XXXXXX")"
  if [[ "${mode}" == "staged" ]]; then
    printf '%s\n' \
      '# 此文件由 debian_security_manager.sh 管理，请勿直接修改。' \
      'AddressFamily inet' \
      'ListenAddress 0.0.0.0:22' \
      "ListenAddress 0.0.0.0:${public_port}" > "${temp_path}"
  else
    printf '%s\n' \
      '# 此文件由 debian_security_manager.sh 管理，请勿直接修改。' \
      'AddressFamily inet' \
      "ListenAddress ${amneziawg_ip}:22" \
      "ListenAddress 0.0.0.0:${public_port}" > "${temp_path}"
  fi
  chmod 600 "${temp_path}"
  chown root:root "${temp_path}"
  mv -f -- "${temp_path}" "${SSH_DROPIN_PATH}"
}

write_ssh_ordering_dropin() {
  local temp_path=""
  install -d -m 755 "$(dirname -- "${SSH_ORDERING_PATH}")"
  temp_path="$(mktemp "$(dirname -- "${SSH_ORDERING_PATH}")/.20-server-kit-ordering.XXXXXX")"
  {
    echo '# 此文件由 debian_security_manager.sh 管理，确保隧道地址先于 SSH 监听出现。'
    echo '[Unit]'
    echo "Wants=awg-quick@${AWG_INTERFACE}.service"
    echo "After=network-online.target awg-quick@${AWG_INTERFACE}.service"
  } > "${temp_path}"
  install -m 644 -o root -g root "${temp_path}" "${SSH_ORDERING_PATH}"
  rm -f -- "${temp_path}"
  "${SYSTEMCTL_BIN}" daemon-reload
}

write_security_config() {
  local status="$1"
  local public_ip="$2"
  local public_port="$3"
  local amneziawg_ip="$4"
  local temp_path=""

  install -d -m 700 "${SERVER_KIT_DIR}"
  temp_path="$(mktemp "${SERVER_KIT_DIR}/.security.XXXXXX")"
  python3 - "${temp_path}" "${status}" "${public_ip}" "${public_port}" \
    "${amneziawg_ip}" "${SSH_DROPIN_PATH}" <<'PYTHON'
import json
import os
import sys

path, status, public_ip, public_port, amneziawg_ip, dropin = sys.argv[1:]
config = {
    "schema_version": 2,
    "ssh": {
        "status": status,
        "address_family": "inet",
        "amneziawg_address": amneziawg_ip,
        "amneziawg_port": 22,
        "public_address": public_ip,
        "public_bind_address": "0.0.0.0",
        "public_port": int(public_port),
        "public_source": "0.0.0.0/0",
        "config_path": dropin,
    },
}
with open(path, "w", encoding="utf-8", newline="\n") as output:
    json.dump(config, output, ensure_ascii=False, indent=2)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PYTHON
  install -m 600 -o root -g root "${temp_path}" "${SECURITY_CONFIG_PATH}"
  rm -f -- "${temp_path}"
}

read_transaction_field() {
  local field="$1"
  python3 - "${SSH_TRANSACTION_PATH}" "${field}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
result = value.get(sys.argv[2], "")
if isinstance(result, bool):
    print("true" if result else "false")
else:
    print(result)
PYTHON
}

create_transaction() {
  local public_ip="$1"
  local public_port="$2"
  local amneziawg_ip="$3"
  local backup_path=""
  local security_backup_path=""
  local existed="false"
  local security_existed="false"
  local timestamp=""
  local temp_path=""

  install -d -m 700 "${SERVER_KIT_DIR}" "${SSH_BACKUP_DIR}"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if [[ -f "${SSH_DROPIN_PATH}" ]]; then
    existed="true"
    backup_path="${SSH_BACKUP_DIR}/20-server-kit-listen.conf.${timestamp}"
    install -m 600 -o root -g root "${SSH_DROPIN_PATH}" "${backup_path}"
  fi
  if [[ -f "${SECURITY_CONFIG_PATH}" ]]; then
    security_existed="true"
    security_backup_path="${SSH_BACKUP_DIR}/security.json.${timestamp}"
    install -m 600 -o root -g root "${SECURITY_CONFIG_PATH}" "${security_backup_path}"
  fi
  temp_path="$(mktemp "${SERVER_KIT_DIR}/.ssh-transaction.XXXXXX")"
  python3 - "${temp_path}" "${public_ip}" "${public_port}" "${amneziawg_ip}" \
    "${existed}" "${backup_path}" "${security_existed}" "${security_backup_path}" <<'PYTHON'
import json
import os
import sys
from datetime import datetime, timezone

path, public_ip, public_port, amneziawg_ip, existed, backup_path, security_existed, security_backup_path = sys.argv[1:]
value = {
    "status": "staged",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "public_ip": public_ip,
    "public_port": int(public_port),
    "amneziawg_ip": amneziawg_ip,
    "dropin_existed": existed == "true",
    "backup_path": backup_path,
    "security_config_existed": security_existed == "true",
    "security_backup_path": security_backup_path,
}
with open(path, "w", encoding="utf-8", newline="\n") as output:
    json.dump(value, output, ensure_ascii=False, indent=2)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PYTHON
  install -m 600 -o root -g root "${temp_path}" "${SSH_TRANSACTION_PATH}"
  rm -f -- "${temp_path}"
}

restore_transaction_backup() {
  local existed=""
  local backup_path=""
  local security_existed=""
  local security_backup_path=""
  existed="$(read_transaction_field dropin_existed)"
  backup_path="$(read_transaction_field backup_path)"
  security_existed="$(read_transaction_field security_config_existed)"
  security_backup_path="$(read_transaction_field security_backup_path)"
  if [[ "${existed}" == "true" ]]; then
    if [[ -z "${backup_path}" || ! -f "${backup_path}" ]]; then
      echo "SSH 回滚备份不存在：${backup_path}" >&2
      return 1
    fi
    install -m 600 -o root -g root "${backup_path}" "${SSH_DROPIN_PATH}"
  else
    rm -f -- "${SSH_DROPIN_PATH}"
  fi
  if [[ "${security_existed}" == "true" ]]; then
    if [[ -z "${security_backup_path}" || ! -f "${security_backup_path}" ]]; then
      echo "SSH 安全元数据回滚备份不存在：${security_backup_path}" >&2
      return 1
    fi
    install -m 600 -o root -g root "${security_backup_path}" "${SECURITY_CONFIG_PATH}"
  else
    rm -f -- "${SECURITY_CONFIG_PATH}"
  fi
}

create_ssh_auth_transaction() {
  local backup_path=""
  local existed="false"
  local timestamp=""
  local temp_path=""

  install -d -m 700 "${SERVER_KIT_DIR}" "${SSH_AUTH_BACKUP_DIR}"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if [[ -f "${SSH_AUTH_DROPIN_PATH}" ]]; then
    existed="true"
    backup_path="${SSH_AUTH_BACKUP_DIR}/30-server-kit-auth.conf.${timestamp}"
    install -m 600 -o root -g root "${SSH_AUTH_DROPIN_PATH}" "${backup_path}"
  fi
  temp_path="$(mktemp "${SERVER_KIT_DIR}/.ssh-auth-transaction.XXXXXX")"
  python3 - "${temp_path}" "${existed}" "${backup_path}" <<'PYTHON'
import json
import os
import sys
from datetime import datetime, timezone

path, existed, backup_path = sys.argv[1:]
value = {
    "status": "staged",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "dropin_existed": existed == "true",
    "backup_path": backup_path,
}
with open(path, "w", encoding="utf-8", newline="\n") as output:
    json.dump(value, output, ensure_ascii=False, indent=2)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PYTHON
  install -m 600 -o root -g root "${temp_path}" "${SSH_AUTH_TRANSACTION_PATH}"
  rm -f -- "${temp_path}"
}

read_ssh_auth_transaction_field() {
  local field="$1"
  python3 - "${SSH_AUTH_TRANSACTION_PATH}" "${field}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source).get(sys.argv[2], "")
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PYTHON
}

restore_ssh_auth_transaction_backup() {
  local existed=""
  local backup_path=""
  existed="$(read_ssh_auth_transaction_field dropin_existed)"
  backup_path="$(read_ssh_auth_transaction_field backup_path)"
  if [[ "${existed}" == "true" ]]; then
    if [[ -z "${backup_path}" || ! -f "${backup_path}" ]]; then
      echo "SSH 认证回滚备份不存在：${backup_path}" >&2
      return 1
    fi
    install -m 600 -o root -g root "${backup_path}" "${SSH_AUTH_DROPIN_PATH}"
  else
    rm -f -- "${SSH_AUTH_DROPIN_PATH}"
  fi
}

validate_and_reload_ssh() {
  "${SSHD_BIN}" -t
  "${SYSTEMCTL_BIN}" reload "${SSH_SERVICE}"
  "${SYSTEMCTL_BIN}" is-active --quiet "${SSH_SERVICE}"
}

cancel_rollback() {
  "${SYSTEMCTL_BIN}" stop "${ROLLBACK_UNIT}.timer" "${ROLLBACK_UNIT}.service" \
    >/dev/null 2>&1 || true
  "${SYSTEMCTL_BIN}" reset-failed "${ROLLBACK_UNIT}.service" >/dev/null 2>&1 || true
}

schedule_rollback() {
  cancel_rollback
  systemd-run --quiet --unit="${ROLLBACK_UNIT}" --on-active="${ROLLBACK_SECONDS}s" \
    --timer-property=AccuracySec=1s "${SCRIPT_PATH}" rollback-ssh --automatic
}

cancel_ssh_auth_rollback() {
  "${SYSTEMCTL_BIN}" stop "${SSH_AUTH_ROLLBACK_UNIT}.timer" \
    "${SSH_AUTH_ROLLBACK_UNIT}.service" >/dev/null 2>&1 || true
  "${SYSTEMCTL_BIN}" reset-failed "${SSH_AUTH_ROLLBACK_UNIT}.service" \
    >/dev/null 2>&1 || true
}

schedule_ssh_auth_rollback() {
  cancel_ssh_auth_rollback
  systemd-run --quiet --unit="${SSH_AUTH_ROLLBACK_UNIT}" \
    --on-active="${ROLLBACK_SECONDS}s" --timer-property=AccuracySec=1s \
    "${SCRIPT_PATH}" rollback-ssh-auth --automatic
}

rollback_ssh_auth() {
  local automatic="${1:-}"
  if [[ ! -r "${SSH_AUTH_TRANSACTION_PATH}" ]]; then
    [[ "${automatic}" == "--automatic" ]] || echo "当前没有待回滚的 SSH 认证加固。"
    return 0
  fi
  restore_ssh_auth_transaction_backup
  validate_and_reload_ssh
  rm -f -- "${SSH_AUTH_TRANSACTION_PATH}"
  cancel_ssh_auth_rollback
  if [[ "${automatic}" == "--automatic" ]]; then
    echo "SSH 认证加固未在时限内确认，已自动恢复原配置。"
  else
    echo "SSH 认证配置已回滚。"
  fi
}

rollback_ssh() {
  local automatic="${1:-}"
  local public_port=""
  if [[ ! -r "${SSH_TRANSACTION_PATH}" ]]; then
    [[ "${automatic}" == "--automatic" ]] || echo "当前没有待回滚的 SSH 切换。"
    return 0
  fi
  public_port="$(read_transaction_field public_port)"
  if [[ -r "${FIREWALL_TRANSACTION_PATH}" ]]; then
    bash "${FIREWALL_MANAGER}" rollback >/dev/null 2>&1 || {
      echo "防火墙事务回滚失败，拒绝继续切换 SSH。" >&2
      return 1
    }
  fi
  bash "${FIREWALL_MANAGER}" close-transaction-temporary \
    "${public_port}" --yes >/dev/null 2>&1 || true
  restore_transaction_backup
  validate_and_reload_ssh
  rm -f -- "${SSH_TRANSACTION_PATH}"
  cancel_rollback
  refresh_ports --quiet || true
  if [[ "${automatic}" == "--automatic" ]]; then
    echo "SSH 新端口未在时限内确认，已自动恢复原配置。"
  else
    echo "SSH 配置已回滚。"
  fi
}

read_security_ssh_field() {
  local field="$1"
  python3 - "${SECURITY_CONFIG_PATH}" "${field}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source).get("ssh", {}).get(sys.argv[2], ""))
PYTHON
}

ssh_plan() {
  local public_ip="${1:-}"
  local public_port="${2:-${SSH_PUBLIC_PORT_DEFAULT}}"
  local amneziawg_ip=""

  public_ip="${public_ip:-$(detect_public_ipv4)}"
  amneziawg_ip="$(detect_amneziawg_ipv4)"
  echo "=== SSH 监听切换计划 ==="
  echo "AmneziaWG：${amneziawg_ip:-<尚未安装>}:22"
  echo "公网：${public_ip:-<未检测到>}:${public_port}"
  echo "地址族：仅 IPv4"
  echo "配置文件：${SSH_DROPIN_PATH}"
  echo "自动回滚：${ROLLBACK_SECONDS} 秒"
  echo
  echo "第一阶段会暂时保留公网 22；只有运行 confirm-ssh 后才会关闭公网 22。"
}

ssh_auth_plan() {
  echo "=== SSH 认证加固计划 ==="
  echo "root 公钥数量：$(root_authorized_key_count)"
  echo "认证配置：${SSH_AUTH_DROPIN_PATH}"
  echo "PasswordAuthentication：no"
  echo "KbdInteractiveAuthentication：no"
  echo "PermitRootLogin：prohibit-password"
  echo "AuthenticationMethods：publickey"
  echo "MaxAuthTries：3"
  echo "自动回滚：${ROLLBACK_SECONDS} 秒"
  echo
  echo "监听地址与端口不会改变。应用后必须立即新建公网和 AWG SSH 连接。"
}

harden_ssh_auth() {
  local key_count=""

  if [[ -r "${SSH_AUTH_TRANSACTION_PATH}" ]]; then
    echo "已有待确认的 SSH 认证加固，请先确认或回滚。" >&2
    return 1
  fi
  key_count="$(root_authorized_key_count)"
  if [[ ! "${key_count}" =~ ^[0-9]+$ ]] || (( key_count < 1 )); then
    echo "root 没有可用的 authorized_keys，拒绝关闭密码认证。" >&2
    return 1
  fi
  if ! "${SYSTEMCTL_BIN}" is-active --quiet "${SSH_SERVICE}"; then
    echo "${SSH_SERVICE} 当前未运行，拒绝修改认证配置。" >&2
    return 1
  fi

  create_ssh_auth_transaction
  write_ssh_auth_dropin
  if ! "${SSHD_BIN}" -t; then
    restore_ssh_auth_transaction_backup
    rm -f -- "${SSH_AUTH_TRANSACTION_PATH}"
    echo "SSH 认证配置校验失败，已恢复原文件。" >&2
    return 1
  fi
  if ! schedule_ssh_auth_rollback; then
    restore_ssh_auth_transaction_backup
    rm -f -- "${SSH_AUTH_TRANSACTION_PATH}"
    echo "无法设置自动回滚，未重新加载 SSH。" >&2
    return 1
  fi
  if ! validate_and_reload_ssh || ! ssh_auth_is_hardened; then
    rollback_ssh_auth
    echo "SSH 认证加固未能生效，已回滚。" >&2
    return 1
  fi

  echo "SSH 已进入仅密钥认证的待确认阶段。"
  echo "监听地址和端口保持不变。"
  echo "请立即从独立终端验证："
  echo "  公网：ssh -p $(read_security_ssh_field public_port) root@$(read_security_ssh_field public_address)"
  echo "  AWG：ssh root@$(read_security_ssh_field amneziawg_address)"
  echo
  echo "两条新连接都成功后运行："
  echo "  bash ${SCRIPT_PATH} confirm-ssh-auth --yes"
  echo "若 ${ROLLBACK_SECONDS} 秒内未确认，将自动恢复密码认证配置。"
}

confirm_ssh_auth() {
  local confirm="${1:-}"
  if [[ ! -r "${SSH_AUTH_TRANSACTION_PATH}" ]]; then
    echo "没有处于待确认状态的 SSH 认证加固，可能已经自动回滚。" >&2
    return 1
  fi
  if [[ "${confirm}" != "--yes" ]]; then
    echo "请先验证公网和 AWG 两条新 SSH 连接，再加 --yes。" >&2
    return 1
  fi
  if ! ssh_auth_is_hardened; then
    rollback_ssh_auth
    echo "SSH 有效认证参数不符合预期，已回滚。" >&2
    return 1
  fi
  rm -f -- "${SSH_AUTH_TRANSACTION_PATH}"
  cancel_ssh_auth_rollback
  echo "SSH 认证加固已确认：root 仅允许使用公钥登录。"
}

install_ssh() {
  local public_ip="${1:-}"
  local public_port="${2:-}"
  local amneziawg_ip=""
  local value=""

  if [[ -r "${SSH_TRANSACTION_PATH}" ]]; then
    echo "已有待确认的 SSH 切换，请先运行 confirm-ssh 或 rollback-ssh。" >&2
    return 1
  fi
  if [[ -r "${FIREWALL_TRANSACTION_PATH}" ]]; then
    echo "已有待确认的防火墙事务，请先确认或回滚。" >&2
    return 1
  fi
  public_ip="${public_ip:-$(detect_public_ipv4)}"
  amneziawg_ip="$(detect_amneziawg_ipv4)"
  if [[ -z "${public_port}" ]]; then
    read -r -p "公网 SSH 高位端口 [${SSH_PUBLIC_PORT_DEFAULT}]: " value
    public_port="${value:-${SSH_PUBLIC_PORT_DEFAULT}}"
  fi
  if ! validate_ipv4 "${public_ip}" || ! address_is_local "${public_ip}"; then
    echo "公网 IPv4 无效或不属于本机：${public_ip}" >&2
    return 1
  fi
  if ! validate_ipv4 "${amneziawg_ip}" || ! address_is_local "${amneziawg_ip}"; then
    echo "未检测到本机 AmneziaWG IPv4：${amneziawg_ip:-<空>}" >&2
    return 1
  fi
  if ! validate_port "${public_port}" || (( 10#${public_port} < 1024 )); then
    echo "公网 SSH 端口必须是 1024–65535：${public_port}" >&2
    return 1
  fi
  if (( 10#${public_port} >= 32768 && 10#${public_port} <= 60999 )); then
    echo "端口 ${public_port} 位于本机临时端口范围 32768–60999，请选择其他高位端口。" >&2
    return 1
  fi
  local public_port_listener=""
  public_port_listener="$(listener_line_by_port "${public_port}")"
  if [[ -n "${public_port_listener}" && "${public_port_listener}" != *'"sshd"'* ]]; then
    echo "TCP ${public_port} 已被其他程序占用，无法改为通配 SSH 监听。" >&2
    return 1
  fi
  if ! "${SYSTEMCTL_BIN}" is-active --quiet "${SSH_SERVICE}"; then
    echo "${SSH_SERVICE} 当前未运行，拒绝修改监听配置。" >&2
    return 1
  fi

  create_transaction "${public_ip}" "${public_port}" "${amneziawg_ip}"
  if ! bash "${FIREWALL_MANAGER}" open-transaction-temporary \
    "${public_port}" "${ROLLBACK_SECONDS}" --yes >/dev/null; then
    restore_transaction_backup
    rm -f -- "${SSH_TRANSACTION_PATH}"
    echo "无法临时放行新公网 SSH 端口，未修改 SSH。" >&2
    return 1
  fi
  write_ssh_dropin staged "${public_ip}" "${public_port}" "${amneziawg_ip}"
  if ! "${SSHD_BIN}" -t; then
    bash "${FIREWALL_MANAGER}" close-transaction-temporary \
      "${public_port}" --yes >/dev/null 2>&1 || true
    restore_transaction_backup
    rm -f -- "${SSH_TRANSACTION_PATH}"
    echo "新 SSH 配置校验失败，已恢复原文件。" >&2
    return 1
  fi
  if ! schedule_rollback; then
    bash "${FIREWALL_MANAGER}" close-transaction-temporary \
      "${public_port}" --yes >/dev/null 2>&1 || true
    restore_transaction_backup
    rm -f -- "${SSH_TRANSACTION_PATH}"
    echo "无法设置自动回滚，未重新加载 SSH。" >&2
    return 1
  fi
  if ! validate_and_reload_ssh; then
    rollback_ssh
    echo "SSH 重新加载失败，已回滚。" >&2
    return 1
  fi
  sleep 1
  if ! listener_exists "0.0.0.0" 22 || ! listener_exists "0.0.0.0" "${public_port}"; then
    rollback_ssh
    echo "新监听未全部生效，已回滚。" >&2
    return 1
  fi
  write_security_config staged "${public_ip}" "${public_port}" "${amneziawg_ip}"
  refresh_ports --quiet || true

  echo
  echo "SSH 新端口已进入待确认阶段，公网 22 仍然保留。"
  echo "请立即在另一窗口执行："
  echo "  ssh -p ${public_port} root@${public_ip}"
  echo
  echo "验证成功后运行："
  echo "  bash ${SCRIPT_PATH} confirm-ssh --yes"
  echo "若 ${ROLLBACK_SECONDS} 秒内未确认，原 SSH 配置会自动恢复。"
}

confirm_ssh() {
  local confirm="${1:-}"
  local public_ip=""
  local public_port=""
  local amneziawg_ip=""

  if [[ ! -r "${SSH_TRANSACTION_PATH}" ]]; then
    echo "没有处于待确认状态的 SSH 切换，可能已经自动回滚。" >&2
    return 1
  fi
  if [[ "${confirm}" != "--yes" ]]; then
    echo "请先从独立终端验证新公网端口，再运行 confirm-ssh --yes。" >&2
    return 1
  fi
  public_ip="$(read_transaction_field public_ip)"
  public_port="$(read_transaction_field public_port)"
  amneziawg_ip="$(read_transaction_field amneziawg_ip)"

  write_ssh_dropin final "${public_ip}" "${public_port}" "${amneziawg_ip}"
  write_ssh_ordering_dropin
  if ! validate_and_reload_ssh; then
    rollback_ssh
    echo "最终 SSH 配置未能生效，已恢复原配置。" >&2
    return 1
  fi
  sleep 1
  if ! listener_exists "${amneziawg_ip}" 22 || \
      ! listener_exists "0.0.0.0" "${public_port}" || \
      { listener_exists "0.0.0.0" 22 || listener_exists "${public_ip}" 22; }; then
    rollback_ssh
    echo "最终监听检查失败，已恢复原配置。" >&2
    return 1
  fi
  write_security_config active "${public_ip}" "${public_port}" "${amneziawg_ip}"
  refresh_ports --quiet
  if ! bash "${FIREWALL_MANAGER}" apply --yes >/dev/null; then
    rollback_ssh
    echo "新 SSH 监听已恢复：防火墙候选规则未能安全应用。" >&2
    return 1
  fi
  if ! bash "${FIREWALL_MANAGER}" confirm --yes >/dev/null; then
    rollback_ssh
    echo "新 SSH 监听已恢复：防火墙规则未能确认。" >&2
    return 1
  fi
  bash "${FIREWALL_MANAGER}" close-transaction-temporary \
    "${public_port}" --yes >/dev/null 2>&1 || true
  rm -f -- "${SSH_TRANSACTION_PATH}"
  cancel_rollback

  echo "SSH 监听切换完成。"
  echo "AmneziaWG：${amneziawg_ip}:22"
  echo "公网：${public_ip}:${public_port}"
  echo "公网 ${public_ip}:22 已关闭。"
}

reconcile_ssh_security() {
  local public_ip=""
  local public_port=""
  local amneziawg_ip=""
  [[ ! -r "${SSH_TRANSACTION_PATH}" ]] || {
    echo "SSH 监听事务仍在进行，拒绝校准元数据。" >&2
    return 1
  }
  public_ip="$(detect_public_ipv4)"
  amneziawg_ip="$(detect_amneziawg_ipv4)"
  public_port="$(awk '
    $1 == "ListenAddress" && $2 ~ /^0\.0\.0\.0:[0-9]+$/ {
      split($2, parts, ":")
      if (parts[2] != "22") { print parts[2]; exit }
    }
  ' "${SSH_DROPIN_PATH}")"
  validate_ipv4 "${public_ip}" && address_is_local "${public_ip}" || {
    echo "无法校准：公网 IPv4 无效。" >&2
    return 1
  }
  validate_ipv4 "${amneziawg_ip}" && address_is_local "${amneziawg_ip}" || {
    echo "无法校准：AmneziaWG IPv4 无效。" >&2
    return 1
  }
  validate_port "${public_port}" || {
    echo "无法校准：SSH 公网高位监听不存在。" >&2
    return 1
  }
  listener_exists "0.0.0.0" "${public_port}" && listener_exists "${amneziawg_ip}" 22 || {
    echo "无法校准：当前 SSH 监听与预期不一致。" >&2
    return 1
  }
  write_security_config active "${public_ip}" "${public_port}" "${amneziawg_ip}"
  refresh_ports --quiet
  echo "SSH 安全元数据已按当前有效监听校准。"
}

repair_ssh_listeners() {
  local public_ip=""
  local public_port=""
  local amneziawg_ip=""

  [[ -r "${SECURITY_CONFIG_PATH}" ]] || {
    echo "尚未安装 server-kit SSH 安全配置。" >&2
    return 1
  }
  public_ip="$(read_security_ssh_field public_address)"
  public_port="$(read_security_ssh_field public_port)"
  amneziawg_ip="$(read_security_ssh_field amneziawg_address)"
  if ! validate_ipv4 "${amneziawg_ip}" || ! address_is_local "${amneziawg_ip}"; then
    echo "AmneziaWG 地址尚未就绪：${amneziawg_ip}" >&2
    return 1
  fi
  write_ssh_ordering_dropin
  validate_and_reload_ssh
  sleep 1
  listener_exists "0.0.0.0" "${public_port}" || {
    echo "公网 SSH 通配监听丢失：0.0.0.0:${public_port}" >&2
    return 1
  }
  if ! listener_exists "${amneziawg_ip}" 22; then
    echo "AmneziaWG SSH 监听仍未恢复：${amneziawg_ip}:22" >&2
    return 1
  fi
  refresh_ports --quiet
  echo "SSH 监听已修复，并已设置隧道服务优先启动。"
}

refresh_ports() {
  local quiet="${1:-}"
  local temp_path=""
  [[ -r "${PORT_FACTS_HELPER}" ]] || {
    echo "缺少端口事实组件：${PORT_FACTS_HELPER}" >&2
    return 1
  }
  install -d -m 700 "${SERVER_KIT_DIR}"
  temp_path="$(mktemp "${SERVER_KIT_DIR}/.ports.XXXXXX")"
  if ! python3 "${PORT_FACTS_HELPER}" collect \
    --output "${temp_path}" \
    --security "${SECURITY_CONFIG_PATH}" \
    --awg "${AWG_STATE_PATH}" \
    --mosh "${MOSH_STATE_PATH}" \
    --management "${MANAGEMENT_STATE_PATH}" \
    --ss "${SS_BIN}" \
    --systemctl "${SYSTEMCTL_BIN}"; then
    rm -f -- "${temp_path}"
    return 1
  fi
  install -m 600 -o root -g root "${temp_path}" "${PORTS_PATH}"
  rm -f -- "${temp_path}"
  if [[ "${quiet}" != "--quiet" ]]; then
    echo "端口清单已更新：${PORTS_PATH}"
  fi
}

show_ports() {
  refresh_ports --quiet
  python3 "${PORT_FACTS_HELPER}" project show --ports "${PORTS_PATH}"
}

audit_ports() {
  refresh_ports --quiet
  python3 "${PORT_FACTS_HELPER}" project audit --ports "${PORTS_PATH}"
}
manage_root_ssh_key() {
  local operation="$1"
  local token="${2:-}"
  local confirmation="${3:-}"
  local format="${4:-}"
  [[ -r "${SSH_KEYS_HELPER}" ]] || { echo "缺少 SSH 公钥管理组件。" >&2; return 1; }
  case "${operation}" in
    list)
      [[ "${token:-}" == "--json" ]] || { echo "SSH 公钥清单只支持 --json。" >&2; return 1; }
      python3 "${SSH_KEYS_HELPER}" list "${ROOT_AUTHORIZED_KEYS_PATH}" "${SSH_KEY_PENDING_DIR}"
      ;;
    preview)
      [[ "${token:-}" == "--json" ]] || { echo "SSH 公钥预览只支持 --json。" >&2; return 1; }
      python3 "${SSH_KEYS_HELPER}" preview "${ROOT_AUTHORIZED_KEYS_PATH}" "${SSH_KEY_PENDING_DIR}"
      ;;
    add)
      [[ "${confirmation}" == "--yes" && "${format}" == "--json" ]] || {
        echo "添加 SSH 公钥必须提供暂存标识、--yes 和 --json。" >&2
        return 1
      }
      python3 "${SSH_KEYS_HELPER}" add "${ROOT_AUTHORIZED_KEYS_PATH}" "${SSH_KEY_PENDING_DIR}" "${token}"
      ;;
    delete)
      [[ "${confirmation}" == "--yes" && "${format}" == "--json" ]] || {
        echo "删除 SSH 公钥必须提供公钥标识、--yes 和 --json。" >&2
        return 1
      }
      python3 "${SSH_KEYS_HELPER}" delete "${ROOT_AUTHORIZED_KEYS_PATH}" "${SSH_KEY_PENDING_DIR}" "${token}"
      ;;
    rename)
      [[ "${confirmation}" == "--yes" && "${format}" == "--json" ]] || {
        echo "修改 SSH 客户端名称必须提供公钥标识、--yes 和 --json。" >&2
        return 1
      }
      python3 "${SSH_KEYS_HELPER}" rename "${ROOT_AUTHORIZED_KEYS_PATH}" "${SSH_KEY_PENDING_DIR}" "${token}"
      ;;
    *) echo "SSH 公钥动作无效。" >&2; return 1 ;;
  esac
}

usage() {
  cat <<EOF
说明：安全管理器负责 SSH 监听切换和 server-kit 端口清单，并通过独立防火墙事务安全同步公网端口。

SSH：
  bash $0 ssh-plan [公网IP] [端口]        查看切换计划
  bash $0 install-ssh [公网IP] [端口]     开放新端口并启动 ${ROLLBACK_SECONDS} 秒回滚计时
  bash $0 confirm-ssh --yes              独立连接验证后关闭公网 22
  bash $0 rollback-ssh                   立即恢复切换前配置
  bash $0 repair-ssh-listeners           修复重启时隧道地址尚未就绪的问题
  bash $0 reconcile-ssh-security         按当前有效监听校准 SSH 安全元数据

SSH 认证：
  bash $0 ssh-auth-plan                  查看仅密钥登录计划
  bash $0 harden-ssh-auth                应用认证加固并启动自动回滚
  bash $0 confirm-ssh-auth --yes         验证两条新连接后确认
  bash $0 rollback-ssh-auth              立即恢复加固前配置

SSH 公钥：
  bash $0 list-root-keys --json          仅显示 root 公钥指纹与备注
  bash $0 preview-root-key --json        从标准输入校验并暂存一条公钥
  bash $0 add-root-key <标识> --yes --json
                                          确认后原子添加暂存公钥
  bash $0 delete-root-key <公钥标识> --yes --json
                                          删除公钥，最后一把有效公钥受保护
  bash $0 rename-root-key <公钥标识> --yes --json
                                          从标准输入读取并修改客户端名称

端口清单：
  bash $0 ports                          查看当前套件端口
  bash $0 refresh-ports                  重建 ${PORTS_PATH}
  bash $0 audit-ports                    检查监听漂移和未托管端口

重要：install-ssh 不会立即关闭公网 22。必须先从另一终端验证新端口，再确认收口。
EOF
}

main() {
  require_root
  check_debian
  case "${1:-}" in
    ssh-plan)
      ssh_plan "${2:-}" "${3:-${SSH_PUBLIC_PORT_DEFAULT}}"
      ;;
    install-ssh)
      install_ssh "${2:-}" "${3:-}"
      ;;
    confirm-ssh)
      confirm_ssh "${2:-}"
      ;;
    rollback-ssh)
      rollback_ssh "${2:-}"
      ;;
    repair-ssh-listeners)
      repair_ssh_listeners
      ;;
    reconcile-ssh-security)
      reconcile_ssh_security
      ;;
    ssh-auth-plan)
      ssh_auth_plan
      ;;
    harden-ssh-auth)
      harden_ssh_auth
      ;;
    confirm-ssh-auth)
      confirm_ssh_auth "${2:-}"
      ;;
    rollback-ssh-auth)
      rollback_ssh_auth "${2:-}"
      ;;
    list-root-keys)
      manage_root_ssh_key list "${2:-}"
      ;;
    preview-root-key)
      manage_root_ssh_key preview "${2:-}"
      ;;
    add-root-key)
      manage_root_ssh_key add "${2:-}" "${3:-}" "${4:-}"
      ;;
    delete-root-key)
      manage_root_ssh_key delete "${2:-}" "${3:-}" "${4:-}"
      ;;
    rename-root-key)
      manage_root_ssh_key rename "${2:-}" "${3:-}" "${4:-}"
      ;;
    ports)
      show_ports
      ;;
    refresh-ports)
      refresh_ports "${2:-}"
      ;;
    audit-ports)
      audit_ports
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
