#!/usr/bin/env bash

set -euo pipefail

# AmneziaWG 服务端管理器。

AWG_DIR="${AWG_DIR:-/etc/amneziawg}"
AWG_QUICK_CONFIG_DIR="${AWG_QUICK_CONFIG_DIR:-/etc/amnezia/amneziawg}"
AWG_IFACE="${AWG_IFACE:-awg0}"
AWG_SUBNET_CIDR="${AWG_SUBNET_CIDR:-10.20.0.0/24}"
AWG_SERVER_IP="${AWG_SERVER_IP:-10.20.0.1}"
AWG_PRIMARY_PORT="${AWG_PRIMARY_PORT:-443}"
AWG_BACKUP_PORT1="${AWG_BACKUP_PORT1:-}"
AWG_BACKUP_PORT2="${AWG_BACKUP_PORT2:-}"
AWG_MTU="${AWG_MTU:-1280}"
AWG_PUBLIC_IP="${AWG_PUBLIC_IP:-}"
AWG_PPA_SERIES="${AWG_PPA_SERIES:-focal}"
AWG_PPA_FINGERPRINT="75C9DD72C799870E310542E24166F2C257290828"
AWG_PPA_KEY_URL="${AWG_PPA_KEY_URL:-https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${AWG_PPA_FINGERPRINT}}"
AWG_PPA_URL="${AWG_PPA_URL:-https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu}"

SERVER_KIT_DIR="${SERVER_KIT_DIR:-/etc/server-kit}"
PORTS_PATH="${PORTS_PATH:-${SERVER_KIT_DIR}/ports.json}"
AWG_ACCESS_PATH_EXPLICIT="$([[ -n "${AWG_ACCESS_PATH+x}" ]] && echo 1 || echo 0)"
AWG_ACCESS_PENDING_PATH_EXPLICIT="$([[ -n "${AWG_ACCESS_PENDING_PATH+x}" ]] && echo 1 || echo 0)"
AWG_ACCESS_PATH="${AWG_ACCESS_PATH:-${SERVER_KIT_DIR}/awg-access.json}"
AWG_ACCESS_PENDING_PATH="${AWG_ACCESS_PENDING_PATH:-${SERVER_KIT_DIR}/awg-access.pending.json}"
MODULES_DIR="${MODULES_DIR:-/lib/modules}"
DRY_RUN="${DRY_RUN:-0}"

refresh_paths() {
  STATE_FILE="${AWG_DIR}/manager.conf"
  CONF="${AWG_DIR}/${AWG_IFACE}.conf"
  PEER_DB="${AWG_DIR}/peers.tsv"
  DISABLED_PEER_DB="${AWG_DIR}/peers.disabled.tsv"
  PEER_CREDENTIAL_DB="${AWG_DIR}/peer-credentials.tsv"
  ENROLLMENT_STATE="${AWG_DIR}/enrollments.json"
  SERVER_KEY_FILE="${AWG_DIR}/server_private.key"
  NFT_RULES_PATH="${AWG_DIR}/server-kit-amneziawg.nft"
  AUTO_REBOOT_CONFIG="${SERVER_KIT_DIR}/52server-kit-no-auto-reboot.conf"
  AUDIT_PATH="${SERVER_KIT_DIR}/amneziawg-audit.log"
  AWG_QUICK_COMPAT_CONF="${AWG_QUICK_CONFIG_DIR}/${AWG_IFACE}.conf"
  if [[ "${AWG_ACCESS_PATH_EXPLICIT}" != "1" ]]; then
    AWG_ACCESS_PATH="${SERVER_KIT_DIR}/awg-access.json"
  fi
  if [[ "${AWG_ACCESS_PENDING_PATH_EXPLICIT}" != "1" ]]; then
    AWG_ACCESS_PENDING_PATH="${SERVER_KIT_DIR}/awg-access.pending.json"
  fi
}
refresh_paths

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }

require_root() {
  if [[ "${EUID}" -ne 0 && "${DRY_RUN}" != "1" ]]; then
    echo "请使用 root 运行此脚本。" >&2
    exit 1
  fi
}

check_debian() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    return 0
  fi
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

ensure_layout() {
  install -d -m 700 "${AWG_DIR}"
  install -d -m 700 "${SERVER_KIT_DIR}" "${SERVER_KIT_DIR}/run"
  [[ -f "${PEER_DB}" ]] || install -m 600 /dev/null "${PEER_DB}"
  [[ -f "${DISABLED_PEER_DB}" ]] || install -m 600 /dev/null "${DISABLED_PEER_DB}"
  [[ -f "${PEER_CREDENTIAL_DB}" ]] || install -m 600 /dev/null "${PEER_CREDENTIAL_DB}"
}

ensure_awg_quick_compat_link() {
  install -d -m 700 "${AWG_QUICK_CONFIG_DIR}"
  if [[ -e "${AWG_QUICK_COMPAT_CONF}" && ! -L "${AWG_QUICK_COMPAT_CONF}" ]]; then
    echo "兼容配置路径已存在且不是软连接：${AWG_QUICK_COMPAT_CONF}" >&2
    return 1
  fi
  ln -sfn -- "${CONF}" "${AWG_QUICK_COMPAT_CONF}"
}

record_audit() {
  local action="$1"
  local subject="${2:--}"
  local address="${3:--}"
  ensure_layout
  printf '%s action=%s subject=%s address=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${action}" "${subject}" "${address}" >> "${AUDIT_PATH}"
  chmod 600 "${AUDIT_PATH}"
  python3 - "${AUDIT_PATH}" <<'PYTHON'
import datetime
import os
import sys

path = sys.argv[1]
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=14)
kept = []
with open(path, encoding="utf-8") as source:
    for line in source:
        try:
            created = datetime.datetime.fromisoformat(line.split(" ", 1)[0].replace("Z", "+00:00"))
        except ValueError:
            continue
        if created >= cutoff:
            kept.append(line)
temporary = f"{path}.tmp.{os.getpid()}"
with open(temporary, "w", encoding="utf-8", newline="\n") as output:
    output.writelines(kept)
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PYTHON
}

enforce_client_key_lockdown() {
  local helper="${SCRIPT_DIR}/lib/server_kit_client_keys.py"
  [[ "${SERVER_KIT_TESTING:-0}" != "1" ]] || return 0
  [[ -r "${helper}" ]] || {
    echo "缺少 AWG 节点凭据安全检查模块。" >&2
    return 1
  }
  python3 "${helper}" verify >/dev/null || {
    echo "AWG 节点凭据安全检查未通过，拒绝修改或启动 AWG。" >&2
    python3 "${helper}" status >&2 || true
    return 1
  }
}

show_audit() {
  [[ -r "${AUDIT_PATH}" ]] || { echo "暂无 AWG 审计记录：${AUDIT_PATH}"; return 0; }
  tail -n 100 "${AUDIT_PATH}"
}

validate_port() {
  local port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] && (( 10#${port} >= 1 && 10#${port} <= 65535 ))
}

validate_low_udp_port() {
  local port="$1"
  validate_port "${port}" && (( 10#${port} >= 1 && 10#${port} <= 9999 ))
}

validate_peer_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]
}

validate_ipv4() {
  python3 - "$1" <<'PYTHON'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 else 1)
PYTHON
}

subnet_value() {
  local action="$1"
  local value="${2:-}"
  python3 - "${AWG_SUBNET_CIDR}" "${AWG_SERVER_IP}" "${action}" "${value}" <<'PYTHON'
import ipaddress
import sys

network_text, server_text, action, value = sys.argv[1:]
network = ipaddress.ip_network(network_text, strict=False)
server = ipaddress.ip_address(server_text)
if network.version != 4 or server not in network:
    raise SystemExit(1)
if action == "prefix":
    print(network.prefixlen)
elif action == "contains-client":
    address = ipaddress.ip_address(value)
    if address not in network or address in {network.network_address, network.broadcast_address, server}:
        raise SystemExit(1)
elif action == "map-last":
    old = ipaddress.ip_address(value)
    address = ipaddress.ip_address(int(network.network_address) + int(str(old).split(".")[-1]))
    if address not in network or address in {network.network_address, network.broadcast_address, server}:
        raise SystemExit(1)
    print(address)
else:
    raise SystemExit(1)
PYTHON
}

validate_settings() {
  validate_ipv4 "${AWG_SERVER_IP}" || {
    echo "AmneziaWG 服务端地址无效：${AWG_SERVER_IP}" >&2
    return 1
  }
  subnet_value prefix >/dev/null || {
    echo "AmneziaWG 网段或服务端地址不匹配：${AWG_SUBNET_CIDR} / ${AWG_SERVER_IP}" >&2
    return 1
  }
  validate_low_udp_port "${AWG_PRIMARY_PORT}" || {
    echo "主入口必须是 1–9999 的 UDP 端口：${AWG_PRIMARY_PORT}" >&2
    return 1
  }
  validate_low_udp_port "${AWG_BACKUP_PORT1}" || {
    echo "备用入口必须是 1–9999 的 UDP 端口：${AWG_BACKUP_PORT1}" >&2
    return 1
  }
  if [[ -n "${AWG_BACKUP_PORT2}" ]] && ! validate_low_udp_port "${AWG_BACKUP_PORT2}"; then
    echo "兼容备用入口必须是 1–9999 的 UDP 端口：${AWG_BACKUP_PORT2}" >&2
    return 1
  fi
  if [[ "${AWG_PRIMARY_PORT}" == "${AWG_BACKUP_PORT1}" ||
        ( -n "${AWG_BACKUP_PORT2}" && "${AWG_PRIMARY_PORT}" == "${AWG_BACKUP_PORT2}" ) ||
        ( -n "${AWG_BACKUP_PORT2}" && "${AWG_BACKUP_PORT1}" == "${AWG_BACKUP_PORT2}" ) ]]; then
    echo "AmneziaWG UDP 入口不能重复。" >&2
    return 1
  fi
  [[ "${AWG_MTU}" =~ ^[0-9]+$ ]] && (( AWG_MTU >= 1180 && AWG_MTU <= 1420 )) || {
    echo "AWG MTU 必须位于 1180–1420：${AWG_MTU}" >&2
    return 1
  }
}

save_state() {
  local temp_path=""
  ensure_layout
  temp_path="$(mktemp "${AWG_DIR}/.manager.XXXXXX")"
  {
    printf 'AWG_IFACE=%q\n' "${AWG_IFACE}"
    printf 'AWG_SUBNET_CIDR=%q\n' "${AWG_SUBNET_CIDR}"
    printf 'AWG_SERVER_IP=%q\n' "${AWG_SERVER_IP}"
    printf 'AWG_PUBLIC_IP=%q\n' "${AWG_PUBLIC_IP}"
    printf 'AWG_PRIMARY_PORT=%q\n' "${AWG_PRIMARY_PORT}"
    printf 'AWG_BACKUP_PORT1=%q\n' "${AWG_BACKUP_PORT1}"
    printf 'AWG_BACKUP_PORT2=%q\n' "${AWG_BACKUP_PORT2}"
    printf 'AWG_MTU=%q\n' "${AWG_MTU}"
    printf 'AWG_JC=%q\n' "${AWG_JC}"
    printf 'AWG_JMIN=%q\n' "${AWG_JMIN}"
    printf 'AWG_JMAX=%q\n' "${AWG_JMAX}"
    printf 'AWG_S1=%q\n' "${AWG_S1}"
    printf 'AWG_S2=%q\n' "${AWG_S2}"
    printf 'AWG_S3=%q\n' "${AWG_S3}"
    printf 'AWG_S4=%q\n' "${AWG_S4}"
    printf 'AWG_H1=%q\n' "${AWG_H1}"
    printf 'AWG_H2=%q\n' "${AWG_H2}"
    printf 'AWG_H3=%q\n' "${AWG_H3}"
    printf 'AWG_H4=%q\n' "${AWG_H4}"
    printf 'AWG_I1=%q\n' "${AWG_I1}"
  } > "${temp_path}"
  install -m 600 "${temp_path}" "${STATE_FILE}"
  rm -f -- "${temp_path}"
}

load_state() {
  if [[ ! -r "${STATE_FILE}" ]]; then
    return 0
  fi
  # 状态文件由 root 以 600 权限生成，只包含脚本自己的 shell 转义赋值。
  # shellcheck disable=SC1090
  source "${STATE_FILE}"
  refresh_paths
}

random_unused_low_port() {
  python3 - "$@" <<'PYTHON'
import secrets
import socket
import sys

reserved = {int(value) for value in sys.argv[1:] if value}
for _ in range(512):
    port = secrets.randbelow(9999 - 1024 + 1) + 1024
    if port in reserved:
        continue
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        sock.close()
        continue
    sock.close()
    print(port)
    raise SystemExit(0)
raise SystemExit("无法找到空闲的低位 UDP 端口")
PYTHON
}

ensure_obfuscation_parameters() {
  local values=()
  if [[ -n "${AWG_JC:-}" && -n "${AWG_H4:-}" && -n "${AWG_I1:-}" ]]; then
    return 0
  fi
  mapfile -t values < <(python3 - <<'PYTHON'
import secrets

jc = secrets.randbelow(5) + 4
jmin = secrets.randbelow(65) + 64
jmax = jmin + secrets.randbelow(193) + 64
s1 = secrets.randbelow(33) + 24
s2 = secrets.randbelow(33) + 24
while s1 + 56 == s2:
    s2 = secrets.randbelow(33) + 24
s3 = secrets.randbelow(25) + 16
s4 = secrets.randbelow(13) + 4

starts = []
while len(starts) < 4:
    # 独立 Windows 客户端错误地以 INT32_MAX 校验 H 范围；统一用 9 位值规避。
    candidate = secrets.randbelow(800_000_000) + 100_000_000
    if all(abs(candidate - item) > 8192 for item in starts):
        starts.append(candidate)
ranges = [f"{item}-{item + secrets.randbelow(1024) + 256}" for item in starts]
prefix = secrets.token_hex(8)
i1 = f"<b 0x{prefix}><r {secrets.randbelow(49) + 16}>"
for value in (jc, jmin, jmax, s1, s2, s3, s4, *ranges, i1):
    print(value)
PYTHON
  )
  AWG_JC="${values[0]}"
  AWG_JMIN="${values[1]}"
  AWG_JMAX="${values[2]}"
  AWG_S1="${values[3]}"
  AWG_S2="${values[4]}"
  AWG_S3="${values[5]}"
  AWG_S4="${values[6]}"
  AWG_H1="${values[7]}"
  AWG_H2="${values[8]}"
  AWG_H3="${values[9]}"
  AWG_H4="${values[10]}"
  AWG_I1="${values[11]}"
}

detect_public_ip() {
  local address=""
  if command -v curl >/dev/null 2>&1; then
    address="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  fi
  if ! validate_ipv4 "${address}" >/dev/null 2>&1; then
    address="$(ip -4 route get 1.1.1.1 2>/dev/null |
      sed -n 's/.*[[:space:]]src[[:space:]]\([^[:space:]]*\).*/\1/p' | head -n 1)"
  fi
  printf '%s\n' "${address}"
}

configure_install_settings() {
  local value=""
  AWG_PUBLIC_IP="${AWG_PUBLIC_IP:-$(detect_public_ip)}"
  AWG_BACKUP_PORT1="${AWG_BACKUP_PORT1:-$(random_unused_low_port "${AWG_PRIMARY_PORT}")}"
  if [[ -t 0 && "${DRY_RUN}" != "1" && ! -r "${STATE_FILE}" ]]; then
    echo "开始配置 AmneziaWG 服务端。"
    read -r -p "服务器公网 IPv4 [${AWG_PUBLIC_IP}]: " value
    AWG_PUBLIC_IP="${value:-${AWG_PUBLIC_IP}}"
    read -r -p "主 UDP 入口 [${AWG_PRIMARY_PORT}]: " value
    AWG_PRIMARY_PORT="${value:-${AWG_PRIMARY_PORT}}"
    read -r -p "备用 UDP 入口 1 [${AWG_BACKUP_PORT1}]: " value
    AWG_BACKUP_PORT1="${value:-${AWG_BACKUP_PORT1}}"
  fi
  validate_ipv4 "${AWG_PUBLIC_IP}" || {
    echo "服务器公网 IPv4 无效：${AWG_PUBLIC_IP:-<空>}" >&2
    return 1
  }
  validate_settings
}

install_dependencies() {
  local current_headers="linux-headers-$(uname -r)"
  if [[ "${DRY_RUN}" == "1" ]]; then
    return 0
  fi
  if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1 &&
     modinfo amneziawg >/dev/null 2>&1; then
    return 0
  fi

  echo "将按 AmneziaWG 官方 Debian 方案使用签名固定的 Launchpad PPA。"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl dkms gnupg nftables python3 qrencode

  if ! apt-cache show "${current_headers}" >/dev/null 2>&1; then
    echo "当前内核 $(uname -r) 已无对应 headers 候选。"
    echo "将安装 Debian 当前标准内核与 headers，但不会自动重启。"
    DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-amd64 linux-headers-amd64
    echo "新内核已安装。请先确认公网 SSH 救援入口，再人工重启并重新执行 install。" >&2
    return 2
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${current_headers}"

  local key_temp=""
  local fingerprint=""
  key_temp="$(mktemp)"
  curl -fsSL "${AWG_PPA_KEY_URL}" | gpg --dearmor > "${key_temp}"
  fingerprint="$(gpg --show-keys --with-colons "${key_temp}" 2>/dev/null |
    awk -F: '$1 == "fpr" {print $10; exit}')"
  if [[ "${fingerprint}" != "${AWG_PPA_FINGERPRINT}" ]]; then
    rm -f -- "${key_temp}"
    echo "Amnezia PPA 签名指纹不匹配，拒绝安装。" >&2
    return 1
  fi
  install -m 644 "${key_temp}" /usr/share/keyrings/amnezia-archive-keyring.gpg
  rm -f -- "${key_temp}"
  printf 'deb [signed-by=/usr/share/keyrings/amnezia-archive-keyring.gpg] %s %s main\n' \
    "${AWG_PPA_URL}" "${AWG_PPA_SERIES}" > /etc/apt/sources.list.d/amnezia.list
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg

  command -v awg >/dev/null 2>&1 || { echo "未安装 awg。" >&2; return 1; }
  command -v awg-quick >/dev/null 2>&1 || { echo "未安装 awg-quick。" >&2; return 1; }
  modprobe amneziawg
  modinfo amneziawg >/dev/null
}

disable_unattended_reboot() {
  local target="/etc/apt/apt.conf.d/52server-kit-no-auto-reboot"
  if [[ "${DRY_RUN}" == "1" ]]; then
    target="${AUTO_REBOOT_CONFIG}"
    install -d -m 700 "$(dirname -- "${target}")"
  fi
  printf '%s\n' \
    '// 此文件由 server-kit 管理：内核模块检查通过后再人工重启。' \
    'Unattended-Upgrade::Automatic-Reboot "false";' > "${target}"
  chmod 644 "${target}"
}

normalize_key() {
  local key="${1//$'\r'/}"
  key="${key//$'\n'/}"
  if [[ "${key}" =~ ^[A-Za-z0-9+/]{43}$ ]]; then
    key="${key}="
  fi
  [[ "${key}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
  printf '%s\n' "${key}"
}

ensure_server_key() {
  local key=""
  if [[ -r "${SERVER_KEY_FILE}" ]]; then
    key="$(normalize_key "$(<"${SERVER_KEY_FILE}")")" || {
      echo "服务端私钥格式无效：${SERVER_KEY_FILE}" >&2
      return 1
    }
  else
    key="$(awg genkey)"
    key="$(normalize_key "${key}")" || return 1
    printf '%s\n' "${key}" | install -m 600 /dev/stdin "${SERVER_KEY_FILE}"
  fi
  SERVER_PRIVATE_KEY="${key}"
  SERVER_PUBLIC_KEY="$(printf '%s' "${key}" | awg pubkey)"
  SERVER_PUBLIC_KEY="$(normalize_key "${SERVER_PUBLIC_KEY}")" || return 1
}

peer_name_exists() {
  awk -F '\t' -v name="$1" '$1 == name {found=1} END {exit !found}' "${PEER_DB}"
}

disabled_peer_name_exists() {
  awk -F '\t' -v name="$1" '$1 == name {found=1} END {exit !found}' "${DISABLED_PEER_DB}"
}

any_peer_name_exists() {
  peer_name_exists "$1" || disabled_peer_name_exists "$1"
}

peer_ip_exists() {
  awk -F '\t' -v ip="$1" '$2 == ip {found=1} END {exit !found}' "${PEER_DB}" "${DISABLED_PEER_DB}"
}

peer_ip_by_name() {
  awk -F '\t' -v name="$1" '$1 == name {print $2; exit}' "${PEER_DB}"
}

peer_credential_record() {
  awk -F '\t' -v name="$1" '$1 == name {print; exit}' "${PEER_CREDENTIAL_DB}"
}

peer_custody() {
  local record=""
  record="$(peer_credential_record "$1")"
  if [[ -n "${record}" ]]; then
    printf '%s\n' "${record##*$'\t'}"
  else
    printf 'unknown\n'
  fi
}

validate_peer_credentials() {
  local line_number=0
  local name=""
  local public_key=""
  local psk=""
  local custody=""
  local extra=""
  declare -A names=()
  while IFS=$'\t' read -r name public_key psk custody extra; do
    line_number=$((line_number + 1))
    [[ -n "${name}${public_key}${psk}${custody}${extra:-}" ]] || continue
    if [[ -n "${extra:-}" ]] || ! validate_peer_name "${name}" ||
       ! normalize_key "${public_key}" >/dev/null || ! normalize_key "${psk}" >/dev/null ||
       [[ "${custody}" != "client" ]]; then
      echo "节点凭据第 ${line_number} 行格式无效。" >&2
      return 1
    fi
    any_peer_name_exists "${name}" || {
      echo "节点凭据引用了不存在的节点：${name}" >&2
      return 1
    }
    [[ -z "${names[${name}]:-}" ]] || {
      echo "节点凭据重复：${name}" >&2
      return 1
    }
    names["${name}"]=1
  done < "${PEER_CREDENTIAL_DB}"
}

validate_peer_db() {
  local line_number=0
  local name=""
  local ip=""
  declare -A names=()
  declare -A ips=()
  while IFS=$'\t' read -r name ip extra; do
    line_number=$((line_number + 1))
    [[ -n "${name}${ip}${extra:-}" ]] || continue
    if [[ -n "${extra:-}" ]] || ! validate_peer_name "${name}"; then
      echo "节点清单第 ${line_number} 行格式无效。" >&2
      return 1
    fi
    subnet_value contains-client "${ip}" >/dev/null || {
      echo "节点 ${name} 的 IP 不属于可用客户端范围：${ip}" >&2
      return 1
    }
    if [[ -n "${names[${name}]:-}" || -n "${ips[${ip}]:-}" ]]; then
      echo "节点名称或 IP 重复：${name} / ${ip}" >&2
      return 1
    fi
    names["${name}"]=1
    ips["${ip}"]=1
  done < "${PEER_DB}"
}

next_available_ip() {
  python3 - "${AWG_SUBNET_CIDR}" "${AWG_SERVER_IP}" "${PEER_DB}" "${DISABLED_PEER_DB}" <<'PYTHON'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
server = ipaddress.ip_address(sys.argv[2])
used = {server}
for path in sys.argv[3:]:
    try:
        with open(path, encoding="utf-8") as source:
            for line in source:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    used.add(ipaddress.ip_address(parts[1]))
    except FileNotFoundError:
        pass
for address in network.hosts():
    if address not in used:
        print(address)
        raise SystemExit(0)
raise SystemExit("网段中没有可分配的地址")
PYTHON
}

install_if_changed() {
  local source="$1"
  local target="$2"
  local mode="${3:-600}"
  if [[ -f "${target}" ]] && cmp -s "${source}" "${target}"; then
    rm -f -- "${source}"
    return 1
  fi
  install -m "${mode}" "${source}" "${target}"
  rm -f -- "${source}"
  return 0
}

write_awg_interface_fields() {
  cat <<EOF
Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
S3 = ${AWG_S3}
S4 = ${AWG_S4}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}
I1 = ${AWG_I1}
EOF
}

profile_port() {
  case "$1" in
    main) printf '%s\n' "${AWG_PRIMARY_PORT}" ;;
    backup1) printf '%s\n' "${AWG_BACKUP_PORT1}" ;;
    backup2) printf '%s\n' "${AWG_BACKUP_PORT2}" ;;
    *) echo "端点名称必须是 main、backup1 或 backup2。" >&2; return 1 ;;
  esac
}

render_nft_rules() {
  local policy_path="${1:-${AWG_ACCESS_PATH}}"
  local helper="${SCRIPT_DIR}/lib/awg_access.py"
  local public_ports="${AWG_PRIMARY_PORT},${AWG_BACKUP_PORT1}"
  [[ -z "${AWG_BACKUP_PORT2}" ]] || public_ports+=",${AWG_BACKUP_PORT2}"
  [[ -r "${helper}" ]] || { echo "缺少 AWG 访问策略模块：${helper}" >&2; return 1; }
  python3 "${helper}" \
    --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
    --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" \
    render-nft --policy "${policy_path}" --iface "${AWG_IFACE}" \
    --public-ports "${public_ports}" --output "${NFT_RULES_PATH}"
}

change_access_policy() {
  local operation="$1"
  local client="$2"
  shift 2
  local helper="${SCRIPT_DIR}/lib/awg_access.py"
  local active_backup=""
  local active_existed=0
  local rollback_failed=0
  local -a helper_arguments=(change "${operation}" "${client}" "$@")
  load_state || return 1
  ensure_layout || return 1
  [[ -r "${helper}" ]] || { echo "缺少 AWG 访问策略模块。" >&2; return 1; }
  if [[ "${operation}" == "allow-batch" ]]; then
    helper_arguments=(allow-batch "${client}")
  fi
  # Snapshot before staging so commit failures can restore both persisted and live policy.
  active_backup="$(mktemp "${AWG_ACCESS_PATH}.backup.XXXXXX")" || return 1
  if [[ -e "${AWG_ACCESS_PATH}" ]]; then
    active_existed=1
    cp -p -- "${AWG_ACCESS_PATH}" "${active_backup}" || { rm -f -- "${active_backup}"; return 1; }
  fi
  if ! python3 "${helper}" \
    --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
    --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" \
    "${helper_arguments[@]}"; then
    rm -f -- "${active_backup}"
    return 1
  fi
  if ! render_nft_rules "${AWG_ACCESS_PENDING_PATH}" || \
     { [[ "${DRY_RUN}" != "1" ]] && ! nft --check -f "${NFT_RULES_PATH}"; } || \
     { [[ "${DRY_RUN}" != "1" ]] && ! nft -f "${NFT_RULES_PATH}"; } || \
     ! python3 "${helper}" \
       --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
       --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" commit; then
    if [[ "${active_existed}" == "1" ]]; then
      cp -p -- "${active_backup}" "${AWG_ACCESS_PATH}" || {
        echo 'SERVER_KIT_DIAGNOSTIC:permission_recovery_required' >&2
        echo "无法恢复活动策略；保留备份：${active_backup}" >&2; return 1;
      }
    else
      rm -f -- "${AWG_ACCESS_PATH}"
    fi
    python3 "${helper}" \
      --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
      --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" discard >/dev/null 2>&1 || rollback_failed=1
    if ! render_nft_rules "${AWG_ACCESS_PATH}" >/dev/null 2>&1; then
      rollback_failed=1
    elif [[ "${DRY_RUN}" != "1" ]] && ! nft -f "${NFT_RULES_PATH}" >/dev/null 2>&1; then
      rollback_failed=1
    fi
    if [[ "${rollback_failed}" == "1" ]]; then
      echo 'SERVER_KIT_DIAGNOSTIC:permission_recovery_required' >&2
      echo "AWG 策略恢复未完成，需要人工核验；保留原策略备份：${active_backup}" >&2
      return 1
    fi
    rm -f -- "${active_backup}"
    echo "AWG 访问策略应用失败，已恢复原策略。" >&2
    return 1
  fi
  rm -f -- "${active_backup}"
  record_audit "access-${operation}" "${client}" "-" || echo "警告：策略已生效，但写入审计失败。" >&2
  green "已更新普通节点访问策略：${client}"
}

render_configuration() {
  local prefix=""
  local server_temp=""
  local name=""
  local ip=""
  local public_key=""
  local psk=""
  local credential=""
  local custody=""
  declare -A public_keys=()
  declare -A preshared_keys=()

  enforce_client_key_lockdown
  validate_peer_db
  validate_peer_credentials
  ensure_server_key
  prefix="$(subnet_value prefix)"

  while IFS=$'\t' read -r name ip; do
    [[ -n "${name}" ]] || continue
    credential="$(peer_credential_record "${name}")"
    [[ -n "${credential}" ]] || {
      echo "节点 ${name} 缺少安全凭据记录；请使用 import-public 或 enroll。" >&2
      return 1
    }
    IFS=$'\t' read -r _ public_key psk custody <<< "${credential}"
    [[ "${custody}" == "client" ]] || {
      echo "节点 ${name} 的凭据不符合安全要求，拒绝生成配置。" >&2
      return 1
    }
    public_key="$(normalize_key "${public_key}")" || return 1
    psk="$(normalize_key "${psk}")" || return 1
    public_keys["${name}"]="${public_key}"
    preshared_keys["${name}"]="${psk}"
  done < "${PEER_DB}"

  server_temp="$(mktemp "${AWG_DIR}/.${AWG_IFACE}.XXXXXX")"
  {
    printf '[Interface]\n'
    printf 'Address = %s/%s\n' "${AWG_SERVER_IP}" "${prefix}"
    printf 'ListenPort = %s\n' "${AWG_PRIMARY_PORT}"
    printf 'PrivateKey = %s\n' "${SERVER_PRIVATE_KEY}"
    printf 'MTU = %s\n' "${AWG_MTU}"
    write_awg_interface_fields
    printf 'PostUp = nft -f %s\n' "${NFT_RULES_PATH}"
    printf 'PostDown = nft list table inet server_kit_amneziawg_filter >/dev/null 2>&1 && nft delete table inet server_kit_amneziawg_filter || true; nft list table ip server_kit_amneziawg_nat >/dev/null 2>&1 && nft delete table ip server_kit_amneziawg_nat || true\n'
    while IFS=$'\t' read -r name ip; do
      [[ -n "${name}" ]] || continue
      printf '\n[Peer]\n# %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n' \
        "${name}" "${public_keys[${name}]}" "${preshared_keys[${name}]}" "${ip}"
    done < "${PEER_DB}"
  } > "${server_temp}"

  render_nft_rules

  install_if_changed "${server_temp}" "${CONF}" 600 || true
}

add_external_peer() {
  local name="${1:-}"
  local ip="${2:-}"
  local public_key="${3:-}"
  local initial_mode="${4:-unrestricted}"
  local psk=""
  local peer_backup=""
  local credential_backup=""
  local access_backup=""
  local access_existed=0
  local access_helper="${SCRIPT_DIR}/lib/awg_access.py"
  [[ -n "${name}" ]] || { echo "请提供节点名称。" >&2; return 1; }
  [[ "${initial_mode}" == "unrestricted" || "${initial_mode}" == "restricted" ]] || {
    echo "节点初始权限无效。" >&2
    return 1
  }
  validate_peer_name "${name}" || { echo "节点名称无效：${name}" >&2; return 1; }
  public_key="$(normalize_key "${public_key}")" || {
    echo "客户端公钥格式无效。" >&2
    return 1
  }
  IFS= read -r psk || true
  psk="$(normalize_key "${psk}")" || {
    echo "请通过标准输入提供有效的预共享密钥。" >&2
    return 1
  }
  load_state
  ensure_layout
  validate_settings
  any_peer_name_exists "${name}" && { echo "节点已存在：${name}" >&2; return 1; }
  ip="${ip:-$(next_available_ip)}"
  subnet_value contains-client "${ip}" >/dev/null || { echo "节点 IP 无效：${ip}" >&2; return 1; }
  peer_ip_exists "${ip}" && { echo "节点 IP 已使用：${ip}" >&2; return 1; }
  peer_backup="$(mktemp "${AWG_DIR}/.peers.XXXXXX")"
  credential_backup="$(mktemp "${AWG_DIR}/.credentials.XXXXXX")"
  access_backup="$(mktemp "${AWG_DIR}/.access.XXXXXX")"
  cp "${PEER_DB}" "${peer_backup}"
  cp "${PEER_CREDENTIAL_DB}" "${credential_backup}"
  if [[ -f "${AWG_ACCESS_PATH}" ]]; then
    cp "${AWG_ACCESS_PATH}" "${access_backup}"
    access_existed=1
  fi
  printf '%s\t%s\n' "${name}" "${ip}" >> "${PEER_DB}"
  printf '%s\t%s\t%s\tclient\n' "${name}" "${public_key}" "${psk}" >> "${PEER_CREDENTIAL_DB}"
  if ! python3 "${access_helper}" \
      --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
      --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" forget "${name}" || \
     ! { [[ "${initial_mode}" != "restricted" ]] || python3 "${access_helper}" \
      --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
      --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" \
      change mode "${name}" restricted; } || \
     ! python3 "${access_helper}" \
      --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
      --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" commit || \
     ! render_configuration || ! apply_configuration; then
    cp "${peer_backup}" "${PEER_DB}"
    cp "${credential_backup}" "${PEER_CREDENTIAL_DB}"
    if [[ "${access_existed}" == "1" ]]; then
      install -m 600 "${access_backup}" "${AWG_ACCESS_PATH}"
    else
      rm -f -- "${AWG_ACCESS_PATH}"
    fi
    rm -f -- "${AWG_ACCESS_PENDING_PATH}" "${peer_backup}" "${credential_backup}" "${access_backup}"
    render_configuration >/dev/null 2>&1 || true
    echo "导入节点失败，已恢复节点清单。" >&2
    return 1
  fi
  rm -f -- "${peer_backup}" "${credential_backup}" "${access_backup}"
  record_audit import-public "${name}" "${ip}"
  green "已导入节点：${name} (${ip})"
}

show_enrollment_context() {
  local suggested=""
  local prefix=""
  local endpoint_host=""
  load_state
  ensure_layout
  validate_settings
  ensure_server_key
  suggested="$(next_available_ip)"
  prefix="$(subnet_value prefix)"
  endpoint_host="$(python3 "${SCRIPT_DIR}/lib/server_kit_public_endpoint.py" get \
    --config "${SERVER_KIT_DIR}/public-endpoint.json")" || {
      echo "稳定公网入口事实无效，拒绝生成新节点配置。" >&2
      return 1
    }
  endpoint_host="${endpoint_host:-${AWG_PUBLIC_IP}}"
  python3 - "${AWG_SUBNET_CIDR}" "${AWG_SERVER_IP}" "${suggested}" \
    "${SERVER_PUBLIC_KEY}" "${endpoint_host}" "${AWG_PRIMARY_PORT}" \
    "${AWG_BACKUP_PORT1}" "${AWG_BACKUP_PORT2}" "${AWG_MTU}" "${prefix}" \
    "${AWG_JC}" "${AWG_JMIN}" "${AWG_JMAX}" "${AWG_S1}" "${AWG_S2}" \
    "${AWG_S3}" "${AWG_S4}" "${AWG_H1}" "${AWG_H2}" "${AWG_H3}" \
    "${AWG_H4}" "${AWG_I1}" <<'PYTHON'
import json
import sys

(
    network, server_ip, suggested, server_public_key, host,
    main, backup1, backup2, mtu, prefix, jc, jmin, jmax,
    s1, s2, s3, s4, h1, h2, h3, h4, i1,
) = sys.argv[1:]
endpoints = [
    {"profile": "main", "host": host, "port": int(main)},
    {"profile": "backup1", "host": host, "port": int(backup1)},
]
if backup2:
    endpoints.append({"profile": "backup2", "host": host, "port": int(backup2)})

result = {
    "schema_version": 1,
    "network": network,
    "server_ip": server_ip,
    "suggested_address": suggested,
    "prefix": int(prefix),
    "server_public_key": server_public_key,
    "mtu": int(mtu),
    "endpoints": endpoints,
    "obfuscation": {
        "Jc": int(jc), "Jmin": int(jmin), "Jmax": int(jmax),
        "S1": int(s1), "S2": int(s2), "S3": int(s3), "S4": int(s4),
        "H1": h1, "H2": h2, "H3": h3, "H4": h4, "I1": i1,
    },
}
json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
print()
PYTHON
}

enroll_peer() {
  local name="${1:-}"
  local ip="${2:-}"
  local public_key="${3:-}"
  local psk=""
  local helper="${SCRIPT_DIR}/lib/awg_enrollment.py"
  IFS= read -r psk || true
  [[ -r "${helper}" ]] || { echo "缺少首次握手状态模块。" >&2; return 1; }
  if ! printf '%s\n' "${psk}" | add_external_peer "${name}" "${ip}" "${public_key}" restricted; then
    return 1
  fi
  # 首次握手前只允许建立隧道，不允许通过隧道访问 VPS 或其他节点。
  if ! python3 "${helper}" start --state "${ENROLLMENT_STATE}" \
      --name "${name}" --public-key "${public_key}"; then
    remove_peer "${name}" >/dev/null 2>&1 || true
    echo "无法建立首次握手确认，节点已撤销。" >&2
    return 1
  fi
  record_audit enrollment-start "${name}" "${ip}"
}

reconcile_enrollments() {
  local helper="${SCRIPT_DIR}/lib/awg_enrollment.py"
  local handshakes="{}"
  local plan=""
  local action=""
  local name=""
  local access_helper="${SCRIPT_DIR}/lib/awg_access.py"
  load_state
  ensure_layout
  [[ -r "${helper}" ]] || { echo "缺少首次握手状态模块。" >&2; return 1; }
  if [[ "${DRY_RUN}" != "1" ]] && ip link show "${AWG_IFACE}" >/dev/null 2>&1; then
    handshakes="$(awg show "${AWG_IFACE}" latest-handshakes 2>/dev/null | python3 -c '
import json, sys
values = {}
for line in sys.stdin:
    fields = line.split()
    if len(fields) == 2 and fields[1].isdigit():
        values[fields[0]] = int(fields[1])
json.dump(values, sys.stdout, separators=(",", ":"))
')"
  fi
  plan="$(printf '%s\n' "${handshakes}" | python3 "${helper}" plan --state "${ENROLLMENT_STATE}")"
  while IFS=$'\t' read -r action name; do
    action="${action%$'\r'}"
    name="${name%$'\r'}"
    [[ -n "${action}" ]] || continue
    if [[ "${action}" == "commit" ]]; then
      if python3 "${access_helper}" \
          --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
          --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" \
          change mode "${name}" unrestricted && \
         python3 "${access_helper}" \
          --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
          --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" commit && \
         render_configuration && apply_configuration; then
        python3 "${helper}" complete --state "${ENROLLMENT_STATE}" --name "${name}" --outcome active >/dev/null
        record_audit enrollment-commit "${name}" "handshake"
      fi
    elif [[ "${action}" == "expire" ]]; then
      if any_peer_name_exists "${name}"; then
        remove_peer "${name}" >/dev/null
      fi
      python3 "${helper}" complete --state "${ENROLLMENT_STATE}" --name "${name}" --outcome expired >/dev/null
      record_audit enrollment-expire "${name}" "timeout"
    fi
  done < <(python3 - "${plan}" <<'PYTHON'
import json
import sys
for item in json.loads(sys.argv[1]).get("actions", []):
    print(f"{item['action']}\t{item['name']}")
PYTHON
)
  python3 "${helper}" overview --state "${ENROLLMENT_STATE}"
}

show_enrollments() {
  local helper="${SCRIPT_DIR}/lib/awg_enrollment.py"
  load_state
  ensure_layout
  python3 "${helper}" overview --state "${ENROLLMENT_STATE}"
}

enable_forwarding() {
  local target="/etc/sysctl.d/90-server-kit-amneziawg.conf"
  if [[ "${DRY_RUN}" == "1" ]]; then
    target="${AWG_DIR}/90-server-kit-amneziawg.conf"
  fi
  printf '%s\n' \
    '# 此文件由 amneziawg-setup.sh 管理。' \
    'net.ipv4.ip_forward = 1' > "${target}"
  [[ "${DRY_RUN}" == "1" ]] || sysctl --system >/dev/null
}

apply_configuration() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    return 0
  fi
  awg-quick strip "${CONF}" >/dev/null
  nft --check -f "${NFT_RULES_PATH}"
  enable_forwarding
  if systemctl is-active --quiet "awg-quick@${AWG_IFACE}.service"; then
    awg syncconf "${AWG_IFACE}" <(awg-quick strip "${CONF}")
    nft -f "${NFT_RULES_PATH}"
  else
    systemctl enable --now "awg-quick@${AWG_IFACE}.service"
  fi
  systemctl is-active --quiet "awg-quick@${AWG_IFACE}.service"
}

refresh_ports_registry() {
  [[ "${SERVER_KIT_TESTING:-0}" != "1" ]] || return 0
  if command -v debian_security_manager.sh >/dev/null 2>&1; then
    debian_security_manager.sh refresh-ports --quiet >/dev/null 2>&1 || true
  elif [[ -x "${SCRIPT_DIR:-}/debian_security_manager.sh" ]]; then
    "${SCRIPT_DIR}/debian_security_manager.sh" refresh-ports --quiet >/dev/null 2>&1 || true
  fi
}

install_and_run() {
  load_state
  disable_unattended_reboot
  install_dependencies
  ensure_layout
  configure_install_settings
  ensure_obfuscation_parameters
  save_state
  render_configuration
  ensure_awg_quick_compat_link
  enable_forwarding
  apply_configuration
  refresh_ports_registry
  record_audit install "${AWG_IFACE}" "${AWG_SERVER_IP}"
  green "AmneziaWG 已安装完成。"
  echo "接口：${AWG_IFACE} / ${AWG_SERVER_IP}"
  echo "入口：${AWG_PRIMARY_PORT}/UDP、${AWG_BACKUP_PORT1}/UDP"
  echo "节点：当前为空，请在管理网页生成，或执行 import-public 添加普通节点。"
}

remove_peer() {
  local name="${1:-}"
  local temp_db=""
  local credential_backup=""
  [[ -n "${name}" ]] || { echo "请提供节点名称。" >&2; return 1; }
  load_state
  ensure_layout
  any_peer_name_exists "${name}" || { echo "节点不存在：${name}" >&2; return 1; }
  local active_backup=""
  local disabled_backup=""
  active_backup="$(mktemp "${AWG_DIR}/.peers-active.XXXXXX")"
  disabled_backup="$(mktemp "${AWG_DIR}/.peers-disabled.XXXXXX")"
  cp "${PEER_DB}" "${active_backup}"
  cp "${DISABLED_PEER_DB}" "${disabled_backup}"
  credential_backup="$(mktemp "${AWG_DIR}/.credentials.XXXXXX")"
  cp "${PEER_CREDENTIAL_DB}" "${credential_backup}"
  temp_db="$(mktemp "${AWG_DIR}/.peers.XXXXXX")"
  awk -F '\t' -v name="${name}" '$1 != name' "${PEER_DB}" > "${temp_db}"
  install -m 600 "${temp_db}" "${PEER_DB}"
  rm -f -- "${temp_db}"
  temp_db="$(mktemp "${AWG_DIR}/.peers.XXXXXX")"
  awk -F '\t' -v name="${name}" '$1 != name' "${DISABLED_PEER_DB}" > "${temp_db}"
  install -m 600 "${temp_db}" "${DISABLED_PEER_DB}"
  rm -f -- "${temp_db}"
  temp_db="$(mktemp "${AWG_DIR}/.credentials.XXXXXX")"
  awk -F '\t' -v name="${name}" '$1 != name' "${PEER_CREDENTIAL_DB}" > "${temp_db}"
  install -m 600 "${temp_db}" "${PEER_CREDENTIAL_DB}"
  rm -f -- "${temp_db}"
  if ! render_configuration || ! apply_configuration; then
    cp "${active_backup}" "${PEER_DB}"
    cp "${disabled_backup}" "${DISABLED_PEER_DB}"
    cp "${credential_backup}" "${PEER_CREDENTIAL_DB}"
    rm -f -- "${active_backup}" "${disabled_backup}" "${credential_backup}"
    render_configuration >/dev/null 2>&1 || true
    echo "删除节点失败，已恢复节点清单。" >&2
    return 1
  fi
  rm -f -- "${active_backup}" "${disabled_backup}" "${credential_backup}"
  if python3 "${SCRIPT_DIR}/lib/awg_access.py" \
      --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
      --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" forget "${name}" && \
     python3 "${SCRIPT_DIR}/lib/awg_access.py" \
      --active "${AWG_ACCESS_PATH}" --pending "${AWG_ACCESS_PENDING_PATH}" \
      --peers "${PEER_DB}" --server-ip "${AWG_SERVER_IP}" --network-cidr "${AWG_SUBNET_CIDR}" commit; then
    if ! render_nft_rules || \
       { [[ "${DRY_RUN}" != "1" ]] && ! nft -f "${NFT_RULES_PATH}"; }; then
      echo "警告：节点已删除，访问策略已清理，但实时规则刷新失败；重启 AWG 服务后会自动恢复一致。" >&2
    fi
  else
    rm -f -- "${AWG_ACCESS_PENDING_PATH}"
    echo "警告：节点已删除，但遗留访问策略清理失败。" >&2
  fi
  record_audit remove "${name}" "-"
  green "已删除节点 ${name}。"
}

set_peer_enabled() {
  local name="${1:-}"
  local enabled="${2:-}"
  local source_db=""
  local target_db=""
  local record=""
  local source_backup=""
  local target_backup=""
  local temp_db=""
  [[ -n "${name}" ]] || { echo "请提供节点名称。" >&2; return 1; }
  load_state
  ensure_layout
  if [[ "${enabled}" == "1" ]]; then
    source_db="${DISABLED_PEER_DB}"
    target_db="${PEER_DB}"
    disabled_peer_name_exists "${name}" || { echo "节点未处于禁用状态：${name}" >&2; return 1; }
  else
    source_db="${PEER_DB}"
    target_db="${DISABLED_PEER_DB}"
    peer_name_exists "${name}" || { echo "节点未处于启用状态：${name}" >&2; return 1; }
  fi
  record="$(awk -F '\t' -v name="${name}" '$1 == name {print; exit}' "${source_db}")"
  source_backup="$(mktemp "${AWG_DIR}/.peers-source.XXXXXX")"
  target_backup="$(mktemp "${AWG_DIR}/.peers-target.XXXXXX")"
  cp "${source_db}" "${source_backup}"
  cp "${target_db}" "${target_backup}"
  temp_db="$(mktemp "${AWG_DIR}/.peers.XXXXXX")"
  awk -F '\t' -v name="${name}" '$1 != name' "${source_db}" > "${temp_db}"
  install -m 600 "${temp_db}" "${source_db}"
  rm -f -- "${temp_db}"
  printf '%s\n' "${record}" >> "${target_db}"
  if ! render_configuration || ! apply_configuration; then
    cp "${source_backup}" "${source_db}"
    cp "${target_backup}" "${target_db}"
    rm -f -- "${source_backup}" "${target_backup}"
    render_configuration >/dev/null 2>&1 || true
    echo "节点状态切换失败，已恢复节点清单。" >&2
    return 1
  fi
  rm -f -- "${source_backup}" "${target_backup}"
  record_audit "$([[ "${enabled}" == "1" ]] && echo enable || echo disable)" "${name}" "${record#*$'\t'}"
  green "已$([[ "${enabled}" == "1" ]] && echo 启用 || echo 禁用)节点：${name}"
}

list_peers() {
  local name=""
  local ip=""
  local public_key=""
  local handshake=""
  local custody=""
  load_state
  ensure_layout
  echo "=== 当前普通 AmneziaWG 节点 ==="
  if [[ ! -s "${PEER_DB}" ]]; then
    echo "暂无节点。"
    return 0
  fi
  while IFS=$'\t' read -r name ip; do
    handshake=""
    if [[ "${DRY_RUN}" != "1" ]] && ip link show "${AWG_IFACE}" >/dev/null 2>&1; then
      custody="$(peer_custody "${name}")"
      public_key="$(peer_credential_record "${name}")"
      IFS=$'\t' read -r _ public_key _ _ <<< "${public_key}"
      handshake="$(awg show "${AWG_IFACE}" latest-handshakes 2>/dev/null |
        awk -v wanted="${public_key}" '$1 == wanted {print $2; exit}' 2>/dev/null || true)"
      if [[ "${handshake}" =~ ^[0-9]+$ ]] && (( handshake > 0 )); then
        handshake="最近握手 $(date -d "@${handshake}" '+%F %T' 2>/dev/null || printf '%s' "${handshake}")"
      else
        handshake="尚未握手"
      fi
    fi
    custody="$(peer_custody "${name}")"
    printf '%-24s %-15s %s\n' "${name}" "${ip}" "${handshake:-配置已生成}"
  done < "${PEER_DB}"
}

show_endpoints() {
  load_state
  echo "=== AmneziaWG 公网入口 ==="
  echo "main:    ${AWG_PUBLIC_IP}:${AWG_PRIMARY_PORT}/UDP"
  echo "backup1: ${AWG_PUBLIC_IP}:${AWG_BACKUP_PORT1}/UDP"
  [[ -z "${AWG_BACKUP_PORT2}" ]] || \
    echo "backup2: ${AWG_PUBLIC_IP}:${AWG_BACKUP_PORT2}/UDP（兼容旧配置）"
  echo
  echo "服务端只能显示各入口聚合计数；当前客户端选择应在客户端配置中确认。"
  if [[ "${DRY_RUN}" != "1" ]] && nft list table ip server_kit_amneziawg_nat >/dev/null 2>&1; then
    nft list table ip server_kit_amneziawg_nat
  fi
}

show_obfuscation() {
  load_state
  [[ -n "${AWG_JC:-}" ]] || { echo "尚未生成混淆参数。" >&2; return 1; }
  echo "=== AmneziaWG 2.0 混淆摘要 ==="
  echo "Jc/Jmin/Jmax: ${AWG_JC}/${AWG_JMIN}/${AWG_JMAX}"
  echo "S1-S4: ${AWG_S1}/${AWG_S2}/${AWG_S3}/${AWG_S4}"
  echo "H1-H4: 已生成四组互不重叠范围"
  echo "I1: 已生成本部署专属模板"
  echo "完整参数：${STATE_FILE}（仅 root 可读）"
}

set_backup_port() {
  local profile="$1"
  local requested_port="$2"
  local old_port=""
  local state_backup=""

  [[ "${profile}" == "backup1" ]] || {
    echo "可修改的备用入口只能是 backup1。" >&2
    return 1
  }
  validate_low_udp_port "${requested_port}" || {
    echo "AWG 备用入口必须是 1–9999 的 UDP 端口。" >&2
    return 1
  }
  requested_port="$((10#${requested_port}))"
  load_state
  old_port="$(profile_port "${profile}")"
  [[ "${old_port}" != "${requested_port}" ]] || { echo "新端口与当前端口相同。" >&2; return 1; }
  if [[ "${requested_port}" == "${AWG_PRIMARY_PORT}" ||
        "${requested_port}" == "${AWG_BACKUP_PORT2}" ]]; then
    echo "AWG 公网 UDP 入口必须互不相同。" >&2
    return 1
  fi
  state_backup="$(mktemp "${AWG_DIR}/.manager-port.XXXXXX")"
  cp -- "${STATE_FILE}" "${state_backup}"
  trap 'rm -f -- "${state_backup:-}"' RETURN
  AWG_BACKUP_PORT1="${requested_port}"
  save_state
  if ! render_nft_rules || \
     { [[ "${DRY_RUN}" != "1" ]] && ! nft --check -f "${NFT_RULES_PATH}"; } || \
     { [[ "${DRY_RUN}" != "1" ]] && ! nft -f "${NFT_RULES_PATH}"; }; then
    install -m 600 -- "${state_backup}" "${STATE_FILE}"
    load_state
    render_nft_rules >/dev/null 2>&1 || true
    [[ "${DRY_RUN}" == "1" ]] || nft -f "${NFT_RULES_PATH}" >/dev/null 2>&1 || true
    echo "备用入口切换失败，已恢复 ${old_port}/UDP。" >&2
    return 1
  fi
  rm -f -- "${state_backup}"
  state_backup=""
  trap - RETURN
  refresh_ports_registry
  record_audit "set-${profile}-port" "${old_port}" "${requested_port}"
  green "AWG ${profile} 已从 ${old_port}/UDP 改为 ${requested_port}/UDP；主隧道未重启。"
}

remove_backup_port() {
  local profile="$1"
  local removed_port=""
  local state_backup=""

  [[ "${profile}" == "backup1" || "${profile}" == "backup2" ]] || {
    echo "备用入口只能是 backup1 或 backup2。" >&2
    return 1
  }
  load_state
  removed_port="$(profile_port "${profile}")"
  [[ -n "${removed_port}" ]] || {
    echo "AWG ${profile} 当前未启用。" >&2
    return 1
  }
  if [[ "${profile}" == "backup1" && -z "${AWG_BACKUP_PORT2}" ]]; then
    echo "至少必须保留一个 AWG 备用入口。" >&2
    return 1
  fi

  state_backup="$(mktemp "${AWG_DIR}/.manager-remove-port.XXXXXX")"
  cp -- "${STATE_FILE}" "${state_backup}"
  trap 'rm -f -- "${state_backup:-}"' RETURN
  if [[ "${profile}" == "backup1" ]]; then
    AWG_BACKUP_PORT1="${AWG_BACKUP_PORT2}"
    AWG_BACKUP_PORT2=""
  else
    AWG_BACKUP_PORT2=""
  fi
  save_state
  if ! render_nft_rules || \
     { [[ "${DRY_RUN}" != "1" ]] && ! nft --check -f "${NFT_RULES_PATH}"; } || \
     { [[ "${DRY_RUN}" != "1" ]] && ! nft -f "${NFT_RULES_PATH}"; }; then
    install -m 600 -- "${state_backup}" "${STATE_FILE}"
    load_state
    render_nft_rules >/dev/null 2>&1 || true
    [[ "${DRY_RUN}" == "1" ]] || nft -f "${NFT_RULES_PATH}" >/dev/null 2>&1 || true
    echo "备用入口移除失败，已恢复 ${removed_port}/UDP。" >&2
    return 1
  fi
  rm -f -- "${state_backup}"
  state_backup=""
  trap - RETURN
  refresh_ports_registry
  record_audit "remove-${profile}-port" "${removed_port}" "-"
  green "已移除 AWG ${profile} 的 ${removed_port}/UDP；保留 ${AWG_BACKUP_PORT1}/UDP，主隧道未重启。"
}

kernel_check() {
  local failed=0
  local running_kernel=""
  local default_kernel=""
  local default_target=""
  local kernel=""
  local kernel_dir=""
  local dkms_output=""
  local kernels=()
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "内核检查通过（测试模式）。"
    return 0
  fi
  command -v awg >/dev/null 2>&1 || { echo "缺少 awg。" >&2; failed=1; }
  command -v awg-quick >/dev/null 2>&1 || { echo "缺少 awg-quick。" >&2; failed=1; }
  command -v dkms >/dev/null 2>&1 || { echo "缺少 dkms。" >&2; failed=1; }

  running_kernel="${RUNNING_KERNEL:-$(uname -r)}"
  default_kernel="${DEFAULT_KERNEL:-}"
  if [[ -z "${default_kernel}" && -e /vmlinuz ]]; then
    default_target="$(readlink -f /vmlinuz 2>/dev/null || true)"
    [[ "${default_target##*/}" == vmlinuz-* ]] && \
      default_kernel="${default_target##*/vmlinuz-}"
  fi
  kernels=("${running_kernel}")
  if [[ -n "${default_kernel}" && "${default_kernel}" != "${running_kernel}" ]]; then
    kernels+=("${default_kernel}")
  fi

  dkms_output="$(dkms status 2>/dev/null || true)"
  for kernel in "${kernels[@]}"; do
    kernel_dir="${MODULES_DIR}/${kernel}"
    if [[ ! -d "${kernel_dir}" ]]; then
      echo "内核 ${kernel} 缺少模块目录。" >&2
      failed=1
      continue
    fi
    if [[ ! -e "${kernel_dir}/build" ]]; then
      echo "内核 ${kernel} 缺少构建目录。" >&2
      failed=1
    fi
    modinfo -k "${kernel}" amneziawg >/dev/null 2>&1 || {
      echo "内核 ${kernel} 找不到 amneziawg 模块。" >&2
      failed=1
    }
    awk -v wanted="${kernel}" '
      index($0, "amneziawg/") == 1 &&
      index($0, ", " wanted ",") > 0 &&
      /: installed$/ { found=1 }
      END { exit !found }
    ' <<< "${dkms_output}" || {
      echo "DKMS 未报告内核 ${kernel} 的 amneziawg 模块已安装。" >&2
      failed=1
    }
  done
  (( failed == 0 )) || return 1
  green "内核检查通过，可以人工安排重启。"
}

start_service() {
  load_state
  systemctl enable --now "awg-quick@${AWG_IFACE}.service"
}

stop_service() {
  load_state
  systemctl stop "awg-quick@${AWG_IFACE}.service" || true
  if command -v nft >/dev/null 2>&1; then
    nft list table inet server_kit_amneziawg_filter >/dev/null 2>&1 && \
      nft delete table inet server_kit_amneziawg_filter || true
    nft list table ip server_kit_amneziawg_nat >/dev/null 2>&1 && \
      nft delete table ip server_kit_amneziawg_nat || true
  fi
  echo "AmneziaWG 已停止，临时 nftables 规则已清理；配置和密钥均未删除。"
}

restart_service() {
  load_state
  systemctl restart "awg-quick@${AWG_IFACE}.service"
}

status_service() {
  load_state
  systemctl --no-pager --full status "awg-quick@${AWG_IFACE}.service"
  awg show "${AWG_IFACE}"
}

usage() {
  cat <<EOF
说明：install 只安装 AmneziaWG；普通节点私钥必须在客户端生成。

安装与节点：
  bash $0 install
  printf '<预共享密钥>\\n' | bash $0 import-public <名称> <客户端公钥> [10.20.0.x]
  printf '<预共享密钥>\\n' | bash $0 enroll <名称> <客户端公钥> [10.20.0.x]
  bash $0 remove <名称>
  bash $0 enable <名称>
  bash $0 disable <名称>
  bash $0 list
  bash $0 endpoints
  bash $0 set-backup-port backup1 <1-9999>
  bash $0 remove-backup-port <backup1|backup2>
  bash $0 show-obfuscation
  bash $0 audit

访问控制（目标与端口独立；省略端口表示全部端口）：
  bash $0 access-allow <节点> <目标节点|vps|all> [端口列表或范围，如22,8000-8010] [tcp|udp]
  bash $0 access-deny <节点> <目标节点|vps|all> [端口列表或范围，如22,8000-8010] [all|tcp|udp]

服务：
  bash $0 start|stop|restart|status
  bash $0 kernel-check

注意：主入口与备用入口共用同一身份，任何时刻只能启用一份客户端配置。
EOF
}

main() {
  require_root
  check_debian
  case "${1:-}" in
    install) install_and_run ;;
    import-public) add_external_peer "${2:-}" "${4:-}" "${3:-}" ;;
    enroll) enroll_peer "${2:-}" "${4:-}" "${3:-}" ;;
    enrollment-context) show_enrollment_context ;;
    enrollment-reconcile) reconcile_enrollments ;;
    enrollment-status) show_enrollments ;;
    remove|delete) remove_peer "${2:-}" ;;
    enable) set_peer_enabled "${2:-}" 1 ;;
    disable) set_peer_enabled "${2:-}" 0 ;;
    list) list_peers ;;
    endpoints) show_endpoints ;;
    set-backup-port)
      [[ -n "${2:-}" && -n "${3:-}" && -z "${4:-}" ]] || {
        echo "用法：set-backup-port backup1 <1-9999>" >&2
        return 1
      }
      set_backup_port "${2}" "${3}"
      ;;
    remove-backup-port)
      [[ -n "${2:-}" && -z "${3:-}" ]] || {
        echo "用法：remove-backup-port <backup1|backup2>" >&2
        return 1
      }
      remove_backup_port "${2}"
      ;;
    show-obfuscation) show_obfuscation ;;
    access-mode) change_access_policy mode "${2:-}" "${3:-}" ;;
    access-allow-batch)
      [[ -n "${2:-}" && $# -eq 2 ]] || { echo "用法：access-allow-batch <节点>（JSON 规则从标准输入读取）" >&2; return 1; }
      change_access_policy allow-batch "${2}"
      ;;
    access-allow)
      if [[ -z "${4:-}" ]]; then
        change_access_policy allow "${2:-}" "${3:-}"
      else
        change_access_policy allow "${2:-}" "${3:-}" "${4:-}" "${5:-tcp}"
      fi
      ;;
    access-deny)
      if [[ -z "${5:-}" ]]; then
        change_access_policy deny "${2:-}" "${3:-}"
      else
        change_access_policy deny "${2:-}" "${3:-}" "${4:-}" "${5:-}"
      fi
      ;;
    audit) show_audit ;;
    kernel-check) kernel_check ;;
    start) start_service ;;
    stop) stop_service ;;
    restart) restart_service ;;
    status) status_service ;;
    help|-h|--help) usage ;;
    *) usage; exit 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  SCRIPT_PATH="$(realpath -m -- "$0")"
  SCRIPT_DIR="$(dirname -- "${SCRIPT_PATH}")"
  main "$@"
else
  SCRIPT_PATH="${BASH_SOURCE[0]}"
  SCRIPT_DIR="$(cd "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
fi
