#!/usr/bin/env bash

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_PATH}" ]]; do
  SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
  SCRIPT_PATH="$(readlink -- "${SCRIPT_PATH}")"
  [[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="${SCRIPT_LINK_DIR}/${SCRIPT_PATH}"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"

SERVER_KIT_DIR="${SERVER_KIT_DIR:-/etc/server-kit}"
MOSH_STATE_PATH="${MOSH_STATE_PATH:-${SERVER_KIT_DIR}/mosh.conf}"
AWG_STATE_PATH="${AWG_STATE_PATH:-/etc/amneziawg/manager.conf}"
SECURITY_MANAGER="${SECURITY_MANAGER:-${SCRIPT_DIR}/debian_security_manager.sh}"
FIREWALL_MANAGER="${FIREWALL_MANAGER:-${SCRIPT_DIR}/debian_firewall_manager.sh}"
APT_GET_BIN="${APT_GET_BIN:-/usr/bin/apt-get}"
DPKG_QUERY_BIN="${DPKG_QUERY_BIN:-/usr/bin/dpkg-query}"
NFT_BIN="${NFT_BIN:-/usr/sbin/nft}"
PGREP_BIN="${PGREP_BIN:-/usr/bin/pgrep}"
PKILL_BIN="${PKILL_BIN:-/usr/bin/pkill}"
MOSH_PORT_START_DEFAULT="${MOSH_PORT_START_DEFAULT:-${MOSH_PORT_DEFAULT:-60001}}"
MOSH_PORT_END_DEFAULT="${MOSH_PORT_END_DEFAULT:-60010}"
MOSH_PORT_DEFAULT="${MOSH_PORT_DEFAULT:-${MOSH_PORT_START_DEFAULT}}"

fail() {
  echo "错误：$*" >&2
  return 1
}

require_platform() {
  if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
    return 0
  fi
  [[ "${EUID}" -eq 0 ]] || { fail "请使用 root 运行。"; exit 1; }
  [[ -r /etc/os-release ]] || { fail "无法识别当前系统。"; exit 1; }
  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" != "debian" ]] && [[ "${ID_LIKE:-}" != *"debian"* ]]; then
    fail "此脚本仅支持 Debian 或 Debian 系发行版。"
    exit 1
  fi
}

read_shell_value() {
  local path="$1"
  local key="$2"
  [[ -r "${path}" ]] || return 1
  python3 - "${path}" "${key}" <<'PYTHON'
import shlex
import sys

path, wanted = sys.argv[1:]
for raw in open(path, encoding="utf-8"):
    line = raw.strip()
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

validate_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

prepare_state_dir() {
  if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
    mkdir -p -- "${SERVER_KIT_DIR}"
  else
    install -d -m 700 "${SERVER_KIT_DIR}"
  fi
}

install_private_file() {
  local source="$1"
  local destination="$2"
  if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
    cp -- "${source}" "${destination}"
  else
    install -m 600 -o root -g root "${source}" "${destination}"
  fi
}

load_awg_boundary() {
  AWG_INTERFACE="$(read_shell_value "${AWG_STATE_PATH}" AWG_IFACE 2>/dev/null || true)"
  AWG_BIND_IP="$(read_shell_value "${AWG_STATE_PATH}" AWG_SERVER_IP 2>/dev/null || true)"
  AWG_SUBNET="$(read_shell_value "${AWG_STATE_PATH}" AWG_SUBNET_CIDR 2>/dev/null || true)"
  [[ -n "${AWG_INTERFACE}" && -n "${AWG_BIND_IP}" && -n "${AWG_SUBNET}" ]] ||
    { fail "AWG 配置缺少接口、服务端地址或网段：${AWG_STATE_PATH}"; return 1; }
  python3 - "${AWG_BIND_IP}" "${AWG_SUBNET}" <<'PYTHON'
import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
network = ipaddress.ip_network(sys.argv[2], strict=False)
if address.version != 4 or address not in network:
    raise SystemExit("AWG 服务端地址不在配置网段内")
PYTHON
}

write_state() {
  local enabled="$1"
  local temp_path=""
  prepare_state_dir
  temp_path="$(mktemp "${SERVER_KIT_DIR}/.mosh.XXXXXX")"
  cat > "${temp_path}" <<EOF
MOSH_ENABLED=${enabled}
MOSH_PORT=${MOSH_PORT_START_DEFAULT}
MOSH_PORT_START=${MOSH_PORT_START_DEFAULT}
MOSH_PORT_END=${MOSH_PORT_END_DEFAULT}
MOSH_BIND_IP=${AWG_BIND_IP}
MOSH_INTERFACE=${AWG_INTERFACE}
MOSH_SUBNET_CIDR=${AWG_SUBNET}
EOF
  install_private_file "${temp_path}" "${MOSH_STATE_PATH}"
  rm -f -- "${temp_path}"
}

package_installed() {
  "${DPKG_QUERY_BIN}" -W -f='${Status}' mosh 2>/dev/null | grep -Fqx 'install ok installed'
}

verify_firewall_boundary() {
  local chain_text=""
  local set_text=""
  local public_text=""
  local port=0
  chain_text="$("${NFT_BIN}" list chain inet server_kit_filter input)"
  set_text="$("${NFT_BIN}" list set inet server_kit_filter awg_udp_ports)"
  public_text="$("${NFT_BIN}" list set inet server_kit_filter public_udp_ports)"
  grep -Fq "iifname \"${AWG_INTERFACE}\" ip saddr ${AWG_SUBNET} ip daddr ${AWG_BIND_IP} udp dport @awg_udp_ports" <<< "${chain_text}" ||
    { fail "防火墙没有生成仅 AWG 的 Mosh 规则。"; return 1; }
  for ((port = MOSH_PORT_START_DEFAULT; port <= MOSH_PORT_END_DEFAULT; port++)); do
    grep -Eq "(^|[^0-9])${port}([^0-9]|$)" <<< "${set_text}" ||
      { fail "AWG UDP 集合没有包含 ${port}。"; return 1; }
    if grep -Eq "(^|[^0-9])${port}([^0-9]|$)" <<< "${public_text}"; then
      fail "检测到 Mosh 端口 ${port} 进入公网 UDP 集合，拒绝确认。"
      return 1
    fi
  done
}

firewall_has_mosh() {
  local set_text=""
  local port=0
  set_text="$("${NFT_BIN}" list set inet server_kit_filter awg_udp_ports 2>/dev/null)" || return 1
  for ((port = MOSH_PORT_START_DEFAULT; port <= MOSH_PORT_END_DEFAULT; port++)); do
    grep -Eq "(^|[^0-9])${port}([^0-9]|$)" <<< "${set_text}" || return 1
  done
}

firewall_has_any_mosh() {
  local set_text=""
  local port=0
  set_text="$("${NFT_BIN}" list set inet server_kit_filter awg_udp_ports 2>/dev/null)" || return 1
  for ((port = MOSH_PORT_START_DEFAULT; port <= MOSH_PORT_END_DEFAULT; port++)); do
    if grep -Eq "(^|[^0-9])${port}([^0-9]|$)" <<< "${set_text}"; then
      return 0
    fi
  done
  return 1
}

reconcile_firewall() {
  local expect_enabled="$1"
  bash "${SECURITY_MANAGER}" refresh-ports --quiet
  bash "${FIREWALL_MANAGER}" apply --yes
  if [[ "${expect_enabled}" == "yes" ]]; then
    verify_firewall_boundary || {
      bash "${FIREWALL_MANAGER}" rollback || true
      return 1
    }
  elif firewall_has_any_mosh; then
    bash "${FIREWALL_MANAGER}" rollback || true
    fail "停止后 Mosh 端口仍在 AWG 放行集合中。"
    return 1
  fi
  bash "${FIREWALL_MANAGER}" confirm --yes
}

install_mosh() {
  local backup_path=""
  load_awg_boundary
  validate_port "${MOSH_PORT_START_DEFAULT}" || { fail "Mosh 起始端口无效：${MOSH_PORT_START_DEFAULT}"; return 1; }
  validate_port "${MOSH_PORT_END_DEFAULT}" || { fail "Mosh 结束端口无效：${MOSH_PORT_END_DEFAULT}"; return 1; }
  (( MOSH_PORT_START_DEFAULT <= MOSH_PORT_END_DEFAULT )) ||
    { fail "Mosh 端口范围无效：${MOSH_PORT_START_DEFAULT}-${MOSH_PORT_END_DEFAULT}"; return 1; }
  if [[ -e "${MOSH_STATE_PATH}" ]]; then
    backup_path="$(mktemp "${SERVER_KIT_DIR}/.mosh-backup.XXXXXX")"
    cp -a -- "${MOSH_STATE_PATH}" "${backup_path}"
  fi
  if ! package_installed; then
    DEBIAN_FRONTEND=noninteractive "${APT_GET_BIN}" update
    DEBIAN_FRONTEND=noninteractive "${APT_GET_BIN}" install -y mosh tmux
  fi
  write_state yes
  if ! reconcile_firewall yes; then
    if [[ -n "${backup_path}" ]]; then
      install_private_file "${backup_path}" "${MOSH_STATE_PATH}"
    else
      rm -f -- "${MOSH_STATE_PATH}"
    fi
    rm -f -- "${backup_path}"
    return 1
  fi
  rm -f -- "${backup_path}"
  echo "Mosh 已安装并仅向 AWG 内网开放。"
  echo "范围：${AWG_INTERFACE} / ${AWG_SUBNET} → ${AWG_BIND_IP}:${MOSH_PORT_START_DEFAULT}-${MOSH_PORT_END_DEFAULT}/UDP"
  echo "连接：mosh -p ${MOSH_PORT_START_DEFAULT}:${MOSH_PORT_END_DEFAULT} --bind-server=${AWG_BIND_IP} root@${AWG_BIND_IP} -- tmux new -As main"
}

stop_mosh() {
  local old_state=""
  load_awg_boundary
  if [[ -r "${MOSH_STATE_PATH}" ]]; then
    old_state="$(mktemp "${SERVER_KIT_DIR}/.mosh-backup.XXXXXX")"
    cp -a -- "${MOSH_STATE_PATH}" "${old_state}"
  fi
  write_state no
  if ! reconcile_firewall no; then
    [[ -n "${old_state}" ]] && install_private_file "${old_state}" "${MOSH_STATE_PATH}"
    rm -f -- "${old_state}"
    return 1
  fi
  rm -f -- "${old_state}"
  "${PKILL_BIN}" -x mosh-server 2>/dev/null || true
  echo "Mosh 已停止，活动会话和 AWG 放行规则均已清理。"
}

uninstall_mosh() {
  local confirm="${1:-}"
  local answer=""
  if [[ "${confirm}" != "--yes" ]]; then
    if [[ ! -t 0 ]]; then
      fail "卸载会终止全部 Mosh 会话，请加 --yes。"
      return 1
    fi
    read -r -p "将终止会话、撤销端口并卸载 Mosh，是否继续？[y/N]: " answer
    case "${answer,,}" in y|yes) ;; *) echo "已取消。"; return 1 ;; esac
  fi
  stop_mosh
  rm -f -- "${MOSH_STATE_PATH}"
  if package_installed; then
    DEBIAN_FRONTEND=noninteractive "${APT_GET_BIN}" purge -y mosh
  fi
  bash "${SECURITY_MANAGER}" refresh-ports --quiet
  echo "Mosh 已彻底卸载。"
}

show_status() {
  local enabled="no"
  local sessions=0
  local firewall="未放行"
  local package="未安装"
  local port_start="${MOSH_PORT_START_DEFAULT}"
  local port_end="${MOSH_PORT_END_DEFAULT}"
  load_awg_boundary
  if [[ -r "${MOSH_STATE_PATH}" ]]; then
    enabled="$(read_shell_value "${MOSH_STATE_PATH}" MOSH_ENABLED 2>/dev/null || true)"
    port_start="$(read_shell_value "${MOSH_STATE_PATH}" MOSH_PORT_START 2>/dev/null || read_shell_value "${MOSH_STATE_PATH}" MOSH_PORT 2>/dev/null || echo "${MOSH_PORT_START_DEFAULT}")"
    port_end="$(read_shell_value "${MOSH_STATE_PATH}" MOSH_PORT_END 2>/dev/null || echo "${port_start}")"
  fi
  package_installed && package="已安装"
  firewall_has_mosh && firewall="AWG 内网已放行"
  sessions="$("${PGREP_BIN}" -xc mosh-server 2>/dev/null || true)"
  sessions="${sessions:-0}"
  echo "Mosh 状态"
  echo "状态：$([[ "${enabled}" == "yes" ]] && echo "已启用" || echo "已停止")"
  echo "软件包：${package}"
  echo "范围：仅 AWG ${AWG_SUBNET}"
  echo "监听：${AWG_BIND_IP}:${port_start}-${port_end}/UDP（按需启动）"
  echo "防火墙：${firewall}"
  echo "活动会话：${sessions}"
  echo "连接：mosh -p ${port_start}:${port_end} --bind-server=${AWG_BIND_IP} root@${AWG_BIND_IP} -- tmux new -As main"
}

usage() {
  cat <<EOF
说明：Mosh 仅通过 AWG 内网访问，使用 UDP ${MOSH_PORT_START_DEFAULT}-${MOSH_PORT_END_DEFAULT}，可支持多个并发窗口，不会开放公网端口。

用法：
  bash $0 install          安装并启用
  bash $0 status           查看状态和连接命令
  bash $0 stop             终止会话并撤销端口
  bash $0 uninstall --yes  彻底卸载
EOF
}

main() {
  require_platform
  case "${1:-}" in
    install) install_mosh ;;
    status) show_status ;;
    stop) stop_mosh ;;
    uninstall) uninstall_mosh "${2:-}" ;;
    help|-h|--help) usage ;;
    *) usage; exit 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
