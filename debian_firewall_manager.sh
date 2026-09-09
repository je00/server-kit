#!/usr/bin/env bash

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_PATH}" ]]; do
  SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
  SCRIPT_PATH="$(readlink -- "${SCRIPT_PATH}")"
  [[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="${SCRIPT_LINK_DIR}/${SCRIPT_PATH}"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename -- "${SCRIPT_PATH}")"

SERVER_KIT_DIR="${SERVER_KIT_DIR:-/etc/server-kit}"
PORTS_PATH="${PORTS_PATH:-${SERVER_KIT_DIR}/ports.json}"
CANDIDATE_PATH="${CANDIDATE_PATH:-${SERVER_KIT_DIR}/firewall-candidate.nft}"
ACTIVE_RULES_PATH="${ACTIVE_RULES_PATH:-${SERVER_KIT_DIR}/firewall.nft}"
TRANSACTION_PATH="${TRANSACTION_PATH:-${SERVER_KIT_DIR}/firewall-transaction.json}"
CUSTOM_PORTS_PATH="${CUSTOM_PORTS_PATH:-${SERVER_KIT_DIR}/custom-ports.json}"
BACKUP_DIR="${BACKUP_DIR:-${SERVER_KIT_DIR}/backups/firewall}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/server-kit-firewall.service}"
SECURITY_MANAGER="${SECURITY_MANAGER:-${SCRIPT_DIR}/debian_security_manager.sh}"
PORT_FACTS_HELPER="${PORT_FACTS_HELPER:-${SCRIPT_DIR}/lib/server_kit_port_facts.py}"
NFT_BIN="${NFT_BIN:-/usr/sbin/nft}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-/usr/bin/systemctl}"
SYSTEMD_RUN_BIN="${SYSTEMD_RUN_BIN:-/usr/bin/systemd-run}"
SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"
IP_BIN="${IP_BIN:-/usr/sbin/ip}"
AWG_STATE_PATH="${AWG_STATE_PATH:-/etc/amneziawg/manager.conf}"
ROLLBACK_SECONDS="${ROLLBACK_SECONDS:-300}"
ROLLBACK_UNIT="server-kit-firewall-rollback"
TABLE_FAMILY="inet"
TABLE_NAME="server_kit_filter"

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

detect_public_interface() {
  "${IP_BIN}" -4 route show default 2>/dev/null |
    awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}'
}

detect_public_ipv4() {
  "${IP_BIN}" -4 route get 1.1.1.1 2>/dev/null |
    sed -n 's/.*[[:space:]]src[[:space:]]\([^[:space:]]*\).*/\1/p' | head -n 1
}

refresh_and_audit_ports() {
  [[ -x "${SECURITY_MANAGER}" || -r "${SECURITY_MANAGER}" ]] ||
    { fail "缺少安全管理器：${SECURITY_MANAGER}"; return 1; }
  bash "${SECURITY_MANAGER}" refresh-ports --quiet
  bash "${SECURITY_MANAGER}" audit-ports
}

generate_candidate() {
  local public_interface="${PUBLIC_INTERFACE:-}"
  local public_ipv4="${PUBLIC_IPV4:-}"
  local awg_interface=""
  local awg_ipv4=""
  local awg_subnet=""
  local temp_path=""

  public_interface="${public_interface:-$(detect_public_interface)}"
  public_ipv4="${public_ipv4:-$(detect_public_ipv4)}"
  awg_interface="$(read_shell_value "${AWG_STATE_PATH}" AWG_IFACE 2>/dev/null || true)"
  awg_ipv4="$(read_shell_value "${AWG_STATE_PATH}" AWG_SERVER_IP 2>/dev/null || true)"
  awg_subnet="$(read_shell_value "${AWG_STATE_PATH}" AWG_SUBNET_CIDR 2>/dev/null || true)"
  [[ -n "${public_interface}" && -n "${public_ipv4}" ]] ||
    { fail "无法检测公网接口或 IPv4。"; return 1; }
  [[ -n "${awg_interface}" && -n "${awg_ipv4}" && -n "${awg_subnet}" ]] ||
    { fail "AWG 状态缺少接口、地址或网段。"; return 1; }
  [[ -r "${PORTS_PATH}" ]] || { fail "端口清单不存在：${PORTS_PATH}"; return 1; }

  install -d -m 700 "${SERVER_KIT_DIR}"
  temp_path="$(mktemp "${SERVER_KIT_DIR}/.firewall-candidate.XXXXXX")"
  [[ -r "${PORT_FACTS_HELPER}" ]] || {
    rm -f -- "${temp_path}"
    fail "缺少端口事实组件：${PORT_FACTS_HELPER}"
    return 1
  }
  if ! python3 "${PORT_FACTS_HELPER}" render-nft \
    --ports "${PORTS_PATH}" \
    --output "${temp_path}" \
    --public-interface "${public_interface}" \
    --public-ipv4 "${public_ipv4}" \
    --awg-interface "${awg_interface}" \
    --awg-ipv4 "${awg_ipv4}" \
    --awg-subnet "${awg_subnet}"; then
    rm -f -- "${temp_path}"
    return 1
  fi
  install -m 600 -o root -g root "${temp_path}" "${CANDIDATE_PATH}"
  rm -f -- "${temp_path}"
}

table_exists() {
  "${NFT_BIN}" list table "${TABLE_FAMILY}" "${TABLE_NAME}" >/dev/null 2>&1
}

build_load_batch() {
  local rules_path="$1"
  local batch_path="$2"
  if table_exists; then
    printf 'delete table %s %s\n' "${TABLE_FAMILY}" "${TABLE_NAME}" > "${batch_path}"
  else
    : > "${batch_path}"
  fi
  sed -e '1{/^#!\//d;}' "${rules_path}" >> "${batch_path}"
}

check_rules_file() {
  local rules_path="$1"
  local batch_path=""
  batch_path="$(mktemp "${SERVER_KIT_DIR}/.firewall-check.XXXXXX")"
  build_load_batch "${rules_path}" "${batch_path}"
  "${NFT_BIN}" --check --file "${batch_path}"
  rm -f -- "${batch_path}"
}

load_rules_file() {
  local rules_path="$1"
  local batch_path=""
  batch_path="$(mktemp "${SERVER_KIT_DIR}/.firewall-load.XXXXXX")"
  build_load_batch "${rules_path}" "${batch_path}"
  "${NFT_BIN}" --check --file "${batch_path}"
  "${NFT_BIN}" --file "${batch_path}"
  rm -f -- "${batch_path}"
  table_exists
  restore_custom_ports
}

delete_owned_table() {
  if table_exists; then
    "${NFT_BIN}" delete table "${TABLE_FAMILY}" "${TABLE_NAME}"
  fi
}

ssh_auth_is_hardened() {
  local effective=""
  effective="$("${SSHD_BIN}" -T 2>/dev/null)" || return 1
  grep -Fxq 'passwordauthentication no' <<< "${effective}" &&
    grep -Fxq 'kbdinteractiveauthentication no' <<< "${effective}" &&
    grep -Eq '^permitrootlogin (prohibit-password|without-password)$' <<< "${effective}" &&
    grep -Fxq 'authenticationmethods publickey' <<< "${effective}"
}

create_transaction() {
  local existed="false"
  local backup_path=""
  local temp_path=""
  local timestamp=""
  install -d -m 700 "${SERVER_KIT_DIR}" "${BACKUP_DIR}"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if table_exists; then
    existed="true"
    backup_path="${BACKUP_DIR}/server-kit-filter.${timestamp}.nft"
    "${NFT_BIN}" list table "${TABLE_FAMILY}" "${TABLE_NAME}" > "${backup_path}"
    chmod 600 "${backup_path}"
  fi
  temp_path="$(mktemp "${SERVER_KIT_DIR}/.firewall-transaction.XXXXXX")"
  python3 - "${temp_path}" "${existed}" "${backup_path}" "${CANDIDATE_PATH}" <<'PYTHON'
import json
import os
import sys
from datetime import datetime, timezone

path, existed, backup_path, candidate_path = sys.argv[1:]
value = {
    "status": "staged",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "table_existed": existed == "true",
    "backup_path": backup_path,
    "candidate_path": candidate_path,
}
with open(path, "w", encoding="utf-8", newline="\n") as output:
    json.dump(value, output, ensure_ascii=False, indent=2)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
PYTHON
  install -m 600 -o root -g root "${temp_path}" "${TRANSACTION_PATH}"
  rm -f -- "${temp_path}"
}

transaction_field() {
  python3 - "${TRANSACTION_PATH}" "$1" <<'PYTHON'
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

cancel_rollback() {
  "${SYSTEMCTL_BIN}" stop "${ROLLBACK_UNIT}.timer" "${ROLLBACK_UNIT}.service" \
    >/dev/null 2>&1 || true
  "${SYSTEMCTL_BIN}" reset-failed "${ROLLBACK_UNIT}.service" >/dev/null 2>&1 || true
}

schedule_rollback() {
  cancel_rollback
  "${SYSTEMD_RUN_BIN}" --quiet --unit="${ROLLBACK_UNIT}" \
    --on-active="${ROLLBACK_SECONDS}s" --timer-property=AccuracySec=1s \
    "${SCRIPT_PATH}" rollback --automatic
}

rollback() {
  local automatic="${1:-}"
  local existed=""
  local backup_path=""
  if [[ ! -r "${TRANSACTION_PATH}" ]]; then
    [[ "${automatic}" == "--automatic" ]] || echo "当前没有待回滚的防火墙事务。"
    return 0
  fi
  existed="$(transaction_field table_existed)"
  backup_path="$(transaction_field backup_path)"
  if [[ "${existed}" == "true" ]]; then
    [[ -r "${backup_path}" ]] || { fail "防火墙备份不存在：${backup_path}"; return 1; }
    load_rules_file "${backup_path}"
  else
    delete_owned_table
  fi
  rm -f -- "${TRANSACTION_PATH}"
  cancel_rollback
  if [[ "${automatic}" == "--automatic" ]]; then
    echo "防火墙未在时限内确认，已自动回滚。"
  else
    echo "防火墙已回滚。"
  fi
}

write_systemd_service() {
  local temp_path=""
  install -d -m 755 "$(dirname -- "${SERVICE_PATH}")"
  temp_path="$(mktemp "$(dirname -- "${SERVICE_PATH}")/.server-kit-firewall.XXXXXX")"
  cat > "${temp_path}" <<EOF
[Unit]
Description=server-kit 独立 nftables 防火墙
After=network-online.target awg-quick@awg0.service
Wants=network-online.target awg-quick@awg0.service

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH} restore-active
ExecStop=${SCRIPT_PATH} runtime-stop
RemainAfterExit=yes
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
  install -m 644 -o root -g root "${temp_path}" "${SERVICE_PATH}"
  rm -f -- "${temp_path}"
  "${SYSTEMCTL_BIN}" daemon-reload
}

show_plan() {
  refresh_and_audit_ports
  generate_candidate
  echo
  echo "=== server-kit 防火墙候选规则 ==="
  sed -n '1,220p' "${CANDIDATE_PATH}"
  echo "候选文件：${CANDIDATE_PATH}"
  echo "说明：plan/check 不会应用规则。"
}

check_candidate() {
  refresh_and_audit_ports
  generate_candidate
  check_rules_file "${CANDIDATE_PATH}"
  echo "候选规则校验通过：${CANDIDATE_PATH}"
}

apply_candidate() {
  local confirm="${1:-}"
  [[ "${confirm}" == "--yes" ]] || { fail "应用防火墙必须加 --yes。"; return 1; }
  [[ ! -r "${TRANSACTION_PATH}" ]] || { fail "已有待确认事务，请先确认或回滚。"; return 1; }
  ssh_auth_is_hardened || { fail "SSH 尚未完成仅密钥登录加固。"; return 1; }
  if "${SYSTEMCTL_BIN}" is-active --quiet nftables.service; then
    fail "系统 nftables.service 正在运行，拒绝与其并行接管。"
    return 1
  fi
  refresh_and_audit_ports
  generate_candidate
  check_rules_file "${CANDIDATE_PATH}"
  create_transaction
  if ! schedule_rollback; then
    rm -f -- "${TRANSACTION_PATH}"
    fail "无法安排自动回滚，未应用规则。"
    return 1
  fi
  if ! load_rules_file "${CANDIDATE_PATH}"; then
    rollback
    fail "候选规则应用失败，已回滚。"
    return 1
  fi
  echo "防火墙已进入待确认阶段，${ROLLBACK_SECONDS} 秒后自动回滚。"
  echo "请立即新建并验证：公网 SSH、AWG SSH、VLESS、Clash 订阅和 AWG 两个 UDP 入口。"
  echo "全部成功后运行：${SCRIPT_PATH} confirm --yes"
}

confirm_candidate() {
  local confirm="${1:-}"
  [[ "${confirm}" == "--yes" ]] || { fail "确认前请完成独立连接验证，并加 --yes。"; return 1; }
  [[ -r "${TRANSACTION_PATH}" ]] || { fail "没有待确认事务。"; return 1; }
  table_exists || { rollback; fail "防火墙表不存在，已回滚。"; return 1; }
  install -m 600 -o root -g root "${CANDIDATE_PATH}" "${ACTIVE_RULES_PATH}"
  write_systemd_service
  "${SYSTEMCTL_BIN}" enable --now server-kit-firewall.service >/dev/null
  rm -f -- "${TRANSACTION_PATH}"
  cancel_rollback
  echo "防火墙已确认并持久化：${ACTIVE_RULES_PATH}"
}

restore_active() {
  local public_interface=""
  local rendered_path=""
  local previous_interface=""
  [[ -r "${ACTIVE_RULES_PATH}" ]] || { fail "缺少已确认规则：${ACTIVE_RULES_PATH}"; return 1; }
  public_interface="$(detect_public_interface)"
  [[ -n "${public_interface}" ]] || {
    fail "默认 IPv4 路由尚未就绪，稍后重试加载防火墙。"
    return 1
  }
  rendered_path="$(mktemp "${SERVER_KIT_DIR}/.firewall-restore.XXXXXX")"
  previous_interface="$(python3 - "${ACTIVE_RULES_PATH}" "${rendered_path}" "${public_interface}" <<'PYTHON'
import os
import re
import sys

source_path, target_path, current_interface = sys.argv[1:]
interface_pattern = r"[A-Za-z0-9_.:-]{1,32}"
if re.fullmatch(interface_pattern, current_interface) is None:
    raise SystemExit("探测到的公网接口名无效")

with open(source_path, encoding="utf-8") as source:
    text = source.read()
if not text.startswith("# 此文件由 debian_firewall_manager.sh 生成，请勿直接修改。\n"):
    raise SystemExit("持久防火墙规则不是 server-kit 生成的文件")

line_pattern = re.compile(
    r'^(\s*meta nfproto ipv4 iifname ")(' + interface_pattern + r')'
    r'(" (?:tcp dport @(?:public_tcp_ports|temporary_public_tcp_ports)'
    r'|udp dport @(?:public_udp_ports|temporary_public_udp_ports)) counter accept\s*)$',
    re.MULTILINE,
)
matches = list(line_pattern.finditer(text))
expected = {
    "tcp dport @public_tcp_ports",
    "tcp dport @temporary_public_tcp_ports",
    "udp dport @public_udp_ports",
    "udp dport @temporary_public_udp_ports",
}
observed = {
    match.group(3).split('" ', 1)[1].rsplit(" counter accept", 1)[0]
    for match in matches
}
interfaces = {match.group(2) for match in matches}
if len(matches) != 4 or observed != expected or len(interfaces) != 1:
    raise SystemExit("持久防火墙规则的公网接口绑定结构无效")

previous_interface = next(iter(interfaces))
rewritten = line_pattern.sub(
    lambda match: match.group(1) + current_interface + match.group(3), text,
)
with open(target_path, "w", encoding="utf-8", newline="\n") as target:
    target.write(rewritten)
    target.flush()
    os.fsync(target.fileno())
print(previous_interface)
PYTHON
)" || {
    rm -f -- "${rendered_path}"
    fail "无法安全解析持久防火墙的公网接口绑定。"
    return 1
  }
  if [[ "${previous_interface}" == "${public_interface}" ]]; then
    rm -f -- "${rendered_path}"
    load_rules_file "${ACTIVE_RULES_PATH}"
    return
  fi
  if ! check_rules_file "${rendered_path}" || ! load_rules_file "${rendered_path}"; then
    rm -f -- "${rendered_path}"
    fail "公网接口从 ${previous_interface} 变为 ${public_interface}，但新规则校验或加载失败；持久规则未修改。"
    return 1
  fi
  install -m 600 -o root -g root "${rendered_path}" "${ACTIVE_RULES_PATH}"
  rm -f -- "${rendered_path}"
  echo "检测到公网接口变化：${previous_interface} -> ${public_interface}；已安全更新并加载防火墙规则。"
}

refresh_service() {
  local current_public_interface=""
  local persisted_public_interface=""
  [[ -r "${ACTIVE_RULES_PATH}" ]] || { fail "缺少已确认规则：${ACTIVE_RULES_PATH}"; return 1; }
  current_public_interface="$(detect_public_interface)"
  persisted_public_interface="$(sed -n 's/.*meta nfproto ipv4 iifname "\([^"]*\)" tcp dport @public_tcp_ports.*/\1/p' "${ACTIVE_RULES_PATH}" | head -n 1)"
  [[ -n "${current_public_interface}" ]] || {
    fail "默认 IPv4 路由尚未就绪，拒绝刷新防火墙服务。"
    return 1
  }
  if [[ -z "${persisted_public_interface}" ]]; then
    fail "持久防火墙规则缺少有效的公网接口绑定。"
    return 1
  fi
  if [[ "${persisted_public_interface}" != "${current_public_interface}" ]]; then
    restore_active
  fi
  write_systemd_service
  "${SYSTEMCTL_BIN}" enable server-kit-firewall.service >/dev/null
  "${SYSTEMCTL_BIN}" reset-failed server-kit-firewall.service >/dev/null 2>&1 || true
  echo "防火墙开机恢复服务已刷新。"
}

normalize_custom_scope() {
  case "$1" in
    public) printf 'public\n' ;;
    awg|amneziawg|internal) printf 'amneziawg\n' ;;
    *) fail "范围只能是 public 或 awg。"; return 1 ;;
  esac
}

custom_protocols() {
  case "$1" in
    tcp|udp) printf '%s\n' "$1" ;;
    both|tcp,udp) printf 'tcp\nudp\n' ;;
    *) fail "协议只能是 tcp、udp 或 both。"; return 1 ;;
  esac
}

custom_set_name() {
  local scope="$1"
  local protocol="$2"
  local duration="$3"
  if [[ "${duration}" == "temporary" ]]; then
    [[ "${scope}" == "public" ]] && printf 'temporary_public_%s_ports\n' "${protocol}" || printf 'temporary_awg_%s_ports\n' "${protocol}"
  else
    [[ "${scope}" == "public" ]] && printf 'public_%s_ports\n' "${protocol}" || printf 'awg_%s_ports\n' "${protocol}"
  fi
}

validate_custom_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )) || {
    fail "端口必须是 1–65535 的整数。"
    return 1
  }
}

validate_custom_duration() {
  local value="$1"
  if [[ "${value}" == "permanent" ]]; then
    return 0
  fi
  [[ "${value}" =~ ^[0-9]+$ ]] && (( 10#${value} >= 60 && 10#${value} <= 604800 )) || {
    fail "时长必须是 60–604800 秒，或 permanent。"
    return 1
  }
}

update_custom_ports_state() {
  local operation="$1"
  local port="$2"
  local scope="$3"
  local protocol="$4"
  local duration="$5"
  install -d -m 700 "${SERVER_KIT_DIR}"
  python3 - "${CUSTOM_PORTS_PATH}" "${operation}" "${port}" "${scope}" "${protocol}" "${duration}" <<'PYTHON'
import json
import os
import sys
import time

path, operation, port_text, scope, protocol_text, duration = sys.argv[1:]
port = int(port_text)
protocols = [protocol_text] if protocol_text in {"tcp", "udp"} else ["tcp", "udp"]
try:
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
except FileNotFoundError:
    data = {"version": 1, "entries": []}
if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("entries"), list):
    raise SystemExit("自定义端口状态格式无效")
now = int(time.time())
entries = [
    item for item in data["entries"]
    if isinstance(item, dict)
    and (item.get("expires_at", 0) == 0 or item.get("expires_at", 0) > now)
    and not (
        item.get("port") == port
        and item.get("scope") == scope
        and item.get("protocol") in protocols
    )
]
if operation == "open":
    expires_at = 0 if duration == "permanent" else now + int(duration)
    for item_protocol in protocols:
        entries.append({
            "scope": scope,
            "protocol": item_protocol,
            "port": port,
            "expires_at": expires_at,
            "created_at": now,
        })
elif operation != "close":
    raise SystemExit("自定义端口动作无效")
entries.sort(key=lambda item: (item["scope"], item["protocol"], item["port"]))
temporary = f"{path}.tmp.{os.getpid()}"
with open(temporary, "w", encoding="utf-8", newline="\n") as output:
    json.dump({"version": 1, "entries": entries}, output, ensure_ascii=False, indent=2)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PYTHON
}

query_custom_ports() {
  local mode="$1"
  local active="false"
  table_exists && active="true"
  python3 - "${CUSTOM_PORTS_PATH}" "${mode}" "${active}" <<'PYTHON'
import json
import os
import sys
import time
from datetime import datetime, timezone

path, mode, active_text = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
except FileNotFoundError:
    data = {"version": 1, "entries": []}
if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("entries"), list):
    raise SystemExit("自定义端口状态格式无效")
now = int(time.time())
entries = [
    item for item in data["entries"]
    if isinstance(item, dict)
    and item.get("scope") in {"public", "amneziawg"}
    and item.get("protocol") in {"tcp", "udp"}
    and isinstance(item.get("port"), int)
    and 1 <= item["port"] <= 65535
    and isinstance(item.get("expires_at"), int)
    and (item["expires_at"] == 0 or item["expires_at"] > now)
]
if entries != data["entries"] and os.path.exists(path):
    temporary = f"{path}.tmp.{os.getpid()}"
    with open(temporary, "w", encoding="utf-8", newline="\n") as output:
        json.dump({"version": 1, "entries": entries}, output, ensure_ascii=False, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
entries.sort(key=lambda item: (item["scope"], item["protocol"], item["port"]))
if mode == "tsv":
    for item in entries:
        duration = "permanent" if item["expires_at"] == 0 else "temporary"
        remaining = 0 if item["expires_at"] == 0 else item["expires_at"] - now
        print(item["scope"], item["protocol"], item["port"], duration, remaining, sep="\t")
elif mode == "json":
    items = []
    for item in entries:
        permanent = item["expires_at"] == 0
        items.append({
            "scope": item["scope"],
            "scope_label": "公网" if item["scope"] == "public" else "AWG 内网",
            "protocol": item["protocol"],
            "port": item["port"],
            "duration": "permanent" if permanent else "temporary",
            "expires_at": "" if permanent else datetime.fromtimestamp(item["expires_at"], timezone.utc).isoformat(),
            "remaining_seconds": 0 if permanent else item["expires_at"] - now,
            "active": active_text == "true",
        })
    print(json.dumps({"schema_version": 1, "firewall_active": active_text == "true", "items": items}, ensure_ascii=False, separators=(",", ":")))
else:
    raise SystemExit("自定义端口查询格式无效")
PYTHON
}

base_rules_have_port() {
  local scope="$1"
  local protocol="$2"
  local port="$3"
  local set_name=""
  set_name="$(custom_set_name "${scope}" "${protocol}" permanent)"
  [[ -r "${ACTIVE_RULES_PATH}" ]] || return 1
  python3 - "${ACTIVE_RULES_PATH}" "${set_name}" "${port}" <<'PYTHON'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
name, wanted = sys.argv[2], int(sys.argv[3])
match = re.search(rf"set\s+{re.escape(name)}\s*\{{(.*?)\n\s*\}}", text, re.DOTALL)
if not match:
    raise SystemExit(1)
elements = re.search(r"elements\s*=\s*\{([^}]*)\}", match.group(1), re.DOTALL)
values = {int(value) for value in re.findall(r"(?<![\w.])(\d{1,5})(?![\w.])", elements.group(1) if elements else "")}
raise SystemExit(0 if wanted in values else 1)
PYTHON
}

remove_custom_runtime_entry() {
  local scope="$1"
  local protocol="$2"
  local port="$3"
  local duration=""
  local set_name=""
  for duration in permanent temporary; do
    set_name="$(custom_set_name "${scope}" "${protocol}" "${duration}")"
    "${NFT_BIN}" delete element "${TABLE_FAMILY}" "${TABLE_NAME}" "${set_name}" "{ ${port} }" >/dev/null 2>&1 || true
  done
}

add_custom_runtime_entry() {
  local scope="$1"
  local protocol="$2"
  local port="$3"
  local duration="$4"
  local remaining="$5"
  local set_name=""
  set_name="$(custom_set_name "${scope}" "${protocol}" "${duration}")"
  if [[ "${duration}" == "temporary" ]]; then
    "${NFT_BIN}" add element "${TABLE_FAMILY}" "${TABLE_NAME}" "${set_name}" "{ ${port} timeout ${remaining}s }"
  else
    "${NFT_BIN}" add element "${TABLE_FAMILY}" "${TABLE_NAME}" "${set_name}" "{ ${port} }"
  fi
}

runtime_custom_entry_exists() {
  local scope="$1"
  local protocol="$2"
  local port="$3"
  local duration="$4"
  local set_name=""
  local output=""
  set_name="$(custom_set_name "${scope}" "${protocol}" "${duration}")"
  output="$("${NFT_BIN}" list set "${TABLE_FAMILY}" "${TABLE_NAME}" "${set_name}" 2>/dev/null)" || return 1
  NFT_SET_OUTPUT="${output}" python3 - "${port}" <<'PYTHON'
import os
import re
import sys

wanted = int(sys.argv[1])
text = os.environ.get("NFT_SET_OUTPUT", "")
values = {
    int(value)
    for value in re.findall(r"(?<![\w.])(\d{1,5})(?![\w.])", text)
    if 1 <= int(value) <= 65535
}
raise SystemExit(0 if wanted in values else 1)
PYTHON
}

custom_fact_entry_exists() {
  local scope="$1"
  local protocol="$2"
  local port="$3"
  local duration="$4"
  query_custom_ports tsv | awk -F '\t' \
    -v scope="${scope}" -v protocol="${protocol}" -v port="${port}" -v duration="${duration}" \
    '$1 == scope && $2 == protocol && $3 == port && $4 == duration { found = 1 } END { exit(found ? 0 : 1) }'
}

verify_custom_port() {
  local operation="${1:-}"
  local port="${2:-}"
  local requested_scope="${3:-}"
  local requested_protocol="${4:-}"
  local duration_value="${5:-permanent}"
  local format="${6:-}"
  local scope=""
  local protocol=""
  local duration="temporary"
  local facts_ok=true
  local nftables_ok=true
  [[ "${operation}" == "open" || "${operation}" == "close" ]] || return 1
  validate_custom_port "${port}" || return 1
  scope="$(normalize_custom_scope "${requested_scope}")" || return 1
  custom_protocols "${requested_protocol}" >/dev/null || return 1
  [[ "${duration_value}" == "permanent" ]] && duration="permanent"
  while read -r protocol; do
    if [[ "${operation}" == "open" ]]; then
      custom_fact_entry_exists "${scope}" "${protocol}" "${port}" "${duration}" || facts_ok=false
      runtime_custom_entry_exists "${scope}" "${protocol}" "${port}" "${duration}" || nftables_ok=false
      if [[ "${duration}" == "permanent" ]]; then
        runtime_custom_entry_exists "${scope}" "${protocol}" "${port}" temporary && nftables_ok=false
      else
        runtime_custom_entry_exists "${scope}" "${protocol}" "${port}" permanent && nftables_ok=false
      fi
    else
      custom_fact_entry_exists "${scope}" "${protocol}" "${port}" permanent && facts_ok=false
      custom_fact_entry_exists "${scope}" "${protocol}" "${port}" temporary && facts_ok=false
      runtime_custom_entry_exists "${scope}" "${protocol}" "${port}" permanent && nftables_ok=false
      runtime_custom_entry_exists "${scope}" "${protocol}" "${port}" temporary && nftables_ok=false
    fi
  done < <(custom_protocols "${requested_protocol}")
  if [[ "${format}" == "--json" ]]; then
    printf '{"schema_version":1,"facts":%s,"nftables":%s}\n' "${facts_ok}" "${nftables_ok}"
  fi
  [[ "${facts_ok}" == true && "${nftables_ok}" == true ]]
}

restore_custom_ports() {
  local scope=""
  local protocol=""
  local port=""
  local duration=""
  local remaining=""
  local entries=""
  [[ -r "${CUSTOM_PORTS_PATH}" ]] || return 0
  entries="$(query_custom_ports tsv)" || {
    fail "自定义端口状态损坏，未恢复任何自定义规则。"
    return 1
  }
  while IFS=$'\t' read -r scope protocol port duration remaining; do
    [[ -n "${scope}" ]] || continue
    remove_custom_runtime_entry "${scope}" "${protocol}" "${port}"
    add_custom_runtime_entry "${scope}" "${protocol}" "${port}" "${duration}" "${remaining}"
  done <<< "${entries}"
}

open_custom_port() {
  local port="${1:-}"
  local requested_scope="${2:-}"
  local requested_protocol="${3:-}"
  local duration_value="${4:-3600}"
  local confirm="${5:-}"
  local scope=""
  local protocol=""
  local duration="temporary"
  local remaining=""
  [[ "${confirm}" == "--yes" ]] || { fail "开放自定义端口必须加 --yes。"; return 1; }
  validate_custom_port "${port}" || return 1
  validate_custom_duration "${duration_value}" || return 1
  scope="$(normalize_custom_scope "${requested_scope}")" || return 1
  custom_protocols "${requested_protocol}" >/dev/null || return 1
  table_exists || { fail "server-kit 防火墙尚未运行。"; return 1; }
  while read -r protocol; do
    base_rules_have_port "${scope}" "${protocol}" "${port}" && {
      fail "${scope} ${protocol^^} ${port} 已由托管服务放行，无需重复添加。"
      return 1
    }
  done < <(custom_protocols "${requested_protocol}")
  [[ "${duration_value}" == "permanent" ]] && duration="permanent"
  update_custom_ports_state open "${port}" "${scope}" "${requested_protocol}" "${duration_value}"
  while read -r protocol; do
    remove_custom_runtime_entry "${scope}" "${protocol}" "${port}"
    remaining="${duration_value}"
    [[ "${duration}" == "permanent" ]] && remaining=0
    if ! add_custom_runtime_entry "${scope}" "${protocol}" "${port}" "${duration}" "${remaining}"; then
      update_custom_ports_state close "${port}" "${scope}" "${requested_protocol}" permanent
      while read -r cleanup_protocol; do
        remove_custom_runtime_entry "${scope}" "${cleanup_protocol}" "${port}"
      done < <(custom_protocols "${requested_protocol}")
      fail "自定义端口应用失败，状态已撤销。"
      return 1
    fi
  done < <(custom_protocols "${requested_protocol}")
  if ! verify_custom_port open "${port}" "${scope}" "${requested_protocol}" "${duration_value}"; then
    update_custom_ports_state close "${port}" "${scope}" "${requested_protocol}" permanent
    while read -r protocol; do
      remove_custom_runtime_entry "${scope}" "${protocol}" "${port}"
    done < <(custom_protocols "${requested_protocol}")
    fail "自定义端口核验失败，状态与规则已撤销。"
    return 1
  fi
  echo "已开放：${scope} ${requested_protocol^^} ${port}（$([[ "${duration}" == "permanent" ]] && echo '永久' || echo "${duration_value} 秒")）。"
}

close_custom_port() {
  local port="${1:-}"
  local requested_scope="${2:-}"
  local requested_protocol="${3:-}"
  local confirm="${4:-}"
  local scope=""
  local protocol=""
  [[ "${confirm}" == "--yes" ]] || { fail "关闭自定义端口必须加 --yes。"; return 1; }
  validate_custom_port "${port}" || return 1
  scope="$(normalize_custom_scope "${requested_scope}")" || return 1
  custom_protocols "${requested_protocol}" >/dev/null || return 1
  while read -r protocol; do
    base_rules_have_port "${scope}" "${protocol}" "${port}" && {
      fail "${scope} ${protocol^^} ${port} 已由基础策略或托管服务放行，不能作为自定义端口关闭。"
      return 1
    }
  done < <(custom_protocols "${requested_protocol}")
  local previous_entries=""
  previous_entries="$(query_custom_ports tsv | awk -F '\t' -v scope="${scope}" -v port="${port}" \
    -v requested="${requested_protocol}" '$1 == scope && $3 == port && (requested == "both" || $2 == requested)')"
  update_custom_ports_state close "${port}" "${scope}" "${requested_protocol}" permanent
  if table_exists; then
    while read -r protocol; do
      remove_custom_runtime_entry "${scope}" "${protocol}" "${port}"
      if base_rules_have_port "${scope}" "${protocol}" "${port}"; then
        add_custom_runtime_entry "${scope}" "${protocol}" "${port}" permanent 0
      fi
    done < <(custom_protocols "${requested_protocol}")
  fi
  if ! verify_custom_port close "${port}" "${scope}" "${requested_protocol}" permanent; then
    while IFS=$'\t' read -r restore_scope restore_protocol restore_port restore_duration restore_remaining; do
      [[ -n "${restore_scope}" ]] || continue
      local restore_value="${restore_remaining}"
      [[ "${restore_duration}" == "permanent" ]] && restore_value=permanent
      update_custom_ports_state open "${restore_port}" "${restore_scope}" "${restore_protocol}" "${restore_value}"
      remove_custom_runtime_entry "${restore_scope}" "${restore_protocol}" "${restore_port}"
      add_custom_runtime_entry "${restore_scope}" "${restore_protocol}" "${restore_port}" \
        "${restore_duration}" "${restore_remaining}" || true
    done <<< "${previous_entries}"
    fail "自定义端口关闭核验失败，原状态已恢复。"
    return 1
  fi
  echo "已关闭自定义端口：${scope} ${requested_protocol^^} ${port}。"
}

list_custom_ports() {
  local format="${1:-}"
  if [[ "${format}" == "--json" ]]; then
    query_custom_ports json
    return
  fi
  local scope=""
  local protocol=""
  local port=""
  local duration=""
  local remaining=""
  echo "自定义端口："
  while IFS=$'\t' read -r scope protocol port duration remaining; do
    [[ -n "${scope}" ]] || continue
    printf '  %-12s %-3s %-5s %s\n' "$([[ "${scope}" == "public" ]] && echo '公网' || echo 'AWG 内网')" "${protocol^^}" "${port}" "$([[ "${duration}" == "permanent" ]] && echo '永久' || echo "剩余 ${remaining} 秒")"
  done < <(query_custom_ports tsv)
}

runtime_stop() {
  delete_owned_table
}

open_temporary() {
  local port="${1:-}"
  local seconds="${2:-900}"
  [[ "${port}" == "80" ]] || { fail "临时公网端口目前只允许 TCP 80。"; return 1; }
  [[ "${seconds}" =~ ^[0-9]+$ ]] && (( seconds >= 60 && seconds <= 3600 )) ||
    { fail "临时放行时间必须是 60–3600 秒。"; return 1; }
  if ! table_exists; then
    echo "server-kit 防火墙尚未启用，无需临时放行。"
    return 0
  fi
  "${NFT_BIN}" add element "${TABLE_FAMILY}" "${TABLE_NAME}" \
    temporary_public_tcp_ports "{ ${port} timeout ${seconds}s }"
  echo "已临时放行 TCP ${port}，最长 ${seconds} 秒。"
}

close_temporary() {
  local port="${1:-}"
  [[ "${port}" == "80" ]] || { fail "临时公网端口目前只允许 TCP 80。"; return 1; }
  table_exists || return 0
  "${NFT_BIN}" delete element "${TABLE_FAMILY}" "${TABLE_NAME}" \
    temporary_public_tcp_ports "{ ${port} }" >/dev/null 2>&1 || true
  echo "已关闭临时 TCP ${port}。"
}

open_transaction_temporary() {
  local port="${1:-}"
  local seconds="${2:-900}"
  local confirm="${3:-}"
  [[ "${confirm}" == "--yes" ]] || { fail "事务临时端口必须加 --yes。"; return 1; }
  validate_custom_port "${port}" || return 1
  (( 10#${port} >= 1024 )) || { fail "事务临时端口必须是 1024–65535。"; return 1; }
  [[ "${seconds}" =~ ^[0-9]+$ ]] && (( seconds >= 60 && seconds <= 3600 )) ||
    { fail "临时放行时间必须是 60–3600 秒。"; return 1; }
  if ! table_exists; then
    echo "server-kit 防火墙尚未启用，无需临时放行。"
    return 0
  fi
  "${NFT_BIN}" delete element "${TABLE_FAMILY}" "${TABLE_NAME}" \
    temporary_public_tcp_ports "{ ${port} }" >/dev/null 2>&1 || true
  "${NFT_BIN}" add element "${TABLE_FAMILY}" "${TABLE_NAME}" \
    temporary_public_tcp_ports "{ ${port} timeout ${seconds}s }"
  echo "已为安全事务临时放行 TCP ${port}，最长 ${seconds} 秒。"
}

close_transaction_temporary() {
  local port="${1:-}"
  local confirm="${2:-}"
  [[ "${confirm}" == "--yes" ]] || { fail "关闭事务临时端口必须加 --yes。"; return 1; }
  validate_custom_port "${port}" || return 1
  table_exists || return 0
  "${NFT_BIN}" delete element "${TABLE_FAMILY}" "${TABLE_NAME}" \
    temporary_public_tcp_ports "{ ${port} }" >/dev/null 2>&1 || true
  echo "已关闭安全事务临时 TCP ${port}。"
}

show_status() {
  echo "server-kit 防火墙"
  if table_exists; then
    echo "运行状态：已加载"
    "${NFT_BIN}" list table "${TABLE_FAMILY}" "${TABLE_NAME}"
  else
    echo "运行状态：未加载"
  fi
  [[ -r "${TRANSACTION_PATH}" ]] && echo "确认状态：等待确认" || echo "确认状态：无待确认事务"
  [[ -r "${ACTIVE_RULES_PATH}" ]] && echo "持久规则：${ACTIVE_RULES_PATH}" || echo "持久规则：未安装"
}

audit_runtime() {
  local service_active=0
  local table_active=0
  local transaction_pending=0
  local current_public_interface=""
  local persisted_public_interface=""

  "${SYSTEMCTL_BIN}" is-active --quiet server-kit-firewall.service && service_active=1
  table_exists && table_active=1
  [[ -r "${TRANSACTION_PATH}" ]] && transaction_pending=1

  if (( service_active == 1 && table_active == 0 )); then
    fail "server-kit-firewall.service 显示运行，但内核规则表 inet ${TABLE_NAME} 不存在。"
    return 1
  fi
  if (( service_active == 0 && table_active == 1 && transaction_pending == 0 )); then
    fail "内核规则表 inet ${TABLE_NAME} 已加载，但持久化服务未运行。"
    return 1
  fi
  if (( service_active == 1 )) && [[ ! -r "${ACTIVE_RULES_PATH}" ]]; then
    fail "防火墙服务正在运行，但持久规则文件不存在：${ACTIVE_RULES_PATH}"
    return 1
  fi
  if (( service_active == 1 )); then
    current_public_interface="$(detect_public_interface)"
    persisted_public_interface="$(sed -n 's/.*meta nfproto ipv4 iifname "\([^"]*\)" tcp dport @public_tcp_ports.*/\1/p' "${ACTIVE_RULES_PATH}" | head -n 1)"
    if [[ -z "${current_public_interface}" ]]; then
      fail "防火墙正在运行，但无法检测默认 IPv4 路由接口。"
      return 1
    fi
    if [[ -z "${persisted_public_interface}" || "${persisted_public_interface}" != "${current_public_interface}" ]]; then
      fail "防火墙公网接口与默认路由不一致：持久规则=${persisted_public_interface:-<无效>}，当前=${current_public_interface}。"
      return 1
    fi
  fi

  if (( transaction_pending == 1 )); then
    echo "防火墙运行审计通过：候选规则正在等待确认。"
  elif (( service_active == 1 )); then
    echo "防火墙运行审计通过：systemd 服务、内核规则表和持久规则一致。"
  else
    echo "防火墙运行审计通过：服务和内核规则表均未运行。"
  fi
}

stop_firewall() {
  local confirm="${1:-}"
  [[ "${confirm}" == "--yes" ]] || { fail "停止防火墙必须加 --yes。"; return 1; }
  "${SYSTEMCTL_BIN}" disable --now server-kit-firewall.service >/dev/null 2>&1 || true
  delete_owned_table
  echo "server-kit 防火墙已停止；规则文件仍保留。"
}

usage() {
  cat <<EOF
server-kit 防火墙管理器

查看与校验：
  $0 plan                         扫描端口并显示候选规则
  $0 check                        扫描端口并执行 nft --check
  $0 status                       查看运行状态和规则
  $0 audit-runtime                核对 systemd、内核规则表和持久规则
  $0 refresh-service              刷新开机恢复服务并校准当前公网接口

事务应用：
  $0 apply --yes                  应用候选规则并启动自动回滚
  $0 confirm --yes                独立验证后确认并持久化
  $0 rollback                     立即回滚待确认规则

证书临时端口：
  $0 open-temporary 80 [秒]       临时开放 Certbot TCP 80
  $0 close-temporary 80           提前关闭临时端口

安全事务临时端口：
  $0 open-transaction-temporary <端口> [秒] --yes
  $0 close-transaction-temporary <端口> --yes

自定义端口：
  $0 open-port <端口> <public|awg> <tcp|udp|both> <秒|permanent> --yes
                                   开放限时或永久自定义端口
  $0 close-port <端口> <public|awg> <tcp|udp|both> --yes
  $0 verify-port <open|close> <端口> <public|awg> <tcp|udp|both> <秒|permanent> [--json]
                                   提前关闭自定义端口
  $0 list-ports [--json]           查看自定义端口与剩余时间

管理：
  $0 stop --yes                   停止并卸载运行中的自有表

扫描只生成候选规则，不会自动应用。未托管端口默认拒绝。
EOF
}

main() {
  require_platform
  case "${1:-plan}" in
    plan) show_plan ;;
    check) check_candidate ;;
    apply) apply_candidate "${2:-}" ;;
    confirm) confirm_candidate "${2:-}" ;;
    rollback) rollback "${2:-}" ;;
    status) show_status ;;
    audit-runtime) audit_runtime ;;
    refresh-service) refresh_service ;;
    restore-active) restore_active ;;
    runtime-stop) runtime_stop ;;
    open-temporary) open_temporary "${2:-}" "${3:-900}" ;;
    close-temporary) close_temporary "${2:-}" ;;
    open-transaction-temporary) open_transaction_temporary "${2:-}" "${3:-900}" "${4:-}" ;;
    close-transaction-temporary) close_transaction_temporary "${2:-}" "${3:-}" ;;
    open-port) open_custom_port "${2:-}" "${3:-}" "${4:-}" "${5:-3600}" "${6:-}" ;;
    close-port) close_custom_port "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
    verify-port) verify_custom_port "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-permanent}" "${7:-}" ;;
    list-ports) list_custom_ports "${2:-}" ;;
    stop) stop_firewall "${2:-}" ;;
    help|-h|--help) usage ;;
    *) usage; exit 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
