#!/usr/bin/env bash

set -euo pipefail

# 管理输出和 JSON 固定使用 UTF-8，避免 Windows Git Bash 继承本地代码页后破坏中文字段。
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_PATH}" ]]; do
  SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
  SCRIPT_PATH="$(readlink -- "${SCRIPT_PATH}")"
  [[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="${SCRIPT_LINK_DIR}/${SCRIPT_PATH}"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"

SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-/usr/bin/systemctl}"
JOURNALCTL_BIN="${JOURNALCTL_BIN:-/usr/bin/journalctl}"
COLUMN_BIN="${COLUMN_BIN:-/usr/bin/column}"
APT_GET_BIN="${APT_GET_BIN:-/usr/bin/apt-get}"
QRENCODE_BIN="${QRENCODE_BIN:-/usr/bin/qrencode}"
SECURITY_MANAGER="${SECURITY_MANAGER:-${SCRIPT_DIR}/debian_security_manager.sh}"
FIREWALL_MANAGER="${FIREWALL_MANAGER:-${SCRIPT_DIR}/debian_firewall_manager.sh}"
MOSH_MANAGER="${MOSH_MANAGER:-${SCRIPT_DIR}/debian_mosh_manager.sh}"
AWG_MANAGER="${AWG_MANAGER:-${SCRIPT_DIR}/amneziawg-setup.sh}"
VLESS_MANAGER="${VLESS_MANAGER:-${SCRIPT_DIR}/debian_vless_manager.sh}"
VLESS_ACCESS_HELPER="${VLESS_ACCESS_HELPER:-${SCRIPT_DIR}/lib/vless_access.py}"
FILE_MANAGER="${FILE_MANAGER:-${SCRIPT_DIR}/debian_file_manager.sh}"
BACKUP_HELPER="${BACKUP_HELPER:-${SCRIPT_DIR}/lib/server_kit_backup.py}"
NODE_DOMAIN_HELPER="${NODE_DOMAIN_HELPER:-${SCRIPT_DIR}/lib/server_kit_node_domains.py}"
PUBLIC_ENDPOINT_HELPER="${PUBLIC_ENDPOINT_HELPER:-${SCRIPT_DIR}/lib/server_kit_public_endpoint.py}"
PUBLICATION_STATE_HELPER="${PUBLICATION_STATE_HELPER:-${SCRIPT_DIR}/lib/server_kit_publication_state.py}"
PUBLIC_ENDPOINT_TRANSACTION_HELPER="${PUBLIC_ENDPOINT_TRANSACTION_HELPER:-${SCRIPT_DIR}/lib/server_kit_public_endpoint_transaction.py}"
DUCKDNS_HELPER="${DUCKDNS_HELPER:-${SCRIPT_DIR}/lib/server_kit_duckdns.py}"
PUBLIC_ENDPOINT_PATH="${PUBLIC_ENDPOINT_PATH:-/etc/server-kit/public-endpoint.json}"
PUBLIC_ENDPOINT_TRANSACTION_DIR="${PUBLIC_ENDPOINT_TRANSACTION_DIR:-/var/lib/server-kit/public-endpoint-transaction}"
PUBLIC_ENDPOINT_OUTCOME_PATH="${PUBLIC_ENDPOINT_OUTCOME_PATH:-/var/lib/server-kit/public-endpoint-last-outcome.json}"
PUBLIC_ENDPOINT_ROLLBACK_SECONDS="${PUBLIC_ENDPOINT_ROLLBACK_SECONDS:-300}"
PUBLIC_ENDPOINT_ROLLBACK_UNIT="${PUBLIC_ENDPOINT_ROLLBACK_UNIT:-server-kit-public-endpoint-rollback}"
DUCKDNS_CONFIG_PATH="${DUCKDNS_CONFIG_PATH:-/etc/server-kit/duckdns.json}"
DUCKDNS_STATE_PATH="${DUCKDNS_STATE_PATH:-/var/lib/server-kit/duckdns-state.json}"
DUCKDNS_TIMER_UNIT="${DUCKDNS_TIMER_UNIT:-server-kit-duckdns.timer}"
SYSTEMD_RUN_BIN="${SYSTEMD_RUN_BIN:-/usr/bin/systemd-run}"
BACKUP_DIR="${BACKUP_DIR:-/var/lib/server-kit-backups}"
WEB_GROUP="${WEB_GROUP:-server-kit-web}"
BACKUP_ROLLBACK_SECONDS="${BACKUP_ROLLBACK_SECONDS:-300}"
PORTS_PATH="${PORTS_PATH:-/etc/server-kit/ports.json}"
PORT_FACTS_HELPER="${PORT_FACTS_HELPER:-${SCRIPT_DIR}/lib/server_kit_port_facts.py}"
MANAGED_PORTS_HELPER="${MANAGED_PORTS_HELPER:-${SCRIPT_DIR}/lib/server_kit_managed_ports.py}"
FIREWALL_ACTIVE_RULES="${FIREWALL_ACTIVE_RULES:-/etc/server-kit/firewall.nft}"
FIREWALL_CANDIDATE_RULES="${FIREWALL_CANDIDATE_RULES:-/etc/server-kit/firewall-candidate.nft}"
FIREWALL_TRANSACTION="${FIREWALL_TRANSACTION:-/etc/server-kit/firewall-transaction.json}"
SSH_AUTH_TRANSACTION="${SSH_AUTH_TRANSACTION:-/etc/server-kit/ssh-auth-transaction.json}"
SSH_TRANSACTION="${SSH_TRANSACTION:-/etc/server-kit/ssh-transaction.json}"
SECURITY_CONFIG="${SECURITY_CONFIG:-/etc/server-kit/security.json}"
SECURITY_CONTEXT_DIR="${SECURITY_CONTEXT_DIR:-/etc/server-kit/security-transaction-contexts}"
BACKUP_CONTEXT_PATH="${BACKUP_CONTEXT_PATH:-${SECURITY_CONTEXT_DIR}/backup_restore.json}"
AWG_STATE="${AWG_STATE:-/etc/amneziawg/manager.conf}"
AWG_PEERS="${AWG_PEERS:-/etc/amneziawg/peers.tsv}"
AWG_DISABLED_PEERS="${AWG_DISABLED_PEERS:-/etc/amneziawg/peers.disabled.tsv}"
AWG_PEER_CREDENTIALS="${AWG_PEER_CREDENTIALS:-/etc/amneziawg/peer-credentials.tsv}"
AWG_ENROLLMENTS="${AWG_ENROLLMENTS:-/etc/amneziawg/enrollments.json}"
VLESS_PENDING_POLICY="${VLESS_PENDING_POLICY:-/etc/server-kit/vless-access.pending.json}"
VLESS_POLICY="${VLESS_POLICY:-/etc/server-kit/vless-access.json}"
AWG_ACCESS_PENDING_POLICY="${AWG_ACCESS_PENDING_POLICY:-/etc/server-kit/awg-access.pending.json}"
AWG_ACCESS_POLICY="${AWG_ACCESS_POLICY:-/etc/server-kit/awg-access.json}"
XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-/usr/local/etc/xray/config.json}"
CLASH_CONFIG="${CLASH_CONFIG:-/etc/secure-file-service/clash-config.json}"
CLASH_INPUT_CONFIG="${CLASH_INPUT_CONFIG:-/etc/server-kit/clash-inputs.json}"
CLASH_PUBLICATION_STATE="${CLASH_PUBLICATION_STATE:-/etc/server-kit/clash-publications.json}"
NODE_DOMAINS_PATH="${NODE_DOMAINS_PATH:-/etc/server-kit/node-domains.json}"
FILE_CONFIG="${FILE_CONFIG:-/etc/secure-file-service/config.json}"
FILE_DATA_DIR="${FILE_DATA_DIR:-/var/lib/secure-file-service}"
PUBLICATION_CERT_PATH="${PUBLICATION_CERT_PATH:-/etc/secure-file-service/server.crt}"
PUBLICATION_KEY_PATH="${PUBLICATION_KEY_PATH:-/etc/secure-file-service/server.key}"
PUBLICATION_CERT_FACT_PATH="${PUBLICATION_CERT_FACT_PATH:-/etc/secure-file-service/certificate-ip}"
FILE_RESOURCE_HELPER="${FILE_RESOURCE_HELPER:-${SCRIPT_DIR}/lib/server_kit_file_resources.py}"
FILE_UPLOAD_MAX_BYTES="${FILE_UPLOAD_MAX_BYTES:-2147483648}"
MOSH_STATE="${MOSH_STATE:-/etc/server-kit/mosh.conf}"
MANAGEMENT_STATE="${MANAGEMENT_STATE:-/etc/server-kit/management.conf}"
MANAGEMENT_LOCK_PATH="${MANAGEMENT_LOCK_PATH:-/run/server-kit/management-change.lock}"
WEB_UPLOAD_DIR="${WEB_UPLOAD_DIR:-/var/lib/server-kit-web/uploads}"
ROOT_UPLOAD_STAGING="${ROOT_UPLOAD_STAGING:-/var/lib/server-kit-staging}"
SSH_AUTH_CONFIG="${SSH_AUTH_CONFIG:-/etc/ssh/sshd_config.d/30-server-kit-auth.conf}"
OS_RELEASE_PATH="${OS_RELEASE_PATH:-/etc/os-release}"
MANAGEMENT_AUDIT="${MANAGEMENT_AUDIT:-/var/log/server-kit/management-actions.jsonl}"

SERVICE_IDS=(amneziawg management vless clash file mosh cert-renew firewall ssh)
START_ORDER=(amneziawg management vless file clash cert-renew mosh)
STOP_ORDER=(mosh cert-renew clash file vless management amneziawg)

declare -A PORT_SUMMARY=()
declare -A SYSTEMD_LOAD_STATE=()
declare -A SYSTEMD_ACTIVE_STATE=()
declare -A SYSTEMD_UNIT_FILE_STATE=()
SYSTEMD_STATE_CACHE_READY=0

fail() {
  echo "错误：$*" >&2
  return 1
}

safe_diagnostic() {
  local code="$1"
  local detail="${2:-}"
  [[ "${code}" =~ ^[a-z][a-z0-9_]{2,63}$ ]] || return 1
  if [[ -n "${detail}" ]]; then
    printf 'SERVER_KIT_DIAGNOSTIC:%s:%s\n' "${code}" "${detail}" >&2
  else
    printf 'SERVER_KIT_DIAGNOSTIC:%s\n' "${code}" >&2
  fi
}

validate_port_value() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]{1,5}$ ]] && (( 10#${value} >= 1 && 10#${value} <= 65535 ))
}

acquire_change_lock() {
  local lock_dir=""
  lock_dir="$(dirname -- "${MANAGEMENT_LOCK_PATH}")"
  install -d -m 755 -- "${lock_dir}"
  exec 9>"${MANAGEMENT_LOCK_PATH}"
  if ! flock -n 9; then
    fail "已有管理变更正在执行，请等待完成后重试。"
    return 1
  fi
}

run_backup_json() {
  local operation="$1"
  local backup_id="${2:-}"
  local automatic="${3:-0}"
  local web_gid="-1"
  local passphrase=""
  local session_id=""
  local actor=""
  local request_json=""
  local result_json=""
  local -a request_values=()
  local -a common_args=()
  [[ -r "${BACKUP_HELPER}" ]] || { fail "缺少加密备份模块。"; return 1; }
  if command -v getent >/dev/null 2>&1; then
    web_gid="$(getent group "${WEB_GROUP}" 2>/dev/null | awk -F: '{print $3}' || true)"
  fi
  [[ "${web_gid}" =~ ^[0-9]+$ ]] || web_gid="-1"
  [[ "${BACKUP_ROLLBACK_SECONDS}" =~ ^[0-9]+$ ]] && \
    (( BACKUP_ROLLBACK_SECONDS >= 60 && BACKUP_ROLLBACK_SECONDS <= 3600 )) || {
      fail "恢复回滚窗口必须为 60–3600 秒。"
      return 1
    }
  common_args=(--backup-dir "${BACKUP_DIR}" --web-gid "${web_gid}" \
    --rollback-seconds "${BACKUP_ROLLBACK_SECONDS}")
  if [[ "${SERVER_KIT_HIGH_RISK_WRITES:-0}" == "1" ]]; then
    common_args+=(--writes-enabled)
  fi
  if [[ "${SERVER_KIT_CONTROL:-0}" == "1" ]]; then
    request_json="$(cat)"
    mapfile -t request_values < <(python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in ("passphrase", "session_id", "actor"):
    item = value.get(key, "")
    if not isinstance(item, str) or "\x00" in item or "\n" in item or "\r" in item:
        raise SystemExit(2)
    print(item)
' <<<"${request_json}")
    [[ "${#request_values[@]}" -eq 3 ]] || { fail "备份任务输入无效。"; return 1; }
    passphrase="${request_values[0]%$'\r'}"
    session_id="${request_values[1]%$'\r'}"
    actor="${request_values[2]%$'\r'}"
  fi
  if [[ "${operation}" == "restore-apply" || "${operation}" == "restore-confirm" || "${operation}" == "restore-rollback" ]]; then
    if [[ "${SERVER_KIT_CONTROL:-0}" == "1" ]]; then
      [[ "${session_id}" =~ ^[0-9a-f]{64}$ ]] || { fail "独立连接标识无效。"; return 1; }
    fi
  fi
  if [[ "${operation}" == "restore-confirm" && "${SERVER_KIT_CONTROL:-0}" == "1" ]]; then
    [[ -r "${BACKUP_CONTEXT_PATH}" ]] || { fail "配置恢复缺少发起会话记录，请使用 root 恢复入口。"; return 1; }
    if python3 - "${BACKUP_CONTEXT_PATH}" "${session_id}" <<'PYTHON'
import hashlib
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    origin = json.load(source).get("session_hash", "")
raise SystemExit(0 if origin == hashlib.sha256(sys.argv[2].encode("ascii")).hexdigest() else 1)
PYTHON
    then
      fail "原发起会话不能确认配置恢复，请从另一条独立登录连接操作。"
      return 1
    fi
  fi
  case "${operation}" in
    list|create)
      [[ -z "${backup_id}" ]] || { fail "${operation} 不接受备份标识。"; return 1; }
      if [[ "${operation}" == "create" && "${SERVER_KIT_CONTROL:-0}" == "1" ]]; then
        printf '%s\n' "${passphrase}" | python3 "${BACKUP_HELPER}" "${operation}" "${common_args[@]}"
      else
        python3 "${BACKUP_HELPER}" "${operation}" "${common_args[@]}"
      fi
      ;;
    verify|delete|preview-restore|restore-apply)
      [[ "${backup_id}" =~ ^backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || {
        fail "备份标识格式不正确。"
        return 1
      }
      if [[ "${operation}" != "delete" && "${SERVER_KIT_CONTROL:-0}" == "1" ]]; then
        result_json="$(printf '%s\n' "${passphrase}" | python3 "${BACKUP_HELPER}" "${operation}" "${backup_id}" "${common_args[@]}")"
      else
        result_json="$(python3 "${BACKUP_HELPER}" "${operation}" "${backup_id}" "${common_args[@]}")"
      fi
      if [[ "${operation}" == "restore-apply" ]]; then
        if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
          mkdir -p -- "$(dirname -- "${BACKUP_CONTEXT_PATH}")"
        else
          install -d -m 700 -o root -g root "$(dirname -- "${BACKUP_CONTEXT_PATH}")"
        fi
        python3 - "${BACKUP_CONTEXT_PATH}" "${session_id}" "${actor}" <<'PYTHON'
import hashlib, json, os, sys, tempfile
from datetime import datetime, timezone
path, session_id, actor = sys.argv[1:]
value = {"session_hash": hashlib.sha256(session_id.encode("ascii")).hexdigest(), "actor": actor, "created_at": datetime.now(timezone.utc).isoformat()}
descriptor, temporary = tempfile.mkstemp(prefix=".backup-context-", dir=os.path.dirname(path))
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
    json.dump(value, output, separators=(",", ":")); output.write("\n"); output.flush(); os.fsync(output.fileno())
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PYTHON
      fi
      if [[ "${operation}" == "restore-apply" ]]; then
        BACKUP_RESULT="${result_json}" python3 - "${BACKUP_CONTEXT_PATH}" "${session_id}" <<'PYTHON'
import hashlib, json, os, sys
value = json.loads(os.environ["BACKUP_RESULT"])
result = value.get("result", {})
with open(sys.argv[1], encoding="utf-8") as source:
    origin = json.load(source).get("session_hash", "")
result["independent_session"] = origin != hashlib.sha256(sys.argv[2].encode("ascii")).hexdigest()
if hasattr(sys.stdout, "reconfigure"): sys.stdout.reconfigure(encoding="utf-8")
json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":")); print()
PYTHON
      else
        printf '%s\n' "${result_json}"
      fi
      ;;
    restore-status|restore-confirm)
      [[ -z "${backup_id}" ]] || { fail "${operation} 不接受备份标识。"; return 1; }
      result_json="$(python3 "${BACKUP_HELPER}" "${operation}" "${common_args[@]}")"
      [[ "${operation}" != "restore-confirm" ]] || rm -f -- "${BACKUP_CONTEXT_PATH}"
      BACKUP_RESULT="${result_json}" python3 - "${BACKUP_CONTEXT_PATH}" "${session_id}" <<'PYTHON'
import hashlib, json, os, sys
value = json.loads(os.environ["BACKUP_RESULT"])
result = value.get("result", {})
independent = True
if result.get("state") == "pending" and os.path.isfile(sys.argv[1]):
    with open(sys.argv[1], encoding="utf-8") as source:
        origin = json.load(source).get("session_hash", "")
    independent = not sys.argv[2] or origin != hashlib.sha256(sys.argv[2].encode("ascii")).hexdigest()
elif result.get("state") == "idle":
    try: os.unlink(sys.argv[1])
    except FileNotFoundError: pass
result["independent_session"] = independent
if hasattr(sys.stdout, "reconfigure"): sys.stdout.reconfigure(encoding="utf-8")
json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":")); print()
PYTHON
      ;;
    restore-rollback)
      [[ -z "${backup_id}" ]] || { fail "restore-rollback 不接受备份标识。"; return 1; }
      if [[ "${automatic}" == "1" ]]; then
        result_json="$(python3 "${BACKUP_HELPER}" "${operation}" "${common_args[@]}" --automatic)"
      else
        result_json="$(python3 "${BACKUP_HELPER}" "${operation}" "${common_args[@]}")"
      fi
      rm -f -- "${BACKUP_CONTEXT_PATH}"
      BACKUP_RESULT="${result_json}" python3 - <<'PYTHON'
import json, os, sys
value = json.loads(os.environ["BACKUP_RESULT"])
value.get("result", {})["independent_session"] = True
if hasattr(sys.stdout, "reconfigure"): sys.stdout.reconfigure(encoding="utf-8")
json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":")); print()
PYTHON
      ;;
    *) fail "备份动作未登记。"; return 1 ;;
  esac
}

terminal_width() {
  local width="${COLUMNS:-}"
  if [[ "${width}" =~ ^[0-9]+$ ]] && ((10#${width} > 0)); then
    echo "$((10#${width}))"
  elif [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    tput cols 2>/dev/null || echo 120
  else
    echo 120
  fi
}

use_compact_layout() {
  (( $(terminal_width) < 96 ))
}

render_tab_table() {
  local column_bin="${COLUMN_BIN}"
  if [[ ! -x "${column_bin}" ]]; then
    column_bin="$(command -v column 2>/dev/null || true)"
  fi
  if [[ -z "${column_bin}" ]]; then
    if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
      fail "测试环境缺少 column 命令。"
      return 1
    fi
    echo "检测到缺少 column，正在安装 bsdextrautils..." >&2
    DEBIAN_FRONTEND=noninteractive "${APT_GET_BIN}" update >&2
    DEBIAN_FRONTEND=noninteractive "${APT_GET_BIN}" install -y bsdextrautils >&2
    column_bin="$(command -v column 2>/dev/null || true)"
    [[ -n "${column_bin}" ]] || { fail "bsdextrautils 安装后仍未找到 column。"; return 1; }
  fi
  "${column_bin}" -t -s $'\t'
}

require_platform() {
  if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
    return 0
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    echo "请使用 root 运行此脚本。" >&2
    exit 1
  fi
  if [[ ! -r "${OS_RELEASE_PATH}" ]]; then
    echo "无法识别当前系统。" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${OS_RELEASE_PATH}"
  if [[ "${ID:-}" != "debian" ]] && [[ "${ID_LIKE:-}" != *"debian"* ]]; then
    echo "此脚本仅支持 Debian 或 Debian 系发行版。" >&2
    exit 1
  fi
}

read_assignment() {
  local path="$1"
  local key="$2"
  local value=""

  [[ -r "${path}" ]] || return 0
  value="$(sed -n "s/^${key}=//p" "${path}" | tail -n 1)"
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"
  printf '%s\n' "${value}"
}

normalize_id() {
  case "${1,,}" in
    awg|amnezia|amneziawg) echo "amneziawg" ;;
    management|manager|web|panel) echo "management" ;;
    xray|vless) echo "vless" ;;
    clash|subscription|subscriptions) echo "clash" ;;
    file|files) echo "file" ;;
    mosh|mobile-shell) echo "mosh" ;;
    cert|certificate|cert-renew) echo "cert-renew" ;;
    firewall|nftables|nft) echo "firewall" ;;
    ssh) echo "ssh" ;;
    all) echo "all" ;;
    *) return 1 ;;
  esac
}

service_label() {
  case "$1" in
    amneziawg) echo "AmneziaWG" ;;
    management) echo "管理网站" ;;
    vless) echo "Xray / VLESS" ;;
    clash) echo "Clash 订阅" ;;
    file) echo "普通文件" ;;
    mosh) echo "Mosh 终端" ;;
    cert-renew) echo "证书续期" ;;
    firewall) echo "主机防火墙" ;;
    ssh) echo "系统 SSH" ;;
  esac
}

service_unit() {
  local iface=""
  case "$1" in
    amneziawg)
      iface="$(read_assignment "${AWG_STATE}" AWG_IFACE)"
      echo "awg-quick@${iface:-awg0}.service"
      ;;
    vless) echo "xray.service" ;;
    management) echo "server-kit-web.service" ;;
    clash) echo "secure-clash-service.service" ;;
    file) echo "secure-file-service.service" ;;
    cert-renew) echo "secure-file-cert-renew.timer" ;;
    firewall) echo "server-kit-firewall.service" ;;
    ssh) echo "ssh.service" ;;
    mosh) echo "server-kit-mosh" ;;
  esac
}

load_service_unit_states() {
  local id=""
  local unit=""
  local output=""
  local line=""
  local key=""
  local value=""
  local block_id=""
  local block_load=""
  local block_active=""
  local block_enabled=""
  local -a units=()
  declare -A seen=()

  for id in "$@"; do
    [[ "${id}" == "mosh" ]] && continue
    unit="$(service_unit "${id}")"
    [[ -n "${unit}" && -z "${seen[${unit}]+x}" ]] || continue
    seen["${unit}"]=1
    units+=("${unit}")
  done
  SYSTEMD_LOAD_STATE=()
  SYSTEMD_ACTIVE_STATE=()
  SYSTEMD_UNIT_FILE_STATE=()
  if ((${#units[@]})); then
    output="$("${SYSTEMCTL_BIN}" show --all \
      --property=Id --property=LoadState --property=ActiveState \
      --property=UnitFileState "${units[@]}" 2>/dev/null || true)"
    while IFS= read -r line || [[ -n "${line}" ]]; do
      if [[ -z "${line}" ]]; then
        if [[ -n "${block_id}" ]]; then
          SYSTEMD_LOAD_STATE["${block_id}"]="${block_load:-not-found}"
          SYSTEMD_ACTIVE_STATE["${block_id}"]="${block_active:-inactive}"
          SYSTEMD_UNIT_FILE_STATE["${block_id}"]="${block_enabled:-disabled}"
        fi
        block_id=""
        block_load=""
        block_active=""
        block_enabled=""
        continue
      fi
      key="${line%%=*}"
      value="${line#*=}"
      case "${key}" in
        Id) block_id="${value}" ;;
        LoadState) block_load="${value}" ;;
        ActiveState) block_active="${value}" ;;
        UnitFileState) block_enabled="${value}" ;;
      esac
    done <<< "${output}"$'\n'
  fi
  SYSTEMD_STATE_CACHE_READY=1
}

unit_exists() {
  if [[ "${SYSTEMD_STATE_CACHE_READY}" == "1" ]]; then
    [[ -n "${SYSTEMD_LOAD_STATE[$1]+x}" && "${SYSTEMD_LOAD_STATE[$1]}" != "not-found" ]]
    return
  fi
  "${SYSTEMCTL_BIN}" cat "$1" >/dev/null 2>&1
}

service_is_configured() {
  case "$1" in
    amneziawg) [[ -r "${AWG_STATE}" ]] ;;
    management) [[ -r "${MANAGEMENT_STATE}" ]] ;;
    mosh) [[ -r "${MOSH_STATE}" ]] ;;
    *) return 0 ;;
  esac
}

service_state() {
  local id="$1"
  local unit=""

  if [[ "${id}" == "mosh" ]]; then
    if [[ ! -r "${MOSH_STATE}" ]]; then
      echo "未安装"
    elif [[ "$(read_assignment "${MOSH_STATE}" MOSH_ENABLED)" == "yes" ]]; then
      echo "运行中"
    else
      echo "已停止"
    fi
    return 0
  fi
  if ! service_is_configured "${id}"; then
    echo "未安装"
    return 0
  fi
  unit="$(service_unit "${id}")"
  if ! unit_exists "${unit}"; then
    echo "未安装"
  elif [[ "${SYSTEMD_STATE_CACHE_READY}" == "1" && "${SYSTEMD_ACTIVE_STATE[${unit}]:-inactive}" == "active" ]] || \
       { [[ "${SYSTEMD_STATE_CACHE_READY}" != "1" ]] && "${SYSTEMCTL_BIN}" is-active --quiet "${unit}"; }; then
    echo "运行中"
  elif [[ "${SYSTEMD_STATE_CACHE_READY}" == "1" && "${SYSTEMD_ACTIVE_STATE[${unit}]:-inactive}" == "failed" ]] || \
       { [[ "${SYSTEMD_STATE_CACHE_READY}" != "1" ]] && "${SYSTEMCTL_BIN}" is-failed --quiet "${unit}"; }; then
    echo "失败"
  else
    echo "已停止"
  fi
}

service_enabled() {
  local id="$1"
  local unit=""

  if [[ "${id}" == "mosh" ]]; then
    if [[ ! -r "${MOSH_STATE}" ]]; then
      echo "-"
    elif [[ "$(read_assignment "${MOSH_STATE}" MOSH_ENABLED)" == "yes" ]]; then
      echo "按需"
    else
      echo "未启用"
    fi
    return 0
  fi
  if [[ "${id}" == "ssh" ]]; then
    echo "受保护"
    return 0
  fi
  if ! service_is_configured "${id}"; then
    echo "-"
    return 0
  fi
  unit="$(service_unit "${id}")"
  if ! service_is_configured "${id}" || ! unit_exists "${unit}"; then
    echo "-"
  elif [[ "${SYSTEMD_STATE_CACHE_READY}" == "1" && "${SYSTEMD_UNIT_FILE_STATE[${unit}]:-disabled}" == enabled* ]] || \
       { [[ "${SYSTEMD_STATE_CACHE_READY}" != "1" ]] && "${SYSTEMCTL_BIN}" is-enabled --quiet "${unit}"; }; then
    echo "自启"
  else
    echo "未自启"
  fi
}

count_lines() {
  if [[ -s "$1" ]]; then
    awk 'NF { count++ } END { print count + 0 }' "$1"
  else
    echo 0
  fi
}

json_count() {
  local path="$1"
  local kind="$2"
  [[ -r "${path}" ]] || { echo 0; return 0; }
  python3 - "${path}" "${kind}" <<'PYTHON'
import json
import sys

path, kind = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
except (OSError, ValueError):
    print(0)
    raise SystemExit

if kind == "vless":
    clients = data.get("clients", {})
    print(sum(
        1 for item in clients.values()
        if isinstance(item, dict) and item.get("enabled", True)
    ) if isinstance(clients, dict) else 0)
elif kind == "downloads":
    downloads = data.get("downloads")
    if downloads is None and any(key in data for key in ("token", "download_name", "payload_path")):
        downloads = [data]
    if downloads is None:
        downloads = []
    print(len(downloads) if isinstance(downloads, list) else 0)
elif kind == "repositories":
    repositories = data.get("repositories")
    if isinstance(repositories, list):
        print(len(repositories))
    elif data.get("repository"):
        print(1)
    else:
        print(0)
else:
    print(0)
PYTHON
}

service_detail() {
  case "$1" in
    amneziawg) printf '%s 个普通节点' "$(count_lines "${AWG_PEERS}")" ;;
    management) printf '内网 TCP %s' "$(read_assignment "${MANAGEMENT_STATE}" MANAGEMENT_PORT)" ;;
    vless) printf '%s 个受限客户端' "$(json_count "${VLESS_POLICY}" vless)" ;;
    clash) printf '%s 个订阅链接' "$(json_count "${CLASH_CONFIG}" downloads)" ;;
    file) printf '%s 个文件资源' "$(json_count "${FILE_CONFIG}" downloads)" ;;
    mosh)
      local port_start=""
      local port_end=""
      port_start="$(read_assignment "${MOSH_STATE}" MOSH_PORT_START)"
      [[ -n "${port_start}" ]] || port_start="$(read_assignment "${MOSH_STATE}" MOSH_PORT)"
      port_end="$(read_assignment "${MOSH_STATE}" MOSH_PORT_END)"
      [[ -n "${port_end}" ]] || port_end="${port_start}"
      if [[ -n "${port_start}" && "${port_start}" != "${port_end}" ]]; then
        printf 'UDP %s-%s（按需分配）' "${port_start}" "${port_end}"
      elif [[ -n "${port_start}" ]]; then
        printf 'UDP %s（按需分配）' "${port_start}"
      else
        printf '未配置端口'
      fi
      ;;
    ssh) echo "公钥可管理，监听受保护" ;;
    cert-renew) echo "证书自动续期" ;;
    firewall) echo "只读保护项" ;;
    *) echo "" ;;
  esac
}

refresh_port_summary() {
  local unit=""
  local summary=""

  if [[ -x "${SECURITY_MANAGER}" ]]; then
    bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null 2>&1 || true
  fi
  [[ -r "${PORTS_PATH}" ]] || return 0
  while IFS=$'\t' read -r unit summary; do
    [[ -n "${unit}" ]] && PORT_SUMMARY["${unit}"]="${summary}"
  done < <(python3 "${PORT_FACTS_HELPER}" project service-summary --ports "${PORTS_PATH}" 2>/dev/null || true)
}

state_icon() {
  case "$1" in
    运行中) echo "✓" ;;
    已停止) echo "○" ;;
    失败) echo "✗" ;;
    未安装) echo "-" ;;
  esac
}

show_port_lines() {
  local summary="$1"
  local part=""
  local protocol_port=""
  local remainder=""
  local scope=""
  local listen_state=""
  local -a parts=()

  [[ -n "${summary}" ]] || return 0
  IFS='|' read -r -a parts <<< "${summary}"
  for part in "${parts[@]}"; do
    protocol_port="${part%% · *}"
    remainder="${part#* · }"
    scope="${remainder%% · *}"
    listen_state="${remainder##* · }"
    printf '  %s\n' "${protocol_port}"
    printf '  %s · %s\n' "${scope}" "${listen_state}"
  done
}

firewall_policy_rows() {
  local rules_path="${1:-}"
  [[ -r "${PORTS_PATH}" ]] || return 0
  python3 "${PORT_FACTS_HELPER}" project firewall-rows \
    --ports "${PORTS_PATH}" --rules "${rules_path}"
}

show_firewall_policy() {
  local firewall_state="$1"
  local effective="未生效"
  local rules_path=""
  local name=""
  local scope=""
  local protocol=""
  local action=""

  case "${firewall_state}" in
    运行中)
      if [[ -r "${FIREWALL_TRANSACTION}" && -r "${FIREWALL_CANDIDATE_RULES}" ]]; then
        effective="等待确认"
        rules_path="${FIREWALL_CANDIDATE_RULES}"
      elif [[ -r "${FIREWALL_ACTIVE_RULES}" ]]; then
        effective="已生效"
        rules_path="${FIREWALL_ACTIVE_RULES}"
      else
        effective="运行中"
      fi
      ;;
    失败) effective="异常" ;;
    未安装) effective="未安装" ;;
  esac

  echo "防火墙策略"
  if [[ ! -r "${PORTS_PATH}" ]]; then
    echo "  无法读取端口清单：${PORTS_PATH}"
    echo
    return 0
  fi

  if use_compact_layout; then
    printf '  方案：nftables 独立表\n'
    printf '  规则表：inet/server_kit_filter\n'
    printf '  状态：%s\n' "${effective}"
    echo "  查看原始规则："
    printf '    nft list table inet \\\n'
    printf '      server_kit_filter\n'
    while IFS=$'\t' read -r name scope protocol action; do
      case "${name}" in
        默认入站) printf '  默认入站：%s\n' "${action}" ;;
        已有连接) printf '  已有连接：%s\n' "${action}" ;;
        公网入口) printf '  公网 %s：%s\n' "${protocol}" "${action}" ;;
        内网入口) printf '  AWG %s：%s\n' "${protocol}" "${action}" ;;
        诊断报文) printf '  ICMP：%s\n' "${action}" ;;
        未登记入口) printf '  未登记入口：%s\n' "${action}" ;;
      esac
    done < <(firewall_policy_rows "${rules_path}")
  else
    {
      printf '项目\t内容\n'
      printf '方案\tnftables 独立 inet 规则表\n'
      printf '规则表\tinet server_kit_filter\n'
      printf '状态\t%s\n' "${effective}"
      printf '原始命令\tnft list table inet server_kit_filter\n'
    } | render_tab_table
    echo
    {
      printf '策略\t范围\t协议\t端口或动作\n'
      while IFS=$'\t' read -r name scope protocol action; do
        printf '%s\t%s\t%s\t%s\n' \
          "${name}" "${scope}" "${protocol}" "${action}"
      done < <(firewall_policy_rows "${rules_path}")
    } | render_tab_table
  fi
  echo
}

show_status() {
  local requested="${1:-all}"
  local id=""
  local unit=""
  local state=""
  local enabled=""
  local detail=""
  local port=""
  local protocol_port=""
  local protocol=""
  local port_value=""
  local remainder=""
  local scope=""
  local listen_state=""
  local failed=0
  local running_count=0
  local stopped_count=0
  local failed_count=0
  local missing_count=0
  local -a ids=()
  local -a missing_ids=()
  local -a port_parts=()
  declare -A states=()
  declare -A enabled_states=()
  declare -A details=()
  declare -A units=()
  declare -A ports=()

  if [[ "${requested}" == "all" ]]; then
    ids=("${SERVICE_IDS[@]}")
  else
    ids=("${requested}")
  fi
  load_service_unit_states "${ids[@]}"
  refresh_port_summary
  for id in "${ids[@]}"; do
    state="$(service_state "${id}")"
    enabled="$(service_enabled "${id}")"
    detail="$(service_detail "${id}")"
    unit="$(service_unit "${id}")"
    port=""
    [[ -n "${unit}" ]] && port="${PORT_SUMMARY[${unit}]:-}"
    states["${id}"]="${state}"
    enabled_states["${id}"]="${enabled}"
    details["${id}"]="${detail}"
    units["${id}"]="${unit}"
    ports["${id}"]="${port}"
    case "${state}" in
      运行中) ((running_count += 1)) ;;
      已停止) ((stopped_count += 1)) ;;
      失败) ((failed_count += 1)); failed=1 ;;
      未安装) ((missing_count += 1)); missing_ids+=("${id}") ;;
    esac
  done

  echo "server-kit 服务概览"
  echo "正常 ${running_count} · 停止 ${stopped_count} · 异常 ${failed_count}"
  [[ "${missing_count}" -gt 0 ]] && echo "未安装 ${missing_count}"
  echo

  if use_compact_layout; then
    for id in "${ids[@]}"; do
      state="${states[${id}]}"
      [[ "${state}" == "未安装" && "${requested}" == "all" ]] && continue
      printf '%s %s [%s]\n' "$(state_icon "${state}")" "$(service_label "${id}")" "${id}"
      printf '  %s · %s\n' "${state}" "${enabled_states[${id}]}"
      [[ -n "${details[${id}]}" ]] && printf '  %s\n' "${details[${id}]}"
      show_port_lines "${ports[${id}]}"
      echo
    done

    if [[ "${requested}" == "all" && "${missing_count}" -gt 0 ]]; then
      echo "未安装"
      for id in "${missing_ids[@]}"; do
        printf '  - %s [%s]\n' "$(service_label "${id}")" "${id}"
      done
      echo
    fi
  else
    {
      printf '状态\t服务\t标识\t运行状态\t启动方式\t详情\n'
      for id in "${ids[@]}"; do
        detail="${details[${id}]:--}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$(state_icon "${states[${id}]}")" "$(service_label "${id}")" "${id}" \
          "${states[${id}]}" "${enabled_states[${id}]}" "${detail}"
      done
    } | render_tab_table
    echo
    echo "监听端口"
    {
      printf '服务\t协议\t端口\t范围\t状态\n'
      for id in "${ids[@]}"; do
        [[ -n "${ports[${id}]}" ]] || continue
        IFS='|' read -r -a port_parts <<< "${ports[${id}]}"
        for port in "${port_parts[@]}"; do
          protocol_port="${port%% · *}"
          remainder="${port#* · }"
          protocol="${protocol_port%% *}"
          port_value="${protocol_port#* }"
          scope="${remainder%% · *}"
          listen_state="${remainder##* · }"
          printf '%s\t%s\t%s\t%s\t%s\n' \
            "$(service_label "${id}")" "${protocol}" "${port_value}" "${scope}" "${listen_state}"
        done
      done
    } | render_tab_table
    echo
  fi

  if [[ "${requested}" == "all" || "${requested}" == "firewall" ]]; then
    show_firewall_policy "${states[firewall]}"
  fi

  if use_compact_layout; then
    echo "端口清单"
    printf '  %s\n' "${PORTS_PATH}"
    echo
    echo "提示"
    echo "  SSH 和防火墙是只读保护项。"
    echo "  总管不会启停系统 SSH 或防火墙。"
  else
    {
      printf '项目\t内容\n'
      printf '端口清单\t%s\n' "${PORTS_PATH}"
      printf '保护项\tSSH、主机防火墙\n'
      printf '操作边界\t总管不会启停系统 SSH 或防火墙\n'
    } | render_tab_table
  fi
  return "${failed}"
}

show_snapshot_json() {
  local id=""
  local state=""
  local enabled=""
  local detail=""
  local unit=""
  local port=""
  local renderer="${SCRIPT_DIR}/lib/server_kit_snapshot.py"

  [[ -r "${renderer}" ]] || { fail "缺少快照渲染器：${renderer}"; return 1; }
  load_service_unit_states "${SERVICE_IDS[@]}"
  refresh_port_summary
  for id in "${SERVICE_IDS[@]}"; do
    state="$(service_state "${id}")"
    enabled="$(service_enabled "${id}")"
    detail="$(service_detail "${id}")"
    unit="$(service_unit "${id}")"
    port=""
    [[ -n "${unit}" ]] && port="${PORT_SUMMARY[${unit}]:-}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${id}" "$(service_label "${id}")" "${state}" "${enabled}" \
      "${detail}" "${unit}" "${port}"
  done | python3 "${renderer}"
}

show_inventory_json() {
  local id="$1"
  local sessions=0
  local cert_state=""
  local cert_next=""
  local cert_last=""
  local renderer="${SCRIPT_DIR}/lib/server_kit_inventory.py"
  [[ -r "${renderer}" ]] || { fail "缺少服务清单渲染器：${renderer}"; return 1; }
  if [[ "${id}" == "mosh" ]]; then
    sessions="$(pgrep -xc mosh-server 2>/dev/null || true)"
    sessions="${sessions:-0}"
  fi
  if [[ "${id}" == "cert-renew" ]]; then
    cert_state="$("${SYSTEMCTL_BIN}" show secure-file-cert-renew.timer --property=ActiveState --value 2>/dev/null || true)"
    cert_next="$("${SYSTEMCTL_BIN}" show secure-file-cert-renew.timer --property=NextElapseUSecRealtime --value 2>/dev/null || true)"
    cert_last="$("${SYSTEMCTL_BIN}" show secure-file-cert-renew.timer --property=LastTriggerUSec --value 2>/dev/null || true)"
  fi
  SERVER_KIT_CERT_TIMER_STATE="${cert_state}" \
  SERVER_KIT_CERT_NEXT_RUN="${cert_next}" \
  SERVER_KIT_CERT_LAST_RUN="${cert_last}" \
  python3 "${renderer}" "${id}" \
    "${VLESS_POLICY}" "${CLASH_CONFIG}" "${FILE_CONFIG}" \
    "${MOSH_STATE}" "${AWG_STATE}" \
    "${AWG_PEERS}" "${MANAGEMENT_STATE}" \
    "${PORTS_PATH}" "${FIREWALL_ACTIVE_RULES}" \
    "${FIREWALL_CANDIDATE_RULES}" "${FIREWALL_TRANSACTION}" \
    "${SSH_AUTH_CONFIG}" "${sessions}"
}

show_secret_resources_json() {
  local service_id="$1"
  local resource="$2"
  local item_id="$3"
  local renderer="${SCRIPT_DIR}/lib/server_kit_secret_resources.py"
  [[ -r "${renderer}" ]] || { fail "缺少敏感资源渲染器。"; return 1; }
  if [[ "${service_id}" == "clash" ]]; then
    if [[ "${resource}" == "airport-link" || "${resource}" == "exit-config" ]]; then
      [[ -r "${SCRIPT_DIR}/lib/server_kit_proxy_resources.py" ]] || { fail "缺少代理资源模块。"; return 1; }
      python3 "${SCRIPT_DIR}/lib/server_kit_proxy_resources.py" reveal "${CLASH_INPUT_CONFIG}" "${resource}" "${item_id}"
      return
    fi
    [[ "${resource}" == "subscription-link" || "${resource}" == "subscription-qr" ]] || { fail "敏感资源未登记。"; return 1; }
  elif [[ "${service_id}" == "file" ]]; then
    [[ "${resource}" == "file-link" || "${resource}" == "file-qr" ]] || { fail "敏感资源未登记。"; return 1; }
  else
    fail "敏感资源未登记。"
    return 1
  fi
  if [[ "${resource}" == *"qr" && ! -x "${QRENCODE_BIN}" && "${SERVER_KIT_TESTING:-0}" != "1" ]]; then
    fail "缺少二维码程序。"
    return 1
  fi
  python3 "${renderer}" "${CLASH_CONFIG}" "${QRENCODE_BIN}" "${FILE_CONFIG}" "${resource}" "${item_id}"
}

show_network_overview_json() {
  local renderer="${SCRIPT_DIR}/lib/server_kit_network.py"
  [[ -r "${renderer}" ]] || { fail "缺少节点视图模块。"; return 1; }
  python3 "${renderer}" "${AWG_PEERS}" "${AWG_DISABLED_PEERS}" \
    "${AWG_PEER_CREDENTIALS}" "${AWG_ENROLLMENTS}" "${AWG_ACCESS_POLICY}" "${AWG_ACCESS_PENDING_POLICY}" \
    "${VLESS_POLICY}" "${VLESS_PENDING_POLICY}" "${CLASH_CONFIG}" \
    "${CLASH_PUBLICATION_STATE}" "${NODE_DOMAINS_PATH}" "${CLASH_INPUT_CONFIG}" \
    "${MANAGEMENT_STATE}" "${SERVER_KIT_NETWORK_WRITES:-0}"
}

manage_duckdns_json() {
  local operation="$1"
  local fqdn=""
  local result=""
  local timer_state="unknown"
  local next_run=""
  [[ -r "${DUCKDNS_HELPER}" ]] || { fail "缺少动态 DNS 自动更新模块。"; return 1; }
  case "${operation}" in
    status)
      if [[ "${SERVER_KIT_TESTING:-0}" != "1" ]]; then
        timer_state="$("${SYSTEMCTL_BIN}" is-enabled "${DUCKDNS_TIMER_UNIT}" 2>/dev/null || true)"
        next_run="$("${SYSTEMCTL_BIN}" show "${DUCKDNS_TIMER_UNIT}" --property=NextElapseUSecRealtime --value 2>/dev/null || true)"
      fi
      SERVER_KIT_DUCKDNS_TIMER_STATE="${timer_state}" \
      SERVER_KIT_DUCKDNS_NEXT_RUN="${next_run}" \
        python3 "${DUCKDNS_HELPER}" status --config "${DUCKDNS_CONFIG_PATH}" --state "${DUCKDNS_STATE_PATH}"
      ;;
    configure)
      [[ "${SERVER_KIT_CONTROL:-0}" == "1" && "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || {
        fail "动态 DNS 凭据只能通过已启用的管理网页配置。"; return 1;
      }
      # DNSPod 的目标完整域名随加密请求传入，不要求先配置稳定公网入口；
      # DuckDNS 仍由 helper 校验这里读到的现有 duckdns.org 入口。
      fqdn="$(python3 "${PUBLIC_ENDPOINT_HELPER}" get --config "${PUBLIC_ENDPOINT_PATH}" 2>/dev/null || true)"
      result="$(python3 "${DUCKDNS_HELPER}" configure --config "${DUCKDNS_CONFIG_PATH}" \
        --state "${DUCKDNS_STATE_PATH}" --fqdn "${fqdn}" \
        --node-domains-config "${NODE_DOMAINS_PATH}")" || return 1
      if [[ "${SERVER_KIT_TESTING:-0}" != "1" ]] && ! "${SYSTEMCTL_BIN}" enable --now "${DUCKDNS_TIMER_UNIT}" >/dev/null; then
        python3 "${DUCKDNS_HELPER}" disable --config "${DUCKDNS_CONFIG_PATH}" --state "${DUCKDNS_STATE_PATH}" >/dev/null || true
        fail "动态 DNS 凭据已验证，但定时器启用失败，配置已保持停用。"
        return 1
      fi
      printf '%s\n' "${result}"
      ;;
    update)
      python3 "${DUCKDNS_HELPER}" update --config "${DUCKDNS_CONFIG_PATH}" --state "${DUCKDNS_STATE_PATH}"
      ;;
    disable|delete)
      [[ "${SERVER_KIT_CONTROL:-0}" == "1" && "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || {
        fail "动态 DNS 凭据只能通过已启用的管理网页变更。"; return 1;
      }
      result="$(python3 "${DUCKDNS_HELPER}" "${operation}" --config "${DUCKDNS_CONFIG_PATH}" --state "${DUCKDNS_STATE_PATH}")" || return 1
      if [[ "${SERVER_KIT_TESTING:-0}" != "1" ]]; then
        "${SYSTEMCTL_BIN}" disable --now "${DUCKDNS_TIMER_UNIT}" >/dev/null || {
          fail "动态 DNS 定时器停用失败。"; return 1;
        }
      fi
      printf '%s\n' "${result}"
      ;;
    *) fail "动态 DNS 动作未登记。"; return 1 ;;
  esac
}

manage_public_endpoint_json() {
  local operation="$1"
  local fqdn=""
  local session_id=""
  local actor=""
  local transaction_id=""
  local request_json=""
  local metadata="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/metadata.json"
  local fact_backup="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/public-endpoint.backup"
  local clash_config_backup="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/clash-config.backup"
  local clash_payload_backup="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/clash-subscriptions.backup"
  local file_config_backup="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/file-config.backup"
  local certificate_backup="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/certificate.backup"
  local key_backup="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/key.backup"
  local certificate_fact_backup="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/certificate-fact.backup"
  local backup_manifest="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/backup-manifest.json"
  local clash_payload_dir="${FILE_DATA_DIR}/clash-subscriptions"
  local clash_backed_up="false"
  local file_config_existed="false"
  local certificate_existed="false"
  local key_existed="false"
  local certificate_fact_existed="false"
  local refreshed="false"
  local result=""
  [[ -r "${PUBLIC_ENDPOINT_HELPER}" ]] || { fail "缺少稳定公网入口模块。"; return 1; }
  [[ -r "${PUBLIC_ENDPOINT_TRANSACTION_HELPER}" ]] || { fail "缺少稳定公网入口事务模块。"; return 1; }
  [[ "${PUBLIC_ENDPOINT_ROLLBACK_SECONDS}" =~ ^[0-9]+$ ]] && \
    (( PUBLIC_ENDPOINT_ROLLBACK_SECONDS >= 60 && PUBLIC_ENDPOINT_ROLLBACK_SECONDS <= 3600 )) || {
      fail "稳定公网入口回滚窗口必须为 60–3600 秒。"; return 1;
    }
  public_endpoint_write_outcome() {
    local outcome="$1"
    local outcome_transaction_id=""
    outcome_transaction_id="$(python3 - "${metadata}" <<'PYTHON'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as source: value = json.load(source)
transaction_id = value.get("transaction_id", "")
if not isinstance(transaction_id, str) or re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None:
    raise SystemExit("稳定公网入口事务标识无效")
print(transaction_id)
PYTHON
)" || return 1
    install -d -m 700 -- "$(dirname -- "${PUBLIC_ENDPOINT_OUTCOME_PATH}")"
    python3 - "${PUBLIC_ENDPOINT_OUTCOME_PATH}" "${outcome}" "${outcome_transaction_id}" <<'PYTHON'
import json, os, sys, tempfile
path, outcome, transaction_id = sys.argv[1:]
fd, temporary = tempfile.mkstemp(prefix=".public-endpoint-outcome-", dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump({"last_outcome": outcome, "transaction_id": transaction_id}, output, separators=(",", ":")); output.write("\n"); output.flush(); os.fsync(output.fileno())
os.chmod(temporary, 0o600); os.replace(temporary, path)
directory = os.open(os.path.dirname(path), os.O_DIRECTORY)
try: os.fsync(directory)
finally: os.close(directory)
PYTHON
  }
  public_endpoint_commit_confirmation() {
    python3 - "${metadata}" <<'PYTHON'
import json, os, sys, tempfile
path = sys.argv[1]
with open(path, encoding="utf-8") as source: value = json.load(source)
value["phase"] = "confirmed"
fd, temporary = tempfile.mkstemp(prefix=".metadata-", dir=os.path.dirname(path))
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(value, output, separators=(",", ":")); output.write("\n"); output.flush(); os.fsync(output.fileno())
os.chmod(temporary, 0o600); os.replace(temporary, path)
directory = os.open(os.path.dirname(path), os.O_DIRECTORY)
try: os.fsync(directory)
finally: os.close(directory)
PYTHON
  }
  public_endpoint_sync_transaction_parent() {
    python3 "${PUBLIC_ENDPOINT_TRANSACTION_HELPER}" sync-parent \
      --path "${PUBLIC_ENDPOINT_TRANSACTION_DIR}"
  }
  public_endpoint_remove_transaction() {
    rm -rf -- "${PUBLIC_ENDPOINT_TRANSACTION_DIR}" || return 1
    public_endpoint_sync_transaction_parent
  }
  public_endpoint_restore_artifact() {
    local metadata_field="$1"
    local backup="$2"
    local target="$3"
    if python3 - "${metadata}" "${metadata_field}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source: value = json.load(source)
raise SystemExit(0 if value.get(sys.argv[2]) is True else 1)
PYTHON
    then
      local temporary=""
      install -d -m 750 -- "$(dirname -- "${target}")"
      temporary="$(mktemp "$(dirname -- "${target}")/.publication.rollback.XXXXXX")"
      rm -f -- "${temporary}"
      cp -a -- "${backup}" "${temporary}" || { rm -f -- "${temporary}"; return 1; }
      mv -f -- "${temporary}" "${target}"
    else
      rm -f -- "${target}"
    fi
  }
  public_endpoint_restore() {
    local automatic="${1:-0}"
    local staged_payload=""
    local displaced_payload=""
    local replaced_payload=""
    [[ -r "${metadata}" ]] || return 0
    if python3 - "${metadata}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source: value = json.load(source)
raise SystemExit(0 if value.get("phase") == "confirmed" else 1)
PYTHON
    then
      public_endpoint_write_outcome confirmed
      public_endpoint_remove_transaction
      return 0
    fi
    if ! python3 "${PUBLIC_ENDPOINT_TRANSACTION_HELPER}" verify \
        --metadata "${metadata}" --manifest "${backup_manifest}" \
        --fact-backup "${fact_backup}" --clash-config-backup "${clash_config_backup}" \
        --clash-payload-backup "${clash_payload_backup}" \
        --file-config-backup "${file_config_backup}" \
        --certificate-backup "${certificate_backup}" --key-backup "${key_backup}" \
        --certificate-fact-backup "${certificate_fact_backup}"
    then
      fail "稳定公网入口回滚备份不完整或摘要不匹配；事务及现有内容已保留，补全备份后重试。"
      return 1
    fi
    if python3 - "${metadata}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
raise SystemExit(0 if value.get("fact_existed") is True else 1)
PYTHON
    then
      local temporary_fact=""
      temporary_fact="$(mktemp "$(dirname -- "${PUBLIC_ENDPOINT_PATH}")/.public-endpoint.rollback.XXXXXX")"
      cp -a -- "${fact_backup}" "${temporary_fact}"
      mv -f -- "${temporary_fact}" "${PUBLIC_ENDPOINT_PATH}"
    else
      rm -f -- "${PUBLIC_ENDPOINT_PATH}"
    fi
    public_endpoint_restore_artifact file_config_existed "${file_config_backup}" "${FILE_CONFIG}" || return 1
    public_endpoint_restore_artifact certificate_existed "${certificate_backup}" "${PUBLICATION_CERT_PATH}" || return 1
    public_endpoint_restore_artifact key_existed "${key_backup}" "${PUBLICATION_KEY_PATH}" || return 1
    public_endpoint_restore_artifact certificate_fact_existed "${certificate_fact_backup}" "${PUBLICATION_CERT_FACT_PATH}" || return 1
    if [[ -r "${clash_config_backup}" && -d "${clash_payload_backup}" ]]; then
      staged_payload="$(mktemp -d "$(dirname -- "${clash_payload_dir}")/.clash-subscriptions.restore.XXXXXX")"
      rm -rf -- "${staged_payload}"
      cp -a -- "${clash_payload_backup}" "${staged_payload}"
      displaced_payload="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/clash-subscriptions.displaced"
      replaced_payload="${PUBLIC_ENDPOINT_TRANSACTION_DIR}/clash-subscriptions.replaced"
      if [[ ! -e "${displaced_payload}" ]]; then
        [[ -d "${clash_payload_dir}" ]] || {
          rm -rf -- "${staged_payload}"
          fail "Clash 在线发布目录缺失且尚未保存置换副本；事务已保留。"; return 1;
        }
        mv -- "${clash_payload_dir}" "${displaced_payload}"
        if [[ "${SERVER_KIT_TESTING:-0}" == "1" && \
              "${SERVER_KIT_TEST_FAILPOINT:-}" == "public_endpoint_restore_after_displace" ]]; then
          rm -rf -- "${staged_payload}"
          return 97
        fi
      fi
      if [[ -e "${clash_payload_dir}" ]]; then
        rm -rf -- "${replaced_payload}"
        mv -- "${clash_payload_dir}" "${replaced_payload}"
      fi
      mv -- "${staged_payload}" "${clash_payload_dir}"
      cp -a -- "${clash_config_backup}" "${CLASH_CONFIG}.rollback.$$"
      mv -f -- "${CLASH_CONFIG}.rollback.$$" "${CLASH_CONFIG}"
      "${SYSTEMCTL_BIN}" restart secure-clash-service >/dev/null 2>&1 || {
        fail "稳定公网入口事实已恢复，但 Clash 服务重启失败；事务已保留，可重试回滚。"; return 1;
      }
    fi
    if [[ -r "${FILE_CONFIG}" ]]; then
      "${SYSTEMCTL_BIN}" restart secure-file-service >/dev/null 2>&1 || {
        fail "稳定公网入口事实已恢复，但普通文件服务重启失败；事务已保留，可重试回滚。"; return 1;
      }
    fi
    local restored_endpoint_valid="true"
    if [[ -e "${PUBLIC_ENDPOINT_PATH}" ]] && ! python3 "${PUBLIC_ENDPOINT_HELPER}" get \
        --config "${PUBLIC_ENDPOINT_PATH}" >/dev/null 2>&1; then
      restored_endpoint_valid="false"
    fi
    if [[ "${restored_endpoint_valid}" == "true" && ( -r "${CLASH_CONFIG}" || -r "${FILE_CONFIG}" ) ]]; then
      PUBLIC_ENDPOINT_CONFIG="${PUBLIC_ENDPOINT_PATH}" \
      FILE_CONFIG_PATH="${FILE_CONFIG}" CLASH_CONFIG_PATH="${CLASH_CONFIG}" \
      CERT_PATH="${PUBLICATION_CERT_PATH}" KEY_PATH="${PUBLICATION_KEY_PATH}" \
      CERT_IP_PATH="${PUBLICATION_CERT_FACT_PATH}" \
        bash "${FILE_MANAGER}" reconcile-public-ip --yes >/dev/null 2>&1 || {
          fail "发布地址已恢复，但证书续期配置未能恢复；事务已保留，可重试回滚。"; return 1;
        }
    fi
    python3 "${PUBLIC_ENDPOINT_TRANSACTION_HELPER}" sync-restored \
      --endpoint "${PUBLIC_ENDPOINT_PATH}" --clash-config "${CLASH_CONFIG}" \
      --clash-payload "${clash_payload_dir}" --file-config "${FILE_CONFIG}" \
      --certificate "${PUBLICATION_CERT_PATH}" --key "${PUBLICATION_KEY_PATH}" \
      --certificate-fact "${PUBLICATION_CERT_FACT_PATH}" || {
        fail "稳定公网入口恢复内容无法完成持久化落盘；事务及备份已保留。"; return 1;
      }
    python3 "${PUBLIC_ENDPOINT_TRANSACTION_HELPER}" verify-restored \
      --metadata "${metadata}" --manifest "${backup_manifest}" \
      --endpoint "${PUBLIC_ENDPOINT_PATH}" --clash-config "${CLASH_CONFIG}" \
      --clash-payload "${clash_payload_dir}" --file-config "${FILE_CONFIG}" \
      --certificate "${PUBLICATION_CERT_PATH}" --key "${PUBLICATION_KEY_PATH}" \
      --certificate-fact "${PUBLICATION_CERT_FACT_PATH}" || {
        fail "稳定公网入口恢复后的在线内容与备份摘要不一致；事务及备份已保留。"; return 1;
      }
    public_endpoint_write_outcome "$([[ "${automatic}" == "1" ]] && echo automatic_rollback || echo rolled_back)"
    public_endpoint_remove_transaction
  }
  public_endpoint_render_transaction() {
    python3 - "${PUBLIC_ENDPOINT_PATH}" "${metadata}" "${PUBLIC_ENDPOINT_OUTCOME_PATH}" \
      "${session_id}" "${operation}" "${PUBLIC_ENDPOINT_ROLLBACK_SECONDS}" "${refreshed}" <<'PYTHON'
import hashlib, json, os, re, sys, time
fact_path, metadata_path, outcome_path, session_id, operation, rollback, refreshed = sys.argv[1:]
fqdn = ""
try:
    with open(fact_path, encoding="utf-8") as source: fact = json.load(source)
    if isinstance(fact, dict) and isinstance(fact.get("fqdn"), str): fqdn = fact["fqdn"]
except (FileNotFoundError, OSError, json.JSONDecodeError): pass
state, expires_at, remaining, independent = "idle", "", 0, True
last_outcome, transaction_id = "", ""
if os.path.isfile(metadata_path):
    with open(metadata_path, encoding="utf-8") as source: metadata = json.load(source)
    transaction_id = metadata.get("transaction_id", "")
    if metadata.get("phase") == "confirmed":
        last_outcome = "confirmed"
    else:
        expires = int(metadata["expires_epoch"])
        state, expires_at, remaining = "pending", metadata["expires_at"], max(0, expires - int(time.time()))
        independent = hashlib.sha256(session_id.encode("ascii")).hexdigest() != metadata["session_hash"]
elif os.path.isfile(outcome_path):
    with open(outcome_path, encoding="utf-8") as source: outcome = json.load(source)
    last_outcome, transaction_id = outcome.get("last_outcome", ""), outcome.get("transaction_id", "")
if transaction_id and (not isinstance(transaction_id, str) or re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None):
    raise SystemExit("稳定公网入口事务标识无效")
print(json.dumps({"schema_version":1,"operation":operation,"transaction_id":transaction_id,"fqdn":fqdn,"subscriptions_refreshed":refreshed == "true","state":state,"expires_at":expires_at,"remaining_seconds":remaining,"rollback_seconds":int(rollback),"independent_session":independent,"last_outcome":last_outcome}, separators=(",", ":")))
PYTHON
  }
  case "${operation}" in
    status) python3 "${PUBLIC_ENDPOINT_HELPER}" status --config "${PUBLIC_ENDPOINT_PATH}" ;;
    transaction-status|apply|confirm|rollback|automatic-rollback)
      if [[ "${operation}" != "automatic-rollback" ]]; then
        [[ "${SERVER_KIT_CONTROL:-0}" == "1" && "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "稳定公网入口只能通过已启用的控制面变更任务修改。"; return 1; }
      fi
      if [[ "${operation}" != "automatic-rollback" ]]; then
        request_json="$(cat)"
        mapfile -t request_values < <(python3 -c 'import json,sys; v=json.load(sys.stdin); [print(v.get(k,"")) for k in ("fqdn","session_id","actor","transaction_id")]' <<<"${request_json}")
        [[ "${#request_values[@]}" -eq 4 ]] || { fail "稳定公网入口任务输入无效。"; return 1; }
        fqdn="${request_values[0]}"; session_id="${request_values[1]}"; actor="${request_values[2]}"; transaction_id="${request_values[3]}"
        [[ "${session_id}" =~ ^[0-9a-f]{64}$ && -n "${actor}" ]] || { fail "稳定公网入口任务会话无效。"; return 1; }
      fi
      if [[ "${operation}" == "transaction-status" ]]; then
        if [[ -r "${metadata}" ]] && ! python3 - "${metadata}" <<'PYTHON'
import json, sys, time
with open(sys.argv[1], encoding="utf-8") as source: value = json.load(source)
raise SystemExit(0 if value.get("phase") == "pending" and int(value["expires_epoch"]) > int(time.time()) else 1)
PYTHON
        then
          public_endpoint_restore 1 || return 1
          "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
        fi
        operation="status"; public_endpoint_render_transaction; return
      fi
      if [[ "${operation}" == "confirm" ]]; then
        [[ -r "${metadata}" ]] || { fail "当前没有待确认的稳定公网入口事务。"; return 1; }
        python3 - "${metadata}" "${transaction_id}" <<'PYTHON' || { fail "稳定公网入口事务标识不匹配。"; return 1; }
import json, secrets, sys
with open(sys.argv[1], encoding="utf-8") as source: expected=json.load(source).get("transaction_id", "")
raise SystemExit(0 if secrets.compare_digest(expected, sys.argv[2]) else 1)
PYTHON
        if ! python3 - "${metadata}" <<'PYTHON'
import json, sys, time
with open(sys.argv[1], encoding="utf-8") as source: value = json.load(source)
raise SystemExit(0 if value.get("phase") == "pending" and int(value["expires_epoch"]) > int(time.time()) else 1)
PYTHON
        then
          public_endpoint_restore 1 || return 1
          "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
          fail "稳定公网入口回滚窗口已过期，变更已自动回滚。"
          return 1
        fi
        if python3 - "${metadata}" "${session_id}" <<'PYTHON'
import hashlib,json,sys
with open(sys.argv[1], encoding="utf-8") as source: origin=json.load(source)["session_hash"]
raise SystemExit(0 if origin == hashlib.sha256(sys.argv[2].encode("ascii")).hexdigest() else 1)
PYTHON
        then fail "原发起会话不能确认稳定公网入口，请从另一条独立登录连接操作。"; return 1; fi
        public_endpoint_commit_confirmation
        if [[ "${SERVER_KIT_TESTING:-0}" == "1" && \
              "${SERVER_KIT_TEST_FAILPOINT:-}" == "public_endpoint_confirm_after_commit" ]]; then
          return 97
        fi
        public_endpoint_write_outcome confirmed
        public_endpoint_remove_transaction
        "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
        public_endpoint_render_transaction; return
      fi
      if [[ "${operation}" == "rollback" || "${operation}" == "automatic-rollback" ]]; then
        if [[ "${operation}" == "rollback" && ! -r "${metadata}" ]]; then
          fail "当前没有待确认的稳定公网入口事务。"
          return 1
        fi
        if [[ "${operation}" == "rollback" ]]; then
          python3 - "${metadata}" "${transaction_id}" <<'PYTHON' || { fail "稳定公网入口事务标识不匹配。"; return 1; }
import json, secrets, sys
with open(sys.argv[1], encoding="utf-8") as source: expected=json.load(source).get("transaction_id", "")
raise SystemExit(0 if secrets.compare_digest(expected, sys.argv[2]) else 1)
PYTHON
        fi
        public_endpoint_restore "$([[ "${operation}" == "automatic-rollback" ]] && echo 1 || echo 0)"
        [[ "${operation}" == "automatic-rollback" ]] || "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
        operation="rollback"; public_endpoint_render_transaction; return
      fi
      [[ ! -e "${metadata}" ]] || { fail "已有待确认的稳定公网入口事务。"; return 1; }
      if [[ -n "${fqdn}" ]] && ! python3 "${NODE_DOMAIN_HELPER}" validate-host \
          --config "${NODE_DOMAINS_PATH}" --active "${AWG_PEERS}" \
          --disabled "${AWG_DISABLED_PEERS}" --reserved-host "${fqdn}" \
          >/dev/null; then
        fail "稳定公网入口会被现有订阅通配符覆盖，拒绝变更。"
        return 1
      fi
      [[ ! -d "${PUBLIC_ENDPOINT_TRANSACTION_DIR}" ]] || public_endpoint_remove_transaction
      install -d -m 700 -- "${PUBLIC_ENDPOINT_TRANSACTION_DIR}"
      public_endpoint_sync_transaction_parent || {
        rm -rf -- "${PUBLIC_ENDPOINT_TRANSACTION_DIR}"
        fail "稳定公网入口事务目录无法完成持久化。"
        return 1
      }
      rm -f -- "${PUBLIC_ENDPOINT_OUTCOME_PATH}"
      result="$(mktemp)"
      trap 'rm -f -- "${result:-}"' RETURN
      if [[ -e "${PUBLIC_ENDPOINT_PATH}" ]]; then
        cp -a -- "${PUBLIC_ENDPOINT_PATH}" "${fact_backup}"
        fact_existed=true
      else
        fact_existed=false
      fi
      if [[ -r "${CLASH_CONFIG}" ]]; then
        if [[ ! -d "${clash_payload_dir}" ]]; then
          public_endpoint_remove_transaction
          fail "检测到 Clash 配置但发布目录缺失，稳定公网入口未变更。"
          return 1
        fi
        if ! cp -a -- "${CLASH_CONFIG}" "${clash_config_backup}" || \
            ! cp -a -- "${clash_payload_dir}" "${clash_payload_backup}"; then
          public_endpoint_remove_transaction
          fail "Clash 发布层备份失败，稳定公网入口未变更。"
          return 1
        fi
        clash_backed_up=true
      fi
      if [[ -e "${FILE_CONFIG}" ]]; then
        cp -a -- "${FILE_CONFIG}" "${file_config_backup}" || {
          public_endpoint_remove_transaction
          fail "普通文件发布配置备份失败，稳定公网入口未变更。"
          return 1
        }
        file_config_existed=true
      fi
      if [[ -e "${PUBLICATION_CERT_PATH}" ]]; then
        cp -a -- "${PUBLICATION_CERT_PATH}" "${certificate_backup}" || {
          public_endpoint_remove_transaction
          fail "HTTPS 发布证书备份失败，稳定公网入口未变更。"
          return 1
        }
        certificate_existed=true
      fi
      if [[ -e "${PUBLICATION_KEY_PATH}" ]]; then
        cp -a -- "${PUBLICATION_KEY_PATH}" "${key_backup}" || {
          public_endpoint_remove_transaction
          fail "HTTPS 发布密钥备份失败，稳定公网入口未变更。"
          return 1
        }
        key_existed=true
      fi
      if [[ -e "${PUBLICATION_CERT_FACT_PATH}" ]]; then
        cp -a -- "${PUBLICATION_CERT_FACT_PATH}" "${certificate_fact_backup}" || {
          public_endpoint_remove_transaction
          fail "HTTPS 证书事实备份失败，稳定公网入口未变更。"
          return 1
        }
        certificate_fact_existed=true
      fi
      manifest_arguments=(
        create --manifest "${backup_manifest}" --fact-backup "${fact_backup}"
        --clash-config-backup "${clash_config_backup}"
        --clash-payload-backup "${clash_payload_backup}"
        --file-config-backup "${file_config_backup}"
        --certificate-backup "${certificate_backup}" --key-backup "${key_backup}"
        --certificate-fact-backup "${certificate_fact_backup}"
      )
      [[ "${fact_existed}" == "true" ]] && manifest_arguments+=(--fact-existed)
      [[ "${clash_backed_up}" == "true" ]] && manifest_arguments+=(--clash-backed-up)
      [[ "${file_config_existed}" == "true" ]] && manifest_arguments+=(--file-config-existed)
      [[ "${certificate_existed}" == "true" ]] && manifest_arguments+=(--certificate-existed)
      [[ "${key_existed}" == "true" ]] && manifest_arguments+=(--key-existed)
      [[ "${certificate_fact_existed}" == "true" ]] && manifest_arguments+=(--certificate-fact-existed)
      backup_manifest_sha256="$(python3 "${PUBLIC_ENDPOINT_TRANSACTION_HELPER}" "${manifest_arguments[@]}")" || {
        public_endpoint_remove_transaction
        "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
        fail "稳定公网入口回滚备份无法完成完整性清单和持久化。"
        return 1
      }
      python3 - "${metadata}" "${fact_existed}" "${clash_backed_up}" \
        "${file_config_existed}" "${certificate_existed}" "${key_existed}" \
        "${certificate_fact_existed}" "${backup_manifest_sha256}" "${session_id}" \
        "${PUBLIC_ENDPOINT_ROLLBACK_SECONDS}" <<'PYTHON'
import hashlib,json,os,secrets,sys,tempfile,time
from datetime import datetime,timezone
path, existed, clash_backed_up, file_config_existed, certificate_existed, key_existed, certificate_fact_existed, manifest_sha256, session, seconds=sys.argv[1:]; expires=int(time.time())+int(seconds)
value={"phase":"pending","transaction_id":secrets.token_hex(32),"fact_existed":existed=="true","clash_backed_up":clash_backed_up=="true","file_config_existed":file_config_existed=="true","certificate_existed":certificate_existed=="true","key_existed":key_existed=="true","certificate_fact_existed":certificate_fact_existed=="true","backup_manifest_sha256":manifest_sha256,"session_hash":hashlib.sha256(session.encode()).hexdigest(),"expires_epoch":expires,"expires_at":datetime.fromtimestamp(expires,timezone.utc).isoformat()}
fd,tmp=tempfile.mkstemp(prefix=".metadata-",dir=os.path.dirname(path))
with os.fdopen(fd,"w") as out: json.dump(value,out,separators=(",", ":")); out.write("\n"); out.flush(); os.fsync(out.fileno())
os.chmod(tmp,0o600); os.replace(tmp,path)
directory=os.open(os.path.dirname(path),os.O_DIRECTORY)
try: os.fsync(directory)
finally: os.close(directory)
PYTHON
      if ! "${SYSTEMD_RUN_BIN}" --quiet --unit="${PUBLIC_ENDPOINT_ROLLBACK_UNIT}" \
          --on-active="${PUBLIC_ENDPOINT_ROLLBACK_SECONDS}s" --timer-property=AccuracySec=1s \
          --property=Restart=on-failure --property=RestartSec=10s \
          "${SCRIPT_PATH}" network public-endpoint automatic-rollback --json; then
        public_endpoint_remove_transaction
        fail "稳定公网入口自动回滚计时器创建失败，入口事实和发布订阅未变更。"
        return 1
      fi
      if [[ -n "${fqdn}" ]]; then
        if ! python3 "${PUBLIC_ENDPOINT_HELPER}" set --config "${PUBLIC_ENDPOINT_PATH}" --fqdn "${fqdn}" >"${result}"; then
          public_endpoint_restore 0
          "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
          fail "稳定公网入口事实写入失败，原事实和发布内容保持不变。"
          return 1
        fi
      else
        if ! python3 "${PUBLIC_ENDPOINT_HELPER}" clear --config "${PUBLIC_ENDPOINT_PATH}" >"${result}"; then
          public_endpoint_restore 0
          "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
          fail "稳定公网入口事实清除失败，原事实和发布内容保持不变。"
          return 1
        fi
      fi
      if [[ -r "${CLASH_CONFIG}" || -r "${FILE_CONFIG}" ]]; then
        if ! PUBLIC_ENDPOINT_CONFIG="${PUBLIC_ENDPOINT_PATH}" \
            SERVER_KIT_CONFIG_DIR="$(dirname -- "${PUBLIC_ENDPOINT_PATH}")" \
            FILE_CONFIG_PATH="${FILE_CONFIG}" CLASH_CONFIG_PATH="${CLASH_CONFIG}" \
            CERT_PATH="${PUBLICATION_CERT_PATH}" KEY_PATH="${PUBLICATION_KEY_PATH}" \
            CERT_IP_PATH="${PUBLICATION_CERT_FACT_PATH}" \
            bash "${FILE_MANAGER}" reconcile-public-ip --yes >/dev/null 2>&1; then
          public_endpoint_restore 0
          "${SYSTEMCTL_BIN}" stop "${PUBLIC_ENDPOINT_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
          fail "稳定公网入口联动迁移失败，入口事实、HTTPS 证书和发布链接已恢复。"
          return 1
        fi
        [[ -r "${CLASH_CONFIG}" ]] && refreshed="true"
      fi
      operation="apply"
      public_endpoint_render_transaction
      rm -f -- "${result}"
      result=""
      trap - RETURN
      ;;
    *) fail "稳定公网入口动作未登记。"; return 1 ;;
  esac
}

change_node_domains_json() {
  local name="$1"
  local domains_json="$2"
  local target_type="${3:-node}"
  local result=""
  local backup=""
  local existed="0"
  local refreshed="false"
  local xray_refreshed="false"
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "节点写操作未启用。"; return 1; }
  if [[ "${target_type}" == "node" ]]; then
    [[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { fail "节点名称格式不正确。"; return 1; }
  elif [[ "${target_type}" != "address" ]]; then
    fail "强制解析目标类型不正确。"
    return 1
  fi
  [[ -r "${NODE_DOMAIN_HELPER}" ]] || { fail "缺少节点域名管理模块。"; return 1; }
  backup="$(mktemp)"
  result="$(mktemp)"
  trap 'rm -f -- "${backup:-}" "${result:-}"' RETURN
  if [[ -e "${NODE_DOMAINS_PATH}" ]]; then
    cp -a -- "${NODE_DOMAINS_PATH}" "${backup}"
    existed="1"
  fi
  if [[ "${target_type}" == "node" ]]; then
    if ! python3 "${NODE_DOMAIN_HELPER}" set --config "${NODE_DOMAINS_PATH}" \
        --active "${AWG_PEERS}" --disabled "${AWG_DISABLED_PEERS}" \
        --public-endpoint-config "${PUBLIC_ENDPOINT_PATH}" \
        --dynamic-dns-config "${DUCKDNS_CONFIG_PATH}" \
        --name "${name}" --domains-json "${domains_json}" >"${result}"; then
      fail "节点域名配置无效。"
      return 1
    fi
  else
    if ! python3 "${NODE_DOMAIN_HELPER}" set-address --config "${NODE_DOMAINS_PATH}" \
        --active "${AWG_PEERS}" --disabled "${AWG_DISABLED_PEERS}" \
        --public-endpoint-config "${PUBLIC_ENDPOINT_PATH}" \
        --dynamic-dns-config "${DUCKDNS_CONFIG_PATH}" \
        --address "${name}" --domains-json "${domains_json}" >"${result}"; then
      fail "自定义强制解析配置无效。"
      return 1
    fi
  fi
  if [[ -r "${XRAY_CONFIG_PATH}" ]]; then
    if ! bash "${VLESS_MANAGER}" refresh-domains >/dev/null 2>&1; then
      if [[ "${existed}" == "1" ]]; then
        install -m 600 -o root -g root -- "${backup}" "${NODE_DOMAINS_PATH}"
      else
        rm -f -- "${NODE_DOMAINS_PATH}"
      fi
      fail "Xray 内网域名刷新失败，节点域名配置已恢复。"
      return 1
    fi
    xray_refreshed="true"
  fi
  if [[ -r "${CLASH_CONFIG}" ]]; then
    if ! bash "${FILE_MANAGER}" refresh-clash >/dev/null 2>&1; then
      if [[ "${existed}" == "1" ]]; then
        install -m 600 -o root -g root -- "${backup}" "${NODE_DOMAINS_PATH}"
      else
        rm -f -- "${NODE_DOMAINS_PATH}"
      fi
      if [[ "${xray_refreshed}" == "true" ]]; then
        bash "${VLESS_MANAGER}" refresh-domains >/dev/null 2>&1 || {
          fail "订阅刷新失败；节点配置已恢复，但 Xray DNS 自动回滚失败。"
          return 1
        }
      fi
      fail "订阅刷新失败，节点域名配置已恢复。"
      return 1
    fi
    refreshed="true"
  fi
  python3 - "${result}" "${refreshed}" "${xray_refreshed}" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    result = json.load(source)
result["subscriptions_refreshed"] = sys.argv[2] == "true"
result["xray_refreshed"] = sys.argv[3] == "true"
json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
print()
PYTHON
  rm -f -- "${backup}" "${result}"
  backup=""
  result=""
  trap - RETURN
}

show_proxy_resources_json() {
  local helper="${SCRIPT_DIR}/lib/server_kit_proxy_resources.py"
  [[ -r "${helper}" ]] || { fail "缺少机场资源模块。"; return 1; }
  python3 "${helper}" overview "${CLASH_INPUT_CONFIG}"
}

show_file_resources_json() {
  local state=""
  [[ -r "${FILE_RESOURCE_HELPER}" ]] || { fail "缺少文件资源模块。"; return 1; }
  load_service_unit_states file
  state="$(service_state file)"
  python3 "${FILE_RESOURCE_HELPER}" overview --config "${FILE_CONFIG}" \
    --data-dir "${FILE_DATA_DIR}" --service-state "${state}"
}

inspect_file_upload_json() {
  local upload_id="$1"
  local upload_path=""
  [[ "${upload_id}" =~ ^[0-9a-f]{32}$ ]] || { fail "上传标识无效。"; return 1; }
  upload_path="${WEB_UPLOAD_DIR}/${upload_id}/payload"
  python3 - "${upload_id}" "${upload_path}" "${FILE_UPLOAD_MAX_BYTES}" <<'PYTHON'
import hashlib
import json
import os
import stat
import sys

upload_id, path, maximum = sys.argv[1], sys.argv[2], int(sys.argv[3])
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= maximum:
        raise ValueError("暂存文件类型或大小无效")
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
finally:
    os.close(descriptor)
json.dump({
    "schema_version": 1,
    "upload_id": upload_id,
    "size": metadata.st_size,
    "sha256": digest.hexdigest(),
}, sys.stdout, ensure_ascii=False, separators=(",", ":"))
print()
PYTHON
}

discard_file_upload_json() {
  local upload_id="$1"
  local upload_root=""
  [[ "${upload_id}" =~ ^[0-9a-f]{32}$ ]] || { fail "上传标识无效。"; return 1; }
  upload_root="${WEB_UPLOAD_DIR}/${upload_id}"
  if [[ -L "${upload_root}" ]]; then
    fail "暂存目录类型无效。"
    return 1
  fi
  if [[ -d "${upload_root}" ]]; then
    rm -rf --one-file-system -- "${upload_root}"
  fi
  printf '{"schema_version":1,"discarded":true}\n'
}

change_file_resource_json() {
  local operation="$1"
  local value="${2:-}"
  local download_name="${3:-}"
  local cdn_cache="${4:-true}"
  local cache_ttl="${5:-86400}"
  local upload_root=""
  local upload_path=""
  local config_backup=""
  local result_path=""
  local payload_path=""
  local was_active="0"
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "文件资源写操作未启用。"; return 1; }
  [[ -r "${FILE_RESOURCE_HELPER}" && -r "${FILE_CONFIG}" ]] || { fail "普通文件服务尚未安装。"; return 1; }
  [[ "${FILE_UPLOAD_MAX_BYTES}" =~ ^[0-9]+$ ]] && (( FILE_UPLOAD_MAX_BYTES >= 52428800 )) || {
    fail "普通文件上传上限配置无效。"
    return 1
  }
  config_backup="$(mktemp)"
  result_path="$(mktemp)"
  cp -a -- "${FILE_CONFIG}" "${config_backup}"
  trap 'rm -f -- "${config_backup:-}" "${result_path:-}"; [[ -n "${upload_root:-}" && -d "${upload_root}" ]] && rm -rf --one-file-system -- "${upload_root}"' RETURN
  if "${SYSTEMCTL_BIN}" is-active --quiet secure-file-service.service; then was_active="1"; fi
  case "${operation}" in
    add)
      [[ "${value}" =~ ^[0-9a-f]{32}$ ]] || { fail "上传标识无效。"; return 1; }
      [[ "${download_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { fail "下载文件名无效。"; return 1; }
      [[ "${cdn_cache}" == "true" || "${cdn_cache}" == "false" ]] || { fail "CDN 缓存开关无效。"; return 1; }
      [[ "${cache_ttl}" =~ ^[0-9]+$ ]] && (( cache_ttl >= 300 && cache_ttl <= 2592000 )) || { fail "CDN 缓存时间无效。"; return 1; }
      upload_root="${WEB_UPLOAD_DIR}/${value}"
      upload_path="${upload_root}/payload"
      [[ -f "${upload_path}" && ! -L "${upload_path}" ]] || { fail "上传文件不存在或类型无效。"; return 1; }
      if ! python3 "${FILE_RESOURCE_HELPER}" add --config "${FILE_CONFIG}" --data-dir "${FILE_DATA_DIR}" \
        --source "${upload_path}" --name "${download_name}" --cdn-cache "${cdn_cache}" \
        --cache-ttl "${cache_ttl}" --max-bytes "${FILE_UPLOAD_MAX_BYTES}" >"${result_path}"; then
        fail "文件资源写入失败。"
        return 1
      fi
      rm -rf --one-file-system -- "${upload_root}"
      upload_root=""
      ;;
    delete)
      [[ "${value}" =~ ^file-[0-9a-f]{16}$ ]] || { fail "文件资源标识无效。"; return 1; }
      if ! python3 "${FILE_RESOURCE_HELPER}" detach --config "${FILE_CONFIG}" --data-dir "${FILE_DATA_DIR}" \
        --resource-id "${value}" >"${result_path}"; then
        fail "文件资源删除失败。"
        return 1
      fi
      ;;
    *) fail "文件资源动作未登记。"; return 1 ;;
  esac
  payload_path="$(python3 - "${result_path}" <<'PYTHON'
import json
import sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
value = data.get("payload_path", "")
print(value if isinstance(value, str) else "")
PYTHON
)"
  if [[ "${was_active}" == "1" ]] && ! "${SYSTEMCTL_BIN}" restart secure-file-service.service; then
    cp -a -- "${config_backup}" "${FILE_CONFIG}"
    "${SYSTEMCTL_BIN}" restart secure-file-service.service >/dev/null 2>&1 || true
    if [[ "${operation}" == "add" && -n "${payload_path}" ]]; then
      python3 "${FILE_RESOURCE_HELPER}" purge --config "${FILE_CONFIG}" --data-dir "${FILE_DATA_DIR}" --payload-path "${payload_path}" >/dev/null 2>&1 || true
    fi
    fail "文件服务重载失败，配置已恢复。"
    return 1
  fi
  if [[ "${operation}" == "delete" && -n "${payload_path}" ]]; then
    python3 "${FILE_RESOURCE_HELPER}" purge --config "${FILE_CONFIG}" --data-dir "${FILE_DATA_DIR}" --payload-path "${payload_path}" >/dev/null
  fi
  python3 - "${result_path}" <<'PYTHON'
import json
import sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
print(json.dumps({
    "schema_version": 1,
    "operation": data["operation"],
    "resource_id": data["resource_id"],
}, ensure_ascii=False, separators=(",", ":")))
PYTHON
  rm -f -- "${config_backup}" "${result_path}"
  config_backup=""
  result_path=""
  trap - RETURN
}

test_proxy_resources_json() {
  local helper="${SCRIPT_DIR}/lib/server_kit_proxy_resources.py"
  [[ -r "${helper}" ]] || { fail "缺少机场资源模块。"; return 1; }
  python3 "${helper}" test "${CLASH_INPUT_CONFIG}"
}

update_proxy_resources_json() {
  local helper="${SCRIPT_DIR}/lib/server_kit_proxy_resources.py"
  local backup=""
  local status_output=""
  local had_existing="0"
  local refresh_output=""
  local relay_refreshed="0"
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { safe_diagnostic "proxy_write_disabled"; fail "机场资源写操作未启用。"; return 1; }
  [[ -r "${helper}" ]] || { safe_diagnostic "proxy_module_missing"; fail "缺少机场资源模块。"; return 1; }
  [[ -r "${CLASH_CONFIG}" ]] || { safe_diagnostic "proxy_service_missing"; fail "Clash 订阅服务尚未安装。"; return 1; }
  backup="$(mktemp)"
  status_output="$(mktemp)"
  refresh_output="$(mktemp)"
  trap 'rm -f -- "${backup:-}" "${status_output:-}" "${refresh_output:-}"' RETURN
  if [[ -r "${CLASH_INPUT_CONFIG}" ]]; then
    cp -a -- "${CLASH_INPUT_CONFIG}" "${backup}"
    had_existing="1"
  fi
  if ! python3 "${helper}" update "${CLASH_INPUT_CONFIG}" >"${status_output}"; then
    fail "机场资源内容无效，未刷新订阅。"
    return 1
  fi
  if [[ -r "$(dirname -- "${CLASH_INPUT_CONFIG}")/server-relay.json" ]]; then
    if ! bash "${VLESS_MANAGER}" relay-refresh >"${refresh_output}" 2>&1; then
      if [[ "${had_existing}" == "1" ]]; then
        cp -a -- "${backup}" "${CLASH_INPUT_CONFIG}"
        bash "${VLESS_MANAGER}" relay-refresh >/dev/null 2>&1 || true
      else
        rm -f -- "${CLASH_INPUT_CONFIG}"
      fi
      safe_diagnostic "proxy_relay_refresh_failed"
      fail "服务端中转出口刷新失败，已恢复原机场资源配置。"
      return 1
    fi
    relay_refreshed="1"
  fi
  if ! bash "${FILE_MANAGER}" refresh-clash >"${refresh_output}" 2>&1; then
    if [[ "${had_existing}" == "1" ]]; then
      cp -a -- "${backup}" "${CLASH_INPUT_CONFIG}"
    else
      rm -f -- "${CLASH_INPUT_CONFIG}"
    fi
    [[ "${relay_refreshed}" == "1" ]] && bash "${VLESS_MANAGER}" relay-refresh >/dev/null 2>&1 || true
    safe_diagnostic "proxy_subscription_refresh_failed"
    fail "机场资源刷新失败，已恢复原配置和订阅。"
    return 1
  fi
  cat "${status_output}"
}

deploy_service_json() {
  local service_id="$1"
  local port="${2:-}"
  local option="${3:-}"
  local output=""
  local helper="${SCRIPT_DIR}/lib/server_kit_proxy_resources.py"
  local upload_id=""
  local download_name=""
  local web_upload=""
  local web_upload_root=""
  local root_staging=""
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "部署写操作未启用。"; return 1; }
  output="$(mktemp)"
  trap 'rm -f -- "${output:-}"; [[ -n "${root_staging:-}" && -d "${root_staging}" ]] && rm -rf --one-file-system -- "${root_staging}"; [[ -n "${web_upload_root:-}" && -d "${web_upload_root}" ]] && rm -rf --one-file-system -- "${web_upload_root}"' RETURN
  case "${service_id}" in
    vless)
      validate_port_value "${port}" || { fail "VLESS 端口无效。"; return 1; }
      [[ "${option}" =~ ^[A-Za-z0-9.-]{3,253}$ && "${option}" == *.* ]] || { fail "REALITY 伪装域名无效。"; return 1; }
      [[ ! -r "${XRAY_CONFIG_PATH}" ]] || { fail "VLESS 已安装，部署向导不会覆盖现有配置。"; return 1; }
      if ! VLESS_INSTALL_NONINTERACTIVE=1 VLESS_INSTALL_PORT="${port}" VLESS_INSTALL_SERVER_NAME="${option}" \
        bash "${VLESS_MANAGER}" install >"${output}" 2>&1; then
        fail "VLESS 安装失败；底层输出已隐藏，请查看服务日志。"
        return 1
      fi
      ;;
    clash)
      validate_port_value "${port}" || { fail "Clash 订阅端口无效。"; return 1; }
      [[ -r "${XRAY_CONFIG_PATH}" ]] || { fail "请先安装 VLESS。"; return 1; }
      [[ ! -r "${CLASH_CONFIG}" ]] || { fail "Clash 订阅已安装，请使用机场资源页更新。"; return 1; }
      python3 "${helper}" update "${CLASH_INPUT_CONFIG}" >"${output}" || { fail "机场或出口节点内容无效。"; return 1; }
      if ! CLASH_INSTALL_NONINTERACTIVE=1 CLASH_INSTALL_PORT="${port}" \
        bash "${FILE_MANAGER}" install-clash >>"${output}" 2>&1; then
        fail "Clash 订阅安装失败；已保存的上游配置可供重试。"
        return 1
      fi
      ;;
    mosh)
      if ! bash "${MOSH_MANAGER}" install >"${output}" 2>&1; then
        fail "Mosh 安装失败；底层输出已隐藏。"
        return 1
      fi
      ;;
    file)
      upload_id="${option%%:*}"
      download_name="${option#*:}"
      validate_port_value "${port}" || { fail "普通文件服务端口无效。"; return 1; }
      [[ "${upload_id}" =~ ^[0-9a-f]{32}$ ]] || { fail "上传标识无效。"; return 1; }
      [[ "${download_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { fail "下载文件名无效。"; return 1; }
      web_upload_root="${WEB_UPLOAD_DIR}/${upload_id}"
      web_upload="${web_upload_root}/payload"
      [[ -f "${web_upload}" && ! -L "${web_upload}" ]] || { fail "上传文件不存在或类型无效。"; return 1; }
      install -d -m 700 "${ROOT_UPLOAD_STAGING}"
      root_staging="$(mktemp -d "${ROOT_UPLOAD_STAGING}/upload.XXXXXX")"
      python3 - "${web_upload}" "${root_staging}/${download_name}" "${FILE_UPLOAD_MAX_BYTES}" <<'PYTHON'
import os
import stat
import sys

source, target, max_bytes_text = sys.argv[1:]
max_bytes = int(max_bytes_text)
flags = os.O_RDONLY
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(source, flags)
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= max_bytes:
        raise SystemExit(1)
    with os.fdopen(os.dup(descriptor), "rb") as source_file, open(target, "xb") as target_file:
        while chunk := source_file.read(1024 * 1024):
            target_file.write(chunk)
        target_file.flush()
        os.fsync(target_file.fileno())
finally:
    os.close(descriptor)
os.chmod(target, 0o600)
PYTHON
      rm -rf --one-file-system -- "${web_upload_root}"
      web_upload_root=""
      if ! FILE_INSTALL_NONINTERACTIVE=1 FILE_INSTALL_PORT="${port}" \
        bash "${FILE_MANAGER}" install "${root_staging}/${download_name}" >"${output}" 2>&1; then
        fail "普通文件服务安装失败；上传暂存已清理。"
        return 1
      fi
      ;;
    *) fail "部署服务未登记。"; return 1 ;;
  esac
  rm -f -- "${output}"
  output=""
  if [[ -n "${root_staging}" && -d "${root_staging}" ]]; then
    rm -rf --one-file-system -- "${root_staging}"
    root_staging=""
  fi
  if [[ -n "${web_upload_root}" && -d "${web_upload_root}" ]]; then
    rm -rf --one-file-system -- "${web_upload_root}"
    web_upload_root=""
  fi
  trap - RETURN
  python3 - "${service_id}" <<'PYTHON'
import json
import sys
json.dump({"schema_version": 1, "service_id": sys.argv[1], "state": "completed"}, sys.stdout, ensure_ascii=False)
print()
PYTHON
}

management_admin_peer() {
  python3 - "${MANAGEMENT_STATE}" <<'PYTHON'
import pathlib
import sys

try:
    lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
except OSError:
    lines = []
for line in lines:
    if line.startswith("MANAGEMENT_ADMIN_PEER="):
        value = line.split("=", 1)[1].strip().strip("'\"")
        print(value)
        break
PYTHON
}

set_management_admin_peer() {
  local name="$1"
  local public_key=""
  local custody=""
  local iface=""
  local handshake="0"
  local now=""
  local management_port=""
  awk -F '\t' -v wanted="${name}" '$1 == wanted {found=1} END {exit !found}' "${AWG_PEERS}" 2>/dev/null || {
    fail "只有已启用的普通 AWG 节点可以接管管理入口。"
    return 1
  }
  IFS=$'\t' read -r public_key _ custody < <(
    awk -F '\t' -v wanted="${name}" '$1 == wanted {print $2 "\t" $3 "\t" $4; exit}' "${AWG_PEER_CREDENTIALS}" 2>/dev/null
  )
  [[ -n "${public_key}" && "${custody}" == "client" ]] || {
    fail "新管理入口的节点凭据不符合安全要求。"
    return 1
  }
  iface="$(read_assignment "${AWG_STATE}" AWG_IFACE 2>/dev/null || true)"
  [[ -n "${iface}" ]] || iface="awg0"
  if command -v awg >/dev/null 2>&1; then
    handshake="$(awg show "${iface}" latest-handshakes 2>/dev/null | awk -F '\t' -v key="${public_key}" '$1 == key {print $2; exit}')"
  fi
  now="$(date +%s)"
  [[ "${handshake}" =~ ^[0-9]+$ && $((now - handshake)) -ge 0 && $((now - handshake)) -le 300 ]] || {
    fail "目标节点最近 5 分钟没有 AWG 握手，不能接管管理入口。"
    return 1
  }
  management_port="$(read_assignment "${MANAGEMENT_STATE}" MANAGEMENT_PORT 2>/dev/null || true)"
  [[ "${management_port}" =~ ^[0-9]+$ ]] || management_port="9080"
  python3 - "${AWG_ACCESS_POLICY}" "${name}" "${management_port}" <<'PYTHON' || {
import json
import sys

try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(1)
client = value.get("clients", {}).get(sys.argv[2], {})
if client.get("mode") == "unrestricted":
    raise SystemExit(0)
required = {22, int(sys.argv[3])}
for permission in client.get("allow", []):
    if not isinstance(permission, dict) or permission.get("target") not in {"all", "vps"}:
        continue
    if permission.get("network") == "all":
        raise SystemExit(0)
    ports = permission.get("ports", [])
    if permission.get("network") == "tcp" and isinstance(ports, list) and required.issubset(set(ports)):
        raise SystemExit(0)
raise SystemExit(1)
PYTHON
    fail "目标节点没有保留 VPS SSH 与管理网站访问权限。"
    return 1
  }
  python3 - "${MANAGEMENT_STATE}" "${name}" <<'PYTHON'
import os
import pathlib
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
name = sys.argv[2]
stat = path.stat()
lines = path.read_text(encoding="utf-8").splitlines()
replacement = f"MANAGEMENT_ADMIN_PEER={name}"
for index, line in enumerate(lines):
    if line.startswith("MANAGEMENT_ADMIN_PEER="):
        lines[index] = replacement
        break
else:
    lines.append(replacement)
descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write("\n".join(lines) + "\n")
        target.flush()
        os.fsync(target.fileno())
    os.chmod(temporary_name, stat.st_mode & 0o7777)
    os.chown(temporary_name, stat.st_uid, stat.st_gid)
    os.replace(temporary_name, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if os.path.exists(temporary_name):
        os.unlink(temporary_name)
PYTHON
}

rollback_new_network_node() {
  local kind="$1"
  local name="$2"
  local output="$3"
  if [[ "${kind}" == "awg" ]]; then
    bash "${AWG_MANAGER}" remove "${name}" >>"${output}" 2>&1
  else
    bash "${VLESS_MANAGER}" client-remove "${name}" >>"${output}" 2>&1 &&
      VLESS_SKIP_SSH_GATE=1 bash "${VLESS_MANAGER}" apply >>"${output}" 2>&1
  fi
}

publish_new_network_node() {
  local kind="$1"
  local name="$2"
  local output="$3"
  [[ -r "${CLASH_CONFIG}" ]] || return 0
  if bash "${FILE_MANAGER}" refresh-clash >>"${output}" 2>&1; then
    return 0
  fi
  if rollback_new_network_node "${kind}" "${name}" "${output}"; then
    # refresh-clash 本身以备份目录和原子替换保护旧发布内容。节点撤销后再做
    # 一次尽力对账，避免底层实现发生变化时留下半成品。
    bash "${FILE_MANAGER}" refresh-clash >>"${output}" 2>&1 || true
    fail "新增节点的订阅发布失败；刚新增的节点已撤销，原有节点与订阅保持不变。"
  else
    fail "新增节点的订阅发布失败，且新增节点回滚状态无法确认；请重新读取节点状态。"
  fi
  return 1
}

change_network_node_json() {
  local kind="$1"
  local operation="$2"
  local name="$3"
  local address="${4:-}"
  local public_key="${5:-}"
  local preshared_key=""
  local output=""
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "节点写操作未启用。"; return 1; }
  [[ "${kind}" == "awg" || "${kind}" == "vless" ]] || { fail "节点类型无效。"; return 1; }
  [[ "${operation}" == "add" || "${operation}" == "import" || "${operation}" == "enroll" || "${operation}" == "enable" || "${operation}" == "disable" || "${operation}" == "remove" || "${operation}" == "set-management" || "${operation}" == "compat-enable" || "${operation}" == "compat-disable" || "${operation}" == "clean-enable" || "${operation}" == "clean-disable" ]] || { fail "节点动作无效。"; return 1; }
  [[ "${kind}" != "awg" || "${operation}" != "add" ]] || {
    fail "AWG 节点必须使用管理网页或公钥导入。"
    return 1
  }
  [[ ( "${operation}" != "import" && "${operation}" != "enroll" ) || "${kind}" == "awg" ]] || { fail "只有 AWG 节点支持公钥导入。"; return 1; }
  [[ "${operation}" != "set-management" || "${kind}" == "awg" ]] || { fail "只有普通 AWG 节点可以设为管理入口。"; return 1; }
  [[ "${operation}" != "compat-enable" && "${operation}" != "compat-disable" || "${kind}" == "vless" ]] || { fail "只有 VLESS 节点支持旧版 Stash 兼容。"; return 1; }
  [[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { fail "节点名称格式不正确。"; return 1; }
  [[ -z "${address}" || "${kind}" == "awg" && ( "${operation}" == "add" || "${operation}" == "import" || "${operation}" == "enroll" ) ]] || { fail "只有新增 AWG 节点可以指定地址。"; return 1; }
  if [[ "${operation}" == "import" || "${operation}" == "enroll" ]]; then
    [[ "${public_key}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { fail "AWG 客户端公钥格式不正确。"; return 1; }
    IFS= read -r preshared_key || true
    [[ "${preshared_key}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { fail "AWG 预共享密钥格式不正确。"; return 1; }
  elif [[ -n "${public_key}" ]]; then
    fail "当前节点操作不接受客户端公钥。"
    return 1
  fi
  if [[ "${kind}" == "awg" && ( "${operation}" == "disable" || "${operation}" == "remove" ) && "${name}" == "$(management_admin_peer)" ]]; then
    fail "该节点是当前管理入口，不能禁用或删除；请先把管理入口转交给其他合规节点。"
    return 1
  fi
  if [[ "${operation}" == "set-management" ]]; then
    [[ "${name}" != "$(management_admin_peer)" ]] || { fail "该节点已经是管理入口。"; return 1; }
    set_management_admin_peer "${name}" || return 1
    python3 - "${kind}" "${operation}" "${name}" <<'PYTHON'
import json
import sys
json.dump({"schema_version": 1, "kind": sys.argv[1], "operation": sys.argv[2], "name": sys.argv[3]}, sys.stdout, ensure_ascii=False)
print()
PYTHON
    return 0
  fi
  if [[ "${operation}" == "clean-enable" || "${operation}" == "clean-disable" ]]; then
    local clean_change_failed="0"
    local publication_backup=""
    local had_publication_state="0"
    if [[ "${kind}" == "awg" ]]; then
      awk -F '\t' -v name="${name}" '$1 == name {found=1} END {exit !found}' \
        "${AWG_PEERS}" "${AWG_DISABLED_PEERS}" 2>/dev/null || {
        fail "普通节点不存在。"
        return 1
      }
    else
      python3 - "${VLESS_POLICY}" "${name}" <<'PYTHON' || {
import json
import sys
try:
    clients = json.load(open(sys.argv[1], encoding="utf-8")).get("clients", {})
except (OSError, ValueError, AttributeError):
    clients = {}
raise SystemExit(0 if sys.argv[2] in clients else 1)
PYTHON
        fail "VLESS 节点不存在。"
        return 1
      }
    fi
    publication_backup="$(mktemp)"
    output="$(mktemp)"
    if [[ -r "${CLASH_PUBLICATION_STATE}" ]]; then
      cp -a -- "${CLASH_PUBLICATION_STATE}" "${publication_backup}"
      had_publication_state="1"
    fi
    if ! python3 "${PUBLICATION_STATE_HELPER}" --config "${CLASH_PUBLICATION_STATE}" \
         set-clean-mode "${name}" "$([[ "${operation}" == "clean-enable" ]] && echo enabled || echo disabled)" \
         >"${output}" 2>&1; then
      clean_change_failed="1"
    elif [[ -r "${CLASH_CONFIG}" ]] && \
         ! bash "${FILE_MANAGER}" refresh-clash >>"${output}" 2>&1; then
      clean_change_failed="1"
    fi
    if [[ "${clean_change_failed}" == "1" ]]; then
      if [[ "${had_publication_state}" == "1" ]]; then
        cp -a -- "${publication_backup}" "${CLASH_PUBLICATION_STATE}"
      else
        rm -f -- "${CLASH_PUBLICATION_STATE}"
      fi
      [[ ! -r "${CLASH_CONFIG}" ]] || bash "${FILE_MANAGER}" refresh-clash >/dev/null 2>&1 || true
      rm -f -- "${publication_backup}" "${output}"
      fail "纯净模式切换失败，原发布状态和订阅已恢复。"
      return 1
    fi
    rm -f -- "${publication_backup}" "${output}"
    python3 - "${kind}" "${operation}" "${name}" <<'PYTHON'
import json
import sys
json.dump({"schema_version": 1, "kind": sys.argv[1], "operation": sys.argv[2], "name": sys.argv[3]}, sys.stdout, ensure_ascii=False)
print()
PYTHON
    return 0
  fi
  if [[ "${operation}" == "add" && "${kind}" == "vless" ]] && \
     awk -F '\t' -v name="${name}" '$1 == name {found=1} END {exit !found}' "${AWG_PEERS}" "${AWG_DISABLED_PEERS}" 2>/dev/null; then
    fail "节点名称已被 AmneziaWG 使用；两类节点必须使用不同名称。"
    return 1
  fi
  if [[ "${operation}" == "add" && "${kind}" == "awg" ]] && \
     python3 - "${VLESS_POLICY}" "${name}" <<'PYTHON'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        clients = json.load(source).get("clients", {})
except (OSError, ValueError, AttributeError):
    clients = {}
raise SystemExit(0 if sys.argv[2] in clients else 1)
PYTHON
  then
    fail "节点名称已被 VLESS 使用；两类节点必须使用不同名称。"
    return 1
  fi
  if [[ -n "${address}" ]]; then
    python3 - "${address}" <<'PYTHON' >/dev/null || { fail "节点地址格式不正确。"; return 1; }
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PYTHON
  fi
  output="$(mktemp)"
  if [[ "${kind}" == "awg" ]]; then
    if [[ "${operation}" == "import" || "${operation}" == "enroll" ]]; then
      printf '%s\n' "${preshared_key}" | bash "${AWG_MANAGER}" "$([[ "${operation}" == "enroll" ]] && echo enroll || echo import-public)" "${name}" "${public_key}" "${address}" >"${output}" 2>&1 || {
        rm -f -- "${output}"
        fail "AmneziaWG 公钥导入失败；底层输出已隐藏，请查看服务端审计。"
        return 1
      }
    elif [[ -n "${address}" ]]; then
      bash "${AWG_MANAGER}" "${operation}" "${name}" "${address}" >"${output}" 2>&1 || {
        rm -f -- "${output}"
        fail "AmneziaWG 节点操作失败；底层输出已隐藏，请查看服务端审计。"
        return 1
      }
    elif ! bash "${AWG_MANAGER}" "${operation}" "${name}" >"${output}" 2>&1; then
      rm -f -- "${output}"
      fail "AmneziaWG 节点操作失败；底层输出已隐藏，请查看服务端审计。"
      return 1
    fi
  else
    [[ ! -e "${VLESS_PENDING_POLICY}" ]] || { rm -f -- "${output}"; fail "存在尚未处理的 VLESS 待应用策略，请先在命令行应用或撤销。"; return 1; }
    [[ -r "${XRAY_CONFIG_PATH}" ]] || { rm -f -- "${output}"; fail "VLESS 服务未完整安装，不能管理客户端。"; return 1; }
    if [[ "${operation}" == "compat-enable" || "${operation}" == "compat-disable" ]]; then
      local policy_backup=""
      policy_backup="$(mktemp)"
      cp -a -- "${VLESS_POLICY}" "${policy_backup}" || {
        rm -f -- "${policy_backup}" "${output}"
        fail "VLESS 兼容配置备份失败，未执行变更。"
        return 1
      }
      if ! bash "${VLESS_MANAGER}" "client-${operation}" "${name}" >"${output}" 2>&1 || \
         ! python3 "${VLESS_ACCESS_HELPER}" \
           --active "${VLESS_POLICY}" --pending "${VLESS_PENDING_POLICY}" \
           --peer-db "${AWG_PEERS}" --awg-state "${AWG_STATE}" commit >>"${output}" 2>&1; then
        install -m 600 -o root -g root -- "${policy_backup}" "${VLESS_POLICY}"
        rm -f -- "${VLESS_PENDING_POLICY}" "${policy_backup}" "${output}"
        fail "VLESS 兼容配置写入失败，原策略已恢复。"
        return 1
      fi
      if [[ -r "${CLASH_CONFIG}" ]] && ! bash "${FILE_MANAGER}" refresh-clash >>"${output}" 2>&1; then
        install -m 600 -o root -g root -- "${policy_backup}" "${VLESS_POLICY}"
        rm -f -- "${VLESS_PENDING_POLICY}"
        bash "${FILE_MANAGER}" refresh-clash >/dev/null 2>&1 || true
        rm -f -- "${policy_backup}" "${output}"
        fail "兼容订阅刷新失败，VLESS 策略和原发布内容已恢复。"
        return 1
      fi
      rm -f -- "${policy_backup}"
    elif ! bash "${VLESS_MANAGER}" "client-${operation}" "${name}" >"${output}" 2>&1 || \
         ! VLESS_SKIP_SSH_GATE=1 bash "${VLESS_MANAGER}" apply >>"${output}" 2>&1; then
        rm -f -- "${VLESS_PENDING_POLICY}"
        rm -f -- "${output}"
        fail "VLESS 节点操作失败；候选策略已清理，底层输出已隐藏。"
        return 1
    fi
  fi
  if [[ "${operation}" == "add" || "${kind}" == "awg" && ( "${operation}" == "import" || "${operation}" == "enroll" ) ]]; then
    if ! publish_new_network_node "${kind}" "${name}" "${output}"; then
      rm -f -- "${VLESS_PENDING_POLICY}" "${output}"
      return 1
    fi
  fi
  rm -f -- "${output}"
  if [[ "${kind}" == "awg" && "${operation}" == "remove" && -r "${NODE_DOMAIN_HELPER}" ]]; then
    python3 "${NODE_DOMAIN_HELPER}" delete-node --config "${NODE_DOMAINS_PATH}" \
      --active "${AWG_PEERS}" --disabled "${AWG_DISABLED_PEERS}" --name "${name}" \
      >/dev/null 2>&1 || true
  fi
  python3 - "${kind}" "${operation}" "${name}" <<'PYTHON'
import json
import sys
json.dump({"schema_version": 1, "kind": sys.argv[1], "operation": sys.argv[2], "name": sys.argv[3]}, sys.stdout, ensure_ascii=False)
print()
PYTHON
}

show_enrollment_context_json() {
  bash "${AWG_MANAGER}" enrollment-context
}

manage_enrollments_json() {
  local operation="$1"
  case "${operation}" in
    overview) bash "${AWG_MANAGER}" enrollment-status ;;
    reconcile) bash "${AWG_MANAGER}" enrollment-reconcile ;;
    *) fail "首次握手动作未登记。"; return 1 ;;
  esac
}

change_network_permission_json() {
  local operation="$1"
  local client="$2"
  local target="$3"
  local ports="${4:-}"
  local network="${5:-}"
  local output=""
  local kind=""
  local -a permission_command=()
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "节点写操作未启用。"; return 1; }
  [[ "${operation}" == "allow" || "${operation}" == "deny" ]] || { fail "权限动作无效。"; return 1; }
  [[ "${client}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || {
    fail "客户端节点名称格式不正确。"
    return 1
  }
  if awk -F '\t' -v name="${client}" '$1 == name {found=1} END {exit !found}' "${AWG_PEERS}" 2>/dev/null; then
    kind="awg"
  else
    kind="vless"
  fi
  if [[ ! "${target}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
    fail "目标节点名称格式不正确。"
    return 1
  fi
  if [[ "${operation}" == "allow" ]]; then
    if [[ -n "${ports}" || -n "${network}" ]]; then
      [[ "${network}" == "tcp" || "${network}" == "udp" ]] || { fail "权限协议只能是 TCP 或 UDP。"; return 1; }
    fi
  elif [[ -n "${ports}" || -n "${network}" ]]; then
    if [[ "${network}" == "all" ]]; then
      [[ -z "${ports}" ]] || { fail "全部协议权限不接受端口列表。"; return 1; }
    else
      [[ "${network}" == "tcp" || "${network}" == "udp" ]] || { fail "权限协议只能是全部、TCP 或 UDP。"; return 1; }
    fi
  fi
  if [[ "${network}" == "tcp" || "${network}" == "udp" ]]; then
    ports="$(python3 "${SCRIPT_DIR}/lib/server_kit_port_ranges.py" "${ports}")" || return 1
  fi
  output="$(mktemp)"
  if [[ "${kind}" == "awg" ]]; then
    [[ ! -e "${AWG_ACCESS_PENDING_POLICY}" ]] || { rm -f -- "${output}"; fail "存在尚未处理的 AWG 待应用策略。"; return 1; }
    if [[ "${operation}" == "allow" ]]; then
      permission_command=(bash "${AWG_MANAGER}" access-allow "${client}" "${target}")
      [[ -z "${network}" ]] || permission_command+=("${ports}" "${network}")
      "${permission_command[@]}" >"${output}" 2>&1 || {
        rm -f -- "${output}"; fail "AWG 访问授权失败；原策略保持不变。"; return 1;
      }
    else
      permission_command=(bash "${AWG_MANAGER}" access-deny "${client}" "${target}")
      [[ -z "${network}" ]] || permission_command+=("${ports}" "${network}")
      "${permission_command[@]}" >"${output}" 2>&1 || {
        rm -f -- "${output}"; fail "AWG 访问授权撤销失败；原策略保持不变。"; return 1;
      }
    fi
  else
    [[ ! -e "${VLESS_PENDING_POLICY}" ]] || { rm -f -- "${output}"; fail "存在尚未处理的 VLESS 待应用策略，请先在命令行应用或撤销。"; return 1; }
    [[ -r "${XRAY_CONFIG_PATH}" ]] || { rm -f -- "${output}"; fail "VLESS 服务未完整安装，不能管理访问权限。"; return 1; }
    permission_command=(bash "${VLESS_MANAGER}" "${operation}" "${client}" "${target}")
    [[ -z "${network}" ]] || permission_command+=("${ports}" "${network}")
    if ! "${permission_command[@]}" >"${output}" 2>&1 || \
       ! VLESS_SKIP_SSH_GATE=1 bash "${VLESS_MANAGER}" apply >>"${output}" 2>&1; then
      rm -f -- "${VLESS_PENDING_POLICY}" "${output}"
      fail "VLESS 权限操作失败；候选策略已清理，底层输出已隐藏。"
      return 1
    fi
  fi
  rm -f -- "${output}"
  python3 - "${operation}" "${client}" "${target}" <<'PYTHON'
import json
import sys
value = {"schema_version": 1, "operation": sys.argv[1], "client": sys.argv[2], "target": sys.argv[3]}
json.dump(value, sys.stdout, ensure_ascii=False)
print()
PYTHON
}

add_network_permissions_json() {
  local client="$1"
  local output=""
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "节点写操作未启用。"; return 1; }
  [[ "${client}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { fail "客户端节点名称格式不正确。"; return 1; }
  output="$(mktemp)" || return 1
  # The caller holds the existing management-change lock. Both helpers validate
  # all rows before writing one candidate, then apply once without restarting AWG.
  if awk -F '\t' -v name="${client}" '$1 == name {found=1} END {exit !found}' "${AWG_PEERS}" 2>/dev/null; then
    [[ ! -e "${AWG_ACCESS_PENDING_POLICY}" ]] || { rm -f -- "${output}"; fail "存在尚未处理的 AWG 待应用策略。"; return 1; }
    if ! bash "${AWG_MANAGER}" access-allow-batch "${client}" >"${output}" 2>&1; then
      if grep -Fqx 'SERVER_KIT_DIAGNOSTIC:permission_recovery_required' "${output}"; then
        printf '%s\n' 'SERVER_KIT_DIAGNOSTIC:permission_recovery_required' >&2
      fi
      rm -f -- "${output}"
      fail "AWG 批量权限操作失败；请重新读取实际状态。"
      return 1
    fi
  else
    [[ ! -e "${VLESS_PENDING_POLICY}" ]] || { rm -f -- "${output}"; fail "存在尚未处理的 VLESS 待应用策略。"; return 1; }
    [[ -r "${XRAY_CONFIG_PATH}" ]] || { rm -f -- "${output}"; fail "VLESS 服务未完整安装。"; return 1; }
    if ! bash "${VLESS_MANAGER}" allow-batch "${client}" >"${output}" 2>&1; then
      rm -f -- "${output}"
      fail "VLESS 批量权限校验失败；没有应用变更。"
      return 1
    fi
    if ! VLESS_SKIP_SSH_GATE=1 bash "${VLESS_MANAGER}" apply >>"${output}" 2>&1; then
      if grep -Fqx 'SERVER_KIT_DIAGNOSTIC:permission_recovery_required' "${output}"; then
        printf '%s\n' 'SERVER_KIT_DIAGNOSTIC:permission_recovery_required' >&2
      fi
      rm -f -- "${VLESS_PENDING_POLICY}" "${output}"
      fail "VLESS 批量权限应用失败；请重新读取实际状态。"
      return 1
    fi
  fi
  rm -f -- "${output}"
  python3 - "${client}" <<'PYTHON'
import json
import sys
json.dump({"schema_version": 1, "operation": "batch", "client": sys.argv[1]}, sys.stdout)
print()
PYTHON
}

sync_network_subscriptions_json() {
  local output=""
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "订阅写操作未启用。"; return 1; }
  output="$(mktemp)"
  if ! bash "${FILE_MANAGER}" refresh-clash >"${output}" 2>&1; then
    rm -f -- "${output}"
    fail "订阅同步失败；底层输出已隐藏，原订阅保持不变。"
    return 1
  fi
  rm -f -- "${output}"
  printf '%s\n' '{"schema_version":1,"operation":"sync","state":"completed"}'
}

rotate_network_subscription_json() {
  local name="$1"
  local output=""
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "订阅写操作未启用。"; return 1; }
  [[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { fail "节点名称格式不正确。"; return 1; }
  output="$(mktemp)"
  if ! bash "${FILE_MANAGER}" rotate-clash-node "${name}" >"${output}" 2>&1; then
    rm -f -- "${output}"
    fail "订阅令牌轮换失败；底层输出已隐藏，原链接已恢复。"
    return 1
  fi
  rm -f -- "${output}"
  python3 - "${name}" <<'PYTHON'
import json
import sys
json.dump({"schema_version": 1, "operation": "rotate", "name": sys.argv[1]}, sys.stdout, ensure_ascii=False)
print()
PYTHON
}

set_network_subscription_state_json() {
  local name="$1"
  local state="$2"
  local backup=""
  local had_existing="0"
  local output=""
  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "订阅写操作未启用。"; return 1; }
  [[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { fail "节点名称格式不正确。"; return 1; }
  [[ "${state}" == "enabled" || "${state}" == "disabled" ]] || { fail "发布状态无效。"; return 1; }
  backup="$(mktemp)"
  output="$(mktemp)"
  trap 'rm -f -- "${backup:-}" "${output:-}"' RETURN
  if [[ -r "${CLASH_PUBLICATION_STATE}" ]]; then
    cp -a -- "${CLASH_PUBLICATION_STATE}" "${backup}"
    had_existing="1"
  fi
  python3 "${PUBLICATION_STATE_HELPER}" --config "${CLASH_PUBLICATION_STATE}" \
    set-publication "${name}" "${state}"
  if ! bash "${FILE_MANAGER}" refresh-clash >"${output}" 2>&1; then
    if [[ "${had_existing}" == "1" ]]; then
      cp -a -- "${backup}" "${CLASH_PUBLICATION_STATE}"
    else
      rm -f -- "${CLASH_PUBLICATION_STATE}"
    fi
    fail "订阅发布状态切换失败；原发布状态和订阅已恢复。"
    return 1
  fi
  python3 - "${name}" "${state}" <<'PYTHON'
import json
import sys
json.dump({"schema_version": 1, "operation": "set-state", "name": sys.argv[1], "state": sys.argv[2]}, sys.stdout, ensure_ascii=False)
print()
PYTHON
}

show_transaction_json() {
  local transaction_type="$1"
  local action="$2"
  local renderer="${SCRIPT_DIR}/lib/server_kit_transactions.py"
  local writes_enabled="${SERVER_KIT_HIGH_RISK_WRITES:-0}"
  local session_id=""
  local actor=""
  local public_ip=""
  local public_port=""
  local context_path=""
  local rendered=""
  local request_json=""
  local -a request_values=()
  [[ -r "${renderer}" ]] || { fail "缺少安全事务渲染器。"; return 1; }
  [[ "${transaction_type}" == "ssh_auth" || "${transaction_type}" == "ssh_listener" || "${transaction_type}" == "firewall" ]] || {
    fail "安全事务未登记。"
    return 1
  }
  if [[ "${SERVER_KIT_CONTROL:-0}" == "1" ]]; then
    request_json="$(cat)"
    mapfile -t request_values < <(python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in ("session_id", "actor", "public_ip", "public_port"):
    item = value.get(key, "")
    if not isinstance(item, str) or "\x00" in item or "\n" in item or "\r" in item:
        raise SystemExit(2)
    print(item)
' <<<"${request_json}") || { fail "安全事务输入无效。"; return 1; }
    [[ "${#request_values[@]}" -eq 4 ]] || { fail "安全事务输入无效。"; return 1; }
    session_id="${request_values[0]:-}"
    actor="${request_values[1]:-}"
    public_ip="${request_values[2]:-}"
    public_port="${request_values[3]:-}"
    session_id="${session_id%$'\r'}"
    actor="${actor%$'\r'}"
    public_ip="${public_ip%$'\r'}"
    public_port="${public_port%$'\r'}"
  fi
  context_path="${SECURITY_CONTEXT_DIR}/${transaction_type}.json"
  if [[ "${action}" == "apply" || "${action}" == "confirm" || "${action}" == "rollback" ]]; then
    [[ "${session_id}" =~ ^[0-9a-f]{64}$ ]] || { fail "独立连接标识无效。"; return 1; }
  fi
  case "${action}" in
    status) ;;
    preview)
      if [[ "${transaction_type}" == "ssh_auth" ]]; then
        bash "${SECURITY_MANAGER}" ssh-auth-plan >/dev/null
      elif [[ "${transaction_type}" == "ssh_listener" ]]; then
        bash "${SECURITY_MANAGER}" ssh-plan "${public_ip}" "${public_port}" >/dev/null
      else
        bash "${FIREWALL_MANAGER}" plan >/dev/null 2>&1 || true
      fi
      ;;
    apply|confirm)
      [[ "${writes_enabled}" == "1" ]] || { fail "高风险网页写操作尚未启用。"; return 1; }
      if [[ "${action}" == "confirm" && ! -r "${context_path}" ]]; then
        fail "安全事务缺少发起会话记录；请使用 root 恢复入口确认或回滚。"
        return 1
      fi
      if [[ "${action}" == "confirm" ]]; then
        if python3 - "${context_path}" "${session_id}" <<'PYTHON'
import hashlib
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    origin = json.load(source).get("session_hash", "")
current = hashlib.sha256(sys.argv[2].encode("ascii")).hexdigest()
raise SystemExit(0 if origin == current else 1)
PYTHON
        then
          fail "原发起会话不能确认安全事务，请从另一条独立登录连接操作。"
          return 1
        fi
      fi
      if [[ "${transaction_type}" == "ssh_auth" ]]; then
        if [[ "${action}" == "apply" ]]; then
          bash "${SECURITY_MANAGER}" harden-ssh-auth >/dev/null
        else
          bash "${SECURITY_MANAGER}" confirm-ssh-auth --yes >/dev/null
        fi
      elif [[ "${transaction_type}" == "ssh_listener" ]]; then
        if [[ "${action}" == "apply" ]]; then
          bash "${SECURITY_MANAGER}" install-ssh "${public_ip}" "${public_port}" >/dev/null
        else
          bash "${SECURITY_MANAGER}" confirm-ssh --yes >/dev/null
        fi
      else
        bash "${FIREWALL_MANAGER}" "${action}" --yes >/dev/null
      fi
      if [[ "${action}" == "apply" ]]; then
        if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
          mkdir -p -- "${SECURITY_CONTEXT_DIR}"
        else
          install -d -m 700 -o root -g root "${SECURITY_CONTEXT_DIR}"
        fi
        python3 - "${context_path}" "${transaction_type}" "${session_id}" "${actor}" <<'PYTHON'
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

path, transaction_type, session_id, actor = sys.argv[1:]
value = {
    "transaction_type": transaction_type,
    "session_hash": hashlib.sha256(session_id.encode("ascii")).hexdigest(),
    "actor": actor,
    "created_at": datetime.now(timezone.utc).isoformat(),
}

descriptor, temporary = tempfile.mkstemp(prefix=".context-", dir=os.path.dirname(path))
try:
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYTHON
      else
        rm -f -- "${context_path}"
      fi
      ;;
    rollback)
      if [[ "${transaction_type}" == "ssh_auth" ]]; then
        bash "${SECURITY_MANAGER}" rollback-ssh-auth >/dev/null
      elif [[ "${transaction_type}" == "ssh_listener" ]]; then
        bash "${SECURITY_MANAGER}" rollback-ssh >/dev/null
      else
        bash "${FIREWALL_MANAGER}" rollback >/dev/null
      fi
      rm -f -- "${context_path}"
      ;;
    *) fail "安全事务动作未登记。"; return 1 ;;
  esac
  rendered="$(python3 "${renderer}" "${transaction_type}" \
    "${SSH_AUTH_CONFIG}" "${SSH_AUTH_TRANSACTION}" \
    "${FIREWALL_ACTIVE_RULES}" "${FIREWALL_CANDIDATE_RULES}" \
    "${FIREWALL_TRANSACTION}" "${PORTS_PATH}" \
    "${SECURITY_CONFIG}" "${SSH_TRANSACTION}" \
    "${public_ip}" "${public_port}" "${writes_enabled}")"
  RENDERED_TRANSACTION="${rendered}" python3 - "${context_path}" "${session_id}" <<'PYTHON'
import hashlib
import json
import os
import sys

value = json.loads(os.environ["RENDERED_TRANSACTION"])
context_path, session_id = sys.argv[1:]
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
independent = True
if value.get("state") == "pending" and os.path.isfile(context_path):
    try:
        with open(context_path, encoding="utf-8") as source:
            origin = json.load(source).get("session_hash", "")
        independent = not session_id or origin != hashlib.sha256(session_id.encode("ascii")).hexdigest()
    except (OSError, ValueError):
        independent = False
elif value.get("state") == "idle":
    try:
        os.unlink(context_path)
    except FileNotFoundError:
        pass
value["independent_session"] = independent
json.dump(value, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
PYTHON
}

show_vless_listener_transaction_json() {
  local action="$1"
  local writes_enabled="${SERVER_KIT_HIGH_RISK_WRITES:-0}"
  local request_json=""
  local -a request_values=()
  [[ "${SERVER_KIT_CONTROL:-0}" == "1" ]] || {
    fail "VLESS 监听事务只允许由受限控制面调用。"
    return 1
  }
  request_json="$(cat)"
  mapfile -t request_values < <(python3 -c '
import json, sys
value = json.load(sys.stdin)
if set(value) != {"session_id", "actor"}:
    raise SystemExit(2)
for key in ("session_id", "actor"):
    item = value[key]
    if not isinstance(item, str) or "\x00" in item or "\n" in item or "\r" in item:
        raise SystemExit(2)
    print(item)
' <<<"${request_json}") || { fail "VLESS 监听事务输入无效。"; return 1; }
  [[ "${#request_values[@]}" -eq 2 ]] || { fail "VLESS 监听事务输入无效。"; return 1; }
  if [[ "${action}" == "apply" || "${action}" == "confirm" || "${action}" == "rollback" ]]; then
    [[ "${request_values[0]}" =~ ^[0-9a-f]{64}$ ]] || { fail "独立连接标识无效。"; return 1; }
  fi
  if [[ "${action}" == "apply" || "${action}" == "confirm" ]]; then
    [[ "${writes_enabled}" == "1" ]] || { fail "高风险网页写操作尚未启用。"; return 1; }
  fi
  printf '%s\n' "${request_json}" | \
    SERVER_KIT_CONTROL=1 SERVER_KIT_HIGH_RISK_WRITES="${writes_enabled}" \
    bash "${VLESS_MANAGER}" "listener-${action}"
}

automatic_rollback_vless_listener_json() {
  if IFS= read -r -t 0.05 _automatic_rollback_input; then
    fail "VLESS 监听自动回滚不接受标准输入。"
    return 1
  fi
  SERVER_KIT_CONTROL=0 SERVER_KIT_HIGH_RISK_WRITES=0 \
    bash "${VLESS_MANAGER}" listener-automatic-rollback
}

manage_firewall_port_json() {
  local operation="$1"
  local port="${2:-}"
  local scope="${3:-}"
  local protocol="${4:-}"
  local duration="${5:-}"
  local verification=''
  local listing=''
  case "${operation}" in
    list) ;;
    open)
      bash "${FIREWALL_MANAGER}" open-port "${port}" "${scope}" "${protocol}" "${duration}" --yes >/dev/null
      ;;
    close)
      bash "${FIREWALL_MANAGER}" close-port "${port}" "${scope}" "${protocol}" --yes >/dev/null
      ;;
    *) fail "自定义防火墙端口动作未登记。"; return 1 ;;
  esac
  if [[ "${operation}" == "list" ]]; then
    bash "${FIREWALL_MANAGER}" list-ports --json
    return
  fi
  verification="$(bash "${FIREWALL_MANAGER}" verify-port "${operation}" "${port}" \
    "${scope}" "${protocol}" "${duration:-permanent}" --json)" || return 1
  listing="$(bash "${FIREWALL_MANAGER}" list-ports --json)" || return 1
  FIREWALL_LISTING="${listing}" FIREWALL_VERIFICATION="${verification}" python3 - <<'PYTHON'
import json
import os

listing = json.loads(os.environ["FIREWALL_LISTING"])
verification = json.loads(os.environ["FIREWALL_VERIFICATION"])
listing["verification"] = {
    "facts": verification.get("facts") is True,
    "nftables": verification.get("nftables") is True,
}
print(json.dumps(listing, ensure_ascii=False, separators=(",", ":")))
PYTHON
}

managed_ports_overview_json() {
  bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null
  python3 "${MANAGED_PORTS_HELPER}" \
    --awg-state "${AWG_STATE}" --file-config "${FILE_CONFIG}" \
    --clash-config "${CLASH_CONFIG}" --ports "${PORTS_PATH}" overview
}

managed_port_plan_json() {
  local target_id="$1"
  local port="$2"
  bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null
  python3 "${MANAGED_PORTS_HELPER}" \
    --awg-state "${AWG_STATE}" --file-config "${FILE_CONFIG}" \
    --clash-config "${CLASH_CONFIG}" --ports "${PORTS_PATH}" plan "${target_id}" "${port}"
}

managed_port_revision() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("revision", ""))'
}

restore_managed_port_config() {
  local target_id="$1"
  local backup_path="$2"
  local old_port="$3"
  local was_active="$4"
  case "${target_id}" in
    clash)
      install -m 640 -o root -g "$(stat -c '%G' "${CLASH_CONFIG}" 2>/dev/null || echo root)" \
        "${backup_path}" "${CLASH_CONFIG}"
      if [[ "${was_active}" == "1" ]]; then
        "${SYSTEMCTL_BIN}" restart secure-clash-service.service >/dev/null 2>&1 || true
      else
        "${SYSTEMCTL_BIN}" stop secure-clash-service.service >/dev/null 2>&1 || true
      fi
      ;;
    file)
      install -m 640 -o root -g "$(stat -c '%G' "${FILE_CONFIG}" 2>/dev/null || echo root)" \
        "${backup_path}" "${FILE_CONFIG}"
      if [[ "${was_active}" == "1" ]]; then
        "${SYSTEMCTL_BIN}" restart secure-file-service.service >/dev/null 2>&1 || true
      else
        "${SYSTEMCTL_BIN}" stop secure-file-service.service >/dev/null 2>&1 || true
      fi
      ;;
    awg-backup1) bash "${AWG_MANAGER}" set-backup-port backup1 "${old_port}" >/dev/null 2>&1 || true ;;
    awg-backup2) bash "${AWG_MANAGER}" set-backup-port backup2 "${old_port}" >/dev/null 2>&1 || true ;;
  esac
}

change_managed_port_json() {
  local target_id="$1"
  local requested_port="$2"
  local expected_revision="$3"
  local plan_json=""
  local current_revision=""
  local old_port=""
  local backup_source=""
  local backup_path=""
  local result_json=""
  local was_active="0"

  [[ "${SERVER_KIT_NETWORK_WRITES:-0}" == "1" ]] || { fail "端口写操作未启用。"; return 1; }
  validate_port_value "${requested_port}" || { fail "端口必须是 1–65535 的整数。"; return 1; }
  [[ "${expected_revision}" =~ ^[0-9a-f]{64}$ ]] || { fail "端口事实版本无效，请重新预览。"; return 1; }
  plan_json="$(managed_port_plan_json "${target_id}" "${requested_port}")" || return 1
  current_revision="$(printf '%s' "${plan_json}" | managed_port_revision)"
  [[ "${current_revision}" == "${expected_revision}" ]] || {
    fail "端口状态在预览后发生变化，请刷新页面后重新确认。"
    return 1
  }
  old_port="$(PLAN_JSON="${plan_json}" python3 -c 'import json,os; print(json.loads(os.environ["PLAN_JSON"])["old_port"])')"
  case "${target_id}" in
    clash)
      backup_source="${CLASH_CONFIG}"
      if "${SYSTEMCTL_BIN}" is-active --quiet secure-clash-service.service; then was_active="1"; fi
      ;;
    file)
      backup_source="${FILE_CONFIG}"
      if "${SYSTEMCTL_BIN}" is-active --quiet secure-file-service.service; then was_active="1"; fi
      ;;
    awg-backup1|awg-backup2) backup_source="${AWG_STATE}" ;;
    *) fail "未知的端口维护目标。"; return 1 ;;
  esac
  backup_path="$(mktemp /tmp/server-kit-managed-port.XXXXXX)"
  cp -- "${backup_source}" "${backup_path}"
  trap 'rm -f -- "${backup_path:-}"' RETURN

  case "${target_id}" in
    clash) bash "${FILE_MANAGER}" set-port clash "${requested_port}" >/dev/null ;;
    file) bash "${FILE_MANAGER}" set-port file "${requested_port}" >/dev/null ;;
    awg-backup1) bash "${AWG_MANAGER}" set-backup-port backup1 "${requested_port}" >/dev/null ;;
    awg-backup2) bash "${AWG_MANAGER}" set-backup-port backup2 "${requested_port}" >/dev/null ;;
  esac
  if [[ "${target_id}" == awg-* ]] && [[ -r "${CLASH_CONFIG}" ]]; then
    if ! bash "${FILE_MANAGER}" refresh-clash >/dev/null; then
      restore_managed_port_config "${target_id}" "${backup_path}" "${old_port}" "${was_active}"
      bash "${FILE_MANAGER}" refresh-clash >/dev/null 2>&1 || true
      fail "备用入口已恢复：Clash 订阅同步失败。"
      return 1
    fi
  fi
  bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null
  if ! bash "${FIREWALL_MANAGER}" apply --yes >/dev/null; then
    restore_managed_port_config "${target_id}" "${backup_path}" "${old_port}" "${was_active}"
    [[ "${target_id}" != awg-* ]] || bash "${FILE_MANAGER}" refresh-clash >/dev/null 2>&1 || true
    fail "端口已恢复：防火墙候选规则未能安全应用。"
    return 1
  fi
  if ! result_json="$(managed_ports_overview_json)" || \
     ! RESULT_JSON="${result_json}" TARGET_ID="${target_id}" REQUESTED_PORT="${requested_port}" \
       python3 -c '
import json, os
value = json.loads(os.environ["RESULT_JSON"])
target = next((item for item in value.get("items", []) if item.get("id") == os.environ["TARGET_ID"]), None)
if not target or target.get("port") != int(os.environ["REQUESTED_PORT"]): raise SystemExit(1)
if target.get("active") and not target.get("listening"): raise SystemExit(1)
'; then
    bash "${FIREWALL_MANAGER}" rollback >/dev/null 2>&1 || true
    restore_managed_port_config "${target_id}" "${backup_path}" "${old_port}" "${was_active}"
    [[ "${target_id}" != awg-* ]] || bash "${FILE_MANAGER}" refresh-clash >/dev/null 2>&1 || true
    fail "端口已恢复：新端口监听验证失败。"
    return 1
  fi
  if ! bash "${FIREWALL_MANAGER}" confirm --yes >/dev/null; then
    bash "${FIREWALL_MANAGER}" rollback >/dev/null 2>&1 || true
    restore_managed_port_config "${target_id}" "${backup_path}" "${old_port}" "${was_active}"
    [[ "${target_id}" != awg-* ]] || bash "${FILE_MANAGER}" refresh-clash >/dev/null 2>&1 || true
    fail "端口已恢复：防火墙规则未能确认。"
    return 1
  fi
  rm -f -- "${backup_path}"
  backup_path=""
  trap - RETURN
  PLAN_JSON="${plan_json}" OVERVIEW_JSON="${result_json}" python3 - <<'PYTHON'
import json
import os

print(json.dumps({
    "changed": True,
    "plan": json.loads(os.environ["PLAN_JSON"]),
    "overview": json.loads(os.environ["OVERVIEW_JSON"]),
}, ensure_ascii=False, separators=(",", ":")))
PYTHON
}

manage_ssh_key_json() {
  local operation="$1"
  local item_id="${2:-}"
  case "${operation}" in
    list)
      bash "${SECURITY_MANAGER}" list-root-keys --json
      ;;
    preview)
      bash "${SECURITY_MANAGER}" preview-root-key --json
      ;;
    add)
      [[ "${item_id}" =~ ^[A-Za-z0-9_-]{20,80}$ ]] || { fail "SSH 公钥暂存标识无效。"; return 1; }
      bash "${SECURITY_MANAGER}" add-root-key "${item_id}" --yes --json
      ;;
    delete)
      [[ "${item_id}" =~ ^key-[0-9a-f]{64}$ ]] || { fail "SSH 公钥标识无效。"; return 1; }
      bash "${SECURITY_MANAGER}" delete-root-key "${item_id}" --yes --json
      ;;
    rename)
      [[ "${item_id}" =~ ^key-[0-9a-f]{64}$ ]] || { fail "SSH 公钥标识无效。"; return 1; }
      bash "${SECURITY_MANAGER}" rename-root-key "${item_id}" --yes --json
      ;;
    *) fail "SSH 公钥动作未登记。"; return 1 ;;
  esac
}

current_ssh_server_address() {
  local _client_ip=""
  local _client_port=""
  local server_ip=""
  local _server_port=""
  read -r _client_ip _client_port server_ip _server_port <<< "${SSH_CONNECTION:-}"
  printf '%s\n' "${server_ip}"
}

protect_current_tunnel() {
  local id="$1"
  local force="$2"
  local current_address=""
  local tunnel_address=""

  [[ "${force}" == "1" ]] && return 0
  case "${id}" in
    amneziawg) tunnel_address="$(read_assignment "${AWG_STATE}" AWG_SERVER_IP)" ;;
    *) return 0 ;;
  esac
  current_address="$(current_ssh_server_address)"
  if [[ -n "${tunnel_address}" && "${current_address}" == "${tunnel_address}" ]]; then
    fail "当前 SSH 正通过 ${tunnel_address} 连接，拒绝中断 $(service_label "${id}")；确认有其他入口后加 --force。"
  fi
}

perform_action() {
  local action="$1"
  local id="$2"
  local force="$3"
  local unit=""

  if [[ "${id}" == "ssh" ]]; then
    fail "SSH 是保护项；请使用 debian_security_manager.sh 管理监听。"
    return
  fi
  if [[ "${id}" == "firewall" ]]; then
    fail "防火墙是保护项；请使用 debian_firewall_manager.sh 管理。"
    return
  fi
  if [[ "${action}" == "stop" || "${action}" == "restart" ]]; then
    protect_current_tunnel "${id}" "${force}" || return 1
  fi
  if [[ "${id}" == "mosh" ]]; then
    if ! service_is_configured "${id}"; then
      echo "跳过未安装服务：mosh"
      return 0
    fi
    case "${action}" in
      start) bash "${MOSH_MANAGER}" install ;;
      stop) bash "${MOSH_MANAGER}" stop ;;
      restart)
        bash "${MOSH_MANAGER}" stop
        bash "${MOSH_MANAGER}" install
        ;;
    esac
    return $?
  fi
  unit="$(service_unit "${id}")"
  if ! unit_exists "${unit}"; then
    echo "跳过未安装服务：${id}（${unit}）"
    return
  fi
  "${SYSTEMCTL_BIN}" "${action}" "${unit}"
  case "${action}" in
    start) echo "✓ 已启动 $(service_label "${id}") [${id}]" ;;
    stop) echo "✓ 已停止 $(service_label "${id}") [${id}]" ;;
    restart) echo "✓ 已重启 $(service_label "${id}") [${id}]" ;;
  esac
  echo "  ${unit}"
}

confirm_batch() {
  local action="$1"
  local yes="$2"
  local answer=""

  [[ "${yes}" == "1" ]] && return 0
  if [[ ! -t 0 ]]; then
    fail "批量 ${action} 可能影响网络，请加 --yes；中断当前隧道还需 --force。"
    return
  fi
  read -r -p "将批量 ${action} 除 SSH 外的已安装服务，是否继续？[y/N]: " answer
  case "${answer,,}" in
    y|yes) ;;
    *) echo "已取消。"; return 1 ;;
  esac
}

run_action() {
  local action="$1"
  local requested="$2"
  shift 2
  local yes=0
  local force=0
  local option=""
  local id=""
  local failed=0
  local -a order=()

  for option in "$@"; do
    case "${option}" in
      --yes) yes=1 ;;
      --force) force=1 ;;
      *) fail "未知选项：${option}"; return 1 ;;
    esac
  done
  if [[ "${requested}" != "all" ]]; then
    perform_action "${action}" "${requested}" "${force}"
    return
  fi
  if [[ "${action}" != "start" ]]; then
    confirm_batch "${action}" "${yes}" || return 1
    # 必须在任何服务发生变化前完成入口检查，避免批量操作只执行一半。
    protect_current_tunnel amneziawg "${force}" || return 1
  fi
  if [[ "${action}" == "stop" ]]; then
    order=("${STOP_ORDER[@]}")
  else
    order=("${START_ORDER[@]}")
  fi
  for id in "${order[@]}"; do
    if ! perform_action "${action}" "${id}" "${force}"; then
      failed=1
    fi
  done
  return "${failed}"
}

autostart_state() {
  local id="$1"
  local unit=""

  if [[ "${id}" == "mosh" ]]; then
    service_is_configured "${id}" && echo "随 SSH 按需" || echo "未安装"
    return 0
  fi
  unit="$(service_unit "${id}")"
  if ! service_is_configured "${id}" || ! unit_exists "${unit}"; then
    echo "未安装"
  elif "${SYSTEMCTL_BIN}" is-enabled --quiet "${unit}"; then
    if [[ "${id}" == "ssh" || "${id}" == "firewall" ]]; then
      echo "自启（保护项）"
    else
      echo "自启"
    fi
  elif [[ "${id}" == "ssh" || "${id}" == "firewall" ]]; then
    echo "未自启（保护项）"
  else
    echo "未自启"
  fi
}

print_autostart_group() {
  local title="$1"
  local id=""
  shift
  (($#)) || return 0
  echo "${title}"
  for id in "$@"; do
    printf '  - %s [%s]\n' "$(service_label "${id}")" "${id}"
  done
  echo
}

show_autostart() {
  local requested="${1:-all}"
  local id=""
  local state=""
  local -a ids=()
  local -a enabled_ids=()
  local -a protected_ids=()
  local -a on_demand_ids=()
  local -a disabled_ids=()
  local -a missing_ids=()

  if [[ "${requested}" == "all" ]]; then
    ids=("${SERVICE_IDS[@]}")
  else
    ids=("${requested}")
  fi
  for id in "${ids[@]}"; do
    state="$(autostart_state "${id}")"
    case "${state}" in
      自启) enabled_ids+=("${id}") ;;
      自启（保护项）) protected_ids+=("${id}") ;;
      随\ SSH\ 按需) on_demand_ids+=("${id}") ;;
      未自启|未自启（保护项）) disabled_ids+=("${id}") ;;
      未安装) missing_ids+=("${id}") ;;
    esac
  done

  if ! use_compact_layout; then
    echo "server-kit 开机自启"
    echo
    {
      printf '服务\t标识\t自启方式\t当前状态\n'
      for id in "${ids[@]}"; do
        printf '%s\t%s\t%s\t%s\n' \
          "$(service_label "${id}")" "${id}" "$(autostart_state "${id}")" "$(service_state "${id}")"
      done
    } | render_tab_table
    echo
    {
      printf '项目\t说明\n'
      printf '按需服务\tMosh 随 SSH 启动，没有独立常驻服务\n'
      printf '保护项\tSSH 和防火墙只能查看，不能由总管禁用\n'
    } | render_tab_table
    return 0
  fi

  echo "server-kit 开机自启"
  echo
  print_autostart_group "开机启动" "${enabled_ids[@]}"
  print_autostart_group "开机启动（保护）" "${protected_ids[@]}"
  print_autostart_group "随 SSH 按需启动" "${on_demand_ids[@]}"
  print_autostart_group "未启用自启" "${disabled_ids[@]}"
  print_autostart_group "未安装" "${missing_ids[@]}"
  if ((${#ids[@]} == 0)); then
    echo "  无"
  fi
  echo "说明：Mosh 随 SSH 按需启动，没有独立常驻服务。"
  echo "SSH 和防火墙是保护项，只能查看，不能由总管禁用。"
}

confirm_autostart_disable() {
  local yes="$1"
  local answer=""

  [[ "${yes}" == "1" ]] && return 0
  if [[ ! -t 0 ]]; then
    fail "禁用开机自启需要加 --yes；隧道服务还需要 --force。"
    return 1
  fi
  read -r -p "只修改开机自启，不停止当前服务，是否继续？[y/N]: " answer
  case "${answer,,}" in
    y|yes) ;;
    *) echo "已取消。"; return 1 ;;
  esac
}

perform_autostart_action() {
  local action="$1"
  local id="$2"
  local force="$3"
  local unit=""

  if [[ "${id}" == "ssh" || "${id}" == "firewall" ]]; then
    fail "$(service_label "${id}") 是自启保护项，不能由总管修改。"
    return 1
  fi
  if [[ "${id}" == "mosh" ]]; then
    if service_is_configured "${id}"; then
      echo "跳过 Mosh：随系统 SSH 按需启动。"
    else
      echo "跳过未安装服务：mosh"
    fi
    return 0
  fi
  if [[ "${action}" == "disable" && "${id}" == "amneziawg" && "${force}" != "1" ]]; then
    fail "禁用 $(service_label "${id}") 自启可能导致重启后失去内网入口；确认公网入口可用后加 --force。"
    return 1
  fi
  unit="$(service_unit "${id}")"
  if ! service_is_configured "${id}" || ! unit_exists "${unit}"; then
    echo "跳过未安装服务：${id}"
    return 0
  fi
  "${SYSTEMCTL_BIN}" "${action}" "${unit}" >/dev/null
  if [[ "${action}" == "enable" ]]; then
    echo "✓ 已启用 $(service_label "${id}") 开机自启"
  else
    echo "✓ 已禁用 $(service_label "${id}") 开机自启"
  fi
  echo "  当前运行状态不变 · ${unit}"
}

run_autostart_action() {
  local action="$1"
  local requested="$2"
  shift 2
  local yes=0
  local force=0
  local option=""
  local id=""
  local failed=0
  local -a ids=()

  for option in "$@"; do
    case "${option}" in
      --yes) yes=1 ;;
      --force) force=1 ;;
      *) fail "未知选项：${option}"; return 1 ;;
    esac
  done
  [[ "${action}" != "disable" ]] || confirm_autostart_disable "${yes}" || return 1
  if [[ "${requested}" == "all" ]]; then
    ids=("${SERVICE_IDS[@]}")
    # 批量操作必须先完成所有危险项预检，避免只修改一半。
    if [[ "${action}" == "disable" && "${force}" != "1" ]]; then
      if service_is_configured amneziawg; then
        fail "批量禁用包含 $(service_label amneziawg)；确认重启后的备用入口后加 --force。"
        return 1
      fi
    fi
  else
    ids=("${requested}")
  fi
  for id in "${ids[@]}"; do
    if [[ "${requested}" == "all" && ( "${id}" == "ssh" || "${id}" == "firewall" ) ]]; then
      echo "跳过保护项：${id}"
      continue
    fi
    if ! perform_autostart_action "${action}" "${id}" "${force}"; then
      failed=1
    fi
  done
  return "${failed}"
}

show_logs() {
  local id="$1"
  local lines="${2:-80}"
  local unit=""

  [[ "${lines}" =~ ^[0-9]+$ ]] && (( 10#${lines} >= 1 && 10#${lines} <= 1000 )) || {
    fail "日志行数必须是 1–1000。"
    return
  }
  [[ "${id}" != "mosh" ]] || { fail "Mosh 是按需进程，请使用 debian_mosh_manager.sh status 查看活动会话。"; return; }
  unit="$(service_unit "${id}")"
  unit_exists "${unit}" || { fail "服务未安装：${id}"; return; }
  "${JOURNALCTL_BIN}" -u "${unit}" -n "$((10#${lines}))" --no-pager
}

show_ports() {
  bash "${SECURITY_MANAGER}" refresh-ports --quiet
  [[ -r "${PORTS_PATH}" ]] || { fail "端口清单不存在：${PORTS_PATH}"; return 1; }

  echo "server-kit 端口清单"
  echo
  if use_compact_layout; then
    python3 "${PORT_FACTS_HELPER}" project show-compact --ports "${PORTS_PATH}"
  else
    python3 "${PORT_FACTS_HELPER}" project listener-rows --ports "${PORTS_PATH}" | render_tab_table
    echo
    echo "未托管监听"
    python3 "${PORT_FACTS_HELPER}" project unmanaged-rows --ports "${PORTS_PATH}" | render_tab_table
  fi
  echo
  printf '清单文件：%s\n' "${PORTS_PATH}"
}

run_audit() {
  local failed=0
  show_status all || failed=1
  echo
  bash "${SECURITY_MANAGER}" audit-ports || failed=1
  bash "${FIREWALL_MANAGER}" audit-runtime || failed=1
  bash "${FILE_MANAGER}" audit-public-ip || failed=1
  return "${failed}"
}

usage() {
  if ! use_compact_layout; then
    echo "server-kit 服务总管"
    echo
    {
      printf '类别\t命令\t说明\n'
      printf '查看\tserver-kit-manager.sh\t查看全部服务\n'
      printf '查看\tserver-kit-manager.sh status [服务]\t查看指定服务\n'
      printf '查看\tserver-kit-manager.sh autostart [服务]\t查看开机自启\n'
      printf '查看\tserver-kit-manager.sh ports\t查看端口清单\n'
      printf '查看\tserver-kit-manager.sh audit\t执行综合审计\n'
      printf '防火墙\tserver-kit-manager.sh firewall-port list --json\t查看自定义端口\n'
      printf '防火墙\tserver-kit-manager.sh firewall-port open 端口 范围 协议 时长 --json\t开放端口\n'
      printf '防火墙\tserver-kit-manager.sh firewall-port close 端口 范围 协议 --json\t关闭端口\n'
      printf '端口\tserver-kit-manager.sh managed-port list --json\t查看可维护服务端口\n'
      printf '端口\tserver-kit-manager.sh managed-port plan 目标 端口 --json\t预览服务端口变更\n'
      printf 'SSH\tserver-kit-manager.sh ssh-key list --json\t查看公钥客户端\n'
      printf 'SSH\tserver-kit-manager.sh ssh-key preview --json\t从标准输入预览新公钥\n'
      printf 'SSH\tserver-kit-manager.sh ssh-key add|rename|delete 标识 --json\t添加、改名或删除公钥\n'
      printf '节点\tserver-kit-manager.sh network domains set 节点 JSON --json\t设置节点地址强制解析并刷新订阅\n'
      printf '节点\tserver-kit-manager.sh network domains set-address IP JSON --json\t设置任意 IP 强制解析并刷新订阅\n'
      printf '自动化\tserver-kit-manager.sh snapshot\t输出只读 JSON 快照\n'
      printf '管理\tserver-kit-manager.sh start 服务|all\t启动服务\n'
      printf '管理\tserver-kit-manager.sh stop 服务|all\t停止服务\n'
      printf '管理\tserver-kit-manager.sh restart 服务|all\t重启服务\n'
      printf '日志\tserver-kit-manager.sh logs 服务 [行数]\t查看服务日志\n'
      printf '自启\tserver-kit-manager.sh enable-autostart 服务|all\t启用开机自启\n'
      printf '自启\tserver-kit-manager.sh disable-autostart 服务|all --yes\t禁用开机自启\n'
    } | render_tab_table
    echo
    {
      printf '项目\t内容\n'
      printf '服务名\tamneziawg、management、vless、clash、file、mosh、cert-renew、firewall、ssh\n'
      printf '批量确认\tstop/restart all 使用 --yes\n'
      printf '隧道保护\t中断当前隧道或禁用其自启需要 --force\n'
      printf '保护项\t总管不会启停系统 SSH 或防火墙\n'
    } | render_tab_table
    return 0
  fi
  cat <<EOF
server-kit 服务总管

SSH 和防火墙是只读保护项。
批量操作不会启停 SSH 或防火墙。

查看：
  server-kit-manager.sh
  server-kit-manager.sh status [服务]
  server-kit-manager.sh autostart [服务]
  server-kit-manager.sh ports
  server-kit-manager.sh audit
  server-kit-manager.sh snapshot
  server-kit-manager.sh inventory 服务

管理：
  server-kit-manager.sh start 服务|all
  server-kit-manager.sh stop 服务|all
  server-kit-manager.sh restart 服务|all
  server-kit-manager.sh logs 服务 [行数]

自定义端口：
  server-kit-manager.sh firewall-port list --json
  server-kit-manager.sh firewall-port open 5201 public tcp 3600 --json
  server-kit-manager.sh firewall-port open 5201 amneziawg both permanent --json
  server-kit-manager.sh firewall-port close 5201 public tcp --json
  范围：public 或 amneziawg；协议：tcp、udp 或 both；时长：60–604800 秒或 permanent

服务端口维护：
  server-kit-manager.sh managed-port list --json
  server-kit-manager.sh managed-port plan clash 52542 --json
  server-kit-manager.sh managed-port change clash 52542 <预览版本> --json

SSH 公钥：
  server-kit-manager.sh ssh-key list --json
  server-kit-manager.sh ssh-key preview --json
  server-kit-manager.sh ssh-key add 暂存标识 --json
  server-kit-manager.sh ssh-key rename 公钥标识 --json
  server-kit-manager.sh ssh-key delete 公钥标识 --json

自启：
  server-kit-manager.sh enable-autostart 服务|all
  server-kit-manager.sh disable-autostart 服务|all --yes
  禁用 AWG 自启还需要 --force

服务名：
  amneziawg  management  vless  clash
  file  mosh  cert-renew  firewall  ssh

批量确认：
  server-kit-manager.sh stop all --yes
  server-kit-manager.sh restart all --yes

强制中断当前隧道：
  server-kit-manager.sh stop amneziawg --force
EOF
}

main() {
  local command="${1:-status}"
  local requested=""
  local id=""

  require_platform
  case "${command}" in
    status|list)
      requested="${2:-all}"
      id="$(normalize_id "${requested}")" || { fail "未知服务：${requested}"; exit 1; }
      show_status "${id}"
      ;;
    start|stop|restart)
      requested="${2:-}"
      [[ -n "${requested}" ]] || { fail "请指定服务名或 all。"; exit 1; }
      id="$(normalize_id "${requested}")" || { fail "未知服务：${requested}"; exit 1; }
      acquire_change_lock
      run_action "${command}" "${id}" "${@:3}"
      ;;
    autostart)
      requested="${2:-all}"
      id="$(normalize_id "${requested}")" || { fail "未知服务：${requested}"; exit 1; }
      show_autostart "${id}"
      ;;
    enable-autostart|disable-autostart)
      requested="${2:-}"
      [[ -n "${requested}" ]] || { fail "请指定服务名或 all。"; exit 1; }
      id="$(normalize_id "${requested}")" || { fail "未知服务：${requested}"; exit 1; }
      acquire_change_lock
      if [[ "${command}" == "enable-autostart" ]]; then
        run_autostart_action enable "${id}" "${@:3}"
      else
        run_autostart_action disable "${id}" "${@:3}"
      fi
      ;;
    logs)
      requested="${2:-}"
      [[ -n "${requested}" ]] || { fail "请指定服务名。"; exit 1; }
      id="$(normalize_id "${requested}")" || { fail "未知服务：${requested}"; exit 1; }
      [[ "${id}" != "all" ]] || { fail "logs 不支持 all。"; exit 1; }
      show_logs "${id}" "${3:-80}"
      ;;
    ports) show_ports ;;
    audit) run_audit ;;
    snapshot)
      [[ $# -le 2 && "${2:---json}" == "--json" ]] || {
        fail "snapshot 只支持可选参数 --json。"
        exit 1
      }
      show_snapshot_json
      ;;
    inventory)
      requested="${2:-}"
      [[ -n "${requested}" ]] || { fail "请指定服务名。"; exit 1; }
      id="$(normalize_id "${requested}")" || { fail "未知服务：${requested}"; exit 1; }
      [[ "${id}" != "all" ]] || { fail "inventory 不支持 all。"; exit 1; }
      [[ $# -le 3 && "${3:---json}" == "--json" ]] || {
        fail "inventory 只支持可选参数 --json。"
        exit 1
      }
      show_inventory_json "${id}"
      ;;
    firewall-port)
      case "${2:-}" in
        list)
          [[ $# -eq 3 && "${3:-}" == "--json" ]] || { fail "firewall-port list 参数不正确。"; exit 1; }
          manage_firewall_port_json list
          ;;
        open)
          [[ $# -eq 7 && "${7:-}" == "--json" ]] || { fail "firewall-port open 参数不正确。"; exit 1; }
          acquire_change_lock
          manage_firewall_port_json open "${3}" "${4}" "${5}" "${6}"
          ;;
        close)
          [[ $# -eq 6 && "${6:-}" == "--json" ]] || { fail "firewall-port close 参数不正确。"; exit 1; }
          acquire_change_lock
          manage_firewall_port_json close "${3}" "${4}" "${5}"
          ;;
        *) fail "firewall-port 动作未登记。"; exit 1 ;;
      esac
      ;;
    managed-port)
      case "${2:-}" in
        list)
          [[ $# -eq 3 && "${3:-}" == "--json" ]] || { fail "managed-port list 参数不正确。"; exit 1; }
          managed_ports_overview_json
          ;;
        plan)
          [[ $# -eq 5 && "${5:-}" == "--json" ]] || { fail "managed-port plan 参数不正确。"; exit 1; }
          managed_port_plan_json "${3}" "${4}"
          ;;
        change)
          [[ $# -eq 6 && "${6:-}" == "--json" ]] || { fail "managed-port change 参数不正确。"; exit 1; }
          acquire_change_lock
          change_managed_port_json "${3}" "${4}" "${5}"
          ;;
        *) fail "managed-port 动作未登记。"; exit 1 ;;
      esac
      ;;
    ssh-key)
      case "${2:-}" in
        list|preview)
          [[ $# -eq 3 && "${3:-}" == "--json" ]] || { fail "ssh-key ${2:-} 参数不正确。"; exit 1; }
          [[ "${2:-}" == "preview" ]] && acquire_change_lock
          manage_ssh_key_json "${2}"
          ;;
        add|rename|delete)
          [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "ssh-key ${2:-} 参数不正确。"; exit 1; }
          acquire_change_lock
          manage_ssh_key_json "${2}" "${3}"
          ;;
        *) fail "ssh-key 动作未登记。"; exit 1 ;;
      esac
      ;;
    network)
      case "${2:-}" in
        public-endpoint)
          case "${3:-}" in
            status)
              [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "稳定公网入口状态参数不正确。"; exit 1; }
              manage_public_endpoint_json status
              ;;
            transaction-status|apply|confirm|rollback)
              [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "稳定公网入口事务参数不正确。"; exit 1; }
              acquire_change_lock
              manage_public_endpoint_json "${3}"
              ;;
            automatic-rollback)
              [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "稳定公网入口自动回滚参数不正确。"; exit 1; }
              if IFS= read -r -t 0.05 _automatic_rollback_input; then
                fail "稳定公网入口自动回滚不接受标准输入。"
                exit 1
              fi
              acquire_change_lock
              manage_public_endpoint_json automatic-rollback
              ;;
            *) fail "稳定公网入口动作未登记。"; exit 1 ;;
          esac
          ;;
        duckdns)
          case "${3:-}" in
            status|update)
              [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "动态 DNS ${3:-} 参数不正确。"; exit 1; }
              [[ "${3:-}" == "update" ]] && acquire_change_lock
              manage_duckdns_json "${3}"
              ;;
            configure|disable|delete)
              [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "动态 DNS ${3:-} 参数不正确。"; exit 1; }
              acquire_change_lock
              manage_duckdns_json "${3}"
              ;;
            *) fail "动态 DNS 动作未登记。"; exit 1 ;;
          esac
          ;;
        overview)
          [[ $# -eq 3 && "${3:-}" == "--json" ]] || { fail "network overview 参数不正确。"; exit 1; }
          show_network_overview_json
          ;;
        node)
          acquire_change_lock
          if [[ "${4:-}" == "import" || "${4:-}" == "enroll" ]]; then
            [[ $# -eq 8 && "${8:-}" == "--json" ]] || { fail "network node ${4:-} 参数不正确。"; exit 1; }
            change_network_node_json "${3}" "${4}" "${5}" "${6}" "${7}"
          elif [[ $# -ge 6 && $# -le 7 && "${6:-}" == "--json" || $# -eq 7 && "${7:-}" == "--json" ]]; then
            if [[ "${6:-}" == "--json" ]]; then
            change_network_node_json "${3}" "${4}" "${5}" ""
            else
              change_network_node_json "${3}" "${4}" "${5}" "${6}"
            fi
          else
            fail "network node 参数不正确。"
            exit 1
          fi
          ;;
        domains)
          [[ $# -eq 6 && "${3:-}" =~ ^(set|set-address)$ && "${6:-}" == "--json" ]] || { fail "network domains 参数不正确。"; exit 1; }
          acquire_change_lock
          if [[ "${3}" == "set" ]]; then
            change_node_domains_json "${4}" "${5}" node
          else
            change_node_domains_json "${4}" "${5}" address
          fi
          ;;
        enrollment)
          case "${3:-}" in
            context)
              [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "network enrollment context 参数不正确。"; exit 1; }
              show_enrollment_context_json
              ;;
            overview|reconcile)
              [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "network enrollment ${3:-} 参数不正确。"; exit 1; }
              [[ "${3:-}" == "reconcile" ]] && acquire_change_lock
              manage_enrollments_json "${3}"
              ;;
            *) fail "network enrollment 动作未登记。"; exit 1 ;;
          esac
          ;;
        permission)
          acquire_change_lock
          if [[ $# -eq 5 && "${3:-}" == "batch" && "${5:-}" == "--json" ]]; then
            add_network_permissions_json "${4}"
          elif [[ $# -eq 6 && "${3:-}" == "allow" && "${6:-}" == "--json" ]]; then
            change_network_permission_json allow "${4}" "${5}"
          elif [[ $# -eq 8 && "${3:-}" == "allow" && "${8:-}" == "--json" ]]; then
            change_network_permission_json allow "${4}" "${5}" "${6}" "${7}"
          elif [[ $# -eq 6 && "${3:-}" == "deny" && "${6:-}" == "--json" ]]; then
            change_network_permission_json deny "${4}" "${5}"
          elif [[ $# -eq 8 && "${3:-}" == "deny" && "${8:-}" == "--json" ]]; then
            change_network_permission_json deny "${4}" "${5}" "${6}" "${7}"
          else
            fail "network permission 参数不正确。"
            exit 1
          fi
          ;;
        subscriptions)
          acquire_change_lock
          if [[ $# -eq 4 && "${3:-}" == "sync" && "${4:-}" == "--json" ]]; then
            sync_network_subscriptions_json
          elif [[ $# -eq 5 && "${3:-}" == "rotate" && "${5:-}" == "--json" ]]; then
            rotate_network_subscription_json "${4}"
          elif [[ $# -eq 6 && "${3:-}" == "set-state" && "${6:-}" == "--json" ]]; then
            set_network_subscription_state_json "${4}" "${5}"
          else
            fail "network subscriptions 参数不正确。"
            exit 1
          fi
          ;;
        proxy)
          if [[ $# -eq 4 && "${3:-}" == "overview" && "${4:-}" == "--json" ]]; then
            show_proxy_resources_json
          elif [[ $# -eq 4 && "${3:-}" == "update" && "${4:-}" == "--json" ]]; then
            acquire_change_lock
            update_proxy_resources_json
          elif [[ $# -eq 4 && "${3:-}" == "test" && "${4:-}" == "--json" ]]; then
            test_proxy_resources_json
          else
            fail "network proxy 参数不正确。"
            exit 1
          fi
          ;;
        *) fail "network 动作未登记。"; exit 1 ;;
      esac
      ;;
    file)
      case "${2:-}" in
        overview)
          [[ $# -eq 3 && "${3:-}" == "--json" ]] || { fail "file overview 参数不正确。"; exit 1; }
          show_file_resources_json
          ;;
        inspect-upload)
          [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "file inspect-upload 参数不正确。"; exit 1; }
          inspect_file_upload_json "${3}"
          ;;
        discard-upload)
          [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "file discard-upload 参数不正确。"; exit 1; }
          acquire_change_lock
          discard_file_upload_json "${3}"
          ;;
        add)
          [[ $# -eq 7 && "${7:-}" == "--json" ]] || { fail "file add 参数不正确。"; exit 1; }
          acquire_change_lock
          change_file_resource_json add "${3}" "${4}" "${5}" "${6}"
          ;;
        delete)
          [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "file delete 参数不正确。"; exit 1; }
          acquire_change_lock
          change_file_resource_json delete "${3}"
          ;;
        *) fail "file 动作未登记。"; exit 1 ;;
      esac
      ;;
    deploy)
      acquire_change_lock
      case "${2:-}" in
        vless)
          [[ $# -eq 5 && "${5:-}" == "--json" ]] || { fail "deploy vless 参数不正确。"; exit 1; }
          deploy_service_json vless "${3}" "${4}"
          ;;
        clash)
          [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "deploy clash 参数不正确。"; exit 1; }
          deploy_service_json clash "${3}"
          ;;
        mosh)
          [[ $# -eq 3 && "${3:-}" == "--json" ]] || { fail "deploy mosh 参数不正确。"; exit 1; }
          deploy_service_json mosh
          ;;
        file)
          [[ $# -eq 6 && "${6:-}" == "--json" ]] || { fail "deploy file 参数不正确。"; exit 1; }
          deploy_service_json file "${3}" "${4}:${5}"
          ;;
        *) fail "部署服务未登记。"; exit 1 ;;
      esac
      ;;
    reveal)
      [[ $# -eq 5 && ( ( "${2:-}" == "clash" && ( "${3:-}" == "subscription-link" || "${3:-}" == "subscription-qr" || "${3:-}" == "airport-link" || "${3:-}" == "exit-config" ) ) || ( "${2:-}" == "file" && ( "${3:-}" == "file-link" || "${3:-}" == "file-qr" ) ) ) && "${5:-}" == "--json" ]] || {
        fail "reveal 参数不受支持。"
        exit 1
      }
      show_secret_resources_json "${2}" "${3}" "${4}"
      ;;
    transaction)
      [[ $# -eq 4 && ( "${2:-}" == "ssh_auth" || "${2:-}" == "ssh_listener" || "${2:-}" == "firewall" || "${2:-}" == "vless_listener" ) && \
        ( "${3:-}" == "status" || "${3:-}" == "preview" || "${3:-}" == "apply" || "${3:-}" == "confirm" || "${3:-}" == "rollback" || ( "${2:-}" == "vless_listener" && "${3:-}" == "automatic-rollback" ) ) && \
        "${4:-}" == "--json" ]] || {
        fail "transaction 参数不正确。"
        exit 1
      }
      if [[ "${2}" == "vless_listener" || "${3:-}" != "status" ]]; then acquire_change_lock; fi
      if [[ "${2}" == "vless_listener" && "${3}" == "automatic-rollback" ]]; then
        automatic_rollback_vless_listener_json
      elif [[ "${2}" == "vless_listener" ]]; then
        show_vless_listener_transaction_json "${3}"
      else
        show_transaction_json "${2}" "${3}"
      fi
      ;;
    backup)
      case "${2:-}" in
        list|create)
          [[ $# -le 3 && "${3:---json}" == "--json" ]] || { fail "备份参数不正确。"; exit 1; }
          if [[ "${2:-}" == "create" ]]; then acquire_change_lock; fi
          run_backup_json "${2}"
          ;;
        verify|delete|preview-restore|restore-apply)
          [[ $# -eq 4 && "${4:-}" == "--json" ]] || { fail "备份参数不正确。"; exit 1; }
          if [[ "${2:-}" == "restore-apply" || "${2:-}" == "delete" ]]; then acquire_change_lock; fi
          run_backup_json "${2}" "${3}"
          ;;
        restore-status|restore-confirm)
          [[ $# -eq 3 && "${3:-}" == "--json" ]] || { fail "恢复事务参数不正确。"; exit 1; }
          if [[ "${2:-}" == "restore-confirm" ]]; then acquire_change_lock; fi
          run_backup_json "${2}"
          ;;
        restore-rollback)
          acquire_change_lock
          if [[ $# -eq 3 && "${3:-}" == "--json" ]]; then
            run_backup_json "${2}"
          elif [[ $# -eq 4 && "${3:-}" == "--automatic" && "${4:-}" == "--json" ]]; then
            run_backup_json "${2}" "" 1
          else
            fail "恢复回滚参数不正确。"
            exit 1
          fi
          ;;
        *) fail "备份动作未登记。"; exit 1 ;;
      esac
      ;;
    help|-h|--help) usage ;;
    *) usage; exit 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
