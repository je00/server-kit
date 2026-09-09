#!/usr/bin/env bash

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_PATH}" ]]; do
  SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
  SCRIPT_PATH="$(readlink -- "${SCRIPT_PATH}")"
  [[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="${SCRIPT_LINK_DIR}/${SCRIPT_PATH}"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"

SERVICE_NAME="xray"
CONFIG_DIR="/usr/local/etc/xray"
CONFIG_PATH="${CONFIG_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"
INSTALL_SCRIPT_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
DEFAULT_PORT="443"
DEFAULT_RESCUE_PORT="2053"
DEFAULT_SERVER_NAME="www.amazon.com"
VLESS_INSTALL_NONINTERACTIVE="${VLESS_INSTALL_NONINTERACTIVE:-0}"
VLESS_INSTALL_PORT="${VLESS_INSTALL_PORT:-}"
VLESS_INSTALL_SERVER_NAME="${VLESS_INSTALL_SERVER_NAME:-}"
PUBLIC_STATE_FILE="/etc/default/vless-manager-public"
PUBLIC_INBOUND_TAG="vless-public"
PUBLIC_RESCUE_INBOUND_TAG="vless-public-rescue"
SERVER_KIT_DIR="${SERVER_KIT_DIR:-/etc/server-kit}"
NODE_DOMAINS_PATH="${NODE_DOMAINS_PATH:-${SERVER_KIT_DIR}/node-domains.json}"
VLESS_ACCESS_PATH="${VLESS_ACCESS_PATH:-${SERVER_KIT_DIR}/vless-access.json}"
VLESS_ACCESS_PENDING_PATH="${VLESS_ACCESS_PENDING_PATH:-${SERVER_KIT_DIR}/vless-access.pending.json}"
VLESS_ACCESS_AUDIT_PATH="${VLESS_ACCESS_AUDIT_PATH:-/var/log/server-kit/vless-access.log}"
VLESS_ACCESS_HELPER="${VLESS_ACCESS_HELPER:-${SCRIPT_DIR}/lib/vless_access.py}"
SERVER_RELAY_HELPER="${SERVER_RELAY_HELPER:-${SCRIPT_DIR}/lib/server_kit_relay.py}"
SERVER_RELAY_CONFIG="${SERVER_RELAY_CONFIG:-${SERVER_KIT_DIR}/server-relay.json}"
EXIT_DNS_HELPER="${EXIT_DNS_HELPER:-${SCRIPT_DIR}/lib/server_kit_exit_dns.py}"
EXIT_DNS_DIR="${EXIT_DNS_DIR:-${SERVER_KIT_DIR}/exit-dns}"
EXIT_DNS_SYSTEMD_DIR="${EXIT_DNS_SYSTEMD_DIR:-/etc/systemd/system}"
EXIT_DNS_TRANSACTION_ROOT="${EXIT_DNS_TRANSACTION_ROOT:-/var/lib/server-kit/exit-dns-transactions}"
EXIT_DNS_SYSTEMCTL_BIN="${EXIT_DNS_SYSTEMCTL_BIN:-/usr/bin/systemctl}"
CLASH_INPUT_CONFIG="${CLASH_INPUT_CONFIG:-${SERVER_KIT_DIR}/clash-inputs.json}"
CLASH_SERVICE_CONFIG="${CLASH_SERVICE_CONFIG:-/etc/secure-file-service/clash-config.json}"
FILE_MANAGER="${FILE_MANAGER:-${SCRIPT_DIR}/debian_file_manager.sh}"
FIREWALL_MANAGER="${FIREWALL_MANAGER:-${SCRIPT_DIR}/debian_firewall_manager.sh}"
SECURITY_MANAGER="${SECURITY_MANAGER:-${SCRIPT_DIR}/debian_security_manager.sh}"
AWG_PEER_DB="${AWG_PEER_DB:-/etc/amneziawg/peers.tsv}"
AWG_STATE_FILE="${AWG_STATE_FILE:-/etc/amneziawg/manager.conf}"
AWG_NETWORK="${AWG_NETWORK:-10.20.0.0/24}"
PUBLIC_SSH_VERIFIED_PATH="${PUBLIC_SSH_VERIFIED_PATH:-${SERVER_KIT_DIR}/run/awg-public-ssh-verified}"
VLESS_SSH_GATE_TTL="${VLESS_SSH_GATE_TTL:-900}"
VLESS_SKIP_SSH_GATE="${VLESS_SKIP_SSH_GATE:-0}"
VLESS_LISTENER_TRANSACTION_DIR="${VLESS_LISTENER_TRANSACTION_DIR:-/var/lib/server-kit/vless-listener-transaction}"
VLESS_LISTENER_OUTCOME_PATH="${VLESS_LISTENER_OUTCOME_PATH:-/var/lib/server-kit/vless-listener-last-outcome.json}"
VLESS_LISTENER_ROLLBACK_SECONDS="${VLESS_LISTENER_ROLLBACK_SECONDS:-300}"
VLESS_LISTENER_ROLLBACK_UNIT="${VLESS_LISTENER_ROLLBACK_UNIT:-server-kit-vless-listener-rollback}"
SYSTEMD_RUN_BIN="${SYSTEMD_RUN_BIN:-/usr/bin/systemd-run}"
VLESS_LISTENER_MANAGER="${SCRIPT_DIR}/server-kit-manager.sh"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "请使用 root 运行此脚本。"
    exit 1
  fi
}

check_debian() {
  if [[ ! -r /etc/os-release ]]; then
    echo "无法识别当前系统。"
    exit 1
  fi

  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" != "debian" ]] && [[ "${ID_LIKE:-}" != *"debian"* ]]; then
    echo "此脚本仅支持 Debian 或 Debian 系发行版。"
    exit 1
  fi
}

prompt_optional() {
  local prompt_text="$1"
  local value=""
  read -r -p "${prompt_text}" value
  printf '%s\n' "${value}"
}

validate_port() {
  local port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] && (( ${#port} <= 5 )) &&
    (( 10#${port} >= 1 && 10#${port} <= 65535 ))
}

validate_domain() {
  local domain="$1"
  local label=""
  local labels=()

  if (( ${#domain} > 253 )) || [[ "${domain}" != *.* ]] ||
     [[ ! "${domain}" =~ ^[A-Za-z0-9.-]+$ ]] || [[ "${domain}" == .* ]] ||
     [[ "${domain}" == *. ]] || [[ "${domain}" == *..* ]]; then
    return 1
  fi

  IFS='.' read -r -a labels <<< "${domain}"
  for label in "${labels[@]}"; do
    if (( ${#label} < 1 || ${#label} > 63 )) ||
       [[ "${label}" == -* ]] || [[ "${label}" == *- ]]; then
      return 1
    fi
  done
}

prompt_server_name() {
  local server_name=""

  while true; do
    server_name="$(prompt_optional "请输入 REALITY 伪装域名 [默认 ${DEFAULT_SERVER_NAME}]: ")"
    server_name="${server_name:-${DEFAULT_SERVER_NAME}}"

    if validate_domain "${server_name}"; then
      printf '%s\n' "${server_name,,}"
      return
    fi

    echo "域名无效，请输入不带协议和端口的完整域名。" >&2
  done
}

validate_uuid() {
  local uuid="$1"
  [[ "${uuid}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

prompt_uuid() {
  local uuid=""

  while true; do
    uuid="$(prompt_optional "请输入 VLESS UUID [直接回车自动生成]: ")"
    if [[ -z "${uuid}" ]]; then
      "${XRAY_BIN}" uuid
      return
    fi

    if validate_uuid "${uuid}"; then
      printf '%s\n' "${uuid,,}"
      return
    fi

    echo "UUID 格式无效，请重新输入。" >&2
  done
}

install_dependencies() {
  local package=""
  local missing_packages=()

  export DEBIAN_FRONTEND=noninteractive
  for package in curl ca-certificates python3 openssl iproute2; do
    if ! dpkg -s "${package}" >/dev/null 2>&1; then
      missing_packages+=("${package}")
    fi
  done

  if (( ${#missing_packages[@]} > 0 )); then
    apt-get update
    apt-get install -y "${missing_packages[@]}"
  fi

  if [[ -x "${XRAY_BIN}" ]] && systemctl cat "${SERVICE_NAME}.service" >/dev/null 2>&1; then
    echo "检测到 Xray-core 已安装，跳过安装步骤。"
    return
  fi

  local installer=""
  installer="$(mktemp)"
  trap 'rm -f "${installer}"' RETURN

  echo "正在从 XTLS 官方仓库安装 Xray-core……"
  curl -fL --retry 3 --connect-timeout 10 "${INSTALL_SCRIPT_URL}" -o "${installer}"
  bash "${installer}" install

  rm -f "${installer}"
  trap - RETURN
}

parse_x25519_field() {
  local field_type="$1"
  local key_output="$2"

  awk -v field_type="${field_type}" '
    {
      line = $0
      sub(/\r$/, "", line)
      separator = index(line, ":")
      if (separator == 0) {
        next
      }

      label = substr(line, 1, separator - 1)
      value = substr(line, separator + 1)
      gsub(/\033\[[0-9;]*[[:alpha:]]/, "", label)
      gsub(/[[:space:]()_-]/, "", label)
      label = tolower(label)
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)

      if (field_type == "private" && label == "privatekey") {
        print value
        exit
      }

      if (field_type == "public" &&
          (label == "password" || label == "passwordpublickey" || label == "publickey")) {
        print value
        exit
      }
    }
  ' <<< "${key_output}"
}

show_x25519_labels() {
  local key_output="$1"
  awk -F':' 'NF > 1 {print $1 ": <密钥值已隐藏>"}' <<< "${key_output}" >&2
}

generate_reality_keypair() {
  local key_output=""
  local private_key=""
  local public_key=""

  if ! key_output="$("${XRAY_BIN}" x25519 2>&1)"; then
    echo "Xray 生成 REALITY 密钥失败：" >&2
    printf '%s\n' "${key_output}" >&2
    return 1
  fi

  private_key="$(parse_x25519_field "private" "${key_output}")"
  public_key="$(parse_x25519_field "public" "${key_output}")"

  if [[ -z "${private_key}" || -z "${public_key}" ]]; then
    echo "无法解析 Xray 生成的 REALITY 密钥。" >&2
    echo "检测到的输出字段：" >&2
    show_x25519_labels "${key_output}"
    return 1
  fi

  printf '%s %s\n' "${private_key}" "${public_key}"
}

install_tested_config() {
  local temp_config="$1"
  local quiet="${2:-0}"
  local service_user=""
  local service_group=""
  local backup_path=""

  "${XRAY_BIN}" run -test -format=json -config "${temp_config}"

  service_user="$(systemctl show "${SERVICE_NAME}.service" -p User --value 2>/dev/null || true)"
  service_user="${service_user:-root}"
  if ! id "${service_user}" >/dev/null 2>&1; then
    service_user="root"
  fi
  service_group="$(id -gn "${service_user}")"

  if [[ -r "${CONFIG_PATH}" ]]; then
    backup_path="${CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "${CONFIG_PATH}" "${backup_path}"
    [[ "${quiet}" == "1" ]] || echo "旧 Xray 配置已备份：${backup_path}"
  fi
  install -m 640 -o root -g "${service_group}" "${temp_config}" "${CONFIG_PATH}"
}

save_public_state() {
  local port="$1"
  local uuid="$2"
  local server_name="$3"
  local public_key="$4"
  local short_id="$5"
  local listen_address="$6"
  local rescue_port="${7:-${DEFAULT_RESCUE_PORT}}"

  (
    umask 077
    cat > "${PUBLIC_STATE_FILE}" <<EOF
VLESS_PUBLIC_PORT="${port}"
VLESS_PUBLIC_UUID="${uuid}"
VLESS_PUBLIC_SERVER_NAME="${server_name}"
VLESS_PUBLIC_REALITY_KEY="${public_key}"
VLESS_PUBLIC_SHORT_ID="${short_id}"
VLESS_PUBLIC_LISTEN_ADDRESS="${listen_address}"
VLESS_PUBLIC_RESCUE_PORT="${rescue_port}"
EOF
  )
  chmod 600 "${PUBLIC_STATE_FILE}"
}

load_public_state() {
  if [[ -r "${PUBLIC_STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${PUBLIC_STATE_FILE}"
  fi
}

write_public_inbound() {
  local uuid="$1"
  local port="$2"
  local listen_address="$3"
  local server_name="$4"
  local private_key="$5"
  local short_id="$6"
  local temp_config=""

  mkdir -p "${CONFIG_DIR}"
  temp_config="$(mktemp "${CONFIG_DIR}/.vless-public.XXXXXX")"
  trap 'rm -f "${temp_config}"' RETURN

  python3 - "${CONFIG_PATH}" "${temp_config}" "${uuid}" "${port}" \
    "${listen_address}" "${server_name}" "${private_key}" "${short_id}" \
    "${PUBLIC_INBOUND_TAG}" "${PUBLIC_RESCUE_INBOUND_TAG}" \
    "${DEFAULT_RESCUE_PORT}" <<'PYTHON'
import json
import os
import sys

(
    source_path,
    target_path,
    uuid,
    port,
    listen,
    server_name,
    private_key,
    short_id,
    public_tag,
    rescue_tag,
    rescue_port,
) = sys.argv[1:]

try:
    with open(source_path, encoding="utf-8") as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }

inbounds = config.setdefault("inbounds", [])

def addresses_overlap(first, second):
    wildcards = {"0.0.0.0", "::", ""}
    return first == second or first in wildcards or second in wildcards

managed_tags = {public_tag, rescue_tag}
if int(port) == int(rescue_port):
    raise SystemExit("公网 VLESS 主端口不能与救援端口相同")
for inbound in inbounds:
    if inbound.get("tag") in managed_tags:
        continue
    for candidate_port in (port, rescue_port):
        if int(inbound.get("port", -1)) == int(candidate_port) and addresses_overlap(
            str(inbound.get("listen", "")), listen
        ):
            raise SystemExit(
                f"监听冲突：{inbound.get('listen', '0.0.0.0')}:{candidate_port} 已被现有入站使用"
            )

def public_inbound(tag, inbound_port):
    return {
        "tag": tag,
        "listen": listen,
        "port": int(inbound_port),
        "protocol": "vless",
        "settings": {
            "clients": [
                {
                    "id": uuid,
                    "level": 0,
                    "flow": "xtls-rprx-vision",
                }
            ],
            "decryption": "none",
        },
        "streamSettings": {
            "method": "raw",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "target": f"{server_name}:443",
                "xver": 0,
                "serverNames": [server_name],
                "privateKey": private_key,
                "shortIds": [short_id],
            },
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": True,
        },
    }

retained = [item for item in inbounds if item.get("tag") not in managed_tags]
config["inbounds"] = retained + [
    public_inbound(public_tag, port),
    public_inbound(rescue_tag, rescue_port),
]

with open(target_path, "w", encoding="utf-8", newline="\n") as config_file:
    json.dump(config, config_file, ensure_ascii=False, indent=2)
    config_file.write("\n")
    config_file.flush()
    os.fsync(config_file.fileno())
PYTHON

  install_tested_config "${temp_config}"
  rm -f "${temp_config}"
  trap - RETURN
}

enable_rescue_inbound() {
  local rescue_port="${1:-${DEFAULT_RESCUE_PORT}}"
  local temp_config=""
  local rollback_config=""
  local values=()

  validate_port "${rescue_port}" || {
    echo "救援端口无效: ${rescue_port}" >&2
    return 1
  }
  rescue_port="$((10#${rescue_port}))"
  [[ "${rescue_port}" != "${DEFAULT_PORT}" ]] || {
    echo "救援端口不能与主端口相同。" >&2
    return 1
  }
  [[ -r "${CONFIG_PATH}" ]] || {
    echo "未找到配置文件 ${CONFIG_PATH}。" >&2
    return 1
  }

  mkdir -p "${CONFIG_DIR}"
  temp_config="$(mktemp "${CONFIG_DIR}/.vless-rescue.XXXXXX")"
  rollback_config="$(mktemp "${CONFIG_DIR}/.vless-rescue-rollback.XXXXXX")"
  trap 'rm -f "${temp_config}" "${rollback_config}"' RETURN
  cp -a -- "${CONFIG_PATH}" "${rollback_config}"

  python3 - "${CONFIG_PATH}" "${temp_config}" "${PUBLIC_INBOUND_TAG}" \
    "${PUBLIC_RESCUE_INBOUND_TAG}" "${rescue_port}" <<'PYTHON'
import copy
import json
import os
import sys

source_path, target_path, public_tag, rescue_tag, rescue_port = sys.argv[1:]
with open(source_path, encoding="utf-8") as config_file:
    config = json.load(config_file)

inbounds = config.get("inbounds", [])
primary = [item for item in inbounds if item.get("tag") == public_tag]
if len(primary) != 1:
    raise SystemExit("未找到唯一的公网 VLESS 主入站")
primary = primary[0]
if primary.get("protocol") != "vless" or primary.get("streamSettings", {}).get("security") != "reality":
    raise SystemExit("公网 VLESS 主入站不是 REALITY 配置")
if int(primary.get("port", -1)) == int(rescue_port):
    raise SystemExit("公网 VLESS 主端口不能与救援端口相同")

def addresses_overlap(first, second):
    wildcards = {"0.0.0.0", "::", ""}
    return first == second or first in wildcards or second in wildcards

listen = str(primary.get("listen", ""))
for inbound in inbounds:
    if inbound.get("tag") in {public_tag, rescue_tag}:
        continue
    if int(inbound.get("port", -1)) == int(rescue_port) and addresses_overlap(
        str(inbound.get("listen", "")), listen
    ):
        raise SystemExit(
            f"监听冲突：{inbound.get('listen', '0.0.0.0')}:{rescue_port} 已被现有入站使用"
        )

rescue = copy.deepcopy(primary)
rescue["tag"] = rescue_tag
rescue["port"] = int(rescue_port)
config["inbounds"] = [
    item for item in inbounds if item.get("tag") != rescue_tag
] + [rescue]

with open(target_path, "w", encoding="utf-8", newline="\n") as config_file:
    json.dump(config, config_file, ensure_ascii=False, indent=2)
    config_file.write("\n")
    config_file.flush()
    os.fsync(config_file.fileno())
PYTHON

  install_tested_config "${temp_config}"
  if ! systemctl restart "${SERVICE_NAME}"; then
    cp -a -- "${rollback_config}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" || true
    echo "Xray 启用救援端口失败，已恢复原配置。" >&2
    return 1
  fi

  mapfile -t values < <(read_public_inbound)
  load_public_state
  save_public_state "${values[1]}" "${values[2]}" "${values[3]}" \
    "${VLESS_PUBLIC_REALITY_KEY:-}" "${values[4]}" "${values[0]}" "${rescue_port}"
  VLESS_PUBLIC_RESCUE_PORT="${rescue_port}"
  if [[ -d "${SERVER_KIT_DIR}" ]]; then
    (umask 077; clash_public_config > "${SERVER_KIT_DIR}/public-vless-clash.yaml")
  fi
  rm -f "${temp_config}" "${rollback_config}"
  trap - RETURN
  echo "公网 VLESS 救援入站已启用：TCP ${rescue_port}（主端口保持不变）。"
}

set_public_server_name() {
  local server_name="${1:-}"
  local temp_config=""

  if [[ -z "${server_name}" ]]; then
    server_name="$(prompt_server_name)"
  else
    server_name="${server_name,,}"
    if ! validate_domain "${server_name}"; then
      echo "域名无效，请输入不带协议和端口的完整域名。" >&2
      return 1
    fi
  fi

  [[ -r "${CONFIG_PATH}" ]] || {
    echo "未找到配置文件 ${CONFIG_PATH}。" >&2
    return 1
  }
  if ! "${XRAY_BIN}" tls ping "${server_name}" >/dev/null 2>&1; then
    echo "${server_name} 未通过 Xray TLS 检查，拒绝修改。" >&2
    return 1
  fi

  temp_config="$(mktemp "${CONFIG_DIR}/.vless-public-sni.XXXXXX")"
  trap 'rm -f "${temp_config}"' RETURN
  python3 - "${CONFIG_PATH}" "${temp_config}" "${PUBLIC_INBOUND_TAG}" \
    "${PUBLIC_RESCUE_INBOUND_TAG}" "${server_name}" <<'PYTHON'
import json
import os
import sys

source_path, target_path, public_tag, rescue_tag, server_name = sys.argv[1:]
with open(source_path, encoding="utf-8") as config_file:
    config = json.load(config_file)

matched = 0
for inbound in config.get("inbounds", []):
    if inbound.get("tag") not in {public_tag, rescue_tag}:
        continue
    reality = inbound.get("streamSettings", {}).get("realitySettings")
    if not reality:
        raise SystemExit("公网入站不是 REALITY 配置")
    reality["target"] = f"{server_name}:443"
    reality["serverNames"] = [server_name]
    matched += 1
if not matched:
    raise SystemExit("未找到公网 VLESS 入站，请先执行 install")

with open(target_path, "w", encoding="utf-8", newline="\n") as config_file:
    json.dump(config, config_file, ensure_ascii=False, indent=2)
    config_file.write("\n")
    config_file.flush()
    os.fsync(config_file.fileno())
PYTHON

  install_tested_config "${temp_config}"
  systemctl restart "${SERVICE_NAME}"
  rm -f "${temp_config}"
  trap - RETURN

  load_public_state
  save_public_state "${VLESS_PUBLIC_PORT}" "${VLESS_PUBLIC_UUID}" \
    "${server_name}" "${VLESS_PUBLIC_REALITY_KEY}" "${VLESS_PUBLIC_SHORT_ID}" \
    "${VLESS_PUBLIC_LISTEN_ADDRESS}" "${VLESS_PUBLIC_RESCUE_PORT:-${DEFAULT_RESCUE_PORT}}"
  if [[ -d "${SERVER_KIT_DIR}" ]]; then
    (umask 077; clash_public_config > "${SERVER_KIT_DIR}/public-vless-clash.yaml")
  fi
  echo "公网 REALITY 伪装站已改为 ${server_name}，UUID 和密钥保持不变。"
}

write_public_any_candidate() {
  local source_path="$1"
  local target_path="$2"
  python3 - "${source_path}" "${target_path}" "${PUBLIC_INBOUND_TAG}" \
    "${PUBLIC_RESCUE_INBOUND_TAG}" <<'PYTHON'
import json
import os
import sys

source_path, target_path, public_tag, rescue_tag = sys.argv[1:]
with open(source_path, encoding="utf-8") as config_file:
    config = json.load(config_file)

matched = 0
for inbound in config.get("inbounds", []):
    if inbound.get("tag") not in {public_tag, rescue_tag}:
        continue
    inbound["listen"] = "0.0.0.0"
    matched += 1
if not matched:
    raise SystemExit("未找到公网 VLESS 入站，请先执行 install")

with open(target_path, "w", encoding="utf-8", newline="\n") as config_file:
    json.dump(config, config_file, ensure_ascii=False, indent=2)
    config_file.write("\n")
    config_file.flush()
    os.fsync(config_file.fileno())
PYTHON
}

vless_listener_transaction() {
  local operation="$1"
  local metadata="${VLESS_LISTENER_TRANSACTION_DIR}/metadata.json"
  local config_backup="${VLESS_LISTENER_TRANSACTION_DIR}/config.backup"
  local state_backup="${VLESS_LISTENER_TRANSACTION_DIR}/state.backup"
  local candidate=""
  local request_json=""
  local session_id=""
  local actor=""
  local transaction_id=""
  local -a request_values=()

  if [[ "${operation}" != "automatic-rollback" ]]; then
    [[ "${SERVER_KIT_CONTROL:-0}" == "1" ]] || {
      echo "VLESS 监听事务只允许由受限控制面调用。" >&2; return 1;
    }
    if [[ "${operation}" == "apply" || "${operation}" == "confirm" ]]; then
      [[ "${SERVER_KIT_HIGH_RISK_WRITES:-0}" == "1" ]] || {
        echo "VLESS 监听事务需要启用高风险写操作。" >&2; return 1;
      }
    fi
  fi

  [[ "${VLESS_LISTENER_ROLLBACK_SECONDS}" =~ ^[0-9]+$ ]] &&
    (( VLESS_LISTENER_ROLLBACK_SECONDS >= 60 && VLESS_LISTENER_ROLLBACK_SECONDS <= 3600 )) || {
      echo "VLESS 监听回滚窗口必须为 60–3600 秒。" >&2; return 1;
    }

  listener_sync_dir() {
    local path="$1"
    python3 - "${path}" <<'PYTHON'
import os, sys
path = sys.argv[1]
descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
try: os.fsync(descriptor)
finally: os.close(descriptor)
PYTHON
  }
  listener_write_outcome() {
    local outcome="$1"
    python3 - "${metadata}" "${VLESS_LISTENER_OUTCOME_PATH}" "${outcome}" <<'PYTHON'
import json, os, re, sys, tempfile
metadata_path, outcome_path, outcome = sys.argv[1:]
with open(metadata_path, encoding="utf-8") as source: transaction_id=json.load(source).get("transaction_id", "")
if re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None: raise SystemExit("事务标识无效")
os.makedirs(os.path.dirname(outcome_path), mode=0o700, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=".vless-listener-outcome-", dir=os.path.dirname(outcome_path))
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump({"transaction_id":transaction_id,"last_outcome":outcome}, output, separators=(",", ":")); output.write("\n"); output.flush(); os.fsync(output.fileno())
os.chmod(temporary, 0o600); os.replace(temporary, outcome_path)
directory=os.open(os.path.dirname(outcome_path), os.O_RDONLY | os.O_DIRECTORY)
try: os.fsync(directory)
finally: os.close(directory)
PYTHON
  }
  listener_mark_confirmed() {
    python3 - "${metadata}" <<'PYTHON'
import json, os, sys, tempfile, time
path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    value = json.load(source)
if value.get("phase") != "pending" or int(value["expires_epoch"]) <= int(time.time()):
    raise SystemExit("事务已经到期或状态无效")
value["phase"] = "confirmed"
descriptor, temporary = tempfile.mkstemp(prefix=".metadata-confirmed-", dir=os.path.dirname(path))
try:
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
finally:
    if os.path.exists(temporary): os.unlink(temporary)
PYTHON
  }
  listener_finalize_confirmed() {
    listener_write_outcome confirmed || return 1
    listener_remove_transaction
    systemctl stop "${VLESS_LISTENER_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
  }
  listener_remove_transaction() {
    rm -rf -- "${VLESS_LISTENER_TRANSACTION_DIR}"
    listener_sync_dir "$(dirname -- "${VLESS_LISTENER_TRANSACTION_DIR}")"
  }
  listener_verify_backups() {
    python3 - "${metadata}" "${config_backup}" "${state_backup}" <<'PYTHON'
import hashlib, json, os, stat, sys
metadata_path, config_path, state_path = sys.argv[1:]
with open(metadata_path, encoding="utf-8") as source:
    metadata = json.load(source)
for prefix, path, required in (
    ("config", config_path, True),
    ("state", state_path, metadata.get("state_existed") is True),
):
    if not required:
        if os.path.lexists(path):
            raise ValueError(f"{prefix} 原事实不存在但出现了意外备份")
        continue
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{prefix} 备份不是普通文件")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        mode = format(stat.S_IMODE(file_stat.st_mode), "04o")
    finally:
        os.close(descriptor)
    if digest.hexdigest() != metadata.get(f"{prefix}_sha256") or mode != metadata.get(f"{prefix}_mode"):
        raise ValueError(f"{prefix} 备份完整性校验失败")
PYTHON
  }
  listener_restore() {
    local outcome="${1:-rolled_back}"
    [[ -r "${metadata}" && -r "${config_backup}" ]] || return 0
    if python3 - "${metadata}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
raise SystemExit(0 if value.get("phase") == "confirmed" else 1)
PYTHON
    then
      listener_finalize_confirmed
      return
    fi
    listener_verify_backups || return 1
    install_tested_config "${config_backup}" 1 || return 1
    systemctl restart "${SERVICE_NAME}" || return 1
    if python3 - "${metadata}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source: value=json.load(source)
raise SystemExit(0 if value.get("state_existed") is True else 1)
PYTHON
    then
      cp -a -- "${state_backup}" "${PUBLIC_STATE_FILE}"
    else
      rm -f -- "${PUBLIC_STATE_FILE}"
    fi
    listener_write_outcome "${outcome}" || return 1
    listener_remove_transaction
  }
  listener_render() {
    python3 - "${CONFIG_PATH}" "${metadata}" "${VLESS_LISTENER_OUTCOME_PATH}" \
      "${session_id}" "${VLESS_LISTENER_ROLLBACK_SECONDS}" "${SERVER_KIT_HIGH_RISK_WRITES:-1}" \
      "${PUBLIC_INBOUND_TAG}" <<'PYTHON'
import hashlib, json, os, re, sys, time
config_path, metadata_path, outcome_path, session_id, rollback, writes, tag = sys.argv[1:]
listen, blocker = "", ""
try:
    with open(config_path, encoding="utf-8") as source: config=json.load(source)
    matches=[item for item in config.get("inbounds", []) if item.get("tag") == tag]
    if len(matches) != 1: blocker="未找到唯一的公网 VLESS 入站。"
    else: listen=str(matches[0].get("listen", ""))
except (OSError, ValueError, TypeError): blocker="Xray 配置无效。"
state, expires_at, remaining, independent = "idle", "", 0, True
transaction_id, last_outcome = "", ""
if os.path.isfile(metadata_path):
    with open(metadata_path, encoding="utf-8") as source: metadata=json.load(source)
    transaction_id=metadata.get("transaction_id", "")
    expires=int(metadata["expires_epoch"])
    state, expires_at, remaining = "pending", metadata["expires_at"], max(0, expires-int(time.time()))
    independent=hashlib.sha256(session_id.encode("ascii")).hexdigest() != metadata["session_hash"]
elif os.path.isfile(outcome_path):
    with open(outcome_path, encoding="utf-8") as source: outcome=json.load(source)
    transaction_id, last_outcome=outcome.get("transaction_id", ""), outcome.get("last_outcome", "")
if transaction_id and re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None: raise SystemExit("事务标识无效")
already_bound=listen == "0.0.0.0"
blockers=[blocker] if blocker else (["公网 VLESS 入站已经监听全部本机 IPv4。"] if already_bound and state == "idle" else [])
value={"schema_version":1,"transaction_type":"vless_listener","title":"VLESS 公网监听迁移","state":state,"expires_at":expires_at,"remaining_seconds":remaining,"writes_enabled":writes == "1","rollback_seconds":int(rollback),"changes":[{"label":"公网监听地址","current":listen or "不可用","target":"0.0.0.0","changed":bool(listen and not already_bound)}],"verifications":["从另一条独立连接验证 VLESS 可用后确认"],"ready":not blockers,"blockers":blockers,"independent_session":independent,"transaction_id":transaction_id,"last_outcome":last_outcome}
print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
PYTHON
  }

  if [[ "${operation}" != "automatic-rollback" ]]; then
    request_json="$(cat)"
    mapfile -t request_values < <(python3 -c 'import json,sys; value=json.load(sys.stdin); [print(value.get(key,"")) for key in ("session_id","actor")]' <<<"${request_json}")
    [[ "${#request_values[@]}" -eq 2 ]] || { echo "VLESS 监听事务输入无效。" >&2; return 1; }
    session_id="${request_values[0]}"; actor="${request_values[1]}"
    [[ -n "${actor}" ]] || { echo "VLESS 监听事务会话无效。" >&2; return 1; }
    if [[ "${operation}" == "apply" || "${operation}" == "confirm" || "${operation}" == "rollback" ]]; then
      [[ "${session_id}" =~ ^[0-9a-f]{64}$ ]] || { echo "VLESS 监听事务会话无效。" >&2; return 1; }
    elif [[ -n "${session_id}" && ! "${session_id}" =~ ^[0-9a-f]{64}$ ]]; then
      echo "VLESS 监听事务会话无效。" >&2
      return 1
    fi
  fi

  if [[ "${operation}" == "status" && -r "${metadata}" ]] && ! python3 - "${metadata}" <<'PYTHON'
import json, sys, time
with open(sys.argv[1], encoding="utf-8") as source: value=json.load(source)
raise SystemExit(0 if value.get("phase") == "pending" and int(value["expires_epoch"]) > int(time.time()) else 1)
PYTHON
  then
    listener_restore automatic_rollback || return 1
    systemctl stop "${VLESS_LISTENER_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
  fi

  case "${operation}" in
    status|preview) listener_render ;;
    confirm)
      [[ -r "${metadata}" ]] || { echo "当前没有待确认的 VLESS 监听事务。" >&2; return 1; }
      if ! python3 - "${metadata}" <<'PYTHON'
import json, sys, time
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
raise SystemExit(0 if int(value["expires_epoch"]) > int(time.time()) else 1)
PYTHON
      then
        listener_restore automatic_rollback || return 1
        systemctl stop "${VLESS_LISTENER_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
        echo "VLESS 监听事务已经到期并回滚，不能再确认。" >&2
        return 1
      fi
      if python3 - "${metadata}" "${session_id}" <<'PYTHON'
import hashlib, json, sys
with open(sys.argv[1], encoding="utf-8") as source: origin=json.load(source)["session_hash"]
raise SystemExit(0 if origin == hashlib.sha256(sys.argv[2].encode("ascii")).hexdigest() else 1)
PYTHON
      then echo "原发起会话不能确认 VLESS 监听迁移。" >&2; return 1; fi
      listener_mark_confirmed || {
        listener_restore automatic_rollback || return 1
        echo "VLESS 监听事务已经到期并回滚，不能再确认。" >&2
        return 1
      }
      if [[ "${SERVER_KIT_TESTING:-0}" == "1" && \
            "${SERVER_KIT_TEST_FAILPOINT:-}" == "vless_listener_confirm_after_commit" ]]; then
        return 97
      fi
      listener_finalize_confirmed
      listener_render
      ;;
    rollback|automatic-rollback)
      if [[ ! -r "${metadata}" ]]; then
        [[ "${operation}" == "automatic-rollback" ]] && return 0
        echo "当前没有待确认的 VLESS 监听事务。" >&2; return 1
      fi
      listener_restore "$([[ "${operation}" == "automatic-rollback" ]] && echo automatic_rollback || echo rolled_back)" || return 1
      [[ "${operation}" == "automatic-rollback" ]] || systemctl stop "${VLESS_LISTENER_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
      listener_render
      ;;
    apply)
      [[ ! -e "${metadata}" ]] || { echo "已有待确认的 VLESS 监听事务。" >&2; return 1; }
      [[ -r "${CONFIG_PATH}" ]] || { echo "未找到配置文件 ${CONFIG_PATH}。" >&2; return 1; }
      candidate="$(mktemp "${CONFIG_DIR}/.vless-public-bind.XXXXXX")"
      trap 'rm -f -- "${candidate:-}"' RETURN
      write_public_any_candidate "${CONFIG_PATH}" "${candidate}" || return 1
      mkdir -p -- "${VLESS_LISTENER_TRANSACTION_DIR}"
      chmod 700 "${VLESS_LISTENER_TRANSACTION_DIR}"
      listener_sync_dir "$(dirname -- "${VLESS_LISTENER_TRANSACTION_DIR}")"
      cp -a -- "${CONFIG_PATH}" "${config_backup}"
      local state_existed=false
      if [[ -r "${PUBLIC_STATE_FILE}" ]]; then cp -a -- "${PUBLIC_STATE_FILE}" "${state_backup}"; state_existed=true; fi
      python3 - "${metadata}" "${state_existed}" "${session_id}" "${VLESS_LISTENER_ROLLBACK_SECONDS}" "${config_backup}" "${state_backup}" <<'PYTHON'
import hashlib, json, os, secrets, stat, sys, time
from datetime import datetime, timezone
path, state_existed, session_id, seconds, config_backup, state_backup=sys.argv[1:]
expires=int(time.time())+int(seconds)
def record(source):
    descriptor=os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode): raise ValueError("备份不是普通文件")
        digest=hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024): digest.update(chunk)
        os.fsync(descriptor)
        return digest.hexdigest(), format(stat.S_IMODE(metadata.st_mode), "04o")
    finally: os.close(descriptor)
config_sha256, config_mode=record(config_backup)
state_present=state_existed == "true"
state_sha256, state_mode=record(state_backup) if state_present else ("", "")
value={"transaction_id":secrets.token_hex(32),"phase":"pending","state_existed":state_present,"session_hash":hashlib.sha256(session_id.encode("ascii")).hexdigest(),"expires_epoch":expires,"expires_at":datetime.fromtimestamp(expires, timezone.utc).isoformat(),"config_sha256":config_sha256,"config_mode":config_mode,"state_sha256":state_sha256,"state_mode":state_mode}
with open(path, "w", encoding="utf-8") as output: json.dump(value, output, separators=(",", ":")); output.write("\n"); output.flush(); os.fsync(output.fileno())
os.chmod(path, 0o600)
directory=os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
try: os.fsync(directory)
finally: os.close(directory)
PYTHON
      rm -f -- "${VLESS_LISTENER_OUTCOME_PATH}"
      listener_sync_dir "$(dirname -- "${VLESS_LISTENER_OUTCOME_PATH}")"
      if ! "${SYSTEMD_RUN_BIN}" --quiet --unit="${VLESS_LISTENER_ROLLBACK_UNIT}" \
          --on-active="${VLESS_LISTENER_ROLLBACK_SECONDS}s" --timer-property=AccuracySec=1s \
          --property=Restart=on-failure --property=RestartSec=10s \
          "${VLESS_LISTENER_MANAGER}" transaction vless_listener automatic-rollback --json; then
        listener_remove_transaction; echo "VLESS 监听自动回滚计时器创建失败。" >&2; return 1
      fi
      if ! install_tested_config "${candidate}" 1 || ! systemctl restart "${SERVICE_NAME}"; then
        listener_restore rolled_back || true
        systemctl stop "${VLESS_LISTENER_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
        echo "VLESS 监听迁移失败，已恢复旧配置。" >&2; return 1
      fi
      load_public_state
      if ! save_public_state "${VLESS_PUBLIC_PORT}" "${VLESS_PUBLIC_UUID}" \
          "${VLESS_PUBLIC_SERVER_NAME}" "${VLESS_PUBLIC_REALITY_KEY}" \
          "${VLESS_PUBLIC_SHORT_ID}" "0.0.0.0"; then
        listener_restore rolled_back || true
        systemctl stop "${VLESS_LISTENER_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
        echo "VLESS 监听状态写入失败，已恢复旧配置。" >&2; return 1
      fi
      rm -f -- "${candidate}"; candidate=""; trap - RETURN
      listener_render
      ;;
    *) echo "VLESS 监听事务动作未登记。" >&2; return 1 ;;
  esac
}

enable_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
}

start_service() {
  systemctl start "${SERVICE_NAME}"
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
}

stop_service() {
  systemctl stop "${SERVICE_NAME}"
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
}

status_service() {
  systemctl --no-pager --full status "${SERVICE_NAME}"
}

get_public_ip() {
  local ip=""
  ip="$(curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  printf '%s\n' "${ip:-<服务器IP>}"
}

get_config_server_address() {
  local listen_address=""
  local stable_endpoint=""

  stable_endpoint="$(python3 "${SCRIPT_DIR}/lib/server_kit_public_endpoint.py" get \
    --config "${SERVER_KIT_DIR}/public-endpoint.json")" || {
      echo "稳定公网入口事实无效，拒绝生成公网 VLESS 客户端配置。" >&2
      return 1
    }
  if [[ -n "${stable_endpoint}" ]]; then
    printf '%s\n' "${stable_endpoint}"
    return
  fi

  listen_address="$(read_config_field "inbounds.0.listen")"
  if [[ "${listen_address}" == "0.0.0.0" ]] || [[ "${listen_address}" == "::" ]]; then
    get_public_ip
  else
    printf '%s\n' "${listen_address}"
  fi
}

read_config_field() {
  local field_path="$1"

  python3 - "${CONFIG_PATH}" "${field_path}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as config_file:
    value = json.load(config_file)

for part in sys.argv[2].split("."):
    if part.isdigit():
        value = value[int(part)]
    else:
        value = value[part]

if isinstance(value, bool):
    print(str(value).lower())
elif value is None:
    print("")
else:
    print(value)
PY
}

read_vless_user_field() {
  local field_name="$1"
  local value=""

  # Xray 26.3.27 只识别入站 clients；较新版本同时兼容 clients 和 users。
  value="$(read_config_field "inbounds.0.settings.clients.0.${field_name}" 2>/dev/null || true)"
  if [[ -z "${value}" ]]; then
    value="$(read_config_field "inbounds.0.settings.users.0.${field_name}" 2>/dev/null || true)"
  fi
  printf '%s\n' "${value}"
}

yaml_quote() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1], ensure_ascii=False))' "$1"
}

install_public_inbound() {
  local port=""
  local uuid=""
  local listen_address=""
  local server_name=""
  local private_key=""
  local public_key=""
  local short_id=""

  install_dependencies
  listen_address="0.0.0.0"

  if [[ "${VLESS_INSTALL_NONINTERACTIVE}" == "1" ]]; then
    port="${VLESS_INSTALL_PORT:-${DEFAULT_PORT}}"
  else
    port="$(prompt_optional "请输入公网 VLESS 端口 [默认 ${DEFAULT_PORT}]: ")"
    port="${port:-${DEFAULT_PORT}}"
  fi
  if ! validate_port "${port}"; then
    echo "端口无效: ${port}" >&2
    return 1
  fi
  port="$((10#${port}))"

  if [[ "${VLESS_INSTALL_NONINTERACTIVE}" == "1" ]]; then
    uuid="$("${XRAY_BIN}" uuid)"
    server_name="${VLESS_INSTALL_SERVER_NAME:-${DEFAULT_SERVER_NAME}}"
    validate_domain "${server_name}" || { echo "REALITY 伪装域名无效。" >&2; return 1; }
    server_name="${server_name,,}"
  else
    uuid="$(prompt_uuid)"
    server_name="$(prompt_server_name)"
  fi
  read -r private_key public_key < <(generate_reality_keypair)
  short_id="$(openssl rand -hex 8)"
  if ! "${XRAY_BIN}" tls ping "${server_name}" >/dev/null 2>&1; then
    echo "警告：无法确认 ${server_name} 的 TLS 可用性；服务仍将继续配置。" >&2
  fi

  write_public_inbound "${uuid}" "${port}" "${listen_address}" \
    "${server_name}" "${private_key}" "${short_id}"
  save_public_state "${port}" "${uuid}" "${server_name}" "${public_key}" \
    "${short_id}" "${listen_address}" "${DEFAULT_RESCUE_PORT}"
  systemctl restart "${SERVICE_NAME}"

  echo
  echo "公网 VLESS REALITY 已启用。"
  echo
  clash_public_config
}

ensure_vless_access_helper() {
  if [[ ! -r "${VLESS_ACCESS_HELPER}" ]]; then
    echo "缺少 VLESS 权限模块：${VLESS_ACCESS_HELPER}" >&2
    return 1
  fi
  command -v python3 >/dev/null 2>&1 || {
    echo "缺少 python3，无法管理 VLESS 客户端权限。" >&2
    return 1
  }
  install -d -m 700 "${SERVER_KIT_DIR}" "$(dirname -- "${VLESS_ACCESS_AUDIT_PATH}")"
}

vless_access_helper() {
  ensure_vless_access_helper
  python3 "${VLESS_ACCESS_HELPER}" \
    --active "${VLESS_ACCESS_PATH}" \
    --pending "${VLESS_ACCESS_PENDING_PATH}" \
    --peer-db "${AWG_PEER_DB}" \
    --awg-state "${AWG_STATE_FILE}" \
    --node-domains "${NODE_DOMAINS_PATH}" \
    "$@"
}

public_ssh_verification_valid() {
  local verified=""
  [[ "${VLESS_SKIP_SSH_GATE}" == "1" ]] && return 0
  [[ -r "${PUBLIC_SSH_VERIFIED_PATH}" ]] || return 1
  verified="$(<"${PUBLIC_SSH_VERIFIED_PATH}")"
  [[ "${verified}" =~ ^[0-9]+$ ]] || return 1
  (( $(date +%s) - verified <= VLESS_SSH_GATE_TTL ))
}

require_public_ssh_verification() {
  public_ssh_verification_valid && return 0
  cat >&2 <<EOF
拒绝应用：尚未完成有效的公网 SSH 双会话验证。
请先在公网 SSH 的第二个会话执行：
  amneziawg-setup.sh public-ssh-challenge
再把该命令输出的验证命令粘贴到第一个会话执行，然后重试 apply。
EOF
  return 1
}

audit_vless_access() {
  if [[ ! -r "${VLESS_ACCESS_AUDIT_PATH}" ]]; then
    echo "暂无 VLESS 权限审计记录：${VLESS_ACCESS_AUDIT_PATH}"
    return 0
  fi
  tail -n 100 "${VLESS_ACCESS_AUDIT_PATH}"
}

record_vless_access_apply() {
  local client_count="0"
  local policy_hash=""
  client_count="$(python3 - "${VLESS_ACCESS_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as policy_file:
    print(len(json.load(policy_file).get("clients", {})))
PYTHON
)"
  policy_hash="$(sha256sum "${VLESS_ACCESS_PATH}" | awk '{print $1}')"
  printf '%s action=apply clients=%s policy_sha256=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${client_count}" "${policy_hash}" \
    >> "${VLESS_ACCESS_AUDIT_PATH}"
  python3 - "${VLESS_ACCESS_AUDIT_PATH}" <<'PYTHON'
import datetime
import os
import sys

path = sys.argv[1]
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=14)
kept = []
with open(path, encoding="utf-8") as source:
    for line in source:
        timestamp = line.split(" ", 1)[0]
        try:
            created = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if created >= cutoff:
            kept.append(line)
temporary = f"{path}.tmp.{os.getpid()}"
with open(temporary, "w", encoding="utf-8", newline="\n") as output:
    output.writelines(kept)
    output.flush()
    os.fsync(output.fileno())
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PYTHON
  chmod 600 "${VLESS_ACCESS_AUDIT_PATH}"
}

activate_xray_candidate() {
  local candidate="$1"
  local backup="$2"
  local restart_service="${3:-1}"
  local service_user=""
  local service_group=""

  "${XRAY_BIN}" run -test -format=json -config "${candidate}" || return 1
  service_user="$(systemctl show "${SERVICE_NAME}.service" -p User --value 2>/dev/null || true)"
  service_user="${service_user:-root}"
  id "${service_user}" >/dev/null 2>&1 || service_user="root"
  service_group="$(id -gn "${service_user}")"
  cp -a -- "${CONFIG_PATH}" "${backup}" || return 1
  if ! install -m 640 -o root -g "${service_group}" "${candidate}" "${CONFIG_PATH}"; then
    cp -a -- "${backup}" "${CONFIG_PATH}" || true
    return 1
  fi

  if [[ "${restart_service}" != "1" ]]; then
    return 0
  fi
  if ! systemctl restart "${SERVICE_NAME}" || ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    cp -a -- "${backup}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" || true
    echo "新配置启动失败，已恢复旧配置：${backup}" >&2
    return 1
  fi
}

apply_vless_access() {
  local candidate=""
  local backup=""

  ensure_vless_access_helper
  [[ -r "${CONFIG_PATH}" ]] || {
    echo "Xray 配置不存在：${CONFIG_PATH}" >&2
    return 1
  }
  [[ -r "${VLESS_ACCESS_PENDING_PATH}" ]] || {
    echo "没有待应用策略。请先执行客户端、兼容模式或访问权限变更。" >&2
    return 1
  }
  require_public_ssh_verification

  candidate="$(mktemp "${CONFIG_DIR}/.vless-access.XXXXXX.json")"
  backup="${CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  trap 'rm -f -- "${candidate}"' RETURN
  vless_access_helper render \
    --config "${CONFIG_PATH}" \
    --output "${candidate}" \
    --public-tag "${PUBLIC_INBOUND_TAG}" \
    --awg-network "${AWG_NETWORK}" >/dev/null
  activate_xray_candidate "${candidate}" "${backup}" "1" || return 1

  if ! vless_access_helper commit; then
    cp -a -- "${backup}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" || true
    echo "无法提交活动策略，已恢复旧 Xray 配置。" >&2
    return 1
  fi
  record_vless_access_apply || echo "警告：服务已生效，但写入权限审计失败。" >&2
  [[ "${VLESS_SKIP_SSH_GATE}" == "1" ]] || rm -f -- "${PUBLIC_SSH_VERIFIED_PATH}"
  rm -f -- "${candidate}"
  trap - RETURN
  echo "VLESS 权限策略已应用，Xray 运行正常。"
  echo "活动策略：${VLESS_ACCESS_PATH}"
  echo "配置备份：${backup}"
}

refresh_vless_domains() {
  local candidate=""
  local backup=""
  local restart_service="0"

  ensure_vless_access_helper
  [[ -r "${CONFIG_PATH}" ]] || {
    echo "Xray 配置不存在：${CONFIG_PATH}" >&2
    return 1
  }
  candidate="$(mktemp "${CONFIG_DIR}/.vless-domains.XXXXXX.json")"
  backup="${CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  trap 'rm -f -- "${candidate}"' RETURN
  vless_access_helper render \
    --active-only \
    --config "${CONFIG_PATH}" \
    --output "${candidate}" \
    --public-tag "${PUBLIC_INBOUND_TAG}" \
    --awg-network "${AWG_NETWORK}" >/dev/null
  systemctl is-active --quiet "${SERVICE_NAME}" && restart_service="1"
  activate_xray_candidate "${candidate}" "${backup}" "${restart_service}" || return 1
  rm -f -- "${candidate}"
  trap - RETURN
  echo "VLESS 内网域名已刷新，Xray 运行正常。"
}

ensure_server_relay_helper() {
  [[ -r "${SERVER_RELAY_HELPER}" ]] || {
    echo "缺少服务端中转模块：${SERVER_RELAY_HELPER}" >&2
    return 1
  }
}

render_server_relay_candidate() {
  local output="$1"
  ensure_server_relay_helper
  [[ -r "${CONFIG_PATH}" ]] || { echo "Xray 配置不存在：${CONFIG_PATH}" >&2; return 1; }
  [[ -r "${CLASH_INPUT_CONFIG}" ]] || { echo "缺少已保存的出口代理配置。" >&2; return 1; }
  python3 "${SERVER_RELAY_HELPER}" render-xray \
    --config "${SERVER_RELAY_CONFIG}" \
    --clash-inputs "${CLASH_INPUT_CONFIG}" \
    --xray "${CONFIG_PATH}" \
    --peer-db "${AWG_PEER_DB}" \
    --vless-policy "${VLESS_ACCESS_PATH}" \
    --public-tag "${PUBLIC_INBOUND_TAG}" \
    --output "${output}"
}

exit_dns_lifecycle() {
  local operation="$1"
  local transaction="$2"
  python3 "${EXIT_DNS_HELPER}" "${operation}" \
    --config "${SERVER_RELAY_CONFIG}" --clash-inputs "${CLASH_INPUT_CONFIG}" \
    --worker-dir "${EXIT_DNS_DIR}" --systemd-dir "${EXIT_DNS_SYSTEMD_DIR}" \
    --transaction "${transaction}" --xray-bin "${XRAY_BIN}" \
    --systemctl-bin "${EXIT_DNS_SYSTEMCTL_BIN}"
}

refresh_server_relay() (
  local candidate=""
  local backup=""
  local dns_transaction=""
  local restart_service="0"
  local dns_committed="0"
  local xray_activated="0"
  [[ -r "${SERVER_RELAY_CONFIG}" ]] || {
    echo "服务端中转尚未启用，无需刷新。"
    return 0
  }
  candidate="$(mktemp "${CONFIG_DIR}/.server-relay.XXXXXX.json")"
  trap '
    if [[ "${dns_committed}" != "1" && -n "${dns_transaction}" ]]; then
      if [[ "${xray_activated}" == "1" && -r "${backup}" ]]; then
        cp -a -- "${backup}" "${CONFIG_PATH}"
        [[ "${restart_service}" != "1" ]] || systemctl restart "${SERVICE_NAME}" || true
      fi
      exit_dns_lifecycle rollback "${dns_transaction}" || true
    fi
    rm -f -- "${candidate}"
  ' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  render_server_relay_candidate "${candidate}" || return 1
  "${XRAY_BIN}" run -test -format=json -config "${candidate}" || return 1
  install -d -m 700 "${EXIT_DNS_TRANSACTION_ROOT}" || return 1
  dns_transaction="$(mktemp -d "${EXIT_DNS_TRANSACTION_ROOT}/change.XXXXXX")" || return 1
  if ! exit_dns_lifecycle prepare "${dns_transaction}"; then
    echo "出口 DNS 配置未通过预检，现有服务未切换。" >&2
    return 1
  fi
  if ! exit_dns_lifecycle apply "${dns_transaction}"; then
    echo "出口 DNS worker 未能就绪，现有 Xray 配置未切换。" >&2
    return 1
  fi
  if cmp -s -- "${candidate}" "${CONFIG_PATH}"; then
    if ! exit_dns_lifecycle commit "${dns_transaction}"; then
      return 1
    fi
    dns_committed="1"
    rm -f -- "${candidate}"
    echo "服务端中转配置已是最新状态。"
    return 0
  fi
  systemctl is-active --quiet "${SERVICE_NAME}" && restart_service="1"
  backup="$(mktemp "${CONFIG_PATH}.bak.XXXXXXXX")" || return 1
  cp -a -- "${CONFIG_PATH}" "${backup}" || return 1
  # Mark rollback before activation: a signal can arrive after install but before
  # activate_xray_candidate returns to this shell.
  xray_activated="1"
  if ! activate_xray_candidate "${candidate}" "${backup}" "${restart_service}"; then
    return 1
  fi
  if ! exit_dns_lifecycle commit "${dns_transaction}"; then
    echo "出口 DNS 事务提交失败，已恢复旧 Xray 配置。" >&2
    return 1
  fi
  dns_committed="1"
  rm -f -- "${candidate}"
  echo "服务端中转出口已同步，Xray 配置校验通过。"
)

configure_server_relay_dns() (
  local relay_backup=""
  local exit_id=""
  local completed="0"
  local -a arguments=(configure-dns --config "${SERVER_RELAY_CONFIG}" --clash-inputs "${CLASH_INPUT_CONFIG}")
  [[ -r "${SERVER_RELAY_CONFIG}" ]] || { echo "请先启用服务端中转。" >&2; return 1; }
  relay_backup="$(mktemp)" || return 1
  cp -a -- "${SERVER_RELAY_CONFIG}" "${relay_backup}" || return 1
  trap '
    [[ "${completed}" == "1" ]] || cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"
    rm -f -- "${relay_backup}"
  ' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  for exit_id in "$@"; do arguments+=(--exit-id "${exit_id}"); done
  if ! python3 "${SERVER_RELAY_HELPER}" "${arguments[@]}" || ! refresh_server_relay; then
    return 1
  fi
  completed="1"
  rm -f -- "${relay_backup}"
  echo "出口一致 DNS 模式已应用。"
)

enable_vless_server_relay() {
  local candidate=""
  local xray_backup=""
  local relay_backup=""
  ensure_server_relay_helper
  [[ -r "${SERVER_RELAY_CONFIG}" ]] || {
    echo "请先启用服务端中转基础配置。" >&2
    return 1
  }
  [[ -r "${CLASH_SERVICE_CONFIG}" ]] || {
    echo "Clash 订阅服务尚未安装。" >&2
    return 1
  }
  relay_backup="$(mktemp)"
  cp -a -- "${SERVER_RELAY_CONFIG}" "${relay_backup}"
  candidate="$(mktemp "${CONFIG_DIR}/.server-relay-vless.XXXXXX.json")"
  xray_backup="${CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  trap 'rm -f -- "${candidate:-}" "${relay_backup:-}"' RETURN

  python3 "${SERVER_RELAY_HELPER}" enable-vless --config "${SERVER_RELAY_CONFIG}" >/dev/null
  if ! render_server_relay_candidate "${candidate}" || \
     ! activate_xray_candidate "${candidate}" "${xray_backup}" "1"; then
    cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"
    return 1
  fi
  if ! bash "${FILE_MANAGER}" refresh-clash >/dev/null; then
    cp -a -- "${xray_backup}" "${CONFIG_PATH}"
    cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    echo "VLESS 转发订阅刷新失败，Xray 和中转配置已恢复。" >&2
    return 1
  fi
  rm -f -- "${candidate}" "${relay_backup}"
  candidate=""
  relay_backup=""
  trap - RETURN
  echo "VLESS 服务端转发已启用：复用 443/2053，每份订阅使用独立 UUID。"
  echo "现有 Shadowsocks 2083 保留，待旧设备验证成功后再关闭。"
}

disable_shadowsocks_server_relay() {
  local candidate=""
  local xray_backup=""
  local relay_backup=""
  local port=""
  local firewall_existed="0"
  ensure_server_relay_helper
  [[ -r "${SERVER_RELAY_CONFIG}" ]] || { echo "服务端中转尚未配置。" >&2; return 1; }
  port="$(python3 - "${SERVER_RELAY_CONFIG}" <<'PYTHON'
import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
port=value.get("port")
if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
    raise SystemExit(1)
print(port)
PYTHON
)" || { echo "无法读取 Shadowsocks 中转端口。" >&2; return 1; }
  if bash "${FIREWALL_MANAGER}" verify-port open "${port}" public both permanent >/dev/null 2>&1; then
    firewall_existed="1"
  fi
  relay_backup="$(mktemp)"
  cp -a -- "${SERVER_RELAY_CONFIG}" "${relay_backup}"
  candidate="$(mktemp "${CONFIG_DIR}/.server-relay-disable.XXXXXX.json")"
  xray_backup="${CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  trap 'rm -f -- "${candidate:-}" "${relay_backup:-}"' RETURN

  python3 "${SERVER_RELAY_HELPER}" disable-shadowsocks --config "${SERVER_RELAY_CONFIG}" >/dev/null
  if ! render_server_relay_candidate "${candidate}" || \
     ! activate_xray_candidate "${candidate}" "${xray_backup}" "1"; then
    cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"
    return 1
  fi
  if ! bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null || \
     ! bash "${FIREWALL_MANAGER}" close-port "${port}" public both --yes >/dev/null; then
    cp -a -- "${xray_backup}" "${CONFIG_PATH}"
    cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    [[ "${firewall_existed}" == "1" ]] && bash "${FIREWALL_MANAGER}" open-port "${port}" public both permanent --yes >/dev/null 2>&1 || true
    bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null 2>&1 || true
    echo "2083 入站或防火墙撤销失败，原配置已恢复。" >&2
    return 1
  fi
  if ! bash "${FILE_MANAGER}" refresh-clash >/dev/null; then
    cp -a -- "${xray_backup}" "${CONFIG_PATH}"
    cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    [[ "${firewall_existed}" == "1" ]] && bash "${FIREWALL_MANAGER}" open-port "${port}" public both permanent --yes >/dev/null 2>&1 || true
    bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null 2>&1 || true
    echo "订阅移除 Shadowsocks 节点失败，原配置已恢复。" >&2
    return 1
  fi
  rm -f -- "${candidate}" "${relay_backup}"
  candidate=""
  relay_backup=""
  trap - RETURN
  echo "Shadowsocks 服务端中转已删除：Xray 不再监听 ${port}，防火墙和订阅已同步撤销。"
}

enable_server_relay() {
  local port="${1:-2083}"
  local candidate=""
  local xray_backup=""
  local relay_backup=""
  local relay_existed="0"
  local firewall_existed="0"
  local subscriptions_refreshed="0"
  validate_port "${port}" || { echo "服务端中转端口无效：${port}" >&2; return 1; }
  port="$((10#${port}))"
  ensure_server_relay_helper
  [[ -r "${CLASH_INPUT_CONFIG}" ]] || { echo "缺少已保存的出口代理配置。" >&2; return 1; }
  [[ -r "${CONFIG_PATH}" ]] || { echo "Xray 配置不存在：${CONFIG_PATH}" >&2; return 1; }

  if [[ ! -r "${SERVER_RELAY_CONFIG}" ]] && ss -H -lntu 2>/dev/null | \
      awk -v wanted=":${port}" '$5 ~ (wanted "$") {found=1} END {exit !found}'; then
    echo "端口 ${port} 已被其他服务监听。" >&2
    return 1
  fi
  relay_backup="$(mktemp)"
  if [[ -r "${SERVER_RELAY_CONFIG}" ]]; then
    cp -a -- "${SERVER_RELAY_CONFIG}" "${relay_backup}"
    relay_existed="1"
  fi
  if bash "${FIREWALL_MANAGER}" verify-port open "${port}" public both permanent >/dev/null 2>&1; then
    firewall_existed="1"
  fi
  candidate="$(mktemp "${CONFIG_DIR}/.server-relay.XXXXXX.json")"
  xray_backup="${CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
  trap 'rm -f -- "${candidate:-}" "${relay_backup:-}"' RETURN

  python3 "${SERVER_RELAY_HELPER}" init --config "${SERVER_RELAY_CONFIG}" --port "${port}" >/dev/null
  if ! render_server_relay_candidate "${candidate}" || \
     ! activate_xray_candidate "${candidate}" "${xray_backup}" "1"; then
    if [[ "${relay_existed}" == "1" ]]; then cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"; else rm -f -- "${SERVER_RELAY_CONFIG}"; fi
    return 1
  fi
  if ! bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null; then
    cp -a -- "${xray_backup}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    if [[ "${relay_existed}" == "1" ]]; then cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"; else rm -f -- "${SERVER_RELAY_CONFIG}"; fi
    bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null 2>&1 || true
    echo "中转端口事实刷新失败，Xray 和中转配置已恢复。" >&2
    return 1
  fi
  if ! bash "${FIREWALL_MANAGER}" open-port "${port}" public both permanent --yes >/dev/null; then
    cp -a -- "${xray_backup}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null 2>&1 || true
    if [[ "${relay_existed}" == "1" ]]; then cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"; else rm -f -- "${SERVER_RELAY_CONFIG}"; fi
    echo "中转端口防火墙放行失败，Xray 和中转配置已恢复。" >&2
    return 1
  fi
  if [[ -r "${CLASH_SERVICE_CONFIG}" ]]; then
    if ! bash "${FILE_MANAGER}" refresh-clash >/dev/null; then
      cp -a -- "${xray_backup}" "${CONFIG_PATH}"
      systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
      bash "${SECURITY_MANAGER}" refresh-ports --quiet >/dev/null 2>&1 || true
      [[ "${firewall_existed}" == "1" ]] || bash "${FIREWALL_MANAGER}" close-port "${port}" public both --yes >/dev/null 2>&1 || true
      if [[ "${relay_existed}" == "1" ]]; then cp -a -- "${relay_backup}" "${SERVER_RELAY_CONFIG}"; else rm -f -- "${SERVER_RELAY_CONFIG}"; fi
      echo "订阅刷新失败，Xray、中转配置和新增防火墙规则已恢复。" >&2
      return 1
    fi
    subscriptions_refreshed="1"
  fi
  rm -f -- "${candidate}" "${relay_backup}"
  candidate=""
  relay_backup=""
  trap - RETURN
  echo "服务端中转已启用：TCP/UDP ${port}，全部订阅已加入 SERVER.RELAY。"
  [[ "${subscriptions_refreshed}" == "1" ]] || echo "Clash 订阅服务尚未安装；安装后会自动包含该节点。"
}

list_network_nodes() {
  local name=""
  local ip=""
  local count=0
  echo "=== 普通 AmneziaWG 节点（双向互访）==="
  if [[ -s "${AWG_PEER_DB}" ]]; then
    while IFS=$'\t' read -r name ip; do
      [[ -n "${name}" ]] || continue
      printf '%-24s %-15s %s\n' "${name}" "${ip}" "普通节点"
      count=$((count + 1))
    done < "${AWG_PEER_DB}"
  fi
  (( count > 0 )) || echo "暂无普通节点。"

  echo
  echo "=== VLESS 节点（无固定内网 IP，仅能发起访问）==="
  vless_access_helper list
  echo
  echo "说明：普通节点可双向互访；VLESS 节点只能访问明确放行的目标。"
}

usage() {
  cat <<'EOF'
用法:
  bash debian_vless_manager.sh install      安装或更新公网 VLESS REALITY
  bash debian_vless_manager.sh set-public-sni [域名] 修改公网 REALITY 伪装站，不重置密钥
  bash debian_vless_manager.sh listener-status       查看一次性公网监听迁移事务
  bash debian_vless_manager.sh start        启动服务
  bash debian_vless_manager.sh stop         停止服务
  bash debian_vless_manager.sh restart      重启服务
  bash debian_vless_manager.sh status       查看服务状态
  bash debian_vless_manager.sh info         查看当前配置信息
  bash debian_vless_manager.sh clash [name] 输出公网 REALITY 节点配置
  bash debian_vless_manager.sh enable-rescue 启用公网 REALITY 救援端口 2053
  bash debian_vless_manager.sh relay-enable [端口] 启用服务端 Shadowsocks 中转（默认 2083）
  bash debian_vless_manager.sh relay-refresh       按当前 SOCKS5 出口刷新中转
  bash debian_vless_manager.sh relay-dns [出口ID...] 启用所选出口一致 DNS；不传 ID 则关闭
  bash debian_vless_manager.sh relay-vless-enable  在现有 REALITY 入站增加独立转发身份
  bash debian_vless_manager.sh relay-shadowsocks-disable 删除 Shadowsocks 入站及防火墙规则
  bash debian_vless_manager.sh client-add <名称> [UUID] 新建独立 VLESS 客户端
  bash debian_vless_manager.sh client-remove <名称>     删除 VLESS 客户端
  bash debian_vless_manager.sh client-enable <名称>     启用 VLESS 客户端
  bash debian_vless_manager.sh client-disable <名称>    禁用 VLESS 客户端
  bash debian_vless_manager.sh client-compat-enable <名称>  启用旧版 Stash 订阅语法
  bash debian_vless_manager.sh client-compat-disable <名称> 关闭旧版 Stash 订阅语法
  bash debian_vless_manager.sh client-list              查看客户端及内网权限
  bash debian_vless_manager.sh nodes                    查看全部 AWG/VLESS 节点
  bash debian_vless_manager.sh client-show <名称> [--reveal] 查看单个客户端
  bash debian_vless_manager.sh allow <客户端> <节点|all> [端口列表] [tcp|udp|tcp,udp]
  bash debian_vless_manager.sh deny <客户端> <节点|all>  删除内网放行
  bash debian_vless_manager.sh plan                      预览待应用变化
  bash debian_vless_manager.sh apply                     校验、应用并失败回滚
  bash debian_vless_manager.sh refresh-domains           同步节点域名到 Xray DNS
  bash debian_vless_manager.sh access-audit              查看权限应用审计

说明:
  1. install 会通过 XTLS 官方安装脚本自动安装 Xray-core。
  2. VLESS 固定使用公网 REALITY 入站，不再维护旧内网无加密入站。
  3. 配置文件位于 /usr/local/etc/xray/config.json。
  4. 权限修改先写入待应用文件；apply 前必须完成公网 SSH 双会话验证。
  5. 节点名 all 表示全部内网节点；省略端口表示全部端口；vps 表示 AWG 服务端。
  6. 其他节点名称读取 /etc/amneziawg/peers.tsv。
  7. 新安装默认监听 0.0.0.0；旧安装通过 server-kit 回滚任务完成一次性监听迁移。
EOF
}

read_public_inbound() {
  python3 - "${CONFIG_PATH}" "${PUBLIC_INBOUND_TAG}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as config_file:
    config = json.load(config_file)
for inbound in config.get("inbounds", []):
    if inbound.get("tag") == sys.argv[2]:
        reality = inbound["streamSettings"]["realitySettings"]
        client = inbound["settings"]["clients"][0]
        print(inbound["listen"])
        print(inbound["port"])
        print(client["id"])
        print(reality["serverNames"][0])
        print(reality["shortIds"][0])
        raise SystemExit(0)
raise SystemExit("未找到公网 VLESS 入站，请先执行 install")
PYTHON
}

clash_public_config() {
  local node_name="${1:-}"
  local values=()
  local server_ip=""
  local port=""
  local uuid=""
  local server_name=""
  local short_id=""
  local public_key=""
  local rescue_port=""

  mapfile -t values < <(read_public_inbound)
  server_ip="$(get_config_server_address)"
  port="${values[1]%$'\r'}"
  uuid="${values[2]%$'\r'}"
  server_name="${values[3]%$'\r'}"
  short_id="${values[4]%$'\r'}"
  load_public_state
  public_key="${VLESS_PUBLIC_REALITY_KEY:-}"
  rescue_port="${VLESS_PUBLIC_RESCUE_PORT:-${DEFAULT_RESCUE_PORT}}"
  if [[ -z "${public_key}" ]]; then
    echo "缺少公网 REALITY 公钥状态，请重新执行 install。" >&2
    return 1
  fi
  node_name="${node_name:-vless-public-${server_ip}}"

  cat <<EOF
# ============================================================
# 公网 VLESS REALITY 主节点、救援节点与自动回退组
# ============================================================
proxies:
  - name: $(yaml_quote "${node_name}.443")
    type: vless
    server: $(yaml_quote "${server_ip}")
    port: ${port}
    uuid: $(yaml_quote "${uuid}")
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: $(yaml_quote "${server_name}")
    client-fingerprint: chrome
    reality-opts:
      public-key: $(yaml_quote "${public_key}")
      short-id: $(yaml_quote "${short_id}")
    packet-encoding: xudp
  - name: $(yaml_quote "${node_name}.${rescue_port}")
    type: vless
    server: $(yaml_quote "${server_ip}")
    port: ${rescue_port}
    uuid: $(yaml_quote "${uuid}")
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: $(yaml_quote "${server_name}")
    client-fingerprint: chrome
    reality-opts:
      public-key: $(yaml_quote "${public_key}")
      short-id: $(yaml_quote "${short_id}")
    packet-encoding: xudp
proxy-groups:
  - name: MID
    type: fallback
    proxies:
      - $(yaml_quote "${node_name}.443")
      - $(yaml_quote "${node_name}.${rescue_port}")
    url: https://www.gstatic.com/generate_204
    interval: 300
    lazy: true
# ============================================================
EOF
}

info_public_service() {
  local values=()
  mapfile -t values < <(read_public_inbound)
  echo "=== 公网 VLESS REALITY ==="
  echo "监听地址: ${values[0]}"
  echo "端口: ${values[1]}"
  load_public_state
  echo "救援端口: ${VLESS_PUBLIC_RESCUE_PORT:-${DEFAULT_RESCUE_PORT}}"
  echo "服务器名称（SNI）: ${values[3]}"
  echo "入站标签: ${PUBLIC_INBOUND_TAG}"
  echo "配置文件: ${CONFIG_PATH}"
  echo
  status_service
}

info_service() {
  if [[ ! -r "${CONFIG_PATH}" ]]; then
    echo "未找到配置文件 ${CONFIG_PATH}，请先执行 install。"
    exit 1
  fi

  local server_ip=""
  local port=""
  local method=""
  local security=""
  local flow=""
  local listen_address=""
  local server_name=""
  local target=""

  server_ip="$(get_config_server_address)"
  port="$(read_config_field "inbounds.0.port")"
  listen_address="$(read_config_field "inbounds.0.listen")"
  method="$(read_config_field "inbounds.0.streamSettings.method")"
  security="$(read_config_field "inbounds.0.streamSettings.security")"
  flow="$(read_vless_user_field "flow")"
  if [[ "${security}" == "reality" ]]; then
    server_name="$(read_config_field "inbounds.0.streamSettings.realitySettings.serverNames.0")"
    target="$(read_config_field "inbounds.0.streamSettings.realitySettings.target")"
  fi

  echo "=== VLESS 当前配置 ==="
  echo "服务器地址: ${server_ip}"
  echo "监听地址: ${listen_address}"
  echo "端口: ${port}"
  echo "传输方式: ${method}"
  echo "流控: ${flow:-无}"
  echo "传输安全: ${security}"
  if [[ "${security}" == "reality" ]]; then
    echo "服务器名称（SNI）: ${server_name}"
    echo "REALITY 目标: ${target}"
  else
    echo "警告：当前入站不是受支持的 REALITY 模式"
  fi
  echo "配置文件: ${CONFIG_PATH}"
  echo
  status_service
}

main() {
  require_root
  check_debian

  local action="${1:-}"
  case "${action}" in
    install)
      install_public_inbound
      ;;
    set-public-sni)
      set_public_server_name "${2:-}"
      ;;
    enable-rescue)
      [[ $# -eq 1 ]] || { echo "enable-rescue 不接受额外参数。" >&2; exit 1; }
      enable_rescue_inbound "${DEFAULT_RESCUE_PORT}"
      ;;
    relay-enable)
      [[ $# -le 2 ]] || { echo "relay-enable 最多接受一个端口参数。" >&2; exit 1; }
      enable_server_relay "${2:-2083}"
      ;;
    relay-refresh)
      [[ $# -eq 1 ]] || { echo "relay-refresh 不接受额外参数。" >&2; exit 1; }
      refresh_server_relay
      ;;
    relay-dns)
      shift
      configure_server_relay_dns "$@"
      ;;
    relay-vless-enable)
      [[ $# -eq 1 ]] || { echo "relay-vless-enable 不接受额外参数。" >&2; exit 1; }
      enable_vless_server_relay
      ;;
    relay-shadowsocks-disable)
      [[ $# -eq 1 ]] || { echo "relay-shadowsocks-disable 不接受额外参数。" >&2; exit 1; }
      disable_shadowsocks_server_relay
      ;;
    listener-status|listener-preview|listener-apply|listener-confirm|listener-rollback)
      vless_listener_transaction "${action#listener-}"
      ;;
    listener-automatic-rollback)
      [[ $# -eq 1 ]] || { echo "自动回滚参数不正确。" >&2; exit 1; }
      if [[ -t 0 ]] || IFS= read -r -t 0.1 _; then
        echo "自动回滚不接受交互输入。" >&2
        exit 1
      fi
      vless_listener_transaction automatic-rollback
      ;;
    start)
      start_service
      ;;
    stop)
      stop_service
      ;;
    restart)
      systemctl restart "${SERVICE_NAME}"
      status_service
      ;;
    status)
      status_service
      ;;
    info)
      info_service
      ;;
    clash)
      clash_public_config "${2:-}"
      ;;
    client-add)
      [[ -n "${2:-}" ]] || { echo "请提供客户端名称。" >&2; exit 1; }
      if [[ -n "${3:-}" ]]; then
        vless_access_helper client-add "${2}" --uuid "${3}"
      else
        vless_access_helper client-add "${2}"
      fi
      ;;
    client-remove)
      [[ -n "${2:-}" ]] || { echo "请提供客户端名称。" >&2; exit 1; }
      vless_access_helper client-remove "${2}"
      ;;
    client-enable|client-disable|client-compat-enable|client-compat-disable)
      [[ -n "${2:-}" ]] || { echo "请提供客户端名称。" >&2; exit 1; }
      vless_access_helper "${1}" "${2}"
      ;;
    client-list)
      vless_access_helper list
      ;;
    nodes)
      list_network_nodes
      ;;
    client-show)
      [[ -n "${2:-}" ]] || { echo "请提供客户端名称。" >&2; exit 1; }
      if [[ "${3:-}" == "--reveal" ]]; then
        vless_access_helper show "${2}" --reveal
      else
        vless_access_helper show "${2}"
      fi
      ;;
    allow)
      [[ -n "${2:-}" && -n "${3:-}" ]] || {
        echo "用法：$0 allow <客户端> <节点|all> [端口列表]" >&2
        exit 1
      }
      vless_access_helper allow "${2}" "${3}" "${4:-}" "${5:-tcp}"
      ;;
    deny)
      [[ -n "${2:-}" && -n "${3:-}" ]] || {
        echo "用法：$0 deny <客户端> <节点> [端口列表] [all|tcp|udp]" >&2
        exit 1
      }
      if [[ -n "${4:-}" || -n "${5:-}" ]]; then
        vless_access_helper deny "${2}" "${3}" "${4:-}" "${5:-}"
      else
        vless_access_helper deny "${2}" "${3}"
      fi
      ;;
    plan)
      vless_access_helper plan
      ;;
    apply)
      apply_vless_access
      ;;
    refresh-domains)
      refresh_vless_domains
      ;;
    access-audit)
      audit_vless_access
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
