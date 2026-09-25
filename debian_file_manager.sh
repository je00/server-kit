#!/usr/bin/env bash

set -euo pipefail

FILE_SERVICE_NAME="secure-file-service"
CLASH_SERVICE_NAME="secure-clash-service"
SERVICE_USER="secure-file"
SERVICE_GROUP="secure-file"
CONFIG_DIR="${CONFIG_DIR:-/etc/secure-file-service}"
FILE_CONFIG_PATH="${FILE_CONFIG_PATH:-${CONFIG_DIR}/config.json}"
CLASH_CONFIG_PATH="${CLASH_CONFIG_PATH:-${CONFIG_DIR}/clash-config.json}"
CERT_PATH="${CERT_PATH:-${CONFIG_DIR}/server.crt}"
KEY_PATH="${KEY_PATH:-${CONFIG_DIR}/server.key}"
CERT_IP_PATH="${CERT_IP_PATH:-${CONFIG_DIR}/certificate-ip}"
DATA_DIR="${DATA_DIR:-/var/lib/secure-file-service}"
PAYLOAD_PATH="${DATA_DIR}/shared-file.yaml"
CLASH_PAYLOAD_DIR="${DATA_DIR}/clash-subscriptions"
CLASH_BACKUP_DIR="${DATA_DIR}/clash-subscription-backups"
AMNEZIAWG_DIR="${AMNEZIAWG_DIR:-/etc/amneziawg}"
AMNEZIAWG_PEER_DB="${AMNEZIAWG_DIR}/peers.tsv"
AMNEZIAWG_STATE_FILE="${AMNEZIAWG_DIR}/manager.conf"
SERVER_KIT_CONFIG_DIR="${SERVER_KIT_CONFIG_DIR:-/etc/server-kit}"
PUBLIC_ENDPOINT_CONFIG="${PUBLIC_ENDPOINT_CONFIG:-${SERVER_KIT_CONFIG_DIR}/public-endpoint.json}"
CLASH_INPUT_CONFIG="${SERVER_KIT_CONFIG_DIR}/clash-inputs.json"
SERVER_RELAY_CONFIG="${SERVER_RELAY_CONFIG:-${SERVER_KIT_CONFIG_DIR}/server-relay.json}"
CLASH_PUBLICATION_STATE="${CLASH_PUBLICATION_STATE:-${SERVER_KIT_CONFIG_DIR}/clash-publications.json}"
NODE_DOMAINS_PATH="${NODE_DOMAINS_PATH:-${SERVER_KIT_CONFIG_DIR}/node-domains.json}"
VLESS_ACCESS_PATH="${VLESS_ACCESS_PATH:-${SERVER_KIT_CONFIG_DIR}/vless-access.json}"
XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-/usr/local/etc/xray/config.json}"
XRAY_STATE_FILE="${XRAY_STATE_FILE:-/etc/default/vless-manager}"
XRAY_PUBLIC_STATE_FILE="${XRAY_PUBLIC_STATE_FILE:-/etc/default/vless-manager-public}"
XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
SERVER_DIR="/usr/local/lib/secure-file-service"
SERVER_PATH="${SERVER_DIR}/server.py"
CERTBOT_VENV="/opt/secure-file-certbot"
CERTBOT_BIN=""
CERT_RENEW_SCRIPT="${SERVER_DIR}/renew-certificate.sh"
CERT_DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/${FILE_SERVICE_NAME}"
FILE_SERVICE_PATH="/etc/systemd/system/${FILE_SERVICE_NAME}.service"
CLASH_SERVICE_PATH="/etc/systemd/system/${CLASH_SERVICE_NAME}.service"
CERT_RENEW_SERVICE_PATH="/etc/systemd/system/secure-file-cert-renew.service"
CERT_RENEW_TIMER_PATH="/etc/systemd/system/secure-file-cert-renew.timer"
DEFAULT_FILE_PORT="8443"
DEFAULT_CLASH_PORT="8444"
CLASH_INSTALL_NONINTERACTIVE="${CLASH_INSTALL_NONINTERACTIVE:-0}"
CLASH_INSTALL_PORT="${CLASH_INSTALL_PORT:-}"
FILE_INSTALL_NONINTERACTIVE="${FILE_INSTALL_NONINTERACTIVE:-0}"
FILE_INSTALL_PORT="${FILE_INSTALL_PORT:-}"
SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_PATH}" ]]; do
  SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
  SCRIPT_PATH="$(readlink -- "${SCRIPT_PATH}")"
  [[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="${SCRIPT_LINK_DIR}/${SCRIPT_PATH}"
done
SCRIPT_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
DEFAULT_SOURCE_FILE="${SCRIPT_DIR}/shared_file.yaml"
DEFAULT_CLASH_SOURCE_FILE="${SCRIPT_DIR}/clash_skeleton.yaml"
CLASH_BUNDLE_HELPER="${CLASH_BUNDLE_HELPER:-${SCRIPT_DIR}/lib/clash_bundle.py}"
PUBLIC_ENDPOINT_HELPER="${PUBLIC_ENDPOINT_HELPER:-${SCRIPT_DIR}/lib/server_kit_public_endpoint.py}"
FIREWALL_MANAGER="${FIREWALL_MANAGER:-${SCRIPT_DIR}/debian_firewall_manager.sh}"
VLESS_MANAGER="${VLESS_MANAGER:-${SCRIPT_DIR}/debian_vless_manager.sh}"

# 默认选择普通文件服务，main 会按命令切换到对应的独立服务配置。
SERVICE_NAME="${FILE_SERVICE_NAME}"
SERVICE_PATH="${FILE_SERVICE_PATH}"
CONFIG_PATH="${FILE_CONFIG_PATH}"
DEFAULT_PORT="${DEFAULT_FILE_PORT}"
SERVICE_DESCRIPTION="轻量安全文件下载服务"
INSTALL_COMMAND="install"

use_file_service() {
  SERVICE_NAME="${FILE_SERVICE_NAME}"
  SERVICE_PATH="${FILE_SERVICE_PATH}"
  CONFIG_PATH="${FILE_CONFIG_PATH}"
  DEFAULT_PORT="${DEFAULT_FILE_PORT}"
  SERVICE_DESCRIPTION="轻量安全文件下载服务"
  INSTALL_COMMAND="install"
}

use_clash_service() {
  SERVICE_NAME="${CLASH_SERVICE_NAME}"
  SERVICE_PATH="${CLASH_SERVICE_PATH}"
  CONFIG_PATH="${CLASH_CONFIG_PATH}"
  DEFAULT_PORT="${DEFAULT_CLASH_PORT}"
  SERVICE_DESCRIPTION="Clash 个性化订阅下载服务"
  INSTALL_COMMAND="install-clash"
}

sync_server_relay_if_configured() {
  [[ -r "${SERVER_RELAY_CONFIG}" ]] || return 0
  [[ -r "${VLESS_MANAGER}" ]] || {
    echo "缺少 VLESS 管理器，无法同步服务端转发身份。" >&2
    return 1
  }
  bash "${VLESS_MANAGER}" relay-refresh >/dev/null
}

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

prompt_secret() {
  local prompt_text="$1"
  local value=""

  if [[ -t 0 ]]; then
    read -r -s -p "${prompt_text}" value
    echo >&2
  else
    read -r -p "${prompt_text}" value
  fi
  printf '%s\n' "${value}"
}

validate_port() {
  local port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] && (( ${#port} <= 5 )) &&
    (( 10#${port} >= 1 && 10#${port} <= 65535 ))
}

validate_token() {
  local token="$1"
  [[ "${token}" =~ ^[0-9a-f]{64}$ ]]
}

validate_download_name() {
  local name="$1"
  [[ -n "${name}" ]] && [[ "${name}" != "." ]] && [[ "${name}" != ".." ]] &&
    [[ "${name}" != */* ]] && [[ "${name}" != *$'\n'* ]] && [[ "${name}" != *$'\r'* ]] &&
    (( ${#name} <= 255 ))
}

resolve_source_file() {
  local requested_path="${1:-${DEFAULT_SOURCE_FILE}}"
  local resolved_path=""

  if [[ ! -f "${requested_path}" ]]; then
    echo "未找到要发布的文件: ${requested_path}" >&2
    if [[ "${requested_path}" == "${DEFAULT_SOURCE_FILE}" ]]; then
      echo "请把默认文件放到脚本同目录并命名为 shared_file.yaml，或把文件路径作为命令的第二个参数。" >&2
    elif [[ "${requested_path}" == "${DEFAULT_CLASH_SOURCE_FILE}" ]]; then
      echo "请把 Clash 骨架放到脚本同目录并命名为 clash_skeleton.yaml，或把文件路径作为命令的第二个参数。" >&2
    fi
    return 1
  fi

  resolved_path="$(realpath -e -- "${requested_path}")"
  if [[ ! -r "${resolved_path}" ]]; then
    echo "文件不可读: ${resolved_path}" >&2
    return 1
  fi

  printf '%s\n' "${resolved_path}"
}

validate_http_url() {
  python3 - "$1" <<'PYTHON'
import sys
from urllib.parse import urlsplit

try:
    parsed = urlsplit(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if parsed.scheme in {"http", "https"} and parsed.netloc else 1)
PYTHON
}

validate_server_name_or_ip() {
  local value="$1"
  [[ -n "${value}" ]] && [[ "${value}" != *[[:space:]/]* ]] &&
    [[ "${value}" != "<server_ip>" ]]
}

read_clash_input_field() {
  local field_name="$1"

  if [[ ! -r "${CLASH_INPUT_CONFIG}" ]]; then
    return 1
  fi
  python3 - "${CLASH_INPUT_CONFIG}" "${field_name}" "${SCRIPT_DIR}" <<'PYTHON'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from lib.server_kit_proxy_resources import default_exit_proxy, normalized_config

config = normalized_config(Path(sys.argv[1]))

if sys.argv[2] == "airport_url":
    airports = config.get("airports", [])
    value = airports[0].get("url", "") if airports else ""
elif sys.argv[2] == "exit_summary":
    try:
        proxy = default_exit_proxy(config)
    except Exception:
        value = ""
    else:
        proxy_type = proxy.get("type", "socks5" if proxy.get("server") else "")
        server = proxy.get("server", "")
        port = proxy.get("port", "")
        value = f"{proxy_type} {server}:{port}" if proxy_type and server and port else ""
else:
    try:
        value = default_exit_proxy(config).get(sys.argv[2], "")
    except Exception:
        value = ""
print(value)
PYTHON
}

save_clash_inputs() {
  local airport_url="$1"
  local exit_proxy_text="$2"
  local temp_config=""
  local temp_proxy=""
  local parse_status=0

  install -d -m 700 "${SERVER_KIT_CONFIG_DIR}"
  temp_config="$(mktemp "${SERVER_KIT_CONFIG_DIR}/.clash-inputs.XXXXXX")"
  temp_proxy="$(mktemp "${SERVER_KIT_CONFIG_DIR}/.exit-proxy.XXXXXX")"
  chmod 600 "${temp_proxy}"
  printf '%s' "${exit_proxy_text}" > "${temp_proxy}"
  trap 'rm -f -- "${temp_config}" "${temp_proxy}"' RETURN
  python3 - "${temp_config}" "${CLASH_INPUT_CONFIG}" "${airport_url}" \
    "${temp_proxy}" "${SCRIPT_DIR}" <<'PYTHON' || parse_status=$?
import json
import shutil
import subprocess
import sys
from pathlib import Path

path, existing_path, airport_url, proxy_text_path, script_dir = sys.argv[1:]
if Path(existing_path).is_file():
    shutil.copy2(existing_path, path)
payload = {
    "airport_url": airport_url,
    "exit_proxy_yaml": Path(proxy_text_path).read_text(encoding="utf-8"),
}
result = subprocess.run(
    [sys.executable, str(Path(script_dir) / "lib/server_kit_proxy_resources.py"), "update", path],
    input=json.dumps(payload, ensure_ascii=False), text=True,
    stdout=subprocess.DEVNULL,
)
raise SystemExit(result.returncode)
PYTHON
  if [[ "${parse_status}" -ne 0 ]]; then
    rm -f -- "${temp_config}" "${temp_proxy}"
    trap - RETURN
    return "${parse_status}"
  fi
  install -m 600 -o root -g root "${temp_config}" "${CLASH_INPUT_CONFIG}"
  rm -f -- "${temp_config}" "${temp_proxy}"
  trap - RETURN
}

configure_clash_inputs() {
  local airport_url=""
  local exit_summary=""
  local exit_proxy_text=""
  local first_line=""
  local line=""
  local value=""

  airport_url="$(read_clash_input_field airport_url 2>/dev/null || true)"
  exit_summary="$(read_clash_input_field exit_summary 2>/dev/null || true)"

  if [[ "${CLASH_INSTALL_NONINTERACTIVE}" == "1" ]]; then
    validate_http_url "${airport_url}" || { echo "缺少有效的已保存机场订阅。" >&2; return 1; }
    [[ -n "${exit_summary}" ]] || { echo "缺少有效的已保存出口节点。" >&2; return 1; }
    echo "已读取网页保存的机场和出口配置。"
    return 0
  fi

  echo
  echo "=== Clash 上游参数 ==="
  echo "这些参数会保存到 ${CLASH_INPUT_CONFIG}（权限 600），不会写入 Git 仓库。"
  while true; do
    if [[ -n "${airport_url}" ]]; then
      value="$(prompt_optional "机场订阅链接 [已保存，直接回车沿用；输入新链接替换]: ")"
      airport_url="${value:-${airport_url}}"
    else
      airport_url="$(prompt_optional "请输入机场订阅链接（http/https，必填）: ")"
    fi
    validate_http_url "${airport_url}" && break
    echo "机场订阅链接无效，请输入完整的 http:// 或 https:// 链接。" >&2
  done

  echo
  echo "出口节点支持 Mihomo 的 SOCKS5、HTTP、SS、VMess、VLESS、Trojan、Hysteria2、TUIC 等类型。"
  echo "请粘贴单个 Clash/Mihomo 节点 YAML；首个节点会保存为“默认出口”。"
  echo "粘贴完成后单独输入一行 END；中转 VLESS 将从当前 Xray 自动读取。"
  while true; do
    if [[ -n "${exit_summary}" ]]; then
      read -r -p "出口节点 [已保存 ${exit_summary}；回车沿用，或直接粘贴第一行]: " first_line
    else
      read -r -p "请粘贴出口节点第一行: " first_line
    fi
    exit_proxy_text=""
    if [[ -n "${first_line}" ]]; then
      exit_proxy_text="${first_line}"
      while IFS= read -r line; do
        [[ "${line}" == "END" ]] && break
        exit_proxy_text+=$'\n'"${line}"
      done
    elif [[ -z "${exit_summary}" ]]; then
      echo "尚未保存出口节点，请粘贴节点内容。" >&2
      continue
    fi
    if save_clash_inputs "${airport_url}" "${exit_proxy_text}"; then
      break
    fi
    echo "出口节点无效，请重新粘贴。" >&2
  done
  echo "上游参数已保存。"
}

render_clash_skeleton() {
  local skeleton_path="$1"
  local output_path="$2"
  local summary_path="$3"

  python3 - "${skeleton_path}" "${output_path}" "${summary_path}" \
    "${CLASH_INPUT_CONFIG}" "${XRAY_CONFIG_PATH}" "${XRAY_STATE_FILE}" \
    "${XRAY_PUBLIC_STATE_FILE}" "${AMNEZIAWG_STATE_FILE}" "${XRAY_BIN}" "${SCRIPT_DIR}" <<'PYTHON'
import copy
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent


(
    skeleton_path,
    output_path,
    summary_path,
    input_path,
    xray_path,
    xray_state_path,
    xray_public_state_path,
    amneziawg_state_path,
    xray_bin,
    script_dir,
) = sys.argv[1:]

sys.path.insert(0, script_dir)
from lib.clash_airport_projection import apply_airport_projection
from lib.server_kit_proxy_resources import ProxyResourceError, normalized_config


def fail(message):
    raise SystemExit(message)


def load_json(path, description):
    try:
        with open(path, "r", encoding="utf-8") as source_file:
            value = json.load(source_file)
    except FileNotFoundError:
        fail(f"未找到{description}: {path}")
    except (OSError, ValueError) as error:
        fail(f"无法读取{description} {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{description}必须是 JSON 对象: {path}")
    return value


def load_shell_assignments(path):
    """只解析简单赋值，不执行配置文件。"""
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as state_file:
            lines = state_file.readlines()
    except FileNotFoundError:
        return values
    except OSError as error:
        fail(f"无法读取状态文件 {path}: {error}")

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        try:
            parts = shlex.split(raw_value, posix=True)
        except ValueError:
            continue
        values[key] = parts[0] if len(parts) == 1 else raw_value
    return values


def find_named_proxy(config, name):
    proxies = config.get("proxies")
    if not isinstance(proxies, list):
        fail("Clash 骨架缺少 proxies 列表")
    for proxy in proxies:
        if isinstance(proxy, dict) and proxy.get("name") == name:
            return proxy
    fail(f"Clash 骨架缺少节点: {name}")


def normalize_exit_proxy(proxy):
    """规范化新节点结构，并兼容旧版 SOCKS5 分字段配置。"""
    if not isinstance(proxy, dict):
        fail("Clash 上游参数中的 exit_proxy 格式无效")
    if not proxy.get("type") and proxy.get("server"):
        legacy = {
            "type": "socks5",
            "server": proxy.get("server"),
            "port": proxy.get("port"),
            "udp": True,
        }
        if proxy.get("username"):
            legacy["username"] = proxy["username"]
            legacy["password"] = proxy.get("password", "")
        proxy = legacy

    proxy_type = proxy.get("type", "")
    server = proxy.get("server", "")
    port = proxy.get("port")
    if not isinstance(proxy_type, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", proxy_type):
        fail("Clash 上游参数中的出口节点缺少有效 type")
    if not isinstance(server, str) or not server or any(char.isspace() for char in server):
        fail("Clash 上游参数中的出口节点缺少有效 server")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        fail("Clash 上游参数中的出口节点缺少有效 port")

    normalized = CommentedMap()
    normalized["name"] = "chain.mid.proxy"
    normalized["type"] = proxy_type.lower()
    for key, value in proxy.items():
        if key not in {"name", "type", "dialer-proxy"}:
            normalized[key] = copy.deepcopy(value)
    normalized["dialer-proxy"] = "MID"
    return normalized


def replace_mapping_contents(mapping, values):
    """替换节点字段，同时保留节点后的分隔空行。"""
    trailing_token = None
    last_key = next(reversed(mapping), None)
    if last_key is not None and hasattr(mapping, "ca"):
        comment_slots = mapping.ca.items.get(last_key)
        if comment_slots and comment_slots[2] is not None:
            comment_token = comment_slots[2]
            if comment_token.value.startswith("\n"):
                trailing_token = copy.copy(comment_token)

    mapping.clear()
    if hasattr(mapping, "ca"):
        mapping.ca.items.clear()
    for key, value in values.items():
        mapping[key] = copy.deepcopy(value)
    if trailing_token is not None:
        last_key = next(reversed(mapping))
        mapping.ca.items[last_key] = [None, None, trailing_token, None]


def set_mapping_field(mapping, key, value):
    """新增字段时同步移动映射末尾空行，避免空行落在节点内部。"""
    if key in mapping:
        mapping[key] = value
        return

    last_key = next(reversed(mapping), None)
    trailing_token = None
    if last_key is not None and hasattr(mapping, "ca"):
        comment_slots = mapping.ca.items.get(last_key)
        if comment_slots and comment_slots[2] is not None:
            comment_token = comment_slots[2]
            comment_text = comment_token.value
            if comment_text.startswith("\n"):
                trailing_token = comment_token
                comment_slots[2] = None
            elif comment_text.startswith("#") and "\n" in comment_text:
                first_line, remainder = comment_text.split("\n", 1)
                if remainder:
                    trailing_token = copy.copy(comment_token)
                    trailing_token.value = "\n" + remainder
                    comment_token.value = first_line + "\n"

    mapping[key] = value
    if trailing_token is not None:
        # 映射字段的分隔空行必须放在其最后一个子字段之后；若绑在父键上，
        # ruamel 会把空行输出到 reality-opts 与 public-key 之间。
        if isinstance(value, CommentedMap) and value:
            nested_last_key = next(reversed(value))
            nested_slots = value.ca.items.setdefault(
                nested_last_key,
                [None, None, None, None],
            )
            nested_slots[2] = trailing_token
        else:
            mapping.ca.items[key] = [None, None, trailing_token, None]


def preferred_vless_inbound(config):
    """迁移期间优先使用公网入站，避免订阅继续依赖 WireGuard 内网。"""
    inbounds = config.get("inbounds", [])
    if not isinstance(inbounds, list):
        fail("Xray 配置中的 inbounds 格式无效")
    for inbound in inbounds:
        if (
            isinstance(inbound, dict)
            and inbound.get("protocol") == "vless"
            and inbound.get("tag") == "vless-public"
        ):
            return inbound
    for inbound in inbounds:
        if isinstance(inbound, dict) and inbound.get("protocol") == "vless":
            return inbound
    fail(f"当前 Xray 配置中没有 VLESS 入站: {xray_path}")


def derive_public_key(private_key):
    if not private_key:
        fail("当前 REALITY 配置缺少 privateKey")
    if not os.path.isfile(xray_bin) or not os.access(xray_bin, os.X_OK):
        fail(f"未找到可执行的 Xray，无法推导 REALITY 公钥: {xray_bin}")
    result = subprocess.run(
        [xray_bin, "x25519", "-i", private_key],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail("Xray 推导 REALITY 公钥失败，请先确认 VLESS 服务配置可用")
    for raw_line in (result.stdout + "\n" + result.stderr).splitlines():
        if ":" not in raw_line:
            continue
        label, value = raw_line.split(":", 1)
        normalized = re.sub(r"[\s()_-]", "", label).lower()
        if normalized in {"password", "passwordpublickey", "publickey"}:
            value = value.strip()
            if value:
                return value
    fail("无法从 Xray 输出中解析 REALITY 公钥")


try:
    inputs = normalized_config(Path(input_path))
except ProxyResourceError as error:
    fail(str(error))
exit_records = list(inputs.get("exits", []))
default_exit_id = inputs.get("default_exit_id", "")
exit_records.sort(key=lambda item: (item.get("id") != default_exit_id, item.get("name", "").casefold()))
if not exit_records:
    fail("Clash 上游参数中没有出口节点")

xray_config = load_json(xray_path, "Xray 配置")
inbound = preferred_vless_inbound(xray_config)
settings = inbound.get("settings", {})
users = settings.get("clients") or settings.get("users") or []
if not isinstance(users, list) or not users:
    fail("当前 VLESS 入站没有可用客户端")
user = next(
    (
        item for item in users
        if isinstance(item, dict)
        and not str(item.get("email", "")).startswith("server-kit-vless:")
    ),
    None,
)
if user is None:
    fail("当前公网 VLESS 入站缺少不受管的通用客户端")
uuid = user.get("id", "")
if not isinstance(uuid, str) or not uuid:
    fail("当前 VLESS 客户端缺少 UUID")

stream = inbound.get("streamSettings", {})
if not isinstance(stream, dict):
    fail("当前 VLESS streamSettings 格式无效")
security = stream.get("security", "none")
if security != "reality":
    fail(f"install-clash 要求公网 VLESS REALITY 入站，当前模式: {security}")

listen = str(inbound.get("listen", "0.0.0.0"))

try:
    vless_port = int(inbound.get("port"))
except (TypeError, ValueError):
    fail("当前 VLESS 端口无效")
if not 1 <= vless_port <= 65535:
    fail("当前 VLESS 端口无效")

xray_state = load_shell_assignments(xray_state_path)
xray_public_state = load_shell_assignments(xray_public_state_path)
reality = stream.get("realitySettings", {})
if security == "reality" and not isinstance(reality, dict):
    fail("当前 VLESS REALITY 配置格式无效")

if listen in {"0.0.0.0", "::"}:
    vless_server = xray_public_state.get("VLESS_PUBLIC_CLIENT_ADDRESS", "")
    if not vless_server or vless_server in {"0.0.0.0", "::"}:
        awg_state = load_shell_assignments(amneziawg_state_path)
        vless_server = awg_state.get("AWG_PUBLIC_IP", "")
    if not vless_server or vless_server in {"0.0.0.0", "::"}:
        fail("公网 VLESS 使用通配监听，但状态文件中缺少客户端可达公网地址")
else:
    vless_server = listen

with open(skeleton_path, "r", encoding="utf-8", newline="") as skeleton_file:
    skeleton_text = skeleton_file.read()
yaml = YAML(typ="rt")
yaml.preserve_quotes = True
yaml.width = 4096
_, guessed_indent, guessed_sequence_offset = load_yaml_guess_indent(skeleton_text)
config = yaml.load(skeleton_text)
if guessed_indent is not None:
    mapping_indent = guessed_indent
    if guessed_sequence_offset is not None:
        mapping_indent = max(guessed_indent - guessed_sequence_offset, 1)
    yaml.indent(
        mapping=mapping_indent,
        sequence=guessed_indent,
        offset=guessed_sequence_offset or 0,
    )
yaml.line_break = "\r\n" if "\r\n" in skeleton_text else "\n"
if not isinstance(config, dict):
    fail("Clash 骨架必须是 YAML 映射")

airport_groups = apply_airport_projection(config, inputs)

exit_node = find_named_proxy(config, "chain.mid.proxy")
proxies = config.get("proxies")
if not isinstance(proxies, list):
    fail("Clash 骨架缺少 proxies 列表")
exit_index = proxies.index(exit_node)
generated_exit_names = []
for record_index, record in enumerate(exit_records):
    normalized_exit = normalize_exit_proxy(record.get("proxy", {}))
    normalized_exit["name"] = str(record.get("proxy", {}).get("name", ""))
    if not normalized_exit["name"]:
        fail("出口节点缺少发布名称")
    generated_exit_names.append(normalized_exit["name"])
    if record_index == 0:
        replace_mapping_contents(exit_node, normalized_exit)
    else:
        proxies.insert(exit_index + record_index, normalized_exit)

proxy_groups = config.get("proxy-groups")
if not isinstance(proxy_groups, list):
    fail("Clash 骨架缺少 proxy-groups 列表")
proxy_group = next((
    item for item in proxy_groups
    if isinstance(item, dict) and item.get("name") == "PROXY"
), None)
if not isinstance(proxy_group, dict) or not isinstance(proxy_group.get("proxies"), list):
    fail("Clash 骨架缺少 PROXY 分组")
proxy_members = proxy_group["proxies"]
try:
    placeholder_index = proxy_members.index("chain.mid.proxy")
except ValueError:
    fail("Clash 骨架的 PROXY 缺少出口占位节点")
proxy_members[placeholder_index:placeholder_index + 1] = generated_exit_names

mid_nodes = [
    (find_named_proxy(config, "ENDPOINT.MID.443"), vless_port),
    (find_named_proxy(config, "ENDPOINT.MID.2053"), 2053),
]
for mid_node, mid_port in mid_nodes:
    for stale_key in (
        "flow",
        "servername",
        "client-fingerprint",
        "reality-opts",
        "encryption",
        "dialer-proxy",
    ):
        mid_node.pop(stale_key, None)
    set_mapping_field(mid_node, "type", "vless")
    set_mapping_field(mid_node, "server", vless_server)
    set_mapping_field(mid_node, "port", mid_port)
    set_mapping_field(mid_node, "uuid", uuid)
    set_mapping_field(mid_node, "network", "tcp")
    set_mapping_field(mid_node, "udp", True)
    set_mapping_field(mid_node, "packet-encoding", "xudp")

summary = {
    "skeleton_path": skeleton_path,
    "airport_count": len(inputs.get("airports", [])),
    "active_airport_groups": airport_groups,
    "exit_count": len(exit_records),
    "default_exit_id": default_exit_id,
    "vless_server": vless_server,
    "vless_port": vless_port,
    "vless_security": security,
}
if security == "reality":
    server_names = reality.get("serverNames", [])
    short_ids = reality.get("shortIds", [])
    if not isinstance(server_names, list) or not server_names:
        fail("当前 REALITY 配置缺少 serverNames")
    if not isinstance(short_ids, list) or not short_ids:
        fail("当前 REALITY 配置缺少 shortIds")
    if inbound.get("tag") == "vless-public":
        public_key = xray_public_state.get("VLESS_PUBLIC_REALITY_KEY", "")
    else:
        public_key = xray_state.get("VLESS_PUBLIC_KEY", "")
    if not public_key:
        public_key = derive_public_key(reality.get("privateKey", ""))
    flow = user.get("flow", "xtls-rprx-vision")
    for mid_node, _ in mid_nodes:
        set_mapping_field(mid_node, "tls", True)
        set_mapping_field(mid_node, "flow", flow)
        set_mapping_field(mid_node, "servername", server_names[0])
        set_mapping_field(mid_node, "client-fingerprint", "chrome")
        set_mapping_field(mid_node, "reality-opts", CommentedMap(
            {"public-key": public_key, "short-id": str(short_ids[0])}
        ))
    summary["vless_server_name"] = server_names[0]
    summary["vless_flow"] = flow
else:
    for mid_node, _ in mid_nodes:
        set_mapping_field(mid_node, "tls", False)
        set_mapping_field(mid_node, "encryption", "")

summary["vless_template"] = copy.deepcopy(mid_nodes[0][0])

with open(output_path, "w", encoding="utf-8", newline="") as output_file:
    yaml.dump(config, output_file)
    output_file.flush()
    os.fsync(output_file.fileno())
os.chmod(output_path, 0o600)

with open(summary_path, "w", encoding="utf-8", newline="\n") as summary_file:
    json.dump(summary, summary_file, ensure_ascii=False, indent=2)
    summary_file.write("\n")
os.chmod(summary_path, 0o600)
PYTHON
}

install_dependencies() {
  local package=""
  local missing_packages=()

  export DEBIAN_FRONTEND=noninteractive
  for package in python3 python3-venv python3-yaml python3-ruamel.yaml qrencode openssl curl ca-certificates iproute2; do
    if ! dpkg -s "${package}" >/dev/null 2>&1; then
      missing_packages+=("${package}")
    fi
  done

  if (( ${#missing_packages[@]} > 0 )); then
    apt-get update
    apt-get install -y "${missing_packages[@]}"
  fi
}

ensure_qrencode_installed() {
  if ! command -v qrencode >/dev/null 2>&1; then
    echo "未找到 qrencode，请重新执行 install 或 install-clash 安装二维码依赖。" >&2
    return 1
  fi
}

certbot_version() {
  local certbot_path="$1"
  "${certbot_path}" --version 2>/dev/null | awk '{print $NF}'
}

certbot_version_supported() {
  local certbot_path="$1"
  local version=""

  [[ -x "${certbot_path}" ]] || return 1
  version="$(certbot_version "${certbot_path}")"
  [[ -n "${version}" ]] && dpkg --compare-versions "${version}" ge "5.4"
}

install_certbot() {
  local system_certbot=""

  system_certbot="$(command -v certbot 2>/dev/null || true)"
  if [[ -n "${system_certbot}" ]] && certbot_version_supported "${system_certbot}"; then
    CERTBOT_BIN="${system_certbot}"
    echo "检测到兼容公网 IP 证书的 Certbot $(certbot_version "${CERTBOT_BIN}")，继续使用。"
    return
  fi

  if certbot_version_supported "${CERTBOT_VENV}/bin/certbot"; then
    CERTBOT_BIN="${CERTBOT_VENV}/bin/certbot"
    echo "检测到独立 Certbot $(certbot_version "${CERTBOT_BIN}")，继续使用。"
    return
  fi

  echo "正在安装支持公网 IP 证书的 Certbot 5.4+……"
  if [[ ! -x "${CERTBOT_VENV}/bin/python" ]]; then
    python3 -m venv "${CERTBOT_VENV}"
  fi
  "${CERTBOT_VENV}/bin/python" -m pip install --disable-pip-version-check --upgrade \
    'certbot>=5.4'
  CERTBOT_BIN="${CERTBOT_VENV}/bin/certbot"

  if ! certbot_version_supported "${CERTBOT_BIN}"; then
    echo "Certbot 安装完成，但版本低于 5.4，无法签发公网 IP 证书。" >&2
    return 1
  fi
}

create_service_user() {
  if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${SERVICE_GROUP}"
  fi

  if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system --gid "${SERVICE_GROUP}" --home-dir /nonexistent \
      --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
  fi
}

prepare_directories() {
  install -d -m 750 -o root -g "${SERVICE_GROUP}" "${CONFIG_DIR}"
  install -d -m 750 -o root -g "${SERVICE_GROUP}" "${DATA_DIR}"
  install -d -m 750 -o root -g "${SERVICE_GROUP}" "${CLASH_BACKUP_DIR}"
  install -d -m 755 -o root -g root "${SERVER_DIR}"
}

validate_public_ipv4() {
  local address="$1"

  python3 - "${address}" <<'PYTHON'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)

if address.version != 4 or not address.is_global:
    raise SystemExit(1)
PYTHON
}

validate_public_address() {
  local address="$1"

  if validate_public_ipv4 "${address}"; then
    return 0
  fi
  python3 - "${address}" <<'PYTHON'
import re
import sys

value = sys.argv[1].strip().rstrip(".").lower()
try:
    value = value.encode("idna").decode("ascii")
except UnicodeError:
    raise SystemExit(1)
label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
parts = value.split(".")
if len(value) > 253 or len(parts) < 2 or any(not label.fullmatch(part) for part in parts):
    raise SystemExit(1)
PYTHON
}

get_publication_address() {
  local fqdn=""

  if [[ -e "${PUBLIC_ENDPOINT_CONFIG}" ]]; then
    fqdn="$(python3 "${PUBLIC_ENDPOINT_HELPER}" get \
      --config "${PUBLIC_ENDPOINT_CONFIG}")" || return 1
    validate_public_address "${fqdn}" || return 1
    printf '%s\n' "${fqdn}"
    return 0
  fi
  get_public_ip
}

check_acme_port() {
  if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':80$'; then
    echo "TCP 80 已被其他进程占用，Certbot standalone 无法完成公网验证。" >&2
    echo "请先释放 TCP 80，再重新执行 ${INSTALL_COMMAND}。" >&2
    return 1
  fi
}

request_public_certificate() {
  local address="$1"
  local -a arguments=(
    certonly --non-interactive --agree-tos --register-unsafely-without-email
    --standalone --cert-name "${address}" --key-type ecdsa --keep-until-expiring
  )
  if validate_public_ipv4 "${address}"; then
    arguments+=(--preferred-profile shortlived --ip-address "${address}")
  else
    arguments+=(--domains "${address}")
  fi
  "${CERTBOT_BIN}" "${arguments[@]}"
}

open_acme_firewall() {
  if [[ -x "${FIREWALL_MANAGER}" && -x /usr/sbin/nft ]]; then
    bash "${FIREWALL_MANAGER}" open-temporary 80 900
  fi
}

close_acme_firewall() {
  if [[ -x "${FIREWALL_MANAGER}" && -x /usr/sbin/nft ]]; then
    bash "${FIREWALL_MANAGER}" close-temporary 80
  fi
}

obtain_public_certificate() {
  local address="$1"
  local lineage="/etc/letsencrypt/live/${address}"

  validate_public_address "${address}" || {
    echo "无法为无效公网发布地址签发证书: ${address}" >&2
    return 1
  }

  check_acme_port
  echo "正在为公网发布地址 ${address} 申请 Let’s Encrypt 证书……"
  echo "签发时 Certbot 会临时监听 TCP 80，完成后立即关闭。"
  open_acme_firewall
  if ! request_public_certificate "${address}"; then
    close_acme_firewall || true
    return 1
  fi
  close_acme_firewall

  if [[ ! -s "${lineage}/fullchain.pem" ]] || [[ ! -s "${lineage}/privkey.pem" ]]; then
    echo "Certbot 没有生成预期的证书文件: ${lineage}" >&2
    return 1
  fi
}

deploy_public_certificate() {
  local address="$1"
  local lineage="/etc/letsencrypt/live/${address}"
  local check_option="-checkhost"

  validate_public_ipv4 "${address}" && check_option="-checkip"
  if ! openssl x509 -in "${lineage}/fullchain.pem" -noout "${check_option}" "${address}" >/dev/null 2>&1; then
    echo "签发的证书不包含公网发布地址: ${address}" >&2
    return 1
  fi

  install -m 644 -o root -g root "${lineage}/fullchain.pem" "${CERT_PATH}"
  install -m 640 -o root -g "${SERVICE_GROUP}" "${lineage}/privkey.pem" "${KEY_PATH}"
  printf '%s\n' "${address}" > "${CERT_IP_PATH}"
  chmod 644 "${CERT_IP_PATH}"
  chown root:root "${CERT_IP_PATH}"
}

write_certificate_automation() {
  local public_address="$1"
  local temp_script=""
  local temp_hook=""
  local temp_service=""
  local temp_timer=""

  install -d -m 755 -o root -g root "$(dirname "${CERT_DEPLOY_HOOK}")"

  temp_script="$(mktemp "${SERVER_DIR}/.renew-certificate.XXXXXX")"
  temp_hook="$(mktemp "${CONFIG_DIR}/.deploy-hook.XXXXXX")"
  temp_service="$(mktemp "${CONFIG_DIR}/.renew-service.XXXXXX")"
  temp_timer="$(mktemp "${CONFIG_DIR}/.renew-timer.XXXXXX")"
  trap 'rm -f -- "${temp_script}" "${temp_hook}" "${temp_service}" "${temp_timer}"' RETURN

  cat > "${temp_script}" <<EOF
#!/usr/bin/env bash

set -euo pipefail

cleanup() {
  if [[ -x "${FIREWALL_MANAGER}" && -x /usr/sbin/nft ]]; then
    bash "${FIREWALL_MANAGER}" close-temporary 80 || true
  fi
}
trap cleanup EXIT

if [[ -x "${FIREWALL_MANAGER}" && -x /usr/sbin/nft ]]; then
  bash "${FIREWALL_MANAGER}" open-temporary 80 900
fi
"${CERTBOT_BIN}" renew --cert-name "${public_address}" --quiet
EOF

  cat > "${temp_hook}" <<EOF
#!/usr/bin/env bash

set -euo pipefail

EXPECTED_LINEAGE="/etc/letsencrypt/live/${public_address}"
if [[ "\${RENEWED_LINEAGE:-}" != "\${EXPECTED_LINEAGE}" ]]; then
  exit 0
fi

install -m 644 -o root -g root "\${EXPECTED_LINEAGE}/fullchain.pem" "${CERT_PATH}"
install -m 640 -o root -g "${SERVICE_GROUP}" "\${EXPECTED_LINEAGE}/privkey.pem" "${KEY_PATH}"
for unit in "${FILE_SERVICE_NAME}.service" "${CLASH_SERVICE_NAME}.service"; do
  if systemctl cat "\${unit}" >/dev/null 2>&1 && systemctl is-active --quiet "\${unit}"; then
    systemctl try-restart "\${unit}"
  fi
done
EOF

  cat > "${temp_service}" <<EOF
[Unit]
Description=续期安全文件服务的公网发布证书
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/debian_file_manager.sh reconcile-public-ip --yes
ExecStart=${CERT_RENEW_SCRIPT}
EOF

  cat > "${temp_timer}" <<'EOF'
[Unit]
Description=定期检查安全文件服务的公网发布证书

[Timer]
OnBootSec=2m
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true
Unit=secure-file-cert-renew.service

[Install]
WantedBy=timers.target
EOF

  install -m 755 -o root -g root "${temp_script}" "${CERT_RENEW_SCRIPT}"
  install -m 755 -o root -g root "${temp_hook}" "${CERT_DEPLOY_HOOK}"
  install -m 644 -o root -g root "${temp_service}" "${CERT_RENEW_SERVICE_PATH}"
  install -m 644 -o root -g root "${temp_timer}" "${CERT_RENEW_TIMER_PATH}"
  rm -f -- "${temp_script}" "${temp_hook}" "${temp_service}" "${temp_timer}"
  trap - RETURN
}

write_server_program() {
  local temp_server=""
  temp_server="$(mktemp "${SERVER_DIR}/.server.XXXXXX")"
  trap 'rm -f -- "${temp_server}"' RETURN

  cat > "${temp_server}" <<'PYTHON'
#!/usr/bin/env python3

import email.utils
import hmac
import json
import os
import re
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit


CHUNK_SIZE = 1024 * 1024
TLS_HANDSHAKE_TIMEOUT = 10
REQUEST_TIMEOUT = 30
MAX_CONCURRENT_REQUESTS = 64
RANGE_PATTERN = re.compile(r"bytes=(\d*)-(\d*)$")


def load_config(path):
    with open(path, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    required = ("port", "cert_path", "key_path")
    for key in required:
        if key not in config:
            raise ValueError(f"配置缺少字段: {key}")

    if "downloads" not in config:
        legacy_required = ("token", "download_name", "payload_path")
        for key in legacy_required:
            if key not in config:
                raise ValueError(f"配置缺少字段: {key}")
        config["downloads"] = [
            {
                "token": config["token"],
                "download_name": config["download_name"],
                "payload_path": config["payload_path"],
                "content_type": "application/octet-stream",
            }
        ]

    if not isinstance(config["downloads"], list):
        raise ValueError("下载项目格式无效")
    for item in config["downloads"]:
        for key in ("token", "download_name", "payload_path"):
            if key not in item:
                raise ValueError(f"下载项目缺少字段: {key}")
        cache_enabled = item.get("cdn_cache", False)
        cache_ttl = item.get("cache_ttl", 86400)
        if not isinstance(cache_enabled, bool):
            raise ValueError("CDN 缓存开关格式无效")
        if not isinstance(cache_ttl, int) or not 300 <= cache_ttl <= 2592000:
            raise ValueError("CDN 缓存时间必须为 5 分钟至 30 天")

    return config


def parse_range(value, file_size):
    if not value:
        return 0, max(file_size - 1, 0), False

    match = RANGE_PATTERN.fullmatch(value.strip())
    if not match or file_size == 0:
        raise ValueError("范围无效")

    start_text, end_text = match.groups()
    if not start_text and not end_text:
        raise ValueError("范围无效")

    if not start_text:
        suffix_length = int(end_text)
        if suffix_length <= 0:
            raise ValueError("范围无效")
        start = max(file_size - suffix_length, 0)
        end = file_size - 1
    else:
        start = int(start_text)
        end = int(end_text) if end_text else file_size - 1
        if start >= file_size or end < start:
            raise ValueError("范围无效")
        end = min(end, file_size - 1)

    return start, end, True


class FileHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    def log_message(self, _format, *_args):
        # 不在日志中记录带密钥的下载路径。
        return

    def send_error(self, _code, _message=None, _explain=None):
        # 解析错误和未知方法也使用相同的最小 404 响应。
        self.not_found(getattr(self, "command", "") != "HEAD")

    def send_minimal_response(self, status, length, content_type="text/plain; charset=utf-8"):
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def not_found(self, include_body=True):
        body = b"Not Found\n"
        self.send_minimal_response(404, len(body))
        if include_body:
            self.wfile.write(body)

    def range_not_satisfiable(self, file_size, include_body=True):
        body = b"Requested Range Not Satisfiable\n"
        self.send_response_only(416)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Range", f"bytes */{file_size}")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if include_body:
            self.wfile.write(body)

    def authorized_download(self):
        request = urlsplit(self.path)
        if request.query or request.fragment:
            return None
        for download_path, download in self.server.downloads:
            if hmac.compare_digest(request.path, download_path):
                return download
        return None

    def serve_file(self, include_body):
        download = self.authorized_download()
        if download is None:
            self.not_found(include_body)
            return

        payload_path = download["payload_path"]
        download_name = download["download_name"]
        content_type = download.get("content_type", "application/octet-stream")
        cdn_cache = download.get("cdn_cache", False)
        cache_ttl = download.get("cache_ttl", 86400)

        try:
            file_size = os.path.getsize(payload_path)
            start, end, is_partial = parse_range(self.headers.get("Range"), file_size)
        except (OSError, ValueError):
            if os.path.exists(payload_path):
                self.range_not_satisfiable(os.path.getsize(payload_path), include_body)
            else:
                self.not_found(include_body)
            return

        content_length = 0 if file_size == 0 else end - start + 1
        status = 206 if is_partial else 200
        encoded_name = quote(download_name, safe="")
        digest = download.get("sha256", "")
        etag = f'"{digest}"' if re.fullmatch(r"[0-9a-f]{64}", digest) else ""

        if etag and self.headers.get("If-None-Match", "").strip() == etag and not is_partial:
            self.send_response_only(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", f"public, max-age={cache_ttl}, s-maxage={cache_ttl}, immutable" if cdn_cache else "private, no-store")
            if cdn_cache:
                self.send_header("CDN-Cache-Control", f"public, max-age={cache_ttl}")
                self.send_header("Surrogate-Control", f"max-age={cache_ttl}")
            self.end_headers()
            return

        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{encoded_name}")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", f"public, max-age={cache_ttl}, s-maxage={cache_ttl}, immutable" if cdn_cache else "private, no-store")
        if cdn_cache:
            self.send_header("CDN-Cache-Control", f"public, max-age={cache_ttl}")
            self.send_header("Surrogate-Control", f"max-age={cache_ttl}")
        if etag:
            self.send_header("ETag", etag)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Last-Modified", email.utils.formatdate(os.path.getmtime(payload_path), usegmt=True))
        if is_partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
        self.end_headers()

        if not include_body or content_length == 0:
            return

        remaining = content_length
        try:
            with open(payload_path, "rb") as payload:
                payload.seek(start)
                while remaining > 0:
                    chunk = payload.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return

    def do_GET(self):
        self.serve_file(True)

    def do_HEAD(self):
        self.serve_file(False)

    # 常见的未使用方法返回普通 404，避免暴露 Python 服务特征。
    def do_POST(self):
        self.not_found(True)

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST
    do_OPTIONS = do_POST
    do_TRACE = do_POST
    do_CONNECT = do_POST


class SecureFileServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, server_address, handler_class, tls_context):
        super().__init__(server_address, handler_class)
        self.tls_context = tls_context
        self.request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    def process_request(self, request, client_address):
        # Do not let slow or abandoned clients consume an unbounded number of
        # handshake threads. Closing an overloaded connection lets a healthy
        # client retry instead of blocking the listening socket.
        if not self.request_slots.acquire(blocking=False):
            self.close_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        tls_request = None
        try:
            try:
                # TLS must be negotiated in the worker thread. Wrapping the listening
                # socket makes accept() perform the handshake in the main thread, so
                # one lossy client can stop every subscription download.
                request.settimeout(TLS_HANDSHAKE_TIMEOUT)
                tls_request = self.tls_context.wrap_socket(
                    request,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                tls_request.do_handshake()
                tls_request.settimeout(REQUEST_TIMEOUT)
            except (OSError, ssl.SSLError, TimeoutError):
                self.close_request(tls_request if tls_request is not None else request)
                return

            super().process_request_thread(tls_request, client_address)
        finally:
            self.request_slots.release()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("用法: server.py <config.json>")

    config = load_config(sys.argv[1])
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.options |= ssl.OP_NO_COMPRESSION
    tls_context.load_cert_chain(config["cert_path"], config["key_path"])

    server = SecureFileServer(
        ("0.0.0.0", int(config["port"])),
        FileHandler,
        tls_context,
    )
    server.downloads = []
    for download in config["downloads"]:
        token = download["token"]
        if not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("下载密钥格式无效")
        download_path = "/" + token + "/" + quote(download["download_name"], safe="")
        server.downloads.append((download_path, download))

    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
PYTHON

  python3 -m py_compile "${temp_server}"
  install -m 755 -o root -g root "${temp_server}" "${SERVER_PATH}"
  rm -f -- "${temp_server}"
  trap - RETURN
}

write_systemd_service() {
  local temp_service=""
  temp_service="$(mktemp "${CONFIG_DIR}/.service.XXXXXX")"
  trap 'rm -f -- "${temp_service}"' RETURN

  cat > "${temp_service}" <<EOF
[Unit]
Description=${SERVICE_DESCRIPTION}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=/usr/bin/python3 -I ${SERVER_PATH} ${CONFIG_PATH}
Restart=on-failure
RestartSec=2s
TimeoutStopSec=15s
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictRealtime=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

  install -m 644 -o root -g root "${temp_service}" "${SERVICE_PATH}"
  rm -f -- "${temp_service}"
  trap - RETURN
}

read_config_field() {
  local field_name="$1"

  read_config_field_from "${CONFIG_PATH}" "${field_name}"
}

read_config_field_from() {
  local config_path="$1"
  local field_name="$2"

  python3 - "${config_path}" "${field_name}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as config_file:
    config = json.load(config_file)

field = sys.argv[2]
if field in config:
    value = config[field]
else:
    downloads = config.get("downloads")
    if not isinstance(downloads, list) or not downloads or not isinstance(downloads[0], dict) or field not in downloads[0]:
        raise KeyError(field)
    value = downloads[0][field]
print(value)
PYTHON
}

ensure_independent_port() {
  local port="$1"
  local other_config=""
  local other_port=""

  if [[ "${SERVICE_NAME}" == "${CLASH_SERVICE_NAME}" ]]; then
    other_config="${FILE_CONFIG_PATH}"
  else
    other_config="${CLASH_CONFIG_PATH}"
  fi

  if [[ ! -r "${other_config}" ]]; then
    return
  fi
  other_port="$(read_config_field_from "${other_config}" port 2>/dev/null || true)"
  if validate_port "${other_port}" && (( 10#${other_port} == 10#${port} )); then
    echo "端口 ${port} 已被另一套文件服务配置使用，请为两个服务设置不同端口。" >&2
    return 1
  fi
}

load_existing_token() {
  local token=""

  if [[ -r "${CONFIG_PATH}" ]]; then
    token="$(read_config_field token 2>/dev/null || true)"
    if validate_token "${token}"; then
      printf '%s\n' "${token}"
      return
    fi
  fi

  printf '\n'
}

choose_download_token() {
  local existing_token="$1"
  local answer=""

  if validate_token "${existing_token}"; then
    answer="$(prompt_optional "检测到旧链接，是否生成新链接？[y/N，默认沿用旧链接]: ")"
    case "${answer,,}" in
      y|yes)
        openssl rand -hex 32
        ;;
      *)
        printf '%s\n' "${existing_token}"
        ;;
    esac
    return
  fi

  openssl rand -hex 32
}

install_payload() {
  local source_path="$1"
  local temp_payload=""

  temp_payload="$(mktemp "${DATA_DIR}/.shared-file.XXXXXX")"
  trap 'rm -f -- "${temp_payload}"' RETURN
  install -m 640 -o root -g "${SERVICE_GROUP}" -- "${source_path}" "${temp_payload}"
  mv -f -- "${temp_payload}" "${PAYLOAD_PATH}"
  chmod 640 "${PAYLOAD_PATH}"
  chown root:"${SERVICE_GROUP}" "${PAYLOAD_PATH}"
  trap - RETURN
}

generate_clash_bundle() {
  local base_subscription="$1"
  local staging_dir="$2"
  local final_dir="$3"
  local existing_config="$4"
  local output_config="$5"
  local port="$6"
  local server_address="$7"
  local vless_summary="${8:-}"
  local relay_address=""

  [[ -s "${vless_summary}" ]] || { echo "缺少 VLESS 摘要。" >&2; return 1; }
  [[ -r "${CLASH_BUNDLE_HELPER}" ]] || {
    echo "缺少 Clash 订阅生成模块：${CLASH_BUNDLE_HELPER}" >&2
    return 1
  }
  relay_address="${server_address}"
  python3 "${CLASH_BUNDLE_HELPER}" \
    --base "${base_subscription}" \
    --awg-peer-db "${AMNEZIAWG_PEER_DB}" \
    --awg-state "${AMNEZIAWG_STATE_FILE}" \
    --public-endpoint "${SERVER_KIT_CONFIG_DIR}/public-endpoint.json" \
    --vless-policy "${VLESS_ACCESS_PATH}" \
    --vless-summary "${vless_summary}" \
    --staging-dir "${staging_dir}" \
    --final-dir "${final_dir}" \
    --existing-config "${existing_config}" \
    --publication-state "${CLASH_PUBLICATION_STATE}" \
    --proxy-inputs "${CLASH_INPUT_CONFIG}" \
    --node-domains "${NODE_DOMAINS_PATH}" \
    --server-relay "${SERVER_RELAY_CONFIG}" \
    --output-config "${output_config}" \
    --port "${port}" \
    --server-address "${server_address}" \
    --relay-address "${relay_address}" \
    --cert "${CERT_PATH}" \
    --key "${KEY_PATH}"
}

verify_clash_vless_relay_bundle() {
  local bundle_dir="$1"
  local relay_config="${2:-${SERVER_RELAY_CONFIG}}"

  python3 - "${relay_config}" "${bundle_dir}" <<'PYTHON'
import json
import re
import sys
from pathlib import Path

from ruamel.yaml import YAML

relay_path = Path(sys.argv[1])
bundle_dir = Path(sys.argv[2])
if not relay_path.is_file():
    raise SystemExit(0)
try:
    relay = json.loads(relay_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as error:
    raise SystemExit(f"无法校验 VLESS 服务端转发发布状态：{error}")
if not relay.get("enabled") or not relay.get("vless_enabled"):
    raise SystemExit(0)
node_name = relay.get("vless_node_name", "SERVER.RELAY.VLESS")
if not isinstance(node_name, str) or not node_name:
    raise SystemExit("VLESS 服务端转发节点名称无效。")
files = sorted(bundle_dir.glob("clash-*.yaml"))
if not files:
    raise SystemExit("VLESS 服务端转发已启用，但没有生成任何订阅。")
yaml = YAML(typ="safe")
missing = []
for path in files:
    try:
        config = yaml.load(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise SystemExit(f"无法校验订阅 {path.name}：{error}")
    proxies = config.get("proxies", []) if isinstance(config, dict) else []
    groups = config.get("proxy-groups", []) if isinstance(config, dict) else []
    relay_groups = [
        item for item in groups
        if isinstance(item, dict)
        and str(item.get("name", "")).startswith(f"{node_name}.")
    ]
    relay_group_names = [str(item.get("name")) for item in relay_groups]
    proxy_group = next(
        (item for item in groups if isinstance(item, dict) and item.get("name") == "PROXY"),
        None,
    )
    proxy_members = proxy_group.get("proxies", []) if isinstance(proxy_group, dict) else []
    has_group_member = (
        bool(relay_group_names)
        and isinstance(proxy_members, list)
        and proxy_members[:len(relay_group_names)] == relay_group_names
    )
    relay_members = [
        member for relay_group in relay_groups
        for member in relay_group.get("proxies", [])
        if isinstance(relay_group.get("proxies"), list)
    ]
    primary_name = relay_members[0] if relay_members else ""
    bootstrap_group_name = relay_group_names[0] if relay_group_names else ""
    has_relay_source = (
        bool(relay_groups)
        and all(
            relay_group.get("type") == "fallback"
            and isinstance(relay_group.get("proxies"), list)
            and len(relay_group["proxies"]) == 2
            and relay_group["proxies"] == [
                f"{relay_group['name']}.443", f"{relay_group['name']}.2053"
            ]
            and relay_group.get("lazy") is False
            for relay_group in relay_groups
        )
        and len(set(relay_members)) == len(relay_members)
        and not any(
            isinstance(item, dict) and item.get("name") == node_name
            for item in proxies
        )
        and not any(
            isinstance(item, dict) and item.get("name") == node_name
            for item in groups
        )
        and not any(
            isinstance(item, dict) and item.get("name") == "DNS.RELAY"
            for item in groups
        )
    )
    relay_nodes = {
        item.get("name"): item
        for item in proxies
        if isinstance(item, dict)
        and item.get("name") in set(relay_members)
    }
    rules = config.get("rules", []) if isinstance(config, dict) else []
    dns = config.get("dns", {}) if isinstance(config, dict) else {}
    nameservers = dns.get("nameserver", []) if isinstance(dns, dict) else []
    proxy_nameservers = dns.get("proxy-server-nameserver", []) if isinstance(dns, dict) else []
    if isinstance(proxy_nameservers, str):
        proxy_nameservers = [proxy_nameservers]
    expected_nameservers = {
        "https://8.8.8.8/dns-query",
        "https://1.0.0.1/dns-query",
    }
    expected_bootstrap_nameservers = {
        "https://223.5.5.5/dns-query",
        "https://1.12.12.12/dns-query",
    }
    modern_dns = isinstance(dns, dict) and "respect-rules" in dns
    has_split_dns = (
        isinstance(nameservers, list)
        and {str(value).split("#", 1)[0] for value in nameservers} == expected_nameservers
        and isinstance(proxy_nameservers, list)
        and bool(proxy_nameservers)
    )
    if modern_dns:
        has_split_dns = (
            has_split_dns
            and {str(value).split("#", 1)[0] for value in proxy_nameservers}
            == expected_bootstrap_nameservers
            and all(str(value).endswith("#PROXY") for value in nameservers)
            and all(str(value).endswith("#DIRECT") for value in proxy_nameservers)
            and dns.get("direct-nameserver") == [
                "https://223.5.5.5/dns-query",
                "https://1.12.12.12/dns-query",
            ]
        )
    else:
        has_split_dns = (
            has_split_dns
            and {str(value).split("#", 1)[0] for value in proxy_nameservers}
            == {"https://223.5.5.5/dns-query"}
            and all("#" not in str(value) for value in nameservers)
            and all("#" not in str(value) for value in proxy_nameservers)
        )
    policies = dns.get("nameserver-policy", {}) if isinstance(dns, dict) else {}
    relay_addresses = {
        str(item.get("server", ""))
        for item in relay_nodes.values()
        if item.get("server")
    }
    has_relay_endpoint_policies = bool(relay_addresses) and isinstance(policies, dict)
    expected_endpoint_nameservers = (
        expected_bootstrap_nameservers
        if modern_dns
        else {"https://223.5.5.5/dns-query"}
    )
    for address in relay_addresses:
        value = policies.get(address)
        values = value if isinstance(value, list) else [value]
        has_relay_endpoint_policies = (
            has_relay_endpoint_policies
            and {str(item).split("#", 1)[0] for item in values}
            == expected_endpoint_nameservers
            and any(
                rule in rules
                for rule in (
                    f"DOMAIN,{address},DIRECT",
                    f"IP-CIDR,{address}/32,DIRECT,no-resolve",
                )
            )
        )
    bootstrap_domains = [
        rule.split(",", 2)[1]
        for rule in rules
        if isinstance(rule, str)
        and rule.startswith("DOMAIN,")
        and rule.endswith(f",{bootstrap_group_name}")
    ]
    has_bootstrap_policies = bool(bootstrap_domains) and isinstance(policies, dict)
    for domain in bootstrap_domains:
        value = policies.get(domain)
        values = value if isinstance(value, list) else [value]
        has_bootstrap_policies = (
            has_bootstrap_policies
            and {str(item).split("#", 1)[0] for item in values}
            == {"https://1.1.1.1/dns-query"}
        )
    provider_groups = [
        item for item in groups
        if isinstance(item, dict) and isinstance(item.get("use"), list)
    ]
    if modern_dns:
        def rejects_empty_provider(group):
            if group.get("empty-fallback") != "REJECT" or group.get("proxies") != ["REJECT"]:
                return False
            try:
                pattern = re.compile(group.get("filter", ""))
                return bool(pattern.search("REJECT")) and not any(
                    pattern.search(name) for name in ("DIRECT", "PASS", "GLOBAL")
                )
            except (TypeError, re.error):
                return False

        stash_profile = any(
            isinstance(item, dict) and str(item.get("name", "")).startswith("PRIVATE-")
            for item in proxies
        )
        has_provider_fallback = all(
            rejects_empty_provider(item) if stash_profile
            else item.get("empty-fallback") == primary_name
            for item in provider_groups
        )
    else:
        has_provider_fallback = all(
            isinstance(item.get("proxies"), list)
            and primary_name in item["proxies"]
            and "empty-fallback" not in item
            for item in provider_groups
        )
    resource_providers = [
        provider
        for section_name, section in config.items()
        if isinstance(section_name, str)
        and section_name.endswith("-providers")
        and isinstance(section, dict)
        for provider in section.values()
        if isinstance(provider, dict)
        and provider.get("type") == "http"
        and isinstance(provider.get("url"), str)
    ]
    if modern_dns:
        has_resource_download_proxy = bool(resource_providers) and all(
            provider.get("proxy") == bootstrap_group_name
            for provider in resource_providers
        )
    else:
        has_resource_download_proxy = bool(resource_providers) and all(
            "proxy" not in provider
            for provider in resource_providers
        )
    relay_prefixes = {
        name.rsplit(".", 1)[0]
        for name in relay_members
        if isinstance(name, str) and name.endswith((".443", ".2053"))
    }
    has_server_relay = (
        set(relay_nodes) == set(relay_members)
        and bool(relay_prefixes)
        and all(
            {f"{prefix}.443", f"{prefix}.2053"} <= set(relay_members)
            and relay_nodes[f"{prefix}.443"].get("port") == 443
            and relay_nodes[f"{prefix}.2053"].get("port") == 2053
            and relay_nodes[f"{prefix}.443"].get("uuid") == relay_nodes[f"{prefix}.2053"].get("uuid")
            for prefix in relay_prefixes
        )
        and f"IP-CIDR,1.1.1.1/32,{bootstrap_group_name},no-resolve" in rules
        and not any(
            f"IP-CIDR,{address}/32,{bootstrap_group_name},no-resolve" in rules
            for address in ("8.8.8.8", "1.0.0.1")
        )
        and all(
            f"IP-CIDR,{address}/32,DIRECT,no-resolve" in rules
            for address in ("223.5.5.5", "1.12.12.12")
        )
        and any(
            isinstance(rule, str)
            and rule.startswith("DOMAIN,")
            and rule.endswith(f",{bootstrap_group_name}")
            for rule in rules
        )
    )
    has_proxy_first = (
        bool(groups)
        and isinstance(groups[0], dict)
        and groups[0].get("name") == "PROXY"
    )
    if (
        not has_relay_source
        or not has_group_member
        or not has_server_relay
        or not has_split_dns
        or not has_relay_endpoint_policies
        or not has_bootstrap_policies
        or not has_provider_fallback
        or not has_resource_download_proxy
        or not has_proxy_first
    ):
        missing.append(path.name)
if missing:
    raise SystemExit(
        f"VLESS 服务端转发组或 DNS 启动链未完整写入订阅：{', '.join(missing)}；拒绝替换现有发布内容。"
    )
PYTHON
}

write_config() {
  local port="$1"
  local server_address="$2"
  local token="$3"
  local download_name="$4"
  local sha256="$5"
  local file_size="$6"
  local temp_config=""

  temp_config="$(mktemp "${CONFIG_DIR}/.config.XXXXXX")"
  trap 'rm -f -- "${temp_config}"' RETURN

  python3 - "${temp_config}" "${port}" "${server_address}" "${token}" "${download_name}" \
    "${sha256}" "${file_size}" "${PAYLOAD_PATH}" "${CERT_PATH}" "${KEY_PATH}" <<'PYTHON'
import json
import hashlib
import os
import sys

path, port, address, token, name, sha256, size, payload, cert, key = sys.argv[1:]
config = {
    "mode": "file",
    "port": int(port),
    "server_address": address,
    "cert_path": cert,
    "key_path": key,
    "downloads": [{
        "resource_id": "file-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16],
        "token": token,
        "download_name": name,
        "sha256": sha256,
        "file_size": int(size),
        "payload_path": payload,
        "content_type": "application/octet-stream",
        "cdn_cache": True,
        "cache_ttl": 86400,
    }],
}

with open(path, "w", encoding="utf-8") as config_file:
    json.dump(config, config_file, ensure_ascii=False, indent=2)
    config_file.write("\n")
    config_file.flush()
    os.fsync(config_file.fileno())
PYTHON

  install -m 640 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  rm -f -- "${temp_config}"
  trap - RETURN
}

get_public_ip() {
  local ip=""

  ip="$(curl -4 -sf --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i+1); exit}}')"
  fi
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi

  if ! validate_public_ipv4 "${ip}"; then
    echo "无法自动获取可签发证书的公网 IPv4 地址。" >&2
    echo "请确认服务器可以访问 https://api.ipify.org，并且拥有公网 IPv4。" >&2
    return 1
  fi

  printf '%s\n' "${ip}"
}

urlencode() {
  python3 -c 'from urllib.parse import quote; import sys; print(quote(sys.argv[1], safe=""))' "$1"
}

download_url() {
  local server_ip=""
  local port=""
  local token=""
  local download_name=""

  if [[ ! -r "${CONFIG_PATH}" ]]; then
    echo "未找到配置文件 ${CONFIG_PATH}，请先执行 ${INSTALL_COMMAND}。" >&2
    return 1
  fi

  server_ip="$(read_config_field server_address 2>/dev/null || true)"
  server_ip="${server_ip:-$(get_public_ip)}"
  port="$(read_config_field port)"
  token="$(read_config_field token)"
  download_name="$(read_config_field download_name)"
  printf 'https://%s:%s/%s/%s\n' "${server_ip}" "${port}" "${token}" "$(urlencode "${download_name}")"
}

service_is_clash() {
  [[ "${SERVICE_NAME}" == "${CLASH_SERVICE_NAME}" ]]
}

show_clash_links() {
  if [[ ! -r "${CONFIG_PATH}" ]]; then
    echo "未找到配置文件 ${CONFIG_PATH}，请先执行 install-clash。" >&2
    return 1
  fi

  python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys
from urllib.parse import quote

with open(sys.argv[1], "r", encoding="utf-8") as config_file:
    config = json.load(config_file)

if config.get("mode") != "clash":
    raise SystemExit("当前不是 Clash 多订阅模式")

address = config["server_address"]
port = config["port"]
downloads = config.get("downloads", [])
print("=== Clash 个性化订阅链接 ===")
for item in downloads:
    name = item["download_name"]
    url = f"https://{address}:{port}/{item['token']}/{quote(name, safe='')}"
    print(f"[{item['peer_name']}] {url}")
print(f"订阅总数: {len(downloads)}")
PYTHON
}

show_qr() {
  local requested="${1:-}"
  local file_config="${2-${FILE_CONFIG_PATH}}"
  local clash_config="${3-${CLASH_CONFIG_PATH}}"
  local records_text=""
  local selected=""
  local choice=""
  local key=""
  local remainder=""
  local label=""
  local url=""
  local index=0
  local record=""
  local -a records=()

  ensure_qrencode_installed

  records_text="$(python3 - "${file_config}" "${clash_config}" <<'PYTHON'
import json
import os
import sys
from urllib.parse import quote

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")

seen_urls = set()


def clean_label(value):
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


for path in sys.argv[1:]:
    if not path or not os.path.isfile(path):
        continue
    with open(path, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    address = config["server_address"]
    port = config["port"]
    if isinstance(config.get("downloads"), list):
        for item in config.get("downloads", []):
            peer_name = item.get("peer_name", item.get("resource_id", "file"))
            if any(char in str(peer_name) for char in "\t\r\n"):
                raise SystemExit(f"资源名称无效: {peer_name!r}")
            name = quote(item["download_name"], safe="")
            url = f"https://{address}:{port}/{item['token']}/{name}"
            if url not in seen_urls:
                label = f"Clash：{peer_name}" if config.get("mode") == "clash" else f"普通文件：{clean_label(item['download_name'])}"
                print(f"{peer_name}\t{label}\t{url}")
                seen_urls.add(url)
    else:
        download_name = config["download_name"]
        name = quote(download_name, safe="")
        url = f"https://{address}:{port}/{config['token']}/{name}"
        if url not in seen_urls:
            print(f"file\t普通文件：{clean_label(download_name)}\t{url}")
            seen_urls.add(url)
PYTHON
)" || return 1

  if [[ -z "${records_text}" ]]; then
    echo "当前没有可用的文件或 Clash 订阅链接，请先执行 install 或 install-clash。" >&2
    return 1
  fi
  mapfile -t records <<< "${records_text}"

  if [[ -z "${requested}" ]]; then
    echo "可用链接："
    for index in "${!records[@]}"; do
      remainder="${records[index]#*$'\t'}"
      label="${remainder%%$'\t'*}"
      printf '  %d) %s\n' "$((index + 1))" "${label}"
    done
    read -r -p "请选择链接编号: " choice || return 1
    if [[ ! "${choice}" =~ ^[0-9]+$ ]] ||
       (( 10#${choice} < 1 || 10#${choice} > ${#records[@]} )); then
      echo "链接编号无效: ${choice}" >&2
      return 1
    fi
    selected="${records[$((10#${choice} - 1))]}"
  else
    for record in "${records[@]}"; do
      key="${record%%$'\t'*}"
      if [[ "${key}" == "${requested}" ]] ||
         [[ "${key}" == "file" && "${requested}" =~ ^(普通|普通文件)$ ]]; then
        selected="${record}"
        break
      fi
    done
    if [[ -z "${selected}" && "${requested}" =~ ^[0-9]+$ ]] &&
       (( 10#${requested} >= 1 && 10#${requested} <= ${#records[@]} )); then
      selected="${records[$((10#${requested} - 1))]}"
    fi
    if [[ -z "${selected}" ]]; then
      echo "未找到链接: ${requested}" >&2
      return 1
    fi
  fi

  remainder="${selected#*$'\t'}"
  label="${remainder%%$'\t'*}"
  url="${remainder#*$'\t'}"
  echo "链接: ${label}"
  echo "地址: ${url}"
  echo "二维码包含私密下载地址，请勿分享。"
  printf '%s' "${url}" | qrencode -t ANSIUTF8 -m 2
}

enable_service() {
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null
  if ! systemctl restart "${SERVICE_NAME}"; then
    echo "服务启动失败，最近日志如下：" >&2
    journalctl -u "${SERVICE_NAME}" -n 30 --no-pager >&2 || true
    return 1
  fi
}

enable_certificate_timer() {
  systemctl daemon-reload
  systemctl enable --now secure-file-cert-renew.timer >/dev/null
}

start_service() {
  systemctl start "${SERVICE_NAME}"
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
}

stop_service() {
  systemctl stop "${SERVICE_NAME}"
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
}

stop_all_services() {
  local unit=""
  local failed="false"

  for unit in "${FILE_SERVICE_NAME}" "${CLASH_SERVICE_NAME}"; do
    if ! systemctl cat "${unit}.service" >/dev/null 2>&1; then
      echo "未安装，已忽略: ${unit}"
      continue
    fi
    if systemctl stop "${unit}"; then
      echo "已停止: ${unit}"
    else
      echo "停止失败: ${unit}" >&2
      failed="true"
    fi
  done

  [[ "${failed}" == "false" ]]
}

remove_managed_tree() {
  local target="$1"

  # 只允许删除本脚本独占的固定目录，防止变量异常扩大删除范围。
  case "${target}" in
    /etc/secure-file-service|/var/lib/secure-file-service|/usr/local/lib/secure-file-service|/opt/secure-file-certbot)
      ;;
    *)
      echo "拒绝删除非托管目录: ${target}" >&2
      return 1
      ;;
  esac

  if [[ -e "${target}" ]] || [[ -L "${target}" ]]; then
    rm -rf --one-file-system -- "${target}"
    echo "已删除: ${target}"
  fi
}

uninstall_all_services() {
  local confirm="${1:-}"
  local answer=""
  local unit=""

  if [[ "${confirm}" != "--yes" ]]; then
    answer="$(prompt_optional "将删除全部文件服务配置、订阅和下载链接，是否继续？[y/N]: ")"
    case "${answer,,}" in
      y|yes)
        ;;
      *)
        echo "已取消卸载。"
        return
        ;;
    esac
  fi

  for unit in \
    "${FILE_SERVICE_NAME}.service" \
    "${CLASH_SERVICE_NAME}.service" \
    "secure-file-cert-renew.service" \
    "secure-file-cert-renew.timer"; do
    systemctl disable --now "${unit}" >/dev/null 2>&1 || true
  done

  rm -f -- \
    "${FILE_SERVICE_PATH}" \
    "${CLASH_SERVICE_PATH}" \
    "${CERT_RENEW_SERVICE_PATH}" \
    "${CERT_RENEW_TIMER_PATH}" \
    "${CERT_DEPLOY_HOOK}"

  remove_managed_tree "${CONFIG_DIR}"
  remove_managed_tree "${DATA_DIR}"
  remove_managed_tree "${SERVER_DIR}"
  remove_managed_tree "${CERTBOT_VENV}"

  if id "${SERVICE_USER}" >/dev/null 2>&1; then
    userdel "${SERVICE_USER}" >/dev/null 2>&1 || true
  fi
  if getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    groupdel "${SERVICE_GROUP}" >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload
  systemctl reset-failed "${FILE_SERVICE_NAME}.service" "${CLASH_SERVICE_NAME}.service" \
    "secure-file-cert-renew.service" >/dev/null 2>&1 || true

  echo "全部文件服务已卸载。"
  echo "Let’s Encrypt 原始证书和系统软件包未删除。"
}

status_service() {
  systemctl --no-pager --full status "${SERVICE_NAME}"
}

show_link() {
  local url=""
  local name=""

  if service_is_clash; then
    show_clash_links
    return
  fi

  url="$(download_url)"
  name="$(read_config_field download_name)"

  echo "=== 文件下载链接 ==="
  echo "${url}"
  echo
  echo "当前使用 Let’s Encrypt 公网发布证书，可直接被浏览器和 Clash 验证。"
  echo "命令行下载："
  printf "curl --fail --location --output %q %q\n" "${name}" "${url}"
}

info_service() {
  local fingerprint=""
  local issuer=""
  local expires=""

  if [[ ! -r "${CONFIG_PATH}" ]]; then
    echo "未找到配置文件 ${CONFIG_PATH}，请先执行 ${INSTALL_COMMAND}。"
    exit 1
  fi

  fingerprint="$(openssl x509 -in "${CERT_PATH}" -noout -fingerprint -sha256 2>/dev/null || true)"
  issuer="$(openssl x509 -in "${CERT_PATH}" -noout -issuer 2>/dev/null || true)"
  expires="$(openssl x509 -in "${CERT_PATH}" -noout -enddate 2>/dev/null || true)"
  echo "=== 文件服务当前配置 ==="
  echo "服务器地址: $(read_config_field server_address 2>/dev/null || get_public_ip)"
  echo "端口: $(read_config_field port)"
  if service_is_clash; then
    echo "服务模式: Clash 个性化多订阅"
  else
    echo "下载文件名: $(read_config_field download_name)"
    echo "文件大小: $(read_config_field file_size) 字节"
    echo "SHA-256: $(read_config_field sha256)"
  fi
  echo "证书颁发者: ${issuer#issuer=}"
  echo "证书到期时间: ${expires#notAfter=}"
  echo "证书指纹: ${fingerprint#*=}"
  echo "自动续期定时器: secure-file-cert-renew.timer"
  echo "配置文件: ${CONFIG_PATH}"
  echo
  show_link
  echo
  status_service
}

install_clash_and_run() {
  local requested_path="${1:-}"
  local source_path=""
  local current_address=""
  local server_address=""
  local existing_address=""
  local existing_port=""
  local port=""
  local default_port=""
  local staging_dir=""
  local temp_config=""
  local prepared_source=""
  local vless_summary=""
  local archive_dir=""
  local existing_clash_config="${CONFIG_PATH}"

  source_path="$(resolve_source_file "${requested_path:-${DEFAULT_CLASH_SOURCE_FILE}}")"
  if [[ ! -s "${AMNEZIAWG_PEER_DB}" && ! -s "${VLESS_ACCESS_PATH}" ]]; then
    echo "没有可发布的 AmneziaWG 或 VLESS 节点。" >&2
    return 1
  fi

  install_dependencies
  create_service_user
  prepare_directories
  install_certbot
  configure_clash_inputs
  sync_server_relay_if_configured
  prepared_source="$(mktemp "${CONFIG_DIR}/.clash-source.XXXXXX")"
  vless_summary="$(mktemp "${CONFIG_DIR}/.clash-vless-summary.XXXXXX")"
  trap 'rm -f -- "${prepared_source}" "${vless_summary}"' RETURN
  render_clash_skeleton "${source_path}" "${prepared_source}" "${vless_summary}"
  echo "已从当前 Xray 配置读取 VLESS 中转：$(python3 - "${vless_summary}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as summary_file:
    summary = json.load(summary_file)
print(f'{summary["vless_server"]}:{summary["vless_port"]}（{summary["vless_security"]}）')
PYTHON
)"
  current_address="$(get_publication_address)"

  if [[ -r "${CONFIG_PATH}" ]]; then
    existing_port="$(read_config_field port 2>/dev/null || true)"
    existing_address="$(read_config_field server_address 2>/dev/null || true)"
  fi
  if validate_port "${existing_port}" && validate_public_address "${existing_address}" &&
     [[ "${existing_address}" == "${current_address}" ]]; then
    port="$((10#${existing_port}))"
    server_address="${existing_address}"
    echo "将沿用现有服务地址和端口：${server_address}:${port}。"
  else
    default_port="${existing_port:-${DEFAULT_PORT}}"
    if ! validate_port "${default_port}"; then
      default_port="${DEFAULT_PORT}"
    fi
    if [[ "${CLASH_INSTALL_NONINTERACTIVE}" == "1" ]]; then
      port="${CLASH_INSTALL_PORT:-${default_port}}"
    else
      port="$(prompt_optional "请输入监听端口 [默认 ${default_port}]，直接回车使用默认值: ")"
      port="${port:-${default_port}}"
    fi
    if ! validate_port "${port}"; then
      echo "端口无效: ${port}" >&2
      return 1
    fi
    port="$((10#${port}))"
    server_address="${current_address}"
  fi
  ensure_independent_port "${port}"

  obtain_public_certificate "${server_address}"
  deploy_public_certificate "${server_address}"
  write_server_program
  write_systemd_service
  write_certificate_automation "${server_address}"

  staging_dir="$(mktemp -d "${DATA_DIR}/.clash-subscriptions.XXXXXX")"
  temp_config="$(mktemp "${CONFIG_DIR}/.clash-config.XXXXXX")"
  trap '[[ -n "${staging_dir}" && -d "${staging_dir}" ]] && rm -rf -- "${staging_dir}"; rm -f -- "${temp_config}" "${prepared_source}" "${vless_summary}"' RETURN
  generate_clash_bundle "${prepared_source}" "${staging_dir}" "${CLASH_PAYLOAD_DIR}" \
    "${existing_clash_config}" "${temp_config}" "${port}" "${server_address}" \
    "${vless_summary}"

  find "${staging_dir}" -type f -exec chmod 640 {} +
  chown -R root:"${SERVICE_GROUP}" "${staging_dir}"
  chmod 750 "${staging_dir}"
  if [[ -d "${CLASH_PAYLOAD_DIR}" ]]; then
    archive_dir="${CLASH_BACKUP_DIR}/$(date +%Y%m%d%H%M%S)"
    if [[ -e "${archive_dir}" ]]; then
      archive_dir="${archive_dir}-$$"
    fi
    mv -- "${CLASH_PAYLOAD_DIR}" "${archive_dir}"
    echo "旧个性化订阅已归档：${archive_dir}"
  fi
  mv -- "${staging_dir}" "${CLASH_PAYLOAD_DIR}"
  staging_dir=""
  install -m 640 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  rm -f -- "${temp_config}"
  temp_config=""
  rm -f -- "${prepared_source}" "${vless_summary}"
  prepared_source=""
  vless_summary=""
  trap - RETURN

  enable_service
  enable_certificate_timer
  echo
  echo "Clash 个性化订阅服务已安装并启动。"
  echo "订阅骨架: ${source_path}"
  echo "机场和出口配置: ${CLASH_INPUT_CONFIG}"
  echo "VLESS 中转来源: ${XRAY_CONFIG_PATH}"
  echo "生成订阅目录: ${CLASH_PAYLOAD_DIR}"
  echo
  echo "修改机场或出口：重新执行 install-clash（直接回车可沿用已保存值）。"
  echo "修改中转：先更新 VLESS，再重新执行 install-clash。"
  echo "修改规则和分组：编辑 ${source_path} 后重新执行 install-clash。"
  echo "请确认防火墙和云安全组已放行 TCP ${port} 端口。"
  echo
  show_clash_links
}

refresh_clash_subscriptions() {
  local requested_path="${1:-}"
  local requested_address="${2:-}"
  local source_path=""
  local prepared_source=""
  local vless_summary=""
  local staging_dir=""
  local temp_config=""
  local rollback_dir=""
  local rollback_config=""
  local port=""
  local server_address=""

  [[ -r "${CONFIG_PATH}" ]] || { echo "Clash 订阅服务尚未安装。" >&2; return 1; }
  [[ -r "${CLASH_INPUT_CONFIG}" ]] || { echo "缺少已保存的机场和出口配置。" >&2; return 1; }
  [[ -d "${CLASH_PAYLOAD_DIR}" ]] || { echo "缺少现有订阅目录。" >&2; return 1; }
  source_path="$(resolve_source_file "${requested_path:-${DEFAULT_CLASH_SOURCE_FILE}}")"
  port="$(read_config_field port)"
  server_address="${requested_address:-$(read_config_field server_address)}"
  validate_port "${port}" || { echo "现有订阅端口无效。" >&2; return 1; }
  validate_public_address "${server_address}" || { echo "现有订阅地址无效。" >&2; return 1; }
  sync_server_relay_if_configured

  prepared_source="$(mktemp "${CONFIG_DIR}/.clash-source.XXXXXX")"
  vless_summary="$(mktemp "${CONFIG_DIR}/.clash-vless-summary.XXXXXX")"
  staging_dir="$(mktemp -d "${DATA_DIR}/.clash-subscriptions.XXXXXX")"
  temp_config="$(mktemp "${CONFIG_DIR}/.clash-config.XXXXXX")"
  rollback_dir="${DATA_DIR}/.clash-subscriptions.rollback.$$"
  rollback_config="$(mktemp "${CONFIG_DIR}/.clash-config.rollback.XXXXXX")"
  cp "${CONFIG_PATH}" "${rollback_config}"
  trap 'rm -rf -- "${staging_dir:-}" "${rollback_dir:-}"; rm -f -- "${prepared_source:-}" "${vless_summary:-}" "${temp_config:-}" "${rollback_config:-}"' RETURN

  render_clash_skeleton "${source_path}" "${prepared_source}" "${vless_summary}"
  generate_clash_bundle "${prepared_source}" "${staging_dir}" "${CLASH_PAYLOAD_DIR}" \
    "${CONFIG_PATH}" "${temp_config}" "${port}" "${server_address}" "${vless_summary}"
  verify_clash_vless_relay_bundle "${staging_dir}"
  find "${staging_dir}" -type f -exec chmod 640 {} +
  chown -R root:"${SERVICE_GROUP}" "${staging_dir}"
  chmod 750 "${staging_dir}"

  mv -- "${CLASH_PAYLOAD_DIR}" "${rollback_dir}"
  mv -- "${staging_dir}" "${CLASH_PAYLOAD_DIR}"
  staging_dir=""
  install -m 640 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  if ! systemctl restart "${SERVICE_NAME}"; then
    rm -rf -- "${CLASH_PAYLOAD_DIR}"
    mv -- "${rollback_dir}" "${CLASH_PAYLOAD_DIR}"
    rollback_dir=""
    install -m 640 -o root -g "${SERVICE_GROUP}" "${rollback_config}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    echo "订阅同步失败，已恢复原订阅。" >&2
    return 1
  fi
  sleep 1
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    rm -rf -- "${CLASH_PAYLOAD_DIR}"
    mv -- "${rollback_dir}" "${CLASH_PAYLOAD_DIR}"
    rollback_dir=""
    install -m 640 -o root -g "${SERVICE_GROUP}" "${rollback_config}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    echo "订阅同步失败，已恢复原订阅。" >&2
    return 1
  fi
  rm -rf -- "${rollback_dir}"
  rollback_dir=""
  rm -f -- "${prepared_source}" "${vless_summary}" "${temp_config}" "${rollback_config}"
  prepared_source=""
  vless_summary=""
  temp_config=""
  rollback_config=""
  trap - RETURN
  echo "已按当前节点状态同步全部 Clash 订阅。"
}

read_config_server_address() {
  local path="$1"
  [[ -r "${path}" ]] || return 1
  python3 - "${path}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source).get("server_address", "")
if not isinstance(value, str):
    raise SystemExit(1)
print(value)
PYTHON
}

update_config_server_address() {
  local path="$1"
  local address="$2"
  [[ -r "${path}" ]] || return 1
  validate_public_address "${address}" || return 1
  python3 - "${path}" "${address}" <<'PYTHON'
import json
import os
import stat
import sys
import tempfile

path, address = sys.argv[1:]
metadata = os.stat(path, follow_symlinks=False)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("配置不是普通文件")
with open(path, encoding="utf-8") as source:
    value = json.load(source)
value["server_address"] = address
descriptor, temporary = tempfile.mkstemp(prefix=".server-address.", dir=os.path.dirname(path))
try:
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
    try:
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
    except (AttributeError, PermissionError):
        pass
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYTHON
}

audit_public_ip() {
  local current_address=""
  local configured_address=""
  local certificate_check="-checkhost"
  local failed=0
  local configured=0
  local path=""
  local label=""
  local label_path=""

  current_address="$(get_publication_address)" || return 1
  validate_public_ipv4 "${current_address}" && certificate_check="-checkip"
  for label_path in \
    "Clash 订阅:${CLASH_CONFIG_PATH}" \
    "普通文件:${FILE_CONFIG_PATH}"; do
    label="${label_path%%:*}"
    path="${label_path#*:}"
    [[ -r "${path}" ]] || continue
    configured=1
    configured_address="$(read_config_server_address "${path}" 2>/dev/null || true)"
    if [[ "${configured_address}" != "${current_address}" ]]; then
      echo "异常：${label}发布地址为 ${configured_address:-<无效>}，当前发布地址为 ${current_address}" >&2
      failed=1
    fi
  done

  if [[ -r "${CERT_IP_PATH}" ]]; then
    configured=1
    configured_address="$(tr -d '\r\n' < "${CERT_IP_PATH}")"
    if [[ "${configured_address}" != "${current_address}" ]]; then
      echo "异常：HTTPS 证书事实为 ${configured_address:-<无效>}，当前发布地址为 ${current_address}" >&2
      failed=1
    elif [[ ! -r "${CERT_PATH}" ]] ||
         ! openssl x509 -in "${CERT_PATH}" -noout "${certificate_check}" "${current_address}" >/dev/null 2>&1; then
      echo "异常：当前 HTTPS 证书不包含发布地址 ${current_address}" >&2
      failed=1
    fi
  fi

  if (( configured == 0 )); then
    echo "公网发布地址审计跳过：尚未安装 HTTPS 发布服务。"
    return 0
  fi
  if (( failed == 0 )); then
    echo "公网发布地址审计通过：发布地址和 HTTPS 证书均为 ${current_address}。"
  fi
  return "${failed}"
}

restore_public_ip_reconcile() {
  local backup_dir="$1"
  local old_certificate_address="$2"
  local file_was_active="$3"
  local clash_was_active="$4"
  local name=""
  local target=""
  local name_target=""

  for name_target in \
    "file-config:${FILE_CONFIG_PATH}" \
    "clash-config:${CLASH_CONFIG_PATH}" \
    "certificate:${CERT_PATH}" \
    "key:${KEY_PATH}" \
    "certificate-ip:${CERT_IP_PATH}"; do
    name="${name_target%%:*}"
    target="${name_target#*:}"
    if [[ -e "${backup_dir}/${name}" ]]; then
      cp -a -- "${backup_dir}/${name}" "${target}"
    else
      rm -f -- "${target}"
    fi
  done

  if [[ -d "${backup_dir}/clash-payload" ]]; then
    if [[ -d "${CLASH_PAYLOAD_DIR}" ]]; then
      mv -- "${CLASH_PAYLOAD_DIR}" "${backup_dir}/failed-clash-payload"
    fi
    mv -- "${backup_dir}/clash-payload" "${CLASH_PAYLOAD_DIR}"
  fi
  if validate_public_address "${old_certificate_address}"; then
    write_certificate_automation "${old_certificate_address}" >/dev/null 2>&1 || true
  fi
  (( file_was_active == 0 )) || systemctl restart "${FILE_SERVICE_NAME}.service" >/dev/null 2>&1 || true
  (( clash_was_active == 0 )) || systemctl restart "${CLASH_SERVICE_NAME}.service" >/dev/null 2>&1 || true
}

reconcile_public_ip() {
  local confirmation="${1:-}"
  local current_address=""
  local old_certificate_address=""
  local backup_dir=""
  local file_was_active=0
  local clash_was_active=0
  local reconcile_complete=0

  current_address="$(get_publication_address)" || return 1
  if audit_public_ip >/dev/null 2>&1; then
    # 即使地址和证书已经一致，也重写续期钩子。稳定入口事务回滚时
    # 会恢复旧证书；这里确保钩子随恢复后的地址一同收敛。
    install_certbot
    write_certificate_automation "${current_address}"
    enable_certificate_timer
    echo "公网发布地址未变化：${current_address}；发布地址、证书和自动检查均已就绪。"
    return 0
  fi

  [[ "${confirmation}" == "--yes" ]] || {
    echo "检测到公网发布地址差异。确认自动申请新证书并重建发布地址时，请加 --yes。" >&2
    return 1
  }

  install_certbot
  install -d -m 750 "${CONFIG_DIR}"
  backup_dir="$(mktemp -d "${CONFIG_DIR}/.public-ip-reconcile.XXXXXX")"
  if [[ -r "${CERT_IP_PATH}" ]]; then
    old_certificate_address="$(tr -d '\r\n' < "${CERT_IP_PATH}")"
  fi
  if systemctl is-active --quiet "${FILE_SERVICE_NAME}.service"; then
    file_was_active=1
  fi
  if systemctl is-active --quiet "${CLASH_SERVICE_NAME}.service"; then
    clash_was_active=1
  fi

  [[ ! -e "${FILE_CONFIG_PATH}" ]] || cp -a -- "${FILE_CONFIG_PATH}" "${backup_dir}/file-config"
  [[ ! -e "${CLASH_CONFIG_PATH}" ]] || cp -a -- "${CLASH_CONFIG_PATH}" "${backup_dir}/clash-config"
  [[ ! -e "${CERT_PATH}" ]] || cp -a -- "${CERT_PATH}" "${backup_dir}/certificate"
  [[ ! -e "${KEY_PATH}" ]] || cp -a -- "${KEY_PATH}" "${backup_dir}/key"
  [[ ! -e "${CERT_IP_PATH}" ]] || cp -a -- "${CERT_IP_PATH}" "${backup_dir}/certificate-ip"
  [[ ! -d "${CLASH_PAYLOAD_DIR}" ]] || cp -a -- "${CLASH_PAYLOAD_DIR}" "${backup_dir}/clash-payload"
  trap 'if (( reconcile_complete == 0 )); then restore_public_ip_reconcile "${backup_dir}" "${old_certificate_address}" "${file_was_active}" "${clash_was_active}"; fi; rm -rf --one-file-system -- "${backup_dir}"' RETURN

  obtain_public_certificate "${current_address}" || return 1
  deploy_public_certificate "${current_address}" || return 1
  write_certificate_automation "${current_address}" || return 1

  if [[ -r "${CLASH_CONFIG_PATH}" ]]; then
    use_clash_service
    refresh_clash_subscriptions "" "${current_address}" || return 1
  fi
  if [[ -r "${FILE_CONFIG_PATH}" ]]; then
    update_config_server_address "${FILE_CONFIG_PATH}" "${current_address}" || return 1
    if (( file_was_active == 1 )); then
      systemctl restart "${FILE_SERVICE_NAME}.service" || return 1
      sleep 1
      systemctl is-active --quiet "${FILE_SERVICE_NAME}.service" || return 1
    fi
  fi
  audit_public_ip >/dev/null || return 1
  enable_certificate_timer
  use_file_service
  reconcile_complete=1
  rm -rf --one-file-system -- "${backup_dir}"
  backup_dir=""
  trap - RETURN
  echo "公网发布地址已对账为 ${current_address}；证书、Clash 订阅和普通文件地址已同步。"
}

install_and_run() {
  local source_path=""
  local requested_path="${1:-}"
  local port=""
  local existing_token=""
  local existing_port=""
  local existing_name=""
  local existing_address=""
  local current_address=""
  local server_address=""
  local token=""
  local download_name=""
  local sha256=""
  local file_size=""

  source_path="$(resolve_source_file "${requested_path:-${DEFAULT_SOURCE_FILE}}")"
  download_name="$(basename -- "${source_path}")"

  install_dependencies
  create_service_user
  prepare_directories
  install_certbot
  current_address="$(get_publication_address)"

  existing_token="$(load_existing_token)"
  if validate_token "${existing_token}"; then
    existing_port="$(read_config_field port 2>/dev/null || true)"
    existing_name="$(read_config_field download_name 2>/dev/null || true)"
    existing_address="$(read_config_field server_address 2>/dev/null || true)"
    if ! validate_port "${existing_port}" || ! validate_download_name "${existing_name}" ||
       ! validate_public_address "${existing_address}" || [[ "${existing_address}" != "${current_address}" ]]; then
      echo "旧配置不完整，将生成新链接。" >&2
      if [[ -n "${existing_address}" ]] && [[ "${existing_address}" != "${current_address}" ]]; then
        echo "旧地址 ${existing_address} 与当前发布地址 ${current_address} 不一致，旧链接已无法继续使用。" >&2
      fi
      existing_token=""
      existing_port=""
      existing_name=""
      existing_address=""
    fi
  fi

  token="$(choose_download_token "${existing_token}")"
  if [[ -n "${existing_token}" ]] && [[ "${token}" == "${existing_token}" ]]; then
    # 下载链接由地址、端口、密钥和文件名共同组成，沿用时必须完整保留四者。
    port="$((10#${existing_port}))"
    download_name="${existing_name}"
    server_address="${existing_address}"
    echo "将完整沿用旧链接（地址、端口、密钥和下载文件名均保持不变）。"
  else
    local default_port="${existing_port:-${DEFAULT_PORT}}"
    if [[ "${FILE_INSTALL_NONINTERACTIVE}" == "1" ]]; then
      port="${FILE_INSTALL_PORT:-${default_port}}"
    else
      port="$(prompt_optional "请输入监听端口 [默认 ${default_port}]，直接回车使用默认值: ")"
      port="${port:-${default_port}}"
    fi
    if ! validate_port "${port}"; then
      echo "端口无效: ${port}"
      exit 1
    fi
    port="$((10#${port}))"
    server_address="${current_address}"
  fi

  if ! validate_download_name "${download_name}"; then
    echo "文件名无效或过长: ${download_name}"
    exit 1
  fi
  ensure_independent_port "${port}"

  obtain_public_certificate "${server_address}"
  deploy_public_certificate "${server_address}"
  write_server_program
  write_systemd_service
  write_certificate_automation "${server_address}"
  install_payload "${source_path}"

  sha256="$(sha256sum -- "${PAYLOAD_PATH}" | awk '{print $1}')"
  file_size="$(stat -c '%s' -- "${PAYLOAD_PATH}")"
  write_config "${port}" "${server_address}" "${token}" "${download_name}" "${sha256}" "${file_size}"
  enable_service
  enable_certificate_timer

  echo
  echo "文件服务已安装并启动。"
  echo "源文件: ${source_path}"
  echo "已安全复制到: ${PAYLOAD_PATH}"
  echo "请确认防火墙和云安全组已放行 TCP ${port} 端口。"
  echo "TCP 80 仅供 Let’s Encrypt 签发和自动续期验证，不运行常驻文件服务。"
  echo
  show_link
}

rotate_link() {
  local new_token=""
  local temp_config=""

  if [[ ! -r "${CONFIG_PATH}" ]]; then
    echo "未找到配置文件 ${CONFIG_PATH}，请先执行 ${INSTALL_COMMAND}。"
    exit 1
  fi

  new_token="$(openssl rand -hex 32)"
  temp_config="$(mktemp "${CONFIG_DIR}/.config.XXXXXX")"
  trap 'rm -f -- "${temp_config}"' RETURN

  python3 - "${CONFIG_PATH}" "${temp_config}" "${new_token}" <<'PYTHON'
import json
import os
import sys

source, target, token = sys.argv[1:]
with open(source, "r", encoding="utf-8") as config_file:
    config = json.load(config_file)
if isinstance(config.get("downloads"), list):
    import secrets
    for item in config.get("downloads", []):
        item["token"] = secrets.token_hex(32)
else:
    config["token"] = token
with open(target, "w", encoding="utf-8") as config_file:
    json.dump(config, config_file, ensure_ascii=False, indent=2)
    config_file.write("\n")
    config_file.flush()
    os.fsync(config_file.fileno())
PYTHON

  install -m 640 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  rm -f -- "${temp_config}"
  trap - RETURN
  systemctl restart "${SERVICE_NAME}"

  echo "下载链接已更新，全部旧链接立即失效。"
  show_link
}

rotate_clash_item_token() {
  local peer_name="$1"
  local temp_config=""
  local rollback_config=""

  [[ "${peer_name}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || {
    echo "节点名称格式不正确。" >&2
    return 1
  }
  [[ -r "${CONFIG_PATH}" ]] || { echo "Clash 订阅服务尚未安装。" >&2; return 1; }
  temp_config="$(mktemp "${CONFIG_DIR}/.clash-config.XXXXXX")"
  rollback_config="$(mktemp "${CONFIG_DIR}/.clash-config.rollback.XXXXXX")"
  cp -- "${CONFIG_PATH}" "${rollback_config}"
  trap 'rm -f -- "${temp_config:-}" "${rollback_config:-}"' RETURN

  python3 - "${CONFIG_PATH}" "${temp_config}" "${peer_name}" <<'PYTHON'
import json
import os
import secrets
import sys

source, target, peer_name = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    config = json.load(handle)
downloads = config.get("downloads")
if config.get("mode") != "clash" or not isinstance(downloads, list):
    raise SystemExit("当前不是 Clash 多订阅配置")
matches = [item for item in downloads if isinstance(item, dict) and item.get("peer_name") == peer_name]
if len(matches) != 1:
    raise SystemExit("未找到唯一订阅节点")
matches[0]["token"] = secrets.token_hex(32)
with open(target, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PYTHON

  install -m 640 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  if ! systemctl restart "${SERVICE_NAME}" || ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    install -m 640 -o root -g "${SERVICE_GROUP}" "${rollback_config}" "${CONFIG_PATH}"
    systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    echo "令牌轮换失败，已恢复原链接。" >&2
    return 1
  fi
  rm -f -- "${temp_config}" "${rollback_config}"
  temp_config=""
  rollback_config=""
  trap - RETURN
  echo "节点 ${peer_name} 的订阅令牌已轮换，旧链接立即失效。"
}

upgrade_server_runtime() {
  local unit=""
  local upgraded="0"
  if [[ ! -r "${FILE_CONFIG_PATH}" && ! -r "${CLASH_CONFIG_PATH}" ]]; then
    echo "普通文件和 Clash 订阅服务均未安装，无需升级运行程序。"
    return 0
  fi
  install -d -m 755 -o root -g root "${SERVER_DIR}"
  write_server_program
  for unit in "${FILE_SERVICE_NAME}.service" "${CLASH_SERVICE_NAME}.service"; do
    if systemctl is-active --quiet "${unit}"; then
      systemctl restart "${unit}"
      systemctl is-active --quiet "${unit}"
      upgraded=$((upgraded + 1))
    fi
  done
  echo "文件下载运行程序已升级；已安全重启 ${upgraded} 个运行中的服务。"
}

set_service_port() {
  local requested_port="$1"
  local current_port=""
  local temp_config=""
  local rollback_config=""
  local was_active="0"

  validate_port "${requested_port}" || { echo "端口必须是 1–65535 的整数。" >&2; return 1; }
  [[ -r "${CONFIG_PATH}" ]] || { echo "${SERVICE_DESCRIPTION}尚未安装。" >&2; return 1; }
  requested_port="$((10#${requested_port}))"
  current_port="$(read_config_field port)"
  [[ "${current_port}" != "${requested_port}" ]] || { echo "新端口与当前端口相同。" >&2; return 1; }
  ensure_independent_port "${requested_port}"

  temp_config="$(mktemp "${CONFIG_DIR}/.port-config.XXXXXX")"
  rollback_config="$(mktemp "${CONFIG_DIR}/.port-rollback.XXXXXX")"
  cp -- "${CONFIG_PATH}" "${rollback_config}"
  if systemctl is-active --quiet "${SERVICE_NAME}"; then was_active="1"; fi
  trap 'rm -f -- "${temp_config:-}" "${rollback_config:-}"' RETURN
  python3 - "${CONFIG_PATH}" "${temp_config}" "${requested_port}" <<'PYTHON'
import json
import os
import sys

source, target, port = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    value = json.load(handle)
value["port"] = int(port)
with open(target, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(value, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PYTHON
  install -m 640 -o root -g "${SERVICE_GROUP}" "${temp_config}" "${CONFIG_PATH}"
  if [[ "${was_active}" == "1" ]]; then
    if ! systemctl restart "${SERVICE_NAME}" || ! systemctl is-active --quiet "${SERVICE_NAME}" || \
       ! ss -H -lnt "sport = :${requested_port}" | grep -q .; then
      install -m 640 -o root -g "${SERVICE_GROUP}" "${rollback_config}" "${CONFIG_PATH}"
      systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
      echo "端口切换失败，已恢复 ${current_port}/TCP。" >&2
      return 1
    fi
  fi
  rm -f -- "${temp_config}" "${rollback_config}"
  temp_config=""
  rollback_config=""
  trap - RETURN
  echo "${SERVICE_DESCRIPTION}端口已从 ${current_port}/TCP 改为 ${requested_port}/TCP。"
}

usage() {
  cat <<EOF
说明:
  普通 install 默认读取 shared_file.yaml；install-clash 默认读取 clash_skeleton.yaml。
  也可以在安装命令后指定文件路径。机场和出口参数保存在 ${CLASH_INPUT_CONFIG}。
  普通服务默认端口 ${DEFAULT_FILE_PORT}，Clash 服务默认端口 ${DEFAULT_CLASH_PORT}，两者独立运行。

普通文件服务:
  install [文件]      安装或更新
  start               启动
  stop                停止
  restart             重启
  status              状态
  info                 配置和链接
  link                 显示链接
  rotate               更换链接

Clash 订阅服务:
  install-clash [YAML] 安装或更新
  refresh-clash [YAML] 使用已保存参数同步当前节点
  start-clash          启动
  stop-clash           停止
  restart-clash        重启
  status-clash         状态
  info-clash           配置和链接
  link-clash           显示链接
  rotate-clash         更换链接
  rotate-clash-node 节点 仅轮换指定节点的链接

二维码:
  qr [file/节点/编号]   选择普通或 Clash 链接并显示二维码

全部服务:
  audit-public-ip     检查 HTTPS 发布地址、证书与当前公网 IP
  reconcile-public-ip --yes
                      IP 变化后保留令牌并同步证书、订阅和文件地址
  upgrade-runtime      升级下载运行程序，不修改链接、证书或文件配置
  stop-all             停止普通和 Clash 服务
  uninstall-all        卸载全部服务并删除配置和订阅
EOF
}

main() {
  require_root
  check_debian

  local action="${1:-}"
  case "${action}" in
    install)
      use_file_service
      install_and_run "${2:-}"
      ;;
    install-clash)
      use_clash_service
      install_clash_and_run "${2:-}"
      ;;
    refresh-clash)
      use_clash_service
      refresh_clash_subscriptions "${2:-}"
      ;;
    audit-public-ip)
      audit_public_ip
      ;;
    reconcile-public-ip)
      reconcile_public_ip "${2:-}"
      ;;
    start)
      use_file_service
      start_service
      ;;
    stop)
      use_file_service
      stop_service
      ;;
    restart)
      use_file_service
      systemctl restart "${SERVICE_NAME}"
      status_service
      ;;
    status)
      use_file_service
      status_service
      ;;
    info)
      use_file_service
      info_service
      ;;
    link)
      use_file_service
      show_link
      ;;
    rotate)
      use_file_service
      rotate_link
      ;;
    start-clash)
      use_clash_service
      start_service
      ;;
    stop-clash)
      use_clash_service
      stop_service
      ;;
    stop-all)
      stop_all_services
      ;;
    upgrade-runtime)
      upgrade_server_runtime
      ;;
    uninstall-all)
      uninstall_all_services "${2:-}"
      ;;
    restart-clash)
      use_clash_service
      systemctl restart "${SERVICE_NAME}"
      status_service
      ;;
    status-clash)
      use_clash_service
      status_service
      ;;
    info-clash)
      use_clash_service
      info_service
      ;;
    link-clash)
      use_clash_service
      show_link
      ;;
    qr)
      show_qr "${2:-}"
      ;;
    rotate-clash)
      use_clash_service
      rotate_link
      ;;
    rotate-clash-node)
      [[ -n "${2:-}" ]] || { echo "请提供节点名称。" >&2; exit 1; }
      use_clash_service
      rotate_clash_item_token "${2}"
      ;;
    set-port)
      case "${2:-}" in
        file) use_file_service ;;
        clash) use_clash_service ;;
        *) echo "服务只能是 file 或 clash。" >&2; exit 1 ;;
      esac
      [[ -n "${3:-}" && -z "${4:-}" ]] || { echo "用法：set-port <file|clash> <端口>" >&2; exit 1; }
      set_service_port "${3}"
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
