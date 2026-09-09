#!/usr/bin/env bash
# server-kit Linux AWG 客户端一键配置器
set -Eeuo pipefail
umask 077

CONFIG_DIR="${SERVER_KIT_AWG_CONFIG_DIR:-/etc/amnezia/amneziawg}"
AWG_QUICK_COMMAND="${SERVER_KIT_AWG_QUICK_COMMAND:-awg-quick}"
AWG_COMMAND="${SERVER_KIT_AWG_COMMAND:-awg}"
SYSTEMCTL_COMMAND="${SERVER_KIT_AWG_SYSTEMCTL_COMMAND:-systemctl}"
JOURNALCTL_COMMAND="${SERVER_KIT_AWG_JOURNALCTL_COMMAND:-journalctl}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ACTION="${1:-install}"
VALUE="${2:-}"

PROFILES=(main backup1)

interface_for_profile() {
  case "$1" in
    main) echo "sk-awg-main" ;;
    backup1) echo "sk-awg-backup1" ;;
    backup2) echo "sk-awg-backup2" ;;
    *) echo "入口只能是 main、backup1 或 backup2。" >&2; return 2 ;;
  esac
}

label_for_profile() {
  case "$1" in
    main) echo "主入口" ;;
    backup1) echo "备用 1" ;;
    backup2) echo "备用 2" ;;
  esac
}

unit_for_profile() {
  echo "awg-quick@$(interface_for_profile "$1").service"
}

config_for_profile() {
  echo "${CONFIG_DIR}/$(interface_for_profile "$1").conf"
}

require_root() {
  if (( EUID != 0 )) && [[ "${SERVER_KIT_AWG_TESTING:-0}" != "1" ]]; then
    echo "请使用 sudo 运行配置、切换、停用或移除操作。" >&2
    exit 1
  fi
}

require_runtime() {
  local command_name
  for command_name in "$AWG_QUICK_COMMAND" "$AWG_COMMAND" "$SYSTEMCTL_COMMAND"; do
    command -v "$command_name" >/dev/null 2>&1 || {
      echo "缺少 ${command_name}。请先按页面上的官方说明安装 AmneziaWG。" >&2
      exit 1
    }
  done
  "$SYSTEMCTL_COMMAND" list-unit-files 'awg-quick@.service' --no-legend 2>/dev/null | grep -q 'awg-quick@.service' || {
    echo "没有找到 awg-quick@.service，请确认 AmneziaWG 工具已完整安装。" >&2
    exit 1
  }
}

runtime_is_ready() {
  command -v "$AWG_QUICK_COMMAND" >/dev/null 2>&1 &&
    command -v "$AWG_COMMAND" >/dev/null 2>&1 &&
    command -v "$SYSTEMCTL_COMMAND" >/dev/null 2>&1 &&
    "$SYSTEMCTL_COMMAND" list-unit-files 'awg-quick@.service' --no-legend 2>/dev/null | grep -q 'awg-quick@.service'
}

install_runtime() {
  local distribution fingerprint armored_key exported_key actual_fingerprint current_headers
  local -a replacement_kernel_packages=()
  runtime_is_ready && return 0
  require_root
  [[ "${SERVER_KIT_AWG_TESTING:-0}" != "1" ]] || {
    echo "测试环境缺少模拟的 AmneziaWG 工具。" >&2
    return 1
  }
  command -v apt-get >/dev/null 2>&1 || {
    echo "自动安装目前只支持 Debian 和 Ubuntu。" >&2
    return 1
  }
  [[ -r /etc/os-release ]] || { echo "无法识别 Linux 发行版。" >&2; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  distribution="${ID:-}"
  [[ "$distribution" == "debian" || "$distribution" == "ubuntu" ]] || {
    echo "自动安装目前只支持 Debian 和 Ubuntu。" >&2
    return 1
  }

  echo "[1/3] 安装 AWG 构建依赖和当前内核头文件..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl dkms gnupg
  if [[ "$distribution" == "ubuntu" ]]; then
    # add-apt-repository 只用于 Ubuntu 的 PPA 配置。Debian 13 已不再提供
    # software-properties-common，且 Debian 分支会直接写入带 signed-by 的源。
    apt-get install -y software-properties-common python3-launchpadlib
  fi
  current_headers="linux-headers-$(uname -r)"
  if ! apt-cache show "$current_headers" >/dev/null 2>&1; then
    echo "当前内核 $(uname -r) 已无对应 headers 候选。"
    if [[ "$distribution" == "debian" ]]; then
      if [[ "$(uname -r)" == *-cloud-amd64 ]] &&
         apt-cache show linux-image-cloud-amd64 linux-headers-cloud-amd64 >/dev/null 2>&1; then
        replacement_kernel_packages=(linux-image-cloud-amd64 linux-headers-cloud-amd64)
      else
        replacement_kernel_packages=(linux-image-amd64 linux-headers-amd64)
      fi
    else
      replacement_kernel_packages=(linux-generic linux-headers-generic)
    fi
    apt-get install -y "${replacement_kernel_packages[@]}"
    echo "已安装发行版当前标准内核与 headers。请重启后再次运行本脚本。" >&2
    return 2
  fi
  apt-get install -y "$current_headers"

  echo "[2/3] 配置 Amnezia 官方软件源..."
  if [[ "$distribution" == "ubuntu" ]]; then
    add-apt-repository -y ppa:amnezia/ppa
  else
    fingerprint="75C9DD72C799870E310542E24166F2C257290828"
    armored_key="$(mktemp)"
    exported_key="$(mktemp)"
    if ! curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${fingerprint}" -o "$armored_key" ||
       ! gpg --batch --dearmor <"$armored_key" >"$exported_key"; then
      rm -f "$armored_key" "$exported_key"
      echo "无法获取 Amnezia PPA 签名密钥。" >&2
      return 1
    fi
    actual_fingerprint="$(gpg --batch --show-keys --with-colons "$exported_key" 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')"
    if [[ "$actual_fingerprint" != "$fingerprint" ]]; then
      rm -f "$armored_key" "$exported_key"
      echo "Amnezia PPA 签名密钥指纹不匹配，已停止安装。" >&2
      return 1
    fi
    install -m 0644 "$exported_key" /usr/share/keyrings/amnezia.gpg
    printf '%s\n' \
      'deb [signed-by=/usr/share/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' \
      'deb-src [signed-by=/usr/share/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' \
      >/etc/apt/sources.list.d/amnezia.list
    rm -f "$armored_key" "$exported_key"
  fi

  echo "[3/3] 安装并验证 AmneziaWG..."
  apt-get update
  apt-get install -y amneziawg
  modprobe amneziawg 2>/dev/null || true
  runtime_is_ready || {
    echo "AmneziaWG 已安装，但工具或 systemd 模板不完整。请检查 DKMS 与当前内核头文件。" >&2
    return 1
  }
}

config_value() {
  local config_file="$1" wanted="$2"
  awk -F '=' -v wanted="$wanted" '
    {
      key=$1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      if (key == wanted) {
        value=substr($0, index($0, "=") + 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        print value
        exit
      }
    }
  ' "$config_file"
}

validate_safe_directives() {
  local config_file="$1" raw_line line key
  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    line="${raw_line%%#*}"
    [[ -n "${line//[[:space:]]/}" ]] || continue
    [[ "$line" =~ ^[[:space:]]*\[(Interface|Peer)\][[:space:]]*$ ]] && continue
    key="${line%%=*}"
    key="${key//[[:space:]]/}"
    case "$key" in
      PrivateKey|Address|MTU|Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|I1|PublicKey|PresharedKey|Endpoint|AllowedIPs|PersistentKeepalive) ;;
      PreUp|PostUp|PreDown|PostDown)
        echo "配置不允许包含可执行钩子：${key}。" >&2
        return 1
        ;;
      *)
        echo "配置包含不支持的字段：${key}。请重新从 server-kit 下载。" >&2
        return 1
        ;;
    esac
  done <"$config_file"
}

validate_profile() {
  local config_file="$1" key value allowed_ips validation_dir validation_file address_ip address_host endpoint_port
  [[ -f "$config_file" ]] || { echo "缺少配置：${config_file}" >&2; return 1; }
  validate_safe_directives "$config_file"
  grep -Eq '^[[:space:]]*\[Interface\][[:space:]]*$' "$config_file" || { echo "配置缺少 [Interface]：${config_file}" >&2; return 1; }
  grep -Eq '^[[:space:]]*\[Peer\][[:space:]]*$' "$config_file" || { echo "配置缺少 [Peer]：${config_file}" >&2; return 1; }
  for key in PrivateKey PublicKey PresharedKey; do
    value="$(config_value "$config_file" "$key")"
    [[ "$value" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "${config_file} 的 ${key} 格式不正确。" >&2; return 1; }
  done
  value="$(config_value "$config_file" Address)"
  [[ "$value" =~ ^10\.20\.0\.[0-9]{1,3}/24$ ]] || { echo "${config_file} 不是 10.20.0.0/24 节点配置。" >&2; return 1; }
  address_ip="${value%/24}"
  address_host="${address_ip##*.}"
  (( address_host >= 2 && address_host <= 254 )) || { echo "${config_file} 的客户端地址超出可用范围。" >&2; return 1; }
  value="$(config_value "$config_file" Endpoint)"
  [[ "$value" =~ ^.+:[0-9]{1,5}$ ]] || { echo "${config_file} 的 Endpoint 格式不正确。" >&2; return 1; }
  endpoint_port="${value##*:}"
  (( endpoint_port >= 1 && endpoint_port <= 65535 )) || { echo "${config_file} 的 Endpoint 端口超出范围。" >&2; return 1; }
  allowed_ips="$(config_value "$config_file" AllowedIPs | tr -d '[:space:]')"
  [[ "$allowed_ips" == "10.20.0.0/24" ]] || { echo "${config_file} 的 AllowedIPs 不是 10.20.0.0/24。" >&2; return 1; }
  value="$(config_value "$config_file" PersistentKeepalive)"
  [[ "$value" =~ ^[0-9]+$ ]] || { echo "${config_file} 缺少 PersistentKeepalive。" >&2; return 1; }
  # awg-quick 会把配置文件名当作接口名；复制为短文件名后再校验，兼容较长的节点名称。
  validation_dir="$(mktemp -d)"
  validation_file="${validation_dir}/sk-check.conf"
  install -m 0600 "$config_file" "$validation_file"
  if ! "$AWG_QUICK_COMMAND" strip "$validation_file" >/dev/null; then
    rm -f "$validation_file"
    rmdir "$validation_dir"
    echo "${config_file} 无法通过 awg-quick 校验。" >&2
    return 1
  fi
  rm -f "$validation_file"
  rmdir "$validation_dir"
}

validate_configuration_set() {
  local prefix="$1" profile key expected actual
  for profile in "${PROFILES[@]}"; do
    validate_profile "${prefix}-${profile}.conf"
  done
  for key in PrivateKey Address PublicKey PresharedKey AllowedIPs S1 S2 S3 S4 H1 H2 H3 H4 I1; do
    expected="$(config_value "${prefix}-main.conf" "$key")"
    [[ -n "$expected" ]] || { echo "主配置缺少 ${key}。" >&2; return 1; }
    for profile in backup1; do
      actual="$(config_value "${prefix}-${profile}.conf" "$key")"
      [[ "$actual" == "$expected" ]] || {
        echo "两份配置不属于同一个节点：${key} 不一致。" >&2
        return 1
      }
    done
  done
}

caller_home() {
  local caller="${SUDO_USER:-${USER:-}}" home=""
  if [[ -n "$caller" ]] && command -v getent >/dev/null 2>&1; then
    home="$(getent passwd "$caller" | cut -d: -f6)"
  fi
  echo "${home:-${HOME:-/root}}"
}

find_configuration_prefix() {
  local requested_dir="${1:-}" home directory candidate newest="" newest_time=-1 modified
  local -a directories=() candidates=()
  local -A visited=()
  home="$(caller_home)"
  [[ -z "$requested_dir" ]] || directories+=("$requested_dir")
  directories+=("$SCRIPT_DIR" "$PWD" "$home/Downloads" "$home/下载")
  shopt -s nullglob
  for directory in "${directories[@]}"; do
    [[ -d "$directory" ]] || continue
    [[ -z "${visited[$directory]:-}" ]] || continue
    visited[$directory]=1
    for candidate in "$directory"/*-main.conf; do
      candidate="${candidate%-main.conf}"
      [[ -f "${candidate}-backup1.conf" ]] || continue
      candidates+=("$candidate")
    done
  done
  shopt -u nullglob
  ((${#candidates[@]} > 0)) || {
    echo "没有找到完整配置。请把脚本与 *-main.conf、*-backup1.conf 放在同一目录。" >&2
    return 1
  }
  for candidate in "${candidates[@]}"; do
    modified="$(stat -c %Y "${candidate}-main.conf")"
    if (( modified > newest_time )); then newest="$candidate"; newest_time="$modified"; fi
  done
  if ((${#candidates[@]} > 1)); then
    echo "检测到 ${#candidates[@]} 组配置，将使用最近下载的：$(basename "$newest")" >&2
  fi
  echo "$newest"
}

active_profile() {
  local profile
  for profile in main backup1 backup2; do
    if "$SYSTEMCTL_COMMAND" is-active --quiet "$(unit_for_profile "$profile")"; then
      echo "$profile"
      return 0
    fi
  done
  return 1
}

stop_all() {
  local profile
  for profile in main backup1 backup2; do
    "$SYSTEMCTL_COMMAND" disable --now "$(unit_for_profile "$profile")" >/dev/null 2>&1 || true
  done
}

start_profile() {
  local profile="$1"
  # 通过 systemctl enable --now 设置开机自启并立即连接。
  "$SYSTEMCTL_COMMAND" enable --now "$(unit_for_profile "$profile")"
}

restore_previous() {
  local backup_dir="$1" previous_profile="$2" profile config_file backup_file
  stop_all
  for profile in "${PROFILES[@]}"; do
    config_file="$(config_for_profile "$profile")"
    backup_file="${backup_dir}/$(basename "$config_file")"
    rm -f "$config_file"
    [[ ! -f "$backup_file" ]] || install -m 0600 "$backup_file" "$config_file"
  done
  [[ -z "$previous_profile" ]] || start_profile "$previous_profile" >/dev/null 2>&1 || true
}

cleanup_transaction_dirs() {
  local backup_dir="$1" stage_dir="$2" profile file_name
  for profile in "${PROFILES[@]}"; do
    file_name="$(basename "$(config_for_profile "$profile")")"
    rm -f "${backup_dir}/${file_name}" "${stage_dir}/${file_name}"
  done
  rmdir "$backup_dir" 2>/dev/null || true
  rmdir "$stage_dir" 2>/dev/null || true
}

install_configuration() {
  local requested_dir="$1" prefix backup_dir stage_dir previous_profile="" profile config_file file_name
  require_root
  install_runtime
  require_runtime
  prefix="$(find_configuration_prefix "$requested_dir")"
  echo "正在校验：$(basename "$prefix")"
  validate_configuration_set "$prefix"
  if [[ "${SERVER_KIT_AWG_TESTING:-0}" == "1" ]]; then
    mkdir -p "$CONFIG_DIR"
  else
    install -d -m 0700 "$CONFIG_DIR"
  fi
  backup_dir="$(mktemp -d)"
  stage_dir="$(mktemp -d "${CONFIG_DIR}/.server-kit-stage.XXXXXX")"
  previous_profile="$(active_profile || true)"
  for profile in "${PROFILES[@]}"; do
    config_file="$(config_for_profile "$profile")"
    file_name="$(basename "$config_file")"
    [[ ! -f "$config_file" ]] || cp -p "$config_file" "$backup_dir/"
    if ! install -m 0600 "${prefix}-${profile}.conf" "${stage_dir}/${file_name}"; then
      cleanup_transaction_dirs "$backup_dir" "$stage_dir"
      return 1
    fi
  done
  stop_all
  for profile in "${PROFILES[@]}"; do
    config_file="$(config_for_profile "$profile")"
    file_name="$(basename "$config_file")"
    if ! mv -f "${stage_dir}/${file_name}" "$config_file"; then
      echo "写入配置失败，正在恢复原配置。" >&2
      restore_previous "$backup_dir" "$previous_profile"
      cleanup_transaction_dirs "$backup_dir" "$stage_dir"
      return 1
    fi
  done
  if ! start_profile main; then
    echo "主入口启动失败，正在恢复原配置。" >&2
    restore_previous "$backup_dir" "$previous_profile"
    "$JOURNALCTL_COMMAND" -u "$(unit_for_profile main)" --no-pager -n 20 2>/dev/null || true
    cleanup_transaction_dirs "$backup_dir" "$stage_dir"
    return 1
  fi
  cleanup_transaction_dirs "$backup_dir" "$stage_dir"
  echo
  echo "配置完成：主入口已连接并设置为开机自启。"
  echo "备用入口已保存，发生异常时可用本脚本切换。"
  show_status
}

show_status() {
  local selected="" profile state startup interface endpoint handshake
  selected="$(active_profile || true)"
  echo "server-kit · Linux AWG 状态"
  for profile in "${PROFILES[@]}"; do
    interface="$(interface_for_profile "$profile")"
    state="已停用"
    startup="不自启"
    [[ "$selected" != "$profile" ]] || state="已连接"
    "$SYSTEMCTL_COMMAND" is-enabled --quiet "$(unit_for_profile "$profile")" 2>/dev/null && startup="开机自启"
    printf '  %-8s  %-8s  %-8s  %s\n' "$(label_for_profile "$profile")" "$state" "$startup" "$(config_for_profile "$profile")"
  done
  if [[ -n "$selected" ]]; then
    interface="$(interface_for_profile "$selected")"
    # awg show 只展示运行状态，不读取或输出客户端私钥。
    endpoint="$($AWG_COMMAND show "$interface" endpoints 2>/dev/null | awk 'NR == 1 {print $2}')"
    handshake="$($AWG_COMMAND show "$interface" latest-handshakes 2>/dev/null | awk 'NR == 1 {print $2}')"
    echo "当前入口：$(label_for_profile "$selected")${endpoint:+ · ${endpoint}}"
    if [[ -n "$handshake" && "$handshake" != "0" ]]; then
      echo "最近握手：$(date -d "@${handshake}" '+%F %T' 2>/dev/null || echo "$handshake")"
    else
      echo "最近握手：暂无"
    fi
  else
    echo "当前入口：未连接"
  fi
}

set_autostart() {
  local mode="$1" selected="" profile unit
  require_root
  require_runtime
  case "$mode" in
    on)
      selected="$(active_profile || true)"
      selected="${selected:-main}"
      [[ -f "$(config_for_profile "$selected")" ]] || { echo "尚未安装 AWG 配置。" >&2; return 1; }
      for profile in main backup1 backup2; do
        unit="$(unit_for_profile "$profile")"
        if [[ "$profile" == "$selected" ]]; then
          "$SYSTEMCTL_COMMAND" enable "$unit" >/dev/null
        else
          "$SYSTEMCTL_COMMAND" disable "$unit" >/dev/null 2>&1 || true
        fi
      done
      echo "已为 $(label_for_profile "$selected") 开启开机自启；当前连接未中断。"
      ;;
    off)
      for profile in main backup1 backup2; do
        "$SYSTEMCTL_COMMAND" disable "$(unit_for_profile "$profile")" >/dev/null 2>&1 || true
      done
      echo "已关闭 AWG 开机自启；当前连接保持不变。"
      ;;
    *) echo "autostart 只接受 on 或 off。" >&2; return 2 ;;
  esac
  show_status
}

enable_connection() {
  local profile="${1:-main}" previous_profile="" item
  require_root
  require_runtime
  interface_for_profile "$profile" >/dev/null
  [[ -f "$(config_for_profile "$profile")" ]] || {
    echo "尚未安装 $(label_for_profile "$profile") 配置，请先运行 awg-install。" >&2
    return 1
  }
  previous_profile="$(active_profile || true)"
  if [[ "$previous_profile" == "$profile" ]]; then
    for item in main backup1 backup2; do
      if [[ "$item" == "$profile" ]]; then
        "$SYSTEMCTL_COMMAND" enable "$(unit_for_profile "$item")" >/dev/null
      else
        "$SYSTEMCTL_COMMAND" disable "$(unit_for_profile "$item")" >/dev/null 2>&1 || true
      fi
    done
    echo "$(label_for_profile "$profile")已经运行，已恢复开机自启。"
    show_status
    return
  fi
  stop_all
  if ! start_profile "$profile"; then
    echo "$(label_for_profile "$profile")启动失败，正在恢复原入口。" >&2
    [[ -z "$previous_profile" ]] || start_profile "$previous_profile" >/dev/null 2>&1 || true
    return 1
  fi
  echo "已启动$(label_for_profile "$profile")并设置为开机自启。"
  show_status
}

use_profile() {
  local profile="$1" previous_profile=""
  require_root
  require_runtime
  interface_for_profile "$profile" >/dev/null
  [[ -f "$(config_for_profile "$profile")" ]] || { echo "尚未安装 $(label_for_profile "$profile") 配置。" >&2; return 1; }
  previous_profile="$(active_profile || true)"
  [[ "$previous_profile" != "$profile" ]] || { echo "$(label_for_profile "$profile") 已经在使用。"; show_status; return; }
  stop_all
  if ! start_profile "$profile"; then
    echo "$(label_for_profile "$profile") 启动失败，正在恢复原入口。" >&2
    [[ -z "$previous_profile" ]] || start_profile "$previous_profile" >/dev/null 2>&1 || true
    return 1
  fi
  echo "已切换到 $(label_for_profile "$profile")。"
  show_status
}

disable_connection() {
  require_root
  require_runtime
  stop_all
  echo "AWG 已停用，主入口和备用入口配置仍保留。"
}

remove_configuration() {
  local confirmation="${1:-}" profile
  require_root
  require_runtime
  if [[ "$confirmation" != "--yes" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "将停用 AWG 并删除托管配置，输入 yes：" confirmation
      [[ "$confirmation" == "yes" ]] || { echo "已取消。"; return; }
    else
      echo "彻底移除需要追加 --yes。" >&2
      return 2
    fi
  fi
  stop_all
  for profile in main backup1 backup2; do rm -f "$(config_for_profile "$profile")"; done
  echo "已移除 server-kit 管理的 Linux AWG 配置；其他 AWG 接口未改动。"
}

usage() {
  cat <<'EOF'
server-kit Linux 节点综合管理器 · AWG 子命令

用法：
  sudo bash ./server-kit-node-linux.sh awg-install [配置目录]  安装 AWG、导入配置并启用主入口
  sudo bash ./server-kit-node-linux.sh awg-status              查看状态与最近握手
  sudo bash ./server-kit-node-linux.sh awg-enable              启动主入口并恢复开机自启
  sudo bash ./server-kit-node-linux.sh awg-enable backup1      启动备用 1 并恢复开机自启
  sudo bash ./server-kit-node-linux.sh awg-use backup1         切换到备用 1
  sudo bash ./server-kit-node-linux.sh awg-use main            切回主入口
  sudo bash ./server-kit-node-linux.sh awg-autostart on         开启当前入口的开机自启
  sudo bash ./server-kit-node-linux.sh awg-autostart off        关闭自启但保持当前连接
  sudo bash ./server-kit-node-linux.sh awg-disable             停用但保留配置
  sudo bash ./server-kit-node-linux.sh awg-remove --yes         停用并删除托管配置
EOF
}

case "$ACTION" in
  install) install_configuration "$VALUE" ;;
  status) require_runtime; show_status ;;
  enable) enable_connection "${VALUE:-main}" ;;
  use) [[ -n "$VALUE" ]] || { usage; exit 2; }; use_profile "$VALUE" ;;
  autostart) [[ -n "$VALUE" ]] || { usage; exit 2; }; set_autostart "$VALUE" ;;
  disable) disable_connection ;;
  remove) remove_configuration "$VALUE" ;;
  help|-h|--help) usage ;;
  *) usage; exit 2 ;;
esac
