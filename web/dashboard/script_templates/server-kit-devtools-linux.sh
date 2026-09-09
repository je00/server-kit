#!/usr/bin/env bash
# server-kit Debian/Ubuntu 开发工具安装器
# 架构：软件目录 + 安装适配器。普通 APT 软件只需新增一条 register_tool。
set -euo pipefail

declare -a TOOL_IDS=()
declare -A TOOL_LABELS=()
declare -A TOOL_DESCRIPTIONS=()
declare -A TOOL_DETECTORS=()
declare -A TOOL_ADAPTERS=()
declare -A TOOL_PAYLOADS=()
declare -A TOOL_USER_PATHS=()

register_tool() {
  local id="$1" label="$2" description="$3" detector="$4" adapter="$5" payload="$6"
  local user_path="${7:-}"
  TOOL_IDS+=("$id")
  TOOL_LABELS["$id"]="$label"
  TOOL_DESCRIPTIONS["$id"]="$description"
  TOOL_DETECTORS["$id"]="$detector"
  TOOL_ADAPTERS["$id"]="$adapter"
  TOOL_PAYLOADS["$id"]="$payload"
  TOOL_USER_PATHS["$id"]="$user_path"
}

# 新增 Debian/Ubuntu 仓库内的软件时，只需登记一行 apt 类型工具。
register_tool "git" "Git" "版本控制" "git" "apt" "git"
register_tool "vim" "Vim" "终端文本编辑器" "vim" "apt" "vim"
register_tool "codex" "Codex" "OpenAI 编程代理" "codex" "codex" ""
register_tool "claude" "Claude Code" "Anthropic 编程代理" "claude" "claude" "" ".local/bin/claude"
register_tool "openclaw" "OpenClaw" "个人 AI 助手 CLI" "openclaw" "openclaw" "" ".openclaw/bin/openclaw"
register_tool "hermes" "Hermes" "Nous Research 自进化 AI 代理" "hermes" "hermes" "" ".hermes/bin/hermes"
register_tool "tmux" "tmux" "持久终端会话" "tmux" "apt" "tmux"
register_tool "mosh" "Mosh" "抗断线远程终端" "mosh-server" "apt" "mosh"
register_tool "docker" "Docker" "容器引擎与 Compose" "docker" "docker" ""

require_supported_system() {
  [[ -r /etc/os-release ]] || { echo "无法识别 Linux 发行版。" >&2; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" ]] || {
    echo "开发工具安装仅支持 Debian 和 Ubuntu。" >&2
    return 1
  }
  command -v apt-get >/dev/null 2>&1 || { echo "未找到 apt-get。" >&2; return 1; }
}

tool_installed() {
  local id="$1" target_user target_home user_path
  user_path="${TOOL_USER_PATHS[$id]}"
  if [[ -n "$user_path" ]]; then
    target_user="${SERVER_KIT_DEVTOOLS_USER:-${SUDO_USER:-${USER:-root}}}"
    target_home="$(getent passwd "$target_user" 2>/dev/null | cut -d: -f6)"
    [[ -n "$target_home" && -x "$target_home/$user_path" ]] && return 0
  fi
  command -v "${TOOL_DETECTORS[$id]}" >/dev/null 2>&1
}

show_catalog() {
  local id index=1 state method
  echo "可安装的开发工具"
  echo
  printf '  %-3s %-14s %-8s %s\n' "序号" "软件" "状态" "安装方式"
  for id in "${TOOL_IDS[@]}"; do
    state="未安装"
    tool_installed "$id" && state="已安装"
    case "${TOOL_ADAPTERS[$id]}" in
      apt) method="Debian / Ubuntu 官方 APT 仓库" ;;
      codex) method="OpenAI 官方 GitHub Release" ;;
      claude) method="Anthropic 官方原生安装器" ;;
      openclaw) method="OpenClaw 官方 CLI 安装器" ;;
      hermes) method="Nous Research 官方安装器" ;;
      docker) method="Docker 官方 APT 仓库" ;;
      *) method="未知" ;;
    esac
    printf '  %-3s %-14s %-8s %s\n' "$index" "${TOOL_LABELS[$id]}" "$state" "$method"
    index=$((index + 1))
  done
  echo
  echo "说明：Mosh 这里只安装软件，不开放防火墙端口；Docker 不会自动把用户加入 docker 组。"
}

declare -a SELECTED_IDS=()
resolve_selection() {
  local raw="$1" token id index
  declare -A seen=()
  SELECTED_IDS=()
  raw="${raw//,/ }"
  [[ -n "${raw// /}" ]] || { echo "没有选择任何软件。" >&2; return 1; }
  if [[ "$raw" == "all" || "$raw" == "全部" ]]; then
    SELECTED_IDS=("${TOOL_IDS[@]}")
    return 0
  fi
  for token in $raw; do
    id=""
    if [[ "$token" =~ ^[0-9]+$ ]]; then
      index=$((token - 1))
      (( index >= 0 && index < ${#TOOL_IDS[@]} )) && id="${TOOL_IDS[$index]}"
    else
      for candidate in "${TOOL_IDS[@]}"; do
        [[ "$candidate" == "$token" ]] && id="$candidate" && break
      done
    fi
    [[ -n "$id" ]] || { echo "无法识别的软件：$token" >&2; return 1; }
    if [[ -z "${seen[$id]:-}" ]]; then
      SELECTED_IDS+=("$id")
      seen["$id"]=1
    fi
  done
}

append_plan_header() {
  local plan_file="$1"
  cat >"$plan_file" <<'PLAN'
#!/usr/bin/env bash
set -euo pipefail
(( EUID == 0 )) || { echo "请使用 sudo 运行开发工具安装。" >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" ]] || {
  echo "仅支持 Debian 和 Ubuntu。" >&2
  exit 1
}
export DEBIAN_FRONTEND=noninteractive
TARGET_USER="${SERVER_KIT_DEVTOOLS_USER:-${SUDO_USER:-root}}"
id "$TARGET_USER" >/dev/null 2>&1 || { echo "目标用户不存在：$TARGET_USER" >&2; exit 1; }
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
PLAN
}

append_base_packages() {
  local plan_file="$1" id adapter package
  local -a packages=()
  declare -A included=()
  for id in "${SELECTED_IDS[@]}"; do
    adapter="${TOOL_ADAPTERS[$id]}"
    package="${TOOL_PAYLOADS[$id]}"
    if [[ "$adapter" == "apt" && -z "${included[$package]:-}" ]]; then
      packages+=("$package")
      included["$package"]=1
    fi
  done
  for id in "${SELECTED_IDS[@]}"; do
    case "${TOOL_ADAPTERS[$id]}" in
      codex)
        for package in ca-certificates curl tar; do
          [[ -n "${included[$package]:-}" ]] || packages+=("$package")
          included["$package"]=1
        done
        ;;
      claude|openclaw|hermes|docker)
        for package in ca-certificates curl; do
          [[ -n "${included[$package]:-}" ]] || packages+=("$package")
          included["$package"]=1
        done
        ;;
    esac
  done
  ((${#packages[@]} > 0)) || return 0
  {
    echo
    echo "# 通过 Debian / Ubuntu APT 仓库安装基础软件与依赖"
    echo "apt-get update"
    printf 'apt-get install -y'
    printf ' %q' "${packages[@]}"
    echo
  } >>"$plan_file"
}

append_codex_plan() {
  cat >>"$1" <<'PLAN'

# Codex：从 OpenAI 官方 GitHub Release 安装独立二进制文件
(
  case "$(uname -m)" in
    x86_64|amd64) codex_target="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) codex_target="aarch64-unknown-linux-musl" ;;
    *) echo "Codex 暂不支持此架构：$(uname -m)" >&2; exit 1 ;;
  esac
  codex_dir="$(mktemp -d)"
  trap 'rm -rf "$codex_dir"' EXIT
  curl -fL "https://github.com/openai/codex/releases/latest/download/codex-${codex_target}.tar.gz" -o "$codex_dir/codex.tar.gz"
  tar -xzf "$codex_dir/codex.tar.gz" -C "$codex_dir"
  install -m 0755 "$codex_dir/codex-${codex_target}" /usr/local/bin/codex
)
PLAN
}

append_claude_plan() {
  cat >>"$1" <<'PLAN'

# Claude Code：下载 Anthropic 官方安装器，再以实际登录用户身份执行
(
  claude_installer="$(mktemp)"
  trap 'rm -f "$claude_installer"' EXIT
  curl -fsSL https://claude.ai/install.sh -o "$claude_installer"
  chown "$TARGET_USER:$(id -gn "$TARGET_USER")" "$claude_installer"
  chmod 0700 "$claude_installer"
  if [[ "$TARGET_USER" == "root" ]]; then
    HOME="$TARGET_HOME" bash "$claude_installer"
  else
    runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" bash "$claude_installer"
  fi
)
PLAN
}

append_openclaw_plan() {
  cat >>"$1" <<'PLAN'

# OpenClaw：使用官方 CLI 安装器；只安装，不进入初始化或启动 Gateway
(
  openclaw_installer="$(mktemp)"
  trap 'rm -f "$openclaw_installer"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 https://openclaw.ai/install-cli.sh -o "$openclaw_installer"
  chown "$TARGET_USER:$(id -gn "$TARGET_USER")" "$openclaw_installer"
  chmod 0700 "$openclaw_installer"
  if [[ "$TARGET_USER" == "root" ]]; then
    HOME="$TARGET_HOME" bash "$openclaw_installer" --no-onboard --prefix "$TARGET_HOME/.openclaw"
  else
    runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" bash "$openclaw_installer" --no-onboard --prefix "$TARGET_HOME/.openclaw"
  fi
)
PLAN
}

append_hermes_plan() {
  cat >>"$1" <<'PLAN'

# Hermes：使用 Nous Research 官方安装器；只安装 CLI，不进入设置或启动 Gateway
(
  hermes_installer="$(mktemp)"
  trap 'rm -f "$hermes_installer"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 https://hermes-agent.nousresearch.com/install.sh -o "$hermes_installer"
  chown "$TARGET_USER:$(id -gn "$TARGET_USER")" "$hermes_installer"
  chmod 0700 "$hermes_installer"
  if [[ "$TARGET_USER" == "root" ]]; then
    HOME="$TARGET_HOME" bash "$hermes_installer" --skip-setup --non-interactive
  else
    runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" bash "$hermes_installer" --skip-setup --non-interactive
  fi
)
PLAN
}

append_docker_plan() {
  cat >>"$1" <<'PLAN'

# Docker：配置 Docker 官方签名 APT 仓库并安装 Engine、Buildx 与 Compose
docker_distro="$ID"
docker_codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
[[ -n "$docker_codename" ]] || { echo "无法识别发行版代号。" >&2; exit 1; }
install -m 0755 -d /etc/apt/keyrings
curl -fsSL "https://download.docker.com/linux/${docker_distro}/gpg" -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${docker_distro}
Suites: ${docker_codename}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
PLAN
}

append_verification() {
  local plan_file="$1" id detector label user_path
  {
    echo
    echo '# 验证所选工具已经可以运行'
    for id in "${SELECTED_IDS[@]}"; do
      detector="${TOOL_DETECTORS[$id]}"
      label="${TOOL_LABELS[$id]}"
      user_path="${TOOL_USER_PATHS[$id]}"
      if [[ -n "$user_path" ]]; then
        printf '[[ -x "$TARGET_HOME/%s" ]] || command -v %q >/dev/null || { echo %q >&2; exit 1; }\n' \
          "$user_path" "$detector" "$label 安装后未找到命令：$detector"
      else
        printf 'command -v %q >/dev/null || { echo %q >&2; exit 1; }\n' \
          "$detector" "$label 安装后未找到命令：$detector"
      fi
    done
    echo 'echo "开发工具安装完成。"'
  } >>"$plan_file"
}

build_plan() {
  local plan_file="$1" id
  append_plan_header "$plan_file"
  append_base_packages "$plan_file"
  for id in "${SELECTED_IDS[@]}"; do
    case "${TOOL_ADAPTERS[$id]}" in
      apt) ;;
      codex) append_codex_plan "$plan_file" ;;
      claude) append_claude_plan "$plan_file" ;;
      openclaw) append_openclaw_plan "$plan_file" ;;
      hermes) append_hermes_plan "$plan_file" ;;
      docker) append_docker_plan "$plan_file" ;;
      *) echo "缺少安装适配器：${TOOL_ADAPTERS[$id]}" >&2; return 1 ;;
    esac
  done
  append_verification "$plan_file"
  chmod 0700 "$plan_file"
}

show_plan() {
  local plan_file="$1" id
  echo
  echo "即将执行以下命令"
  for id in "${SELECTED_IDS[@]}"; do
    if [[ "$id" == "docker" ]]; then
      echo "注意：Docker 发布容器端口可能绕过 UFW / firewalld；对外映射端口前请同步检查 server-kit 防火墙策略。"
    elif [[ "$id" == "openclaw" ]]; then
      echo "注意：OpenClaw 具备读取文件和执行命令的能力，建议使用专用低权限用户。"
      echo "边界：本次只安装 CLI，不运行 onboarding、不启动 Gateway、不开放端口。"
    elif [[ "$id" == "hermes" ]]; then
      echo "注意：Hermes 具备读取文件和执行命令的能力，建议使用专用低权限用户。"
      echo "边界：本次只安装 CLI，不运行 setup、不启动 Gateway、不开放端口。"
    fi
  done
  echo "────────────────────────────────────────"
  cat "$plan_file"
  echo "────────────────────────────────────────"
  echo
}

prepare_plan() {
  local selection="$1" plan_file="$2"
  require_supported_system
  resolve_selection "$selection"
  build_plan "$plan_file"
  show_plan "$plan_file"
}

install_selection() {
  local selection="$1" confirm_option="${2:-}" plan_file confirmation install_status
  [[ -z "$confirm_option" || "$confirm_option" == "--yes" ]] || {
    echo "仅支持确认参数 --yes。" >&2
    return 2
  }
  plan_file="$(mktemp)"
  if ! prepare_plan "$selection" "$plan_file"; then
    rm -f "$plan_file"
    return 1
  fi
  if [[ "$confirm_option" == "--yes" ]]; then
    echo "已指定 --yes，跳过交互确认并执行以上计划。"
  else
    if ! read -r -p "输入 yes 确认安装：" confirmation; then
      rm -f "$plan_file"
      return 1
    fi
    if [[ "$confirmation" != "yes" ]]; then
      rm -f "$plan_file"
      echo "已取消，没有执行任何安装命令。"
      return 0
    fi
  fi
  set +e
  bash "$plan_file"
  install_status=$?
  set -e
  rm -f "$plan_file"
  return "$install_status"
}

preview_selection() {
  local selection="$1" plan_file
  plan_file="$(mktemp)"
  if ! prepare_plan "$selection" "$plan_file"; then
    rm -f "$plan_file"
    return 1
  fi
  rm -f "$plan_file"
  echo "这里只显示计划，没有执行安装。"
}

show_menu() {
  local selection
  while true; do
    clear 2>/dev/null || true
    echo "server-kit · Debian / Ubuntu 开发工具"
    echo
    show_catalog
    echo
    echo "输入序号安装，可用逗号选择多个；输入 all 安装全部；输入 0 返回。"
    read -r -p ">: " selection || return 0
    [[ "$selection" == "0" ]] && return 0
    install_selection "$selection" || true
    echo
    read -r -p "按回车继续..." _ || true
  done
}

main() {
  local action="${1:-menu}" selection="${2:-}" confirm_option="${3:-}"
  case "$action" in
    menu) show_menu ;;
    list) require_supported_system; show_catalog ;;
    plan) preview_selection "$selection" ;;
    install) install_selection "$selection" "$confirm_option" ;;
    *) echo "未知开发工具操作：$action" >&2; return 2 ;;
  esac
}

[[ "${SERVER_KIT_DEVTOOLS_LIBRARY_ONLY:-0}" == "1" ]] || main "$@"
