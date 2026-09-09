#!/data/data/com.termux/files/usr/bin/bash
# server-kit Termux SSH 综合管理器
# 默认打开菜单；也支持 status、enable、disable、keygen、key-list、key-add、key-remove 子命令。
set -Eeuo pipefail

ACTION="${1:-menu}"
PORT="${2:-}"
CONFIG="${PREFIX:-}/etc/ssh/sshd_config"
AUTHORIZED_USER="$(whoami)"

usage() {
  echo "用法：$0 [menu | status | enable <端口> | disable | keygen [名称] | key-list | key-add | key-remove <序号>]"
}

require_termux() {
  if [[ -z "${PREFIX:-}" || ! -d "$PREFIX" ]]; then
    echo "请在 Termux 中运行本脚本。" >&2
    exit 1
  fi
}

configured_value() {
  local key="$1"
  awk -v key="$key" '$1 == key {print $2; exit}' "$CONFIG" 2>/dev/null || true
}

show_status() {
  require_termux
  local address port service listeners
  address="$(configured_value ListenAddress)"
  port="$(configured_value Port)"
  if pgrep -x sshd >/dev/null 2>&1; then service="运行中"; else service="已停止"; fi
  listeners="$(ss -ltnp 2>/dev/null | awk '$4 ~ /^10\.20\.0\./ {print $4}' | paste -sd, -)"
  echo "server-kit SSH 当前状态"
  echo "  服务：$service"
  echo "  自启：Termux 被系统结束或手机重启后需重新启用"
  echo "  配置：${address:-未配置}:${port:-未配置}"
  echo "  监听：${listeners:-未监听}"
  echo "  防火墙：未 Root 的 Termux 无系统防火墙权限；依靠只监听 AWG 地址限制入口"
}

authorized_keys_path() {
  echo "$HOME/.ssh/authorized_keys"
}

ensure_authorized_keys() {
  require_termux
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "正在安装 Termux OpenSSH..."
    pkg update -y >/dev/null
    pkg install -y openssh >/dev/null
  fi
  mkdir -p "$HOME/.ssh"; chmod 0700 "$HOME/.ssh"
  touch "$(authorized_keys_path)"; chmod 0600 "$(authorized_keys_path)"
}

key_entries() {
  local path index line temp details fingerprint type name
  path="$(authorized_keys_path)"; index=0; [[ -f "$path" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(ssh-[^[:space:]]+|ecdsa-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]+(.*))?[[:space:]]*$ ]] || continue
    index=$((index + 1)); type="${BASH_REMATCH[1]}"; name="${BASH_REMATCH[4]:-未命名}"
    temp="$(mktemp)"; printf '%s\n' "$line" >"$temp"; details="$(ssh-keygen -lf "$temp" 2>/dev/null || true)"; rm -f "$temp"
    fingerprint="$(awk '{print $2}' <<<"$details")"; printf '%s\t%s\t%s\t%s\n' "$index" "$type" "${fingerprint:-未知}" "$name"
  done <"$path"
}

list_keys() {
  ensure_authorized_keys
  local entries path
  path="$(authorized_keys_path)"; entries="$(key_entries)"; echo "允许登录 Termux 的公钥"; echo "文件：$path"
  if [[ -z "$entries" ]]; then echo "  暂无公钥。"; return; fi
  while IFS=$'\t' read -r index type fingerprint name; do printf '  [%s] %s · %s · %s\n' "$index" "$type" "$fingerprint" "$name"; done <<<"$entries"
}

generate_key() {
  require_termux
  pkg install -y openssh >/dev/null
  local name="${PORT:-id_ed25519}" path
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { echo "密钥名称格式不正确。" >&2; exit 2; }
  mkdir -p "$HOME/.ssh"; chmod 0700 "$HOME/.ssh"; path="$HOME/.ssh/$name"
  [[ ! -e "$path" ]] || { echo "密钥已存在：$path。请换一个名称。" >&2; exit 1; }
  echo "接下来可以设置密钥口令；直接回车表示不设置。"
  ssh-keygen -t ed25519 -a 64 -f "$path" -C "android-$(whoami)"
  echo "私钥：$path（不要发送给任何人）"; echo "公钥：$path.pub"; cat "$path.pub"
}

select_authorized_account() {
  echo "Termux 只有当前应用账户可管理。"
  echo "已选择：$AUTHORIZED_USER"
}

add_key() {
  ensure_authorized_keys
  local path line type blob original_name name temp
  path="$(authorized_keys_path)"; echo "请粘贴一整行公钥，然后按回车："; IFS= read -r line
  [[ "$line" =~ ^(ssh-[^[:space:]]+|ecdsa-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]+(.*))?$ ]] || { echo "公钥格式不正确。" >&2; exit 2; }
  type="${BASH_REMATCH[1]}"; blob="${BASH_REMATCH[2]}"; original_name="${BASH_REMATCH[4]:-}"
  awk -v blob="$blob" '$2 == blob {found=1} END {exit !found}' "$path" && { echo "这把公钥已经存在。" >&2; exit 1; }
  temp="$(mktemp)"; printf '%s %s\n' "$type" "$blob" >"$temp"; ssh-keygen -lf "$temp" >/dev/null 2>&1 || { rm -f "$temp"; echo "公钥校验失败。" >&2; exit 2; }; rm -f "$temp"
  read -r -p "给这台客户端起个名字（直接回车保留原名称）：" name; name="${name:-$original_name}"
  if [[ -n "$name" ]]; then printf '%s %s %s\n' "$type" "$blob" "$name" >>"$path"; else printf '%s %s\n' "$type" "$blob" >>"$path"; fi
  ensure_authorized_keys; echo "公钥已添加。"; list_keys
}

remove_key() {
  ensure_authorized_keys
  local selected="${PORT:-}" entries count path answer current output line
  entries="$(key_entries)"; [[ -n "$entries" ]] || { echo "暂无可删除的公钥。"; return; }; list_keys
  [[ -n "$selected" ]] || read -r -p "输入要删除的序号：" selected
  [[ "$selected" =~ ^[0-9]+$ ]] || { echo "公钥序号无效。" >&2; exit 2; }
  count="$(wc -l <<<"$entries" | tr -d ' ')"; (( selected >= 1 && selected <= count )) || { echo "公钥序号无效。" >&2; exit 2; }
  read -r -p "确认删除 [$selected]？输入 yes：" answer; [[ "$answer" == "yes" ]] || { echo "已取消。"; return; }
  path="$(authorized_keys_path)"; output="$(mktemp)"; current=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*(ssh-|ecdsa-|sk-) ]]; then current=$((current + 1)); (( current == selected )) && continue; fi
    printf '%s\n' "$line" >>"$output"
  done <"$path"
  cat "$output" >"$path"; rm -f "$output"; ensure_authorized_keys; echo "公钥已删除。"; list_keys
}

enable_ssh() {
  require_termux
  if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "开启时必须传入 1–65535 的端口。" >&2
    usage
    exit 2
  fi
  echo "[1/4] 安装 OpenSSH..."
  pkg update -y
  pkg install -y openssh iproute2

  echo "[2/4] 检查 AmneziaWG 地址..."
  local awg_address
  awg_address="$(ip -o -4 addr show | awk '$4 ~ /^10\.20\.0\./ {split($4,a,"/"); print a[1]; exit}')"
  if [[ -z "$awg_address" ]]; then
    echo "没有找到 10.20.0.x 地址。请先连接 AmneziaWG。" >&2
    exit 1
  fi

  echo "[3/4] 只监听 AWG 地址并设置端口 $PORT..."
  cp -a "$CONFIG" "${CONFIG}.server-kit.bak.$(date +%Y%m%d%H%M%S)"
  sed -i -E '/^[[:space:]]*#?[[:space:]]*(Port|ListenAddress)[[:space:]]+/d' "$CONFIG"
  cat >>"$CONFIG" <<EOF

# 由 server-kit 管理：只监听 AWG 地址
Port $PORT
ListenAddress $awg_address
EOF
  sshd -t

  echo "[4/4] 启动 SSH..."
  pkill -x sshd 2>/dev/null || true
  sshd
  echo "完成：SSH 正在 ${awg_address}:${PORT} 监听。"
  echo "Termux 用户名：$(whoami)"
  show_status
}

disable_ssh() {
  require_termux
  echo "[1/2] 停止 Termux SSH..."
  pkill -x sshd 2>/dev/null || true
  echo "[2/2] 检查 Android 防火墙..."
  echo "未 Root 的 Termux 没有创建系统防火墙规则，因此无需删除。"
  echo "完成：SSH 已关闭。"
  show_status
}

invoke_action() {
  case "$1" in
    enable) enable_ssh ;;
    disable) disable_ssh ;;
    status) show_status ;;
    keygen) generate_key ;;
    key-list) list_keys ;;
    key-add) add_key ;;
    key-remove) remove_key ;;
    *) usage; return 2 ;;
  esac
}

write_menu() {
  echo "server-kit · Android / Termux SSH 管理"
  echo "公钥账户：$AUTHORIZED_USER"
  echo
  echo "  1. 查看 SSH 状态"
  echo "  2. 开启或修改 SSH 端口"
  echo "  3. 关闭 SSH"
  echo "  4. 生成本机 Ed25519 密钥"
  echo "  5. 选择公钥所属账户"
  echo "  6. 查看允许登录的公钥"
  echo "  7. 添加允许登录的公钥"
  echo "  8. 删除允许登录的公钥"
  echo "  m / ?  重新显示菜单"
  echo "  0. 退出"
  echo
}

run_menu_action() {
  local action="$1" value="${2:-}" status
  set +e
  (set -e; PORT="$value"; invoke_action "$action")
  status=$?
  set -e
  ((status == 0)) && return 0
  echo "操作失败，请检查上面的提示。" >&2
  return 0
}

show_menu() {
  clear 2>/dev/null || true
  write_menu
  local choice value
  while true; do
    echo "下一步：1–8 操作 · m/? 菜单 · 0 退出 · 公钥账户 $AUTHORIZED_USER"
    read -r -p ">: " choice || return 0
    case "$choice" in
      1) run_menu_action status ;;
      2) read -r -p "请输入 SSH 端口，例如 8022：" value; run_menu_action enable "$value" ;;
      3) read -r -p "关闭后现有 SSH 会话会断开，输入 yes 继续：" value; [[ "$value" == "yes" ]] && run_menu_action disable ;;
      4) read -r -p "密钥名称（直接回车使用 id_ed25519）：" value; run_menu_action keygen "$value" ;;
      5) select_authorized_account ;;
      6) run_menu_action key-list ;;
      7) run_menu_action key-add ;;
      8) run_menu_action key-remove ;;
      m|M|\?) echo; write_menu ;;
      0) return 0 ;;
      *) echo "无效选项。请输入 1–8、m、? 或 0。" ;;
    esac
    echo
  done
}

if [[ "$ACTION" == "menu" ]]; then show_menu; else invoke_action "$ACTION"; fi
