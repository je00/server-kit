#!/usr/bin/env bash
# server-kit Debian/Ubuntu SSH 综合管理器
# 默认打开菜单；也支持服务、公钥、允许来源网段与仅公钥认证子命令。
set -Eeuo pipefail

ACTION="${1:-menu}"
PORT="${2:-}"
INITIAL_NETWORK="10.20.0.0/24"
NETWORKS_FILE="${SERVER_KIT_SSH_NETWORKS_FILE:-/etc/server-kit/ssh-allowed-networks.conf}"
FIREWALL_STATE="${SERVER_KIT_SSH_FIREWALL_STATE:-/var/lib/server-kit-ssh/firewall-rules}"
MANAGED_CONFIG="${SERVER_KIT_SSH_CONFIG:-/etc/ssh/sshd_config.d/90-server-kit-awg.conf}"
AUTH_CONFIG="${SERVER_KIT_SSH_AUTH_CONFIG:-/etc/ssh/sshd_config.d/00-server-kit-auth.conf}"
AUTH_STATE_DIR="${SERVER_KIT_SSH_AUTH_STATE_DIR:-/var/lib/server-kit-ssh}"
AUTH_TRANSACTION="${AUTH_STATE_DIR}/auth-transaction"
AUTH_BACKUP="${AUTH_STATE_DIR}/auth-config.backup"
AUTH_INSTALLED_SCRIPT="${SERVER_KIT_SSH_INSTALLED_SCRIPT:-/usr/local/lib/server-kit/node-ssh-manager.sh}"
AUTH_ROLLBACK_UNIT="server-kit-node-ssh-auth-rollback"
AUTH_ROLLBACK_SECONDS=300
SSHD_BIN="${SERVER_KIT_SSHD_BIN:-/usr/sbin/sshd}"
SSHD_RUNTIME_DIR="${SERVER_KIT_SSHD_RUNTIME_DIR:-/run/sshd}"
SYSTEMCTL_BIN="${SERVER_KIT_SYSTEMCTL_BIN:-systemctl}"
SYSTEMD_RUN_BIN="${SERVER_KIT_SYSTEMD_RUN_BIN:-systemd-run}"
AUTHORIZED_KEYS_OVERRIDE="${SERVER_KIT_AUTHORIZED_KEYS_PATH:-}"
CALLER_USER="${SUDO_USER:-$(id -un)}"
[[ -n "$CALLER_USER" ]] || CALLER_USER="$(id -un)"
AUTHORIZED_USER="$CALLER_USER"

usage() {
  echo "用法：$0 [menu | status | enable <端口> | disable | network-list | network-add <IPv4 CIDR> | network-remove <IPv4 CIDR> | keygen [名称] | key-list | key-add | key-remove <序号> | auth-status | auth-harden | auth-confirm | auth-rollback]"
}

require_root() {
  if (( EUID != 0 )) && [[ "${SERVER_KIT_TESTING:-0}" != "1" ]]; then
    echo "请使用 sudo 运行开启或关闭操作。" >&2
    exit 1
  fi
}

prepare_sshd_runtime_dir() {
  # /run 是临时文件系统；sshd -t 也要求权限分离目录已经存在。
  install -d -m 0755 "$SSHD_RUNTIME_DIR"
  (( EUID != 0 )) || chown root:root "$SSHD_RUNTIME_DIR"
}

configured_value() {
  local key="$1"
  awk -v key="$key" '$1 == key {print $2; exit}' "$MANAGED_CONFIG" 2>/dev/null || true
}

valid_ipv4() {
  local ip="$1" octet
  local -a parts
  IFS=. read -r -a parts <<<"$ip"
  ((${#parts[@]} == 4)) || return 1
  for octet in "${parts[@]}"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

valid_cidr() {
  local cidr="$1" address prefix
  [[ "$cidr" == */* ]] || return 1
  address="${cidr%/*}"; prefix="${cidr##*/}"
  valid_ipv4 "$address" && [[ "$prefix" =~ ^[0-9]{1,2}$ ]] && ((10#$prefix <= 32))
}

ipv4_number() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  echo $(((10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d))
}

address_in_cidr() {
  local address="$1" cidr="$2" prefix mask address_number network_number
  prefix="${cidr##*/}"
  address_number="$(ipv4_number "$address")"
  network_number="$(ipv4_number "${cidr%/*}")"
  ((prefix == 0)) && return 0
  mask=$(((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF))
  (((address_number & mask) == (network_number & mask)))
}

allowed_networks() {
  if [[ ! -f "$NETWORKS_FILE" ]]; then
    printf '%s\n' "$INITIAL_NETWORK"
    return 0
  fi
  local cidr
  local -A seen=()
  while IFS= read -r cidr || [[ -n "$cidr" ]]; do
    if valid_cidr "$cidr" && [[ -z "${seen[$cidr]:-}" ]]; then
      seen[$cidr]=1
      printf '%s\n' "$cidr"
    fi
  done <"$NETWORKS_FILE"
  ((${#seen[@]} > 0)) || printf '%s\n' "$INITIAL_NETWORK"
}

materialize_networks_file() {
  [[ -f "$NETWORKS_FILE" ]] && return 0
  install -d -m 0755 "$(dirname "$NETWORKS_FILE")"
  printf '%s\n' "$INITIAL_NETWORK" >"$NETWORKS_FILE"
  chmod 0644 "$NETWORKS_FILE"
}

managed_addresses() {
  local address cidr
  local -A seen=()
  while IFS= read -r address; do
    while IFS= read -r cidr; do
      if address_in_cidr "$address" "$cidr" && [[ -z "${seen[$address]:-}" ]]; then
        seen[$address]=1
        printf '%s\n' "$address"
      fi
    done < <(allowed_networks)
  done < <(ip -o -4 addr show | awk '{split($4,a,"/"); print a[1]}')
}

list_networks() {
  echo "SSH 允许来源网段"
  local cidr
  while IFS= read -r cidr; do
    [[ "$cidr" == "$INITIAL_NETWORK" ]] && printf '  %s · 初始值，可替换\n' "$cidr" || printf '  %s\n' "$cidr"
  done < <(allowed_networks)
}

reapply_ssh_if_running() {
  local current_port old_port
  current_port="$(configured_value Port)"
  [[ -n "$current_port" ]] && "$SYSTEMCTL_BIN" is-active --quiet ssh || return 0
  old_port="$PORT"; PORT="$current_port"; enable_ssh; PORT="$old_port"
}

add_network() {
  require_root
  local cidr="${PORT:-}"
  valid_cidr "$cidr" || { echo "请输入有效的 IPv4 CIDR，例如 192.168.1.0/24。" >&2; return 2; }
  allowed_networks | grep -Fxq "$cidr" && { echo "允许网段已存在：$cidr"; return 0; }
  materialize_networks_file
  printf '%s\n' "$cidr" >>"$NETWORKS_FILE"; chmod 0644 "$NETWORKS_FILE"
  reapply_ssh_if_running
  echo "已加入允许网段：$cidr"
}

remove_network() {
  require_root
  local cidr="${PORT:-}" temporary network_count
  valid_cidr "$cidr" || { echo "请输入有效的 IPv4 CIDR。" >&2; return 2; }
  allowed_networks | grep -Fxq "$cidr" || { echo "允许网段不存在：$cidr" >&2; return 1; }
  network_count="$(allowed_networks | grep -c .)"
  (( network_count > 1 )) || { echo "至少保留一个允许网段，请先添加新网段。" >&2; return 2; }
  materialize_networks_file
  temporary="$(mktemp)"
  grep -Fvx "$cidr" "$NETWORKS_FILE" >"$temporary" || true
  install -m 0644 "$temporary" "$NETWORKS_FILE"; rm -f "$temporary"
  reapply_ssh_if_running
  echo "已删除允许网段：$cidr"
}

remove_firewall_rule() {
  local backend rule number old_address old_port old_rule
  old_address="$(configured_value ListenAddress)"
  old_port="$(configured_value Port)"
  if [[ -f "$FIREWALL_STATE" ]]; then
    while IFS=$'\t' read -r backend rule || [[ -n "$backend$rule" ]]; do
      [[ "$backend" == "firewalld" && -n "$rule" ]] || continue
      firewall-cmd --permanent --remove-rich-rule="$rule" >/dev/null 2>&1 || true
    done <"$FIREWALL_STATE"
    rm -f "$FIREWALL_STATE"
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    if [[ -n "$old_address" && -n "$old_port" ]]; then
      old_rule="rule family=ipv4 source address=$INITIAL_NETWORK destination address=$old_address port port=$old_port protocol=tcp accept"
      firewall-cmd --permanent --remove-rich-rule="$old_rule" >/dev/null 2>&1 || true
    fi
    firewall-cmd --reload >/dev/null
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
    while number="$(ufw status numbered | awk '/server-kit SSH allowed/ {gsub(/[][]/, "", $1); print $1; exit}')" && [[ -n "$number" ]]; do
      ufw --force delete "$number" >/dev/null
    done
    # 兼容旧版本脚本创建的规则。
    while number="$(ufw status numbered | awk '/server-kit SSH via AWG/ {gsub(/[][]/, "", $1); print $1; exit}')" && [[ -n "$number" ]]; do
      ufw --force delete "$number" >/dev/null
    done
  fi
}

show_status() {
  local addresses port service startup listeners firewall
  addresses="$(awk '$1 == "ListenAddress" {print $2}' "$MANAGED_CONFIG" 2>/dev/null | paste -sd, -)"
  port="$(configured_value Port)"
  service="$(systemctl is-active ssh 2>/dev/null || true)"
  startup="$(systemctl is-enabled ssh 2>/dev/null || true)"
  listeners="$(ss -ltnp 2>/dev/null | awk '$0 ~ /sshd/ {print $4}' | paste -sd, -)"
  firewall="未开放"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'server-kit SSH allowed'; then
    firewall="已应用允许网段（UFW）"
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld && [[ -s "$FIREWALL_STATE" ]]; then
    firewall="已应用允许网段（firewalld）"
  fi
  echo "server-kit SSH 当前状态"
  echo "  服务：${service:-未安装}"
  echo "  自启：${startup:-未设置}"
  echo "  监听地址：${addresses:-未配置}"
  echo "  端口：${port:-未配置}"
  echo "  监听：${listeners:-未监听}"
  echo "  防火墙：$firewall"
  list_networks
  show_auth_status
}

target_user() {
  echo "$AUTHORIZED_USER"
}

target_home() {
  getent passwd "$(target_user)" | cut -d: -f6
}

client_home() {
  getent passwd "$CALLER_USER" | cut -d: -f6
}

manageable_accounts() {
  if (( EUID != 0 )); then
    echo "$CALLER_USER"
    return
  fi
  getent passwd | awk -F: '($1 == "root" || $3 >= 1000) && $7 !~ /(nologin|false)$/ && $6 != "" {print $1}' | awk '!seen[$0]++'
}

select_authorized_account() {
  local accounts=() selected index user label
  mapfile -t accounts < <(manageable_accounts)
  ((${#accounts[@]})) || { echo "没有找到可管理的系统账户。" >&2; return 1; }
  echo "请选择要管理公钥的 Linux 账户"
  for index in "${!accounts[@]}"; do
    user="${accounts[$index]}"
    label=""
    [[ "$user" == "$AUTHORIZED_USER" ]] && label=" · 当前"
    printf '  [%s] %s%s\n' "$((index + 1))" "$user" "$label"
  done
  read -r -p "输入账户序号：" selected
  [[ "$selected" =~ ^[0-9]+$ ]] && ((selected >= 1 && selected <= ${#accounts[@]})) || {
    echo "账户序号无效。" >&2
    return 1
  }
  AUTHORIZED_USER="${accounts[$((selected - 1))]}"
  echo "已选择：$AUTHORIZED_USER"
}

authorized_keys_path() {
  if [[ -n "$AUTHORIZED_KEYS_OVERRIDE" ]]; then echo "$AUTHORIZED_KEYS_OVERRIDE"; else echo "$(target_home)/.ssh/authorized_keys"; fi
}

ensure_authorized_keys() {
  local user home group path
  user="$(target_user)"; home="$(target_home)"; group="$(id -gn "$user")"; path="$(authorized_keys_path)"
  install -d -m 0700 -o "$user" -g "$group" "$home/.ssh"
  touch "$path"
  chown "$user:$group" "$path"
  chmod 0600 "$path"
}

key_entries() {
  local path index line temp details fingerprint type name
  path="$(authorized_keys_path)"; index=0
  [[ -f "$path" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(ssh-[^[:space:]]+|ecdsa-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]+(.*))?[[:space:]]*$ ]] || continue
    index=$((index + 1)); type="${BASH_REMATCH[1]}"; name="${BASH_REMATCH[4]:-未命名}"
    temp="$(mktemp)"; printf '%s\n' "$line" >"$temp"
    details="$(ssh-keygen -lf "$temp" 2>/dev/null || true)"; rm -f "$temp"
    fingerprint="$(awk '{print $2}' <<<"$details")"
    printf '%s\t%s\t%s\t%s\n' "$index" "$type" "${fingerprint:-未知}" "$name"
  done <"$path"
}

valid_authorized_key_count() {
  key_entries | awk -F '\t' '$3 != "未知" {count++} END {print count + 0}'
}

effective_auth_value() {
  local key="$1"
  [[ -x "$SSHD_BIN" ]] || return 0
  "$SSHD_BIN" -T -C "user=${AUTHORIZED_USER},host=localhost,addr=127.0.0.1" 2>/dev/null |
    awk -v key="$key" '$1 == key {print $2; exit}'
}

auth_is_hardened() {
  [[ "$(effective_auth_value pubkeyauthentication)" == "yes" ]] &&
    [[ "$(effective_auth_value passwordauthentication)" == "no" ]] &&
    [[ "$(effective_auth_value kbdinteractiveauthentication)" == "no" ]] &&
    [[ "$(effective_auth_value authenticationmethods)" == "publickey" ]]
}

show_auth_status() {
  local password="未知" methods="未知" state="未启用" keys=0
  keys="$(valid_authorized_key_count)"
  if [[ -x "$SSHD_BIN" ]]; then
    password="$(effective_auth_value passwordauthentication)"; password="${password:-未知}"
    methods="$(effective_auth_value authenticationmethods)"; methods="${methods:-未知}"
    auth_is_hardened && state="仅公钥" || state="允许其他认证"
  fi
  [[ -f "$AUTH_TRANSACTION" ]] && state="${state}（等待确认）"
  echo "  公钥：${keys} 把有效公钥（账户 ${AUTHORIZED_USER}）"
  echo "  认证：${state} · PasswordAuthentication ${password} · AuthenticationMethods ${methods}"
}

write_auth_config() {
  local temporary
  temporary="$(mktemp)"
  printf '%s\n' \
    '# 由 server-kit 管理：SSH 端到端仅公钥认证' \
    'PubkeyAuthentication yes' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'AuthenticationMethods publickey' >"$temporary"
  if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
    cp "$temporary" "$AUTH_CONFIG"
  else
    install -m 0644 -o root -g root "$temporary" "$AUTH_CONFIG"
  fi
  rm -f "$temporary"
}

restore_auth_config() {
  local existed
  existed="$(cat "$AUTH_TRANSACTION" 2>/dev/null || true)"
  if [[ "$existed" == "existing" ]]; then
    [[ -f "$AUTH_BACKUP" ]] || { echo "认证回滚备份缺失。" >&2; return 1; }
    if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then cp "$AUTH_BACKUP" "$AUTH_CONFIG"; else install -m 0644 -o root -g root "$AUTH_BACKUP" "$AUTH_CONFIG"; fi
  else
    rm -f "$AUTH_CONFIG"
  fi
}

cancel_auth_rollback() {
  "$SYSTEMCTL_BIN" stop "${AUTH_ROLLBACK_UNIT}.timer" >/dev/null 2>&1 || true
  "$SYSTEMCTL_BIN" reset-failed "${AUTH_ROLLBACK_UNIT}.service" >/dev/null 2>&1 || true
}

schedule_auth_rollback() {
  if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then
    mkdir -p "$(dirname "$AUTH_INSTALLED_SCRIPT")"; cp "$0" "$AUTH_INSTALLED_SCRIPT"
  else
    install -d -m 0755 "$(dirname "$AUTH_INSTALLED_SCRIPT")"
    install -m 0700 "$0" "$AUTH_INSTALLED_SCRIPT"
  fi
  cancel_auth_rollback
  "$SYSTEMD_RUN_BIN" --quiet --unit="$AUTH_ROLLBACK_UNIT" \
    --on-active="${AUTH_ROLLBACK_SECONDS}s" --timer-property=AccuracySec=1s \
    "$AUTH_INSTALLED_SCRIPT" auth-rollback automatic
}

rollback_auth() {
  require_root
  local automatic="${PORT:-}"
  if [[ ! -f "$AUTH_TRANSACTION" ]]; then
    [[ "$automatic" == "automatic" ]] || echo "当前没有待回滚的认证变更。"
    return 0
  fi
  restore_auth_config
  prepare_sshd_runtime_dir
  "$SSHD_BIN" -t
  "$SYSTEMCTL_BIN" reload ssh
  rm -f "$AUTH_TRANSACTION" "$AUTH_BACKUP"
  cancel_auth_rollback
  if [[ "$automatic" == "automatic" ]]; then
    echo "仅公钥认证未在 5 分钟内确认，已自动恢复。"
  else
    echo "SSH 认证配置已回滚。"
  fi
}

harden_auth() {
  require_root
  [[ -x "$SSHD_BIN" ]] || { echo "请先开启 SSH 服务。" >&2; return 1; }
  [[ ! -f "$AUTH_TRANSACTION" ]] || { echo "已有等待确认的认证变更。" >&2; return 1; }
  local keys
  keys="$(valid_authorized_key_count)"
  [[ "$keys" =~ ^[0-9]+$ ]] && ((keys >= 1)) || {
    echo "账户 ${AUTHORIZED_USER} 没有可用公钥，拒绝关闭密码认证。" >&2; return 1;
  }
  "$SYSTEMCTL_BIN" is-active --quiet ssh || { echo "SSH 服务未运行。" >&2; return 1; }
  if [[ "${SERVER_KIT_TESTING:-0}" == "1" ]]; then mkdir -p "$AUTH_STATE_DIR"; else install -d -m 0700 "$AUTH_STATE_DIR"; fi
  if [[ -f "$AUTH_CONFIG" ]]; then
    cp -a "$AUTH_CONFIG" "$AUTH_BACKUP"; printf 'existing\n' >"$AUTH_TRANSACTION"
  else
    rm -f "$AUTH_BACKUP"; printf 'absent\n' >"$AUTH_TRANSACTION"
  fi
  chmod 0600 "$AUTH_TRANSACTION" "$AUTH_BACKUP" 2>/dev/null || true
  if ! write_auth_config; then
    restore_auth_config; rm -f "$AUTH_TRANSACTION" "$AUTH_BACKUP"
    echo "无法写入认证配置，原配置保持不变。" >&2; return 1
  fi
  prepare_sshd_runtime_dir
  if ! "$SSHD_BIN" -t || ! schedule_auth_rollback; then
    restore_auth_config; rm -f "$AUTH_TRANSACTION" "$AUTH_BACKUP"
    echo "认证配置或自动回滚校验失败，原配置保持不变。" >&2; return 1
  fi
  if ! "$SYSTEMCTL_BIN" reload ssh || ! auth_is_hardened; then
    rollback_auth
    echo "仅公钥认证未正确生效，已恢复原配置。" >&2; return 1
  fi
  echo "仅公钥认证已临时生效。请保留当前窗口，另开窗口用公钥登录测试。"
  echo "成功后在 5 分钟内运行：sudo $0 auth-confirm"
}

confirm_auth() {
  require_root
  [[ -f "$AUTH_TRANSACTION" ]] || { echo "没有等待确认的认证变更。" >&2; return 1; }
  auth_is_hardened || { rollback_auth; echo "实际认证参数不符合预期，已回滚。" >&2; return 1; }
  rm -f "$AUTH_TRANSACTION" "$AUTH_BACKUP"
  cancel_auth_rollback
  echo "已确认：SSH 只接受公钥认证。"
}

list_keys() {
  ensure_authorized_keys
  local entries path
  path="$(authorized_keys_path)"; entries="$(key_entries)"
  echo "允许登录 $(target_user) 的公钥"
  echo "文件：$path"
  if [[ -z "$entries" ]]; then echo "  暂无公钥。"; return; fi
  while IFS=$'\t' read -r index type fingerprint name; do
    printf '  [%s] %s · %s · %s\n' "$index" "$type" "$fingerprint" "$name"
  done <<<"$entries"
}

generate_key() {
  local user home group name path
  user="$CALLER_USER"; home="$(client_home)"; group="$(id -gn "$user")"; name="${PORT:-id_ed25519}"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { echo "密钥名称格式不正确。" >&2; exit 2; }
  install -d -m 0700 -o "$user" -g "$group" "$home/.ssh"
  path="$home/.ssh/$name"
  [[ ! -e "$path" ]] || { echo "密钥已存在：$path。请换一个名称。" >&2; exit 1; }
  echo "接下来可以设置密钥口令；直接回车表示不设置。"
  if (( EUID == 0 )) && [[ "$user" != "root" ]]; then
    runuser -u "$user" -- ssh-keygen -t ed25519 -a 64 -f "$path" -C "$(hostname)-$user"
  else
    ssh-keygen -t ed25519 -a 64 -f "$path" -C "$(hostname)-$user"
  fi
  echo "私钥：$path（不要发送给任何人）"
  echo "公钥：$path.pub"
  cat "$path.pub"
}

add_key() {
  ensure_authorized_keys
  local path line type blob original_name name temp
  path="$(authorized_keys_path)"
  echo "请粘贴一整行公钥，然后按回车："
  IFS= read -r line
  [[ "$line" =~ ^(ssh-[^[:space:]]+|ecdsa-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]+(.*))?$ ]] || { echo "公钥格式不正确。" >&2; exit 2; }
  type="${BASH_REMATCH[1]}"; blob="${BASH_REMATCH[2]}"; original_name="${BASH_REMATCH[4]:-}"
  awk -v blob="$blob" '$2 == blob {found=1} END {exit !found}' "$path" && { echo "这把公钥已经存在。" >&2; exit 1; }
  temp="$(mktemp)"; printf '%s %s\n' "$type" "$blob" >"$temp"
  ssh-keygen -lf "$temp" >/dev/null 2>&1 || { rm -f "$temp"; echo "公钥校验失败。" >&2; exit 2; }; rm -f "$temp"
  read -r -p "给这台客户端起个名字（直接回车保留原名称）：" name
  name="${name:-$original_name}"
  if [[ -n "$name" ]]; then printf '%s %s %s\n' "$type" "$blob" "$name" >>"$path"; else printf '%s %s\n' "$type" "$blob" >>"$path"; fi
  ensure_authorized_keys
  echo "公钥已添加。"
  list_keys
}

remove_key() {
  ensure_authorized_keys
  local selected="${PORT:-}" entries count path target_line answer current output index line
  entries="$(key_entries)"; [[ -n "$entries" ]] || { echo "暂无可删除的公钥。"; return; }
  list_keys
  [[ -n "$selected" ]] || read -r -p "输入要删除的序号：" selected
  [[ "$selected" =~ ^[0-9]+$ ]] || { echo "公钥序号无效。" >&2; exit 2; }
  count="$(wc -l <<<"$entries" | tr -d ' ')"; (( selected >= 1 && selected <= count )) || { echo "公钥序号无效。" >&2; exit 2; }
  read -r -p "确认删除 [$selected]？输入 yes：" answer; [[ "$answer" == "yes" ]] || { echo "已取消。"; return; }
  path="$(authorized_keys_path)"; output="$(mktemp)"; current=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*(ssh-[^[:space:]]+|ecdsa-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+ ]]; then current=$((current + 1)); fi
    if (( current == selected )) && [[ "$line" =~ ^[[:space:]]*(ssh-|ecdsa-|sk-) ]]; then continue; fi
    printf '%s\n' "$line" >>"$output"
  done <"$path"
  cat "$output" >"$path"; rm -f "$output"; ensure_authorized_keys
  echo "公钥已删除。"; list_keys
}

enable_ssh() {
  require_root
  if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "开启时必须传入 1–65535 的端口。" >&2
    usage
    exit 2
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "本脚本仅支持 Debian 和 Ubuntu。" >&2
    exit 1
  fi

  echo "[1/5] 安装系统自带 OpenSSH Server..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y openssh-server iproute2

  echo "[2/5] 检查允许网段对应的本机地址..."
  local backup main_backup rule cidr address deny_pattern="*"
  local -a addresses=()
  mapfile -t addresses < <(managed_addresses)
  ((${#addresses[@]} > 0)) || { echo "没有找到允许网段对应的本机 IPv4 地址。" >&2; exit 1; }

  echo "[3/5] 清理旧入口并设置端口 $PORT..."
  remove_firewall_rule
  install -d -m 0755 /etc/ssh/sshd_config.d
  backup=""
  if [[ -f "$MANAGED_CONFIG" ]]; then
    backup="${MANAGED_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$MANAGED_CONFIG" "$backup"
  fi
  {
    echo '# 由 server-kit 管理：只监听允许网段对应的本机地址'
    echo "Port $PORT"
    for address in "${addresses[@]}"; do echo "ListenAddress $address"; done
    while IFS= read -r cidr; do deny_pattern+=",!$cidr"; done < <(allowed_networks)
    echo "Match Address $deny_pattern"
    echo '    DenyUsers *'
    echo 'Match all'
  } >"$MANAGED_CONFIG"
  chmod 0644 "$MANAGED_CONFIG"
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    main_backup="/etc/ssh/sshd_config.server-kit.bak.$(date +%Y%m%d%H%M%S)"
    cp -a /etc/ssh/sshd_config "$main_backup"
    sed -i '1iInclude /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  fi
  prepare_sshd_runtime_dir
  if ! "$SSHD_BIN" -t; then
    if [[ -n "$backup" ]]; then cp -a "$backup" "$MANAGED_CONFIG"; else rm -f "$MANAGED_CONFIG"; fi
    echo "OpenSSH 配置校验失败，已经恢复旧配置。" >&2
    exit 1
  fi

  echo "[4/5] 启动 SSH 并设置开机自启..."
  systemctl enable ssh
  if ! systemctl restart ssh; then
    if [[ -n "$backup" ]]; then cp -a "$backup" "$MANAGED_CONFIG"; else rm -f "$MANAGED_CONFIG"; fi
    systemctl restart ssh || true
    echo "新配置启动失败，已经恢复旧配置。" >&2
    exit 1
  fi

  echo "[5/5] 应用 SSH 允许来源网段..."
  install -d -m 0700 "$(dirname "$FIREWALL_STATE")"
  : >"$FIREWALL_STATE"; chmod 0600 "$FIREWALL_STATE"
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    while IFS= read -r cidr; do
      for address in "${addresses[@]}"; do
        rule="rule family=ipv4 source address=$cidr destination address=$address port port=$PORT protocol=tcp accept"
        firewall-cmd --permanent --add-rich-rule="$rule"
        printf 'firewalld\t%s\n' "$rule" >>"$FIREWALL_STATE"
      done
    done < <(allowed_networks)
    firewall-cmd --reload
  elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
    while IFS= read -r cidr; do
      for address in "${addresses[@]}"; do
        ufw allow from "$cidr" to "$address" port "$PORT" proto tcp comment 'server-kit SSH allowed'
      done
    done < <(allowed_networks)
  else
    echo "未检测到启用中的 UFW 或 firewalld；SSH 仍只监听允许网段对应的本机地址。"
  fi
  echo "完成：SSH 正在 ${addresses[*]} 的 ${PORT} 端口监听。"
  show_status
}

disable_ssh() {
  require_root
  echo "[1/2] 删除 SSH 允许网段防火墙规则..."
  remove_firewall_rule
  echo "[2/2] 停止 SSH 并禁止开机自启..."
  systemctl disable --now ssh || true
  echo "完成：SSH 服务和对应防火墙入口都已关闭。"
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
    auth-status) show_auth_status ;;
    auth-harden) harden_auth ;;
    auth-confirm) confirm_auth ;;
    auth-rollback) rollback_auth ;;
    network-list) list_networks ;;
    network-add) add_network ;;
    network-remove) remove_network ;;
    *) usage; return 2 ;;
  esac
}

write_menu() {
  echo "server-kit · Linux SSH 管理"
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
  echo "  9. 安全启用仅公钥认证"
  echo " 10. 确认仅公钥认证"
  echo " 11. 回滚认证配置"
  echo " 12. 查看 SSH 允许网段"
  echo " 13. 添加 SSH 允许网段"
  echo " 14. 删除 SSH 允许网段"
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
    echo "下一步：1–14 操作 · m/? 菜单 · 0 退出 · 公钥账户 $AUTHORIZED_USER"
    read -r -p ">: " choice || return 0
    case "$choice" in
      1) run_menu_action status ;;
      2) read -r -p "请输入 SSH 端口，例如 22：" value; run_menu_action enable "$value" ;;
      3) read -r -p "关闭后现有 SSH 会话会断开，输入 yes 继续：" value; [[ "$value" == "yes" ]] && run_menu_action disable ;;
      4) read -r -p "密钥名称（直接回车使用 id_ed25519）：" value; run_menu_action keygen "$value" ;;
      5) select_authorized_account || true ;;
      6) run_menu_action key-list ;;
      7) run_menu_action key-add ;;
      8) run_menu_action key-remove ;;
      9) read -r -p "将关闭密码认证；确认已添加公钥？输入 yes：" value; [[ "$value" == "yes" ]] && run_menu_action auth-harden ;;
      10) run_menu_action auth-confirm ;;
      11) run_menu_action auth-rollback ;;
      12) run_menu_action network-list ;;
      13) read -r -p "输入 IPv4 CIDR，例如 192.168.1.0/24：" value; run_menu_action network-add "$value" ;;
      14) read -r -p "输入要删除的 IPv4 CIDR：" value; run_menu_action network-remove "$value" ;;
      m|M|\?) echo; write_menu ;;
      0) return 0 ;;
      *) echo "无效选项。请输入 1–14、m、? 或 0。" ;;
    esac
    echo
  done
}

if [[ "$ACTION" == "menu" ]]; then show_menu; else invoke_action "$ACTION"; fi
