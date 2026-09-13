#!/bin/zsh
# server-kit macOS SSH 综合管理器
# 使用 macOS 自带 sshd、launchd 和应用防火墙。
# 默认打开菜单；也支持服务、公钥与仅公钥认证子命令。
set -euo pipefail

ACTION="${1:-menu}"
PORT="${2:-}"
INITIAL_NETWORK="10.20.0.0/24"
LABEL="com.server-kit.sshd"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
CONFIG_DIR="/usr/local/etc/server-kit"
CONFIG="${CONFIG_DIR}/sshd_config"
NETWORKS_FILE="${SERVER_KIT_SSH_NETWORKS_FILE:-${CONFIG_DIR}/ssh-allowed-networks.conf}"
AUTH_STATE_DIR="/var/db/server-kit-ssh"
AUTH_TRANSACTION="${AUTH_STATE_DIR}/auth-transaction"
AUTH_BACKUP="${AUTH_STATE_DIR}/sshd_config.backup"
AUTH_INSTALLED_SCRIPT="/usr/local/lib/server-kit/node-ssh-manager.sh"
AUTH_ROLLBACK_LABEL="com.server-kit.ssh-auth-rollback"
AUTH_ROLLBACK_PLIST="/Library/LaunchDaemons/${AUTH_ROLLBACK_LABEL}.plist"
AUTH_ROLLBACK_SECONDS=300
AUTH_BEGIN="# server-kit 仅公钥认证开始"
AUTH_END="# server-kit 仅公钥认证结束"
CALLER_USER="${SUDO_USER:-$(id -un)}"
[[ -n "$CALLER_USER" ]] || CALLER_USER="$(id -un)"
AUTHORIZED_USER="$CALLER_USER"
RECOVERY_LABEL="com.server-kit.ssh-network-recovery"
RECOVERY_PLIST="/Library/LaunchDaemons/${RECOVERY_LABEL}.plist"
RECOVERY_SCRIPT="/Library/PrivilegedHelperTools/server-kit-ssh-network.sh"
RECOVERY_MODE=0
AUTH_SNAPSHOT=""

usage() {
  echo "用法：$0 [menu | status | enable <端口> | disable | network-list | network-add <IPv4 CIDR> | network-remove <IPv4 CIDR> | keygen [名称] | key-list | key-add | key-remove <序号> | auth-status | auth-harden | auth-confirm | auth-rollback]"
}

require_root() {
  if (( EUID != 0 )); then
    echo "请使用 sudo 运行开启或关闭操作。" >&2
    exit 1
  fi
}

configured_value() {
  local key="$1"
  awk -v key="$key" '$1 == key {print $2; exit}' "$CONFIG" 2>/dev/null || true
}

valid_ipv4() {
  local ip="$1" octet
  local -a parts
  parts=("${(@s:.:)ip}")
  ((${#parts[@]} == 4)) || return 1
  for octet in "${parts[@]}"; do
    [[ "$octet" == <-> ]] && ((octet >= 0 && octet <= 255)) || return 1
  done
}

valid_cidr() {
  local cidr="$1" address prefix
  [[ "$cidr" == */* ]] || return 1
  address="${cidr%/*}"; prefix="${cidr##*/}"
  valid_ipv4 "$address" && [[ "$prefix" == <-> ]] && ((prefix >= 0 && prefix <= 32))
}

ipv4_number() {
  local -a parts
  parts=("${(@s:.:)1}")
  echo $((parts[1] * 16777216 + parts[2] * 65536 + parts[3] * 256 + parts[4]))
}

address_in_cidr() {
  local address="$1" cidr="$2" prefix mask address_number network_number
  prefix="${cidr##*/}"; address_number="$(ipv4_number "$address")"; network_number="$(ipv4_number "${cidr%/*}")"
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
  local -A seen
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
  local -A seen
  while IFS= read -r address; do
    while IFS= read -r cidr; do
      if address_in_cidr "$address" "$cidr" && [[ -z "${seen[$address]:-}" ]]; then
        seen[$address]=1; printf '%s\n' "$address"
      fi
    done < <(allowed_networks)
  done < <(ifconfig | awk '$1 == "inet" {print $2}')
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
  [[ -n "$current_port" ]] && launchctl print "system/$LABEL" >/dev/null 2>&1 || return 0
  old_port="$PORT"; PORT="$current_port"; enable_ssh; PORT="$old_port"
}

add_network() {
  require_root
  local cidr="${PORT:-}"
  valid_cidr "$cidr" || { echo "请输入有效的 IPv4 CIDR，例如 192.168.1.0/24。" >&2; return 2; }
  allowed_networks | grep -Fxq "$cidr" && { echo "允许网段已存在：$cidr"; return 0; }
  materialize_networks_file
  printf '%s\n' "$cidr" >>"$NETWORKS_FILE"; chmod 0644 "$NETWORKS_FILE"
  reapply_ssh_if_running; echo "已加入允许网段：$cidr"
}

remove_network() {
  require_root
  local cidr="${PORT:-}" temporary network_count
  valid_cidr "$cidr" || { echo "请输入有效的 IPv4 CIDR。" >&2; return 2; }
  allowed_networks | grep -Fxq "$cidr" || { echo "允许网段不存在：$cidr" >&2; return 1; }
  network_count="$(allowed_networks | grep -c .)"
  (( network_count > 1 )) || { echo "至少保留一个允许网段，请先添加新网段。" >&2; return 2; }
  materialize_networks_file
  temporary="$(mktemp)"; grep -Fvx "$cidr" "$NETWORKS_FILE" >"$temporary" || true
  install -m 0644 "$temporary" "$NETWORKS_FILE"; rm -f "$temporary"
  reapply_ssh_if_running; echo "已删除允许网段：$cidr"
}

show_status() {
  local addresses port service startup listeners firewall remote_login
  addresses="$(awk '$1 == "ListenAddress" {print $2}' "$CONFIG" 2>/dev/null | paste -sd, -)"
  port="$(configured_value Port)"
  if launchctl print "system/$LABEL" 2>/dev/null | grep -Eq '^[[:space:]]*state = running'; then service="运行中"; else service="已停止"; fi
  if [[ ! -f "$PLIST" ]]; then startup="未安装"
  elif launchctl print-disabled system 2>/dev/null | grep -Eq '"com\.server-kit\.sshd"[[:space:]]*=>[[:space:]]*true'; then startup="已禁用"; else startup="已启用"; fi
  listeners="$(lsof -nP -a -c sshd -iTCP -sTCP:LISTEN 2>/dev/null | awk '$1 == "sshd" {print $9}' | paste -sd, -)"
  if /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | grep -q '/usr/sbin/sshd'; then firewall="已允许系统 sshd"; else firewall="未开放"; fi
  remote_login="$(systemsetup -getremotelogin 2>/dev/null | sed 's/.*: //')"
  echo "server-kit SSH 当前状态"
  echo "  服务：$service"
  echo "  自启：$startup"
  echo "  监听地址：${addresses:-未配置}"
  echo "  端口：${port:-未配置}"
  echo "  监听：${listeners:-未监听}"
  echo "  防火墙：$firewall"
  echo "  系统‘远程登录’：${remote_login:-未知}（server-kit 使用独立的系统 sshd 实例）"
  list_networks
  show_auth_status
}

target_user() {
  echo "$AUTHORIZED_USER"
}

target_home() {
  dscl . -read "/Users/$(target_user)" NFSHomeDirectory | awk '{print $2}'
}

client_home() {
  dscl . -read "/Users/$CALLER_USER" NFSHomeDirectory | awk '{print $2}'
}

manageable_accounts() {
  if (( EUID != 0 )); then
    echo "$CALLER_USER"
    return
  fi
  dscl . -list /Users UniqueID | awk '($1 == "root" || $2 >= 500) {print $1}' | awk '!seen[$0]++'
}

select_authorized_account() {
  local -a accounts
  local selected index user label
  accounts=("${(@f)$(manageable_accounts)}")
  ((${#accounts[@]})) || { echo "没有找到可管理的 macOS 账户。" >&2; return 1; }
  echo "请选择要管理公钥的 macOS 账户"
  for ((index = 1; index <= ${#accounts[@]}; index++)); do
    user="${accounts[$index]}"; label=""
    [[ "$user" == "$AUTHORIZED_USER" ]] && label=" · 当前"
    printf '  [%s] %s%s\n' "$index" "$user" "$label"
  done
  read "selected?输入账户序号："
  [[ "$selected" == <-> ]] && ((selected >= 1 && selected <= ${#accounts[@]})) || {
    echo "账户序号无效。" >&2
    return 1
  }
  AUTHORIZED_USER="${accounts[$selected]}"
  echo "已选择：$AUTHORIZED_USER"
}

authorized_keys_path() {
  echo "$(target_home)/.ssh/authorized_keys"
}

ensure_authorized_keys() {
  local user home group authorized_path
  user="$(target_user)"; home="$(target_home)"; group="$(id -gn "$user")"; authorized_path="$(authorized_keys_path)"
  install -d -m 0700 -o "$user" -g "$group" "$home/.ssh"
  touch "$authorized_path"; chown "$user:$group" "$authorized_path"; chmod 0600 "$authorized_path"
}

key_entries() {
  local authorized_path index line temp details fingerprint type name
  authorized_path="$(authorized_keys_path)"; index=0; [[ -f "$authorized_path" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(ssh-[^[:space:]]+|ecdsa-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]+(.*))?[[:space:]]*$ ]] || continue
    index=$((index + 1)); type="${match[1]}"; name="${match[4]:-未命名}"
    temp="$(mktemp)"; printf '%s\n' "$line" >"$temp"
    details="$(ssh-keygen -lf "$temp" 2>/dev/null || true)"; rm -f "$temp"
    fingerprint="$(awk '{print $2}' <<<"$details")"
    printf '%s\t%s\t%s\t%s\n' "$index" "$type" "${fingerprint:-未知}" "$name"
  done <"$authorized_path"
}

valid_authorized_key_count() {
  key_entries | awk -F '\t' '$3 != "未知" {count++} END {print count + 0}'
}

effective_auth_value() {
  local key="$1"
  [[ -f "$CONFIG" ]] || return 0
  if [[ -n "$AUTH_SNAPSHOT" ]]; then
    awk -v key="$key" '$1 == key {print $2; exit}' <<<"$AUTH_SNAPSHOT"
  else
    /usr/sbin/sshd -T -f "$CONFIG" -C "user=${AUTHORIZED_USER},host=localhost,addr=127.0.0.1" 2>/dev/null |
      awk -v key="$key" '$1 == key {print $2; exit}'
  fi
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
  if [[ -f "$CONFIG" ]]; then
    AUTH_SNAPSHOT="$(/usr/sbin/sshd -T -f "$CONFIG" -C "user=${AUTHORIZED_USER},host=localhost,addr=127.0.0.1" 2>/dev/null || true)"
    password="$(effective_auth_value passwordauthentication)"; password="${password:-未知}"
    methods="$(effective_auth_value authenticationmethods)"; methods="${methods:-未知}"
    auth_is_hardened && state="仅公钥" || state="允许其他认证"
  fi
  [[ -f "$AUTH_TRANSACTION" ]] && state="${state}（等待确认）"
  echo "  公钥：${keys} 把有效公钥（账户 ${AUTHORIZED_USER}）"
  echo "  认证：${state} · PasswordAuthentication ${password} · AuthenticationMethods ${methods}"
  AUTH_SNAPSHOT=""
}

write_auth_config() {
  local temporary
  temporary="$(mktemp)"
  awk -v begin="$AUTH_BEGIN" -v end="$AUTH_END" '
    $0 == begin {skip=1; next}
    $0 == end {skip=0; next}
    skip {next}
    !inserted && $0 ~ /^[[:space:]]*Include[[:space:]]+\/etc\/ssh\/sshd_config/ {
      print begin
      print "PubkeyAuthentication yes"
      print "PasswordAuthentication no"
      print "KbdInteractiveAuthentication no"
      print "AuthenticationMethods publickey"
      print end
      inserted=1
    }
    {print}
    END {
      if (!inserted) {
        print begin
        print "PubkeyAuthentication yes"
        print "PasswordAuthentication no"
        print "KbdInteractiveAuthentication no"
        print "AuthenticationMethods publickey"
        print end
      }
    }
  ' "$CONFIG" >"$temporary"
  install -m 0644 -o root -g wheel "$temporary" "$CONFIG"
  rm -f "$temporary"
}

cancel_auth_rollback() {
  launchctl bootout "system/$AUTH_ROLLBACK_LABEL" >/dev/null 2>&1 || true
  rm -f "$AUTH_ROLLBACK_PLIST"
}

schedule_auth_rollback() {
  install -d -m 0755 "$(dirname "$AUTH_INSTALLED_SCRIPT")"
  install -m 0700 "$0" "$AUTH_INSTALLED_SCRIPT"
  cancel_auth_rollback
  cat >"$AUTH_ROLLBACK_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$AUTH_ROLLBACK_LABEL</string>
<key>ProgramArguments</key><array><string>$AUTH_INSTALLED_SCRIPT</string><string>auth-rollback</string><string>automatic</string></array>
<key>StartInterval</key><integer>$AUTH_ROLLBACK_SECONDS</integer>
</dict></plist>
EOF
  chmod 0644 "$AUTH_ROLLBACK_PLIST"
  plutil -lint "$AUTH_ROLLBACK_PLIST" >/dev/null
  launchctl bootstrap system "$AUTH_ROLLBACK_PLIST"
}

reload_managed_sshd() {
  /usr/sbin/sshd -t -f "$CONFIG"
  launchctl kickstart -k "system/$LABEL"
  launchctl print "system/$LABEL" >/dev/null
}

rollback_auth() {
  require_root
  local automatic="${PORT:-}"
  if [[ ! -f "$AUTH_TRANSACTION" ]]; then
    [[ "$automatic" == "automatic" ]] || echo "当前没有待回滚的认证变更。"
    return 0
  fi
  [[ -f "$AUTH_BACKUP" ]] || { echo "认证回滚备份缺失。" >&2; return 1; }
  install -m 0644 -o root -g wheel "$AUTH_BACKUP" "$CONFIG"
  reload_managed_sshd
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
  [[ -f "$CONFIG" ]] || { echo "请先开启 server-kit SSH。" >&2; return 1; }
  [[ ! -f "$AUTH_TRANSACTION" ]] || { echo "已有等待确认的认证变更。" >&2; return 1; }
  local keys
  keys="$(valid_authorized_key_count)"
  [[ "$keys" == <-> ]] && ((keys >= 1)) || {
    echo "账户 ${AUTHORIZED_USER} 没有可用公钥，拒绝关闭密码认证。" >&2; return 1;
  }
  launchctl print "system/$LABEL" >/dev/null 2>&1 || { echo "server-kit SSH 未运行。" >&2; return 1; }
  install -d -m 0700 "$AUTH_STATE_DIR"
  cp -a "$CONFIG" "$AUTH_BACKUP"
  printf 'pending\n' >"$AUTH_TRANSACTION"; chmod 0600 "$AUTH_TRANSACTION" "$AUTH_BACKUP"
  if ! write_auth_config; then
    install -m 0644 -o root -g wheel "$AUTH_BACKUP" "$CONFIG"
    rm -f "$AUTH_TRANSACTION" "$AUTH_BACKUP"
    echo "无法写入认证配置，原配置保持不变。" >&2; return 1
  fi
  if ! /usr/sbin/sshd -t -f "$CONFIG" || ! schedule_auth_rollback; then
    install -m 0644 -o root -g wheel "$AUTH_BACKUP" "$CONFIG"
    rm -f "$AUTH_TRANSACTION" "$AUTH_BACKUP"
    echo "认证配置或自动回滚校验失败，原配置保持不变。" >&2; return 1
  fi
  if ! reload_managed_sshd || ! auth_is_hardened; then
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
  local entries authorized_path
  authorized_path="$(authorized_keys_path)"; entries="$(key_entries)"
  echo "允许登录 $(target_user) 的公钥"; echo "文件：$authorized_path"
  if [[ -z "$entries" ]]; then echo "  暂无公钥。"; return; fi
  while IFS=$'\t' read -r index type fingerprint name; do printf '  [%s] %s · %s · %s\n' "$index" "$type" "$fingerprint" "$name"; done <<<"$entries"
}

generate_key() {
  local user home group name key_path
  user="$CALLER_USER"; home="$(client_home)"; group="$(id -gn "$user")"; name="${PORT:-id_ed25519}"
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { echo "密钥名称格式不正确。" >&2; exit 2; }
  install -d -m 0700 -o "$user" -g "$group" "$home/.ssh"; key_path="$home/.ssh/$name"
  [[ ! -e "$key_path" ]] || { echo "密钥已存在：$key_path。请换一个名称。" >&2; exit 1; }
  echo "接下来可以设置密钥口令；直接回车表示不设置。"
  if (( EUID == 0 )) && [[ "$user" != "root" ]]; then sudo -u "$user" ssh-keygen -t ed25519 -a 64 -f "$key_path" -C "$(scutil --get ComputerName)-$user"; else ssh-keygen -t ed25519 -a 64 -f "$key_path" -C "$(scutil --get ComputerName)-$user"; fi
  echo "私钥：$key_path（不要发送给任何人）"; echo "公钥：$key_path.pub"; cat "$key_path.pub"
}

add_key() {
  ensure_authorized_keys
  local authorized_path line type blob original_name name temp
  authorized_path="$(authorized_keys_path)"; echo "请粘贴一整行公钥，然后按回车："; IFS= read -r line
  [[ "$line" =~ ^(ssh-[^[:space:]]+|ecdsa-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+([^[:space:]]+)([[:space:]]+(.*))?$ ]] || { echo "公钥格式不正确。" >&2; exit 2; }
  type="${match[1]}"; blob="${match[2]}"; original_name="${match[4]:-}"
  awk -v blob="$blob" '$2 == blob {found=1} END {exit !found}' "$authorized_path" && { echo "这把公钥已经存在。" >&2; exit 1; }
  temp="$(mktemp)"; printf '%s %s\n' "$type" "$blob" >"$temp"; ssh-keygen -lf "$temp" >/dev/null 2>&1 || { rm -f "$temp"; echo "公钥校验失败。" >&2; exit 2; }; rm -f "$temp"
  read "name?给这台客户端起个名字（直接回车保留原名称）："; name="${name:-$original_name}"
  if [[ -n "$name" ]]; then printf '%s %s %s\n' "$type" "$blob" "$name" >>"$authorized_path"; else printf '%s %s\n' "$type" "$blob" >>"$authorized_path"; fi
  ensure_authorized_keys; echo "公钥已添加。"; list_keys
}

remove_key() {
  ensure_authorized_keys
  local selected="${PORT:-}" entries count authorized_path answer current output line
  entries="$(key_entries)"; [[ -n "$entries" ]] || { echo "暂无可删除的公钥。"; return; }; list_keys
  [[ -n "$selected" ]] || read "selected?输入要删除的序号："
  [[ "$selected" =~ ^[0-9]+$ ]] || { echo "公钥序号无效。" >&2; exit 2; }
  count="$(wc -l <<<"$entries" | tr -d ' ')"; (( selected >= 1 && selected <= count )) || { echo "公钥序号无效。" >&2; exit 2; }
  read "answer?确认删除 [$selected]？输入 yes："; [[ "$answer" == "yes" ]] || { echo "已取消。"; return; }
  authorized_path="$(authorized_keys_path)"; output="$(mktemp)"; current=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*(ssh-|ecdsa-|sk-) ]]; then current=$((current + 1)); [[ "$current" == "$selected" ]] && continue; fi
    printf '%s\n' "$line" >>"$output"
  done <"$authorized_path"
  cat "$output" >"$authorized_path"; rm -f "$output"; ensure_authorized_keys; echo "公钥已删除。"; list_keys
}

network_applied() {
  local expected actual listeners deny_pattern="*" cidr
  [[ -f "$CONFIG" && "$(configured_value Port)" == "$PORT" ]] || return 1
  expected="$(managed_addresses | sort -u)"
  [[ -n "$expected" ]] || return 1
  actual="$(awk '$1 == "ListenAddress" {print $2}' "$CONFIG" | sort -u)"
  [[ "$expected" == "$actual" ]] || return 1
  while IFS= read -r cidr; do deny_pattern+=",!$cidr"; done < <(allowed_networks)
  grep -Fxq "Match Address $deny_pattern" "$CONFIG" || return 1
  listeners="$(lsof -nP -a -c sshd -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null |
    awk '$1 == "sshd" {sub(/:[0-9]+$/, "", $9); print $9}' | sort -u)"
  [[ "$expected" == "$listeners" ]]
}

install_network_recovery() {
  install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools
  [[ "${0:A}" == "$RECOVERY_SCRIPT" ]] || install -o root -g wheel -m 0700 "${0:A}" "$RECOVERY_SCRIPT"
  local temporary
  temporary="$(mktemp)"
  cat >"$temporary" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$RECOVERY_LABEL</string>
<key>ProgramArguments</key><array><string>/bin/zsh</string><string>$RECOVERY_SCRIPT</string><string>reconcile</string></array>
<key>RunAtLoad</key><true/><key>StartInterval</key><integer>30</integer>
<key>ProcessType</key><string>Background</string>
</dict></plist>
EOF
  plutil -lint "$temporary" >/dev/null
  if ! cmp -s "$temporary" "$RECOVERY_PLIST"; then
    install -o root -g wheel -m 0644 "$temporary" "$RECOVERY_PLIST"
    launchctl bootout "system/$RECOVERY_LABEL" 2>/dev/null || true
  fi
  rm -f "$temporary"
  launchctl enable "system/$RECOVERY_LABEL"
  launchctl print "system/$RECOVERY_LABEL" >/dev/null 2>&1 || launchctl bootstrap system "$RECOVERY_PLIST"
}

reconcile_network() {
  require_root
  [[ -f "$PLIST" && -f "$CONFIG" && ! -f "$AUTH_TRANSACTION" ]] || return 0
  launchctl print-disabled system 2>/dev/null | grep -Eq '"com\.server-kit\.sshd"[[:space:]]*=>[[:space:]]*true' && return 0
  PORT="$(configured_value Port)"
  [[ -n "$(managed_addresses)" ]] || return 0
  network_applied && return 0
  RECOVERY_MODE=1
  enable_ssh
}

enable_ssh() {
  require_root
  if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "开启时必须传入 1–65535 的端口。" >&2
    usage
    exit 2
  fi
  echo "[1/5] 检查允许网段对应的本机地址..."
  local preserve_auth=0 address cidr deny_pattern="*" backup="" candidate active_config attempt
  local -a addresses
  addresses=("${(@f)$(managed_addresses)}")
  ((${#addresses[@]} > 0)) || { echo "没有找到允许网段对应的本机 IPv4 地址。" >&2; exit 1; }
  if ((RECOVERY_MODE == 0)); then install_network_recovery; fi
  if network_applied && ! launchctl print-disabled system 2>/dev/null | grep -Eq '"com\.server-kit\.sshd"[[:space:]]*=>[[:space:]]*true'; then
    echo 'SSH 配置和监听未变化，无需重启。'
    return 0
  fi

  echo "[2/5] 关闭系统默认的全接口远程登录..."
  if ((RECOVERY_MODE == 0)) && ! systemsetup -getremotelogin 2>/dev/null | grep -q ': Off$' &&
     ! systemsetup -f -setremotelogin off >/dev/null 2>&1; then
    echo "无法关闭系统远程登录。请在‘系统设置 → 通用 → 共享’中先关闭远程登录。" >&2
    exit 1
  fi

  echo "[3/5] 使用系统 sshd 配置允许地址和端口 $PORT..."
  if ((RECOVERY_MODE == 0)); then ssh-keygen -A; fi
  install -d -m 0755 "$CONFIG_DIR"
  if [[ -f "$CONFIG" ]]; then
    grep -Fxq "$AUTH_BEGIN" "$CONFIG" && preserve_auth=1 || true
    backup="${CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$CONFIG" "$backup"
  fi
  candidate="$(mktemp "${CONFIG}.candidate.XXXXXX")"
  {
    echo '# 由 server-kit 管理：只监听允许网段对应的本机地址'
    echo "Port $PORT"
    for address in "${addresses[@]}"; do echo "ListenAddress $address"; done
    while IFS= read -r cidr; do deny_pattern+=",!$cidr"; done < <(allowed_networks)
    echo "Match Address $deny_pattern"
    echo '    DenyUsers *'
    echo 'Match all'
    echo 'PidFile /var/run/server-kit-sshd.pid'
    echo 'Include /etc/ssh/sshd_config'
  } >"$candidate"
  active_config="$CONFIG"; CONFIG="$candidate"
  ((preserve_auth == 0)) || write_auth_config
  CONFIG="$active_config"
  if ! /usr/sbin/sshd -t -f "$candidate"; then
    rm -f "$candidate"
    echo '候选 SSH 配置无效，运行配置未更改。' >&2
    return 1
  fi
  chmod 0644 "$candidate"
  mv -f "$candidate" "$CONFIG"

  echo "[4/5] 配置系统 launchd 自启动..."
  cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/usr/sbin/sshd</string><string>-D</string><string>-f</string><string>$CONFIG</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
  chmod 0644 "$PLIST"
  plutil -lint "$PLIST" >/dev/null

  echo "[5/5] 启动 SSH 并允许系统 sshd 通过应用防火墙..."
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  launchctl enable "system/$LABEL"
  if ! launchctl bootstrap system "$PLIST"; then
    [[ -z "$backup" ]] || cp -a "$backup" "$CONFIG"
    launchctl bootstrap system "$PLIST" 2>/dev/null || true
    echo '启动失败，已尝试恢复原配置。' >&2
    return 1
  fi
  /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/sbin/sshd >/dev/null 2>&1 || true
  /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/sbin/sshd >/dev/null 2>&1 || true
  for attempt in {1..10}; do
    network_applied && break
    sleep 0.2
  done
  if ! network_applied; then
    if [[ -n "$backup" ]]; then
      cp -a "$backup" "$CONFIG"
      launchctl kickstart -k "system/$LABEL" || true
    fi
    echo 'SSH 实际监听未通过校验，已尝试恢复原配置。' >&2
    return 1
  fi
  echo "完成：SSH 正在 ${addresses[*]} 的 ${PORT} 端口监听。"
  if ((RECOVERY_MODE == 0)); then show_status; fi
}

disable_ssh() {
  require_root
  launchctl disable "system/$RECOVERY_LABEL"
  launchctl bootout "system/$RECOVERY_LABEL" 2>/dev/null || true
  echo "[1/2] 删除系统 sshd 的应用防火墙允许项..."
  /usr/libexec/ApplicationFirewall/socketfilterfw --remove /usr/sbin/sshd >/dev/null 2>&1 || true
  echo "[2/2] 停止 SSH 并禁止开机自启..."
  launchctl disable "system/$LABEL"
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  echo "完成：SSH 服务和对应防火墙入口都已关闭。"
  show_status
}

invoke_action() {
  local lock_fd="" action_result=0
  if [[ "$1" == (enable|disable|reconcile|network-add|network-remove|auth-harden|auth-confirm|auth-rollback) ]]; then
    require_root
    zmodload zsh/system
    : >>/var/run/server-kit-ssh.lock
    zsystem flock -t 0 -f lock_fd /var/run/server-kit-ssh.lock || { echo '另一项 SSH 操作正在运行。' >&2; return 1; }
  fi
  {
  case "$1" in
    enable) enable_ssh ;;
    disable) disable_ssh ;;
    status) show_status ;;
    reconcile) reconcile_network ;;
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
  } always {
    [[ -z "$lock_fd" ]] || zsystem flock -u "$lock_fd"
  }
}

write_menu() {
  echo "server-kit · macOS SSH 管理"
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
  local action="$1" value="${2:-}" action_status
  set +e
  (set -e; PORT="$value"; invoke_action "$action")
  action_status=$?
  set -e
  ((action_status == 0)) && return 0
  echo "操作失败，请检查上面的提示。" >&2
  return 0
}

show_menu() {
  clear 2>/dev/null || true
  write_menu
  local choice value
  while true; do
    echo "下一步：1–14 操作 · m/? 菜单 · 0 退出 · 公钥账户 $AUTHORIZED_USER"
    read "choice?>: " || return 0
    case "$choice" in
      1) run_menu_action status ;;
      2) read "value?请输入 SSH 端口，例如 22："; run_menu_action enable "$value" ;;
      3) read "value?关闭后现有 SSH 会话会断开，输入 yes 继续："; [[ "$value" == "yes" ]] && run_menu_action disable ;;
      4) read "value?密钥名称（直接回车使用 id_ed25519）："; run_menu_action keygen "$value" ;;
      5) select_authorized_account || true ;;
      6) run_menu_action key-list ;;
      7) run_menu_action key-add ;;
      8) run_menu_action key-remove ;;
      9) read "value?将关闭密码认证；确认已添加公钥？输入 yes："; [[ "$value" == "yes" ]] && run_menu_action auth-harden ;;
      10) run_menu_action auth-confirm ;;
      11) run_menu_action auth-rollback ;;
      12) run_menu_action network-list ;;
      13) read "value?输入 IPv4 CIDR，例如 192.168.1.0/24："; run_menu_action network-add "$value" ;;
      14) read "value?输入要删除的 IPv4 CIDR："; run_menu_action network-remove "$value" ;;
      m|M|\?) echo; write_menu ;;
      0) return 0 ;;
      *) echo "无效选项。请输入 1–14、m、? 或 0。" ;;
    esac
    echo
  done
}

if [[ "${SERVER_KIT_LIBRARY_ONLY:-0}" != "1" ]]; then
  if [[ "$ACTION" == "menu" ]]; then show_menu; else invoke_action "$ACTION"; fi
fi
