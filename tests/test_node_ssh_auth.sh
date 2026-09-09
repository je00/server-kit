#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MANAGER="${SCRIPT_DIR}/../web/dashboard/script_templates/server-kit-ssh-linux.sh"
test_dir="$(mktemp -d)"
trap 'rm -rf -- "$test_dir"' EXIT

mkdir -p "$test_dir/bin" "$test_dir/ssh" "$test_dir/state" "$test_dir/lib"
auth_config="$test_dir/ssh/00-server-kit-auth.conf"
authorized_keys="$test_dir/authorized_keys"
system_log="$test_dir/system.log"

cat >"$test_dir/bin/sshd" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-t" ]]; then exit 0; fi
if [[ "${1:-}" == "-T" ]]; then
  if grep -q '^AuthenticationMethods publickey$' "${SERVER_KIT_SSH_AUTH_CONFIG}" 2>/dev/null; then
    printf '%s\n' 'pubkeyauthentication yes' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'authenticationmethods publickey'
  else
    printf '%s\n' 'pubkeyauthentication yes' 'passwordauthentication yes' 'kbdinteractiveauthentication yes' 'authenticationmethods any'
  fi
  exit 0
fi
exit 2
EOF

cat >"$test_dir/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"${SERVER_KIT_TEST_LOG}"
if [[ "${1:-}" == "reload" && "${SERVER_KIT_FAIL_RELOAD:-0}" == "1" && ! -e "${SERVER_KIT_FAIL_MARKER}" ]]; then
  : >"${SERVER_KIT_FAIL_MARKER}"
  exit 1
fi
exit 0
EOF

cat >"$test_dir/bin/systemd-run" <<'EOF'
#!/usr/bin/env bash
printf 'systemd-run %s\n' "$*" >>"${SERVER_KIT_TEST_LOG}"
exit 0
EOF
chmod +x "$test_dir/bin/sshd" "$test_dir/bin/systemctl" "$test_dir/bin/systemd-run"

ssh-keygen -q -t ed25519 -N '' -f "$test_dir/test-key"
cp "$test_dir/test-key.pub" "$authorized_keys"

common_env=(
  SERVER_KIT_TESTING=1
  SERVER_KIT_SSH_AUTH_CONFIG="$auth_config"
  SERVER_KIT_SSH_AUTH_STATE_DIR="$test_dir/state"
  SERVER_KIT_SSHD_RUNTIME_DIR="$test_dir/run/sshd"
  SERVER_KIT_SSH_INSTALLED_SCRIPT="$test_dir/lib/node-ssh-manager.sh"
  SERVER_KIT_SSHD_BIN="$test_dir/bin/sshd"
  SERVER_KIT_SYSTEMCTL_BIN="$test_dir/bin/systemctl"
  SERVER_KIT_SYSTEMD_RUN_BIN="$test_dir/bin/systemd-run"
  SERVER_KIT_AUTHORIZED_KEYS_PATH="$authorized_keys"
  SERVER_KIT_TEST_LOG="$system_log"
  SERVER_KIT_FAIL_MARKER="$test_dir/reload-failed-once"
)

run_manager() {
  env "${common_env[@]}" bash "$MANAGER" "$@"
}

run_manager auth-status | grep -Fq 'PasswordAuthentication yes'
run_manager auth-harden >/dev/null
grep -Fxq 'AuthenticationMethods publickey' "$auth_config"
[[ -f "$test_dir/state/auth-transaction" ]]
grep -q '^systemd-run ' "$system_log"
run_manager auth-status | grep -Fq '等待确认'
run_manager auth-rollback >/dev/null
[[ ! -e "$auth_config" && ! -e "$test_dir/state/auth-transaction" ]]

run_manager auth-harden >/dev/null
run_manager auth-confirm >/dev/null
grep -Fxq 'PasswordAuthentication no' "$auth_config"
[[ ! -e "$test_dir/state/auth-transaction" ]]

rm -f "$auth_config"
: >"$authorized_keys"
if run_manager auth-harden >/dev/null 2>&1; then
  echo "无有效公钥时不应允许关闭密码认证。" >&2
  exit 1
fi
[[ ! -e "$auth_config" && ! -e "$test_dir/state/auth-transaction" ]]

cp "$test_dir/test-key.pub" "$authorized_keys"
if env "${common_env[@]}" SERVER_KIT_FAIL_RELOAD=1 bash "$MANAGER" auth-harden >/dev/null 2>&1; then
  echo "SSH 重载失败时认证加固不应成功。" >&2
  exit 1
fi
[[ ! -e "$auth_config" && ! -e "$test_dir/state/auth-transaction" ]]

echo "通过：Linux 节点仅公钥认证支持状态、确认和失败自动恢复。"
