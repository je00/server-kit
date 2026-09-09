#!/usr/bin/env bash
# 验证切换 SSH 端口时会在配置校验前准备 OpenSSH 运行目录。
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
MANAGER="${ROOT_DIR}/web/dashboard/script_templates/server-kit-ssh-linux.sh"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/config" "$TEST_DIR/state"

cat >"$TEST_DIR/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$TEST_DIR/bin/ip" <<'EOF'
#!/usr/bin/env bash
echo '7: sk-awg-main    inet 172.31.50.12/20 scope global sk-awg-main'
EOF

cat >"$TEST_DIR/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "is-active" && "${*: -1}" == "firewalld" ]]; then exit 1; fi
if [[ "${1:-}" == "is-active" ]]; then echo active; exit 0; fi
if [[ "${1:-}" == "is-enabled" ]]; then echo enabled; exit 0; fi
exit 0
EOF

cat >"$TEST_DIR/bin/ufw" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "status" ]] && echo 'Status: inactive'
exit 0
EOF

cat >"$TEST_DIR/bin/firewall-cmd" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$TEST_DIR/bin/ss" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TEST_DIR/bin/"*

export PATH="$TEST_DIR/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export SERVER_KIT_TESTING=1
export SERVER_KIT_SSH_CONFIG="$TEST_DIR/config/90-server-kit-awg.conf"
export SERVER_KIT_SSH_NETWORKS_FILE="$TEST_DIR/config/allowed-networks.conf"
export SERVER_KIT_SSH_FIREWALL_STATE="$TEST_DIR/state/firewall-rules"
export SERVER_KIT_AUTHORIZED_KEYS_PATH="$TEST_DIR/config/authorized_keys"
: >"$SERVER_KIT_AUTHORIZED_KEYS_PATH"

bash "$MANAGER" network-add 172.31.48.0/20 >/dev/null
bash "$MANAGER" network-remove 10.20.0.0/24 >/dev/null

unshare --mount --propagation private bash -c '
  set -euo pipefail
  mount -t tmpfs tmpfs /run
  bash "$1" enable 5080
  [[ -d /run/sshd ]]
  [[ "$(stat -c %U:%G:%a /run/sshd)" == "root:root:755" ]]
  grep -Fxq "ListenAddress 172.31.50.12" "$SERVER_KIT_SSH_CONFIG"
  ! grep -Fq "10.20." "$SERVER_KIT_SSH_CONFIG"
' _ "$MANAGER"

echo "通过：任意 IPv4 网段可用于 Linux SSH，且端口切换前会准备 /run/sshd。"
