#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANAGER="${REPO_DIR}/debian_firewall_manager.sh"

if [[ "${EUID}" -ne 0 ]] || ! command -v nft >/dev/null || ! command -v unshare >/dev/null; then
  echo "跳过：真实 nftables 隔离测试需要 root、nft 和 unshare。"
  exit 0
fi

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT
mkdir -p "${test_dir}/server-kit"

cat > "${test_dir}/ports.json" <<'JSON'
{
  "policy": {"unmanaged_firewall_action": "deny_by_default"},
  "listeners": [
    {"id":"ssh-public","protocol":"tcp","port":48554,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"xray-0","service":"xray.service","protocol":"tcp","port":443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"clash-subscription","protocol":"tcp","port":52541,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"amneziawg-primary","protocol":"udp","port":443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"amneziawg-backup1","protocol":"udp","port":8443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"amneziawg-backup2","protocol":"udp","port":1848,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"ssh-amneziawg","protocol":"tcp","port":22,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":true}
  ],
  "observed_unmanaged": []
}
JSON
cat > "${test_dir}/awg.conf" <<'EOF'
AWG_IFACE=awg0
AWG_SERVER_IP=10.20.0.1
AWG_SUBNET_CIDR=10.20.0.0/24
EOF
cat > "${test_dir}/security" <<'BASH'
#!/usr/bin/env bash
case "${1:-}" in refresh-ports|audit-ports) exit 0 ;; *) exit 1 ;; esac
BASH
cat > "${test_dir}/ip" <<'BASH'
#!/usr/bin/env bash
case "$*" in
  '-4 route show default') echo 'default via 203.0.113.1 dev eth0' ;;
  '-4 route get 1.1.1.1') echo '1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.10' ;;
  *) exit 1 ;;
esac
BASH
cat > "${test_dir}/sshd" <<'BASH'
#!/usr/bin/env bash
cat <<'EOF'
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin prohibit-password
authenticationmethods publickey
EOF
BASH
cat > "${test_dir}/noop" <<'BASH'
#!/usr/bin/env bash
exit 0
BASH
cat > "${test_dir}/systemctl" <<'BASH'
#!/usr/bin/env bash
if [[ "${1:-}" == "is-active" && "${*: -1}" == "nftables.service" ]]; then
  exit 1
fi
exit 0
BASH
chmod +x "${test_dir}/security" "${test_dir}/ip" "${test_dir}/sshd" "${test_dir}/noop" "${test_dir}/systemctl"

unshare --net env \
  SERVER_KIT_TESTING=1 \
  SERVER_KIT_DIR="${test_dir}/server-kit" \
  PORTS_PATH="${test_dir}/ports.json" \
  CANDIDATE_PATH="${test_dir}/server-kit/candidate.nft" \
  ACTIVE_RULES_PATH="${test_dir}/server-kit/active.nft" \
  TRANSACTION_PATH="${test_dir}/server-kit/transaction.json" \
  CUSTOM_PORTS_PATH="${test_dir}/server-kit/custom-ports.json" \
  BACKUP_DIR="${test_dir}/server-kit/backups" \
  SERVICE_PATH="${test_dir}/server-kit/firewall.service" \
  SECURITY_MANAGER="${test_dir}/security" \
  NFT_BIN="$(command -v nft)" \
  SYSTEMCTL_BIN="${test_dir}/systemctl" \
  SYSTEMD_RUN_BIN="${test_dir}/noop" \
  SSHD_BIN="${test_dir}/sshd" \
  IP_BIN="${test_dir}/ip" \
  AWG_STATE_PATH="${test_dir}/awg.conf" \
  bash -euo pipefail -c '
    manager="$1"
    assert_set() {
      local set_name="$1"
      local pattern="$2"
      local output=""
      output="$(nft list set inet server_kit_filter "${set_name}")"
      if ! grep -Eq "${pattern}" <<< "${output}"; then
        echo "集合 ${set_name} 不符合预期：${pattern}" >&2
        echo "${output}" >&2
        return 1
      fi
    }
    bash "${manager}" plan >/dev/null
    bash "${manager}" check >/dev/null
    bash "${manager}" apply --yes >/dev/null
    bash "${manager}" confirm --yes >/dev/null
    bash "${manager}" open-port 5201 public both 600 --yes >/dev/null
    bash "${manager}" open-port 5202 awg tcp permanent --yes >/dev/null
    assert_set temporary_public_tcp_ports "5201.*timeout"
    assert_set temporary_public_udp_ports "5201.*timeout"
    assert_set awg_tcp_ports "5202"
    bash "${manager}" runtime-stop
    bash "${manager}" restore-active
    assert_set temporary_public_tcp_ports "5201.*timeout"
    assert_set awg_tcp_ports "5202"
    bash "${manager}" close-port 5201 public both --yes >/dev/null
    bash "${manager}" close-port 5202 awg tcp --yes >/dev/null
  ' _ "${MANAGER}"

echo "通过：真实 nftables 网络命名空间内，限时与永久端口均可应用并在规则重载后恢复。"
