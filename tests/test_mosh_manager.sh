#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANAGER="${REPO_DIR}/debian_mosh_manager.sh"

fail() {
  echo "失败：$1"
  exit 1
}

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT
state_path="${test_dir}/mosh.conf"
awg_state="${test_dir}/awg.conf"
action_log="${test_dir}/actions.log"
package_marker="${test_dir}/mosh-installed"
firewall_marker="${test_dir}/firewall-enabled"

cat > "${awg_state}" <<'EOF'
AWG_IFACE=awg0
AWG_SERVER_IP=10.20.0.1
AWG_SUBNET_CIDR=10.20.0.0/24
EOF

cat > "${test_dir}/apt-get" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
printf 'apt-get %s\n' "$*" >> "${ACTION_LOG}"
case " $* " in
  *" install "*) touch "${PACKAGE_MARKER}" ;;
  *" purge "*) rm -f -- "${PACKAGE_MARKER}" ;;
esac
BASH

cat > "${test_dir}/dpkg-query" <<'BASH'
#!/usr/bin/env bash
[[ -f "${PACKAGE_MARKER}" ]] || exit 1
printf 'install ok installed'
BASH

cat > "${test_dir}/security-manager" <<'BASH'
#!/usr/bin/env bash
printf 'security %s\n' "$*" >> "${ACTION_LOG}"
BASH

cat > "${test_dir}/firewall-manager" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
printf 'firewall %s\n' "$*" >> "${ACTION_LOG}"
case "${1:-}" in
  apply)
    if grep -Fq 'MOSH_ENABLED=yes' "${MOSH_STATE_PATH}" 2>/dev/null; then
      touch "${FIREWALL_MARKER}"
    else
      rm -f -- "${FIREWALL_MARKER}"
    fi
    ;;
esac
BASH

cat > "${test_dir}/nft" <<'BASH'
#!/usr/bin/env bash
if [[ -f "${FIREWALL_MARKER}" ]]; then
  case "$*" in
    *"chain inet server_kit_filter input"*)
      echo 'iifname "awg0" ip saddr 10.20.0.0/24 ip daddr 10.20.0.1 udp dport @awg_udp_ports accept'
      exit 0
      ;;
    *"set inet server_kit_filter awg_udp_ports"*)
      echo 'set awg_udp_ports { elements = { 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010 } }'
      exit 0
      ;;
    *"set inet server_kit_filter public_udp_ports"*)
      echo 'set public_udp_ports { elements = { 443, 1848, 8443 } }'
      exit 0
      ;;
  esac
fi
exit 1
BASH

cat > "${test_dir}/pgrep" <<'BASH'
#!/usr/bin/env bash
exit 1
BASH

cat > "${test_dir}/pkill" <<'BASH'
#!/usr/bin/env bash
printf 'pkill %s\n' "$*" >> "${ACTION_LOG}"
exit 0
BASH

chmod +x "${test_dir}/"{apt-get,dpkg-query,security-manager,firewall-manager,nft,pgrep,pkill}

common_env=(
  SERVER_KIT_TESTING=1
  SERVER_KIT_DIR="${test_dir}"
  MOSH_STATE_PATH="${state_path}"
  AWG_STATE_PATH="${awg_state}"
  APT_GET_BIN="${test_dir}/apt-get"
  DPKG_QUERY_BIN="${test_dir}/dpkg-query"
  SECURITY_MANAGER="${test_dir}/security-manager"
  FIREWALL_MANAGER="${test_dir}/firewall-manager"
  NFT_BIN="${test_dir}/nft"
  PGREP_BIN="${test_dir}/pgrep"
  PKILL_BIN="${test_dir}/pkill"
  ACTION_LOG="${action_log}"
  PACKAGE_MARKER="${package_marker}"
  FIREWALL_MARKER="${firewall_marker}"
)

install_output="$(env "${common_env[@]}" bash "${MANAGER}" install)"
grep -Fq 'Mosh 已安装并仅向 AWG 内网开放' <<< "${install_output}" ||
  fail "安装结果没有说明访问边界"
grep -Fq 'MOSH_ENABLED=yes' "${state_path}" || fail "安装后没有启用 Mosh"
grep -Fq 'MOSH_PORT=60001' "${state_path}" || fail "没有固定使用 UDP 60001"
grep -Fq 'MOSH_PORT_START=60001' "${state_path}" || fail "没有记录 Mosh 起始端口"
grep -Fq 'MOSH_PORT_END=60010' "${state_path}" || fail "没有记录 Mosh 结束端口"
grep -Fq 'MOSH_BIND_IP=10.20.0.1' "${state_path}" || fail "没有绑定 AWG 服务端地址"
grep -Fq 'MOSH_SUBNET_CIDR=10.20.0.0/24' "${state_path}" || fail "没有限制 AWG 来源网段"
grep -Fq 'firewall apply --yes' "${action_log}" || fail "安装没有应用防火墙"
grep -Fq 'firewall confirm --yes' "${action_log}" || fail "安装没有确认防火墙事务"

status_output="$(env "${common_env[@]}" bash "${MANAGER}" status)"
grep -Fq '状态：已启用' <<< "${status_output}" || fail "状态没有显示已启用"
grep -Fq '范围：仅 AWG 10.20.0.0/24' <<< "${status_output}" || fail "状态没有显示内网边界"
grep -Fq '监听：10.20.0.1:60001-60010/UDP（按需启动）' <<< "${status_output}" ||
  fail "状态没有显示完整端口范围"
grep -Fq 'mosh -p 60001:60010 --bind-server=10.20.0.1' <<< "${status_output}" ||
  fail "状态没有给出受限连接命令"

env "${common_env[@]}" bash "${MANAGER}" stop >/dev/null
grep -Fq 'MOSH_ENABLED=no' "${state_path}" || fail "停止后没有禁用 Mosh"
[[ ! -e "${firewall_marker}" ]] || fail "停止后没有撤销防火墙放行"
grep -Fq 'pkill -x mosh-server' "${action_log}" || fail "停止后没有清理活动会话"

env "${common_env[@]}" bash "${MANAGER}" install >/dev/null
env "${common_env[@]}" bash "${MANAGER}" uninstall --yes >/dev/null
[[ ! -e "${state_path}" ]] || fail "卸载后仍保留状态文件"
[[ ! -e "${package_marker}" ]] || fail "卸载后仍保留 Mosh 软件包"
[[ ! -e "${firewall_marker}" ]] || fail "卸载后仍放行 Mosh 端口"

echo "通过：Mosh 安装、状态、停止和卸载生命周期符合预期。"
echo "通过：Mosh 使用 UDP 60001-60010，并明确限制为 AWG 内网。"
