#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANAGER="${REPO_DIR}/debian_firewall_manager.sh"

if [[ "${MSYSTEM:-}" != "" || "$(uname -s)" == "Darwin" ]]; then
  install() {
    local directory_mode=0
    local operands=()
    while (($#)); do
      case "$1" in
        -d) directory_mode=1; shift ;;
        -m|-o|-g) shift 2 ;;
        --) shift ;;
        *) operands+=("$1"); shift ;;
      esac
    done
    if (( directory_mode )); then
      mkdir -p -- "${operands[@]}"
    else
      cp -- "${operands[${#operands[@]}-2]}" "${operands[${#operands[@]}-1]}"
    fi
  }
  export -f install
fi

fail() {
  echo "失败：$1"
  exit 1
}

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT
server_kit_dir="${test_dir}/server-kit"
ports_path="${server_kit_dir}/ports.json"
awg_state="${test_dir}/awg.conf"
fake_security="${test_dir}/security-manager.sh"
fake_nft="${test_dir}/nft"
fake_systemctl="${test_dir}/systemctl"
fake_systemd_run="${test_dir}/systemd-run"
fake_sshd="${test_dir}/sshd"
fake_ip="${test_dir}/ip"
public_interface_state="${test_dir}/public-interface"
nft_state="${test_dir}/nft-state"
action_log="${test_dir}/actions.log"
install -d "${server_kit_dir}"
printf 'eth0\n' > "${public_interface_state}"

cat > "${ports_path}" <<'JSON'
{
  "policy": {"unmanaged_firewall_action": "deny_by_default"},
  "listeners": [
    {"id":"ssh-public","protocol":"tcp","port":62222,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"xray-0","protocol":"tcp","port":443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"clash-subscription","protocol":"tcp","port":52541,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"amneziawg-primary","protocol":"udp","port":443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"amneziawg-backup1","protocol":"udp","port":8443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"amneziawg-backup2","protocol":"udp","port":1848,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"ssh-amneziawg","protocol":"tcp","port":22,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":true},
    {"id":"management-web","protocol":"tcp","port":9080,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":true},
    {"id":"mosh-awg","protocol":"udp","port":60001,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60002","protocol":"udp","port":60002,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60003","protocol":"udp","port":60003,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60004","protocol":"udp","port":60004,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60005","protocol":"udp","port":60005,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60006","protocol":"udp","port":60006,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60007","protocol":"udp","port":60007,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60008","protocol":"udp","port":60008,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60009","protocol":"udp","port":60009,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true},
    {"id":"mosh-awg-60010","protocol":"udp","port":60010,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true}
  ],
  "observed_unmanaged": []
}
JSON

cat > "${awg_state}" <<'EOF'
AWG_IFACE=awg0
AWG_SERVER_IP=10.20.0.1
AWG_SUBNET_CIDR=10.20.0.0/24
EOF

cat > "${fake_security}" <<'BASH'
#!/usr/bin/env bash
case "${1:-}" in
  refresh-ports) exit 0 ;;
  audit-ports) echo "端口审计通过" ;;
  *) exit 1 ;;
esac
BASH

cat > "${fake_ip}" <<'BASH'
#!/usr/bin/env bash
public_interface="$(cat "${PUBLIC_INTERFACE_STATE}")"
if [[ "$*" == "-4 route show default" ]]; then
  [[ -n "${public_interface}" ]] || exit 1
  echo "default via 203.0.113.1 dev ${public_interface}"
elif [[ "$*" == "-4 route get 1.1.1.1" ]]; then
  [[ -n "${public_interface}" ]] || exit 1
  echo "1.1.1.1 via 203.0.113.1 dev ${public_interface} src 203.0.113.10"
else
  exit 1
fi
BASH

cat > "${fake_sshd}" <<'BASH'
#!/usr/bin/env bash
[[ "${1:-}" == "-T" ]] || exit 1
cat <<'EOF'
passwordauthentication no
kbdinteractiveauthentication no
permitrootlogin prohibit-password
authenticationmethods publickey
EOF
BASH

cat > "${fake_nft}" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
printf 'nft %s\n' "$*" >> "${ACTION_LOG}"
case "${1:-}" in
  list)
    [[ -f "${NFT_STATE}" ]] || exit 1
    if [[ "${2:-}" == "set" ]]; then
      set_name="${5:-}"
      values=""
      if [[ -r "${NFT_STATE}.dynamic" ]]; then
        values="$(awk -F '\t' -v name="${set_name}" '$1 == name {print $2}' "${NFT_STATE}.dynamic" | paste -sd, -)"
      fi
      printf 'set %s { elements = { %s } }\n' "${set_name}" "${values}"
    else
      cat "${NFT_STATE}"
    fi
    ;;
  --check)
    [[ "${2:-}" == "--file" && -s "${3:-}" ]]
    grep -Fq 'table inet server_kit_filter' "${3}"
    ;;
  --file)
    cp -- "${2}" "${NFT_STATE}"
    ;;
  delete)
    if [[ "${2:-}" == "table" ]]; then
      rm -f -- "${NFT_STATE}"
    elif [[ "${2:-}" == "element" && -r "${NFT_STATE}.dynamic" ]]; then
      port="$(grep -oE '[0-9]+' <<< "${6:-}" | head -n 1)"
      awk -F '\t' -v name="${5:-}" -v port="${port}" \
        '!($1 == name && $2 == port)' "${NFT_STATE}.dynamic" > "${NFT_STATE}.dynamic.tmp"
      mv -- "${NFT_STATE}.dynamic.tmp" "${NFT_STATE}.dynamic"
    fi
    ;;
  add)
    if [[ "${2:-}" == "element" ]]; then
      port="$(grep -oE '[0-9]+' <<< "${6:-}" | head -n 1)"
      [[ -z "${NFT_FAIL_ADD_PORT:-}" || "${port}" != "${NFT_FAIL_ADD_PORT}" ]] || exit 1
      printf '%s\t%s\n' "${5:-}" "${port}" >> "${NFT_STATE}.dynamic"
    fi
    exit 0
    ;;
  *) exit 1 ;;
esac
BASH

cat > "${fake_systemctl}" <<'BASH'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${ACTION_LOG}"
if [[ "${1:-}" == "is-active" && "${*: -1}" == "nftables.service" ]]; then
  exit 1
fi
exit 0
BASH

cat > "${fake_systemd_run}" <<'BASH'
#!/usr/bin/env bash
printf 'systemd-run %s\n' "$*" >> "${ACTION_LOG}"
BASH
chmod +x "${fake_security}" "${fake_nft}" "${fake_systemctl}" \
  "${fake_systemd_run}" "${fake_sshd}" "${fake_ip}"

common_env=(
  SERVER_KIT_TESTING=1
  SERVER_KIT_DIR="${server_kit_dir}"
  PORTS_PATH="${ports_path}"
  CANDIDATE_PATH="${server_kit_dir}/firewall-candidate.nft"
  ACTIVE_RULES_PATH="${server_kit_dir}/firewall.nft"
  TRANSACTION_PATH="${server_kit_dir}/firewall-transaction.json"
  CUSTOM_PORTS_PATH="${server_kit_dir}/custom-ports.json"
  BACKUP_DIR="${server_kit_dir}/backups"
  SERVICE_PATH="${test_dir}/systemd/server-kit-firewall.service"
  SECURITY_MANAGER="${fake_security}"
  NFT_BIN="${fake_nft}"
  SYSTEMCTL_BIN="${fake_systemctl}"
  SYSTEMD_RUN_BIN="${fake_systemd_run}"
  SSHD_BIN="${fake_sshd}"
  IP_BIN="${fake_ip}"
  AWG_STATE_PATH="${awg_state}"
  NFT_STATE="${nft_state}"
  ACTION_LOG="${action_log}"
  PUBLIC_INTERFACE_STATE="${public_interface_state}"
  ROLLBACK_SECONDS=60
)

plan_output="$(env "${common_env[@]}" bash "${MANAGER}" plan)"
grep -Fq 'elements = { 443, 52541, 62222 }' <<< "${plan_output}" ||
  fail "公网 TCP 集合不正确"
grep -Fq 'elements = { 443, 1848, 8443 }' <<< "${plan_output}" ||
  fail "公网 UDP 集合不正确"
grep -Fq 'elements = { 22, 9080 }' "${server_kit_dir}/firewall-candidate.nft" ||
  fail "AWG TCP 集合缺少 SSH 或管理网站端口"
grep -Fq 'iifname "awg0" ip saddr 10.20.0.0/24 ip daddr 10.20.0.1 tcp dport @awg_tcp_ports' \
  "${server_kit_dir}/firewall-candidate.nft" || fail "缺少 AWG TCP 内网精确规则"
grep -Fq 'elements = { 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010 }' "${server_kit_dir}/firewall-candidate.nft" ||
  fail "AWG UDP 集合缺少完整的 Mosh 端口范围"
grep -Fq 'iifname "awg0" ip saddr 10.20.0.0/24 ip daddr 10.20.0.1 udp dport @awg_udp_ports' \
  "${server_kit_dir}/firewall-candidate.nft" || fail "缺少 Mosh 的 AWG 内网精确规则"
grep -Fq 'meta nfproto ipv4 iifname "eth0" tcp dport @public_tcp_ports' \
  "${server_kit_dir}/firewall-candidate.nft" || fail "公网 TCP 规则没有绑定公网接口"
grep -Fq 'meta nfproto ipv4 iifname "eth0" udp dport @public_udp_ports' \
  "${server_kit_dir}/firewall-candidate.nft" || fail "公网 UDP 规则没有绑定公网接口"
if grep -Fq 'meta nfproto ipv6 iifname "eth0"' "${server_kit_dir}/firewall-candidate.nft"; then
  fail "IPv4 公网入口意外放行了 IPv6 业务端口"
fi
if grep -Fq 'iifname "eth0" ip daddr 203.0.113.10' "${server_kit_dir}/firewall-candidate.nft"; then
  fail "公网防火墙规则仍绑定易变目标 IPv4"
fi
grep -Fq 'set temporary_public_udp_ports' "${server_kit_dir}/firewall-candidate.nft" ||
  fail "缺少公网 UDP 临时端口集合"
grep -Fq 'set temporary_awg_tcp_ports' "${server_kit_dir}/firewall-candidate.nft" ||
  fail "缺少 AWG TCP 临时端口集合"
grep -Fq 'set temporary_awg_udp_ports' "${server_kit_dir}/firewall-candidate.nft" ||
  fail "缺少 AWG UDP 临时端口集合"
public_udp_line="$(grep -F 'elements = { 443, 1848, 8443 }' "${server_kit_dir}/firewall-candidate.nft")"
[[ "${public_udp_line}" != *60001* ]] || fail "Mosh 端口错误进入公网 UDP 集合"
[[ "${public_udp_line}" != *60010* ]] || fail "Mosh 端口范围错误进入公网 UDP 集合"

env "${common_env[@]}" bash "${MANAGER}" check >/dev/null
env "${common_env[@]}" bash "${MANAGER}" apply --yes >/dev/null
[[ -r "${server_kit_dir}/firewall-transaction.json" ]] || fail "应用后没有事务文件"
[[ -r "${nft_state}" ]] || fail "应用后没有加载自有表"
grep -Fq 'systemd-run --quiet --unit=server-kit-firewall-rollback' "${action_log}" ||
  fail "应用前没有安排自动回滚"

env "${common_env[@]}" bash "${MANAGER}" confirm --yes >/dev/null
[[ -r "${server_kit_dir}/firewall.nft" ]] || fail "确认后没有持久规则"
[[ ! -e "${server_kit_dir}/firewall-transaction.json" ]] || fail "确认后事务未清理"
grep -Fq 'systemctl enable --now server-kit-firewall.service' "${action_log}" ||
  fail "确认后没有启用独立防火墙服务"
grep -Fq "ExecStart=${MANAGER} restore-active" \
  "${test_dir}/systemd/server-kit-firewall.service" ||
  fail "防火墙服务没有使用当前受管版本恢复规则"
grep -Fq 'Restart=on-failure' "${test_dir}/systemd/server-kit-firewall.service" ||
  fail "默认路由未就绪时防火墙服务不会自动重试"
env "${common_env[@]}" bash "${MANAGER}" audit-runtime >/dev/null ||
  fail "运行规则与 systemd 状态一致时审计失败"
rm -f -- "${nft_state}"
if env "${common_env[@]}" bash "${MANAGER}" audit-runtime >/dev/null 2>&1; then
  fail "systemd 显示防火墙运行时，审计没有发现内核规则表丢失"
fi
env "${common_env[@]}" bash "${MANAGER}" restore-active >/dev/null

cp -- "${server_kit_dir}/firewall.nft" "${server_kit_dir}/firewall.before-no-route.nft"
: > "${public_interface_state}"
if env "${common_env[@]}" bash "${MANAGER}" restore-active >/dev/null 2>&1; then
  fail "默认路由不存在时仍加载了防火墙规则"
fi
cmp -s "${server_kit_dir}/firewall.before-no-route.nft" "${server_kit_dir}/firewall.nft" ||
  fail "默认路由探测失败时覆盖了持久规则"

printf 'ens3\n' > "${public_interface_state}"
env "${common_env[@]}" bash "${MANAGER}" restore-active >/dev/null
grep -Fq 'iifname "ens3" tcp dport @public_tcp_ports' "${server_kit_dir}/firewall.nft" ||
  fail "开机恢复没有把持久规则切换到新的公网接口"
if grep -Fq 'iifname "eth0" tcp dport @public_tcp_ports' "${server_kit_dir}/firewall.nft"; then
  fail "开机恢复后仍保留旧公网接口"
fi
env "${common_env[@]}" bash "${MANAGER}" audit-runtime >/dev/null ||
  fail "公网接口自动迁移后审计失败"
nft_actions_before_refresh="$(wc -l < "${action_log}")"
env "${common_env[@]}" bash "${MANAGER}" refresh-service >/dev/null ||
  fail "无法刷新防火墙开机恢复服务"
[[ "$(wc -l < "${action_log}")" -eq $((nft_actions_before_refresh + 3)) ]] ||
  fail "接口未变化时刷新服务意外重载了运行中的防火墙"

env "${common_env[@]}" bash "${MANAGER}" open-temporary 80 120 >/dev/null
env "${common_env[@]}" bash "${MANAGER}" close-temporary 80 >/dev/null
grep -Fq 'temporary_public_tcp_ports { 80 timeout 120s }' "${action_log}" ||
  fail "没有通过临时集合开放 Certbot 端口"
env "${common_env[@]}" bash "${MANAGER}" open-transaction-temporary 63333 300 --yes >/dev/null
env "${common_env[@]}" bash "${MANAGER}" close-transaction-temporary 63333 --yes >/dev/null
grep -Fq 'temporary_public_tcp_ports { 63333 timeout 300s }' "${action_log}" ||
  fail "SSH 安全事务没有通过临时集合开放新公网端口"
if env "${common_env[@]}" bash "${MANAGER}" open-transaction-temporary 63333 300 >/dev/null 2>&1; then
  fail "SSH 安全事务临时端口可以绕过 --yes"
fi

env "${common_env[@]}" bash "${MANAGER}" open-port 5201 public both 600 --yes >/dev/null
env "${common_env[@]}" bash "${MANAGER}" open-port 5202 awg tcp permanent --yes >/dev/null
if env "${common_env[@]}" bash "${MANAGER}" close-port 22 awg tcp --yes >/dev/null 2>&1; then
  fail "基础策略端口可被自定义关闭"
fi
env "${common_env[@]}" bash "${MANAGER}" verify-port open 5201 public both 600 --json | \
  grep -Fq '"facts":true,"nftables":true' || fail "未同时核验事实配置与 nftables 规则"
if env "${common_env[@]}" NFT_FAIL_ADD_PORT=5203 bash "${MANAGER}" open-port 5203 public tcp 600 --yes >/dev/null 2>&1; then
  fail "nftables 应用失败时仍报告成功"
fi
if env "${common_env[@]}" bash "${MANAGER}" list-ports --json | grep -Fq '"port":5203'; then
  fail "nftables 应用失败后遗留了自定义端口事实"
fi
if env "${common_env[@]}" bash "${MANAGER}" open-port 5203 public icmp permanent --yes >/dev/null 2>&1; then
  fail "未拒绝未登记的自定义端口协议"
fi
custom_json="$(env "${common_env[@]}" bash "${MANAGER}" list-ports --json)"
CUSTOM_JSON="${custom_json}" python3 - <<'PYTHON' || fail "自定义端口清单不正确"
import json
import os

items = json.loads(os.environ["CUSTOM_JSON"])["items"]
assert {(item["port"], item["scope"], item["protocol"], item["duration"]) for item in items} == {
    (5201, "public", "tcp", "temporary"),
    (5201, "public", "udp", "temporary"),
    (5202, "amneziawg", "tcp", "permanent"),
}
PYTHON
grep -Fq 'temporary_public_tcp_ports { 5201 timeout 600s }' "${action_log}" ||
  fail "没有开放公网 TCP 临时端口"
grep -Fq 'temporary_public_udp_ports { 5201 timeout 600s }' "${action_log}" ||
  fail "没有开放公网 UDP 临时端口"
grep -Fq 'nft add element inet server_kit_filter awg_tcp_ports { 5202 }' "${action_log}" ||
  fail "没有开放 AWG 永久 TCP 端口"
if grep -Fq 'temporary_awg_tcp_ports { 5202 timeout permanents }' "${action_log}"; then
  fail "永久端口被错误写入限时集合"
fi
env "${common_env[@]}" bash "${MANAGER}" close-port 5201 public both --yes >/dev/null
env "${common_env[@]}" bash "${MANAGER}" close-port 5202 awg tcp --yes >/dev/null
[[ "$(env "${common_env[@]}" bash "${MANAGER}" list-ports --json)" == *'"items":[]'* ]] ||
  fail "关闭后仍残留自定义端口"

echo "通过：端口扫描只生成候选规则，未运行和未托管端口不会被放行。"
echo "通过：应用、自动回滚、确认持久化和 Certbot 临时端口事务可用。"
echo "通过：自定义端口支持公网/AWG、TCP/UDP、限时和永久规则。"
