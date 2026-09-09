#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_PATH="${SCRIPT_DIR}/../amneziawg-setup.sh"

# shellcheck disable=SC1090
source "${MANAGER_PATH}"

# Git for Windows 的 install.exe 无法在临时目录设置 Unix 权限；测试只验证内容。
if [[ "${MSYSTEM:-}" != "" ]]; then
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
      cp -- "${operands[-2]}" "${operands[-1]}"
    fi
  }

  # Git for Windows 会把软连接落成普通文件；这里仅模拟兼容路径的内容。
  ensure_awg_quick_compat_link() {
    mkdir -p -- "${AWG_QUICK_CONFIG_DIR}"
    cp -- "${CONF}" "${AWG_QUICK_COMPAT_CONF}"
  }
fi

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

DRY_RUN=1
SERVER_KIT_TESTING=1
AWG_DIR="${test_dir}/amneziawg"
AWG_QUICK_CONFIG_DIR="${test_dir}/amnezia-compat"
SERVER_KIT_DIR="${test_dir}/server-kit"
AWG_IFACE="awg-test"
AWG_SUBNET_CIDR="10.20.0.0/24"
AWG_SERVER_IP="10.20.0.1"
AWG_PUBLIC_IP="203.0.113.10"
AWG_PRIMARY_PORT="443"
AWG_BACKUP_PORT1="8443"
AWG_BACKUP_PORT2="5821"
refresh_paths


awg() {
  local action="${1:-}"
  local key=""
  local counter=0
  case "${action}" in
    genkey|genpsk)
      [[ -r "${test_dir}/key-counter" ]] && counter="$(<"${test_dir}/key-counter")"
      counter=$((counter + 1))
      printf '%s\n' "${counter}" > "${test_dir}/key-counter"
      printf 'K%042d=\n' "${counter}"
      ;;
    pubkey)
      IFS= read -r key
      [[ "${key}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
      printf 'P%s\n' "${key:1}"
      ;;
    show)
      return 0
      ;;
    *)
      echo "测试 awg 收到未知命令：${action}" >&2
      return 1
      ;;
  esac
}

qrencode() {
  local content=""
  content="$(cat)"
  grep -q '^Endpoint = ' <<< "${content}"
  echo "██ AWG 测试二维码 ██"
}


assert_manual_editor_compatible_h_values() {
  local field=""
  local value=""
  for field in AWG_H1 AWG_H2 AWG_H3 AWG_H4; do
    value="${!field//$'\r'/}"
    [[ "${value}" =~ ^[0-9]{1,9}-[0-9]{1,9}$ ]] || {
      echo "失败：${field}=${value} 超出 Windows 手动编辑器兼容的 9 位范围。"
      return 1
    }
  done
}

# 生成器使用安全随机数；重复取样把旧实现产生 10 位 H 值的复现概率提高到接近 100%。
for _ in {1..8}; do
  unset AWG_JC AWG_JMIN AWG_JMAX AWG_S1 AWG_S2 AWG_S3 AWG_S4
  unset AWG_H1 AWG_H2 AWG_H3 AWG_H4 AWG_I1
  ensure_obfuscation_parameters
  assert_manual_editor_compatible_h_values
done

install_and_run >/dev/null
printf '{"schema_version":1,"fqdn":"vpn.example.com"}\n' > "${SERVER_KIT_DIR}/public-endpoint.json"
context="$(show_enrollment_context)"
python3 - "${context}" <<'PYTHON'
import json, sys
value = json.loads(sys.argv[1])
assert [item["host"] for item in value["endpoints"]] == ["vpn.example.com"] * 3
assert [item["port"] for item in value["endpoints"]] == [443, 8443, 5821]
PYTHON
rm -f -- "${SERVER_KIT_DIR}/public-endpoint.json"
context="$(show_enrollment_context)"
python3 - "${context}" <<'PYTHON'
import json, sys
assert {item["host"] for item in json.loads(sys.argv[1])["endpoints"]} == {"203.0.113.10"}
PYTHON

[[ -f "${CONF}" ]] || { echo "失败：没有生成 AWG 服务端配置。"; exit 1; }
[[ -f "${STATE_FILE}" ]] || { echo "失败：没有保存 AWG 状态。"; exit 1; }
if [[ "${MSYSTEM:-}" != "" ]]; then
  [[ -f "${AWG_QUICK_COMPAT_CONF}" ]] || { echo "失败：没有生成 awg-quick 兼容配置。"; exit 1; }
else
  [[ -L "${AWG_QUICK_COMPAT_CONF}" ]] || { echo "失败：没有生成 awg-quick 兼容软连接。"; exit 1; }
  [[ "$(readlink "${AWG_QUICK_COMPAT_CONF}")" == "${CONF}" ]] || {
    echo "失败：awg-quick 兼容软连接没有指向真实配置。"
    exit 1
  }
fi
[[ ! -s "${PEER_DB}" ]] || { echo "失败：AWG 首次安装创建了默认节点。"; exit 1; }
if grep -q $'^dev\t\|^target\t' "${PEER_DB}"; then
  echo "失败：AWG 创建了 dev/target 默认节点。"
  exit 1
fi
grep -q '^ListenPort = 443$' "${CONF}" || { echo "失败：AWG 主监听端口不正确。"; exit 1; }
if grep -q '^destroy table ' "${NFT_RULES_PATH}"; then
  echo "失败：nftables 规则使用了 Debian 12 不支持的 destroy table。"
  exit 1
fi
grep -q '^table inet server_kit_amneziawg_filter { }$' "${NFT_RULES_PATH}" || {
  echo "失败：nftables 规则没有先声明兼容的过滤表。"
  exit 1
}
grep -q '^flush table inet server_kit_amneziawg_filter$' "${NFT_RULES_PATH}" || {
  echo "失败：nftables 规则没有仅清空 server-kit 过滤表。"
  exit 1
}
grep -q '^table ip server_kit_amneziawg_nat { }$' "${NFT_RULES_PATH}" || {
  echo "失败：nftables 规则没有先声明兼容的 NAT 表。"
  exit 1
}
grep -q '^flush table ip server_kit_amneziawg_nat$' "${NFT_RULES_PATH}" || {
  echo "失败：nftables 规则没有仅清空 server-kit NAT 表。"
  exit 1
}
grep -q 'udp dport 8443.*redirect to :443' "${NFT_RULES_PATH}" || {
  echo "失败：备用端口 8443 没有重定向到主入口。"
  exit 1
}
grep -q 'udp dport 5821.*redirect to :443' "${NFT_RULES_PATH}" || {
  echo "失败：随机备用端口没有重定向到主入口。"
  exit 1
}
if set_backup_port backup2 2053 >/dev/null 2>&1; then
  echo "失败：双入口模式仍允许新增第二个备用端口。"
  exit 1
fi
remove_backup_port backup1 >/dev/null
grep -Fq 'AWG_BACKUP_PORT1=5821' "${STATE_FILE}" || {
  echo "失败：移除 backup1 后没有保留原 backup2 端口。"
  exit 1
}
# shellcheck disable=SC1090
source "${STATE_FILE}"
[[ -z "${AWG_BACKUP_PORT2}" ]] || {
  echo "失败：移除 backup1 后仍保留第二备用入口。"
  exit 1
}
if grep -q 'udp dport 8443' "${NFT_RULES_PATH}"; then
  echo "失败：移除 backup1 后仍生成 8443 转发。"
  exit 1
fi
grep -q 'udp dport 5821.*redirect to :443' "${NFT_RULES_PATH}" || {
  echo "失败：移除 backup1 时破坏了保留的备用入口。"
  exit 1
}
context="$(show_enrollment_context)"
python3 - "${context}" <<'PYTHON'
import json, sys
value = json.loads(sys.argv[1])
assert [item["profile"] for item in value["endpoints"]] == ["main", "backup1"]
assert [item["port"] for item in value["endpoints"]] == [443, 5821]
PYTHON
if remove_backup_port backup1 >/dev/null 2>&1; then
  echo "失败：允许移除最后一个 AWG 备用入口。"
  exit 1
fi
[[ -r "${AUTO_REBOOT_CONFIG}" ]] || {
  echo "失败：安装前没有写入禁止自动重启配置。"
  exit 1
}

state_before="$(sha256sum "${STATE_FILE}" | awk '{print $1}')"
server_key_before="$(<"${SERVER_KEY_FILE}")"
install_and_run >/dev/null
state_after="$(sha256sum "${STATE_FILE}" | awk '{print $1}')"
[[ "${state_before}" == "${state_after}" ]] || {
  echo "失败：重复 install 改变了端口或混淆参数。"
  exit 1
}
[[ "${server_key_before}" == "$(<"${SERVER_KEY_FILE}")" ]] || {
  echo "失败：重复 install 重置了服务端私钥。"
  exit 1
}

external_private="$(awg genkey)"
external_public="$(printf '%s' "${external_private}" | awg pubkey)"
external_psk="$(awg genpsk)"
printf '%s\n' "${external_psk}" | add_external_peer home-desk 10.20.0.101 "${external_public}" >/dev/null
python3 - "${AWG_ACCESS_PATH}" <<'PYTHON'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
assert "home-desk" not in value.get("clients", {}), "新节点不应继承同名旧访问策略"
PYTHON
grep -Fq "PublicKey = ${external_public}" "${CONF}" || {
  echo "失败：服务端配置没有使用客户端提供的公钥。"
  exit 1
}
grep -Fq "PresharedKey = ${external_psk}" "${CONF}" || {
  echo "失败：服务端配置没有使用客户端提供的预共享密钥。"
  exit 1
}
if grep -q '限制 home-desk' "${NFT_RULES_PATH}"; then
  echo "失败：普通节点默认被访问策略限制。"
  exit 1
fi

phone_private="$(awg genkey)"
phone_public="$(printf '%s' "${phone_private}" | awg pubkey)"
phone_psk="$(awg genpsk)"
printf '%s\n' "${phone_psk}" | add_external_peer home-phone 10.20.0.102 "${phone_public}" >/dev/null
change_access_policy allow home-desk home-phone 22,443 tcp >/dev/null
if grep -q '限制 home-desk' "${NFT_RULES_PATH}"; then
  echo "失败：只保存允许项时不应改变默认完全互通模式。"
  exit 1
fi
change_access_policy mode home-desk restricted >/dev/null
grep -q 'home-desk -> home-phone' "${NFT_RULES_PATH}" || {
  echo "失败：按列表限制后没有生成允许规则。"
  exit 1
}
grep -q '限制 home-desk 横向访问' "${NFT_RULES_PATH}" || {
  echo "失败：按列表限制后没有生成兜底拦截。"
  exit 1
}
change_access_policy mode home-desk unrestricted >/dev/null
if grep -q '限制 home-desk' "${NFT_RULES_PATH}"; then
  echo "失败：恢复完全互通后仍残留拦截规则。"
  exit 1
fi
change_access_policy allow home-desk all 22,443 tcp >/dev/null
change_access_policy allow home-desk all 53 udp >/dev/null
change_access_policy mode home-desk restricted >/dev/null
[[ "$(grep -c 'ip daddr 10.20.0.0/24 tcp dport { 22, 443 }' "${NFT_RULES_PATH}")" -eq 2 ]] || {
  echo "失败：全部节点的指定端口规则没有同时覆盖 VPS 与节点转发。"
  exit 1
}
[[ "$(grep -c 'ip daddr 10.20.0.0/24 udp dport { 53 }' "${NFT_RULES_PATH}")" -eq 2 ]] || {
  echo "失败：同一目标的第二条权限没有追加生效。"
  exit 1
}
change_access_policy deny home-desk all 53 udp >/dev/null
grep -q 'tcp dport { 22, 443 }' "${NFT_RULES_PATH}" || {
  echo "失败：精确删除端口权限时误删了同目标的其他规则。"
  exit 1
}
if grep -q 'udp dport { 53 }' "${NFT_RULES_PATH}"; then
  echo "失败：精确删除后 UDP 端口规则仍然存在。"
  exit 1
fi
change_access_policy allow home-desk home-phone >/dev/null
grep -q 'ip daddr 10.20.0.102 counter accept comment "server-kit home-desk -> home-phone"' "${NFT_RULES_PATH}" || {
  echo "失败：单个节点的全部端口授权没有生效。"
  exit 1
}
change_access_policy allow home-desk all >/dev/null
if grep -q '限制 home-desk' "${NFT_RULES_PATH}"; then
  echo "失败：全部节点与全部端口没有恢复完全互通。"
  exit 1
fi
remove_peer home-phone >/dev/null

# 普通节点只向 VPS 提交公钥和 PSK，不生成或归档客户端私钥配置。
external_private="$(awg genkey)"
external_public="$(printf '%s' "${external_private}" | awg pubkey)"
external_psk="$(awg genpsk)"
printf '%s\n' "${external_psk}" | add_external_peer client-held 10.20.0.103 "${external_public}" >/dev/null
grep -Fq $'client-held\t' "${PEER_CREDENTIAL_DB}" || {
  echo "失败：普通节点没有写入独立凭据事实。"
  exit 1
}
grep -Fq $'\tclient' "${PEER_CREDENTIAL_DB}" || {
  echo "失败：节点凭据没有标记安全托管类型。"
  exit 1
}
grep -Fq "PublicKey = ${external_public}" "${CONF}" || {
  echo "失败：服务端配置没有使用客户端提供的公钥。"
  exit 1
}
grep -Fq "PresharedKey = ${external_psk}" "${CONF}" || {
  echo "失败：服务端配置没有使用客户端提供的预共享密钥。"
  exit 1
}
peer_list="$(list_peers)"
grep -Fq 'client-held' <<< "${peer_list}" || {
  echo "失败：节点列表没有显示节点名称。"
  exit 1
}
set_peer_enabled client-held 0 >/dev/null
set_peer_enabled client-held 1 >/dev/null
remove_peer client-held >/dev/null
if grep -Fq $'client-held\t' "${PEER_CREDENTIAL_DB}"; then
  echo "失败：删除节点后仍残留预共享密钥。"
  exit 1
fi

if printf 'not-a-key\n' | add_external_peer invalid-held 10.20.0.104 "${external_public}" >/dev/null 2>&1; then
  echo "失败：接受了无效的预共享密钥。"
  exit 1
fi
if any_peer_name_exists invalid-held; then
  echo "失败：无效导入留下了节点记录。"
  exit 1
fi

context_json="$(show_enrollment_context)"
python3 - "${context_json}" <<'PYTHON'
import json
import sys
value = json.loads(sys.argv[1])
assert value["schema_version"] == 1
assert value["suggested_address"] == "10.20.0.2"
assert [item["profile"] for item in value["endpoints"]] == ["main", "backup1"]
assert [item["port"] for item in value["endpoints"]] == [443, 5821]
assert value["server_public_key"]
assert "private" not in sys.argv[1].lower()
assert "preshared" not in sys.argv[1].lower()
PYTHON

enroll_private="$(awg genkey)"
enroll_public="$(printf '%s' "${enroll_private}" | awg pubkey)"
enroll_psk="$(awg genpsk)"
printf '%s\n' "${enroll_psk}" | enroll_peer pending-laptop 10.20.0.105 "${enroll_public}" >/dev/null
python3 - "${AWG_ACCESS_PATH}" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    client = json.load(source)["clients"]["pending-laptop"]
assert client == {"mode": "restricted", "allow": []}
PYTHON
show_enrollments | grep -Fq 'pending-laptop' || {
  echo "失败：新节点没有进入首次握手等待状态。"
  exit 1
}
python3 - "${ENROLLMENT_STATE}" <<'PYTHON'
import json
import os
import sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["items"]["pending-laptop"]["expires_epoch"] = 0
temporary = path + ".tmp"
with open(temporary, "w", encoding="utf-8") as output:
    json.dump(value, output)
os.replace(temporary, path)
PYTHON
reconcile_enrollments >/dev/null
if any_peer_name_exists pending-laptop; then
  echo "失败：首次握手超时后没有撤销节点。"
  exit 1
fi
show_enrollments | grep -Fq '"items":[]' || {
  echo "失败：超时节点仍残留首次握手状态。"
  exit 1
}
show_enrollments | grep -Fq '"state":"expired"' || {
  echo "失败：页面无法恢复展示首次握手已超时状态。"
  exit 1
}

if DRY_RUN=1 bash "${MANAGER_PATH}" add forbidden-node 10.20.0.120 >/dev/null 2>&1; then
  echo "失败：公开 CLI 仍可创建服务端持钥节点。"
  exit 1
fi
help_output="$(DRY_RUN=1 bash "${MANAGER_PATH}" help)"
if grep -Fq ' add <名称>' <<< "${help_output}" || grep -Fq ' config <名称>' <<< "${help_output}"; then
  echo "失败：帮助仍在引导服务端生成或读取客户端配置。"
  exit 1
fi
if declare -F show_config >/dev/null || declare -F stage_rotation >/dev/null || declare -F add_peer >/dev/null; then
  echo "失败：脚本仍加载旧服务端持钥或迁移函数。"
  exit 1
fi

# Debian 13 的 DKMS 3.2 会输出多行状态；在 pipefail 下，grep -q 提前退出会让
# 上游收到 SIGPIPE。内核检查必须完整消费输出，不能把已安装模块误判为缺失。
DRY_RUN=0
MODULES_DIR="${test_dir}/empty-modules"
RUNNING_KERNEL="6.12.100-test-running"
DEFAULT_KERNEL="6.12.101-test-default"
mkdir -p "${MODULES_DIR}/${RUNNING_KERNEL}/build" \
  "${MODULES_DIR}/${DEFAULT_KERNEL}/build" \
  "${MODULES_DIR}/4.19.0-stale"
awg-quick() { return 0; }
modinfo() { return 0; }
dkms() {
  local index=0
  printf 'amneziawg/1.0.0, %s, x86_64: installed\n' "${RUNNING_KERNEL}"
  printf 'amneziawg/1.0.0, %s, x86_64: installed\n' "${DEFAULT_KERNEL}"
  for index in {1..20000}; do
    printf 'amneziawg/1.0.0, 6.12.%s-cloud-amd64, x86_64: installed\n' "${index}"
  done
}
if ! kernel_check >/dev/null 2>"${test_dir}/kernel-check.err"; then
  cat "${test_dir}/kernel-check.err" >&2
  echo "失败：DKMS 多行输出被 pipefail/SIGPIPE 误判为模块未安装。" >&2
  exit 1
fi

echo "通过：AWG 安装默认不创建任何节点。"
echo "通过：重复安装不重置端口、混淆参数或服务端密钥。"
echo "通过：普通节点始终使用客户端提交的公钥和预共享密钥。"
echo "通过：旧 add/config/rotate 入口和实现均已移除。"
echo "通过：Debian 13 的 DKMS 多行状态不会触发 SIGPIPE 误判。"
