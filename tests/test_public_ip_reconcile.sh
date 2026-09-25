#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_PATH="${SCRIPT_DIR}/../debian_file_manager.sh"

# shellcheck disable=SC1090
source "${MANAGER_PATH}"

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
fi

fail() {
  echo "失败：$1"
  exit 1
}

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

CONFIG_DIR="${test_dir}/config"
FILE_CONFIG_PATH="${CONFIG_DIR}/config.json"
CLASH_CONFIG_PATH="${CONFIG_DIR}/clash-config.json"
CERT_PATH="${CONFIG_DIR}/server.crt"
KEY_PATH="${CONFIG_DIR}/server.key"
CERT_IP_PATH="${CONFIG_DIR}/certificate-ip"
CLASH_PAYLOAD_DIR="${test_dir}/clash-subscriptions"
CERT_RENEW_SCRIPT="${test_dir}/renew-certificate.sh"
CERT_DEPLOY_HOOK="${test_dir}/deploy-hook"
CERT_RENEW_SERVICE_PATH="${test_dir}/secure-file-cert-renew.service"
CERT_RENEW_TIMER_PATH="${test_dir}/secure-file-cert-renew.timer"
action_log="${test_dir}/actions.log"
mkdir -p "${CONFIG_DIR}" "${CLASH_PAYLOAD_DIR}"

printf '{"mode":"clash","server_address":"9.9.9.9","port":52541,"downloads":[]}\n' \
  > "${CLASH_CONFIG_PATH}"
printf '{"server_address":"9.9.9.9","port":8443,"downloads":[]}\n' \
  > "${FILE_CONFIG_PATH}"
printf 'old-certificate\n' > "${CERT_PATH}"
printf 'old-key\n' > "${KEY_PATH}"
printf '9.9.9.9\n' > "${CERT_IP_PATH}"
printf 'payload\n' > "${CLASH_PAYLOAD_DIR}/subscription.yaml"

get_public_ip() { printf '8.8.8.8\n'; }
get_publication_address() { printf 'gateway-demo.duckdns.org\n'; }
install_certbot() { CERTBOT_BIN="${test_dir}/certbot"; }
obtain_public_certificate() { printf 'obtain:%s\n' "$1" >> "${action_log}"; }
deploy_public_certificate() {
  printf 'new-certificate:%s\n' "$1" > "${CERT_PATH}"
  printf 'new-key:%s\n' "$1" > "${KEY_PATH}"
  printf '%s\n' "$1" > "${CERT_IP_PATH}"
}
write_certificate_automation() { printf 'automation:%s\n' "$1" >> "${action_log}"; }
enable_certificate_timer() { printf 'enable-timer\n' >> "${action_log}"; }
refresh_clash_subscriptions() {
  local _source="${1:-}"
  local address="${2:-}"
  printf 'refresh-clash:%s\n' "${address}" >> "${action_log}"
  update_config_server_address "${CLASH_CONFIG_PATH}" "${address}"
}
systemctl() {
  case "${1:-}" in
    is-active) [[ "${SYSTEMCTL_ACTIVE:-1}" == "1" ]] ;;
    restart|try-restart|daemon-reload) printf 'systemctl:%s:%s\n' "$1" "${2:-}" >> "${action_log}" ;;
    *) return 0 ;;
  esac
}
openssl() {
  if [[ "$*" == *"-checkhost gateway-demo.duckdns.org"* ]] && grep -Fq 'gateway-demo.duckdns.org' "${CERT_PATH}"; then
    return 0
  fi
  return 1
}

reconcile_public_ip --yes >/dev/null || fail "公网 IP 对账失败"
[[ "$(stat -c '%a' "${CONFIG_DIR}")" == "750" ]] ||
  fail "公网发布地址对账破坏了服务配置目录的组读取权限"

python3 - "${CLASH_CONFIG_PATH}" "${FILE_CONFIG_PATH}" <<'PYTHON' || fail "服务地址没有同步到新 IP"
import json
import sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as source:
        assert json.load(source)["server_address"] == "gateway-demo.duckdns.org"
PYTHON
grep -Fxq 'obtain:gateway-demo.duckdns.org' "${action_log}" || fail "没有为发布域名申请证书"
grep -Fxq 'refresh-clash:gateway-demo.duckdns.org' "${action_log}" || fail "没有按发布域名重建 Clash 订阅"
grep -Fxq 'automation:gateway-demo.duckdns.org' "${action_log}" || fail "没有更新证书自动化"
audit_public_ip >/dev/null || fail "对账完成后公网 IP 审计仍失败"

update_config_server_address "${FILE_CONFIG_PATH}" "9.9.9.9"
if audit_public_ip >/dev/null 2>&1; then
  fail "公网文件地址回到旧 IP 后审计仍然通过"
fi

rm -f -- "${CERT_IP_PATH}"
SYSTEMCTL_ACTIVE=0
: > "${action_log}"
reconcile_public_ip --yes >/dev/null || fail "服务未启动且证书状态文件缺失时公网 IP 对账失败"
if grep -Fq 'systemctl:restart:' "${action_log}"; then
  fail "公网 IP 对账错误启动了原本未运行的服务"
fi

grep -Fq 'reconcile-public-ip --yes' "${MANAGER_PATH}" ||
  fail "证书续期服务没有自动执行公网 IP 对账"
grep -Fq 'renew --cert-name "${public_address}" --quiet' "${MANAGER_PATH}" ||
  fail "证书续期任务没有限定为当前公网发布证书"
grep -Fq 'OnBootSec=2m' "${MANAGER_PATH}" ||
  fail "证书检查没有在开机后及时运行"

echo "通过：公网发布地址对账会保留配置结构并同步证书、订阅和文件地址。"
echo "通过：发布地址差异会被审计发现，证书任务会在开机后自动修复。"
