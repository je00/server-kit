#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1090
source "${REPO_DIR}/debian_vless_manager.sh"

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

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

CONFIG_DIR="${test_dir}/xray"
CONFIG_PATH="${CONFIG_DIR}/config.json"
SERVER_KIT_DIR="${test_dir}/server-kit"
VLESS_ACCESS_PATH="${SERVER_KIT_DIR}/vless-access.json"
VLESS_ACCESS_PENDING_PATH="${SERVER_KIT_DIR}/vless-access.pending.json"
NODE_DOMAINS_PATH="${SERVER_KIT_DIR}/node-domains.json"
VLESS_ACCESS_AUDIT_PATH="${test_dir}/log/vless-access.log"
VLESS_ACCESS_HELPER="${REPO_DIR}/lib/vless_access.py"
AWG_PEER_DB="${test_dir}/amneziawg/peers.tsv"
AWG_STATE_FILE="${test_dir}/amneziawg/manager.conf"
PUBLIC_SSH_VERIFIED_PATH="${SERVER_KIT_DIR}/run/verified"
VLESS_SKIP_SSH_GATE=1
XRAY_BIN="${test_dir}/xray-bin"

mkdir -p "${CONFIG_DIR}" "${SERVER_KIT_DIR}" "$(dirname "${AWG_PEER_DB}")"
printf 'apie-p15v\t10.20.0.201\n' > "${AWG_PEER_DB}"
printf 'AWG_SERVER_IP=10.20.0.1\n' > "${AWG_STATE_FILE}"
cat > "${NODE_DOMAINS_PATH}" <<'JSON'
{
  "version": 1,
  "nodes": {"apie-p15v": ["*.internal.example", "git.example.com"]}
}
JSON
cat > "${CONFIG_PATH}" <<'JSON'
{
  "inbounds": [
    {
      "tag": "vless-public",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "11111111-1111-4111-8111-111111111111",
            "email": "generic",
            "flow": "xtls-rprx-vision"
          }
        ]
      }
    }
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"rules": []}
}
JSON
cat > "${XRAY_BIN}" <<'EOF'
#!/usr/bin/env bash
python3 -m json.tool "${@: -1}" >/dev/null
EOF
chmod 700 "${XRAY_BIN}"

FAIL_RESTART=0
TEST_SERVICE_USER="$(id -un)"
if [[ "${MSYSTEM:-}" != "" ]]; then
  id() {
    [[ "${1:-}" == "-gn" ]] && { echo root; return 0; }
    return 0
  }
fi
systemctl() {
  case "${1:-}" in
    show) echo "${TEST_SERVICE_USER}" ;;
    restart)
      if [[ "${FAIL_RESTART}" == "1" ]]; then
        FAIL_RESTART=0
        return 1
      fi
      ;;
    is-active) return 0 ;;
    *) return 0 ;;
  esac
}

vless_access_helper client-add home-iphone --uuid 22222222-2222-4222-8222-222222222222 >/dev/null
vless_access_helper allow home-iphone vps 22 tcp >/dev/null
vless_access_helper allow home-iphone apie-p15v 22 tcp >/dev/null
apply_vless_access >/dev/null

[[ -r "${VLESS_ACCESS_PATH}" && ! -e "${VLESS_ACCESS_PENDING_PATH}" ]] || {
  echo "失败：成功应用后没有提交活动策略。"
  exit 1
}
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
clients = config["inbounds"][0]["settings"]["clients"]
assert [item["email"] for item in clients] == ["generic", "server-kit-vless:home-iphone"]
outbound = next(item for item in config["outbounds"] if item.get("tag") == "server-kit-vless-home-iphone")
assert outbound["settings"] == {"domainStrategy": "UseIP"}
assert config["dns"]["hosts"] == {
    "domain:internal.example": "10.20.0.201",
    "git.example.com": "10.20.0.201",
}
assert config["dns"]["servers"] == ["localhost"]
rules = config["routing"]["rules"]
assert rules[0]["ip"] == ["10.20.0.201/32"]
assert rules[0]["network"] == "tcp"
assert rules[1]["ip"] == ["10.20.0.1/32"]
assert rules[2]["ip"] == ["10.20.0.0/24"]
assert rules[2]["outboundTag"] == "block"
assert "ip" not in rules[3]
PYTHON

vless_access_helper allow home-iphone apie-p15v 443 tcp >/dev/null
apply_vless_access >/dev/null
require_root() { return 0; }
check_debian() { return 0; }
main deny home-iphone apie-p15v 22 tcp >/dev/null
python3 - "${VLESS_ACCESS_PENDING_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    policy = json.load(source)
rules = [
    item for item in policy["clients"]["home-iphone"]["allow"]
    if item.get("target") == "apie-p15v"
]
assert rules == [{
    "target": "apie-p15v", "ip": "10.20.0.201",
    "ports": [443], "network": "tcp",
}]
PYTHON
apply_vless_access >/dev/null
vless_access_helper deny home-iphone apie-p15v >/dev/null
apply_vless_access >/dev/null

cat > "${NODE_DOMAINS_PATH}" <<'JSON'
{
  "version": 1,
  "nodes": {"apie-p15v": ["code.example.com"]}
}
JSON
refresh_vless_domains >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
assert config["dns"]["hosts"] == {"code.example.com": "10.20.0.201"}
PYTHON

vless_access_helper allow home-iphone all >/dev/null
apply_vless_access >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
rules = config["routing"]["rules"]
full_access = next(rule for rule in rules if rule.get("ip") == ["10.20.0.0/24"] and rule.get("outboundTag") != "block")
assert "network" not in full_access
assert "port" not in full_access
PYTHON

vless_access_helper allow home-iphone all 22 tcp >/dev/null
apply_vless_access >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
rules = config["routing"]["rules"]
allows = [
    rule for rule in rules
    if rule.get("ip") == ["10.20.0.0/24"] and rule.get("outboundTag") != "block"
]
assert len(allows) == 2
limited = next(rule for rule in allows if rule.get("network") == "tcp")
assert limited["network"] == "tcp"
assert limited["port"] == "22"
PYTHON

vless_access_helper deny home-iphone all '' all >/dev/null
apply_vless_access >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
allows = [
    rule for rule in config["routing"]["rules"]
    if rule.get("ip") == ["10.20.0.0/24"] and rule.get("outboundTag") != "block"
]
assert len(allows) == 1
assert allows[0]["network"] == "tcp"
assert allows[0]["port"] == "22"
PYTHON

before_hash="$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')"
vless_access_helper client-add failing-client --uuid 33333333-3333-4333-8333-333333333333 >/dev/null
FAIL_RESTART=1
if apply_vless_access >/dev/null 2>&1; then
  echo "失败：模拟重启失败时 apply 仍返回成功。"
  exit 1
fi
after_hash="$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')"
[[ "${before_hash}" == "${after_hash}" ]] || {
  echo "失败：Xray 重启失败后没有恢复旧配置。"
  exit 1
}
[[ -r "${VLESS_ACCESS_PENDING_PATH}" ]] || {
  echo "失败：应用失败后错误提交了待应用策略。"
  exit 1
}

echo "通过：VLESS 权限应用会校验、提交活动策略并保留通用用户。"
echo "通过：VLESS 的全部节点目标覆盖完整 AWG 网段且不限制协议和端口。"
echo "通过：VLESS 的全部节点目标也可独立限制协议和端口。"
echo "通过：VLESS 同目标权限按条追加并可精确删除。"
echo "通过：VLESS 删除命令会透传协议和端口，省略范围时仍兼容删除目标。"
echo "通过：VLESS 服务端会同步全局强制解析记录，并清理旧映射。"
echo "通过：Xray 重启失败时恢复旧配置，待应用策略不会丢失。"
