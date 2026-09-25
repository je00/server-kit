#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANAGER="${REPO_DIR}/server-kit-manager.sh"

fail() {
  echo "失败：$1"
  exit 1
}

test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT
fake_systemctl="${test_dir}/systemctl"
fake_journalctl="${test_dir}/journalctl"
fake_security="${test_dir}/security-manager.sh"
fake_mosh="${test_dir}/mosh-manager.sh"
fake_file="${test_dir}/file-manager.sh"
fake_awg_manager="${test_dir}/awg-manager.sh"
fake_vless="${test_dir}/vless-manager.sh"
fake_qrencode="${test_dir}/qrencode"
fake_flock="${test_dir}/flock"
action_log="${test_dir}/actions.log"
systemctl_read_log="${test_dir}/systemctl-reads.log"
vless_transaction_log="${test_dir}/vless-transactions.log"
vless_transaction_state="${test_dir}/vless-transaction-state"

cat > "${fake_systemctl}" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
command="$1"
shift
if [[ -n "${SYSTEMCTL_READ_LOG:-}" ]]; then
  printf '%s %s\n' "${command}" "$*" >> "${SYSTEMCTL_READ_LOG}"
fi
[[ "${1:-}" == "--quiet" ]] && shift
unit="${1:-}"
case "${command}" in
  cat)
    case "${unit}" in
      awg-quick@awg0.service|server-kit-web.service|xray.service|secure-clash-service.service|secure-file-service.service|secure-file-cert-renew.timer|server-kit-firewall.service|ssh.service) exit 0 ;;
      *) exit 1 ;;
    esac
    ;;
  is-active) exit 0 ;;
  is-failed) exit 1 ;;
  is-enabled) exit 0 ;;
  show)
    if [[ " $* " == *" --property=Id "* ]]; then
      for argument in "$@"; do
        case "${argument}" in
          *.service|*.timer)
            printf 'Id=%s\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\n' "${argument}"
            ;;
        esac
      done
    else
      case "$*" in
        *ActiveState*) echo active ;;
        *NextElapseUSecRealtime*) echo 'Fri 2026-08-07 12:31:08 UTC' ;;
        *LastTriggerUSec*) echo 'Fri 2026-08-07 00:49:10 UTC' ;;
      esac
    fi
    ;;
  start|stop|restart|enable|disable)
    printf '%s %s\n' "${command}" "${unit}" >> "${ACTION_LOG}"
    ;;
  *) exit 1 ;;
esac
BASH

cat > "${fake_journalctl}" <<'BASH'
#!/usr/bin/env bash
printf '测试日志 %s\n' "$*"
BASH

cat > "${fake_security}" <<'BASH'
#!/usr/bin/env bash
case "${1:-}" in
  refresh-ports) exit 0 ;;
  ports) echo "测试端口清单" ;;
  audit-ports) echo "测试端口审计通过" ;;
  ssh-auth-plan) echo "测试 SSH 认证预览" ;;
  *) exit 1 ;;
esac
BASH

cat > "${fake_mosh}" <<'BASH'
#!/usr/bin/env bash
printf 'mosh %s\n' "${1:-}" >> "${ACTION_LOG}"
BASH
cat > "${fake_file}" <<'BASH'
#!/usr/bin/env bash
[[ "${1:-}" == "refresh-clash" ]] || exit 1
printf 'refresh-clash\n' >> "${ACTION_LOG}"
[[ "${FAIL_CLASH_REFRESH:-0}" != "1" ]]
BASH
cat > "${fake_awg_manager}" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  import-public|enroll)
    printf '%s\t%s\n' "${2}" "${4}" >> "${AWG_PEERS}"
    printf 'awg-%s:%s\n' "${1}" "${2}" >> "${ACTION_LOG}"
    ;;
  remove)
    temporary="$(mktemp)"
    awk -F '\t' -v name="${2}" '$1 != name' "${AWG_PEERS}" > "${temporary}"
    mv -- "${temporary}" "${AWG_PEERS}"
    printf 'awg-remove:%s\n' "${2}" >> "${ACTION_LOG}"
    ;;
  access-allow|access-deny)
    printf 'awg-%s:%s\n' "${1}" "$*" >> "${ACTION_LOG}"
    ;;
  *) exit 1 ;;
esac
BASH
cat > "${fake_vless}" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  client-add)
    python3 - "${VLESS_POLICY}" "${VLESS_PENDING_POLICY}" "${2}" <<'PYTHON'
import json, sys
active, pending, name = sys.argv[1:]
with open(active, encoding="utf-8") as source:
    value = json.load(source)
value.setdefault("clients", {})[name] = {"enabled": True, "allow": []}
with open(pending, "w", encoding="utf-8") as target:
    json.dump(value, target)
PYTHON
    ;;
  client-remove)
    python3 - "${VLESS_POLICY}" "${VLESS_PENDING_POLICY}" "${2}" <<'PYTHON'
import json, sys
active, pending, name = sys.argv[1:]
with open(active, encoding="utf-8") as source:
    value = json.load(source)
value.setdefault("clients", {}).pop(name, None)
with open(pending, "w", encoding="utf-8") as target:
    json.dump(value, target)
PYTHON
    ;;
  apply)
    mv -- "${VLESS_PENDING_POLICY}" "${VLESS_POLICY}"
    ;;
  refresh-domains)
    printf 'refresh-vless-domains\n' >> "${ACTION_LOG}"
    ;;
  listener-status|listener-preview|listener-apply|listener-confirm|listener-rollback)
    request="$(cat)"
    session_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])' <<<"${request}")"
    printf '%s|%s|control=%s|risk=%s\n' "${1}" "${request}" \
      "${SERVER_KIT_CONTROL:-0}" "${SERVER_KIT_HIGH_RISK_WRITES:-0}" \
      >> "${VLESS_TRANSACTION_LOG}"
    case "${1}" in
      listener-apply) printf 'pending|%s\n' "${session_id}" > "${VLESS_TRANSACTION_STATE}" ;;
      listener-confirm)
        stored="$(cat "${VLESS_TRANSACTION_STATE}" 2>/dev/null || true)"
        [[ "${stored}" != "pending|${session_id}" ]] || exit 1
        printf 'confirmed\n' > "${VLESS_TRANSACTION_STATE}"
        ;;
      listener-rollback) printf 'rolled_back\n' > "${VLESS_TRANSACTION_STATE}" ;;
    esac
    python3 - "${1}" "${VLESS_TRANSACTION_STATE}" "${session_id}" <<'PYTHON'
import json, os, sys
operation, path, session_id = sys.argv[1:]
stored = open(path, encoding="utf-8").read().strip() if os.path.exists(path) else "idle"
pending = stored.startswith("pending|")
origin_session = stored.split("|", 1)[1] if pending else ""
last_outcome = stored if stored in {"confirmed", "rolled_back"} else ""
print(json.dumps({
    "schema_version": 1,
    "transaction_type": "vless_listener",
    "title": "VLESS 公网监听迁移",
    "state": "pending" if pending else "idle",
    "expires_at": "2026-08-14T12:05:00+00:00" if pending else "",
    "remaining_seconds": 300 if pending else 0,
    "writes_enabled": True,
    "rollback_seconds": 300,
    "changes": [{"label": "公网监听地址", "current": "203.0.113.10", "target": "0.0.0.0", "changed": True}],
    "verifications": ["独立 VLESS 连接"],
    "ready": True,
    "blockers": [],
    "independent_session": not pending or origin_session != session_id,
    "transaction_id": "f" * 64 if pending or last_outcome else "",
    "last_outcome": last_outcome,
}, ensure_ascii=False, separators=(",", ":")))
PYTHON
    ;;
  *) exit 1 ;;
esac
BASH
cat > "${fake_qrencode}" <<'BASH'
#!/usr/bin/env bash
cat >/dev/null
printf '██  ██\n  ██  \n'
BASH
cat > "${fake_flock}" <<'BASH'
#!/usr/bin/env bash
exit 0
BASH
chmod +x "${fake_systemctl}" "${fake_journalctl}" "${fake_security}" "${fake_mosh}" "${fake_file}" "${fake_awg_manager}" "${fake_vless}" "${fake_qrencode}" "${fake_flock}"

printf 'AWG_IFACE=awg0\nAWG_SERVER_IP=10.20.0.1\n' > "${test_dir}/awg.conf"
printf 'home-desk\t10.20.0.101\napie-p15v\t10.20.0.201\n' > "${test_dir}/awg.tsv"
printf '{"clients":{"home-iphone":{"enabled":true}}}\n' > "${test_dir}/vless.json"
printf '{"version":1,"disabled":["home-nas"]}\n' > "${test_dir}/publications.json"
printf '{}\n' > "${test_dir}/xray.json"
cat > "${test_dir}/clash.json" <<'JSON'
{
  "mode": "clash",
  "server_address": "203.0.113.10",
  "port": 52541,
  "downloads": [
    {"peer_name":"home-desk","download_name":"desk.yaml","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    {"peer_name":"home-iphone","download_name":"phone.yaml","token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  ]
}
JSON
printf '{"mode":"file","server_address":"203.0.113.10","port":8444,"downloads":[]}\n' > "${test_dir}/file.json"
cat > "${test_dir}/clash-inputs.json" <<'JSON'
{
  "version": 3,
  "airports": [
    {
      "id": "111111111111",
      "name": "主用机场",
      "url": "https://airport.test/sub?token=private-token",
      "enabled": true,
      "countries": ["hk"]
    }
  ],
  "exit_proxy": {
    "name": "chain.mid.proxy",
    "type": "socks5",
    "server": "exit.test",
    "port": 1080,
    "password": "private-password",
    "dialer-proxy": "MID"
  }
}
JSON
cat > "${test_dir}/ssh-auth.conf" <<'EOF'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
AuthenticationMethods publickey
EOF
cat > "${test_dir}/mosh.conf" <<'EOF'
MOSH_ENABLED=yes
MOSH_PORT=60001
MOSH_PORT_START=60001
MOSH_PORT_END=60010
MOSH_BIND_IP=10.20.0.1
MOSH_INTERFACE=awg0
MOSH_SUBNET_CIDR=10.20.0.0/24
EOF
cat > "${test_dir}/management.conf" <<'EOF'
MANAGEMENT_ENABLED=yes
MANAGEMENT_AWG_IP=10.20.0.1
MANAGEMENT_PORT=9080
MANAGEMENT_ADMIN_PEER=home-admin
MANAGEMENT_OWNER=owner
EOF
install -d "${test_dir}/git-home/.ssh"
printf 'ssh-ed25519 test\n' > "${test_dir}/git-home/.ssh/authorized_keys"
cat > "${test_dir}/ports.json" <<'JSON'
{
  "policy": {"unmanaged_firewall_action":"deny_by_default"},
  "listeners": [
    {"service":"awg-quick@awg0.service","protocol":"udp","port":443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"service":"xray.service","protocol":"tcp","port":443,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"service":"ssh.service","protocol":"tcp","port":62222,"exposure":"public","enabled":true,"service_active":true,"listening":true},
    {"id":"ssh-amneziawg","service":"ssh.service","protocol":"tcp","port":22,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":true},
    {"id":"management-web","service":"server-kit-web.service","protocol":"tcp","port":9080,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":true},
    {"id":"mosh-awg","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60001,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60002","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60002,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60003","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60003,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60004","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60004,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60005","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60005,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60006","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60006,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60007","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60007,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60008","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60008,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60009","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60009,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"id":"mosh-awg-60010","service":"server-kit-mosh","protocol":"udp","bind_addresses":["10.20.0.1"],"port":60010,"exposure":"amneziawg","enabled":true,"service_active":true,"listening":false,"on_demand":true,"purpose":"Mosh 按需远程终端"},
    {"service":"secure-file-service.service","protocol":"tcp","port":8444,"exposure":"public","enabled":true,"service_active":true,"listening":true}
  ]
}
JSON
cat > "${test_dir}/firewall.nft" <<'NFT'
table inet server_kit_filter {
    set public_tcp_ports {
        type inet_service
        elements = { 443, 8444, 62222 }
    }
    set public_udp_ports {
        type inet_service
        elements = { 443 }
    }
    set awg_tcp_ports {
        type inet_service
        elements = { 22, 9080 }
    }
    set awg_udp_ports {
        type inet_service
        elements = { 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010 }
    }
    chain input {
        type filter hook input priority 10; policy drop;
        iifname "awg0" ip saddr 10.20.0.0/24 ip daddr 10.20.0.1 tcp dport @awg_tcp_ports accept
        iifname "awg0" ip saddr 10.20.0.0/24 ip daddr 10.20.0.1 udp dport @awg_udp_ports accept
    }
}
NFT

common_env=(
  PATH="${test_dir}:${PATH}"
  SERVER_KIT_TESTING=1
  # Mock services only: do not inherit the test host's real SSH transport.
  # The SSH protection cases below provide their own explicit connection.
  SSH_CONNECTION=""
  SERVER_KIT_QR_TEST_BASE64='iVBORw0KGgoAAAANSUhEUgAAAIAAAACA'
  SYSTEMCTL_BIN="${fake_systemctl}"
  QRENCODE_BIN="${fake_qrencode}"
  JOURNALCTL_BIN="${fake_journalctl}"
  SECURITY_MANAGER="${fake_security}"
  MOSH_MANAGER="${fake_mosh}"
  FILE_MANAGER="${fake_file}"
  AWG_MANAGER="${fake_awg_manager}"
  VLESS_MANAGER="${fake_vless}"
  VLESS_TRANSACTION_LOG="${vless_transaction_log}"
  VLESS_TRANSACTION_STATE="${vless_transaction_state}"
  PORTS_PATH="${test_dir}/ports.json"
  FIREWALL_ACTIVE_RULES="${test_dir}/firewall.nft"
  FIREWALL_CANDIDATE_RULES="${test_dir}/firewall-candidate.nft"
  FIREWALL_TRANSACTION="${test_dir}/firewall-transaction.json"
  SSH_AUTH_TRANSACTION="${test_dir}/ssh-auth-transaction.json"
  AWG_STATE="${test_dir}/awg.conf"
  AWG_PEERS="${test_dir}/awg.tsv"
  AWG_DISABLED_PEERS="${test_dir}/awg-disabled.tsv"
  AWG_ACCESS_POLICY="${test_dir}/awg-access.json"
  AWG_ACCESS_PENDING_POLICY="${test_dir}/awg-access.pending.json"
  NODE_DOMAINS_PATH="${test_dir}/node-domains.json"
  PUBLIC_ENDPOINT_PATH="${test_dir}/public-endpoint.json"
  DUCKDNS_CONFIG_PATH="${test_dir}/duckdns.json"
  VLESS_POLICY="${test_dir}/vless.json"
  VLESS_PENDING_POLICY="${test_dir}/vless.pending.json"
  XRAY_CONFIG_PATH="${test_dir}/xray.json"
  CLASH_CONFIG="${test_dir}/clash.json"
  CLASH_INPUT_CONFIG="${test_dir}/clash-inputs.json"
  CLASH_PUBLICATION_STATE="${test_dir}/publications.json"
  FILE_CONFIG="${test_dir}/file.json"
  MOSH_STATE="${test_dir}/mosh.conf"
  MANAGEMENT_STATE="${test_dir}/management.conf"
  MANAGEMENT_LOCK_PATH="${test_dir}/management-change.lock"
  SECURITY_CONTEXT_DIR="${test_dir}/security-contexts"
  SSH_AUTH_CONFIG="${test_dir}/ssh-auth.conf"
  ACTION_LOG="${action_log}"
  SYSTEMCTL_READ_LOG="${systemctl_read_log}"
)

: > "${test_dir}/awg-disabled.tsv"
printf '%s\n' '{"version":1,"clients":{}}' > "${test_dir}/awg-access.json"
printf '%s\n' '{"schema_version":1,"fqdn":"gateway-demo.managed.example.com"}' > "${test_dir}/public-endpoint.json"
proxy_update_error="${test_dir}/proxy-update-error.log"
if printf '%s' '{"operation":"exit_add","exit_name":"broken","exit_proxy_yaml":"password: must-not-leak"}' | \
  env "${common_env[@]}" SERVER_KIT_CONTROL=1 SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network proxy update --json >/dev/null 2>"${proxy_update_error}"; then
  fail "无效出口节点被错误接受"
fi
if ! grep -Fq 'SERVER_KIT_DIAGNOSTIC:proxy_input_invalid:' "${proxy_update_error}"; then
  sed -n '1,10p' "${proxy_update_error}" >&2
  fail "无效出口节点没有返回安全诊断"
fi
if grep -Fq 'must-not-leak' "${proxy_update_error}"; then
  fail "安全诊断泄露了出口节点内容"
fi

permission_output="$(env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network permission allow home-desk apie-p15v 22 tcp --json)"
PERMISSION_OUTPUT="${permission_output}" python3 - <<'PYTHON' || fail "追加权限响应不正确"
import json
import os
assert json.loads(os.environ["PERMISSION_OUTPUT"]) == {
    "schema_version": 1, "operation": "allow",
    "client": "home-desk", "target": "apie-p15v",
}
PYTHON
env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network permission deny home-desk apie-p15v 22 tcp --json >/dev/null
grep -Fq 'awg-access-allow:access-allow home-desk apie-p15v 22 tcp' "${action_log}" ||
  fail "追加端口权限没有完整传给 AWG 管理器"
grep -Fq 'awg-access-deny:access-deny home-desk apie-p15v 22 tcp' "${action_log}" ||
  fail "精确删除权限没有完整传给 AWG 管理器"
env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network permission allow home-desk apie-p15v '8002-8004,22,8000-8002' tcp --json >/dev/null
env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network permission deny home-desk apie-p15v '22,8000-8004' tcp --json >/dev/null
grep -Fq 'awg-access-allow:access-allow home-desk apie-p15v 22,8000-8004 tcp' "${action_log}" ||
  fail "端口范围没有规范化后传给 AWG 管理器"
grep -Fq 'awg-access-deny:access-deny home-desk apie-p15v 22,8000-8004 tcp' "${action_log}" ||
  fail "端口范围不能精确删除"
permission_log_lines="$(wc -l < "${action_log}")"
if env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network permission allow home-desk apie-p15v '8004-8000' tcp --json >/dev/null 2>&1; then
  fail "倒序端口范围被错误接受"
fi
[[ "$(wc -l < "${action_log}")" == "${permission_log_lines}" ]] ||
  fail "无效端口范围触发了底层写操作"

vless_add_output="$(env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network node vless add auto-phone --json)"
VLESS_ADD_OUTPUT="${vless_add_output}" python3 - "${test_dir}/vless.json" <<'PYTHON' || fail "新增 VLESS 节点没有联动发布订阅"
import json, os, sys
assert json.loads(os.environ["VLESS_ADD_OUTPUT"])["name"] == "auto-phone"
with open(sys.argv[1], encoding="utf-8") as source:
    assert "auto-phone" in json.load(source)["clients"]
PYTHON
if env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 FAIL_CLASH_REFRESH=1 \
  bash "${MANAGER}" network node vless add rollback-phone --json >/dev/null 2>&1; then
  fail "VLESS 订阅发布失败时仍保留新增任务"
fi
python3 - "${test_dir}/vless.json" <<'PYTHON' || fail "VLESS 订阅失败后没有撤销刚新增的节点"
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert "rollback-phone" not in json.load(source)["clients"]
PYTHON

public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
preshared_key='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='
awg_add_output="$(printf '%s\n' "${preshared_key}" | env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network node awg import auto-laptop 10.20.0.220 "${public_key}" --json)"
AWG_ADD_OUTPUT="${awg_add_output}" python3 - "${test_dir}/awg.tsv" <<'PYTHON' || fail "导入 AWG 节点没有联动发布订阅"
import json, os, sys
assert json.loads(os.environ["AWG_ADD_OUTPUT"])["name"] == "auto-laptop"
assert any(line.startswith("auto-laptop\t10.20.0.220") for line in open(sys.argv[1], encoding="utf-8"))
PYTHON
if printf '%s\n' "${preshared_key}" | env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 FAIL_CLASH_REFRESH=1 \
  bash "${MANAGER}" network node awg import rollback-laptop 10.20.0.221 "${public_key}" --json >/dev/null 2>&1; then
  fail "AWG 订阅发布失败时仍保留新增任务"
fi
if awk -F '\t' '$1 == "rollback-laptop" {found=1} END {exit !found}' "${test_dir}/awg.tsv"; then
  fail "AWG 订阅失败后没有撤销刚导入的节点"
fi
refresh_count="$(grep -Fc 'refresh-clash' "${action_log}")"
[[ "${refresh_count}" -ge 4 ]] || fail "新增节点没有在同一任务中刷新订阅"
env "${common_env[@]}" bash "${fake_vless}" client-remove auto-phone
env "${common_env[@]}" bash "${fake_vless}" apply
env "${common_env[@]}" bash "${fake_awg_manager}" remove auto-laptop

domain_output="$(env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network domains set home-desk '["nas.internal.example","git.example.com"]' --json)"
DOMAIN_OUTPUT="${domain_output}" python3 - <<'PYTHON' || fail "节点域名更新响应不正确"
import json
import os

value = json.loads(os.environ["DOMAIN_OUTPUT"])
assert value["name"] == "home-desk"
assert value["address"] == "10.20.0.101"
assert value["domains"] == ["nas.internal.example", "git.example.com"]
assert value["subscriptions_refreshed"] is True
assert value["xray_refreshed"] is True
PYTHON
grep -Fq 'refresh-clash' "${action_log}" || fail "节点域名更新后没有刷新全部订阅"
grep -Fq 'refresh-vless-domains' "${action_log}" || fail "节点域名更新后没有刷新 Xray DNS"
python3 - "${test_dir}/node-domains.json" <<'PYTHON' || fail "节点域名没有持久化"
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
assert value["nodes"]["home-desk"] == ["nas.internal.example", "git.example.com"]
PYTHON

custom_domain_output="$(env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network domains set-address 192.168.0.103 '["gitea.example.com"]' --json)"
CUSTOM_DOMAIN_OUTPUT="${custom_domain_output}" python3 - <<'PYTHON' || fail "自定义 IP 域名更新响应不正确"
import json
import os

value = json.loads(os.environ["CUSTOM_DOMAIN_OUTPUT"])
assert value["operation"] == "set-address"
assert value["address"] == "192.168.0.103"
assert value["domains"] == ["gitea.example.com"]
assert value["subscriptions_refreshed"] is True
assert value["xray_refreshed"] is True
PYTHON
python3 - "${test_dir}/node-domains.json" <<'PYTHON' || fail "自定义 IP 域名没有持久化"
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
assert value["addresses"]["192.168.0.103"] == ["gitea.example.com"]
assert value["nodes"]["home-desk"] == ["nas.internal.example", "git.example.com"]
PYTHON

if env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network domains set home-desk '["*.managed.example.com"]' --json >/dev/null 2>&1; then
  fail "覆盖 VPS 域名的通配符被错误接受"
fi
python3 - "${test_dir}/node-domains.json" <<'PYTHON' || fail "被拒绝的通配符改变了现有记录"
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
assert value["nodes"]["home-desk"] == ["nas.internal.example", "git.example.com"]
PYTHON

clean_output="$(env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  bash "${MANAGER}" network node awg clean-enable home-desk --json)"
CLEAN_OUTPUT="${clean_output}" python3 - "${test_dir}/publications.json" <<'PYTHON' || fail "纯净模式没有安全持久化"
import json
import os
import sys

assert json.loads(os.environ["CLEAN_OUTPUT"]) == {
    "schema_version": 1,
    "kind": "awg",
    "operation": "clean-enable",
    "name": "home-desk",
}
with open(sys.argv[1], encoding="utf-8") as source:
    state = json.load(source)
assert state == {
    "version": 1,
    "disabled": ["home-nas"],
    "clean_mode": ["home-desk"],
}
PYTHON
grep -Fq 'refresh-clash' "${action_log}" || fail "纯净模式切换后没有刷新订阅"
if env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 FAIL_CLASH_REFRESH=1 \
  bash "${MANAGER}" network node awg clean-disable home-desk --json >/dev/null 2>&1; then
  fail "订阅刷新失败时仍提交了纯净模式变更"
fi
python3 - "${test_dir}/publications.json" <<'PYTHON' || fail "订阅刷新失败后没有恢复纯净模式状态"
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    state = json.load(source)
assert state["disabled"] == ["home-nas"]
assert state["clean_mode"] == ["home-desk"]
PYTHON

transfer_peers="${test_dir}/transfer-peers.tsv"
transfer_credentials="${test_dir}/transfer-credentials.tsv"
transfer_access="${test_dir}/transfer-access.json"
transfer_management="${test_dir}/transfer-management.conf"
printf 'home-desk\t10.20.0.101\nhome-laptop2\t10.20.0.3\n' > "${transfer_peers}"
printf 'home-laptop2\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\tBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\tclient\n' > "${transfer_credentials}"
printf '{"version":1,"clients":{"home-laptop2":{"mode":"unrestricted","allow":[]}}}\n' > "${transfer_access}"
cp -- "${test_dir}/management.conf" "${transfer_management}"
cat > "${test_dir}/awg" <<'BASH'
#!/usr/bin/env bash
if [[ "$*" == "show awg0 latest-handshakes" ]]; then
  printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t%s\n' "$(date +%s)"
  exit 0
fi
exit 1
BASH
chmod +x "${test_dir}/awg"

transfer_output="$(env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  AWG_PEERS="${transfer_peers}" AWG_PEER_CREDENTIALS="${transfer_credentials}" \
  AWG_ACCESS_POLICY="${transfer_access}" MANAGEMENT_STATE="${transfer_management}" \
  bash "${MANAGER}" network node awg set-management home-laptop2 --json)"
TRANSFER_OUTPUT="${transfer_output}" python3 - <<'PYTHON' || fail "管理入口转交响应不正确"
import json
import os

assert json.loads(os.environ["TRANSFER_OUTPUT"]) == {
    "schema_version": 1,
    "kind": "awg",
    "operation": "set-management",
    "name": "home-laptop2",
}
PYTHON
grep -Fxq 'MANAGEMENT_ADMIN_PEER=home-laptop2' "${transfer_management}" ||
  fail "管理入口没有原子转交到目标节点"
if env "${common_env[@]}" SERVER_KIT_NETWORK_WRITES=1 \
  AWG_PEERS="${transfer_peers}" AWG_PEER_CREDENTIALS="${transfer_credentials}" \
  AWG_ACCESS_POLICY="${transfer_access}" MANAGEMENT_STATE="${transfer_management}" \
  bash "${MANAGER}" network node awg set-management home-laptop2 --json >/dev/null 2>&1; then
  fail "已经是管理入口的节点仍可重复转交"
fi

status_output="$(env "${common_env[@]}" COLUMNS=36 bash "${MANAGER}")"
grep -Fq 'server-kit 服务概览' <<< "${status_output}" || fail "缺少服务概览"
grep -Fq 'amneziawg' <<< "${status_output}" || fail "状态缺少 AmneziaWG"
grep -Fq '2 个普通节点' <<< "${status_output}" || fail "没有统计 AWG 节点"
grep -Fq 'UDP 443' <<< "${status_output}" || fail "没有显示 AWG 协议和端口"
grep -Fq '公网 · 监听中' <<< "${status_output}" || fail "没有显示 AWG 范围和状态"
grep -Fq '1 个受限客户端' <<< "${status_output}" || fail "没有统计 VLESS 客户端"
grep -Fq 'Mosh 终端 [mosh]' <<< "${status_output}" || fail "状态缺少 Mosh"
grep -Fq '管理网站 [management]' <<< "${status_output}" || fail "状态缺少管理网站"
grep -Fq '内网 TCP 9080' <<< "${status_output}" || fail "状态缺少管理网站端口"
grep -Fq 'UDP 60001' <<< "${status_output}" || fail "没有显示 Mosh 协议和端口"
grep -Fq 'AWG 内网 · 按需' <<< "${status_output}" || fail "没有显示 Mosh 范围和状态"
grep -Fq '防火墙策略' <<< "${status_output}" || fail "状态缺少防火墙策略"
grep -Fq '方案：nftables 独立表' <<< "${status_output}" || fail "没有说明防火墙方案"
grep -Fq 'nft list table inet \' <<< "${status_output}" || fail "手机端缺少原始规则命令"
grep -Fq 'server_kit_filter' <<< "${status_output}" || fail "没有显示防火墙规则表名"
grep -Fq '状态：已生效' <<< "${status_output}" || fail "没有显示防火墙生效状态"
grep -Fq '默认入站：拒绝' <<< "${status_output}" || fail "没有显示默认入站策略"
grep -Fq '公网 TCP：443/8444/62222' <<< "${status_output}" || fail "没有汇总公网 TCP 策略"
grep -Fq 'AWG TCP：22/9080' <<< "${status_output}" || fail "没有显示完整的 AWG TCP 策略"
grep -Fq 'AWG UDP：60001-60010' <<< "${status_output}" || fail "没有显示完整的 AWG UDP 策略"
grep -Fq '未登记入口：拒绝' <<< "${status_output}" || fail "没有显示未登记入口策略"
if grep -Fq '· 公网 · ✓' <<< "${status_output}"; then
  fail "手机布局仍将端口、范围和状态挤在一行"
fi
grep -Fq '只读保护项' <<< "${status_output}" || fail "没有标记 SSH 保护状态"
if grep -Fq '状态=' <<< "${status_output}"; then
  fail "状态仍在使用窄屏易错位的表格格式"
fi
STATUS_OUTPUT="${status_output}" python3 - <<'PYTHON' || fail "手机窄屏输出存在过长行"
import os

for line in os.environ["STATUS_OUTPUT"].splitlines():
    if line.startswith("  /"):
        continue
    if len(line) > 40:
        raise SystemExit(1)
PYTHON

wide_status_output="$(env "${common_env[@]}" COLUMNS=140 bash "${MANAGER}")"
grep -Eq '状态 +服务 +标识 +运行状态 +启动方式 +详情' <<< "${wide_status_output}" ||
  fail "宽屏状态没有使用对齐表头"
grep -Eq '✓ +AmneziaWG +amneziawg +运行中 +自启' <<< "${wide_status_output}" ||
  fail "宽屏状态没有对齐 AWG 数据"
grep -Fq '监听端口' <<< "${wide_status_output}" || fail "宽屏状态缺少独立端口表"
grep -Eq '服务 +协议 +端口 +范围 +状态' <<< "${wide_status_output}" ||
  fail "宽屏端口表缺少分列表头"
grep -Eq 'AmneziaWG +UDP +443 +公网 +监听中' <<< "${wide_status_output}" ||
  fail "宽屏端口表没有对齐 AWG 端口"
grep -Eq '方案 +nftables 独立 inet 规则表' <<< "${wide_status_output}" ||
  fail "宽屏状态没有说明防火墙方案"
grep -Eq '原始命令 +nft list table inet server_kit_filter' <<< "${wide_status_output}" ||
  fail "宽屏状态缺少原始规则命令"
grep -Eq '策略 +范围 +协议 +端口或动作' <<< "${wide_status_output}" ||
  fail "宽屏状态缺少防火墙策略表"
grep -Eq '默认入站 +全部 +全部 +拒绝' <<< "${wide_status_output}" ||
  fail "宽屏状态没有显示默认拒绝策略"
grep -Eq '公网入口 +公网 +TCP +443/8444/62222' <<< "${wide_status_output}" ||
  fail "宽屏状态没有显示公网 TCP 放行策略"
grep -Eq '内网入口 +AWG +TCP +22/9080' <<< "${wide_status_output}" ||
  fail "宽屏状态没有解析 AWG TCP 端口集合"
grep -Eq '内网入口 +AWG +UDP +60001-60010' <<< "${wide_status_output}" ||
  fail "宽屏状态没有解析 AWG UDP 端口集合"

mv -- "${test_dir}/firewall.nft" "${test_dir}/firewall.nft.saved"
fallback_status_output="$(env "${common_env[@]}" COLUMNS=140 bash "${MANAGER}")"
mv -- "${test_dir}/firewall.nft.saved" "${test_dir}/firewall.nft"
grep -Eq '内网入口 +AWG +TCP +22/9080' <<< "${fallback_status_output}" ||
  fail "规则文件不可读时没有从端口清单恢复 AWG TCP 策略"
grep -Eq '内网入口 +AWG +UDP +60001-60010' <<< "${fallback_status_output}" ||
  fail "规则文件不可读时没有从端口清单恢复 AWG UDP 策略"

: > "${systemctl_read_log}"
snapshot_output="$(env "${common_env[@]}" bash "${MANAGER}" snapshot)"
SNAPSHOT_OUTPUT="${snapshot_output}" python3 - <<'PYTHON' || fail "JSON 快照结构不正确"
import json
import os

data = json.loads(os.environ["SNAPSHOT_OUTPUT"])
assert data["schema_version"] == 1
assert data["summary"] == {"running": 9, "stopped": 0, "failed": 0, "missing": 0}
services = {item["id"]: item for item in data["services"]}
assert services["amneziawg"]["detail"] == "2 个普通节点"
assert services["amneziawg"]["ports"][0]["protocol"] == "udp"
assert services["mosh"]["detail"] == "UDP 60001-60010（按需分配）"
assert services["mosh"]["ports"][0]["scope"] == "AWG 内网"
assert services["mosh"]["ports"][0]["port"] == "60001-60010"
PYTHON
[[ "$(grep -c '^show ' "${systemctl_read_log}" || true)" == "1" ]] ||
  fail "JSON 快照没有批量读取一次 systemd 状态"
if grep -Eq '^(cat|is-active|is-failed|is-enabled) ' "${systemctl_read_log}"; then
  fail "JSON 快照仍在逐项调用 systemctl"
fi

file_overview="$(env "${common_env[@]}" bash "${MANAGER}" file overview --json)"
FILE_OVERVIEW="${file_overview}" python3 - <<'PYTHON' || fail "文件资源概览没有携带轻量服务状态"
import json
import os

overview = json.loads(os.environ["FILE_OVERVIEW"])
assert overview["service_state"] == "运行中"
assert overview["items"] == []
PYTHON

vless_inventory="$(env "${common_env[@]}" bash "${MANAGER}" inventory vless --json)"
VLESS_INVENTORY="${vless_inventory}" python3 - <<'PYTHON' || fail "VLESS 专用清单不正确"
import json
import os

inventory = json.loads(os.environ["VLESS_INVENTORY"])
assert inventory["service_id"] == "vless"
assert inventory["items"] == [
    {"name": "home-iphone", "state": "已启用", "detail": "0 条访问授权"}
]
PYTHON

mosh_inventory="$(env "${common_env[@]}" bash "${MANAGER}" inventory mosh --json)"
MOSH_INVENTORY="${mosh_inventory}" python3 - <<'PYTHON' || fail "Mosh 专用清单不正确"
import json
import os

inventory = json.loads(os.environ["MOSH_INVENTORY"])
assert inventory["facts"]["UDP 范围"] == "60001-60010"
assert inventory["facts"]["访问范围"] == "仅 AWG 内网"
PYTHON

firewall_inventory="$(env "${common_env[@]}" bash "${MANAGER}" inventory firewall --json)"
FIREWALL_INVENTORY="${firewall_inventory}" python3 - <<'PYTHON' || fail "防火墙网页清单不正确"
import json
import os

inventory = json.loads(os.environ["FIREWALL_INVENTORY"])
assert inventory["facts"]["方案"] == "nftables 独立 inet 规则表"
assert inventory["facts"]["当前状态"] == "已生效"
assert {item["detail"]: item["state"] for item in inventory["items"]}["AWG 内网 · UDP"] == "60001-60010"
PYTHON

for inventory_service in amneziawg management cert-renew ssh; do
  inventory_output="$(env "${common_env[@]}" bash "${MANAGER}" inventory "${inventory_service}" --json)"
  INVENTORY_OUTPUT="${inventory_output}" python3 - <<'PYTHON' || fail "服务网页清单为空：${inventory_service}"
import json
import os

inventory = json.loads(os.environ["INVENTORY_OUTPUT"])
assert inventory["facts"]
PYTHON
done

secret_output="$(env "${common_env[@]}" bash "${MANAGER}" reveal clash subscription-link home-desk --json)"
SECRET_OUTPUT="${secret_output}" python3 - <<'PYTHON' || fail "Clash 单节点链接输出不正确"
import json
import os

resource = json.loads(os.environ["SECRET_OUTPUT"])
assert resource["resource"] == "clash_subscription_link"
assert resource["item_id"] == "home-desk"
assert resource["value"] == "https://203.0.113.10:52541/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/desk.yaml"
PYTHON

airport_link_output="$(env "${common_env[@]}" bash "${MANAGER}" reveal clash airport-link 111111111111 --json)"
AIRPORT_LINK_OUTPUT="${airport_link_output}" python3 - <<'PYTHON' || fail "机场敏感链接读取不正确"
import json
import os

data = json.loads(os.environ["AIRPORT_LINK_OUTPUT"])
assert data["resource"] == "proxy_airport_link"
assert data["name"] == "主用机场"
assert data["value"] == "https://airport.test/sub?token=private-token"
PYTHON

exit_config_output="$(env "${common_env[@]}" bash "${MANAGER}" reveal clash exit-config current --json)"
EXIT_CONFIG_OUTPUT="${exit_config_output}" python3 - <<'PYTHON' || fail "出口节点敏感配置读取不正确"
import json
import os

data = json.loads(os.environ["EXIT_CONFIG_OUTPUT"])
assert data["resource"] == "proxy_exit_config"
assert "private-password" in data["value"]
assert "dialer-proxy: MID" in data["value"]
PYTHON
qr_output="$(env "${common_env[@]}" bash "${MANAGER}" reveal clash subscription-qr home-desk --json)"
QR_OUTPUT="${qr_output}" python3 - <<'PYTHON' || fail "Clash 单节点二维码输出不正确"
import base64
import json
import os

resource = json.loads(os.environ["QR_OUTPUT"])
assert resource["resource"] == "clash_subscription_qr"
assert base64.b64decode(resource["image_base64"]).startswith(b"\x89PNG\r\n\x1a\n")
assert "value" not in resource and "url" not in resource
PYTHON
if env "${common_env[@]}" bash "${MANAGER}" reveal git repository server-kit --json >/dev/null 2>&1; then
  fail "总管错误地允许读取未登记敏感资源"
fi

transaction_output="$(env "${common_env[@]}" bash "${MANAGER}" transaction ssh_auth preview --json)"
TRANSACTION_OUTPUT="${transaction_output}" python3 - <<'PYTHON' || fail "SSH 安全事务预览不正确"
import json
import os

transaction = json.loads(os.environ["TRANSACTION_OUTPUT"])
assert transaction["transaction_type"] == "ssh_auth"
assert transaction["state"] == "idle"
assert transaction["writes_enabled"] is False
assert transaction["rollback_seconds"] == 300
PYTHON
if env "${common_env[@]}" bash "${MANAGER}" transaction ssh_auth apply --json >/dev/null 2>&1; then
  fail "总管在开关关闭时错误地允许 SSH 高风险写操作"
fi

origin_session="$(printf 'a%.0s' {1..64})"
independent_session="$(printf 'b%.0s' {1..64})"
vless_request() {
  printf '{"session_id":"%s","actor":"owner"}\n' "$1"
}
vless_preview="$(vless_request "${origin_session}" | env "${common_env[@]}" \
  SERVER_KIT_CONTROL=1 SERVER_KIT_HIGH_RISK_WRITES=1 \
  bash "${MANAGER}" transaction vless_listener preview --json)"
VLESS_PREVIEW="${vless_preview}" python3 - <<'PYTHON' || fail "VLESS 监听安全事务预览不正确"
import json, os
value = json.loads(os.environ["VLESS_PREVIEW"])
assert value["transaction_type"] == "vless_listener"
assert value["state"] == "idle"
PYTHON
grep -Fq 'listener-preview|{"session_id":"' "${vless_transaction_log}" ||
  fail "总管没有向 VLESS 监听脚本发送固定 JSON 请求"
if grep -Fq 'public_ip' "${vless_transaction_log}" || grep -Fq 'public_port' "${vless_transaction_log}"; then
  fail "VLESS 监听事务请求仍携带公网端点参数"
fi
grep -Fq 'control=1|risk=1' "${vless_transaction_log}" ||
  fail "总管没有独占 VLESS 监听脚本的控制与高风险写环境"

vless_apply="$(vless_request "${origin_session}" | env "${common_env[@]}" \
  SERVER_KIT_CONTROL=1 SERVER_KIT_HIGH_RISK_WRITES=1 \
  bash "${MANAGER}" transaction vless_listener apply --json)"
VLESS_APPLY="${vless_apply}" python3 - <<'PYTHON' || fail "VLESS 监听安全事务应用不正确"
import json, os
value = json.loads(os.environ["VLESS_APPLY"])
assert value["state"] == "pending"
assert value["independent_session"] is False
PYTHON
if vless_request "${origin_session}" | env "${common_env[@]}" \
  SERVER_KIT_CONTROL=1 SERVER_KIT_HIGH_RISK_WRITES=1 \
  bash "${MANAGER}" transaction vless_listener confirm --json >/dev/null 2>&1; then
  fail "总管允许原发起会话确认 VLESS 监听事务"
fi
vless_request "${independent_session}" | env "${common_env[@]}" \
  SERVER_KIT_CONTROL=1 SERVER_KIT_HIGH_RISK_WRITES=1 \
  bash "${MANAGER}" transaction vless_listener confirm --json >/dev/null

if env "${common_env[@]}" bash "${MANAGER}" stop ssh >/dev/null 2>&1; then
  fail "总管错误地允许停止 SSH"
fi
if env "${common_env[@]}" bash "${MANAGER}" stop firewall >/dev/null 2>&1; then
  fail "总管错误地允许停止防火墙"
fi
: > "${action_log}"
batch_output="${test_dir}/batch-output.log"
if ! env "${common_env[@]}" bash "${MANAGER}" stop all --yes >"${batch_output}" 2>&1; then
  sed 's/^/批量停止输出：/' "${batch_output}" >&2
  fail "批量停止返回失败"
fi
grep -Fq 'stop xray.service' "${action_log}" || fail "批量停止没有处理 Xray"
grep -Fq 'stop awg-quick@awg0.service' "${action_log}" || fail "批量停止没有处理 AWG"
grep -Fq 'mosh stop' "${action_log}" || fail "批量停止没有处理 Mosh"
if grep -Fq 'ssh.service' "${action_log}"; then
  fail "批量停止触碰了 SSH"
fi

if env "${common_env[@]}" SSH_CONNECTION='192.0.2.10 50000 10.20.0.1 22' \
  bash "${MANAGER}" restart amneziawg >/dev/null 2>&1; then
  fail "当前 SSH 走 AWG 时没有阻止重启"
fi
: > "${action_log}"
if env "${common_env[@]}" SSH_CONNECTION='192.0.2.10 50000 10.20.0.1 22' \
  bash "${MANAGER}" stop all --yes >/dev/null 2>&1; then
  fail "当前 SSH 走 AWG 时没有阻止批量停止"
fi
[[ ! -s "${action_log}" ]] || fail "入口预检失败后仍执行了部分批量操作"
env "${common_env[@]}" SSH_CONNECTION='192.0.2.10 50000 10.20.0.1 22' \
  bash "${MANAGER}" restart amneziawg --force >/dev/null
grep -Fq 'restart awg-quick@awg0.service' "${action_log}" || fail "--force 没有执行 AWG 重启"

ports_output="$(env "${common_env[@]}" COLUMNS=140 bash "${MANAGER}" ports)"
grep -Eq '协议 +监听地址 +端口 +范围 +状态 +用途' <<< "${ports_output}" ||
  fail "宽屏端口清单没有使用 Tab 表格"
grep -Eq 'UDP +10.20.0.1 +60001 +AWG 内网 +按需' <<< "${ports_output}" ||
  fail "宽屏端口清单没有对齐 Mosh"
compact_ports_output="$(env "${common_env[@]}" COLUMNS=36 bash "${MANAGER}" ports)"
grep -Fq -- '- UDP 10.20.0.1:60001' <<< "${compact_ports_output}" ||
  fail "手机端口清单没有使用短列表"
logs_output="$(env "${common_env[@]}" bash "${MANAGER}" logs vless 20)"
grep -Fq 'xray.service' <<< "${logs_output}" || fail "logs 没有读取 Xray 日志"

autostart_output="$(env "${common_env[@]}" COLUMNS=36 bash "${MANAGER}" autostart)"
grep -Fq '开机启动' <<< "${autostart_output}" || fail "自启状态缺少开机启动分组"
grep -Fq '  - AmneziaWG [amneziawg]' <<< "${autostart_output}" || fail "自启状态缺少 AWG"
grep -Fq '随 SSH 按需启动' <<< "${autostart_output}" || fail "缺少按需启动分组"
grep -Fq '  - Mosh 终端 [mosh]' <<< "${autostart_output}" || fail "没有说明 Mosh 无需独立自启"
grep -Fq '开机启动（保护）' <<< "${autostart_output}" || fail "缺少自启保护分组"
grep -Fq '  - 主机防火墙 [firewall]' <<< "${autostart_output}" || fail "没有保护防火墙自启"

wide_autostart_output="$(env "${common_env[@]}" COLUMNS=140 bash "${MANAGER}" autostart)"
grep -Eq '服务 +标识 +自启方式 +当前状态' <<< "${wide_autostart_output}" ||
  fail "宽屏自启状态没有使用对齐表头"
grep -Eq 'Mosh 终端 +mosh +随 SSH 按需 +运行中' <<< "${wide_autostart_output}" ||
  fail "宽屏自启状态没有对齐 Mosh 数据"

wide_help_output="$(env "${common_env[@]}" COLUMNS=140 bash "${MANAGER}" help)"
grep -Eq '类别 +命令 +说明' <<< "${wide_help_output}" || fail "宽屏帮助没有使用 Tab 表格"
compact_help_output="$(env "${common_env[@]}" COLUMNS=36 bash "${MANAGER}" help)"
grep -Fq '查看：' <<< "${compact_help_output}" || fail "手机帮助没有切换为短列表"

: > "${action_log}"
env "${common_env[@]}" bash "${MANAGER}" enable-autostart vless >/dev/null
grep -Fq 'enable xray.service' "${action_log}" || fail "不能启用 Xray 自启"
if grep -Fq 'start xray.service' "${action_log}"; then
  fail "启用自启错误地立即启动了 Xray"
fi

: > "${action_log}"
if env "${common_env[@]}" bash "${MANAGER}" disable-autostart clash >/dev/null 2>&1; then
  fail "禁用自启没有要求显式确认"
fi
[[ ! -s "${action_log}" ]] || fail "确认前已经修改自启状态"
env "${common_env[@]}" bash "${MANAGER}" disable-autostart clash --yes >/dev/null
grep -Fq 'disable secure-clash-service.service' "${action_log}" || fail "不能禁用 Clash 自启"
if grep -Fq 'stop secure-clash-service.service' "${action_log}"; then
  fail "禁用自启错误地停止了当前服务"
fi

if env "${common_env[@]}" bash "${MANAGER}" disable-autostart firewall --yes >/dev/null 2>&1; then
  fail "总管错误地允许禁用防火墙自启"
fi
if env "${common_env[@]}" bash "${MANAGER}" disable-autostart amneziawg --yes >/dev/null 2>&1; then
  fail "未加 --force 时允许禁用 AWG 自启"
fi
env "${common_env[@]}" bash "${MANAGER}" disable-autostart amneziawg --yes --force >/dev/null
grep -Fq 'disable awg-quick@awg0.service' "${action_log}" || fail "强制确认后仍不能禁用 AWG 自启"

echo "通过：总管可汇总服务、节点、订阅和端口状态。"
echo "通过：批量操作保护 SSH，并能识别当前 SSH 所依赖的隧道。"
echo "通过：总管可查看和管理自启，按需服务与保护项不会被误操作。"
