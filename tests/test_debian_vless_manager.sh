#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_PATH="${SCRIPT_DIR}/../debian_vless_manager.sh"

# shellcheck disable=SC1090
source "${MANAGER_PATH}"

fail() {
  echo "失败：$1"
  exit 1
}

temp_dir="$(mktemp -d)"
trap 'rm -rf -- "${temp_dir}"' EXIT

fake_xray="${temp_dir}/xray"
cat > "${fake_xray}" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "x25519" ]]; then
  cat <<'OUTPUT'
PrivateKey: private-key-value
Password (PublicKey): public-key-value
Hash32: hash-value
OUTPUT
fi
exit 0
EOF
chmod 700 "${fake_xray}"
XRAY_BIN="${fake_xray}"

actual="$(generate_reality_keypair)"
[[ "${actual}" == "private-key-value public-key-value" ]] ||
  fail "无法解析 Xray 的 REALITY 密钥输出"
[[ "${DEFAULT_SERVER_NAME}" == "www.amazon.com" ]] ||
  fail "默认 REALITY 域名不正确"

grep -q '"clients": \[' "${MANAGER_PATH}" || fail "VLESS 入站没有使用 clients 字段"
if grep -q 'disable-private)' "${MANAGER_PATH}" || grep -q 'install-public)' "${MANAGER_PATH}"; then
  fail "脚本仍暴露旧内网 VLESS 迁移命令"
fi
if grep -q '^[[:space:]]*bind-public-any)' "${MANAGER_PATH}"; then
  fail "脚本仍暴露未受回滚窗口保护的 bind-public-any 命令"
fi
if grep -q 'WireGuard 内网\|WG_SERVER_IP\|vless-private' "${MANAGER_PATH}"; then
  fail "脚本仍维护旧 WireGuard VLESS 入站"
fi

CONFIG_DIR="${temp_dir}/config"
CONFIG_PATH="${CONFIG_DIR}/config.json"
PUBLIC_STATE_FILE="${temp_dir}/vless-manager-public"
SERVER_KIT_DIR="${temp_dir}/server-kit"
SERVICE_NAME="xray"
VLESS_LISTENER_TRANSACTION_DIR="${temp_dir}/vless-listener-transaction"
VLESS_LISTENER_OUTCOME_PATH="${temp_dir}/vless-listener-last-outcome.json"
VLESS_LISTENER_ROLLBACK_SECONDS=300
VLESS_LISTENER_ROLLBACK_UNIT="server-kit-vless-listener-rollback"
SYSTEMD_RUN_BIN="${temp_dir}/systemd-run"
SYSTEMD_RUN_LOG="${temp_dir}/systemd-run.log"
SYSTEMD_RUN_FAIL=0
cat >"${SYSTEMD_RUN_BIN}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${SYSTEMD_RUN_LOG}"
[[ "${SYSTEMD_RUN_FAIL:-0}" != "1" ]]
EOF
chmod 700 "${SYSTEMD_RUN_BIN}"
export SYSTEMD_RUN_LOG SYSTEMD_RUN_FAIL
export SERVER_KIT_TESTING=1 SERVER_KIT_CONTROL=1 SERVER_KIT_HIGH_RISK_WRITES=1
mkdir -p "${SERVER_KIT_DIR}"
printf '{"schema_version":1,"fqdn":"vpn.example.com"}\n' > "${SERVER_KIT_DIR}/public-endpoint.json"

SYSTEMCTL_RESTART_FAILURES=0
systemctl() {
  [[ "${1:-}" == "show" ]] && printf '\n'
  if [[ "${1:-}" == "restart" && "${SYSTEMCTL_RESTART_FAILURES}" -gt 0 ]]; then
    SYSTEMCTL_RESTART_FAILURES=$((SYSTEMCTL_RESTART_FAILURES - 1))
    return 1
  fi
  return 0
}
id() {
  if [[ "${1:-}" == "-gn" ]]; then
    printf 'root\n'
  fi
  return 0
}
install() {
  local args=("$@")
  local count="${#args[@]}"
  command cp "${args[count - 2]}" "${args[count - 1]}"
}

write_public_inbound "223e4567-e89b-12d3-a456-426614174000" "443" \
  "203.0.113.10" "www.apple.com" "private-key-value" "0123456789abcdef"
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as config_file:
    config = json.load(config_file)
assert len(config["inbounds"]) == 2
inbound = next(item for item in config["inbounds"] if item["tag"] == "vless-public")
rescue = next(item for item in config["inbounds"] if item["tag"] == "vless-public-rescue")
client = inbound["settings"]["clients"][0]
reality = inbound["streamSettings"]["realitySettings"]
assert inbound["tag"] == "vless-public"
assert inbound["listen"] == "203.0.113.10"
assert inbound["port"] == 443
assert rescue["listen"] == "203.0.113.10"
assert rescue["port"] == 2053
assert rescue["settings"] == inbound["settings"]
assert rescue["streamSettings"] == inbound["streamSettings"]
assert inbound["streamSettings"]["security"] == "reality"
assert client["flow"] == "xtls-rprx-vision"
assert reality["target"] == "www.apple.com:443"
PYTHON

save_public_state "443" "223e4567-e89b-12d3-a456-426614174000" \
  "www.apple.com" "public-key-value" "0123456789abcdef" "203.0.113.10"
clash_output="$(clash_public_config public-test)"
grep -q 'server: "vpn.example.com"' <<< "${clash_output}" ||
  fail "公网 Clash 节点没有使用稳定入口"
grep -q 'public-key: "public-key-value"' <<< "${clash_output}" ||
  fail "公网 Clash 节点缺少 REALITY 公钥"

python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    config = json.load(source)
config["inbounds"] = [
    item for item in config["inbounds"]
    if item["tag"] != "vless-public-rescue"
]
with open(path, "w", encoding="utf-8") as output:
    json.dump(config, output)
    output.write("\n")
PYTHON
enable_rescue_inbound 2053 >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)
primary = next(item for item in config["inbounds"] if item["tag"] == "vless-public")
rescue = next(item for item in config["inbounds"] if item["tag"] == "vless-public-rescue")
assert rescue["port"] == 2053
assert rescue["listen"] == primary["listen"]
assert rescue["settings"] == primary["settings"]
assert rescue["streamSettings"] == primary["streamSettings"]
PYTHON
grep -Fq 'VLESS_PUBLIC_RESCUE_PORT="2053"' "${PUBLIC_STATE_FILE}" ||
  fail "启用救援端口没有同步状态事实"
config_before_failed_rescue="$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')"
SYSTEMCTL_RESTART_FAILURES=1
if enable_rescue_inbound 2054 >/dev/null 2>&1; then
  fail "Xray 重启失败后仍报告救援端口启用成功"
fi
[[ "$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')" == "${config_before_failed_rescue}" ]] ||
  fail "救援端口启用失败后没有恢复原配置"

set_public_server_name "www.amazon.com" >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as config_file:
    inbounds = json.load(config_file)["inbounds"]
for inbound in inbounds:
    reality = inbound["streamSettings"]["realitySettings"]
    assert reality["target"] == "www.amazon.com:443"
    assert reality["serverNames"] == ["www.amazon.com"]
PYTHON

before_identity="$(python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    inbound = json.load(source)["inbounds"][0]
reality = inbound["streamSettings"]["realitySettings"]
client = inbound["settings"]["clients"][0]
print("|".join((client["id"], reality["privateKey"], reality["shortIds"][0], str(inbound["port"]), reality["serverNames"][0])))
PYTHON
)"
origin_session="$(printf 'a%.0s' {1..64})"
independent_session="$(printf 'b%.0s' {1..64})"
listener_request() {
  printf '{"session_id":"%s","actor":"owner","public_ip":"","public_port":""}\n' "$1"
}

SERVER_KIT_CONTROL=0
if listener_request "${origin_session}" | vless_listener_transaction preview >/dev/null 2>&1; then
  fail "VLESS 监听事务没有要求控制面环境"
fi
SERVER_KIT_CONTROL=1
SERVER_KIT_HIGH_RISK_WRITES=0
listener_request "${origin_session}" | vless_listener_transaction status >/dev/null ||
  fail "只读 VLESS 监听状态错误地要求高风险写环境"
listener_request "" | vless_listener_transaction status >/dev/null ||
  fail "只读 VLESS 监听状态错误地要求网页会话标识"
if listener_request "invalid-session" | vless_listener_transaction status >/dev/null 2>&1; then
  fail "只读 VLESS 监听状态接受了畸形会话标识"
fi
listener_request "${origin_session}" | vless_listener_transaction preview >/dev/null ||
  fail "VLESS 监听预览错误地要求高风险写环境"
if listener_request "${origin_session}" | vless_listener_transaction apply >/dev/null 2>&1; then
  fail "VLESS 监听应用没有要求高风险写环境"
fi
SERVER_KIT_HIGH_RISK_WRITES=1

config_before_schedule_failure="$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')"
state_before_schedule_failure="$(sha256sum "${PUBLIC_STATE_FILE}" | awk '{print $1}')"
config_mode_before="$(stat -c '%a' "${CONFIG_PATH}")"
state_mode_before="$(stat -c '%a' "${PUBLIC_STATE_FILE}")"
SYSTEMD_RUN_FAIL=1
if listener_request "${origin_session}" | vless_listener_transaction apply >/dev/null 2>&1; then
  fail "自动回滚计时器创建失败后仍报告应用成功"
fi
SYSTEMD_RUN_FAIL=0
[[ "$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')" == "${config_before_schedule_failure}" ]] ||
  fail "计时器创建失败后改变了 Xray 配置"
[[ "$(sha256sum "${PUBLIC_STATE_FILE}" | awk '{print $1}')" == "${state_before_schedule_failure}" ]] ||
  fail "计时器创建失败后改变了 VLESS 状态"
[[ ! -e "${VLESS_LISTENER_TRANSACTION_DIR}" ]] ||
  fail "计时器创建失败后留下了伪待确认事务"

apply_result="$(listener_request "${origin_session}" | vless_listener_transaction apply)"
python3 - "${apply_result}" <<'PYTHON'
import json, sys
value = json.loads(sys.argv[1])
assert value["transaction_type"] == "vless_listener"
assert value["state"] == "pending"
assert value["independent_session"] is False
assert value["remaining_seconds"] > 0
PYTHON
[[ -r "${VLESS_LISTENER_TRANSACTION_DIR}/config.backup" ]] ||
  fail "监听迁移没有持久化旧 Xray 配置"
[[ -r "${VLESS_LISTENER_TRANSACTION_DIR}/state.backup" ]] ||
  fail "监听迁移没有持久化旧 VLESS 状态"
if ! python3 - "${VLESS_LISTENER_TRANSACTION_DIR}/metadata.json" <<'PYTHON'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as source:
    metadata = json.load(source)
assert re.fullmatch(r"[0-9a-f]{64}", metadata["config_sha256"])
assert re.fullmatch(r"0[0-7]{3}", metadata["config_mode"])
assert re.fullmatch(r"[0-9a-f]{64}", metadata["state_sha256"])
assert re.fullmatch(r"0[0-7]{3}", metadata["state_mode"])
PYTHON
then
  fail "监听迁移元数据没有记录备份 SHA-256 与模式"
fi
integrity_copy="${temp_dir}/config.backup.integrity-copy"
command cp -a -- "${VLESS_LISTENER_TRANSACTION_DIR}/config.backup" "${integrity_copy}"
printf '\n' >> "${VLESS_LISTENER_TRANSACTION_DIR}/config.backup"
if listener_request "${independent_session}" | vless_listener_transaction rollback >/dev/null 2>&1; then
  fail "VLESS 监听事务恢复了 SHA-256 不匹配的备份"
fi
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert json.load(source)["inbounds"][0]["listen"] == "0.0.0.0"
PYTHON
[[ -r "${VLESS_LISTENER_TRANSACTION_DIR}/metadata.json" ]] ||
  fail "备份完整性失败后事务不可重试"
command cp -a -- "${integrity_copy}" "${VLESS_LISTENER_TRANSACTION_DIR}/config.backup"
if listener_request "${origin_session}" | vless_listener_transaction confirm >/dev/null 2>&1; then
  fail "原发起会话确认了 VLESS 监听迁移"
fi
listener_request "${origin_session}" | vless_listener_transaction rollback >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert json.load(source)["inbounds"][0]["listen"] == "203.0.113.10"
PYTHON
grep -Fq 'VLESS_PUBLIC_LISTEN_ADDRESS="203.0.113.10"' "${PUBLIC_STATE_FILE}" ||
  fail "手动回滚没有恢复旧监听状态事实"
[[ "$(stat -c '%a' "${CONFIG_PATH}")" == "${config_mode_before}" ]] ||
  fail "手动回滚没有恢复旧 Xray 配置模式"
[[ "$(stat -c '%a' "${PUBLIC_STATE_FILE}")" == "${state_mode_before}" ]] ||
  fail "手动回滚没有恢复旧 VLESS 状态模式"

# Reading an expired transaction actively restores it before reporting idle.
listener_request "${origin_session}" | vless_listener_transaction apply >/dev/null
python3 - "${VLESS_LISTENER_TRANSACTION_DIR}/metadata.json" <<'PYTHON'
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    value = json.load(source)
value["expires_epoch"] = 1
value["expires_at"] = "1970-01-01T00:00:01+00:00"
temporary = path + ".test"
with open(temporary, "w", encoding="utf-8") as output:
    json.dump(value, output, separators=(",", ":"))
    output.write("\n")
os.replace(temporary, path)
PYTHON
expired_result="$(listener_request "${independent_session}" | vless_listener_transaction status)"
python3 - "${expired_result}" <<'PYTHON'
import json, sys
value = json.loads(sys.argv[1])
assert value["state"] == "idle"
assert value["last_outcome"] == "automatic_rollback"
PYTHON
grep -Fq 'VLESS_PUBLIC_LISTEN_ADDRESS="203.0.113.10"' "${PUBLIC_STATE_FILE}" ||
  fail "读取过期事务没有主动恢复旧监听状态"

listener_request "${origin_session}" | vless_listener_transaction apply >/dev/null
SERVER_KIT_TEST_FAILPOINT=vless_listener_confirm_after_commit
export SERVER_KIT_TEST_FAILPOINT
if listener_request "${independent_session}" | vless_listener_transaction confirm >/dev/null 2>&1; then
  fail "确认提交后的崩溃注入没有中断清理"
fi
unset SERVER_KIT_TEST_FAILPOINT
confirmed_after_restart="$(listener_request "${independent_session}" | vless_listener_transaction status)"
python3 - "${confirmed_after_restart}" <<'PYTHON'
import json, sys
value = json.loads(sys.argv[1])
assert value["state"] == "idle"
assert value["last_outcome"] == "confirmed"
PYTHON
[[ ! -e "${VLESS_LISTENER_TRANSACTION_DIR}" ]] ||
  fail "确认提交后重启收敛没有清理 VLESS 监听事务"
after_identity="$(python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    inbound = json.load(source)["inbounds"][0]
reality = inbound["streamSettings"]["realitySettings"]
client = inbound["settings"]["clients"][0]
assert inbound["listen"] == "0.0.0.0"
print("|".join((client["id"], reality["privateKey"], reality["shortIds"][0], str(inbound["port"]), reality["serverNames"][0])))
PYTHON
)"
[[ "${before_identity}" == "${after_identity}" ]] ||
  fail "公网监听迁移改变了 VLESS 身份、密钥、端口或 SNI"
clash_output="$(clash_public_config public-test)"
grep -q 'server: "vpn.example.com"' <<< "${clash_output}" ||
  fail "通配监听地址泄漏到 VLESS 客户端配置"
grep -Fq 'VLESS_PUBLIC_LISTEN_ADDRESS="0.0.0.0"' "${PUBLIC_STATE_FILE}" ||
  fail "公网监听迁移没有同步状态事实"
[[ ! -e "${VLESS_LISTENER_TRANSACTION_DIR}" ]] || fail "确认后没有清理 VLESS 监听事务"
grep -Fq -- "--unit=server-kit-vless-listener-rollback --on-active=300s --timer-property=AccuracySec=1s --property=Restart=on-failure --property=RestartSec=10s ${VLESS_LISTENER_MANAGER} transaction vless_listener automatic-rollback --json" "${SYSTEMD_RUN_LOG}" ||
  fail "VLESS 监听自动回滚计时器 argv 或重试属性不正确"

# An automatic timer invocation restores the exact old config/state too.
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source: value = json.load(source)
value["inbounds"][0]["listen"] = "203.0.113.10"
with open(path, "w", encoding="utf-8") as output: json.dump(value, output)
PYTHON
sed -i 's/VLESS_PUBLIC_LISTEN_ADDRESS="0.0.0.0"/VLESS_PUBLIC_LISTEN_ADDRESS="203.0.113.10"/' "${PUBLIC_STATE_FILE}"
listener_request "${origin_session}" | vless_listener_transaction apply >/dev/null
SYSTEMCTL_RESTART_FAILURES=1
if vless_listener_transaction automatic-rollback </dev/null >/dev/null 2>&1; then
  fail "旧配置重启失败时自动回滚错误地报告成功"
fi
[[ -r "${VLESS_LISTENER_TRANSACTION_DIR}/metadata.json" ]] ||
  fail "旧配置重启失败后事务不可重试"
vless_listener_transaction automatic-rollback </dev/null >/dev/null
python3 - "${CONFIG_PATH}" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    assert json.load(source)["inbounds"][0]["listen"] == "203.0.113.10"
PYTHON

if printf '{"unexpected":true}\n' | main listener-automatic-rollback >/dev/null 2>&1; then
  fail "自动回滚接受了标准输入"
fi
if ( main listener-automatic-rollback unexpected </dev/null >/dev/null 2>&1 ); then
  fail "自动回滚接受了额外 argv"
fi

grep -Fq 'listen_address="0.0.0.0"' "${MANAGER_PATH}" ||
  fail "新安装仍绑定易变的公网 IP"

echo "通过：VLESS 只维护公网 REALITY 入站并使用 clients 字段。"
echo "通过：公网 Clash 节点和 SNI 更新保持密钥与身份不变。"
echo "通过：VLESS 公网监听可迁移到任意本机 IPv4，身份和端口保持不变。"
