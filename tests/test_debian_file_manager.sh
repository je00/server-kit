#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_PATH="${SCRIPT_DIR}/../debian_file_manager.sh"

# shellcheck disable=SC1090
source "${MANAGER_PATH}"

# Windows Git Bash 的 python3 启动器可能与安装了 ruamel.yaml 的 python 不同。
if ! python3 -c 'import ruamel.yaml' >/dev/null 2>&1; then
  yaml_python="$(command -v python)"
  python3() { "${yaml_python}" "$@"; }
fi

# Git for Windows 不提供 Unix 所有者语义；测试只验证生成内容。
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
  chown() { return 0; }
fi

fail() {
  echo "失败：$1"
  exit 1
}

[[ "${DEFAULT_SOURCE_FILE}" == */shared_file.yaml ]] ||
  fail "默认源文件不是 shared_file.yaml"
[[ "${DEFAULT_CLASH_SOURCE_FILE}" == */clash_skeleton.yaml ]] ||
  fail "Clash 默认源文件不是 clash_skeleton.yaml"
[[ "${PAYLOAD_PATH}" == */shared-file.yaml ]] ||
  fail "普通服务保存路径没有使用 YAML 文件名"
[[ "${FILE_CONFIG_PATH}" != "${CLASH_CONFIG_PATH}" ]] ||
  fail "普通服务与 Clash 服务仍在共用配置文件"
[[ "${FILE_SERVICE_NAME}" != "${CLASH_SERVICE_NAME}" ]] ||
  fail "普通服务与 Clash 服务仍在共用 systemd 服务名"

use_clash_service
[[ "${SERVICE_NAME}" == "${CLASH_SERVICE_NAME}" ]] || fail "无法切换到 Clash 服务"
[[ "${CONFIG_PATH}" == "${CLASH_CONFIG_PATH}" ]] || fail "Clash 服务没有使用独立配置"
[[ "${DEFAULT_PORT}" == "8444" ]] || fail "Clash 服务默认端口不是 8444"
use_file_service
[[ "${SERVICE_NAME}" == "${FILE_SERVICE_NAME}" ]] || fail "无法切换回普通文件服务"
[[ "${CONFIG_PATH}" == "${FILE_CONFIG_PATH}" ]] || fail "普通服务没有使用独立配置"
[[ "${DEFAULT_PORT}" == "8443" ]] || fail "普通文件服务默认端口不是 8443"

relay_bundle_test_dir="$(mktemp -d)"
cat > "${relay_bundle_test_dir}/relay.json" <<'JSON'
{"enabled":true,"vless_enabled":true,"vless_node_name":"SERVER.RELAY.VLESS"}
JSON
cat > "${relay_bundle_test_dir}/clash-test.yaml" <<'YAML'
proxies:
  - name: SERVER.RELAY.VLESS.Primary.443
    type: vless
    server: vpn.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
  - name: SERVER.RELAY.VLESS.Primary.2053
    type: vless
    server: vpn.example.com
    port: 2053
    uuid: 11111111-1111-4111-8111-111111111111
  - name: SERVER.RELAY.VLESS.Backup.443
    type: vless
    server: vpn.example.com
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
  - name: SERVER.RELAY.VLESS.Backup.2053
    type: vless
    server: vpn.example.com
    port: 2053
    uuid: 22222222-2222-4222-8222-222222222222
proxy-providers:
  provider:
    type: http
    url: https://example.com/provider.yaml
    proxy: SERVER.RELAY.VLESS.Primary
proxy-groups:
  - name: PROXY
    type: select
    proxies: [SERVER.RELAY.VLESS.Primary, SERVER.RELAY.VLESS.Backup]
  - name: SERVER.RELAY.VLESS.Primary
    type: fallback
    proxies: [SERVER.RELAY.VLESS.Primary.443, SERVER.RELAY.VLESS.Primary.2053]
    lazy: false
  - name: SERVER.RELAY.VLESS.Backup
    type: fallback
    proxies: [SERVER.RELAY.VLESS.Backup.443, SERVER.RELAY.VLESS.Backup.2053]
    lazy: false
  - name: airport
    type: url-test
    use: [provider]
    empty-fallback: SERVER.RELAY.VLESS.Primary.443
dns:
  respect-rules: true
  proxy-server-nameserver: ['https://223.5.5.5/dns-query#DIRECT', 'https://1.12.12.12/dns-query#DIRECT']
  direct-nameserver: ['https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query']
  nameserver: ['https://8.8.8.8/dns-query#PROXY', 'https://1.0.0.1/dns-query#PROXY']
  nameserver-policy:
    vpn.example.com: ['https://223.5.5.5/dns-query#DIRECT', 'https://1.12.12.12/dns-query#DIRECT']
    example.com: ['https://1.1.1.1/dns-query#SERVER.RELAY.VLESS.Primary']
rules:
  - IP-CIDR,223.5.5.5/32,DIRECT,no-resolve
  - IP-CIDR,1.12.12.12/32,DIRECT,no-resolve
  - IP-CIDR,1.1.1.1/32,SERVER.RELAY.VLESS.Primary,no-resolve
  - DOMAIN,vpn.example.com,DIRECT
  - DOMAIN,example.com,SERVER.RELAY.VLESS.Primary
YAML
verify_clash_vless_relay_bundle "${relay_bundle_test_dir}" "${relay_bundle_test_dir}/relay.json" ||
  fail "包含 VLESS 服务端转发节点的订阅未通过发布校验"
python3 - "${relay_bundle_test_dir}/clash-test.yaml" <<'PYTHON'
import sys
from pathlib import Path
from ruamel.yaml import YAML
path = Path(sys.argv[1])
yaml = YAML()
yaml.preserve_quotes = True
config = yaml.load(path.read_text())
config["proxies"].append({"name": "PRIVATE-test", "type": "vless", "server": "vpn.example.com", "port": 443})
group = config["proxy-groups"][-1]
group.update({"proxies": ["REJECT"], "empty-fallback": "REJECT", "filter": "(?i)DE|^REJECT$"})
with path.open("w") as handle:
    yaml.dump(config, handle)
PYTHON
verify_clash_vless_relay_bundle "${relay_bundle_test_dir}" "${relay_bundle_test_dir}/relay.json" ||
  fail "Stash 空机场拒绝保护未通过发布校验"
sed -i.bak 's/filter: .*/filter: .*/' "${relay_bundle_test_dir}/clash-test.yaml"
if verify_clash_vless_relay_bundle "${relay_bundle_test_dir}" "${relay_bundle_test_dir}/relay.json" >/dev/null 2>&1; then
  fail "会接受 DIRECT 占位节点的 Stash 过滤器仍通过发布校验"
fi
sed -i.bak '/SERVER.RELAY.VLESS/d' "${relay_bundle_test_dir}/clash-test.yaml"
if verify_clash_vless_relay_bundle "${relay_bundle_test_dir}" "${relay_bundle_test_dir}/relay.json" >/dev/null 2>&1; then
  fail "缺少 VLESS 服务端转发节点的订阅仍通过发布校验"
fi
if remove_managed_tree "/tmp" >/dev/null 2>&1; then
  fail "卸载目录保护允许删除非托管目录"
fi

validate_port "1" || fail "端口 1 应当有效"
validate_port "65535" || fail "端口 65535 应当有效"
! validate_port "0" || fail "端口 0 应当无效"
! validate_port "65536" || fail "端口 65536 应当无效"
! validate_port "443x" || fail "非数字端口应当无效"

valid_token="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
validate_token "${valid_token}" || fail "64 位十六进制密钥应当有效"
! validate_token "${valid_token}00" || fail "超过 64 位的密钥应当无效"
! validate_token "${valid_token^^}" || fail "大写密钥不应通过规范校验"

validate_download_name "示例 文件.tar.gz" || fail "普通下载文件名应当有效"
! validate_download_name "../secret" || fail "包含路径分隔符的文件名应当无效"
! validate_download_name ".." || fail "上级目录名称应当无效"
validate_public_ipv4 "8.8.8.8" || fail "公网 IPv4 应当通过证书地址校验"
! validate_public_ipv4 "10.0.0.1" || fail "私有 IPv4 不应通过证书地址校验"
validate_public_address "gateway-demo.duckdns.org" || fail "有效发布域名应当通过地址校验"
! validate_public_address "not_a_domain" || fail "无效发布域名不应通过地址校验"

# 回归检查：Clash 远程订阅必须使用受公共根信任的公网 IP 证书。
grep -q -- '--preferred-profile shortlived' "${MANAGER_PATH}" ||
  fail "没有请求 Let’s Encrypt shortlived 证书配置"
grep -q -- '--ip-address' "${MANAGER_PATH}" ||
  fail "没有按公网 IP 请求证书"
grep -q 'secure-file-cert-renew.timer' "${MANAGER_PATH}" ||
  fail "没有安装自动续期定时器"
grep -q 'open-temporary 80 900' "${MANAGER_PATH}" ||
  fail "证书续期没有临时开放防火墙 TCP 80"
grep -q 'close-temporary 80' "${MANAGER_PATH}" ||
  fail "证书续期没有清理临时防火墙端口"
grep -q 'systemctl cat' "${MANAGER_PATH}" ||
  fail "证书部署钩子仍会重启不存在的文件服务"
grep -q 'python3-ruamel.yaml' "${MANAGER_PATH}" ||
  fail "没有安装 YAML 往返编辑依赖"
grep -q 'qrencode' "${MANAGER_PATH}" || fail "没有安装二维码依赖"
grep -q 'for unit in "${FILE_SERVICE_NAME}.service" "${CLASH_SERVICE_NAME}.service"' \
  "${MANAGER_PATH}" || fail "证书续期没有覆盖两个文件服务"
grep -Fq 'systemctl try-restart "\${unit}"' "${MANAGER_PATH}" ||
  fail "证书续期不会重启实际存在的文件服务"
grep -q 'stop-clash)' "${MANAGER_PATH}" || fail "缺少 Clash 独立停止命令"
grep -A2 'refresh-clash)' "${MANAGER_PATH}" | grep -q 'use_clash_service' ||
  fail "refresh-clash 没有切换到 Clash 独立配置"
grep -q '    qr)' "${MANAGER_PATH}" || fail "缺少通用二维码命令"
grep -q 'stop-all)' "${MANAGER_PATH}" || fail "缺少停止全部服务命令"
grep -q 'for unit in "${FILE_SERVICE_NAME}" "${CLASH_SERVICE_NAME}"' "${MANAGER_PATH}" ||
  fail "停止全部服务命令没有覆盖当前两套文件服务"
grep -q 'uninstall-all)' "${MANAGER_PATH}" || fail "缺少卸载全部服务命令"
grep -q 'remove_managed_tree "${CONFIG_DIR}"' "${MANAGER_PATH}" ||
  fail "卸载命令没有清理服务配置"
grep -q 'secure-file-cert-renew.timer' "${MANAGER_PATH}" ||
  fail "卸载命令没有处理证书续期定时器"
if grep -q 'openssl req -x509' "${MANAGER_PATH}"; then
  fail "仍在生成 Clash 无法信任的自签名证书"
fi

certbot_test_dir="$(mktemp -d)"
certbot_args_log="${certbot_test_dir}/args.log"
fake_certbot="${certbot_test_dir}/certbot"
cat > "${fake_certbot}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${CERTBOT_ARGS_LOG}"
EOF
chmod 700 "${fake_certbot}"
CERTBOT_BIN="${fake_certbot}"
CERTBOT_ARGS_LOG="${certbot_args_log}"
export CERTBOT_ARGS_LOG
request_public_certificate "8.8.8.8"

grep -Fxq -- '--standalone' "${certbot_args_log}" || fail "Certbot 没有使用临时监听 80 的 standalone 模式"
grep -Fxq -- '--preferred-profile' "${certbot_args_log}" || fail "Certbot 没有指定证书配置"
grep -Fxq -- 'shortlived' "${certbot_args_log}" || fail "Certbot 没有请求短期证书"
grep -Fxq -- '--ip-address' "${certbot_args_log}" || fail "Certbot 没有使用公网 IP 参数"
grep -Fxq -- '8.8.8.8' "${certbot_args_log}" || fail "Certbot 没有收到目标公网 IP"

request_public_certificate "gateway-demo.duckdns.org"
grep -Fxq -- '--domains' "${certbot_args_log}" || fail "Certbot 没有使用域名参数"
grep -Fxq -- 'gateway-demo.duckdns.org' "${certbot_args_log}" || fail "Certbot 没有收到发布域名"
if grep -Fxq -- '--ip-address' "${certbot_args_log}"; then
  fail "域名证书错误使用了公网 IP 参数"
fi
rm -rf -- "${certbot_test_dir}"

# 验证运行时才把仓库外参数与当前 VLESS 配置注入 Clash 骨架。
render_test_dir="$(mktemp -d)"
render_input="${render_test_dir}/clash-inputs.json"
render_xray="${render_test_dir}/xray.json"
render_xray_state="${render_test_dir}/vless-manager"
render_xray_public_state="${render_test_dir}/vless-manager-public"
render_awg_state="${render_test_dir}/manager.conf"
render_output="${render_test_dir}/rendered.yaml"
render_summary="${render_test_dir}/summary.json"
cat > "${render_input}" <<'EOF'
{
  "version": 3,
  "airports": [
    {
      "id": "111111111111",
      "name": "主用机场",
      "url": "https://airport.example/subscription?token=test-token",
      "enabled": true,
      "countries": ["hk", "jp"]
    },
    {
      "id": "222222222222",
      "name": "停用机场",
      "url": "https://disabled.example/subscription",
      "enabled": false,
      "countries": ["all"]
    }
  ],
  "exit_proxy": {
    "server": "198.51.100.8",
    "port": 1080,
    "username": "exit-user",
    "password": "exit-password"
  }
}
EOF
cat > "${render_xray}" <<'EOF'
{
  "inbounds": [
    {
      "tag": "vless-public",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "11111111-2222-3333-4444-555555555555", "flow": "xtls-rprx-vision"}]
      },
      "streamSettings": {
        "security": "reality",
        "realitySettings": {
          "serverNames": ["www.example.com"],
          "privateKey": "private-key-must-not-leak",
          "shortIds": ["1234abcd"]
        }
      }
    }
  ]
}
EOF
cat > "${render_xray_state}" <<'EOF'
VLESS_PUBLIC_KEY="public-key-for-test"
EOF
cat > "${render_xray_public_state}" <<'EOF'
VLESS_PUBLIC_REALITY_KEY="public-key-for-public-test"
VLESS_PUBLIC_LISTEN_ADDRESS="0.0.0.0"
EOF
cat > "${render_awg_state}" <<'EOF'
AWG_PUBLIC_IP="203.0.113.10"
EOF
CLASH_INPUT_CONFIG="${render_input}"
XRAY_CONFIG_PATH="${render_xray}"
XRAY_STATE_FILE="${render_xray_state}"
XRAY_PUBLIC_STATE_FILE="${render_xray_public_state}"
AMNEZIAWG_STATE_FILE="${render_awg_state}"
render_clash_skeleton "${DEFAULT_CLASH_SOURCE_FILE}" "${render_output}" "${render_summary}"
python3 - "${render_output}" "${render_summary}" <<'PYTHON'
import json
import re
import sys

from ruamel.yaml import YAML

output_path, summary_path = sys.argv[1:]
with open(output_path, encoding="utf-8") as output_file:
    text = output_file.read()
config = YAML(typ="safe").load(text)
with open(summary_path, encoding="utf-8") as summary_file:
    summary = json.load(summary_file)

assert list(config["proxy-providers"]) == ["airport-111111111111"]
assert config["proxy-providers"]["airport-111111111111"]["url"].endswith("token=test-token")
proxy_group = next(item for item in config["proxy-groups"] if item["name"] == "PROXY")
assert proxy_group["proxies"][-2:] == ["机场 · 主用机场 · 香港", "机场 · 主用机场 · 日本"]
assert not any(item.get("name") == "plane-tw" for item in config["proxy-groups"])
proxies = {item["name"]: item for item in config["proxies"]}
exit_node = proxies["EXIT.Default"]
assert exit_node["type"] == "socks5"
assert exit_node["server"] == "198.51.100.8"
assert exit_node["port"] == 1080
assert exit_node["username"] == "exit-user"
assert exit_node["password"] == "exit-password"
assert exit_node["udp"] is True
assert exit_node["dialer-proxy"] == "MID"
for name, port in (("ENDPOINT.MID.443", 443), ("ENDPOINT.MID.2053", 2053)):
    mid_node = proxies[name]
    assert mid_node["server"] == "203.0.113.10"
    assert mid_node["port"] == port
    assert mid_node["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert mid_node["tls"] is True
    assert mid_node["reality-opts"]["public-key"] == "public-key-for-public-test"
assert "    reality-opts:\n\n" not in text
assert re.search(
    r"    reality-opts:\n"
    r"      public-key: [^\n]+\n"
    r"      short-id: [^\n]+\n\n"
    r"proxy-groups:\n",
    text,
), repr(text[text.index("    reality-opts:"):][:240])
assert "private-key-must-not-leak" not in text
assert "test-token" not in json.dumps(summary)
assert summary["vless_security"] == "reality"
assert summary["airport_count"] == 2
assert summary["active_airport_groups"] == ["机场 · 主用机场 · 香港", "机场 · 主用机场 · 日本"]
PYTHON

# 一次粘贴完整的 SS 节点后，协议专有字段必须原样保存并接入中转。
SERVER_KIT_CONFIG_DIR="${render_test_dir}"
configure_clash_inputs <<'EOF'

proxies:
  - name: copied-exit
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: copied-password
    udp: true
END
EOF
render_clash_skeleton "${DEFAULT_CLASH_SOURCE_FILE}" "${render_output}" "${render_summary}"
python3 - "${render_output}" "${render_input}" <<'PYTHON'
import json
import sys

from ruamel.yaml import YAML

output_path, input_path = sys.argv[1:]
with open(output_path, encoding="utf-8") as output_file:
    text = output_file.read()
config = YAML(typ="safe").load(text)
with open(input_path, encoding="utf-8") as input_file:
    saved = json.load(input_file)

exit_node = next(item for item in config["proxies"] if item["name"] == "EXIT.Default")
assert exit_node == {
    "name": "EXIT.Default",
    "type": "ss",
    "server": "ss.example.com",
    "port": 8388,
    "cipher": "aes-128-gcm",
    "password": "copied-password",
    "udp": True,
    "dialer-proxy": "MID",
}
assert saved["version"] == 4
assert saved["exits"][0]["proxy"] == exit_node
assert saved["default_exit_id"] == saved["exits"][0]["id"]
assert "copied-exit" not in text
assert "    dialer-proxy: MID\n\n  - name: ENDPOINT.MID.443\n" in text
PYTHON

rm -rf -- "${render_test_dir}"

prompt_optional() { printf '\n'; }
openssl() {
  if [[ "$1" == "rand" ]]; then
    printf '%s\n' "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    return
  fi
  command openssl "$@"
}

actual_token="$(choose_download_token "${valid_token}")"
[[ "${actual_token}" == "${valid_token}" ]] || fail "重装直接回车时没有沿用旧链接"

prompt_optional() { printf 'y\n'; }
actual_token="$(choose_download_token "${valid_token}")"
[[ "${actual_token}" == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]] ||
  fail "选择更新链接时没有生成新密钥"

resolve_source_file() { printf '%s\n' "/tmp/new-name.bin"; }
install_dependencies() { return 0; }
create_service_user() { return 0; }
prepare_directories() { return 0; }
install_certbot() { CERTBOT_BIN="/usr/bin/certbot"; }
get_public_ip() { printf '%s\n' "8.8.8.8"; }
get_publication_address() { get_public_ip; }
load_existing_token() { printf '%s\n' "${valid_token}"; }
read_config_field() {
  case "$1" in
    port) printf '%s\n' "9443" ;;
    download_name) printf '%s\n' "old-name.txt" ;;
    server_address) printf '%s\n' "8.8.8.8" ;;
    *) return 1 ;;
  esac
}
prompt_optional() { printf '\n'; }
obtain_public_certificate() { return 0; }
deploy_public_certificate() { return 0; }
write_server_program() { return 0; }
write_systemd_service() { return 0; }
write_certificate_automation() { return 0; }
install_payload() { return 0; }
sha256sum() { printf '%s  %s\n' "hash-value" "${PAYLOAD_PATH}"; }
stat() { printf '%s\n' "123"; }
write_config() { printf 'CONFIG:%s:%s:%s:%s:%s:%s\n' "$1" "$2" "$3" "$4" "$5" "$6"; }
enable_service() { return 0; }
enable_certificate_timer() { return 0; }
show_link() { return 0; }

install_output="$(install_and_run)"
expected_config="CONFIG:9443:8.8.8.8:${valid_token}:old-name.txt:hash-value:123"
grep -Fq "${expected_config}" <<< "${install_output}" ||
  fail "沿用旧链接时没有同时保留旧地址、旧端口、旧密钥和旧文件名"

temp_dir="$(mktemp -d)"
trap 'rm -rf -- "${temp_dir}"' EXIT
server_source="${temp_dir}/server.py"

# 两套服务必须拒绝复用同一监听端口，避免独立启动时发生端口冲突。
original_file_config_path="${FILE_CONFIG_PATH}"
original_clash_config_path="${CLASH_CONFIG_PATH}"
FILE_CONFIG_PATH="${temp_dir}/file-config.json"
CLASH_CONFIG_PATH="${temp_dir}/clash-config.json"
printf '{"port": 8444}\n' > "${CLASH_CONFIG_PATH}"
use_file_service
if ensure_independent_port "8444" >/dev/null 2>&1; then
  fail "普通服务仍允许与 Clash 服务使用相同端口"
fi
ensure_independent_port "8443" || fail "不同端口被错误判定为冲突"
FILE_CONFIG_PATH="${original_file_config_path}"
CLASH_CONFIG_PATH="${original_clash_config_path}"
use_file_service

awk '
  /^  cat > "\$\{temp_server\}" <<'"'"'PYTHON'"'"'$/ {inside = 1; next}
  inside && /^PYTHON$/ {exit}
  inside {sub(/^\+/, ""); print}
' "${MANAGER_PATH}" > "${server_source}"

[[ -s "${server_source}" ]] || fail "无法提取内嵌 Python 服务程序"
python3 -m py_compile "${server_source}" || fail "内嵌 Python 服务程序语法错误"
if grep -Fq 'server.socket = tls_context.wrap_socket' "${server_source}"; then
  fail "TLS 仍在监听 socket 上握手，会被单个慢连接阻塞"
fi
grep -Fq 'def process_request_thread(self, request, client_address):' "${server_source}" ||
  fail "TLS 握手没有移入连接工作线程"
grep -Fq 'tls_request.do_handshake()' "${server_source}" ||
  fail "工作线程没有执行受控 TLS 握手"
grep -Fq 'request.settimeout(TLS_HANDSHAKE_TIMEOUT)' "${server_source}" ||
  fail "TLS 握手缺少超时保护"
grep -Fq 'threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)' "${server_source}" ||
  fail "TLS 工作线程缺少并发上限"
python3 - "${server_source}" "${temp_dir}" <<'PYTHON'
import importlib.util
import json
import os
import ssl
import sys
import threading

server_path, temp_dir = sys.argv[1:]
spec = importlib.util.spec_from_file_location("secure_file_server", server_path)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

legacy_path = os.path.join(temp_dir, "legacy-config.json")
legacy = {
    "port": 8443,
    "token": "a" * 64,
    "download_name": "legacy.bin",
    "payload_path": "/tmp/legacy.bin",
    "cert_path": "/tmp/server.crt",
    "key_path": "/tmp/server.key",
}
with open(legacy_path, "w", encoding="utf-8") as config_file:
    json.dump(legacy, config_file)
loaded_legacy = server.load_config(legacy_path)
assert len(loaded_legacy["downloads"]) == 1
assert loaded_legacy["downloads"][0]["download_name"] == "legacy.bin"

multi_path = os.path.join(temp_dir, "multi-config.json")
multi = {
    "mode": "clash",
    "port": 8443,
    "cert_path": "/tmp/server.crt",
    "key_path": "/tmp/server.key",
    "downloads": [
        {
            "token": "b" * 64,
            "download_name": "clash-phone.yaml",
            "payload_path": "/tmp/clash-phone.yaml",
            "cdn_cache": True,
            "cache_ttl": 86400,
        },
        {
            "token": "c" * 64,
            "download_name": "clash-laptop.yaml",
            "payload_path": "/tmp/clash-laptop.yaml",
        },
    ],
}
with open(multi_path, "w", encoding="utf-8") as config_file:
    json.dump(multi, config_file)
loaded_multi = server.load_config(multi_path)
assert len(loaded_multi["downloads"]) == 2
assert loaded_multi["downloads"][0]["cdn_cache"] is True


class FakeRawSocket:
    def settimeout(self, value):
        self.timeout = value


class FakeTLSSocket(FakeRawSocket):
    def do_handshake(self):
        raise ssl.SSLError("stalled handshake")


class FakeTLSContext:
    def wrap_socket(self, request, **_kwargs):
        return FakeTLSSocket()


# A failed TLS handshake must return its concurrency slot; otherwise repeated
# bad clients eventually disable the service even though the listener stays up.
test_server = server.SecureFileServer.__new__(server.SecureFileServer)
test_server.tls_context = FakeTLSContext()
test_server.request_slots = threading.BoundedSemaphore(1)
test_server.close_request = lambda _request: None
assert test_server.request_slots.acquire(blocking=False)
test_server.process_request_thread(FakeRawSocket(), ("127.0.0.1", 12345))
assert test_server.request_slots.acquire(blocking=False)
PYTHON
grep -Fq 'CDN-Cache-Control' "${server_source}" || fail "内嵌服务缺少 CDN 缓存响应头"
grep -Fq 'If-None-Match' "${server_source}" || fail "内嵌服务缺少 ETag 重验证"

# 验证普通文件与 Clash 订阅可由同一命令选择，并将完整链接传给二维码程序。
clash_test_dir="${temp_dir}/clash"
generated_config="${clash_test_dir}/config.json"
mkdir -p "${clash_test_dir}"
python3 - "${generated_config}" <<'PYTHON'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as config_file:
    json.dump(
        {
            "mode": "clash",
            "port": 8443,
            "server_address": "203.0.113.10",
            "downloads": [
                {
                    "peer_name": "phone",
                    "token": "b" * 64,
                    "download_name": "clash-phone.yaml",
                    "payload_path": "/tmp/clash-phone.yaml",
                },
                {
                    "peer_name": "laptop",
                    "token": "c" * 64,
                    "download_name": "clash-laptop.yaml",
                    "payload_path": "/tmp/clash-laptop.yaml",
                },
            ],
        },
        config_file,
    )
PYTHON

qrencode() {
  [[ "$*" == "-t ANSIUTF8 -m 2" ]] || return 1
  printf '二维码内容:%s\n' "$(cat)"
}
qr_file_config="${clash_test_dir}/file-config.json"
python3 - "${qr_file_config}" "${valid_token}" <<'PYTHON'
import json
import sys

path, token = sys.argv[1:]
with open(path, "w", encoding="utf-8") as config_file:
    json.dump(
        {
            "port": 9443,
            "server_address": "203.0.113.10",
            "token": token,
            "download_name": "shared_file.yaml",
        },
        config_file,
    )
PYTHON

qr_output="$(show_qr file "${qr_file_config}" "${generated_config}")"
grep -Fq '链接: 普通文件：shared_file.yaml' <<< "${qr_output}" || fail "通用二维码无法选择普通链接"
grep -Fq 'https://203.0.113.10:9443/' <<< "${qr_output}" || fail "普通二维码缺少完整下载地址"
grep -Fq '/shared_file.yaml' <<< "${qr_output}" || fail "普通二维码没有使用下载链接"

qr_output="$(show_qr phone "${qr_file_config}" "${generated_config}")"
grep -Fq '链接: Clash：phone' <<< "${qr_output}" || fail "无法按节点名选择二维码订阅"
grep -Fq 'https://203.0.113.10:8443/' <<< "${qr_output}" || fail "二维码缺少完整订阅地址"
grep -Fq '/clash-phone.yaml' <<< "${qr_output}" || fail "二维码没有使用 phone 订阅链接"

qr_output="$(show_qr "" "${qr_file_config}" "${generated_config}" <<< '3')"
grep -Fq '链接: Clash：laptop' <<< "${qr_output}" || fail "无法按编号选择二维码订阅"
grep -Fq '/clash-laptop.yaml' <<< "${qr_output}" || fail "二维码没有使用 laptop 订阅链接"

echo "通过：端口、密钥和文件名校验正确。"
echo "通过：重装默认完整沿用旧链接，可选择生成新链接。"
echo "通过：Certbot 使用公网 IP、shortlived 和 standalone 参数。"
echo "通过：内嵌 Python 服务程序语法正确。"
echo "通过：install-clash 使用 AWG 与 VLESS 节点生成独立订阅。"
echo "通过：install-clash 从仓库外参数和当前 VLESS 配置安全渲染订阅。"
echo "通过：出口节点可一次粘贴完整 YAML，并兼容旧版 SOCKS5 配置。"
echo "通过：AWG endpoint 自动直连，节点间空行位置正确。"
echo "通过：install-clash 保留基础 YAML 的缩进、空行、引号和注释。"
echo "通过：可选择普通文件或 Clash 订阅并显示完整链接二维码。"
