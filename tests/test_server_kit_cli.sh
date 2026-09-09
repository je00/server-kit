#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CLI="${REPO_DIR}/server-kit"
REAL_PYTHON_BIN="$(command -v python3)"
export PYTHON_BIN="${REAL_PYTHON_BIN}"
test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

fail() {
  echo "失败：$1"
  exit 1
}

preflight_output="$(SERVER_KIT_TESTING=1 bash "${CLI}" preflight)"
grep -Fq '初始化预检通过' <<< "${preflight_output}" || fail "初始化预检没有成功"
grep -Fq '不会修改 SSH' <<< "${preflight_output}" || fail "初始化没有声明 SSH 安全边界"
grep -Fq '不会应用或重写主机防火墙' <<< "${preflight_output}" || fail "初始化没有声明防火墙边界"

cat > "${test_dir}/client-key-fail.py" <<'PYTHON'
raise SystemExit(1)
PYTHON
if SERVER_KIT_TESTING=1 CLIENT_KEY_HELPER="${test_dir}/client-key-fail.py" \
  bash "${CLI}" preflight >/dev/null 2>&1; then
  fail "初始化没有执行 AWG 节点凭据安全约束"
fi

help_output="$(bash "${CLI}" help)"
grep -Fq 'server-kit init' <<< "${help_output}" || fail "帮助缺少初始化命令"
grep -Fq 'server-kit recovery' <<< "${help_output}" || fail "帮助缺少恢复命令"
grep -Fq 'server-kit update-web' <<< "${help_output}" || fail "帮助缺少管理网站原子更新命令"
grep -Fq 'server-kit service' <<< "${help_output}" || fail "帮助缺少异步服务变更命令"
grep -Fq 'server-kit task' <<< "${help_output}" || fail "帮助缺少任务查询命令"
grep -Fq -- '--cancel' <<< "${help_output}" || fail "帮助缺少任务取消命令"
grep -Fq '更新不修改管理员密码、AWG、SSH 或防火墙' <<< "${help_output}" ||
  fail "更新命令没有声明安全边界"

recovery_body="$(python3 - "${CLI}" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
print(text.split("recovery_menu() {", 1)[1].split("\n}\n\nusage()", 1)[0])
PY
)"
grep -Fq '回滚待确认稳定公网入口事务' <<< "${recovery_body}" ||
  fail "恢复入口缺少待确认稳定公网入口事务"
grep -Fq 'network public-endpoint rollback --json' <<< "${recovery_body}" ||
  fail "恢复入口没有调用受限的公网入口回滚子命令"
grep -Fq 'network public-endpoint transaction-status --json' <<< "${recovery_body}" ||
  fail "恢复入口没有先读取待确认公网入口事务标识"
grep -Fq 'transaction_id' <<< "${recovery_body}" ||
  fail "恢复入口没有把当前公网入口事务标识绑定到回滚请求"
grep -Fq 'SERVER_KIT_CONTROL=1 SERVER_KIT_NETWORK_WRITES=1' <<< "${recovery_body}" ||
  fail "恢复入口没有显式启用受限控制面回滚"
grep -Fq 'recovery-console' <<< "${recovery_body}" ||
  fail "恢复入口没有提供固定的非敏感审计身份"
grep -Fq '回滚待确认 VLESS 公网监听事务' <<< "${recovery_body}" ||
  fail "恢复入口缺少待确认 VLESS 公网监听事务"
grep -Fq 'transaction vless_listener rollback --json' <<< "${recovery_body}" ||
  fail "恢复入口没有调用既有安全事务回滚子命令"
grep -Fq '/security/transactions/' "${REPO_DIR}/docs/public-ip-change-runbook.md" ||
  fail "公网 IP 变更手册没有指向既有安全事务页面"
if grep -Fq 'bind-public-any' "${REPO_DIR}/docs/public-ip-change-runbook.md"; then
  fail "公网 IP 变更手册仍建议不受保护的 VLESS 监听迁移"
fi
update_body="$(sed -n '/^update_management() {/,/^}/p' "${CLI}")"
init_body="$(sed -n '/^init_management() {/,/^}/p' "${CLI}")"
install_body="$(sed -n '/^install_management_plane() {/,/^}/p' "${CLI}")"
grep -Fq 'require_no_active_tasks' <<< "${update_body}" ||
  fail "管理网站更新前没有阻止活动任务"
grep -Fq 'require_no_active_tasks' <<< "${init_body}" ||
  fail "管理网站初始化前没有阻止活动任务"
grep -Fq 'local task_status=0' "${CLI}" ||
  fail "管理网站更新没有区分旧代理与真实任务查询错误"
grep -Fq '"${task_status}" == "4"' "${CLI}" ||
  fail "首次任务引擎迁移没有精确匹配旧代理退出码"
grep -Fq 'else' <<< "$(sed -n '/^require_no_active_tasks() {/,/^}/p' "${CLI}")" ||
  fail "管理网站更新没有保留失败命令的真实退出码"
grep -Fq 'management_health_check' <<< "${update_body}" ||
  fail "管理网站更新没有 HTTP 健康检查"
grep -Fq 'management_agent_check' <<< "${update_body}" ||
  fail "管理网站更新没有 Unix Socket 功能检查"
grep -Fq 'install_release_commands "${new_release}"' "${CLI}" ||
  fail "管理网站更新没有把全局命令切换到不可变发布目录"
grep -Fq 'restore_command_links "${command_links_backup}"' "${CLI}" ||
  fail "全局命令检查失败时不会恢复旧命令"
python3 - "${CLI}" <<'PYTHON' || fail "全局命令没有在代理功能检查前切换"
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
body = text[text.index("update_management() {"):text.index("ensure_root_ssh_directory() {")]
assert body.index('install_release_commands "${new_release}"') < body.index("management_agent_check")
PYTHON
grep -Fq 'except Exception:' "${CLI}" ||
  fail "HTTP 健康检查重试会向终端打印预期异常堆栈"
grep -Fq 'activate_management_release "${old_release}"' <<< "${update_body}" ||
  fail "管理网站更新失败时不会切回旧版本"
if grep -Fq 'bootstrap_owner' <<< "${update_body}"; then
  fail "管理网站更新会错误地触碰管理员账号或密码"
fi
grep -Fq 'chmod -R a+rX -- "${VENV_DIR}"' "${CLI}" ||
  fail "安装器没有消除调用者 umask 对低权限 Web 运行环境的影响"
grep -Fq 'WEB_SECRET_DIR="${WEB_SECRET_DIR:-/etc/server-kit-web}"' "${CLI}" ||
  fail "管理网站密钥没有使用独立配置目录"
grep -Fq 'install -d -m 710 -o root -g "${WEB_USER}" "${WEB_SECRET_DIR}"' "${CLI}" ||
  fail "Web 用户无法穿越独立密钥目录"
database_hardening_body="$(sed -n '/^harden_web_database() {/,/^}/p' "${CLI}")"
grep -Fq 'chmod 600 -- "${database_path}"' <<< "${database_hardening_body}" ||
  fail "管理网站数据库没有收紧为仅服务账号可读写"
grep -Fq 'harden_web_database' <<< "${update_body}" ||
  fail "管理网站更新后没有收紧数据库权限"
grep -Fq 'harden_web_database' <<< "${install_body}" ||
  fail "管理网站初始化后没有收紧数据库权限"
grep -Fq 'python3-ruamel.yaml' "${CLI}" ||
  fail "管理网站升级没有安装多机场配置解析依赖"
if grep -Fq 'ensure_admin_peer' <<< "${init_body}"; then
  fail "初始化仍然依赖外部扩展生成首个管理节点"
fi
grep -Fq 'ssh -L ${web_port}:${awg_ip}:${web_port}' <<< "${init_body}" ||
  fail "初始化没有提供首次访问管理网站的 SSH 转发入口"
grep -Fq '首次登录网页后新增普通节点' <<< "${init_body}" ||
  fail "初始化没有引导用户通过内置生成器创建首个节点"

# 模拟 Debian 大版本升级：系统 Python 已升到 3.13，但旧虚拟环境仍记录 3.11。
# 安装逻辑必须重建环境，不能让 bin/python 跟随系统软连接后读取不到旧依赖。
mock_bin="${test_dir}/bin"
stale_venv="${test_dir}/web-venv"
mkdir -p "${mock_bin}" "${stale_venv}/bin"
cat > "${mock_bin}/apt-get" <<'BASH'
#!/usr/bin/env bash
exit 0
BASH
cat > "${mock_bin}/install" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do target="${argument}"; done
mkdir -p "${target}"
BASH
cat > "${mock_bin}/python3" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-c" ]]; then
  printf '3.13\n'
elif [[ "${1:-}" == "-m" && "${2:-}" == "venv" ]]; then
  target="${3}"
  mkdir -p "${target}/bin"
  printf 'version = 3.13.5\n' > "${target}/pyvenv.cfg"
  cat > "${target}/bin/python" <<'PYTHON'
#!/usr/bin/env bash
exit 0
PYTHON
  chmod +x "${target}/bin/python"
else
  exit 1
fi
BASH
cat > "${stale_venv}/bin/python" <<'BASH'
#!/usr/bin/env bash
exit 0
BASH
chmod +x "${mock_bin}/apt-get" "${mock_bin}/install" "${mock_bin}/python3" \
  "${stale_venv}/bin/python"
printf 'version = 3.11.2\n' > "${stale_venv}/pyvenv.cfg"
touch "${stale_venv}/旧环境标记"

# shellcheck disable=SC1090
source "${CLI}" help >/dev/null
APT_GET_BIN="${mock_bin}/apt-get"
INSTALL_BIN="${mock_bin}/install"
PYTHON_BIN="${mock_bin}/python3"
VENV_DIR="${stale_venv}"
install_python_environment
[[ ! -e "${stale_venv}/旧环境标记" ]] ||
  fail "系统 Python 大版本变化后没有重建旧虚拟环境"
grep -Fq 'version = 3.13.5' "${stale_venv}/pyvenv.cfg" ||
  fail "重建后的虚拟环境没有使用当前系统 Python"

if [[ -z "${MSYSTEM:-}" ]]; then
  PYTHON_BIN="${REAL_PYTHON_BIN}"
  release_root="${test_dir}/releases"
  APP_DIR="${test_dir}/current"
  RELEASES_DIR="${release_root}"
  publish_management_app
  published_release="$(readlink -f -- "${APP_DIR}")"
  for required_path in \
    server-kit server-kit-manager.sh install-server-kit.sh clash_skeleton.yaml \
    lib/server_kit_backup.py lib/server_kit_client_keys.py lib/server_kit_bootstrap.py lib/server_kit_public_endpoint.py lib/server_kit_public_endpoint_transaction.py lib/server_kit_audit.py lib/awg_enrollment.py management/systemd/server-kit-agent.service.in \
    management/systemd/server-kit-awg-enrollment.service.in management/systemd/server-kit-awg-enrollment.timer.in \
    lib/server_kit_duckdns.py management/systemd/server-kit-duckdns.service.in management/systemd/server-kit-duckdns.timer.in \
    lib/server_kit_port_facts.py control_plane/read_model.py \
    web/dashboard/ssh_scripts.py web/dashboard/deployment_guide.py \
    web/static/awg.js web/static/qrcode.js; do
    [[ -f "${published_release}/${required_path}" ]] ||
      fail "不可变发布目录缺少全局命令依赖：${required_path}"
  done
  COMMAND_BIN_DIR="${test_dir}/release-bin"
  install -d "${COMMAND_BIN_DIR}"
  install_release_commands "${published_release}"
  [[ "$(readlink -f -- "${COMMAND_BIN_DIR}/server-kit-manager.sh")" == \
     "${published_release}/server-kit-manager.sh" ]] ||
    fail "全局命令没有落到不可变发布目录"
fi

cat > "${test_dir}/management.conf" <<'EOF'
MANAGEMENT_ENABLED=yes
MANAGEMENT_AWG_IP=10.20.0.1
MANAGEMENT_PORT=9080
MANAGEMENT_ADMIN_PEER=home-admin
MANAGEMENT_OWNER=owner
EOF
cat > "${test_dir}/systemctl" <<'BASH'
#!/usr/bin/env bash
echo "测试 systemd 状态：$*"
BASH
chmod +x "${test_dir}/systemctl"
status_output="$(SERVER_KIT_TESTING=1 WEB_CONFIG="${test_dir}/management.conf" \
  SYSTEMCTL_BIN="${test_dir}/systemctl" bash "${CLI}" status)"
grep -Fq '地址：http://10.20.0.1:9080' <<< "${status_output}" ||
  fail "管理平面状态无法读取初始化配置"

python3 - "${REPO_DIR}" <<'PYTHON' || fail "systemd 管理平面模板违反权限分离约束"
import sys
from pathlib import Path

root = Path(sys.argv[1])
web = (root / "management/systemd/server-kit-web.service.in").read_text(encoding="utf-8")
agent = (root / "management/systemd/server-kit-agent.service.in").read_text(encoding="utf-8")
socket = (root / "management/systemd/server-kit-agent.socket.in").read_text(encoding="utf-8")
enrollment_service = (root / "management/systemd/server-kit-awg-enrollment.service.in").read_text(encoding="utf-8")
enrollment_timer = (root / "management/systemd/server-kit-awg-enrollment.timer.in").read_text(encoding="utf-8")
duckdns_service = (root / "management/systemd/server-kit-duckdns.service.in").read_text(encoding="utf-8")
duckdns_timer = (root / "management/systemd/server-kit-duckdns.timer.in").read_text(encoding="utf-8")
assert "User=server-kit-web" in web
assert "--host @AWG_IP@" in web
assert "Environment=PYTHONPATH=@APP_DIR@" in web
assert "Environment=SERVER_KIT_SECRET_KEY_FILE=@SECRET_PATH@" in web
assert "ReadOnlyPaths=@APP_DIR@ @SECRET_PATH@" in web
assert "ProtectSystem=strict" in web
assert "User=root" in agent
assert "--manager @APP_DIR@/server-kit-manager.sh" in agent
assert "Environment=SERVER_KIT_HIGH_RISK_WRITES=0" in agent
assert "StateDirectory=server-kit-agent" in agent
assert "ExecStart=@PYTHON_BIN@" in agent
assert "--task-db /var/lib/server-kit-agent/tasks.sqlite3" in agent
assert "--task-key /var/lib/server-kit-agent/task-payload.key" in agent
assert "ProtectHome=read-only" in agent
assert "ReadWritePaths=/root/.ssh /var/lib/server-kit-agent /var/lib/server-kit-web/uploads" in agent
assert "network enrollment reconcile --json" in enrollment_service
assert "ExecStart=@APP_DIR@/server-kit-manager.sh" in enrollment_service
assert "network rotation reconcile --json" not in enrollment_service
assert "ReadWritePaths=/etc/amneziawg /etc/server-kit" in enrollment_service
assert "/run/server-kit" in enrollment_service
assert "OnUnitActiveSec=15s" in enrollment_timer
assert "network duckdns update --json" in duckdns_service
assert "ReadWritePaths=/etc/server-kit /var/lib/server-kit" in duckdns_service
assert "/run/server-kit" in duckdns_service
assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in duckdns_service
assert "Restart=on-failure" in duckdns_service
assert "RestartSec=5s" in duckdns_service
assert "OnBootSec=1s" in duckdns_timer
assert "OnActiveSec=1s" in duckdns_timer
assert "AccuracySec=1s" in duckdns_timer
assert "OnUnitActiveSec=60s" in duckdns_timer
assert "RandomizedDelaySec" not in duckdns_timer
assert "SocketGroup=server-kit-web" in socket
assert "SocketMode=0660" in socket
for content in (web, agent, socket):
    assert "http://" not in content and "https://" not in content
PYTHON

echo "通过：初始化入口明确限制系统范围且不修改 SSH/防火墙。"
echo "通过：Web、Unix Socket 和 root 代理的 systemd 权限边界正确。"
