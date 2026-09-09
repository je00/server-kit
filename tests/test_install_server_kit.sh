#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLER="${REPO_DIR}/install-server-kit.sh"

fail() {
  echo "失败：$1"
  exit 1
}

temp_dir="$(mktemp -d)"
trap 'rm -rf -- "${temp_dir}"' EXIT
bin_dir="${temp_dir}/bin"
install -d "${bin_dir}"

BIN_DIR="${bin_dir}" bash "${INSTALLER}" install >/dev/null
for script_name in \
  server-kit \
  amneziawg-setup.sh \
  debian_file_manager.sh \
  debian_vless_manager.sh \
  debian_mosh_manager.sh \
  debian_security_manager.sh \
  debian_firewall_manager.sh \
  server-kit-manager.sh \
  install-server-kit.sh; do
  if [[ -n "${MSYSTEM:-}" ]]; then
    [[ -x "${bin_dir}/${script_name}" ]] || fail "没有安装 ${script_name} 测试副本"
  else
    [[ -L "${bin_dir}/${script_name}" ]] || fail "没有安装 ${script_name} 软连接"
    [[ "$(readlink "${bin_dir}/${script_name}")" == "${REPO_DIR}/${script_name}" ]] ||
      fail "${script_name} 没有指向当前仓库"
  fi
done

if [[ -n "${MSYSTEM:-}" ]]; then
  echo "通过：Windows Git Bash 已验证全部管理脚本可安装到目标目录。"
  exit 0
fi

if [[ -z "${MSYSTEM:-}" ]]; then
  resolved_file_dir="$(bash -c 'source "$1"; printf "%s\n" "${SCRIPT_DIR}"' \
    _ "${bin_dir}/debian_file_manager.sh")"
  [[ "${resolved_file_dir}" == "${REPO_DIR}" ]] || fail "文件服务脚本无法从软连接定位仓库"
fi

status_output="$(BIN_DIR="${bin_dir}" "${bin_dir}/install-server-kit.sh" status)"
grep -Fq '已安装：server-kit' <<< "${status_output}" || fail "无法安装统一初始化命令"
grep -Fq '已安装：debian_file_manager.sh' <<< "${status_output}" ||
  fail "无法通过软连接查看安装状态"

BIN_DIR="${bin_dir}" bash "${INSTALLER}" uninstall >/dev/null
[[ ! -e "${bin_dir}/debian_file_manager.sh" ]] || fail "卸载没有删除文件服务软连接"

printf '用户自己的命令\n' > "${bin_dir}/debian_file_manager.sh"
if BIN_DIR="${bin_dir}" bash "${INSTALLER}" install >/dev/null 2>&1; then
  fail "安装错误地覆盖了普通文件"
fi
[[ -f "${bin_dir}/debian_file_manager.sh" && ! -L "${bin_dir}/debian_file_manager.sh" ]] ||
  fail "普通文件被安装程序替换"
for script_name in server-kit amneziawg-setup.sh debian_vless_manager.sh; do
  [[ ! -e "${bin_dir}/${script_name}" ]] || fail "安装预检失败前已经部分改写 ${script_name}"
done

echo "通过：全部管理脚本可安装到 PATH 目录并从任意位置运行。"
echo "通过：卸载只删除本仓库软连接，不覆盖已有普通文件。"
