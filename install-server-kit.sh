#!/usr/bin/env bash

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [[ -L "${SCRIPT_PATH}" ]]; do
  SCRIPT_LINK_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
  SCRIPT_PATH="$(readlink -- "${SCRIPT_PATH}")"
  [[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="${SCRIPT_LINK_DIR}/${SCRIPT_PATH}"
done
REPO_DIR="$(cd -P -- "$(dirname -- "${SCRIPT_PATH}")" && pwd)"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"

SCRIPTS=(
  server-kit
  amneziawg-setup.sh
  debian_file_manager.sh
  debian_vless_manager.sh
  debian_mosh_manager.sh
  debian_security_manager.sh
  debian_firewall_manager.sh
  server-kit-manager.sh
  install-server-kit.sh
)

require_writable_target() {
  local parent_dir=""

  if [[ "${BIN_DIR}" != /* ]]; then
    echo "命令目录必须是绝对路径: ${BIN_DIR}" >&2
    return 1
  fi
  parent_dir="$(dirname -- "${BIN_DIR}")"
  if [[ ! -d "${BIN_DIR}" && ! -w "${parent_dir}" && "${EUID}" -ne 0 ]]; then
    echo "没有权限创建 ${BIN_DIR}，请使用 root 运行。" >&2
    return 1
  fi
  if [[ -d "${BIN_DIR}" && ! -w "${BIN_DIR}" && "${EUID}" -ne 0 ]]; then
    echo "没有权限写入 ${BIN_DIR}，请使用 root 运行。" >&2
    return 1
  fi
}

install_links() {
  local script_name=""
  local source_path=""
  local link_path=""

  require_writable_target
  install -d -m 755 "${BIN_DIR}"
  # 先验证全部来源和目标，避免第 N 个目标异常时留下半套新旧命令。
  for script_name in "${SCRIPTS[@]}"; do
    source_path="${REPO_DIR}/${script_name}"
    link_path="${BIN_DIR}/${script_name}"
    if [[ ! -f "${source_path}" ]]; then
      echo "脚本不存在: ${source_path}" >&2
      return 1
    fi
    if [[ -e "${link_path}" && ! -L "${link_path}" ]]; then
      echo "目标已存在且不是软连接，未覆盖: ${link_path}" >&2
      return 1
    fi
  done
  for script_name in "${SCRIPTS[@]}"; do
    source_path="${REPO_DIR}/${script_name}"
    link_path="${BIN_DIR}/${script_name}"
    chmod +x "${source_path}"
    ln -sfn -- "${source_path}" "${link_path}"
    echo "已安装：${script_name}"
  done

  echo
  echo "安装完成，命令目录：${BIN_DIR}"
  case ":${PATH}:" in
    *":${BIN_DIR}:"*) echo "现在可以在任意目录直接运行以上脚本。" ;;
    *) echo "注意：${BIN_DIR} 尚未加入 PATH，请把它加入 shell 的 PATH 环境变量。" ;;
  esac
}

uninstall_links() {
  local script_name=""
  local source_path=""
  local link_path=""
  local link_target=""

  require_writable_target
  for script_name in "${SCRIPTS[@]}"; do
    source_path="${REPO_DIR}/${script_name}"
    link_path="${BIN_DIR}/${script_name}"
    if [[ ! -L "${link_path}" ]]; then
      continue
    fi
    link_target="$(readlink -- "${link_path}")"
    if [[ "${link_target}" != "${source_path}" ]]; then
      echo "跳过不属于本仓库的软连接：${link_path} -> ${link_target}"
      continue
    fi
    rm -f -- "${link_path}"
    echo "已删除：${link_path}"
  done
  echo "命令软连接已卸载，仓库文件未删除。"
}

show_status() {
  local script_name=""
  local link_path=""

  echo "仓库目录：${REPO_DIR}"
  echo "命令目录：${BIN_DIR}"
  for script_name in "${SCRIPTS[@]}"; do
    link_path="${BIN_DIR}/${script_name}"
    if [[ -L "${link_path}" ]]; then
      echo "已安装：${script_name} -> $(readlink -- "${link_path}")"
    else
      echo "未安装：${script_name}"
    fi
  done
}

usage() {
  cat <<EOF
说明：把 server-kit 管理脚本软连接到 PATH 命令目录，默认使用 /usr/local/bin。

用法：
  bash $0 install          安装或刷新软连接
  bash $0 uninstall        删除本仓库创建的软连接
  bash $0 status           查看软连接状态

管理平面：
  server-kit preflight     检查初始化条件
  server-kit init          初始化 AWG 管理入口和内网网站
  server-kit recovery      恢复管理入口

自定义目录：
  BIN_DIR=/自定义/PATH目录 bash $0 install
EOF
}

case "${1:-}" in
  install)
    install_links
    ;;
  uninstall)
    uninstall_links
    ;;
  status)
    show_status
    ;;
  *)
    usage
    exit 1
    ;;
esac
