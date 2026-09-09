"""统一定义 SSH 综合管理脚本契约，平台文件只实现操作系统 adapter。"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path


SSH_ACTIONS = (
    "status", "enable", "disable", "keygen", "key-list", "key-add", "key-remove",
)
SSH_AUTH_ACTIONS = ("auth-status", "auth-harden", "auth-confirm", "auth-rollback")
SSH_NETWORK_ACTIONS = ("network-list", "network-add", "network-remove")
LINUX_NODE_ACTIONS = (
    "awg-install", "awg-status", "awg-enable", "awg-use", "awg-autostart",
    "awg-disable", "awg-remove", "lid-status", "lid-ignore", "lid-default",
    "ssh-menu", "devtools-menu", "devtools-list", "devtools-plan", "devtools-install",
    "userdirs-menu", "userdirs-status", "userdirs-plan", "userdirs-english",
)


@dataclass(frozen=True)
class SshPlatformAdapter:
    """一个平台 adapter 的发布信息与特有能力。"""

    platform: str
    template: str
    filename: str
    content_type: str
    service_backend: str
    firewall_backend: str
    launcher: str = ""
    auth_hardening: bool = False


WINDOWS_LAUNCHER = r"""@echo off
setlocal
set "SERVER_KIT_SELF=%~f0"
set "SERVER_KIT_ACTION=%~1"
set "SERVER_KIT_VALUE=%~2"
if not defined SERVER_KIT_CALLER_PROFILE set "SERVER_KIT_CALLER_PROFILE=%USERPROFILE%"
if not defined SERVER_KIT_CALLER_ACCOUNT set "SERVER_KIT_CALLER_ACCOUNT=%USERDOMAIN%\%USERNAME%"
fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if ([string]::IsNullOrWhiteSpace($env:SERVER_KIT_ACTION)) { Start-Process -FilePath $env:SERVER_KIT_SELF -Verb RunAs } elseif ([string]::IsNullOrWhiteSpace($env:SERVER_KIT_VALUE)) { Start-Process -FilePath $env:SERVER_KIT_SELF -Verb RunAs -ArgumentList $env:SERVER_KIT_ACTION } else { Start-Process -FilePath $env:SERVER_KIT_SELF -Verb RunAs -ArgumentList @($env:SERVER_KIT_ACTION,$env:SERVER_KIT_VALUE) }"
  exit /b
)
chcp 65001 >nul
set "SERVER_KIT_TEMP_PS=%TEMP%\server-kit-ssh-%RANDOM%-%RANDOM%.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$raw=[IO.File]::ReadAllText($env:SERVER_KIT_SELF,[Text.Encoding]::UTF8); $marker='###SERVER_'+'KIT_POWERSHELL###'; $index=$raw.IndexOf($marker); if($index -lt 0){throw 'missing payload'}; $code=$raw.Substring($index+$marker.Length).TrimStart([char]13,[char]10); [IO.File]::WriteAllText($env:SERVER_KIT_TEMP_PS,$code,(New-Object Text.UTF8Encoding($true)))"
if errorlevel 1 (
  echo Failed to prepare the SSH manager.
  pause
  exit /b 1
)
if "%SERVER_KIT_ACTION%"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SERVER_KIT_TEMP_PS%" menu
) else if "%SERVER_KIT_VALUE%"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SERVER_KIT_TEMP_PS%" "%SERVER_KIT_ACTION%"
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SERVER_KIT_TEMP_PS%" "%SERVER_KIT_ACTION%" "%SERVER_KIT_VALUE%"
)
set "SERVER_KIT_EXIT=%ERRORLEVEL%"
del /q "%SERVER_KIT_TEMP_PS%" >nul 2>&1
if "%SERVER_KIT_ACTION%"=="" pause
exit /b %SERVER_KIT_EXIT%
###SERVER_KIT_POWERSHELL###
"""


LINUX_NODE_LAUNCHER = r'''#!/usr/bin/env bash
# server-kit Linux 节点综合管理器
set -euo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ACTION="${1:-menu}"
VALUE="${2:-}"
OPTION="${3:-}"
AWG_START='###SERVER_''KIT_AWG_PAYLOAD###'
AWG_END='###SERVER_''KIT_AWG_PAYLOAD_END###'
SSH_START='###SERVER_''KIT_SSH_PAYLOAD###'
SSH_END='###SERVER_''KIT_SSH_PAYLOAD_END###'
DEVTOOLS_START='###SERVER_''KIT_DEVTOOLS_PAYLOAD###'
DEVTOOLS_END='###SERVER_''KIT_DEVTOOLS_PAYLOAD_END###'
USERDIRS_START='###SERVER_''KIT_USERDIRS_PAYLOAD###'
USERDIRS_END='###SERVER_''KIT_USERDIRS_PAYLOAD_END###'

run_payload() {
  local start_marker="$1" end_marker="$2"
  shift 2
  local payload_file payload_status
  payload_file="$(mktemp)"
  awk -v start="$start_marker" -v end="$end_marker" '
    $0 == start {copy=1; next}
    $0 == end {copy=0}
    copy {print}
  ' "$SELF" >"$payload_file"
  chmod 0700 "$payload_file"
  set +e
  bash "$payload_file" "$@"
  payload_status=$?
  set -e
  rm -f "$payload_file"
  return "$payload_status"
}

run_awg() { run_payload "$AWG_START" "$AWG_END" "$@"; }
run_ssh() { run_payload "$SSH_START" "$SSH_END" "$@"; }
run_devtools() { run_payload "$DEVTOOLS_START" "$DEVTOOLS_END" "$@"; }
run_userdirs() { run_payload "$USERDIRS_START" "$USERDIRS_END" "$@"; }

show_menu() {
  local choice value
  while true; do
    clear 2>/dev/null || true
    echo "server-kit · Linux 节点综合管理"
    echo
    echo "  1. 安装或更新 AWG，并导入双入口配置"
    echo "  2. 查看 AWG 状态"
    echo "  3. 启动 AWG"
    echo "  4. 切换 AWG 入口"
    echo "  5. 设置 AWG 开机自启"
    echo "  6. 停用 AWG"
    echo "  7. 移除 AWG 托管配置"
    echo "  8. SSH 服务、公钥和允许网段管理"
    echo "  9. 查看笔记本合盖策略"
    echo " 10. 设置合盖不休眠（Debian / Ubuntu）"
    echo " 11. 恢复系统默认合盖策略"
    echo " 12. 安装或更新常用开发工具"
    echo " 13. 用户目录语言管理"
    echo "  0. 退出"
    echo
    read -r -p ">: " choice || return 0
    case "$choice" in
      1) run_awg install || true ;;
      2) run_awg status || true ;;
      3) read -r -p "启动入口（main / backup1，回车默认 main）：" value; run_awg enable "${value:-main}" || true ;;
      4) read -r -p "输入 main 或 backup1：" value; run_awg use "$value" || true ;;
      5) read -r -p "输入 on 或 off：" value; run_awg autostart "$value" || true ;;
      6) read -r -p "停用后内网会断开，输入 yes：" value; [[ "$value" == "yes" ]] && run_awg disable || true ;;
      7) read -r -p "将删除托管配置，输入 yes：" value; [[ "$value" == "yes" ]] && run_awg remove --yes || true ;;
      8) run_ssh menu || true ;;
      9) manage_lid status || true ;;
      10) manage_lid ignore || true ;;
      11) manage_lid default || true ;;
      12) run_devtools menu || true ;;
      13) run_userdirs menu || true ;;
      0) return 0 ;;
      *) echo "无效选项。" ;;
    esac
    [[ "$choice" == "8" || "$choice" == "12" || "$choice" == "13" ]] || { echo; read -r -p "按回车继续..." _ || true; }
  done
}

manage_lid() {
  local operation="$1" config_dir
  local config_file="${SERVER_KIT_LID_CONFIG:-/etc/systemd/logind.conf.d/80-server-kit-lid.conf}"
  config_dir="$(dirname "$config_file")"
  [[ -r /etc/os-release ]] || { echo "无法识别 Linux 发行版。" >&2; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" ]] || {
    echo "合盖策略快捷操作仅支持 Debian 和 Ubuntu。" >&2
    return 1
  }
  case "$operation" in
    status)
      if [[ -f "$config_file" ]] && grep -Eq '^HandleLidSwitch=ignore$' "$config_file"; then
        echo "合盖策略：不休眠（server-kit 管理）"
      else
        echo "合盖策略：系统默认"
      fi
      systemd-analyze cat-config systemd/logind.conf 2>/dev/null |
        grep -E '^(HandleLidSwitch|HandleLidSwitchExternalPower|HandleLidSwitchDocked)=' || true
      ;;
    ignore|default)
      (( EUID == 0 )) || { echo "请使用 sudo 运行合盖策略变更。" >&2; return 1; }
      if [[ "$operation" == "ignore" ]]; then
        install -d -m 0755 "$config_dir"
        printf '%s\n' '[Login]' 'HandleLidSwitch=ignore' \
          'HandleLidSwitchExternalPower=ignore' 'HandleLidSwitchDocked=ignore' >"$config_file"
        chmod 0644 "$config_file"
      else
        rm -f "$config_file"
      fi
      systemctl kill --kill-whom=main --signal=HUP systemd-logind.service
      [[ "$operation" == "ignore" ]] && echo "已生效：合盖不会触发休眠。" || echo "已恢复系统默认合盖策略。"
      ;;
    *) return 2 ;;
  esac
}

case "$ACTION" in
  menu) show_menu ;;
  awg-install) run_awg install "$VALUE" ;;
  awg-status) run_awg status ;;
  awg-enable) run_awg enable "${VALUE:-main}" ;;
  awg-use) run_awg use "$VALUE" ;;
  awg-autostart) run_awg autostart "$VALUE" ;;
  awg-disable) run_awg disable ;;
  awg-remove) run_awg remove "$VALUE" ;;
  lid-status) manage_lid status ;;
  lid-ignore) manage_lid ignore ;;
  lid-default) manage_lid default ;;
  devtools-menu) run_devtools menu ;;
  devtools-list) run_devtools list ;;
  devtools-plan) run_devtools plan "$VALUE" ;;
  devtools-install) run_devtools install "$VALUE" "$OPTION" ;;
  userdirs-menu) run_userdirs menu ;;
  userdirs-status) run_userdirs status ;;
  userdirs-plan) run_userdirs plan ;;
  userdirs-english) run_userdirs english "$VALUE" ;;
  ssh-menu) run_ssh menu ;;
  ssh-network-list) run_ssh network-list ;;
  ssh-network-add) run_ssh network-add "$VALUE" ;;
  ssh-network-remove) run_ssh network-remove "$VALUE" ;;
  ssh-*) run_ssh "${ACTION#ssh-}" "$VALUE" ;;
  *) run_ssh "$ACTION" "$VALUE" ;;
esac
exit $?
'''


ADAPTERS = {
    adapter.platform: adapter
    for adapter in (
        SshPlatformAdapter(
            "windows", "server-kit-ssh-windows.ps1", "server-kit-ssh.cmd",
            "text/plain; charset=utf-8", "Windows OpenSSH", "Windows Defender 防火墙",
            WINDOWS_LAUNCHER, True,
        ),
        SshPlatformAdapter(
            "linux", "server-kit-ssh-linux.sh", "server-kit-node-linux.sh",
            "text/x-shellscript; charset=utf-8", "systemd OpenSSH", "UFW / firewalld",
            auth_hardening=True,
        ),
        SshPlatformAdapter(
            "macos", "server-kit-ssh-macos.sh", "server-kit-ssh.sh",
            "text/x-shellscript; charset=utf-8", "launchd sshd", "应用防火墙",
            auth_hardening=True,
        ),
        SshPlatformAdapter(
            "android", "server-kit-ssh-termux.sh", "server-kit-ssh.sh",
            "text/x-shellscript; charset=utf-8", "Termux sshd", "仅监听 AWG 地址",
        ),
    )
}


@dataclass(frozen=True)
class SshScriptDownload:
    payload: bytes
    filename: str
    content_type: str


class SshScriptBundle:
    """校验共同契约并把平台 adapter 组装成可直接运行的下载物。"""

    def __init__(self, template_dir: Path) -> None:
        self._template_dir = template_dir

    def download(self, platform: str) -> SshScriptDownload:
        try:
            adapter = ADAPTERS[platform]
        except KeyError as error:
            raise ValueError("不支持该系统") from error
        payload = (self._template_dir / adapter.template).read_bytes()
        script = payload.decode("utf-8-sig")
        if platform == "linux":
            awg_script = (
                self._template_dir / "server-kit-awg-linux.sh"
            ).read_text(encoding="utf-8-sig")
            devtools_script = (
                self._template_dir / "server-kit-devtools-linux.sh"
            ).read_text(encoding="utf-8-sig")
            userdirs_script = (
                self._template_dir / "server-kit-userdirs-linux.sh"
            ).read_text(encoding="utf-8-sig")
            script = (
                f"{LINUX_NODE_LAUNCHER.rstrip()}\n"
                "###SERVER_KIT_AWG_PAYLOAD###\n"
                f"{awg_script.rstrip()}\n"
                "###SERVER_KIT_AWG_PAYLOAD_END###\n"
                "###SERVER_KIT_SSH_PAYLOAD###\n"
                f"{script.rstrip()}\n"
                "###SERVER_KIT_SSH_PAYLOAD_END###\n"
                "###SERVER_KIT_DEVTOOLS_PAYLOAD###\n"
                f"{devtools_script.rstrip()}\n"
                "###SERVER_KIT_DEVTOOLS_PAYLOAD_END###\n"
                "###SERVER_KIT_USERDIRS_PAYLOAD###\n"
                f"{userdirs_script.rstrip()}\n"
                "###SERVER_KIT_USERDIRS_PAYLOAD_END###\n"
            )
            payload = script.encode("utf-8")
        self._validate_contract(adapter, script)
        if adapter.launcher:
            payload = (
                adapter.launcher.replace("\n", "\r\n").encode("utf-8")
                + script.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
            )
        return SshScriptDownload(payload, adapter.filename, adapter.content_type)

    def download_all(self) -> SshScriptDownload:
        """把所有平台的已校验脚本打包为一个可分发的 ZIP。"""
        members = (
            ("windows", "windows/server-kit-ssh.cmd"),
            ("linux", "linux/server-kit-node-linux.sh"),
            ("macos", "macos/server-kit-ssh.sh"),
            ("android", "android-termux/server-kit-ssh.sh"),
        )
        readme = """server-kit 节点脚本包

选择自己的系统目录：
- windows：Windows SSH 综合管理脚本
- linux：Linux 节点综合管理脚本，包含 AWG、SSH、开发工具、英文用户目录与笔记本合盖管理
- macos：macOS SSH 综合管理脚本
- android-termux：Android Termux SSH 综合管理脚本

所有脚本不带子命令直接运行时都会打开交互菜单，可以按提示完成操作。
Windows 可双击 server-kit-ssh.cmd；Linux、macOS 和 Android 在终端运行对应脚本。

Linux 安装 AWG 时，请把 linux/server-kit-node-linux.sh 与下载的主/备两份 AWG 配置放在同一目录。
脚本不包含节点私钥、账号密码或服务器专属配置。
"""
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            self._write_archive_member(archive, "README.txt", readme.encode("utf-8"), 0o644)
            for platform, member_name in members:
                self._write_archive_member(
                    archive, member_name, self.download(platform).payload, 0o755
                )
        return SshScriptDownload(
            output.getvalue(), "server-kit-node-scripts.zip", "application/zip"
        )

    @staticmethod
    def _write_archive_member(
        archive: zipfile.ZipFile, name: str, payload: bytes, mode: int
    ) -> None:
        # 固定元数据，保证同一版本生成的压缩包内容稳定且不泄露服务器时间。
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = ((0o100000 | mode) & 0xFFFF) << 16
        archive.writestr(info, payload)

    @staticmethod
    def _validate_contract(adapter: SshPlatformAdapter, script: str) -> None:
        missing = [action for action in SSH_ACTIONS if action not in script]
        if adapter.auth_hardening:
            missing.extend(action for action in SSH_AUTH_ACTIONS if action not in script)
        if adapter.platform in {"windows", "linux", "macos"}:
            missing.extend(action for action in SSH_NETWORK_ACTIONS if action not in script)
        if adapter.platform == "linux":
            missing.extend(action for action in LINUX_NODE_ACTIONS if action not in script)
        if missing:
            raise RuntimeError(f"{adapter.platform} SSH adapter 缺少动作：{', '.join(missing)}")
        for marker in ("10.20.0", "id_ed25519", "公钥", "端口"):
            if marker not in script:
                raise RuntimeError(f"{adapter.platform} SSH adapter 缺少契约能力：{marker}")
