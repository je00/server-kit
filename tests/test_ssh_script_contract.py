#!/usr/bin/env python3
"""以一份能力矩阵验证四个平台 SSH adapter。"""

from __future__ import annotations

import re
import os
import io
import shutil
import subprocess
import unittest
import zipfile
from pathlib import Path

from web.dashboard.ssh_scripts import (
    ADAPTERS,
    LINUX_NODE_ACTIONS,
    SSH_ACTIONS,
    SSH_AUTH_ACTIONS,
    SSH_NETWORK_ACTIONS,
    SshScriptBundle,
)


class SshScriptContractTests(unittest.TestCase):
    def test_every_platform_implements_the_same_user_actions(self) -> None:
        root = Path(__file__).resolve().parents[1] / "web" / "dashboard" / "script_templates"
        bundle = SshScriptBundle(root)
        self.assertEqual(set(ADAPTERS), {"windows", "linux", "macos", "android"})
        for platform, adapter in ADAPTERS.items():
            with self.subTest(platform=platform):
                download = bundle.download(platform)
                script = download.payload.decode("utf-8")
                for action in SSH_ACTIONS:
                    self.assertIn(action, script)
                if adapter.auth_hardening:
                    for action in SSH_AUTH_ACTIONS:
                        self.assertIn(action, script)
                    for marker in ("PasswordAuthentication", "publickey", "自动回滚"):
                        self.assertIn(marker, script)
                if platform in {"windows", "linux", "macos"}:
                    for action in SSH_NETWORK_ACTIONS:
                        self.assertIn(action, script)
                    for marker in ("10.20.0.0/24", "允许网段", "CIDR"):
                        self.assertIn(marker, script)
                    self.assertIn("初始值，可替换", script)
                    self.assertNotIn("没有找到 10.20.0.x", script)
                    self.assertIn("DenyUsers", script)
                self.assertTrue(adapter.service_backend)
                self.assertTrue(adapter.firewall_backend)
                self.assertEqual(download.filename, adapter.filename)

    def test_linux_download_is_one_combined_node_manager(self) -> None:
        root = Path(__file__).resolve().parents[1] / "web" / "dashboard" / "script_templates"
        download = SshScriptBundle(root).download("linux")
        script = download.payload.decode("utf-8")

        self.assertEqual(download.filename, "server-kit-node-linux.sh")
        self.assertEqual(script.count("###SERVER_KIT_AWG_PAYLOAD###"), 1)
        self.assertEqual(script.count("###SERVER_KIT_SSH_PAYLOAD###"), 1)
        self.assertEqual(script.count("###SERVER_KIT_DEVTOOLS_PAYLOAD###"), 1)
        self.assertEqual(script.count("###SERVER_KIT_USERDIRS_PAYLOAD###"), 1)
        for marker in (
            "awg-install", "awg-status", "awg-enable", "awg-use", "ssh-menu",
            "lid-status", "lid-ignore", "lid-default", "devtools-menu",
            "apt-get install -y amneziawg", "75C9DD72C799870E310542E24166F2C257290828",
        ):
            self.assertIn(marker, script)
        for action in LINUX_NODE_ACTIONS:
            self.assertIn(action, script)

    def test_all_platform_archive_contains_each_validated_download(self) -> None:
        root = Path(__file__).resolve().parents[1] / "web" / "dashboard" / "script_templates"
        bundle = SshScriptBundle(root)
        download = bundle.download_all()

        self.assertEqual(download.filename, "server-kit-node-scripts.zip")
        self.assertEqual(download.content_type, "application/zip")
        with zipfile.ZipFile(io.BytesIO(download.payload)) as archive:
            expected = {
                "windows/server-kit-ssh.cmd": "windows",
                "linux/server-kit-node-linux.sh": "linux",
                "macos/server-kit-ssh.sh": "macos",
                "android-termux/server-kit-ssh.sh": "android",
            }
            self.assertEqual(set(archive.namelist()), {"README.txt", *expected})
            readme = archive.read("README.txt").decode("utf-8")
            self.assertIn("选择自己的系统目录", readme)
            self.assertIn("不带子命令直接运行时都会打开交互菜单", readme)
            self.assertIn("开发工具", readme)
            for member, platform in expected.items():
                self.assertEqual(archive.read(member), bundle.download(platform).payload)
                self.assertEqual((archive.getinfo(member).external_attr >> 16) & 0o777, 0o755)

    def test_desktop_platforms_expose_end_to_end_authentication_hardening(self) -> None:
        self.assertTrue(all(ADAPTERS[name].auth_hardening for name in ("windows", "linux", "macos")))
        self.assertFalse(ADAPTERS["android"].auth_hardening)

    def test_unknown_platform_cannot_select_an_arbitrary_file(self) -> None:
        bundle = SshScriptBundle(Path("unused"))
        with self.assertRaises(ValueError):
            bundle.download("../../windows")

    def test_macos_does_not_shadow_zsh_special_parameters(self) -> None:
        root = Path(__file__).resolve().parents[1] / "web" / "dashboard" / "script_templates"
        script = SshScriptBundle(root).download("macos").payload.decode("utf-8")
        local_declarations = [
            line.strip().removeprefix("local ")
            for line in script.splitlines()
            if line.strip().startswith("local ")
        ]
        for parameter in ("status", "path"):
            with self.subTest(parameter=parameter):
                self.assertFalse(any(
                    re.search(
                        rf"(?:^|\s){re.escape(parameter)}(?:=|\s|$)",
                        declaration,
                    )
                    for declaration in local_declarations
                ))

        zsh = shutil.which("zsh")
        if zsh is None:
            return
        function_text = script.split("run_menu_action() {", 1)[1].split("\n}", 1)[0]
        harness = (
            "set -e\n"
            "invoke_action() { return 7; }\n"
            f"run_menu_action() {{{function_text}\n}}\n"
            "run_menu_action status\n"
        )
        completed = subprocess.run(
            [zsh, "-c", harness], text=True, capture_output=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("read-only variable", completed.stderr)

    def test_windows_sshd_management_survives_powershell_51_encoding(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script_path = root / "web" / "dashboard" / "script_templates" / "server-kit-ssh-windows.ps1"
        script = script_path.read_text(encoding="utf-8")

        markers = dict(re.findall(
            r'^\$(ManagedMarker|ManagedAccessBegin|ManagedAccessEnd|AuthMarker)\s*=\s*"([^"]+)"',
            script,
            re.MULTILINE,
        ))
        self.assertEqual(
            set(markers),
            {"ManagedMarker", "ManagedAccessBegin", "ManagedAccessEnd", "AuthMarker"},
        )
        self.assertTrue(
            all(marker.isascii() for marker in markers.values()),
            "sshd_config management markers must remain ASCII under Windows PowerShell 5.1",
        )
        self.assertIn(
            "[IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8)",
            script,
        )
        self.assertNotRegex(
            script,
            r"Get-Content\s+-LiteralPath\s+\$ConfigPath",
            "PowerShell 5.1 decodes BOM-less UTF-8 as the system ANSI code page",
        )
        self.assertIn("LegacyManagedAccessBegin", script)
        self.assertIn("LegacyManagedAccessEnd", script)
        self.assertIn("拒绝静默跳过重应用", script)
        self.assertIn("允许网段已存在，正在重新应用", script)
        self.assertIn("Invoke-ServerKitNetworkFileChange", script)
        self.assertIn("网段文件已恢复", script)
        self.assertIn("ConvertTo-ServerKitCanonicalIpv4Network", script)
        self.assertIn("ConvertTo-ServerKitComparableNetworks", script)
        self.assertIn("Assert-ServerKitSshApplied -Address $managedAddresses -Port $portNumber", script)
        for validation_cmdlet in (
            "HNetCfg.FwPolicy2",
            "ConvertTo-ServerKitComparableNetworks",
            "Get-ServerKitListeners",
        ):
            self.assertIn(validation_cmdlet, script)

    def test_windows_network_helpers_validate_and_render_idempotently(self) -> None:
        powershell = (
            shutil.which("powershell.exe")
            or shutil.which("powershell")
            or shutil.which("pwsh")
        )
        if powershell is None:
            self.skipTest("Windows PowerShell or PowerShell Core is not installed")
        root = Path(__file__).resolve().parents[1]
        script_path = root / "web" / "dashboard" / "script_templates" / "server-kit-ssh-windows.ps1"
        command = rf'''
$env:SERVER_KIT_LIBRARY_ONLY="1"
$networkRoot=Join-Path ([IO.Path]::GetTempPath()) ("server-kit-networks-" + [guid]::NewGuid().ToString("N"))
$env:SERVER_KIT_SSH_NETWORKS_FILE=Join-Path $networkRoot "allowed.conf"
. "{script_path}"
if (-not (Test-ServerKitIpv4Cidr "192.168.1.0/24")) {{ throw "CIDR 校验失败" }}
if (Test-ServerKitIpv4Cidr "300.1.1.1/24") {{ throw "错误 CIDR 被接受" }}
if (-not (Test-ServerKitAddressInCidr "192.168.1.9" "192.168.1.0/24")) {{ throw "网段匹配失败" }}
if ((ConvertTo-ServerKitCanonicalIpv4Network "10.20.0.0/255.255.255.0") -ne "10.20.0.0/24") {{ throw "Windows 子网掩码格式未规范化" }}
if ((ConvertTo-ServerKitCanonicalIpv4Network "192.168.1.9/24") -ne "192.168.1.0/24") {{ throw "CIDR 网络地址未规范化" }}
if ($null -ne (ConvertTo-ServerKitCanonicalIpv4Network "10.20.0.0/255.0.255.0")) {{ throw "非连续子网掩码被接受" }}
New-Item -ItemType Directory -Path $networkRoot -Force | Out-Null
[IO.File]::WriteAllLines($NetworksPath,[string[]]@("172.31.48.0/20"),[Text.Encoding]::ASCII)
$networks=@(Get-ServerKitAllowedNetworks)
if ($networks.Count -ne 1 -or $networks[0] -ne "172.31.48.0/20") {{ throw "任意网段未成为唯一事实来源" }}
$source="PasswordAuthentication yes`r`nMatch User demo`r`n    X11Forwarding no`r`n"
$once=ConvertTo-ServerKitSshdConfig -Content $source -Address @("10.20.0.101","192.168.1.8") -Port 5080
$twice=ConvertTo-ServerKitSshdConfig -Content $once -Address @("10.20.0.101","192.168.1.8") -Port 5080
if (([regex]::Matches($twice,[regex]::Escape($ManagedAccessBegin))).Count -ne 1) {{ throw "管理块重复" }}
if ($twice -notmatch "DenyUsers \*") {{ throw "来源限制缺失" }}
$legacy="$LegacyManagedAccessBegin`r`n$LegacyManagedMarker`r`nPort 22`r`nListenAddress 10.20.0.101`r`nMatch Address *,!172.31.48.0/20`r`n    DenyUsers *`r`nMatch all`r`n$LegacyManagedAccessEnd`r`n"
$legacyBlock=Get-ServerKitManagedAccessBlock -Content $legacy
if ($legacyBlock -notmatch "Port 22") {{ throw "旧版中文管理块无法读取" }}
$migrated=ConvertTo-ServerKitSshdConfig -Content $legacy -Address @("10.20.0.101","192.168.1.8") -Port 22
if ($migrated -match [regex]::Escape($LegacyManagedAccessBegin)) {{ throw "旧版中文管理块未清理" }}
$garbled="# server-kit garbled begin`r`n# server-kit garbled marker`r`nPort 22`r`nListenAddress 10.20.0.101`r`nMatch Address *,!172.31.48.0/20`r`n    DenyUsers *`r`nMatch all`r`n# server-kit garbled end`r`n"
$garbledBlock=Get-ServerKitManagedAccessBlock -Content $garbled
if ($garbledBlock -notmatch "Port 22") {{ throw "乱码管理块无法识别" }}
$cleaned=ConvertTo-ServerKitSshdConfig -Content $garbled -Address @("10.20.0.101","192.168.1.8") -Port 22
if ($cleaned -match "garbled") {{ throw "乱码管理块未清理" }}
if (([regex]::Matches($cleaned,[regex]::Escape($ManagedAccessBegin))).Count -ne 1) {{ throw "迁移后管理块数量错误" }}
function Assert-ServerKitAdministrator {{ }}
$script:reapplyCalls=0
function Update-ServerKitSshAfterNetworkChange {{ $script:reapplyCalls++; return $true }}
$script:Value="172.31.48.0/20"
Add-ServerKitNetwork
if ($script:reapplyCalls -ne 1) {{ throw "已存在网段未触发重应用" }}
function Get-Service {{ [pscustomobject]@{{ Status="Running" }} }}
$script:reapplyCalls=0
function Update-ServerKitSshAfterNetworkChange {{
    $script:reapplyCalls++
    if ($script:reapplyCalls -eq 1) {{ throw "simulated apply failure" }}
    return $true
}}
$script:Value="192.168.5.0/24"
$changeFailed=$false
try {{ Add-ServerKitNetwork }} catch {{ $changeFailed=$true }}
if (-not $changeFailed) {{ throw "失败的重应用未向调用方报错" }}
$restoredNetworks=@(Get-ServerKitAllowedNetworks)
if ($restoredNetworks.Count -ne 1 -or $restoredNetworks[0] -ne "172.31.48.0/20") {{ throw "重应用失败后网段文件未恢复" }}
if ($script:reapplyCalls -ne 2) {{ throw "重应用失败后未尝试恢复运行配置" }}
function Get-ServerKitAllowedNetworks {{ return @("172.31.48.0/20","192.168.0.0/24") }}
function Get-ServerKitConfig {{ return [ordered]@{{ Address=@("10.20.0.101","192.168.0.100"); Port="5080" }} }}
$script:firewallDirection=1
$script:firewallProtocol=6
$script:firewallRemote=@("172.31.48.0/20","192.168.0.0/24")
function Get-ServerKitFirewallRule {{ return [pscustomobject]@{{ Enabled=$true; Direction=$script:firewallDirection;
    Action=1; Protocol=$script:firewallProtocol; LocalPorts="5080"; Profiles=2147483647;
    LocalAddresses="10.20.0.101,192.168.0.100"; RemoteAddresses=($script:firewallRemote -join ',') }} }}
function Get-ServerKitListeners {{ return @(
    [pscustomobject]@{{ OwningProcess=42; LocalAddress="10.20.0.101"; LocalPort=5080 }},
    [pscustomobject]@{{ OwningProcess=42; LocalAddress="192.168.0.100"; LocalPort=5080 }}
) }}
Assert-ServerKitSshApplied -Address @("10.20.0.101","192.168.0.100") -Port 5080
$script:firewallRemote=@("172.31.48.0/255.255.240.0","192.168.0.0/255.255.255.0")
Assert-ServerKitSshApplied -Address @("10.20.0.101","192.168.0.100") -Port 5080
$script:firewallRemote=@("172.31.48.0/20","192.168.0.0/24","0.0.0.0/0")
$rejected=$false
try {{ Assert-ServerKitSshApplied -Address @("10.20.0.101","192.168.0.100") -Port 5080 }} catch {{ $rejected=$true }}
if (-not $rejected) {{ throw "过宽防火墙来源范围未被拒绝" }}
$script:firewallRemote=@("172.31.48.0/20","192.168.0.0/24")
$script:firewallProtocol=17
$rejected=$false
try {{ Assert-ServerKitSshApplied -Address @("10.20.0.101","192.168.0.100") -Port 5080 }} catch {{ $rejected=$true }}
if (-not $rejected) {{ throw "错误防火墙协议未被拒绝" }}
$script:firewallProtocol=6
$script:firewallDirection=2
$rejected=$false
try {{ Assert-ServerKitSshApplied -Address @("10.20.0.101","192.168.0.100") -Port 5080 }} catch {{ $rejected=$true }}
if (-not $rejected) {{ throw "错误防火墙方向未被拒绝" }}
Remove-Item -LiteralPath $networkRoot -Recurse -Force
'''
        environment = os.environ.copy()
        environment["SERVER_KIT_LIBRARY_ONLY"] = "1"
        completed = subprocess.run(
            [powershell, "-NoProfile", "-Command", command],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
