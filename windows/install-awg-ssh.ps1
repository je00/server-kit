#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Status', 'Uninstall')]
    [string]$Action = 'Install',

    [string]$PublicKey,

    [string]$AwgSubnet = '10.20.0.0/24'
)

$ErrorActionPreference = 'Stop'
$FirewallRule = 'server-kit-amneziawg-ssh'
$DefaultFirewallRule = 'OpenSSH-Server-In-TCP'
$SshDirectory = Join-Path $env:ProgramData 'ssh'
$ConfigPath = Join-Path $SshDirectory 'sshd_config'
$AdminKeysPath = Join-Path $SshDirectory 'administrators_authorized_keys'
$BeginMarker = '# BEGIN server-kit AWG SSH'
$EndMarker = '# END server-kit AWG SSH'

function Get-AwgAddress {
    $prefix = ($AwgSubnet -split '/')[0] -replace '\.0$', '.'
    $address = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress.StartsWith($prefix) -and $_.IPAddress -ne '10.20.0.1' } |
        Select-Object -First 1
    if (-not $address) {
        throw "没有检测到 $AwgSubnet 内的本机地址，请先启用系统级 AmneziaWG 接口。"
    }
    return $address.IPAddress
}

function Set-ManagedConfigBlock {
    param([string]$Text, [bool]$Enabled)

    $escapedBegin = [regex]::Escape($BeginMarker)
    $escapedEnd = [regex]::Escape($EndMarker)
    $withoutBlock = [regex]::Replace(
        $Text,
        "(?ms)^$escapedBegin\r?\n.*?^$escapedEnd\r?\n?",
        ''
    ).TrimEnd()
    if (-not $Enabled) {
        return "$withoutBlock`r`n"
    }
    $block = @"
$BeginMarker
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
$EndMarker
"@
    return "$withoutBlock`r`n`r`n$block`r`n"
}

function Show-Status {
    $service = Get-Service sshd -ErrorAction SilentlyContinue
    $rule = Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
    Write-Host "OpenSSH 服务：$(if ($service) { $service.Status } else { '未安装' })"
    Write-Host "AWG 防火墙规则：$(if ($rule -and $rule.Enabled -eq 'True') { '已启用' } else { '未启用' })"
    Write-Host "公钥文件：$AdminKeysPath"
    if ($rule) {
        Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule |
            Format-List LocalAddress, RemoteAddress
    }
}

function Install-AwgSsh {
    if ([string]::IsNullOrWhiteSpace($PublicKey)) {
        throw 'Install 必须通过 -PublicKey 传入一整行 SSH 公钥。'
    }
    if ($PublicKey -notmatch '^ssh-(ed25519|rsa|ecdsa-[^ ]+)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$') {
        throw 'SSH 公钥格式无效。'
    }
    $awgAddress = Get-AwgAddress

    $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($capability.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
    }
    New-Item -ItemType Directory -Path $SshDirectory -Force | Out-Null
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\OpenSSH\sshd_config_default') -Destination $ConfigPath
    }

    $backupPath = "$ConfigPath.server-kit.$(Get-Date -Format yyyyMMddHHmmss).bak"
    Copy-Item -LiteralPath $ConfigPath -Destination $backupPath
    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw
        Set-Content -LiteralPath $ConfigPath -Value (Set-ManagedConfigBlock -Text $config -Enabled $true) -Encoding ascii
        Set-Content -LiteralPath $AdminKeysPath -Value "$PublicKey`r`n" -Encoding ascii
        & icacls.exe $AdminKeysPath /inheritance:r /grant '*S-1-5-32-544:F' /grant 'SYSTEM:F' | Out-Null

        $sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
        & $sshd -t -f $ConfigPath
        if ($LASTEXITCODE -ne 0) {
            throw 'sshd 配置校验失败。'
        }

        Disable-NetFirewallRule -Name $DefaultFirewallRule -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
        New-NetFirewallRule -Name $FirewallRule `
            -DisplayName 'server-kit：仅允许 AmneziaWG 内网 SSH' `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 `
            -LocalAddress $awgAddress -RemoteAddress $AwgSubnet -Profile Any | Out-Null
        Set-Service -Name sshd -StartupType Automatic
        Restart-Service -Name sshd
    }
    catch {
        Copy-Item -LiteralPath $backupPath -Destination $ConfigPath -Force
        Restart-Service -Name sshd -ErrorAction SilentlyContinue
        throw
    }

    Write-Host "OpenSSH 已启用：$awgAddress`:22"
    Write-Host "仅允许来源：$AwgSubnet；密码和键盘交互登录已关闭。"
    Write-Host "配置备份：$backupPath"
}

function Uninstall-AwgSsh {
    Remove-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $ConfigPath) {
        $config = Get-Content -LiteralPath $ConfigPath -Raw
        Set-Content -LiteralPath $ConfigPath -Value (Set-ManagedConfigBlock -Text $config -Enabled $false) -Encoding ascii
        $sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
        & $sshd -t -f $ConfigPath
        if ($LASTEXITCODE -ne 0) {
            throw '删除受管配置后 sshd 校验失败，服务未重启。'
        }
        Restart-Service -Name sshd -ErrorAction SilentlyContinue
    }
    Write-Host '已删除 server-kit 的 AWG SSH 防火墙规则和密钥登录配置块。'
    Write-Host 'OpenSSH 功能、公钥文件和其他 SSH 配置均保留。'
}

switch ($Action) {
    'Install' { Install-AwgSsh }
    'Status' { Show-Status }
    'Uninstall' { Uninstall-AwgSsh }
}
