# server-kit Windows SSH 综合管理器
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("menu", "enable", "disable", "status", "keygen", "key-list", "key-add", "key-remove", "auth-status", "auth-harden", "auth-confirm", "auth-rollback", "network-list", "network-add", "network-remove")]
    [string]$Action = "menu",

    [Parameter(Position = 1)]
    [string]$Value = ""
)

$ErrorActionPreference = "Stop"
$InitialNetwork = "10.20.0.0/24"
$FirewallRule = "server-kit-SSHD-AWG"
$ManagedMarker = "# SERVER-KIT MANAGED SSH ACCESS"
$ManagedAccessBegin = "# BEGIN SERVER-KIT MANAGED SSH ACCESS"
$ManagedAccessEnd = "# END SERVER-KIT MANAGED SSH ACCESS"
$LegacyManagedMarker = "# 由 server-kit 管理：只监听 AWG 地址"
$LegacyManagedAccessBegin = "# server-kit 允许网段开始"
$LegacyManagedAccessEnd = "# server-kit 允许网段结束"
$ConfigPath = Join-Path $env:ProgramData "ssh\sshd_config"
$NetworksPath = if ($env:SERVER_KIT_SSH_NETWORKS_FILE) { $env:SERVER_KIT_SSH_NETWORKS_FILE } else { Join-Path $env:ProgramData "server-kit\ssh-allowed-networks.conf" }
$AuthStateDirectory = Join-Path $env:ProgramData "server-kit\ssh"
$AuthTransactionPath = Join-Path $AuthStateDirectory "auth-transaction.json"
$AuthBackupPath = Join-Path $AuthStateDirectory "sshd_config.backup"
$AuthManagedLauncher = Join-Path $env:ProgramData "server-kit\server-kit-ssh.cmd"
$AuthRollbackTask = "server-kit-node-ssh-auth-rollback"
$AuthRollbackSeconds = 300
$AuthMarker = "# SERVER-KIT MANAGED SSH PUBLIC KEY AUTH"
$LegacyAuthMarker = "# 由 server-kit 管理：SSH 端到端仅公钥认证"
$CallerProfile = if ($env:SERVER_KIT_CALLER_PROFILE) { $env:SERVER_KIT_CALLER_PROFILE } else { $env:USERPROFILE }
$CallerAccount = if ($env:SERVER_KIT_CALLER_ACCOUNT) { $env:SERVER_KIT_CALLER_ACCOUNT } else { "$env:USERDOMAIN\$env:USERNAME" }
$script:AuthorizedAccount = $null

function Test-ServerKitAdministrator {
    return (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-ServerKitAdministrator {
    if (-not (Test-ServerKitAdministrator)) {
        throw "请以管理员身份运行 server-kit-ssh.cmd。"
    }
}

function Get-ServerKitLegacyAccessPattern {
    # PowerShell 5.1 may already have persisted mojibake in the old comments.  The
    # generated directives remain ASCII, so use their exact shape for migration.
    return '(?ims)^[\t ]*#[^\r\n]*server-kit[^\r\n]*\r?\n' +
        '^[\t ]*#[^\r\n]*server-kit[^\r\n]*\r?\n' +
        '^[\t ]*Port[\t ]+\d+[\t ]*\r?\n' +
        '(?:^[\t ]*ListenAddress[\t ]+\S+[\t ]*\r?\n)+' +
        '^[\t ]*Match[\t ]+Address[\t ]+\*,![^\r\n]+\r?\n' +
        '^[\t ]+DenyUsers[\t ]+\*[\t ]*\r?\n' +
        '^[\t ]*Match[\t ]+all[\t ]*\r?\n' +
        '^[\t ]*#[^\r\n]*server-kit[^\r\n]*(?:\r?\n)?'
}

function Get-ServerKitManagedAccessBlock {
    param([Parameter(Mandatory = $true)][string]$Content)
    $boundaries = @(
        [pscustomobject]@{ Begin = $ManagedAccessBegin; End = $ManagedAccessEnd },
        [pscustomobject]@{ Begin = $LegacyManagedAccessBegin; End = $LegacyManagedAccessEnd }
    )
    foreach ($boundary in $boundaries) {
        $pattern = '(?ms)^' + [regex]::Escape($boundary.Begin) + '.*?^' +
            [regex]::Escape($boundary.End) + '[\t ]*(?:\r?\n)?'
        $match = [regex]::Match($Content, $pattern)
        if ($match.Success) { return $match.Value }
    }
    $match = [regex]::Match($Content, (Get-ServerKitLegacyAccessPattern))
    if ($match.Success) { return $match.Value }
    return ""
}

function Remove-ServerKitManagedAccessBlocks {
    param([Parameter(Mandatory = $true)][string]$Content)
    $boundaries = @(
        [pscustomobject]@{ Begin = $ManagedAccessBegin; End = $ManagedAccessEnd },
        [pscustomobject]@{ Begin = $LegacyManagedAccessBegin; End = $LegacyManagedAccessEnd }
    )
    foreach ($boundary in $boundaries) {
        $pattern = '(?ms)^' + [regex]::Escape($boundary.Begin) + '.*?^' +
            [regex]::Escape($boundary.End) + '[\t ]*\r?\n?'
        $Content = [regex]::Replace($Content, $pattern, '')
    }
    return [regex]::Replace($Content, (Get-ServerKitLegacyAccessPattern), '')
}

function ConvertTo-ServerKitSshdConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string[]]$Address,
        [Parameter(Mandatory = $true)][int]$Port
    )

    # 先移除当前、旧版及已乱码的完整管理块，避免其中的 Match 被误认为用户配置。
    $Content = Remove-ServerKitManagedAccessBlocks -Content $Content
    # OpenSSH 的 Match 会一直作用到文件末尾；全局指令必须放在第一个 Match 之前。
    $matchBlock = [regex]::Match($Content, '(?m)^[\t ]*Match[\t ]+')
    if ($matchBlock.Success) {
        $globalContent = $Content.Substring(0, $matchBlock.Index)
        $matchContent = $Content.Substring($matchBlock.Index)
    } else {
        $globalContent = $Content
        $matchContent = ""
    }

    $globalContent = [regex]::Replace($globalContent, '(?m)^[\t ]*Port[\t ]+\d+[\t ]*\r?\n?', '')
    $globalContent = [regex]::Replace($globalContent, '(?m)^[\t ]*ListenAddress[\t ]+\S+[\t ]*\r?\n?', '')
    foreach ($marker in @($ManagedMarker, $LegacyManagedMarker)) {
        $markerPattern = '(?m)^[\t ]*' + [regex]::Escape($marker) + '[\t ]*\r?\n?'
        $globalContent = [regex]::Replace($globalContent, $markerPattern, '')
    }

    $listenLines = ($Address | ForEach-Object { "ListenAddress $_" }) -join "`r`n"
    $denyPattern = "*," + ((Get-ServerKitAllowedNetworks | ForEach-Object { "!$_" }) -join ",")
    $managedBlock = "$ManagedAccessBegin`r`n$ManagedMarker`r`nPort $Port`r`n$listenLines`r`nMatch Address $denyPattern`r`n    DenyUsers *`r`nMatch all`r`n$ManagedAccessEnd`r`n"
    $prefix = $globalContent.TrimEnd()
    if ($prefix.Length) { $prefix += "`r`n`r`n" }
    if ($matchContent.Length) {
        return $prefix + $managedBlock + "`r`n" + $matchContent.TrimStart([char]13, [char]10)
    }
    return $prefix + $managedBlock
}

function ConvertTo-ServerKitAuthConfig {
    param([Parameter(Mandatory = $true)][string]$Content)
    $matchBlock = [regex]::Match($Content, '(?m)^[\t ]*Match[\t ]+')
    if ($matchBlock.Success) {
        $globalContent = $Content.Substring(0, $matchBlock.Index)
        $matchContent = $Content.Substring($matchBlock.Index)
    } else {
        $globalContent = $Content
        $matchContent = ""
    }
    foreach ($directive in @("PubkeyAuthentication", "PasswordAuthentication", "KbdInteractiveAuthentication", "AuthenticationMethods")) {
        $pattern = '(?m)^[\t ]*' + [regex]::Escape($directive) + '[\t ]+\S+(?:[\t ]+\S+)*[\t ]*\r?\n?'
        $globalContent = [regex]::Replace($globalContent, $pattern, '')
    }
    foreach ($marker in @($AuthMarker, $LegacyAuthMarker)) {
        $markerPattern = '(?m)^[\t ]*' + [regex]::Escape($marker) + '[\t ]*\r?\n?'
        $globalContent = [regex]::Replace($globalContent, $markerPattern, '')
    }
    $mojibakeMarkerPattern = '(?im)^[\t ]*#[^\r\n]*server-kit[^\r\n]*\r?\n(?=^[\t ]*PubkeyAuthentication[\t ]+yes)'
    $globalContent = [regex]::Replace($globalContent, $mojibakeMarkerPattern, '')
    $block = "$AuthMarker`r`nPubkeyAuthentication yes`r`nPasswordAuthentication no`r`nKbdInteractiveAuthentication no`r`nAuthenticationMethods publickey`r`n"
    $prefix = $globalContent.TrimEnd()
    if ($prefix.Length) { $prefix += "`r`n`r`n" }
    if ($matchContent.Length) { return $prefix + $block + "`r`n" + $matchContent.TrimStart([char]13, [char]10) }
    return $prefix + $block
}

function Get-ServerKitConfig {
    $result = [ordered]@{ Address = @(); Port = "未配置" }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $result }
    $content = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8)
    $block = Get-ServerKitManagedAccessBlock -Content $content
    if (-not $block) { return $result }
    $blockLines = $block -split '\r?\n'
    foreach ($line in $blockLines) {
        if ($line -match '^\s*Port\s+(\d+)\s*$') { $result.Port = $Matches[1] }
        if ($line -match '^\s*ListenAddress\s+(\S+)\s*$') { $result.Address += $Matches[1] }
        if ($line -match '^\s*Match\s+') { break }
    }
    return $result
}

function Test-ServerKitIpv4Cidr([string]$Cidr) {
    if ($Cidr -notmatch '^(.+)/(\d{1,2})$') { return $false }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Matches[1], [ref]$address)) { return $false }
    return $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and [int]$Matches[2] -le 32
}

function ConvertTo-ServerKitCanonicalIpv4Network([string]$Network) {
    if ([string]::IsNullOrWhiteSpace($Network)) { return $null }
    $value = $Network.Trim()
    if ($value -notmatch '^([^/]+)/([^/]+)$') { return $null }

    $address = $null
    if (-not [Net.IPAddress]::TryParse($Matches[1], [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        return $null
    }
    $suffix = $Matches[2]
    [byte[]]$maskBytes = @(0, 0, 0, 0)
    if ($suffix -match '^\d{1,2}$') {
        $prefixLength = [int]$suffix
        if ($prefixLength -gt 32) { return $null }
        $remaining = $prefixLength
        for ($index = 0; $index -lt 4; $index++) {
            $bits = [Math]::Min(8, [Math]::Max(0, $remaining))
            $maskBytes[$index] = if ($bits -eq 0) { 0 } else { (0xFF -shl (8 - $bits)) -band 0xFF }
            $remaining -= $bits
        }
    } else {
        $maskAddress = $null
        if (-not [Net.IPAddress]::TryParse($suffix, [ref]$maskAddress) -or
            $maskAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            return $null
        }
        $maskBytes = $maskAddress.GetAddressBytes()
        $prefixLength = 0
        $foundZero = $false
        foreach ($maskByte in $maskBytes) {
            for ($bit = 7; $bit -ge 0; $bit--) {
                $isOne = ($maskByte -band (1 -shl $bit)) -ne 0
                if ($isOne) {
                    if ($foundZero) { return $null }
                    $prefixLength++
                } else {
                    $foundZero = $true
                }
            }
        }
    }

    $addressBytes = $address.GetAddressBytes()
    $networkBytes = for ($index = 0; $index -lt 4; $index++) {
        [int]($addressBytes[$index] -band $maskBytes[$index])
    }
    return (($networkBytes -join '.') + "/$prefixLength")
}

function ConvertTo-ServerKitComparableNetworks([object[]]$Network) {
    return @($Network | ForEach-Object {
        $original = ([string]$_).Trim()
        $canonical = ConvertTo-ServerKitCanonicalIpv4Network $original
        if ($null -eq $canonical) { $original } else { $canonical }
    } | Sort-Object -Unique)
}

function Test-ServerKitAddressInCidr([string]$Address, [string]$Cidr) {
    if (-not (Test-ServerKitIpv4Cidr $Cidr)) { return $false }
    $networkText, $prefixText = $Cidr -split '/', 2
    $addressBytes = ([Net.IPAddress]::Parse($Address)).GetAddressBytes()
    $networkBytes = ([Net.IPAddress]::Parse($networkText)).GetAddressBytes()
    $remaining = [int]$prefixText
    for ($index = 0; $index -lt 4; $index++) {
        $bits = [Math]::Min(8, [Math]::Max(0, $remaining))
        $mask = if ($bits -eq 0) { 0 } else { (0xFF -shl (8 - $bits)) -band 0xFF }
        if (($addressBytes[$index] -band $mask) -ne ($networkBytes[$index] -band $mask)) { return $false }
        $remaining -= $bits
    }
    return $true
}

function Get-ServerKitAllowedNetworks {
    if (-not (Test-Path -LiteralPath $NetworksPath)) { return @($InitialNetwork) }
    $networks = @(Get-Content -LiteralPath $NetworksPath | Where-Object { Test-ServerKitIpv4Cidr $_ })
    if (-not $networks.Count) { return @($InitialNetwork) }
    return @($networks | Select-Object -Unique)
}

function Initialize-ServerKitNetworksFile {
    if (Test-Path -LiteralPath $NetworksPath) { return }
    New-Item -ItemType Directory -Path (Split-Path -Parent $NetworksPath) -Force | Out-Null
    [IO.File]::WriteAllLines($NetworksPath, [string[]]@($InitialNetwork), [Text.Encoding]::ASCII)
}

function Get-ServerKitManagedAddresses {
    $networks = @(Get-ServerKitAllowedNetworks)
    return @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $candidate = $_.IPAddress
            @($networks | Where-Object { Test-ServerKitAddressInCidr $candidate $_ }).Count -gt 0
        } | Select-Object -ExpandProperty IPAddress -Unique)
}

function Show-ServerKitNetworks {
    Write-Host "SSH 允许来源网段" -ForegroundColor Cyan
    foreach ($cidr in @(Get-ServerKitAllowedNetworks)) {
        if ($cidr -eq $InitialNetwork) { Write-Host "  $cidr · 初始值，可替换" } else { Write-Host "  $cidr" }
    }
}

function Assert-ServerKitSshApplied {
    param(
        [Parameter(Mandatory = $true)][string[]]$Address,
        [Parameter(Mandatory = $true)][int]$Port
    )
    $expectedNetworks = @(Get-ServerKitAllowedNetworks)
    $config = Get-ServerKitConfig
    if ([string]$config.Port -ne [string]$Port) {
        throw "sshd_config 端口校验失败：期望 $Port，实际 $($config.Port)。"
    }
    $missingConfigAddresses = @($Address | Where-Object { @($config.Address) -notcontains $_ })
    $extraConfigAddresses = @($config.Address | Where-Object { $Address -notcontains $_ })
    if ($missingConfigAddresses.Count -or $extraConfigAddresses.Count) {
        throw "sshd_config 监听地址校验失败。"
    }

    $rule = Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
    if (-not $rule -or [string]$rule.Enabled -ne "True") {
        throw "防火墙规则 $FirewallRule 未启用。"
    }
    if ([string]$rule.Direction -ne "Inbound" -or [string]$rule.Action -ne "Allow") {
        throw "防火墙规则方向或动作校验失败。"
    }
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    if ([string]$portFilter.Protocol -ne "TCP" -or [string]$portFilter.LocalPort -ne [string]$Port) {
        throw "防火墙协议或端口校验失败：期望 TCP/$Port。"
    }
    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $actualLocalAddresses = @($addressFilter.LocalAddress)
    $actualRemoteNetworks = @($addressFilter.RemoteAddress)
    $missingLocalAddresses = @($Address | Where-Object { $actualLocalAddresses -notcontains $_ })
    $extraLocalAddresses = @($actualLocalAddresses | Where-Object { $Address -notcontains $_ })
    if ($missingLocalAddresses.Count -or $extraLocalAddresses.Count) {
        throw "防火墙本机地址校验失败。"
    }
    $expectedComparableNetworks = @(ConvertTo-ServerKitComparableNetworks $expectedNetworks)
    $actualComparableNetworks = @(ConvertTo-ServerKitComparableNetworks $actualRemoteNetworks)
    $missingRemoteNetworks = @($expectedComparableNetworks | Where-Object { $actualComparableNetworks -notcontains $_ })
    $extraRemoteNetworks = @($actualComparableNetworks | Where-Object { $expectedComparableNetworks -notcontains $_ })
    if ($missingRemoteNetworks.Count -or $extraRemoteNetworks.Count) {
        throw "防火墙允许来源网段校验失败。脚本期望：$($expectedNetworks -join ', ')；Windows 返回：$($actualRemoteNetworks -join ', ')。"
    }

    $sshdProcessIds = @(Get-Process -Name sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $sshdProcessIds -contains $_.OwningProcess -and $_.LocalPort -eq $Port })
    foreach ($expectedAddress in $Address) {
        if (-not @($listeners | Where-Object { $_.LocalAddress -eq $expectedAddress }).Count) {
            throw "SSH 未在 $expectedAddress`:$Port 实际监听。"
        }
    }
}

function Update-ServerKitSshAfterNetworkChange {
    $service = Get-Service sshd -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Warning "SSH 尚未安装；允许网段已保存，将在首次开启 SSH 时应用。"
        return $false
    }
    if ($service.Status -ne "Running") {
        throw "SSH 服务未运行，允许网段尚未应用；请先启动 SSH 后重试。"
    }
    $config = Get-ServerKitConfig
    if ($config.Port -eq "未配置") {
        throw "无法识别 server-kit 管理的 SSH 配置，拒绝静默跳过重应用。"
    }
    $previous = $script:Value
    $script:Value = [string]$config.Port
    try { Enable-ServerKitSsh } finally { $script:Value = $previous }
    return $true
}

function Invoke-ServerKitNetworkFileChange {
    param([Parameter(Mandatory = $true)][scriptblock]$Change)
    $fileExisted = Test-Path -LiteralPath $NetworksPath
    $previousBytes = if ($fileExisted) { [IO.File]::ReadAllBytes($NetworksPath) } else { $null }
    try {
        & $Change
        $applied = Update-ServerKitSshAfterNetworkChange
        return $applied
    } catch {
        $applyError = $_.Exception.Message
        if ($fileExisted) {
            [IO.File]::WriteAllBytes($NetworksPath, $previousBytes)
        } else {
            Remove-Item -LiteralPath $NetworksPath -Force -ErrorAction SilentlyContinue
        }

        $rollbackError = ""
        $service = Get-Service sshd -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            try { [void](Update-ServerKitSshAfterNetworkChange) }
            catch { $rollbackError = $_.Exception.Message }
        }
        if ($rollbackError) {
            throw "应用 SSH 允许网段失败，网段文件已恢复，但运行配置自动回滚失败：$rollbackError；原错误：$applyError"
        }
        throw "应用 SSH 允许网段失败，已恢复原网段文件和运行配置：$applyError"
    }
}

function Add-ServerKitNetwork {
    Assert-ServerKitAdministrator
    $cidr = $Value.Trim()
    if (-not (Test-ServerKitIpv4Cidr $cidr)) { throw "请输入有效的 IPv4 CIDR，例如 192.168.1.0/24。" }
    if (@(Get-ServerKitAllowedNetworks) -contains $cidr) {
        Write-Host "允许网段已存在，正在重新应用 SSH 与防火墙配置：$cidr"
        $applied = Update-ServerKitSshAfterNetworkChange
        if ($applied) {
            Write-Host "已重新应用允许网段：$cidr" -ForegroundColor Green
        } else {
            Write-Host "允许网段已保存，尚未应用：$cidr" -ForegroundColor Yellow
        }
        return
    }
    $applied = Invoke-ServerKitNetworkFileChange -Change {
        Initialize-ServerKitNetworksFile
        Add-Content -LiteralPath $NetworksPath -Value $cidr -Encoding ascii
    }
    if ($applied) {
        Write-Host "已加入并应用允许网段：$cidr" -ForegroundColor Green
    } else {
        Write-Host "已保存允许网段，尚未应用：$cidr" -ForegroundColor Yellow
    }
}

function Remove-ServerKitNetwork {
    Assert-ServerKitAdministrator
    $cidr = $Value.Trim()
    if (-not (Test-ServerKitIpv4Cidr $cidr)) { throw "请输入有效的 IPv4 CIDR。" }
    $networks = @(Get-ServerKitAllowedNetworks)
    if ($networks -notcontains $cidr) { throw "允许网段不存在：$cidr" }
    if ($networks.Count -le 1) { throw "至少保留一个允许网段，请先添加新网段。" }
    $remaining = @($networks | Where-Object { $_ -ne $cidr })
    $applied = Invoke-ServerKitNetworkFileChange -Change {
        Initialize-ServerKitNetworksFile
        [IO.File]::WriteAllLines($NetworksPath, [string[]]$remaining, [Text.Encoding]::ASCII)
    }
    if ($applied) {
        Write-Host "已删除并应用允许网段：$cidr" -ForegroundColor Green
    } else {
        Write-Host "已保存允许网段变更，尚未应用：$cidr" -ForegroundColor Yellow
    }
}

function Show-ServerKitStatus {
    $service = Get-Service sshd -ErrorAction SilentlyContinue
    $serviceState = if ($service) { $service.Status } else { "未安装" }
    $startup = if ($service) { (Get-CimInstance Win32_Service -Filter "Name='sshd'").StartMode } else { "—" }
    $config = Get-ServerKitConfig
    $sshdProcessIds = @(Get-Process -Name sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $sshdProcessIds -contains $_.OwningProcess } |
        ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" } | Select-Object -Unique)
    $firewall = Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
    Write-Host "server-kit SSH 当前状态" -ForegroundColor Cyan
    Write-Host "  服务：$serviceState"
    Write-Host "  自启：$startup"
    Write-Host "  监听地址：$(if (@($config.Address).Count) { @($config.Address) -join ', ' } else { '未配置' })"
    Write-Host "  端口：$($config.Port)"
    Write-Host "  监听：$(if ($listeners.Count) { $listeners -join ', ' } else { '未监听' })"
    Write-Host "  防火墙：$(if ($firewall -and $firewall.Enabled -eq 'True') { '已应用允许网段' } else { '未开放' })"
    Show-ServerKitNetworks
    Show-ServerKitAuthStatus
}

function Get-ServerKitSshdPath {
    $path = Join-Path $env:WINDIR "System32\OpenSSH\sshd.exe"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    return $path
}

function Get-EffectiveAuthValue([string]$Name) {
    $sshd = Get-ServerKitSshdPath
    if (-not $sshd -or -not (Test-Path -LiteralPath $ConfigPath)) { return "" }
    $account = Get-SelectedAuthorizedAccount
    $user = ($account.Name -split '\\')[-1]
    $output = & $sshd -T -f $ConfigPath -C "user=$user,host=localhost,addr=127.0.0.1" 2>$null
    if ($LASTEXITCODE -ne 0) { return "" }
    $line = @($output | Where-Object { $_ -match "^$([regex]::Escape($Name))\s+" } | Select-Object -First 1)
    if (-not $line.Count) { return "" }
    return (($line[0] -split '\s+', 2)[1]).Trim()
}

function Test-ServerKitAuthHardened {
    return (
        (Get-EffectiveAuthValue "pubkeyauthentication") -eq "yes" -and
        (Get-EffectiveAuthValue "passwordauthentication") -eq "no" -and
        (Get-EffectiveAuthValue "kbdinteractiveauthentication") -eq "no" -and
        (Get-EffectiveAuthValue "authenticationmethods") -eq "publickey"
    )
}

function Show-ServerKitAuthStatus {
    $keys = 0
    try { $keys = @(Get-AuthorizedKeyEntries).Count } catch { $keys = 0 }
    $password = Get-EffectiveAuthValue "passwordauthentication"
    $methods = Get-EffectiveAuthValue "authenticationmethods"
    $state = if (Test-ServerKitAuthHardened) { "仅公钥" } elseif (Get-ServerKitSshdPath) { "允许其他认证" } else { "未启用" }
    if (Test-Path -LiteralPath $AuthTransactionPath) { $state += "（等待确认）" }
    Write-Host "  公钥：$keys 把有效公钥（账户 $((Get-SelectedAuthorizedAccount).Name)）"
    Write-Host "  认证：$state · PasswordAuthentication $(if ($password) { $password } else { '未知' }) · AuthenticationMethods $(if ($methods) { $methods } else { '未知' })"
}

function Stop-ServerKitAuthRollback {
    Unregister-ScheduledTask -TaskName $AuthRollbackTask -Confirm:$false -ErrorAction SilentlyContinue
}

function Start-ServerKitAuthRollback {
    if (-not $env:SERVER_KIT_SELF -or -not (Test-Path -LiteralPath $env:SERVER_KIT_SELF)) {
        throw "无法定位当前综合管理脚本，不能建立自动回滚。"
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $AuthManagedLauncher) -Force | Out-Null
    Copy-Item -LiteralPath $env:SERVER_KIT_SELF -Destination $AuthManagedLauncher -Force
    Stop-ServerKitAuthRollback
    $execute = Join-Path $env:SystemRoot "System32\cmd.exe"
    $arguments = "/d /c `"`"$AuthManagedLauncher`" auth-rollback automatic`""
    $taskAction = New-ScheduledTaskAction -Execute $execute -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($AuthRollbackSeconds)
    Register-ScheduledTask -TaskName $AuthRollbackTask -Action $taskAction -Trigger $trigger `
        -User "SYSTEM" -RunLevel Highest -Force | Out-Null
}

function Restore-ServerKitAuthConfig {
    if (-not (Test-Path -LiteralPath $AuthBackupPath)) { throw "认证回滚备份缺失。" }
    Copy-Item -LiteralPath $AuthBackupPath -Destination $ConfigPath -Force
    $sshd = Get-ServerKitSshdPath
    & $sshd -t -f $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw "恢复后的 OpenSSH 配置校验失败。" }
    Restart-Service sshd -Force
}

function Undo-ServerKitAuth {
    Assert-ServerKitAdministrator
    if (-not (Test-Path -LiteralPath $AuthTransactionPath)) {
        if ($Value -ne "automatic") { Write-Host "当前没有待回滚的认证变更。" }
        return
    }
    Restore-ServerKitAuthConfig
    Remove-Item -LiteralPath $AuthTransactionPath, $AuthBackupPath -Force -ErrorAction SilentlyContinue
    Stop-ServerKitAuthRollback
    if ($Value -eq "automatic") {
        Write-Host "仅公钥认证未在 5 分钟内确认，已自动恢复。" -ForegroundColor Yellow
    } else {
        Write-Host "SSH 认证配置已回滚。" -ForegroundColor Green
    }
}

function Enable-ServerKitAuthHardened {
    Assert-ServerKitAdministrator
    if (-not (Get-ServerKitSshdPath) -or -not (Test-Path -LiteralPath $ConfigPath)) { throw "请先开启 SSH 服务。" }
    if ((Get-Service sshd -ErrorAction SilentlyContinue).Status -ne "Running") { throw "SSH 服务未运行。" }
    if (Test-Path -LiteralPath $AuthTransactionPath) { throw "已有等待确认的认证变更。" }
    if (@(Get-AuthorizedKeyEntries).Count -lt 1) {
        throw "当前所选账户没有可用公钥，拒绝关闭密码认证。"
    }
    New-Item -ItemType Directory -Path $AuthStateDirectory -Force | Out-Null
    Copy-Item -LiteralPath $ConfigPath -Destination $AuthBackupPath -Force
    @{ created_at = (Get-Date).ToUniversalTime().ToString("o"); account = (Get-SelectedAuthorizedAccount).Name } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $AuthTransactionPath -Encoding UTF8
    $sshd = Get-ServerKitSshdPath
    try {
        $content = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8)
        $content = ConvertTo-ServerKitAuthConfig -Content $content
        [IO.File]::WriteAllText($ConfigPath, $content, (New-Object Text.UTF8Encoding($false)))
        & $sshd -t -f $ConfigPath
        if ($LASTEXITCODE -ne 0) { throw "OpenSSH 配置校验失败。" }
        Start-ServerKitAuthRollback
        Restart-Service sshd -Force
        if (-not (Test-ServerKitAuthHardened)) { throw "实际认证参数不符合预期。" }
    } catch {
        Restore-ServerKitAuthConfig
        Remove-Item -LiteralPath $AuthTransactionPath, $AuthBackupPath -Force -ErrorAction SilentlyContinue
        Stop-ServerKitAuthRollback
        throw "仅公钥认证未正确生效，已恢复原配置：$($_.Exception.Message)"
    }
    Write-Host "仅公钥认证已临时生效。请保留当前窗口，另开窗口用公钥登录测试。" -ForegroundColor Yellow
    Write-Host "成功后在 5 分钟内再次运行脚本，选择‘确认仅公钥认证’。"
}

function Confirm-ServerKitAuthHardened {
    Assert-ServerKitAdministrator
    if (-not (Test-Path -LiteralPath $AuthTransactionPath)) { throw "没有等待确认的认证变更。" }
    if (-not (Test-ServerKitAuthHardened)) {
        Undo-ServerKitAuth
        throw "实际认证参数不符合预期，已回滚。"
    }
    Remove-Item -LiteralPath $AuthTransactionPath, $AuthBackupPath -Force -ErrorAction SilentlyContinue
    Stop-ServerKitAuthRollback
    Write-Host "已确认：SSH 只接受公钥认证。" -ForegroundColor Green
}

function Enable-ServerKitSsh {
    Assert-ServerKitAdministrator
    $portNumber = 0
    if (-not [int]::TryParse($Value, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) {
        throw "SSH 端口必须是 1–65535 的整数。"
    }
    Write-Host "[1/5] 检查允许网段对应的本机地址..."
    $managedAddresses = @(Get-ServerKitManagedAddresses)
    if (-not $managedAddresses.Count) { throw "没有找到允许网段对应的本机 IPv4 地址。" }

    Write-Host "[2/5] 安装系统自带 OpenSSH Server..."
    $capability = Get-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"
    if ($capability.State -ne "Installed") { Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0" | Out-Null }
    Disable-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $ConfigPath)) { Start-Service sshd; Stop-Service sshd }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "找不到 OpenSSH 配置文件：$ConfigPath" }

    Write-Host "[3/5] 绑定允许地址并设置端口 $portNumber..."
    $backupPath = "$ConfigPath.server-kit.bak.$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -LiteralPath $ConfigPath -Destination $backupPath -Force
    $content = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8)
    $content = ConvertTo-ServerKitSshdConfig -Content $content -Address $managedAddresses -Port $portNumber
    [IO.File]::WriteAllText($ConfigPath, $content, (New-Object Text.UTF8Encoding($false)))
    $sshd = Join-Path $env:WINDIR "System32\OpenSSH\sshd.exe"
    try {
        & $sshd -t -f $ConfigPath
        if ($LASTEXITCODE -ne 0) { throw "OpenSSH 配置校验失败。" }
    } catch {
        Copy-Item -LiteralPath $backupPath -Destination $ConfigPath -Force
        throw
    }

    Write-Host "[4/5] 启动 SSH 并设置开机自启..."
    Set-Service -Name sshd -StartupType Automatic
    try {
        if ((Get-Service sshd).Status -eq "Running") { Restart-Service sshd -Force } else { Start-Service sshd }
    } catch {
        Copy-Item -LiteralPath $backupPath -Destination $ConfigPath -Force
        Start-Service sshd -ErrorAction SilentlyContinue
        throw "新配置启动失败，已经恢复旧配置：$($_.Exception.Message)"
    }

    Write-Host "[5/5] 应用 SSH 允许来源网段..."
    Remove-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $FirewallRule -DisplayName "server-kit SSH（允许网段）" `
        -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $managedAddresses `
        -LocalPort $portNumber -RemoteAddress (Get-ServerKitAllowedNetworks) | Out-Null
    Disable-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    Assert-ServerKitSshApplied -Address $managedAddresses -Port $portNumber
    Write-Host "完成：SSH 正在 $($managedAddresses -join ', ') 的 $portNumber 端口监听，防火墙规则已校验。" -ForegroundColor Green
    Show-ServerKitStatus
}

function Disable-ServerKitSsh {
    Assert-ServerKitAdministrator
    Write-Host "[1/2] 删除 SSH 允许网段防火墙规则..."
    Remove-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
    Disable-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    Write-Host "[2/2] 停止 SSH 并禁止开机自启..."
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        Stop-Service sshd -Force -ErrorAction SilentlyContinue
        Set-Service -Name sshd -StartupType Disabled
    }
    Write-Host "完成：SSH 服务和对应防火墙入口都已关闭。" -ForegroundColor Green
    Show-ServerKitStatus
}

function Get-SshKeygenPath {
    $tool = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
    if ($tool) { return $tool.Source }
    Assert-ServerKitAdministrator
    Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0" | Out-Null
    return (Get-Command ssh-keygen.exe -ErrorAction Stop).Source
}

function Get-ManageableAuthorizedAccounts {
    Assert-ServerKitAdministrator
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $administratorSids = @()
    try {
        $administratorSids = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop |
            ForEach-Object { $_.SID.Value })
    } catch {
        # 某些 Windows 版本无法加载 LocalAccounts 模块，当前登录账户仍可通过令牌判断。
    }

    $accounts = @()
    foreach ($profile in @(Get-CimInstance Win32_UserProfile -ErrorAction Stop |
        Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) })) {
        try {
            $sid = New-Object Security.Principal.SecurityIdentifier($profile.SID)
            $accountName = $sid.Translate([Security.Principal.NTAccount]).Value
        } catch { continue }
        if ($accountName -like "NT AUTHORITY\*") { continue }
        $isAdministrator = $administratorSids -contains $sid.Value
        if ($sid.Value -eq $currentIdentity.User.Value) { $isAdministrator = Test-ServerKitAdministrator }
        $accounts += [pscustomobject]@{
            Name = $accountName
            Sid = $sid.Value
            Profile = $profile.LocalPath
            IsAdministrator = $isAdministrator
            TypeLabel = if ($isAdministrator) { "管理员（共享公钥文件）" } else { "标准用户（独立公钥文件）" }
        }
    }

    if ($CallerProfile -and (Test-Path -LiteralPath $CallerProfile) -and
        -not @($accounts | Where-Object { $_.Profile -eq $CallerProfile }).Count) {
        try {
            $callerSid = (New-Object Security.Principal.NTAccount($CallerAccount)).Translate(
                [Security.Principal.SecurityIdentifier]
            )
            $callerIsAdministrator = $administratorSids -contains $callerSid.Value
            $accounts += [pscustomobject]@{
                Name = $CallerAccount
                Sid = $callerSid.Value
                Profile = $CallerProfile
                IsAdministrator = $callerIsAdministrator
                TypeLabel = if ($callerIsAdministrator) { "管理员（共享公钥文件）" } else { "标准用户（独立公钥文件）" }
            }
        } catch { }
    }

    return @($accounts | Sort-Object @{ Expression = { if ($_.Profile -eq $CallerProfile) { 0 } else { 1 } } }, Name -Unique)
}

function Get-SelectedAuthorizedAccount {
    if (-not $script:AuthorizedAccount) {
        $accounts = @(Get-ManageableAuthorizedAccounts)
        if (-not $accounts.Count) { throw "没有找到可管理的 Windows 用户。请先让目标用户登录 Windows 一次。" }
        $script:AuthorizedAccount = @($accounts | Where-Object { $_.Profile -eq $CallerProfile })[0]
        if (-not $script:AuthorizedAccount) { $script:AuthorizedAccount = $accounts[0] }
    }
    return $script:AuthorizedAccount
}

function Select-AuthorizedAccount {
    $accounts = @(Get-ManageableAuthorizedAccounts)
    if (-not $accounts.Count) { throw "没有找到可管理的 Windows 用户。请先让目标用户登录 Windows 一次。" }
    Write-Host "请选择要管理公钥的 Windows 账户" -ForegroundColor Cyan
    for ($index = 0; $index -lt $accounts.Count; $index++) {
        $current = if ($script:AuthorizedAccount -and $script:AuthorizedAccount.Sid -eq $accounts[$index].Sid) { " · 当前" } else { "" }
        Write-Host ("  [{0}] {1} · {2}{3}" -f ($index + 1), $accounts[$index].Name, $accounts[$index].TypeLabel, $current)
    }
    $selected = 0
    $rawIndex = Read-Host "输入账户序号"
    if (-not [int]::TryParse($rawIndex, [ref]$selected) -or $selected -lt 1 -or $selected -gt $accounts.Count) {
        throw "账户序号无效。"
    }
    $script:AuthorizedAccount = $accounts[$selected - 1]
    Write-Host "已选择：$($script:AuthorizedAccount.Name) · $($script:AuthorizedAccount.TypeLabel)" -ForegroundColor Green
}

function Get-AuthorizedKeysPath {
    $account = Get-SelectedAuthorizedAccount
    if ($account.IsAdministrator) { return Join-Path $env:ProgramData "ssh\administrators_authorized_keys" }
    return Join-Path $account.Profile ".ssh\authorized_keys"
}

function Initialize-AuthorizedKeysFile {
    $account = Get-SelectedAuthorizedAccount
    $path = Get-AuthorizedKeysPath
    $directory = Split-Path -Parent $path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType File -Path $path -Force | Out-Null }
    if ($account.IsAdministrator) {
        & icacls.exe $path /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
    } else {
        & icacls.exe $directory /inheritance:r /grant:r "*$($account.Sid):F" "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
        & icacls.exe $path /inheritance:r /grant:r "*$($account.Sid):F" "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
    }
    return $path
}

function Get-AuthorizedKeyEntries {
    $path = Initialize-AuthorizedKeysFile
    $tool = Get-SshKeygenPath
    $entries = @()
    $lineNumber = 0
    foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $lineNumber++
        if ($line -notmatch '^\s*(ssh-\S+|ecdsa-\S+|sk-\S+)\s+(\S+)(?:\s+(.*))?\s*$') { continue }
        $keyType = $Matches[1]
        $keyBlob = $Matches[2]
        $keyName = if ($Matches[3]) { $Matches[3] } else { "未命名" }
        $temp = New-TemporaryFile
        try {
            [IO.File]::WriteAllText($temp.FullName, $line.Trim(), [Text.Encoding]::ASCII)
            $details = & $tool -lf $temp.FullName 2>$null
            if (-not $details -or $LASTEXITCODE -ne 0) { continue }
            $fingerprint = ($details -split '\s+')[1]
        } finally { Remove-Item -LiteralPath $temp.FullName -Force -ErrorAction SilentlyContinue }
        $entries += [pscustomobject]@{
            Index = $entries.Count + 1; LineNumber = $lineNumber; Type = $keyType
            Blob = $keyBlob; Name = $keyName
            Fingerprint = $fingerprint; Line = $line.Trim()
        }
    }
    return @($entries)
}

function Show-AuthorizedKeys {
    $account = Get-SelectedAuthorizedAccount
    $path = Initialize-AuthorizedKeysFile
    $entries = @(Get-AuthorizedKeyEntries)
    Write-Host "允许登录 $($account.Name) 的公钥" -ForegroundColor Cyan
    Write-Host "账户：$($account.TypeLabel)"
    Write-Host "文件：$path"
    if (-not $entries.Count) { Write-Host "  暂无公钥。"; return }
    foreach ($entry in $entries) {
        Write-Host ("  [{0}] {1} · {2} · {3}" -f $entry.Index, $entry.Type, $entry.Fingerprint, $entry.Name)
    }
}

function New-LocalSshKey {
    $name = if ([string]::IsNullOrWhiteSpace($Value)) { "id_ed25519" } else { $Value.Trim() }
    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { throw "密钥名称只能包含字母、数字、点、下划线和短横线。" }
    $profile = if ($CallerProfile -and (Test-Path -LiteralPath $CallerProfile)) { $CallerProfile } else { $env:USERPROFILE }
    $directory = Join-Path $profile ".ssh"
    $path = Join-Path $directory $name
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    if (Test-Path -LiteralPath $path -PathType Leaf) { throw "密钥已存在：$path。为防止覆盖，请换一个名称。" }
    $tool = Get-SshKeygenPath
    Write-Host "接下来可以设置密钥口令；直接回车表示不设置。" -ForegroundColor Yellow
    & $tool -t ed25519 -a 64 -f $path -C "$env:COMPUTERNAME-$CallerAccount"
    if ($LASTEXITCODE -ne 0) { throw "密钥生成失败。" }
    Write-Host "私钥：$path（不要发送给任何人）" -ForegroundColor Yellow
    Write-Host "公钥：$path.pub" -ForegroundColor Green
    Get-Content -LiteralPath "$path.pub"
}

function Add-AuthorizedKey {
    $path = Initialize-AuthorizedKeysFile
    $tool = Get-SshKeygenPath
    Write-Host "请粘贴一整行公钥，然后按回车：" -ForegroundColor Cyan
    $line = (Read-Host).Trim()
    if ($line -notmatch '^(ssh-\S+|ecdsa-\S+|sk-\S+)\s+(\S+)(?:\s+(.*))?$') { throw "公钥格式不正确。" }
    $type = $Matches[1]; $blob = $Matches[2]; $originalName = $Matches[3]
    if (@(Get-AuthorizedKeyEntries | Where-Object { $_.Blob -eq $blob }).Count) { throw "这把公钥已经存在，无需重复添加。" }
    $temp = New-TemporaryFile
    try {
        [IO.File]::WriteAllText($temp.FullName, "$type $blob", [Text.Encoding]::ASCII)
        & $tool -lf $temp.FullName *> $null
        if ($LASTEXITCODE -ne 0) { throw "公钥校验失败。" }
    } finally { Remove-Item -LiteralPath $temp.FullName -Force -ErrorAction SilentlyContinue }
    $name = (Read-Host "给这台客户端起个名字（直接回车保留原名称）").Trim()
    if (-not $name) { $name = $originalName }
    $stored = if ($name) { "$type $blob $name" } else { "$type $blob" }
    Add-Content -LiteralPath $path -Value $stored -Encoding ascii
    Initialize-AuthorizedKeysFile | Out-Null
    Write-Host "公钥已添加。" -ForegroundColor Green
    Show-AuthorizedKeys
}

function Remove-AuthorizedKey {
    $path = Initialize-AuthorizedKeysFile
    $entries = @(Get-AuthorizedKeyEntries)
    if (-not $entries.Count) { Write-Host "暂无可删除的公钥。"; return }
    Show-AuthorizedKeys
    $selected = 0
    $rawIndex = if ($Value) { $Value } else { Read-Host "输入要删除的序号" }
    if (-not [int]::TryParse($rawIndex, [ref]$selected) -or $selected -lt 1 -or $selected -gt $entries.Count) { throw "公钥序号无效。" }
    $target = $entries[$selected - 1]
    $answer = Read-Host "确认删除 [$selected] $($target.Name)？输入 yes"
    if ($answer -ne "yes") { Write-Host "已取消。"; return }
    $lines = @(Get-Content -LiteralPath $path)
    $kept = @(
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($index + 1 -ne $target.LineNumber) { $lines[$index] }
        }
    )
    [IO.File]::WriteAllLines($path, [string[]]$kept, [Text.Encoding]::ASCII)
    Initialize-AuthorizedKeysFile | Out-Null
    Write-Host "公钥已删除。" -ForegroundColor Green
    Show-AuthorizedKeys
}

function Invoke-ServerKitAction([string]$SelectedAction, [string]$SelectedValue) {
    $script:Value = $SelectedValue
    switch ($SelectedAction) {
        "enable" { Enable-ServerKitSsh }
        "disable" { Disable-ServerKitSsh }
        "status" { Show-ServerKitStatus }
        "keygen" { New-LocalSshKey }
        "key-list" { Show-AuthorizedKeys }
        "key-add" { Add-AuthorizedKey }
        "key-remove" { Remove-AuthorizedKey }
        "auth-status" { Show-ServerKitAuthStatus }
        "auth-harden" { Enable-ServerKitAuthHardened }
        "auth-confirm" { Confirm-ServerKitAuthHardened }
        "auth-rollback" { Undo-ServerKitAuth }
        "network-list" { Show-ServerKitNetworks }
        "network-add" { Add-ServerKitNetwork }
        "network-remove" { Remove-ServerKitNetwork }
        default { throw "不支持的操作：$SelectedAction" }
    }
}

function Write-ServerKitMenu {
    $account = Get-SelectedAuthorizedAccount
    Write-Host "server-kit · Windows SSH 管理" -ForegroundColor Cyan
    Write-Host "公钥账户：$($account.Name) · $($account.TypeLabel)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  1. 查看 SSH 状态"
    Write-Host "  2. 开启或修改 SSH 端口"
    Write-Host "  3. 关闭 SSH"
    Write-Host "  4. 生成本机 Ed25519 密钥"
    Write-Host "  5. 选择公钥所属账户"
    Write-Host "  6. 查看允许登录的公钥"
    Write-Host "  7. 添加允许登录的公钥"
    Write-Host "  8. 删除允许登录的公钥"
    Write-Host "  9. 安全启用仅公钥认证"
    Write-Host " 10. 确认仅公钥认证"
    Write-Host " 11. 回滚认证配置"
    Write-Host " 12. 查看 SSH 允许网段"
    Write-Host " 13. 添加 SSH 允许网段"
    Write-Host " 14. 删除 SSH 允许网段"
    Write-Host "  m / ?  重新显示菜单"
    Write-Host "  0. 退出"
    Write-Host ""
}

function Show-ServerKitMenu {
    Clear-Host
    Write-ServerKitMenu
    while ($true) {
        $account = Get-SelectedAuthorizedAccount
        $accountLabel = ($account.Name -split '\\')[-1]
        Write-Host "下一步：1–14 操作 · m/? 菜单 · 0 退出 · 公钥账户 $accountLabel" -ForegroundColor DarkGray
        $choice = Read-Host ">"
        try {
            switch ($choice) {
                "1" { Invoke-ServerKitAction "status" "" }
                "2" { Invoke-ServerKitAction "enable" (Read-Host "请输入 SSH 端口，例如 22") }
                "3" {
                    if ((Read-Host "关闭后现有 SSH 会话会断开，输入 yes 继续") -eq "yes") { Invoke-ServerKitAction "disable" "" }
                }
                "4" { Invoke-ServerKitAction "keygen" (Read-Host "密钥名称（直接回车使用默认名称）") }
                "5" { Select-AuthorizedAccount }
                "6" { Invoke-ServerKitAction "key-list" "" }
                "7" { Invoke-ServerKitAction "key-add" "" }
                "8" { Invoke-ServerKitAction "key-remove" "" }
                "9" {
                    if ((Read-Host "将关闭密码认证；确认已添加公钥？输入 yes") -eq "yes") { Invoke-ServerKitAction "auth-harden" "" }
                }
                "10" { Invoke-ServerKitAction "auth-confirm" "" }
                "11" { Invoke-ServerKitAction "auth-rollback" "" }
                "12" { Invoke-ServerKitAction "network-list" "" }
                "13" { Invoke-ServerKitAction "network-add" (Read-Host "输入 IPv4 CIDR，例如 192.168.1.0/24") }
                "14" { Invoke-ServerKitAction "network-remove" (Read-Host "输入要删除的 IPv4 CIDR") }
                { $_ -in @("m", "M", "?") } { Write-Host ""; Write-ServerKitMenu }
                "0" { return }
                default { Write-Host "无效选项。请输入 1–14、m、? 或 0。" -ForegroundColor Yellow }
            }
        } catch { Write-Host "操作失败：$($_.Exception.Message)" -ForegroundColor Red }
        Write-Host ""
    }
}

if ($env:SERVER_KIT_LIBRARY_ONLY -ne "1") {
    if ($Action -eq "menu") { Show-ServerKitMenu } else { Invoke-ServerKitAction $Action $Value }
}
