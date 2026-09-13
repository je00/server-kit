param([string]$SourcePath = (Join-Path $PSScriptRoot '..\web\dashboard\script_templates\server-kit-ssh-windows.ps1'))
$ErrorActionPreference = 'Stop'
$env:SERVER_KIT_LIBRARY_ONLY = '1'
. ([scriptblock]::Create([IO.File]::ReadAllText((Resolve-Path $SourcePath), [Text.Encoding]::UTF8)))
$testRoot = Join-Path $env:TEMP ('server-kit-recovery-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $testRoot | Out-Null
$ConfigPath = Join-Path $testRoot 'sshd_config'
$AuthTransactionPath = Join-Path $testRoot 'transaction.json'
$script:ips = @('192.0.2.10', '192.0.2.11')
$script:live = @('192.0.2.10', '192.0.2.11')
$script:remote = '192.0.2.0/255.255.255.0'
$script:local = '192.0.2.10-192.0.2.10,192.0.2.11/255.255.255.255'
$script:startType = 'Automatic'
function Assert-ServerKitAdministrator { }
function Get-Service { [pscustomobject]@{Status='Running';StartType=$script:startType} }
function Get-ServerKitAllowedNetworks { '192.0.2.0/24' }
function Get-ServerKitManagedAddresses { $script:ips }
function Get-ServerKitFirewallRule {
    [pscustomobject]@{Enabled=$true;Direction=1;Action=1;Protocol=6;Profiles=2147483647;
        LocalPorts='22';LocalAddresses=$script:local;RemoteAddresses=$script:remote}
}
function Get-ServerKitListeners { foreach ($ip in $script:live) { [pscustomobject]@{LocalAddress=$ip;LocalPort=22} } }
function Get-ServerKitSshdPath { 'installed-sshd' }
function Get-WindowsCapability { throw 'No-op queried DISM' }
function Add-WindowsCapability { throw 'No-op installed a component' }
function Restart-Service { throw 'No-op restarted SSH' }
$script:recoveryInstalled=0
$originalEnable = (Get-Command Enable-ServerKitSsh).ScriptBlock
function Install-ServerKitRecovery { $script:recoveryInstalled++ }
try {
    $content=ConvertTo-ServerKitSshdConfig "PasswordAuthentication no`r`n" $script:ips 22
    [IO.File]::WriteAllText($ConfigPath,$content,[Text.Encoding]::UTF8)
    if (-not (Test-ServerKitNetworkApplied $script:ips 22)) { throw 'Single-IP range normalization failed' }
    $script:Value='22'; Enable-ServerKitSsh
    if ($script:recoveryInstalled -ne 1) { throw 'Recovery not installed during explicit enable' }
    $script:remote='0.0.0.0/0'
    if (Test-ServerKitNetworkApplied $script:ips 22) { throw 'World-access rule accepted' }
    $script:remote='192.0.2.0/24';$script:local='192.0.2.10/24,192.0.2.11/32'
    if (Test-ServerKitNetworkApplied $script:ips 22) { throw 'Broad local subnet accepted' }
    $script:local='192.0.2.10,192.0.2.11'
    $script:live=@('192.0.2.10')
    if (Test-ServerKitNetworkApplied $script:ips 22) { throw 'Partial listener accepted' }
    $script:repairs=0
    function Enable-ServerKitSsh { param([switch]$Recovery); if (-not $Recovery) { throw 'Not a recovery call' };$script:repairs++ }
    Repair-ServerKitNetwork
    if ($script:repairs -ne 1) { throw 'Partial listener was not repaired' }
    $script:live=$script:ips; Repair-ServerKitNetwork
    if ($script:repairs -ne 1) { throw 'Healthy listener restarted' }
    $script:ips=@(); Repair-ServerKitNetwork
    if ($script:repairs -ne 1) { throw 'Disconnected network changed SSH' }
    $script:ips=@('192.0.2.12');$script:startType='Disabled'; Repair-ServerKitNetwork
    if ($script:repairs -ne 1) { throw 'Disabled service re-enabled' }
    $script:startType='Automatic';[IO.File]::WriteAllText($AuthTransactionPath,'{}');Repair-ServerKitNetwork
    if ($script:repairs -ne 1) { throw 'Pending authentication transaction interrupted' }
    # Fail the first start after a valid candidate has been written. Neither
    # the real Windows service nor the real firewall may be changed by this test.
    $script:ips=@('192.0.2.10','192.0.2.11');$script:live=$script:ips
    $script:Value='2222';$script:starts=0
    function Set-Service { }
    function Get-NetFirewallRule { return $null }
    function Restart-Service { $script:starts++; if($script:starts -eq 1){throw 'injected startup failure'} }
    function New-Object {
        param([string]$TypeName,[object[]]$ArgumentList,[string]$ComObject)
        if($ComObject -eq 'HNetCfg.FwPolicy2'){ return [pscustomobject]@{Rules=$null} }
        Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
    }
    $before=[IO.File]::ReadAllText($ConfigPath,[Text.Encoding]::UTF8)
    $failed=$false
    try { & $originalEnable -Recovery } catch { $failed=$true; Write-Output $_.Exception.Message }
    if(-not $failed -or $script:starts -ne 2){throw 'Startup failure did not attempt rollback restart'}
    if([IO.File]::ReadAllText($ConfigPath,[Text.Encoding]::UTF8) -cne $before){throw 'Startup failure did not restore config'}
    Write-Output 'PASS: no-op, restricted firewall, partial listener, disconnected network, disabled service, transaction guard'
    Write-Output 'PASS: injected startup failure restores the previous configuration'
} finally { Remove-Item -LiteralPath $testRoot -Recurse -Force }
