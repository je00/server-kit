$ErrorActionPreference = "Stop"
$env:SERVER_KIT_LIBRARY_ONLY = "1"
$sourcePath = Join-Path $PSScriptRoot "..\web\dashboard\script_templates\server-kit-ssh-windows.ps1"
$temporaryPath = Join-Path $env:TEMP "server-kit-ssh-contract-$PID.ps1"
$sourceText = [IO.File]::ReadAllText((Resolve-Path $sourcePath), [Text.Encoding]::UTF8)
[IO.File]::WriteAllText($temporaryPath, $sourceText, (New-Object Text.UTF8Encoding($true)))
try {
    . $temporaryPath
} finally {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
}

$source = @"
Port 22
PasswordAuthentication yes
KbdInteractiveAuthentication yes

Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@
$rendered = ConvertTo-ServerKitAuthConfig -Content $source
$matchIndex = $rendered.IndexOf("Match Group administrators")
$authIndex = $rendered.IndexOf("AuthenticationMethods publickey")
if ($authIndex -lt 0 -or $matchIndex -lt 0 -or $authIndex -gt $matchIndex) {
    throw "Authentication directives must appear before the first Match block."
}
if ([regex]::Matches($rendered, '(?m)^PasswordAuthentication no\r?$').Count -ne 1) {
    throw "PasswordAuthentication must be disabled exactly once."
}
if ($rendered -match '(?m)^PasswordAuthentication yes$') {
    throw "The previous password authentication directive still exists."
}
Write-Host "PASS: Windows authentication directives stay outside Match blocks."
