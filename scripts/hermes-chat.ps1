param(
    [string]$Url,
    [string]$AuthorizationReference,
    [switch]$Crawl,
    [switch]$Reflection,
    [switch]$Redirect,
    [switch]$Encoding,
    [switch]$Assessment,
    [switch]$NewTarget,
    [switch]$ConfiguredTarget
)

$ErrorActionPreference = 'Stop'
if (@($Crawl, $Reflection, $Redirect, $Encoding, $Assessment).Where({ $_ }).Count -gt 1) {
    throw 'Choose only one of -Crawl, -Reflection, -Redirect, -Encoding or -Assessment for one task'
}
$otherArguments = @($PSBoundParameters.Keys | Where-Object { $_ -ne 'ConfiguredTarget' })
if ($ConfiguredTarget -and $otherArguments.Count -gt 0) {
    throw '-ConfiguredTarget cannot be combined with a target or task mode'
}
$configuredStart = $PSBoundParameters.Count -eq 0
if (-not $configuredStart -and -not $ConfiguredTarget) {
    if ([string]::IsNullOrWhiteSpace($Url)) { $Url = Read-Host 'Authorized URL' }
    if (-not $NewTarget -and [string]::IsNullOrWhiteSpace($AuthorizationReference)) {
        $AuthorizationReference = Read-Host 'Authorization reference'
    }
}
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $sourceRoot
try {
    $chatArgs = @()
    if ($ConfiguredTarget) {
        $chatArgs += '--configured-target'
    } elseif (-not $configuredStart) {
        $chatArgs += @('--url', $Url)
        if ($NewTarget) { $chatArgs += '--new-target' }
        else { $chatArgs += @('--authorization-reference', $AuthorizationReference) }
        if ($Crawl) { $chatArgs += '--crawl' }
        if ($Reflection) { $chatArgs += '--reflection' }
        if ($Redirect) { $chatArgs += '--redirect' }
        if ($Encoding) { $chatArgs += '--encoding' }
        if ($Assessment) { $chatArgs += '--assessment' }
    }
    & node (Join-Path $PSScriptRoot 'hermes-chat.mjs') @chatArgs
    if ($LASTEXITCODE -ne 0) { throw "Hermes chat exited with code $LASTEXITCODE" }
} finally {
    Pop-Location
}
