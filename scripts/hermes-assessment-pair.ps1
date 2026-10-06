# Run the two local known-answer comparisons with one private credential prompt.
param(
    [ValidateSet('Both', 'Raw', 'Encoded')]
    [string]$Scenario = 'Both'
)

$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$projectsRoot = Split-Path -Parent $sourceRoot
$sharedHermes = Join-Path $projectsRoot '.phantomveil-hermes-runtime\.venv\Scripts\hermes.exe'
$isolatedHermes = Join-Path $env:LOCALAPPDATA 'PhantomVeil\hermes-runtime\source\.venv\Scripts\hermes.exe'
$physicalHermes = Join-Path $env:LOCALAPPDATA 'Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\PhantomVeil\hermes-runtime\source\.venv\Scripts\hermes.exe'
$officialHermes = Join-Path $env:LOCALAPPDATA 'hermes\bin\hermes.exe'
$hermesExecutable = @($sharedHermes, $isolatedHermes, $physicalHermes, $officialHermes) |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1
if (-not $hermesExecutable) {
    throw 'Hermes CLI was not found; install the official Windows CLI and reopen PowerShell'
}

$hadHermesBin = Test-Path Env:HERMES_BIN
$originalHermesBin = $env:HERMES_BIN
$addedKey = [string]::IsNullOrWhiteSpace($env:DEEPSEEK_API_KEY)
$secret = $null
$bstr = [IntPtr]::Zero

try {
    $env:HERMES_BIN = $hermesExecutable
    if ($addedKey) {
        $secret = Read-Host 'DeepSeek API key (input hidden)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
        $env:DEEPSEEK_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrWhiteSpace($env:DEEPSEEK_API_KEY)) {
            throw 'No DeepSeek API key was entered for the isolated Hermes evaluation'
        }
    }

    $scenarios = switch ($Scenario) {
        'Raw' { @('raw') }
        'Encoded' { @('encoded') }
        default { @('raw', 'encoded') }
    }
    Push-Location $sourceRoot
    try {
        foreach ($item in $scenarios) {
            & npm run hermes:assessment-pair -- deepseek-flash deepseek both $item
            if ($LASTEXITCODE -ne 0) {
                throw "The $item comparison did not pass (exit code $LASTEXITCODE); see the score/run outcome above. This script is only an evaluation runner"
            }
        }
    } finally {
        Pop-Location
    }
} finally {
    if ($bstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if ($addedKey) {
        Remove-Item Env:\DEEPSEEK_API_KEY -ErrorAction SilentlyContinue
    }
    if ($hadHermesBin) {
        $env:HERMES_BIN = $originalHermesBin
    } else {
        Remove-Item Env:\HERMES_BIN -ErrorAction SilentlyContinue
    }
    $secret = $null
}
