# Local, one-process credential prompt for the DeepSeek runtime comparison.
# The key is never echoed, written to this repository, or added to User PATH/env.
$ErrorActionPreference = 'Stop'
$projectsRoot = Split-Path -Parent (Resolve-Path (Join-Path $PSScriptRoot '..'))
$sharedHermes = Join-Path $projectsRoot '.phantomveil-hermes-runtime\.venv\Scripts\hermes.exe'
$isolatedHermes = Join-Path $env:LOCALAPPDATA 'PhantomVeil\hermes-runtime\source\.venv\Scripts\hermes.exe'
$physicalHermes = Join-Path $env:LOCALAPPDATA 'Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\PhantomVeil\hermes-runtime\source\.venv\Scripts\hermes.exe'
$officialHermes = Join-Path $env:LOCALAPPDATA 'hermes\bin\hermes.exe'
if (Test-Path -LiteralPath $sharedHermes -PathType Leaf) {
    $hermesExecutable = $sharedHermes
} elseif (Test-Path -LiteralPath $isolatedHermes -PathType Leaf) {
    $hermesExecutable = $isolatedHermes
} elseif (Test-Path -LiteralPath $physicalHermes -PathType Leaf) {
    $hermesExecutable = $physicalHermes
} elseif (Test-Path -LiteralPath $officialHermes -PathType Leaf) {
    $hermesExecutable = $officialHermes
} else {
    throw 'Hermes CLI was not found; install the official Windows CLI and reopen PowerShell'
}
$hadHermesBin = Test-Path Env:HERMES_BIN
$originalHermesBin = $env:HERMES_BIN
$hadKey = -not [string]::IsNullOrWhiteSpace($env:DEEPSEEK_API_KEY)
$addedKey = $false
$secret = $null
$bstr = [IntPtr]::Zero

try {
    # Pin this comparison to the verified isolated install, then restore the caller's override.
    $env:HERMES_BIN = $hermesExecutable
    if (-not $hadKey) {
        $secret = Read-Host 'DeepSeek API key (input hidden)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
        $env:DEEPSEEK_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $addedKey = $true
        if ([string]::IsNullOrWhiteSpace($env:DEEPSEEK_API_KEY)) {
            throw 'No process DeepSeek API key was entered; isolated evaluation does not read Hermes saved credentials'
        }
    }
    Push-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
    try {
        & npm run hermes:pair -- deepseek-flash deepseek
        if ($LASTEXITCODE -ne 0) {
            throw "Hermes/OpenCode pair did not pass (exit code $LASTEXITCODE); inspect the status above"
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
