param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('SessionStart', 'UserPromptSubmit', 'PostToolUse', 'PreCompact', 'PostCompact', 'SubagentStart', 'SubagentStop', 'Stop')]
    [string]$Event
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

function Write-IntegrityUnavailable {
    param(
        [string]$Reason = 'the local runtime failed before it produced a trusted continuity result'
    )
    if ($Event -in @('SessionStart', 'UserPromptSubmit', 'PostToolUse', 'SubagentStart')) {
        $output = @{
            hookSpecificOutput = @{
                hookEventName = $Event
                additionalContext = "INTEGRITY MEMORY UNAVAILABLE. $Reason; no continuity claim is valid."
            }
        }
    }
    else {
        $output = @{
            continue = $true
            systemMessage = "Integrity Seed unavailable: $Reason."
        }
    }
    [Console]::Out.WriteLine(($output | ConvertTo-Json -Compress -Depth 5))
    exit 0
}

$pluginRoot = [Environment]::GetEnvironmentVariable('PLUGIN_ROOT')
if ([string]::IsNullOrWhiteSpace($pluginRoot)) {
    Write-IntegrityUnavailable 'the trusted plugin root was not provided'
}
$launcher = [IO.Path]::GetFullPath((Join-Path $pluginRoot 'skills\integrity-seed\scripts\integrity_seed.py'))
if (-not [IO.File]::Exists($launcher)) {
    Write-IntegrityUnavailable 'the bundled launcher was not found'
}
$providerGuard = [IO.Path]::GetFullPath((Join-Path $pluginRoot 'hooks\canonical-provider-guard.py'))

$candidates = [Collections.Generic.List[string]]::new()
$override = [Environment]::GetEnvironmentVariable('INTEGRITY_SEED_PYTHON')
if (-not [string]::IsNullOrWhiteSpace($override) -and [IO.Path]::IsPathRooted($override)) {
    $candidates.Add($override)
}
if ([Environment]::GetEnvironmentVariable('INTEGRITY_SEED_PYTHON_ONLY') -ne '1') {
    foreach ($pattern in @(
        (Join-Path $env:LOCALAPPDATA 'Python\pythoncore-*\python.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\python.exe'),
        (Join-Path $env:ProgramFiles 'Python*\python.exe')
    )) {
        Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
            $candidates.Add($_.FullName)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Python*\python.exe') -File -ErrorAction SilentlyContinue | ForEach-Object {
            $candidates.Add($_.FullName)
        }
    }
}

$python = $null
foreach ($candidate in $candidates | Select-Object -Unique) {
    if (-not [IO.File]::Exists($candidate)) {
        continue
    }
    try {
        & $candidate -X utf8 -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) {
            $python = [IO.Path]::GetFullPath($candidate)
            break
        }
    }
    catch {
        continue
    }
}
if ($null -eq $python) {
    Write-IntegrityUnavailable 'a trusted Python 3.11+ interpreter was not found'
}

$codexHome = [Environment]::GetEnvironmentVariable('CODEX_HOME')
if ([string]::IsNullOrWhiteSpace($codexHome)) {
    $codexHome = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'
}
$providerMarker = Join-Path $codexHome 'integrity-seed\canonical-provider.json'
if ([IO.File]::Exists($providerGuard)) {
    & $python -X utf8 -I $providerGuard $providerMarker 2>$null
    if ($LASTEXITCODE -eq 0) {
        exit 0
    }
}

$stdinPayload = [Console]::In.ReadToEnd()
try {
    $childOutput = $stdinPayload | & $python -X utf8 -I $launcher hook --event $Event 2>$null
    $childExit = $LASTEXITCODE
}
catch {
    Write-IntegrityUnavailable
}
$outputText = (($childOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine)
if ($childExit -ne 0) {
    Write-IntegrityUnavailable
}
if (-not [string]::IsNullOrEmpty($outputText)) {
    [Console]::Out.WriteLine($outputText)
}
exit 0
