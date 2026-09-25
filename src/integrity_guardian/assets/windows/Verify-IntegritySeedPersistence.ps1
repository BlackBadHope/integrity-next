[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GuardianRoot,
    [Parameter(Mandatory = $true)][string]$ProfilePath,
    [Parameter(Mandatory = $true)][string]$PersistenceReceiptPath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [switch]$RequireReboot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Get-StringSha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        ).Replace("-", "").ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Write-NewUtf8([string]$Path, [string]$Text) {
    $stream = New-Object System.IO.FileStream(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $bytes = $Utf8NoBom.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

$root = [System.IO.Path]::GetFullPath($GuardianRoot)
$guardian = Join-Path $root "Scripts\guardian.exe"
if (-not (Test-Path -LiteralPath $guardian -PathType Leaf)) {
    throw "Guardian launcher is absent"
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "persistence witness output must be absent"
}
$profile = (& $guardian private-document-read `
    --schema local-machine-profile `
    --path $ProfilePath) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "private local profile read failed (exit $LASTEXITCODE)"
}
$receipt = (& $guardian private-document-read `
    --schema windows-seed-persistence-receipt `
    --path $PersistenceReceiptPath) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "private persistence receipt read failed (exit $LASTEXITCODE)"
}
if (
    $receipt.protocol -ne "integrity-guardian/windows-seed-persistence-receipt/v1" -or
    $receipt.status -ne "PASS" -or
    $profile.runtime.persistence_task -ne $receipt.task_name -or
    $profile.runtime.host -ne "127.0.0.1"
) {
    throw "persistence receipt and local profile binding rejected"
}
$task = Get-ScheduledTask `
    -TaskName $receipt.task_name `
    -TaskPath $receipt.task_path `
    -ErrorAction Stop
$taskInfo = Get-ScheduledTaskInfo `
    -TaskName $receipt.task_name `
    -TaskPath $receipt.task_path `
    -ErrorAction Stop
if ($task.Actions.Count -ne 1 -or $task.Triggers.Count -ne 1) {
    throw "scheduled task action or trigger count rejected"
}
$actualActionDigest = "sha256:" + (Get-StringSha256 (
    [string]$task.Actions[0].Execute + "`0" +
    [string]$task.Actions[0].Arguments + "`0" +
    [string]$task.Actions[0].WorkingDirectory
))
$bootTime = (
    (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).
        LastBootUpTime.ToUniversalTime()
)
$installedBootTime = [DateTime]::Parse(
    [string]$receipt.install_boot_time,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::RoundtripKind
).ToUniversalTime()
$lastRunTime = ([DateTime]$taskInfo.LastRunTime).ToUniversalTime()
$taskRanThisBoot = $lastRunTime -ge $bootTime
$rebootSinceInstall = $bootTime -gt $installedBootTime
$health = Invoke-RestMethod -Uri (
    "http://127.0.0.1:" + [string]$profile.runtime.port + "/healthz"
) -TimeoutSec 5
$listener = "127.0.0.1:" + [string]$profile.runtime.port
$valid = (
    $actualActionDigest -eq $receipt.action_digest -and
    [string]$task.TaskPath -eq [string]$receipt.task_path -and
    [string]$task.Principal.UserId -eq [string]$receipt.user_id -and
    [string]$task.Principal.LogonType -eq [string]$receipt.logon_type -and
    [string]$task.Principal.RunLevel -eq [string]$receipt.run_level -and
    $task.Triggers[0].CimClass.CimClassName -eq "MSFT_TaskLogonTrigger" -and
    [string]$receipt.trigger -eq "AtLogOn" -and
    [string]$task.Triggers[0].UserId -eq [string]$receipt.trigger_user_id -and
    [string]$task.Settings.MultipleInstances -eq "IgnoreNew" -and
    [string]$receipt.multiple_instances -eq "IgnoreNew" -and
    $task.Settings.StartWhenAvailable -eq $true -and
    $receipt.start_when_available -eq $true -and
    $task.Settings.Hidden -eq $true -and
    [string]$task.State -eq "Running" -and
    $listener -eq [string]$receipt.listener -and
    $taskRanThisBoot -and
    $health.ok -eq $true -and
    $health.production_authority -eq $false -and
    [string]$health.source_digest -eq [string]$receipt.source_digest -and
    [string]$health.catalog_digest -eq [string]$receipt.catalog_digest -and
    [int]$health.event_count -eq [int]$receipt.event_count -and
    ((-not $RequireReboot) -or $rebootSinceInstall)
)
$witness = [ordered]@{
    protocol = "integrity-guardian/windows-seed-persistence-witness/v1"
    status = if ($valid) { "PASS" } else { "FAIL" }
    observed_at = [DateTime]::UtcNow.ToString("o")
    task_name = [string]$receipt.task_name
    task_path = [string]$receipt.task_path
    mode = [string]$receipt.mode
    task_state = [string]$task.State
    last_task_result = [long]$taskInfo.LastTaskResult
    task_last_run_time = $lastRunTime.ToString("o")
    current_boot_time = $bootTime.ToString("o")
    installed_boot_time = $installedBootTime.ToString("o")
    action_digest = $actualActionDigest
    trigger = "AtLogOn"
    trigger_user_id = [string]$task.Triggers[0].UserId
    multiple_instances = "IgnoreNew"
    start_when_available = $true
    hidden = $true
    console_application = $false
    listener = $listener
    source_digest = [string]$health.source_digest
    catalog_digest = [string]$health.catalog_digest
    event_count = [int]$health.event_count
    task_ran_this_boot = [bool]$taskRanThisBoot
    reboot_since_install = [bool]$rebootSinceInstall
    require_reboot = [bool]$RequireReboot
    production_authority = $false
}
$json = $witness | ConvertTo-Json -Depth 6 -Compress
$staging = Join-Path $root (
    ".persistence-witness-" + [Guid]::NewGuid().ToString("N") + ".json"
)
Write-NewUtf8 $staging "$json`n"
try {
    & $guardian private-document-store `
        --schema windows-seed-persistence-witness `
        --input $staging `
        --output $OutputPath | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "private persistence witness write failed (exit $LASTEXITCODE)"
    }
}
catch {
    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
    }
    throw
}
finally {
    Remove-Item -LiteralPath $staging -Force -ErrorAction SilentlyContinue
}
$json
if (-not $valid) { throw "persistence semantic witness is FAIL" }
