[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GuardianRoot,
    [Parameter(Mandatory = $true)][string]$ProfilePath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
    [string]$TaskName,
    [Parameter(Mandatory = $true)][string]$ReceiptPath,
    [ValidateSet("CurrentUser", "System")][string]$Mode = "CurrentUser",
    [switch]$ConfirmSystemAuthority,
    [switch]$HeadlessS4U,
    [string]$TriggerUserId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$TaskPath = "\"

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Quote-Argument([string]$Value) {
    if ($Value.Contains('"') -or $Value.EndsWith('\')) {
        throw "runtime argument path cannot be quoted safely"
    }
    return '"' + $Value + '"'
}

function Get-StringSha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        ).Replace("-", "").ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Resolve-AccountSid([string]$AccountId) {
    return (
        (New-Object System.Security.Principal.NTAccount($AccountId)).Translate(
            [System.Security.Principal.SecurityIdentifier]
        )
    ).Value
}

function Initialize-PrivateOutputDestination(
    [string]$Path,
    [string]$PythonExecutable,
    [string]$Label
) {
    $full = [System.IO.Path]::GetFullPath($Path)
    if (Test-Path -LiteralPath $full) {
        throw "$Label must be absent"
    }
    $parent = Split-Path -Parent $full
    $admission = (
        "from pathlib import Path; import sys; " +
        "from integrity_guardian._windows_files import " +
        "assert_private_directory_acl, create_private_directory_tree; " +
        "parent = Path(sys.argv[1]); create_private_directory_tree(parent); " +
        "assert_private_directory_acl(parent)"
    )
    & $PythonExecutable -I -c $admission $parent
    if ($LASTEXITCODE -ne 0) {
        throw "$Label private parent admission failed (exit $LASTEXITCODE)"
    }
    if (Test-Path -LiteralPath $full) {
        throw "$Label appeared during private parent admission"
    }
    return $full
}

function Write-NewUtf8([string]$Path, [string]$Text) {
    $parent = Split-Path -Parent ([System.IO.Path]::GetFullPath($Path))
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -ErrorAction Stop | Out-Null
    }
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

function Test-ListenerOpen([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.ConnectAsync("127.0.0.1", $Port)
        if (-not $pending.Wait(500)) { return $false }
        return $client.Connected
    }
    catch { return $false }
    finally { $client.Dispose() }
}

if ($Mode -eq "System" -and (-not $ConfirmSystemAuthority -or -not (Test-IsAdministrator))) {
    throw "SYSTEM persistence requires elevation and -ConfirmSystemAuthority before mutation"
}
if ($HeadlessS4U -and $Mode -ne "CurrentUser") {
    throw "headless S4U persistence is valid only for CurrentUser mode"
}
if ($HeadlessS4U -and [string]::IsNullOrWhiteSpace($TriggerUserId)) {
    throw "headless S4U persistence requires an explicit logon trigger user before mutation"
}
if ((-not $HeadlessS4U) -and -not [string]::IsNullOrWhiteSpace($TriggerUserId)) {
    throw "an alternate logon trigger user requires -HeadlessS4U"
}
if (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
    throw "scheduled task already exists; replacement is never implicit"
}
$root = [System.IO.Path]::GetFullPath($GuardianRoot)
$python = Join-Path $root "Scripts\python.exe"
$pythonw = Join-Path $root "Scripts\pythonw.exe"
$guardian = Join-Path $root "Scripts\guardian.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
    -not (Test-Path -LiteralPath $pythonw -PathType Leaf) -or
    -not (Test-Path -LiteralPath $guardian -PathType Leaf)) {
    throw "installed Guardian launcher, python or pythonw is absent"
}
$status = (& $guardian status --profile $ProfilePath) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $status.status -ne "READY_LOCAL_READONLY" -or
    $status.runtime.persistence_task -ne $TaskName -or
    $status.production_authority -ne $false) {
    throw "local profile is not ready for persistence"
}
$profile = (& $guardian private-document-read `
    --schema local-machine-profile `
    --path $ProfilePath) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "private local profile read failed (exit $LASTEXITCODE)"
}
if ($profile.runtime.host -ne "127.0.0.1") {
    throw "runtime listener must remain IPv4 loopback"
}
if (Test-ListenerOpen ([int]$profile.runtime.port)) {
    throw "runtime listener is already present before persistence mutation"
}
$installedAt = [DateTime]::UtcNow.ToString("o")
$installBootTime = (
    (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).
        LastBootUpTime.ToUniversalTime().ToString("o")
)
$arguments = "-m integrity_guardian.cli seed-serve --catalog " +
    (Quote-Argument ([string]$profile.seed.catalog)) +
    " --host 127.0.0.1 --port " + [string]$profile.runtime.port
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$resolvedTriggerUserId = if ($HeadlessS4U) { $TriggerUserId } else { $identity.Name }
$action = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $resolvedTriggerUserId
$settings = New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650) -StartWhenAvailable
if ($Mode -eq "System") {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $expectedUserId = "SYSTEM"
    $expectedLogonType = "ServiceAccount"
    $expectedRunLevel = "Highest"
}
elseif ($HeadlessS4U) {
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType S4U -RunLevel Limited
    $expectedUserId = $identity.Name
    $expectedLogonType = "S4U"
    $expectedRunLevel = "Limited"
}
else {
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $expectedUserId = $identity.Name
    $expectedLogonType = "Interactive"
    $expectedRunLevel = "Limited"
}
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal
$receiptFull = Initialize-PrivateOutputDestination `
    $ReceiptPath `
    $python `
    "persistence receipt output"
$registered = $false
try {
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -InputObject $task | Out-Null
    $registered = $true
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    $health = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri (
                "http://127.0.0.1:" + [string]$profile.runtime.port + "/healthz"
            ) -TimeoutSec 2
            if ($health.ok -eq $true) { break }
        }
        catch { Start-Sleep -Milliseconds 250 }
    }
    if ($null -eq $health -or $health.ok -ne $true -or
        $health.production_authority -ne $false) {
        throw "loopback runtime health post-check failed"
    }
    $actual = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    $actualPrincipalSid = Resolve-AccountSid ([string]$actual.Principal.UserId)
    $expectedPrincipalSid = Resolve-AccountSid $expectedUserId
    $actualTriggerSid = Resolve-AccountSid ([string]$actual.Triggers[0].UserId)
    $expectedTriggerSid = Resolve-AccountSid $resolvedTriggerUserId
    if ($actual.Actions.Count -ne 1 -or
        $actual.Triggers.Count -ne 1 -or
        [string]$actual.TaskPath -ne $TaskPath -or
        [string]$actual.Actions[0].Execute -ne $pythonw -or
        [string]$actual.Actions[0].Arguments -ne $arguments -or
        [string]$actual.Actions[0].WorkingDirectory -ne $root -or
        $actualPrincipalSid -ne $expectedPrincipalSid -or
        [string]$actual.Principal.LogonType -ne $expectedLogonType -or
        [string]$actual.Principal.RunLevel -ne $expectedRunLevel -or
        $actual.Triggers[0].CimClass.CimClassName -ne "MSFT_TaskLogonTrigger" -or
        $actualTriggerSid -ne $expectedTriggerSid -or
        [string]$actual.Settings.MultipleInstances -ne "IgnoreNew" -or
        $actual.Settings.StartWhenAvailable -ne $true -or
        $actual.Settings.Hidden -ne $true) {
        throw "scheduled task action post-check mismatch"
    }
    $actionDigest = "sha256:" + (Get-StringSha256 (
        $pythonw + "`0" + $arguments + "`0" + $root
    ))
    $receipt = [ordered]@{
        protocol = "integrity-guardian/windows-seed-persistence-receipt/v1"
        status = "PASS"
        task_name = $TaskName
        task_path = $TaskPath
        mode = $Mode
        user_id = [string]$actual.Principal.UserId
        logon_type = [string]$actual.Principal.LogonType
        run_level = [string]$actual.Principal.RunLevel
        trigger = "AtLogOn"
        trigger_user_id = [string]$actual.Triggers[0].UserId
        multiple_instances = "IgnoreNew"
        start_when_available = $true
        hidden = $true
        console_application = $false
        action_digest = $actionDigest
        listener = "127.0.0.1:" + [string]$profile.runtime.port
        installed_at = $installedAt
        install_boot_time = $installBootTime
        source_digest = [string]$health.source_digest
        catalog_digest = [string]$health.catalog_digest
        event_count = [int]$health.event_count
        credential_in_arguments = $false
        production_authority = $false
    }
    $json = $receipt | ConvertTo-Json -Depth 6 -Compress
    $receiptStaging = Join-Path $root (
        ".persistence-receipt-" + [Guid]::NewGuid().ToString("N") + ".json"
    )
    Write-NewUtf8 $receiptStaging "$json`n"
    try {
        & $guardian private-document-store `
            --schema windows-seed-persistence-receipt `
            --input $receiptStaging `
            --output $receiptFull | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $receiptFull -PathType Leaf)) {
            throw "private persistence receipt write failed (exit $LASTEXITCODE)"
        }
    }
    finally {
        Remove-Item -LiteralPath $receiptStaging -Force -ErrorAction SilentlyContinue
    }
    $json
}
catch {
    $originalFailure = $_
    $rollbackErrors = @()
    if (Test-Path -LiteralPath $receiptFull) {
        try { Remove-Item -LiteralPath $receiptFull -Force }
        catch { $rollbackErrors += "persistence receipt: " + $_.Exception.Message }
    }
    if ($registered) {
        try {
            Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
            if (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
                throw "scheduled task remained present"
            }
        }
        catch { $rollbackErrors += "scheduled task: " + $_.Exception.Message }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $deadline -and
            (Test-ListenerOpen ([int]$profile.runtime.port))) {
            Start-Sleep -Milliseconds 250
        }
        if (Test-ListenerOpen ([int]$profile.runtime.port)) {
            $rollbackErrors += "runtime listener remained present"
        }
    }
    if ($rollbackErrors.Count -ne 0) {
        throw (
            "persistence installation failed and rollback was incomplete: " +
            [string]::Join(" | ", $rollbackErrors) +
            "; original failure: " + $originalFailure.Exception.Message
        )
    }
    throw $originalFailure
}
