[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GuardianRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
    [string]$TaskName,
    [Parameter(Mandatory = $true)][string]$ReceiptPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$TaskPath = "\"

function Get-StringSha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        ).Replace("-", "").ToLowerInvariant()
    }
    finally { $sha.Dispose() }
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

$root = [System.IO.Path]::GetFullPath($GuardianRoot)
$python = Join-Path $root "Scripts\python.exe"
$guardian = Join-Path $root "Scripts\guardian.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or
    -not (Test-Path -LiteralPath $guardian -PathType Leaf)) {
    throw "Guardian launcher or python is absent"
}
$receipt = (& $guardian private-document-read `
    --schema windows-seed-persistence-receipt `
    --path $ReceiptPath) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or
    $receipt.protocol -ne "integrity-guardian/windows-seed-persistence-receipt/v1" -or
    $receipt.status -ne "PASS" -or
    $receipt.task_name -ne $TaskName -or
    $receipt.task_path -ne $TaskPath) {
    throw "persistence receipt does not authorize this exact removal"
}
$task = Get-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath $TaskPath `
    -ErrorAction Stop
if ($task.Actions.Count -ne 1 -or $task.Triggers.Count -ne 1) {
    throw "scheduled task action or trigger count rejected"
}
$actualActionDigest = "sha256:" + (Get-StringSha256 (
    [string]$task.Actions[0].Execute + "`0" +
    [string]$task.Actions[0].Arguments + "`0" +
    [string]$task.Actions[0].WorkingDirectory
))
if (
    $actualActionDigest -ne [string]$receipt.action_digest -or
    [string]$task.TaskPath -ne $TaskPath -or
    [string]$task.Principal.UserId -ne [string]$receipt.user_id -or
    [string]$task.Principal.LogonType -ne [string]$receipt.logon_type -or
    [string]$task.Principal.RunLevel -ne [string]$receipt.run_level -or
    $task.Triggers[0].CimClass.CimClassName -ne "MSFT_TaskLogonTrigger" -or
    [string]$task.Triggers[0].UserId -ne [string]$receipt.trigger_user_id -or
    [string]$task.Settings.MultipleInstances -ne "IgnoreNew" -or
    $task.Settings.StartWhenAvailable -ne $true -or
    $task.Settings.Hidden -ne $true
) {
    throw "scheduled task no longer matches its persistence receipt"
}
$listenerParts = ([string]$receipt.listener).Split(":")
if ($listenerParts.Count -ne 2 -or $listenerParts[0] -ne "127.0.0.1") {
    throw "persistence listener receipt rejected"
}
$listenerPort = [int]$listenerParts[1]
$taskXml = Export-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath $TaskPath `
    -ErrorAction Stop
$wasRunning = [string]$task.State -eq "Running"
$listenerWasOpen = Test-ListenerOpen $listenerPort
$outputFull = Initialize-PrivateOutputDestination `
    $OutputPath `
    $python `
    "persistence removal receipt output"
$mutationStarted = $false
try {
    $mutationStarted = $true
    Stop-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -ErrorAction SilentlyContinue
    Unregister-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -Confirm:$false
    if (Get-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -ErrorAction SilentlyContinue) {
        throw "scheduled task removal post-check failed"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-ListenerOpen $listenerPort)) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-ListenerOpen $listenerPort) {
        throw "runtime listener remained present after scheduled task removal"
    }
    $removal = [ordered]@{
        protocol = "integrity-guardian/windows-seed-persistence-removal/v1"
        status = "PASS"
        task_name = $TaskName
        task_path = $TaskPath
        mode = [string]$receipt.mode
        action_digest = $actualActionDigest
        trigger_user_id = [string]$receipt.trigger_user_id
        listener = [string]$receipt.listener
        removed_at = [DateTime]::UtcNow.ToString("o")
        task_removed = $true
        runtime_listener_absent = $true
        state_removed = $false
        production_authority = $false
    }
    $json = $removal | ConvertTo-Json -Depth 6 -Compress
    $staging = Join-Path $root (
        ".persistence-removal-" + [Guid]::NewGuid().ToString("N") + ".json"
    )
    Write-NewUtf8 $staging "$json`n"
    try {
        & $guardian private-document-store `
            --schema windows-seed-persistence-removal-receipt `
            --input $staging `
            --output $outputFull | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputFull -PathType Leaf)) {
            throw "private persistence removal receipt write failed (exit $LASTEXITCODE)"
        }
    }
    finally {
        Remove-Item -LiteralPath $staging -Force -ErrorAction SilentlyContinue
    }
    $json
}
catch {
    $originalFailure = $_
    $rollbackErrors = @()
    if (Test-Path -LiteralPath $outputFull) {
        try { Remove-Item -LiteralPath $outputFull -Force }
        catch { $rollbackErrors += "removal receipt: " + $_.Exception.Message }
    }
    if ($mutationStarted) {
        try {
            $existing = Get-ScheduledTask `
                -TaskName $TaskName `
                -TaskPath $TaskPath `
                -ErrorAction SilentlyContinue
            if (-not $existing) {
                Register-ScheduledTask `
                    -TaskName $TaskName `
                    -TaskPath $TaskPath `
                    -Xml $taskXml | Out-Null
            }
            $restored = Get-ScheduledTask `
                -TaskName $TaskName `
                -TaskPath $TaskPath `
                -ErrorAction Stop
            if ($restored.Actions.Count -ne 1 -or $restored.Triggers.Count -ne 1) {
                throw "restored scheduled task cardinality mismatch"
            }
            $restoredDigest = "sha256:" + (Get-StringSha256 (
                [string]$restored.Actions[0].Execute + "`0" +
                [string]$restored.Actions[0].Arguments + "`0" +
                [string]$restored.Actions[0].WorkingDirectory
            ))
            if (
                $restoredDigest -ne $actualActionDigest -or
                [string]$restored.TaskPath -ne $TaskPath -or
                [string]$restored.Principal.UserId -ne [string]$receipt.user_id -or
                [string]$restored.Principal.LogonType -ne [string]$receipt.logon_type -or
                [string]$restored.Principal.RunLevel -ne [string]$receipt.run_level -or
                $restored.Triggers[0].CimClass.CimClassName -ne "MSFT_TaskLogonTrigger" -or
                [string]$restored.Triggers[0].UserId -ne [string]$receipt.trigger_user_id -or
                [string]$restored.Settings.MultipleInstances -ne "IgnoreNew" -or
                $restored.Settings.StartWhenAvailable -ne $true -or
                $restored.Settings.Hidden -ne $true
            ) {
                throw "restored scheduled task identity mismatch"
            }
            if ($wasRunning -and [string]$restored.State -ne "Running") {
                Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
                $stateDeadline = [DateTime]::UtcNow.AddSeconds(10)
                do {
                    $restored = Get-ScheduledTask `
                        -TaskName $TaskName `
                        -TaskPath $TaskPath `
                        -ErrorAction Stop
                    if ([string]$restored.State -eq "Running") { break }
                    Start-Sleep -Milliseconds 250
                } while ([DateTime]::UtcNow -lt $stateDeadline)
                if ([string]$restored.State -ne "Running") {
                    throw "restored scheduled task did not resume"
                }
            }
            if ($listenerWasOpen) {
                $listenerDeadline = [DateTime]::UtcNow.AddSeconds(10)
                while ([DateTime]::UtcNow -lt $listenerDeadline -and
                    -not (Test-ListenerOpen $listenerPort)) {
                    Start-Sleep -Milliseconds 250
                }
                if (-not (Test-ListenerOpen $listenerPort)) {
                    throw "restored runtime listener did not resume"
                }
            }
        }
        catch { $rollbackErrors += "scheduled task restore: " + $_.Exception.Message }
    }
    if ($rollbackErrors.Count -ne 0) {
        throw (
            "persistence removal failed and rollback was incomplete: " +
            [string]::Join(" | ", $rollbackErrors) +
            "; original failure: " + $originalFailure.Exception.Message
        )
    }
    throw $originalFailure
}
