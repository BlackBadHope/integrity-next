[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GuardianRoot,
    [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
    [Parameter(Mandatory = $true)][string]$CodexHome,
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [string[]]$LegacyRoots = @(),
    [ValidateSet("Plan", "Apply", "Reconcile")][string]$Mode = "Plan",
    [string]$ConfirmHost,
    [string]$ExpectedPlanDigest,
    [string]$ExpectedReservationSha256,
    [string]$OriginalPlanPath,
    [ValidateSet(
        "retained-before-action",
        "reconstructed-from-captured-terminal-output"
    )][string]$OriginalPlanProvenance = "retained-before-action",
    [switch]$ConfirmDestructiveReset,
    [switch]$ConfirmReconciliation,
    [switch]$DeleteCodexCredentials,
    [ValidateRange(5, 300)][int]$DeleteTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$TaskPath = "\"
$ReconciliationListenerPorts = @(8765, 8775)

if (
    $PSVersionTable.PSEdition -ne "Desktop" -or
    $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSVersion.Minor -ne 1
) {
    throw "zero-day reset requires Windows PowerShell 5.1 Desktop"
}

function Get-Sha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        ).Replace("-", "").ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Assert-SafeTaskName([string]$Name) {
    if (
        [string]::IsNullOrWhiteSpace($Name) -or
        $Name.Length -gt 200 -or
        $Name -match '[*?\[\]\\/]'
    ) {
        throw "TaskName must be one exact non-wildcard root-task name"
    }
}

function Get-ExactScheduledTask([string]$Name) {
    $matching = @(Get-ScheduledTask -TaskPath $TaskPath -ErrorAction Stop |
        Where-Object {
            [string]::Equals(
                [string]$_.TaskName,
                $Name,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -and [string]$_.TaskPath -eq $TaskPath
        })
    if ($matching.Count -gt 1) {
        throw "exact scheduled task identity is not unique"
    }
    if ($matching.Count -eq 1) {
        return $matching[0]
    }
    return $null
}

function Get-NormalizedDirectory([string]$Value, [string]$Label) {
    $full = [System.IO.Path]::GetFullPath($Value).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($full).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($full) -or $full -eq $root) {
        throw "$Label cannot be a filesystem root"
    }
    return $full
}

function Test-IsSameOrChild([string]$Candidate, [string]$Parent) {
    return (
        [string]::Equals($Candidate, $Parent, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Candidate.StartsWith(
            $Parent + '\',
            [System.StringComparison]::OrdinalIgnoreCase
        )
    )
}

function Get-PathWitness([string]$Path) {
    $directoryExists = [System.IO.Directory]::Exists($Path)
    $fileExists = [System.IO.File]::Exists($Path)
    $exists = $directoryExists -or $fileExists
    $reparse = $false
    if ($exists) {
        $attributes = [System.IO.File]::GetAttributes($Path)
        $reparse = ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    }
    return [ordered]@{
        path = $Path
        exists = $exists
        reparse_point = $reparse
    }
}

function Test-PathOccupied([string]$Path) {
    return (
        [System.IO.Directory]::Exists($Path) -or
        [System.IO.File]::Exists($Path)
    )
}

function Assert-NoReparsePathChain([string]$Path, [string]$Label) {
    $cursor = [System.IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (
            [System.IO.Directory]::Exists($cursor) -or
            [System.IO.File]::Exists($cursor)
        ) {
            $attributes = [System.IO.File]::GetAttributes($cursor)
            if (
                ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "$Label path chain contains a reparse point"
            }
        }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }
        $next = $parent.FullName
        if ([string]::Equals(
            $next,
            $cursor,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            break
        }
        $cursor = $next
    }
}

function New-PrivateAcl([bool]$Directory) {
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $administrators = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    if ($Directory) {
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $inheritance = (
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        )
    }
    else {
        $security = New-Object System.Security.AccessControl.FileSecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $security.SetOwner($current)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($current, $system, $administrators)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    return $security
}

function Assert-PrivateAcl([string]$Path, [bool]$Directory) {
    $security = if ($Directory) {
        [System.IO.Directory]::GetAccessControl($Path)
    }
    else {
        [System.IO.File]::GetAccessControl($Path)
    }
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $expected = @($current, "S-1-5-18", "S-1-5-32-544") | Sort-Object
    $owner = $security.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
    if (-not $security.AreAccessRulesProtected -or $owner -ne $current) {
        throw "private reset evidence owner or DACL protection rejected"
    }
    $rules = @($security.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ))
    $actual = @($rules | ForEach-Object { $_.IdentityReference.Value }) | Sort-Object
    if ($rules.Count -ne 3 -or (Compare-Object $expected $actual)) {
        throw "private reset evidence principal set rejected"
    }
    $requiredInheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    else { [System.Security.AccessControl.InheritanceFlags]::None }
    foreach ($rule in $rules) {
        if (
            $rule.IsInherited -or
            $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $requiredInheritance -or
            $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
        ) {
            throw "private reset evidence ACL rule rejected"
        }
    }
}

if ($null -eq ("IntegrityGuardian.ResetReceiptNative" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace IntegrityGuardian {
    public static class ResetReceiptNative {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool MoveFileEx(
            string existingFileName,
            string newFileName,
            uint flags
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint desiredAccess,
            bool inheritHandle,
            uint processId
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool QueryFullProcessImageName(
            IntPtr process,
            uint flags,
            StringBuilder executablePath,
            ref uint size
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CommandLineToArgvW(
            string commandLine,
            out int argumentCount
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr handle);
    }
}
"@
}

function ConvertFrom-NativeCommandLine([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }
    $count = 0
    $pointer = [IntegrityGuardian.ResetReceiptNative]::CommandLineToArgvW(
        $Value,
        [ref]$count
    )
    if ($pointer -eq [IntPtr]::Zero -or $count -lt 1 -or $count -gt 4096) {
        throw "process command line could not be parsed within bounds"
    }
    try {
        $arguments = @()
        for ($index = 0; $index -lt $count; $index++) {
            $item = [Runtime.InteropServices.Marshal]::ReadIntPtr(
                $pointer,
                $index * [IntPtr]::Size
            )
            $arguments += [Runtime.InteropServices.Marshal]::PtrToStringUni($item)
        }
        return @($arguments)
    }
    finally {
        [void][IntegrityGuardian.ResetReceiptNative]::LocalFree($pointer)
    }
}

function Move-PrivateFileWriteThrough([string]$Source, [string]$Destination) {
    Assert-NoReparsePathChain $Source "private receipt source"
    Assert-NoReparsePathChain $Destination "private receipt destination"
    if (-not [System.IO.File]::Exists($Source)) {
        throw "private receipt source is absent"
    }
    if (
        [System.IO.File]::Exists($Destination) -or
        [System.IO.Directory]::Exists($Destination)
    ) {
        throw "private receipt destination must be absent"
    }
    $moveFileWriteThrough = [uint32]0x8
    $moved = [IntegrityGuardian.ResetReceiptNative]::MoveFileEx(
        $Source,
        $Destination,
        $moveFileWriteThrough
    )
    if (-not $moved) {
        $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw (New-Object ComponentModel.Win32Exception($code))
    }
}

function Get-LimitedProcessImagePath([uint32]$ProcessId) {
    $queryLimitedInformation = [uint32]0x1000
    $handle = [IntegrityGuardian.ResetReceiptNative]::OpenProcess(
        $queryLimitedInformation,
        $false,
        $ProcessId
    )
    if ($handle -eq [IntPtr]::Zero) {
        return ""
    }
    try {
        $capacity = [uint32]32768
        $builder = New-Object Text.StringBuilder([int]$capacity)
        if ([IntegrityGuardian.ResetReceiptNative]::QueryFullProcessImageName(
            $handle,
            [uint32]0,
            $builder,
            [ref]$capacity
        )) {
            return $builder.ToString()
        }
        return ""
    }
    finally {
        [void][IntegrityGuardian.ResetReceiptNative]::CloseHandle($handle)
    }
}

function Get-CodexClientProcessWitness {
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $matches = @()
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        [string]$_.Name -in @("ChatGPT.exe", "codex.exe")
    })) {
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
        if (
            [int]$owner.ReturnValue -ne 0 -or
            [string]$owner.Sid -cne $currentSid
        ) {
            continue
        }
        $executable = [string]$process.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($executable)) {
            $executable = Get-LimitedProcessImagePath ([uint32]$process.ProcessId)
        }
        $matches += [ordered]@{
            process_id = [uint32]$process.ProcessId
            parent_process_id = [uint32]$process.ParentProcessId
            session_id = [uint32]$process.SessionId
            name = [string]$process.Name
            executable_path = $executable
        }
    }
    return [ordered]@{
        matching_process_count = $matches.Count
        processes = $matches
    }
}

function Reserve-PrivateReceipt(
    [string]$Directory,
    [string]$Path,
    [string]$PlanDigest,
    [string]$StartedAt,
    [string]$AttemptUid,
    [string]$FinalReceiptName,
    [string]$ArchiveReceiptName
) {
    $createdDirectory = $false
    $createdReceipt = $false
    $guard = $null
    Assert-NoReparsePathChain $Directory "EvidenceDirectory"
    if (-not [System.IO.Directory]::Exists($Directory)) {
        $parent = [System.IO.Directory]::GetParent($Directory)
        if ($null -eq $parent -or -not [System.IO.Directory]::Exists($parent.FullName)) {
            throw "reset evidence parent must already exist"
        }
        [void][System.IO.Directory]::CreateDirectory($Directory)
        [System.IO.Directory]::SetAccessControl($Directory, (New-PrivateAcl $true))
        $createdDirectory = $true
    }
    try {
        Assert-NoReparsePathChain $Directory "EvidenceDirectory"
        Assert-PrivateAcl $Directory $true
        if ([System.IO.File]::Exists($Path)) {
            throw "reset receipt reservation already exists"
        }
        $reservation = [ordered]@{
            protocol = "integrity-guardian/uroboros-winops-zero-day-reset-reservation/v2"
            outcome = "unknown-outcome"
            receipt_state = "reserved-before-mutation"
            started_at = $StartedAt
            attempt_uid = $AttemptUid
            plan_digest = $PlanDigest
            final_receipt_name = $FinalReceiptName
            archive_receipt_name = $ArchiveReceiptName
            reconciliation_required = $true
            automatic_retry_allowed = $false
            action_replayed = $false
            production_authority = $false
        }
        $reservationText = ($reservation | ConvertTo-Json -Depth 4 -Compress) + "`n"
        $stream = New-Object System.IO.FileStream(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $createdReceipt = $true
        try {
            $bytes = $Utf8NoBom.GetBytes($reservationText)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        [System.IO.File]::SetAccessControl($Path, (New-PrivateAcl $false))
        Assert-PrivateAcl $Path $false
        $guard = New-Object System.IO.FileStream(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        return [ordered]@{
            text = $reservationText
            guard = $guard
        }
    }
    catch {
        if ($null -ne $guard) {
            $guard.Dispose()
        }
        if ($createdReceipt -and [System.IO.File]::Exists($Path)) {
            [System.IO.File]::Delete($Path)
        }
        if ($createdDirectory -and [System.IO.Directory]::Exists($Directory)) {
            [System.IO.Directory]::Delete($Directory, $false)
        }
        throw
    }
}

function Write-PrivateCreateNewUtf8(
    [string]$Path,
    [string]$Text
) {
    Assert-NoReparsePathChain $Path "private receipt"
    if ([System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path)) {
        throw "private receipt output must be absent"
    }
    $stream = $null
    try {
        $stream = New-Object System.IO.FileStream(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $bytes = $Utf8NoBom.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [System.IO.File]::SetAccessControl($Path, (New-PrivateAcl $false))
        Assert-PrivateAcl $Path $false
        $observed = [System.IO.File]::ReadAllText($Path, $Utf8NoBom)
        if (-not [string]::Equals(
            $observed,
            $Text,
            [System.StringComparison]::Ordinal
        )) {
            throw "private receipt readback mismatch"
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Write-PrivateAtomicCreateNewUtf8(
    [string]$EvidenceDirectory,
    [string]$FinalPath,
    [string]$Text,
    [string]$Role
) {
    $fragmentDirectory = Join-Path $EvidenceDirectory "receipt-fragments"
    Ensure-PrivateDirectory $fragmentDirectory
    $fragmentPath = Join-Path $fragmentDirectory (
        "r-" + $Role.Substring(0, 1).ToLowerInvariant() + "-" +
        [Guid]::NewGuid().ToString("N") + ".part"
    )
    Write-PrivateCreateNewUtf8 $fragmentPath $Text
    Move-PrivateFileWriteThrough $fragmentPath $FinalPath
    Assert-PrivateAcl $FinalPath $false
    $observed = [System.IO.File]::ReadAllText($FinalPath, $Utf8NoBom)
    if (-not [string]::Equals($observed, $Text, [StringComparison]::Ordinal)) {
        throw "atomic private receipt final readback mismatch"
    }
}

function Ensure-PrivateDirectory([string]$Path) {
    Assert-NoReparsePathChain $Path "private directory"
    if (-not [System.IO.Directory]::Exists($Path)) {
        [void][System.IO.Directory]::CreateDirectory($Path)
        [System.IO.Directory]::SetAccessControl($Path, (New-PrivateAcl $true))
    }
    Assert-NoReparsePathChain $Path "private directory"
    Assert-PrivateAcl $Path $true
}

function Ensure-PrivateEvidenceRoot([string]$Path) {
    Assert-NoReparsePathChain $Path "EvidenceDirectory"
    if (-not [System.IO.Directory]::Exists($Path)) {
        $parent = [System.IO.Directory]::GetParent($Path)
        if ($null -eq $parent -or -not [System.IO.Directory]::Exists($parent.FullName)) {
            throw "reset evidence parent must already exist"
        }
        [void][System.IO.Directory]::CreateDirectory($Path)
        [System.IO.Directory]::SetAccessControl($Path, (New-PrivateAcl $true))
    }
    Assert-NoReparsePathChain $Path "EvidenceDirectory"
    Assert-PrivateAcl $Path $true
}

function Commit-ReservedReceipt(
    [string]$Path,
    [string]$ExpectedReservation,
    [System.IO.FileStream]$ReservationGuard,
    [string]$FinalPath,
    [string]$ArchiveDirectory,
    [string]$ArchivePath,
    [string]$Text,
    [bool]$ArchiveReservation = $true
) {
    if ($null -eq $ReservationGuard -or -not $ReservationGuard.CanRead) {
        throw "reset receipt reservation guard is unavailable"
    }
    Assert-PrivateAcl $Path $false
    $current = [System.IO.File]::ReadAllText($Path, $Utf8NoBom)
    if (-not [string]::Equals(
        $current,
        $ExpectedReservation,
        [System.StringComparison]::Ordinal
    )) {
        throw "reset receipt reservation content mismatch"
    }
    Ensure-PrivateDirectory $ArchiveDirectory
    if ($ArchiveReservation -and [System.IO.File]::Exists($ArchivePath)) {
        throw "reset reservation archive path already exists"
    }
    # The final receipt is a monotonic CreateNew record.  It is fully flushed,
    # ACL-bound and read back while the original reservation guard is still
    # held.  Only then is the reservation moved into the private archive.  A
    # crash at either boundary leaves at least one fail-closed top-level record;
    # no replace-with-null-backup call or destructive retry is required.
    Write-PrivateAtomicCreateNewUtf8 `
        ([System.IO.Path]::GetDirectoryName($FinalPath)) `
        $FinalPath `
        $Text `
        "terminal"
    try {
        $current = [System.IO.File]::ReadAllText($Path, $Utf8NoBom)
        if (-not [string]::Equals(
            $current,
            $ExpectedReservation,
            [System.StringComparison]::Ordinal
        )) {
            throw "reset receipt reservation changed before archive"
        }
        if ($ArchiveReservation) {
            $ReservationGuard.Dispose()
            $ReservationGuard = $null
            Move-PrivateFileWriteThrough $Path $ArchivePath
            if ([System.IO.File]::Exists($Path)) {
                throw "reset receipt reservation remained after archive"
            }
            Assert-PrivateAcl $ArchivePath $false
            $archived = [System.IO.File]::ReadAllText($ArchivePath, $Utf8NoBom)
            if (-not [string]::Equals(
                $archived,
                $ExpectedReservation,
                [System.StringComparison]::Ordinal
            )) {
                throw "reset receipt reservation archive mismatch"
            }
        }
    }
    finally {
        if ($null -ne $ReservationGuard) {
            $ReservationGuard.Dispose()
        }
    }
}

function Assert-ExactProperties($Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value) {
        throw "$Label is absent"
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if ($actual.Count -ne $wanted.Count -or (Compare-Object $wanted $actual)) {
        throw "$Label property set rejected"
    }
}

function Read-OriginalResetPlan(
    [string]$Path,
    [string]$ExpectedDigest,
    [string[]]$ExpectedTargets,
    [string[]]$ExpectedLegacyRoots,
    [string]$ExpectedTaskName,
    [string]$ExpectedHost,
    [bool]$ExpectedDeleteCodexCredentials,
    [int]$ExpectedDeleteTimeoutSeconds
) {
    Assert-NoReparsePathChain $Path "OriginalPlanPath"
    if (-not [System.IO.File]::Exists($Path)) {
        throw "original reset plan is absent"
    }
    Assert-PrivateAcl $Path $false
    $details = New-Object System.IO.FileInfo($Path)
    if ($details.Length -lt 1 -or $details.Length -gt (1024 * 1024)) {
        throw "original reset plan size rejected"
    }
    try {
        $document = [System.IO.File]::ReadAllText($Path, $Utf8NoBom) |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "original reset plan JSON rejected"
    }
    Assert-ExactProperties $document @("plan", "plan_digest") "original reset plan"
    $core = $document.plan
    Assert-ExactProperties $core @(
        "protocol", "host", "targets", "legacy_roots", "task_name", "task",
        "delete_codex_credentials", "delete_timeout_seconds", "process_match",
        "reparse_traversal", "reparse_revalidation",
        "receipt_guard_held_until_atomic_commit", "receipt_guard_release",
        "same_principal_precommit_swap_window", "path_identity_held_during_delete",
        "hostile_same_principal_race_proven", "external_watchdog_required",
        "automatic_retry_after_unknown", "local_destructive_authority_required",
        "owner_authorization_proven", "imports_remote_memory", "production_authority"
    ) "original reset plan core"
    if (
        [string]$document.plan_digest -cne $ExpectedDigest -or
        [string]$core.protocol -cne
            "integrity-guardian/uroboros-winops-zero-day-reset-plan/v1" -or
        -not [string]::Equals(
            [string]$core.host,
            $ExpectedHost,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$core.task_name -cne $ExpectedTaskName -or
        [bool]$core.delete_codex_credentials -ne $ExpectedDeleteCodexCredentials -or
        [int]$core.delete_timeout_seconds -ne $ExpectedDeleteTimeoutSeconds -or
        [bool]$core.reparse_traversal -or
        [bool]$core.automatic_retry_after_unknown -or
        [bool]$core.owner_authorization_proven -or
        [bool]$core.imports_remote_memory -or
        [bool]$core.production_authority
    ) {
        throw "original reset plan safety boundary rejected"
    }
    $planTargets = @($core.targets)
    if ($planTargets.Count -ne $ExpectedTargets.Count) {
        throw "original reset plan target count rejected"
    }
    $rebuiltTargets = @()
    for ($index = 0; $index -lt $planTargets.Count; $index++) {
        $target = $planTargets[$index]
        Assert-ExactProperties $target @("path", "exists", "reparse_point") (
            "original reset plan target[" + [string]$index + "]"
        )
        if (
            -not [string]::Equals(
                [string]$target.path,
                $ExpectedTargets[$index],
                [System.StringComparison]::OrdinalIgnoreCase
            ) -or
            [bool]$target.reparse_point
        ) {
            throw "original reset plan target identity rejected"
        }
        $rebuiltTargets += [ordered]@{
            path = [string]$target.path
            exists = [bool]$target.exists
            reparse_point = [bool]$target.reparse_point
        }
    }
    $planLegacy = @($core.legacy_roots)
    if ($planLegacy.Count -ne $ExpectedLegacyRoots.Count) {
        throw "original reset plan legacy-root count rejected"
    }
    for ($index = 0; $index -lt $planLegacy.Count; $index++) {
        if (-not [string]::Equals(
            [string]$planLegacy[$index],
            $ExpectedLegacyRoots[$index],
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "original reset plan legacy-root identity rejected"
        }
    }
    $task = $core.task
    $rebuiltTask = $null
    if ([bool]$task.present) {
        Assert-ExactProperties $task @(
            "present", "exact_scope_bound", "task_path", "action_execute"
        ) "original reset plan task"
        $rebuiltTask = [ordered]@{
            present = $true
            exact_scope_bound = [bool]$task.exact_scope_bound
            task_path = [string]$task.task_path
            action_execute = [string]$task.action_execute
        }
    }
    else {
        Assert-ExactProperties $task @("present") "original reset plan task"
        $rebuiltTask = [ordered]@{ present = $false }
    }
    $rebuilt = [ordered]@{
        protocol = [string]$core.protocol
        host = [string]$core.host
        targets = $rebuiltTargets
        legacy_roots = @($planLegacy | ForEach-Object { [string]$_ })
        task_name = [string]$core.task_name
        task = $rebuiltTask
        delete_codex_credentials = [bool]$core.delete_codex_credentials
        delete_timeout_seconds = [int]$core.delete_timeout_seconds
        process_match = [string]$core.process_match
        reparse_traversal = [bool]$core.reparse_traversal
        reparse_revalidation = [string]$core.reparse_revalidation
        receipt_guard_held_until_atomic_commit = [bool]$core.receipt_guard_held_until_atomic_commit
        receipt_guard_release = [string]$core.receipt_guard_release
        same_principal_precommit_swap_window = [bool]$core.same_principal_precommit_swap_window
        path_identity_held_during_delete = [bool]$core.path_identity_held_during_delete
        hostile_same_principal_race_proven = [bool]$core.hostile_same_principal_race_proven
        external_watchdog_required = [bool]$core.external_watchdog_required
        automatic_retry_after_unknown = [bool]$core.automatic_retry_after_unknown
        local_destructive_authority_required = [bool]$core.local_destructive_authority_required
        owner_authorization_proven = [bool]$core.owner_authorization_proven
        imports_remote_memory = [bool]$core.imports_remote_memory
        production_authority = [bool]$core.production_authority
    }
    $rebuiltJson = $rebuilt | ConvertTo-Json -Depth 8 -Compress
    $rebuiltDigest = "sha256:" + (Get-Sha256 $rebuiltJson)
    if ($rebuiltDigest -cne $ExpectedDigest) {
        throw "original reset plan digest mismatch"
    }
    return [ordered]@{ plan = $rebuilt; plan_digest = $rebuiltDigest }
}

function Open-PrivateResetReservation(
    [string]$Directory,
    [string]$ExpectedPlanDigest,
    [string]$ExpectedSha256
) {
    Assert-NoReparsePathChain $Directory "reset evidence"
    Assert-PrivateAcl $Directory $true
    $activePath = Join-Path $Directory "uroboros-winops-zero-day-reset-active.json"
    $candidatePaths = @()
    if ([System.IO.File]::Exists($activePath)) {
        $candidatePaths += $activePath
    }
    $archiveDirectory = Join-Path $Directory "reservation-archive"
    if ([System.IO.Directory]::Exists($archiveDirectory)) {
        Assert-NoReparsePathChain $archiveDirectory "reset reservation archive"
        Assert-PrivateAcl $archiveDirectory $true
        $archived = @([System.IO.Directory]::GetFiles(
            $archiveDirectory,
            "*.json",
            [System.IO.SearchOption]::TopDirectoryOnly
        ))
        if ($archived.Count -gt 256) {
            throw "reset reservation archive bound exceeded"
        }
        $candidatePaths += $archived
    }
    $matches = @()
    foreach ($candidatePath in $candidatePaths) {
        Assert-NoReparsePathChain $candidatePath "reset reservation candidate"
        Assert-PrivateAcl $candidatePath $false
        $candidateDetails = New-Object System.IO.FileInfo($candidatePath)
        if ($candidateDetails.Length -lt 1 -or $candidateDetails.Length -gt (1024 * 1024)) {
            throw "reset reservation candidate size rejected"
        }
        $candidateText = [System.IO.File]::ReadAllText($candidatePath, $Utf8NoBom)
        $candidateSha = "sha256:" + (Get-Sha256 $candidateText)
        if ($candidateSha -ceq $ExpectedSha256) {
            $matches += [ordered]@{
                path = $candidatePath
                text = $candidateText
                sha256 = $candidateSha
                location = if ([string]::Equals(
                    $candidatePath,
                    $activePath,
                    [StringComparison]::OrdinalIgnoreCase
                )) { "active" } else { "archive" }
            }
        }
    }
    if ($matches.Count -ne 1) {
        throw "exact reset reservation source is absent or ambiguous"
    }
    $selected = $matches[0]
    $Path = [string]$selected.path
    Assert-PrivateAcl $Path $false
    $details = New-Object System.IO.FileInfo($Path)
    if ($details.Length -lt 1 -or $details.Length -gt (1024 * 1024)) {
        throw "reset reservation size rejected"
    }
    $text = [string]$selected.text
    $sha256 = [string]$selected.sha256
    if (
        [string]::IsNullOrWhiteSpace($ExpectedSha256) -or
        $sha256 -cne $ExpectedSha256
    ) {
        throw "reset reservation digest mismatch"
    }
    try {
        $document = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "reset reservation JSON rejected"
    }
    $protocol = [string]$document.protocol
    if ($protocol -eq "integrity-guardian/uroboros-winops-zero-day-reset-reservation/v1") {
        Assert-ExactProperties $document @(
            "protocol", "outcome", "receipt_state", "started_at", "plan_digest",
            "reconciliation_required", "automatic_retry_allowed", "action_replayed",
            "production_authority"
        ) "reset reservation v1"
    }
    elseif ($protocol -eq "integrity-guardian/uroboros-winops-zero-day-reset-reservation/v2") {
        Assert-ExactProperties $document @(
            "protocol", "outcome", "receipt_state", "started_at", "attempt_uid",
            "plan_digest", "final_receipt_name", "archive_receipt_name",
            "reconciliation_required", "automatic_retry_allowed", "action_replayed",
            "production_authority"
        ) "reset reservation v2"
        if ([string]$document.attempt_uid -notmatch '^[0-9a-f]{32}$') {
            throw "reset reservation attempt UID rejected"
        }
    }
    else {
        throw "reset reservation protocol rejected"
    }
    if (
        [string]$document.outcome -cne "unknown-outcome" -or
        [string]$document.receipt_state -cne "reserved-before-mutation" -or
        [string]$document.plan_digest -cne $ExpectedPlanDigest -or
        $document.reconciliation_required -ne $true -or
        $document.automatic_retry_allowed -ne $false -or
        $document.action_replayed -ne $false -or
        $document.production_authority -ne $false
    ) {
        throw "reset reservation safety state rejected"
    }
    $guard = New-Object System.IO.FileStream(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $guardedText = [System.IO.File]::ReadAllText($Path, $Utf8NoBom)
        if (-not [string]::Equals(
            $guardedText,
            $text,
            [System.StringComparison]::Ordinal
        )) {
            throw "reset reservation changed before guard"
        }
        return [ordered]@{
            document = $document
            text = $text
            sha256 = $sha256
            path = $Path
            location_at_open = [string]$selected.location
            guard = $guard
        }
    }
    catch {
        $guard.Dispose()
        throw
    }
}

function Get-ResetEvidenceInventory([string]$Directory) {
    $locations = @(
        [ordered]@{ path = $Directory; role = "top-level"; pattern = "uroboros-winops-zero-day-reset-*.json" },
        [ordered]@{ path = (Join-Path $Directory "reservation-archive"); role = "reservation-archive"; pattern = "*.json" },
        [ordered]@{ path = (Join-Path $Directory "receipt-fragments"); role = "receipt-fragment"; pattern = "*" }
    )
    $entries = @()
    foreach ($location in $locations) {
        if (-not [System.IO.Directory]::Exists([string]$location.path)) {
            continue
        }
        Assert-NoReparsePathChain ([string]$location.path) "reset evidence inventory"
        Assert-PrivateAcl ([string]$location.path) $true
        $files = @([System.IO.Directory]::GetFiles(
            [string]$location.path,
            [string]$location.pattern,
            [System.IO.SearchOption]::TopDirectoryOnly
        ))
        if ($files.Count -gt 256) {
            throw "reset evidence inventory bound exceeded"
        }
        foreach ($file in $files) {
            Assert-NoReparsePathChain $file "reset evidence inventory candidate"
            Assert-PrivateAcl $file $false
            $details = New-Object System.IO.FileInfo($file)
            if ($details.Length -gt (1024 * 1024)) {
                throw "reset evidence inventory candidate size rejected"
            }
            $text = [System.IO.File]::ReadAllText($file, $Utf8NoBom)
            $contentDigest = if ($details.Length -gt 0) {
                "sha256:" + (Get-Sha256 $text)
            }
            else { $null }
            $validation = "partial-invalid"
            if ($details.Length -gt 0) {
                try {
                    [void]($text | ConvertFrom-Json -ErrorAction Stop)
                    $validation = "json-valid"
                }
                catch { $validation = "partial-invalid" }
            }
            $entries += [ordered]@{
                role = [string]$location.role
                name_digest = "sha256:" + (Get-Sha256 (
                    [System.IO.Path]::GetFileName($file).ToLowerInvariant()
                ))
                content_digest = $contentDigest
                size = [int64]$details.Length
                validation = $validation
            }
        }
    }
    $ordered = @($entries | Sort-Object role, name_digest)
    $canonical = $ordered | ConvertTo-Json -Depth 6 -Compress
    return [ordered]@{
        entries = $ordered
        digest = "sha256:" + (Get-Sha256 $canonical)
    }
}

function Get-OriginalTerminalWitness(
    $Reservation,
    [string]$Directory,
    [string]$ReservationDigest
) {
    $name = if (
        [string]$Reservation.protocol -eq
            "integrity-guardian/uroboros-winops-zero-day-reset-reservation/v2"
    ) { [string]$Reservation.final_receipt_name } else { "legacy-v1-terminal-unbound" }
    $nameDigest = "sha256:" + (Get-Sha256 $name.ToLowerInvariant())
    if ($name -eq "legacy-v1-terminal-unbound") {
        return [ordered]@{
            state = "absent"
            name_digest = $nameDigest
            content_digest = $null
            recorded_outcome = $null
            trusted_for_outcome = $false
        }
    }
    if ([System.IO.Path]::GetFileName($name) -cne $name) {
        throw "reservation-declared terminal name rejected"
    }
    $path = Join-Path $Directory $name
    if (-not [System.IO.File]::Exists($path)) {
        return [ordered]@{
            state = "absent"
            name_digest = $nameDigest
            content_digest = $null
            recorded_outcome = $null
            trusted_for_outcome = $false
        }
    }
    Assert-NoReparsePathChain $path "reservation-declared terminal"
    Assert-PrivateAcl $path $false
    $details = New-Object System.IO.FileInfo($path)
    if ($details.Length -gt (1024 * 1024)) {
        throw "reservation-declared terminal size rejected"
    }
    $text = [System.IO.File]::ReadAllText($path, $Utf8NoBom)
    $digest = if ($details.Length -gt 0) { "sha256:" + (Get-Sha256 $text) } else { $null }
    $state = "partial-invalid"
    $recordedOutcome = $null
    if ($details.Length -gt 0) {
        try {
            $terminal = $text | ConvertFrom-Json -ErrorAction Stop
            $disposition = Get-ResetEvidenceDisposition $terminal $name
            if (
                [string]$terminal.protocol -eq
                    "integrity-guardian/uroboros-winops-zero-day-reset-receipt/v2" -and
                [string]$terminal.reservation_digest -ceq
                    $ReservationDigest
            ) {
                $state = "valid"
                $recordedOutcome = [string]$terminal.outcome
            }
        }
        catch { $state = "partial-invalid" }
    }
    return [ordered]@{
        state = $state
        name_digest = $nameDigest
        content_digest = $digest
        recorded_outcome = $recordedOutcome
        trusted_for_outcome = $false
    }
}

function Get-ReservationArchiveName($Reservation, [string]$ReservationDigest) {
    $digestHex = $ReservationDigest.Substring(7)
    $name = if (
        [string]$Reservation.protocol -eq
            "integrity-guardian/uroboros-winops-zero-day-reset-reservation/v2"
    ) { [string]$Reservation.archive_receipt_name } else {
        "res-v1-" + $digestHex.Substring(0, 16) + ".json"
    }
    if ([System.IO.Path]::GetFileName($name) -cne $name) {
        throw "reservation archive name rejected"
    }
    return $name
}

function Find-ExistingReconciliation(
    [string]$Directory,
    [string]$ReservationDigest
) {
    $digestHex = $ReservationDigest.Substring(7)
    Assert-NoReparsePathChain $Directory "existing reconciliation directory"
    if (-not [System.IO.Directory]::Exists($Directory)) {
        throw "existing reconciliation directory disappeared"
    }
    $prefix = "recon-" + $digestHex.Substring(0, 16) + "-"
    $candidates = @(Get-ChildItem -LiteralPath $Directory -File -ErrorAction Stop |
        Where-Object {
            $_.Name.StartsWith($prefix, [StringComparison]::Ordinal) -and
            $_.Name.EndsWith(".json", [StringComparison]::Ordinal)
        } | ForEach-Object { $_.FullName })
    if ($candidates.Count -gt 256) {
        throw "existing reconciliation candidate bound exceeded"
    }
    $matches = @()
    foreach ($candidate in $candidates) {
        Assert-NoReparsePathChain $candidate "existing reconciliation"
        Assert-PrivateAcl $candidate $false
        $details = New-Object System.IO.FileInfo($candidate)
        if ($details.Length -lt 1 -or $details.Length -gt (1024 * 1024)) {
            throw "existing reconciliation candidate size rejected"
        }
        $text = [System.IO.File]::ReadAllText($candidate, $Utf8NoBom)
        try {
            $document = $text | ConvertFrom-Json -ErrorAction Stop
        }
        catch { throw "existing reconciliation candidate JSON rejected" }
        if (
            [string]$document.protocol -cne
                "integrity-guardian/uroboros-winops-zero-day-reset-reconciliation/v2" -or
            [string]$document.source_reservation.digest -cne $ReservationDigest -or
            (Get-ResetEvidenceDisposition $document ([System.IO.Path]::GetFileName($candidate))) -cne "closed"
        ) {
            throw "existing reconciliation candidate binding rejected"
        }
        $matches += [ordered]@{
            path = $candidate
            text = $text
            document = $document
        }
    }
    if ($matches.Count -gt 1) {
        throw "multiple exact reconciliation closures rejected"
    }
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

function Get-TaskAbsenceWitness([string]$Name) {
    $matching = Get-ExactScheduledTask $Name
    return [ordered]@{
        name_digest = "sha256:" + (Get-Sha256 ($Name.ToLowerInvariant()))
        absent = $null -eq $matching
    }
}

function Test-IsBoundedProtectedProcess($Process, [string]$Executable) {
    $processId = [uint32]$Process.ProcessId
    if (
        $processId -le 4 -or
        [string]$Process.Name -in @("Registry", "Memory Compression")
    ) { return $true }
    $protectedOsNames = @(
        "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "wininit.exe"
    )
    return (
        $protectedOsNames -contains [string]$Process.Name -and
        -not [string]::IsNullOrWhiteSpace($Executable) -and
        (Test-IsSameOrChild `
            ([System.IO.Path]::GetFullPath($Executable)) `
            $env:SystemRoot)
    )
}

function Get-ProcessAbsenceWitness([string[]]$TargetPaths) {
    $allProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $controller = Get-ControllerProcessBoundary $allProcesses $TargetPaths
    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    $servicePathsByProcess = @{}
    foreach ($service in $services) {
        $processId = [uint32]$service.ProcessId
        if ($processId -eq 0) { continue }
        $key = [string]$processId
        if (-not $servicePathsByProcess.ContainsKey($key)) {
            $servicePathsByProcess[$key] = @()
        }
        $servicePathsByProcess[$key] += [string]$service.PathName
    }
    $matchingCount = 0
    $uninspectableCount = 0
    $protectedOsProcessCount = 0
    $selfProcessExcludedCount = 0
    foreach ($process in $allProcesses) {
        $processId = [uint32]$process.ProcessId
        $processKey = [string]$processId
        if ($controller.process_ids.ContainsKey($processKey)) {
            if ($processId -eq [uint32]$PID) {
                $selfProcessExcludedCount += 1
            }
            continue
        }
        $executable = [string]$process.ExecutablePath
        $commandLine = [string]$process.CommandLine
        if ([string]::IsNullOrWhiteSpace($executable) -and $processId -gt 4) {
            $executable = Get-LimitedProcessImagePath $processId
        }
        $servicePaths = @()
        $key = [string]$processId
        if ($servicePathsByProcess.ContainsKey($key)) {
            $servicePaths = @($servicePathsByProcess[$key])
        }
        $surrogate = [pscustomobject]@{
            ProcessId = $processId
            Name = [string]$process.Name
            ExecutablePath = $executable
            CommandLine = (@($commandLine) + $servicePaths) -join " "
        }
        if (Test-IsBoundedProtectedProcess $surrogate $executable) {
            $protectedOsProcessCount += 1
            continue
        }
        $classification = Get-ProcessTargetClassification $surrogate $TargetPaths
        if ($classification -eq "match") {
            $matchingCount += 1
            continue
        }
        if ($classification -eq "ambiguous") {
            $uninspectableCount += 1
            continue
        }
        # A process with no executable, command line, service path, or target
        # reference is global host opacity, not evidence of a relationship to
        # one of these exact reset targets. Positive target references that
        # cannot be normalized remain classified as ambiguous above.
    }
    if ($selfProcessExcludedCount -ne 1) {
        throw "current reset process identity was not uniquely observed"
    }
    return [ordered]@{
        inspected_process_count = $allProcesses.Count
        self_process_excluded_count = $selfProcessExcludedCount
        controller_process_excluded_count = [int]$controller.excluded_count
        matching_process_count = $matchingCount
        uninspectable_process_count = $uninspectableCount
        protected_os_process_count = $protectedOsProcessCount
    }
}

function Get-ListenerAbsenceWitness([int[]]$Ports) {
    $uniquePorts = @($Ports | Sort-Object -Unique)
    if ($uniquePorts.Count -ne $Ports.Count) {
        throw "reconciliation listener ports must be unique"
    }
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
        $uniquePorts -contains [int]$_.LocalPort
    })
    $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
        $uniquePorts -contains [int]$_.LocalPort
    })
    return [ordered]@{
        inspected_listener_ports = @($uniquePorts | ForEach-Object { [int]$_ })
        matching_tcp_listener_count = $tcp.Count
        matching_udp_listener_count = $udp.Count
    }
}

function Get-ResetEvidenceDisposition($Document, [string]$Label) {
    $protocol = if ($Document.PSObject.Properties.Name -contains "protocol") {
        [string]$Document.protocol
    }
    else { "" }
    $reservationCommon = @(
        "protocol", "outcome", "receipt_state", "started_at", "plan_digest",
        "reconciliation_required", "automatic_retry_allowed", "action_replayed",
        "production_authority"
    )
    if ($protocol -eq "integrity-guardian/uroboros-winops-zero-day-reset-reservation/v1") {
        Assert-ExactProperties $Document $reservationCommon "$Label reservation v1"
        if (
            [string]$Document.outcome -cne "unknown-outcome" -or
            [string]$Document.receipt_state -cne "reserved-before-mutation" -or
            $Document.reconciliation_required -ne $true -or
            $Document.automatic_retry_allowed -ne $false -or
            $Document.action_replayed -ne $false -or
            $Document.production_authority -ne $false
        ) { throw "$Label reservation v1 safety state rejected" }
        return "blocking"
    }
    if ($protocol -eq "integrity-guardian/uroboros-winops-zero-day-reset-reservation/v2") {
        Assert-ExactProperties $Document ($reservationCommon + @(
            "attempt_uid", "final_receipt_name", "archive_receipt_name"
        )) "$Label reservation v2"
        if (
            [string]$Document.attempt_uid -notmatch '^[0-9a-f]{32}$' -or
            [string]$Document.outcome -cne "unknown-outcome" -or
            [string]$Document.receipt_state -cne "reserved-before-mutation" -or
            $Document.reconciliation_required -ne $true -or
            $Document.automatic_retry_allowed -ne $false -or
            $Document.action_replayed -ne $false -or
            $Document.production_authority -ne $false
        ) { throw "$Label reservation v2 safety state rejected" }
        return "blocking"
    }
    $receiptV1 = @(
        "protocol", "outcome", "started_at", "finished_at", "plan_digest",
        "task_name", "contained_processes", "deletions", "target_absence",
        "task_absent", "credentials_deleted", "failure",
        "automatic_retry_allowed", "action_replayed", "local_destructive_action",
        "owner_authorization_proven", "imports_remote_memory", "production_authority",
        "path_identity_held_during_delete", "hostile_same_principal_race_proven",
        "receipt_guard_held_until_atomic_commit", "receipt_guard_release",
        "same_principal_precommit_swap_window"
    )
    $receiptV2 = $receiptV1 + @(
        "attempt_uid", "self_process_excluded_count",
        "controller_process_excluded_count", "reservation_digest"
    )
    if ($protocol -in @(
        "integrity-guardian/uroboros-winops-zero-day-reset-receipt/v1",
        "integrity-guardian/uroboros-winops-zero-day-reset-receipt/v2"
    )) {
        $isV2 = $protocol.EndsWith("/v2")
        Assert-ExactProperties $Document $(if ($isV2) { $receiptV2 } else { $receiptV1 }) "$Label terminal receipt"
        if (
            [string]$Document.outcome -notin @("confirmed-success", "confirmed-failure", "unknown-outcome") -or
            $Document.automatic_retry_allowed -ne $false -or
            $Document.action_replayed -ne $false -or
            $Document.local_destructive_action -ne $true -or
            $Document.owner_authorization_proven -ne $false -or
            $Document.imports_remote_memory -ne $false -or
            $Document.production_authority -ne $false -or
            $Document.path_identity_held_during_delete -ne $false -or
            $Document.hostile_same_principal_race_proven -ne $false
        ) { throw "$Label terminal receipt safety state rejected" }
        if ($isV2 -and (
            [string]$Document.attempt_uid -notmatch '^[0-9a-f]{32}$' -or
            [int]$Document.self_process_excluded_count -ne 1 -or
            [int]$Document.controller_process_excluded_count -lt 1 -or
            [int]$Document.controller_process_excluded_count -gt 32 -or
            $Document.receipt_guard_held_until_atomic_commit -ne $true -or
            $Document.same_principal_precommit_swap_window -ne $false
        )) { throw "$Label terminal receipt v2 boundary rejected" }
        if ([string]$Document.outcome -cne "confirmed-success") {
            return "blocking"
        }
        if (
            $Document.task_absent -ne $true -or
            @($Document.target_absence | Where-Object { $_ -ne $true }).Count -ne 0 -or
            $null -ne $Document.failure
        ) { throw "$Label confirmed-success postconditions rejected" }
        return "closed"
    }
    if ($protocol -in @(
        "integrity-guardian/uroboros-winops-zero-day-reset-reconciliation/v1",
        "integrity-guardian/uroboros-winops-zero-day-reset-reconciliation/v2"
    )) {
        $isReconciliationV2 = $protocol.EndsWith("/v2")
        $expectedReconciliationProperties = @(
            "protocol", "reconciliation_id", "reconciled_at", "host", "attempt_uid",
            "original_action_outcome", "reconciliation_outcome", "postconditions_status",
            "plan_digest", "reservation_digest", "original_plan_provenance",
            "postconditions", "limitations", "reconciliation_only",
            "reconciliation_required", "action_replayed", "automatic_retry_allowed",
            "destructive_write_performed", "event_write_performed",
            "evidence_write_scope", "local_destructive_authority",
            "imports_remote_memory", "production_authority"
        )
        if ($isReconciliationV2) {
            $expectedReconciliationProperties += @(
            "reconciliation_uid", "source_attempt_id", "source_reservation",
            "original_terminal", "bound_preexisting_artifacts",
            "artifact_inventory_digest"
            )
        }
        Assert-ExactProperties `
            $Document `
            $expectedReconciliationProperties `
            "$Label reconciliation receipt"
        if ($isReconciliationV2) {
            Assert-ExactProperties $Document.source_reservation @(
                "protocol", "digest", "location_at_open", "name_digest"
            ) "$Label source reservation"
            Assert-ExactProperties $Document.original_terminal @(
                "state", "name_digest", "content_digest", "recorded_outcome",
                "trusted_for_outcome"
            ) "$Label original terminal"
            foreach ($artifact in @($Document.bound_preexisting_artifacts)) {
                Assert-ExactProperties $artifact @(
                    "role", "name_digest", "content_digest", "size", "validation"
                ) "$Label bound artifact"
            }
        }
        Assert-ExactProperties $Document.postconditions @(
            "targets", "task", "inspected_process_count",
            "self_process_excluded_count", "controller_process_excluded_count",
            "matching_process_count", "uninspectable_process_count",
            "protected_os_process_count", "inspected_listener_ports",
            "matching_tcp_listener_count", "matching_udp_listener_count"
        ) "$Label reconciliation postconditions"
        $ports = @($Document.postconditions.inspected_listener_ports)
        if (
            [string]$Document.original_action_outcome -cne "unknown-outcome" -or
            [string]$Document.reconciliation_outcome -cne "confirmed-success" -or
            [string]$Document.postconditions_status -cne "confirmed-absent" -or
            $Document.reconciliation_only -ne $true -or
            $Document.reconciliation_required -ne $false -or
            $Document.action_replayed -ne $false -or
            $Document.automatic_retry_allowed -ne $false -or
            $Document.destructive_write_performed -ne $false -or
            $Document.event_write_performed -ne $false -or
            $Document.local_destructive_authority -ne $false -or
            $Document.imports_remote_memory -ne $false -or
            $Document.production_authority -ne $false -or
            ($isReconciliationV2 -and (
                [string]$Document.reconciliation_uid -notmatch '^[0-9a-f]{32}$' -or
                [string]$Document.source_reservation.digest -cne [string]$Document.reservation_digest -or
                $Document.original_terminal.trusted_for_outcome -ne $false
            )) -or
            [int]$Document.postconditions.self_process_excluded_count -ne 1 -or
            [int]$Document.postconditions.controller_process_excluded_count -lt 1 -or
            [int]$Document.postconditions.matching_process_count -ne 0 -or
            [int]$Document.postconditions.uninspectable_process_count -ne 0 -or
            $ports.Count -ne 2 -or [int]$ports[0] -ne 8765 -or [int]$ports[1] -ne 8775 -or
            [int]$Document.postconditions.matching_tcp_listener_count -ne 0 -or
            [int]$Document.postconditions.matching_udp_listener_count -ne 0
        ) { throw "$Label reconciliation safety state rejected" }
        return "closed"
    }
    throw "$Label protocol requires reconciliation"
}

function Assert-NoPendingResetReservation([string]$Directory) {
    if (-not [System.IO.Directory]::Exists($Directory)) {
        return
    }
    Assert-NoReparsePathChain $Directory "EvidenceDirectory"
    Assert-PrivateAcl $Directory $true
    $candidates = @([System.IO.Directory]::GetFiles(
        $Directory,
        "uroboros-winops-zero-day-reset-*.json",
        [System.IO.SearchOption]::TopDirectoryOnly
    ))
    if ($candidates.Count -gt 256) {
        throw "reset evidence candidate bound exceeded"
    }
    foreach ($candidate in $candidates) {
        if (
            ([System.IO.File]::GetAttributes($candidate) -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "reset evidence candidate is a reparse point"
        }
        Assert-PrivateAcl $candidate $false
        $details = New-Object System.IO.FileInfo($candidate)
        if ($details.Length -lt 1 -or $details.Length -gt (1024 * 1024)) {
            throw "reset evidence candidate size requires reconciliation"
        }
        try {
            $document = [System.IO.File]::ReadAllText(
                $candidate,
                $Utf8NoBom
            ) | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "reset evidence candidate is unreadable; reconciliation required"
        }
        $candidateName = [System.IO.Path]::GetFileName($candidate)
        $disposition = Get-ResetEvidenceDisposition $document $candidateName
        if (
            $candidateName -eq "uroboros-winops-zero-day-reset-active.json" -or
            $disposition -eq "blocking"
        ) {
            throw "existing reset reservation requires reconciliation; retry forbidden"
        }
    }
}

function Test-NormalizedArgumentTouchesTarget(
    [string]$Argument,
    [string[]]$Targets
) {
    $candidates = @($Argument)
    $equals = $Argument.IndexOf('=')
    if ($equals -ge 0 -and $equals -lt ($Argument.Length - 1)) {
        $candidates += $Argument.Substring($equals + 1)
    }
    foreach ($candidate in $candidates) {
        $isRooted = $false
        try {
            $isRooted = [System.IO.Path]::IsPathRooted($candidate)
        }
        catch {
            # Process command lines are an observation surface.  A third-party
            # argument with characters rejected by legacy .NET path parsing is
            # not itself evidence that it names one of the reset targets.
            continue
        }
        if (-not $isRooted) {
            continue
        }
        try {
            $normalized = [System.IO.Path]::GetFullPath($candidate).TrimEnd('\')
        }
        catch {
            continue
        }
        foreach ($target in $Targets) {
            if (Test-IsSameOrChild $normalized $target) {
                return $true
            }
        }
    }
    return $false
}

function Get-ProcessTargetClassification($Process, [string[]]$Targets) {
    $executable = [string]$Process.ExecutablePath
    $commandLine = [string]$Process.CommandLine
    if (-not [string]::IsNullOrWhiteSpace($executable)) {
        $normalizedExecutable = $null
        try {
            $normalizedExecutable = [System.IO.Path]::GetFullPath(
                $executable
            ).TrimEnd('\')
        }
        catch {
            foreach ($target in $Targets) {
                if ($executable.IndexOf(
                    $target,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -ge 0) {
                    return "ambiguous"
                }
            }
        }
        if ($null -ne $normalizedExecutable) {
            foreach ($target in $Targets) {
                if (Test-IsSameOrChild $normalizedExecutable $target) {
                    return "match"
                }
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($commandLine)) {
        foreach ($argument in @(ConvertFrom-NativeCommandLine $commandLine)) {
            if (Test-NormalizedArgumentTouchesTarget $argument $Targets) {
                return "match"
            }
        }
        foreach ($target in $Targets) {
            if ($commandLine.IndexOf(
                $target,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -ge 0) {
                return "ambiguous"
            }
        }
    }
    return "none"
}

function Get-ControllerProcessBoundary($Processes, [string[]]$Targets) {
    $byId = @{}
    foreach ($process in @($Processes)) {
        $key = [string][uint32]$process.ProcessId
        if ($byId.ContainsKey($key)) {
            throw "process snapshot contains duplicate PID"
        }
        $byId[$key] = $process
    }
    $excluded = @{}
    $cursor = [uint32]$PID
    for ($depth = 0; $depth -lt 32; $depth++) {
        if ($cursor -le 4) {
            break
        }
        $key = [string]$cursor
        if (-not $byId.ContainsKey($key)) {
            if ($depth -eq 0) {
                throw "current reset process identity was not observed"
            }
            break
        }
        $process = $byId[$key]
        $executable = [string]$process.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($executable)) {
            $executable = Get-LimitedProcessImagePath $cursor
        }
        if ([string]::IsNullOrWhiteSpace($executable)) {
            throw "controller process executable is uninspectable"
        }
        foreach ($target in $Targets) {
            if (Test-IsSameOrChild ([System.IO.Path]::GetFullPath($executable)) $target) {
                throw "controller process executable overlaps a reset target"
            }
        }
        $excluded[$key] = $true
        $parent = [uint32]$process.ParentProcessId
        if ($parent -eq 0 -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }
    if (-not $excluded.ContainsKey([string][uint32]$PID)) {
        throw "current reset process was not excluded"
    }
    return [ordered]@{
        process_ids = $excluded
        excluded_count = $excluded.Count
    }
}

function Stop-ExactTargetProcess($Snapshot, [string[]]$Targets) {
    $processId = [uint32]$Snapshot.ProcessId
    $current = Get-CimInstance Win32_Process `
        -Filter ("ProcessId=" + [string]$processId) `
        -ErrorAction SilentlyContinue
    if (
        $null -eq $current -or
        [string]$current.CreationDate -cne [string]$Snapshot.CreationDate
    ) {
        throw "target process identity changed before containment"
    }
    if ((Get-ProcessTargetClassification $current $Targets) -cne "match") {
        throw "target process binding changed before containment"
    }
    $pinned = $null
    try {
        $pinned = [System.Diagnostics.Process]::GetProcessById([int]$processId)
        [void]$pinned.Handle
        $revalidated = Get-CimInstance Win32_Process `
            -Filter ("ProcessId=" + [string]$processId) `
            -ErrorAction SilentlyContinue
        if (
            $null -eq $revalidated -or
            [string]$revalidated.CreationDate -cne [string]$Snapshot.CreationDate -or
            (Get-ProcessTargetClassification $revalidated $Targets) -cne "match"
        ) {
            throw "target process identity changed after handle acquisition"
        }
        $pinned.Kill()
        if (-not $pinned.WaitForExit(30000)) {
            throw "exact target-bound process did not exit after containment"
        }
    }
    finally {
        if ($null -ne $pinned) {
            $pinned.Dispose()
        }
    }
    $remaining = Get-CimInstance Win32_Process `
        -Filter ("ProcessId=" + [string]$processId) `
        -ErrorAction SilentlyContinue
    if (
        $null -ne $remaining -and
        [string]$remaining.CreationDate -ceq [string]$Snapshot.CreationDate
    ) {
        throw "exact target-bound process remained after containment"
    }
}

function Remove-DirectoryBounded([string]$Path, [int]$TimeoutSeconds) {
    if (-not [System.IO.Directory]::Exists($Path)) {
        return [ordered]@{ path = $Path; result = "already-absent"; elapsed_ms = 0 }
    }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = "$env:SystemRoot\System32\cmd.exe"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    if ($Path -notmatch '^[A-Za-z]:\\[A-Za-z0-9 ._\\-]+$') {
        throw "native delete target contains unsupported cmd characters"
    }
    # Windows PowerShell 5 runs on .NET Framework, where ProcessStartInfo has
    # no ArgumentList property.  Keep the command grammar closed and quote the
    # already normalized exact directory as the sole data argument.
    $start.Arguments = '/d /c rd /s /q "' + $Path + '"'
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            $process.WaitForExit()
            return [ordered]@{
                path = $Path
                result = "unknown-outcome-timeout"
                elapsed_ms = $watch.ElapsedMilliseconds
            }
        }
        return [ordered]@{
            path = $Path
            result = if (
                $process.ExitCode -eq 0 -and -not [System.IO.Directory]::Exists($Path)
            ) { "confirmed-absent" } else { "confirmed-failure" }
            exit_code = $process.ExitCode
            elapsed_ms = $watch.ElapsedMilliseconds
        }
    }
    finally {
        $process.Dispose()
        $watch.Stop()
    }
}

$guardian = Get-NormalizedDirectory $GuardianRoot "GuardianRoot"
$workspace = Get-NormalizedDirectory $WorkspaceRoot "WorkspaceRoot"
$codex = Get-NormalizedDirectory $CodexHome "CodexHome"
$evidence = Get-NormalizedDirectory $EvidenceDirectory "EvidenceDirectory"
$legacyTargets = @()
for ($index = 0; $index -lt $LegacyRoots.Count; $index++) {
    $legacyTargets += Get-NormalizedDirectory `
        $LegacyRoots[$index] `
        ("LegacyRoots[" + [string]$index + "]")
}
$targets = @($guardian, $workspace, $codex) + $legacyTargets
Assert-SafeTaskName $TaskName
for ($left = 0; $left -lt $targets.Count; $left++) {
    for ($right = $left + 1; $right -lt $targets.Count; $right++) {
        if (
            (Test-IsSameOrChild $targets[$left] $targets[$right]) -or
            (Test-IsSameOrChild $targets[$right] $targets[$left])
        ) {
            throw "reset targets must be distinct non-overlapping directories"
        }
    }
}
foreach ($target in $targets) {
    Assert-NoReparsePathChain $target "reset target"
    if (Test-IsSameOrChild $evidence $target) {
        throw "EvidenceDirectory must remain outside every reset target"
    }
    if ($target -notmatch '^[A-Za-z]:\\[A-Za-z0-9 ._\\-]+$') {
        throw "reset target contains unsupported native delete characters"
    }
}
$codexClientWitness = Get-CodexClientProcessWitness
if ([int]$codexClientWitness.matching_process_count -ne 0) {
    throw "current-user Codex client processes must be closed before reset Plan or Apply"
}
$pathWitnesses = @($targets | ForEach-Object { Get-PathWitness $_ })
if ($pathWitnesses.reparse_point -contains $true) {
    throw "reset target is a reparse point"
}
$task = Get-ExactScheduledTask $TaskName
$taskWitness = if ($null -eq $task) {
    [ordered]@{ present = $false }
}
else {
    $execute = [System.IO.Path]::GetFullPath([string]$task.Actions[0].Execute)
    $arguments = [string]$task.Actions[0].Arguments
    $bound = (
        $task.Actions.Count -eq 1 -and
        (Test-IsSameOrChild $execute $guardian) -and
        $arguments.IndexOf($workspace, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    )
    [ordered]@{
        present = $true
        exact_scope_bound = $bound
        task_path = [string]$task.TaskPath
        action_execute = $execute
    }
}
$planCore = [ordered]@{
    protocol = "integrity-guardian/uroboros-winops-zero-day-reset-plan/v1"
    host = [System.Net.Dns]::GetHostName()
    targets = $pathWitnesses
    legacy_roots = $legacyTargets
    task_name = $TaskName
    task = $taskWitness
    delete_codex_credentials = [bool]$DeleteCodexCredentials
    delete_timeout_seconds = $DeleteTimeoutSeconds
    process_match = "exact-target-executable-or-command-line"
    reparse_traversal = $false
    reparse_revalidation = "after-containment-before-each-delete"
    receipt_guard_held_until_atomic_commit = $true
    receipt_guard_release = "after-final-create-flush-acl-and-byte-readback-before-write-through-reservation-archive"
    same_principal_precommit_swap_window = $false
    path_identity_held_during_delete = $false
    hostile_same_principal_race_proven = $false
    external_watchdog_required = $true
    automatic_retry_after_unknown = $false
    local_destructive_authority_required = $true
    owner_authorization_proven = $false
    imports_remote_memory = $false
    production_authority = $false
}
$planJson = $planCore | ConvertTo-Json -Depth 8 -Compress
$planDigest = "sha256:" + (Get-Sha256 $planJson)
$plan = [ordered]@{ plan = $planCore; plan_digest = $planDigest }
if ($Mode -eq "Plan") {
    $plan | ConvertTo-Json -Depth 10 -Compress
    exit 0
}

if ($Mode -eq "Reconcile") {
    if ($ConfirmDestructiveReset) {
        throw "Reconcile rejects destructive-reset confirmation"
    }
    if (-not $ConfirmReconciliation) {
        throw "Reconcile requires -ConfirmReconciliation"
    }
    $actualHost = [System.Net.Dns]::GetHostName()
    if (-not [string]::Equals(
        $ConfirmHost,
        $actualHost,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Reconcile host confirmation mismatch"
    }
    if (
        [string]::IsNullOrWhiteSpace($ExpectedPlanDigest) -or
        $ExpectedPlanDigest -notmatch '^sha256:[0-9a-f]{64}$'
    ) {
        throw "Reconcile expected plan digest rejected"
    }
    if ([string]::IsNullOrWhiteSpace($OriginalPlanPath)) {
        throw "Reconcile requires -OriginalPlanPath"
    }
    $originalPlan = Read-OriginalResetPlan `
        $OriginalPlanPath `
        $ExpectedPlanDigest `
        $targets `
        $legacyTargets `
        $TaskName `
        $actualHost `
        ([bool]$DeleteCodexCredentials) `
        $DeleteTimeoutSeconds
    $openedReservation = Open-PrivateResetReservation `
        $evidence `
        $ExpectedPlanDigest `
        $ExpectedReservationSha256
    $receiptPath = [string]$openedReservation.path
    $reservationGuard = [System.IO.FileStream]$openedReservation.guard
    try {
        $existingReconciliation = Find-ExistingReconciliation `
            $evidence `
            ([string]$openedReservation.sha256)
        if ($null -ne $existingReconciliation) {
            if ([string]$openedReservation.location_at_open -eq "active") {
                $existingArchiveDirectory = Join-Path $evidence "reservation-archive"
                Ensure-PrivateDirectory $existingArchiveDirectory
                $existingArchivePath = Join-Path `
                    $existingArchiveDirectory `
                    (Get-ReservationArchiveName `
                        $openedReservation.document `
                        ([string]$openedReservation.sha256))
                if (Test-PathOccupied $existingArchivePath) {
                    throw "existing reconciliation reservation archive collision"
                }
                $guardedText = [System.IO.File]::ReadAllText(
                    [string]$openedReservation.path,
                    $Utf8NoBom
                )
                if (-not [string]::Equals(
                    $guardedText,
                    [string]$openedReservation.text,
                    [StringComparison]::Ordinal
                )) { throw "reservation changed before closure archive" }
                $reservationGuard.Dispose()
                $reservationGuard = $null
                Move-PrivateFileWriteThrough `
                    ([string]$openedReservation.path) `
                    $existingArchivePath
                Assert-PrivateAcl $existingArchivePath $false
            }
            ([string]$existingReconciliation.text).Trim()
            exit 0
        }
        $preexistingInventory = Get-ResetEvidenceInventory $evidence
        $originalTerminal = Get-OriginalTerminalWitness `
            $openedReservation.document `
            $evidence `
            ([string]$openedReservation.sha256)
        $targetPostconditions = @($targets | ForEach-Object {
            [ordered]@{
                path_digest = "sha256:" + (Get-Sha256 ($_.ToLowerInvariant()))
                absent = -not (Test-PathOccupied $_)
            }
        })
        if ($targetPostconditions.absent -contains $false) {
            throw "Reconcile target postcondition is not absent"
        }
        $taskPostcondition = Get-TaskAbsenceWitness $TaskName
        if (-not $taskPostcondition.absent) {
            throw "Reconcile task postcondition is not absent"
        }
        $processPostcondition = Get-ProcessAbsenceWitness $targets
        if (
            $processPostcondition.matching_process_count -ne 0 -or
            $processPostcondition.uninspectable_process_count -ne 0
        ) {
            throw ((
                "Reconcile process postcondition is ambiguous; matching={0}; " +
                "uninspectable={1}"
            ) -f
                [int]$processPostcondition.matching_process_count,
                [int]$processPostcondition.uninspectable_process_count
            )
        }
        $listenerPostcondition = Get-ListenerAbsenceWitness $ReconciliationListenerPorts
        if (
            $listenerPostcondition.matching_tcp_listener_count -ne 0 -or
            $listenerPostcondition.matching_udp_listener_count -ne 0
        ) {
            throw "Reconcile listener postcondition is not absent"
        }
        $reconciliationToken = [Guid]::NewGuid().ToString("N")
        $reconciliationId = (
            "uroboros-winops-zero-day-reset-reconciliation:" +
            (Get-Sha256 (
                [string]$openedReservation.sha256 + "|" +
                $reconciliationToken + "|" + $actualHost
            ))
        )
        $archiveDirectory = Join-Path $evidence "reservation-archive"
        $reservationDigestHex = ([string]$openedReservation.sha256).Substring(7)
        $finalReceiptPath = Join-Path $evidence (
            "recon-" + $reservationDigestHex.Substring(0, 16) + "-" +
            $reconciliationToken + ".json"
        )
        $archiveName = Get-ReservationArchiveName `
            $openedReservation.document `
            ([string]$openedReservation.sha256)
        $archivePath = Join-Path $archiveDirectory $archiveName
        if (
            (Test-PathOccupied $finalReceiptPath) -or
            (
                [string]$openedReservation.location_at_open -eq "active" -and
                (Test-PathOccupied $archivePath)
            )
        ) {
            throw "Reconcile evidence output collision"
        }
        $limitations = @("original_action_outcome_remains_unknown")
        if ($OriginalPlanProvenance -eq "reconstructed-from-captured-terminal-output") {
            $limitations += "original_plan_reconstructed_from_captured_terminal_output"
        }
        $sourceAttemptUid = if (
            $openedReservation.document.PSObject.Properties.Name -contains "attempt_uid"
        ) {
            [string]$openedReservation.document.attempt_uid
        }
        else {
            "legacy-v1:" + $reservationDigestHex
        }
        $reconciliationReceipt = [ordered]@{
            protocol = "integrity-guardian/uroboros-winops-zero-day-reset-reconciliation/v2"
            reconciliation_uid = $reconciliationToken
            reconciliation_id = $reconciliationId
            reconciled_at = [DateTime]::UtcNow.ToString("o")
            host = $actualHost
            attempt_uid = $sourceAttemptUid
            source_attempt_id = $sourceAttemptUid
            source_reservation = [ordered]@{
                protocol = [string]$openedReservation.document.protocol
                digest = [string]$openedReservation.sha256
                location_at_open = [string]$openedReservation.location_at_open
                name_digest = "sha256:" + (Get-Sha256 (
                    [System.IO.Path]::GetFileName(
                        [string]$openedReservation.path
                    ).ToLowerInvariant()
                ))
            }
            original_terminal = $originalTerminal
            bound_preexisting_artifacts = @($preexistingInventory.entries)
            artifact_inventory_digest = [string]$preexistingInventory.digest
            original_action_outcome = "unknown-outcome"
            reconciliation_outcome = "confirmed-success"
            postconditions_status = "confirmed-absent"
            plan_digest = [string]$originalPlan.plan_digest
            reservation_digest = [string]$openedReservation.sha256
            original_plan_provenance = $OriginalPlanProvenance
            postconditions = [ordered]@{
                targets = $targetPostconditions
                task = $taskPostcondition
                inspected_process_count = [int]$processPostcondition.inspected_process_count
                self_process_excluded_count = [int]$processPostcondition.self_process_excluded_count
                controller_process_excluded_count = [int]$processPostcondition.controller_process_excluded_count
                matching_process_count = [int]$processPostcondition.matching_process_count
                uninspectable_process_count = [int]$processPostcondition.uninspectable_process_count
                protected_os_process_count = [int]$processPostcondition.protected_os_process_count
                inspected_listener_ports = @($listenerPostcondition.inspected_listener_ports)
                matching_tcp_listener_count = [int]$listenerPostcondition.matching_tcp_listener_count
                matching_udp_listener_count = [int]$listenerPostcondition.matching_udp_listener_count
            }
            limitations = $limitations
            reconciliation_only = $true
            action_replayed = $false
            destructive_write_performed = $false
            event_write_performed = $false
            evidence_write_scope = "reconciliation-receipt-only"
            local_destructive_authority = $false
            automatic_retry_allowed = $false
            reconciliation_required = $false
            imports_remote_memory = $false
            production_authority = $false
        }
        $reconciliationJson = $reconciliationReceipt |
            ConvertTo-Json -Depth 10 -Compress
        Commit-ReservedReceipt `
            $receiptPath `
            ([string]$openedReservation.text) `
            $reservationGuard `
            $finalReceiptPath `
            $archiveDirectory `
            $archivePath `
            ($reconciliationJson + "`n") `
            ([string]$openedReservation.location_at_open -eq "active")
        $reconciliationJson
        exit 0
    }
    finally {
        if ($null -ne $reservationGuard) {
            $reservationGuard.Dispose()
        }
    }
}

if (-not $ConfirmDestructiveReset) {
    throw "Apply requires -ConfirmDestructiveReset before mutation"
}
if (-not [string]::Equals(
    $ConfirmHost,
    [string]$planCore.host,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Apply host confirmation mismatch"
}
if ($ExpectedPlanDigest -ne $planDigest) {
    throw "Apply plan digest mismatch"
}
if (-not $DeleteCodexCredentials -and [System.IO.File]::Exists((Join-Path $codex "auth.json"))) {
    throw "Codex credentials exist; zero-day reset requires explicit -DeleteCodexCredentials"
}
if ($taskWitness.present -and -not $taskWitness.exact_scope_bound) {
    throw "scheduled task is present but does not bind the exact reset targets"
}
foreach ($target in $targets) {
    if ([System.IO.File]::Exists($target)) {
        throw "reset target is occupied by a file"
    }
}
Assert-NoPendingResetReservation $evidence
$receiptPath = Join-Path $evidence "uroboros-winops-zero-day-reset-active.json"
$attemptUid = [Guid]::NewGuid().ToString("N")
$finalReceiptPath = Join-Path $evidence (
    "uroboros-winops-zero-day-reset-" + $attemptUid + ".json"
)
$archiveDirectory = Join-Path $evidence "reservation-archive"
$archivePath = Join-Path $archiveDirectory (
    "uroboros-winops-zero-day-reset-reservation-" + $attemptUid + ".json"
)
Ensure-PrivateEvidenceRoot $evidence
Ensure-PrivateDirectory $archiveDirectory
if (
    (Test-PathOccupied $finalReceiptPath) -or
    (Test-PathOccupied $archivePath)
) {
    throw "reset evidence output collision"
}
$startedAt = [DateTime]::UtcNow.ToString("o")
$reservation = Reserve-PrivateReceipt `
    $evidence `
    $receiptPath `
    $planDigest `
    $startedAt `
    $attemptUid `
    ([System.IO.Path]::GetFileName($finalReceiptPath)) `
    ([System.IO.Path]::GetFileName($archivePath))
$reservationText = [string]$reservation.text
$reservationGuard = [System.IO.FileStream]$reservation.guard
$outcome = "not-started"
$containedProcesses = @()
$deletions = @()
$selfProcessExcludedCount = 0
$controllerProcessExcludedCount = 0
try {
    $processSnapshot = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $controller = Get-ControllerProcessBoundary $processSnapshot $targets
    $selfProcessExcludedCount = @($processSnapshot | Where-Object {
        [uint32]$_.ProcessId -eq [uint32]$PID -and
        $controller.process_ids.ContainsKey([string][uint32]$_.ProcessId)
    }).Count
    $controllerProcessExcludedCount = [int]$controller.excluded_count
    if ($selfProcessExcludedCount -ne 1) {
        throw "current reset process identity was not uniquely observed"
    }
    $processes = @()
    foreach ($candidate in $processSnapshot) {
        if ($controller.process_ids.ContainsKey([string][uint32]$candidate.ProcessId)) {
            continue
        }
        $candidateExecutable = [string]$candidate.ExecutablePath
        if (
            [string]::IsNullOrWhiteSpace($candidateExecutable) -and
            [uint32]$candidate.ProcessId -gt 4
        ) {
            $candidateExecutable = Get-LimitedProcessImagePath `
                ([uint32]$candidate.ProcessId)
        }
        if (Test-IsBoundedProtectedProcess $candidate $candidateExecutable) {
            continue
        }
        $candidateSurrogate = [pscustomobject]@{
            ProcessId = [uint32]$candidate.ProcessId
            Name = [string]$candidate.Name
            ExecutablePath = $candidateExecutable
            CommandLine = [string]$candidate.CommandLine
            CreationDate = [string]$candidate.CreationDate
            ParentProcessId = [uint32]$candidate.ParentProcessId
        }
        $classification = Get-ProcessTargetClassification $candidateSurrogate $targets
        if ($classification -eq "ambiguous") {
            throw "target process classification is ambiguous before mutation"
        }
        if ($classification -eq "match") {
            $processes += $candidateSurrogate
        }
    }
    if ($taskWitness.present) {
        Stop-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -InputObject $task -Confirm:$false
    }
    foreach ($process in $processes) {
        $identity = [ordered]@{
            process_id = [uint32]$process.ProcessId
            parent_process_id = [uint32]$process.ParentProcessId
            creation_date = [string]$process.CreationDate
            executable_path = [string]$process.ExecutablePath
        }
        Stop-ExactTargetProcess $process $targets
        $containedProcesses += $identity
    }
    foreach ($target in $targets) {
        Assert-NoReparsePathChain $target "reset target"
        $deleteWitness = Get-PathWitness $target
        if ($deleteWitness.reparse_point) {
            throw "reset target became a reparse point before delete"
        }
        $deletions += Remove-DirectoryBounded $target $DeleteTimeoutSeconds
        if ($deletions[-1].result -eq "unknown-outcome-timeout") {
            $outcome = "unknown-outcome"
            $failure = "bounded delete timeout; outcome remains unknown"
            break
        }
        if ($deletions[-1].result -eq "confirmed-failure") {
            $outcome = "confirmed-failure"
            $failure = "bounded delete returned confirmed failure"
            break
        }
    }
    if ($outcome -eq "not-started") {
        $post = @($targets | ForEach-Object { Get-PathWitness $_ })
        $taskAbsent = (Get-TaskAbsenceWitness $TaskName).absent
        $outcome = if (
            $taskAbsent -and -not ($post.exists -contains $true)
        ) { "confirmed-success" } else { "confirmed-failure" }
        if ($outcome -eq "confirmed-failure") {
            $failure = "final bounded absence postcondition failed"
        }
    }
}
catch {
    $outcome = if ($outcome -eq "not-started") { "confirmed-failure" } else { $outcome }
    $failure = $_.Exception.Message
}
$finalReceipt = [ordered]@{
    protocol = "integrity-guardian/uroboros-winops-zero-day-reset-receipt/v2"
    outcome = $outcome
    attempt_uid = $attemptUid
    started_at = $startedAt
    finished_at = [DateTime]::UtcNow.ToString("o")
    plan_digest = $planDigest
    task_name = $TaskName
    contained_processes = $containedProcesses
    self_process_excluded_count = $selfProcessExcludedCount
    controller_process_excluded_count = $controllerProcessExcludedCount
    deletions = $deletions
    reservation_digest = "sha256:" + (Get-Sha256 $reservationText)
    target_absence = @($targets | ForEach-Object { -not (Test-PathOccupied $_) })
    task_absent = (Get-TaskAbsenceWitness $TaskName).absent
    credentials_deleted = [bool]$DeleteCodexCredentials
    failure = if (Get-Variable failure -ErrorAction SilentlyContinue) { $failure } else { $null }
    automatic_retry_allowed = $false
    action_replayed = $false
    local_destructive_action = $true
    owner_authorization_proven = $false
    imports_remote_memory = $false
    production_authority = $false
    path_identity_held_during_delete = $false
    hostile_same_principal_race_proven = $false
    receipt_guard_held_until_atomic_commit = $true
    receipt_guard_release = "after-final-create-flush-acl-and-byte-readback-before-write-through-reservation-archive"
    same_principal_precommit_swap_window = $false
}
$receiptJson = $finalReceipt | ConvertTo-Json -Depth 10 -Compress
Commit-ReservedReceipt `
    $receiptPath `
    $reservationText `
    $reservationGuard `
    $finalReceiptPath `
    $archiveDirectory `
    $archivePath `
    ($receiptJson + "`n")
$receiptJson
if ($outcome -ne "confirmed-success") {
    throw "zero-day reset did not reach confirmed-success; automatic retry is forbidden"
}
