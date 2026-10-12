[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AssetsDirectory,
    [Parameter(Mandatory = $true)][string]$GuardianExecutable,
    [Parameter(Mandatory = $true)][string]$ApplicationDirectory,
    [Parameter(Mandatory = $true)][string]$ProfilePath,
    [Parameter(Mandatory = $true)][string]$ReceiptPath,
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$NodeId,
    [string]$CollectorId = "collector:integrity-windows-host-v1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
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

function Set-OwnerPrivateAcl([string]$Path) {
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($current)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($current, $system, $admins)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

$assets = [System.IO.Path]::GetFullPath($AssetsDirectory)
$source = Join-Path $assets "IntegrityHostCollector.cs"
$manifestPath = Join-Path $assets "windows-asset-manifest.json"
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "shipped Windows collector source is absent"
}
$assetVerification = (& $GuardianExecutable windows-assets-verify `
    --manifest $manifestPath `
    --assets-directory $assets) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or
    $assetVerification.status -ne "PASS" -or
    $assetVerification.asset_count -ne 9 -or
    $assetVerification.production_authority -ne $false) {
    throw "shipped Windows asset manifest verification failed"
}
$assetManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$sourceRecord = @($assetManifest.assets | Where-Object {
    $_.name -eq "IntegrityHostCollector.cs"
})
if ($sourceRecord.Count -ne 1) {
    throw "shipped Windows collector manifest entry is absent"
}
$sourceDigest = "sha256:" + (Get-Sha256 $source)
if ($sourceDigest -ne ("sha256:" + [string]$sourceRecord[0].sha256)) {
    throw "shipped Windows collector source digest mismatch"
}
$compilerCandidates = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
)
$compiler = $compilerCandidates | Where-Object {
    Test-Path -LiteralPath $_ -PathType Leaf
} | Select-Object -First 1
if (-not $compiler) {
    throw "Windows C# compiler not found; dynamic compilation fallback is disabled"
}
$compilerDigest = "sha256:" + (Get-Sha256 $compiler)
$application = [System.IO.Path]::GetFullPath($ApplicationDirectory)
$profileFull = [System.IO.Path]::GetFullPath($ProfilePath)
$receiptFull = [System.IO.Path]::GetFullPath($ReceiptPath)
$outputRoot = Split-Path -Parent $application
if ((Split-Path -Parent $profileFull) -ne $outputRoot -or
    (Split-Path -Parent $receiptFull) -ne $outputRoot) {
    throw "collector application, profile and receipt must share one output root"
}
if (Test-Path -LiteralPath $outputRoot) {
    throw "collector output root must be absent"
}
if (Test-Path -LiteralPath $application) {
    throw "collector application directory must be absent"
}
if (Test-Path -LiteralPath $profileFull) {
    throw "collector profile output must be absent"
}
if (Test-Path -LiteralPath $receiptFull) {
    throw "collector build receipt output must be absent"
}
try {
    New-Item -ItemType Directory -Path $outputRoot -ErrorAction Stop | Out-Null
    Set-OwnerPrivateAcl $outputRoot
    New-Item -ItemType Directory -Path $application -ErrorAction Stop | Out-Null
    Set-OwnerPrivateAcl $application
    $executable = Join-Path $application "IntegrityHostCollector.exe"
    & $compiler /nologo /target:exe /optimize+ "/out:$executable" $source
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Windows collector compilation failed (exit $LASTEXITCODE)"
    }
    if (("sha256:" + (Get-Sha256 $compiler)) -ne $compilerDigest -or
        ("sha256:" + (Get-Sha256 $source)) -ne $sourceDigest) {
        throw "compiler or collector source changed during build"
    }
    $executableDigest = "sha256:" + (Get-Sha256 $executable)
    & $GuardianExecutable windows-host-profile `
        --executable $executable `
        --tenant-id $TenantId `
        --collector-id $CollectorId `
        --node-id $NodeId `
        --output $profileFull
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $profileFull -PathType Leaf)) {
        throw "Guardian collector profile builder failed (exit $LASTEXITCODE)"
    }
    $profileDigest = "sha256:" + (Get-Sha256 $profileFull)
    $receipt = [ordered]@{
        protocol = "integrity-guardian/windows-host-collector-build-receipt/v1"
        status = "PASS"
        compiler = $compiler
        compiler_digest = $compilerDigest
        assets_manifest_digest = [string]$assetVerification.manifest_digest
        source_digest = $sourceDigest
        executable_digest = $executableDigest
        profile_digest = $profileDigest
        add_type_used = $false
        application_file_count = 1
        production_authority = $false
    }
    $receiptJson = $receipt | ConvertTo-Json -Depth 6 -Compress
    $receiptStaging = Join-Path $application (
        ".build-receipt-" + [Guid]::NewGuid().ToString("N") + ".json"
    )
    Write-NewUtf8 $receiptStaging "$receiptJson`n"
    try {
        & $GuardianExecutable private-document-store `
            --schema windows-host-collector-build-receipt `
            --input $receiptStaging `
            --output $receiptFull | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $receiptFull -PathType Leaf)) {
            throw "private collector build receipt write failed (exit $LASTEXITCODE)"
        }
    }
    finally {
        Remove-Item -LiteralPath $receiptStaging -Force -ErrorAction SilentlyContinue
    }
    $verifiedReceiptJson = (& $GuardianExecutable private-document-read `
        --schema windows-host-collector-build-receipt `
        --path $receiptFull) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "private collector build receipt verification failed (exit $LASTEXITCODE)"
    }
    $verifiedReceiptJson
}
catch {
    $originalFailure = $_
    $rollbackErrors = @()
    if (Test-Path -LiteralPath $outputRoot) {
        try { Remove-Item -LiteralPath $outputRoot -Recurse -Force }
        catch { $rollbackErrors += "collector output root: " + $_.Exception.Message }
    }
    if ($rollbackErrors.Count -ne 0) {
        throw (
            "collector build failed and rollback was incomplete: " +
            [string]::Join(" | ", $rollbackErrors) +
            "; original failure: " + $originalFailure.Exception.Message
        )
    }
    throw $originalFailure
}
