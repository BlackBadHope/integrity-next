[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GuardianRoot,
    [Parameter(Mandatory = $true)][string]$ProfilePath,
    [Parameter(Mandatory = $true)][string]$CredentialReceiptPath,
    [Parameter(Mandatory = $true)][string[]]$CredentialSourcePath,
    [Parameter(Mandatory = $true)][string]$SeedBuildReceiptPath,
    [Parameter(Mandatory = $true)][string[]]$CollectorResultPath,
    [Parameter(Mandatory = $true)][string]$OperationManifestPath,
    [Parameter(Mandatory = $true)][string]$OperationReceiptPath,
    [Parameter(Mandatory = $true)][string]$OperationEvidenceDirectory,
    [Parameter(Mandatory = $true)][string]$PersistenceReceiptPath,
    [Parameter(Mandatory = $true)][string]$PersistenceWitnessPath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [switch]$RequireReboot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$guardian = Join-Path ([System.IO.Path]::GetFullPath($GuardianRoot)) "Scripts\guardian.exe"
if (-not (Test-Path -LiteralPath $guardian -PathType Leaf)) {
    throw "Guardian launcher is absent"
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "zero-day final witness output must be absent"
}
if (Test-Path -LiteralPath $CredentialReceiptPath) {
    throw "credential custody receipt output must be absent"
}
if (-not (Test-Path -LiteralPath $PersistenceWitnessPath -PathType Leaf)) {
    throw "precomputed persistence witness is absent"
}
$arguments = @(
    "zero-day-verify",
    "--profile", $ProfilePath,
    "--credential-receipt", $CredentialReceiptPath,
    "--seed-build-receipt", $SeedBuildReceiptPath,
    "--operation-manifest", $OperationManifestPath,
    "--operation-receipt", $OperationReceiptPath,
    "--operation-evidence-directory", $OperationEvidenceDirectory,
    "--persistence-receipt", $PersistenceReceiptPath,
    "--persistence-witness", $PersistenceWitnessPath,
    "--require-runtime",
    "--output", $OutputPath
)
foreach ($collector in $CollectorResultPath) {
    $arguments += @("--collector-result", $collector)
}
foreach ($credentialSource in $CredentialSourcePath) {
    $arguments += @("--credential-source", $credentialSource)
}
if ($RequireReboot) { $arguments += "--require-cold-start" }
& $guardian @arguments
$guardianExit = $LASTEXITCODE
if ($guardianExit -ne 0) {
    throw "zero-day semantic receipt gate failed (exit $guardianExit)"
}
if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    throw "zero-day verifier exited without its required receipt"
}
$witness = (& $guardian private-document-read `
    --schema zero-day-final-witness `
    --path $OutputPath) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "private zero-day witness read failed (exit $LASTEXITCODE)"
}
if ($witness.protocol -ne "integrity-guardian/zero-day-final-witness/v2" -or
    $witness.result -ne "BOUNDED_PASS_NOT_PRODUCTION_READY" -or
    $witness.local_acceptance -ne "PASS" -or
    $witness.operational_ready -ne $false -or
    $witness.production_ready -ne $false -or
    $witness.unproven_external_claims.Count -ne 4 -or
    $witness.production_authority -ne $false) {
    throw "zero-day final witness semantics rejected"
}
