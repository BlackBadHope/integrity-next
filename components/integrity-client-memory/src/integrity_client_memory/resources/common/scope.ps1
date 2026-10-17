[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Event,
    [Parameter(Mandatory=$true)][ValidateSet('codex','claude')][string]$Harness
)
if (-not $env:INTEGRITY_CLIENT_MEMORY_CONFIG) { throw "Own client configuration is required" }
& integrity-client-memory --config $env:INTEGRITY_CLIENT_MEMORY_CONFIG common/integrity_scope_synapse --event $Event --harness $Harness
exit $LASTEXITCODE
